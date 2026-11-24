"""Own images of the core (lib/own_images.py, compat/own-images.yaml, tools/build-images).

A core service that runs code of this repository runs it from an image built here:
one Dockerfile per service on a base pinned by digest, not root, with the notice
files inside. The build covers linux/amd64 and linux/arm64 and is reproducible; the
image is pushed, signed with the release key into the signature repository and
pinned in compose as `<name>:<VERSION>@sha256:<digest>`. Its entry in the suite bill
of materials carries that tag and digest. The start check treats it like any other
image: listed with that digest and signed, or refused.

Docker and cosign are replaced by a recording runner here; the round trip through a
real registry is in test_own_images_registry.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation
from test_images import FakeRegistry, _bom, _image, _new_keypair

from lib import envtree, images, own_images, suite

REPO = Path(__file__).resolve().parents[2]
REQUIRE_COMPOSE = os.environ.get("PAPAIA_REQUIRE_GOLDEN_COMPOSE") == "1"
VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
BASE = "python:3.12.16-alpine3.24@sha256:" + "a" * 64
MIRROR = "127.0.0.1:59860/unpublished/"


# ── the shipped declaration ──────────────────────────────────────────────────


def test_the_core_builds_its_own_images_for_the_services_that_run_its_code():
    declared = {image.name: image for image in own_images.load(REPO)}

    assert set(declared) == {
        "ghcr.io/fidonis/papaia-egress",
        "ghcr.io/fidonis/papaia-lifecycle",
        "ghcr.io/fidonis/papaia-audit",
        "ghcr.io/fidonis/papaia-people",
        "ghcr.io/fidonis/papaia-docker-gate",
    }
    assert declared["ghcr.io/fidonis/papaia-egress"].services == ("papaia-egress",)
    assert declared["ghcr.io/fidonis/papaia-lifecycle"].services == (
        "papaia-lifecycle",
        "papaia-startgate-check",
    )
    assert declared["ghcr.io/fidonis/papaia-audit"].services == (
        "papaia-audit",
        "papaia-audit-schema",
    )
    assert declared["ghcr.io/fidonis/papaia-people"].services == ("papaia-people",)
    assert declared["ghcr.io/fidonis/papaia-docker-gate"].services == ("papaia-docker-gate",)
    for image in declared.values():
        assert image.license == "MIT"
        assert image.license_class == "P"
        assert (REPO / image.dockerfile).is_file()


def test_the_shipped_tree_passes_every_rule():
    assert own_images.check(REPO) == []


def test_every_own_image_is_pinned_in_compose_with_the_core_version_and_a_digest():
    services = images.compose_services(REPO)
    for image in own_images.load(REPO):
        for service in image.services:
            ref = images.parse_ref(services[service])
            assert f"{ref.registry}/{ref.repository}" == image.name
            assert ref.tag == VERSION
            assert ref.digest is not None


def test_no_core_service_runs_code_of_this_repository_from_a_mount():
    for path in sorted((REPO / "src").rglob("docker-compose*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            if not name.startswith("papaia-"):
                continue
            for mount in body.get("volumes") or []:
                source = mount.get("source", "") if isinstance(mount, dict) else mount
                assert not str(source).startswith("./"), f"{path}: {name} mounts {source}"


def test_the_image_notice_lists_the_runtime_components():
    for image in own_images.load(REPO):
        notice = (REPO / Path(image.dockerfile).parent / "THIRD_PARTY_LICENSES.md").read_text(
            encoding="utf-8"
        )
        assert "Python" in notice and "PSF-2.0" in notice


def test_the_inventory_documents_the_own_images():
    inventory = (REPO / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    for image in own_images.load(REPO):
        assert f"`{image.name}`" in inventory


# ── a synthetic tree ─────────────────────────────────────────────────────────


DOCKERFILE = f"""\
FROM {BASE}
ARG VERSION=0.0.0
LABEL org.opencontainers.image.licenses="MIT" \\
      org.opencontainers.image.version="${{VERSION}}"
COPY LICENSE /usr/share/licenses/papaia-probe/LICENSE
COPY src/infra/probe/THIRD_PARTY_LICENSES.md \\
     /usr/share/licenses/papaia-probe/THIRD_PARTY_LICENSES.md
COPY --from={BASE} /usr/local/lib/python3.12/LICENSE.txt \\
     /usr/share/licenses/papaia-probe/texts/Python-2.0.txt
COPY src/infra/probe/probe.py /opt/papaia-probe/probe.py
USER 65532:65532
CMD ["python3", "/opt/papaia-probe/probe.py"]
"""


def _declaration(**changes: object) -> dict:
    entry = {
        "name": "ghcr.io/example/papaia-probe",
        "dockerfile": "src/infra/probe/Dockerfile",
        "inputs": [
            "src/infra/probe/Dockerfile",
            "src/infra/probe/probe.py",
            "src/infra/probe/THIRD_PARTY_LICENSES.md",
        ],
        "services": ["papaia-probe"],
        "license": "MIT",
        "license_class": "P",
    }
    entry.update(changes)
    return {"schema": own_images.SCHEMA, "images": [entry]}


def _tree(
    tmp_path: Path,
    *,
    declaration: dict | None = None,
    dockerfile: str = DOCKERFILE,
    image: str = f"ghcr.io/example/papaia-probe:1.10.0@{D1}",
    extra_service: dict | None = None,
) -> Path:
    root = tmp_path / "core"
    probe = root / "src" / "infra" / "probe"
    probe.mkdir(parents=True)
    (root / "compat").mkdir()
    (root / "VERSION").write_text("1.10.0\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (probe / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    (probe / "probe.py").write_text("print('probe')\n", encoding="utf-8")
    (probe / "THIRD_PARTY_LICENSES.md").write_text("Python (PSF-2.0)\n", encoding="utf-8")
    services = {
        "papaia-probe": {"image": image, "read_only": True},
        # Another service of the same file: pin must not touch it.
        "papaia-probe-init": {"image": f"python:3.12.16-alpine3.24@{D3}", "read_only": True},
    }
    if extra_service:
        services.update(extra_service)
    (probe / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": services}, sort_keys=False), encoding="utf-8"
    )
    (root / own_images.DECLARATION_PATH).write_text(
        yaml.safe_dump(declaration or _declaration(), sort_keys=False), encoding="utf-8"
    )
    (root / images.SIGNATURES_PATH).write_text(
        f"schema: {images.SIGNATURES_SCHEMA}\nrepository: ghcr.io/example/signatures\n",
        encoding="utf-8",
    )
    return root


def _git(root: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.org",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.org",
        "GIT_AUTHOR_DATE": "2026-11-01T10:00:00Z",
        "GIT_COMMITTER_DATE": "2026-11-01T10:00:00Z",
    }
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, env=env, check=True
    )
    return done.stdout.strip()


def _committed(tmp_path: Path, **kwargs) -> Path:
    root = _tree(tmp_path, **kwargs)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "probe")
    return root


def test_the_synthetic_tree_passes(tmp_path: Path):
    assert own_images.check(_tree(tmp_path)) == []


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"extra": 1}, "unknown"),
        ({"name": "ghcr.io/example/papaia-probe:1.0.0"}, "name"),
        ({"name": "papaia-probe"}, "registry"),
        ({"dockerfile": "src/infra/other/Dockerfile"}, "inputs"),
        ({"inputs": ["src/infra/probe/Dockerfile", "../outside"]}, "path"),
        ({"inputs": ["src/infra/probe/Dockerfile", "/etc/passwd"]}, "path"),
        ({"inputs": ["src/infra/probe/Dockerfile", "src/infra/probe/missing.py"]}, "file"),
        ({"license_class": "Z"}, "license_class"),
        ({"license": "MIT; rm"}, "license"),
        ({"services": []}, "services"),
        ({"services": ["Bad Name"]}, "services"),
    ],
)
def test_the_declaration_is_validated(tmp_path: Path, changes: dict, message: str):
    root = _tree(tmp_path, declaration=_declaration(**changes))

    with pytest.raises(own_images.OwnImageError, match=message):
        own_images.load(root)


def test_the_declaration_refuses_unknown_top_level_fields_and_duplicates(tmp_path: Path):
    doc = _declaration()
    doc["images"].append(dict(doc["images"][0]))
    with pytest.raises(own_images.OwnImageError, match="twice"):
        own_images.load(_tree(tmp_path / "a", declaration=doc))
    doc = _declaration()
    doc["note"] = "x"
    with pytest.raises(own_images.OwnImageError, match="schema"):
        own_images.load(_tree(tmp_path / "b", declaration=doc))


def test_a_stage_may_run_on_the_build_platform(tmp_path: Path):
    """A stage that only fetches files for the target (such as wheels pinned by hash)
    runs natively; what it produces is copied into the final stage by name."""
    staged = DOCKERFILE.replace(
        f"FROM {BASE}",
        f"FROM --platform=$BUILDPLATFORM {BASE} AS deps\nRUN true\nFROM {BASE}",
        1,
    ).replace("COPY src/infra/probe/probe.py", "COPY --from=deps /opt/lib /opt/lib\n"
              "COPY src/infra/probe/probe.py", 1)

    assert own_images.check(_tree(tmp_path, dockerfile=staged)) == []


def test_an_input_that_is_a_symlink_is_refused(tmp_path: Path):
    root = _tree(tmp_path)
    target = root / "src" / "infra" / "probe" / "probe.py"
    target.unlink()
    target.symlink_to(root / "LICENSE")

    with pytest.raises(own_images.OwnImageError, match="regular file"):
        own_images.load(root)


@pytest.mark.parametrize(
    "old, new, message",
    [
        (f"FROM {BASE}", "FROM python:3.12.16-alpine3.24", "FROM"),
        (f"FROM {BASE}", "FROM python@sha256:" + "a" * 64, "FROM"),
        (f"FROM {BASE}", "ARG BASE\nFROM $BASE", "FROM"),
        (f"--from={BASE}", "--from=python:3.12", "--from"),
        ("USER 65532:65532", "USER 0:0", "USER"),
        ("USER 65532:65532", "USER root", "USER"),
        ("USER 65532:65532\n", "", "USER"),
        ('licenses="MIT"', 'licenses="Apache-2.0"', "licenses"),
        ("COPY LICENSE /usr/share/licenses/papaia-probe/LICENSE\n", "", "LICENSE"),
        ("src/infra/probe/probe.py /opt", "src/infra/probe/other.py /opt", "inputs"),
        ("CMD [", "ADD https://example.org/x.tar.gz /opt/\nCMD [", "ADD"),
        (f"FROM {BASE}", "FROM --platform=$BUILDPLATFORM python:3.12.16-alpine3.24", "FROM"),
        (f"FROM {BASE}", f"FROM --platform=linux/amd64 {BASE}", "--platform"),
        (f"FROM {BASE}", f"FROM --network=host {BASE}", "--network"),
    ],
)
def test_the_dockerfile_rules(tmp_path: Path, old: str, new: str, message: str):
    assert old in DOCKERFILE
    root = _tree(tmp_path, dockerfile=DOCKERFILE.replace(old, new, 1))
    (image,) = own_images.load(root)

    problems = own_images.dockerfile_problems(root, image)

    assert any(message in problem for problem in problems), problems


@pytest.mark.parametrize(
    "image, message",
    [
        ("ghcr.io/example/papaia-probe:1.10.0", "digest"),
        (f"ghcr.io/example/papaia-probe:1.9.0@{D1}", "1.10.0"),
        (f"ghcr.io/example/other:1.10.0@{D1}", "ghcr.io/example/papaia-probe"),
        (f"python:3.12.16-alpine3.24@{D1}", "ghcr.io/example/papaia-probe"),
    ],
)
def test_the_service_of_an_own_image_must_pin_it(tmp_path: Path, image: str, message: str):
    problems = own_images.compose_problems(_tree(tmp_path, image=image))

    assert any(message in problem for problem in problems), problems


def test_a_compose_build_or_a_code_mount_is_refused(tmp_path: Path):
    root = _tree(
        tmp_path,
        extra_service={
            "papaia-built": {"build": {"context": "."}, "image": "papaia-built:local"},
            "papaia-mounted": {
                "image": f"python:3.12.16-alpine3.24@{D2}",
                "volumes": [{"type": "bind", "source": "./probe.py", "target": "/opt/p.py"}],
            },
        },
    )

    problems = own_images.compose_problems(root)

    assert any("papaia-built" in p and "build" in p for p in problems), problems
    assert any("papaia-mounted" in p and "./probe.py" in p for p in problems), problems


def test_a_declared_service_missing_from_compose_is_refused(tmp_path: Path):
    root = _tree(tmp_path, declaration=_declaration(services=["papaia-probe", "papaia-gone"]))

    assert any("papaia-gone" in p for p in own_images.compose_problems(root))


# ── build ────────────────────────────────────────────────────────────────────


class Recorder:
    """Stands in for docker and cosign: records each call; a buildx build writes the
    metadata file the way buildx does."""

    def __init__(self, digest: str = D1, fail: bool = False) -> None:
        self.calls: list[tuple[list[str], dict | None]] = []
        self.contexts: list[list[str]] = []
        self.digest = digest
        self.fail = fail

    def __call__(self, cmd: list[str], env: dict | None = None):
        self.calls.append((list(cmd), env))
        if cmd[:3] == ["docker", "buildx", "build"]:
            context = Path(cmd[-1])
            self.contexts.append(
                sorted(p.relative_to(context).as_posix() for p in context.rglob("*") if p.is_file())
            )
            meta = Path(cmd[cmd.index("--metadata-file") + 1])
            meta.write_text(json.dumps({"containerimage.digest": self.digest}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 1 if self.fail else 0, "", "")


def test_build_covers_both_platforms_reproducibly_from_the_declared_inputs(tmp_path: Path):
    root = _committed(tmp_path)
    (image,) = own_images.load(root)
    run = Recorder()

    built = own_images.build(root, image, prefix=MIRROR, workdir=tmp_path / "work", run=run)

    assert built == {
        "name": "ghcr.io/example/papaia-probe",
        "tag": "1.10.0",
        "digest": D1,
        "revision": _git(root, "rev-parse", "HEAD"),
    }
    ((cmd, _),) = run.calls
    assert cmd[:3] == ["docker", "buildx", "build"]
    assert cmd[cmd.index("--platform") + 1] == "linux/amd64,linux/arm64"
    assert "--provenance=false" in cmd and "--sbom=false" in cmd
    assert "SOURCE_DATE_EPOCH=0" in cmd
    assert "VERSION=1.10.0" in cmd
    output = cmd[cmd.index("--output") + 1].split(",")
    assert f"name={MIRROR}ghcr.io/example/papaia-probe:1.10.0" in output
    assert {"type=image", "push=true", "rewrite-timestamp=true"} <= set(output)
    # Only the declared inputs and the license are in the context.
    assert run.contexts == [
        [
            "LICENSE",
            "src/infra/probe/Dockerfile",
            "src/infra/probe/THIRD_PARTY_LICENSES.md",
            "src/infra/probe/probe.py",
        ]
    ]


def test_the_build_does_not_depend_on_when_or_where_it_was_committed(tmp_path: Path):
    """Timestamps are fixed (SOURCE_DATE_EPOCH=0), so a rebuild from any later commit,
    a shallow clone or another machine gives the same image for the same inputs."""
    first = _committed(tmp_path / "a")
    (first / "README.md").write_text("unrelated\n", encoding="utf-8")
    _git(first, "add", "README.md")
    _git(first, "commit", "-q", "--date=2027-01-01T00:00:00Z", "-m", "docs")
    second = _committed(tmp_path / "b")
    commands = []
    for root in (first, second):
        (image,) = own_images.load(root)
        run = Recorder()
        own_images.build(root, image, prefix="", workdir=tmp_path / "work", run=run)
        ((cmd, _),) = run.calls
        commands.append([part for part in cmd if str(tmp_path) not in part])

    assert commands[0] == commands[1]
    assert "SOURCE_DATE_EPOCH=0" in commands[0]


def test_the_context_modes_do_not_depend_on_the_checkout_or_the_umask(tmp_path: Path):
    """COPY keeps the modes of the context: they are part of the digest, and the user of
    the image (not root) must be able to read every file and enter every folder."""
    root = _tree(tmp_path)
    (root / "src" / "infra" / "probe" / "probe.py").chmod(0o600)
    (image,) = own_images.load(root)
    old = os.umask(0o077)
    try:
        context = own_images.stage_context(root, image, tmp_path / "work")
    finally:
        os.umask(old)

    for path in [context, *context.rglob("*")]:
        assert path.stat().st_mode & 0o777 == (0o755 if path.is_dir() else 0o644), path


def test_build_refuses_uncommitted_inputs(tmp_path: Path):
    root = _committed(tmp_path)
    (root / "src" / "infra" / "probe" / "probe.py").write_text("changed\n", encoding="utf-8")
    (image,) = own_images.load(root)
    run = Recorder()

    with pytest.raises(own_images.OwnImageError, match="uncommitted"):
        own_images.build(root, image, prefix="", workdir=tmp_path / "work", run=run)
    assert run.calls == []


def test_a_failed_or_digestless_build_is_an_error(tmp_path: Path):
    root = _committed(tmp_path)
    (image,) = own_images.load(root)

    with pytest.raises(own_images.OwnImageError, match="failed"):
        own_images.build(root, image, prefix="", workdir=tmp_path / "w1", run=Recorder(fail=True))
    with pytest.raises(own_images.OwnImageError, match="digest"):
        own_images.build(root, image, prefix="", workdir=tmp_path / "w2",
                         run=Recorder(digest="sha256:short"))


def test_an_invalid_registry_prefix_is_refused(tmp_path: Path):
    root = _committed(tmp_path)
    (image,) = own_images.load(root)

    with pytest.raises(own_images.OwnImageError, match="prefix"):
        own_images.build(root, image, prefix="no-slash", workdir=tmp_path / "w", run=Recorder())


# ── builds file ──────────────────────────────────────────────────────────────


def _builds(tmp_path: Path, *, prefix: str = MIRROR, digest: str = D1) -> Path:
    path = tmp_path / "builds.json"
    own_images.write_builds(
        path,
        prefix,
        [{"name": "ghcr.io/example/papaia-probe", "tag": "1.10.0", "digest": digest,
          "revision": "a" * 40}],
    )
    return path


def test_the_builds_file_round_trips_and_refuses_unknown_fields(tmp_path: Path):
    path = _builds(tmp_path)
    prefix, entries = own_images.read_builds(path)
    assert prefix == MIRROR and entries[0]["digest"] == D1

    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["images"][0]["extra"] = 1
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(own_images.OwnImageError, match="images\\[0\\]"):
        own_images.read_builds(path)


# ── sign ─────────────────────────────────────────────────────────────────────


def _key(tmp_path: Path) -> Path:
    key = tmp_path / "keys" / "cosign.key"
    key.parent.mkdir()
    key.write_text("encrypted cosign key\n", encoding="ascii")
    return key


def test_sign_signs_each_digest_into_the_signature_repository(tmp_path: Path):
    root = _tree(tmp_path)
    prefix, entries = own_images.read_builds(_builds(tmp_path))
    run = Recorder()
    env = {"COSIGN_PASSWORD": "session-only", "PATH": os.environ.get("PATH", "")}

    own_images.sign(root, prefix, entries, key=_key(tmp_path), env=env, run=run)

    ((cmd, used_env),) = run.calls
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert own_images.COSIGN_IMAGE in cmd
    assert f"COSIGN_REPOSITORY={MIRROR}ghcr.io/example/signatures" in cmd
    # The passphrase is handed over by name, never on the command line.
    assert "COSIGN_PASSWORD" in cmd and not any("session-only" in part for part in cmd)
    assert used_env["COSIGN_PASSWORD"] == "session-only"
    assert cmd[-1] == f"{MIRROR}ghcr.io/example/papaia-probe@{D1}"
    # A loopback test registry: plain HTTP, no transparency log.
    assert "--allow-http-registry" in cmd and "--tlog-upload=false" in cmd
    mount = cmd[cmd.index("-v") + 1]
    assert mount.endswith(":ro")
    # The key stays private to the signing account: cosign runs as that account.
    assert cmd[cmd.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


def test_sign_with_a_cosign_binary_keeps_the_transparency_log_for_a_real_registry(
    tmp_path: Path,
):
    root = _tree(tmp_path)
    prefix, entries = own_images.read_builds(_builds(tmp_path, prefix=""))
    run = Recorder()
    key = _key(tmp_path)

    own_images.sign(root, prefix, entries, key=key, cosign="/usr/local/bin/cosign",
                    env={"COSIGN_PASSWORD": ""}, run=run)

    ((cmd, used_env),) = run.calls
    assert cmd[:2] == ["/usr/local/bin/cosign", "sign"]
    assert used_env["COSIGN_REPOSITORY"] == "ghcr.io/example/signatures"
    assert "--allow-http-registry" not in cmd and "--tlog-upload=false" not in cmd
    assert cmd[-1] == f"ghcr.io/example/papaia-probe@{D1}"


def test_sign_refuses_a_key_inside_the_checkout_and_a_missing_passphrase(tmp_path: Path):
    root = _tree(tmp_path)
    prefix, entries = own_images.read_builds(_builds(tmp_path))
    inside = root / "cosign.key"
    inside.write_text("key\n", encoding="ascii")
    run = Recorder()

    with pytest.raises(own_images.OwnImageError, match="outside"):
        own_images.sign(root, prefix, entries, key=inside, env={"COSIGN_PASSWORD": "x"}, run=run)
    with pytest.raises(own_images.OwnImageError, match="COSIGN_PASSWORD"):
        own_images.sign(root, prefix, entries, key=_key(tmp_path), env={}, run=run)
    assert run.calls == []


def test_a_failed_signature_is_an_error(tmp_path: Path):
    root = _tree(tmp_path)
    prefix, entries = own_images.read_builds(_builds(tmp_path))

    with pytest.raises(own_images.OwnImageError, match="sign"):
        own_images.sign(root, prefix, entries, key=_key(tmp_path),
                        env={"COSIGN_PASSWORD": "x"}, run=Recorder(fail=True))


# ── pin ──────────────────────────────────────────────────────────────────────


def test_pin_rewrites_only_the_image_of_the_declared_services(tmp_path: Path):
    root = _tree(tmp_path)
    compose = root / "src" / "infra" / "probe" / "docker-compose.yml"
    before = compose.read_text(encoding="utf-8")
    _, entries = own_images.read_builds(_builds(tmp_path, digest=D2))

    changed = own_images.pin(root, entries)

    after = compose.read_text(encoding="utf-8")
    assert changed == ["src/infra/probe/docker-compose.yml: services.papaia-probe.image"]
    assert after == before.replace(f"papaia-probe:1.10.0@{D1}", f"papaia-probe:1.10.0@{D2}")
    assert images.compose_services(root)["papaia-probe-init"].endswith(D3)
    assert own_images.pin(root, entries) == []


def test_pin_refuses_a_build_of_another_version_or_an_undeclared_image(tmp_path: Path):
    root = _tree(tmp_path)
    other = {"name": "ghcr.io/example/papaia-probe", "tag": "1.9.0", "digest": D2,
             "revision": "a" * 40}
    with pytest.raises(own_images.OwnImageError, match="1.10.0"):
        own_images.pin(root, [other])
    with pytest.raises(own_images.OwnImageError, match="not declared"):
        own_images.pin(root, [dict(other, name="ghcr.io/example/unknown", tag="1.10.0")])


# ── bill of materials ────────────────────────────────────────────────────────


def test_the_bill_of_materials_entries_list_every_own_image_with_its_pinned_digest(
    tmp_path: Path,
):
    root = _tree(tmp_path)
    sbom = tmp_path / "probe.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")

    entries = own_images.bom_entries(root, {"ghcr.io/example/papaia-probe": sbom})

    assert entries == [
        {
            "name": "ghcr.io/example/papaia-probe",
            "tag": "1.10.0",
            "digest": D1,
            "license": "MIT",
            "license_class": "P",
            "sbom_digest": own_images.file_digest(sbom),
            "delivery": "shipped",
        }
    ]
    suite._validate_image(entries[0], "images[0]", "delivery", "core")


def test_the_bill_of_materials_entries_need_an_sbom_per_image(tmp_path: Path):
    with pytest.raises(own_images.OwnImageError, match="SBOM"):
        own_images.bom_entries(_tree(tmp_path), {})


def test_the_shipped_entries_name_every_own_image(tmp_path: Path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    declared = own_images.load(REPO)

    entries = own_images.bom_entries(REPO, {image.name: sbom for image in declared})

    services = images.compose_services(REPO)
    assert {(e["name"], e["tag"], e["digest"]) for e in entries} == {
        (image.name, VERSION, images.parse_ref(services[image.services[0]]).digest)
        for image in declared
    }


# ── start check ──────────────────────────────────────────────────────────────


def test_the_start_check_treats_an_own_image_like_any_other(tmp_path: Path):
    """Signed and listed with its digest: passes from the local registry. Unsigned,
    another digest or missing from the bill of materials: refused. No exception for an
    image built here."""
    private, pem = _new_keypair(tmp_path)
    name = "ghcr.io/fidonis/papaia-egress"
    bom = _bom(pem, [_image(name, "1.10.0", D1)])
    signatures = images.parse_ref(f"{MIRROR}ghcr.io/fidonis/papaia-signatures")
    registry = FakeRegistry()
    pinned = images.mirrored([f"{name}:1.10.0@{D1}"], MIRROR)

    def check(refs: list[str], doc: dict = bom) -> list[images.Problem]:
        return images.verify_images(refs, doc, registry=registry, mirror=MIRROR,
                                    signatures=f"{MIRROR}ghcr.io/fidonis/papaia-signatures")

    (unsigned,) = check(pinned)
    assert "no signature" in unsigned.reason

    registry.add_signature(signatures.registry, signatures.repository, D1, private, tmp_path)
    assert check(pinned) == []

    (other,) = check(images.mirrored([f"{name}:1.10.0@{D2}"], MIRROR))
    assert "digest differs" in other.reason
    (missing,) = check(pinned, _bom(pem, [_image("postgres", "18.3", D3)]))
    assert missing.reason == "not in the bill of materials"


# ── rendered compose ─────────────────────────────────────────────────────────


def _have_compose() -> bool:
    if shutil.which("docker") is None:
        return False
    done = subprocess.run(["docker", "compose", "version", "--short"], capture_output=True,
                          text=True, timeout=20, check=False)
    return done.returncode == 0


def test_the_rendered_compose_has_no_image_without_digest_and_no_local_build(tmp_path: Path):
    if not _have_compose():
        if REQUIRE_COMPOSE:
            pytest.fail("docker compose is required to render the core project")
        pytest.skip("docker compose is not available")
    inst = Installation(tmp_path, ["--app-host=https://papaia.example.org",
                                   "--enable-manager=true", "--enable-rag=true"])
    inst.setup(*inst.flags)
    envtree.materialize_core_env(inst.config, inst.repo)
    files = ["-f", str(inst.repo / "src" / "docker-compose.yml")]
    for override in sorted((inst.config / "overrides").glob("docker-compose.*.override.yml")):
        files += ["-f", str(override)]
    done = subprocess.run(
        ["docker", "compose", *files, "--env-file", str(inst.repo / "src" / ".env"),
         "--profile", "*", "config", "--format", "json"],
        capture_output=True, text=True, timeout=120, check=False,
        env={**os.environ, "UID": "1000", "GID": "1000", "DOCKER_GID": "999"},
    )
    assert done.returncode == 0, done.stderr
    services = json.loads(done.stdout)["services"]

    own = {image.name: image for image in own_images.load(REPO)}
    for name, body in services.items():
        assert "build" not in body, f"{name} is built locally"
        ref = images.parse_ref(body["image"])
        assert ref.digest is not None, f"{name}: {body['image']} has no digest"
    for image in own.values():
        for service in image.services:
            assert services[service]["image"].startswith(f"{image.name}:{VERSION}@sha256:")
