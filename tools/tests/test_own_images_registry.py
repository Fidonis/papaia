"""Own images through a real registry: build, push, sign, list and check at start.

A throwaway `registry` container on 127.0.0.1 stands in for the release registry, the
way a local test environment does (images under `<host>/unpublished/`, used through
PAPAIA_IMAGE_MIRROR). The images are built by `tools/build-images` from a commit of
this checkout's declared inputs, for linux/amd64 and linux/arm64; one is signed with a
throwaway key, the bill of materials is signed with the same key, and the start check
(`image-verify`) runs against the registry:

- the signed image passes;
- the same image unsigned is refused;
- the same name and tag with another digest is refused.

The build is reproducible, so the digest built here must be the one the shipped compose
file pins: a change to an input without a new pin fails here.

Needs Docker with a buildx builder that builds both platforms at once (the docker
driver with the containerd image store, or a docker-container builder) and network
access for the base images; skipped otherwise, unless PAPAIA_REQUIRE_OWN_IMAGE_BUILD=1.
PAPAIA_OWN_IMAGES_TEST_PROJECT names the containers (default papaia-own-images-test),
PAPAIA_OWN_IMAGES_TEST_PORT the registry port (default: a free port).
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
import yaml
from test_images import _bom, _new_keypair, _sign_bytes

from lib import cli, images, own_images, suite

REPO = Path(__file__).resolve().parents[2]
PROJECT = os.environ.get("PAPAIA_OWN_IMAGES_TEST_PROJECT", "papaia-own-images-test")
REGISTRY_IMAGE = (
    "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)
EGRESS = "ghcr.io/fidonis/papaia-egress"
LIFECYCLE = "ghcr.io/fidonis/papaia-lifecycle"
AUDIT = "ghcr.io/fidonis/papaia-audit"
PEOPLE = "ghcr.io/fidonis/papaia-people"
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(["docker", "buildx", "version"], capture_output=True,
                              timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def _multi_platform() -> bool:
    """Whether the current builder can build and push an index of two platforms: the
    docker driver only with the containerd image store, other drivers always."""
    inspect = subprocess.run(["docker", "buildx", "inspect"], capture_output=True, text=True,
                             timeout=30, check=False)
    if inspect.returncode != 0:
        return False
    driver = next((line.split(":", 1)[1].strip() for line in inspect.stdout.splitlines()
                   if line.startswith("Driver:")), "")
    if driver != "docker":
        return True
    info = subprocess.run(["docker", "info", "--format", "{{json .DriverStatus}}"],
                          capture_output=True, text=True, timeout=30, check=False)
    return "io.containerd.snapshotter" in info.stdout


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker buildx is not available")


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, env=env, timeout=900,
                          check=check)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def registry():
    port = int(os.environ.get("PAPAIA_OWN_IMAGES_TEST_PORT") or _free_port())
    name = f"{PROJECT}-registry"
    _run("docker", "rm", "-f", "-v", name, check=False)
    _run("docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:5000",
         "--read-only", "--tmpfs", "/var/lib/registry", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", REGISTRY_IMAGE)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v2/", timeout=2).close()
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("the test registry did not start")
        yield f"127.0.0.1:{port}/unpublished/"
    finally:
        _run("docker", "rm", "-f", "-v", name, check=False)


def _checkout(tmp_path: Path) -> Path:
    """A commit with exactly what the build reads: the declaration, the inputs, the
    license, VERSION, the signature setting and the compose files of the services."""
    root = tmp_path / "core"
    files = {own_images.DECLARATION_PATH.as_posix(), images.SIGNATURES_PATH.as_posix(),
             "VERSION", "LICENSE"}
    services = set()
    for image in own_images.load(REPO):
        files.update(image.inputs)
        services.update(image.services)
    for path in (REPO / "src").rglob("docker-compose*.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if services & set(doc.get("services") or {}):
            files.add(path.relative_to(REPO).as_posix())
    for rel in sorted(files):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
    for args in (("init", "-q", "-b", "main"), ("add", "-A"), ("commit", "-q", "-m", "core")):
        _run("git", "-C", str(root), *args, env=env)
    return root


def _cosign_key(tmp_path: Path, private: Path, password: str) -> Path:
    """The throwaway P-256 key in cosign's encrypted format (cosign import-key-pair)."""
    keys = tmp_path / "keys"
    keys.mkdir()
    pkcs8 = keys / "signing.pem"
    _run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(private), "-out", str(pkcs8))
    _run("docker", "run", "--rm", "--name", f"{PROJECT}-cosign-import", "--network", "none",
         "-e", "COSIGN_PASSWORD", "--user", f"{os.getuid()}:{os.getgid()}",
         "-v", f"{keys}:/keys", own_images.COSIGN_IMAGE, "import-key-pair",
         "--key", "/keys/signing.pem", "--output-key-prefix", "/keys/cosign",
         env={**os.environ, "COSIGN_PASSWORD": password})
    pkcs8.unlink()
    return keys / "cosign.key"


def _index(prefix: str, name: str, digest: str) -> dict:
    ref = images.parse_ref(f"{prefix}{name}@{digest}")
    request = urllib.request.Request(
        f"http://{ref.registry}/v2/{ref.repository}/manifests/{digest}",
        headers={"Accept": ", ".join(INDEX_TYPES)},
    )
    with urllib.request.urlopen(request, timeout=10) as answer:
        return json.loads(answer.read())


def _verify(root: Path, config: Path, refs: list[str]) -> int:
    listing = config / "images.txt"
    listing.write_text("\n".join(refs) + "\n", encoding="utf-8")
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     f"--images-file={listing}", "--command=start"])


@pytest.fixture
def builder():
    if not _multi_platform():
        if os.environ.get("PAPAIA_REQUIRE_OWN_IMAGE_BUILD") == "1":
            pytest.fail("the buildx builder cannot build linux/amd64 and linux/arm64 together")
        pytest.skip("the buildx builder cannot build linux/amd64 and linux/arm64 together "
                    "(docker driver without the containerd image store)")


def test_own_images_round_trip_through_a_registry(
    tmp_path: Path, builder, registry: str, capsys
):
    prefix = registry
    root = _checkout(tmp_path)
    builds = tmp_path / "builds.json"

    # Build every image for both platforms, twice: the same digest each time, and the
    # digest the shipped compose file pins.
    assert own_images.main(["--repo-root", str(root), "build", f"--registry={prefix}",
                            f"--out={builds}"]) == 0
    _, first = own_images.read_builds(builds)
    assert own_images.main(["--repo-root", str(root), "build", f"--registry={prefix}",
                            f"--out={builds}"]) == 0
    _, second = own_images.read_builds(builds)
    assert [b["digest"] for b in first] == [b["digest"] for b in second]
    built = {b["name"]: b for b in second}
    shipped = images.compose_services(REPO)
    for image in own_images.load(REPO):
        pinned = images.parse_ref(shipped[image.services[0]])
        assert built[image.name]["digest"] == pinned.digest, (
            f"{image.name}: the inputs build to {built[image.name]['digest']}, compose pins "
            f"{pinned.digest}; run tools/build-images build and pin"
        )
        index = _index(prefix, image.name, pinned.digest)
        assert index["mediaType"] in INDEX_TYPES
        platforms = {(m["platform"]["os"], m["platform"]["architecture"])
                     for m in index["manifests"]}
        assert platforms == {("linux", "amd64"), ("linux", "arm64")}

    # Sign the egress image only, with a throwaway key that also signs the bill of
    # materials; the signature goes to the release's signature repository behind the
    # mirror prefix.
    private, pem = _new_keypair(tmp_path)
    password = secrets.token_hex(16)
    key = _cosign_key(tmp_path, private, password)
    egress_only = tmp_path / "egress-build.json"
    own_images.write_builds(egress_only, prefix, [built[EGRESS]])
    env = {**os.environ, "COSIGN_PASSWORD": password}
    _, entries = own_images.read_builds(egress_only)
    own_images.sign(root, prefix, entries, key=key, env=env)

    # The bill of materials lists every own image with its digest.
    sboms = {}
    for name in built:
        sbom = tmp_path / f"{name.rsplit('/', 1)[1]}.cdx.json"
        sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "component": name}), "utf-8")
        sboms[name] = sbom
    listed = own_images.bom_entries(root, sboms)
    assert {(e["name"], e["digest"]) for e in listed} == {
        (name, build["digest"]) for name, build in built.items()
    }
    assert {EGRESS, LIFECYCLE, AUDIT, PEOPLE} <= set(built)
    version = images.core_version(root)
    doc = _bom(pem, listed, version=version)
    (root / suite.RELEASE_KEY_PATH).write_text(pem, encoding="ascii")
    bom_file = images.bom_path(root, version)
    bom_file.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    sig_dir = tmp_path / "sig"
    sig_dir.mkdir()
    Path(f"{bom_file}.sig").write_text(_sign_bytes(private, bom_file.read_bytes(), sig_dir),
                                       encoding="ascii")
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(f"{images.MIRROR_VAR}={prefix}\n", encoding="utf-8")
    pins = images.compose_services(root)
    egress_pin = pins["papaia-egress"]
    lifecycle_pin = pins["papaia-lifecycle"]

    capsys.readouterr()
    assert _verify(root, config, [egress_pin]) == 0
    assert "verified" in capsys.readouterr().out

    assert _verify(root, config, [lifecycle_pin]) == 2
    assert "no signature" in capsys.readouterr().err

    arm64 = next(m["digest"] for m in _index(prefix, EGRESS, built[EGRESS]["digest"])["manifests"]
                 if m["platform"]["architecture"] == "arm64")
    other = egress_pin.split("@", 1)[0] + "@" + arm64
    assert _verify(root, config, [other]) == 2
    assert "digest differs" in capsys.readouterr().err

    # The image runs as a non-root user and carries its notice files.
    served = f"{prefix}{egress_pin}"
    try:
        shown = _run("docker", "run", "--rm", "--name", f"{PROJECT}-probe", "--network", "none",
                     served, "sh", "-c",
                     "id -u; ls /usr/share/licenses/papaia-egress "
                     "/usr/share/licenses/papaia-egress/texts").stdout.split()
    finally:
        _run("docker", "image", "rm", served, check=False)
    assert shown[0] != "0"
    assert {"LICENSE", "THIRD_PARTY_LICENSES.md", "Python-2.0.txt"} <= set(shown)
