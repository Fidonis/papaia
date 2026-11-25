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
access for the base images; skipped otherwise, unless PAPAIA_REQUIRE_OWN_IMAGE_BUILD=1,
which turns every such skip into a failure. The docker probes, the commands and the wait
for the registry share one deadline (`hang_guard`, PAPAIA_TEST_HANG_GUARD_SECONDS); a
probe that runs out of it is reported with its measured duration.
PAPAIA_OWN_IMAGES_TEST_PROJECT names the containers (default papaia-own-images-test),
PAPAIA_OWN_IMAGES_TEST_PORT the registry port (default: a free port).
"""

from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

import hang_guard
import live_names
import pytest
import yaml
from test_images import _bom, _new_keypair, _sign_bytes
from test_own_images import ALPINE_FIXES, ALPINE_IMAGES, DEBIAN_FIXES, DEBIAN_IMAGES

from lib import cli, images, own_images, suite

REPO = Path(__file__).resolve().parents[2]
PROJECT = live_names.project("own-images-test", "PAPAIA_OWN_IMAGES_TEST_PROJECT")
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


def _required() -> bool:
    return os.environ.get("PAPAIA_REQUIRE_OWN_IMAGE_BUILD") == "1"


def _unavailable(reason: str) -> None:
    """Skip without the build, fail loudly when the build is required."""
    if _required():
        pytest.fail(f"{reason} (PAPAIA_REQUIRE_OWN_IMAGE_BUILD=1)", pytrace=False)
    pytest.skip(reason)


def _probe(*args: str) -> subprocess.CompletedProcess:
    """Run a docker probe under the hang guard. A probe that runs out of time is reported
    with its measured duration: a slow host is no reason to skip quietly."""
    limit = hang_guard.seconds()
    started = time.monotonic()
    proc = subprocess.Popen(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        _unavailable(f"'{' '.join(args)}' did not answer within {limit:g} s (measured "
                     f"{time.monotonic() - started:.1f} s); on a slow host raise "
                     f"{hang_guard.ENV}")
    return subprocess.CompletedProcess(list(args), proc.returncode, out, err)


def _docker_available() -> None:
    if shutil.which("docker") is None:
        _unavailable("Docker is not installed")
    if _probe("docker", "buildx", "version").returncode != 0:
        _unavailable("Docker buildx is not available")


def _multi_platform() -> bool:
    """Whether the current builder can build and push an index of two platforms: the
    docker driver only with the containerd image store, other drivers always."""
    inspect = _probe("docker", "buildx", "inspect")
    if inspect.returncode != 0:
        return False
    driver = next((line.split(":", 1)[1].strip() for line in inspect.stdout.splitlines()
                   if line.startswith("Driver:")), "")
    if driver != "docker":
        return True
    info = _probe("docker", "info", "--format", "{{json .DriverStatus}}")
    return "io.containerd.snapshotter" in info.stdout


@pytest.fixture(scope="module")
def docker_buildx() -> None:
    _docker_available()


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, env=env,
                          timeout=hang_guard.seconds(), check=check)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_registry(name: str, port: int) -> None:
    """Wait until the registry answers /v2/, under one overall deadline (the hang guard);
    a container that stopped fails at once, with its log."""
    limit = hang_guard.seconds()
    started = time.monotonic()
    while True:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/v2/", timeout=5).close()
            return
        except OSError:
            pass
        state = _run("docker", "inspect", "--format", "{{.State.Status}}", name, check=False)
        if state.returncode != 0 or state.stdout.strip() in ("exited", "dead"):
            logs = _run("docker", "logs", "--tail", "20", name, check=False)
            pytest.fail(f"the test registry stopped ({state.stdout.strip() or 'gone'}):\n"
                        f"{logs.stdout}{logs.stderr}")
        if time.monotonic() - started >= limit:
            pytest.fail(f"the test registry did not answer /v2/ within {limit:g} s; on a "
                        f"slow host raise {hang_guard.ENV}")
        time.sleep(0.5)


@pytest.fixture
def registry(docker_buildx):
    port = int(os.environ.get("PAPAIA_OWN_IMAGES_TEST_PORT") or _free_port())
    name = f"{PROJECT}-registry"
    _run("docker", "rm", "-f", "-v", name, check=False)
    try:
        _run("docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:5000",
             "--read-only", "--tmpfs", "/var/lib/registry", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges:true", REGISTRY_IMAGE)
        _wait_for_registry(name, port)
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


def _dpkg_status(ref: str, platform: str) -> dict[str, dict[str, str]]:
    """The dpkg status of one platform of `ref` by package name, read from the image's
    file system without running it, so the foreign platform needs no emulation."""
    name = f"{PROJECT}-dpkg-{platform.rsplit('/', 1)[1]}"
    _run("docker", "rm", "-f", name, check=False)
    try:
        _run("docker", "create", "--platform", platform, "--name", name, ref)
        copied = subprocess.run(["docker", "cp", f"{name}:/var/lib/dpkg/status", "-"],
                                capture_output=True, timeout=hang_guard.seconds(), check=True)
    finally:
        _run("docker", "rm", "-f", name, check=False)
    with tarfile.open(fileobj=io.BytesIO(copied.stdout)) as archive:
        member = archive.extractfile("status")
        assert member is not None
        text = member.read().decode("utf-8")
    packages: dict[str, dict[str, str]] = {}
    for stanza in text.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in stanza.splitlines()
                      if ": " in line and not line.startswith(" "))
        if "Package" in fields:
            packages[fields["Package"]] = fields
    return packages


def _at_least(ref: str, installed: str, fixed: str) -> bool:
    """dpkg's own version order, from the image on the host's platform."""
    done = _run("docker", "run", "--rm", "--name", f"{PROJECT}-dpkg-compare",
                "--network", "none", "--entrypoint", "dpkg", ref,
                "--compare-versions", installed, "ge", fixed, check=False)
    return done.returncode == 0


def _apk_installed(ref: str, platform: str) -> list[dict[str, str]]:
    """The apk database of one platform of `ref`, one entry per package record, read
    from the image's file system without running it, so the foreign platform needs no
    emulation."""
    name = f"{PROJECT}-apk-{platform.rsplit('/', 1)[1]}"
    _run("docker", "rm", "-f", name, check=False)
    try:
        _run("docker", "create", "--platform", platform, "--name", name, ref)
        copied = subprocess.run(["docker", "cp", f"{name}:/lib/apk/db/installed", "-"],
                                capture_output=True, timeout=hang_guard.seconds(), check=True)
    finally:
        _run("docker", "rm", "-f", name, check=False)
    with tarfile.open(fileobj=io.BytesIO(copied.stdout)) as archive:
        member = archive.extractfile("installed")
        assert member is not None
        text = member.read().decode("utf-8")
    records = []
    for stanza in text.split("\n\n"):
        fields = dict(line.split(":", 1) for line in stanza.splitlines()
                      if len(line) > 1 and line[1] == ":" and line[0] in "PVA")
        if "P" in fields:
            records.append(fields)
    return records


def _apk_at_least(ref: str, installed: str, fixed: str) -> bool:
    """apk's own version order (`apk version -t`), from the image on the host's platform."""
    done = _run("docker", "run", "--rm", "--name", f"{PROJECT}-apk-compare",
                "--network", "none", "--entrypoint", "apk", ref,
                "version", "-t", installed, fixed, check=False)
    return done.returncode == 0 and done.stdout.strip() in (">", "=")


@pytest.fixture
def builder(docker_buildx):
    if not _multi_platform():
        _unavailable("the buildx builder cannot build linux/amd64 and linux/arm64 together "
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

    # The Debian-based images carry the fixed zstd and zlib on both platforms.
    for name in sorted(DEBIAN_IMAGES):
        served = f"{prefix}{name}@{built[name]['digest']}"
        try:
            for arch in ("amd64", "arm64"):
                status = _dpkg_status(served, f"linux/{arch}")
                for package, fixed in DEBIAN_FIXES.items():
                    entry = status[package]
                    assert entry["Architecture"] == arch
                    assert entry["Status"] == "install ok installed"
                    assert _at_least(served, entry["Version"], fixed), (
                        f"{name} ({arch}): {package} {entry['Version']} is older than {fixed}"
                    )
                # The copy of the upgrade left no package half installed.
                assert all(e.get("Status") == "install ok installed" for e in status.values())
        finally:
            _run("docker", "image", "rm", served, check=False)

    # The Alpine-based images carry the fixed krb5 on both platforms.
    for name in sorted(ALPINE_IMAGES):
        served = f"{prefix}{name}@{built[name]['digest']}"
        try:
            for arch, apk_arch in (("amd64", "x86_64"), ("arm64", "aarch64")):
                records = _apk_installed(served, f"linux/{arch}")
                packages = [r["P"] for r in records]
                # The copy of the upgrade left every package listed exactly once.
                assert len(packages) == len(set(packages)), (
                    f"{name} ({arch}): packages listed twice in the apk database"
                )
                # Every package is of the platform's architecture (or of none).
                assert {r.get("A") for r in records} <= {apk_arch, "noarch"}
                installed = {r["P"]: r["V"] for r in records}
                for package, fixed in ALPINE_FIXES.items():
                    assert next(r["A"] for r in records if r["P"] == package) == apk_arch
                    assert _apk_at_least(served, installed[package], fixed), (
                        f"{name} ({arch}): {package} {installed[package]} is older than {fixed}"
                    )
        finally:
            _run("docker", "image", "rm", served, check=False)

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
    # The bill of materials is the one of the suite the core belongs to: for a release
    # candidate (VERSION 1.10.0-rc.1) the suite it is a candidate of.
    version = images.suite_version(images.core_version(root))
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


# ── the docker probes on a slow host ─────────────────────────────────────────


def _slow_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `docker` on PATH that answers nothing for a minute."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    fake.write_text("#!/bin/sh\nexec sleep 60\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_a_probe_out_of_time_fails_loudly_when_the_build_is_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _slow_docker(tmp_path, monkeypatch)
    monkeypatch.setenv(hang_guard.ENV, "0.5")
    monkeypatch.setenv("PAPAIA_REQUIRE_OWN_IMAGE_BUILD", "1")
    started = time.monotonic()
    with pytest.raises(pytest.fail.Exception) as failed:
        _docker_available()
    assert time.monotonic() - started < 30
    message = str(failed.value)
    assert "'docker buildx version' did not answer within 0.5 s" in message
    assert "measured " in message and hang_guard.ENV in message
    with pytest.raises(pytest.fail.Exception, match="'docker buildx inspect' did not answer"):
        _multi_platform()


def test_a_probe_out_of_time_skips_with_its_duration_when_the_build_is_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _slow_docker(tmp_path, monkeypatch)
    monkeypatch.setenv(hang_guard.ENV, "0.5")
    monkeypatch.delenv("PAPAIA_REQUIRE_OWN_IMAGE_BUILD", raising=False)
    with pytest.raises(pytest.skip.Exception, match=r"did not answer within 0\.5 s \(measured"):
        _docker_available()


def test_the_probes_wait_as_long_as_the_hang_guard(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(hang_guard.ENV, raising=False)
    assert hang_guard.seconds() == hang_guard.DEFAULT_SECONDS >= 300
    monkeypatch.setenv(hang_guard.ENV, "1200")
    assert hang_guard.seconds() == 1200
    for bad in ("0", "-5", "nan", "inf", "soon", str(hang_guard.MAX_SECONDS + 1)):
        monkeypatch.setenv(hang_guard.ENV, bad)
        with pytest.raises(ValueError, match=hang_guard.ENV):
            hang_guard.seconds()
