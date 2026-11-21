"""Image checks, second part: where trust comes from and which paths are covered.

- Key continuity: an upgrade verifies the target's bill of materials against the
  release key of the installed core, never against the key the target brings; a new
  key is accepted only through a rotation signed by the installed one.
- The signature repository ships with the release (compat/image-signatures.yaml);
  PAPAIA_IMAGE_SIGNATURES only overrides it for a mirror.
- Registry access: host credentials, a cache of verified signatures, rate limits and
  server errors reported as "not reachable", redirects that neither leak the token nor
  drop to plain HTTP.
- One correlation id for both phases of an upgrade.
- Add-on (module) images: `addon install`, `addon start` and `start --addons` check
  them before anything starts; an image outside the bill of materials needs an
  explicit confirmation, which is audited.

Helpers (fake registry, signed bills of materials) come from test_images.py.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest
import yaml
from test_images import (
    BASH,
    D1,
    D2,
    D3,
    ENTRIES,
    LIFECYCLE,
    POSTGRES,
    REPO,
    UPGRADE,
    FakeRegistry,
    _audit_rows,
    _bom,
    _config,
    _core,
    _doctor_ctx,
    _image,
    _images_file,
    _new_keypair,
    _refs,
    _sign_bytes,
    _signed_registry,
)

from lib import cli, doctor, images, status, suite

ADDON_SH = REPO / "tools" / "lib" / "sh" / "addon.sh"
WIKI = "ghcr.io/example/wiki"


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path)


def _other_keypair(tmp_path: Path, name: str = "other") -> tuple[Path, str]:
    return _new_keypair(tmp_path, name)


def _subdir(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir()
    return path


# ── key continuity across an upgrade (CORE-015-B1) ───────────────────────────


def test_target_with_its_own_release_key_is_refused(tmp_path, keypair):
    """The target ships another release key and a bill of materials signed by it:
    self-consistent, but not vouched for by the installed core."""
    installed = suite.key_fingerprint(keypair[1])
    other = _other_keypair(tmp_path)
    target = _core(_subdir(tmp_path, "target"), other)
    with pytest.raises(images.ImageError, match="release key"):
        images.load_trusted_bom(target, anchor=installed)


def test_target_with_the_installed_release_key_passes(tmp_path, keypair):
    target = _core(_subdir(tmp_path, "target"), keypair)
    doc = images.load_trusted_bom(target, anchor=suite.key_fingerprint(keypair[1]))
    assert doc["suite"] == "1.10.0"


def _rotation(path: Path, previous_pem: str, signature: str) -> None:
    (path / images.ROTATION_PATH).write_text(yaml.safe_dump({
        "schema": images.ROTATION_SCHEMA,
        "rotations": [{"previous_key": previous_pem, "signature": signature}],
    }, sort_keys=False), "utf-8")


def test_new_release_key_with_a_rotation_signed_by_the_installed_key_passes(tmp_path, keypair):
    old_private, old_pem = keypair
    new = _other_keypair(tmp_path, "new")
    target = _core(_subdir(tmp_path, "target"), new)
    statement = _sign_bytes(old_private, new[1].encode("ascii"), tmp_path)
    _rotation(target, old_pem, statement)
    doc = images.load_trusted_bom(target, anchor=suite.key_fingerprint(old_pem))
    assert doc["signing_key"]["fingerprint"] == suite.key_fingerprint(new[1])


def test_rotation_signed_by_another_key_is_refused(tmp_path, keypair):
    _, old_pem = keypair
    new = _other_keypair(tmp_path, "new")
    target = _core(_subdir(tmp_path, "target"), new)
    # Claims the installed key as predecessor, but the new key signed it itself.
    _rotation(target, old_pem, _sign_bytes(new[0], new[1].encode("ascii"), tmp_path))
    with pytest.raises(images.ImageError, match="rotation"):
        images.load_trusted_bom(target, anchor=suite.key_fingerprint(old_pem))


def test_rotation_from_another_previous_key_is_refused(tmp_path, keypair):
    """A rotation chain that does not start at the installed key proves nothing."""
    middle = _other_keypair(tmp_path, "middle")
    new = _other_keypair(tmp_path, "new")
    target = _core(_subdir(tmp_path, "target"), new)
    _rotation(target, middle[1], _sign_bytes(middle[0], new[1].encode("ascii"), tmp_path))
    with pytest.raises(images.ImageError, match="rotation"):
        images.load_trusted_bom(target, anchor=suite.key_fingerprint(keypair[1]))


def test_rotation_file_rejects_unknown_fields(tmp_path, keypair):
    old_private, old_pem = keypair
    new = _other_keypair(tmp_path, "new")
    target = _core(_subdir(tmp_path, "target"), new)
    (target / images.ROTATION_PATH).write_text(yaml.safe_dump({
        "schema": images.ROTATION_SCHEMA,
        "rotations": [{"previous_key": old_pem, "extra": 1,
                       "signature": _sign_bytes(old_private, new[1].encode(), tmp_path)}],
    }), "utf-8")
    with pytest.raises(images.ImageError, match="rotation"):
        images.load_trusted_bom(target, anchor=suite.key_fingerprint(old_pem))


def test_target_without_release_key_is_refused_under_an_anchor(tmp_path, keypair):
    target = _core(_subdir(tmp_path, "target"), keypair, with_key=False)
    with pytest.raises(images.ImageError, match="trust anchor|release key"):
        images.load_trusted_bom(target, anchor=suite.key_fingerprint(keypair[1]))


def test_image_verify_checks_the_target_against_the_installed_anchor(
    tmp_path, keypair, monkeypatch, capsys
):
    installed = suite.key_fingerprint(keypair[1])
    other = _other_keypair(tmp_path)
    target = _core(_subdir(tmp_path, "target"), other)
    config = _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: _signed_registry(other, tmp_path))
    argv = ["--repo-root", str(target), "--config-dir", str(config), "image-verify",
            f"--images-file={_images_file(tmp_path, _refs())}", "--command=upgrade"]
    assert cli.main([*argv, f"--anchor-fingerprint={installed}"]) == 2
    assert "release key" in capsys.readouterr().err
    # Without an anchor the target would vouch for itself; that is what the anchor stops.
    assert cli.main([*argv, "--anchor-fingerprint=sha256:xyz"]) == 2


def test_image_trust_anchor_prints_the_installed_fingerprint(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "image-trust-anchor"]) == 0
    assert capsys.readouterr().out.strip() == suite.key_fingerprint(keypair[1])


def test_image_trust_anchor_refuses_without_a_release_key(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair, with_key=False), _config(tmp_path)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "image-trust-anchor"]) == 2
    assert "trust anchor" in capsys.readouterr().err


# ── upgrade: both phases ─────────────────────────────────────────────────────

_ANCHOR = "sha256:" + "a" * 64
_CORRELATION = "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"
_COMMIT = "c" * 40

_UPGRADE = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@TMP@/config"
REPO_ROOT="@TMP@/repo"
COMPOSE_FILE="@TMP@/repo/src/docker-compose.yml"
BASH="@TMP@/next-phase"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
is_tty() { return 1; }
source "@LIFECYCLE@"
source "@UPGRADE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
cmd_backup() { echo "backup"; LAST_BACKUP_ID=rp1; }
cmd_stop() { echo "stop $*"; }
cmd_setup() { echo "setup $*"; }
cmd_start() { echo "cmd_start $* corr=${IMAGES_CORRELATION_ID:-} anchor=${IMAGES_ANCHOR:-}"; }
_upgrade_log() { :; }
git() {
    echo "git $*" >> "@TMP@/git.log"
    case "$*" in
        *"worktree add"*) mkdir -p "${@: -2:1}" ;;
        *"status --porcelain"*) ;;
        *"rev-parse"*"^{commit}"*) echo "@COMMIT@" ;;
    esac
    return 0
}
py_cli() {
    case "$1" in
        image-trust-anchor) [ -n "@ANCHOR@" ] || return 2; echo "@ANCHOR@"; return ;;
        new-correlation-id) echo "@CORRELATION@"; return ;;
        active-addons) return ;;
    esac
    echo "py_cli $*"
    case "$1" in
        upgrade-resolve)
            printf 'CURRENT\\t1.9.0\\nTARGET\\t1.10.0\\nTAG\\tv1.10.0\\nSTATUS\\tupgrade\\n' ;;
    esac
}
_py_cli_at() {
    echo "py_cli_at $*"
    case "$2" in image-verify) return @VERIFY@ ;; esac
    return 0
}
cmd_upgrade -y @FLAGS@
"""


def _upgrade(tmp_path: Path, *, verify: int = 0, flags: str = "", anchor: str = _ANCHOR):
    if BASH is None:
        pytest.skip("bash is not available")
    nxt = tmp_path / "next-phase"
    nxt.write_text('#!/bin/sh\necho "phase2 $*"\n', encoding="utf-8")
    nxt.chmod(0o755)
    (tmp_path / "config").mkdir(exist_ok=True)
    script = (
        _UPGRADE.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@VERIFY@", str(verify))
        .replace("@FLAGS@", flags)
        .replace("@ANCHOR@", anchor)
        .replace("@CORRELATION@", _CORRELATION)
        .replace("@COMMIT@", _COMMIT)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_upgrade_checks_the_target_against_the_installed_anchor(tmp_path):
    done = _upgrade(tmp_path)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(c for c in calls if "image-verify" in c)
    assert f"--anchor-fingerprint={_ANCHOR}" in verify
    # The second phase checks against the same anchor, not the key it now runs from.
    assert f"--resume-anchor={_ANCHOR}" in calls[-1]


def test_upgrade_without_an_installed_anchor_is_refused_before_anything_changes(tmp_path):
    done = _upgrade(tmp_path, anchor="")
    assert done.returncode == 2
    calls = done.stdout.splitlines()
    assert not any("image-verify" in c for c in calls)
    assert "backup" not in calls and not any(c.startswith("phase2") for c in calls)
    assert "release key" in done.stderr


def test_upgrade_without_an_installed_anchor_needs_insecure_images(tmp_path):
    done = _upgrade(tmp_path, anchor="", flags="--insecure-images")
    assert done.returncode == 0, done.stderr
    verify = next(c for c in done.stdout.splitlines() if "image-verify" in c)
    assert "--insecure-images" in verify and "--anchor-fingerprint" not in verify


def test_upgrade_moves_the_checkout_to_the_commit_it_verified(tmp_path):
    """The worktree that was checked and the checkout that is started are the same
    commit; a tag moved in between does not change what runs."""
    done = _upgrade(tmp_path)
    assert done.returncode == 0, done.stderr
    log = (tmp_path / "git.log").read_text("utf-8").splitlines()
    added = next(line for line in log if "worktree add" in line)
    moved = next(line for line in log if "checkout --detach" in line)
    assert added.endswith(_COMMIT) and moved.endswith(_COMMIT)


def test_upgrade_phases_share_one_correlation_id(tmp_path):
    done = _upgrade(tmp_path, flags="--insecure-images")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(c for c in calls if "image-verify" in c)
    assert f"--correlation-id={_CORRELATION}" in verify
    assert f"--resume-correlation-id={_CORRELATION}" in calls[-1]


def _phase2(tmp_path: Path, flags: str):
    script = _UPGRADE.replace(
        "cmd_upgrade -y @FLAGS@",
        "cmd_upgrade --resume-from=1.9.0 --resume-target=1.10.0 @FLAGS@",
    )
    if BASH is None:
        pytest.skip("bash is not available")
    (tmp_path / "config").mkdir(exist_ok=True)
    script = (
        script.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@VERIFY@", "0")
        .replace("@FLAGS@", flags)
        .replace("@ANCHOR@", _ANCHOR)
        .replace("@CORRELATION@", _CORRELATION)
        .replace("@COMMIT@", _COMMIT)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_upgrade_second_phase_passes_the_flag_to_start_only(tmp_path):
    done = _phase2(tmp_path, f"--insecure-images --resume-anchor={_ANCHOR} "
                             f"--resume-correlation-id={_CORRELATION}")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    starts = [c for c in calls if c.startswith("cmd_start ")]
    assert len(starts) == 1
    assert "--insecure-images" in starts[0]
    assert f"corr={_CORRELATION}" in starts[0] and f"anchor={_ANCHOR}" in starts[0]
    others = [c for c in calls if "--insecure-images" in c and not c.startswith("cmd_start ")]
    assert others == []


def test_upgrade_second_phase_without_the_flag_starts_without_it(tmp_path):
    done = _phase2(tmp_path, f"--resume-anchor={_ANCHOR}")
    assert done.returncode == 0, done.stderr
    start = next(c for c in done.stdout.splitlines() if c.startswith("cmd_start "))
    assert "--insecure-images" not in start and f"anchor={_ANCHOR}" in start


# ── audit correlation ────────────────────────────────────────────────────────


def test_insecure_images_uses_the_given_correlation_id(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    refs = _images_file(tmp_path, _refs())
    argv = ["--repo-root", str(root), "--config-dir", str(config), "image-verify",
            f"--images-file={refs}", "--insecure-images"]
    assert cli.main([*argv, "--command=upgrade", f"--correlation-id={_CORRELATION}"]) == 0
    assert cli.main([*argv, "--command=start", f"--correlation-id={_CORRELATION}"]) == 0
    rows = _audit_rows(config)
    assert [r["correlation_id"] for r in rows] == [_CORRELATION, _CORRELATION]
    assert [r["operation"] for r in rows] == ["upgrade", "start"]


def test_correlation_id_is_validated(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    refs = _images_file(tmp_path, _refs())
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     f"--images-file={refs}", "--command=start", "--insecure-images",
                     "--correlation-id=not-a-uuid\n"]) == 2
    assert _audit_rows(config) == []


def test_new_correlation_id_prints_a_uuid(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "new-correlation-id"]) == 0
    uuid.UUID(capsys.readouterr().out.strip())


# ── signature repository ships with the release ──────────────────────────────


def _signatures_file(root: Path, repository: str) -> None:
    (root / images.SIGNATURES_PATH).write_text(yaml.safe_dump({
        "schema": images.SIGNATURES_SCHEMA, "repository": repository,
    }), "utf-8")


def _registry_with_signatures_in(keypair, tmp_path: Path, repository: str) -> FakeRegistry:
    registry = FakeRegistry()
    ref = images.parse_ref(repository)
    for digest in (D1, D2):
        registry.add_signature(ref.registry, ref.repository, digest, keypair[0], tmp_path)
    return registry


def test_the_repo_ships_its_signature_repository():
    repository = images.release_signature_repository(REPO)
    assert repository, "compat/image-signatures.yaml must name the signature repository"
    images.parse_ref(repository)


def test_release_signature_repository_is_used_by_default(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    _signatures_file(root, "ghcr.io/example/signatures")
    registry = _registry_with_signatures_in(keypair, tmp_path, "ghcr.io/example/signatures")
    monkeypatch.setattr(images, "Registry", lambda **_: registry)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     f"--images-file={_images_file(tmp_path, _refs())}",
                     "--command=start"]) == 0
    assert {(h, r) for h, r, _ in registry.requests} == {("ghcr.io", "example/signatures")}


def test_operator_signature_repository_overrides_the_release_one(tmp_path, keypair, monkeypatch):
    root = _core(tmp_path, keypair)
    _signatures_file(root, "ghcr.io/example/signatures")
    config = _config(tmp_path, "PAPAIA_IMAGE_SIGNATURES=registry.example.com/sigs\n")
    registry = _registry_with_signatures_in(keypair, tmp_path, "registry.example.com/sigs")
    monkeypatch.setattr(images, "Registry", lambda **_: registry)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     f"--images-file={_images_file(tmp_path, _refs())}",
                     "--command=start"]) == 0


def test_release_signature_repository_is_served_by_the_mirror(tmp_path, keypair):
    root = _core(tmp_path, keypair)
    _signatures_file(root, "ghcr.io/example/signatures")
    mirror = "127.0.0.1:58601/mirror/"
    _, signatures = images.settings({images.MIRROR_VAR: mirror}, root)
    assert signatures == mirror + "ghcr.io/example/signatures"


@pytest.mark.parametrize("doc", [
    {"schema": "papaia.image-signatures/1"},
    {"schema": "papaia.image-signatures/1", "repository": "ghcr.io/x/y:1.0"},
    {"schema": "papaia.image-signatures/1", "repository": "ghcr.io/x/y", "extra": 1},
    {"schema": "other", "repository": "ghcr.io/x/y"},
])
def test_signature_repository_file_is_validated(tmp_path, doc):
    (tmp_path / "compat").mkdir()
    (tmp_path / images.SIGNATURES_PATH).write_text(yaml.safe_dump(doc), "utf-8")
    with pytest.raises(images.ImageError):
        images.release_signature_repository(tmp_path)


# ── registry: credentials, rate limits, cache, redirects ─────────────────────


def test_rate_limit_is_reported_as_not_reachable(tmp_path, keypair):
    class Limited(FakeRegistry):
        def manifest(self, host, repository, reference):
            raise images.Unreachable(f"{host}: HTTP 429 (rate limited)")

    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=Limited())
    assert len(problems) == 2
    assert all(p.transient and "not reachable" in p.reason for p in problems)


@pytest.mark.parametrize("code", [429, 500, 502, 503])
def test_registry_maps_rate_limits_and_server_errors_to_unreachable(monkeypatch, code):
    registry = images.Registry()

    def fail(url, headers, limit):
        raise urllib.error.HTTPError(url, code, "x", {}, None)

    monkeypatch.setattr(registry, "_fetch", fail)
    with pytest.raises(images.Unreachable):
        registry.manifest("docker.io", "library/postgres", "sha256-x.sig")


def test_doctor_warns_when_the_registry_rate_limits(tmp_path, keypair, monkeypatch):
    class Limited(FakeRegistry):
        def manifest(self, host, repository, reference):
            raise images.Unreachable(f"{host}: HTTP 429 (rate limited)")

    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: Limited())
    ctx = _doctor_ctx(tmp_path, root, config, {"papaia-db-1": _refs()[1]})
    assert doctor.check_image_signatures(ctx).status == doctor.WARN


def test_credentials_come_from_the_docker_config(tmp_path, monkeypatch):
    docker = tmp_path / "docker"
    docker.mkdir()
    auth = base64.b64encode(b"reader:s3cret").decode()
    (docker / "config.json").write_text(json.dumps({
        "auths": {"https://index.docker.io/v1/": {"auth": auth},
                  "ghcr.io": {"auth": base64.b64encode(b"gh:tok").decode()}},
    }), "utf-8")
    monkeypatch.setenv("DOCKER_CONFIG", str(docker))
    creds = images.DockerCredentials()
    assert creds.lookup("docker.io") == ("reader", "s3cret")
    assert creds.lookup("ghcr.io") == ("gh", "tok")
    assert creds.lookup("quay.io") is None


def test_credentials_come_from_a_credential_helper(tmp_path, monkeypatch):
    docker, bin_dir = tmp_path / "docker", tmp_path / "bin"
    docker.mkdir()
    bin_dir.mkdir()
    (docker / "config.json").write_text(json.dumps({"credHelpers": {"ghcr.io": "fake"}}),
                                        "utf-8")
    helper = bin_dir / "docker-credential-fake"
    helper.write_text('#!/bin/sh\nread host\n'
                      'printf \'{"ServerURL":"%s","Username":"u","Secret":"p"}\' "$host"\n',
                      "utf-8")
    helper.chmod(0o755)
    monkeypatch.setenv("DOCKER_CONFIG", str(docker))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    assert images.DockerCredentials().lookup("ghcr.io") == ("u", "p")


def test_token_request_carries_the_host_credentials(monkeypatch):
    class Creds:
        def lookup(self, host):
            return ("reader", "s3cret") if host == "docker.io" else None

    registry = images.Registry(credentials=Creds())
    seen: list[dict] = []

    def fetch(url, headers, limit):
        seen.append({"url": url, **headers})
        return b'{"token": "t"}'

    monkeypatch.setattr(registry, "_fetch", fetch)
    challenge = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
    assert registry._token(challenge, "docker.io", "library/postgres") == "t"
    expected = "Basic " + base64.b64encode(b"reader:s3cret").decode()
    assert seen[0]["Authorization"] == expected


def test_verified_signatures_are_cached_per_key(tmp_path, keypair):
    cache = images.SignatureCache(tmp_path / "config" / images.CACHE_PATH)
    registry = _signed_registry(keypair, tmp_path)
    bom = _bom(keypair[1], ENTRIES)
    assert images.verify_images(_refs(), bom, registry=registry, cache=cache) == []
    cache.save()
    assert oct(cache.path.stat().st_mode & 0o777) == "0o600"

    registry.requests.clear()
    again = images.SignatureCache(cache.path)
    assert images.verify_images(_refs(), bom, registry=registry, cache=again) == []
    assert registry.requests == []

    # Another key does not inherit what this one verified.
    other = _other_keypair(tmp_path)
    assert images.verify_images(_refs(), _bom(other[1], ENTRIES), registry=registry,
                                cache=again) != []


def test_cache_never_skips_the_bill_of_materials(tmp_path, keypair):
    cache = images.SignatureCache(tmp_path / "cache.json")
    registry = _signed_registry(keypair, tmp_path)
    assert images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=registry,
                                cache=cache) == []
    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES[:1]),
                                    registry=registry, cache=cache)
    assert [p.ref for p in problems] == [_refs()[1]]


def test_damaged_cache_is_ignored(tmp_path, keypair):
    path = tmp_path / "cache.json"
    path.write_text("{not json", "utf-8")
    cache = images.SignatureCache(path)
    registry = _signed_registry(keypair, tmp_path)
    assert images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=registry,
                                cache=cache) == []
    assert registry.requests != []


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []
    target = ""

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append({"path": self.path, "auth": self.headers.get("Authorization")})
        if self.path.startswith("/v2/"):
            self.send_response(307)
            self.send_header("Location", type(self).target)
            self.end_headers()
            return
        body = b"payload"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve() -> http.server.HTTPServer:
    """A recorder on a port the system picks, so parallel runs never collide."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_redirect_to_another_host_drops_the_token():
    """A registry hands a blob off to storage on another host: the bearer token
    stays with the registry."""
    _Recorder.seen = []
    servers = [_serve(), _serve()]
    registry_host = f"127.0.0.1:{servers[0].server_address[1]}"
    # Another host: another port, and 'localhost' instead of '127.0.0.1'.
    _Recorder.target = f"http://localhost:{servers[1].server_address[1]}/storage/blob"
    try:
        registry = images.Registry()
        registry._tokens[(registry_host, "test/x")] = "registry-token"
        data = registry.blob(registry_host, "test/x", D1, 1024)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    assert data == b"payload"
    assert _Recorder.seen[0]["auth"] == "Bearer registry-token"
    assert _Recorder.seen[1]["path"] == "/storage/blob" and _Recorder.seen[1]["auth"] is None


def test_redirect_on_the_same_host_keeps_the_token():
    handler = images._SafeRedirect()
    request = urllib.request.Request("https://ghcr.io/v2/x/blobs/sha256:1",
                                     headers={"Authorization": "Bearer t"})
    new = handler.redirect_request(request, None, 307, "x", {}, "https://ghcr.io/other")
    assert new.get_header("Authorization") == "Bearer t"


def test_redirect_to_another_host_strips_the_token():
    handler = images._SafeRedirect()
    request = urllib.request.Request("https://ghcr.io/v2/x/blobs/sha256:1",
                                     headers={"Authorization": "Bearer t"})
    new = handler.redirect_request(request, None, 307, "x", {},
                                   "https://pkg-containers.example.net/blob")
    assert new.get_header("Authorization") is None


def test_redirect_from_https_to_plain_http_is_refused():
    handler = images._SafeRedirect()
    request = urllib.request.Request("https://ghcr.io/v2/x/blobs/sha256:1")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(request, None, 302, "x", {}, "http://cdn.example.net/blob")


# ── doctor: what actually runs ───────────────────────────────────────────────


def _ctx_with(tmp_path, root, config, *, ps, inspect, image_inspect):
    def run(cmd, timeout=0):
        if cmd[:2] == ["docker", "ps"]:
            return ps
        if cmd[:3] == ["docker", "image", "inspect"]:
            return image_inspect(cmd)
        if cmd[:2] == ["docker", "inspect"]:
            return inspect(cmd)
        return status.CommandResult(127, "", "unexpected")

    return doctor.Context(config, root, run=run, probes=doctor.Probes(),
                          now=doctor.datetime.now(doctor.timezone.utc))


def test_doctor_warns_when_inspect_fails(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    ctx = _ctx_with(
        tmp_path, root, config,
        ps=status.CommandResult(0, "papaia-db-1\n"),
        inspect=lambda cmd: status.CommandResult(1, "", "No such object"),
        image_inspect=lambda cmd: status.CommandResult(0, ""),
    )
    result = doctor.check_image_signatures(ctx)
    assert result.status == doctor.WARN and "unknown" in result.summary


def test_doctor_warns_when_a_listed_container_is_not_inspected(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    ctx = _ctx_with(
        tmp_path, root, config,
        ps=status.CommandResult(0, "papaia-db-1\npapaia-keycloak-1\n"),
        inspect=lambda cmd: status.CommandResult(0, f"/papaia-db-1\t{_refs()[1]}\tsha256:i2\n"),
        image_inspect=lambda cmd: status.CommandResult(0, f'sha256:i2\t["{POSTGRES}@{D2}"]\n'),
    )
    assert doctor.check_image_signatures(ctx).status == doctor.WARN


def test_doctor_fails_when_the_running_image_is_not_the_pinned_digest(
    tmp_path, keypair, monkeypatch
):
    """The container was created from a pinned reference, but the image it runs has
    another digest (a retagged local image)."""
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: _signed_registry(keypair, tmp_path))
    ctx = _ctx_with(
        tmp_path, root, config,
        ps=status.CommandResult(0, "papaia-db-1\n"),
        inspect=lambda cmd: status.CommandResult(0, f"/papaia-db-1\t{_refs()[1]}\tsha256:i2\n"),
        image_inspect=lambda cmd: status.CommandResult(0, f'sha256:i2\t["{POSTGRES}@{D3}"]\n'),
    )
    result = doctor.check_image_signatures(ctx)
    assert result.status == doctor.FAIL and "digest" in result.summary


# ── start: the checked set is the started set ───────────────────────────────

_START = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@TMP@/config"
REPO_ROOT="@TMP@/repo"
COMPOSE_FILE="@TMP@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
source "@LIFECYCLE@"
source "@ADDON@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
_pull_quietly() { return 1; }
_addon_path() { echo "@TMP@/addons/$1"; }
docker() {
    case " $* " in
        *" config --images "*)
            echo "docker $*" >> "@TMP@/docker.log"
            # An add-on compose file picks its image through a variable of its .env.
            local a prev="" env=""
            for a in "$@"; do [ "$prev" = --env-file ] && env="$a"; prev="$a"; done
            case "$env" in
                */addons/*) if grep -q '^WIKI_IMAGE=' "$env"; then
                    sed -n 's/^WIKI_IMAGE=//p' "$env"; return 0; fi ;;
            esac
            echo "@REF@" ;;
        *" network inspect net-a "*) return 0 ;;
        *" network inspect "*) return 1 ;;
        *) echo "docker $*" ;;
    esac
}
py_cli() {
    case "$1" in
        active-addons) echo wiki; return ;;
        addon-networks) echo "@ADDON_NET@"; return ;;
        override-external-nets)
            case "$2" in
                *a.override.yml) echo net-a ;;
                *b.override.yml) echo net-b ;;
            esac
            return ;;
    esac
    echo "py_cli $*"
    case "$1" in
        image-verify)
            local a
            for a in "$@"; do
                case "$a" in
                    --images-file=*) sed 's/^/listed /' "${a#--images-file=}" ;;
                    --addon-images=*) sed 's/^/addon-listed /' "${a#*=*=}" ;;
                esac
            done
            return @VERIFY@ ;;
        addon-start)
            # As lib.addons.materialize_addon_env: the bundle .env over the checkout's.
            local name="${2#--name=}"
            if [ -f "@TMP@/config/addons/$name/.env" ]; then
                cp "@TMP@/config/addons/$name/.env" "@TMP@/addons/$name/.env"
            fi ;;
    esac
}
@CALL@
"""


def _shell(tmp_path: Path, call: str, *, verify: int = 0, addon_net: str = ""):
    if BASH is None:
        pytest.skip("bash is not available")
    overrides = tmp_path / "config" / "overrides"
    overrides.mkdir(parents=True, exist_ok=True)
    for name in ("a", "b"):
        (overrides / f"docker-compose.{name}.override.yml").write_text("services: {}\n")
    addon = tmp_path / "addons" / "wiki"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n")
    script = (
        _START.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@REF@", f"{WIKI}:1.0.0@{D3}")
        .replace("@VERIFY@", str(verify))
        .replace("@ADDON_NET@", addon_net)
        .replace("@CALL@", call)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def _core_calls(tmp_path: Path) -> list[str]:
    return [c for c in (tmp_path / "docker.log").read_text("utf-8").splitlines()
            if "/repo/src/docker-compose.yml" in c]


def test_start_checks_with_exactly_the_overrides_it_starts_with(tmp_path):
    done = _shell(tmp_path, "cmd_start")
    assert done.returncode == 0, done.stderr
    checked = _core_calls(tmp_path)[0]
    up = next(c for c in done.stdout.splitlines() if c.startswith("docker compose")
              and " up " in c)
    for line in (checked, up):
        assert "a.override.yml" in line and "b.override.yml" not in line


def test_start_counts_the_network_an_addon_brings_up_in_the_same_command(tmp_path):
    done = _shell(tmp_path, "cmd_start --addons", addon_net="net-b")
    assert done.returncode == 0, done.stderr
    checked = _core_calls(tmp_path)[0]
    up = next(c for c in done.stdout.splitlines() if c.startswith("docker compose")
              and " up " in c and "-p wiki" not in c)
    for line in (checked, up):
        assert "a.override.yml" in line and "b.override.yml" in line


# ── add-on (module) images: PLT-36-A6, A7, A8 ────────────────────────────────


def test_start_checks_addon_images_with_the_core_before_anything_starts(tmp_path):
    done = _shell(tmp_path, "cmd_start --addons")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verifies = [i for i, c in enumerate(calls) if c.startswith("py_cli image-verify")]
    assert len(verifies) == 1, "core and add-on images are checked in one call"
    log = (tmp_path / "docker.log").read_text("utf-8")
    assert "-p wiki" in log and "/addons/wiki/docker-compose.yml" in log
    # The add-on env is materialised first, so the check sees what `up` will use.
    materialised = next(i for i, c in enumerate(calls) if c.startswith("py_cli addon-start"))
    first_up = next(i for i, c in enumerate(calls) if " up " in c)
    assert materialised < verifies[0] < first_up


def test_start_with_a_refused_addon_image_starts_nothing(tmp_path):
    done = _shell(tmp_path, "cmd_start --addons", verify=2)
    assert done.returncode == 2
    calls = done.stdout.splitlines()
    assert not any(" up " in c for c in calls)


def test_addon_start_checks_its_images_before_up(tmp_path):
    done = _shell(tmp_path, "cmd_addon_start wiki")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    assert "--command=addon-start" in calls[verify]
    up = next(i for i, c in enumerate(calls) if " up " in c)
    assert verify < up


def test_addon_start_refused_starts_no_container(tmp_path):
    done = _shell(tmp_path, "cmd_addon_start wiki", verify=2)
    assert done.returncode == 2
    assert not any(" up " in c for c in done.stdout.splitlines())


def test_addon_start_passes_insecure_images_to_the_check_only(tmp_path):
    done = _shell(tmp_path, "cmd_addon_start wiki --insecure-images")
    assert done.returncode == 0, done.stderr
    flagged = [c for c in done.stdout.splitlines() if "--insecure-images" in c]
    assert len(flagged) == 1 and flagged[0].startswith("py_cli image-verify")


def test_addon_install_checks_images_before_registering(tmp_path):
    path = (tmp_path / "addons" / "wiki").as_posix()
    done = _shell(tmp_path, f"cmd_addon_install wiki --path={path}")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    assert "--command=addon-install" in calls[verify] and "--addon=wiki" in calls[verify]
    assert verify < next(i for i, c in enumerate(calls) if c.startswith("py_cli addon-install"))


def test_addon_install_refused_registers_nothing(tmp_path):
    path = (tmp_path / "addons" / "wiki").as_posix()
    done = _shell(tmp_path, f"cmd_addon_install wiki --path={path}", verify=2)
    assert done.returncode == 2
    assert not any(c.startswith("py_cli addon-install") for c in done.stdout.splitlines())


def test_addon_install_forwards_the_confirmation_to_the_check_only(tmp_path):
    path = (tmp_path / "addons" / "wiki").as_posix()
    done = _shell(tmp_path, f"cmd_addon_install wiki --path={path} --accept-unlisted-images")
    assert done.returncode == 0, done.stderr
    flagged = [c for c in done.stdout.splitlines() if "--accept-unlisted-images" in c]
    assert len(flagged) == 1 and flagged[0].startswith("py_cli image-verify")


def _addon_dir(tmp_path: Path) -> Path:
    addon = tmp_path / "probe"
    addon.mkdir()
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump({
        "name": "probe",
        "version": "1.0.0",
        "addon_repo": "papaia-addon-probe",
        "networks": {"app_network": "papaia-probe-net", "attach": ["litellm"]},
        "exposes": [{
            "id": "probe", "kind": "mcp",
            "operations": [{"name": "list_items", "effect": "read"},
                           {"name": "delete_item", "effect": "delete"}],
        }],
    }), "utf-8")
    return addon


def _addon_bom(pem: str, entries: list[dict]) -> dict:
    bom = _bom(pem, ENTRIES)
    for repo in bom["repos"]:
        if repo["role"] == "addon":
            repo["images"] = entries
            repo["containers"] = len(entries)
    every = [i for r in bom["repos"] for i in r["images"]]
    bom["totals"] = {"containers": sum(r["containers"] for r in bom["repos"]),
                     "images": len({i["digest"] for i in every})}
    return bom


def _addon_verify(root, config, refs_file, addon, *extra):
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     f"--addon-images=probe={refs_file}", "--command=addon-install",
                     "--addon=probe", f"--addon-path={addon}", *extra])


def test_addon_image_with_another_digest_is_refused(tmp_path, keypair, monkeypatch, capsys):
    """PLT-36-A6: same tag, other content."""
    root = _core(tmp_path, keypair, bom=_addon_bom(keypair[1], [_image(WIKI, "1.0.0", D1)]))
    config, addon = _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: _signed_registry(keypair, tmp_path))
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _addon_verify(root, config, refs, addon) == 2
    assert "digest differs" in capsys.readouterr().err


def test_addon_image_without_signature_is_refused(tmp_path, keypair, monkeypatch, capsys):
    """PLT-36-A7: the digest matches the bill of materials, the signature is missing."""
    root = _core(tmp_path, keypair, bom=_addon_bom(keypair[1], [_image(WIKI, "1.0.0", D3)]))
    config, addon = _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _addon_verify(root, config, refs, addon) == 2
    assert "no signature" in capsys.readouterr().err


def test_unlisted_addon_is_refused_with_what_it_would_bring(tmp_path, keypair, monkeypatch,
                                                            capsys):
    """PLT-36-A8: outside the bill of materials, no confirmation: refused, and the
    operator sees origin, digest, declared operations with effect and networks."""
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _addon_verify(root, config, refs, addon) == 2
    err = capsys.readouterr().err
    for text in ("ghcr.io/example/wiki", D3, "papaia-addon-probe", "list_items (read)",
                 "delete_item (delete)", "papaia-probe-net", "litellm",
                 "--accept-unlisted-images"):
        assert text in err, text
    assert _audit_rows(config) == []
    assert not (config / images.ACCEPTED_PATH).exists()


def test_confirmed_unlisted_addon_is_installed_with_an_audit_row(tmp_path, keypair,
                                                                 monkeypatch):
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    pending = tmp_path / "pending.txt"
    assert _addon_verify(root, config, refs, addon, "--accept-unlisted-images",
                         f"--pending-file={pending}") == 0
    # Recorded once the add-on is registered (addon.sh runs image-accept after it).
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-accept",
                     "--addon=probe", f"--pending-file={pending}"]) == 0
    rows = _audit_rows(config)
    assert len(rows) == 1
    assert rows[0]["event"] == "addon_images_accepted"
    assert rows[0]["operation"] == "addon-install"
    assert rows[0]["detail"]["addon"] == "probe"
    assert rows[0]["detail"]["images"] == [f"{WIKI}:1.0.0@{D3}"]
    assert oct((config / images.ACCEPTED_PATH).stat().st_mode & 0o777) == "0o600"

    # A later start of that add-on accepts exactly that digest, and nothing else
    # under that name.
    start = ["--repo-root", str(root), "--config-dir", str(config), "image-verify",
             "--command=start"]
    ok = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert cli.main([*start, f"--addon-images=probe={ok}"]) == 0
    other = tmp_path / "other.txt"
    other.write_text(f"{WIKI}:1.0.0@{D2}\n", "utf-8")
    assert cli.main([*start, f"--addon-images=probe={other}"]) == 2


def test_confirmation_does_not_cover_an_unpinned_image(tmp_path, keypair, monkeypatch):
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0"])
    assert _addon_verify(root, config, refs, addon, "--accept-unlisted-images",
                         f"--pending-file={tmp_path / 'pending.txt'}") == 2
    assert _audit_rows(config) == []


def test_confirmation_does_not_cover_a_listed_image_with_another_digest(tmp_path, keypair,
                                                                       monkeypatch):
    """Acceptance is for images outside the bill of materials, never for a listed
    image whose digest or signature is wrong."""
    root = _core(tmp_path, keypair, bom=_addon_bom(keypair[1], [_image(WIKI, "1.0.0", D1)]))
    config, addon = _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _addon_verify(root, config, refs, addon, "--accept-unlisted-images",
                         f"--pending-file={tmp_path / 'pending.txt'}") == 2


def test_accepted_images_file_is_validated(tmp_path):
    path = tmp_path / images.ACCEPTED_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema": "x", "images": {}}), "utf-8")
    with pytest.raises(images.ImageError):
        images.load_accepted(tmp_path, "probe")


def test_readme_does_not_claim_a_check_that_does_not_exist():
    text = (REPO / "README.md").read_text("utf-8")
    assert "checked by their own install and start path" not in text


def test_addon_upgrade_checks_the_new_version_before_it_starts(tmp_path):
    call = f'CONFIG_DIR="{tmp_path / "config"}"; _addon_recreate wiki || echo recreate-failed=$?'
    done = _shell(tmp_path, call, verify=2)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert any(c.startswith("py_cli image-verify --command=addon-upgrade") for c in calls)
    assert not any(" up " in c for c in calls)
    assert calls[-1] == "recreate-failed=2"
