"""Image checks, fourth part: only the images the installation runs.

- The mirror override (`PAPAIA_IMAGE_MIRROR`) names only services of the Compose project
  the installation uses: `src/docker-compose.yml` and the files it includes. The link
  gateway is not part of it; a single host neither checks nor starts it. On a node of a
  distributed installation the gateway gets its mirrored image through the node's own
  gateway override.
- Stage 0 of `upgrade` on a single host checks the images the installation runs after
  the upgrade: the services of the target's project that the installed `COMPOSE_PROFILES`
  enable, with the accelerator images the installed variants select, and the active
  add-ons with their own lists. A distributed installation still checks every pin of
  the target tree.

Where Docker Compose is at hand, the lists are compared with what
`docker compose config --images` prints for a real installation (nothing is started).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation, run_cli
from test_images import (
    BASH,
    D1,
    D2,
    D3,
    ENTRIES,
    KEYCLOAK,
    LIFECYCLE,
    POSTGRES,
    REPO,
    UPGRADE,
    _audit_rows,
    _bom,
    _config,
    _core,
    _image,
    _new_keypair,
    _signed_registry,
)
from test_topology import FULL, dmz_split, write_topology

from lib import cli, common, gen_override, images, link, topology

MIRROR = "registry.example.com/papaia/"
D4 = "sha256:" + "4" * 64
D5 = "sha256:" + "5" * 64
LOCALAI = "localai/localai"
HAPROXY = "haproxy"


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path)


def _gateway_image(repo: Path) -> str:
    doc = yaml.safe_load((repo / link.GATEWAY_FRAGMENT).read_text("utf-8"))
    return doc["services"][link.GATEWAY_SERVICE]["image"]


# ── docker compose, where it is at hand ──────────────────────────────────────


def _compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    done = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
    return done.returncode == 0


needs_compose = pytest.mark.skipif(not _compose_available(),
                                   reason="docker compose is not installed")


def _compose_images(repo: Path, files: list[Path], profiles: str | None = None) -> set[str]:
    """`docker compose config --images` as `start` runs it: the core file, the override
    files, the root env file of the checkout. Reads files only; starts nothing."""
    argv = ["docker", "compose", "-f", str(repo / "src" / "docker-compose.yml")]
    for path in files:
        argv += ["-f", str(path)]
    argv += ["--env-file", str(repo / "src" / ".env"), "config", "--images"]
    env = None
    if profiles is not None:
        env = {**os.environ, "COMPOSE_PROFILES": profiles}
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False,
                          env=env)
    assert done.returncode == 0, done.stderr
    return {line.strip() for line in done.stdout.splitlines() if line.strip()}


def _overrides(config: Path) -> list[Path]:
    return sorted((config / "overrides").glob("docker-compose.*.override.yml"))


def _set_env(inst: Installation, **values: str) -> None:
    path = inst.config / ".env"
    lines = [line for line in path.read_text("utf-8").splitlines()
             if line.split("=", 1)[0] not in values]
    lines += [f"{key}={value}" for key, value in values.items()]
    path.write_text("\n".join(lines) + "\n", "utf-8")
    # As `start` does before its check: the configuration into the checkout, then render.
    run_cli(inst.repo, inst.config, "materialize-core")
    run_cli(inst.repo, inst.config, "render")


@pytest.fixture
def full(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    return inst


# ── mirror override: single host ─────────────────────────────────────────────


def test_mirror_override_defines_no_service_outside_the_project(tmp_path):
    """A service the project does not define would be a new service without a profile,
    always enabled: the link gateway on a single host."""
    config = tmp_path / "config"
    (config / "overrides").mkdir(parents=True)
    gen_override.generate_image_mirror_override(config, REPO, MIRROR)
    path = config / "overrides" / gen_override.IMAGE_MIRROR_OVERRIDE
    services = yaml.safe_load(path.read_text("utf-8"))["services"]
    project = {s.name for s in topology.compose_services(REPO)}
    assert link.GATEWAY_SERVICE not in services
    assert set(services) <= project
    # Every service of the project that names an image is mirrored.
    assert set(services) == {s.name for s in topology.compose_services(REPO)
                             if isinstance(s.body.get("image"), str)}


@needs_compose
def test_start_with_a_mirror_on_a_single_host_lists_no_link_gateway(full: Installation):
    _set_env(full, PAPAIA_IMAGE_MIRROR=MIRROR)
    listed = _compose_images(full.repo, _overrides(full.config))
    gateway = _gateway_image(full.repo)
    assert not any(gateway in ref for ref in listed)
    assert listed and all(ref.startswith(MIRROR) for ref in listed)


@needs_compose
def test_start_without_a_mirror_lists_the_same_images_unmirrored(full: Installation):
    plain = _compose_images(full.repo, _overrides(full.config))
    _set_env(full, PAPAIA_IMAGE_MIRROR=MIRROR)
    mirrored = _compose_images(full.repo, _overrides(full.config))
    assert {ref.removeprefix(MIRROR) for ref in mirrored} == plain


# ── mirror override: a node of a distributed installation ────────────────────


def _project_with_mirror(inst: Installation) -> Path:
    _set_env(inst, PAPAIA_IMAGE_MIRROR=MIRROR)
    write_topology(inst.config, dmz_split())
    topology.project(inst.config, inst.repo, dmz_split())
    return topology.bundle_dir(inst.config, "edge")


def test_the_gateway_of_a_node_keeps_its_mirrored_image(full: Installation):
    bundle = _project_with_mirror(full)
    gateway = yaml.safe_load(
        (bundle / "overrides" / link.GATEWAY_OVERRIDE).read_text("utf-8")
    )["services"][link.GATEWAY_SERVICE]
    assert gateway["image"] == MIRROR + _gateway_image(full.repo)
    # The node's copy of the mirror override does not define the gateway either.
    mirror = yaml.safe_load(
        (bundle / "overrides" / gen_override.IMAGE_MIRROR_OVERRIDE).read_text("utf-8")
    )["services"]
    assert link.GATEWAY_SERVICE not in mirror


def test_the_gateway_override_names_no_image_without_a_mirror(full: Installation):
    write_topology(full.config, dmz_split())
    topology.project(full.config, full.repo, dmz_split())
    bundle = topology.bundle_dir(full.config, "edge")
    gateway = yaml.safe_load(
        (bundle / "overrides" / link.GATEWAY_OVERRIDE).read_text("utf-8")
    )["services"][link.GATEWAY_SERVICE]
    assert "image" not in gateway


@needs_compose
def test_a_node_with_the_gateway_pulls_it_through_the_mirror(full: Installation):
    bundle = _project_with_mirror(full)
    files = [full.repo / link.GATEWAY_FRAGMENT, *_overrides(bundle)]
    listed = _compose_images(full.repo, files, profiles=link.GATEWAY_PROFILE)
    assert listed == {MIRROR + _gateway_image(full.repo)}


# ── the images an installation runs ──────────────────────────────────────────


def _tree(root: Path) -> Path:
    """A core tree: two included files, the link gateway beside them (not included)."""
    src = root / "src"
    for rel, doc in {
        "docker-compose.yml": {
            "include": [{"path": "./infra/keycloak/docker-compose.yml"},
                        {"path": "./ai/localai/docker-compose.yml"}],
            "services": {"audit-db": {"image": f"{POSTGRES}:18.3@{D2}"}},
        },
        "infra/keycloak/docker-compose.yml": {
            "services": {"keycloak": {"image": f"{KEYCLOAK}:26.7.0@{D1}",
                                      "profiles": ["keycloak"]}},
        },
        "ai/localai/docker-compose.yml": {
            "x-papaia-localai-gpu-images": {
                "vulkan": f"{LOCALAI}:v4.12.1-gpu-vulkan@{D4}",
            },
            "services": {"localai": {"image": f"{LOCALAI}:v4.12.1@{D3}",
                                     "profiles": ["localai"]}},
        },
        "infra/link-gateway/docker-compose.yml": {
            "services": {"link-gateway": {"image": f"{HAPROXY}:3.2.26-alpine@{D5}",
                                          "profiles": ["link-gateway"]}},
        },
    }.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")
    return root


def test_installation_images_follow_the_profiles_of_the_installation(tmp_path):
    root = _tree(tmp_path)
    found = gen_override.installation_images(root, {"COMPOSE_PROFILES": "keycloak"})
    assert sorted(found) == sorted([f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    found = gen_override.installation_images(root, {"COMPOSE_PROFILES": "keycloak, localai"})
    assert f"{LOCALAI}:v4.12.1@{D3}" in found
    # Never the link gateway, never another profile's image.
    assert not any(HAPROXY in ref for ref in found)


def test_installation_images_take_the_accelerator_image_the_render_chooses(tmp_path):
    root = _tree(tmp_path)
    env = {"COMPOSE_PROFILES": "localai", "LOCALAI_IMAGE_VARIANT": "vulkan"}
    found = gen_override.installation_images(root, env)
    assert f"{LOCALAI}:v4.12.1-gpu-vulkan@{D4}" in found
    assert f"{LOCALAI}:v4.12.1@{D3}" not in found
    # An unknown or CPU variant keeps the image of the compose file.
    for variant in ("cpu", "nonsense", ""):
        env["LOCALAI_IMAGE_VARIANT"] = variant
        assert f"{LOCALAI}:v4.12.1@{D3}" in gen_override.installation_images(root, env)


@needs_compose
@pytest.mark.parametrize("profiles", [
    "keycloak,oauth2-proxy,nginx",
    None,  # every profile the setup enabled
])
def test_installation_images_are_what_compose_lists(full: Installation, profiles):
    """The list stage 0 checks is the list `start` checks after the render."""
    if profiles is not None:
        _set_env(full, COMPOSE_PROFILES=profiles)
    env = common.parse_env_file(full.config / ".env")
    expected = _compose_images(full.repo, _overrides(full.config))
    assert set(gen_override.installation_images(full.repo, env)) == expected


@needs_compose
def test_installation_images_with_an_accelerator_and_a_mirror(full: Installation):
    _set_env(full, LOCALAI_IMAGE_VARIANT="vulkan", PAPAIA_IMAGE_MIRROR=MIRROR)
    env = common.parse_env_file(full.config / ".env")
    expected = _compose_images(full.repo, _overrides(full.config))
    found = set(images.mirrored(gen_override.installation_images(full.repo, env), MIRROR))
    assert found == expected
    assert any("-gpu-vulkan@" in ref for ref in found)


# ── image-verify --as-installed ──────────────────────────────────────────────


def _target(tmp_path: Path, keypair, entries: list[dict]) -> Path:
    return _tree(_core(tmp_path, keypair, bom=_bom(keypair[1], entries)))


def _verify_installed(root: Path, config: Path, *extra: str) -> int:
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     "--as-installed", "--command=upgrade", *extra])


def test_a_bill_of_materials_of_the_installed_profiles_passes(tmp_path, keypair,
                                                               monkeypatch):
    """The bill of materials lists exactly what the installation runs: keycloak and the
    database without a profile. Neither LocalAI nor the link gateway is needed."""
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    assert _verify_installed(root, config) == 0
    # The whole tree needs images the bill of materials does not list.
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     "--from-checkout", "--command=upgrade"]) == 2


def test_a_missing_image_of_an_installed_profile_is_refused(tmp_path, keypair, monkeypatch,
                                                            capsys):
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak,localai\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    assert _verify_installed(root, config) == 2
    assert f"{LOCALAI}:v4.12.1@{D3}" in capsys.readouterr().err


def test_the_service_without_a_profile_is_always_checked(tmp_path, keypair, monkeypatch,
                                                         capsys):
    root = _target(tmp_path, keypair, [_image(KEYCLOAK, "26.7.0", D1)])
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    assert _verify_installed(root, config) == 2
    assert f"{POSTGRES}:18.3@{D2}" in capsys.readouterr().err


def test_a_wrongly_signed_image_of_an_installed_profile_is_refused(tmp_path, keypair,
                                                                   monkeypatch, capsys):
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak\n")
    other = _new_keypair(tmp_path, "other")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(other, tmp_path))
    assert _verify_installed(root, config) == 2
    assert f"{KEYCLOAK}:26.7.0@{D1}" in capsys.readouterr().err


def test_the_accelerator_image_of_the_installation_is_checked(tmp_path, keypair, monkeypatch,
                                                              capsys):
    root = _target(tmp_path, keypair, [*ENTRIES, _image(LOCALAI, "v4.12.1", D3)])
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak,localai\n"
                                "LOCALAI_IMAGE_VARIANT=vulkan\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    assert _verify_installed(root, config) == 2
    assert f"{LOCALAI}:v4.12.1-gpu-vulkan@{D4}" in capsys.readouterr().err


def test_as_installed_goes_through_the_mirror(tmp_path, keypair, monkeypatch):
    mirror = "127.0.0.1:57500/unpublished/"
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, f"COMPOSE_PROFILES=keycloak\nPAPAIA_IMAGE_MIRROR={mirror}\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path, mirror))
    assert _verify_installed(root, config) == 0


def test_as_installed_and_from_checkout_do_not_go_together(tmp_path, keypair):
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak\n")
    assert _verify_installed(root, config, "--from-checkout") == 2


def test_as_installed_with_insecure_images_is_audited_as_before(tmp_path, keypair, capsys):
    root = _target(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, "COMPOSE_PROFILES=keycloak\n")
    assert _verify_installed(root, config, "--insecure-images") == 0
    assert "INSECURE" in capsys.readouterr().err
    rows = _audit_rows(config)
    assert len(rows) == 1 and rows[0]["event"] == "image_verification_skipped"
    assert rows[0]["detail"]["images"] == 2 and rows[0]["detail"]["command"] == "upgrade"


# ── upgrade stage 0: which list ──────────────────────────────────────────────

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
_topology_mode() { echo @MODE@; }
cmd_backup() { echo "backup"; LAST_BACKUP_ID=rp1; }
cmd_stop() { echo "stop $*"; }
git() {
    case "$*" in
        *"worktree add"*) mkdir -p "${@: -2:1}" ;;
        *"status --porcelain"*) ;;
        *"rev-parse"*) echo "${@: -1}" | sed 's/\\^{commit}$//' ;;
    esac
    return 0
}
docker() { echo "docker $*"; }
py_cli() {
    case "$1" in
        image-trust-anchor) echo "sha256:@ANCHOR@"; return ;;
        new-correlation-id) echo "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"; return ;;
        upgrade-stage) [ "$2" = restore-point ] && return 0; echo "py_cli $*"; return ;;
        active-addons) return ;;
    esac
    echo "py_cli $*"
    if [ "$1" = "upgrade-resolve" ]; then
        printf 'CURRENT\\t1.9.0\\nTARGET\\t1.10.0\\nTAG\\tv1.10.0\\nSTATUS\\tupgrade\\n'
    fi
}
ctl_runtime_at() { :; }
_py_cli_at() {
    echo "py_cli_at $*"
    case "$2" in image-verify) return @VERIFY@ ;; esac
    return 0
}
cmd_upgrade -y @FLAGS@
"""


def _upgrade(tmp_path: Path, mode: str, *, verify: int = 0,
             flags: str = "") -> subprocess.CompletedProcess:
    if BASH is None:
        pytest.skip("bash is not available")
    nxt = tmp_path / "next-phase"
    nxt.write_text('#!/bin/sh\necho "phase2 $*"\n', encoding="utf-8")
    nxt.chmod(0o755)
    (tmp_path / "config").mkdir()
    script = (
        _UPGRADE.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@MODE@", mode)
        .replace("@VERIFY@", str(verify))
        .replace("@FLAGS@", flags)
        .replace("@ANCHOR@", "a" * 64)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=60,
                          check=False)


def _stage0(done: subprocess.CompletedProcess) -> tuple[list[str], int]:
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if " image-verify " in f"{c} ")
    return calls, verify


def test_stage_0_on_a_single_host_checks_what_the_installation_runs(tmp_path):
    done = _upgrade(tmp_path, "single")
    assert done.returncode == 0, done.stderr
    calls, verify = _stage0(done)
    assert calls[verify].startswith("py_cli_at ") and "/target " in calls[verify]
    assert "--as-installed" in calls[verify] and "--command=upgrade" in calls[verify]
    assert "--from-checkout" not in calls[verify]
    assert verify < calls.index("backup")


def test_stage_0_refusal_on_a_single_host_changes_nothing(tmp_path):
    done = _upgrade(tmp_path, "single", verify=2)
    assert done.returncode == 2
    calls = done.stdout.splitlines()
    assert "backup" not in calls
    assert not any(c.startswith(("stop", "phase2")) for c in calls)


def test_stage_0_of_a_distributed_installation_checks_the_whole_tree(tmp_path):
    done = _upgrade(tmp_path, "distributed", flags="--dry-run")
    assert done.returncode == 0, done.stderr
    calls, verify = _stage0(done)
    assert "--from-checkout" in calls[verify]
    assert "--as-installed" not in calls[verify]


def test_stage_0_keeps_insecure_images_for_this_command(tmp_path):
    done = _upgrade(tmp_path, "single", flags="--insecure-images")
    assert done.returncode == 0, done.stderr
    calls, verify = _stage0(done)
    assert "--insecure-images" in calls[verify] and "--as-installed" in calls[verify]

