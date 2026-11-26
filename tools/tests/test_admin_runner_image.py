"""The one-shot runner of the Keycloak admin steps is an image the installation runs.

On a host where the bundled Keycloak publishes no port, every admin step (role sync,
realm sync, post-restore, the clients of an add-on) runs in a one-shot container with the
image papaia-manager pins (lib/keycloak_admin_path.py, docs/adr/0033). That image is
therefore treated like every image of the Compose project:

- `runner_image` applies `PAPAIA_IMAGE_MIRROR`; the digest does not change.
- The image check of `start`, `upgrade`, `restore` and the add-on commands lists it,
  before any container starts, with digest and signature against the bill of materials.
  With a published Keycloak port, or another identity provider, no runner runs and none
  is listed.
- `installation-images`, the list a bill of materials is generated from, names it.
- `start` fails when the role sync, or another step that creates roles or rights, fails:
  non-zero exit after the stack is up, the cause and the retry command on stderr, no
  `start complete` line.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation, run_cli
from test_cluster import fake_cluster
from test_images import (
    BASH,
    D1,
    D2,
    ENTRIES,
    KEYCLOAK,
    LIFECYCLE,
    POSTGRES,
    REPO,
    _bom,
    _config,
    _core,
    _image,
    _new_keypair,
    _signed_registry,
)
from test_topology import FULL, dmz_split, write_topology

from lib import cli, cluster, common, images, keycloak_admin_path

MIRROR = "127.0.0.1:52240/unpublished/"
D6 = "sha256:" + "6" * 64
MANAGER = "ghcr.io/fidonis/papaia-manager"
RUNNER = f"{MANAGER}:1.8.0@{D6}"
# The bundled proxy in front of Keycloak: its port is not published.
EDGE = "COMPOSE_PROFILES=keycloak,nginx\nREVERSE_PROXY_PROVIDER=internal_nginx\n"
# Direct port access with the keycloak profile: Keycloak publishes its port.
DIRECT = "COMPOSE_PROFILES=keycloak\nREVERSE_PROXY_PROVIDER=no_proxy\n"


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path)


def _with_runner(root: Path, image: str = RUNNER) -> Path:
    """The core tree gets the compose file of papaia-manager, whose pin the runner uses,
    and a project with Keycloak and its database."""
    src = root / "src"
    for rel, doc in {
        "docker-compose.yml": {
            "include": [{"path": "./infra/keycloak/docker-compose.yml"},
                        {"path": "./manager/docker-compose.yml"}],
            "services": {"audit-db": {"image": f"{POSTGRES}:18.3@{D2}"}},
        },
        "infra/keycloak/docker-compose.yml": {
            "services": {"keycloak": {"image": f"{KEYCLOAK}:26.7.0@{D1}",
                                      "profiles": ["keycloak"]}},
        },
        "manager/docker-compose.yml": {
            "services": {"papaia-manager": {"image": image, "profiles": ["manager"]}},
        },
    }.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")
    return root


def _tree(tmp_path: Path, keypair, entries: list[dict]) -> Path:
    return _with_runner(_core(tmp_path, keypair, bom=_bom(keypair[1], entries)))


def _registry(keypair, tmp_path: Path, host: str = "", *, runner_key=None):
    """Keycloak and the database signed by `keypair`, the runner by `runner_key`."""
    registry = _signed_registry(keypair, tmp_path, host)
    ref = images.parse_ref(f"{host}{RUNNER}")
    private, _ = runner_key or keypair
    registry.add_signature(ref.registry, ref.repository, D6, private, tmp_path)
    return registry


def _images_file(tmp_path: Path, refs: list[str]) -> Path:
    path = tmp_path / "compose-images.txt"
    path.write_text("\n".join(refs) + "\n", encoding="utf-8")
    return path


def _verify(root: Path, config: Path, *extra: str) -> int:
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     *extra])


# ── runner_image: the mirror ─────────────────────────────────────────────────


def test_runner_image_without_a_mirror_is_the_pin_of_papaia_manager():
    pinned = keycloak_admin_path.runner_image(REPO)
    assert pinned.startswith(f"{MANAGER}:") and "@sha256:" in pinned
    assert keycloak_admin_path.runner_image(REPO, {}) == pinned


def test_runner_image_goes_through_the_mirror_with_the_same_digest():
    pinned = keycloak_admin_path.runner_image(REPO)
    mirrored = keycloak_admin_path.runner_image(REPO, {"PAPAIA_IMAGE_MIRROR": MIRROR})
    assert mirrored == MIRROR + pinned
    assert images.parse_ref(mirrored).digest == images.parse_ref(pinned).digest


def test_runner_image_refuses_a_mirror_that_is_no_registry_prefix():
    with pytest.raises(keycloak_admin_path.AdminPathError, match="PAPAIA_IMAGE_MIRROR"):
        keycloak_admin_path.runner_image(REPO, {"PAPAIA_IMAGE_MIRROR": "not a prefix"})


def test_the_one_shot_container_runs_the_mirrored_reference_by_digest(monkeypatch, tmp_path):
    monkeypatch.setattr(common, "in_container", lambda: False)
    root = {"COMPOSE_PROFILES": "keycloak,nginx", "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "AUTH_PROVIDER": "internal_keycloak", "PAPAIA_IMAGE_MIRROR": MIRROR}
    argv = keycloak_admin_path.oneshot_argv(root, tmp_path, REPO, ["keycloak-role-sync"])
    image = argv[argv.index("--entrypoint") + 2]
    assert image == MIRROR + keycloak_admin_path.runner_image(REPO)
    assert "@sha256:" in image
    # The restrictions stay: read-only root, no capabilities, no socket, the host user.
    assert "--read-only" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert not any("docker.sock" in a for a in argv)


# ── which installations run the runner ───────────────────────────────────────


def test_the_runner_is_installed_on_the_host_admin_path(tmp_path):
    root = _with_runner(tmp_path / "core")
    edge = {"COMPOSE_PROFILES": "keycloak,nginx", "REVERSE_PROXY_PROVIDER": "internal_nginx"}
    assert keycloak_admin_path.installed_images(root, edge) == [RUNNER]
    # Unmirrored: the bill of materials names the image without the mirror.
    with_mirror = {**edge, "PAPAIA_IMAGE_MIRROR": MIRROR}
    assert keycloak_admin_path.installed_images(root, with_mirror) == [RUNNER]


def test_no_runner_with_a_published_port_or_another_identity_provider(tmp_path):
    root = _with_runner(tmp_path / "core")
    direct = {"COMPOSE_PROFILES": "keycloak", "REVERSE_PROXY_PROVIDER": "no_proxy"}
    assert keycloak_admin_path.installed_images(root, direct) == []
    external = {"COMPOSE_PROFILES": "nginx", "REVERSE_PROXY_PROVIDER": "internal_nginx",
                "AUTH_PROVIDER": "external_oidc"}
    assert keycloak_admin_path.installed_images(root, external) == []


def test_an_unpinned_runner_is_refused(tmp_path):
    root = _with_runner(tmp_path / "core", image=f"{MANAGER}:1.8.0")
    edge = {"COMPOSE_PROFILES": "keycloak,nginx", "REVERSE_PROXY_PROVIDER": "internal_nginx"}
    with pytest.raises(keycloak_admin_path.AdminPathError, match="not pinned by digest"):
        keycloak_admin_path.installed_images(root, edge)


# ── the image check lists the runner ─────────────────────────────────────────


def test_start_on_the_host_admin_path_checks_the_runner(tmp_path, keypair, monkeypatch, capsys):
    root = _tree(tmp_path, keypair, [*ENTRIES, _image(MANAGER, "1.8.0", D6)])
    config = _config(tmp_path, EDGE)
    registry = _registry(keypair, tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: registry)
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start") == 0
    assert "3 image(s) verified" in capsys.readouterr().out
    assert any(repo == "fidonis/papaia-manager" for _host, repo, _tag in registry.requests)


def test_a_runner_missing_from_the_bill_of_materials_is_refused(tmp_path, keypair, monkeypatch,
                                                                capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, EDGE)
    monkeypatch.setattr(images, "Registry", lambda: _registry(keypair, tmp_path))
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start") == 2
    err = capsys.readouterr().err
    assert f"{RUNNER}: not in the bill of materials" in err
    assert "Nothing was started" in err


def test_a_wrongly_signed_runner_is_refused(tmp_path, keypair, monkeypatch, capsys):
    root = _tree(tmp_path, keypair, [*ENTRIES, _image(MANAGER, "1.8.0", D6)])
    config = _config(tmp_path, EDGE)
    other = _new_keypair(tmp_path, "other")
    monkeypatch.setattr(images, "Registry",
                        lambda: _registry(keypair, tmp_path, runner_key=other))
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start") == 2
    assert RUNNER in capsys.readouterr().err


def test_with_a_published_keycloak_port_the_runner_is_not_required(tmp_path, keypair,
                                                                   monkeypatch, capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, DIRECT)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start") == 0
    assert "2 image(s) verified" in capsys.readouterr().out


def test_the_runner_is_checked_through_the_mirror(tmp_path, keypair, monkeypatch):
    root = _tree(tmp_path, keypair, [*ENTRIES, _image(MANAGER, "1.8.0", D6)])
    config = _config(tmp_path, f"{EDGE}PAPAIA_IMAGE_MIRROR={MIRROR}\n")
    registry = _registry(keypair, tmp_path, MIRROR)
    monkeypatch.setattr(images, "Registry", lambda: registry)
    listed = _images_file(tmp_path, [f"{MIRROR}{KEYCLOAK}:26.7.0@{D1}",
                                     f"{MIRROR}{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start") == 0
    hosts = {host for host, repo, _tag in registry.requests if repo.endswith("papaia-manager")}
    assert hosts == {"127.0.0.1:52240"}


@pytest.mark.parametrize("source", ["--as-installed", "--from-checkout"])
def test_upgrade_stage_0_checks_the_runner_of_the_target(tmp_path, keypair, monkeypatch, capsys,
                                                         source):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, EDGE)
    monkeypatch.setattr(images, "Registry", lambda: _registry(keypair, tmp_path))
    assert _verify(root, config, source, "--command=upgrade") == 2
    assert RUNNER in capsys.readouterr().err


def test_restore_checks_the_runner_before_post_restore(tmp_path, keypair, monkeypatch, capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, EDGE)
    monkeypatch.setattr(images, "Registry", lambda: _registry(keypair, tmp_path))
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=restore") == 2
    assert RUNNER in capsys.readouterr().err


def test_an_add_on_check_covers_the_runner_its_client_step_uses(tmp_path, keypair, monkeypatch,
                                                                capsys):
    """`addon start` and `addon upgrade` create the add-on's clients in the runner."""
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, EDGE)
    monkeypatch.setattr(images, "Registry", lambda: _registry(keypair, tmp_path))
    own = _images_file(tmp_path, [f"{POSTGRES}:18.3@{D2}"])
    assert _verify(root, config, f"--addon-images=wiki={own}", "--command=addon-start") == 2
    assert RUNNER in capsys.readouterr().err


def test_insecure_images_counts_the_runner_in_its_audit_row(tmp_path, keypair, capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, EDGE)
    listed = _images_file(tmp_path, [f"{KEYCLOAK}:26.7.0@{D1}"])
    assert _verify(root, config, f"--images-file={listed}", "--command=start",
                   "--insecure-images") == 0
    assert "2 image(s) are started" in capsys.readouterr().err


# ── the list a bill of materials is generated from ───────────────────────────


def _installation_images(root: Path, config: Path, capsys) -> list[str]:
    capsys.readouterr()
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "installation-images"]) == 0
    return capsys.readouterr().out.split()


def test_the_bill_of_materials_list_names_the_runner_on_the_host_admin_path(tmp_path, keypair,
                                                                            capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, f"{EDGE}PAPAIA_IMAGE_MIRROR={MIRROR}\n")
    found = _installation_images(root, config, capsys)
    assert sorted(found) == sorted([f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}", RUNNER])


def test_the_bill_of_materials_list_has_no_runner_with_a_published_port(tmp_path, keypair,
                                                                        capsys):
    root = _tree(tmp_path, keypair, ENTRIES)
    config = _config(tmp_path, DIRECT)
    found = _installation_images(root, config, capsys)
    assert sorted(found) == sorted([f"{KEYCLOAK}:26.7.0@{D1}", f"{POSTGRES}:18.3@{D2}"])


def test_the_bill_of_materials_list_of_this_checkout_names_its_runner(tmp_path, capsys):
    config = _config(tmp_path, EDGE)
    found = _installation_images(REPO, config, capsys)
    assert keycloak_admin_path.runner_image(REPO) in found


# ── start fails when a step that creates roles or rights fails ───────────────

_START = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
warn() { echo "WARN: $*" >&2; }
info() { :; }
success() { echo "OK: $*"; }
usage() { :; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
_addon_image_list() { :; }
_addon_image_flags() { :; }
_addon_image_files_remove() { :; }
_core_override_files() { :; }
docker() { echo "docker $*"; }
# Every call is logged to calls.log as well: the model keys step captures the output of
# its py_cli call. A step named in @FAIL@ fails; one named as `step:n` fails on its n-th
# call only (an add-on is started once before `up` and again after a new model key).
_nth() {
    local count="@CONFIG@/count.$1" n=0
    [ -f "$count" ] && n="$(cat "$count")"
    n=$((n + 1))
    echo "$n" > "$count"
    case " @FAIL@ " in *" $1 "*|*" $1:$n "*) return 1 ;; esac
    return 0
}
_addon_path() {
    echo "addon-path $1" >> "@CONFIG@/calls.log"
    _nth addon-path || return 1
    echo "/addons/$1"
}
_addon_compose_up() {
    echo "compose-up $1" >> "@CONFIG@/calls.log"
    echo "compose-up $1"
    _nth compose-up
}
py_cli() {
    echo "py_cli $*" >> "@CONFIG@/calls.log"
    case "$1" in
        active-addons) printf '%s\n' @ADDONS@; return 0 ;;
        model-keys-sync) printf 'MODEL_KEY_CHANGED=%s\n' @CHANGED@ ;;
        *) echo "py_cli $*" ;;
    esac
    _nth "$1"
}
cmd_start @ARGS@
"""


def _start(tmp_path: Path, fail: str = "", args: str = "--no-addons", addons: str = "",
           changed: str = "") -> subprocess.CompletedProcess:
    if BASH is None:
        pytest.skip("bash is not available")
    script = (_START.replace("@CONFIG@", tmp_path.as_posix())
              .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
              .replace("@FAIL@", fail)
              .replace("@ARGS@", args)
              .replace("@ADDONS@", addons)
              .replace("@CHANGED@", changed))
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=60,
                          check=False)


def _calls(tmp_path: Path) -> list[str]:
    return (tmp_path / "calls.log").read_text(encoding="utf-8").splitlines()


def test_a_succeeding_role_sync_keeps_the_output_of_start(tmp_path):
    done = _start(tmp_path)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert calls[-1] == "OK: start complete."
    assert "py_cli keycloak-role-sync" in calls
    assert "failed" not in done.stderr


def test_a_failed_role_sync_fails_start_after_the_stack_is_up(tmp_path):
    done = _start(tmp_path, fail="keycloak-role-sync")
    assert done.returncode != 0
    assert "start complete" not in done.stdout + done.stderr
    calls = done.stdout.splitlines()
    up = next(i for i, c in enumerate(calls) if c.startswith("docker compose") and " up " in c)
    assert up < calls.index("py_cli keycloak-role-sync")
    # The later steps still ran; the cause and the retry command are on stderr.
    assert "py_cli replay-chat-sync" in calls
    assert "py_cli model-keys-sync" in _calls(tmp_path)
    assert "Keycloak role sync failed" in done.stderr
    assert "papaia-ctl keycloak-role-sync" in done.stderr


@pytest.mark.parametrize("step, retry", [
    ("replay-chat-sync", "papaia-ctl start"),
    ("model-keys-sync", "papaia-ctl start --addons"),
])
def test_the_other_steps_that_create_roles_or_rights_fail_start_too(tmp_path, step, retry):
    done = _start(tmp_path, fail=step)
    assert done.returncode != 0
    assert "start complete" not in done.stdout + done.stderr
    assert retry in done.stderr


def test_an_add_on_with_a_new_model_key_is_started_again(tmp_path):
    done = _start(tmp_path, args="--addons", addons="wiki", changed="wiki")
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[-1] == "OK: start complete."
    assert _calls(tmp_path).count("compose-up wiki") == 2


@pytest.mark.parametrize("fail", ["compose-up:2", "addon-path:2", "addon-start:2"])
def test_a_failed_restart_after_a_new_model_key_fails_start(tmp_path, fail):
    """Each failure of the restart decides the outcome, not errexit: the step runs on the
    left of `||`, where bash ignores `set -e` in the whole function body."""
    done = _start(tmp_path, fail=fail, args="--addons", addons="wiki", changed="wiki")
    assert done.returncode != 0
    assert "start complete" not in done.stdout + done.stderr
    assert "wiki" in done.stderr
    assert "papaia-ctl start --addons" in done.stderr
    # The model keys themselves were checked: only the restart is reported.
    assert "Not every module key" not in done.stderr


def test_a_failed_restart_does_not_stop_the_restart_of_the_next_add_on(tmp_path):
    done = _start(tmp_path, fail="compose-up:3", args="--addons", addons="wiki chat",
                  changed="wiki chat")
    assert done.returncode != 0
    assert "start complete" not in done.stdout + done.stderr
    assert _calls(tmp_path).count("compose-up chat") == 2


def test_a_failed_proxy_provisioning_still_only_warns(tmp_path):
    """npm-provision creates proxy hosts, no client, role or right."""
    done = _start(tmp_path, fail="npm-provision")
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[-1] == "OK: start complete."
    assert "WARN: NPM proxy-host provisioning failed" in done.stderr


def test_a_refused_image_check_starts_no_container_and_no_runner(tmp_path):
    done = _start(tmp_path, fail="image-verify")
    assert done.returncode != 0
    calls = done.stdout.splitlines()
    assert not any(c.startswith("docker compose") and " up " in c for c in calls)
    assert "py_cli keycloak-role-sync" not in calls


# ── a distributed start fails the same way ───────────────────────────────────


def test_a_failed_role_sync_on_keycloaks_node_fails_a_distributed_start(tmp_path, monkeypatch,
                                                                       capsys):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    run_cli(inst.repo, inst.config, "render")
    found, _log = fake_cluster(inst, monkeypatch, edge={"fail": {"hook keycloak-role-sync"}})
    capsys.readouterr()
    assert cluster.start(found) != 0
    err = capsys.readouterr().err
    assert "keycloak-role-sync failed on node 'edge'" in err
    assert "papaia-ctl start --node=edge" in err


def test_a_failed_proxy_hook_still_only_warns_in_a_distributed_start(tmp_path, monkeypatch,
                                                                    capsys):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    run_cli(inst.repo, inst.config, "render")
    found, _log = fake_cluster(inst, monkeypatch, edge={"fail": {"hook npm-provision"}})
    assert cluster.start(found) == 0
    assert "WARNING: npm-provision failed on node 'edge'" in capsys.readouterr().err


# ── the rule is recorded ─────────────────────────────────────────────────────

ADR = REPO / "docs" / "adr" / (
    "0033-check-and-mirror-the-runner-of-the-admin-steps-and-fail-start-on-a-failed-role-sync.md"
)


def test_the_rule_is_an_indexed_adr():
    text = ADR.read_text(encoding="utf-8")
    assert text.startswith("---\nadr: 0033\n")
    for needed in ("installed_images", "PAPAIA_IMAGE_MIRROR", "start complete.",
                   "keycloak-role-sync", "npm-provision", "release-day-images.yaml"):
        assert needed in text, needed
    index = (REPO / "docs" / "adr" / "README.md").read_text(encoding="utf-8")
    assert f"(./{ADR.name})" in index


def test_the_operator_handbook_names_the_runner_and_the_failed_start():
    start = (REPO / "docs" / "de" / "betrieb" / "handbuch.md").read_text(encoding="utf-8")
    section = start.split("\n## Start\n", 1)[1].split("\n## ", 1)[0]
    for needed in ("papaia-manager", "PAPAIA_IMAGE_MIRROR", "Ausgang 3",
                   "papaia-ctl keycloak-role-sync", "start complete."):
        assert needed in section, needed
    images_chapter = (REPO / "docs" / "de" / "betrieb" / "lizenz-und-bezug.md").read_text("utf-8")
    assert "Hilfscontainer der Verwaltungsschritte" in images_chapter
