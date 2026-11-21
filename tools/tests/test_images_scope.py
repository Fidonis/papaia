"""Image checks, third part: what an acceptance covers and which commands can skip the check.

- Only an image whose repository the bill of materials does not list at all can be
  accepted at `addon install`. Another tag, or an untagged digest, of a listed repository
  is a hard refusal, at install and at start, whatever was accepted.
- An acceptance covers the add-on it was given for: not another add-on, not the core.
- The acceptance is recorded only once the add-on is registered; a failed install
  leaves nothing accepted. `addon uninstall` forgets it.
- The audit row names who confirmed it on the host.
- `upgrade` checks the images of the active add-ons in stage 0, before anything is
  backed up, stopped or moved; a refused start in the second phase is reported like
  any other failed start.
- `addon upgrade`, `addon rollback` and `restore` accept `--insecure-images` for the
  check they run.

Helpers (fake registry, signed bills of materials, shell harnesses) come from the
other test modules.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import test_addon_upgrade_cli as addon_cli
import test_backup_scoped_cli as backup_cli
from test_images import (
    BASH,
    D2,
    D3,
    ENTRIES,
    KEYCLOAK,
    LIFECYCLE,
    REPO,
    UPGRADE,
    FakeRegistry,
    _audit_rows,
    _bom,
    _config,
    _core,
    _images_file,
    _new_keypair,
)
from test_images_trust import (
    _ANCHOR,
    _COMMIT,
    _CORRELATION,
    _START,
    ADDON_SH,
    WIKI,
    _addon_dir,
    _shell,
)

from lib import cli, images

_PROBE = "probe"


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path)


# ── what can be accepted ─────────────────────────────────────────────────────


def test_another_tag_of_a_listed_repository_is_a_hard_refusal(keypair):
    bom = _bom(keypair[1], ENTRIES)
    ref = f"{KEYCLOAK}:9.9.9@{D3}"
    problems = images.verify_images([ref], bom, registry=FakeRegistry())
    assert len(problems) == 1 and not problems[0].unlisted
    assert "repository" in problems[0].reason
    parsed = images.parse_ref(ref)
    accepted = {(parsed.registry, parsed.repository, D3)}
    again = images.verify_images([ref], bom, registry=FakeRegistry(), accepted=accepted)
    assert len(again) == 1 and not again[0].unlisted


def test_an_untagged_unlisted_digest_of_a_listed_repository_is_a_hard_refusal(keypair):
    bom = _bom(keypair[1], ENTRIES)
    ref = f"{KEYCLOAK}@{D3}"
    parsed = images.parse_ref(ref)
    accepted = {(parsed.registry, parsed.repository, D3)}
    problems = images.verify_images([ref], bom, registry=FakeRegistry(), accepted=accepted)
    assert len(problems) == 1 and not problems[0].unlisted


def _install(root, config, addon, refs_file, *extra):
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     "--command=addon-install", f"--addon={_PROBE}", f"--addon-path={addon}",
                     f"--addon-images={_PROBE}={refs_file}", *extra])


def _start(root, config, *extra):
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-verify",
                     "--command=start", *extra])


@pytest.mark.parametrize("ref", [f"{KEYCLOAK}:9.9.9@{D3}", f"{KEYCLOAK}@{D3}"])
def test_a_listed_repository_cannot_be_accepted_at_install(tmp_path, keypair, monkeypatch,
                                                          ref, capsys):
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    pending = tmp_path / "pending.txt"
    refs = _images_file(tmp_path, [ref])
    assert _install(root, config, addon, refs, "--accept-unlisted-images",
                    f"--pending-file={pending}") == 2
    assert "repository" in capsys.readouterr().err
    assert _audit_rows(config) == []
    assert not (config / images.ACCEPTED_PATH).exists()
    assert not pending.exists() or pending.read_text("utf-8").strip() == ""


def _write_accepted(config: Path, addon: str, refs: list[str]) -> None:
    path = config / images.ACCEPTED_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": images.ACCEPTED_SCHEMA, "images": {addon: refs}}),
                    "utf-8")


def test_an_accepted_digest_of_a_listed_repository_does_not_pass_at_start(
    tmp_path, keypair, monkeypatch
):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    ref = f"{KEYCLOAK}:9.9.9@{D3}"
    _write_accepted(config, _PROBE, [ref])
    refs = _images_file(tmp_path, [ref])
    assert _start(root, config, f"--addon-images={_PROBE}={refs}") == 2


# ── whom an acceptance covers ────────────────────────────────────────────────


def test_an_acceptance_covers_only_its_own_add_on(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    ref = f"{WIKI}:1.0.0@{D3}"
    _write_accepted(config, _PROBE, [ref])
    refs = _images_file(tmp_path, [ref])
    assert _start(root, config, f"--addon-images={_PROBE}={refs}") == 0
    assert _start(root, config, f"--addon-images=other={refs}") == 2
    # Not for the core either.
    assert _start(root, config, f"--images-file={refs}") == 2


def test_addon_images_names_are_validated(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _start(root, config, f"--addon-images=../x={refs}") == 2
    assert _start(root, config, f"--addon-images={refs}") == 2


def test_a_mirrored_acceptance_matches_at_start(tmp_path, keypair, monkeypatch):
    """The acceptance is recorded under the name the bill of materials would list,
    not under the mirror the image is pulled through."""
    root = _core(tmp_path, keypair)
    config = _config(tmp_path, "PAPAIA_IMAGE_MIRROR=registry.example.com/papaia/\n")
    addon = _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"registry.example.com/papaia/{WIKI}:1.0.0@{D3}"])
    pending = tmp_path / "pending.txt"
    assert _install(root, config, addon, refs, "--accept-unlisted-images",
                    f"--pending-file={pending}") == 0
    assert _accept(root, config, pending) == 0
    assert images._accepted_doc(config)["images"][_PROBE] == [f"{WIKI}:1.0.0@{D3}"]
    assert _start(root, config, f"--addon-images={_PROBE}={refs}") == 0


# ── when an acceptance is recorded ───────────────────────────────────────────


def _accept(root, config, pending, *extra):
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-accept",
                     f"--addon={_PROBE}", f"--pending-file={pending}",
                     f"--correlation-id={_CORRELATION}", *extra])


def test_the_check_at_install_records_nothing_until_the_add_on_is_registered(
    tmp_path, keypair, monkeypatch
):
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    pending = tmp_path / "pending.txt"
    assert _install(root, config, addon, refs, "--accept-unlisted-images",
                    f"--pending-file={pending}") == 0
    assert _audit_rows(config) == []
    assert not (config / images.ACCEPTED_PATH).exists()
    assert pending.read_text("utf-8").split() == [f"{WIKI}:1.0.0@{D3}"]

    assert _accept(root, config, pending) == 0
    rows = _audit_rows(config)
    assert len(rows) == 1 and rows[0]["event"] == "addon_images_accepted"
    assert rows[0]["correlation_id"] == _CORRELATION
    assert rows[0]["detail"]["images"] == [f"{WIKI}:1.0.0@{D3}"]
    assert rows[0]["detail"]["confirmed_by"]
    assert images._accepted_doc(config)["images"][_PROBE] == [f"{WIKI}:1.0.0@{D3}"]


def test_confirmation_without_a_pending_file_is_refused(tmp_path, keypair, monkeypatch):
    root, config, addon = _core(tmp_path, keypair), _config(tmp_path), _addon_dir(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda **_: FakeRegistry())
    refs = _images_file(tmp_path, [f"{WIKI}:1.0.0@{D3}"])
    assert _install(root, config, addon, refs, "--accept-unlisted-images") == 2
    assert _audit_rows(config) == []


def test_image_accept_checks_the_pending_images_again(tmp_path, keypair):
    """The pending file is input like any other: a listed repository or an unpinned
    image in it is refused, and nothing is recorded."""
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    for bad in (f"{KEYCLOAK}:9.9.9@{D3}", f"{WIKI}:1.0.0", "not a reference"):
        pending = tmp_path / "pending.txt"
        pending.write_text(f"{WIKI}:1.0.0@{D2}\n{bad}\n", "utf-8")
        assert _accept(root, config, pending) == 2, bad
    assert _audit_rows(config) == []
    assert not (config / images.ACCEPTED_PATH).exists()


def test_image_accept_forget_drops_the_add_on_with_an_audit_row(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    _write_accepted(config, _PROBE, [f"{WIKI}:1.0.0@{D3}"])
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-accept",
                     f"--addon={_PROBE}", "--forget"]) == 0
    assert images._accepted_doc(config)["images"] == {}
    rows = _audit_rows(config)
    assert len(rows) == 1 and rows[0]["event"] == "addon_images_forgotten"
    # Nothing accepted: nothing to forget, no row.
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config), "image-accept",
                     f"--addon={_PROBE}", "--forget"]) == 0
    assert len(_audit_rows(config)) == 1


def test_the_acceptance_row_names_who_confirmed_it(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "alice")
    row = images.acceptance_row(_PROBE, [f"{WIKI}:1.0.0@{D3}"], _CORRELATION)
    assert row["detail"]["confirmed_by"] == "alice"
    monkeypatch.setenv("SUDO_USER", "x; rm -rf /")
    row = images.acceptance_row(_PROBE, [f"{WIKI}:1.0.0@{D3}"], _CORRELATION)
    assert row["detail"]["confirmed_by"] != "x; rm -rf /"


def _install_shell(tmp_path: Path, *, install_rc: int, verify: int = 0):
    path = (tmp_path / "addons" / "wiki").as_posix()
    call = (f"cmd_addon_install wiki --path={path} --accept-unlisted-images"
            " || echo install-failed=$?")
    script_patch = (
        # The check hands the accepted images over in the pending file.
        "image-verify) echo \"py_cli $*\"; for a in \"$@\"; do case \"$a\" in"
        " --pending-file=*) echo ref > \"${a#*=}\" ;; esac; done; return " + str(verify)
        + " ;;\n"
        "        addon-install) echo \"py_cli $*\"; return " + str(install_rc) + " ;;\n"
        "        image-accept) echo \"py_cli $*\"; return 0 ;;\n"
        "        new-correlation-id) echo " + _CORRELATION + "; return ;;\n"
        "        active-addons)"
    )
    return _shell_with(tmp_path, call, verify=verify,
                       patch=("        active-addons)", "        " + script_patch))


def _shell_with(tmp_path: Path, call: str, *, verify: int = 0, patch: tuple[str, str]):
    if BASH is None:
        pytest.skip("bash is not available")
    overrides = tmp_path / "config" / "overrides"
    overrides.mkdir(parents=True, exist_ok=True)
    addon = tmp_path / "addons" / "wiki"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n")
    script = (
        _START.replace(*patch)
        .replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@REF@", f"{WIKI}:1.0.0@{D3}")
        .replace("@VERIFY@", str(verify))
        .replace("@ADDON_NET@", "")
        .replace("@CALL@", call)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_addon_install_records_the_acceptance_after_the_registration(tmp_path):
    done = _install_shell(tmp_path, install_rc=0)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    install = next(i for i, c in enumerate(calls) if c.startswith("py_cli addon-install"))
    accept = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-accept"))
    assert verify < install < accept
    assert "--pending-file=" in calls[verify] and "--accept-unlisted-images" in calls[verify]
    assert f"--correlation-id={_CORRELATION}" in calls[verify]
    assert f"--correlation-id={_CORRELATION}" in calls[accept]
    assert "--addon=wiki" in calls[accept]


def test_a_failed_install_records_no_acceptance(tmp_path):
    done = _install_shell(tmp_path, install_rc=3)
    assert "install-failed" in done.stdout or done.returncode != 0
    assert not any(c.startswith("py_cli image-accept") for c in done.stdout.splitlines())


def test_addon_uninstall_forgets_the_acceptance(tmp_path):
    done, calls = addon_cli._run(tmp_path, "cmd_addon_uninstall paperless")
    assert done.returncode == 0, done.stderr
    uninstall = next(i for i, c in enumerate(calls) if c.startswith("py_cli addon-uninstall"))
    forget = next(i for i, c in enumerate(calls)
                  if c.startswith("py_cli image-accept") and "--forget" in c)
    assert uninstall < forget and "--addon=paperless" in calls[forget]


# ── upgrade: add-on images in stage 0, a refused start in phase 2 ───────────

_UPGRADE_ADDONS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@TMP@/config"
REPO_ROOT="@TMP@/repo"
COMPOSE_FILE="@TMP@/repo/src/docker-compose.yml"
BASH="@TMP@/next-phase"
error() { echo "ERROR: $*" >&2; }
warn() { echo "WARN: $*" >&2; }
info() { :; }
success() { :; }
usage() { :; }
is_tty() { return 1; }
source "@LIFECYCLE@"
source "@ADDON@"
source "@UPGRADE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_addon_path() { echo "@TMP@/addons/$1"; }
cmd_backup() { echo "backup"; LAST_BACKUP_ID=rp1; }
cmd_stop() { echo "stop $*"; }
cmd_setup() { echo "setup $*"; }
@CMD_START@
_upgrade_log() { echo "log $*"; }
docker() {
    case " $* " in
        *" config --images "*)
            local a prev="" env=""
            for a in "$@"; do [ "$prev" = --env-file ] && env="$a"; prev="$a"; done
            case "$env" in
                */addons/*) if grep -q '^WIKI_IMAGE=' "$env"; then
                    sed -n 's/^WIKI_IMAGE=//p' "$env"; return 0; fi ;;
            esac
            echo "@REF@" ;;
        *) echo "docker $*" ;;
    esac
}
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
        image-trust-anchor) echo "@TRUSTED@"; return ;;
        new-correlation-id) echo "@CORRELATION@"; return ;;
        active-addons) echo wiki; return ;;
        addon-override-files) return ;;
    esac
    echo "py_cli $*"
    case "$1" in
        upgrade-resolve)
            printf 'CURRENT\\t1.9.0\\nTARGET\\t1.10.0\\nTAG\\tv1.10.0\\nSTATUS\\tupgrade\\n' ;;
    esac
}
_py_cli_at() {
    echo "py_cli_at $*"
    case "$2" in
        image-verify)
            local a
            for a in "$@"; do
                case "$a" in --addon-images=*) sed 's/^/addon-listed /' "${a#*=*=}" ;; esac
            done
            return @VERIFY@ ;;
    esac
    return 0
}
@CALL@
"""


def _upgrade_addons(tmp_path: Path, call: str, *, verify: int = 0,
                    cmd_start: str = 'cmd_start() { echo "cmd_start $*"; }',
                    trusted: str = _ANCHOR):
    if BASH is None:
        pytest.skip("bash is not available")
    nxt = tmp_path / "next-phase"
    nxt.write_text('#!/bin/sh\necho "phase2 $*"\n', encoding="utf-8")
    nxt.chmod(0o755)
    (tmp_path / "config").mkdir(exist_ok=True)
    addon = tmp_path / "addons" / "wiki"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n")
    script = (
        _UPGRADE_ADDONS.replace("@CMD_START@", cmd_start)
        .replace("@CALL@", call)
        .replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@REF@", f"{WIKI}:1.0.0@{D3}")
        .replace("@VERIFY@", str(verify))
        .replace("@TRUSTED@", trusted)
        .replace("@CORRELATION@", _CORRELATION)
        .replace("@COMMIT@", _COMMIT)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_upgrade_checks_the_active_add_ons_in_stage_0(tmp_path):
    done = _upgrade_addons(tmp_path, "cmd_upgrade -y")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if "image-verify" in c)
    assert "--from-checkout" in calls[verify] and "--addon-images=wiki=" in calls[verify]
    assert f"addon-listed {WIKI}:1.0.0@{D3}" in calls
    assert verify < calls.index("backup")


def test_upgrade_with_a_refused_add_on_image_stops_in_stage_0(tmp_path):
    done = _upgrade_addons(tmp_path, "cmd_upgrade -y", verify=2)
    assert done.returncode == 2
    calls = done.stdout.splitlines()
    assert "backup" not in calls
    assert not any(c.startswith(("stop", "phase2", "cmd_start")) for c in calls)
    log = (tmp_path / "git.log").read_text("utf-8")
    assert "checkout --detach" not in log


def test_a_refused_start_in_the_second_phase_is_reported_as_a_failed_start(tmp_path):
    done = _upgrade_addons(
        tmp_path,
        f"cmd_upgrade --resume-from=1.9.0 --resume-target=1.10.0 "
        f"--resume-restore-point=rp1 --resume-anchor={_ANCHOR}",
        cmd_start='cmd_start() { echo "cmd_start $*"; exit 2; }',
    )
    assert done.returncode != 0
    assert any(c.startswith("log 1.9.0 1.10.0 failed") and "stage=start" in c
               for c in done.stdout.splitlines())
    assert "papaia-ctl restore --restore-point=rp1" in done.stderr


def test_the_second_phase_without_an_anchor_names_the_key_it_trusted(tmp_path):
    """The first upgrade from a core that pinned no key: the target's own key is all
    there is. The operator is shown its fingerprint to compare out of band."""
    done = _upgrade_addons(
        tmp_path, "cmd_upgrade --resume-from=1.9.0 --resume-target=1.10.0",
        trusted="sha256:" + "b" * 64,
    )
    assert done.returncode == 0, done.stderr
    assert "sha256:" + "b" * 64 in done.stderr
    assert "out of band" in done.stderr


def test_start_returns_on_a_refused_image_check(tmp_path):
    """cmd_start reports a refused check by its status, so a caller like the upgrade
    can still run its own failure handling."""
    done = _shell(tmp_path, "cmd_start --addons || echo start-returned=$?", verify=2)
    assert done.returncode == 0, done.stderr
    assert "start-returned=2" in done.stdout.splitlines()


# ── the add-on env a start checks is the one `up` uses ──────────────────────

_BUNDLE_IMAGE = f"{WIKI}:2.0.0@{D2}"


def _bundle_env(tmp_path: Path) -> None:
    """The checkout .env still names the old pin; the bundle .env, which `start`
    materialises over it before `up`, names another digest."""
    checkout = tmp_path / "addons" / "wiki"
    checkout.mkdir(parents=True, exist_ok=True)
    (checkout / ".env").write_text(f"WIKI_IMAGE={WIKI}:1.0.0@{D3}\n", "utf-8")
    bundle = tmp_path / "config" / "addons" / "wiki"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / ".env").write_text(f"WIKI_IMAGE={_BUNDLE_IMAGE}\n", "utf-8")


def _addon_listed(calls: list[str]) -> list[str]:
    return [c.removeprefix("addon-listed ") for c in calls if c.startswith("addon-listed ")]


def test_start_checks_the_add_on_image_of_the_bundle_env(tmp_path):
    _bundle_env(tmp_path)
    done = _shell(tmp_path, "cmd_start --addons")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert _addon_listed(calls) == [_BUNDLE_IMAGE]
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    assert verify < next(i for i, c in enumerate(calls) if " up " in c)
    # `up` reads the checkout .env, which now holds what was checked.
    checkout = (tmp_path / "addons" / "wiki" / ".env").read_text("utf-8")
    assert checkout == f"WIKI_IMAGE={_BUNDLE_IMAGE}\n"


def test_start_refuses_a_bundle_image_before_any_up(tmp_path):
    _bundle_env(tmp_path)
    done = _shell(tmp_path, "cmd_start --addons", verify=2)
    assert done.returncode == 2
    calls = done.stdout.splitlines()
    assert _addon_listed(calls) == [_BUNDLE_IMAGE]
    assert not any(" up " in c for c in calls)


def test_a_distributed_start_checks_the_add_on_image_of_the_bundle_env(tmp_path):
    """The nodes start an add-on with the bundle .env (lib/node_shell.py)."""
    _bundle_env(tmp_path)
    done = _shell(tmp_path, "_cluster_require_unlocked() { :; }\n"
                            'CONFIG_DIR="$DEFAULT_CONFIG_DIR"\n'
                            "_start_distributed '' '' 1 0 0")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert _addon_listed(calls) == [_BUNDLE_IMAGE]
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    assert verify < next(i for i, c in enumerate(calls) if c.startswith("py_cli cluster-start"))


def test_a_refused_bundle_image_stops_a_distributed_start(tmp_path):
    _bundle_env(tmp_path)
    done = _shell(tmp_path, "_cluster_require_unlocked() { :; }\n"
                            'CONFIG_DIR="$DEFAULT_CONFIG_DIR"\n'
                            "_start_distributed '' '' 1 0 0", verify=2)
    assert done.returncode == 2
    assert not any(c.startswith("py_cli cluster-start") for c in done.stdout.splitlines())


def test_upgrade_stage_0_checks_the_add_on_image_of_the_bundle_env(tmp_path):
    _bundle_env(tmp_path)
    done = _upgrade_addons(tmp_path, "cmd_upgrade -y")
    assert done.returncode == 0, done.stderr
    listed = [c for c in done.stdout.splitlines() if c.startswith("addon-listed ")]
    assert listed == [f"addon-listed {_BUNDLE_IMAGE}"]


# ── addon uninstall with a damaged acceptance file ──────────────────────────


def test_addon_uninstall_survives_a_damaged_acceptance_file(tmp_path):
    """The add-on is already deregistered when the acceptance is forgotten: a file that
    cannot be read is a warning naming it, not a failed uninstall."""
    config = tmp_path / "config"
    (config / "trust").mkdir(parents=True)
    damaged = config / "trust" / "accepted-images.json"
    damaged.write_text("{not json", "utf-8")
    tools = Path(cli.__file__).resolve().parents[1]
    body = (
        'eval "$(declare -f py_cli | sed \'1s/^py_cli/_harness_py_cli/\')"\n'
        "py_cli() {\n"
        '    if [ "$1" = image-accept ]; then\n'
        '        echo "py_cli $*" >> "' + (tmp_path / "calls.log").as_posix() + '"\n'
        '        PYTHONPATH="' + tools.as_posix() + '" "' + sys.executable + '" -m lib.cli'
        ' --repo-root "$REPO_ROOT" --config-dir "$CONFIG_DIR" "$@"\n'
        "    else\n"
        '        _harness_py_cli "$@"\n'
        "    fi\n"
        "}\n"
        "cmd_addon_uninstall paperless\n"
    )
    done, calls = addon_cli._run(tmp_path, body)
    assert done.returncode == 0, done.stderr
    assert any(c.startswith("py_cli addon-uninstall") for c in calls)
    assert any(c.startswith("py_cli image-accept") and "--forget" in c for c in calls)
    assert damaged.as_posix() in done.stderr
    assert "OK: addon uninstall complete: paperless" in done.stdout


# ── --insecure-images for every command that checks ─────────────────────────


def _image_calls(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("image-verify")]


def _insecure(call: str) -> str:
    """The --insecure-images switch of a logged `_verify_images` call: command, core
    tree, list (empty for an add-on), whole tree, switch."""
    return call.split(" ")[5]


def test_addon_upgrade_passes_insecure_images_to_the_check(tmp_path):
    done, calls = addon_cli._run(
        tmp_path, "cmd_addon_upgrade paperless --path=/v2/paperless -y --insecure-images")
    assert done.returncode == 0, done.stderr
    checks = _image_calls(calls)
    assert len(checks) == 1
    assert checks[0].startswith("image-verify addon-upgrade ")
    assert _insecure(checks[0]) == "1"


def test_addon_upgrade_without_the_flag_checks(tmp_path):
    done, calls = addon_cli._run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/paperless -y")
    assert done.returncode == 0, done.stderr
    assert _insecure(_image_calls(calls)[0]) == "0"


def test_addon_rollback_passes_insecure_images_to_the_check(tmp_path):
    done, calls = addon_cli._run(tmp_path, "cmd_addon_rollback paperless -y --insecure-images")
    assert done.returncode == 0, done.stderr
    checks = _image_calls(calls)
    assert len(checks) == 1 and checks[0].startswith("image-verify addon-rollback ")
    assert _insecure(checks[0]) == "1"


def test_addon_rollback_with_data_passes_insecure_images_to_the_restore(tmp_path):
    done, calls = addon_cli._run(
        tmp_path, "cmd_addon_rollback paperless --restore-data -y --insecure-images")
    assert done.returncode == 0, done.stderr
    restore = next(c for c in calls if c.startswith("cmd_restore_scoped"))
    assert "--insecure-images" in restore


def _restore(tmp_path: Path, args: str):
    snapshot = tmp_path / "backups" / "2026-10-25_10-00-00"
    snapshot.mkdir(parents=True, exist_ok=True)
    addon = tmp_path / "addons" / "paperless"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", "utf-8")
    py_cli = f"""
    case "$1" in
        restore-resolve)
            printf 'SNAPSHOT\\t{snapshot.as_posix()}\\nID\\t2026-10-25_10-00-00\\n'
            printf 'ADDONS\\tpaperless\\nPROFILES\\tlibrechat\\n'
            printf 'volume\\tvolumes/paperless_pgdata.tar.gz\\t'
            printf 'paperless_pgdata\\taddon:paperless\\n'
            ;;
    esac
    """
    body = f"""
_restore_teardown() {{ :; }}
_restore_teardown_scoped() {{ :; }}
_restore_artifact() {{ return 0; }}
_containers_using_volume() {{ :; }}
_backup_log() {{ :; }}
_verify_images() {{ echo "image-verify $*" >> "{(tmp_path / 'calls.log').as_posix()}"; }}
cmd_start() {{ echo "cmd_start $*" >> "{(tmp_path / 'calls.log').as_posix()}"; }}
cmd_restore {args} -y
"""
    return backup_cli._run(tmp_path, body, py_cli=py_cli)


def test_a_full_restore_passes_insecure_images_to_the_start(tmp_path):
    done, calls = _restore(tmp_path, "--insecure-images")
    assert done.returncode == 0, done.stderr
    start = next(c for c in calls if c.startswith("cmd_start"))
    assert "--addons" in start and "--insecure-images" in start


def test_a_full_restore_without_the_flag_starts_with_the_check(tmp_path):
    done, calls = _restore(tmp_path, "")
    assert done.returncode == 0, done.stderr
    start = next(c for c in calls if c.startswith("cmd_start"))
    assert "--insecure-images" not in start


def test_a_scoped_restore_passes_insecure_images_to_both_checks(tmp_path):
    done, calls = _restore(tmp_path, "--only=addon:paperless --insecure-images")
    assert done.returncode == 0, done.stderr
    checks = _image_calls(calls)
    assert len(checks) == 1 and checks[0].startswith("image-verify restore ")
    assert _insecure(checks[0]) == "1"
    start = next(c for c in calls if c.startswith("cmd_start"))
    assert "--profiles=librechat" in start and "--insecure-images" in start


def test_the_usage_and_readme_name_the_flag_for_every_command_that_checks():
    header = (REPO / "tools" / "papaia-ctl").read_text("utf-8")
    readme = (REPO / "README.md").read_text("utf-8")
    for command in ("addon upgrade", "addon rollback", "restore "):
        block = header[header.index(f"papaia-ctl {command}"):]
        block = block[:block.index("\n#   papaia-ctl", 1)]
        assert "--insecure-images" in block, command
        rdm = readme[readme.index(f"tools/papaia-ctl {command}"):]
        rdm = rdm[:rdm.index("\n```") if command == "restore " else rdm.index("\ntools/", 1)]
        assert "--insecure-images" in rdm, command


# ── documented limits of the trust anchor ────────────────────────────────────


def test_the_docs_state_that_a_rotation_cannot_be_revoked():
    text = (REPO / "docs" / "compatibility.md").read_text("utf-8")
    assert "cannot be revoked" in text
    assert "never" in text and "rotated to again" in text


def test_the_docs_state_the_bootstrap_upgrade():
    text = (REPO / "docs" / "compatibility.md").read_text("utf-8")
    assert "out of band" in text and "first upgrade" in text


def test_the_readme_names_the_host_operator_as_the_confirming_admin():
    text = (REPO / "README.md").read_text("utf-8")
    assert "papaia-admin" in text and "confirmed_by" in text


# ── registry redirects: no fixed ports ───────────────────────────────────────


def test_the_redirect_test_binds_no_fixed_port():
    text = (REPO / "tools" / "tests" / "test_images_trust.py").read_text("utf-8")
    assert 'HTTPServer(("127.0.0.1", 0)' in text
    assert "_serve(5" not in text

