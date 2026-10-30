"""The bash half of `addon upgrade | rollback | list`, with `py_cli`, `docker` and the
backup and restore verbs replaced by functions that record what they were called with.

What is checked is the order bash does things in and what it refuses to do: nothing
reaches a backup or the registration before the plan step has said yes, a failed
restore point stops the upgrade, the answers travel by file, the containers are
recreated only when they were running. What the plan says is covered by
test_addon_upgrade.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo USAGE; }
is_tty() { return 1; }
_require_setup_done() { :; }
_topology_mode() { echo single; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    case "$1" in
        addon-path) echo "@ADDON_PATH@" ;;
        addon-override-files) ;;
        addon-upgrade-plan)
            for a in "$@"; do
                case "$a" in --answers-out=*) echo "KEY=secret-value" > "${a#*=}" ;; esac
            done
            echo "PLAN"
            return @PLAN_RC@
            ;;
        addon-upgrade-apply)
            for a in "$@"; do
                case "$a" in --answers-file=*) cp "${a#*=}" "@LOG@.answers" ;; esac
            done
            return @APPLY_RC@
            ;;
        addon-rollback-plan)
            printf 'FROM\\t1.1.0\\nTO\\t1.0.0\\nPATH\\t@ADDON_PATH@\\nRESTORE_POINT\\t@POINT@\\n'
            return @PLAN_RC@
            ;;
        restore-resolve) return @RESOLVE_RC@ ;;
        *) ;;
    esac
}
docker() {
    echo "docker $*" >> "@LOG@"
    case " $* " in
        *" ps "*) [ "@RUNNING@" = 1 ] && echo abc123 || true ;;
        *" up "*) return @UP_RC@ ;;
    esac
}
cmd_backup() {
    echo "cmd_backup $*" >> "@LOG@"
    case "@BACKUP_RC@" in
        0) LAST_BACKUP_ID="2026-10-25_10-00-00" ;;
        *) exit @BACKUP_RC@ ;;
    esac
}
cmd_restore_scoped() { echo "cmd_restore_scoped $*" >> "@LOG@"; }
source "@ADDON@"
"""

_DEFAULTS = {
    "PLAN_RC": "0",
    "APPLY_RC": "0",
    "BACKUP_RC": "0",
    "RESOLVE_RC": "0",
    "UP_RC": "0",
    "RUNNING": "1",
    "POINT": "2026-10-25_10-00-00",
}


def _run(tmp_path: Path, body: str, **overrides: str) -> tuple[
    subprocess.CompletedProcess[str], list[str]
]:
    assert BASH is not None
    settings = {**_DEFAULTS, **overrides}
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    addon = tmp_path / "addons" / "paperless"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "root" / "src").mkdir(parents=True, exist_ok=True)
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@ROOT@", (tmp_path / "root").as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@ADDON_PATH@", addon.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
    )
    for key, value in settings.items():
        harness = harness.replace(f"@{key}@", value)
    done = subprocess.run(
        [BASH, "-c", f"{harness}\n{body}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return done, log.read_text(encoding="utf-8").splitlines()


def _verbs(calls: list[str]) -> list[str]:
    """The calls reduced to their first two words, in order."""
    return [" ".join(c.split()[:2]) for c in calls]


# ── upgrade ───────────────────────────────────────────────────────────────────


def test_a_dry_run_only_asks_for_the_plan(tmp_path: Path) -> None:
    done, calls = _run(
        tmp_path, "cmd_addon_upgrade paperless --path=/v2/paperless --dry-run --json"
    )

    assert done.returncode == 0, done.stderr
    assert calls == ["py_cli addon-upgrade-plan --name=paperless --path=/v2/paperless --json"]


def test_a_dry_run_hands_the_gate_override_on(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --dry-run --force")

    assert calls == ["py_cli addon-upgrade-plan --name=paperless --path=/v2/p --force"]


def test_a_refused_dry_run_exits_with_the_status_of_the_plan(tmp_path: Path) -> None:
    done, _ = _run(
        tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --dry-run --json", PLAN_RC="2"
    )

    assert done.returncode == 2


def test_json_without_a_dry_run_is_refused_before_anything_runs(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --json -y")

    assert done.returncode == 2
    assert "--dry-run" in done.stderr
    assert calls == []


@pytest.mark.parametrize("args", ["", "paperless", "--path=/v2/p"])
def test_the_name_and_the_path_are_both_required(tmp_path: Path, args: str) -> None:
    done, calls = _run(tmp_path, f"cmd_addon_upgrade {args}")

    assert done.returncode == 2
    assert "Usage: papaia-ctl addon upgrade" in done.stderr
    assert calls == []


def test_an_upgrade_plans_backs_up_applies_and_recreates_in_that_order(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/paperless -y")

    assert done.returncode == 0, done.stderr
    assert _verbs(calls) == [
        "py_cli addon-upgrade-plan",
        "py_cli addon-path",
        "docker compose",  # ps: is it running?
        "cmd_backup --only=addon:paperless",
        "py_cli addon-upgrade-apply",
        "py_cli addon-path",
        "docker compose",  # up
    ]
    apply_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-apply"))
    assert "--restore-point=2026-10-25_10-00-00" in apply_call
    assert "--path=/v2/paperless" in apply_call
    up = calls[-1]
    assert " up -d --remove-orphans" in up
    assert "-p paperless" in up
    assert "OK: addon upgrade complete: paperless" in done.stdout
    assert "Restore point: 2026-10-25_10-00-00" in done.stdout


def test_the_answers_travel_in_a_private_file_and_are_gone_afterwards(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y")

    assert done.returncode == 0, done.stderr
    assert not any("secret-value" in c for c in calls)
    plan_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-plan"))
    apply_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-apply"))
    handed_in = plan_call.split("--answers-out=")[1].split()[0]
    assert f"--answers-file={handed_in}" in apply_call
    assert (tmp_path / "calls.log.answers").read_text(encoding="utf-8") == "KEY=secret-value\n"
    assert not Path(handed_in).exists()


def test_an_answers_file_of_the_caller_goes_to_the_plan_step(tmp_path: Path) -> None:
    _, calls = _run(
        tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --answers-file=/tmp/in -y"
    )

    plan_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-plan"))
    assert "--answers-file=/tmp/in" in plan_call
    apply_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-apply"))
    assert "/tmp/in" not in apply_call


def test_a_plan_that_says_no_stops_before_a_restore_point_is_taken(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", PLAN_RC="2")

    assert done.returncode == 2
    assert _verbs(calls) == ["py_cli addon-upgrade-plan"]


def test_without_a_terminal_an_upgrade_needs_the_flag_to_confirm(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p")

    assert done.returncode == 2
    assert "Re-run with -y" in done.stderr
    assert _verbs(calls) == ["py_cli addon-upgrade-plan"]


def test_no_backup_skips_the_restore_point_and_says_so(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --no-backup -y")

    assert done.returncode == 0, done.stderr
    assert not any(c.startswith("cmd_backup") for c in calls)
    apply_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-apply"))
    assert "--restore-point" not in apply_call
    assert "no restore point is created" in done.stderr


def test_an_add_on_without_data_is_upgraded_without_a_restore_point(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", BACKUP_RC="2")

    assert done.returncode == 0, done.stderr
    assert "no volumes or data directories" in done.stderr
    apply_call = next(c for c in calls if c.startswith("py_cli addon-upgrade-apply"))
    assert "--restore-point" not in apply_call


def test_a_failed_restore_point_stops_the_upgrade_before_anything_is_changed(
    tmp_path: Path,
) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", BACKUP_RC="3")

    assert done.returncode == 3
    assert "Nothing was changed" in done.stderr
    assert not any(c.startswith("py_cli addon-upgrade-apply") for c in calls)


def test_an_add_on_that_was_not_running_is_not_started(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", RUNNING="0")

    assert done.returncode == 0, done.stderr
    assert not any(" up " in c for c in calls)
    assert "was not running" in done.stdout


def test_no_restart_leaves_the_containers_alone(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p --no-restart -y")

    assert done.returncode == 0, done.stderr
    assert not any(c.startswith("docker") for c in calls)


def test_a_failed_recreate_is_reported_with_the_way_back_and_not_rolled_back(
    tmp_path: Path,
) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", UP_RC="1")

    assert done.returncode == 3
    assert "papaia-ctl addon rollback paperless" in done.stderr
    assert not any(c.startswith("py_cli addon-rollback") for c in calls)


def test_a_refused_apply_exits_with_its_status_and_recreates_nothing(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_upgrade paperless --path=/v2/p -y", APPLY_RC="2")

    assert done.returncode == 2
    assert not any(" up " in c for c in calls)


# ── rollback ─────────────────────────────────────────────────────────────────


def test_a_rollback_without_data_repoints_and_recreates(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless -y")

    assert done.returncode == 0, done.stderr
    assert _verbs(calls) == [
        "py_cli addon-rollback-plan",
        "py_cli addon-path",
        "docker compose",  # ps
        "py_cli addon-rollback-apply",
        "py_cli addon-path",
        "docker compose",  # up
    ]
    assert " up -d --remove-orphans" in calls[-1]
    assert "Its data is not touched" in done.stdout
    assert "--restore-data" in done.stdout
    assert not any(c.startswith("cmd_restore_scoped") for c in calls)
    assert "OK: addon rollback complete: paperless" in done.stdout


def test_a_rollback_with_data_restores_the_recorded_point_after_repointing(
    tmp_path: Path,
) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless --restore-data -y")

    assert done.returncode == 0, done.stderr
    verbs = _verbs(calls)
    assert verbs.index("py_cli restore-resolve") < verbs.index("py_cli addon-rollback-apply")
    restore_at = verbs.index("cmd_restore_scoped --only=addon:paperless")
    assert verbs.index("py_cli addon-rollback-apply") < restore_at
    restore = next(c for c in calls if c.startswith("cmd_restore_scoped"))
    assert "--restore-point=2026-10-25_10-00-00" in restore
    assert restore.endswith("-y")
    assert not any(" up " in c for c in calls), "restore-scoped starts the add-on itself"
    assert "reset to restore point 2026-10-25_10-00-00" in done.stderr


def test_a_rollback_with_data_and_no_recorded_point_is_refused_before_anything_changes(
    tmp_path: Path,
) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless --restore-data -y", POINT="")

    assert done.returncode == 2
    assert "No restore point was recorded" in done.stderr
    changed = ("py_cli addon-rollback-apply", "cmd_restore_scoped")
    assert not any(c.startswith(changed) for c in calls)


def test_a_restore_point_that_is_gone_stops_the_rollback_before_repointing(
    tmp_path: Path,
) -> None:
    done, calls = _run(
        tmp_path, "cmd_addon_rollback paperless --restore-data -y", RESOLVE_RC="3"
    )

    assert done.returncode == 3
    assert not any(c.startswith("py_cli addon-rollback-apply") for c in calls)


def test_restoring_data_cannot_be_combined_with_no_restart(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless --restore-data --no-restart -y")

    assert done.returncode == 2
    assert "--no-restart" in done.stderr
    assert calls == []


def test_a_rollback_without_a_previous_version_exits_2_and_goes_no_further(
    tmp_path: Path,
) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless -y", PLAN_RC="2")

    assert done.returncode == 2
    assert _verbs(calls) == ["py_cli addon-rollback-plan"]


def test_without_a_terminal_a_rollback_needs_the_flag_to_confirm(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless")

    assert done.returncode == 2
    assert "Re-run with -y" in done.stderr
    assert not any(c.startswith("py_cli addon-rollback-apply") for c in calls)


def test_a_rollback_of_a_stopped_add_on_starts_nothing(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_rollback paperless -y", RUNNING="0")

    assert done.returncode == 0, done.stderr
    assert not any(" up " in c for c in calls)


# ── list ─────────────────────────────────────────────────────────────────────


def test_list_passes_json_through(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_list --json")

    assert done.returncode == 0, done.stderr
    assert calls == ["py_cli addon-list --json"]


def test_list_rejects_unknown_options(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_list --verbose")

    assert done.returncode == 2
    assert calls == []


# ── names ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("args", "hint"),
    [
        (["update"], "papaia-ctl upgrade"),
        (["addon", "update", "paperless"], "papaia-ctl addon upgrade"),
    ],
)
def test_update_is_not_a_verb_and_points_at_upgrade(
    tmp_path: Path, args: list[str], hint: str
) -> None:
    done = subprocess.run(
        [BASH, str(TOOLS / "papaia-ctl"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PAPAIA_CONFIG_DIR": str(tmp_path)},
        check=False,
    )

    assert done.returncode == 2
    assert f"Did you mean '{hint}'?" in done.stdout + done.stderr
