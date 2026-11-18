"""The bash half of `addon uninstall --clean-up` with a clean-up action, and of the
LibreChat agent and prompt sync after `addon remove` / `addon uninstall`.

`py_cli` and `docker` are replaced by functions that log what they were called with.
What is checked is the order: the clean-up action runs before anything is taken down,
a failing one stops the uninstall unless --force, an add-on without one uninstalls as
before, and LibreChat's init scripts run once in a one-off container after an add-on
with agents or prompts is gone -- only while LibreChat runs, and never failing the
add-on command.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
SH = TOOLS / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
source "@SH@/lifecycle.sh"
source "@SH@/addon.sh"
source "@SH@/librechat.sh"
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/src/docker-compose.yml"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo USAGE; }
_require_setup_done() { :; }
_topology_mode() { echo @MODE@; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    case "$1" in
        addon-path) echo "@ADDON_PATH@" ;;
        addon-uninstall-action)
            [ "@SPEC@" = "refuse" ] && { echo "ERROR: malformed" >&2; return 2; }
            [ "@SPEC@" = "none" ] && return 0
            printf 'purge\\0job\\0purge\\0two words\\0'
            ;;
        addon-dependents) return 0 ;;
        *) ;;
    esac
}
docker() {
    echo "docker $*" >> "@LOG@"
    case " $* " in
        *" network inspect "*) return 0 ;;
        *" ps -q --status running librechat "*) [ "@RUNNING@" = 1 ] && echo abc123 || true ;;
        *" run --rm --no-deps "*) return @SYNC_RC@ ;;
        *" run "*) return @ACTION_RC@ ;;
    esac
}
"""

_DEFAULTS = {
    "MODE": "single",
    "SPEC": "ok",
    "ACTION_RC": "0",
    "SYNC_RC": "0",
    "RUNNING": "1",
}


def _run(
    tmp_path: Path, body: str, *, chat_content: bool = False, **overrides: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    settings = {**_DEFAULTS, **overrides}
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    addon = tmp_path / "addons" / "importer"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "root" / "src").mkdir(parents=True, exist_ok=True)
    config = tmp_path / "config"
    agents = config / "ai" / "librechat" / "addon-agents"
    agents.mkdir(parents=True, exist_ok=True)
    (agents / "other__helper.yaml").write_text("id: helper\n", encoding="utf-8")
    if chat_content:
        (agents / "importer__assistant.yaml").write_text("id: a\n", encoding="utf-8")
    harness = (
        _HARNESS.replace("@SH@", SH.as_posix())
        .replace("@CONFIG@", config.as_posix())
        .replace("@ROOT@", (tmp_path / "root").as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@ADDON_PATH@", addon.as_posix())
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
    return done, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def _index(calls: list[str], needle: str) -> int:
    return next(i for i, c in enumerate(calls) if needle in c)


# ── clean-up action ──────────────────────────────────────────────────────────


def test_clean_up_runs_the_action_before_anything_is_removed(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer --clean-up")

    assert done.returncode == 0, done.stderr
    action = _index(calls, " run --rm job purge two words")
    assert calls[action].startswith("docker compose -p importer -f ")
    assert action < _index(calls, " down -v")
    assert _index(calls, " down -v") < _index(calls, "py_cli addon-uninstall --name=importer")


def test_a_failing_action_stops_the_uninstall(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer --clean-up", ACTION_RC="4")

    assert done.returncode == 3
    assert "Nothing was removed" in done.stderr
    assert "papaia-ctl addon run importer purge" in done.stderr
    assert not any(" down" in c for c in calls)
    assert not any(c.startswith("py_cli addon-uninstall --name") for c in calls)


def test_force_uninstalls_past_a_failing_action(tmp_path: Path) -> None:
    done, calls = _run(
        tmp_path, "cmd_addon_uninstall importer --clean-up --force", ACTION_RC="4"
    )

    assert done.returncode == 0, done.stderr
    assert "failed (exit status 4)" in done.stderr
    assert any(" down -v" in c for c in calls)
    assert "py_cli addon-uninstall --name=importer" in calls


def test_an_addon_without_a_clean_up_action_uninstalls_as_before(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer --clean-up", SPEC="none")

    assert done.returncode == 0, done.stderr
    assert not any(" run " in c for c in calls)
    assert any(" down -v" in c for c in calls)


def test_without_clean_up_no_action_runs(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer")

    assert done.returncode == 0, done.stderr
    assert not any("addon-uninstall-action" in c for c in calls)
    assert not any(" run " in c for c in calls)


def test_a_malformed_actions_block_stops_the_uninstall(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer --clean-up", SPEC="refuse")

    assert done.returncode == 2
    assert not any(" down" in c for c in calls)
    assert not any(c.startswith("py_cli addon-uninstall --name") for c in calls)


def test_force_uninstalls_past_a_malformed_actions_block(tmp_path: Path) -> None:
    done, calls = _run(
        tmp_path, "cmd_addon_uninstall importer --clean-up --force", SPEC="refuse"
    )

    assert done.returncode == 0, done.stderr
    assert "py_cli addon-uninstall --name=importer" in calls


# ── LibreChat agents and prompts ─────────────────────────────────────────────


@pytest.mark.parametrize("verb", ["uninstall", "remove"])
def test_chat_content_is_synced_in_a_one_off_container(tmp_path: Path, verb: str) -> None:
    done, calls = _run(tmp_path, f"cmd_addon_{verb} importer", chat_content=True)

    assert done.returncode == 0, done.stderr
    sync = _index(calls, " run --rm --no-deps ")
    assert _index(calls, f"py_cli addon-{verb} --name=importer") < sync
    assert calls[sync].startswith("docker compose -f ")
    assert "--entrypoint /bin/sh librechat -c" in calls[sync]
    assert "agents-init.js" in calls[sync] and "prompts-init.js" in calls[sync]


def test_an_addon_without_chat_content_leaves_librechat_alone(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer")

    assert done.returncode == 0, done.stderr
    assert not any("librechat" in c for c in calls)


def test_a_stopped_librechat_is_not_touched(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_addon_uninstall importer", chat_content=True, RUNNING="0")

    assert done.returncode == 0, done.stderr
    assert not any(" run " in c for c in calls)
    assert "its next start removes" in done.stdout


def test_a_failed_sync_warns_and_the_uninstall_completes(tmp_path: Path) -> None:
    done, _ = _run(tmp_path, "cmd_addon_uninstall importer", chat_content=True, SYNC_RC="1")

    assert done.returncode == 0, done.stderr
    assert "papaia-ctl start" in done.stderr
    assert "OK: addon uninstall complete" in done.stdout


def test_a_distributed_installation_gets_the_restart_hint(tmp_path: Path) -> None:
    done, calls = _run(
        tmp_path, "_librechat_sync_addon_content importer", chat_content=True, MODE="distributed"
    )

    assert done.returncode == 0, done.stderr
    assert not any(c.startswith("docker") for c in calls)
    assert "papaia-ctl start" in done.stdout
