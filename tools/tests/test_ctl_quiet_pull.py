"""`--quiet-pull` on `docker compose up` when stderr is not a terminal.

Without a terminal, Compose prints one line per progress event of every layer it pulls,
and papaia-manager reads a fixed tail of its runner logs. Docker is replaced by a function
that logs its calls; stderr is either a pipe (as in a runner container) or a pseudo
terminal (as for an operator in a shell).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
ADDON = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")

pytestmark = [
    pytest.mark.skipif(BASH is None, reason="bash is not available"),
    pytest.mark.skipif(os.name == "nt", reason="needs a pseudo terminal"),
]

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
CONFIG_DIR="@CONFIG@"
REPO_ROOT="@REPO@"
COMPOSE_FILE="@REPO@/src/docker-compose.yml"
error() { echo "ERROR: $*" >> "@LOG@"; }
info() { echo "INFO: $*" >> "@LOG@"; }
warn() { :; }
success() { :; }
usage() { :; }
py_cli() {
    case "$1" in
        active-addons) echo crm ;;
    esac
}
docker() {
    case "$1" in
        info) return 0 ;;
    esac
    echo "docker $*" >> "@LOG@"
}
source "@LIFECYCLE@"
source "@ADDON@"
# After the libraries, which define the real ones.
_require_setup_done() { :; }
_addon_path() { echo "@REPO@/addons/$1"; }
"""


def _run(tmp_path: Path, command: str, *, terminal: bool) -> list[str]:
    assert BASH is not None
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    addon = tmp_path / "addons" / "crm"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@REPO@", tmp_path.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@ADDON@", ADDON.as_posix())
    )
    if terminal:
        primary, secondary = os.openpty()
        try:
            done = subprocess.run(
                [BASH, "-c", f"{harness}\n{command}"],
                stdout=subprocess.PIPE,
                stderr=secondary,
                text=True,
                timeout=30,
                check=False,
            )
        finally:
            os.close(secondary)
            os.close(primary)
    else:
        done = subprocess.run(
            [BASH, "-c", f"{harness}\n{command}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    assert done.returncode == 0, (done.stdout, done.stderr, log.read_text(encoding="utf-8"))
    return log.read_text(encoding="utf-8").splitlines()


def _ups(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("docker compose") and " up " in f"{c} "]


def test_start_without_a_terminal_pulls_quietly_and_says_so(tmp_path: Path) -> None:
    calls = _run(tmp_path, "cmd_start --addons", terminal=False)

    ups = _ups(calls)
    assert len(ups) == 2  # the add-on, then the core
    assert all(c.endswith(" --quiet-pull") for c in ups), ups
    assert any("without progress output" in c for c in calls)


def test_start_in_a_terminal_keeps_the_progress(tmp_path: Path) -> None:
    calls = _run(tmp_path, "cmd_start --addons", terminal=True)

    ups = _ups(calls)
    assert len(ups) == 2
    assert not any("--quiet-pull" in c for c in ups), ups
    assert not any("without progress output" in c for c in calls)


@pytest.mark.parametrize("terminal", [False, True])
def test_an_addon_recreate_follows_the_same_rule(tmp_path: Path, terminal: bool) -> None:
    calls = _run(tmp_path, "_addon_recreate crm", terminal=terminal)

    [up] = _ups(calls)
    assert " up -d --remove-orphans" in up
    assert ("--quiet-pull" in up) is not terminal
