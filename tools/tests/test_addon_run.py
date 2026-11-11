"""`papaia-ctl addon run <addon> <action>` (cmd_addon_run, #318).

py_cli and docker are replaced by functions: py_cli answers like `addon-action` (the
service and its fixed arguments, NUL-separated) or refuses with exit 2, and docker logs
its arguments and exits with a chosen code. What is checked is the exact `docker
compose run` that runs, that its exit code comes back, and that nothing runs when the
action is refused.
"""

from __future__ import annotations

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
source "@ADDON@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@REPO@"
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; }
success() { :; }
usage() { :; }
_require_setup_done() { :; }
_topology_mode() { echo single; }
_addon_path() { echo "@ADDON_PATH@"; }
py_cli() {
    case "$1" in
        addon-action)
            [ "@SPEC@" = "refuse" ] && { echo "ERROR: declares no action" >&2; return 2; }
            printf 'job\\0--reset-existing\\0two words\\0'
            ;;
        addon-actions) echo "LIST $*" ;;
        addon-override-files) : ;;
    esac
}
docker() {
    printf '%s|' "$@" >> "@LOG@"; echo >> "@LOG@"
    return @RC@
}
"""


def _run(
    tmp_path: Path, *args: str, spec: str = "ok", rc: int = 0
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    addon = tmp_path / "addons" / "wiki"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@REPO@", tmp_path.as_posix())
        .replace("@ADDON_PATH@", addon.as_posix())
        .replace("@SPEC@", spec)
        .replace("@RC@", str(rc))
        .replace("@LOG@", log.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
    )
    quoted = " ".join(f"'{a}'" for a in args)
    done = subprocess.run(
        [BASH, "-c", f"{harness}\ncmd_addon_run {quoted}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return done, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def test_runs_the_declared_service_with_its_fixed_arguments(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "wiki", "reset")
    assert done.returncode == 0, done.stderr
    assert len(calls) == 1
    # Project pinned like `addon start`; arguments with spaces stay one argument.
    assert calls[0].startswith("compose|-p|wiki|-f|")
    assert calls[0].endswith("|run|--rm|job|--reset-existing|two words|")


def test_passes_the_action_exit_code_through(tmp_path: Path) -> None:
    done, _ = _run(tmp_path, "wiki", "check", rc=3)
    assert done.returncode == 3


def test_an_undeclared_action_runs_nothing(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "wiki", "nope", spec="refuse")
    assert done.returncode == 2
    assert calls == []


def test_without_an_action_lists_the_declared_ones(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "wiki", "--json")
    assert done.returncode == 0, done.stderr
    assert "LIST addon-actions --name=wiki --json" in done.stdout
    assert calls == []


def test_refuses_free_arguments_after_the_action(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "wiki", "reset", "rm -rf /")
    assert done.returncode == 2
    assert calls == []
