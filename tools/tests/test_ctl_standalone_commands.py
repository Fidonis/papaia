"""`npm-provision` and `keycloak-role-sync` as commands of their own.

`start` runs both after `docker compose up` and, when one fails, tells the operator to
run it again by name. Handed straight to `py_cli` by the dispatcher, a standalone call
died with `CONFIG_DIR: unbound variable`, because `py_cli` expands the variable that only
a command's own option parsing sets (`--config-dir=PATH` was never read either).

The behaviour is checked hermetically: `py_cli` is a stub that reports what it was called
with, so no Keycloak, no NPM and no configuration of the machine running the tests is
touched.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
CTL = TOOLS / "papaia-ctl"
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

# The shell state papaia-ctl has when a command runs: strict mode, the globals the
# entrypoint sets, `error` and `usage`, and a `py_cli` that only reports its call.
_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@DEFAULT@"
error() { echo "ERROR: $*" >&2; }
usage() { echo "USAGE"; }
py_cli() { echo "py_cli $* CONFIG_DIR=$CONFIG_DIR"; return "${STUB_RC:-0}"; }
source "@LIFECYCLE@"
"""

STEPS = ["npm-provision", "keycloak-role-sync"]
FUNCTIONS = {"npm-provision": "cmd_npm_provision", "keycloak-role-sync": "cmd_keycloak_role_sync"}


def _call(function: str, *args: str, default: Path | None = None, rc: int = 0):
    assert BASH is not None
    harness = _HARNESS.replace("@DEFAULT@", (default or Path("/no/such/default")).as_posix())
    harness = harness.replace("@LIFECYCLE@", LIFECYCLE.as_posix())
    quoted = " ".join(f"'{a}'" for a in args)
    return subprocess.run(
        [BASH, "-c", f"{harness}\nSTUB_RC={rc}\n{function} {quoted}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _seeded(path: Path) -> Path:
    """A configuration directory `_require_setup_done` accepts."""
    path.mkdir(parents=True, exist_ok=True)
    (path / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    (path / "deployment.yaml").write_text("core: {}\n", encoding="utf-8")
    return path


def test_the_dispatcher_never_hands_a_command_straight_to_py_cli():
    """py_cli expands CONFIG_DIR, which only a command's own option parsing sets."""
    dispatch = CTL.read_text(encoding="utf-8")
    offenders = re.findall(r"^    [a-z-]+\) .*\bpy_cli\b.*$", dispatch, re.MULTILINE)

    assert offenders == []


@pytest.mark.parametrize("step", STEPS)
def test_each_step_has_a_command_function_and_the_dispatcher_calls_it(step):
    dispatch = CTL.read_text(encoding="utf-8")

    assert f'{step}) {FUNCTIONS[step]} "$@" ;;' in dispatch
    assert re.search(rf"^{FUNCTIONS[step]}\(\)", LIFECYCLE.read_text(encoding="utf-8"), re.M)


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_the_config_dir_flag_reaches_py_cli(tmp_path, step):
    config = _seeded(tmp_path / "config")

    result = _call(FUNCTIONS[step], f"--config-dir={config.as_posix()}")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"py_cli {step} CONFIG_DIR={config.as_posix()}"


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_without_the_flag_the_default_config_dir_is_used(tmp_path, step):
    default = _seeded(tmp_path / "papaia-config")

    result = _call(FUNCTIONS[step], default=default)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"py_cli {step} CONFIG_DIR={default.as_posix()}"


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_a_config_dir_without_a_setup_is_refused_before_py_cli_runs(tmp_path, step):
    empty = tmp_path / "never-set-up"
    empty.mkdir()

    result = _call(FUNCTIONS[step], f"--config-dir={empty.as_posix()}")

    assert result.returncode == 2
    assert "py_cli" not in result.stdout
    assert f"No setup found at {empty.as_posix()}" in result.stderr
    assert "papaia-ctl setup" in result.stderr


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_an_unknown_option_is_refused(tmp_path, step):
    result = _call(FUNCTIONS[step], "--bogus", default=_seeded(tmp_path / "c"))

    assert result.returncode == 2
    assert "py_cli" not in result.stdout
    assert f"Unknown option for {step}: --bogus" in result.stderr


@needs_bash
@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_prints_the_usage_and_runs_nothing(tmp_path, flag):
    result = _call("cmd_keycloak_role_sync", flag, default=_seeded(tmp_path / "c"))

    assert result.returncode == 0
    assert result.stdout.strip() == "USAGE"


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_the_exit_status_of_the_step_is_the_commands_own(tmp_path, step):
    """A retry that fails again has to be visible to a script."""
    config = _seeded(tmp_path / "config")

    result = _call(FUNCTIONS[step], f"--config-dir={config.as_posix()}", rc=1)

    assert result.returncode == 1


@needs_bash
@pytest.mark.parametrize("step", STEPS)
def test_the_real_entrypoint_no_longer_dies_on_an_unbound_variable(tmp_path, step):
    """Through papaia-ctl itself, as an operator calls it. Stops at the setup check, so
    nothing but the option parsing runs; the directory is empty on purpose."""
    assert BASH is not None
    empty = tmp_path / "never-set-up"
    empty.mkdir()

    result = subprocess.run(
        [BASH, str(CTL), step, f"--config-dir={empty.as_posix()}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert "unbound variable" not in result.stderr
    assert result.returncode == 2
    assert f"No setup found at {empty.as_posix()}" in result.stderr


@needs_bash
def test_the_real_entrypoint_refuses_an_unknown_option_of_a_step():
    assert BASH is not None

    result = subprocess.run(
        [BASH, str(CTL), "keycloak-role-sync", "--bogus"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 2
    assert "Unknown option for keycloak-role-sync: --bogus" in result.stderr
