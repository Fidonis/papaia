"""The native LocalAI runtime in the Bash front end (ADR 0012): which hosts see the setup
question and accept the flag, the flag on its way to Python, and the `start` hook.

Hermetic: `uname`, `docker` and `py_cli` are shell functions that answer what a test
needs and record their calls.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _bash(script: str, answer: str = "") -> subprocess.CompletedProcess:
    assert BASH is not None
    return subprocess.run(
        [BASH, "-c", script], input=answer + "\n", capture_output=True, text=True, timeout=30,
        check=False,
    )  # fmt: skip


def _host(system: str, machine: str, engine: str) -> str:
    return (
        f'uname() {{ case "${{1:-}}" in -m) echo "{machine}" ;; *) echo "{system}" ;; esac; }}\n'
        f'docker() {{ echo "{engine}"; }}\n'
    )


def _setup_lib(system: str = "Darwin", machine: str = "arm64", engine: str = "Docker Desktop"):
    return (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "setup.sh"}"\n' + _host(system, machine, engine)
    )


# ── which hosts ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "system, machine, engine, native",
    [
        ("Darwin", "arm64", "Docker Desktop", True),
        ("Darwin", "arm64", "OrbStack", False),
        ("Darwin", "x86_64", "Docker Desktop", False),
        ("Linux", "aarch64", "Docker Desktop", False),
        ("Linux", "x86_64", "Ubuntu 24.04 LTS", False),
    ],
)
def test_only_an_apple_silicon_mac_with_docker_desktop_runs_localai_natively(
    system, machine, engine, native
):
    done = _bash(
        _setup_lib(system, machine, engine)
        + "if _native_localai_host; then echo NATIVE=yes; else echo NATIVE=no; fi\n"
    )
    assert done.returncode == 0, done.stderr
    assert f"NATIVE={'yes' if native else 'no'}" in done.stdout


# ── the question ────────────────────────────────────────────────────────────


def _ask(answer: str = "", sticky: str = "") -> subprocess.CompletedProcess:
    return _bash(
        _setup_lib()
        + f'LOCALAI_RUNTIME_STICKY="{sticky}"\n'
        + 'printf "RUNTIME=%s\\n" "$(_prompt_localai_runtime)"\n',
        answer,
    )


def test_the_question_defaults_to_native():
    done = _ask()
    assert done.returncode == 0, done.stderr
    assert "RUNTIME=native" in done.stdout
    assert "Apple GPU (Metal) (default)" in done.stderr


def test_an_installation_that_runs_the_container_keeps_it_as_the_default():
    done = _ask(sticky="container")
    assert "RUNTIME=container" in done.stdout
    assert "CPU only (default)" in done.stderr


def test_the_container_can_be_chosen():
    assert "RUNTIME=container" in _ask(answer="2").stdout


# ── the flag ────────────────────────────────────────────────────────────────


def _setup_with_flag(system: str, machine: str, engine: str, flag: str):
    return _bash(
        _setup_lib(system, machine, engine)
        + "py_cli() { :; }\n"
        + f'DEFAULT_CONFIG_DIR="/nonexistent"; cmd_setup -y {flag}\n'
    )


@pytest.mark.parametrize(
    "system, machine, engine",
    [("Linux", "x86_64", "Ubuntu"), ("Darwin", "x86_64", "Docker Desktop"),
     ("Darwin", "arm64", "Colima")],
)  # fmt: skip
def test_the_flag_is_refused_where_localai_cannot_run_natively(system, machine, engine):
    done = _setup_with_flag(system, machine, engine, "--localai-runtime=native")
    assert done.returncode == 2
    assert "--localai-runtime is for an Apple Silicon Mac with Docker Desktop" in done.stderr


def test_an_unknown_runtime_is_refused():
    done = _setup_with_flag("Darwin", "arm64", "Docker Desktop", "--localai-runtime=metal")
    assert done.returncode == 2
    assert "Invalid --localai-runtime value: 'metal'" in done.stderr


def test_the_flag_reaches_python_bundled():
    done = _bash(
        _setup_lib()
        + 'py_cli() { printf "ARG %s\\n" "$@"; }\n'
        + "SETUP_SMTP_ARGS=()\nSETUP_LOCALAI_ARGS=(--localai-runtime=native)\n"
        + '_run_setup_py papaia "" "" "" 0 "" 0 "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" ""\n'
    )
    assert done.returncode == 0, done.stderr
    assert "ARG --localai-runtime=native" in done.stdout.splitlines()


def test_a_re_render_passes_no_runtime():
    done = _bash(
        _setup_lib()
        + 'py_cli() { printf "ARG %s\\n" "$@"; }\n'
        + "SETUP_SMTP_ARGS=()\n"
        + '_run_setup_py papaia "" "" "" 0 "" 0 "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" ""\n'
    )
    assert done.returncode == 0, done.stderr
    assert not any("localai-runtime" in line for line in done.stdout.splitlines())


# ── the start hook ──────────────────────────────────────────────────────────

_START = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*"; }
warn() { echo "WARN: $*"; }
info() { echo "INFO: $*"; }
success() { echo "OK: $*"; }
usage() { :; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
docker() { echo "docker $*"; }
py_cli() {
    echo "py_cli $*" >&2
    case "$1" in
        localai-native-install) @INSTALL@ ;;
        localai-native-probe) @PROBE@ ;;
    esac
}
cmd_start
"""

_INSTALLED = (
    'printf "LOCALAI_NATIVE=installed\\nLOCALAI_NATIVE_VERSION=v4.7.1\\n'
    'LOCALAI_NATIVE_REPLACED=@REPLACED@\\nLOCALAI_NATIVE_SCRIPT=/ws/localai/papaia/run-localai\\n"'
)


def _start(tmp_path: Path, install: str, probe: str = "return 1") -> subprocess.CompletedProcess:
    script = (
        _START.replace("@CONFIG@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", (SH_LIB / "lifecycle.sh").as_posix())
        .replace("@INSTALL@", install)
        .replace("@PROBE@", probe)
    )
    assert BASH is not None
    return subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, timeout=30, check=False
    )


def test_start_installs_before_up_and_says_how_to_start_localai(tmp_path):
    done = _start(tmp_path, _INSTALLED.replace("@REPLACED@", ""))
    assert done.returncode == 0, done.stderr
    calls = done.stderr.splitlines()
    assert calls.index("py_cli render") < calls.index("py_cli localai-native-install")
    out = done.stdout.splitlines()
    up = next(
        i for i, line in enumerate(out) if line.startswith("docker compose") and " up " in line
    )
    hint = out.index("INFO:   /ws/localai/papaia/run-localai")
    assert up < hint
    assert "py_cli localai-native-probe" in calls
    assert out[-1] == "OK: start complete."


def test_a_running_localai_gets_no_start_hint(tmp_path):
    done = _start(tmp_path, _INSTALLED.replace("@REPLACED@", ""), probe="return 0")
    assert done.returncode == 0, done.stderr
    assert "run-localai" not in done.stdout


def test_a_new_binary_asks_for_a_restart(tmp_path):
    done = _start(tmp_path, _INSTALLED.replace("@REPLACED@", "v4.6.0"))
    assert done.returncode == 0, done.stderr
    assert "WARN: LocalAI v4.7.1 is installed. Restart LocalAI to use v4.7.1:" in done.stdout
    assert "py_cli localai-native-probe" not in done.stderr


def test_a_failed_install_warns_and_the_stack_still_starts(tmp_path):
    done = _start(tmp_path, "return 1")
    assert done.returncode == 0, done.stderr
    assert "WARN: The native LocalAI was not installed" in done.stdout
    assert any(" up " in line for line in done.stdout.splitlines())
    assert done.stdout.splitlines()[-1] == "OK: start complete."


@pytest.mark.parametrize("state", ["off", "skipped"])
def test_the_container_runtime_and_an_unsupported_host_see_nothing(tmp_path, state):
    done = _start(tmp_path, f'echo "LOCALAI_NATIVE={state}"')
    assert done.returncode == 0, done.stderr
    assert "LocalAI" not in done.stdout
    assert "py_cli localai-native-probe" not in done.stderr
