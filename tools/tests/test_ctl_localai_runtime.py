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


def _host(system: str, machine: str, engine: str | None) -> str:
    """engine None: Docker does not answer (Docker Desktop not running)."""
    docker = "docker() { return 1; }\n" if engine is None else f'docker() {{ echo "{engine}"; }}\n'
    return (
        f'uname() {{ case "${{1:-}}" in -m) echo "{machine}" ;; *) echo "{system}" ;; esac; }}\n'
        + docker
    )


def _setup_lib(
    system: str = "Darwin", machine: str = "arm64", engine: str | None = "Docker Desktop"
):
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
        ("Darwin", "arm64", None, False),
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
def test_native_is_refused_where_localai_cannot_run_natively(system, machine, engine):
    done = _setup_with_flag(system, machine, engine, "--localai-runtime=native")
    assert done.returncode == 2
    assert "--localai-runtime=native needs an Apple Silicon Mac with Docker Desktop" in done.stderr


@pytest.mark.parametrize(
    "system, machine, engine, why",
    [("Linux", "x86_64", "Ubuntu", "this host is Linux/x86_64, not an Apple Silicon Mac"),
     ("Darwin", "arm64", "Colima", "Docker here is 'Colima', not Docker Desktop"),
     ("Darwin", "arm64", None, "Docker does not answer; start Docker Desktop")],
)  # fmt: skip
def test_the_refusal_says_why(system, machine, engine, why):
    done = _setup_with_flag(system, machine, engine, "--localai-runtime=native")
    assert done.returncode == 2
    assert why in done.stderr


# ── a stored `native` on a host that cannot run it ──────────────────────────

_STORED_NATIVE = (
    "LOCALAI_RUNTIME_STICKY=native\\nLOCAL_AI_STICKY=true\\nCONFIG_SEEDED=true\\n"
    "APP_HOST_STICKY=https://papaia.example.com\\nLOCALAI_HOST_STICKY=http://localhost:8080\\n"
    "AUTH_HOST_DERIVED=https://papaia.example.com:8443\\n"
)


def _setup_on(
    system: str, machine: str, engine: str | None, args: str, *, interactive: bool = False
) -> subprocess.CompletedProcess:
    """cmd_setup with a stored native configuration, up to the call into Python, which
    prints the LocalAI arguments it would get and ends the run."""
    tty = "is_tty() { return 0; }\n_installation_exists() { return 0; }\n" if interactive else ""
    return _bash(
        _setup_lib(system, machine, engine)
        + f"py_cli() {{ case \"$1\" in defaults) printf '{_STORED_NATIVE}' ;; esac; }}\n"
        + "_run_setup_py() { printf 'SETUP_PY local_ai=%s url=%s args=%s\\n'"
        + ' "${13}" "${12}" "${SETUP_LOCALAI_ARGS[*]-}"; exit 0; }\n'
        + tty
        + f'DEFAULT_CONFIG_DIR="/nonexistent"; cmd_setup {args}\n',
        "\n" * 100,
    )


_OFF_THE_GATE = [
    ("Linux", "x86_64", "Ubuntu 24.04 LTS"),
    ("Linux", "aarch64", "Docker Desktop"),
    ("Darwin", "arm64", "OrbStack"),
    ("Darwin", "arm64", None),
]


@pytest.mark.parametrize("system, machine, engine", _OFF_THE_GATE)
def test_the_way_back_to_the_container_is_accepted_everywhere(system, machine, engine):
    done = _setup_on(system, machine, engine, "-y --localai-runtime=container")
    assert done.returncode == 0, done.stderr
    assert "args=--localai-runtime=container" in done.stdout


def test_the_container_flag_on_a_qualifying_mac():
    done = _setup_on("Darwin", "arm64", "Docker Desktop", "-y --localai-runtime=container")
    assert done.returncode == 0, done.stderr
    assert "args=--localai-runtime=container" in done.stdout


@pytest.mark.parametrize("system, machine, engine", _OFF_THE_GATE)
def test_interactive_setup_switches_a_stored_native_back_to_the_container(
    system, machine, engine
):
    done = _setup_on(system, machine, engine, "--local-ai", interactive=True)
    assert done.returncode == 0, done.stderr
    assert "LocalAI was set to run natively, but" in done.stderr
    assert "Switching LocalAI back to its container" in done.stderr
    assert "args=--localai-runtime=container" in done.stdout
    # The URL question is asked again, with the container's URL and not the native one.
    assert "Public URL of LocalAI" in done.stderr
    assert "url=https://papaia.example.com:8080" in done.stdout


def test_interactive_setup_names_a_docker_that_does_not_answer():
    done = _setup_on("Darwin", "arm64", None, "--local-ai", interactive=True)
    assert "but Docker does not answer; start Docker Desktop" in done.stderr


def test_interactive_setup_on_a_qualifying_mac_asks_and_keeps_native():
    done = _setup_on("Darwin", "arm64", "Docker Desktop", "--local-ai", interactive=True)
    assert done.returncode == 0, done.stderr
    assert "LocalAI on this Mac" in done.stderr
    assert "args=--localai-runtime=native" in done.stdout
    assert "Switching LocalAI back" not in done.stderr


def test_a_non_interactive_setup_warns_about_a_stored_native_it_keeps():
    done = _setup_on("Linux", "x86_64", "Ubuntu", "-y")
    assert done.returncode == 0, done.stderr
    assert "LOCALAI_RUNTIME=native is stored, but this host is Linux/x86_64" in done.stderr
    assert "'papaia-ctl setup --localai-runtime=container'" in done.stderr
    assert "args=" in done.stdout and "--localai-runtime" not in done.stdout


def test_the_stored_native_is_not_mentioned_on_a_qualifying_mac():
    done = _setup_on("Darwin", "arm64", "Docker Desktop", "-y")
    assert done.returncode == 0, done.stderr
    assert "LOCALAI_RUNTIME=native is stored" not in done.stderr


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


def test_a_bare_rerun_flags_the_stored_native_and_reconfigures_by_default():
    done = _setup_on("Linux", "x86_64", "Ubuntu", "", interactive=True)
    assert done.returncode == 0, done.stderr
    assert "LocalAI runtime   = native (Apple GPU), not available here" in done.stderr
    # An empty answer to "Reconfigure?" goes on to the questions (default yes here).
    assert "args=--localai-runtime=container" in done.stdout
