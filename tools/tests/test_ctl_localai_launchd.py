"""The native LocalAI hooks of `start`, `stop` and `uninstall` (lib/sh/lifecycle.sh, ADR 0012).

Hermetic: `docker` and `py_cli` are shell functions that answer what a test needs and
record their calls in order. Python decides whether there is a launchd job and whether the
host can run it (test_localai_native.py); here only the order of the calls and what the
shell does with their results is checked. Every test runs under each Bash at hand,
including the 3.2 that ships with macOS.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"


def _bashes() -> list[str]:
    found = []
    for candidate in (shutil.which("bash"), "/bin/bash"):
        if candidate and Path(candidate).is_file() and candidate not in found:
            found.append(candidate)
    return found


BASHES = _bashes()

pytestmark = pytest.mark.skipif(not BASHES, reason="bash is not available")


@pytest.fixture(params=BASHES)
def bash(request) -> str:
    return request.param


_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
LOG="@LOG@"
error() { echo "ERROR: $*"; }
warn() { echo "WARN: $*"; }
info() { echo "INFO: $*"; }
success() { echo "OK: $*"; }
usage() { :; }
is_tty() { return 1; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
_addon_compose_all() { echo "addons $*" >> "$LOG"; }
docker() {
    echo "docker COMPOSE_PROFILES=${COMPOSE_PROFILES:-} $*" >> "$LOG"
    case " $* " in *" config "*) echo "service" ;; esac
}
py_cli() {
    echo "py_cli $*" >> "$LOG"
    case "$1" in
        localai-native-install) @INSTALL@ ;;
        localai-native-start) @START@ ;;
        localai-native-stop) @STOP@ ;;
        localai-native-uninstall) @UNINSTALL@ ;;
    esac
}
"""

_INSTALLED = (
    'printf "LOCALAI_NATIVE=installed\\nLOCALAI_NATIVE_VERSION=v4.7.1\\n'
    "LOCALAI_NATIVE_REPLACED=@REPLACED@\\nLOCALAI_NATIVE_SCRIPT=/ws/localai/papaia/run-localai\\n"
    'LOCALAI_NATIVE_RESTART=@RESTART@\\n"'
)
_UNCHANGED = (
    'printf "LOCALAI_NATIVE=unchanged\\nLOCALAI_NATIVE_VERSION=v4.7.1\\n'
    "LOCALAI_NATIVE_REPLACED=\\nLOCALAI_NATIVE_SCRIPT=/ws/localai/papaia/run-localai\\n"
    'LOCALAI_NATIVE_RESTART=0\\n"'
)


def installed(replaced: str = "", restart: str = "1") -> str:
    return _INSTALLED.replace("@REPLACED@", replaced).replace("@RESTART@", restart)


def _run(
    bash: str,
    tmp_path: Path,
    command: str,
    *,
    install: str = 'echo "LOCALAI_NATIVE=off"',
    start: str = "return 0",
    stop: str = "return 0",
    uninstall: str = "return 0",
) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    script = (
        (
            _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
            .replace("@LOG@", log.as_posix())
            .replace("@LIFECYCLE@", (SH_LIB / "lifecycle.sh").as_posix())
            .replace("@INSTALL@", install)
            .replace("@START@", start)
            .replace("@STOP@", stop)
            .replace("@UNINSTALL@", uninstall)
        )
        + command
        + "\n"
    )
    done = subprocess.run(
        [bash, "-c", script], capture_output=True, text=True, timeout=30, check=False
    )
    calls = [
        line
        for line in log.read_text(encoding="utf-8").splitlines()
        if " config --services" not in line
    ]
    return done, calls


def _index(calls: list[str], prefix: str) -> int:
    return next(i for i, line in enumerate(calls) if line.startswith(prefix))


def _has(calls: list[str], prefix: str) -> bool:
    return any(line.startswith(prefix) for line in calls)


def _up(calls: list[str]) -> int:
    return next(i for i, line in enumerate(calls) if line.startswith("docker") and " up " in line)


# ── start ───────────────────────────────────────────────────────────────────


def test_start_installs_before_up_and_starts_the_job_after_it(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start", install=installed())
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls.index("py_cli render") < calls.index("py_cli localai-native-install")
    assert calls.index("py_cli localai-native-install") < _up(calls)
    assert _up(calls) < _index(calls, "py_cli localai-native-start")
    # The provisioning steps follow; keycloak-role-sync stays the last one.
    assert _index(calls, "py_cli localai-native-start") < calls.index("py_cli npm-provision")
    assert calls[-1] == "py_cli keycloak-role-sync"
    assert done.stdout.splitlines()[-1] == "OK: start complete."
    # No terminal step is left for the operator.
    assert "terminal" not in done.stdout


def test_a_new_binary_or_script_restarts_the_job(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start", install=installed("v4.6.0"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "py_cli localai-native-start --restart" in calls
    assert "INFO: LocalAI v4.7.1 replaces v4.6.0." in done.stdout


def test_an_unchanged_install_starts_without_a_restart(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start", install=_UNCHANGED)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "py_cli localai-native-start" in calls


def test_a_failed_install_starts_no_job_and_the_stack_still_starts(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start", install="return 1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "WARN: The native LocalAI was not installed" in done.stdout
    assert not _has(calls, "py_cli localai-native-start")
    _up(calls)
    assert done.stdout.splitlines()[-1] == "OK: start complete."


def test_a_job_that_does_not_start_warns_and_start_goes_on(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start", install=installed(), start="return 1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "WARN: The native LocalAI did not start" in done.stdout
    assert calls[-1] == "py_cli keycloak-role-sync"
    assert done.stdout.splitlines()[-1] == "OK: start complete."


@pytest.mark.parametrize("state", ["off", "skipped"])
def test_the_container_runtime_a_container_and_an_unsupported_host_start_no_job(
    bash, tmp_path, state
):
    # `skipped` is what the install step says inside a container (papaia-manager) and on
    # a host that is not an Apple Silicon Mac with Docker Desktop; it warned already.
    done, calls = _run(bash, tmp_path, "cmd_start", install=f'echo "LOCALAI_NATIVE={state}"')
    assert done.returncode == 0, done.stdout + done.stderr
    assert not _has(calls, "py_cli localai-native-start")
    _up(calls)
    assert "LocalAI" not in done.stdout


def test_a_start_scoped_to_other_profiles_leaves_localai_alone(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start --profiles=rag", install=installed())
    assert done.returncode == 0, done.stdout + done.stderr
    assert not _has(calls, "py_cli localai-native")


def test_a_start_scoped_to_localai_starts_it(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_start --profiles=keycloak,localai", install=installed())
    assert done.returncode == 0, done.stdout + done.stderr
    assert _has(calls, "py_cli localai-native-start")


# ── stop ────────────────────────────────────────────────────────────────────


def test_stop_unloads_the_job_before_the_compose_part(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_stop")
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls[0] == "py_cli localai-native-stop"
    assert calls[1].startswith("docker COMPOSE_PROFILES= compose") and calls[1].endswith(" stop")


def test_stop_with_addons_unloads_the_job_first(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_stop --addons --clean-up")
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls[:2] == ["py_cli localai-native-stop", "addons down"]
    assert calls[2].endswith(" down")


def test_deleting_the_localai_volumes_deletes_the_native_models_too(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_stop --clean-up --volumes --profiles=localai")
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls[0] == "py_cli localai-native-stop --purge-models"
    assert calls[1].startswith("docker COMPOSE_PROFILES=localai compose")
    assert calls[1].endswith(" down --volumes")


def test_a_clean_up_without_volumes_keeps_the_models(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_stop --clean-up --profiles=localai")
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls[0] == "py_cli localai-native-stop"


@pytest.mark.parametrize("profiles", ["rag", "librechat-websearch,smtp"])
def test_a_stop_scoped_to_other_profiles_leaves_localai_running(bash, tmp_path, profiles):
    done, calls = _run(bash, tmp_path, f"cmd_stop --clean-up --volumes --profiles={profiles}")
    assert done.returncode == 0, done.stdout + done.stderr
    assert not _has(calls, "py_cli localai-native")


def test_a_job_that_does_not_stop_warns_and_the_stack_still_stops(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_stop", stop="return 1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "WARN: The native LocalAI was not stopped" in done.stdout
    assert calls[-1].endswith(" stop")
    assert done.stdout.splitlines()[-1] == "OK: stop complete."


# ── uninstall ───────────────────────────────────────────────────────────────


def _configured(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    repo_src = config / "repo" / "src"
    repo_src.mkdir(parents=True)
    (repo_src / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (repo_src / ".env").write_text("", encoding="utf-8")
    return config


@pytest.mark.parametrize(
    "flag, expected",
    [
        ("", "py_cli localai-native-uninstall"),
        ("--clean-up", "py_cli localai-native-uninstall --purge"),
    ],
)
def test_uninstall_removes_the_job_before_the_configuration(bash, tmp_path, flag, expected):
    config = _configured(tmp_path)
    done, calls = _run(bash, tmp_path, f"cmd_uninstall -y {flag}")
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls[0] == expected
    assert calls[1].startswith("docker COMPOSE_PROFILES= compose")
    assert not config.exists()


def test_a_failed_job_removal_warns_and_the_uninstall_goes_on(bash, tmp_path):
    config = _configured(tmp_path)
    done, _ = _run(bash, tmp_path, "cmd_uninstall -y", uninstall="return 1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "WARN: The native LocalAI was not removed completely" in done.stdout
    assert not config.exists()


def test_uninstall_without_a_configuration_asks_python_nothing(bash, tmp_path):
    done, calls = _run(bash, tmp_path, "cmd_uninstall -y")
    assert done.returncode == 0, done.stdout + done.stderr
    assert not _has(calls, "py_cli")
