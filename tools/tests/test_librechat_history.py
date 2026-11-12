"""`papaia-ctl librechat clear-history`: the Python side and the shell command.

Docker is replaced by a recorder, so the tests pin which container is asked, what the
script receives and how its result line is read, without a daemon. The shell command
is checked with `py_cli`, `is_tty` and `confirm` stubbed: the order of the dry run, the
question and the deletion is what protects the history.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from lib import cli, librechat_history, status
from lib.librechat_history import ClearHistoryError

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
SCRIPT = REPO / librechat_history.SCRIPT
LIBRECHAT_SH = TOOLS / "lib" / "sh" / "librechat.sh"
CTL = TOOLS / "papaia-ctl"
BASH = shutil.which("bash")
NODE = shutil.which("node")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _result(**fields: object) -> str:
    return librechat_history.RESULT_MARKER + json.dumps(fields)


class FakeDocker:
    """Answers `docker ps` and `docker exec` and records every call."""

    def __init__(self, *, running: str = "papaia-librechat-1", exec_stdout: str = "", rc: int = 0):
        self.running = running
        self.exec_stdout = exec_stdout
        self.rc = rc
        self.calls: list[tuple[list[str], str]] = []

    def __call__(self, cmd, stdin, timeout):
        self.calls.append((list(cmd), stdin))
        if cmd[:2] == ["docker", "ps"]:
            return status.CommandResult(0, f"{self.running}\n" if self.running else "", "")
        if cmd[:2] == ["docker", "exec"]:
            return status.CommandResult(self.rc, self.exec_stdout, "")
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "config"
    path.mkdir()
    (path / ".env").write_text("COMPOSE_PROJECT_NAME=acme\n", encoding="utf-8")
    (path / "deployment.yaml").write_text("core: {}\n", encoding="utf-8")
    return path


# -- finding the container -------------------------------------------------------------


def test_the_container_is_looked_up_by_project_and_service(config):
    docker = FakeDocker(running="acme-librechat-1")

    assert librechat_history.find_container(config, docker) == "acme-librechat-1"
    [(cmd, _)] = docker.calls
    assert "label=com.docker.compose.project=acme" in cmd
    assert "label=com.docker.compose.service=librechat" in cmd
    assert "status=running" in cmd


def test_a_stopped_stack_is_an_error_that_says_it_needs_one(config):
    with pytest.raises(ClearHistoryError, match="needs the running stack.*papaia-ctl start"):
        librechat_history.find_container(config, FakeDocker(running=""))


def test_librechat_on_another_node_names_the_node(config, monkeypatch):
    placed = SimpleNamespace(distributed=True, controller="internal", node_of=lambda _s: "dmz")
    monkeypatch.setattr(librechat_history.topology, "load_config", lambda _c: placed)

    with pytest.raises(ClearHistoryError, match="placed on node 'dmz'"):
        librechat_history.find_container(config, FakeDocker(running=""))


def test_docker_that_cannot_list_containers_is_reported(config):
    def broken(cmd, stdin, timeout):
        return status.CommandResult(1, "", "Cannot connect to the Docker daemon\n")

    with pytest.raises(ClearHistoryError, match="Cannot connect to the Docker daemon"):
        librechat_history.find_container(config, broken)


# -- running the script ------------------------------------------------------------------


def test_the_script_goes_to_node_on_stdin_with_the_arguments(config):
    docker = FakeDocker(exec_stdout=_result(email="a@example.org", dry_run=True, conversations=2))

    librechat_history.clear_history(
        REPO, config, "a@example.org", before="2026-06-01", dry_run=True, runner=docker
    )

    cmd, stdin = docker.calls[-1]
    assert cmd == [
        "docker", "exec", "-i", "-w", "/app", "papaia-librechat-1",
        "node", "-", "--email=a@example.org", "--before=2026-06-01", "--dry-run",
    ]
    assert stdin == SCRIPT.read_text(encoding="utf-8")


def test_a_real_run_has_no_dry_run_flag(config):
    docker = FakeDocker(exec_stdout=_result(email="a@example.org", dry_run=False))

    librechat_history.clear_history(REPO, config, "a@example.org", runner=docker)

    cmd, _ = docker.calls[-1]
    assert "--dry-run" not in cmd
    assert not any(arg.startswith("--before") for arg in cmd)


def test_the_result_line_is_found_among_librechats_log_output(config):
    noise = "2026-11-12 09:43:19 info: Connected to MongoDB\n{\"not\": \"ours\"}\n"
    docker = FakeDocker(
        exec_stdout=noise + _result(email="a@example.org", dry_run=False, messages=7) + "\n"
    )

    result = librechat_history.clear_history(REPO, config, "a@example.org", runner=docker)

    assert result["messages"] == 7


def test_an_unknown_user_is_an_error(config):
    docker = FakeDocker(exec_stdout=_result(error="unknown_user", email="x@example.org"), rc=3)

    with pytest.raises(ClearHistoryError, match="no user with the e-mail address 'x@example.org'"):
        librechat_history.clear_history(REPO, config, "x@example.org", runner=docker)


def test_a_failure_in_the_script_is_reported_with_its_message(config):
    docker = FakeDocker(exec_stdout=_result(error="failed", message="connection refused"), rc=1)

    with pytest.raises(ClearHistoryError, match="connection refused"):
        librechat_history.clear_history(REPO, config, "a@example.org", runner=docker)


def test_no_result_line_is_an_error(config):
    docker = FakeDocker(exec_stdout="Error: Cannot find module 'module-alias'\n", rc=1)

    with pytest.raises(ClearHistoryError, match="no result.*module-alias"):
        librechat_history.clear_history(REPO, config, "a@example.org", runner=docker)


@pytest.mark.parametrize("email", ["", "alice", "a b@example.org", "--dry-run"])
def test_a_value_that_is_not_an_email_address_never_reaches_docker(config, email):
    docker = FakeDocker()

    with pytest.raises(ClearHistoryError, match="not an e-mail address"):
        librechat_history.clear_history(REPO, config, email, runner=docker)
    assert docker.calls == []


@pytest.mark.parametrize("before", ["2026-13-01", "01.06.2026", "2026-6-1", "yesterday"])
def test_a_before_that_is_not_a_date_never_reaches_docker(config, before):
    docker = FakeDocker()

    with pytest.raises(ClearHistoryError, match="YYYY-MM-DD"):
        librechat_history.clear_history(REPO, config, "a@example.org", before=before, runner=docker)
    assert docker.calls == []


# -- the summary and the exit status -------------------------------------------------------


def test_the_dry_run_summary_lists_every_kind_and_says_nothing_changed():
    text = librechat_history.format_result(
        {"email": "a@example.org", "dry_run": True, "conversations": 2, "messages": 4,
         "files": 1, "shared_links": 1, "tool_calls": 3},
        before="2026-06-01",
    )

    assert text.splitlines()[0] == (
        "Would remove from a@example.org's history last updated before 2026-06-01:"
    )
    for label in ("conversations", "messages", "files", "shared links", "tool call records"):
        assert label in text
    assert "Nothing was changed" in text


def test_files_that_stayed_in_storage_are_named():
    text = librechat_history.format_result(
        {"email": "a@example.org", "dry_run": False, "files": 1, "files_failed": ["f-1"]}
    )

    assert text.startswith("Removed from a@example.org's history:")
    assert "1 file(s) could not be removed from storage and were kept: f-1" in text


def _cli(config: Path, *extra: str) -> list[str]:
    return [
        "--repo-root", str(REPO), "--config-dir", str(config), "librechat-clear-history", *extra
    ]


def test_the_command_exits_0_and_prints_the_summary(config, monkeypatch, capsys):
    docker = FakeDocker(exec_stdout=_result(email="a@example.org", dry_run=False, conversations=1))
    monkeypatch.setattr(librechat_history, "run_with_input", docker)

    assert cli.main(_cli(config, "--email=a@example.org")) == 0
    assert "conversations" in capsys.readouterr().out


def test_the_command_exits_1_for_an_unknown_user(config, monkeypatch, capsys):
    docker = FakeDocker(exec_stdout=_result(error="unknown_user", email="x@example.org"), rc=3)
    monkeypatch.setattr(librechat_history, "run_with_input", docker)

    assert cli.main(_cli(config, "--email=x@example.org", "--dry-run")) == 1
    assert "no user with the e-mail address" in capsys.readouterr().err


def test_the_command_exits_1_when_files_stayed_in_storage(config, monkeypatch):
    docker = FakeDocker(
        exec_stdout=_result(email="a@example.org", dry_run=False, files_failed=["f-1"]), rc=1
    )
    monkeypatch.setattr(librechat_history, "run_with_input", docker)

    assert cli.main(_cli(config, "--email=a@example.org")) == 1


# -- the script itself ---------------------------------------------------------------------


@pytest.mark.skipif(NODE is None, reason="node is not available")
def test_the_script_parses():
    subprocess.run([NODE, "--check", str(SCRIPT)], check=True, timeout=30)


def test_the_script_keeps_the_files_that_are_not_part_of_a_conversation():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "const KEPT_CONTEXTS = ['avatar', 'agents', 'assistants', 'skill_file'];" in text
    assert librechat_history.RESULT_MARKER in text


# -- the shell command -----------------------------------------------------------------------

# The shell state papaia-ctl has when the command runs, with py_cli, is_tty and confirm
# replaced: py_cli reports its call and fails for a dry run when DRY_RC says so.
_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
error() { echo "ERROR: $*" >&2; }
usage() { echo "USAGE"; }
_require_setup_done() { :; }
is_tty() { [ "${TTY:-no}" = yes ]; }
confirm() { echo "ASKED"; [ "${ANSWER:-n}" = y ]; }
py_cli() {
    echo "py_cli $*"
    case " $* " in *" --dry-run "*) return "${DRY_RC:-0}" ;; esac
    return 0
}
source "@LIB@"
"""


def _sh(*args: str, tty: bool = False, answer: str = "n", dry_rc: int = 0):
    assert BASH is not None
    harness = _HARNESS.replace("@CONFIG@", "/no/config").replace("@LIB@", LIBRECHAT_SH.as_posix())
    quoted = " ".join(f"'{a}'" for a in args)
    env_line = f"TTY={'yes' if tty else 'no'} ANSWER={answer} DRY_RC={dry_rc}"
    return subprocess.run(
        [BASH, "-c", f"{harness}\n{env_line} cmd_librechat {quoted}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _py_calls(proc) -> list[str]:
    return [line for line in proc.stdout.splitlines() if line.startswith("py_cli ")]


@needs_bash
def test_a_dry_run_only_counts():
    proc = _sh("clear-history", "a@example.org", "--dry-run", "--before=2026-06-01")

    assert proc.returncode == 0
    assert _py_calls(proc) == [
        "py_cli librechat-clear-history --email=a@example.org --before=2026-06-01 --dry-run"
    ]


@needs_bash
def test_yes_deletes_without_asking():
    proc = _sh("clear-history", "a@example.org", "-y")

    assert proc.returncode == 0
    assert "ASKED" not in proc.stdout
    assert _py_calls(proc) == ["py_cli librechat-clear-history --email=a@example.org"]


@needs_bash
def test_without_a_terminal_and_without_yes_nothing_runs():
    proc = _sh("clear-history", "a@example.org")

    assert proc.returncode == 2
    assert "pass -y" in proc.stderr
    assert _py_calls(proc) == []


@needs_bash
def test_in_a_terminal_the_counts_come_first_then_the_question_then_the_deletion():
    proc = _sh("clear-history", "a@example.org", tty=True, answer="y")

    assert proc.returncode == 0
    lines = [line for line in proc.stdout.splitlines() if line.startswith(("py_cli", "ASKED"))]
    assert lines == [
        "py_cli librechat-clear-history --email=a@example.org --dry-run",
        "ASKED",
        "py_cli librechat-clear-history --email=a@example.org",
    ]


@needs_bash
def test_a_no_deletes_nothing():
    proc = _sh("clear-history", "a@example.org", tty=True, answer="n")

    assert proc.returncode == 3
    assert _py_calls(proc) == ["py_cli librechat-clear-history --email=a@example.org --dry-run"]


@needs_bash
def test_an_unknown_user_stops_before_the_question():
    proc = _sh("clear-history", "x@example.org", tty=True, answer="y", dry_rc=1)

    assert proc.returncode == 1
    assert "ASKED" not in proc.stdout
    assert len(_py_calls(proc)) == 1


@needs_bash
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("clear-history",), "Usage: papaia-ctl librechat clear-history"),
        (("clear-history", "a@example.org", "b@example.org"), "takes one e-mail address"),
        (("clear-history", "a@example.org", "--all"), "Unknown option"),
        (("purge",), "Unknown librechat command"),
    ],
)
def test_wrong_arguments_exit_2(args, message):
    proc = _sh(*args)

    assert proc.returncode == 2
    assert message in proc.stderr
    assert _py_calls(proc) == []


def test_the_dispatcher_and_the_help_know_the_command():
    text = CTL.read_text(encoding="utf-8")

    assert 'librechat)     cmd_librechat "$@" ;;' in text
    assert "#   papaia-ctl librechat clear-history <email>" in text
    assert 'source "$SH_LIB/librechat.sh"' in text
