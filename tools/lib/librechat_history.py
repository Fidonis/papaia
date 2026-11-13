"""`papaia-ctl librechat clear-history`: remove one LibreChat user's conversation history.

The deletion runs inside the running `librechat` container: the script
`src/ai/librechat/scripts/clear-history.js` is handed to `node -` on stdin and goes
through LibreChat's own model methods and file strategies. The collection layout and
the storage of uploaded files therefore stay LibreChat's concern, and nothing has to be
mounted into the container. It needs a running stack: without the container there is
neither LibreChat's code nor a path to its database and its upload volumes.

The script prints one result line, `PAPAIA_RESULT {json}`, among LibreChat's own log
output; this module finds the container, runs the script and turns that line into
counts or an error.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from . import status, topology

SERVICE = "librechat"
SCRIPT = Path("src") / "ai" / "librechat" / "scripts" / "clear-history.js"
RESULT_MARKER = "PAPAIA_RESULT "
# Thousands of messages and files on a slow disk; the script itself has no timeout.
EXEC_TIMEOUT_SECONDS = 900.0

# (key in the result, label) in the order the summary lists them.
KINDS: tuple[tuple[str, str], ...] = (
    ("conversations", "conversations"),
    ("messages", "messages"),
    ("files", "files"),
    ("shared_links", "shared links"),
    ("tool_calls", "tool call records"),
)

Runner = Callable[[Sequence[str], str, float], status.CommandResult]


class ClearHistoryError(Exception):
    """The history could not be read or cleared; the message says why."""


def run_with_input(cmd: Sequence[str], stdin: str, timeout: float) -> status.CommandResult:
    """`status.run_command` with text on stdin. Never raises."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(cmd),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return status.CommandResult(127, "", f"{cmd[0]}: command not found")
    except subprocess.TimeoutExpired:
        return status.CommandResult(124, "", f"{cmd[0]} timed out after {timeout:g}s")
    except (OSError, subprocess.SubprocessError) as exc:
        return status.CommandResult(126, "", f"{cmd[0]}: {exc}")
    return status.CommandResult(proc.returncode, proc.stdout, proc.stderr)


def validate_email(email: str) -> str:
    value = email.strip()
    if not value or "@" not in value or any(c.isspace() for c in value) or value.startswith("-"):
        raise ClearHistoryError(f"'{email}' is not an e-mail address.")
    return value


def validate_before(value: str) -> str:
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError(value)
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ClearHistoryError(
            f"--before must be a date as YYYY-MM-DD, not '{value}'."
        ) from None
    return value


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _not_running_hint(config_dir: Path) -> str:
    """Where LibreChat would have to run for this command to reach it."""
    try:
        config = topology.load_config(config_dir)
    except (topology.TopologyError, yaml.YAMLError, AttributeError, TypeError, OSError):
        config = None
    if config is not None and config.distributed:
        node = config.node_of(SERVICE)
        if node and node != config.controller:
            return (
                f"LibreChat is placed on node '{node}'; run this command on that node, "
                "where its container runs."
            )
    return "Start the stack with 'papaia-ctl start' and run the command again."


def find_container(config_dir: Path, runner: Runner | None = None) -> str:
    """Name of the running LibreChat container of this installation."""
    runner = runner or run_with_input
    project = status.compose_project(config_dir)
    result = runner(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={SERVICE}",
            "--filter",
            "status=running",
            "--format",
            "{{.Names}}",
        ],
        "",
        status.DOCKER_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        reason = _last_line(result.stderr) or f"exit status {result.returncode}"
        raise ClearHistoryError(f"Docker could not list the containers: {reason}")
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not names:
        raise ClearHistoryError(
            "LibreChat is not running. Clearing a history needs the running stack, "
            f"because it goes through LibreChat itself. {_not_running_hint(config_dir)}"
        )
    return names[0]


def parse_result(stdout: str) -> dict[str, Any] | None:
    """The script's result object, or None when it printed none."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(RESULT_MARKER):
            try:
                document = json.loads(line[len(RESULT_MARKER) :])
            except ValueError:
                return None
            return document if isinstance(document, dict) else None
    return None


def clear_history(
    repo_root: Path,
    config_dir: Path,
    email: str,
    *,
    before: str | None = None,
    dry_run: bool = False,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Count (dry run) or remove the user's history. Returns the script's result;
    raises ClearHistoryError for an unknown user and every failure."""
    runner = runner or run_with_input
    email = validate_email(email)
    if before is not None:
        before = validate_before(before)
    script = (repo_root / SCRIPT).read_text(encoding="utf-8")
    container = find_container(config_dir, runner)

    argv = ["docker", "exec", "-i", "-w", "/app", container, "node", "-", f"--email={email}"]
    if before is not None:
        argv.append(f"--before={before}")
    if dry_run:
        argv.append("--dry-run")
    result = runner(argv, script, EXEC_TIMEOUT_SECONDS)

    document = parse_result(result.stdout)
    if document is None:
        reason = _last_line(result.stderr) or _last_line(result.stdout)
        raise ClearHistoryError(
            f"The LibreChat container gave no result (exit status {result.returncode})"
            + (f": {reason}" if reason else ".")
        )
    error = document.get("error")
    if error == "unknown_user":
        raise ClearHistoryError(f"LibreChat has no user with the e-mail address '{email}'.")
    if error:
        raise ClearHistoryError(f"Clearing the history failed: {document.get('message') or error}")
    return document


def _count(document: dict[str, Any], key: str) -> int:
    value = document.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def format_result(document: dict[str, Any], *, before: str | None = None) -> str:
    """The summary printed to the operator."""
    dry_run = bool(document.get("dry_run"))
    email = document.get("email") or "?"
    scope = f" last updated before {before}" if before else ""
    head = (
        f"Would remove from {email}'s history{scope}:"
        if dry_run
        else f"Removed from {email}'s history{scope}:"
    )
    width = max(len(label) for _, label in KINDS)
    lines = [head]
    lines.extend(f"  {label:<{width}}  {_count(document, key)}" for key, label in KINDS)
    failed = document.get("files_failed")
    if isinstance(failed, list) and failed:
        lines.append(
            f"  {len(failed)} file(s) could not be removed from storage and were kept: "
            + ", ".join(str(f) for f in failed)
        )
    if dry_run:
        lines.append("Nothing was changed (dry run).")
    return "\n".join(lines)
