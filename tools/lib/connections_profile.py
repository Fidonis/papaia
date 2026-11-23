"""The core profile `connections`: the connection registry (ADR 0021).

`papaia-ctl secrets rotate connections/credentials` replaces the key that seals the
stored credentials: in the running registry it runs `rotate-keys` of papaia-connections,
which makes a new master key active, seals every stored credential again with a new data
key and removes the key files nothing needs any more. The registry journals the change;
papaia-ctl writes one `papaia.audit/1` row with the outcome. No credential, key or key id
reaches papaia-ctl's output or its row, only the registry's summary line (counts).

The command needs the registry running on this host: it is the only process that holds
the keys, and the key volume is mounted into no other container.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from . import common, images

PROFILE = "connections"
SERVICE = "connections"
ROTATE_TARGET = "connections/credentials"
ROTATE_TARGETS = (ROTATE_TARGET,)
# The registry's command line inside its image (papaia-connections, `rotate-keys`).
ROTATE_COMMAND = ("/app/.venv/bin/python", "-m", "papaia_connections.main", "rotate-keys")
DOCKER_TIMEOUT_SECONDS = 60
ROTATE_TIMEOUT_SECONDS = 600
_MAX_SUMMARY = 500

Runner = Callable[..., subprocess.CompletedProcess]


class ConnectionsError(Exception):
    """The registry cannot do what was asked; the message says what to do."""


def _container(project: str, run: Runner) -> str:
    try:
        found = run(
            [
                "docker", "ps", "-q",
                "--filter", f"label=com.docker.compose.project={project}",
                "--filter", f"label=com.docker.compose.service={SERVICE}",
                "--filter", "status=running",
            ],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConnectionsError(f"docker did not answer: {exc}") from None
    ids = found.stdout.split() if found.returncode == 0 else []
    if len(ids) != 1:
        raise ConnectionsError(
            "the registry is not running; start it with 'papaia-ctl start' and run the "
            "command again"
        )
    return ids[0]


def _audit(config_dir: Path, correlation: str, *, failed: bool) -> None:
    """One `papaia.audit/1` row per rotation; no key, id or value is part of it."""
    event = "connections_credentials_rotated"
    row = images._row("secrets-rotate", event, {"target": ROTATE_TARGET}, correlation)
    row["effect"] = "write"
    if failed:
        row["result"], row["error_code"] = "failed", "rotate_keys_failed"
    images.append_audit(config_dir, row)


def rotate_credentials(
    config_dir: Path, *, correlation: str | None = None, run: Runner = subprocess.run
) -> str:
    """Run `rotate-keys` in the running registry; returns its summary line."""
    config_dir = Path(config_dir)
    correlation = images.correlation_id(correlation)  # checked before anything happens
    root = common.parse_env_file(config_dir / ".env")
    if PROFILE not in common.cluster_profiles(root):
        raise ConnectionsError(
            "the profile connections is not on; switch it on with "
            "'papaia-ctl setup --connections' first"
        )
    container = _container(root.get("COMPOSE_PROJECT_NAME") or "papaia", run)
    try:
        done = run(
            ["docker", "exec", container, *ROTATE_COMMAND],
            capture_output=True, text=True, timeout=ROTATE_TIMEOUT_SECONDS, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        _audit(config_dir, correlation, failed=True)
        raise ConnectionsError(f"rotate-keys failed: {type(exc).__name__}") from None
    if done.returncode != 0:
        _audit(config_dir, correlation, failed=True)
        # The registry prints its error code, never a value; only the last line is shown.
        lines = (done.stderr or done.stdout or "").strip().splitlines()
        reason = lines[-1][:_MAX_SUMMARY] if lines else f"exit {done.returncode}"
        raise ConnectionsError(f"rotate-keys failed: {reason}")
    _audit(config_dir, correlation, failed=False)
    lines = (done.stdout or "").strip().splitlines()
    return lines[-1][:_MAX_SUMMARY] if lines else "rotate-keys finished"
