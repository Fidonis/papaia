#!/usr/bin/env python3
"""1.5.0 -- build LibreChat's tenant-scoped MongoDB indexes.

LibreChat 0.8.8 replaced the unique indexes of several collections (User, Role, Preset,
AccessRole, MCPServer, AgentCategory, Message, Conversation) with tenant-scoped ones. A
database written by 0.8.7 or earlier still carries the old unique indexes under the same
names, so the new ones cannot be built and LibreChat logs `Index build failed` on every
start -- single-tenant installs included. Upstream ships the fix as an explicit maintenance
command (`npm run migrate:tenant-indexes`) and requires every writer to be stopped.

`papaia-ctl upgrade` has stopped the stack and taken a backup by the time migrations run,
which is that precondition. This script starts a throwaway MongoDB on the LibreChat volume
and runs the command from the LibreChat image this release ships, after a dry run. Upstream
builds the new indexes first, drops only the known superseded ones, never touches documents
and completes a partially applied run when repeated, so the script is safe to re-run.

No LibreChat volume (fresh install, or the profile was never used) means nothing to do.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from lib import common

COMPOSE_FILE = Path("src/ai/librechat/docker-compose.yml")

# Fixed names, not pid-derived: a run killed half-way leaves its MongoDB holding the
# volume lock, and the next run has to find and remove exactly that container.
NETWORK = "papaia-librechat-migrate"
MONGO_CONTAINER = "papaia-librechat-migrate-mongo"

READY_TIMEOUT_S = 90
READY_POLL_S = 2


class MigrationError(Exception):
    pass


def _docker(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], text=True, capture_output=capture, check=False)


def _say(message: str) -> None:
    print(f"  librechat-tenant-indexes: {message}", flush=True)


def _images(repo_root: Path) -> tuple[str, str]:
    """The LibreChat and MongoDB images this release pins, read from its compose file so
    the migration cannot drift from what the stack is about to start."""
    compose = yaml.safe_load((repo_root / COMPOSE_FILE).read_text(encoding="utf-8"))
    try:
        services = compose["services"]
        return services["librechat"]["image"], services["librechat-mongodb"]["image"]
    except (KeyError, TypeError) as exc:
        raise MigrationError(
            f"cannot find the librechat / librechat-mongodb images in {COMPOSE_FILE}"
        ) from exc


def _volume_exists(volume: str) -> bool:
    result = _docker("volume", "inspect", volume, capture=True)
    if result.returncode == 0:
        return True
    stderr = (result.stderr or "").strip()
    # Anything but "no such volume" (daemon down, permission denied) must not read as
    # "nothing to migrate": that would skip the migration silently.
    if "no such volume" in stderr.lower():
        return False
    raise MigrationError(f"cannot inspect volume {volume}: {stderr or 'docker failed'}")


def _remove_leftovers() -> None:
    _docker("rm", "-f", MONGO_CONTAINER, capture=True)
    _docker("network", "rm", NETWORK, capture=True)


def _require_unused(volume: str) -> None:
    result = _docker("ps", "-q", "--filter", f"volume={volume}", capture=True)
    if result.returncode != 0:
        raise MigrationError(f"cannot list the containers using {volume}")
    if (result.stdout or "").strip():
        raise MigrationError(
            f"volume {volume} is in use by a running container. Stop the stack"
            " (papaia-ctl stop --addons) and run the upgrade again."
        )


def _start_mongo(image: str, volume: str) -> None:
    if _docker("network", "create", NETWORK, capture=True).returncode != 0:
        raise MigrationError(f"cannot create the temporary network {NETWORK}")
    result = _docker(
        "run", "-d", "--name", MONGO_CONTAINER, "--network", NETWORK,
        "-v", f"{volume}:/data/db", image, "mongod", "--noauth",
        capture=True,
    )  # fmt: skip
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise MigrationError(f"cannot start the temporary MongoDB from {image}: {detail}")

    deadline = time.monotonic() + READY_TIMEOUT_S
    while time.monotonic() < deadline:
        ping = _docker(
            "exec", MONGO_CONTAINER, "mongosh", "--quiet", "--eval",
            "db.adminCommand('ping').ok", capture=True,
        )  # fmt: skip
        if ping.returncode == 0 and (ping.stdout or "").strip() == "1":
            return
        time.sleep(READY_POLL_S)
    _docker("logs", "--tail", "20", MONGO_CONTAINER)
    raise MigrationError(f"the temporary MongoDB was not ready after {READY_TIMEOUT_S}s")


def _npm(image: str, script: str) -> None:
    _say(f"npm run {script}")
    # -w /app: the root npm scripts live there, the image would otherwise start in /app/api.
    result = _docker(
        "run", "--rm", "--network", NETWORK,
        "-e", f"MONGO_URI=mongodb://{MONGO_CONTAINER}:27017/LibreChat",
        "-w", "/app", "--entrypoint", "npm", image, "run", script,
    )  # fmt: skip
    if result.returncode != 0:
        raise MigrationError(f"`npm run {script}` failed with exit code {result.returncode}")


def main() -> int:
    config_dir = Path(os.environ["PAPAIA_CONFIG_DIR"])
    repo_root = Path(os.environ["PAPAIA_REPO_ROOT"])
    project = common.parse_env_file(config_dir / ".env").get("COMPOSE_PROJECT_NAME") or "papaia"
    volume = f"{project}_librechat-mongodb"

    try:
        if not _volume_exists(volume):
            _say(f"no {volume} volume, nothing to migrate")
            return 0
        librechat_image, mongo_image = _images(repo_root)
        _require_unused(volume)

        _remove_leftovers()
        try:
            _say(f"starting a temporary MongoDB on {volume}")
            _start_mongo(mongo_image, volume)
            _npm(librechat_image, "migrate:tenant-indexes:dry-run")
            _npm(librechat_image, "migrate:tenant-indexes")
        finally:
            _remove_leftovers()
    except FileNotFoundError:
        print("error: the docker CLI was not found", file=sys.stderr)
        return 1
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
