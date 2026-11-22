"""The internal path to the Keycloak admin API.

Keycloak publishes no host port: browsers reach it through the edge, and its admin API is
never routed through the edge at all. The steps that call the admin API (role and realm
sync, post-restore, service accounts, the clients of an add-on) therefore run where the
stack's own services reach Keycloak: on the stack network, at `https://keycloak:8443`.

- In a container (papaia-manager and its runners) the step joins the stack network
  (lib/stack_network.py) and runs in place.
- On the host it runs in a one-shot container on the stack network, the network Keycloak
  is on, and is removed when it ends. The container runs the same `lib.cli` command from
  this checkout with the image papaia-manager runs papaia-ctl in (pinned in
  src/manager/docker-compose.yml), as the host user, with a read-only root file system,
  no capabilities and no Docker socket. It first checks that the image's python3 can
  run this checkout (its Python version and PyYAML) and stops with a clear message if
  not. The checkout and the active add-on checkouts
  (realm sync reads their manifests) are mounted read-only, the configuration folder
  read-write, each at the same path as on the host (the steps write files there).
- With direct port access, which publishes Keycloak's port, the host uses that port as
  before.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import yaml

from . import common, deployment, direct_ports

RUNNER_COMPOSE = Path("src") / "manager" / "docker-compose.yml"
RUNNER_SERVICE = "papaia-manager"
ROLE_LABEL = "keycloak-admin-step"
DEFAULT_NETWORK = "papaia-net"
STEP_TIMEOUT_SECONDS = 900

# The `lib.cli` commands that call the admin API.
ADMIN_COMMANDS = frozenset(
    {
        "keycloak-role-sync",
        "realm-sync",
        "realm-keys-apply",
        "post-restore",
        "service-account-list",
        "service-account-rotate",
        "addon-clients-sync",
    }
)

_PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_:-]{0,250}@sha256:[0-9a-f]{64}$")
_NETWORK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ID = re.compile(r"^[0-9]{1,10}$")
_MOUNT = re.compile(r"^/[^:,\0]{0,4095}$")

Runner = Callable[..., subprocess.CompletedProcess]

# The exit status of the one-shot container when its python3 cannot run lib.cli.
PREFLIGHT_FAILED = 3
# Run in the container before lib.cli: the image's python3 must meet this checkout's
# requires-python and carry PyYAML, or every admin step would end in a traceback.
PREFLIGHT = f"""\
import sys
_image = "the papaia-manager image (src/manager/docker-compose.yml)"
if sys.version_info < (3, 10):
    sys.stderr.write(
        "ERROR: python3 %d.%d of %s is too old for papaia-ctl, which needs 3.10 or later\\n"
        % (sys.version_info[0], sys.version_info[1], _image)
    )
    sys.exit({PREFLIGHT_FAILED})
try:
    import yaml  # noqa: F401
except ImportError:
    sys.stderr.write("ERROR: python3 of %s has no PyYAML, which papaia-ctl needs\\n" % _image)
    sys.exit({PREFLIGHT_FAILED})
import runpy
sys.argv = ["lib.cli", *sys.argv[1:]]
runpy.run_module("lib.cli", run_name="__main__", alter_sys=True)
"""


class AdminPathError(RuntimeError):
    """The one-shot container cannot be set up."""


def keycloak_published(root: dict[str, str]) -> bool:
    """Whether Keycloak has a host port: only with direct port access and its profile."""
    profiles = {p.strip() for p in (root.get("COMPOSE_PROFILES") or "").split(",")}
    return direct_ports.direct_mode(root) is not None and "keycloak" in profiles


def needs_oneshot(root: dict[str, str]) -> bool:
    """Whether an admin step started here has to run in a one-shot container: on the
    host, with the bundled Keycloak, which publishes no port."""
    if common.in_container():
        return False
    if (root.get("AUTH_PROVIDER") or "internal_keycloak") != "internal_keycloak":
        return False
    return not keycloak_published(root)


def runner_image(repo_root: Path) -> str:
    """The pinned image of papaia-manager, which carries the runtime papaia-ctl needs."""
    path = repo_root / RUNNER_COMPOSE
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        image = doc["services"][RUNNER_SERVICE]["image"]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise AdminPathError(f"cannot read the image of {RUNNER_SERVICE} from {path}") from exc
    if not isinstance(image, str) or not _PINNED_IMAGE.match(image):
        raise AdminPathError(f"the image of {RUNNER_SERVICE} is not pinned by digest")
    return image


def _host_id(root: dict[str, str], key: str, fallback: int) -> str:
    value = (root.get(key) or "").strip()
    if value and _ID.match(value):
        return value
    return str(fallback)


def _read_only_mounts(config_dir: Path, repo_root: Path) -> list[Path]:
    """The checkout and the active add-on checkouts, without a path below another one.
    AdminPathError for a path Docker's volume syntax cannot carry."""
    paths = [repo_root.resolve()]
    try:
        doc = deployment.load(config_dir) or {}
        addons = deployment.active_addons(doc)
    except Exception as exc:  # an unreadable deployment.yaml: the step reports it itself
        print(f"WARNING: add-on checkouts not mounted: {exc}", file=sys.stderr)
        addons = []
    for addon in addons:
        if isinstance(addon, dict) and isinstance(addon.get("path"), str):
            path = deployment.resolve_addon_path(addon, repo_root)
            if path.is_dir():
                paths.append(path)
    kept: list[Path] = []
    for path in sorted(set(paths), key=lambda p: len(p.parts)):
        if any(path.is_relative_to(k) for k in kept):
            continue
        if not _MOUNT.match(str(path)):
            raise AdminPathError(f"cannot mount {path}: the path carries ':' or ','")
        kept.append(path)
    return kept


def oneshot_argv(
    root: dict[str, str], config_dir: Path, repo_root: Path, command: list[str]
) -> list[str]:
    """The `docker run` command line of one admin step. AdminPathError for a command
    that is not an admin step or values that cannot be used."""
    if not command or command[0] not in ADMIN_COMMANDS:
        raise AdminPathError(f"not an admin step: {command[:1]}")
    network = (root.get("DOCKER_NETWORK") or DEFAULT_NETWORK).strip()
    if not _NETWORK.match(network):
        raise AdminPathError(f"DOCKER_NETWORK={network!r} is not a network name")
    config = config_dir.resolve()
    repo = repo_root.resolve()
    if not _MOUNT.match(str(config)):
        raise AdminPathError(f"cannot mount {config}: the path carries ':' or ','")
    read_only = [
        arg
        for path in _read_only_mounts(config_dir, repo_root)
        if path != config
        for arg in ("--volume", f"{path}:{path}:ro")
    ]
    uid = _host_id(root, "UID", os.getuid() if hasattr(os, "getuid") else 1000)
    gid = _host_id(root, "GID", os.getgid() if hasattr(os, "getgid") else 1000)
    return [
        "docker", "run", "--rm",
        "--network", network,
        "--user", f"{uid}:{gid}",
        "--read-only",
        "--tmpfs", "/tmp:size=16m,mode=1777",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--label", "de.fidonis.module=papaia-auth",
        "--label", f"de.fidonis.role={ROLE_LABEL}",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        *read_only,
        "--volume", f"{config}:{config}",
        "--workdir", str(repo / "tools"),
        "--entrypoint", "python3",
        runner_image(repo_root),
        "-c", PREFLIGHT,
        "--repo-root", str(repo),
        "--config-dir", str(config),
        *command,
    ]


def run(
    root: dict[str, str],
    config_dir: Path,
    repo_root: Path,
    command: list[str],
    *,
    runner: Runner | None = None,
) -> int:
    """Run one admin step in the one-shot container; its exit status is the step's."""
    try:
        argv = oneshot_argv(root, config_dir, repo_root, command)
    except AdminPathError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Running '{command[0]}' in a one-shot container on the stack network"
        " (Keycloak publishes no port).",
        flush=True,
    )
    try:
        done = (runner or subprocess.run)(argv, check=False, timeout=STEP_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: cannot run docker: {exc}", file=sys.stderr)
        return 1
    return int(done.returncode)
