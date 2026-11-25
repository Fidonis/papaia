"""Per-session Docker names and address ranges of the live tests.

Two test sessions may share one Docker host: two CI shards of a self-hosted runner, two
local runs, a local run beside a running stack. A fixed Compose project name or subnet
then collides ("Pool overlaps", containers of the other session in the same project).
Every live module therefore takes its defaults from here:

  * `project(base, variable)`: the variable when set, otherwise
    `<prefix>-<base>-<session>`. The session part is `<GITHUB_RUN_ID>-<shard>-<pid>` in CI
    (the shard from PAPAIA_TEST_SHARD), otherwise a random value with the shard and the
    process id. The prefix is PAPAIA_TEST_PROJECT_PREFIX, default `papaia`.
  * `subnet(variable)`: the variable when set, otherwise a block of the pool
    PAPAIA_TEST_SUBNET_POOL (default 10.240.0.0/12, a private range the stack does not
    use) of the size PAPAIA_TEST_SUBNET_SIZE (prefix length 24 to 27, default 24). A block
    overlapping a Docker network of the host or a block another running session holds is
    never handed out; a session holds its blocks through claim files in the temporary
    directory until it exits.
  * `port(variable)`: the variable when set, otherwise a free loopback port.

The overrides of every module keep working; this module never removes a Docker object.
"""

from __future__ import annotations

import atexit
import errno
import fcntl
import functools
import ipaddress
import os
import re
import secrets
import socket
import subprocess
import tempfile
from pathlib import Path

PREFIX_VARIABLE = "PAPAIA_TEST_PROJECT_PREFIX"
SHARD_VARIABLE = "PAPAIA_TEST_SHARD"
POOL_VARIABLE = "PAPAIA_TEST_SUBNET_POOL"
SIZE_VARIABLE = "PAPAIA_TEST_SUBNET_SIZE"
DEFAULT_PREFIX = "papaia"
DEFAULT_POOL = "10.240.0.0/12"
DEFAULT_SIZE = 24
SIZES = range(24, 28)
CLAIMS = Path(tempfile.gettempdir()) / "papaia-test-subnets"

_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_held: list[Path] = []


def _label(value: str, what: str) -> str:
    label = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower()).strip("-")
    if not _NAME.fullmatch(label):
        raise ValueError(f"{what} {value!r} gives no usable Compose name part")
    return label


@functools.cache
def session() -> str:
    """The session part of every default name, the same for the whole process."""
    run = os.environ.get("GITHUB_RUN_ID", "").strip()
    shard = os.environ.get(SHARD_VARIABLE, "").strip()
    parts = [_label(run, "GITHUB_RUN_ID") if run else secrets.token_hex(3)]
    if shard:
        parts.append(_label(shard, SHARD_VARIABLE))
    parts.append(str(os.getpid()))
    return "-".join(parts)


def project(base: str, variable: str) -> str:
    """The Compose project (and name prefix of every Docker object) of one live module."""
    override = os.environ.get(variable, "").strip()
    if override:
        return override
    prefix = _label(os.environ.get(PREFIX_VARIABLE, "") or DEFAULT_PREFIX, PREFIX_VARIABLE)
    return f"{prefix}-{_label(base, 'base')}-{session()}"


def port(variable: str) -> int:
    """A host port of one live module: the variable when set, otherwise a free one."""
    override = os.environ.get(variable, "").strip()
    if override:
        return int(override)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _pool() -> tuple[ipaddress.IPv4Network, int]:
    pool = ipaddress.ip_network(os.environ.get(POOL_VARIABLE, "").strip() or DEFAULT_POOL)
    size = int(os.environ.get(SIZE_VARIABLE, "").strip() or DEFAULT_SIZE)
    if not isinstance(pool, ipaddress.IPv4Network) or not pool.is_private:
        raise ValueError(f"{POOL_VARIABLE} must be a private IPv4 range, not {pool}")
    if size not in SIZES or pool.prefixlen > size:
        raise ValueError(f"{SIZE_VARIABLE} must be 24 to 27 and not larger than {pool}")
    return pool, size


@functools.cache
def _docker_subnets() -> tuple[ipaddress.IPv4Network, ...]:
    """The IPv4 ranges of the host's Docker networks (none when Docker does not answer)."""
    try:
        ids = subprocess.run(["docker", "network", "ls", "-q"], capture_output=True,
                             text=True, timeout=30, check=True).stdout.split()  # fmt: skip
        if not ids:
            return ()
        shown = subprocess.run(
            ["docker", "network", "inspect", "--format",
             "{{range .IPAM.Config}}{{.Subnet}} {{end}}", *ids],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout.split()  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return ()
    found = []
    for value in shown:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            found.append(network)
    return tuple(found)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError as error:
        return error.errno == errno.EPERM
    return True


def _claims() -> list[ipaddress.IPv4Network]:
    """Blocks held by running sessions; claims of ended sessions are removed."""
    held = []
    for path in CLAIMS.glob("*.claim"):
        try:
            pid = int(path.read_text(encoding="utf-8").strip() or "0")
            network = ipaddress.ip_network(path.stem.replace("_", "/"))
        except (OSError, ValueError):
            continue
        if pid != os.getpid() and not _alive(pid):
            path.unlink(missing_ok=True)
            continue
        held.append(network)
    return held


def _release() -> None:
    for path in _held:
        try:
            if path.read_text(encoding="utf-8").strip() == str(os.getpid()):
                path.unlink()
        except OSError:
            pass


def subnet(variable: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """The address range of one live module for this session."""
    override = os.environ.get(variable, "").strip()
    if override:
        return ipaddress.ip_network(override)
    pool, size = _pool()
    blocks = list(pool.subnets(new_prefix=size))
    taken = _docker_subnets()
    CLAIMS.mkdir(mode=0o700, exist_ok=True)
    with open(CLAIMS / ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        held = _claims()
        start = secrets.randbelow(len(blocks))
        for index in range(len(blocks)):
            block = blocks[(start + index) % len(blocks)]
            if any(block.overlaps(other) for other in (*taken, *held)):
                continue
            path = CLAIMS / f"{str(block).replace('/', '_')}.claim"
            path.write_text(f"{os.getpid()}\n", encoding="utf-8")
            if not _held:
                atexit.register(_release)
            _held.append(path)
            return block
    raise RuntimeError(f"no free /{size} left in {pool} ({POOL_VARIABLE})")
