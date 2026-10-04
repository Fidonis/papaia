"""Preflight and diagnostics: is this host, and this installation, in shape?

`run_checks()` evaluates an ordered registry of checks and returns a
`DoctorReport`; rendering is separate, the shape `compat.py` and `status.py`
follow. Each check answers `pass`, `warn`, `fail` or `skip` (not applicable
here: offline, not set up yet, nothing to look at). Only `fail` makes the
command exit non-zero.

Nothing here changes anything. The probes are reads: `docker version/info` and
`docker system df`, `shutil.disk_usage`, `/proc/meminfo` and the load average, `nvidia-smi` /
`rocm-smi` / `timedatectl`, a TCP connect to localhost, a name lookup,
`openssl x509` on a file, plus everything `status` reads. Inside a container,
where the host's driver tools and `timedatectl` are out of reach, the NVIDIA GPU
is read with a `docker exec` of `nvidia-smi` into the LocalAI container and the
clock with `adjtimex(2)`, which only reads.

Load and pressure findings (memory, CPU, VRAM, temperature, clock) are at most
`warn`: a busy host is not a broken installation, and `doctor` is also the
preflight before `setup` and `upgrade`. The one `fail` among the host checks is
a GPU variant that cannot start (driver, runtime or device missing).

`doctor` may be slower than `status` (lookups, connects) and is not meant for
tight polling. It works before `setup`: checks that need the installation's
configuration report `skip` instead of aborting.

Checks are registered in `CHECKS`; a new one is a function taking the shared
`Context` and returning a `CheckResult`, appended to that list. Every probe that
touches the outside world goes through `Probes` or `Context.run`, which is what
keeps the checks testable without a Docker daemon, a network or a certificate.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import json
import math
import os
import re
import shutil
import socket
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import backup, cli_addon, common, compat, deployment, envtree, gpu_detect, semver, status
from .status import Runner

SCHEMA_VERSION = 1

PASS = "pass"
WARN = "warn"
FAIL = "fail"
SKIP = "skip"

# The Compose files use top-level `include:` and `depends_on.required`, both
# introduced with Compose 2.20.0. Docker Engine itself is only checked for
# reachability: no engine floor is documented.
MIN_COMPOSE = "2.20.0"

_GIB = 1024**3
DISK_WARN_FREE_BYTES = 10 * _GIB
DISK_FAIL_FREE_BYTES = 2 * _GIB

CERT_WARN_DAYS = 30
CERT_FAIL_DAYS = 7

# The documented recommendation is "8 GB". Decimal on purpose: a host sold as
# 8 GiB reports less than that as MemTotal once the kernel has taken its share,
# and would warn on every run against a binary threshold.
MEMORY_WARN_TOTAL_BYTES = 8 * 10**9
MEMORY_WARN_AVAILABLE_BYTES = 1 * _GIB
MEMORY_WARN_AVAILABLE_FRACTION = 0.10

# Runnable tasks per core, over five minutes. At 1.0 the CPUs are saturated for
# a sustained stretch; LocalAI inference on the CPU image does that by design,
# which is why this is a warning and never a failure.
CPU_WARN_LOAD_PER_CORE = 1.0

# Utilization is reported but does not count: it is high during any inference.
GPU_VRAM_WARN_PERCENT = 90
GPU_TEMP_WARN_CELSIUS = 85

DNS_TIMEOUT_SECONDS = 3.0
PORT_PROBE_TIMEOUT_SECONDS = 0.5
DOCKER_PROBE_TIMEOUT_SECONDS = 10.0
# `docker system df` makes the daemon work out the size of every volume and of the
# build cache, which grows with the data: 1.5 s on a stack with 75 volumes.
DOCKER_USAGE_TIMEOUT_SECONDS = 20.0
# nvidia-smi is known to hang on a broken driver, hence its own bound.
GPU_PROBE_TIMEOUT_SECONDS = 10.0
# Through `docker exec` the bound has to be set inside the container as well:
# killing the CLI that started an exec leaves its process running there. The
# inner one is the shorter, so a hang is `timeout`'s exit 124 and not a kill.
GPU_EXEC_TIMEOUT_SECONDS = 8
TIME_PROBE_TIMEOUT_SECONDS = 5.0

# What systemd's `NTPSynchronized` means: the kernel's estimated maximum error is
# under sixteen seconds. The kernel starts at exactly that figure and only lowers
# it while something disciplines the clock.
KERNEL_CLOCK_SYNCED_MAXERROR_US = 16_000_000

LOCALAI_PROFILE = "localai"
LOCALAI_SERVICE = "localai"
GPU_OVERRIDE = Path("overrides") / "docker-compose.localai-gpu.override.yml"

_SEVERITY = {FAIL: 0, WARN: 1, PASS: 2, SKIP: 3}


class DoctorError(Exception):
    """A user-facing, non-traceback-worthy failure (bad flag value)."""


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


class CertReadError(Exception):
    """A certificate whose expiry could not be read (no openssl, bad file)."""


# ─────────────────────────────────────────────────────────────────────────
# probes
# ─────────────────────────────────────────────────────────────────────────

# Name lookup outcomes.
RESOLVED = "resolved"
NOT_FOUND = "not_found"
UNAVAILABLE = "unavailable"


def _disk_usage(path: Path) -> tuple[int, int]:
    usage = shutil.disk_usage(path)
    return usage.total, usage.free


def _connect(host: str, port: int) -> bool:
    """Whether something accepts TCP connections on host:port.

    A connect rather than a bind: it needs no privilege for ports below 1024,
    and it cannot take the port from the service that is about to use it."""
    try:
        with socket.create_connection((host, port), timeout=PORT_PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def _resolve(host: str) -> str:
    """RESOLVED, NOT_FOUND, or UNAVAILABLE (resolver unreachable or too slow).

    getaddrinfo has no timeout of its own, so it runs in a worker thread."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(socket.getaddrinfo, host, None)
    try:
        future.result(timeout=DNS_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        return UNAVAILABLE
    except socket.gaierror as exc:
        # EAI_AGAIN is "temporary failure": the resolver could not be asked.
        return UNAVAILABLE if exc.errno == getattr(socket, "EAI_AGAIN", None) else NOT_FOUND
    except OSError:
        return UNAVAILABLE
    finally:
        pool.shutdown(wait=False)
    return RESOLVED


def _cert_enddate(path: Path, run: Runner) -> datetime:
    """`notAfter` of a PEM certificate, read by openssl.

    openssl is already a hard requirement of `setup` (it generates the bundled
    certificates), and the standard library cannot parse X.509 dates without
    private APIs, so this adds no dependency."""
    result = run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"], 10.0)
    if result.returncode == 127:
        raise CertReadError("openssl not found")
    line = status.first_line(result.stdout)
    if result.returncode != 0 or not line.startswith("notAfter="):
        raise CertReadError(status.first_line(result.stderr) or "not a readable certificate")
    value = " ".join(line.removeprefix("notAfter=").split())
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CertReadError(f"unexpected date format: {value}") from exc


@dataclass(frozen=True)
class MemInfo:
    """Host memory in bytes. Swap is zero on a host without any."""

    total: int
    available: int
    swap_total: int
    swap_free: int


def parse_meminfo(text: str) -> MemInfo | None:
    """`/proc/meminfo` as MemInfo, or None if it does not carry a total.

    The kernel prints `kB` but means KiB. `MemAvailable` exists since Linux 3.14;
    on anything older free plus reclaimable caches is the closest honest answer.
    """
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            values[key.strip()] = int(fields[0]) * 1024
    total = values.get("MemTotal")
    if not total:
        return None
    available = values.get("MemAvailable")
    if available is None:
        available = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    return MemInfo(
        total=total,
        available=min(available, total),
        swap_total=values.get("SwapTotal", 0),
        swap_free=values.get("SwapFree", 0),
    )


def _meminfo() -> MemInfo | None:
    """None where there is no /proc (macOS, Windows): the caller falls back to
    what the Docker daemon reports."""
    try:
        return parse_meminfo(Path("/proc/meminfo").read_text(encoding="ascii", errors="replace"))
    except OSError:
        return None


def _loadavg() -> tuple[float, float, float] | None:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):  # not available on Windows
        return None


def _in_container() -> bool:
    """Whether this process runs inside a container, where the host's driver
    tools, device nodes and `timedatectl` are not visible. `papaia-manager`
    runs `doctor` in its own container."""
    return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    """`struct timex` of the 64-bit Linux ABI (glibc and musl alike, 208 bytes).

    Only `maxerror` is read; the rest is here because the kernel fills the whole
    structure and the buffer must be as large as it expects."""

    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time", _Timeval),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("reserved", ctypes.c_int * 11),
    ]


def _kernel_clock_synchronized() -> bool | None:
    """Whether the kernel considers the clock synchronized, read with `adjtimex(2)`.

    The clock belongs to the kernel, which a container shares with its host, so
    this answers the same as `timedatectl` does without needing systemd or its bus.
    With `modes` zero the call only reads and needs no capability; Docker's default
    seccomp profile allows it.

    Judged the way systemd judges `NTPSynchronized`: by `maxerror`, not by the
    `STA_UNSYNC` flag. systemd ignores the flag on purpose, because it can be set
    to keep the kernel from writing the RTC, and a flag-based check would call a
    host unsynchronized that `timedatectl` calls synchronized.

    None where it cannot be read: not 64-bit Linux, no `adjtimex` in the C
    library, or the call refused."""
    if not sys.platform.startswith("linux") or ctypes.sizeof(ctypes.c_long) != 8:
        return None
    try:
        adjtimex = ctypes.CDLL(None, use_errno=True).adjtimex
    except (OSError, AttributeError):
        return None
    adjtimex.argtypes = [ctypes.POINTER(_Timex)]
    adjtimex.restype = ctypes.c_int
    state = _Timex()
    if adjtimex(ctypes.byref(state)) < 0:
        return None
    return state.maxerror < KERNEL_CLOCK_SYNCED_MAXERROR_US


@dataclass
class Probes:
    disk_usage: Callable[[Path], tuple[int, int]] = _disk_usage
    connect: Callable[[str, int], bool] = _connect
    resolve: Callable[[str], str] = _resolve
    cert_enddate: Callable[[Path, Runner], datetime] = _cert_enddate
    meminfo: Callable[[], MemInfo | None] = _meminfo
    loadavg: Callable[[], tuple[float, float, float] | None] = _loadavg
    cpu_count: Callable[[], int | None] = os.cpu_count
    in_container: Callable[[], bool] = _in_container
    kernel_clock_synchronized: Callable[[], bool | None] = _kernel_clock_synchronized
    # Where device nodes live; the same seam `gpu_detect.compose_fragment` has.
    dev_root: Path = Path("/dev")


# ─────────────────────────────────────────────────────────────────────────
# context
# ─────────────────────────────────────────────────────────────────────────


class Context:
    """What the checks share: paths, the command runner, probes, and the
    values every check would otherwise re-read."""

    def __init__(
        self,
        config_dir: Path,
        repo_root: Path,
        *,
        run: Runner,
        probes: Probes,
        now: datetime,
    ):
        self.config_dir = config_dir
        self.repo_root = repo_root
        self.run = run
        self.probes = probes
        self.now = now
        self._status: status.StatusReport | None = None
        self._env: dict[str, dict[str, str]] | None = None
        self._totals: tuple[int | None, int | None] | None = None

    def docker_totals(self) -> tuple[int | None, int | None]:
        """(CPU count, memory in bytes) as the Docker daemon sees them.

        The platform-neutral answer for hosts without /proc: on Docker Desktop
        and WSL2 it describes the VM the containers actually run in. Asked
        lazily and once, so a Linux host never pays for it."""
        if self._totals is None:
            cpus: int | None = None
            memory: int | None = None
            result = self.run(
                ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
                DOCKER_PROBE_TIMEOUT_SECONDS,
            )
            parts = status.first_line(result.stdout).split()
            if result.returncode == 0 and len(parts) == 2 and all(p.isdigit() for p in parts):
                cpus, memory = int(parts[0]) or None, int(parts[1]) or None
            self._totals = (cpus, memory)
        return self._totals

    @property
    def configured(self) -> bool:
        """Whether `setup` has run: the same marker `_require_setup_done` uses."""
        return (self.config_dir / ".env").is_file() and (
            self.config_dir / "deployment.yaml"
        ).is_file()

    @property
    def tree(self) -> dict[str, dict[str, str]]:
        if self._env is None:
            self._env = envtree.load_config_dir_tree(self.config_dir, self.repo_root)
        return self._env

    @property
    def env(self) -> dict[str, str]:
        """All env values in one dict; the root `.env` wins, as it does for the
        `--env-file` Compose substitutes from."""
        flat: dict[str, str] = {}
        for rel_dir, values in self.tree.items():
            if rel_dir:
                flat.update(values)
        flat.update(self.tree.get("", {}))
        # The tree only knows directories the shipped seed has; whatever the
        # root file holds on top of that still counts.
        flat.update(common.parse_env_file(self.config_dir / ".env"))
        return flat

    @property
    def active_profiles(self) -> set[str]:
        return status.active_profiles(self.config_dir)

    def status_report(self) -> status.StatusReport:
        if self._status is None:
            self._status = status.collect(
                self.config_dir, self.repo_root, include_addons=True, run=self.run, now=self.now
            )
        return self._status


def _not_set_up(name: str) -> CheckResult:
    return CheckResult(name, SKIP, "not set up yet (run 'papaia-ctl setup' first)")


def _worst(statuses: Iterable[str]) -> str:
    items = list(statuses)
    return min(items, key=_SEVERITY.__getitem__) if items else SKIP


def _fmt_bytes(value: int) -> str:
    return f"{value / _GIB:.1f} GiB"


# ─────────────────────────────────────────────────────────────────────────
# checks
# ─────────────────────────────────────────────────────────────────────────


def _compose_version(text: str) -> str | None:
    match = re.search(r"\d+\.\d+\.\d+", text)
    return match.group(0) if match else None


def check_docker_version(ctx: Context) -> CheckResult:
    name = "docker_version"
    server = ctx.run(
        ["docker", "version", "--format", "{{.Server.Version}}"], DOCKER_PROBE_TIMEOUT_SECONDS
    )
    if server.returncode == 127:
        return CheckResult(name, FAIL, "docker not found on PATH")
    if server.returncode != 0:
        reason = status.first_line(server.stderr) or f"exit {server.returncode}"
        return CheckResult(name, FAIL, f"Docker daemon not reachable: {reason}")
    engine = status.first_line(server.stdout)

    compose = ctx.run(["docker", "compose", "version", "--short"], DOCKER_PROBE_TIMEOUT_SECONDS)
    details = {"engine": engine, "compose": None, "min_compose": MIN_COMPOSE}
    if compose.returncode != 0:
        return CheckResult(name, FAIL, "Docker Compose plugin not found", details)
    raw = status.first_line(compose.stdout)
    details["compose"] = raw
    found = _compose_version(raw)
    if found is None:
        return CheckResult(name, WARN, f"cannot read the Compose version from '{raw}'", details)
    if semver.compare(found, MIN_COMPOSE) < 0:
        return CheckResult(
            name,
            FAIL,
            f"Compose {found} is older than {MIN_COMPOSE}"
            " (needed for 'include:' and 'depends_on.required')",
            details,
        )
    return CheckResult(name, PASS, f"Docker Engine {engine}, Compose {found}", details)


def _nearest_existing(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return None


def check_disk_space(ctx: Context) -> CheckResult:
    name = "disk_space"
    targets: list[tuple[str, Path]] = [("config_dir", ctx.config_dir)]
    notes: list[str] = []

    backup_value = common.parse_env_file(ctx.config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if backup_value and not common.is_placeholder(backup_value):
        targets.append(("backup_dir", Path(backup_value).expanduser()))
    else:
        notes.append("backup_dir: PAPAIA_BACKUP_DIR not set")

    root = ctx.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"], DOCKER_PROBE_TIMEOUT_SECONDS
    )
    root_dir = status.first_line(root.stdout) if root.returncode == 0 else ""
    if root_dir and Path(root_dir).is_dir():
        targets.append(("docker_root", Path(root_dir)))
    else:
        # Docker Desktop keeps its data root inside a VM; the path it reports
        # does not exist on the host and cannot be measured from here.
        notes.append("docker_root: not reachable from the host")

    measured: list[dict[str, Any]] = []
    for label, path in targets:
        existing = _nearest_existing(path)
        if existing is None:
            notes.append(f"{label}: {path} does not exist")
            continue
        try:
            total, free = ctx.probes.disk_usage(existing)
        except OSError as exc:
            notes.append(f"{label}: {exc}")
            continue
        if free < DISK_FAIL_FREE_BYTES:
            verdict = FAIL
        elif free < DISK_WARN_FREE_BYTES:
            verdict = WARN
        else:
            verdict = PASS
        measured.append(
            {
                "label": label,
                "path": str(path),
                "free_bytes": free,
                "total_bytes": total,
                "status": verdict,
            }
        )

    if not measured:
        return CheckResult(name, SKIP, "no path could be measured", {"notes": notes})
    overall = _worst(m["status"] for m in measured)
    summary = ", ".join(f"{m['label']} {_fmt_bytes(m['free_bytes'])} free" for m in measured)
    if overall != PASS:
        summary += (
            f" (warn below {_fmt_bytes(DISK_WARN_FREE_BYTES)},"
            f" fail below {_fmt_bytes(DISK_FAIL_FREE_BYTES)})"
        )
    return CheckResult(name, overall, summary, {"paths": measured, "notes": notes})


# ─── docker_usage ────────────────────────────────────────────────────────

# The rows of `docker system df`, which names them in prose, and the keys the
# details use for them. Docker's own order, which is also the summary's.
_DOCKER_USAGE_TYPES = {
    "Images": "images",
    "Containers": "containers",
    "Local Volumes": "volumes",
    "Build Cache": "build_cache",
}

# Docker prints decimal units with four significant digits: `50.46GB`, `16.38kB`.
_DOCKER_UNITS = {"B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4, "PB": 1000**5}
_DOCKER_SIZE = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([kKMGTP]?B)\b")


def parse_docker_size(text: Any) -> int | None:
    """Bytes out of Docker's size text. `14.08GB (27 %)` reads as 14.08GB: the
    reclaimable column carries a share after the size, build cache's does not.
    The figure is as exact as the four digits Docker prints."""
    match = _DOCKER_SIZE.match(text) if isinstance(text, str) else None
    if match is None:
        return None
    return round(float(match.group(1)) * _DOCKER_UNITS[match.group(2).upper()])


def _fmt_docker_size(value: int) -> str:
    """Back to the spelling Docker uses, so the summary reads like `docker system df`."""
    size = float(value)
    for unit in ("B", "kB", "MB", "GB"):
        if size < 1000:
            return f"{size:.4g}{unit}"
        size /= 1000
    return f"{size:.4g}TB"


def _count(text: Any) -> int | None:
    return int(text) if isinstance(text, str) and text.strip().isdigit() else None


def parse_docker_system_df(text: str) -> dict[str, dict[str, int | None]]:
    """One entry per row of `docker system df --format '{{json .}}'`, by `_DOCKER_USAGE_TYPES`.

    A line that is not a JSON object, a row Docker adds later and a row whose size
    cannot be read are dropped; the caller reports what is left."""
    usage: dict[str, dict[str, int | None]] = {}
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        key = _DOCKER_USAGE_TYPES.get(str(row.get("Type")))
        size = parse_docker_size(row.get("Size"))
        if key is None or size is None:
            continue
        usage[key] = {
            "count": _count(row.get("TotalCount")),
            "active": _count(row.get("Active")),
            "size_bytes": size,
            "reclaimable_bytes": parse_docker_size(row.get("Reclaimable")),
        }
    return usage


def check_docker_usage(ctx: Context) -> CheckResult:
    """What Docker's data takes, as the daemon reports it.

    `disk_space` says how much room is left, and only where the data root can be
    seen: not on Docker Desktop, not inside a container. The daemon answers the
    other question, how much of the disk is Docker's, over the socket wherever the
    CLI runs. Report-only: how much Docker may take is the operator's call, and
    "reclaimable" volumes are ones no container uses now, not ones safe to delete."""
    name = "docker_usage"
    result = ctx.run(
        ["docker", "system", "df", "--format", "{{json .}}"], DOCKER_USAGE_TIMEOUT_SECONDS
    )
    # Nothing here is a finding about the installation: `docker_version` is the
    # check that fails for a daemon that is not there.
    if result.returncode == 127:
        return CheckResult(name, SKIP, "docker not found")
    if result.returncode == 124:
        return CheckResult(
            name, SKIP, f"docker system df timed out after {DOCKER_USAGE_TIMEOUT_SECONDS:g}s"
        )
    if result.returncode != 0:
        reason = status.first_line(result.stderr) or f"exit {result.returncode}"
        return CheckResult(name, SKIP, f"docker system df failed: {reason}")
    usage = parse_docker_system_df(result.stdout)
    if not usage:
        return CheckResult(name, SKIP, "cannot read the docker system df output")

    total = sum(row["size_bytes"] or 0 for row in usage.values())
    reclaimable = sum(row["reclaimable_bytes"] or 0 for row in usage.values())
    parts = []
    for key in _DOCKER_USAGE_TYPES.values():
        row = usage.get(key)
        if row is None:
            continue
        part = f"{key.replace('_', ' ')} {_fmt_docker_size(row['size_bytes'] or 0)}"
        if row["reclaimable_bytes"]:
            part += f" ({_fmt_docker_size(row['reclaimable_bytes'])} reclaimable)"
        parts.append(part)
    summary = f"Docker uses {_fmt_docker_size(total)}: " + ", ".join(parts)
    details = {"types": usage, "total_bytes": total, "reclaimable_bytes": reclaimable}
    return CheckResult(name, PASS, summary, details)


def check_memory(ctx: Context) -> CheckResult:
    name = "memory"
    info = ctx.probes.meminfo()
    available: int | None
    if info is not None:
        total, available = info.total, info.available
        details: dict[str, Any] = {
            "source": "proc",
            "total_bytes": total,
            "available_bytes": available,
            "used_percent": round(100 * (total - available) / total, 1),
            "swap_total_bytes": info.swap_total,
            "swap_used_bytes": max(info.swap_total - info.swap_free, 0),
        }
    else:
        # No /proc: the daemon knows the total of the machine (or VM) the
        # containers run on, but not how much of it is taken.
        docker_total = ctx.docker_totals()[1]
        if docker_total is None:
            return CheckResult(name, SKIP, "memory figures are not available on this platform")
        total, available = docker_total, None
        details = {
            "source": "docker_info",
            "total_bytes": total,
            "available_bytes": None,
            "used_percent": None,
            "swap_total_bytes": None,
            "swap_used_bytes": None,
        }

    reasons: list[str] = []
    if total < MEMORY_WARN_TOTAL_BYTES:
        reasons.append(f"total is below the recommended {MEMORY_WARN_TOTAL_BYTES // 10**9} GB")
    if available is not None and (
        available < MEMORY_WARN_AVAILABLE_BYTES
        or available < total * MEMORY_WARN_AVAILABLE_FRACTION
    ):
        reasons.append(
            f"available memory is low (warn below {MEMORY_WARN_AVAILABLE_FRACTION:.0%}"
            f" or {_fmt_bytes(MEMORY_WARN_AVAILABLE_BYTES)})"
        )

    if available is None:
        summary = f"{_fmt_bytes(total)} total (usage cannot be read on this platform)"
    else:
        summary = (
            f"{_fmt_bytes(total)} total, {_fmt_bytes(available)} available"
            f" ({details['used_percent']:.0f} % used)"
        )
    if reasons:
        summary += f" - {'; '.join(reasons)}"
    return CheckResult(name, WARN if reasons else PASS, summary, details)


def check_cpu(ctx: Context) -> CheckResult:
    name = "cpu"
    cores = ctx.probes.cpu_count()
    source = "os"
    if not cores:
        cores, source = ctx.docker_totals()[0], "docker_info"
    load = ctx.probes.loadavg()
    details: dict[str, Any] = {
        "source": source,
        "cores": cores,
        "load1": None,
        "load5": None,
        "load15": None,
        "load_per_core": None,
    }
    if not cores:
        return CheckResult(name, SKIP, "cannot determine the number of CPU cores", details)
    if load is None:
        return CheckResult(
            name, SKIP, f"{cores} core(s), no load average on this platform", details
        )

    load1, load5, load15 = load
    per_core = load5 / cores
    details.update(
        load1=round(load1, 2),
        load5=round(load5, 2),
        load15=round(load15, 2),
        load_per_core=round(per_core, 2),
    )
    summary = (
        f"{cores} core(s), load {load1:.2f} {load5:.2f} {load15:.2f}"
        f" (5 min: {per_core:.2f} per core)"
    )
    if per_core >= CPU_WARN_LOAD_PER_CORE:
        summary += f" - sustained load (warn at {CPU_WARN_LOAD_PER_CORE:g} per core)"
        return CheckResult(name, WARN, summary, details)
    return CheckResult(name, PASS, summary, details)


# ─── gpu ─────────────────────────────────────────────────────────────────

_NVIDIA_QUERY = "index,name,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu"
_NVIDIA_FIELDS = 7
_MIB = 1024**2


def _number(text: str) -> float | None:
    """A number out of tool output; None for `[N/A]`, `[Not Supported]` and the like."""
    try:
        value = float(text.strip())
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _whole(value: float | None) -> int | None:
    return None if value is None else int(value)


def _gpu_entry(
    index: int,
    name: str | None,
    driver: str | None,
    total_mib: int | None,
    used_mib: int | None,
    utilization: int | None,
    temperature: int | None,
) -> dict[str, Any]:
    percent = round(100 * used_mib / total_mib, 1) if total_mib and used_mib is not None else None
    return {
        "index": index,
        "name": name,
        "driver": driver,
        "memory_total_mib": total_mib,
        "memory_used_mib": used_mib,
        "vram_percent": percent,
        "utilization_percent": utilization,
        "temperature_c": temperature,
    }


def parse_nvidia_smi(text: str) -> list[dict[str, Any]]:
    """One entry per GPU out of `nvidia-smi --query-gpu=... --format=csv,noheader,nounits`.

    Parsed from both ends because only the name is free text, and it is the one
    field that could carry a comma. A line that does not fit is dropped, which
    is what a changed format looks like."""
    gpus: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < _NVIDIA_FIELDS:
            continue
        index = _number(parts[0])
        if index is None:
            continue
        total, used, utilization, temperature = (_whole(_number(p)) for p in parts[-4:])
        gpus.append(
            _gpu_entry(
                int(index),
                ", ".join(parts[1:-5]),
                parts[-5],
                total,
                used,
                utilization,
                temperature,
            )
        )
    return gpus


def parse_rocm_smi(text: str) -> list[dict[str, Any]]:
    """One entry per card out of `rocm-smi --showmeminfo vram --showuse --showtemp --json`.

    The key names differ between ROCm releases (`VRAM Total Memory (B)`,
    `GPU use (%)`, `Temperature (Sensor edge) (C)`), so they are matched by what
    they say rather than by exact spelling. Anything unrecognised yields no
    entry; the caller then reports the GPU without figures instead of guessing."""
    try:
        document = json.loads(text)
    except ValueError:
        return []
    if not isinstance(document, dict):
        return []
    gpus: list[dict[str, Any]] = []
    for key, card in document.items():
        match = re.fullmatch(r"card(\d+)", str(key))
        if not match or not isinstance(card, dict):
            continue
        total = used = utilization = temperature = None
        for label, raw in card.items():
            lower = str(label).lower()
            value = _number(str(raw))
            if "vram" in lower and "used" in lower:
                used = value
            elif "vram" in lower and "total" in lower:
                total = value
            elif lower.startswith("gpu use"):
                utilization = value
            elif "temperature" in lower and (temperature is None or "edge" in lower):
                temperature = value
        if all(v is None for v in (total, used, utilization, temperature)):
            continue
        gpus.append(
            _gpu_entry(
                int(match.group(1)),
                None,
                None,
                _whole(None if total is None else total / _MIB),
                _whole(None if used is None else used / _MIB),
                _whole(utilization),
                _whole(temperature),
            )
        )
    return sorted(gpus, key=lambda g: g["index"])


def _gpu_warnings(gpus: Sequence[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    for gpu in gpus:
        label = f"GPU {gpu['index']}"
        total, used = gpu["memory_total_mib"], gpu["memory_used_mib"]
        # The exact figures decide; `vram_percent` is rounded for display and
        # would turn 89.96 % into a warning.
        if total and used is not None and used * 100 >= total * GPU_VRAM_WARN_PERCENT:
            warnings.append(
                f"{label} VRAM {gpu['vram_percent']:.0f} % used (warn at {GPU_VRAM_WARN_PERCENT} %)"
            )
        temperature = gpu["temperature_c"]
        if temperature is not None and temperature >= GPU_TEMP_WARN_CELSIUS:
            warnings.append(f"{label} at {temperature}C (warn at {GPU_TEMP_WARN_CELSIUS}C)")
    return warnings


def _gpu_line(gpu: dict[str, Any]) -> str:
    parts: list[str] = []
    if gpu["memory_total_mib"] and gpu["memory_used_mib"] is not None:
        parts.append(
            f"{gpu['memory_used_mib'] / 1024:.1f}/{gpu['memory_total_mib'] / 1024:.1f} GiB VRAM"
        )
    if gpu["utilization_percent"] is not None:
        parts.append(f"{gpu['utilization_percent']} % util")
    if gpu["temperature_c"] is not None:
        parts.append(f"{gpu['temperature_c']}C")
    label = gpu["name"] or f"GPU {gpu['index']}"
    return f"{label}: {', '.join(parts)}" if parts else label


def _gpu_measured(
    name: str, gpus: Sequence[dict[str, Any]], details: dict[str, Any]
) -> CheckResult:
    details["gpus"] = list(gpus)
    summary = "; ".join(_gpu_line(g) for g in gpus)
    warnings = _gpu_warnings(gpus)
    if warnings:
        return CheckResult(name, WARN, f"{summary} ({'; '.join(warnings)})", details)
    return CheckResult(name, PASS, summary, details)


def _runtime_names(text: str) -> set[str] | None:
    """The runtimes registered with Docker, from `docker info --format '{{json .Runtimes}}'`.

    Keys of the JSON object, not a substring search: the values carry long
    feature annotations of their own. None if the output is not that object."""
    try:
        document = json.loads(text)
    except ValueError:
        return None
    return set(document) if isinstance(document, dict) else None


def _localai_container(ctx: Context) -> str | None:
    """Name of the running LocalAI container of the core stack, from the status
    report `container_health` shares. None if there is none: not started, or
    declared and never created."""
    for module in ctx.status_report().modules:
        if module.kind != "core":
            continue
        for container in module.containers:
            if (
                container.service == LOCALAI_SERVICE
                and container.state == "running"
                and container.name
            ):
                return container.name
    return None


def _exec_failure(result: status.CommandResult) -> str | None:
    """Why a `docker exec ... nvidia-smi` never reached `nvidia-smi`, or None when
    it did and the exit status is its own.

    `docker exec` hands back the command's exit status, so 126 and 127 (found but
    not runnable, not found) mean this image has no usable tool, and a refusal by
    the daemon (no such container, not running, no socket access) is exit 1 with a
    message of its own. Neither says anything about the driver, which is why they
    are not held against the host the way the same words from a local
    `nvidia-smi` are."""
    reason = status.first_line(result.stderr)
    if result.returncode in (126, 127):
        return f"nvidia-smi cannot be run in the LocalAI container (exit {result.returncode})"
    if (
        result.returncode == 125
        or reason.startswith("Error response from daemon")
        or "docker daemon" in reason.lower()
    ):
        return f"cannot reach the LocalAI container: {reason or 'docker exec failed'}"
    return None


def _gpu_nvidia(
    ctx: Context, variant: str, details: dict[str, Any], *, container: str | None = None
) -> CheckResult:
    """`nvidia-smi` on this host, or, given a `container`, inside that one.

    The figures are judged by the same parser and the same limits either way; only
    where the tool runs differs, and with it what a failure to run it proves."""
    name = "gpu"
    query = ["nvidia-smi", f"--query-gpu={_NVIDIA_QUERY}", "--format=csv,noheader,nounits"]
    if container is None:
        result = ctx.run(query, GPU_PROBE_TIMEOUT_SECONDS)
    else:
        result = ctx.run(
            ["docker", "exec", container, "timeout", str(GPU_EXEC_TIMEOUT_SECONDS), *query],
            GPU_PROBE_TIMEOUT_SECONDS,
        )
        unreachable = _exec_failure(result)
        if unreachable is not None:
            return CheckResult(name, SKIP, unreachable, details)
    if result.returncode == 127:
        return CheckResult(
            name,
            FAIL,
            f"nvidia-smi not found: the NVIDIA driver is not installed ({variant} is configured)",
            details,
        )
    if result.returncode == 124:
        return CheckResult(name, WARN, "nvidia-smi timed out: the driver does not answer", details)
    if result.returncode != 0:
        # nvidia-smi reports a broken driver on stdout as often as on stderr.
        reason = (
            status.first_line(result.stderr)
            or status.first_line(result.stdout)
            or f"exit {result.returncode}"
        )
        return CheckResult(name, FAIL, f"nvidia-smi failed: {reason}", details)
    gpus = parse_nvidia_smi(result.stdout)
    if not gpus:
        return CheckResult(name, WARN, "cannot read the nvidia-smi output", details)

    # The Compose reservation names the `nvidia` runtime; without it registered
    # Docker refuses to start LocalAI. If the daemon cannot be asked, that is
    # not evidence of a missing runtime.
    runtimes = ctx.run(
        ["docker", "info", "--format", "{{json .Runtimes}}"], DOCKER_PROBE_TIMEOUT_SECONDS
    )
    names = _runtime_names(runtimes.stdout) if runtimes.returncode == 0 else None
    details["nvidia_runtime"] = None if names is None else "nvidia" in names
    if details["nvidia_runtime"] is False:
        details["gpus"] = gpus
        return CheckResult(
            name,
            FAIL,
            "the 'nvidia' runtime is not registered with Docker: install the NVIDIA Container"
            " Toolkit, otherwise LocalAI cannot start",
            details,
        )
    return _gpu_measured(name, gpus, details)


def _gpu_amd(ctx: Context, details: dict[str, Any]) -> CheckResult:
    name = "gpu"
    if not (ctx.probes.dev_root / "kfd").exists():
        return CheckResult(
            name,
            FAIL,
            "/dev/kfd is missing: the ROCm kernel driver is not loaded, LocalAI cannot start",
            details,
        )
    result = ctx.run(
        ["rocm-smi", "--showmeminfo", "vram", "--showuse", "--showtemp", "--json"],
        GPU_PROBE_TIMEOUT_SECONDS,
    )
    if result.returncode == 124:
        return CheckResult(name, WARN, "rocm-smi timed out: the driver does not answer", details)
    gpus = parse_rocm_smi(result.stdout) if result.returncode == 0 else []
    if not gpus:
        # The ROCm stack lives in the LocalAI image, so a host without rocm-smi
        # is no fault; there is just nothing to measure with.
        reason = "rocm-smi not installed" if result.returncode == 127 else "rocm-smi unreadable"
        details["utilization_measured"] = False
        return CheckResult(
            name, PASS, f"/dev/kfd present, utilization not measured ({reason})", details
        )
    return _gpu_measured(name, gpus, details)


def _gpu_render_node(ctx: Context, variant: str, details: dict[str, Any]) -> CheckResult:
    name = "gpu"
    present = gpu_detect.has_render_node(ctx.probes.dev_root)
    details["render_node"] = present
    if present:
        return CheckResult(
            name,
            PASS,
            f"render node under /dev/dri present ({variant}; utilization is not measured)",
            details,
        )
    if variant == gpu_detect.INTEL:
        # The generated override maps /dev/dri into the container, so a missing
        # directory stops the start.
        return CheckResult(
            name,
            FAIL,
            "no render node under /dev/dri: the Intel GPU is not accessible, LocalAI cannot start",
            details,
        )
    # Vulkan maps whatever nodes exist; with none, LocalAI starts and quietly
    # runs on the CPU.
    return CheckResult(
        name, WARN, "no render node under /dev/dri: LocalAI falls back to the CPU", details
    )


def check_gpu(ctx: Context) -> CheckResult:
    name = "gpu"
    if not ctx.configured:
        return _not_set_up(name)
    if LOCALAI_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "LocalAI is not enabled")
    variant = ctx.env.get("LOCALAI_IMAGE_VARIANT", "").strip() or gpu_detect.CPU
    if variant == gpu_detect.CPU:
        return CheckResult(name, SKIP, "LocalAI runs on the CPU image")

    details: dict[str, Any] = {
        "variant": variant,
        "override_present": (ctx.config_dir / GPU_OVERRIDE).is_file(),
    }
    if variant not in gpu_detect.VARIANTS:
        return CheckResult(
            name,
            WARN,
            f"unknown LOCALAI_IMAGE_VARIANT '{variant}' (one of: {', '.join(gpu_detect.VARIANTS)})",
            details,
        )
    nvidia = variant in (gpu_detect.NVIDIA_CUDA_12, gpu_detect.NVIDIA_CUDA_13)
    if ctx.probes.in_container():
        if not nvidia:
            # /dev/kfd and the render nodes are the host's devices, and the
            # manager's own /dev has neither; AMD's tool is not on offer either.
            return CheckResult(
                name,
                SKIP,
                "not measurable from inside a container: the host's driver tools and devices"
                " are not visible",
                details,
            )
        # The container with the GPU is the one place NVIDIA's tool is guaranteed
        # to be: the toolkit puts `nvidia-smi` into every container that asked for
        # the `utility` capability, which LocalAI's image does.
        container = _localai_container(ctx)
        if container is None:
            return CheckResult(
                name,
                SKIP,
                "LocalAI is not running, and from inside a container the GPU can only be"
                " read through its container",
                details,
            )
        return _gpu_nvidia(ctx, variant, details, container=container)
    if nvidia:
        return _gpu_nvidia(ctx, variant, details)
    if variant == gpu_detect.HIPBLAS:
        return _gpu_amd(ctx, details)
    return _gpu_render_node(ctx, variant, details)


def _published_host_port(entry: str, env: dict[str, str]) -> tuple[str, int] | None:
    """(bind address, host port) of one short-syntax `ports:` entry, or None
    when the host side is not a single resolvable port (ephemeral, range,
    unset variable)."""
    expanded = backup.expand(entry, env).split("/", 1)[0]
    parts = expanded.split(":")
    if len(parts) == 3:
        address, host_port = parts[0], parts[1]
    elif len(parts) == 2:
        address, host_port = "", parts[0]
    else:
        return None
    if not host_port.isdigit():
        return None
    return address, int(host_port)


def check_ports(ctx: Context) -> CheckResult:
    name = "ports"
    if not ctx.configured:
        return _not_set_up(name)

    env = ctx.env
    expected = status.core_inventory(ctx.repo_root, ctx.active_profiles)
    wanted: dict[int, tuple[str, list[str]]] = {}
    for item in expected:
        for entry in item.ports:
            published = _published_host_port(entry, env)
            if published is None:
                continue
            address, port = published
            wanted.setdefault(port, (address, []))[1].append(item.service)
    if not wanted:
        return CheckResult(name, SKIP, "no published ports for the active profiles")

    report = ctx.status_report()
    ours = report.host_ports_in_use()
    items: list[dict[str, Any]] = []
    for port in sorted(wanted):
        address, services = wanted[port]
        probe_host = address if address and address not in ("0.0.0.0", "::") else "127.0.0.1"
        item: dict[str, Any] = {"port": port, "services": services, "holder": None}
        if not ctx.probes.connect(probe_host, port):
            item["status"] = PASS
        elif port in ours:
            item["status"] = PASS
            item["holder"] = ours[port]
        elif not report.docker.reachable:
            item["status"] = WARN
            item["holder"] = "unknown (Docker not reachable)"
        else:
            item["status"] = FAIL
            item["holder"] = "another process"
        items.append(item)

    overall = _worst(i["status"] for i in items)
    busy = [i for i in items if i["status"] in (WARN, FAIL)]
    if busy:
        listing = ", ".join(f"{i['port']} ({', '.join(i['services'])})" for i in busy)
        summary = f"already in use by something else: {listing}"
    else:
        held = sum(1 for i in items if i["holder"])
        summary = f"{len(items)} port(s) free or held by this installation" + (
            f" ({held} held)" if held else ""
        )
    return CheckResult(name, overall, summary, {"ports": items})


# Which env key holds a public URL, and the profile that makes it relevant.
_HOST_KEYS: tuple[tuple[str | None, str], ...] = (
    (None, "PAPAIA_HOST"),
    ("keycloak", "AUTH_HOST"),
    ("nginx", "NPM_ADMIN_HOST"),
    ("librechat", "DOMAIN_SERVER"),
    ("litellm", "LITELLM_PUBLIC_URL"),
    ("localai", "LOCALAI_PUBLIC_URL"),
    ("manager", "MANAGER_PUBLIC_URL"),
    ("rag", "QDRANT_PUBLIC_URL"),
    ("rag", "QDRANT_INGEST_PUBLIC_URL"),
)

_LOCAL_HOSTS = frozenset({"localhost", "host.docker.internal"})


def _public_hostname(url: str) -> str | None:
    """The hostname of a URL if a name lookup can say anything about it."""
    try:
        hostname = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    if not hostname or hostname in _LOCAL_HOSTS or ":" in hostname:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname) or "." not in hostname:
        return None
    return hostname


def check_dns(ctx: Context) -> CheckResult:
    name = "dns"
    if not ctx.configured:
        return _not_set_up(name)

    env = ctx.env
    active = ctx.active_profiles
    keys = [key for profile, key in _HOST_KEYS if profile is None or profile in active]
    if env.get("AUTH_PROVIDER") == "external_oidc":
        keys.append("OIDC_ISSUER")
    hosts: list[str] = []
    for key in keys:
        hostname = _public_hostname(env.get(key, ""))
        if hostname and hostname not in hosts:
            hosts.append(hostname)
    if not hosts:
        return CheckResult(name, SKIP, "no public hostnames configured (local setup)")

    outcomes = {host: ctx.probes.resolve(host) for host in hosts}
    details = {"hosts": [{"host": h, "result": r} for h, r in outcomes.items()]}
    unresolved = [h for h, r in outcomes.items() if r == NOT_FOUND]
    if unresolved:
        return CheckResult(
            name,
            WARN,
            f"does not resolve from this host: {', '.join(unresolved)}",
            details,
        )
    if all(r == UNAVAILABLE for r in outcomes.values()):
        return CheckResult(name, SKIP, "resolver not reachable (offline?)", details)
    return CheckResult(name, PASS, f"{len(hosts)} hostname(s) resolve", details)


def _clock_result(name: str, synchronized: bool) -> CheckResult:
    if synchronized:
        return CheckResult(name, PASS, "system clock is synchronized", {"ntp_synchronized": True})
    return CheckResult(
        name,
        WARN,
        "system clock is not synchronized: OIDC token and TLS certificate validation"
        " depend on it",
        {"ntp_synchronized": False},
    )


def check_time_sync(ctx: Context) -> CheckResult:
    """Whether the host clock is disciplined by NTP.

    OIDC tokens carry `iat` / `exp` / `nbf`, and TLS certificates a validity
    window; a clock that drifted makes logins and certificate checks fail in
    ways that point everywhere but at the clock.

    On a host this asks `timedatectl`. Inside a container that is out of reach,
    but the clock is the host's, so the kernel's own state is read instead."""
    name = "time_sync"
    if ctx.probes.in_container():
        synchronized = ctx.probes.kernel_clock_synchronized()
        if synchronized is None:
            return CheckResult(
                name, SKIP, "not measurable from inside a container (adjtimex is not available)"
            )
        return _clock_result(name, synchronized)
    result = ctx.run(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"], TIME_PROBE_TIMEOUT_SECONDS
    )
    if result.returncode != 0:
        # Not systemd (macOS, WSL2 without it, Alpine): nothing to read, which
        # is not a finding about the clock.
        reason = status.first_line(result.stderr) or f"exit {result.returncode}"
        return CheckResult(name, SKIP, f"timedatectl is not usable here ({reason})")
    value = status.first_line(result.stdout).lower()
    if value in ("yes", "no"):
        return _clock_result(name, value == "yes")
    return CheckResult(name, SKIP, f"unexpected timedatectl output: '{value}'")


def _certificate_files(config_dir: Path) -> list[Path]:
    files = sorted((config_dir / "certs").glob("*.crt"))
    # nginx-proxy-manager keeps its Let's Encrypt certificates in a bind mount
    # (infra/nginx/docker-compose.yml), so they are plain files on the host.
    files += sorted(
        (config_dir / "infra" / "nginx" / "nginx-letsencrypt" / "live").glob("*/fullchain.pem")
    )
    return files


def check_certs(ctx: Context) -> CheckResult:
    name = "certs"
    files = _certificate_files(ctx.config_dir)
    if not files:
        return CheckResult(name, SKIP, "no certificates found in the configuration directory")

    items: list[dict[str, Any]] = []
    for path in files:
        label = path.relative_to(ctx.config_dir).as_posix()
        try:
            not_after = ctx.probes.cert_enddate(path, ctx.run)
        except CertReadError as exc:
            items.append({"path": label, "status": SKIP, "reason": str(exc)})
            continue
        days = (not_after - ctx.now).days
        if days < CERT_FAIL_DAYS:
            verdict = FAIL
        elif days < CERT_WARN_DAYS:
            verdict = WARN
        else:
            verdict = PASS
        items.append(
            {
                "path": label,
                "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "days_left": days,
                "status": verdict,
            }
        )

    overall = _worst(i["status"] for i in items)
    read = [i for i in items if i["status"] != SKIP]
    if not read:
        return CheckResult(
            name, SKIP, f"cannot read certificates: {items[0]['reason']}", {"certificates": items}
        )
    soonest = min(read, key=lambda i: i["days_left"])
    if soonest["days_left"] < 0:
        summary = f"{soonest['path']} expired {-soonest['days_left']} day(s) ago"
    else:
        summary = f"{soonest['path']} expires in {soonest['days_left']} day(s)"
    if len(read) > 1:
        summary = f"{len(read)} certificates, soonest: {summary}"
    return CheckResult(name, overall, summary, {"certificates": items})


def check_addon_compat(ctx: Context) -> CheckResult:
    name = "addon_compat"
    deployed = deployment.load(ctx.config_dir)
    if not deployed:
        return _not_set_up(name)
    try:
        core = compat.resolve_core_target(ctx.repo_root)
    except ValueError as exc:
        return CheckResult(name, FAIL, str(exc))

    results = cli_addon.evaluate_active_addons(deployed, ctx.repo_root, core)
    if not results:
        return CheckResult(name, PASS, "no active add-ons")
    mode = compat.resolve_mode(deployed)

    items: list[dict[str, Any]] = []
    for result in results:
        if result.status == compat.STATUS_OK:
            verdict = PASS
        elif result.status == compat.STATUS_UNKNOWN:
            verdict = WARN
        elif result.status == compat.STATUS_INCOMPATIBLE:
            # The same policy `start` applies: fatal in enforce mode, a warning
            # in warn mode.
            verdict = FAIL if compat.gate([result], mode=mode) else WARN
        else:
            verdict = FAIL
        items.append(
            {
                "name": result.name,
                "compat_status": result.status,
                "axis": result.axis,
                "reason": result.reason,
                "status": verdict,
            }
        )

    overall = _worst(i["status"] for i in items)
    problems = [i for i in items if i["status"] != PASS]
    if problems:
        summary = "; ".join(
            f"{i['name']}: {i['compat_status']}" + (f" ({i['reason']})" if i["reason"] else "")
            for i in problems
        )
    else:
        summary = f"{len(items)} add-on(s) compatible with core {core.platform_version or '?'}"
    return CheckResult(name, overall, summary, {"mode": mode, "addons": items})


_HEALTH_VERDICT = {
    status.Health.HEALTHY: PASS,
    status.Health.COMPLETED: PASS,
    status.Health.STARTING: WARN,
    status.Health.UNKNOWN: WARN,
    status.Health.MISSING: WARN,
    status.Health.UNHEALTHY: FAIL,
    status.Health.STOPPED: FAIL,
}


def check_container_health(ctx: Context) -> CheckResult:
    name = "container_health"
    if not ctx.configured:
        return _not_set_up(name)
    report = ctx.status_report()
    if not report.docker.reachable:
        # Not knowing is not the same as knowing it is down.
        return CheckResult(
            name,
            WARN,
            f"container state unknown, Docker not reachable ({report.docker.reason})",
        )
    modules = report.modules
    if not modules:
        return CheckResult(name, SKIP, "no modules declared")

    items = [
        {
            "name": m.name,
            "kind": m.kind,
            "health": m.status.value,
            "status": _HEALTH_VERDICT[m.status],
        }
        for m in modules
    ]
    overall = _worst(i["status"] for i in items)
    attention = [i for i in items if i["status"] != PASS]
    if attention:
        summary = f"{len(attention)} of {len(items)} module(s) need attention: " + ", ".join(
            f"{i['name']} ({i['health']})" for i in attention
        )
    else:
        summary = f"all {len(items)} module(s) healthy"
    return CheckResult(name, overall, summary, {"modules": items})


CHECKS: list[tuple[str, Callable[[Context], CheckResult]]] = [
    ("docker_version", check_docker_version),
    ("disk_space", check_disk_space),
    ("docker_usage", check_docker_usage),
    ("memory", check_memory),
    ("cpu", check_cpu),
    ("gpu", check_gpu),
    ("ports", check_ports),
    ("dns", check_dns),
    ("time_sync", check_time_sync),
    ("certs", check_certs),
    ("addon_compat", check_addon_compat),
    ("container_health", check_container_health),
]

CHECK_NAMES = tuple(name for name, _ in CHECKS)


# ─────────────────────────────────────────────────────────────────────────
# report
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class DoctorReport:
    generated_at: str
    platform_version: str
    checks: list[CheckResult]

    @property
    def summary(self) -> dict[str, int]:
        counts = dict.fromkeys((PASS, WARN, FAIL, SKIP), 0)
        for check in self.checks:
            counts[check.status] += 1
        return counts

    @property
    def ok(self) -> bool:
        return self.summary[FAIL] == 0

    @property
    def exit_code(self) -> int:
        """0 when nothing failed; 2 otherwise, as `addon check` does when its
        gate refuses."""
        return 0 if self.ok else 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "platform_version": self.platform_version,
            "checks": [
                {"name": c.name, "status": c.status, "summary": c.summary, "details": c.details}
                for c in self.checks
            ],
            "summary": self.summary,
            "ok": self.ok,
        }


def parse_skip(values: Sequence[str] | None) -> list[str]:
    """Validate `--skip` names against the registry."""
    names = [v.strip() for v in values or [] if v.strip()]
    unknown = [n for n in names if n not in CHECK_NAMES]
    if unknown:
        raise DoctorError(
            f"Unknown check(s): {', '.join(unknown)}. Valid: {', '.join(CHECK_NAMES)}."
        )
    return names


def run_checks(
    config_dir: Path,
    repo_root: Path,
    *,
    skip: Sequence[str] | None = None,
    run: Runner | None = None,
    probes: Probes | None = None,
    now: datetime | None = None,
) -> DoctorReport:
    skipped = set(parse_skip(skip))
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ctx = Context(
        config_dir,
        repo_root,
        run=run or status.run_command,
        probes=probes or Probes(),
        now=moment,
    )
    results: list[CheckResult] = []
    for name, check in CHECKS:
        if name in skipped:
            results.append(CheckResult(name, SKIP, "skipped (--skip)"))
            continue
        try:
            results.append(check(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken probe must not hide the others
            results.append(CheckResult(name, FAIL, f"check crashed: {type(exc).__name__}: {exc}"))
    return DoctorReport(
        generated_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        platform_version=envtree.resolve_platform_version(repo_root),
        checks=results,
    )


def format_table(report: DoctorReport) -> str:
    rows = [(c.name, c.status, c.summary) for c in report.checks]
    header = ("CHECK", "RESULT", "SUMMARY")
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(2)]
    lines = [f"papAIa {report.platform_version} - doctor", ""]
    lines.append("  ".join(header[i].ljust(widths[i]) for i in range(2)) + "  " + header[2])
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(2)) + "  " + row[2])
    counts = report.summary
    lines.append("")
    lines.append(
        f"{counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail, {counts[SKIP]} skip"
    )
    return "\n".join(lines)


def to_json(report: DoctorReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
