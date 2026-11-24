"""Preflight and diagnostics: is this host, and this installation, in shape?

`run_checks()` evaluates an ordered registry of checks and returns a
`DoctorReport`; rendering is separate, the shape `compat.py` and `status.py`
follow. Each check answers `pass`, `warn`, `fail` or `skip` (not applicable
here: offline, not set up yet, nothing to look at). Only `fail` makes the
command exit non-zero.

Nothing here changes anything. The probes are reads: `docker version/info` and
`docker system df`, `shutil.disk_usage`, `/proc/meminfo` and the load average, `nvidia-smi` /
`rocm-smi` / `timedatectl`, a TCP connect to localhost, a name lookup,
`openssl x509` on a file, a handshake with the configured mail server (greeting, EHLO,
STARTTLS and a login -- no mail is sent) and `postqueue -p` in the mail relay's container,
`iptables -S` of the SQL uplink's chain and of `DOCKER-USER`, `docker network inspect`,
`GET /healthz` and `GET /metrics` of the catalog's modules from a short-lived probe
container on each module's network (lib/module_health.py), the `selftest` of a SQL Server
source, plus everything `status` reads. Inside a container,
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
import dataclasses
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

from . import (
    backup,
    catalog,
    cli_addon,
    common,
    compat,
    deployment,
    diagnosis,
    direct_ports,
    egress,
    envtree,
    erasure_journal,
    federation,
    gen_override,
    gpu_detect,
    halt,
    host_size,
    images,
    localai_native,
    model_gateway,
    module_health,
    pki,
    semver,
    setup_answers,
    smtp,
    sql_uplink,
    status,
)
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
# `postqueue -p` reads the queue directory; a large queue takes a moment.
SMTP_QUEUE_TIMEOUT_SECONDS = 10.0
IPTABLES_TIMEOUT_SECONDS = 10.0

# What systemd's `NTPSynchronized` means: the kernel's estimated maximum error is
# under sixteen seconds. The kernel starts at exactly that figure and only lowers
# it while something disciplines the clock.
KERNEL_CLOCK_SYNCED_MAXERROR_US = 16_000_000

LOCALAI_PROFILE = "localai"
LOCALAI_SERVICE = "localai"
GPU_OVERRIDE = Path("overrides") / "docker-compose.localai-gpu.override.yml"
VOICE_PROFILE = "voice"
LIFECYCLE_PROFILE = "lifecycle"
LIFECYCLE_SERVICE = "papaia-lifecycle"
# The container's own health command (src/infra/lifecycle/docker-compose.yml): it only
# reads the published list and the service's state, nothing in Keycloak.
LIFECYCLE_HEALTH_COMMAND = (
    "python3",
    "-I",
    "/opt/papaia-lifecycle/lifecycle.py",
    "health",
    "--key-dir=/var/lib/papaia-lifecycle",
    "--state-dir=/var/lib/papaia-security-state",
    "--journal-dir=/var/lib/papaia-backup/erasure-journal",
    "--journal-local-dir=/var/lib/papaia-lifecycle/erasure-journal",
)
LIFECYCLE_TIMEOUT_SECONDS = 20.0
# security 1.12 no. 2: the reconciliation independent of events runs hourly; older than
# two hours is `fail`. A gap revoke is reported as `warn` for as long as Keycloak keeps
# events (people grant their delegations anew in that time).
LIFECYCLE_RECONCILE_FAIL_SECONDS = 2 * 3600
LIFECYCLE_GAP_WARN_SECONDS = 7 * 24 * 3600
# security 1.13: the status sync with the upstream directory failing for longer than
# 300 s is `fail` (and papaia-lifecycle sends the warning mail).
STATUS_SYNC_FAIL_SECONDS = 300
VOICE_GPU_OVERRIDE = Path("overrides") / "docker-compose.voice-gpu.override.yml"
AUDIT_PROFILE = "audit"
AUDIT_SERVICE = "papaia-audit"
AUDIT_DB_SERVICE = "papaia-audit-db"
AUDIT_DB_DATA = "/var/lib/postgresql/data"
# The service's own report (src/infra/audit/papaia_audit/watch.py): backlog, lag and
# delivery state per SIEM target, the GV-05/GV-06 measurements and chain verification.
OPERATIONS_MAIL_KEY = "PAPAIA_OPERATIONS_MAIL"
SIEM_STATUS_COMMAND = ("python3", "-I", "-m", "papaia_audit", "siem-status")
SIEM_TIMEOUT_SECONDS = 60.0
# Fill level of the audit database's volume (governance GV-06): the export has no
# buffer of its own, so the volume is where an outage of the SIEM piles up.
SIEM_DISK_WARN_PERCENT = 80
SIEM_DISK_FAIL_PERCENT = 95
# The service verifies every chain every full hour; older than two runs is stale.
SIEM_VERIFY_STALE_SECONDS = 2 * 3600

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
    return common.in_container()


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


def _realm_check(config_dir: Path, repo_root: Path) -> tuple[int, str]:
    """`realm sync --check` in this process: (exit code, what it printed). It reads the
    realm with the sync account and the master admin and writes nothing."""
    import contextlib
    import io

    from . import realm_sync

    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = realm_sync.sync(tree, config_dir, repo_root, check=True)
    return code, out.getvalue()


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
    # (host, port, security, user, password, check_login) -> smtp.ProbeResult
    smtp_probe: Callable[..., smtp.ProbeResult] = smtp.probe_upstream
    # Where device nodes live; the same seam `gpu_detect.compose_fragment` has.
    dev_root: Path = Path("/dev")
    # Whether the native LocalAI answers on a /readyz URL.
    localai_ready: Callable[[str], bool] = localai_native.probe
    # Whether launchctl of the logged-in user is at hand (a Mac, not a container).
    launchd_host: Callable[[], bool] = lambda: localai_native.launchd_host()[0]
    # `realm sync --check`: (config_dir, repo_root) -> (exit code, printed lines).
    realm_check: Callable[[Path, Path], tuple[int, str]] = _realm_check


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
        self._modules: _ModuleScan | None = None
        self._members: dict[str, set[str] | None] = {}
        self._lifecycle_health: dict[str, status.CommandResult] = {}

    def lifecycle_health(self, container: str) -> status.CommandResult:
        """`lifecycle.py health` in `container`, asked once: `doctor lifecycle` and
        `doctor startgate` read the same report."""
        if container not in self._lifecycle_health:
            self._lifecycle_health[container] = self.run(
                ["docker", "exec", container, *LIFECYCLE_HEALTH_COMMAND],
                LIFECYCLE_TIMEOUT_SECONDS,
            )
        return self._lifecycle_health[container]

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


# ─── profile_size ────────────────────────────────────────────────────────


def _disk_for_profile(ctx: Context) -> tuple[int | None, str]:
    """Free bytes where the containers keep their data: Docker's root directory when the
    host can see it, otherwise the configuration directory (Docker Desktop keeps its
    root inside a VM)."""
    root = ctx.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"], DOCKER_PROBE_TIMEOUT_SECONDS
    )
    root_dir = status.first_line(root.stdout) if root.returncode == 0 else ""
    path = Path(root_dir) if root_dir and Path(root_dir).is_dir() else ctx.config_dir
    existing = _nearest_existing(path)
    if existing is None:
        return None, str(path)
    try:
        return ctx.probes.disk_usage(existing)[1], str(existing)
    except OSError:
        return None, str(existing)


def _largest_gpu_memory(ctx: Context) -> int | None:
    result = ctx.run(
        ["nvidia-smi", f"--query-gpu={_NVIDIA_QUERY}", "--format=csv,noheader,nounits"],
        GPU_PROBE_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    sizes = [g["memory_total_mib"] for g in parse_nvidia_smi(result.stdout)
             if g["memory_total_mib"]]
    return max(sizes) * _MIB if sizes else None


def measure_host(ctx: Context, *, with_gpu: bool) -> host_size.Measured:
    """CPU cores and memory as the Docker daemon sees them (on Docker Desktop: its VM,
    where the containers run), else as this host reports them; free disk where the data
    goes; the video memory of the largest NVIDIA GPU only when `with_gpu`."""
    docker_cores, docker_memory = ctx.docker_totals()
    cores = docker_cores or ctx.probes.cpu_count()
    memory = docker_memory
    if memory is None:
        info = ctx.probes.meminfo()
        memory = info.total if info is not None else None
    disk_free, disk_path = _disk_for_profile(ctx)
    gpu = _largest_gpu_memory(ctx) if with_gpu else None
    return host_size.Measured(cores, memory, disk_free, disk_path, gpu)


def size_result(ctx: Context, profile_name: str, *, before_setup: bool = False) -> CheckResult:
    """The host against one size profile: `fail` naming every size that is missing,
    `warn` when a size cannot be read, `pass` otherwise."""
    name = "profile_size"
    try:
        wanted = host_size.profile(profile_name)
    except ValueError as exc:
        return CheckResult(name, FAIL, f"{host_size.ENV_KEY}: {exc}")
    host = measure_host(ctx, with_gpu=False)
    if (
        wanted.gpu_alternative is not None
        and host.memory is not None
        and host.memory < wanted.memory * (1 - host_size.MEMORY_TOLERANCE)
    ):
        # Asked only when it can decide: the GPU alternative of the profile.
        host = dataclasses.replace(host, gpu_memory=_largest_gpu_memory(ctx))
    missing, unknown = host_size.shortfall(wanted, host)
    details: dict[str, Any] = {
        "profile": wanted.name,
        "before_setup": before_setup,
        "cores": host.cores,
        "memory_bytes": host.memory,
        "disk_free_bytes": host.disk_free,
        "disk_path": host.disk_path,
        "gpu_memory_bytes": host.gpu_memory,
        "missing": missing,
        "unknown": unknown,
    }
    which = f"size profile '{wanted.name}'"
    if before_setup:
        which += " (the smallest; setup measures the profile chosen there)"
    if missing:
        return CheckResult(
            name, FAIL, f"this host is below {which}: " + "; ".join(missing), details
        )
    if unknown:
        return CheckResult(
            name, WARN, f"{which} cannot be confirmed: " + "; ".join(unknown), details
        )
    return CheckResult(name, PASS, f"this host fits {which}", details)


def check_profile_size(ctx: Context) -> CheckResult:
    name = "profile_size"
    if not ctx.configured:
        return size_result(ctx, host_size.SMALLEST, before_setup=True)
    chosen = ctx.env.get(host_size.ENV_KEY, "").strip()
    if not chosen:
        return CheckResult(
            name, SKIP, f"no size profile chosen ({host_size.ENV_KEY} is empty)"
        )
    return size_result(ctx, chosen)


def check_size(
    config_dir: Path,
    repo_root: Path,
    profile_name: str,
    *,
    run: Runner | None = None,
    probes: Probes | None = None,
) -> CheckResult:
    """The size check `setup` runs before it writes anything (PLT-58-A5)."""
    ctx = Context(
        config_dir,
        repo_root,
        run=run or status.run_command,
        probes=probes or Probes(),
        now=datetime.now(timezone.utc),
    )
    return size_result(ctx, profile_name)


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
    ctx: Context,
    variant: str,
    details: dict[str, Any],
    *,
    container: str | None = None,
    subject: str = "LocalAI",
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
            f" Toolkit, otherwise {subject} cannot start",
            details,
        )
    return _gpu_measured(name, gpus, details)


def _gpu_amd(ctx: Context, details: dict[str, Any], *, subject: str = "LocalAI") -> CheckResult:
    name = "gpu"
    if not (ctx.probes.dev_root / "kfd").exists():
        return CheckResult(
            name,
            FAIL,
            f"/dev/kfd is missing: the ROCm kernel driver is not loaded, {subject} cannot start",
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


# Which voice TTS variant a LocalAI accelerator probe already proves: the engines
# share the host prerequisites per vendor (NVIDIA: driver plus Container Toolkit;
# AMD: the ROCm kernel driver), so one probe per vendor is enough. Intel and
# Vulkan prove neither.
_LOCALAI_COVERS_VOICE = {
    gpu_detect.NVIDIA_CUDA_12: "nvidia",
    gpu_detect.NVIDIA_CUDA_13: "nvidia",
    gpu_detect.HIPBLAS: "hipblas",
}


def _worse_gpu(a: CheckResult, b: CheckResult) -> CheckResult:
    """One verdict for two accelerator demands: the more alarming one leads,
    the other survives in the details so neither probe's outcome is lost."""
    if _SEVERITY[b.status] < _SEVERITY[a.status]:
        a, b = b, a
    details = dict(a.details or {})
    details["other_accelerator"] = {
        "variant": (b.details or {}).get("variant"),
        "status": b.status,
        "summary": b.summary,
    }
    return CheckResult(a.name, a.status, a.summary, details)


def check_gpu(ctx: Context) -> CheckResult:
    name = "gpu"
    if not ctx.configured:
        return _not_set_up(name)
    localai_result: CheckResult | None = None
    covered: str | None = None
    native = localai_native.runtime(ctx.env) == localai_native.NATIVE
    if LOCALAI_PROFILE in ctx.active_profiles and not native:
        variant = ctx.env.get("LOCALAI_IMAGE_VARIANT", "").strip() or gpu_detect.CPU
        if variant != gpu_detect.CPU:
            localai_result = _gpu_localai(ctx, variant)
            covered = _LOCALAI_COVERS_VOICE.get(variant)
    voice_result = _gpu_voice(ctx, covered)
    if localai_result is not None and voice_result is not None:
        return _worse_gpu(localai_result, voice_result)
    if localai_result is not None:
        return localai_result
    if voice_result is not None:
        return voice_result
    if LOCALAI_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "LocalAI is not enabled")
    if native:
        # Metal is not measured here and no variant is reported: papaia-manager maps
        # details.variant to labels of its own. The process is checked by localai_native.
        return CheckResult(
            name, SKIP, "LocalAI runs natively on the Apple GPU (see localai_native)"
        )
    return CheckResult(name, SKIP, "LocalAI runs on the CPU image")


def _gpu_localai(ctx: Context, variant: str) -> CheckResult:
    name = "gpu"
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


def check_localai_native(ctx: Context) -> CheckResult:
    """The native LocalAI of an Apple Silicon Mac (LOCALAI_RUNTIME=native, ADR 0012).

    Whether /readyz answers (on the host at 127.0.0.1, in a container at
    host.docker.internal), whether the installed binary is the pinned release and, on the
    Mac, the state of the launchd job: `warn` when the job is loaded but LocalAI does not
    answer, or when it is not loaded although the stack runs. `warn` at most: LocalAI is
    optional for the rest of the stack."""
    name = "localai_native"
    if not ctx.configured:
        return _not_set_up(name)
    env = ctx.env
    if localai_native.runtime(env) != localai_native.NATIVE:
        return CheckResult(name, SKIP, "LocalAI runs in its container")
    if LOCALAI_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "LocalAI is not enabled")
    try:
        home = localai_native.localai_home(env)
        pinned = localai_native.pinned_version(ctx.repo_root)
    except localai_native.InstallError as exc:
        return CheckResult(name, WARN, str(exc))
    installed = localai_native.installed_version(home)
    url = localai_native.probe_url(env, inside_container=ctx.probes.in_container())
    ready = ctx.probes.localai_ready(url)
    log = localai_native.log_path(home)
    details: dict[str, Any] = {
        "url": url,
        "home": str(home),
        "pinned": pinned,
        "installed": installed,
        "ready": ready,
        "log": str(log),
    }
    if installed is None:
        return CheckResult(
            name, WARN, "the LocalAI binary is not installed yet: run 'papaia-ctl start'", details
        )
    if installed != pinned:
        return CheckResult(
            name,
            WARN,
            f"LocalAI {installed} is installed, this release pins {pinned}:"
            " run 'papaia-ctl start'",
            details,
        )
    job = _launchd_job(ctx, env, details)
    if job is None:
        # In a container (papaia-manager), or launchctl did not answer: the probe alone.
        if not ready:
            return CheckResult(
                name,
                WARN,
                f"LocalAI {installed} does not answer on {url}: run 'papaia-ctl start' on the"
                f" Mac (log: {log})",
                details,
            )
        return CheckResult(name, PASS, f"LocalAI {installed} answers on {url}", details)
    label = details["launchd"]["label"]
    if job.loaded:
        if not ready:
            state = job.state or "unknown"
            return CheckResult(
                name,
                WARN,
                f"the launchd job {label} is loaded ({state}) but LocalAI does not answer on"
                f" {url}: see {log}",
                details,
            )
        return CheckResult(
            name, PASS, f"LocalAI {installed} answers on {url} (launchd: {label})", details
        )
    if _stack_runs(ctx):
        cause = (
            "LocalAI answers but not through launchd (started by hand?)"
            if ready
            else "LocalAI is stopped"
        )
        return CheckResult(
            name,
            WARN,
            f"the launchd job {label} is not loaded although the stack runs: {cause};"
            " run 'papaia-ctl start'",
            details,
        )
    if ready:
        # Not through launchd, so not papaia-ctl's: it would keep the port at the next start.
        return CheckResult(
            name,
            WARN,
            f"the stack is stopped, but LocalAI answers on {url} without the launchd job"
            f" {label} (started by hand?): stop that process before 'papaia-ctl start'",
            details,
        )
    return CheckResult(name, SKIP, "the stack is stopped, and LocalAI with it", details)


def _launchd_job(
    ctx: Context, env: dict[str, str], details: dict[str, Any]
) -> localai_native.JobState | None:
    """The launchd job of the native LocalAI, or None where launchctl cannot be asked."""
    if ctx.probes.in_container() or not ctx.probes.launchd_host():
        return None
    try:
        label = localai_native.label_for(env)
        job = localai_native.state(label, run=ctx.run)
    except localai_native.LaunchdError:
        return None
    details["launchd"] = {"label": label, **job.to_dict()}
    return job


def _stack_runs(ctx: Context) -> bool:
    """Whether any container of the core is running."""
    report = ctx.status_report()
    return any(
        container.state == "running" for module in report.core for container in module.containers
    )


def _gpu_voice(ctx: Context, covered: str | None = None) -> CheckResult | None:
    """The voice TTS accelerator, probed with the engine named in the verdict.

    `covered` is the voice variant a LocalAI probe of this same run already proves
    (see _LOCALAI_COVERS_VOICE); matching demands collapse into that one probe. A
    cross-vendor setup (say LocalAI on CUDA, the TTS engine on ROCm) keeps both
    probes, and check_gpu merges the verdicts. None means nothing to check."""
    name = "gpu"
    if VOICE_PROFILE not in ctx.active_profiles:
        return None
    variant = ctx.env.get("VOICE_TTS_IMAGE_VARIANT", "").strip() or "cpu"
    if variant == "cpu" or variant == covered:
        return None
    details: dict[str, Any] = {
        "variant": f"{variant} (voice)",
        "override_present": (ctx.config_dir / VOICE_GPU_OVERRIDE).is_file(),
    }
    if variant not in ("nvidia", "hipblas"):
        return CheckResult(
            name,
            WARN,
            f"unknown VOICE_TTS_IMAGE_VARIANT '{variant}' (one of: cpu, nvidia, hipblas)",
            details,
        )
    if ctx.probes.in_container():
        # Unlike LocalAI there is no container that is guaranteed to carry the
        # vendor tools, so the host is the only place this can be measured.
        return CheckResult(
            name,
            SKIP,
            "not measurable from inside a container: the host's driver tools and devices"
            " are not visible",
            details,
        )
    if variant == "nvidia":
        # The nvidia image carries a CUDA floor the runtime enforces (see
        # gpu_detect.VOICE_NVIDIA_MIN_CUDA); the banner names the highest
        # CUDA the driver supports. An unreadable banner is not held against
        # the host — the generic probe below still judges driver and runtime.
        banner = ctx.run(["nvidia-smi"], GPU_PROBE_TIMEOUT_SECONDS)
        cuda = gpu_detect.cuda_version(banner.stdout) if banner.returncode == 0 else None
        if cuda is not None:
            details["cuda_version"] = f"{cuda[0]}.{cuda[1]}"
            if cuda < gpu_detect.VOICE_NVIDIA_MIN_CUDA:
                floor = ".".join(str(part) for part in gpu_detect.VOICE_NVIDIA_MIN_CUDA)
                return CheckResult(
                    name,
                    FAIL,
                    f"the driver supports CUDA {cuda[0]}.{cuda[1]}, but the voice TTS"
                    f" accelerator image needs >= {floor} — the NVIDIA runtime refuses"
                    " the container",
                    details,
                )
        return _gpu_nvidia(ctx, variant, details, subject="the voice TTS engine")
    return _gpu_amd(ctx, details, subject="the voice TTS engine")


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
    # A native LocalAI holds its port as a host process; that is no conflict.
    expected = status.core_inventory(
        ctx.repo_root, ctx.active_profiles, status.native_skip(ctx.config_dir)
    )
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


def check_direct_ports(ctx: Context) -> CheckResult:
    """The generated direct-ports override: present only with direct port access, never
    edited by hand, equal to what setup writes for the configuration (BE-06)."""
    name = "direct_ports"
    if not ctx.configured:
        return _not_set_up(name)
    root = common.parse_env_file(ctx.config_dir / ".env")
    findings = direct_ports.verify(ctx.config_dir, root)
    mode = direct_ports.direct_mode(root)
    details: dict[str, Any] = {"mode": mode or "edge", "findings": findings}
    if direct_ports.missing(ctx.config_dir, root):
        return CheckResult(name, WARN, "; ".join(findings), details)
    if findings:
        return CheckResult(name, FAIL, "; ".join(findings), details)
    if mode is None:
        return CheckResult(name, PASS, "only the edge proxy publishes ports", details)
    return CheckResult(
        name, PASS, f"direct port access ({mode}) through the generated override", details
    )


def check_addon_ports(ctx: Context) -> CheckResult:
    """Services that never publish a port (header identity, me-web, modules with
    delegation): no port in any mode, and no direct port access while one is installed
    (RE-21, ISB-P10)."""
    name = "addon_ports"
    if not ctx.configured:
        return _not_set_up(name)
    root = common.parse_env_file(ctx.config_dir / ".env")
    findings = direct_ports.refusals(root, ctx.config_dir, ctx.repo_root)
    if findings:
        return CheckResult(name, FAIL, "; ".join(findings), {"findings": findings})
    return CheckResult(
        name, PASS, "no service with header identity, me-web or delegation publishes a port"
    )


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
    # The platform PKI: its CA, every service certificate and the trust bundle (OPS-17).
    return files + pki.doctor_files(config_dir)


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


def _smtp_relay_container(ctx: Context) -> tuple[str | None, str | None]:
    """(name, state) of the mail relay's container in the status report, or
    (None, None) if there is none: not started, or declared and never created."""
    for module in ctx.status_report().modules:
        if module.kind != "core":
            continue
        for container in module.containers:
            if container.service == smtp.SERVICE:
                return container.name or None, container.state
    return None, None


def check_smtp(ctx: Context) -> CheckResult:
    """The outbound mail relay and the mail server behind it.

    Off by default (`not configured`). When it is on, three things are read: whether
    the relay container runs, whether the upstream answers (greeting, EHLO, STARTTLS or
    TLS and the login -- no mail is sent, so a run never delivers anything), and how
    many messages wait in the relay's queue. The relay accepts mail even while the
    upstream is down, so only this check tells that apart. A mail server that does not
    answer is `fail` (BE-29 no. 9: notices and warning mails stop); everything else about
    mail is a `warn` at most.

    Inside a container (papaia-manager polls `doctor`) the upstream is not contacted:
    the check would reach the provider on every poll, and the relay's own state and
    queue already say whether mail is flowing."""
    name = "smtp"
    if not ctx.configured:
        return _not_set_up(name)
    relay = smtp.Settings.load(ctx.config_dir)
    if not relay.profile_on:
        return CheckResult(name, SKIP, "not configured (the smtp profile is off)")
    details: dict[str, Any] = {
        "host": relay.host,
        "port": relay.port,
        "security": relay.security,
        "login": bool(relay.user),
    }
    if not relay.configured:
        return CheckResult(
            name,
            WARN,
            "not configured: the mail server or the sender address is empty"
            " ('papaia-ctl setup --smtp' sets them)",
            details,
        )

    issues: list[str] = []
    notes: list[str] = []
    unreachable = False
    container, state = _smtp_relay_container(ctx)
    details["relay"] = state or "not created"

    if ctx.probes.in_container():
        details["upstream"] = "not probed from a container"
        notes.append("the mail server is only probed on the host")
    else:
        probe = ctx.probes.smtp_probe(
            relay.host,
            relay.port or smtp.DEFAULT_PORTS[relay.security],
            relay.security,
            relay.user,
            smtp.read_password(ctx.config_dir),
            True,
        )
        details["upstream"] = {
            "ok": probe.ok,
            "stage": probe.stage,
            "reason": probe.reason,
            "login": probe.login,
        }
        if probe.ok:
            notes.append(f"reachable ({relay.security}, login {probe.login})")
        else:
            unreachable = True
            issues.append(f"unreachable ({probe.stage}: {probe.reason})")

    if state is None:
        issues.append("the relay is not created ('papaia-ctl start' creates it)")
    elif state != "running":
        issues.append(f"the relay is {state}")
    else:
        notes.append("relay running")
        listing = ctx.run(
            ["docker", "exec", container or "", *smtp.QUEUE_COMMAND], SMTP_QUEUE_TIMEOUT_SECONDS
        )
        queued = smtp.parse_queue_count(listing.stdout) if listing.returncode == 0 else None
        details["queued"] = queued
        if queued:
            issues.append(f"{queued} message(s) waiting in the relay's queue")
        elif queued == 0:
            notes.append("queue empty")

    summary = "; ".join(issues + notes)
    # A mail server that does not answer stops every notice and warning mail (BE-29 no. 9):
    # `fail`. Everything else about mail is a warning.
    verdict = FAIL if unreachable else WARN if issues else PASS
    return CheckResult(name, verdict, summary, details)


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

    joins = _missing_offered_networks(ctx, deployed)
    overall = _worst([*(i["status"] for i in items), *(WARN for _ in joins)])
    problems = [i for i in items if i["status"] != PASS]
    if problems or joins:
        summary = "; ".join(
            [
                f"{i['name']}: {i['compat_status']}"
                + (f" ({i['reason']})" if i["reason"] else "")
                for i in problems
            ]
            + [
                f"{j['addon']}: the network {j['network']} that '{j['target']}' offers does"
                " not exist; the add-on runs without it"
                for j in joins
            ]
        )
    else:
        summary = f"{len(items)} add-on(s) compatible with core {core.platform_version or '?'}"
    return CheckResult(
        name, overall, summary, {"mode": mode, "addons": items, "missing_joins": joins}
    )


def _missing_offered_networks(ctx: Context, deployed: dict) -> list[dict[str, str]]:
    """The joins of offered networks (addon_api 17) that `addon start` leaves out because
    the network does not exist: one {addon, target, network} per network named in an
    active add-on's offer override (gen_override.usable_addon_override_files)."""
    missing: list[dict[str, str]] = []
    for addon in deployment.active_addons(deployed):
        consumer = addon.get("name")
        if not consumer:
            continue
        for path in deployment.addon_override_files(ctx.config_dir, consumer, deployed):
            target = gen_override.offer_target(path, consumer)
            if target is None:
                continue
            for network in gen_override.external_networks(path):
                found = ctx.run(
                    ["docker", "network", "inspect", network], DOCKER_PROBE_TIMEOUT_SECONDS
                )
                if found.returncode != 0:
                    missing.append({"addon": consumer, "target": target, "network": network})
    return missing


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


_IMAGE_INSPECT_FORMAT = "{{.Name}}\t{{.Config.Image}}\t{{.Image}}"
_IMAGE_DIGESTS_FORMAT = "{{.Id}}\t{{json .RepoDigests}}"


def _running_images(ctx: Context, names: list[str]) -> dict[str, tuple[str, str]] | None:
    """{container: (reference it was created from, image id)}, or None when Docker
    does not tell for every listed container."""
    inspected = ctx.run(
        ["docker", "inspect", "--format", _IMAGE_INSPECT_FORMAT, *names],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if inspected.returncode != 0:
        return None
    running: dict[str, tuple[str, str]] = {}
    for line in inspected.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].strip() and parts[2].strip():
            running[parts[0].strip().lstrip("/")] = (parts[1].strip(), parts[2].strip())
    return running if set(names) <= set(running) else None


def _repo_digests(ctx: Context, image_ids: list[str]) -> dict[str, set[str]] | None:
    """{image id: digests the local image is known under}, or None when unknown."""
    done = ctx.run(
        ["docker", "image", "inspect", "--format", _IMAGE_DIGESTS_FORMAT, *image_ids],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if done.returncode != 0:
        return None
    found: dict[str, set[str]] = {}
    for line in done.stdout.splitlines():
        image_id, _, raw = line.partition("\t")
        try:
            digests = json.loads(raw) if raw.strip() else []
        except ValueError:
            continue
        if isinstance(digests, list):
            found[image_id.strip()] = {
                d.rpartition("@")[2] for d in digests if isinstance(d, str) and "@" in d
            }
    return found if set(image_ids) <= set(found) else None


def check_image_signatures(ctx: Context) -> CheckResult:
    """Every running container of the core project runs an image that is listed with
    its digest in the signed bill of materials and carries a valid signature, and the
    image it runs is the one with that digest.

    `fail` for an unpinned, unlisted or unsigned image, for a running image whose
    digest is not the pinned one, and when there is no trust anchor while containers
    run; `warn` when the registry cannot be asked (no connection, rate limit, server
    error) or Docker does not say what runs, since then nothing is known."""
    name = "image_signatures"
    if not ctx.configured:
        return _not_set_up(name)
    project = status.compose_project(ctx.config_dir)
    listed = ctx.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
         "--format", "{{.Names}}"],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if listed.returncode != 0:
        return CheckResult(name, WARN, "running containers unknown, Docker not reachable")
    names = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not names:
        return CheckResult(name, PASS, "no running containers")
    running = _running_images(ctx, names)
    if running is None:
        return CheckResult(name, WARN, f"running images unknown: docker inspect did not "
                           f"describe all {len(names)} container(s)")
    digests = _repo_digests(ctx, sorted({image_id for _, image_id in running.values()}))
    if digests is None:
        return CheckResult(name, WARN, "running images unknown: docker image inspect failed")
    try:
        mirror, signatures = images.settings(
            common.parse_env_file(ctx.config_dir / ".env"), ctx.repo_root
        )
        bom = images.load_trusted_bom(ctx.repo_root)
    except images.ImageError as exc:
        return CheckResult(name, FAIL, f"{len(running)} running image(s) not verifiable: {exc}")

    registry = images.Registry()
    cache = images.SignatureCache(ctx.config_dir / images.CACHE_PATH)
    items: list[dict[str, Any]] = []
    for container, (ref, image_id) in sorted(running.items()):
        problems = images.verify_images(
            # Core containers only: an add-on acceptance never covers a core image.
            [ref], bom, registry=registry, mirror=mirror, signatures=signatures, cache=cache,
        )
        reason, verdict = "", PASS
        if problems:
            reason = problems[0].reason
            verdict = WARN if problems[0].transient else FAIL
        else:
            pinned = ref.partition("@")[2]
            if pinned not in digests.get(image_id, set()):
                reason = f"the running image is not the pinned digest {pinned}"
                verdict = FAIL
        items.append({"container": container, "image": ref, "status": verdict, "reason": reason})
    try:
        cache.save()
    except OSError:
        pass
    bad = [i for i in items if i["status"] != PASS]
    if bad:
        summary = "; ".join(f"{i['container']}: {i['reason']}" for i in bad)
    else:
        summary = f"{len(items)} running image(s) signed and listed in suite {bom['suite']}"
    return CheckResult(name, _worst(i["status"] for i in items), summary, {"images": items})


def _core_container(ctx: Context, service: str) -> tuple[str | None, str | None] | None:
    """(name, state) of a core service's container; None when this host's stack does not
    declare or run it (another node in a distributed installation)."""
    for module in ctx.status_report().modules:
        if module.kind != "core":
            continue
        for container in module.containers:
            if container.service == service:
                return container.name or None, container.state or None
    return None


def _lifecycle_container(ctx: Context) -> tuple[str | None, str | None] | None:
    return _core_container(ctx, LIFECYCLE_SERVICE)


def _count_field(report: dict[str, Any], key: str, *, optional: bool = False) -> int | None:
    value = report.get(key)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(key)
    return value


def check_lifecycle(ctx: Context) -> CheckResult:
    """papaia-lifecycle (`doctor lifecycle`): its reconciliation independent of events and
    the revocation list, as the service's own health command reports them.

    `fail` when the last reconciliation is older than 2 h or never ran, a deactivated
    account still holds a consent, the list is old or does not verify, or the service
    does not run; `warn` for a gap revoke in the last 7 days and for accounts it could
    not revoke (parked events, accounts outside the persons group)."""
    name = "lifecycle"
    if not ctx.configured:
        return _not_set_up(name)
    if LIFECYCLE_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "not enabled (the lifecycle profile is off)")
    found = _lifecycle_container(ctx)
    if found is None:
        return CheckResult(name, SKIP, "papaia-lifecycle does not run on this host")
    container, state = found
    if container is None or state != "running":
        return CheckResult(
            name,
            FAIL,
            f"papaia-lifecycle is {state or 'not created'}: deactivations are not revoked "
            "('papaia-ctl start' starts it)",
            {"state": state},
        )
    done = ctx.lifecycle_health(container)
    try:
        report = json.loads(status.first_line(done.stdout))
        if not isinstance(report, dict):
            raise ValueError("not an object")
        values = {
            key: _count_field(report, key, optional=optional)
            for key, optional in (
                ("revocations_age_seconds", True),
                ("last_reconcile_age_seconds", True),
                ("gap_revoke_age_seconds", True),
                ("disabled_with_consent", True),
                ("parked_revocations", True),
                ("skipped_revocations", True),
                ("journal_pending", True),
            )
        }
        target = report.get("journal_target")
        if target not in (None, "ok", "unreachable", "corrupt"):
            raise ValueError("journal_target")
        health = report.get("status")
        if health not in ("ok", "warn", "fail"):
            raise ValueError("status")
    except (ValueError, TypeError):
        return CheckResult(
            name, FAIL, "the health report of papaia-lifecycle cannot be read",
            {"exit_code": done.returncode},
        )
    details: dict[str, Any] = {**values, "health": health}
    failures: list[str] = []
    warnings: list[str] = []
    if values["revocations_age_seconds"] is None:
        # The health command stops there: no list, or one that does not verify.
        return CheckResult(
            name, FAIL, "the revocation list of papaia-lifecycle is missing or does not verify",
            details,
        )
    reconcile = values["last_reconcile_age_seconds"]
    if reconcile is None:
        failures.append("no reconciliation has run yet")
    elif reconcile > LIFECYCLE_RECONCILE_FAIL_SECONDS:
        failures.append(f"the last reconciliation ran {reconcile // 60} min ago (more than 2 h)")
    if values["disabled_with_consent"]:
        failures.append(
            f"{values['disabled_with_consent']} deactivated account(s) still hold a consent"
        )
    if health == "fail" and not failures:
        failures.append(
            "the revocation list is old or does not verify, or Keycloak is not read"
        )
    gap = values["gap_revoke_age_seconds"]
    if gap is not None and gap <= LIFECYCLE_GAP_WARN_SECONDS:
        warnings.append(
            f"lifecycle_gap_revoke {gap // 3600} h ago: events were missed, every delegation "
            "was ended and people grant them anew"
        )
    if values["parked_revocations"]:
        warnings.append(f"{values['parked_revocations']} revocation(s) parked after failures")
    if values["skipped_revocations"]:
        warnings.append(
            f"{values['skipped_revocations']} account(s) outside the group papaia-persons "
            "not revoked"
        )
    if values["journal_pending"] or target not in (None, "ok"):
        warnings.append(
            f"{values['journal_pending'] or 0} erasure journal entr(ies) not at the backup "
            f"target yet (target {target})"
        )
    if health == "warn" and not warnings and not failures:
        warnings.append("the revocation list or the last read of Keycloak is late")
    if failures:
        return CheckResult(name, FAIL, "; ".join(failures + warnings), details)
    if warnings:
        return CheckResult(name, WARN, "; ".join(warnings), details)
    return CheckResult(
        name,
        PASS,
        f"last reconciliation {reconcile // 60} min ago, revocation list "
        f"{values['revocations_age_seconds']} s old",
        details,
    )


def _siem_report(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    report = json.loads(status.first_line(text))
    targets, metrics = report["targets"], report["metrics"]
    if not isinstance(targets, list) or not isinstance(metrics, dict):
        raise ValueError("shape")
    for target in targets:
        if not (
            isinstance(target, dict)
            and isinstance(target.get("target"), str)
            and isinstance(target.get("active"), bool)
            and target.get("status") in ("ok", "warn", "fail")
            and isinstance(target.get("text"), str)
        ):
            raise ValueError("target")
        for key in ("backlog", "lag_seconds", "failing_seconds"):
            _count_field(target, key)
    verified = metrics.get("papaia_audit_verify_ok")
    if not isinstance(verified, dict) or not all(v in (0, 1) for v in verified.values()):
        raise ValueError("verify")
    age = metrics["papaia_audit_verify_age_seconds"]
    if age is not None and (isinstance(age, bool) or not isinstance(age, int) or age < 0):
        raise ValueError("verify age")
    return targets, metrics


def _disk_percent(text: str) -> int | None:
    """The `Capacity` column of `df -P` for the one file system it lists."""
    lines = [line.split() for line in text.splitlines()[1:] if line.strip()]
    if len(lines) != 1:
        return None
    found = [f for f in lines[0] if f.endswith("%") and f[:-1].isdigit()]
    return int(found[0][:-1]) if len(found) == 1 else None


def check_siem(ctx: Context) -> CheckResult:
    """The SIEM export of papaia-audit (`doctor siem`, betrieb BE-28, governance GV-06).

    `fail` when a target has not taken events for more than 10 minutes (lag or failing
    deliveries), a chain does not verify, the volume of papaia-audit-db is 95 % full or
    more, or the service does not run; `warn` for more than 60 s behind, from 80 %, a
    target no longer configured that still holds events back from retention, when no
    target is set at all, when the hourly chain verification is missing or older than
    2 h, and when an operations address is set without an active mail relay.

    Gaps in `seq` per source (BE-28) are part of the chain verification: `seq` is gapless
    by construction (ingest refuses a `source_seq` gap, papaia-audit assigns `seq`), so a
    gap means a stored event is missing and the chain does not verify. That is `fail`,
    not `warn`: it is the tamper evidence of GV-07, not a delivery delay."""
    name = "siem"
    if not ctx.configured:
        return _not_set_up(name)
    if AUDIT_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "not enabled (the audit profile is off)")
    found = _core_container(ctx, AUDIT_SERVICE)
    if found is None:
        return CheckResult(name, SKIP, "papaia-audit does not run on this host")
    container, state = found
    if container is None or state != "running":
        return CheckResult(
            name, FAIL,
            f"papaia-audit is {state or 'not created'}: no audit event is stored or sent to "
            "the SIEM ('papaia-ctl start' starts it)",
            {"state": state},
        )
    done = ctx.run(["docker", "exec", container, *SIEM_STATUS_COMMAND], SIEM_TIMEOUT_SECONDS)
    try:
        targets, metrics = _siem_report(done.stdout)
    except (ValueError, TypeError, KeyError):
        return CheckResult(name, FAIL, "the SIEM report of papaia-audit cannot be read",
                           {"exit_code": done.returncode})
    percent = None
    database = _core_container(ctx, AUDIT_DB_SERVICE)
    if database is not None and database[0] and database[1] == "running":
        listing = ctx.run(["docker", "exec", database[0], "df", "-P", AUDIT_DB_DATA],
                          SIEM_TIMEOUT_SECONDS)
        percent = _disk_percent(listing.stdout) if listing.returncode == 0 else None
    details: dict[str, Any] = {"targets": targets, "metrics": metrics, "disk_percent": percent}
    failures: list[str] = []
    warnings: list[str] = []
    for target in targets:
        line = f"{target['target']} {target['text']}"
        if target["status"] == "fail":
            failures.append(line + " ('papaia-ctl logs papaia-audit' names the cause)")
        elif target["status"] == "warn":
            warnings.append(line)
    if not any(t["active"] for t in targets):
        warnings.append("no SIEM target set (PAPAIA_AUDIT_SIEM_TARGET): audit events stay in "
                        "the store only")
    broken = sorted(s for s, ok in metrics["papaia_audit_verify_ok"].items() if not ok)
    if broken:
        failures.append(f"the chain of {', '.join(broken)} does not verify "
                        "('papaia-ctl audit verify' names the position)")
    age = metrics["papaia_audit_verify_age_seconds"]
    if age is None or age > SIEM_VERIFY_STALE_SECONDS:
        when = "has not run yet" if age is None else f"last ran {age // 3600} h ago"
        warnings.append(f"the hourly chain verification {when} ('papaia-ctl audit verify' "
                        "checks every chain now)")
    if ctx.env.get(OPERATIONS_MAIL_KEY, "").strip() and not smtp.Settings.load(
        ctx.config_dir
    ).active:
        warnings.append(f"{OPERATIONS_MAIL_KEY} is set, but the mail relay is not active "
                        "(profile smtp with a mail server): no warning mail can be sent")
    if percent is None:
        warnings.append("the fill level of the papaia-audit-db volume could not be read")
    elif percent >= SIEM_DISK_FAIL_PERCENT:
        failures.append(f"the papaia-audit-db volume is {percent} % full: undelivered events "
                        "pile up there")
    elif percent >= SIEM_DISK_WARN_PERCENT:
        warnings.append(f"the papaia-audit-db volume is {percent} % full")
    if failures:
        return CheckResult(name, FAIL, "; ".join(failures + warnings), details)
    if warnings:
        return CheckResult(name, WARN, "; ".join(warnings), details)
    active = sum(1 for t in targets if t["active"])
    return CheckResult(
        name, PASS,
        f"{active} SIEM target(s) up to date, papaia-audit-db volume {percent} % full", details,
    )


def check_approvals(ctx: Context) -> CheckResult:
    """The four-eyes rule (`doctor approvals`, BE-26): reports `approvals.four_eyes` as the
    catalog publishes it. `fail` for a malformed `approvals.yaml` and for a stored `off` in
    security profile kritis, where the rule cannot be switched off (the catalog states `on`
    all the same; the stored value contradicts the profile)."""
    name = "approvals"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        profile = catalog.profile_name(common.parse_env_file(ctx.config_dir / ".env"))
    except catalog.CatalogError as exc:
        return CheckResult(
            name, FAIL,
            f"{exc}; the four-eyes rule cannot be read from an unknown security profile",
            {"security_profile": None},
        )
    try:
        stored = catalog.stored_four_eyes(ctx.config_dir)
    except catalog.CatalogError as exc:
        return CheckResult(name, FAIL, f"{exc} (papaia-ctl settings set approvals.four_eyes)",
                           {"security_profile": profile})
    value = catalog.four_eyes_in_effect(profile, stored)
    details = {"four_eyes": value, "security_profile": profile, "stored": stored}
    if profile == catalog.FOUR_EYES_FIXED_PROFILE:
        if stored == "off":
            return CheckResult(
                name, FAIL,
                f"approvals.yaml says four eyes off, which security profile {profile} does not "
                "allow; the catalog states on ('papaia-ctl settings set approvals.four_eyes on')",
                details,
            )
        return CheckResult(name, PASS, f"four eyes on (fixed by security profile {profile})",
                           details)
    origin = "default" if stored is None else "set"
    return CheckResult(name, PASS, f"four eyes {value} ({origin}, security profile {profile})",
                       details)


def check_contact_point(ctx: Context) -> CheckResult:
    """The contact point for users (`doctor contact_point`, PLT-82): `warn` while none is
    set, since every module then shows "Ansprechstelle nicht hinterlegt"."""
    name = "contact_point"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        contact = catalog.current_branding(ctx.config_dir).get("contact")
    except catalog.CatalogError as exc:
        return CheckResult(name, FAIL, str(exc))
    if not contact:
        return CheckResult(
            name, WARN,
            "no contact point for users is set; modules show 'Ansprechstelle nicht hinterlegt' "
            "('papaia-ctl settings set contact.name <name>', then contact.mail or contact.phone)",
            {"contact": None},
        )
    if contact.get("name") == setup_answers.derived_contact(ctx.config_dir):
        return CheckResult(
            name, WARN,
            f"the contact point is still the one setup derived ({contact['name']}); set the "
            "people's real contact ('papaia-ctl settings set contact.name <name>')",
            {"contact": contact, "derived": True},
        )
    return CheckResult(name, PASS, f"contact point: {contact['name']}", {"contact": contact})


def _uplink_members(ctx: Context, network: str) -> list[tuple[str, str, str]] | None:
    """(container, compose service, compose project) of every running container on
    `network`, or None when Docker does not answer."""
    listed = ctx.run(
        [
            "docker",
            "ps",
            "--filter",
            f"network={network}",
            "--format",
            '{{.Names}}\t{{.Label "com.docker.compose.service"}}'
            '\t{{.Label "com.docker.compose.project"}}',
        ],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if listed.returncode != 0:
        return None
    found = []
    for line in listed.stdout.splitlines():
        parts = (line.split("\t") + ["", ""])[:3]
        if parts[0].strip():
            found.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return found


def _check_uplink_network(
    ctx: Context, network: str, subnet: str, details: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """(failures, warnings) about the uplink network itself and who is on it."""
    fails: list[str] = []
    warns: list[str] = []
    try:
        addon = sql_uplink.sql_addon(ctx.config_dir, ctx.repo_root)
    except sql_uplink.SqlUplinkError as exc:
        return [str(exc)], []
    inspected = ctx.run(
        ["docker", "network", "inspect", "--format", "{{json .}}", network],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if inspected.returncode != 0:
        warns.append(
            f"{network} is not created yet (the start of the add-on with {sql_uplink.SERVICE}"
            " creates it)"
        )
        return fails, warns
    try:
        data = json.loads(inspected.stdout or "{}")
    except ValueError:
        return [f"docker network inspect {network}: unreadable answer"], warns
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return [f"docker network inspect {network}: unreadable answer"], warns
    if data.get("Internal") is True:
        fails.append(f"{network} is internal: {sql_uplink.SERVICE} has no route to the SQL source")
    configs = (data.get("IPAM") or {}).get("Config") or []
    subnets = [c.get("Subnet") for c in configs if isinstance(c, dict)]
    details["live_subnets"] = subnets
    ipv6 = [str(s) for s in subnets if ":" in str(s or "")]
    if data.get("EnableIPv6") is True or ipv6:
        fails.append(
            f"{network} has IPv6 ({', '.join(ipv6) or 'EnableIPv6'}): the host rules are IPv4"
            " only, so it is a way out no rule covers (remove the network and start the add-on"
            " again)"
        )
    expected_bridge = sql_uplink.bridge(sql_uplink.root_env(ctx.config_dir))
    live_bridge = (data.get("Options") or {}).get(sql_uplink.BRIDGE_OPTION)
    details["bridge"] = live_bridge
    if live_bridge != expected_bridge:
        fails.append(
            f"{network} is on the bridge {live_bridge or 'chosen by Docker'}, the host rules are"
            f" for {expected_bridge} (remove the network and start the add-on again)"
        )
    if subnets != [subnet]:
        fails.append(
            f"{network} has the range {', '.join(map(str, subnets)) or 'none'}, the host rules"
            f" are for {subnet} (remove the network and start the add-on again)"
        )
    members = _uplink_members(ctx, network)
    if members is None:
        warns.append(f"the members of {network} could not be listed")
        return fails, warns
    details["members"] = [m[0] for m in members]
    project = addon[1].name if addon else None
    foreign = [
        name
        for name, service, owner in members
        if service != sql_uplink.SERVICE or owner != project
    ]
    if foreign:
        fails.append(
            f"{network} has members other than {sql_uplink.SERVICE}: {', '.join(foreign)}"
        )
    for container, service, owner in members:
        if service == sql_uplink.SERVICE and owner == project:
            routed, unknown = _second_routes(ctx, container, network)
            if routed:
                fails.append(
                    f"{container} is also on {', '.join(routed)}, which is not internal: Docker"
                    " may put its default route there and the host rules drop that traffic"
                    " (the other networks of the SQL add-on must be internal)"
                )
            if unknown:
                warns.append(f"the networks of {container} could not be read: {unknown}")
    return fails, warns


def _second_routes(ctx: Context, container: str, uplink: str) -> tuple[list[str], str]:
    """(networks of `container` besides the uplink that are not internal, reason when they
    cannot be read). Only an internal network carries no default route."""
    listed = ctx.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if listed.returncode != 0:
        return [], status.first_line(listed.stderr) or f"exit {listed.returncode}"
    try:
        attached = json.loads(listed.stdout or "{}")
    except ValueError:
        return [], "unreadable answer"
    if not isinstance(attached, dict):
        return [], "unreadable answer"
    routed: list[str] = []
    for name in sorted(n for n in attached if isinstance(n, str) and n != uplink):
        inspected = ctx.run(
            ["docker", "network", "inspect", "--format", "{{json .}}", name],
            DOCKER_PROBE_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(inspected.stdout or "{}") if inspected.returncode == 0 else None
        except ValueError:
            data = None
        if isinstance(data, list):
            data = data[0] if data else None
        if not isinstance(data, dict):
            return routed, f"docker network inspect {name} failed"
        if data.get("Internal") is not True:
            routed.append(name)
    return routed, ""


def _check_host_rules(
    ctx: Context, expected: list[str], chain: str, rules_file: Path
) -> tuple[list[str], list[str]]:
    """(failures, warnings) from comparing the host's chain with the rendered one."""
    load = f"load them as root with 'sudo sh {rules_file}'"
    live = ctx.run(["iptables", "-S", chain], IPTABLES_TIMEOUT_SECONDS)
    user = ctx.run(["iptables", "-S", sql_uplink.DOCKER_USER], IPTABLES_TIMEOUT_SECONDS)
    if live.returncode == 0 and user.returncode == 0:
        problems = sql_uplink.compare(expected, chain, live.stdout, user.stdout)
        if problems:
            return [f"host rules differ from {rules_file}: {'; '.join(problems)}; {load}"], []
        return [], []
    answers = [r for r in (live, user) if r.returncode != 0]
    if all(r.returncode not in (124, 126, 127) and "No chain" in r.stderr for r in answers):
        return [f"host rules not loaded (no chain {chain}); {load}"], []
    reason = status.first_line(answers[0].stderr) or f"exit {answers[0].returncode}"
    return [], [
        f"host rules not verified: {reason} (run 'sudo papaia-ctl doctor' on the Docker host;"
        " on Docker Desktop the rules live in its VM)"
    ]


def check_network(ctx: Context) -> CheckResult:
    """The one direct route out of the stack, to the SQL source (row K-14,
    docs/network.md). Without a SQL source there is nothing to check. With one: the
    network `<project>-sql-uplink` is not internal, has the rendered range and only
    `mcp-mssql` of the SQL add-on on it, and the host's chain equals the rendered rules
    (`iptables -S`, which needs root) with the jump as the first rule of DOCKER-USER.
    A drifted, missing or misplaced rule is `fail`; rules that cannot be read here
    (not root, no iptables, inside a container) are `warn`, never `pass`."""
    name = "network"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        expected = sql_uplink.expected_rules(ctx.config_dir)
    except (sql_uplink.SqlUplinkError, egress.EgressError) as exc:
        return CheckResult(name, FAIL, str(exc))
    if not expected:
        return CheckResult(name, SKIP, "no SQL source: nothing leaves the stack directly")
    env = sql_uplink.root_env(ctx.config_dir)
    network = sql_uplink.network_name(env)
    subnet = str(sql_uplink.subnet(env))
    chain = sql_uplink.chain(env)
    rules_file = ctx.config_dir / sql_uplink.RULES_FILE
    details: dict[str, Any] = {
        "network": network,
        "subnet": subnet,
        "chain": chain,
        "rules_file": str(rules_file),
        "members": [],
    }
    fails, warns = _check_uplink_network(ctx, network, subnet, details)
    rule_fails, rule_warns = _check_host_rules(ctx, expected, chain, rules_file)
    fails += rule_fails
    warns += rule_warns
    if fails:
        return CheckResult(name, FAIL, "; ".join(fails + warns), details)
    if warns:
        return CheckResult(name, WARN, "; ".join(warns), details)
    hosts = len(sql_uplink.targets(ctx.config_dir))
    return CheckResult(
        name,
        PASS,
        f"direct route to {hosts} SQL source(s) only through {network}; host rules match",
        details,
    )


def _lifecycle_report(ctx: Context, container: str) -> dict[str, Any] | None:
    done = ctx.lifecycle_health(container)
    try:
        report = json.loads(status.first_line(done.stdout))
    except ValueError:
        return None
    return report if isinstance(report, dict) else None


def check_startgate(ctx: Context) -> CheckResult:
    """The core start gate (`doctor startgate`; sicherheit §4.9 (2a), betrieb BE-16a Nr.
    2a): `fail` while papaia-lifecycle keeps the edge closed (checking, behind the
    erasure journal, target unreachable, replay failed) or when a person of an override
    was locked or changed afterwards; `warn` while an override is in effect and for
    accounts the replay deactivated (credentials or a role changed after the snapshot)."""
    from . import startgate

    name = "startgate"
    if not ctx.configured:
        return _not_set_up(name)
    if LIFECYCLE_PROFILE not in ctx.active_profiles:
        return CheckResult(name, SKIP, "not enabled (the lifecycle profile is off)")
    found = _lifecycle_container(ctx)
    if found is None:
        return CheckResult(name, SKIP, "papaia-lifecycle does not run on this host")
    container, state = found
    if container is None or state != "running":
        return CheckResult(
            name, FAIL,
            f"papaia-lifecycle is {state or 'not created'}: the edge stays closed "
            "('papaia-ctl start' starts it)",
            {"state": state},
        )  # fmt: skip
    report = _lifecycle_report(ctx, container)
    gate = report.get("startgate") if report is not None else None
    if gate is None:
        return CheckResult(name, FAIL, "papaia-lifecycle reports no start gate")
    try:
        result, text = startgate.doctor_result(gate)
    except ValueError:
        return CheckResult(name, FAIL, "the start gate in the health report cannot be read")
    details = {
        "status": gate["status"],
        "failed": list(gate["failed"]),
        "credential_replay": len(gate["credential_replay"]),
        "role_replay": len(gate["role_replay"]),
    }
    return CheckResult(name, result, text, details)


def check_state_epoch(ctx: Context) -> CheckResult:
    """The data state against the erasure journal (`doctor state_epoch`; betrieb BE-16a
    Nr. 3, sicherheit §4.9 (4)): `fail` while an add-on has not applied its journal after a
    restore or `recover-snapshot`, while the core start gate is behind the journal or its
    replay failed, and for a damaged `epoch`; `warn` while the backup target or the mirror
    cannot be read (the check is then provisional, see `lifecycle`) and while the start gate
    has raised the generation beyond the one `recover-snapshot` confirmed: after a returned
    VM or volume snapshot `recover-snapshot` is still due (§S-10)."""
    from papaia_kit.erasure import (
        STATE_EPOCH_BEHIND_MESSAGE,
        JournalError,
        JournalUnavailableError,
        read_epoch,
    )

    from . import erasure_mirror, module_actions

    name = "state_epoch"
    if not ctx.configured:
        return _not_set_up(name)
    backup_dir = common.parse_env_file(ctx.config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if not backup_dir or common.is_placeholder(backup_dir):
        return CheckResult(name, SKIP, "no backup target set (PAPAIA_BACKUP_DIR)")
    target = Path(backup_dir) / erasure_mirror.JOURNAL_FOLDER
    lifecycle_on = LIFECYCLE_PROFILE in ctx.active_profiles
    fails: list[str] = []
    warns: list[str] = []
    details: dict[str, Any] = {}
    sentence = f"{STATE_EPOCH_BEHIND_MESSAGE} (Handbuch §S-10)"

    try:
        pending = module_actions.load(ctx.config_dir)
    except module_actions.ModuleActionError:
        fails.append(f"the add-ons' pending restore steps cannot be read. {sentence}")
    else:
        due = sorted(n for n, a in (pending or {}).get("modules", {}).items()
                     if "erasure-replay" in a)
        if due:
            details["behind"] = due
            fails.append(f"{', '.join(due)}: erasure journal not applied yet. {sentence}")

    epoch = None
    try:
        epoch = read_epoch(target)
    except JournalUnavailableError:
        if not lifecycle_on and not target.parent.is_dir():
            return CheckResult(name, SKIP, "no erasure journal on this installation")
        warns.append(f"the erasure journal at the backup target {target} is not reachable; "
                     "the comparison is provisional (see doctor lifecycle)")
    except JournalError:
        fails.append(f"{target}/epoch is damaged; the start gate stays closed")
    if epoch is None and not warns and not fails and not lifecycle_on:
        return CheckResult(name, SKIP,
                           "no erasure journal epoch yet (the lifecycle profile is off)")

    if lifecycle_on:
        found = _lifecycle_container(ctx)
        if found is not None and found[0] is not None and found[1] == "running":
            report = _lifecycle_report(ctx, found[0])
            gate = report.get("startgate") if report is not None else None
            gate_status = gate.get("status") if isinstance(gate, dict) else None
            details["startgate"] = gate_status
            if gate_status in ("behind", "replay_failed", "checking"):
                fails.append(f"the core start gate is {gate_status}. {sentence}")
            elif gate_status == "unverified":
                warns.append("the start gate cannot read the erasure journal at the backup "
                              "target (see doctor startgate)")

    try:
        settings = erasure_mirror.load_settings(ctx.config_dir)
    except erasure_mirror.MirrorError as exc:
        fails.append(str(exc))
    else:
        details["mirror"] = settings.mirror is not None
        if settings.mirror is not None and (
            settings.mirror.is_symlink() or not settings.mirror.is_dir()
        ):
            warns.append(f"the erasure journal mirror {settings.mirror} is not reachable")

    if epoch is not None:
        confirmed = erasure_mirror.confirmed_generation(ctx.config_dir)
        details.update({"generation": epoch.generation, "confirmed": confirmed})
        if epoch.generation > (confirmed or 0):
            warns.append(
                f"the start gate replayed the erasure journal (generation {epoch.generation}, "
                f"confirmed {confirmed if confirmed is not None else 'none'}): a returned "
                "snapshot is not finished; run 'papaia-ctl recover-snapshot' (Handbuch §S-10)"
            )
    if fails:
        return CheckResult(name, FAIL, "; ".join(fails + warns), details)
    if warns:
        return CheckResult(name, WARN, "; ".join(warns), details)
    return CheckResult(name, PASS, "no add-on and no core service is behind the erasure "
                                   "journal", details)


def check_identity(ctx: Context) -> CheckResult:
    """The federation with the upstream provider (`doctor identity`; security 1.13):
    `fail` when papaia-lifecycle's status sync with the upstream directory has failed
    for longer than 300 s or never ran, or the service does not run; locks in the
    company directory then do not reach papaia. Skipped without `security/idp.yaml`."""
    name = "identity"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        fed = federation.load(ctx.config_dir)
    except federation.FederationError as exc:
        return CheckResult(name, FAIL, f"the federation is not usable: {exc}")
    if fed is None:
        return CheckResult(name, SKIP, "no federation (no security/idp.yaml)")
    if LIFECYCLE_PROFILE not in ctx.active_profiles:
        return CheckResult(
            name, FAIL,
            "federation without the lifecycle profile: no status sync, locks in the company "
            "directory do not reach papaia",
        )
    found = _lifecycle_container(ctx)
    if found is None:
        return CheckResult(name, SKIP, "papaia-lifecycle does not run on this host")
    container, state = found
    if container is None or state != "running":
        return CheckResult(
            name, FAIL, f"papaia-lifecycle is {state or 'not created'}: no status sync",
            {"state": state},
        )
    report = _lifecycle_report(ctx, container)
    try:
        if report is None:
            raise ValueError("report")
        age = _count_field(report, "status_sync_age_seconds", optional=True)
        failing = _count_field(report, "status_sync_failing_seconds", optional=True)
    except ValueError:
        return CheckResult(name, FAIL, "the health report of papaia-lifecycle cannot be read")
    details = {"status_sync_age_seconds": age, "status_sync_failing_seconds": failing}
    if failing is None:
        return CheckResult(
            name, FAIL, "the status sync has not run (papaia-lifecycle without the federation "
            "folder; 'papaia-ctl start' applies it)", details,
        )
    if failing > STATUS_SYNC_FAIL_SECONDS:
        return CheckResult(
            name, FAIL,
            f"federation disturbed: the status sync with the upstream directory fails for "
            f"{failing // 60} min; locks in the company directory do not reach papaia",
            details,
        )
    if age is None or age > STATUS_SYNC_FAIL_SECONDS:
        return CheckResult(
            name, FAIL, "federation disturbed: no successful status sync in the last 5 min",
            details,
        )
    return CheckResult(name, PASS, f"last status sync {age} s ago", details)


def _hours_left(seconds: float) -> str:
    hours, rest = divmod(max(int(seconds), 0) // 60, 60)
    return f"{hours} h {rest:02d} min"


def check_rollback_window(ctx: Context) -> CheckResult:
    """The rollback key of the last upgrade (`doctor rollback_window`, BE-11, RE-11): how
    long `rollback` still works without the operator key. `fail` for a key that is still
    there after its window or after its run ended, for a key file others can read, and
    for a malformed window setting; `skip` without any key."""
    from . import rollback_key, upgrade_stages

    name = "rollback_window"
    if not ctx.configured:
        return _not_set_up(name)
    now = ctx.now.timestamp()
    try:
        hours = rollback_key.window_hours(ctx.config_dir)
        state = upgrade_stages.load_state(ctx.config_dir)
        keys = rollback_key.classify(ctx.config_dir, state, hours, now)
    except (rollback_key.RollbackKeyError, upgrade_stages.StageError, OSError) as exc:
        return CheckResult(name, FAIL, str(exc))
    details: dict[str, Any] = {
        "window_hours": hours,
        "keys": [
            {"upgrade_id": k.upgrade_id, "state": k.kind,
             "deadline": None if k.deadline is None else
             datetime.fromtimestamp(k.deadline, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for k in keys
        ],
    }
    if not keys:
        return CheckResult(name, SKIP, "no rollback key on this host; 'rollback' needs the "
                                       "operator key (--identity)", details)
    problems: list[str] = []
    warnings: list[str] = []
    passes: list[str] = []
    folder = rollback_key.key_dir(ctx.config_dir)
    try:
        if os.lstat(folder).st_mode & 0o077:
            problems.append(f"{folder} is open to others than its owner (0700 expected)")
    except OSError as exc:
        problems.append(f"{folder} cannot be read ({exc.strerror})")
    for entry in rollback_key.list_keys(ctx.config_dir):
        if entry.mode & 0o077:
            problems.append(f"{entry.path.name} is readable by others than its owner")
    for key in keys:
        when = None if key.deadline is None else datetime.fromtimestamp(
            key.deadline, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if key.kind == "bad":
            problems.append(f"{key.path.name} is not a rollback key file")
        elif key.kind == "expired":
            problems.append(
                f"the rollback key of upgrade {key.upgrade_id} is still there although its "
                f"window ended {when}; delete it with 'papaia-ctl upgrade --finalize -y'"
            )
        elif key.kind == "ended":
            problems.append(
                f"the rollback key of upgrade {key.upgrade_id} is still there although the "
                "run ended; delete it with 'papaia-ctl upgrade --finalize -y'"
            )
        elif key.kind == "orphan":
            text = f"rollback key {key.upgrade_id} belongs to no recorded upgrade"
            if key.deadline is not None and now >= key.deadline:
                problems.append(f"{text}; delete it with 'papaia-ctl upgrade --finalize -y'")
            else:
                warnings.append(text)
        elif key.kind == "running":
            passes.append(
                f"upgrade to {state['to']} in progress; its rollback key stays until it ends"
            )
        else:
            passes.append(
                f"'rollback' works without the operator key for {_hours_left(key.deadline - now)}"
                f" more (until {when})"
            )
    if problems:
        return CheckResult(name, FAIL, "; ".join(problems), details)
    if warnings:
        return CheckResult(name, WARN, "; ".join(warnings + passes), details)
    return CheckResult(name, PASS, "; ".join(passes), details)


# ─────────────────────────────────────────────────────────────────────────
# modules of the platform catalog (PLT-42, BE-26, RE-56)
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class _ModuleScan:
    """The catalog, the active add-ons and what the probes saw, shared by `modules` and
    `revocations_age` so that every network is probed once per run."""

    entries: list[module_health.Entry] | None
    addons: dict[str, module_health.Addon]
    networks: dict[str, str | None]  # provider -> network it is probed from
    probes: dict[str, module_health.Probe]  # origin -> answer
    failures: dict[str, tuple[str, str]]  # network -> (status, text) of a probe that failed
    refused: dict[str, str]  # origin -> why it is not probed (a host outside the stack)


def _unprobed(scan: _ModuleScan, origin: str, network: str | None) -> tuple[str, str] | None:
    """(status, text) when a running *origin* has no probe answer, else None."""
    if origin in scan.refused:
        return WARN, scan.refused[origin]
    if network is None:
        return WARN, f"{origin}: no network known to probe it from"
    if network in scan.failures:
        return scan.failures[network]
    if origin not in scan.probes:
        return WARN, f"{origin} was not probed"
    return None


def _provider_network(ctx: Context, provider: str, addons: dict[str, module_health.Addon]):
    if provider.startswith(module_health.CORE_PROVIDER_PREFIX):
        return module_health.core_network(ctx.config_dir)
    addon = addons.get(provider)
    return addon.network if addon is not None else None


def _module_scan(ctx: Context) -> _ModuleScan:
    """Raises module_health.ModuleHealthError for a catalog that cannot be used."""
    if ctx._modules is not None:
        return ctx._modules
    entries = module_health.load_entries(ctx.config_dir)
    addons = {a.name: a for a in module_health.active_addons(ctx.config_dir, ctx.repo_root)}
    scan = _ModuleScan(entries, addons, {}, {}, {}, {})
    by_network: dict[str, list[str]] = {}
    for entry in entries or []:
        network = _provider_network(ctx, entry.provider, addons)
        scan.networks[entry.provider] = network
        if entry.state != catalog.RUNNING or entry.origin is None:
            continue
        refused = module_health.outside_the_stack(entry.origin)
        if refused is not None:
            scan.refused[entry.origin] = refused
            continue
        if network is None:
            continue
        origins = by_network.setdefault(network, [])
        if entry.origin not in origins:
            origins.append(entry.origin)
    for network, origins in by_network.items():
        for start in range(0, len(origins), module_health.MAX_ORIGINS_PER_PROBE):
            batch = origins[start:start + module_health.MAX_ORIGINS_PER_PROBE]
            try:
                argv = module_health.probe_argv(ctx.repo_root, network, batch)
            except module_health.ModuleHealthError as exc:
                scan.failures[network] = (WARN, f"cannot probe from network {network}: {exc}")
                break
            done = ctx.run(argv, module_health.PROBE_TIMEOUT_SECONDS)
            if done.returncode != 0:
                reason = status.first_line(done.stderr) or f"exit {done.returncode}"
                scan.failures[network] = (
                    WARN, f"the probe container on network {network} did not run ({reason})"
                )
                break
            try:
                scan.probes.update(module_health.parse_probe(done.stdout, batch))
            except (ValueError, TypeError, AttributeError):
                scan.failures[network] = (
                    WARN, f"the probe on network {network} gave an answer that cannot be read"
                )
                break
    ctx._modules = scan
    return scan


def _network_members(ctx: Context, network: str) -> set[str] | None:
    """Container names on *network*; None when Docker does not say (no such network,
    no daemon)."""
    if network not in ctx._members:
        done = ctx.run(
            ["docker", "network", "inspect", network, "--format", "{{json .Containers}}"],
            DOCKER_PROBE_TIMEOUT_SECONDS,
        )
        members: set[str] | None = None
        if done.returncode == 0:
            try:
                members = module_health.parse_network_members(done.stdout)
            except ValueError:
                members = None
        ctx._members[network] = members
    return ctx._members[network]


def _neighbours(ctx: Context, addon: module_health.Addon) -> list[dict[str, Any]]:
    """One item per attached core service: is it on the add-on's app network (PLT-42-A2)?"""
    items: list[dict[str, Any]] = []
    reachable = ctx.status_report().docker.reachable
    for service in addon.attach:
        item: dict[str, Any] = {"neighbour": service, "network": addon.network}
        found = _core_container(ctx, service) if reachable else None
        if not reachable:
            item.update(status=WARN, text=f"neighbour {service} unknown, Docker not reachable")
        elif addon.network is None:
            item.update(status=FAIL, text=f"attaches {service} but declares no app network")
        elif found is None:
            item.update(status=WARN, text=f"neighbour {service} does not run on this host")
        elif found[0] is None or found[1] != "running":
            item.update(status=FAIL, text=f"neighbour {service} is {found[1] or 'not created'}")
        else:
            members = _network_members(ctx, addon.network)
            if members is None:
                item.update(
                    status=FAIL,
                    text=f"network {addon.network} does not exist; no network path to {service}",
                )
            elif found[0] not in members:
                item.update(
                    status=FAIL,
                    text=f"no network path to neighbour {service}: {found[0]} is not on "
                         f"network {addon.network}",
                )
            else:
                item.update(status=PASS, text=f"{service} reachable on {addon.network}")
        items.append(item)
    return items


def _addon_health(ctx: Context, addon: module_health.Addon) -> str | None:
    """The container state `status` reports for the add-on's project."""
    report = ctx.status_report()
    if not report.docker.reachable:
        return None
    states = [m.status for m in report.addons if m.compose_project == addon.project]
    return status.worst(states).value if states else None


def check_modules(ctx: Context) -> CheckResult:
    """One row per module of the platform catalog and per active add-on (`doctor modules`,
    PLT-42, BE-26): version and state from the catalog, the answer of `/healthz` of every
    running entry asked from the module's own network, and the network path to every
    core service the add-on attaches."""
    name = "modules"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        scan = _module_scan(ctx)
    except module_health.ModuleHealthError as exc:
        return CheckResult(name, FAIL, f"the platform catalog cannot be used: {exc}")
    providers: list[str] = []
    for entry in scan.entries or []:
        if entry.provider not in providers:
            providers.append(entry.provider)
    providers.extend(n for n in scan.addons if n not in providers)
    if not providers:
        return CheckResult(name, SKIP, "no module in the platform catalog and no active add-on")

    rows: list[dict[str, Any]] = []
    for provider in providers:
        entries = [e for e in scan.entries or [] if e.provider == provider]
        addon = scan.addons.get(provider)
        running = any(e.state == catalog.RUNNING for e in entries)
        row: dict[str, Any] = {
            "module": provider,
            "version": entries[0].version if entries else
            (str(addon.manifest.get("version")) if addon and addon.manifest.get("version")
             else None),
            "state": (catalog.RUNNING if running else catalog.STOPPED) if entries else None,
            "containers": _addon_health(ctx, addon) if addon else None,
            "entries": [e.id for e in entries],
            "health": [],
            "neighbours": _neighbours(ctx, addon) if addon else [],
        }
        network = scan.networks.get(provider)
        origins: list[str] = []
        for entry in entries:
            if entry.state == catalog.RUNNING and entry.origin and entry.origin not in origins:
                origins.append(entry.origin)
        for origin in origins:
            item: dict[str, Any] = {"origin": origin, "network": network}
            missing = _unprobed(scan, origin, network)
            if missing is not None:
                item.update(status=missing[0], text=missing[1])
            else:
                probe = scan.probes[origin]
                verdict, text = module_health.health_verdict(probe, network)
                item.update(status=verdict, text=text, health=probe.health,
                            http_status=probe.healthz_code)
            row["health"].append(item)
        row["status"] = _worst(
            [i["status"] for i in row["health"] + row["neighbours"]] or [PASS]
        )
        rows.append(row)

    overall = _worst(r["status"] for r in rows)
    problems = [
        f"{r['module']}: {i['text']}"
        for r in rows
        for i in r["health"] + r["neighbours"]
        if i["status"] != PASS
    ]
    if problems:
        summary = "; ".join(problems)
    else:
        summary = f"{len(rows)} module(s): " + ", ".join(
            f"{r['module']} {r['version'] or '?'} ({r['state'] or 'not in the catalog'})"
            for r in rows
        )
    return CheckResult(name, overall, summary, {"modules": rows})


def check_revocations_age(ctx: Context) -> CheckResult:
    """`revocations_age_seconds` of every running module (`doctor revocations_age`, BE-26,
    EXI-P15): older than 60 s is `warn`, older than 300 s `fail`. Read from `/metrics` by
    the same probe as `modules`; a module whose `/metrics` needs the operations token is
    reported as `skip`."""
    name = "revocations_age"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        scan = _module_scan(ctx)
    except module_health.ModuleHealthError as exc:
        return CheckResult(name, FAIL, f"the platform catalog cannot be used: {exc}")
    if scan.entries is None:
        return CheckResult(name, SKIP, "no platform catalog yet ('papaia-ctl catalog render')")
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in scan.entries:
        if entry.state != catalog.RUNNING or entry.origin is None or entry.origin in seen:
            continue
        seen.add(entry.origin)
        # A running module without a probe answer has an unknown revocation age: warn
        # with the reason (probe did not start, answer unreadable, host outside the stack).
        missing = _unprobed(scan, entry.origin, scan.networks.get(entry.provider))
        if missing is not None:
            verdict, text, age = missing[0], missing[1], None
        else:
            verdict, text, age = module_health.revocations_verdict(scan.probes[entry.origin])
        items.append({"module": entry.provider, "origin": entry.origin,
                      "revocations_age_seconds": age, "status": verdict, "text": text})
    counted = [i for i in items if i["status"] != SKIP]
    if not counted:
        return CheckResult(name, SKIP, "no running module reported revocations_age_seconds",
                           {"modules": items})
    overall = _worst(i["status"] for i in counted)
    problems = [f"{i['module']}: {i['text']}" for i in counted if i["status"] != PASS]
    if problems:
        return CheckResult(name, overall, "; ".join(problems), {"modules": items})
    oldest = max(i["revocations_age_seconds"] for i in counted)
    return CheckResult(
        name, PASS, f"{len(counted)} module(s), oldest revocation list {oldest:.0f} s",
        {"modules": items},
    )


def check_egress(ctx: Context) -> CheckResult:
    """The single exit (`doctor egress`, RE-55, docs/egress.md): the profile is on,
    papaia-egress runs, its configuration is there and holds a source for every active
    add-on that declares an egress network, each with its attachment override."""
    name = "egress"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        declared = egress.declarations(ctx.config_dir, ctx.repo_root)
    except egress.EgressError as exc:
        return CheckResult(name, FAIL, f"an egress declaration is not usable: {exc}")
    names = [d["name"] for d in declared]
    details: dict[str, Any] = {"declared": names}
    if egress.PROFILE not in ctx.active_profiles:
        if names:
            return CheckResult(
                name, FAIL,
                f"the egress profile is off although {', '.join(names)} need(s) the exit",
                details,
            )
        return CheckResult(
            name, WARN, "the egress profile is off; 'papaia-ctl setup' turns it back on", details
        )
    found = _core_container(ctx, egress.SERVICE)
    if found is None:
        return CheckResult(name, SKIP, f"{egress.SERVICE} does not run on this host", details)
    if found[0] is None or found[1] != "running":
        return CheckResult(
            name, FAIL, f"{egress.SERVICE} is {found[1] or 'not created'}: nothing leaves the "
            "stack", details,
        )
    path = ctx.config_dir / egress.CONFIG_FILE
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(config, dict) or config.get("format") != egress.CONFIG_FORMAT:
            raise ValueError("format")
        sources = config["sources"]
        if not isinstance(sources, list) or not all(
            isinstance(s, dict) and isinstance(s.get("name"), str) for s in sources
        ):
            raise ValueError("sources")
    except (OSError, ValueError, KeyError, UnicodeDecodeError):
        return CheckResult(
            name, FAIL, f"{path} is missing or not a {egress.CONFIG_FORMAT} configuration; "
            "'papaia-ctl start' renders it", details,
        )
    present = {s["name"] for s in sources}
    details["sources"] = sorted(present)
    problems = [
        f"{n} has no source in {egress.CONFIG_FILE}" for n in names if n not in present
    ] + [
        f"{n} has no attachment override" for n in names
        if not egress.override_path(ctx.config_dir, n).is_file()
    ]
    if problems:
        return CheckResult(
            name, FAIL, "; ".join(problems) + "; 'papaia-ctl start' renders them", details
        )
    return CheckResult(
        name, PASS, f"{egress.SERVICE} runs with {len(present)} source(s)", details
    )


# mssql-mcp-rbac reports the SQL Server version and the encryption in effect in its
# commissioning check (`selftest`, one line `version + encryption [<alias>]` per database).
MSSQL_COMPONENT = "mssql-mcp-rbac"
MSSQL_SERVICE = "mssql-mcp-rbac"
MSSQL_SELFTEST = ("/usr/local/bin/entrypoint.sh", "python", "main.py", "selftest")
MSSQL_SELFTEST_TIMEOUT_SECONDS = 90.0
# The step prefix is matched without a length limit on the detail: the version line joins
# every problem of one database, and a long [FAIL] line is still the verdict. The detail is
# shortened only for display.
_SELFTEST_LINE = re.compile(
    r"\A\[(ok|FAIL)\] (version \+ encryption|TLS \+ login) \[([a-z][a-z0-9_-]{0,31})\]"
    r"(?:: (.*))?\Z"
)
_SELFTEST_VERSION_STEP = re.compile(r"\A\[(?:ok|FAIL)\] version \+ encryption\b")
MSSQL_DETAIL_SHOWN = 300


def _shown(text: str) -> str:
    return text if len(text) <= MSSQL_DETAIL_SHOWN else text[:MSSQL_DETAIL_SHOWN - 3] + "..."


def _mssql_container(ctx: Context, addon: module_health.Addon) -> tuple[str | None, str | None]:
    for module in ctx.status_report().addons:
        if module.compose_project != addon.project:
            continue
        for container in module.containers:
            if container.service == MSSQL_SERVICE:
                return container.name or None, container.state or None
    return None, None


def check_source_protection(ctx: Context) -> CheckResult:
    """The SQL Server behind every `mssql-mcp-rbac` add-on (`doctor source_protection`,
    RE-61): version and the encryption in effect, as the server's own `selftest` reports
    them per database. `fail` for an unsupported version or weaker encryption than
    required, `warn` for what the server reports as a warning (no TDS 8.0)."""
    name = "source_protection"
    if not ctx.configured:
        return _not_set_up(name)
    addons = [
        a for a in module_health.active_addons(ctx.config_dir, ctx.repo_root)
        if any(isinstance(c, dict) and c.get("id") == MSSQL_COMPONENT
               for c in a.manifest.get("components") or [])
    ]
    if not addons:
        return CheckResult(name, SKIP, "no SQL Server source")
    if not ctx.status_report().docker.reachable:
        return CheckResult(name, WARN, "Docker not reachable; version and encryption unknown")
    items: list[dict[str, Any]] = []
    for addon in addons:
        container, state = _mssql_container(ctx, addon)
        if container is None or state != "running":
            items.append({"addon": addon.name, "status": FAIL,
                          "text": f"{MSSQL_SERVICE} is {state or 'not created'}; version and "
                                  "encryption unknown"})
            continue
        done = ctx.run(["docker", "exec", container, *MSSQL_SELFTEST],
                       MSSQL_SELFTEST_TIMEOUT_SECONDS)
        lines: dict[str, tuple[str, str, str]] = {}
        unreadable = False
        for line in done.stdout.splitlines():
            found = _SELFTEST_LINE.match(line.strip())
            if found is None:
                unreadable = unreadable or bool(_SELFTEST_VERSION_STEP.match(line.strip()))
                continue
            mark, step, alias, text = found.groups()
            if step == "version + encryption" or alias not in lines:
                lines[alias] = (mark, step, text or "")
        if unreadable:
            items.append({"addon": addon.name, "status": FAIL,
                          "text": f"a version + encryption line of the {MSSQL_SERVICE} "
                                  "selftest cannot be read"})
        if not lines:
            if unreadable:
                continue
            reason = status.first_line(done.stderr) or "it reports no SQL Server version"
            items.append({"addon": addon.name, "status": FAIL,
                          "text": f"selftest of {MSSQL_SERVICE} failed ({reason})"})
            continue
        for alias, (mark, step, text) in sorted(lines.items()):
            if mark == "FAIL":
                verdict = FAIL
            elif step == "version + encryption" and "Encrypt=" in text:
                verdict = PASS
            else:
                verdict = WARN
            items.append({"addon": addon.name, "database": alias, "status": verdict,
                          "text": f"[{alias}] {_shown(text)}" if text else f"[{alias}] {step}"})
    overall = _worst(i["status"] for i in items)
    shown = [i for i in items if i["status"] != PASS] or items
    return CheckResult(
        name, overall, "; ".join(f"{i['addon']}: {i['text']}" for i in shown),
        {"sources": items},
    )


def check_erasure_journal(ctx: Context) -> CheckResult:
    """Each module reaches its own erasure journal alone (`doctor erasure_journal`, PLT-66,
    BE-16; lib/erasure_journal.py). `fail` for a container other than papaia-lifecycle
    that can write the journal folder, the backup target or a journal or `epoch` not its
    own, for a file that is a link, has a second name, belongs to another account or can
    be written by others, and for a journal holding a line of another module (planted;
    the kit does not replay it); `warn` for a module that can read journals not its own."""
    name = "erasure_journal"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        folder = erasure_journal.journal_folder(ctx.config_dir)
    except erasure_journal.ErasureJournalError as exc:
        return CheckResult(name, FAIL, str(exc))
    if folder is None:
        return CheckResult(name, SKIP, "the lifecycle profile is off: no erasure journal")
    if not folder.is_dir():
        return CheckResult(
            name, FAIL, f"{folder} is missing: the backup target is not mounted"
        )
    try:
        findings = erasure_journal.inspect_folder(folder, os.stat(ctx.config_dir).st_uid)
    except OSError as exc:
        return CheckResult(name, FAIL, f"{folder} cannot be read ({exc.strerror})")
    journals = sum(1 for f in findings if f.subject.endswith(".jsonl"))
    report = ctx.status_report()
    if not report.docker.reachable:
        findings.append(erasure_journal.Finding(
            "mounts", WARN, "Docker not reachable; the mounts of the containers are unchecked"
        ))
    else:
        findings.extend(_journal_mounts(ctx, report, folder))
    overall = _worst(f.status for f in findings) if findings else PASS
    shown = [f for f in findings if f.status != PASS]
    summary = (
        "; ".join(f"{f.subject}: {f.text}" for f in shown)
        or f"{journals} journal(s); every module reaches its own alone"
    )
    return CheckResult(
        name, overall, summary,
        {"findings": [{"subject": f.subject, "status": f.status, "text": f.text}
                      for f in findings]},
    )


def _journal_mounts(
    ctx: Context, report: status.StatusReport, folder: Path
) -> list[erasure_journal.Finding]:
    """The bind mounts of every container of the core and the add-ons, from one
    `docker inspect`, judged by `erasure_journal.inspect_mounts`."""
    roles: dict[str, tuple[str, str | None]] = {}
    for module in report.core:
        for container in module.containers:
            if container.name:
                role = (
                    "lifecycle" if container.service == erasure_journal.LIFECYCLE_SERVICE
                    else "core"
                )
                roles[container.name] = (role, None)
    projects = {a.project: a.name for a in module_health.active_addons(
        ctx.config_dir, ctx.repo_root)}
    for module in report.addons:
        owner = projects.get(module.compose_project, module.name)
        for container in module.containers:
            if container.name:
                roles[container.name] = ("module", f"{owner}.jsonl")
    if not roles:
        return []
    done = ctx.run(
        ["docker", "inspect", "--format", "{{.Name}}\t{{json .Mounts}}", *sorted(roles)],
        DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    findings: list[erasure_journal.Finding] = []
    seen: set[str] = set()
    for line in done.stdout.splitlines():
        container, _, raw = line.partition("\t")
        container = container.strip().lstrip("/")
        if container not in roles:
            continue
        try:
            mounts = json.loads(raw)
        except ValueError:
            continue
        seen.add(container)
        role, own = roles[container]
        findings.extend(
            erasure_journal.inspect_mounts(container, mounts, folder, role=role, own=own)
        )
    unread = sorted(set(roles) - seen)
    if unread:
        findings.append(erasure_journal.Finding(
            "mounts", WARN, f"the mounts of {', '.join(unread)} could not be read"
        ))
    return findings


def check_person_export(ctx: Context) -> CheckResult:
    """Archives of information requests (`doctor person_export`, security 1.14 no. 2b):
    `warn` while one waits for its hand-over in state/person-export/, `fail` for one
    older than 14 days (the sweep did not run) or a folder others can open; `pass`
    without any."""
    from . import person_request

    name = "person_export"
    if not ctx.configured:
        return _not_set_up(name)
    try:
        found = person_request.archives(ctx.config_dir)
    except (person_request.RequestError, OSError) as exc:
        return CheckResult(name, FAIL, str(exc))
    if not found:
        return CheckResult(name, PASS, "no archive of an information request on this host")
    ages = {rid: max(0, int((ctx.now - created).total_seconds() // 86400))
            for rid, created in found if created is not None}
    details: dict[str, Any] = {
        "archives": [{"request": rid, "age_days": ages.get(rid)} for rid, _ in found],
    }
    overdue = sorted(rid for rid, days in ages.items()
                     if days >= person_request.ARCHIVE_DAYS)
    if overdue:
        return CheckResult(
            name, FAIL,
            f"{len(overdue)} archive(s) older than {person_request.ARCHIVE_DAYS} days still "
            "on this host; run 'papaia-ctl person sweep'",
            details,
        )
    return CheckResult(
        name, WARN,
        f"{len(found)} archive(s) of an information request wait for their hand-over "
        f"(deleted after it or after {person_request.ARCHIVE_DAYS} days; 'papaia-ctl person "
        "handover <request>')",
        details,
    )


# ─── model_gateway / model_ready ─────────────────────────────────────────

# LiteLLM answers on its own port inside its container; the probe runs there with the
# container's interpreter, reads the master key from the container's environment (it never
# leaves the container) and prints one JSON line with status codes and seconds only, never
# a body. With an alias it also asks for one token of that model (BE-26 `model_ready`).
_GATEWAY_PROBE = (
    "import json,os,sys,time,urllib.error,urllib.request\n"
    "m=sys.argv[1] if len(sys.argv)>1 else ''\n"
    "o=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "h={'Authorization':'Bearer '+os.environ.get('LITELLM_MASTER_KEY',''),"
    "'Content-Type':'application/json'}\n"
    "def ask(p,b,t):\n"
    "    q=urllib.request.Request('http://127.0.0.1:4000'+p,headers=h,"
    "data=None if b is None else json.dumps(b).encode(),method='GET' if b is None else 'POST')\n"
    "    s=time.monotonic()\n"
    "    try:\n"
    "        with o.open(q,timeout=t) as r: r.read(65536); c=r.status\n"
    "    except urllib.error.HTTPError as e: c=e.code\n"
    "    except OSError: c=0\n"
    "    return c,round(time.monotonic()-s,1)\n"
    "out={'ready':ask('/health/readiness',None,10)[0]}\n"
    "if m and out['ready']==200:\n"
    "    out['model'],out['seconds']=ask('/v1/chat/completions',{'model':m,'max_tokens':1,"
    "'messages':[{'role':'user','content':'ping'}]},MODEL_TIMEOUT)\n"
    "print(json.dumps(out))\n"
)
# BE-26: one request with one token per default model, bounded at 30 s.
MODEL_READY_TIMEOUT_SECONDS = 30
GATEWAY_PROBE_TIMEOUT_SECONDS = 50.0
MODEL_ALIAS = "papaia-chat"
_ALIAS_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")


def _gateway_container(ctx: Context) -> tuple[str | None, str | None] | None:
    """(name, state) of LiteLLM's container, or None when the installation has none."""
    return _core_container(ctx, model_gateway.SERVICE)


def _gateway_probe(ctx: Context, container: str, alias: str = "") -> dict[str, Any] | None:
    """The probe's answer, validated: {"ready": int, "model"?: int, "seconds"?: float}."""
    if alias and not _ALIAS_RE.fullmatch(alias):
        raise ValueError(f"{alias!r} is not a model alias")
    script = _GATEWAY_PROBE.replace("MODEL_TIMEOUT", str(MODEL_READY_TIMEOUT_SECONDS))
    argv = ["docker", "exec", container, "python", "-I", "-c", script]
    if alias:
        argv.append(alias)
    done = ctx.run(argv, GATEWAY_PROBE_TIMEOUT_SECONDS)
    try:
        answer = json.loads(status.first_line(done.stdout)) if done.returncode == 0 else None
    except ValueError:
        return None
    if not isinstance(answer, dict) or set(answer) - {"ready", "model", "seconds"}:
        return None
    for key in ("ready", "model"):
        value = answer.get(key)
        if key in answer and (isinstance(value, bool) or not isinstance(value, int)
                              or not 0 <= value <= 599):
            return None
    seconds = answer.get("seconds")
    if "seconds" in answer and (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                                or not 0 <= seconds <= 3600):
        return None
    if "ready" not in answer:
        return None
    return answer


def check_model_gateway(ctx: Context) -> CheckResult:
    """LiteLLM runs and is ready (`doctor model_gateway`, BE-26, BE-29 no. 1): its
    container state and `GET /health/readiness` asked inside its container."""
    name = "model_gateway"
    if not ctx.configured:
        return _not_set_up(name)
    found = _gateway_container(ctx)
    if found is None:
        return CheckResult(name, SKIP, "the model gateway is not part of this installation")
    container, state = found
    details: dict[str, Any] = {"state": state or "not created"}
    if container is None or state != "running":
        return CheckResult(
            name, FAIL, f"LiteLLM is {state or 'not created'}; no module can use a model", details
        )
    probe = _gateway_probe(ctx, container)
    if probe is None:
        return CheckResult(name, FAIL, "LiteLLM does not answer inside its container", details)
    details["readiness"] = probe["ready"]
    if probe["ready"] != 200:
        code = probe["ready"] or "no answer"
        return CheckResult(name, FAIL, f"LiteLLM is not ready (readiness: {code})", details)
    return CheckResult(name, PASS, "LiteLLM running and ready", details)


def check_model_ready(ctx: Context) -> CheckResult:
    """The default model answers (`doctor model_ready`, BE-26, BE-29 no. 2): one request
    for one token through LiteLLM's alias `papaia-chat`, bounded at 30 s."""
    name = "model_ready"
    if not ctx.configured:
        return _not_set_up(name)
    found = _gateway_container(ctx)
    if found is None:
        return CheckResult(name, SKIP, "the model gateway is not part of this installation")
    container, state = found
    if container is None or state != "running":
        return CheckResult(name, SKIP, "the model gateway does not run (see model_gateway)")
    model = ctx.env.get(model_gateway.DEFAULT_MODEL_VAR, "").strip()
    if not model or common.is_placeholder(model):
        return CheckResult(name, SKIP, f"no default model ({model_gateway.DEFAULT_MODEL_VAR})")
    details: dict[str, Any] = {"alias": MODEL_ALIAS, "model": model}
    probe = _gateway_probe(ctx, container, MODEL_ALIAS)
    if probe is None:
        return CheckResult(name, FAIL, "LiteLLM does not answer inside its container", details)
    if probe["ready"] != 200:
        return CheckResult(name, SKIP, "the model gateway is not ready (see model_gateway)",
                           details)
    code, seconds = probe.get("model", 0), probe.get("seconds")
    details.update(http_status=code, seconds=seconds)
    if code == 200:
        return CheckResult(name, PASS, f"{model} answered in {seconds} s", details)
    if code == 0:
        return CheckResult(
            name, FAIL,
            f"{model} did not answer within {MODEL_READY_TIMEOUT_SECONDS} s", details,
        )
    return CheckResult(name, FAIL, f"{model} does not answer (HTTP {code})", details)


# ─── halt ────────────────────────────────────────────────────────────────


def check_halt(ctx: Context) -> CheckResult:
    """The platform's emergency halt (`doctor halt`, BE-29 no. 5): `fail` while it is set,
    because every write, send and delete of every module is stopped; also for a halt file
    that cannot be used, which every service reads as set."""
    name = "halt"
    if not ctx.configured:
        return _not_set_up(name)
    path = halt.state_path(ctx.config_dir)
    if not path.parent.is_dir():
        return CheckResult(name, SKIP, "no halt folder yet ('papaia-ctl start' creates it)")
    state = halt.read(path)
    if not state.active:
        return CheckResult(name, PASS, "no emergency halt", {"active": False})
    if state.problem:
        return CheckResult(
            name, FAIL, f"{state.problem}; every service treats the platform as halted",
            {"active": True, "problem": state.problem},
        )
    since = (
        datetime.fromtimestamp(state.since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if state.since is not None else "?"
    )
    return CheckResult(
        name, FAIL,
        f"emergency halt set by {state.by} since {since}; lift it with "
        "'papaia-ctl halt clear --reason=...'",
        {"active": True, "since": state.since, "by": state.by},
    )


# ─── realm ───────────────────────────────────────────────────────────────

# Lines `realm sync --check` prints for a deviation; more are cut off in the details.
REALM_DEVIATIONS_MAX = 50


def check_realm(ctx: Context) -> CheckResult:
    """The realm matches the declarations (`doctor realm`, BE-26 `identity` scope
    comparison, BE-29 no. 6): `realm sync --check` without a write. `fail` for every
    deviation (a missing scope assignment first of all), `warn` when the comparison could
    not run. Skipped with external OIDC, before the sync account exists, inside a container
    and while Keycloak does not run (container_health reports that)."""
    name = "realm"
    if not ctx.configured:
        return _not_set_up(name)
    from . import keycloak_role_sync as kcs
    from . import realm_sync

    root = ctx.tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        return CheckResult(name, SKIP, "external OIDC: the realm is not managed here")
    secret = (
        ctx.tree.get(kcs._KEYCLOAK_NODE, {}).get(realm_sync.SYNC_SECRET_KEY)
        or common.parse_env_file(ctx.config_dir / kcs._KEYCLOAK_NODE / ".env").get(
            realm_sync.SYNC_SECRET_KEY, "")
    )
    if not secret or common.is_placeholder(secret) or secret.startswith("GENERATE_"):
        return CheckResult(name, SKIP, "no realm sync account yet ('papaia-ctl setup')")
    if ctx.probes.in_container():
        return CheckResult(name, SKIP, "the realm is only compared on the host")
    # Only against a healthy Keycloak: the comparison waits up to 90 s for one that does
    # not answer, and container_health already reports it.
    healthy = any(
        c.service == "keycloak" and c.health == status.Health.HEALTHY
        for m in ctx.status_report().modules if m.kind == "core" for c in m.containers
    )
    if not healthy:
        return CheckResult(name, SKIP, "Keycloak is not healthy (see container_health)")
    code, output = ctx.probes.realm_check(ctx.config_dir, ctx.repo_root)
    deviations = [line.strip() for line in output.splitlines()
                  if line.strip().startswith("fail: ")]
    details: dict[str, Any] = {
        "deviations": deviations[:REALM_DEVIATIONS_MAX], "count": len(deviations),
    }
    if code == 0:
        return CheckResult(name, PASS, "the realm matches the declarations", details)
    if deviations:
        shown = "; ".join(d.removeprefix("fail: ") for d in deviations[:3])
        more = f" (+{len(deviations) - 3} more)" if len(deviations) > 3 else ""
        return CheckResult(
            name, FAIL,
            f"{len(deviations)} deviation(s) from the declarations: {shown}{more} "
            "('papaia-ctl realm sync' corrects them)",
            details,
        )
    last = status.first_line("\n".join(reversed(output.strip().splitlines())))
    if code == 2:
        return CheckResult(name, FAIL, last or "a declaration was refused", details)
    return CheckResult(name, WARN, f"the realm could not be compared: {last or 'no answer'}",
                       details)


CHECKS: list[tuple[str, Callable[[Context], CheckResult]]] = [
    ("docker_version", check_docker_version),
    ("disk_space", check_disk_space),
    ("docker_usage", check_docker_usage),
    ("memory", check_memory),
    ("cpu", check_cpu),
    ("profile_size", check_profile_size),
    ("gpu", check_gpu),
    ("localai_native", check_localai_native),
    ("ports", check_ports),
    ("direct_ports", check_direct_ports),
    ("addon_ports", check_addon_ports),
    ("dns", check_dns),
    ("time_sync", check_time_sync),
    ("certs", check_certs),
    ("smtp", check_smtp),
    ("addon_compat", check_addon_compat),
    ("container_health", check_container_health),
    ("model_gateway", check_model_gateway),
    ("model_ready", check_model_ready),
    ("modules", check_modules),
    ("revocations_age", check_revocations_age),
    ("image_signatures", check_image_signatures),
    ("lifecycle", check_lifecycle),
    ("startgate", check_startgate),
    ("state_epoch", check_state_epoch),
    ("siem", check_siem),
    ("approvals", check_approvals),
    ("halt", check_halt),
    ("contact_point", check_contact_point),
    ("network", check_network),
    ("egress", check_egress),
    ("source_protection", check_source_protection),
    ("identity", check_identity),
    ("realm", check_realm),
    ("rollback_window", check_rollback_window),
    ("person_export", check_person_export),
    ("erasure_journal", check_erasure_journal),
]

CHECK_NAMES = tuple(name for name, _ in CHECKS)

# Added by lib/cluster.py in a distributed installation only; a single host never reports
# them. Accepted by --skip everywhere, so a script can pass them unconditionally.
DISTRIBUTED_CHECK_NAMES = ("nodes", "links", "file_modes")


# ─────────────────────────────────────────────────────────────────────────
# report
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class DoctorReport:
    generated_at: str
    platform_version: str
    checks: list[CheckResult]
    # The German sentence(s) behind each failing check (lib/diagnosis.py); a failing check
    # without an entry gets the general sentence when the report is rendered.
    causes: dict[str, list[diagnosis.Cause]] = field(default_factory=dict)

    def causes_of(self, check: CheckResult) -> list[diagnosis.Cause]:
        if check.status != FAIL:
            return []
        return self.causes.get(check.name) or [diagnosis.general(check.name)]

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
            "checks": [self._check_dict(c) for c in self.checks],
            "summary": self.summary,
            "ok": self.ok,
        }


    def _check_dict(self, check: CheckResult) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": check.name, "status": check.status, "summary": check.summary,
            "details": check.details,
        }
        causes = self.causes_of(check)
        if causes:
            out["causes"] = [cause.to_dict() for cause in causes]
        return out


def parse_skip(values: Sequence[str] | None) -> list[str]:
    """Validate `--skip` names against the registry."""
    names = [v.strip() for v in values or [] if v.strip()]
    unknown = [n for n in names if n not in CHECK_NAMES + DISTRIBUTED_CHECK_NAMES]
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
    failing = [r for r in results if r.status == FAIL]
    report = None
    if failing and ctx.configured:
        try:
            report = ctx.status_report()
        except Exception:  # noqa: BLE001 - the rows above already say what is wrong
            report = None
    return DoctorReport(
        generated_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        platform_version=envtree.resolve_platform_version(repo_root),
        checks=results,
        causes=diagnosis.explain(failing, report),
    )


def format_table(report: DoctorReport) -> str:
    rows = [(c.name, c.status, c.summary) for c in report.checks]
    header = ("CHECK", "RESULT", "SUMMARY")
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(2)]
    lines = [f"papAIa {report.platform_version} - doctor", ""]
    lines.append("  ".join(header[i].ljust(widths[i]) for i in range(2)) + "  " + header[2])
    for check, row in zip(report.checks, rows, strict=True):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(2)) + "  " + row[2])
        lines.extend(diagnosis.format_lines(report.causes_of(check)))
    counts = report.summary
    lines.append("")
    lines.append(
        f"{counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail, {counts[SKIP]} skip"
    )
    return "\n".join(lines)


def to_json(report: DoctorReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
