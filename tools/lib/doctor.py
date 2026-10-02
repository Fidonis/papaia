"""Preflight and diagnostics: is this host, and this installation, in shape?

`run_checks()` evaluates an ordered registry of checks and returns a
`DoctorReport`; rendering is separate, the shape `compat.py` and `status.py`
follow. Each check answers `pass`, `warn`, `fail` or `skip` (not applicable
here: offline, not set up yet, nothing to look at). Only `fail` makes the
command exit non-zero.

Nothing here changes anything. The probes are reads: `docker version/info`,
`shutil.disk_usage`, a TCP connect to localhost, a name lookup, `openssl x509`
on a file, plus everything `status` reads.

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
import json
import re
import shutil
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import backup, cli_addon, common, compat, deployment, envtree, semver, status
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

DNS_TIMEOUT_SECONDS = 3.0
PORT_PROBE_TIMEOUT_SECONDS = 0.5
DOCKER_PROBE_TIMEOUT_SECONDS = 10.0

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


@dataclass
class Probes:
    disk_usage: Callable[[Path], tuple[int, int]] = _disk_usage
    connect: Callable[[str, int], bool] = _connect
    resolve: Callable[[str], str] = _resolve
    cert_enddate: Callable[[Path, Runner], datetime] = _cert_enddate


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
    ("ports", check_ports),
    ("dns", check_dns),
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
