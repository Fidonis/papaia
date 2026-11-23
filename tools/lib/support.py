"""Troubleshooting from the host: `logs`, `support-bundle` and `metrics` (BE-27, OPS-10).

`papaia-ctl logs <module|service>` shows the logs of every container of a module (or of
one service), core or add-on, merged in time order. Each line carries the service and the
correlation id (`X-Papaia-Correlation-Id`) when the service logged one, so one request can
be followed through every service it touched. `--follow` keeps reading.

`papaia-ctl support-bundle` writes one archive for a support case: `doctor --json`,
`status --json`, versions, the bill of materials, the configuration without secrets and
the last 1 000 log lines of every container. Before anything is written, every file is
masked (the installation's secrets, token and key patterns, mail addresses and person
identifiers) and then scanned again; a single hit stops the command and nothing is
written. The archive is the operator's (mode 0600); writing it is one `papaia.audit/1` row.

`papaia-ctl metrics` prints the platform's own measurements in the Prometheus text format
(for the textfile collector of a node exporter, or any collector that reads it): the
result of every doctor check, the days left of every certificate, the revocation age of
every module, the audit export backlog, the age of the last successful backup, the mail
queue and the status sync with an upstream directory. No label carries a person.

Every probe goes through the `status.Runner` seam (`docker logs`, `docker ps`,
`docker version`), so all of it is testable without a Docker daemon.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import backup, common, deployment, doctor, envtree, status
from . import realm_sync as rs

LOG_LINES = 1000
MAX_LOG_LINES = 10000
LOGS_TIMEOUT_SECONDS = 60.0
WRITER = "papaia-ctl/support-bundle"
BUNDLE_DIR = Path("support")
MASK = "[redacted]"

_TARGET_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
# What `docker logs --since` takes: a duration or an RFC 3339 date or time.
_SINCE_RE = re.compile(
    r"\A(?:\d{1,6}[smh]|\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?)\Z"
)
_TIMESTAMP_RE = re.compile(r"\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ?(.*)\Z", re.S)
_CORRELATION_KEYS = (
    "correlation_id", "correlationId", "X-Papaia-Correlation-Id", "x-papaia-correlation-id",
    "x_papaia_correlation_id",
)
_CORRELATION_RE = re.compile(
    r"(?i)(?:x-papaia-correlation-id|correlation[_-]?id)[\"']?\s*[=:]\s*[\"']?"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_CID_RE = re.compile(r"\A[0-9A-Za-z._:-]{1,64}\Z")


class SupportError(Exception):
    """A refused input or a bundle that would carry a secret; nothing was written."""


class LeakError(SupportError):
    """A secret, token or key pattern survived the masking; nothing was written."""


# ─── inputs ──────────────────────────────────────────────────────────────


def check_target(raw: object) -> str:
    if not isinstance(raw, str) or not _TARGET_RE.fullmatch(raw):
        raise SupportError(f"{raw!r} is not a module or service name")
    return raw


def check_since(raw: object) -> str | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str) or not _SINCE_RE.fullmatch(raw):
        raise SupportError(
            f"--since={raw!r}: give a duration (30m, 2h) or a date or time (2026-09-27, "
            "2026-09-27T10:15:00Z)"
        )
    return raw


def check_lines(raw: object) -> int:
    try:
        value = int(str(raw))
    except ValueError:
        raise SupportError(f"--lines={raw!r} is not a number") from None
    if not 1 <= value <= MAX_LOG_LINES:
        raise SupportError(f"--lines must be between 1 and {MAX_LOG_LINES}")
    return value


# ─── logs ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Source:
    project: str
    module: str
    service: str
    container: str


@dataclass(frozen=True)
class Entry:
    timestamp: str
    service: str
    correlation: str
    message: str


def sources(report: status.StatusReport) -> list[Source]:
    """Every container that exists (running or not) of the core and the add-ons."""
    return [
        Source(module.compose_project, module.name, c.service, c.name)
        for module in report.modules
        for c in module.containers
        if c.name
    ]


def _names(source: Source) -> set[str]:
    module = source.module.removeprefix("papaia-")
    return {module, f"papaia-{module}", source.service, source.project}


def resolve(report: status.StatusReport, target: str) -> list[Source]:
    """The containers of `target`: a module (`papaia-keycloak` or `keycloak`), an add-on
    (its compose project) or one service."""
    if not report.docker.reachable:
        raise SupportError(f"Docker is not reachable ({report.docker.reason})")
    found = [s for s in sources(report) if target in _names(s)]
    if not found:
        known = sorted({n for s in sources(report) for n in _names(s) if _TARGET_RE.fullmatch(n)})
        raise SupportError(
            f"no container of {target!r} on this host. Known: {', '.join(known) or '(none)'}"
        )
    return found


def correlation(message: str) -> str:
    """The correlation id a JSON log line (or a key=value line) carries, or `-`."""
    text = message.strip()
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            for key in _CORRELATION_KEYS:
                value = doc.get(key)
                if isinstance(value, str) and _CID_RE.fullmatch(value):
                    return value
    found = _CORRELATION_RE.search(text)
    return found.group(1) if found else "-"


def parse(service: str, text: str) -> list[Entry]:
    entries = []
    for line in text.splitlines():
        found = _TIMESTAMP_RE.match(line)
        if not found:
            continue
        stamp, message = found.groups()
        entries.append(Entry(stamp, service, correlation(message), message))
    return entries


def _since_args(since: str | None) -> list[str]:
    return ["--since", since] if since else []


def collect(
    run: status.Runner, found: Sequence[Source], *, since: str | None, lines: int
) -> list[Entry]:
    """The last `lines` lines of each container, merged in time order (both streams)."""
    entries: list[Entry] = []
    for source in found:
        done = run(
            ["docker", "logs", "--timestamps", "--tail", str(lines), *_since_args(since),
             source.container],
            LOGS_TIMEOUT_SECONDS,
        )
        entries += parse(source.service, (done.stdout or "") + "\n" + (done.stderr or ""))
    # RFC 3339 with a fixed `Z` sorts as text once the fraction has one length.
    return sorted(entries, key=lambda e: _sort_key(e.timestamp))


def _sort_key(stamp: str) -> str:
    head, _, fraction = stamp.rstrip("Z").partition(".")
    return f"{head}.{fraction.ljust(9, '0')[:9]}"


def format_entries(entries: Iterable[Entry]) -> list[str]:
    items = list(entries)
    width = max((len(e.service) for e in items), default=0)
    return [f"{e.timestamp} {e.service.ljust(width)} {e.correlation} {e.message}" for e in items]


def follow(found: Sequence[Source], *, since: str | None, out=None) -> int:
    """`docker logs --follow` of every container at once; lines are printed as they come,
    which is time order. Ends with Ctrl-C or when every container's log ends."""
    out = out or sys.stdout
    lock = threading.Lock()
    width = max(len(s.service) for s in found)
    procs: list[subprocess.Popen] = []

    def pump(source: Source, stream) -> None:
        for raw in iter(stream.readline, ""):
            for entry in parse(source.service, raw):
                with lock:
                    out.write(f"{entry.timestamp} {entry.service.ljust(width)} "
                              f"{entry.correlation} {entry.message}\n")
                    out.flush()

    threads = []
    try:
        for source in found:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, validated container names
                ["docker", "logs", "--follow", "--timestamps", "--tail", "0",
                 *_since_args(since), source.container],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            procs.append(proc)
            thread = threading.Thread(target=pump, args=(source, proc.stdout), daemon=True)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
    return 0


# ─── masking ─────────────────────────────────────────────────────────────

# Keys whose values are secrets, in .env files and in key=value log lines.
_SECRET_KEY = re.compile(
    r"(?i)(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|private|credential|salt|"
    r"cookie|signing|master[_-]?key|_key$|^key$|dsn|smtp_pw)"
)
# Values that are safe to show in the configuration listing.
_SAFE_KEY = re.compile(
    r"(?i)(?:^COMPOSE_PROFILES$|^COMPOSE_PROJECT_NAME$|_HOST$|_URL$|_PORT$|_VARIANT$|"
    r"_RUNTIME$|_PROVIDER$|_VERSION$|_MODE$|_PROFILE$|_ENABLED$|^HOST_IP$|^TZ$|_MODEL$)"
)
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
        re.S)),
    ("age key", re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("api key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("mail address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)
# key=value and "key": "value" pairs whose key names a secret or a person.
_PAIR = re.compile(
    r"(?i)(?P<key>[\"']?[\w.-]*(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret|"
    r"authorization|cookie|preferred_username|given_name|family_name|\bsub|\bemail|"
    r"\busername)[\w.-]*[\"']?\s*[=:]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
)
# Long random strings: hex (not an image digest) and base64-like without slashes.
_RANDOM = re.compile(
    r"(?<!sha256:)\b[A-Fa-f0-9]{40,}\b|\b(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])"
    r"[A-Za-z0-9+_-]{40,}={0,2}"
)
_MIN_SECRET = 8


def installation_secrets(config_dir: Path, repo_root: Path) -> list[str]:
    """Every secret value of the installation: values of secret-named keys in every .env
    of the configuration tree, every long value, and small single-value secret files."""
    found: set[str] = set()
    for values in env_files(config_dir).values():
        for key, value in values.items():
            value = (value or "").strip().strip("'\"")
            if len(value) < _MIN_SECRET or common.is_placeholder(value):
                continue
            if _SECRET_KEY.search(key) or (len(value) >= 24 and not _SAFE_KEY.search(key)
                                           and " " not in value and "/" not in value):
                found.add(value)
    for path in _secret_files(config_dir):
        try:
            text = path.read_text("utf-8").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) >= _MIN_SECRET and "\n" not in text:
            found.add(text)
    return sorted(found, key=len, reverse=True)


def env_files(config_dir: Path) -> dict[str, dict[str, str]]:
    """{path relative to the configuration directory: values} of every .env file below
    it, also of modules the shipped seed does not know (add-ons, overlays)."""
    out: dict[str, dict[str, str]] = {}
    for path in sorted({*config_dir.rglob(".env"), *config_dir.rglob("*.env")}):
        if path.is_file() and not path.is_symlink():
            out[path.relative_to(config_dir).as_posix()] = common.parse_env_file(path)
    return out


def _secret_files(config_dir: Path) -> list[Path]:
    names = re.compile(r"(?i)(?:password|passwd|secret|token|\.key$|credential)")
    out = []
    for path in sorted(config_dir.rglob("*")):
        try:
            if path.is_file() and not path.is_symlink() and names.search(path.name) \
                    and path.stat().st_size <= 4096:
                out.append(path)
        except OSError:
            continue
    return out


def mask(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, MASK)
    for _, pattern in _PATTERNS:
        text = pattern.sub(MASK, text)
    text = _PAIR.sub(lambda m: m.group("key") + MASK, text)
    return _RANDOM.sub(MASK, text)


def scan(text: str, secrets: Sequence[str]) -> list[str]:
    """What is still in `text`: the kinds of every hit, never the value."""
    hits = [f"secret of the installation ({len(s)} characters)" for s in secrets if s in text]
    hits += [kind for kind, pattern in _PATTERNS if pattern.search(text)]
    return hits


# ─── support bundle ──────────────────────────────────────────────────────


def _config_listing(config_dir: Path, repo_root: Path) -> str:
    """Every key of every .env in the configuration tree; a value only for keys that
    hold no secret by name (host names, ports, profiles, variants)."""
    tree = env_files(config_dir)
    lines = []
    for rel in sorted(tree):
        lines.append(f"[{rel}]")
        for key in sorted(tree[rel]):
            value = tree[rel][key] or ""
            if not value:
                shown = "(empty)"
            elif _SAFE_KEY.search(key) and not _SECRET_KEY.search(key):
                shown = value
            else:
                shown = "(set)"
            lines.append(f"{key}={shown}")
    deployed = deployment.load(config_dir) or {}
    lines.append("")
    lines.append("[deployment.yaml]")
    lines.append(yaml.safe_dump(
        {
            "platform_version": deployed.get("platform_version"),
            "core": deployed.get("core"),
            "addons": [
                {"name": a.get("name"), "version": a.get("version"), "active": a.get("active")}
                for a in deployed.get("addons") or []
            ],
        },
        sort_keys=False,
    ))
    return "\n".join(lines) + "\n"


def _versions(run: status.Runner, repo_root: Path, config_dir: Path) -> dict[str, Any]:
    def first(argv: list[str]) -> str | None:
        done = run(argv, 15.0)
        return status.first_line(done.stdout) or None if done.returncode == 0 else None

    images = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}"], 30.0)
    containers = {}
    for line in (images.stdout or "").splitlines() if images.returncode == 0 else []:
        name, _, image = line.partition("\t")
        if name:
            containers[name] = image
    deployed = deployment.load(config_dir) or {}
    return {
        "platform_version": envtree.resolve_platform_version(repo_root),
        "docker": first(["docker", "version", "--format", "{{.Server.Version}}"]),
        "compose": first(["docker", "compose", "version", "--short"]),
        "addons": {
            str(a.get("name")): a.get("version") for a in deployed.get("addons") or []
            if a.get("name")
        },
        "containers": containers,
    }


def _bill_of_materials(repo_root: Path) -> str:
    path = repo_root / "compat" / "suite.yaml"
    try:
        return path.read_text("utf-8")
    except OSError:
        return "# no bill of materials in this checkout\n"


def build(
    config_dir: Path,
    repo_root: Path,
    *,
    run: status.Runner,
    lines: int = LOG_LINES,
    doctor_report: doctor.DoctorReport | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """{name in the archive: masked text}; raises SupportError when a scan still finds a
    secret after masking."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report = status.collect(config_dir, repo_root, include_addons=True, run=run, now=moment)
    checked = doctor_report or doctor.run_checks(config_dir, repo_root, run=run, now=moment)
    files: dict[str, str] = {
        "doctor.json": doctor.to_json(checked) + "\n",
        "status.json": status.to_json(report) + "\n",
        "versions.json": json.dumps(_versions(run, repo_root, config_dir), indent=2) + "\n",
        "bom.yaml": _bill_of_materials(repo_root),
        "config.txt": _config_listing(config_dir, repo_root),
    }
    if report.docker.reachable:
        for source in sources(report):
            done = run(["docker", "logs", "--timestamps", "--tail", str(lines), source.container],
                       LOGS_TIMEOUT_SECONDS)
            text = (done.stdout or "") + (done.stderr or "")
            files[f"logs/{source.project}/{source.service}.log"] = text
    secrets = installation_secrets(config_dir, repo_root)
    masked = {name: mask(text, secrets) for name, text in files.items()}
    leaks = {name: hits for name, text in masked.items() if (hits := scan(text, secrets))}
    if leaks:
        shown = "; ".join(f"{n}: {', '.join(sorted(set(h)))}" for n, h in sorted(leaks.items()))
        raise LeakError(f"the bundle would still hold secrets ({shown}); nothing was written")
    return masked


def archive(files: dict[str, str], *, stamp: datetime) -> bytes:
    buffer = io.BytesIO()
    root = f"papaia-support-{stamp.strftime('%Y%m%dT%H%M%SZ')}"
    mtime = int(stamp.timestamp())
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size, info.mode, info.mtime = len(data), 0o600, mtime
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def default_out(config_dir: Path, stamp: datetime) -> Path:
    return config_dir / BUNDLE_DIR / f"papaia-support-{stamp.strftime('%Y%m%dT%H%M%SZ')}.tar.gz"


def check_out(raw: str | None, config_dir: Path, stamp: datetime) -> Path:
    if not raw:
        return default_out(config_dir, stamp)
    if "\x00" in raw or len(raw) > 4096:
        raise SupportError("--out is not a usable path")
    path = Path(raw).expanduser()
    if not path.name.endswith(".tar.gz"):
        raise SupportError("--out must name a .tar.gz file")
    if not path.parent.is_dir():
        raise SupportError(f"--out: the folder {path.parent} does not exist")
    return path


def write_private(path: Path, data: bytes) -> None:
    """Create `path` with mode 0600; never replaces an existing file."""
    if path.parent == path.parent.parent:
        raise SupportError("--out is not a usable path")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise SupportError(f"{path} exists already; nothing was written") from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _audit_row(config_dir: Path, correlation_id: str, name: str, result: str,
               error_code: str | None) -> None:
    with rs.AuditLog(rs.audit_path(config_dir), correlation_id, writer=WRITER) as audit:
        audit.write(
            rs.Change("support-bundle", name, "written", "write", event="operation"),
            result, error_code, host=True,
        )


def bundle(
    config_dir: Path,
    repo_root: Path,
    *,
    out: str | None = None,
    lines: int = LOG_LINES,
    run: status.Runner | None = None,
    now: datetime | None = None,
    doctor_report: doctor.DoctorReport | None = None,
) -> tuple[Path, str]:
    """Build, check and write the bundle; (path, correlation id). One audit row either
    way: `allowed` for a written bundle, `error` when the scan stopped it."""
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    path = check_out(out, config_dir, stamp)
    correlation_id = rs.new_correlation_id()
    try:
        files = build(config_dir, repo_root, run=run or status.run_command, lines=lines,
                      now=stamp, doctor_report=doctor_report)
    except LeakError:
        _audit_row(config_dir, correlation_id, path.name, "error", "secret_found")
        raise
    write_private(path, archive(files, stamp=stamp))
    _audit_row(config_dir, correlation_id, path.name, "allowed", None)
    return path, correlation_id


# ─── metrics ─────────────────────────────────────────────────────────────

_STATUS_VALUE = {doctor.PASS: 0, doctor.WARN: 1, doctor.FAIL: 2}
_LABEL_RE = re.compile(r"[^A-Za-z0-9._/:-]")


def _label(value: object) -> str:
    return _LABEL_RE.sub("_", str(value))[:128]


def _backup_age(config_dir: Path, now: datetime) -> float | None:
    raw = common.parse_env_file(config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if not raw or common.is_placeholder(raw):
        return None
    try:
        index = backup.load_index(Path(raw).expanduser())
    except (backup.BackupError, OSError):
        return None
    stamps = [backup._parse_ts(str(b.get("created_at", ""))) for b in index.get("backups") or []
              if b.get("result") == "ok"]
    stamps = [s for s in stamps if s is not None]
    return max(0.0, (now - max(stamps)).total_seconds()) if stamps else None


def metrics(report: doctor.DoctorReport, config_dir: Path, now: datetime) -> str:
    """The Prometheus text exposition of a doctor run plus the backup age."""
    families: dict[str, tuple[str, list[str]]] = {}

    def add(name: str, help_text: str, value: float | int | None, **labels: object) -> None:
        if value is None or isinstance(value, bool):
            return
        family = families.setdefault(name, (help_text, []))
        shown = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
        family[1].append(f"{name}{{{shown}}} {value}" if shown else f"{name} {value}")

    for check in report.checks:
        add("papaia_check_status", "doctor result per check: 0 pass, 1 warn, 2 fail",
            _STATUS_VALUE.get(check.status), check=check.name)
        details = check.details if isinstance(check.details, dict) else {}
        if check.name == "certs":
            for item in details.get("certificates") or []:
                add("papaia_certificate_days_left", "days until the certificate expires",
                    item.get("days_left"), file=item.get("path"))
        elif check.name == "revocations_age":
            for item in details.get("modules") or []:
                add("papaia_module_revocations_age_seconds",
                    "age of the revocation list a module holds",
                    item.get("revocations_age_seconds"), module=item.get("module"))
        elif check.name == "siem":
            for target in details.get("targets") or []:
                labels = {"target": target.get("target")}
                add("papaia_audit_export_backlog", "audit events not yet delivered",
                    target.get("backlog"), **labels)
                add("papaia_audit_export_lag_seconds", "age of the oldest undelivered event",
                    target.get("lag_seconds"), **labels)
        elif check.name == "smtp":
            add("papaia_smtp_queue_messages", "messages waiting in the mail relay",
                details.get("queued"))
        elif check.name == "identity":
            add("papaia_status_sync_age_seconds", "age of the last status sync with the "
                "upstream directory", details.get("status_sync_age_seconds"))
        elif check.name == "model_ready":
            add("papaia_model_ready_seconds", "seconds the default model took for one token",
                details.get("seconds"))
    add("papaia_backup_last_ok_age_seconds", "age of the last successful restore point",
        _backup_age(config_dir, now))
    add("papaia_metrics_generated_timestamp_seconds", "when these values were read",
        int(now.timestamp()))
    lines = []
    for name, (help_text, samples) in families.items():
        lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", *samples]
    return "\n".join(lines) + "\n"


def write_metrics(path_raw: str, text: str) -> Path:
    """Replace `path` atomically (the textfile collector must never read half a file)."""
    path = Path(path_raw).expanduser()
    if not path.name.endswith(".prom") or not path.parent.is_dir():
        raise SupportError("--out must name a .prom file in an existing folder")
    common.atomic_write(path, text)
    return path


def now_utc() -> datetime:
    return datetime.fromtimestamp(time.time(), timezone.utc)
