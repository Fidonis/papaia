"""Requests for information and erasure of a person without an account (security 1.14
no. 2b): `papaia-ctl person find|export|erase|status|run|handover|sweep`.

The flow, with two persons (docs/person-requests.md):

1. `person find --name=…|--email=…` hashes the input with the installation key
   `security/erasure-hmac` and asks papaia-lifecycle (`docker exec … lifecycle.py find`)
   for the persons with that HMAC in its name index or among its tombstones: deactivated
   and deleted accounts too. It shows `sub`, state, day of the last sign-in and day of the
   deletion; never a name, never content.
2. `person export|erase --sub=… --requested-by=SUB --confirmed-by=SUB` files a request in
   papaia-audit and prints its id. Nothing runs.
3. The person named by `--confirmed-by` confirms it in the manager after a fresh sign-in;
   for an export the manager shows her the passphrase of the archive, once.
4. `person run <id>` runs the confirmed request (lib/person.py). An export is written to
   `state/person-export/<id>.zip.age` (folder 0700, file 0600, never in a backup),
   encrypted to the passphrase with the key the confirmation derived from it; the host
   never sees the passphrase.
5. `person handover <id>` deletes the archive after it was handed over; `person sweep`
   (also at the start of every other `person` command) deletes every archive older than
   14 days. `doctor person_export` warns while an archive exists.

papaia-audit is reached through `docker exec` of `python -m papaia_audit person`, the
request on stdin (`service_gate`); papaia-lifecycle through `docker
exec` of its `find` command with the two HMACs as arguments. A command line switch never
confirms anything.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import access_report, audit, status
from . import realm_sync as rs

ARCHIVE_DIR = Path("state") / "person-export"
ARCHIVE_SUFFIX = ".zip.age"
RECORD_SUFFIX = ".json"
RECORD_FORMAT = "papaia.person-export/1"
ARCHIVE_DAYS = 14
ARCHIVE_LIFETIME = timedelta(days=ARCHIVE_DAYS)
WRITER = "papaia-ctl/person"
CATALOG_ID = "core.person"
LIFECYCLE_SERVICE = "papaia-lifecycle"
LIFECYCLE_KEY_DIR = "/var/lib/papaia-lifecycle"
FIND_TIMEOUT_SECONDS = 30.0
MAX_NAME = 320

# German labels of the states for the operator (betrieb BE-30, sicherheit 1.14 no. 2).
STATE_LABELS = {
    "open": "offen (wartet auf Bestätigung)",
    "confirmed": "bestätigt (bereit für person run)",
    "rejected": "abgelehnt",
    "running": "läuft",
    "done": "erledigt",
    "partial": "teilweise",
    "expired": "abgelaufen",
}

_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_REF_RE = re.compile(r"[0-9a-f]{64}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# gate(path, body) -> (HTTP status, answer document)
Gate = Callable[[str, dict], "tuple[int, dict]"]


class RequestError(ValueError):
    """Input or an answer the command cannot act on; the message says why."""


@dataclass(frozen=True)
class ArchiveKey:
    """What the confirmation derived from the passphrase: an age scrypt stanza's salt,
    work factor and key. Enough to encrypt the archive, not to know the passphrase."""

    salt: bytes
    log_n: int
    key: bytes


def service_gate(config_dir: Path) -> Gate:
    """The person routes of the running papaia-audit, through `docker exec`
    (`python -m papaia_audit person`): the request goes on stdin without a token; the
    answer is one JSON object {"status", "body"}."""

    def call(path: str, body: dict) -> tuple[int, dict]:
        try:
            container = audit.find_container(config_dir)
        except audit.AuditError as exc:
            raise RequestError(str(exc)) from None
        argv = ["docker", "exec", "-i", container, "python3", "-I", "-m", "papaia_audit", "person"]
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                input=json.dumps({"path": path, "body": body}),
                text=True,
                capture_output=True,
                timeout=access_report.EXEC_TIMEOUT_SECONDS,
                check=False,
            )
            answer = json.loads(done.stdout) if done.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            answer = None
        if not isinstance(answer, dict) or type(answer.get("status")) is not int:
            raise RequestError("papaia-audit did not answer; is the stack running?")
        body_out = answer.get("body")
        return answer["status"], body_out if isinstance(body_out, dict) else {}

    return call


def check_request_id(value: object) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise RequestError("the request id is the UUID that `person export|erase` printed")
    return value


def _answer(status_code: int, body: dict, expected: int = 200) -> dict:
    if status_code == expected:
        return body
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    code = body.get("code") if isinstance(body.get("code"), str) else f"HTTP {status_code}"
    raise RequestError(f"refused by papaia-audit ({status_code}, {code}). {message}".strip())


def _view(body: dict) -> dict:
    required = {"id", "operation", "state", "person", "requested_by", "confirmed_by"}
    if not required <= set(body) or not _ID_RE.fullmatch(str(body["id"])):
        raise RequestError("papaia-audit answered something that is not a request")
    return body


# ── requests ─────────────────────────────────────────────────────────────────


def create(gate: Gate, *, operation: str, sub: str, requested_by: str, confirmed_by: str,
           transfer_to: str | None = None) -> dict:
    """File a request; nothing runs. The checks of the persons are the service's."""
    if operation not in ("export", "erase"):
        raise RequestError("the operation is export or erase")
    if requested_by == confirmed_by:
        raise RequestError(
            "--confirmed-by must name a second person: the requesting person never confirms"
        )
    return _view(_answer(*gate("/v1/person-requests", {
        "operation": operation, "person": sub, "requested_by": requested_by,
        "confirmed_by": confirmed_by, "transfer_to": transfer_to,
    }), expected=201))


def get(gate: Gate, request_id: str) -> dict:
    return _view(_answer(*gate(f"/v1/person-requests/{check_request_id(request_id)}", {})))


def start(gate: Gate, request_id: str) -> dict:
    """confirmed -> running; refused before the confirmation or a day after it."""
    return _view(_answer(*gate(f"/v1/person-requests/{check_request_id(request_id)}/start",
                               {})))


def take_key(gate: Gate, request_id: str) -> ArchiveKey:
    body = _answer(*gate(f"/v1/person-requests/{check_request_id(request_id)}/key", {}))
    try:
        salt = base64.b64decode(body["salt"], validate=True)
        key = base64.b64decode(body["key"], validate=True)
        log_n = body["log_n"]
    except (KeyError, TypeError, ValueError):
        raise RequestError("papaia-audit answered no archive key") from None
    if len(salt) != 16 or len(key) != 32 or type(log_n) is not int or not 10 <= log_n <= 20:
        raise RequestError("papaia-audit answered no archive key")
    return ArchiveKey(salt, log_n, key)


def finish(gate: Gate, request_id: str, result: str) -> dict:
    return _view(_answer(*gate(f"/v1/person-requests/{check_request_id(request_id)}/finish",
                               {"result": result})))


def render_request(view: dict) -> str:
    """The operator's view of a request: ids and states, never content."""
    label = STATE_LABELS.get(view["state"], view["state"])
    lines = [
        f"request {view['id']}: person {view['operation']} {view['person']}",
        f"  state         {view['state']} ({label})",
        f"  requested by  {view['requested_by']} at {view.get('requested_at')}",
        f"  confirmed by  {view['confirmed_by']}"
        + (f" (decided {view['decided_at']})" if view.get("decided_at") else ""),
    ]
    if view.get("transfer_to"):
        lines.append(f"  transfer to   {view['transfer_to']}")
    return "\n".join(lines) + "\n"


# ── find ─────────────────────────────────────────────────────────────────────


def _hmac_key(config_dir: Path, repo_root: Path) -> tuple[bytes, object]:
    from . import model_gateway

    lc = model_gateway._lifecycle_module(repo_root)
    path = Path(config_dir) / "security" / "erasure-hmac"
    try:
        return lc.read_erasure_key(path), lc
    except (OSError, lc.LifecycleError) as exc:
        raise RequestError(
            f"the installation key {path} cannot be read ({exc}); person find needs it"
        ) from None


def refs(config_dir: Path, repo_root: Path, *, name: str | None,
         email: str | None) -> tuple[str | None, str | None]:
    """The HMACs papaia-lifecycle keeps instead of the user name and mail."""
    if (name is None) == (email is None):
        raise RequestError("person find needs exactly one of --name and --email")
    value = name if name is not None else email
    if not value or len(value) > MAX_NAME or _CONTROL_RE.search(value):
        raise RequestError("--name and --email take 1 to 320 printable characters")
    if email is not None and "@" not in email:
        raise RequestError("--email must be a mail address")
    key, lc = _hmac_key(config_dir, repo_root)
    ref = lc.name_ref(key, value)
    if ref is None:
        raise RequestError("--name and --email take 1 to 320 printable characters")
    return (ref, None) if name is not None else (None, ref)


def _lifecycle_container(config_dir: Path) -> str:
    project = status.compose_project(config_dir)
    done = status.run_command(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
         "--filter", f"label=com.docker.compose.service={LIFECYCLE_SERVICE}",
         "--filter", "status=running", "--format", "{{.Names}}"],
        status.DOCKER_TIMEOUT_SECONDS,
    )
    names = [line.strip() for line in done.stdout.splitlines() if line.strip()]
    if done.returncode != 0 or not names:
        raise RequestError(
            "papaia-lifecycle is not running (profile lifecycle); person find reads its "
            "name index and tombstones"
        )
    return names[0]


def lookup(config_dir: Path, name_ref: str | None, mail_ref: str | None) -> list[dict]:
    """The answer of papaia-lifecycle's `find` for the two HMACs."""
    argv = ["docker", "exec", _lifecycle_container(config_dir), "python3", "-I",
            "/opt/papaia-lifecycle/lifecycle.py", "find", f"--key-dir={LIFECYCLE_KEY_DIR}"]
    if name_ref:
        argv.append(f"--name-ref={name_ref}")
    if mail_ref:
        argv.append(f"--mail-ref={mail_ref}")
    done = status.run_command(argv, FIND_TIMEOUT_SECONDS)
    try:
        persons = json.loads(status.first_line(done.stdout))["persons"]
        if done.returncode != 0 or not isinstance(persons, list):
            raise ValueError
        return [_person(p) for p in persons]
    except (ValueError, TypeError, KeyError):
        raise RequestError("papaia-lifecycle did not answer the search") from None


def _person(item: object) -> dict:
    if not isinstance(item, dict) or set(item) != {"sub", "status", "last_login", "deleted"}:
        raise ValueError("person")
    if item["status"] not in ("active", "disabled", "deleted", "unknown"):
        raise ValueError("status")
    return item


def find(config_dir: Path, repo_root: Path, *, name: str | None, email: str | None,
         search: Callable[[Path, str | None, str | None], list[dict]] = lookup) -> list[dict]:
    """`person find`: the persons, one audit row with their number (never the input)."""
    name_ref, mail_ref = refs(config_dir, repo_root, name=name, email=email)
    persons = search(config_dir, name_ref, mail_ref)
    with _log(config_dir, rs.new_correlation_id()) as log:
        _record(log, operation="person.find", effect="read", object_ref=None,
                detail={"count": len(persons)})
    return persons


def render_find(persons: list[dict]) -> str:
    if not persons:
        return "no person found (also no deactivated or deleted account)\n"
    lines = [f"{'sub':<40} {'status':<9} {'last sign-in':<12} deleted"]
    for p in persons:
        lines.append(f"{p['sub']:<40} {p['status']:<9} {p['last_login'] or '-':<12} "
                     f"{p['deleted'] or '-'}")
    return "\n".join(lines) + "\n"


# ── archive folder ───────────────────────────────────────────────────────────


def _log(config_dir: Path, correlation: str) -> rs.AuditLog:
    try:
        return rs.AuditLog(rs.audit_path(config_dir), correlation, writer=WRITER)
    except (OSError, rs.RealmSyncError) as exc:
        raise RequestError(f"the audit outbox cannot be written: {exc}") from None


def _record(log: rs.AuditLog, *, operation: str, effect: str, object_ref: dict | None,
            detail: dict | None) -> None:
    log.append({
        "role": "caller", "sub": log.host_account, "identity_kind": "person",
        "service_account": None, "azp": "papaia-ctl", "aud": None, "origin_azp": None,
        "origin_source": None, "origin_asserted_by": None, "context": None,
        "catalog_id": CATALOG_ID, "operation": operation, "effect": effect,
        "object_ref": object_ref, "data_class": None, "result": "allowed",
        "error_code": None, "client_ip": None, "detail": detail, "event": "operation",
    })


def archive_dir(config_dir: Path, *, create: bool = False) -> Path:
    """`state/person-export/`, a folder only this account opens (0700)."""
    folder = Path(config_dir) / ARCHIVE_DIR
    if create:
        folder.parent.mkdir(parents=True, exist_ok=True)
        try:
            folder.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        info = os.lstat(folder)
    except FileNotFoundError:
        if create:
            raise
        return folder
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RequestError(f"{folder} must be a folder only this account can open (mode 0700)")
    return folder


def archive_path(config_dir: Path, request_id: str) -> Path:
    return archive_dir(config_dir) / f"{check_request_id(request_id)}{ARCHIVE_SUFFIX}"


def record_archive(config_dir: Path, request_id: str, now: datetime) -> None:
    """The business time of the archive, which the 14 days count from."""
    path = archive_dir(config_dir) / f"{check_request_id(request_id)}{RECORD_SUFFIX}"
    data = json.dumps({
        "format": RECORD_FORMAT, "request": request_id,
        "created_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
    }).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def archives(config_dir: Path) -> list[tuple[str, datetime | None]]:
    """(request id, creation time) of every archive in the folder; None when its record
    is missing or unreadable (then the file time counts)."""
    folder = archive_dir(config_dir)
    if not folder.is_dir():
        return []
    found: list[tuple[str, datetime | None]] = []
    for path in sorted(folder.glob(f"*{ARCHIVE_SUFFIX}")):
        request_id = path.name[: -len(ARCHIVE_SUFFIX)]
        if not _ID_RE.fullmatch(request_id):
            continue
        created: datetime | None
        try:
            record = json.loads((folder / f"{request_id}{RECORD_SUFFIX}").read_bytes())
            created = datetime.fromisoformat(record["created_at"])
            if record.get("request") != request_id or created.tzinfo is None:
                raise ValueError
        except (OSError, ValueError, TypeError, KeyError):
            created = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        found.append((request_id, created))
    return found


def _remove(config_dir: Path, request_id: str, operation: str) -> bool:
    folder = archive_dir(config_dir)
    archive = folder / f"{request_id}{ARCHIVE_SUFFIX}"
    existed = archive.exists()
    archive.unlink(missing_ok=True)
    (folder / f"{request_id}{RECORD_SUFFIX}").unlink(missing_ok=True)
    if existed:
        with _log(config_dir, request_id) as log:
            _record(log, operation=operation, effect="delete",
                    object_ref={"type": "person_request", "id": request_id}, detail=None)
    return existed


def handover(config_dir: Path, request_id: str) -> bool:
    """The archive was handed over: it goes now. False when there was none."""
    return _remove(config_dir, check_request_id(request_id), "person.export_handed_over")


def sweep(config_dir: Path, now: datetime | None = None) -> list[str]:
    """Delete every archive 14 days after it was written; returns their request ids."""
    now = now or datetime.now(timezone.utc)
    gone = []
    for request_id, created in archives(config_dir):
        if created is not None and now - created >= ARCHIVE_LIFETIME:
            _remove(config_dir, request_id, "person.export_expired")
            gone.append(request_id)
    return gone
