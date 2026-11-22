"""`papaia-ctl report permissions`: the permission report by person or by system, and the
recertification of its rows (security 1.16, OPS-19).

The report is built from the `papaia` realm (read with the master admin; reads only),
the confirmed exchange-right pairings (`security/pairings.yaml`), the declared service
accounts and the delegation lifetime in effect:

- by person: realm roles, roles of the module clients, groups, the service accounts the
  person owns or deputises, the stored delegations (offline sessions) per module client,
  whether the person holds two of the separated platform roles (`papaia-admin`,
  `papaia-auditor`, `papaia-operator`), and whether it is the emergency account;
- by system (catalog entry / audience): the clients with an exchange right and its
  effects, who asked for and who confirmed it, and the service accounts with that
  audience. Rights inside the target system are kept there ("im Zielsystem geführt").

No content, no secret and no credential is read into the report. Rows are sorted, each
carries the digest of its content, and the report carries a checksum over the sorted
content and the session limits: two reports of the same realm are equal, and a change
of one person changes only that person's row.

Released only by papaia-audit: before anything is printed, `POST /v1/access-reports`
with the person's token (role `papaia-auditor`, a person token for the audience
`papaia-audit`), the kind, the number of rows and the checksum. papaia-audit records every
retrieval, also a refused one, and answers with the latest confirmation of every row.
A row whose last confirmation is missing, older than the recertification period
(`PAPAIA_RECERTIFICATION_DAYS`, default 180, 30 to 730) or for another content than the
current one is marked `confirmation_due`. `papaia-ctl report confirm` records a
confirmation (role `papaia-admin`, never for one's own row) the same way.

The token is read from a file or stdin (`--token-file=PATH|-`), never from the command
line, and never printed. The call to papaia-audit runs inside its container
(`docker exec`), like `audit verify`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TextIO

from . import audit
from . import realm_sync as rs

FORMAT = "papaia.access-report/1"
KINDS = ("person", "system")
FORMATS = ("json", "csv")
PERIOD_KEY = "PAPAIA_RECERTIFICATION_DAYS"
PERIOD_DEFAULT, PERIOD_MIN, PERIOD_MAX = 180, 30, 730
SEPARATED_ROLES = ("papaia-admin", "papaia-auditor", "papaia-operator")
TARGET_RIGHTS = "im Zielsystem geführt"
REPORT_PATH = "/v1/access-reports"
CONFIRM_PATH = "/v1/access-reports/confirmations"
MAX_TOKEN_BYTES = 8192
PAGE = 100
EXEC_TIMEOUT_SECONDS = 60.0
# Exit status of a refused release (401/403): the report is not shown.
REFUSED = 3

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Same names as papaia-audit accepts: valid object_ref ids of the audit schema (no '|').
_KEY_RE = re.compile(r"^(person|system):[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}$")
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_PERIOD_RE = re.compile(r"^[0-9]{1,4}$")
# Spreadsheet programs run a cell that starts with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

Gate = Callable[[str, str, dict], tuple[int, dict]]


class ReportError(Exception):
    """The report cannot be built or released; the message says why (no token)."""


class AuditUnavailable(ReportError):
    """papaia-audit is not running or did not answer (exit status 1, not invalid input)."""


@dataclass
class Snapshot:
    persons: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    pairings: list[rs.Pairing] = field(default_factory=list)
    sessions: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────
# collecting
# ─────────────────────────────────────────────────────────────────────────


def _names(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    return sorted(
        {i["name"] for i in items if isinstance(i, dict) and isinstance(i.get("name"), str)}
    )


def _users(call) -> Iterable[dict]:
    first = 0
    while True:
        page = call("GET", f"/users?first={first}&max={PAGE}&briefRepresentation=false") or []
        yield from (u for u in page if isinstance(u, dict))
        if len(page) < PAGE:
            return
        first += PAGE


def _module_clients(call) -> list[tuple[str, str]]:
    """(uuid, clientId) of the managed clients persons sign in to (delegations live there)."""
    found = []
    for client in call("GET", "/clients") or []:
        attributes = client.get("attributes") or {}
        if attributes.get(rs.MANAGED) != "true" or attributes.get(rs.KIND) == rs.SERVICE_ACCOUNT:
            continue
        if _ID_RE.match(str(client.get("id", ""))) and isinstance(client.get("clientId"), str):
            found.append((client["id"], client["clientId"]))
    return sorted(found, key=lambda c: c[1])


def _person(
    call, user: dict, clients: list[tuple[str, str]], breakglass_ids: frozenset[str]
) -> dict:
    uid = user["id"]
    mappings = call("GET", f"/users/{uid}/role-mappings") or {}
    module_roles = {}
    for client, entry in sorted((mappings.get("clientMappings") or {}).items()):
        names = _names((entry or {}).get("mappings"))
        if names:
            module_roles[client] = names
    effective = _names(call("GET", f"/users/{uid}/role-mappings/realm/composite"))
    groups = sorted(
        g["path"]
        for g in call("GET", f"/users/{uid}/groups") or []
        if isinstance(g, dict) and isinstance(g.get("path"), str)
    )
    delegations = {}
    for client_uuid, client_id in clients:
        sessions = call("GET", f"/users/{uid}/offline-sessions/{client_uuid}") or []
        if sessions:
            delegations[client_id] = len(sessions)
    return {
        "sub": uid,
        "username": str(user.get("username", "")),
        "enabled": user.get("enabled") is True,
        "realm_roles": _names(mappings.get("realmMappings")),
        "effective_realm_roles": effective,
        "module_roles": module_roles,
        "groups": groups,
        "delegations": delegations,
        # By the id papaia-ctl recorded (lib/breakglass.py), never by name or attribute.
        "breakglass": uid in breakglass_ids,
    }


def collect(
    call,
    *,
    service_accounts: list[dict],
    pairings: list[rs.Pairing],
    delegations: dict,
    breakglass_ids: frozenset[str],
) -> Snapshot:
    """The report's inputs; `call` is the Admin API of the `papaia` realm (GET only)."""
    from . import realm_hardening  # it imports delegation_lifetime, which imports kcs

    clients = _module_clients(call)
    persons = [
        _person(call, user, clients, breakglass_ids)
        for user in _users(call)
        if _ID_RE.match(str(user.get("id", ""))) and not user.get("serviceAccountClientId")
    ]
    return Snapshot(
        persons=persons,
        service_accounts=service_accounts,
        pairings=list(pairings),
        sessions={
            "offline": realm_hardening.offline_limits(call("GET", "") or {}),
            "delegations": dict(delegations),
        },
    )


# ─────────────────────────────────────────────────────────────────────────
# building
# ─────────────────────────────────────────────────────────────────────────


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def checksum(sessions: dict, rows: list[dict]) -> str:
    """Over the session limits and the content of the sorted rows (not their
    confirmation state, which changes without any right changing)."""
    content = [{k: v for k, v in row.items() if k not in _STATE_FIELDS} for row in rows]
    return _digest({"sessions": sessions, "rows": content})


_STATE_FIELDS = frozenset({"digest", "last_confirmed_at", "confirmation_due"})


def _person_rows(snapshot: Snapshot) -> list[dict]:
    owner: dict[str, list[str]] = {}
    deputy: dict[str, list[str]] = {}
    for account in snapshot.service_accounts:
        for held, holder in (
            (owner, account.get("owner_sub")),
            (deputy, account.get("deputy_sub")),
        ):
            if isinstance(holder, str):
                held.setdefault(holder, []).append(account["id"])
    rows = []
    for person in snapshot.persons:
        sub = person["sub"]
        effective = set(person["effective_realm_roles"]) | set(person["realm_roles"])
        rows.append(
            {
                "key": f"person:{sub}",
                "sub": sub,
                "username": person["username"],
                "enabled": person["enabled"],
                "breakglass": person["breakglass"],
                "realm_roles": person["realm_roles"],
                "module_roles": person["module_roles"],
                "groups": person["groups"],
                "service_accounts": {
                    "owner": sorted(owner.get(sub, [])),
                    "deputy": sorted(deputy.get(sub, [])),
                },
                "delegations": dict(sorted(person["delegations"].items())),
                "separation_conflict": (
                    [r for r in SEPARATED_ROLES if r in effective]
                    if sum(r in effective for r in SEPARATED_ROLES) > 1
                    else []
                ),
            }
        )
    return rows


def _system_rows(snapshot: Snapshot) -> list[dict]:
    exchange: dict[str, list[dict]] = {}
    for pairing in snapshot.pairings:
        if not pairing.confirmed:
            continue  # waiting for a second person: no right yet
        exchange.setdefault(pairing.audience, []).append(
            {
                "client": pairing.client,
                "effects": [e for e in rs.EFFECTS if e in pairing.effects],
                "requested_by": pairing.requested_by,
                "confirmed_by": pairing.confirmed_by,
            }
        )
    accounts: dict[str, list[dict]] = {}
    for account in snapshot.service_accounts:
        for audience in account.get("audiences") or []:
            accounts.setdefault(audience, []).append(
                {
                    "id": account["id"],
                    "module": account.get("module"),
                    "effects": sorted(account.get("effects") or []),
                }
            )
    return [
        {
            "key": f"system:{audience}",
            "audience": audience,
            "exchange_clients": sorted(exchange.get(audience, []), key=lambda c: c["client"]),
            "service_accounts": sorted(accounts.get(audience, []), key=lambda a: a["id"]),
            "target_rights": TARGET_RIGHTS,
        }
        for audience in sorted(set(exchange) | set(accounts))
    ]


def _parse_time(text: object) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def build(
    snapshot: Snapshot,
    by: str,
    confirmations: list[dict],
    now: datetime,
    *,
    period_days: int = PERIOD_DEFAULT,
) -> dict:
    """The report document (format papaia.access-report/1, schemas/access-report)."""
    if by not in KINDS:
        raise ReportError(f"unknown report '{by}' (person or system)")
    rows = sorted(
        _person_rows(snapshot) if by == "person" else _system_rows(snapshot),
        key=lambda r: r["key"],
    )
    latest = {c.get("key"): c for c in confirmations if isinstance(c, dict)}
    limit = now - timedelta(days=period_days)
    for row in rows:
        row["digest"] = _digest(row)
        confirmed = latest.get(row["key"])
        at = _parse_time(confirmed.get("confirmed_at")) if confirmed else None
        row["last_confirmed_at"] = confirmed["confirmed_at"] if at else None
        row["confirmation_due"] = (
            at is None or at < limit or confirmed.get("digest") != row["digest"]
        )
    return {
        "format": FORMAT,
        "by": by,
        "checksum": checksum(snapshot.sessions, rows),
        "recertification_days": period_days,
        "sessions": snapshot.sessions,
        "rows": rows,
    }


def period_days(env: dict[str, str]) -> int:
    value = env.get(PERIOD_KEY)
    if value is None or value == "":
        return PERIOD_DEFAULT
    if not _PERIOD_RE.match(value) or not PERIOD_MIN <= int(value) <= PERIOD_MAX:
        raise ReportError(f"{PERIOD_KEY} must be {PERIOD_MIN} to {PERIOD_MAX} days")
    return int(value)


# ─────────────────────────────────────────────────────────────────────────
# output
# ─────────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = {
    "person": (
        "key", "sub", "username", "enabled", "breakglass", "realm_roles", "module_roles",
        "groups", "service_accounts_owner", "service_accounts_deputy", "delegations",
        "separation_conflict", "digest", "last_confirmed_at", "confirmation_due",
    ),
    "system": (
        "key", "audience", "exchange_clients", "service_accounts", "target_rights", "digest",
        "last_confirmed_at", "confirmation_due",
    ),
}


def _cell(value: object) -> str:
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif value is None:
        text = ""
    elif isinstance(value, list):
        text = " ".join(_cell(v) for v in value)
    elif isinstance(value, dict):
        text = " ".join(
            f"{k}={'|'.join(map(str, v)) if isinstance(v, list) else v}" for k, v in value.items()
        )
    else:
        text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _csv_row(row: dict, by: str) -> dict:
    if by == "person":
        flat = dict(row)
        flat["service_accounts_owner"] = row["service_accounts"]["owner"]
        flat["service_accounts_deputy"] = row["service_accounts"]["deputy"]
    else:
        flat = dict(row)
        flat["exchange_clients"] = [
            f"{c['client']}:{''.join(c['effects'])}" for c in row["exchange_clients"]
        ]
        flat["service_accounts"] = [a["id"] for a in row["service_accounts"]]
    return {column: _cell(flat.get(column)) for column in _CSV_COLUMNS[by]}


def render(doc: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt != "csv":
        raise ReportError(f"unknown format '{fmt}' (json or csv)")
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=_CSV_COLUMNS[doc["by"]], lineterminator="\n")
    writer.writeheader()
    for row in doc["rows"]:
        writer.writerow(_csv_row(row, doc["by"]))
    return out.getvalue()


# ─────────────────────────────────────────────────────────────────────────
# release through papaia-audit
# ─────────────────────────────────────────────────────────────────────────


def read_token(source: str, *, stdin: TextIO | None = None) -> str:
    """The person's bearer token from a file, or `-` for stdin."""
    try:
        if source == "-":
            text = (stdin or sys.stdin).read(MAX_TOKEN_BYTES + 2)
        else:
            with open(source, encoding="ascii") as fh:
                text = fh.read(MAX_TOKEN_BYTES + 2)
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"the token cannot be read ({type(exc).__name__})") from None
    token = text.strip()
    if not token or len(token) > MAX_TOKEN_BYTES or not _TOKEN_RE.match(token):
        raise ReportError("the token file does not hold one bearer token")
    return token


def service_gate(config_dir: Path) -> Gate:
    """The route call inside the running papaia-audit (`python -m papaia_audit access`):
    the request, with the token, goes on stdin; the answer is one JSON object."""

    def gate(path: str, token: str, body: dict) -> tuple[int, dict]:
        try:
            container = audit.find_container(config_dir)
        except audit.AuditError as exc:
            raise AuditUnavailable(str(exc)) from None
        argv = ["docker", "exec", "-i", container, "python3", "-I", "-m", "papaia_audit", "access"]
        request = {
            "method": "POST",
            "path": path,
            "authorization": f"Bearer {token}",
            "body": body,
        }
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=EXEC_TIMEOUT_SECONDS,
                check=False,
            )
            answer = json.loads(done.stdout) if done.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            answer = None
        if not isinstance(answer, dict) or type(answer.get("status")) is not int:
            raise AuditUnavailable("papaia-audit did not answer; is the stack running?")
        body_out = answer.get("body")
        return answer["status"], body_out if isinstance(body_out, dict) else {}

    return gate


def _refusal(status: int, body: dict, err: TextIO) -> int:
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    code = body.get("code") if isinstance(body.get("code"), str) else f"HTTP {status}"
    print(f"Refused by papaia-audit ({status}, {code}). {message}", file=err, flush=True)
    return REFUSED if status in (401, 403) else 1


def run(
    snapshot: Snapshot,
    by: str,
    fmt: str,
    token: str,
    gate: Gate,
    out: TextIO,
    *,
    now: datetime | None = None,
    period: int = PERIOD_DEFAULT,
    err: TextIO | None = None,
) -> int:
    """Build the report, have papaia-audit release it, then print it. 0: printed,
    3: refused (no role, no valid token), 1: papaia-audit unavailable or another error."""
    err = err or sys.stderr
    now = now or datetime.now(timezone.utc)
    draft = build(snapshot, by, [], now, period_days=period)
    status, body = gate(
        REPORT_PATH, token, {"by": by, "rows": len(draft["rows"]), "checksum": draft["checksum"]}
    )
    if status != 200:
        return _refusal(status, body, err)
    confirmations = body.get("confirmations")
    doc = build(
        snapshot,
        by,
        confirmations if isinstance(confirmations, list) else [],
        now,
        period_days=period,
    )
    out.write(render(doc, fmt))
    out.flush()
    return 0


def confirm(key: str, digest: str, token: str, gate: Gate, out: TextIO, *, err=None) -> int:
    """Record that the administration confirmed one row (`key`) with the content `digest`."""
    if not _KEY_RE.match(key):
        raise ReportError("--key must be person:<sub> or system:<audience>")
    if not _DIGEST_RE.match(digest):
        raise ReportError("--digest must be sha256:<64 hex>, the row's digest in the report")
    status, body = gate(CONFIRM_PATH, token, {"key": key, "digest": digest})
    if status != 201:
        return _refusal(status, body, err or sys.stderr)
    print(f"Confirmed {key} at {body.get('confirmed_at')}.", file=out, flush=True)
    return 0
