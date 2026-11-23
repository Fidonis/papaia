"""The permission report by person or by system, built inside papaia-audit (security 1.16,
OPS-19; docs/permission-report.md).

Standard library only. Two inputs, both read on every build:

- the Admin API of the `papaia` realm, read as the service account
  `svc-papaia-audit-report` (idp.py; `realm-management` `view-users` and nothing else,
  GET only): the persons, their role mappings, effective realm roles, groups and the
  stored delegations (offline sessions) per module client;
- the inputs file `access-report-inputs.json` (format `papaia.access-report-inputs/1`)
  that papaia-ctl writes on `realm sync` and `start` into the service folder: the managed
  module clients (uuid and client id), the declared service accounts with owner, deputy
  and audience, the confirmed exchange-right pairings (the platform pairing of the realm
  sync included), the ids of the emergency account, the delegation lifetime, the
  offline-session limits of the realm and the recertification period. It holds no secret
  and no credential; what `view-users` cannot read (the client list and the realm's
  session limits) comes from it, so the account needs no further right.

The content is the one papaia-ctl built on the host before: by person, realm roles, roles
of the module clients, groups, the service accounts the person owns or deputises, the
stored delegations per module client, whether the person holds two of the separated
platform roles, and whether it is the emergency account; by system (audience), the
clients with an exchange right and its effects, who asked for and who confirmed it, and
the service accounts with that audience. Rights inside the target system are kept there.

No content, no secret and no credential is read into the report. Rows are sorted, each
carries the digest of its content, and the report carries a checksum over the sorted
content and the session limits: two reports of the same realm are equal, and a change of
one person changes only that person's row. The confirmation state of a row (latest
confirmation, `confirmation_due`) is outside both.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FORMAT = "papaia.access-report/1"
INPUTS_FORMAT = "papaia.access-report-inputs/1"
INPUTS_FILE = "access-report-inputs.json"
KINDS = ("person", "system")
FORMATS = ("json", "csv")
PERIOD_DEFAULT, PERIOD_MIN, PERIOD_MAX = 180, 30, 730
SEPARATED_ROLES = ("papaia-admin", "papaia-auditor", "papaia-operator")
TARGET_RIGHTS = "im Zielsystem geführt"
EFFECTS = ("r", "w", "d", "x")
# Who asked for and confirmed a pairing the realm sync sets itself (papaia-manager for
# papaia-audit); an operator's pairing names two host accounts.
PLATFORM = "platform"
PAGE = 100
MAX_INPUTS_BYTES = 1 << 20
MAX_ITEMS = 10_000

_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_ACCOUNT_RE = re.compile(r"^svc-[a-z][a-z0-9]*-[a-z0-9]+(-[a-z0-9]+)*$")
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,254}$")
_PERSON_RE = re.compile(r"^(host:[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}|platform)$")
_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_INPUT_KEYS = frozenset(
    {
        "format",
        "written_at",
        "module_clients",
        "service_accounts",
        "pairings",
        "breakglass_ids",
        "sessions",
        "recertification_days",
    }
)
_ACCOUNT_KEYS = frozenset({"id", "module", "owner_sub", "deputy_sub", "audiences", "effects"})
_PAIRING_KEYS = frozenset({"client", "audience", "effects", "requested_by", "confirmed_by"})
# Spreadsheet programs run a cell that starts with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

Call = Callable[[str], Any]


class InputsMissing(Exception):
    """The inputs file is not there yet: `papaia-ctl realm sync` writes it."""


class InputsInvalid(Exception):
    """The inputs file cannot be used; the message says which part (no value)."""


class SourceError(Exception):
    """The realm cannot be read (Keycloak down, the account refused, a malformed answer)."""


@dataclass(frozen=True)
class Inputs:
    written_at: str
    module_clients: tuple[tuple[str, str], ...]
    service_accounts: tuple[dict, ...]
    pairings: tuple[dict, ...]
    breakglass_ids: frozenset[str]
    sessions: dict
    recertification_days: int


@dataclass
class Snapshot:
    persons: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    pairings: list[dict] = field(default_factory=list)
    sessions: dict = field(default_factory=dict)
    inputs_at: str | None = None


# ─────────────────────────────────────────────────────────────────────────
# the inputs file
# ─────────────────────────────────────────────────────────────────────────


def _invalid(part: str) -> InputsInvalid:
    return InputsInvalid(f"the inputs file is not usable: {part}")


def _list(value: object, part: str) -> list:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise _invalid(part)
    return value


def _exact(value: object, keys: frozenset[str], part: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise _invalid(part)
    return value


def _effects(value: object, part: str, allowed: Iterable[str] | None = None) -> list[str]:
    items = _list(value, part)
    if not all(isinstance(e, str) and len(e) <= 16 for e in items) or len(set(items)) != len(
        items
    ):
        raise _invalid(part)
    if allowed is not None and not set(items) <= set(allowed):
        raise _invalid(part)
    return items


def _sub(value: object, part: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SUBJECT_RE.match(value):
        raise _invalid(part)
    return value


def _days(value: object, part: str, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if type(value) is not int or not 0 <= value <= 36_500:
        raise _invalid(part)
    return value


def parse_inputs(document: object) -> Inputs:
    """The checked content of the inputs file; InputsInvalid for anything else (unknown
    fields included)."""
    doc = _exact(document, _INPUT_KEYS, "fields")
    if doc["format"] != INPUTS_FORMAT:
        raise _invalid("format")
    if not isinstance(doc["written_at"], str) or not _TIME_RE.match(doc["written_at"]):
        raise _invalid("written_at")
    clients = []
    for entry in _list(doc["module_clients"], "module_clients"):
        entry = _exact(entry, frozenset({"id", "client_id"}), "module_clients")
        if not isinstance(entry["id"], str) or not _ID_RE.match(entry["id"]):
            raise _invalid("module_clients")
        if not isinstance(entry["client_id"], str) or not _NAME_RE.match(entry["client_id"]):
            raise _invalid("module_clients")
        clients.append((entry["id"], entry["client_id"]))
    accounts = []
    for entry in _list(doc["service_accounts"], "service_accounts"):
        entry = _exact(entry, _ACCOUNT_KEYS, "service_accounts")
        if not isinstance(entry["id"], str) or not _ACCOUNT_RE.match(entry["id"]):
            raise _invalid("service_accounts")
        module = entry["module"]
        if module is not None and (not isinstance(module, str) or not _NAME_RE.match(module)):
            raise _invalid("service_accounts")
        audiences = _list(entry["audiences"], "service_accounts")
        if not all(isinstance(a, str) and _NAME_RE.match(a) for a in audiences):
            raise _invalid("service_accounts")
        accounts.append(
            {
                "id": entry["id"],
                "module": module,
                "owner_sub": _sub(entry["owner_sub"], "service_accounts"),
                "deputy_sub": _sub(entry["deputy_sub"], "service_accounts"),
                "audiences": sorted(set(audiences)),
                "effects": sorted(_effects(entry["effects"], "service_accounts")),
            }
        )
    pairings = []
    for entry in _list(doc["pairings"], "pairings"):
        entry = _exact(entry, _PAIRING_KEYS, "pairings")
        for name in ("client", "audience"):
            if not isinstance(entry[name], str) or not _NAME_RE.match(entry[name]):
                raise _invalid("pairings")
        for name in ("requested_by", "confirmed_by"):
            value = entry[name]
            if value is not None and (not isinstance(value, str) or not _PERSON_RE.match(value)):
                raise _invalid("pairings")
        effects = _effects(entry["effects"], "pairings", EFFECTS)
        pairings.append(dict(entry, effects=[e for e in EFFECTS if e in effects]))
    ids = _list(doc["breakglass_ids"], "breakglass_ids")
    if not all(isinstance(i, str) and _ID_RE.match(i) for i in ids):
        raise _invalid("breakglass_ids")
    sessions = _exact(doc["sessions"], frozenset({"offline", "delegations"}), "sessions")
    offline = _exact(sessions["offline"], frozenset({"idle_days", "max_age_days"}), "sessions")
    _days(offline["idle_days"], "sessions")
    _days(offline["max_age_days"], "sessions", optional=True)
    if not isinstance(sessions["delegations"], dict) or len(json.dumps(sessions)) > 4096:
        raise _invalid("sessions")
    period = doc["recertification_days"]
    if type(period) is not int or not PERIOD_MIN <= period <= PERIOD_MAX:
        raise _invalid("recertification_days")
    return Inputs(
        written_at=doc["written_at"],
        module_clients=tuple(sorted(clients, key=lambda c: c[1])),
        service_accounts=tuple(accounts),
        pairings=tuple(pairings),
        breakglass_ids=frozenset(ids),
        sessions={"offline": dict(offline), "delegations": dict(sessions["delegations"])},
        recertification_days=period,
    )


def load_inputs(path: Path) -> Inputs:
    """Read and check the inputs file; InputsMissing when it is not there yet."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_INPUTS_BYTES + 1)
    except FileNotFoundError:
        raise InputsMissing(str(path.name)) from None
    except OSError as error:
        raise _invalid(type(error).__name__) from None
    if len(raw) > MAX_INPUTS_BYTES:
        raise _invalid("size")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _invalid("not JSON") from None
    return parse_inputs(document)


# ─────────────────────────────────────────────────────────────────────────
# collecting (Admin API, GET only)
# ─────────────────────────────────────────────────────────────────────────


def _names(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    return sorted(
        {i["name"] for i in items if isinstance(i, dict) and isinstance(i.get("name"), str)}
    )


def _users(call: Call) -> Iterable[dict]:
    first = 0
    while True:
        page = call(f"/users?first={first}&max={PAGE}&briefRepresentation=true") or []
        if not isinstance(page, list):
            raise SourceError("malformed user list")
        yield from (u for u in page if isinstance(u, dict))
        if len(page) < PAGE:
            return
        first += PAGE


def _person(call: Call, user: dict, inputs: Inputs) -> dict:
    uid = user["id"]
    mappings = call(f"/users/{uid}/role-mappings") or {}
    if not isinstance(mappings, dict):
        raise SourceError("malformed role mappings")
    module_roles = {}
    for client, entry in sorted((mappings.get("clientMappings") or {}).items()):
        names = _names((entry or {}).get("mappings"))
        if names:
            module_roles[client] = names
    effective = _names(call(f"/users/{uid}/role-mappings/realm/composite"))
    groups = sorted(
        g["path"]
        for g in call(f"/users/{uid}/groups") or []
        if isinstance(g, dict) and isinstance(g.get("path"), str)
    )
    delegations = {}
    for client_uuid, client_id in inputs.module_clients:
        sessions = call(f"/users/{uid}/offline-sessions/{client_uuid}") or []
        if isinstance(sessions, list) and sessions:
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
        # By the id papaia-ctl recorded, never by name or attribute.
        "breakglass": uid in inputs.breakglass_ids,
    }


def collect(call: Call, inputs: Inputs) -> Snapshot:
    """The report's inputs; `call(path)` is a GET on the Admin API of the `papaia` realm.
    Only the fields the report shows are taken from the answers."""
    persons = [
        _person(call, user, inputs)
        for user in _users(call)
        if _ID_RE.match(str(user.get("id", ""))) and not user.get("serviceAccountClientId")
    ]
    return Snapshot(
        persons=persons,
        service_accounts=[dict(a) for a in inputs.service_accounts],
        pairings=[dict(p) for p in inputs.pairings],
        sessions={"offline": dict(inputs.sessions["offline"]),
                  "delegations": dict(inputs.sessions["delegations"])},
        inputs_at=inputs.written_at,
    )


# ─────────────────────────────────────────────────────────────────────────
# building
# ─────────────────────────────────────────────────────────────────────────


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


_STATE_FIELDS = frozenset({"digest", "last_confirmed_at", "confirmation_due"})


def checksum(sessions: dict, rows: list[dict]) -> str:
    """Over the session limits and the content of the sorted rows (not their
    confirmation state, which changes without any right changing)."""
    content = [{k: v for k, v in row.items() if k not in _STATE_FIELDS} for row in rows]
    return _digest({"sessions": sessions, "rows": content})


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
        exchange.setdefault(pairing["audience"], []).append(
            {
                "client": pairing["client"],
                "effects": [e for e in EFFECTS if e in pairing["effects"]],
                "requested_by": pairing["requested_by"],
                "confirmed_by": pairing["confirmed_by"],
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
    """The report document (format papaia.access-report/1, access-report.schema.json)."""
    if by not in KINDS:
        raise ValueError(f"unknown report '{by}'")
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
    doc = {
        "format": FORMAT,
        "by": by,
        "checksum": checksum(snapshot.sessions, rows),
        "recertification_days": period_days,
        "sessions": snapshot.sessions,
        "rows": rows,
    }
    if snapshot.inputs_at is not None:
        doc["inputs_written_at"] = snapshot.inputs_at
    return doc


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
    flat = dict(row)
    if by == "person":
        flat["service_accounts_owner"] = row["service_accounts"]["owner"]
        flat["service_accounts_deputy"] = row["service_accounts"]["deputy"]
    else:
        flat["exchange_clients"] = [
            f"{c['client']}:{''.join(c['effects'])}" for c in row["exchange_clients"]
        ]
        flat["service_accounts"] = [a["id"] for a in row["service_accounts"]]
    return {column: _cell(flat.get(column)) for column in _CSV_COLUMNS[by]}


def render(doc: dict, fmt: str) -> str:
    """The report as papaia-ctl prints it: JSON (indented, sorted keys) or CSV."""
    if fmt == "json":
        return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt != "csv":
        raise ValueError(f"unknown format '{fmt}'")
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=_CSV_COLUMNS[doc["by"]], lineterminator="\n")
    writer.writeheader()
    for row in doc["rows"]:
        writer.writerow(_csv_row(row, doc["by"]))
    return out.getvalue()
