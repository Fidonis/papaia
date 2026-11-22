"""papaia-audit person routes for the permission report and the deletion lock
(docs/audit.md, "Permission report" and "Deletion lock"; security 1.15 and 1.16).

Standard library only, besides `read` and `core`. The routes are part of the read API
(`AccessApi` extends `read.ReadApi`) and answer the same clients
(`read.AUDITOR_CALLERS`) with the same person tokens; each checks its own role here, on
every request:

- `POST /v1/access-reports` (`papaia-auditor`): the release of one permission report.
  The caller states which report (`by`), how many rows and the checksum over its sorted
  content; the answer is the recertification state of every row. Every call with a valid
  token is one event `inventory_exported`, also the refused one (403 without the role).
- `POST /v1/access-reports/confirmations` (`papaia-admin`): the administration confirms
  one row of the report (recertification) with the digest of the content it saw; nobody
  confirms their own row. Event `approval_changed`.
- `GET|POST /v1/legal-holds`, `POST /v1/legal-holds/<id>/confirm|reject`
  (`papaia-legal-hold`): a deletion lock is set or lifted by two different persons, both
  taken from their verified tokens and both after a fresh sign-in; the body never names a
  person who acts. The confirmation runs `audit.legal_hold_confirm` with the role
  `audit_hold` and writes `legal_hold_set` or `legal_hold_lifted` in the same database
  transaction. This holds whatever the platform's four-eyes setting says.

A change is stored only together with its own event (`ReadApi._own_write`); without the
event the answer is 503 and nothing changed.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from papaia_audit import read
from papaia_audit.read import Identity, Request, Response

AUDITOR_ROLE = read.AUDITOR_ROLE
ADMIN_ROLE = "papaia-admin"
LEGAL_HOLD_ROLE = "papaia-legal-hold"
REPORT_WRITER = "papaia-audit/access"
HOLD_WRITER = "papaia-audit/hold"
EVENTS = ("inventory_exported", "approval_changed", "legal_hold_set", "legal_hold_lifted")
REPORT_KINDS = frozenset({"person", "system"})
REPORT_FIELDS = frozenset({"by", "rows", "checksum"})
CONFIRM_FIELDS = frozenset({"key", "digest"})
HOLD_FIELDS = frozenset({"action", "person", "reason"})
HOLD_ACTIONS = frozenset({"set", "lift"})
MAX_ROWS = 100_000
OPEN_LIFETIME = timedelta(hours=24)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# A row key and a locked person name the object_ref id of their event, so they follow its
# pattern in audit.v1.schema.json: a subject with '|' is refused here (400), not by the
# event check (503).
_REF_ID = r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}"
_REF_ID_RE = re.compile(rf"^{_REF_ID}$")
_KEY_RE = re.compile(rf"^(person|system):({_REF_ID})$")
_HOLD_PATH_RE = re.compile(r"^/v1/legal-holds/([0-9a-f-]{36})/(confirm|reject)$")
# What the host reaches through `docker exec` (papaia-ctl report), with the token on stdin.
HOST_ROUTES = frozenset({"/v1/access-reports", "/v1/access-reports/confirmations"})
HOST_FIELDS = frozenset({"method", "path", "authorization", "body"})
HOST_CALLER = "papaia-ctl"
HOST_REQUEST_MAX = read.MAX_TOKEN_BYTES + read.MAX_JSON_BODY + 512
# The object a confirmed row names in its event; `person` is shown as pseudonym.
_KEY_OBJECT = {"person": "person", "system": "catalog_entry"}


def _problem(status: int, code: str, message: str, hint: str) -> read.Problem:
    klass = {401: "unauthenticated", 403: "forbidden_or_not_found", 409: "conflict"}[status]
    return read.Problem(status, klass, code, message, hint)


NO_AUDITOR = _problem(
    403,
    "AUDIT-REPORT-403",
    "Der Berechtigungsbericht ist nur mit der Rolle Audit-Prüfung abrufbar.",
    "Bitten Sie die Verwaltung um die Rolle „Audit-Prüfung“.",
)
NO_ADMIN = _problem(
    403,
    "AUDIT-REPORT-ADMIN",
    "Zeilen des Berechtigungsberichts bestätigt nur die Verwaltung.",
    "Bitten Sie eine Person mit der Rolle Verwaltung, die Zeile zu bestätigen.",
)
OWN_ROW = _problem(
    403,
    "AUDIT-REPORT-SELF",
    "Sie können Ihre eigenen Rechte nicht selbst bestätigen.",
    "Bitten Sie eine andere Person der Verwaltung, Ihre Zeile zu bestätigen.",
)
NO_LEGAL_HOLD = _problem(
    403,
    "AUDIT-HOLD-403",
    "Löschsperren setzen und aufheben nur Personen mit der Rolle Löschsperre.",
    "Bitten Sie die Verwaltung um die Rolle „Löschsperre“.",
)
OWN_HOLD = _problem(
    403,
    "AUDIT-HOLD-SELF",
    "Sie können Ihren eigenen Antrag nicht bestätigen. Eine Löschsperre setzen und "
    "aufheben immer zwei Personen.",
    "Bitten Sie eine andere Person mit der Rolle Löschsperre, den Antrag zu bestätigen.",
)
HOLD_EXISTS = _problem(
    409,
    "AUDIT-HOLD-409",
    "Für diese Person besteht bereits eine Löschsperre, oder es gibt keine, die sich "
    "aufheben ließe.",
    "Laden Sie die Liste der Löschsperren neu.",
)


@dataclass
class Confirmation:
    key: str
    digest: str
    confirmed_by: str
    confirmed_at: datetime


@dataclass
class HoldRequest:
    id: str
    action: str
    sub: str
    reason: str
    requested_by: str
    requested_at: datetime
    state: str = "open"
    decided_by: str | None = None
    decided_at: datetime | None = None


class AccessStore(Protocol):
    def confirmations_latest(self) -> list[Confirmation]:
        """The newest confirmation of every row key, sorted by key."""
        ...

    def add_confirmation(self, confirmation: Confirmation, build: Callable[[int], str]) -> None:
        """Store a confirmation and its event in one transaction."""
        ...

    def hold_active(self, sub: str) -> bool: ...

    def active_holds(self) -> list[tuple[str, datetime]]:
        """(sub, set_at) of every lock not lifted, sorted by sub."""
        ...

    def add_hold_request(self, request: HoldRequest, build: Callable[[int], str]) -> None: ...

    def get_hold_request(self, request_id: str) -> HoldRequest | None: ...

    def open_hold_requests(self, since: datetime) -> list[HoldRequest]: ...

    def decide_hold_request(
        self, request_id: str, state: str, by: str, at: datetime, build: Callable[[int], str]
    ) -> bool:
        """Close an open request; for `confirmed` also set or lift the lock (refused by the
        database when `by` asked for it). All with the event in one transaction; False and
        nothing changed when the request is no longer open, the lock to set exists or the
        lock to lift does not."""
        ...


def host_request(text: str) -> Request | None:
    """The request of papaia-ctl on stdin of `python -m papaia_audit access`, as the caller
    `papaia-ctl`: running `docker exec` is the host's administration, like the client
    certificate of papaia-ctl. Only the report routes, only POST; None when malformed."""
    if len(text) > HOST_REQUEST_MAX:
        return None
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict) or set(document) != HOST_FIELDS:
        return None
    if document["method"] != "POST" or document["path"] not in HOST_ROUTES:
        return None
    if not isinstance(document["authorization"], str) or not isinstance(document["body"], dict):
        return None
    return Request(
        "POST",
        document["path"],
        "",
        HOST_CALLER,
        document["authorization"],
        None,
        json.dumps(document["body"]).encode("utf-8"),
    )


def _exact(document: dict[str, Any], fields: frozenset[str], what: str) -> None:
    if set(document) != fields:
        raise read._invalid(what)


class AccessApi(read.ReadApi):
    """The read API with the routes of the permission report and the deletion lock; the
    store also implements `AccessStore`."""

    def _route(self, request: Request, cid: str) -> Response:
        answer = self.access_route(request, cid)
        return answer if answer is not None else super()._route(request, cid)

    def access_route(self, request: Request, cid: str) -> Response | None:
        """The answer of an access route, or None when the path is none of them."""
        path, method = request.path, request.method
        decision = _HOLD_PATH_RE.match(path)
        known = {
            ("POST", "/v1/access-reports"),
            ("POST", "/v1/access-reports/confirmations"),
            ("GET", "/v1/legal-holds"),
            ("POST", "/v1/legal-holds"),
        }
        if (method, path) not in known and not (decision and method == "POST"):
            return None
        if request.caller not in read.AUDITOR_CALLERS:
            raise read._not_found()
        identity = self._identity(request)
        if path == "/v1/access-reports":
            return self._release_report(identity, request, cid)
        if path == "/v1/access-reports/confirmations":
            return self._confirm_row(identity, request, cid)
        if LEGAL_HOLD_ROLE not in identity.roles:
            raise NO_LEGAL_HOLD
        if decision:
            return self._decide_hold(identity, decision[1], decision[2], cid)
        if method == "GET":
            if request.query:
                raise read._invalid()
            return self._holds(identity)
        return self._request_hold(identity, request, cid)

    # -- events -----------------------------------------------------------

    def _event(
        self,
        write: Callable[[Callable[[int], str]], Any],
        event: str,
        identity: Identity,
        cid: str,
        *,
        writer: str,
        operation: str,
        object_ref: dict[str, str] | None,
        effect: str = "write",
        result: str = "allowed",
        error_code: str | None = None,
        rows: int | None = None,
        moment: datetime | None = None,
    ) -> Any:
        return self._own_write(
            write,
            event,
            identity,
            cid,
            query_id=None,
            result=result,
            effect=effect,
            rows=rows,
            error_code=error_code,
            writer=writer,
            operation=operation,
            object_ref=object_ref,
            moment=moment,
        )

    def _denied(self, identity: Identity, cid: str, problem: read.Problem, **fields: Any) -> None:
        self._event(
            self.store.append_own,
            identity=identity,
            cid=cid,
            result="denied",
            error_code=problem.code,
            **fields,
        )
        raise problem

    def _fresh(self, identity: Identity) -> None:
        if identity.auth_time is None or identity.auth_time < self.clock() - read.FRESH_SIGN_IN:
            raise read.NOT_FRESH

    # -- permission report ------------------------------------------------

    def _release_report(self, identity: Identity, request: Request, cid: str) -> Response:
        if AUDITOR_ROLE not in identity.roles:
            # Every retrieval is an event, the refused one too (EXI-PLT-60-A4).
            self._denied(
                identity,
                cid,
                NO_AUDITOR,
                event="inventory_exported",
                writer=REPORT_WRITER,
                operation="access_report.refused",
                object_ref=None,
                effect="read",
            )
        document = read._json_body(request.body)
        _exact(document, REPORT_FIELDS, "Berichtsart, Zeilenzahl und Prüfsumme")
        by, rows, checksum = document["by"], document["rows"], document["checksum"]
        if by not in REPORT_KINDS or type(rows) is not int or not 0 <= rows <= MAX_ROWS:
            raise read._invalid("Berichtsart, Zeilenzahl und Prüfsumme")
        if not isinstance(checksum, str) or not _DIGEST_RE.match(checksum):
            raise read._invalid("Berichtsart, Zeilenzahl und Prüfsumme")
        self._event(
            self.store.append_own,
            "inventory_exported",
            identity,
            cid,
            writer=REPORT_WRITER,
            operation=f"access_report.{by}",
            object_ref={"type": "access_report", "id": checksum},
            effect="read",
            rows=rows,
        )
        confirmations = [
            {
                "key": item.key,
                "digest": item.digest,
                "confirmed_at": read.time_text(item.confirmed_at),
                "confirmed_by": read.pseudonym(self._key, item.confirmed_by),
            }
            for item in self.store.confirmations_latest()
        ]
        return read._json(200, {"confirmations": confirmations})

    def _confirm_row(self, identity: Identity, request: Request, cid: str) -> Response:
        if ADMIN_ROLE not in identity.roles:
            raise NO_ADMIN
        document = read._json_body(request.body)
        _exact(document, CONFIRM_FIELDS, "Zeile und Prüfsumme")
        key, digest = document["key"], document["digest"]
        match = _KEY_RE.match(key) if isinstance(key, str) else None
        if match is None or not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise read._invalid("Zeile und Prüfsumme")
        kind, name = match[1], match[2]
        fields: dict[str, Any] = {
            "event": "approval_changed",
            "writer": REPORT_WRITER,
            "operation": "access_report.confirmed",
            "object_ref": {"type": _KEY_OBJECT[kind], "id": name},
        }
        if kind == "person" and name == identity.sub:
            self._denied(identity, cid, OWN_ROW, **fields)
        now = self._now()
        confirmation = Confirmation(key, digest, identity.sub, now)
        self._event(
            lambda build: self.store.add_confirmation(confirmation, build),
            identity=identity,
            cid=cid,
            moment=now,
            **fields,
        )
        return read._json(
            201, {"key": key, "digest": digest, "confirmed_at": read.time_text(now)}
        )

    # -- deletion lock ----------------------------------------------------

    def _hold_view(self, request: HoldRequest, identity: Identity) -> dict[str, Any]:
        return {
            "id": request.id,
            "action": request.action,
            "state": request.state,
            "person": read.pseudonym(self._key, request.sub),
            "reason": request.reason,
            "requested_by": read.pseudonym(self._key, request.requested_by),
            "requested_at": read.time_text(request.requested_at),
            "own": request.requested_by == identity.sub,
        }

    def _holds(self, identity: Identity) -> Response:
        since = self._now() - OPEN_LIFETIME
        return read._json(
            200,
            {
                "requests": [
                    self._hold_view(r, identity) for r in self.store.open_hold_requests(since)
                ],
                "holds": [
                    {"person": read.pseudonym(self._key, sub), "set_at": read.time_text(at)}
                    for sub, at in self.store.active_holds()
                ],
            },
        )

    def _request_hold(self, identity: Identity, request: Request, cid: str) -> Response:
        document = read._json_body(request.body)
        _exact(document, HOLD_FIELDS, "Aktion, Person und Begründung")
        action, person = document["action"], document["person"]
        if action not in HOLD_ACTIONS or not isinstance(person, str):
            raise read._invalid("Aktion, Person und Begründung")
        reason = read._reason(document["reason"])
        if read._PSEUD_RE.match(person):
            matches = [s for s in self.store.subjects() if read.pseudonym(self._key, s) == person]
            if len(matches) != 1:
                raise read._not_found()
            sub = matches[0]
        elif read._SUBJECT_RE.match(person):
            sub = person
        else:
            raise read._invalid("die Person")
        if not _REF_ID_RE.match(sub):
            raise read._invalid("die Person")
        self._fresh(identity)
        if self.store.hold_active(sub) != (action == "lift"):
            raise HOLD_EXISTS
        hold = HoldRequest(str(uuid.uuid4()), action, sub, reason, identity.sub, self._now())
        self._event(
            lambda build: self.store.add_hold_request(hold, build),
            "approval_changed",
            identity,
            cid,
            writer=HOLD_WRITER,
            operation=f"legal_hold.{action}.requested",
            object_ref={"type": "legal_hold_request", "id": hold.id},
        )
        return read._json(201, self._hold_view(hold, identity))

    def _decide_hold(self, identity: Identity, request_id: str, decision: str, cid: str):
        if not read._UUID_RE.match(request_id):
            raise read._not_found()
        hold = self.store.get_hold_request(request_id)
        now = self._now()
        if hold is None or (hold.state == "open" and now >= hold.requested_at + OPEN_LIFETIME):
            raise read._not_found()
        if hold.state != "open":
            raise read.NOT_OPEN
        request_ref = {"type": "legal_hold_request", "id": hold.id}
        if decision == "reject":
            state, event = "rejected", "approval_changed"
            operation, ref = f"legal_hold.{hold.action}.rejected", request_ref
        else:
            if hold.requested_by == identity.sub:
                # Two persons, whatever the platform's four-eyes setting says.
                self._denied(
                    identity,
                    cid,
                    OWN_HOLD,
                    event="approval_changed",
                    writer=HOLD_WRITER,
                    operation=f"legal_hold.{hold.action}.confirm",
                    object_ref=request_ref,
                )
            self._fresh(identity)
            state = "confirmed"
            event = "legal_hold_set" if hold.action == "set" else "legal_hold_lifted"
            operation = f"legal_hold.{hold.action}"
            ref = {"type": "person", "id": hold.sub}
        decided = self._event(
            lambda build: self.store.decide_hold_request(hold.id, state, identity.sub, now, build),
            event,
            identity,
            cid,
            writer=HOLD_WRITER,
            operation=operation,
            object_ref=ref,
            moment=now,
        )
        if not decided:
            raise HOLD_EXISTS if state == "confirmed" else read.NOT_OPEN
        hold.state, hold.decided_by, hold.decided_at = state, identity.sub, now
        return read._json(200, self._hold_view(hold, identity))
