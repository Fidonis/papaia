"""papaia-audit: requests for information and erasure of a person without an account
(docs/person-requests.md, "Requests and confirmation"; security 1.14 no. 2b).

`papaia-ctl person export|erase --requested-by=SUB --confirmed-by=SUB` files a request
here and prints its id; nothing runs yet. The person named as confirming signs in to the
manager again (at most 5 minutes ago) and confirms it; only a person with
`papaia-confirm` or `papaia-admin` who did not ask for it can. For an export the
confirmation makes a one-time passphrase, answers it once to the confirming person and
keeps only the key derived from it (age scrypt, `ARCHIVE_LOG_N`) until the run takes it.
`papaia-ctl person run <id>` then runs the request: confirmed -> running -> done or
partial. The passphrase itself is never stored and never reaches the host.

Two kinds of callers:

- The manager, with the confirming person's token (read API, `request.caller` =
  `papaia-manager`): `GET /v1/person-requests`, `POST /v1/person-requests/<id>/confirm`,
  `POST /v1/person-requests/<id>/reject`.
- The host, through `docker exec` (`python -m papaia_audit person < request.json`), with
  no token: running `docker exec` in this container is the host's administration. These
  routes (`host_routes`) are never reachable over the network.

Every change is stored together with its own event (writer `papaia-audit/person`) in one
database transaction: `person_request_created` names the requesting person,
`person_request_confirmed` and `person_request_rejected` the deciding one, all with the
request id as `object_ref`; run, key and result are `operation` events with the same id.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Protocol

from papaia_audit import access, read
from papaia_audit.read import Identity, Request, Response

WRITER = "papaia-audit/person"
# The catalog entry of the run's `operation` events, as papaia-ctl person names it.
CATALOG_ID = "core.person"
CONFIRM_ROLES = frozenset({"papaia-confirm", "papaia-admin"})
OPERATIONS = frozenset({"export", "erase"})
STATES = ("open", "confirmed", "rejected", "running", "done", "partial")
RESULTS = frozenset({"done", "partial"})
# An open request waits a week for its confirmation; a confirmed one must start within a
# day, so the derived key of an export does not wait longer than that.
OPEN_LIFETIME = timedelta(days=7)
RUN_LIFETIME = timedelta(hours=24)
LIST_MAX = 200
# age scrypt work factor of the archive (2^16, 64 MiB). The passphrase holds 200 random
# bits, so the work factor does not carry its strength.
ARCHIVE_LOG_N = 16
SCRYPT_LABEL = b"age-encryption.org/v1/scrypt"
# Crockford base32 without the letters that read like digits: 40 characters in 8 groups.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PASSPHRASE_GROUPS = 8
PASSPHRASE_GROUP = 5

CREATE_FIELDS = frozenset({"operation", "person", "requested_by", "confirmed_by", "transfer_to"})
FINISH_FIELDS = frozenset({"result"})
HOST_FIELDS = frozenset({"path", "body"})
HOST_REQUEST_MAX = read.MAX_JSON_BODY + 512
HOST_CALLER = "papaia-ctl"
LIST_PATH = "/v1/person-requests"
_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_DECIDE_RE = re.compile(rf"/v1/person-requests/({_ID})/(confirm|reject)")
_HOST_RE = re.compile(rf"/v1/person-requests(?:/({_ID})(?:/(start|key|finish))?)?")
_SUB_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}")


def _problem(status: int, code: str, message: str, hint: str) -> read.Problem:
    klass = {403: "forbidden_or_not_found", 409: "conflict"}[status]
    return read.Problem(status, klass, code, message, hint)


NO_ROLE = _problem(
    403,
    "AUDIT-PERSON-REQ-403",
    "Anträge auf Auskunft oder Löschung bestätigen nur Personen mit der Rolle Bestätigung "
    "oder Verwaltung.",
    "Bitten Sie die Verwaltung um die Rolle „Bestätigung“.",
)
OWN_REQUEST = _problem(
    403,
    "AUDIT-PERSON-REQ-SELF",
    "Sie können Ihren eigenen Antrag nicht bestätigen. Auskunft und Löschung ohne Konto "
    "brauchen immer eine zweite Person.",
    "Die im Antrag als bestätigend genannte Person bestätigt ihn im Manager.",
)
WRONG_STATE = _problem(
    409,
    "AUDIT-PERSON-REQ-409",
    "Der Antrag ist in einem anderen Zustand, als dieser Schritt verlangt, oder seine Frist "
    "ist abgelaufen.",
    "Fragen Sie den Stand mit „papaia-ctl person status <Antrag>“ ab.",
)


@dataclass
class PersonRequest:
    id: str
    operation: str
    sub: str
    transfer_to: str | None
    requested_by: str
    confirmed_by: str
    requested_at: datetime
    state: str = "open"
    decided_by: str | None = None
    decided_at: datetime | None = None
    changed_at: datetime | None = None


class PersonRequestStore(Protocol):
    def add_person_request(self, request: PersonRequest, build: Callable[[int], str]) -> None:
        """Store a new request and its event in one transaction."""
        ...

    def get_person_request(self, request_id: str) -> PersonRequest | None: ...

    def person_requests_of(self, sub: str, since: datetime) -> list[PersonRequest]:
        """Requests asked since `since` that name `sub` as requesting or confirming person,
        newest first, at most LIST_MAX."""
        ...

    def decide_person_request(
        self, request_id: str, state: str, by: str, at: datetime, key: bytes | None,
        build: Callable[[int], str],
    ) -> bool:
        """Close an open request (`confirmed` with the archive key of an export, or
        `rejected`) with its event; False and nothing changed when it is no longer open or
        older than OPEN_LIFETIME. The database refuses a confirmation by anybody other
        than the named confirming person, or by the requesting one."""
        ...

    def advance_person_request(
        self, request_id: str, from_state: str, to_state: str, at: datetime,
        build: Callable[[int], str],
    ) -> bool:
        """confirmed -> running (within RUN_LIFETIME of the confirmation) or running ->
        done|partial (which also drops a key not taken), with its event; False otherwise."""
        ...

    def take_person_request_key(
        self, request_id: str, build: Callable[[int], str]
    ) -> bytes | None:
        """The archive key of a running export, removed in the same transaction as its
        event; None when there is none (any more)."""
        ...


def new_passphrase() -> str:
    groups = (
        "".join(secrets.choice(_ALPHABET) for _ in range(PASSPHRASE_GROUP))
        for _ in range(PASSPHRASE_GROUPS)
    )
    return "-".join(groups)


def archive_key(passphrase: str, salt: bytes, log_n: int = ARCHIVE_LOG_N) -> bytes:
    """salt (16 bytes) + log_n (1 byte) + the scrypt key of an age passphrase stanza (32
    bytes): what the host needs to encrypt the archive to `passphrase` without knowing it."""
    if len(salt) != 16 or not 10 <= log_n <= 20:
        raise ValueError("salt of 16 bytes and a work factor 2^10 to 2^20")
    wrap = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=SCRYPT_LABEL + salt, n=1 << log_n, r=8, p=1,
        maxmem=(128 * 8 * (1 << log_n)) + (64 << 20), dklen=32,
    )
    return salt + bytes([log_n]) + wrap


def host_request(text: str) -> Request | None:
    """The request of papaia-ctl on stdin of `python -m papaia_audit person`; None when
    malformed. Always POST, never with a token."""
    if len(text) > HOST_REQUEST_MAX:
        return None
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict) or set(document) != HOST_FIELDS:
        return None
    if not isinstance(document["path"], str) or not _HOST_RE.fullmatch(document["path"]):
        return None
    if not isinstance(document["body"], dict):
        return None
    return Request(
        "POST", document["path"], "", HOST_CALLER, None, None,
        json.dumps(document["body"]).encode("utf-8"),
    )


def _sub(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _SUB_RE.fullmatch(value):
        raise read._invalid(what)
    return value


class PersonRequestApi(access.AccessApi):
    """The read API with the access routes and the person request routes; the store also
    implements `PersonRequestStore`."""

    def _route(self, request: Request, cid: str) -> Response:
        path, method = request.path, request.method
        decision = _DECIDE_RE.fullmatch(path)
        if (method, path) == ("GET", LIST_PATH) or (decision and method == "POST"):
            if request.caller != "papaia-manager":
                raise read._not_found()
            identity = self._identity(request)
            if not CONFIRM_ROLES & identity.roles:
                raise NO_ROLE
            if decision is None:
                if request.query:
                    raise read._invalid()
                return self._list(identity)
            return self._decide_request(identity, decision[1], decision[2], cid)
        if path.startswith(LIST_PATH):
            raise read._not_found()
        return super()._route(request, cid)

    # -- views and events -------------------------------------------------

    def _view(self, item: PersonRequest, identity: Identity | None) -> dict[str, Any]:
        view = {
            "id": item.id,
            "operation": item.operation,
            "state": self._state(item),
            "requested_at": read.time_text(item.requested_at),
            "decided_at": read.time_text(item.decided_at) if item.decided_at else None,
        }
        if identity is None:
            # The host: the operator who filed it sees the persons it names.
            view.update({
                "person": item.sub,
                "transfer_to": item.transfer_to,
                "requested_by": item.requested_by,
                "confirmed_by": item.confirmed_by,
                "decided_by": item.decided_by,
            })
            return view
        view.update({
            "person": read.pseudonym(self._key, item.sub),
            "requested_by": read.pseudonym(self._key, item.requested_by),
            "confirmed_by": read.pseudonym(self._key, item.confirmed_by),
            "transfer": item.transfer_to is not None,
            "own": item.requested_by == identity.sub,
            "can_confirm": (
                self._state(item) == "open"
                and item.confirmed_by == identity.sub
                and item.requested_by != identity.sub
            ),
        })
        return view

    def _state(self, item: PersonRequest) -> str:
        """The stored state, `expired` for an open one past OPEN_LIFETIME or a confirmed
        one past RUN_LIFETIME."""
        now = self._now()
        if item.state == "open" and now >= item.requested_at + OPEN_LIFETIME:
            return "expired"
        if item.state == "confirmed" and item.decided_at and now >= item.decided_at + RUN_LIFETIME:
            return "expired"
        return item.state

    def _person_event(
        self,
        write: Callable[[Callable[[int], str]], Any],
        event: str,
        sub: str,
        cid: str,
        request_id: str,
        *,
        operation: str,
        effect: str = "write",
        result: str = "allowed",
        error_code: str | None = None,
        azp: str | None = None,
        moment: datetime | None = None,
    ) -> Any:
        identity = Identity(sub, frozenset(), None, azp)
        return self._own_write(
            write, event, identity, cid, query_id=None, result=result, effect=effect,
            error_code=error_code, writer=WRITER, operation=operation,
            object_ref={"type": "person_request", "id": request_id}, moment=moment,
            catalog_id=CATALOG_ID if event == "operation" else None,
        )

    # -- manager ------------------------------------------------------------

    def _list(self, identity: Identity) -> Response:
        since = self._now() - OPEN_LIFETIME
        items = self.store.person_requests_of(identity.sub, since)
        return read._json(200, {"requests": [self._view(i, identity) for i in items]})

    def _decide_request(
        self, identity: Identity, request_id: str, decision: str, cid: str
    ) -> Response:
        item = self.store.get_person_request(request_id)
        # Only the two persons it names see a request; anybody else gets 404.
        if item is None or identity.sub not in (item.requested_by, item.confirmed_by):
            raise read._not_found()
        if self._state(item) != "open":
            raise WRONG_STATE
        if decision == "confirm":
            if item.requested_by == identity.sub:
                # A refused confirmation is an event too, like a refused deletion lock.
                self._person_event(
                    self.store.append_own, "person_request_confirmed", identity.sub, cid,
                    item.id, operation=f"person_request.{item.operation}.confirm",
                    result="denied", error_code=OWN_REQUEST.code, azp=identity.azp,
                )
                raise OWN_REQUEST
            self._fresh(identity)
        now = self._now()
        passphrase = key = None
        if decision == "confirm" and item.operation == "export":
            passphrase = new_passphrase()
            key = archive_key(passphrase, secrets.token_bytes(16))
        state = "confirmed" if decision == "confirm" else "rejected"
        decided = self._person_event(
            lambda build: self.store.decide_person_request(
                item.id, state, identity.sub, now, key, build
            ),
            f"person_request_{state}",
            identity.sub,
            cid,
            item.id,
            operation=f"person_request.{item.operation}.{decision}",
            azp=identity.azp,
            moment=now,
        )
        if not decided:
            raise WRONG_STATE
        view = self._view(
            replace(item, state=state, decided_by=identity.sub, decided_at=now), identity
        )
        if passphrase is not None:
            # Shown once, here; the service keeps only the key derived from it.
            view["passphrase"] = passphrase
        return read._json(200, view)

    # -- host -----------------------------------------------------------------

    def host(self, request: Request) -> Response:
        """One request of papaia-ctl (`host_request`); the routes need no token."""
        cid = read.new_correlation_id()
        try:
            response = self._host(request, cid)
        except (read.Problem, read.StoreError) as error:
            problem = error if isinstance(error, read.Problem) else read.UNAVAILABLE
            response = read._json(problem.status, problem.document(cid))
        response.correlation_id = cid
        return response

    def _host(self, request: Request, cid: str) -> Response:
        match = _HOST_RE.fullmatch(request.path)
        if match is None or request.caller != HOST_CALLER or request.authorization:
            raise read._not_found()
        document = read._json_body(request.body)
        request_id, step = match[1], match[2]
        if request_id is None:
            return self._create(document, cid)
        item = self.store.get_person_request(request_id)
        if item is None:
            raise read._not_found()
        if step is None:
            if document:
                raise read._invalid("den Antrag")
            return read._json(200, self._view(item, None))
        if step == "start":
            if document:
                raise read._invalid("den Antrag")
            return self._advance(item, "confirmed", "running", "start", cid)
        if step == "finish":
            if set(document) != FINISH_FIELDS or document["result"] not in RESULTS:
                raise read._invalid("das Ergebnis")
            return self._advance(item, "running", document["result"], "finish", cid)
        if document:
            raise read._invalid("den Antrag")
        return self._take_key(item, cid)

    def _create(self, document: dict[str, Any], cid: str) -> Response:
        if set(document) != CREATE_FIELDS or document["operation"] not in OPERATIONS:
            raise read._invalid("Art, Person und die beiden beteiligten Personen")
        sub = _sub(document["person"], "die Person")
        requested_by = _sub(document["requested_by"], "die beantragende Person")
        confirmed_by = _sub(document["confirmed_by"], "die bestätigende Person")
        transfer_to = document["transfer_to"]
        if transfer_to is not None:
            transfer_to = _sub(transfer_to, "die neue Eigentümerin")
            if document["operation"] != "erase" or transfer_to == sub:
                raise read._invalid("die neue Eigentümerin")
        if requested_by == confirmed_by:
            raise OWN_REQUEST
        item = PersonRequest(
            str(uuid.uuid4()), document["operation"], sub, transfer_to, requested_by,
            confirmed_by, self._now(),
        )
        self._person_event(
            lambda build: self.store.add_person_request(item, build),
            "person_request_created",
            requested_by,
            cid,
            item.id,
            operation=f"person_request.{item.operation}.create",
            azp=HOST_CALLER,
            moment=item.requested_at,
        )
        return read._json(201, self._view(item, None))

    def _advance(
        self, item: PersonRequest, from_state: str, to_state: str, step: str, cid: str
    ) -> Response:
        if self._state(item) != from_state:
            raise WRONG_STATE
        now = self._now()
        moved = self._person_event(
            lambda build: self.store.advance_person_request(
                item.id, from_state, to_state, now, build
            ),
            "operation",
            item.requested_by,
            cid,
            item.id,
            operation=f"person_request.{item.operation}.{step}",
            azp=HOST_CALLER,
            moment=now,
        )
        if not moved:
            raise WRONG_STATE
        return read._json(200, self._view(replace(item, state=to_state, changed_at=now), None))

    def _take_key(self, item: PersonRequest, cid: str) -> Response:
        if item.operation != "export" or item.state != "running":
            raise WRONG_STATE
        key = self._person_event(
            lambda build: self.store.take_person_request_key(item.id, build),
            "operation",
            item.requested_by,
            cid,
            item.id,
            operation="person_request.export.key",
            effect="read",
            azp=HOST_CALLER,
        )
        if not isinstance(key, bytes) or len(key) != 49:
            raise WRONG_STATE
        return read._json(200, {
            "salt": base64.b64encode(key[:16]).decode("ascii"),
            "log_n": key[16],
            "key": base64.b64encode(key[17:]).decode("ascii"),
        })
