"""papaia-audit read API: search and export with pseudonyms, and the person filter that
needs a reason and a second person (docs/audit.md, "Reading").

Standard library only, besides `core`. The database and the TLS server live in
`__main__.py`; `ReadApi.handle` takes one request and returns one response, so every rule
here runs (and is tested) without them.

Rules:

- Every route needs a bearer token of the realm for the audience `papaia-audit` (RS256,
  checked against the keys in `token-keys.json`) with a session (`sid`): persons only.
- The routes of the audit log answer only the reading clients (`AUDITOR_CALLERS`, by
  client certificate) and only tokens with the realm role `papaia-auditor`.
- Rows show the pseudonym `P-XXXXXXXX` instead of `sub`; no grouping or counting by
  person is offered.
- A filter by person (`sub`, `pseud` or `ticket`) needs a ticket: a person query that
  one auditor requested with a reason and another auditor confirmed after a fresh sign-in.
  Nobody confirms their own request, whatever the platform's four-eyes setting says; the
  ticket holds for the requester, for that person and period, for 60 minutes.
- The identity map (`POST /v1/idmap`, `papaia-ctl audit idmap`) resolves one person at a
  time and only with such a ticket: from the pseudonym to `sub`, user name and the
  upstream provider's `tid`/`oid`, or from `tid`/`oid` back to the pseudonym. papaia-lifecycle
  feeds the map (`POST /v1/identities`, client certificate only); nobody reads it whole.
- Requests, decisions, reads with a ticket, resolutions and exports are events of the
  source `papaia-audit`, written before the answer; the affected person reads the reads
  about them at `/v1/me/reads` (through `papaia-me`).

Answers carry no reason text, token or row in any log; error bodies follow the platform's
error envelope (class, code, message, hint, correlation id).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import parse_qs

from papaia_audit import core

AUDIENCE = "papaia-audit"
AUDITOR_ROLE = "papaia-auditor"
TOKEN_KEYS_FORMAT = "papaia.audit-token-keys/1"
OWN_SOURCE = "papaia-audit"
WRITER = "papaia-audit/read"
# Clients that reach the read API, by the source of their client certificate.
AUDITOR_CALLERS = frozenset({"papaia-manager", "papaia-ctl"})
ME_CALLERS = frozenset({"papaia-me"})
# The service that knows the provider's ids of the persons and feeds the identity map.
IDENTITY_CALLERS = frozenset({"papaia-lifecycle"})
IDMAP_PATH = "/v1/idmap"
IDENTITIES_PATH = "/v1/identities"
MAX_IDENTITY_BODY = 256 * 1024
IDENTITIES_MAX = 500
# `object_ref.type` values whose id names a person (a lifecycle change on an account, a
# realm sync on a user). Without a ticket for that person the id is shown as pseudonym,
# like `sub`; so is any id equal to the row's own `sub`, whatever its type.
PERSON_REF_TYPES = frozenset({"user", "person", "member", "account", "subject", "principal"})

MAX_TOKEN_BYTES = 8192
MAX_JSON_BODY = 8192
CLOCK_SKEW = 60
FRESH_SIGN_IN = 300
TICKET_LIFETIME = timedelta(minutes=60)
OPEN_LIFETIME = timedelta(hours=24)
MAX_PERIOD = timedelta(days=93)
REASON_MIN, REASON_MAX = 20, 1000
PAGE_DEFAULT, PAGE_MAX = 100, 500
EXPORT_MAX = 100_000
ME_READS_MAX = 500

SEARCH_FIELDS = frozenset(
    {
        "source",
        "event",
        "catalog_id",
        "result",
        "correlation_id",
        "from",
        "to",
        "ticket",
        "sub",
        "pseud",
    }
)
PAGE_FIELDS = frozenset({"page_token", "limit"})
# Asking for an evaluation by person is refused as such, not as an unknown parameter.
GROUPING_FIELDS = frozenset({"group_by", "count", "count_by", "per", "aggregate", "distinct"})
REQUEST_FIELDS = frozenset({"person", "from", "to", "reason"})
IDMAP_FROM_PSEUDONYM = frozenset({"ticket", "pseud"})
IDMAP_FROM_UPSTREAM = frozenset({"ticket", "tid", "oid"})
IDENTITY_FIELDS = frozenset({"sub", "username", "tid", "oid"})

_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,254}$")
_PSEUD_RE = re.compile(r"^P-[A-Z2-7]{8}$")
_EVENT_RE = re.compile(r"^[a-z][a-z_]{0,63}$")
_CATALOG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_UPSTREAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PAGE_TOKEN_RE = re.compile(r"^([0-9]{1,15})\.([a-z][a-z0-9-]{0,62})\.([0-9]{1,18})$")
_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z)?$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_QUERY_PATH_RE = re.compile(r"^/v1/person-queries/([0-9a-f-]{36})/(confirm|reject)$")
_RESULTS = frozenset({"allowed", "denied", "error"})
# DigestInfo of SHA-256 (RFC 8017, section 9.2, note 1).
_SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


# ─────────────────────────────────────────────────────────────────────────
# errors (platform error envelope; texts follow message pattern 8)
# ─────────────────────────────────────────────────────────────────────────


class Problem(Exception):
    def __init__(self, status: int, klass: str, code: str, message: str, hint: str) -> None:
        super().__init__(code)
        self.status, self.klass, self.code = status, klass, code
        self.message, self.hint = message, hint

    def document(self, correlation_id: str) -> dict[str, Any]:
        return {
            "type": f"https://schemas.papaia.dev/errors/{self.klass}",
            "title": self.klass,
            "status": self.status,
            "code": self.code,
            "class": self.klass,
            "message": self.message,
            "hint": self.hint,
            "correlation_id": correlation_id,
            "retryable": self.klass == "upstream_unavailable",
        }


def _unauthenticated() -> Problem:
    return Problem(
        401,
        "unauthenticated",
        "AUDIT-AUTH-401",
        "Ihre Anmeldung ist nicht gültig oder abgelaufen.",
        "Melden Sie sich erneut an.",
    )


def _not_found() -> Problem:
    return Problem(
        404,
        "forbidden_or_not_found",
        "AUDIT-READ-404",
        "Diese Adresse gibt es nicht oder sie ist für Sie nicht freigegeben.",
        "Öffnen Sie das Audit-Log über den Manager.",
    )


def _invalid(what: str = "Filter oder Zeitraum") -> Problem:
    return Problem(
        400,
        "invalid_input",
        "AUDIT-READ-400",
        "Die Anfrage enthält einen ungültigen oder unbekannten Wert.",
        f"Prüfen Sie {what}.",
    )


NO_ROLE = Problem(
    403,
    "forbidden_or_not_found",
    "AUDIT-READ-403",
    "Das Audit-Log ist nur mit der Rolle Audit-Prüfung lesbar.",
    "Bitten Sie die Verwaltung um die Rolle „Audit-Prüfung“.",
)
GROUPING = Problem(
    403,
    "forbidden_or_not_found",
    "AUDIT-READ-GROUP",
    "Auswertungen nach Person bietet das Audit-Log nicht an.",
    "Filtern Sie nach Zeitraum, Modul oder Ereignisart.",
)
PERSON_FILTER = Problem(
    403,
    "forbidden_or_not_found",
    "AUDIT-PERSON-403",
    "Ein Filter nach Person ist nur mit einem bestätigten Personenfilter "
    "für diese Person und diesen Zeitraum möglich.",
    "Stellen Sie unter „Personenfilter beantragen“ einen Antrag.",
)
SELF_CONFIRM = Problem(
    403,
    "forbidden_or_not_found",
    "AUDIT-PERSON-SELF",
    "Sie können Ihren eigenen Antrag nicht bestätigen. Ohne zweite Person "
    "bleibt der Personenfilter gesperrt.",
    "Bitten Sie eine andere Person mit der Rolle Audit-Prüfung, den Antrag "
    "unter „Audit-Log → Offene Anträge“ zu bestätigen.",
)
EXPIRED = Problem(
    403,
    "forbidden_or_not_found",
    "AUDIT-PERSON-EXPIRED",
    "Ihr Personenfilter ist abgelaufen (gültig 60 Minuten). Die Liste zeigt "
    "wieder Kennungen statt Namen.",
    "Stellen Sie bei Bedarf einen neuen Antrag.",
)
NOT_FRESH = Problem(
    401,
    "unauthenticated",
    "AUDIT-AUTH-FRESH",
    "Für die Bestätigung ist eine Anmeldung nötig, die höchstens 5 Minuten zurückliegt.",
    "Melden Sie sich erneut an und bestätigen Sie dann.",
)
NOT_OPEN = Problem(
    409,
    "conflict",
    "AUDIT-PERSON-409",
    "Der Antrag ist nicht mehr offen.",
    "Laden Sie die Liste der offenen Anträge neu.",
)
UNAVAILABLE = Problem(
    503,
    "upstream_unavailable",
    "AUDIT-READ-503",
    "Das Audit-Log ist gerade nicht erreichbar.",
    "Versuchen Sie es in einigen Minuten erneut.",
)


# ─────────────────────────────────────────────────────────────────────────
# tokens
# ─────────────────────────────────────────────────────────────────────────


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rsa_sha256_verify(n: int, e: int, message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017, 8.2.2): the whole encoded block is
    compared, nothing of it is parsed."""
    size = (n.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    info = _SHA256_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(info) - 3) + b"\x00" + info
    return hmac.compare_digest(pow(value, e, n).to_bytes(size, "big"), expected)


@dataclass(frozen=True)
class TokenKeys:
    issuer: str
    keys: dict[str, tuple[int, int]]

    @classmethod
    def parse(cls, data: Any) -> TokenKeys:
        """`token-keys.json` -> keys by kid. Only RSA signing keys of at least 2048 bits
        are kept (a realm also lists encryption keys); ValueError when malformed."""
        if not isinstance(data, dict) or set(data) != {"format", "issuer", "keys"}:
            raise ValueError("token-keys.json: expected format, issuer and keys")
        issuer, entries = data["issuer"], data["keys"]
        if data["format"] != TOKEN_KEYS_FORMAT or not isinstance(issuer, str):
            raise ValueError("token-keys.json: unknown format")
        if not issuer.startswith(("https://", "http://")) or len(issuer) > 512:
            raise ValueError("token-keys.json: invalid issuer")
        if not isinstance(entries, list) or len(entries) > 32:
            raise ValueError("token-keys.json: invalid keys")
        keys: dict[str, tuple[int, int]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
                raise ValueError("token-keys.json: invalid key")
            if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
                continue
            if entry.get("alg", "RS256") != "RS256":
                continue
            try:
                n = int.from_bytes(_b64url(entry["n"]), "big")
                e = int.from_bytes(_b64url(entry["e"]), "big")
            except (KeyError, TypeError, ValueError):
                raise ValueError("token-keys.json: invalid key") from None
            if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
                raise ValueError("token-keys.json: key too weak")
            keys[entry["kid"]] = (n, e)
        return cls(issuer, keys)


@dataclass(frozen=True)
class Identity:
    sub: str
    roles: frozenset[str]
    auth_time: int | None
    azp: str | None


def check_token(authorization: str | None, keys: TokenKeys, now: float) -> Identity:
    """The person behind a bearer token for `papaia-audit`, or Problem 401."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or len(token) > MAX_TOKEN_BYTES or not _JWT_RE.match(token):
        raise _unauthenticated()
    head_text, body_text, signature_text = token.split(".")
    try:
        header = json.loads(_b64url(head_text))
        claims = json.loads(_b64url(body_text))
        signature = _b64url(signature_text)
    except (ValueError, UnicodeDecodeError):
        raise _unauthenticated() from None
    if not isinstance(header, dict) or header.get("alg") != "RS256" or "crit" in header:
        raise _unauthenticated()
    key = keys.keys.get(header.get("kid")) if isinstance(header.get("kid"), str) else None
    if key is None or not rsa_sha256_verify(*key, f"{head_text}.{body_text}".encode(), signature):
        raise _unauthenticated()
    if not isinstance(claims, dict) or claims.get("iss") != keys.issuer:
        raise _unauthenticated()
    audience = claims.get("aud")
    if audience != AUDIENCE and audience != [AUDIENCE]:
        raise _unauthenticated()
    exp, nbf, iat = claims.get("exp"), claims.get("nbf", 0), claims.get("iat", 0)
    if not all(type(v) is int for v in (exp, nbf, iat)) or exp <= now:
        raise _unauthenticated()
    if nbf > now + CLOCK_SKEW or iat > now + CLOCK_SKEW:
        raise _unauthenticated()
    if claims.get("typ", "Bearer") != "Bearer" or not isinstance(claims.get("sid"), str):
        # An ID token, or a service account's token: neither reads the audit log.
        raise _unauthenticated()
    sub = claims.get("sub")
    if not isinstance(sub, str) or not _SUBJECT_RE.match(sub):
        raise _unauthenticated()
    roles: set[str] = set()
    for value in (claims.get("roles"), (claims.get("realm_access") or {}).get("roles")):
        if isinstance(value, list):
            roles.update(role for role in value if isinstance(role, str))
    auth_time = claims.get("auth_time")
    azp = claims.get("azp")
    return Identity(
        sub,
        frozenset(roles),
        auth_time if type(auth_time) is int else None,
        azp if isinstance(azp, str) and _SUBJECT_RE.match(azp) else None,
    )


def pseudonym(key: bytes, sub: str) -> str:
    """`P-` and 8 characters of base32(HMAC-SHA-256(key, sub)): stable per installation."""
    digest = hmac.new(key, sub.encode("utf-8"), hashlib.sha256).digest()
    return "P-" + base64.b32encode(digest).decode("ascii")[:8]


# ─────────────────────────────────────────────────────────────────────────
# requests
# ─────────────────────────────────────────────────────────────────────────


def _parse_time(text: str) -> datetime:
    if not _TIME_RE.match(text):
        raise _invalid()
    try:
        if len(text) == 10:
            return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in text else "%Y-%m-%dT%H:%M:%SZ"
        return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
    except ValueError:
        raise _invalid() from None


def time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Search:
    source: str | None = None
    event: str | None = None
    catalog_id: str | None = None
    result: str | None = None
    correlation_id: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    ticket: str | None = None
    sub: str | None = None
    pseud: str | None = None
    after: tuple[datetime, str, int] | None = None
    limit: int = PAGE_DEFAULT
    person_sub: str | None = field(default=None, repr=False)  # set from a valid ticket

    @property
    def by_person(self) -> bool:
        return bool(self.ticket or self.sub or self.pseud)


_FIELD_RULES: dict[str, Callable[[str], bool]] = {
    "source": lambda v: bool(core.SOURCE_RE.match(v)),
    "event": lambda v: bool(_EVENT_RE.match(v)),
    "catalog_id": lambda v: len(v) <= 128 and bool(_CATALOG_RE.match(v)),
    "result": lambda v: v in _RESULTS,
    "correlation_id": lambda v: bool(_CORRELATION_RE.match(v)),
    "ticket": lambda v: bool(_UUID_RE.match(v)),
    "sub": lambda v: bool(_SUBJECT_RE.match(v)),
    "pseud": lambda v: bool(_PSEUD_RE.match(v)),
}


def parse_search(values: Mapping[str, str], allowed: frozenset[str]) -> Search:
    """Filters from query parameters or an export body; unknown names are refused."""
    if set(values) & GROUPING_FIELDS:
        raise GROUPING
    if not set(values) <= allowed:
        raise _invalid()
    search = Search()
    for name, value in values.items():
        if not isinstance(value, str) or not value or len(value) > 255:
            raise _invalid()
        if name in ("from", "to"):
            setattr(search, "start" if name == "from" else "end", _parse_time(value))
        elif name == "limit":
            if not value.isdigit() or not 1 <= int(value) <= PAGE_MAX:
                raise _invalid("die Seitengröße (1 bis 500)")
            search.limit = int(value)
        elif name == "page_token":
            match = _PAGE_TOKEN_RE.match(value)
            if not match:
                raise _invalid()
            moment = datetime.fromtimestamp(int(match[1]) / 1000, tz=timezone.utc)
            search.after = (moment, match[2], int(match[3]))
        elif _FIELD_RULES[name](value):
            setattr(search, name, value)
        else:
            raise _invalid()
    if search.start and search.end and search.start >= search.end:
        raise _invalid()
    return search


def _query_values(query: str) -> dict[str, str]:
    try:
        parsed = parse_qs(
            query, keep_blank_values=True, strict_parsing=bool(query), max_num_fields=32
        )
    except ValueError:
        raise _invalid() from None
    if any(len(values) != 1 for values in parsed.values()):
        raise _invalid()
    return {name: values[0] for name, values in parsed.items()}


def _json_body(body: bytes | None) -> dict[str, Any]:
    if body is None or len(body) > MAX_JSON_BODY:
        raise _invalid("den Inhalt der Anfrage")
    try:
        document = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=core._unique_keys,
            parse_float=core._no_fraction,
            parse_constant=core._no_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _invalid("den Inhalt der Anfrage") from None
    if not isinstance(document, dict):
        raise _invalid("den Inhalt der Anfrage")
    return document


@dataclass
class PersonQuery:
    id: str
    requested_by: str
    person_sub: str
    start: datetime
    end: datetime
    reason: str
    requested_at: datetime
    state: str = "open"
    decided_by: str | None = None
    decided_at: datetime | None = None


def _reason(value: Any) -> str:
    if not isinstance(value, str):
        raise _invalid("die Begründung (20 bis 1000 Zeichen)")
    text = value.strip()
    if not REASON_MIN <= len(text) <= REASON_MAX or any(
        ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in text
    ):
        raise _invalid("die Begründung (20 bis 1000 Zeichen)")
    return text


# ─────────────────────────────────────────────────────────────────────────
# store and API
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PersonIdentity:
    """One entry of the identity map: a person's user name and upstream ids."""

    sub: str
    username: str | None
    tid: str | None
    oid: str | None


@dataclass
class Row:
    source: str
    seq: int
    prev_hash: bytes
    hash: bytes
    time: datetime
    body: dict[str, Any]


class StoreError(Exception):
    """The store could not be reached or refused a statement; answered with 503."""


class ReadStore(Protocol):
    def subjects(self) -> Iterable[str]:
        """Every `sub` that occurs in a stored event."""
        ...

    def search(self, search: Search, limit: int) -> list[Row]:
        """Rows matching the filters (and `search.person_sub`), ordered by time, source,
        seq, after `search.after`."""
        ...

    def add_query(self, query: PersonQuery, build: Callable[[int], str]) -> None:
        """Store a new query and its own event `build(next source_seq)` in one
        transaction: neither without the other."""
        ...

    def get_query(self, query_id: str) -> PersonQuery | None: ...

    def open_queries(self, since: datetime) -> list[PersonQuery]:
        """Open queries requested after `since`, oldest first."""
        ...

    def decide_query(
        self,
        query_id: str,
        state: str,
        decided_by: str,
        at: datetime,
        build: Callable[[int], str],
    ) -> bool:
        """Close an open query and append its own event `build(next source_seq)` in one
        transaction; False (and no event) when it is no longer open."""
        ...

    def append_own(self, build: Callable[[int], str]) -> int:
        """Append the canonical event `build(next source_seq)` to the chain of
        `papaia-audit`, under the source's lock; returns its seq."""
        ...

    def reads_about(self, sub: str, limit: int) -> list[tuple[datetime, PersonQuery]]:
        """Times of allowed reads, resolutions and exports with a ticket for `sub`, newest
        first."""
        ...

    def identity(self, sub: str) -> PersonIdentity | None: ...

    def sub_by_upstream(self, tid: str, oid: str) -> str | None: ...

    def put_identities(
        self, identities: list[PersonIdentity], build: Callable[[int], str]
    ) -> int:
        """Store the entries and the own event `build(next source_seq)` in one
        transaction; returns how many."""
        ...


@dataclass
class Request:
    method: str
    path: str
    query: str
    caller: str
    authorization: str | None
    correlation_id: str | None = None
    body: bytes | None = None


@dataclass
class Response:
    status: int
    body: bytes
    content_type: str = "application/json"
    correlation_id: str = ""


def new_correlation_id() -> str:
    """A UUIDv7 (RFC 9562): 48 bits of milliseconds, version, 74 random bits."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(secrets.token_bytes(10), "big")
    value = (value & ~(0xF << 76)) | (0x7 << 76)
    value = (value & ~(0x3 << 62)) | (0x2 << 62)
    return str(uuid.UUID(int=value))


def _json(status: int, document: Any) -> Response:
    return Response(
        status, json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


class ReadApi:
    def __init__(
        self,
        store: ReadStore,
        keys: Callable[[], TokenKeys | None],
        pseudonym_key: bytes,
        check: core.SubmissionCheck,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if len(pseudonym_key) < 32:
            raise ValueError("the pseudonym key must hold at least 32 bytes")
        self.store, self._keys, self._key = store, keys, pseudonym_key
        self.check, self.clock = check, clock
        token_free = json.loads(core.SCHEMA_FILE.read_text(encoding="utf-8"))
        self._token_shape = re.compile(token_free["$defs"]["token_free"]["not"]["pattern"])

    # -- entry ------------------------------------------------------------

    def handle(self, request: Request) -> Response:
        cid = request.correlation_id or ""
        if not _CORRELATION_RE.match(cid) or self._token_shape.search(cid):
            cid = new_correlation_id()
        try:
            response = self._route(request, cid)
        except (Problem, StoreError) as error:
            problem = error if isinstance(error, Problem) else UNAVAILABLE
            response = _json(problem.status, problem.document(cid))
            response.content_type = "application/problem+json"
        response.correlation_id = cid
        return response

    def _route(self, request: Request, cid: str) -> Response:
        method, path = request.method, request.path
        if (method, path) == ("GET", "/v1/me/reads"):
            if request.caller not in ME_CALLERS:
                raise _not_found()
            return self._me_reads(self._identity(request), request)
        if (method, path) == ("POST", IDENTITIES_PATH):
            # A service, proven by its client certificate; no person token.
            if request.caller not in IDENTITY_CALLERS:
                raise _not_found()
            return self._identities(request, cid)
        decision = _QUERY_PATH_RE.match(path)
        routes = {
            ("GET", "/v1/events"): self._events,
            ("POST", "/v1/exports"): self._export,
            ("GET", "/v1/person-queries"): self._open_queries,
            ("POST", "/v1/person-queries"): self._request_query,
            ("POST", IDMAP_PATH): self._idmap,
        }
        handler = routes.get((method, path))
        if handler is None and not (decision and method == "POST"):
            raise _not_found()
        if request.caller not in AUDITOR_CALLERS:
            raise _not_found()
        identity = self._identity(request)
        if AUDITOR_ROLE not in identity.roles:
            raise NO_ROLE
        if handler is not None:
            return handler(identity, request, cid)
        assert decision is not None
        return self._decide(identity, decision[1], decision[2], cid)

    def _identity(self, request: Request) -> Identity:
        keys = self._keys()
        if keys is None:
            raise UNAVAILABLE
        return check_token(request.authorization, keys, self.clock())

    def _now(self) -> datetime:
        moment = datetime.fromtimestamp(self.clock(), tz=timezone.utc)
        # Stored times carry milliseconds; a ticket's limits must compare alike.
        return moment.replace(microsecond=moment.microsecond // 1000 * 1000)

    # -- own events -------------------------------------------------------

    def _emit(self, event: str, identity: Identity, cid: str, **fields: Any) -> None:
        self._own_write(self.store.append_own, event, identity, cid, **fields)

    def _own_write(
        self,
        write: Callable[[Callable[[int], str]], Any],
        event: str,
        identity: Identity,
        cid: str,
        *,
        query_id: str | None,
        result: str = "allowed",
        effect: str = "write",
        rows: int | None = None,
        error_code: str | None = None,
        writer: str = WRITER,
        operation: str | None = None,
        object_ref: dict[str, str] | None = None,
        moment: datetime | None = None,
        catalog_id: str | None = None,
    ) -> Any:
        """Run `write` with the builder of the own event; the store appends the event in
        the transaction of its own change, so there is no change without its event.
        `object_ref` names another object than a person query (access.py); an `operation`
        event names its catalog entry (person_requests.py)."""
        stamp = time_text(moment or self._now())
        if query_id:
            object_ref = {"type": "person_query", "id": query_id}

        def build(source_seq: int) -> str:
            body = {
                "format": core.FORMAT,
                "time": stamp,
                "source_seq": source_seq,
                "correlation_id": cid,
                "writer": writer,
                "role": "server",
                "sub": identity.sub,
                "identity_kind": "person",
                "service_account": None,
                "azp": identity.azp,
                "aud": AUDIENCE,
                "operation": operation,
                "effect": effect,
                "object_ref": object_ref,
                "result": result,
                "error_code": error_code,
                "detail": {"rows": rows} if rows is not None else None,
                "event": event,
            }
            if operation is not None:
                body["operation"] = operation
            if catalog_id is not None:
                body["catalog_id"] = catalog_id
            _, canonical = self.check.check(json.dumps(body).encode("utf-8"), OWN_SOURCE)
            return canonical.decode("utf-8")

        try:
            return write(build)
        except core.Refused:
            # No answer and no change without its audit event.
            raise UNAVAILABLE from None

    # -- search and export ------------------------------------------------

    def _confirmed(self, ticket: str | None, identity: Identity) -> PersonQuery:
        """The confirmed query `ticket` of this requester, within its 60 minutes."""
        query = self.store.get_query(ticket) if ticket else None
        if query is None or query.state != "confirmed" or query.requested_by != identity.sub:
            raise PERSON_FILTER
        assert query.decided_at is not None
        if self._now() >= query.decided_at + TICKET_LIFETIME:
            raise EXPIRED
        return query

    def _ticket(self, search: Search, identity: Identity) -> PersonQuery | None:
        if not search.by_person:
            return None
        query = self._confirmed(search.ticket, identity)
        if search.sub and search.sub != query.person_sub:
            raise PERSON_FILTER
        if search.pseud and search.pseud != pseudonym(self._key, query.person_sub):
            raise PERSON_FILTER
        start, end = search.start or query.start, search.end or query.end
        if start < query.start or end > query.end or start >= end:
            raise PERSON_FILTER
        search.start, search.end, search.person_sub = start, end, query.person_sub
        return query

    def present(self, row: Row, reveal: str | None) -> dict[str, Any]:
        """A row in the stored form of `papaia.audit/1`, every person as pseudonym except
        `reveal`, the person of a ticket. `hash` covers the stored body (with the real
        identifiers)."""
        body = dict(row.body)
        sub = body.get("sub")
        if isinstance(sub, str) and sub != reveal:
            body["sub"] = pseudonym(self._key, sub)
            body["client_ip"] = None
        elif reveal is None and body.get("client_ip") is not None:
            body["client_ip"] = None
        ref = body.get("object_ref")
        if isinstance(ref, dict) and isinstance(ref.get("id"), str):
            names_person = ref.get("type") in PERSON_REF_TYPES or ref["id"] == sub
            if names_person and ref["id"] != reveal:
                body["object_ref"] = {**ref, "id": pseudonym(self._key, ref["id"])}
        body.update(
            source=row.source,
            seq=row.seq,
            prev_hash=core.hash_text(row.prev_hash),
            hash=core.hash_text(row.hash),
        )
        return body

    def _events(self, identity: Identity, request: Request, cid: str) -> Response:
        search = parse_search(_query_values(request.query), SEARCH_FIELDS | PAGE_FIELDS)
        ticket = self._ticket(search, identity)
        rows = self.store.search(search, search.limit + 1)
        person = ticket.person_sub if ticket is not None else None
        more, rows = len(rows) > search.limit, rows[: search.limit]
        if ticket is not None:
            self._emit(
                "audit_read", identity, cid, query_id=ticket.id, effect="read", rows=len(rows)
            )
        last = rows[-1] if rows else None
        token = (
            f"{int(last.time.timestamp() * 1000)}.{last.source}.{last.seq}"
            if more and last
            else None
        )
        return _json(
            200,
            {
                "format": core.FORMAT,
                "events": [self.present(row, person) for row in rows],
                "next_page_token": token,
                "pseudonymous": ticket is None,
            },
        )

    def _export(self, identity: Identity, request: Request, cid: str) -> Response:
        search = parse_search(_json_body(request.body), SEARCH_FIELDS)
        ticket = self._ticket(search, identity)
        person = ticket.person_sub if ticket is not None else None
        rows: list[Row] = []
        while len(rows) < EXPORT_MAX:
            page = self.store.search(search, min(PAGE_MAX, EXPORT_MAX - len(rows)))
            rows.extend(page)
            if len(page) < PAGE_MAX:
                break
            last = page[-1]
            search.after = (last.time, last.source, last.seq)
        self._emit(
            "audit_exported",
            identity,
            cid,
            query_id=ticket.id if ticket else None,
            effect="read",
            rows=len(rows),
        )
        lines = [
            json.dumps(self.present(row, person), ensure_ascii=False, separators=(",", ":"))
            for row in rows
        ]
        return Response(
            200, ("\n".join(lines) + "\n" if lines else "").encode("utf-8"), "application/x-ndjson"
        )

    # -- person queries ---------------------------------------------------

    def _query_view(self, query: PersonQuery, identity: Identity) -> dict[str, Any]:
        own = query.requested_by == identity.sub
        view: dict[str, Any] = {
            "id": query.id,
            "state": query.state,
            "from": time_text(query.start),
            "to": time_text(query.end),
            "reason": query.reason,
            "requested_by": pseudonym(self._key, query.requested_by),
            "requested_at": time_text(query.requested_at),
            "own": own,
        }
        # The requester may have named the person by `sub`: before the second person has
        # confirmed, nothing in the answer may link that `sub` to its pseudonym, or the
        # pseudonymous search would serve as a person filter without confirmation.
        if not own or query.state == "confirmed":
            view["person"] = pseudonym(self._key, query.person_sub)
        if query.state == "confirmed" and query.decided_at is not None:
            view["valid_until"] = time_text(query.decided_at + TICKET_LIFETIME)
        return view

    def _open_queries(self, identity: Identity, request: Request, cid: str) -> Response:
        if request.query:
            raise _invalid()
        queries = self.store.open_queries(self._now() - OPEN_LIFETIME)
        return _json(200, {"queries": [self._query_view(q, identity) for q in queries]})

    def _request_query(self, identity: Identity, request: Request, cid: str) -> Response:
        document = _json_body(request.body)
        if set(document) != REQUEST_FIELDS:
            raise _invalid("Person, Zeitraum und Begründung")
        person, start_text, end_text = document["person"], document["from"], document["to"]
        if not all(isinstance(v, str) for v in (person, start_text, end_text)):
            raise _invalid("Person, Zeitraum und Begründung")
        start, end = _parse_time(start_text), _parse_time(end_text)
        if start >= end or end - start > MAX_PERIOD:
            raise _invalid("den Zeitraum (höchstens 93 Tage)")
        reason = _reason(document["reason"])
        if _PSEUD_RE.match(person):
            matches = [s for s in self.store.subjects() if pseudonym(self._key, s) == person]
        elif _SUBJECT_RE.match(person):
            # Taken as given, whether or not it occurs in the log: the answer must not tell
            # the requester whether a person has events. A ticket for nobody reveals nothing.
            matches = [person]
        else:
            raise _invalid("die Person")
        if len(matches) != 1:
            raise _not_found()
        query = PersonQuery(
            str(uuid.uuid4()), identity.sub, matches[0], start, end, reason, self._now()
        )
        self._own_write(
            lambda build: self.store.add_query(query, build),
            "audit_person_query_requested",
            identity,
            cid,
            query_id=query.id,
        )
        return _json(201, self._query_view(query, identity))

    def _decide(self, identity: Identity, query_id: str, action: str, cid: str) -> Response:
        if not _UUID_RE.match(query_id):
            raise _not_found()
        query = self.store.get_query(query_id)
        now = self._now()
        if query is None or (query.state == "open" and now >= query.requested_at + OPEN_LIFETIME):
            raise _not_found()
        if query.state != "open":
            raise NOT_OPEN
        if action == "confirm":
            if query.requested_by == identity.sub:
                # Two persons, whatever the platform's four-eyes setting says.
                self._emit(
                    "audit_person_query_rejected",
                    identity,
                    cid,
                    query_id=query.id,
                    result="denied",
                    error_code=SELF_CONFIRM.code,
                )
                raise SELF_CONFIRM
            auth_time = identity.auth_time
            if auth_time is None or auth_time < self.clock() - FRESH_SIGN_IN:
                raise NOT_FRESH
        state = "confirmed" if action == "confirm" else "rejected"
        decided = self._own_write(
            lambda build: self.store.decide_query(query.id, state, identity.sub, now, build),
            f"audit_person_query_{state}",
            identity,
            cid,
            query_id=query.id,
        )
        if not decided:
            raise NOT_OPEN
        query.state, query.decided_by, query.decided_at = state, identity.sub, now
        return _json(200, self._query_view(query, identity))

    # -- identity map -----------------------------------------------------

    def _idmap(self, identity: Identity, request: Request, cid: str) -> Response:
        document = _json_body(request.body)
        fields = set(document)
        what = "das Ticket und genau eine Kennung (Pseudonym oder tid und oid)"
        if fields not in (IDMAP_FROM_PSEUDONYM, IDMAP_FROM_UPSTREAM) or not all(
            isinstance(value, str) for value in document.values()
        ):
            raise _invalid(what)
        if not _UUID_RE.fullmatch(document["ticket"]):
            raise _invalid(what)
        if fields == IDMAP_FROM_PSEUDONYM and not _PSEUD_RE.fullmatch(document["pseud"]):
            raise _invalid(what)
        if fields == IDMAP_FROM_UPSTREAM and not all(
            _UPSTREAM_RE.fullmatch(document[name]) for name in ("tid", "oid")
        ):
            raise _invalid(what)
        query = self._confirmed(document["ticket"], identity)
        person = query.person_sub
        pseud = pseudonym(self._key, person)
        if fields == IDMAP_FROM_PSEUDONYM:
            if document["pseud"] != pseud:
                raise PERSON_FILTER
            found = self.store.identity(person)
            answer: dict[str, Any] = {
                "pseud": pseud,
                "sub": person,
                "username": found.username if found else None,
                "tid": found.tid if found else None,
                "oid": found.oid if found else None,
            }
            operation = "idmap.pseudonym_to_identity"
        else:
            # Another person's upstream id is refused like an unknown one.
            if self.store.sub_by_upstream(document["tid"], document["oid"]) != person:
                raise PERSON_FILTER
            answer = {"pseud": pseud}
            operation = "idmap.upstream_to_pseudonym"
        self._emit(
            "pseudonym_resolved", identity, cid, query_id=query.id, effect="read",
            operation=operation,
        )
        return _json(200, answer)

    def _identity_entry(self, entry: Any) -> PersonIdentity:
        if not isinstance(entry, dict) or set(entry) != IDENTITY_FIELDS:
            raise _invalid("die Einträge der Zuordnung")
        sub, username, tid, oid = (entry[name] for name in ("sub", "username", "tid", "oid"))
        valid = (
            isinstance(sub, str)
            and bool(_SUBJECT_RE.fullmatch(sub))
            and (
                username is None
                or (
                    isinstance(username, str)
                    and 1 <= len(username) <= 255
                    and not any(ord(c) < 32 or ord(c) == 127 for c in username)
                )
            )
            and (
                (tid is None and oid is None)
                or all(isinstance(v, str) and _UPSTREAM_RE.fullmatch(v) for v in (tid, oid))
            )
        )
        texts = [v for v in (sub, username, tid, oid) if isinstance(v, str)]
        if not valid or any(self._token_shape.search(text) for text in texts):
            raise _invalid("die Einträge der Zuordnung")
        return PersonIdentity(sub, username, tid, oid)

    def _identities(self, request: Request, cid: str) -> Response:
        if request.query or request.body is None or len(request.body) > MAX_IDENTITY_BODY:
            raise _invalid("die Einträge der Zuordnung")
        try:
            document = json.loads(
                request.body.decode("utf-8"),
                object_pairs_hook=core._unique_keys,
                parse_float=core._no_fraction,
                parse_constant=core._no_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _invalid("die Einträge der Zuordnung") from None
        entries = document.get("identities") if isinstance(document, dict) else None
        if set(document if isinstance(document, dict) else ()) != {"identities"} or not (
            isinstance(entries, list) and 1 <= len(entries) <= IDENTITIES_MAX
        ):
            raise _invalid("die Einträge der Zuordnung")
        identities = [self._identity_entry(entry) for entry in entries]
        moment = time_text(self._now())
        caller = request.caller

        def build(source_seq: int) -> str:
            # The write of a service: who delivered how many entries, never an entry.
            body = {
                "format": core.FORMAT,
                "time": moment,
                "source_seq": source_seq,
                "correlation_id": cid,
                "writer": WRITER,
                "role": "server",
                "sub": caller,
                "identity_kind": "service",
                "service_account": caller,
                "azp": caller,
                "catalog_id": "papaia-audit.identity_map",
                "operation": "identity_map.put",
                "effect": "write",
                "result": "allowed",
                "detail": {"count": len(identities)},
                "event": "operation",
            }
            _, canonical = self.check.check(json.dumps(body).encode("utf-8"), OWN_SOURCE)
            return canonical.decode("utf-8")

        try:
            stored = self.store.put_identities(identities, build)
        except core.Refused:
            raise UNAVAILABLE from None
        return _json(200, {"stored": stored})

    # -- the affected person ----------------------------------------------

    def _me_reads(self, identity: Identity, request: Request) -> Response:
        if request.query:
            raise _invalid()
        reads = self.store.reads_about(identity.sub, ME_READS_MAX)
        return _json(
            200,
            {
                "reads": [
                    {
                        "time": time_text(moment),
                        "role": AUDITOR_ROLE,
                        "from": time_text(query.start),
                        "to": time_text(query.end),
                        "confirmed": True,
                    }
                    for moment, query in reads
                ]
            },
        )
