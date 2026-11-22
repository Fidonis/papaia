"""papaia-people: the exact-match people lookup of the core (`GET /v1/people/lookup`).

The assistant must find every person who holds an assistant role, also one who never
opened it, without any module getting a right on the directory (sicherheit §1.4, RE-51).
This service answers

    GET /v1/people/lookup?q=<full display name or full mail>&role=<assistant role>

with `{"people": [{"sub", "display_name"}]}` and nothing else, under these limits, all
checked here on every request:

- the bearer token is a person token (it carries `sid`) of the realm, signed with one of
  the realm's keys (RS256), for exactly the audience `papaia-people`, issued to
  `assist-gate` (the only pairing, effect x); anything else is 401 or 403;
- at most 30 requests per person and 10 minutes, and `--per-client` (default 300) per
  calling client; every admitted request counts, also an invalid one; more is 429
  `rate_limited`;
- exactly the parameters `q` and `role`, each once; `role` is `assist-member` or
  `assist-admin`; `q` is a whole display name (two to five words of letters, each at
  least two long) or a whole mail address; a prefix, a wildcard, an empty or partial
  query is 400;
- a hit is an enabled account whose display name ("first last") or mail is equal to
  `q` (case-insensitive) and that holds the role (directly, through a group or a
  composite); at most 5 hits.

Every request with a verified token is one `papaia.audit/1` row on stdout (operation
`people_lookup`, effect `read`, the role and the hit count, never the search text, a
name or a token). Operational messages go to stderr.

The directory is read as `svc-papaia-people`, which holds `realm-management`
`query-users` and `view-users` and nothing else (the realm sync keeps it so), signing in
with a client assertion (private_key_jwt, ES256); the key is mounted read-only from the
configuration directory. Only exact searches are sent (`exact=true`).

Standard library and the `openssl` command line only; runs as an unprivileged user on a
read-only file system.
"""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

REALM = "papaia"
CLIENT_ID = "svc-papaia-people"
AUDIENCE = "papaia-people"
WRITER = "papaia-people"
ROUTE = "/v1/people/lookup"
PAIRED_CLIENTS = frozenset({"assist-gate"})
LOOKUP_ROLES = frozenset({"assist-member", "assist-admin"})
PER_PERSON = 30
PER_CLIENT = 300
WINDOW_SECONDS = 600.0
MAX_HITS = 5
# Tolerance on `exp`, `iat` and `nbf` (clock skew between Keycloak and this host).
CLOCK_SKEW = 30
# An unknown key id reads the realm's keys again, at most this often.
KEYS_REFRESH_SECONDS = 30.0
KEYS_MAX_AGE_SECONDS = 300.0
ASSERTION_SECONDS = 60
MAX_RESPONSE_BYTES = 1 << 20
MAX_TOKEN = 8192
MAX_QUERY_STRING = 600
MAX_Q = 254
ACCOUNT_KEY_FILE = "private-key.pem"
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
# DER prefix of the SHA-256 DigestInfo in an RSASSA-PKCS1-v1_5 signature (RFC 8017 9.2).
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

_LETTER = r"[^\W\d_]"
_WORD_RE = re.compile(rf"{_LETTER}{{2,}}|{_LETTER}+(?:['-]{_LETTER}+)+")
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9!#$&'+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$&'+/=?^_`{|}~-]+)*"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,63}"
)
_ROLE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
_SUB_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_CLIENT_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
_KID_RE = re.compile(r"[A-Za-z0-9_.:=-]{1,128}")
_CORRELATION_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
# A correlation id shaped like a prefixed key is replaced (papaia.audit/1, token_free).
_KEY_SHAPED_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9]{16}|gh[opusr]_[A-Za-z0-9]{20}|github_pat_|"
    r"glpat-[A-Za-z0-9]{16}|xox[abeprs]-|AKIA[A-Z0-9]{16})"
)


class PeopleError(Exception):
    """A configuration or key file that cannot be used."""


class DirectoryError(Exception):
    """Keycloak could not answer the search (the body is never kept)."""


class Refused(Exception):
    """A request that is not answered: HTTP status and error code."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status, self.code = status, code


def _log(message: str) -> None:
    print(f"papaia-people: {message}", file=sys.stderr, flush=True)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(doc: object) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _uuid7() -> str:
    ms = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & (2**48 - 1)) << 80 | 7 << 76 | (rand >> 66 & 0xFFF) << 64
    value |= 2 << 62 | rand & (2**62 - 1)
    return str(uuid.UUID(int=value))


def keycloak_url(value: str) -> str:
    """https to any host, or http to a loopback address only; no path, query or user."""
    parts = urllib.parse.urlsplit(value)
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise PeopleError("the Keycloak URL must be scheme://host[:port]")
    if not parts.hostname:
        raise PeopleError("the Keycloak URL has no host")
    if parts.scheme == "https":
        return value.rstrip("/")
    if parts.scheme == "http":
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(parts.hostname).is_loopback:
                return value.rstrip("/")
    raise PeopleError("the Keycloak URL must use https (http only on a loopback address)")


# ─────────────────────────────────────────────────────────────────────────
# tokens
# ─────────────────────────────────────────────────────────────────────────


def rsa_verify(n: int, e: int, message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RS256): the whole encoded block is compared."""
    size = (n.bit_length() + 7) // 8
    if size < 256 or len(signature) != size:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    block = pow(s, e, n).to_bytes(size, "big")
    digest = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    return hmac.compare_digest(block, expected)


class Keys:
    """The realm's signing keys (JWKS), read again when a token names an unknown key."""

    def __init__(self, fetch, *, clock=time.monotonic) -> None:
        self.fetch, self.clock = fetch, clock
        self._keys: dict[str, tuple[int, int]] = {}
        self._read_at: float | None = None
        self._lock = threading.Lock()

    def _load(self) -> None:
        self._read_at = self.clock()
        doc = self.fetch()
        listed = doc.get("keys") if isinstance(doc, dict) else None
        keys = {}
        for jwk in listed if isinstance(listed, list) else []:
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
                continue
            if jwk.get("use", "sig") != "sig" or jwk.get("alg", "RS256") != "RS256":
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
                continue
            try:
                n = int.from_bytes(_b64decode(jwk["n"]), "big")
                e = int.from_bytes(_b64decode(jwk["e"]), "big")
            except (KeyError, TypeError, ValueError):
                continue
            if n.bit_length() >= 2048 and e in (3, 65537):
                keys[kid] = (n, e)
        self._keys = keys

    def key(self, kid: str) -> tuple[int, int] | None:
        with self._lock:
            now = self.clock()
            stale = self._read_at is None or now - self._read_at >= KEYS_MAX_AGE_SECONDS
            unknown = kid not in self._keys and (
                self._read_at is None or now - self._read_at >= KEYS_REFRESH_SECONDS
            )
            if stale or unknown:
                try:
                    self._load()
                except (DirectoryError, OSError, ValueError) as exc:
                    _log(f"the realm's keys cannot be read: {exc}")
            return self._keys.get(kid)


@dataclass(frozen=True)
class Principal:
    sub: str
    azp: str
    person: bool
    iat: int
    auth_time: int | None
    remaining: int


def _int_claim(claims: dict, name: str, required: bool = True) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63:
        raise Refused(401, "invalid_token")
    return value


class TokenVerifier:
    def __init__(self, keys: Keys, issuer: str, *, wall=time.time) -> None:
        self.keys, self.issuer, self.wall = keys, issuer, wall

    def verify(self, authorization: str | None) -> Principal:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise Refused(401, "invalid_token")
        token = authorization[len("Bearer ") :]
        if not 0 < len(token) <= MAX_TOKEN or token.count(".") != 2:
            raise Refused(401, "invalid_token")
        head_b64, body_b64, sig_b64 = token.split(".")
        try:
            header = json.loads(_b64decode(head_b64))
            claims = json.loads(_b64decode(body_b64))
            signature = _b64decode(sig_b64)
        except ValueError:
            raise Refused(401, "invalid_token") from None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise Refused(401, "invalid_token")
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
            raise Refused(401, "invalid_token")
        key = self.keys.key(kid)
        if key is None or not rsa_verify(*key, f"{head_b64}.{body_b64}".encode(), signature):
            raise Refused(401, "invalid_token")
        now = int(self.wall())
        exp = _int_claim(claims, "exp")
        iat = _int_claim(claims, "iat")
        nbf = _int_claim(claims, "nbf", required=False)
        auth_time = _int_claim(claims, "auth_time", required=False)
        aud = claims.get("aud")
        if aud not in (AUDIENCE, [AUDIENCE]):
            raise Refused(401, "invalid_token")
        if claims.get("iss") != self.issuer or claims.get("typ") != "Bearer":
            raise Refused(401, "invalid_token")
        if exp + CLOCK_SKEW < now or iat > now + CLOCK_SKEW or (nbf or 0) > now + CLOCK_SKEW:
            raise Refused(401, "invalid_token")
        sub, azp, sid = claims.get("sub"), claims.get("azp"), claims.get("sid")
        if not isinstance(sub, str) or not _SUB_RE.fullmatch(sub):
            raise Refused(401, "invalid_token")
        if not isinstance(azp, str) or not _CLIENT_RE.fullmatch(azp):
            raise Refused(401, "invalid_token")
        # Service tokens carry no `sid` (spike T8): `sid` tells a person from a service.
        person = isinstance(sid, str) and bool(sid)
        return Principal(sub, azp, person, iat, auth_time, max(0, exp - now))


# ─────────────────────────────────────────────────────────────────────────
# query
# ─────────────────────────────────────────────────────────────────────────


def classify(q: object) -> str | None:
    """'email' or 'name' for a whole query; None for anything partial, wild or odd."""
    if not isinstance(q, str) or not 0 < len(q) <= MAX_Q:
        return None
    if not unicodedata.is_normalized("NFC", q):
        return None
    if "@" in q:
        return "email" if _EMAIL_RE.fullmatch(q) else None
    words = q.split(" ")
    if len(q) > 128 or not 2 <= len(words) <= 5:
        return None
    return "name" if all(_WORD_RE.fullmatch(w) for w in words) else None


def parse_query(query: str) -> tuple[str, str]:
    """(q, role) of the query string, or Refused(400)."""
    if not isinstance(query, str) or len(query) > MAX_QUERY_STRING:
        raise Refused(400, "malformed_query")
    try:
        pairs = urllib.parse.parse_qsl(
            query, keep_blank_values=True, strict_parsing=bool(query), max_num_fields=4
        )
    except ValueError:
        raise Refused(400, "malformed_query") from None
    keys = [k for k, _ in pairs]
    if any(k not in ("q", "role") for k in keys):
        raise Refused(400, "unknown_parameter")
    if len(set(keys)) != len(keys):
        raise Refused(400, "duplicate_parameter")
    params = dict(pairs)
    if "q" not in params or "role" not in params:
        raise Refused(400, "missing_parameter")
    return params["q"], params["role"]


def display_name(user: dict) -> str:
    return " ".join(
        part for part in (user.get("firstName") or "", user.get("lastName") or "") if part
    )


class Directory:
    """Exact searches in the realm's accounts; `api.get(path, params)` reads the Admin API."""

    def __init__(self, api) -> None:
        self.api = api

    def _users(self, params: dict) -> list:
        params = dict(params, exact="true", briefRepresentation="true", max=str(MAX_HITS + 1))
        found = self.api.get("/users", params)
        if not isinstance(found, list):
            raise DirectoryError("malformed answer")
        return found

    def candidates(self, kind: str, q: str) -> list:
        if kind == "email":
            return self._users({"email": q})
        words = q.split(" ")
        found: list = []
        for cut in range(1, len(words)):
            found += self._users(
                {"firstName": " ".join(words[:cut]), "lastName": " ".join(words[cut:])}
            )
        return found

    def roles(self, user_id: str) -> set[str]:
        found = self.api.get(
            f"/users/{user_id}/role-mappings/realm/composite", {"briefRepresentation": "true"}
        )
        if not isinstance(found, list):
            raise DirectoryError("malformed answer")
        return {r.get("name") for r in found if isinstance(r, dict)}

    def find(self, kind: str, q: str, role: str) -> list[dict]:
        want = q.casefold()
        hits: list[dict] = []
        seen: set[str] = set()
        for user in self.candidates(kind, q):
            uid = user.get("id") if isinstance(user, dict) else None
            if not isinstance(uid, str) or not _SUB_RE.fullmatch(uid):
                raise DirectoryError("malformed answer")
            if uid in seen or user.get("enabled") is not True:
                continue
            if str(user.get("username", "")).startswith("service-account-"):
                continue
            value = (user.get("email") or "") if kind == "email" else display_name(user)
            if not isinstance(value, str) or value.casefold() != want:
                continue
            seen.add(uid)
            if role in self.roles(uid):
                hits.append({"sub": uid, "display_name": display_name(user)})
            if len(hits) >= MAX_HITS:
                break
        return hits


# ─────────────────────────────────────────────────────────────────────────
# the lookup
# ─────────────────────────────────────────────────────────────────────────


class Window:
    """Sliding window: at most `limit` events per key within `seconds`."""

    def __init__(self, limit: int, seconds: float, clock) -> None:
        self.limit, self.seconds, self.clock = limit, seconds, clock
        self._events: dict[object, collections.deque] = {}

    def retry_after(self, key: object) -> int:
        """0 when one more is admitted, else the seconds until the oldest one leaves."""
        events = self._events.get(key)
        if not events:
            return 0
        edge = self.clock() - self.seconds
        while events and events[0] <= edge:
            events.popleft()
        if not events:
            del self._events[key]
            return 0
        if len(events) < self.limit:
            return 0
        return max(1, int(events[0] - edge) + 1)

    def add(self, key: object) -> None:
        self._events.setdefault(key, collections.deque()).append(self.clock())


class Lookup:
    def __init__(
        self,
        verifier: TokenVerifier,
        directory: Directory,
        *,
        per_client: int = PER_CLIENT,
        per_person: int = PER_PERSON,
        clock=time.monotonic,
        wall=time.time,
        out=None,
    ) -> None:
        for value in (per_client, per_person):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError("the limits must be positive integers")
        self.verifier, self.directory = verifier, directory
        self.wall, self.out = wall, out or sys.stdout
        self._person = Window(per_person, WINDOW_SECONDS, clock)
        self._client = Window(per_client, WINDOW_SECONDS, clock)
        self._lock = threading.Lock()
        self._out_lock = threading.Lock()

    def handle(
        self, authorization: str | None, query: str, correlation: str | None
    ) -> tuple[int, dict, dict]:
        """(status, body, headers) of one request to the route."""
        try:
            principal = self.verifier.verify(authorization)
        except Refused as exc:
            # No verified identity, so no audit row (it would name nobody).
            return exc.status, {"error": exc.code}, {"WWW-Authenticate": 'Bearer realm="papaia"'}
        if not (
            isinstance(correlation, str)
            and _CORRELATION_RE.fullmatch(correlation)
            and not _KEY_SHAPED_RE.search(correlation)
        ):
            correlation = _uuid7()
        role, hits, headers = None, None, {}
        try:
            if principal.azp not in PAIRED_CLIENTS:
                raise Refused(403, "client_not_paired")
            if not principal.person:
                raise Refused(403, "person_token_required")
            with self._lock:
                person = (principal.azp, principal.sub)
                wait = self._person.retry_after(person) or self._client.retry_after(principal.azp)
                if wait:
                    headers["Retry-After"] = str(wait)
                    raise Refused(429, "rate_limited")
                self._person.add(person)
                self._client.add(principal.azp)
            q, wanted = parse_query(query)
            if not _ROLE_RE.fullmatch(wanted):
                raise Refused(400, "invalid_role")
            if wanted not in LOOKUP_ROLES:
                raise Refused(403, "role_not_allowed")
            role = wanted
            kind = classify(q)
            if kind is None:
                raise Refused(400, "invalid_query")
            try:
                people = self.directory.find(kind, q, role)
            except (DirectoryError, OSError, ValueError) as exc:
                _log(f"the directory did not answer: {exc}")
                raise Refused(502, "directory_unavailable") from None
            hits = len(people)
        except Refused as exc:
            result = "error" if exc.status >= 500 else "denied"
            self._audit(principal, correlation, role, result, exc.code, None)
            return exc.status, {"error": exc.code}, headers
        self._audit(principal, correlation, role, "allowed", None, hits)
        return 200, {"people": people}, headers

    def _audit(self, principal, correlation, role, result, error_code, hits) -> None:
        now = self.wall()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        row = {
            "format": "papaia.audit/1",
            "time": f"{stamp}.{int(now % 1 * 1000):03d}Z",
            "correlation_id": correlation,
            "writer": WRITER,
            "role": "server",
            "sub": principal.sub,
            "identity_kind": "person" if principal.person else "service",
            "service_account": None if principal.person else principal.azp,
            "azp": principal.azp,
            "aud": AUDIENCE,
            "catalog_id": "people.lookup",
            "operation": "people_lookup",
            "effect": "read",
            "object_ref": {"type": "role", "id": role} if role else None,
            "data_class": None,
            "result": result,
            "error_code": error_code,
            "detail": None if hits is None else {"count": hits},
            "event": "operation",
            "token_iat": principal.iat,
            "token_auth_time": principal.auth_time,
            "token_remaining_s": principal.remaining,
        }
        with self._out_lock:
            print(json.dumps(row, sort_keys=True), file=self.out, flush=True)


# ─────────────────────────────────────────────────────────────────────────
# Keycloak as svc-papaia-people
# ─────────────────────────────────────────────────────────────────────────


def _openssl(args: list[str]) -> bytes:
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, timeout=30, check=False)
    except FileNotFoundError:
        raise PeopleError("openssl not found") from None
    if result.returncode != 0:
        raise PeopleError(f"openssl {args[0]} failed")
    return result.stdout


def _check_private(path: Path) -> None:
    """A key file: regular, not a link, not readable by group or others."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PeopleError(f"{path} does not exist") from None
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise PeopleError(f"{path} must be a regular file readable by its owner only")


def _raw_signature(der: bytes) -> bytes:
    """ECDSA DER (SEQUENCE of two INTEGERs) as JOSE wants it: r || s."""
    if len(der) < 8 or der[0] != 0x30 or der[1] & 0x80:
        raise PeopleError("unexpected signature from openssl")
    pos, parts = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise PeopleError("unexpected signature from openssl")
        length = der[pos + 1]
        value = der[pos + 2 : pos + 2 + length].lstrip(b"\0")
        if len(value) > 32:
            raise PeopleError("unexpected signature from openssl")
        parts.append(value.rjust(32, b"\0"))
        pos += 2 + length
    return parts[0] + parts[1]


class AccountKey:
    """The P-256 key of `svc-papaia-people`, mounted from the configuration directory."""

    def __init__(self, folder: Path) -> None:
        self.path = folder / ACCOUNT_KEY_FILE
        _check_private(self.path)
        der = _openssl(["pkey", "-in", str(self.path), "-pubout", "-outform", "DER"])
        if len(der) != len(P256_SPKI_PREFIX) + 64 or not der.startswith(P256_SPKI_PREFIX):
            raise PeopleError("the account key is not a P-256 key")
        jwk = {"crv": "P-256", "kty": "EC", "x": _b64(der[-64:-32]), "y": _b64(der[-32:])}
        self.kid = _b64(hashlib.sha256(_canonical(jwk)).digest())

    def assertion(self, audience: str) -> str:
        issued = int(time.time())
        header = {"alg": "ES256", "kid": self.kid, "typ": "JWT"}
        claims = {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": issued,
            "exp": issued + ASSERTION_SECONDS,
        }
        signing_input = ".".join(_b64(_canonical(part)) for part in (header, claims))
        _check_private(self.path)
        with tempfile.TemporaryDirectory() as folder:
            message = Path(folder) / "message"
            message.write_bytes(signing_input.encode("ascii"))
            der = _openssl(["dgst", "-sha256", "-sign", str(self.path), str(message)])
        return f"{signing_input}.{_b64(_raw_signature(der))}"


class AdminApi:
    """The `papaia` realm's Admin API (and its keys) as `svc-papaia-people`."""

    def __init__(self, base_url: str, ctx: ssl.SSLContext | None, account_dir: Path) -> None:
        self.base_url = keycloak_url(base_url)
        self.ctx, self.account_dir = ctx, account_dir
        self._token: str | None = None
        self._until = 0.0
        self._lock = threading.Lock()

    def _open(self, req: urllib.request.Request):
        try:
            with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 401:
                self._token = None
            raise DirectoryError(f"HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise DirectoryError(f"transport: {type(exc).__name__}") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise DirectoryError("answer too large")
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            raise DirectoryError("malformed answer") from None

    def jwks(self) -> dict:
        realm = f"{self.base_url}/realms/{REALM}"
        return self._open(urllib.request.Request(f"{realm}/protocol/openid-connect/certs"))

    def _bearer(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._until:
                return self._token
            realm = f"{self.base_url}/realms/{REALM}"
            discovery = self._open(
                urllib.request.Request(f"{realm}/.well-known/openid-configuration")
            )
            issuer = discovery.get("issuer") if isinstance(discovery, dict) else None
            if not isinstance(issuer, str):
                raise DirectoryError("discovery document without issuer")
            form = urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": CLIENT_ID,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": AccountKey(self.account_dir).assertion(issuer),
                }
            ).encode()
            body = self._open(
                urllib.request.Request(f"{realm}/protocol/openid-connect/token", data=form)
            )
            if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
                raise DirectoryError("token answer without access token")
            lifetime = body.get("expires_in")
            lifetime = lifetime if isinstance(lifetime, int) and lifetime > 0 else 60
            self._token = body["access_token"]
            self._until = time.monotonic() + max(5, lifetime - 30)
            return self._token

    def get(self, path: str, params: dict):
        try:
            bearer = self._bearer()
        except PeopleError as exc:
            raise DirectoryError(str(exc)) from None
        url = f"{self.base_url}/admin/realms/{REALM}{path}?{urllib.parse.urlencode(params)}"
        return self._open(
            urllib.request.Request(
                url, headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"}
            )
        )


# ─────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "papaia-people"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # A request that does not finish its headers within this time is dropped.
    timeout = 10

    def log_message(self, fmt: str, *args) -> None:
        # The request line carries the search text: never logged.
        pass

    def _send(self, status: int, body: dict, headers: dict | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        if path == "/healthz" and not query:
            self._send(200, {"status": "ok"})
        elif path == ROUTE:
            status, body, headers = self.server.lookup.handle(
                self.headers.get("Authorization"),
                query,
                self.headers.get("X-Papaia-Correlation-Id"),
            )
            self._send(status, body, headers)
        else:
            self._send(404, {"error": "not_found"})

    def _refuse(self) -> None:
        # A body is never read: the connection ends with the answer.
        self.close_connection = True
        self._send(405, {"error": "method_not_allowed"}, {"Allow": "GET", "Connection": "close"})

    do_POST = do_PUT = do_DELETE = do_PATCH = _refuse


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def make_server(lookup: Lookup, host: str, port: int) -> _Server:
    server = _Server((host, port), _Handler)
    server.lookup = lookup
    return server


def _listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise PeopleError("--listen must be host:port")
    return host, int(port)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="people.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="serve the lookup")
    run.add_argument("--keycloak-url", required=True)
    run.add_argument("--issuer", required=True, help="the realm's public issuer URL")
    run.add_argument("--ca-file", type=Path)
    run.add_argument("--account-dir", type=Path, required=True)
    run.add_argument("--listen", default="0.0.0.0:8080")
    run.add_argument("--per-client", type=int, default=PER_CLIENT)
    health = sub.add_parser("health", help="ask the running service")
    health.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "health":
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/healthz", timeout=5) as r:
                return 0 if r.status == 200 else 1
        except (urllib.error.URLError, OSError):
            return 1
    try:
        issuer = args.issuer.rstrip("/")
        parts = urllib.parse.urlsplit(issuer)
        if parts.scheme != "https" or not parts.path.endswith(f"/realms/{REALM}"):
            raise PeopleError(f"--issuer must be https://<host>/realms/{REALM}")
        ctx = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
        api = AdminApi(args.keycloak_url, ctx, args.account_dir)
        AccountKey(args.account_dir)
        lookup = Lookup(
            TokenVerifier(Keys(api.jwks), issuer), Directory(api), per_client=args.per_client
        )
        server = make_server(lookup, *_listen(args.listen))
    except (PeopleError, ValueError, OSError) as exc:
        _log(f"cannot start: {exc}")
        return 2
    _log(f"serving {ROUTE} on {args.listen}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
