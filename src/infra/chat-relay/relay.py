"""papaia-chat-relay: the only way from the chat to a tool server outside the suite
(ADR 0029).

LibreChat sends every tool server the signed-in person's access token, which carries the
audience of every suite server the chat calls. A server outside the suite (`trust:
addon`) must never receive it. The chat therefore calls such a server here,

    POST /servers/<audience>/mcp            (MCP, streamable HTTP, JSON answers)

and the relay, on every request:

- accepts only a token of the realm (RS256, one of the realm's keys), from the realm's
  issuer, not expired (30 s clock skew), whose `aud` contains `papaia-chat-relay`, whose
  `azp` is `librechat` and that carries a session (`sid`: a person, never a service);
- looks the target up only in its list of allowed servers (`servers.json`, format
  `papaia.chat-relay-servers/1`, mounted read-only and written by the core when the
  operator allows an add-on); a missing or malformed list, or an audience not on it, is
  refused before any exchange;
- answers `initialize`, `ping` and `tools/list` itself, the tools exactly as the list
  declares them, so the add-on cannot change what the model sees; `notifications/
  initialized` and `notifications/cancelled` are acknowledged; every other method is
  refused, and so is every request from the add-on back to the chat;
- for `tools/call` checks the tool against the list and the arguments against its
  declared `input_schema`, then exchanges the chat token at the identity provider
  (OAuth 2.0 Token Exchange, RFC 8693) for a token with exactly one audience, the
  add-on's: `scope=aud-<audience>` as the list names it, `private_key_jwt` (ES256) as the
  client `papaia-chat-relay`. The answer must carry a Bearer access token and no refresh
  token; the token must check against the realm's keys, have exactly the target as `aud`,
  `papaia-chat-relay` as `azp`, the person's `sub` and at most 300 s left;
- forwards the call with `Authorization: Bearer <exchanged token>` and the correlation
  id, nothing else of the incoming request: never the chat token, not in a header, the
  body or a log line. Upstream it opens one MCP session per call (initialize,
  notifications/initialized, tools/call) and closes it.

Limits: request body 1 MiB, answer of the add-on 8 MiB, 60 s per call, 60 requests per
minute per person and add-on; nothing is retried and nothing falls back to a direct call
or to the chat token. Every failure ends the call with a JSON-RPC error that names its
reason (`token_invalid`, `not_allowed`, `exchange_refused`, `idp_unavailable`,
`upstream_unavailable`, `upstream_timeout`, `response_too_large`, `audit_unavailable`, ...).

Every request with a verified token for an add-on is one `papaia.audit/1` row on stdout:
`chat_relay.tool_call` for `tools/call`, `chat_relay.session` for the other methods,
event `operation`, role `caller`, the person's `sub`, `azp` `librechat`, the add-on's
audience, catalog entry, `tool/<add-on>/<tool>`, the declared effect and data class,
result, error code and correlation id. Never a token, the arguments or the result. A call
is not forwarded while the audit stream cannot be written. Operational messages go to
stderr.

Standard library and the `openssl` command line only; runs as an unprivileged user on a
read-only file system, keeps no token beyond the call it serves.
"""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

REALM = "papaia"
RELAY = "papaia-chat-relay"
CHAT_CLIENT = "librechat"
WRITER = "papaia-chat-relay"
VERSION = "1"
# The catalog id of rows about a target that is not on the list.
RELAY_CATALOG_ID = "papaia.chat-relay"
SERVERS_FORMAT = "papaia.chat-relay-servers/1"
MAX_SERVERS = 12
MAX_TOOLS = 100
MAX_LIST_BYTES = 4 << 20
MAX_BODY = 1 << 20
MAX_UPSTREAM = 8 << 20
MAX_IDP_ANSWER = 64 << 10
MAX_TOKEN = 8192
CALL_SECONDS = 60.0
IDP_SECONDS = 10.0
PER_PERSON = 60
MAX_HANDLERS = 128
WINDOW_SECONDS = 60.0
CLOCK_SKEW = 30
MAX_EXCHANGED_LIFETIME = 300
KEYS_REFRESH_SECONDS = 30.0
KEYS_MAX_AGE_SECONDS = 300.0
ASSERTION_SECONDS = 60
MAX_SCHEMA_DEPTH = 32
KEY_FILE = "private-key.pem"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
# DER prefix of the SHA-256 DigestInfo in an RSASSA-PKCS1-v1_5 signature (RFC 8017 9.2).
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

SESSION_METHODS = frozenset(
    {"initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list"}
)
METHODS = SESSION_METHODS | {"tools/call"}
EFFECTS = frozenset({"read", "write", "send", "delete", "check"})
DATA_CLASSES = frozenset(
    {"public", "internal", "partner_contact", "personal", "employee", "confidential",
     "special", "professional_secret"}
)  # fmt: skip

_PATH_RE = re.compile(r"/servers/([a-z][a-z0-9-]{0,59})/mcp")
_AUDIENCE_RE = re.compile(r"[a-z][a-z0-9-]{0,59}")
_SCOPE_RE = re.compile(r"aud-[a-z][a-z0-9-]{0,59}")
_ADDON_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
_CATALOG_RE = re.compile(r"[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*")
_TOOL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SUB_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,254}")
_CLIENT_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
_KID_RE = re.compile(r"[A-Za-z0-9_.:=-]{1,128}")
_CORRELATION_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_SESSION_RE = re.compile(r"[\x21-\x7e]{1,256}")
_ERROR_RE = re.compile(r"[a-z_]{1,64}")
# A correlation id shaped like a prefixed key is replaced (papaia.audit/1, token_free).
_KEY_SHAPED_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9]{16}|gh[opusr]_[A-Za-z0-9]{20}|github_pat_|"
    r"glpat-[A-Za-z0-9]{16}|xox[abeprs]-|AKIA[A-Z0-9]{16})"
)

# JSON-RPC error codes of the answers.
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
PARSE_ERROR = -32700
REFUSED = -32001
FAILED = -32002


class RelayError(Exception):
    """The relay cannot start (configuration, key)."""


class Refused(Exception):
    """A request the relay refuses: HTTP status, JSON-RPC code and reason code."""

    def __init__(self, status: int, code: str, rpc: int = REFUSED, result: str = "denied"):
        super().__init__(code)
        self.status, self.code, self.rpc, self.result = status, code, rpc, result


class ExchangeRefused(Exception):
    """The identity provider refused the exchange (4xx)."""


class IdpUnavailable(Exception):
    """The identity provider did not answer usably (transport, 5xx, malformed)."""


class UpstreamUnavailable(Exception):
    """The add-on did not answer usably."""


class UpstreamTimeout(UpstreamUnavailable):
    """The add-on did not answer within the time of the call."""


class UpstreamTooLarge(UpstreamUnavailable):
    """The add-on answered with more than the limit."""


class AuditUnavailable(Exception):
    """The audit row cannot be written."""


def _log(message: str) -> None:
    print(f"papaia-chat-relay: {message}", file=sys.stderr, flush=True)


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


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def _unique(pairs: list[tuple[str, object]]) -> dict:
    found: dict = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("duplicate key")
        found[key] = value
    return found


def strict_json(raw: bytes | str) -> object:
    """JSON without duplicate keys, NaN or infinities."""
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=_no_constant)


def correlation_id(value: object) -> str:
    """The incoming correlation id when it is valid, else a new one."""
    if (
        isinstance(value, str)
        and _CORRELATION_RE.fullmatch(value)
        and not _KEY_SHAPED_RE.search(value)
    ):
        return value
    return _uuid7()


def keycloak_url(value: str) -> str:
    """https to any host, or http to a loopback address only; no path, query or user."""
    parts = urllib.parse.urlsplit(value)
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise RelayError("the Keycloak URL must be scheme://host[:port]")
    if not parts.hostname:
        raise RelayError("the Keycloak URL has no host")
    if parts.scheme == "https":
        return value.rstrip("/")
    if parts.scheme == "http":
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(parts.hostname).is_loopback:
                return value.rstrip("/")
    raise RelayError("the Keycloak URL must use https (http only on a loopback address)")


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
                except (IdpUnavailable, OSError, ValueError) as exc:
                    _log(f"the realm's keys cannot be read: {type(exc).__name__}")
            return self._keys.get(kid)


def verify_signature(keys: Keys, token: object) -> dict:
    """The claims of a JWT signed with one of the realm's keys (RS256 only: no `none`,
    no symmetric algorithm), else Refused(401, token_invalid)."""
    if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN or token.count(".") != 2:
        raise Refused(401, "token_invalid")
    head_b64, body_b64, sig_b64 = token.split(".")
    try:
        header = strict_json(_b64decode(head_b64))
        claims = strict_json(_b64decode(body_b64))
        signature = _b64decode(sig_b64)
    except ValueError:
        raise Refused(401, "token_invalid") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise Refused(401, "token_invalid")
    kid = header.get("kid")
    if header.get("alg") != "RS256" or not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
        raise Refused(401, "token_invalid")
    key = keys.key(kid)
    if key is None or not rsa_verify(*key, f"{head_b64}.{body_b64}".encode(), signature):
        raise Refused(401, "token_invalid")
    return claims


def _int_claim(claims: dict, name: str, required: bool = True) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63:
        raise Refused(401, "token_invalid")
    return value


def _audiences(claims: dict) -> list[str]:
    aud = claims.get("aud")
    values = [aud] if isinstance(aud, str) else aud
    if not isinstance(values, list) or not values or not all(isinstance(a, str) for a in values):
        raise Refused(401, "token_invalid")
    return values


@dataclass(frozen=True)
class Principal:
    sub: str
    azp: str
    person: bool
    token: str


class TokenVerifier:
    """The chat token at the relay: signature, issuer, lifetime and the relay's audience.
    `azp` and the session are checked by the relay, which names the person in its row."""

    def __init__(self, keys: Keys, issuer: str, *, wall=time.time) -> None:
        self.keys, self.issuer, self.wall = keys, issuer, wall

    def _timely(self, claims: dict) -> int:
        now = int(self.wall())
        exp = _int_claim(claims, "exp")
        iat = _int_claim(claims, "iat")
        nbf = _int_claim(claims, "nbf", required=False)
        if exp + CLOCK_SKEW < now or iat > now + CLOCK_SKEW or (nbf or 0) > now + CLOCK_SKEW:
            raise Refused(401, "token_invalid")
        return exp - now

    def verify(self, authorization: object) -> Principal:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise Refused(401, "token_invalid")
        token = authorization[len("Bearer ") :]
        claims = verify_signature(self.keys, token)
        if claims.get("iss") != self.issuer or claims.get("typ", "Bearer") != "Bearer":
            raise Refused(401, "token_invalid")
        self._timely(claims)
        if RELAY not in _audiences(claims):
            raise Refused(401, "token_invalid")
        sub, azp, sid = claims.get("sub"), claims.get("azp"), claims.get("sid")
        if not isinstance(sub, str) or not _SUB_RE.fullmatch(sub):
            raise Refused(401, "token_invalid")
        if not isinstance(azp, str) or not _CLIENT_RE.fullmatch(azp):
            raise Refused(401, "token_invalid")
        # Service tokens carry no `sid`: `sid` tells a person from a service.
        return Principal(sub, azp, isinstance(sid, str) and bool(sid), token)

    def exchanged(self, token: object, target: str, sub: str) -> None:
        """The token the identity provider issued for `target`: the realm's signature and
        issuer, exactly `target` as audience, the relay as `azp`, the person's `sub` and
        at most MAX_EXCHANGED_LIFETIME seconds left."""
        try:
            claims = verify_signature(self.keys, token)
            remaining = self._timely(claims)
            audiences = _audiences(claims)
        except Refused:
            raise ExchangeRefused("the exchanged token does not check") from None
        if (
            claims.get("iss") != self.issuer
            or audiences != [target]
            or claims.get("azp") != RELAY
            or claims.get("sub") != sub
            or not 0 <= remaining <= MAX_EXCHANGED_LIFETIME
        ):
            raise ExchangeRefused("the exchanged token is not for this call")


# ─────────────────────────────────────────────────────────────────────────
# the list of allowed servers
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict
    effect: str
    data_class_max: str | None


@dataclass(frozen=True)
class Server:
    audience: str
    scope: str
    addon: str
    catalog_id: str
    address: str
    data_class_max: str | None
    tools: dict[str, Tool]


_LIST_KEYS = frozenset({"format", "servers"})
_SERVER_KEYS = frozenset(
    {"audience", "scope", "addon", "catalog_id", "address", "data_class_max", "tools"}
)
_TOOL_KEYS = frozenset(
    {"name", "title", "description", "input_schema", "effect", "data_class_max"}
)


def _exact(value: object, keys: frozenset[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must hold exactly {', '.join(sorted(keys))}")
    return value


def _text(value: object, limit: int, label: str) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        raise ValueError(f"{label} must be a text of 1 to {limit} characters")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"{label} holds control characters")
    return value


def _data_class(value: object, label: str) -> str | None:
    if value is not None and value not in DATA_CLASSES:
        raise ValueError(f"{label} is not a data class")
    return value


def _address(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("address must be a URL of at most 512 characters")
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("address must be an http or https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("address must carry no user, query or fragment")
    return value


def parse_servers(doc: object) -> dict[str, Server]:
    doc = _exact(doc, _LIST_KEYS, "the list")
    if doc["format"] != SERVERS_FORMAT:
        raise ValueError(f"format must be {SERVERS_FORMAT}")
    rows = doc["servers"]
    if not isinstance(rows, list) or len(rows) > MAX_SERVERS:
        raise ValueError(f"servers must be a list of at most {MAX_SERVERS}")
    servers: dict[str, Server] = {}
    for index, row in enumerate(rows):
        label = f"server {index + 1}"
        row = _exact(row, _SERVER_KEYS, label)
        audience, scope, addon = row["audience"], row["scope"], row["addon"]
        if not isinstance(audience, str) or not _AUDIENCE_RE.fullmatch(audience):
            raise ValueError(f"{label}: audience is not a name")
        if audience in (RELAY, CHAT_CLIENT) or audience in servers:
            raise ValueError(f"{label}: audience {audience} cannot be relayed or is listed twice")
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
            raise ValueError(f"{label}: scope must be one aud-* scope")
        if not isinstance(addon, str) or len(addon) > 64 or not _ADDON_RE.fullmatch(addon):
            raise ValueError(f"{label}: addon is not a name")
        catalog_id = row["catalog_id"]
        if (
            not isinstance(catalog_id, str)
            or len(catalog_id) > 128
            or not _CATALOG_RE.fullmatch(catalog_id)
        ):
            raise ValueError(f"{label}: catalog_id is not a catalog id")
        tools_rows = row["tools"]
        if not isinstance(tools_rows, list) or not 0 < len(tools_rows) <= MAX_TOOLS:
            raise ValueError(f"{label}: tools must be a list of 1 to {MAX_TOOLS}")
        tools: dict[str, Tool] = {}
        for number, tool_row in enumerate(tools_rows):
            where = f"{label}, tool {number + 1}"
            tool_row = _exact(tool_row, _TOOL_KEYS, where)
            name = tool_row["name"]
            if not isinstance(name, str) or not _TOOL_RE.fullmatch(name) or name in tools:
                raise ValueError(f"{where}: name is not a tool name or is listed twice")
            schema = tool_row["input_schema"]
            if not isinstance(schema, dict) or schema.get("type") != "object":
                raise ValueError(f"{where}: input_schema must be an object schema")
            if tool_row["effect"] not in EFFECTS:
                raise ValueError(f"{where}: effect is not one of {', '.join(sorted(EFFECTS))}")
            tools[name] = Tool(
                name,
                _text(tool_row["title"], 200, f"{where}: title"),
                _text(tool_row["description"], 2000, f"{where}: description"),
                schema,
                tool_row["effect"],
                _data_class(tool_row["data_class_max"], f"{where}: data_class_max"),
            )
        servers[audience] = Server(
            audience,
            scope,
            addon,
            catalog_id,
            _address(row["address"]),
            _data_class(row["data_class_max"], f"{label}: data_class_max"),
            tools,
        )
    return servers


class ServerList:
    """`servers.json`, read again when it changes. Missing, unreadable or malformed:
    no server at all (every call is refused)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stamp: tuple | None = None
        self._servers: dict[str, Server] = {}
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Server]:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            self._stamp = None
            return {}
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            stamp = (st.st_ino, st.st_mtime_ns, st.st_size)
            if stamp == self._stamp:
                return self._servers
            self._stamp = stamp
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_LIST_BYTES:
                raise ValueError("not a regular file of at most 4 MiB")
            return parse_servers(strict_json(fh.read(MAX_LIST_BYTES + 1)))

    def get(self, audience: str) -> Server | None:
        with self._lock:
            try:
                self._servers = self._read()
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                _log(f"the list of allowed servers is not usable: {exc}")
                self._servers = {}
            return self._servers.get(audience)


# ─────────────────────────────────────────────────────────────────────────
# arguments against the declared input schema
# ─────────────────────────────────────────────────────────────────────────


class SchemaMismatch(Exception):
    """The arguments do not match the schema, or the schema uses a keyword the relay
    does not check (fails closed)."""


_ANNOTATIONS = frozenset(
    {"title", "description", "default", "examples", "format", "$schema", "$comment",
     "deprecated", "readOnly", "writeOnly"}
)  # fmt: skip
_CHECKED = frozenset(
    {"type", "properties", "required", "additionalProperties", "items", "enum", "const",
     "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
     "minItems", "maxItems", "uniqueItems", "pattern", "anyOf", "oneOf", "allOf",
     "minProperties", "maxProperties"}
)  # fmt: skip
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: (
        isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
    ),
}


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaMismatch("schema bound is not a number")
    return value


def check_arguments(schema: object, value: object, depth: int = 0) -> None:
    """`value` against `schema`, a subset of JSON Schema (draft 2020-12) without
    references; any other keyword fails."""
    if depth > MAX_SCHEMA_DEPTH:
        raise SchemaMismatch("schema too deep")
    if schema is True:
        return
    if not isinstance(schema, dict):
        raise SchemaMismatch("schema is not an object")
    unknown = set(schema) - _ANNOTATIONS - _CHECKED
    if unknown:
        raise SchemaMismatch(f"schema keyword {sorted(unknown)[0]} is not checked")
    kind = schema.get("type")
    if kind is not None:
        kinds = kind if isinstance(kind, list) else [kind]
        if not kinds or not all(k in _TYPES for k in kinds):
            raise SchemaMismatch("unknown type")
        if not any(_TYPES[k](value) for k in kinds):
            raise SchemaMismatch("wrong type")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaMismatch("not in enum")
    if "const" in schema and value != schema["const"]:
        raise SchemaMismatch("not the constant")
    for key in ("allOf", "anyOf", "oneOf"):
        if key not in schema:
            continue
        options = schema[key]
        if not isinstance(options, list) or not options:
            raise SchemaMismatch(f"{key} must be a list")
        passed = 0
        for option in options:
            try:
                check_arguments(option, value, depth + 1)
                passed += 1
            except SchemaMismatch:
                if key == "allOf":
                    raise
        if (key == "anyOf" and passed == 0) or (key == "oneOf" and passed != 1):
            raise SchemaMismatch(f"{key} not satisfied")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get(
            "maxLength", math.inf
        ):
            raise SchemaMismatch("length out of range")
        if "pattern" in schema:
            try:
                if not re.search(schema["pattern"], value):
                    raise SchemaMismatch("pattern")
            except (re.error, TypeError):
                raise SchemaMismatch("pattern not usable") from None
    if _TYPES["number"](value):
        if "minimum" in schema and value < _number(schema["minimum"]):
            raise SchemaMismatch("below minimum")
        if "maximum" in schema and value > _number(schema["maximum"]):
            raise SchemaMismatch("above maximum")
        if "exclusiveMinimum" in schema and value <= _number(schema["exclusiveMinimum"]):
            raise SchemaMismatch("below minimum")
        if "exclusiveMaximum" in schema and value >= _number(schema["exclusiveMaximum"]):
            raise SchemaMismatch("above maximum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get(
            "maxItems", math.inf
        ):
            raise SchemaMismatch("item count out of range")
        if schema.get("uniqueItems") and len({_canonical(v) for v in value}) != len(value):
            raise SchemaMismatch("items not unique")
        if "items" in schema:
            for item in value:
                check_arguments(schema["items"], item, depth + 1)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise SchemaMismatch("properties or required malformed")
        if any(name not in value for name in required):
            raise SchemaMismatch("required property missing")
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get(
            "maxProperties", math.inf
        ):
            raise SchemaMismatch("property count out of range")
        extra = schema.get("additionalProperties", True)
        for name, item in value.items():
            if name in properties:
                check_arguments(properties[name], item, depth + 1)
            elif extra is False:
                raise SchemaMismatch("additional property")
            elif extra is not True:
                check_arguments(extra, item, depth + 1)


# ─────────────────────────────────────────────────────────────────────────
# identity provider: the exchange as papaia-chat-relay
# ─────────────────────────────────────────────────────────────────────────


_OPENSSL_SUBCOMMANDS = frozenset({"pkey", "dgst"})


def _openssl(args: list[str]) -> bytes:
    # Excepted from the conformance rule code-exec (static-exceptions.toml): the two
    # callers below pass literal options, the relay's own key file and a scratch file.
    if not args or args[0] not in _OPENSSL_SUBCOMMANDS:
        raise RelayError("unexpected openssl subcommand")
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, timeout=30, check=False)
    except FileNotFoundError:
        raise RelayError("openssl not found") from None
    if result.returncode != 0:
        raise RelayError(f"openssl {args[0]} failed")
    return result.stdout


def _check_private(path: Path) -> None:
    """A key file: regular, not a link, not readable by group or others."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise RelayError(f"{path} does not exist") from None
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise RelayError(f"{path} must be a regular file readable by its owner only")


def _raw_signature(der: bytes) -> bytes:
    """ECDSA DER (SEQUENCE of two INTEGERs) as JOSE wants it: r || s."""
    if len(der) < 8 or der[0] != 0x30 or der[1] & 0x80:
        raise RelayError("unexpected signature from openssl")
    pos, parts = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise RelayError("unexpected signature from openssl")
        length = der[pos + 1]
        value = der[pos + 2 : pos + 2 + length].lstrip(b"\0")
        if len(value) > 32:
            raise RelayError("unexpected signature from openssl")
        parts.append(value.rjust(32, b"\0"))
        pos += 2 + length
    return parts[0] + parts[1]


class ClientKey:
    """The P-256 key of the relay's client, mounted from the configuration directory."""

    def __init__(self, folder: Path) -> None:
        self.path = folder / KEY_FILE
        _check_private(self.path)
        der = _openssl(["pkey", "-in", str(self.path), "-pubout", "-outform", "DER"])
        if len(der) != len(P256_SPKI_PREFIX) + 64 or not der.startswith(P256_SPKI_PREFIX):
            raise RelayError("the relay's key is not a P-256 key")
        jwk = {"crv": "P-256", "kty": "EC", "x": _b64(der[-64:-32]), "y": _b64(der[-32:])}
        self.kid = _b64(hashlib.sha256(_canonical(jwk)).digest())

    def assertion(self, audience: str) -> str:
        issued = int(time.time())
        header = {"alg": "ES256", "kid": self.kid, "typ": "JWT"}
        claims = {
            "iss": RELAY,
            "sub": RELAY,
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: a token never follows one to another address."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class _Watch:
    """The overall deadline of one request.

    A socket timeout bounds each read only, so a server that sends one byte at a time
    could hold the request (and the token in it) for as long as it likes. At the
    deadline the watch shuts the connection down, which ends a read that is waiting;
    the caller then reports a timeout, whatever stage the answer was in."""

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self.fired = False
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._fire)
        self._timer.daemon = True

    def attach(self, sock: socket.socket) -> None:
        with self._lock:
            self._sockets.append(sock)
            if self.fired:
                _shut(sock)

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            for sock in self._sockets:
                _shut(sock)

    def __enter__(self) -> _Watch:
        self._timer.start()
        return self

    def __exit__(self, *exc) -> None:
        self._timer.cancel()


def _shut(sock: socket.socket) -> None:
    with contextlib.suppress(OSError, ValueError):
        sock.shutdown(socket.SHUT_RDWR)


def _watched(base: type, watch: _Watch) -> type:
    class Watched(base):
        def connect(self) -> None:
            super().connect()
            watch.attach(self.sock)

    return Watched


class _WatchedHTTP(urllib.request.HTTPHandler):
    def __init__(self, watch: _Watch) -> None:
        super().__init__()
        self.watch = watch

    def http_open(self, req):  # noqa: D102
        return self.do_open(_watched(http.client.HTTPConnection, self.watch), req)


class _WatchedHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, ctx: ssl.SSLContext | None, watch: _Watch) -> None:
        super().__init__(context=ctx)
        self.watch = watch

    def https_open(self, req):  # noqa: D102
        return self.do_open(
            _watched(http.client.HTTPSConnection, self.watch), req, context=self._context
        )


def _opener(ctx: ssl.SSLContext | None, watch: _Watch) -> urllib.request.OpenerDirector:
    # No proxy from the environment, no redirects, every connection under the watch.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _WatchedHTTP(watch),
        _WatchedHTTPS(ctx, watch),
        _NoRedirect(),
    )


def _fetch(ctx, req, deadline: float, limit: int):
    """(body, headers) of one request, all of it before `deadline`, the body cut at
    `limit` + 1 bytes. Raises TimeoutError when the deadline passes at any stage,
    urllib.error.HTTPError for an error status and OSError for everything else."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("no time left")
    with _Watch(deadline) as watch:
        try:
            with _opener(ctx, watch).open(req, timeout=remaining) as resp:
                raw = resp.read(limit + 1)
                headers = resp.headers
        except urllib.error.HTTPError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            if watch.fired or isinstance(exc, TimeoutError) or isinstance(
                getattr(exc, "reason", None), TimeoutError
            ):
                raise TimeoutError("no answer in time") from None
            if isinstance(exc, OSError):
                raise
            raise OSError(type(exc).__name__) from None
        if watch.fired:
            # A body without a length ends where the watch shut the connection.
            raise TimeoutError("no answer in time")
    return raw, headers


class Exchanger:
    """RFC 8693 at the realm's token endpoint, authenticated with private_key_jwt."""

    def __init__(self, token_url: str, issuer: str, key: ClientKey, ctx) -> None:
        self.token_url, self.issuer, self.key = token_url, issuer, key
        self.ctx = ctx

    def exchange(self, form: dict) -> dict:
        try:
            assertion = self.key.assertion(self.issuer)
        except RelayError as exc:
            raise IdpUnavailable(str(exc)) from None
        body = urllib.parse.urlencode(
            {
                **form,
                "client_id": RELAY,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": assertion,
            }
        ).encode()
        req = urllib.request.Request(
            self.token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
        )  # fmt: skip
        try:
            raw, _ = _fetch(self.ctx, req, time.monotonic() + IDP_SECONDS, MAX_IDP_ANSWER)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if 400 <= code < 500:
                raise ExchangeRefused(f"HTTP {code}") from None
            raise IdpUnavailable(f"HTTP {code}") from None
        except OSError as exc:
            raise IdpUnavailable(type(exc).__name__) from None
        if len(raw) > MAX_IDP_ANSWER:
            raise IdpUnavailable("answer too large")
        try:
            doc = strict_json(raw)
        except (ValueError, UnicodeDecodeError):
            raise IdpUnavailable("malformed answer") from None
        if not isinstance(doc, dict):
            raise IdpUnavailable("malformed answer")
        return doc


# ─────────────────────────────────────────────────────────────────────────
# the add-on
# ─────────────────────────────────────────────────────────────────────────


def _sse_messages(raw: bytes) -> list[object]:
    """The JSON messages of a text/event-stream body (`data:` lines of each event)."""
    messages = []
    for block in raw.decode("utf-8").replace("\r\n", "\n").split("\n\n"):
        data = [line[5:].lstrip(" ") for line in block.split("\n") if line.startswith("data:")]
        if data:
            messages.append(strict_json("\n".join(data)))
    return messages


class Upstream:
    """One MCP session per relayed call at the add-on's address, with the exchanged
    token and the correlation id only."""

    def __init__(self, ctx: ssl.SSLContext | None) -> None:
        self.ctx = ctx

    def _post(self, address, headers, payload, deadline, want_id):
        req = urllib.request.Request(
            address, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        try:
            raw, answer_headers = _fetch(self.ctx, req, deadline, MAX_UPSTREAM)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise UpstreamUnavailable(f"HTTP {code}") from None
        except TimeoutError:
            raise UpstreamTimeout("no answer in time") from None
        except OSError as exc:
            raise UpstreamUnavailable(type(exc).__name__) from None
        kind = (answer_headers.get("Content-Type") or "").split(";")[0].strip().lower()
        session = answer_headers.get("Mcp-Session-Id")
        if len(raw) > MAX_UPSTREAM:
            raise UpstreamTooLarge("answer over 8 MiB")
        if want_id is None:
            return None, session
        try:
            if kind == "text/event-stream":
                messages = _sse_messages(raw)
            else:
                messages = [strict_json(raw)]
        except (ValueError, UnicodeDecodeError):
            raise UpstreamUnavailable("malformed answer") from None
        for message in messages:
            if isinstance(message, dict) and message.get("id") == want_id and (
                "result" in message or "error" in message
            ):
                return message, session
        raise UpstreamUnavailable("no answer to the request")

    def __call__(self, address, token, correlation, name, arguments, deadline) -> dict:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Papaia-Correlation-Id": correlation,
        }
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSIONS[0],
                "capabilities": {},
                "clientInfo": {"name": RELAY, "version": VERSION},
            },
        }
        answer, session = self._post(address, headers, init, deadline, 1)
        result = answer.get("result") if isinstance(answer, dict) else None
        version = result.get("protocolVersion") if isinstance(result, dict) else None
        if not isinstance(version, str) or version not in PROTOCOL_VERSIONS:
            raise UpstreamUnavailable("initialize failed")
        headers["MCP-Protocol-Version"] = version
        if session is not None:
            if not _SESSION_RE.fullmatch(session):
                raise UpstreamUnavailable("malformed session id")
            headers["Mcp-Session-Id"] = session
        try:
            self._post(
                address, headers, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                deadline, None,
            )  # fmt: skip
            call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
            answer, _ = self._post(address, headers, call, deadline, 2)
        finally:
            if session is not None:
                self._close(address, headers, deadline)
        return answer

    def _close(self, address, headers, deadline) -> None:
        req = urllib.request.Request(address, headers=headers, method="DELETE")
        with contextlib.suppress(OSError):
            _fetch(self.ctx, req, min(time.monotonic() + 5.0, deadline), 1024)


# ─────────────────────────────────────────────────────────────────────────
# the relay
# ─────────────────────────────────────────────────────────────────────────


class Window:
    """Sliding window: at most `limit` events per key within `seconds`."""

    def __init__(self, limit: int, seconds: float, clock) -> None:
        self.limit, self.seconds, self.clock = limit, seconds, clock
        self._events: dict[object, collections.deque] = {}
        self._swept = clock()

    def admit(self, key: object) -> int:
        """0 and counted when one more is admitted, else the seconds to wait."""
        edge = self.clock() - self.seconds
        if self._swept <= edge:
            # Once per window: forget the keys whose last event has expired.
            self._events = {k: v for k, v in self._events.items() if v and v[-1] > edge}
            self._swept = self.clock()
        events = self._events.setdefault(key, collections.deque())
        while events and events[0] <= edge:
            events.popleft()
        if len(events) >= self.limit:
            return max(1, int(events[0] - edge) + 1)
        events.append(self.clock())
        return 0


@dataclass
class _Call:
    """What one request names, for its answer and its audit row."""

    principal: Principal
    correlation: str
    audience: str
    server: Server | None = None
    rid: object = None
    method: str | None = None
    tool: Tool | None = None
    tool_name: str | None = None


_ENVELOPE = frozenset({"jsonrpc", "id", "method", "params"})
_CALL_PARAMS = frozenset({"name", "arguments", "_meta"})


class Relay:
    def __init__(
        self,
        verifier: TokenVerifier,
        servers: ServerList,
        exchange,
        upstream,
        *,
        wall=time.time,
        clock=time.monotonic,
        out=None,
    ) -> None:
        self.verifier, self.servers = verifier, servers
        self.exchange, self.upstream = exchange, upstream
        self.wall, self.clock = wall, clock
        self.out = out or sys.stdout
        self._window = Window(PER_PERSON, WINDOW_SECONDS, clock)
        self._lock = threading.Lock()
        self._out_lock = threading.Lock()

    # answers ---------------------------------------------------------------
    @staticmethod
    def _error(rid, rpc: int, code: str) -> bytes:
        return json.dumps(
            {"jsonrpc": "2.0", "id": rid,
             "error": {"code": rpc, "message": code.replace("_", " "),
                       "data": {"error_code": code}}}
        ).encode()  # fmt: skip

    def handle(self, method: str, path: str, headers: dict, body: bytes):
        """(status, headers, body) of one HTTP request."""
        correlation = correlation_id(headers.get("X-Papaia-Correlation-Id"))
        out = {"X-Papaia-Correlation-Id": correlation, "Cache-Control": "no-store"}
        found = _PATH_RE.fullmatch(path)
        if found is None:
            return 404, out, self._error(None, REFUSED, "not_allowed")
        if method != "POST":
            out["Allow"] = "POST"
            return 405, out, self._error(None, REFUSED, "method_not_allowed")
        kind = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if kind != "application/json":
            return 415, out, self._error(None, REFUSED, "unsupported_media_type")
        if len(body) > MAX_BODY:
            return 413, out, self._error(None, REFUSED, "request_too_large")
        try:
            principal = self.verifier.verify(headers.get("Authorization"))
        except Refused as exc:
            # No verified identity: nobody to name in a row.
            _log(f"refused: {exc.code}")
            out["WWW-Authenticate"] = 'Bearer realm="papaia", error="invalid_token"'
            return exc.status, out, self._error(None, exc.rpc, exc.code)
        current = _Call(principal, correlation, found.group(1))
        try:
            status, answer = self._serve(current, body, out)
        except AuditUnavailable:
            return 503, out, self._error(current.rid, FAILED, "audit_unavailable")
        except Refused as exc:
            status, answer = exc.status, self._error(current.rid, exc.rpc, exc.code)
            try:
                self._audit(current, exc.result, exc.code)
            except AuditUnavailable:
                return 503, out, self._error(current.rid, FAILED, "audit_unavailable")
            return status, out, answer
        return status, out, answer

    def _serve(self, current: _Call, body: bytes, out: dict) -> tuple[int, bytes]:
        principal = current.principal
        if principal.azp != CHAT_CLIENT or not principal.person:
            raise Refused(403, "token_invalid")
        current.server = self.servers.get(current.audience)
        if current.server is None:
            raise Refused(403, "not_allowed")
        with self._lock:
            wait = self._window.admit((principal.sub, current.audience))
        if wait:
            out["Retry-After"] = str(wait)
            raise Refused(429, "rate_limited")
        try:
            request = strict_json(body)
        except (ValueError, UnicodeDecodeError):
            raise Refused(400, "invalid_request", PARSE_ERROR) from None
        if not isinstance(request, dict) or not set(request) <= _ENVELOPE:
            raise Refused(400, "invalid_request", INVALID_REQUEST)
        rid = request.get("id")
        if "id" in request and (
            isinstance(rid, bool)
            or not (isinstance(rid, int) or (isinstance(rid, str) and 0 < len(rid) <= 128))
        ):
            raise Refused(400, "invalid_request", INVALID_REQUEST)
        current.rid = rid
        name, params = request.get("method"), request.get("params", {})
        if request.get("jsonrpc") != "2.0" or not isinstance(name, str):
            raise Refused(400, "invalid_request", INVALID_REQUEST)
        if not isinstance(params, dict):
            raise Refused(200, "invalid_request", INVALID_PARAMS)
        if name not in METHODS:
            raise Refused(200, "method_not_allowed", METHOD_NOT_FOUND)
        current.method = name
        notification = name.startswith("notifications/")
        if notification == ("id" in request):
            raise Refused(400, "invalid_request", INVALID_REQUEST)
        if name == "tools/call":
            return self._tool_call(current, params)
        self._audit(current, "allowed", None)
        if notification:
            return 202, b""
        return 200, json.dumps(
            {"jsonrpc": "2.0", "id": rid, "result": self._session(current, name, params)}
        ).encode()

    def _session(self, current: _Call, name: str, params: dict) -> dict:
        if name == "ping":
            return {}
        if name == "tools/list":
            return {
                "tools": [
                    {
                        "name": tool.name,
                        "title": tool.title,
                        "description": tool.description,
                        "inputSchema": tool.input_schema,
                    }
                    for tool in current.server.tools.values()
                ]
            }
        asked = params.get("protocolVersion")
        version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": RELAY, "version": VERSION},
        }

    def _tool_call(self, current: _Call, params: dict) -> tuple[int, bytes]:
        if not set(params) <= _CALL_PARAMS:
            raise Refused(200, "invalid_request", INVALID_PARAMS)
        name = params.get("name")
        if not isinstance(name, str) or not _TOOL_RE.fullmatch(name):
            raise Refused(200, "invalid_request", INVALID_PARAMS)
        current.tool_name = name
        current.tool = current.server.tools.get(name)
        if current.tool is None:
            raise Refused(200, "tool_not_declared", INVALID_PARAMS)
        arguments = params.get("arguments", {})
        try:
            if not isinstance(arguments, dict):
                raise SchemaMismatch("arguments must be an object")
            check_arguments(current.tool.input_schema, arguments)
        except SchemaMismatch:
            raise Refused(200, "invalid_arguments", INVALID_PARAMS) from None
        # The row of this call must be writable before anything leaves the relay.
        self._audit_ready()
        started = time.monotonic()
        token = self._exchange(current)
        try:
            answer = self.upstream(
                current.server.address, token, current.correlation, name, arguments,
                started + CALL_SECONDS,
            )  # fmt: skip
        except UpstreamTimeout:
            raise Refused(504, "upstream_timeout", FAILED, "error") from None
        except UpstreamTooLarge:
            raise Refused(502, "response_too_large", FAILED, "error") from None
        except UpstreamUnavailable:
            raise Refused(502, "upstream_unavailable", FAILED, "error") from None
        result, code, outcome = self._result(answer)
        duration = int((time.monotonic() - started) * 1000)
        self._audit(current, outcome, code, {"duration_ms": duration})
        if result is None:
            return 200, self._error(current.rid, FAILED, code)
        return 200, json.dumps({"jsonrpc": "2.0", "id": current.rid, "result": result}).encode()

    @staticmethod
    def _result(answer: object) -> tuple[dict | None, str | None, str]:
        if isinstance(answer, dict) and isinstance(answer.get("result"), dict):
            result = answer["result"]
            return result, ("tool_error" if result.get("isError") is True else None), "allowed"
        return None, "upstream_error", "error"

    def _exchange(self, current: _Call) -> str:
        form = {
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": current.principal.token,
            "subject_token_type": ACCESS_TOKEN,
            "requested_token_type": ACCESS_TOKEN,
            "scope": current.server.scope,
        }
        try:
            answer = self.exchange(form)
            token = answer.get("access_token") if isinstance(answer, dict) else None
            kind = answer.get("token_type") if isinstance(answer, dict) else None
            if (
                not isinstance(token, str)
                or not isinstance(kind, str)
                or kind.lower() != "bearer"
                or "refresh_token" in answer
            ):
                raise ExchangeRefused("the answer is not one access token")
            self.verifier.exchanged(token, current.audience, current.principal.sub)
        except ExchangeRefused:
            raise Refused(502, "exchange_refused", FAILED, "error") from None
        except IdpUnavailable:
            raise Refused(503, "idp_unavailable", FAILED, "error") from None
        return token

    # audit -----------------------------------------------------------------
    def _audit_ready(self) -> None:
        with self._out_lock:
            try:
                self.out.write("")
                self.out.flush()
            except (OSError, ValueError):
                _log("the audit stream cannot be written")
                raise Refused(503, "audit_unavailable", FAILED, "error") from None

    def _audit(self, current: _Call, result: str, error_code, detail=None) -> None:
        server = current.server
        tool_call = current.method == "tools/call"
        if server is None:
            ref = {"type": "audience", "id": current.audience}
        elif tool_call and current.tool_name:
            ref = {"type": "tool", "id": f"{server.addon}/{current.tool_name}"}
        else:
            ref = {"type": "addon", "id": server.addon}
        now = self.wall()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        principal = current.principal
        row = {
            "format": "papaia.audit/1",
            "time": f"{stamp}.{int(now % 1 * 1000):03d}Z",
            "correlation_id": current.correlation,
            "writer": WRITER,
            "role": "caller",
            "sub": principal.sub,
            "identity_kind": "person" if principal.person else "service",
            "service_account": None if principal.person else principal.azp,
            "azp": principal.azp,
            "aud": server.audience if server else None,
            "catalog_id": server.catalog_id if server else RELAY_CATALOG_ID,
            "operation": "chat_relay.tool_call" if tool_call else "chat_relay.session",
            "effect": current.tool.effect if current.tool else "read",
            "object_ref": ref,
            "data_class": current.tool.data_class_max if current.tool else None,
            "result": result,
            "error_code": error_code,
            "detail": detail,
            "event": "operation",
        }
        line = json.dumps(row, sort_keys=True) + "\n"
        with self._out_lock:
            try:
                self.out.write(line)
                self.out.flush()
            except (OSError, ValueError):
                _log("the audit stream cannot be written")
                raise AuditUnavailable() from None


# ─────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "papaia-chat-relay"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # A request that does not finish its headers within this time is dropped.
    timeout = 10

    def log_message(self, fmt: str, *args) -> None:
        # Request lines and headers are never logged.
        pass

    def _send(self, status: int, headers: dict, body: bytes) -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {}, b'{"status":"ok"}')
            return
        self._unread("GET")

    def _unread(self, method: str) -> None:
        # A body is never read: the connection ends with the answer.
        self.close_connection = True
        status, headers, body = self.server.relay.handle(method, self.path, {}, b"")
        headers["Connection"] = "close"
        self._send(status, headers, body)

    def do_DELETE(self) -> None:
        self._unread("DELETE")

    do_PUT = do_PATCH = do_DELETE

    def do_POST(self) -> None:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._send(411, {"Connection": "close"}, b"")
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            self.close_connection = True
            self._send(411, {"Connection": "close"}, b"")
            return
        if int(length) > MAX_BODY:
            self.close_connection = True
            status, headers, body = self.server.relay.handle(
                "POST", self.path, {"Content-Type": "application/json"}, b"x" * (MAX_BODY + 1)
            )
            headers["Connection"] = "close"
            self._send(status, headers, body)
            return
        raw = self.rfile.read(int(length))
        headers = {
            key: self.headers.get(key)
            for key in ("Authorization", "Content-Type", "X-Papaia-Correlation-Id")
            if self.headers.get(key) is not None
        }
        status, out, body = self.server.relay.handle("POST", self.path, headers, raw)
        self._send(status, out, body)


_BUSY_BODY = Relay._error(None, FAILED, "busy")
_BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
    b"Content-Length: " + str(len(_BUSY_BODY)).encode() + b"\r\n"
    b"Retry-After: 1\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + _BUSY_BODY
)


class _Server(http.server.ThreadingHTTPServer):
    """One thread per connection, at most `max_handlers` at a time; a connection
    beyond that is answered 503 `busy` at once and closed."""

    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, handler, max_handlers: int) -> None:
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(max_handlers)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.settimeout(1.0)
                request.sendall(_BUSY)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(relay: Relay, host: str, port: int, max_handlers: int = MAX_HANDLERS) -> _Server:
    server = _Server((host, port), _Handler, max_handlers)
    server.relay = relay
    return server


def _listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise RelayError("--listen must be host:port")
    return host, int(port)


def _jwks_fetch(base_url: str, ctx):
    url = f"{base_url}/realms/{REALM}/protocol/openid-connect/certs"

    def fetch() -> dict:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            raw, _ = _fetch(ctx, req, time.monotonic() + IDP_SECONDS, MAX_IDP_ANSWER)
        except OSError as exc:
            raise IdpUnavailable(type(exc).__name__) from None
        if len(raw) > MAX_IDP_ANSWER:
            raise IdpUnavailable("answer too large")
        return strict_json(raw)

    return fetch


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="relay.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="serve the relay")
    run.add_argument("--keycloak-url", required=True)
    run.add_argument("--issuer", required=True, help="the realm's public issuer URL")
    run.add_argument("--ca-file", type=Path, help="CA bundle for https to Keycloak and add-ons")
    run.add_argument("--key-dir", type=Path, required=True)
    run.add_argument("--servers-file", type=Path, required=True)
    run.add_argument("--listen", default="0.0.0.0:8080")
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
            raise RelayError(f"--issuer must be https://<host>/realms/{REALM}")
        base = keycloak_url(args.keycloak_url)
        ctx = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
        key = ClientKey(args.key_dir)
        token_url = f"{base}/realms/{REALM}/protocol/openid-connect/token"
        relay = Relay(
            TokenVerifier(Keys(_jwks_fetch(base, ctx)), issuer),
            ServerList(args.servers_file),
            Exchanger(token_url, issuer, key, ctx).exchange,
            Upstream(ctx),
        )
        server = make_server(relay, *_listen(args.listen))
    except (RelayError, ValueError, OSError) as exc:
        _log(f"cannot start: {exc}")
        return 2
    _log(f"serving /servers/<audience>/mcp on {args.listen}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
