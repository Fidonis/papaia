"""papaia-replay: deletions in chat and model gateway for the core start gate.

After a restored snapshot, papaia-lifecycle replays the erasure journal (docs/lifecycle.md,
"Core start gate"). Its container holds `manage-users` of the identity provider, so it
must not reach the databases of chat and model gateway as well. This service does those
deletions on its behalf and does nothing else (docs/replay.md):

* One endpoint, `POST /replay` over mutual TLS, answered only for the client certificate
  `CN=papaia-lifecycle` of the platform PKI. Any other caller gets 403.
* Three fixed request kinds, `{"kind": ..., "sub"?: ..., "key_id"?: ...}`, unknown
  fields refused:
  - `erase_subject` (`sub`): the person's chat account and every chat object filed
    under it, and the gateway's usage rows of the person (end users named by the `sub`
    or the chat account id);
  - `chat_sessions_reset`: every stored chat session of every account;
  - `key_revoke` (`key_id`): one gateway key, by the id the gateway stores.
* The answer is `{"counts": {name: number}}`: no content, no account data.
* One `papaia.audit/1` line on stdout per request, with the counts and the correlation
  id papaia-lifecycle sends.

Chat: the chat database is reached on its own network as the fixed role
`papaia-replay-chat` (made by `papaia-ctl start`), which may find and remove documents of
the named collections only. The client below speaks the database's wire protocol (OP_MSG,
SCRAM-SHA-256) with the standard library alone. It reads only the `_id` of the accounts
with the person's `sub`; it never reads a conversation or a message.

Gateway: the management routes `/customer/info`, `/customer/delete` and `/key/delete` on
the gateway's own network with the key in `gateway-key` (docs/replay.md, residual risk).

The service holds no `erasure-hmac`: papaia-lifecycle resolves journal entries to the
`sub` and sends that.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Self

WRITER = "papaia-replay"
CALLER = "papaia-lifecycle"
CORRELATION_HEADER = "X-Papaia-Correlation-Id"
KINDS = ("erase_subject", "chat_sessions_reset", "key_revoke")
MAX_BODY_BYTES = 1024
MAX_ANSWER_BYTES = 1 << 20
# The same forms papaia-lifecycle sends (lifecycle.py, _SUB_RE and _KEY_REF_RE).
_SUB_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CORRELATION_RE = re.compile(r"[A-Za-z0-9-]{1,64}")

CHAT_DATABASE = "LibreChat"
CHAT_LOGIN = "papaia-replay-chat"
ACCOUNTS = "users"
ACCOUNT_SUB_FIELD = "openidId"
# (collection, field naming the account, count name). The account goes last, so a
# request that fails half-way finds it again when it is repeated. papaia-ctl grants the
# role exactly these collections (lib/replay_access.py, CHAT_COLLECTIONS).
CHAT_OBJECTS: tuple[tuple[str, str, str], ...] = (
    ("conversations", "user", "chat_conversations"),
    ("messages", "user", "chat_messages"),
    ("files", "user", "chat_files"),
    ("presets", "user", "chat_presets"),
    ("prompts", "author", "chat_prompts"),
    ("promptgroups", "author", "chat_prompt_groups"),
    ("sharedlinks", "user", "chat_shared_links"),
    ("conversationtags", "user", "chat_tags"),
    ("toolcalls", "user", "chat_tool_calls"),
    ("memoryentries", "userId", "chat_memories"),
    ("pluginauths", "userId", "chat_plugin_settings"),
    ("keys", "userId", "chat_keys"),
    ("balances", "user", "chat_balances"),
    ("transactions", "user", "chat_transactions"),
    ("tokens", "userId", "chat_tokens"),
    ("sessions", "user", "chat_sessions"),
)
SESSIONS = "sessions"
MAX_ACCOUNTS = 16


class ReplayError(Exception):
    """A backend could not be reached or refused; the message names no person."""


class BadRequest(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _log(message: str) -> None:
    print(f"papaia-replay: {message}", file=sys.stderr, flush=True)


# ─────────────────────────────────────────────────────────────────────────
# request
# ─────────────────────────────────────────────────────────────────────────


def _unique(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise BadRequest("duplicate_field")
    return dict(pairs)


def _no_constant(_: str):
    raise BadRequest("malformed_json")


def parse_job(raw: bytes) -> dict:
    """The job of one request; BadRequest for anything but the three fixed forms."""
    if len(raw) > MAX_BODY_BYTES:
        raise BadRequest("too_large")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                         parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BadRequest("malformed_json") from None
    if not isinstance(doc, dict):
        raise BadRequest("malformed_json")
    kind = doc.get("kind")
    if kind not in KINDS:
        raise BadRequest("unknown_kind")
    allowed = {"erase_subject": {"kind", "sub"}, "chat_sessions_reset": {"kind"},
               "key_revoke": {"kind", "key_id"}}[kind]
    if set(doc) != allowed:
        raise BadRequest("unknown_or_missing_field")
    if "sub" in doc and not (isinstance(doc["sub"], str) and _SUB_RE.fullmatch(doc["sub"])):
        raise BadRequest("malformed_sub")
    if "key_id" in doc and not (
        isinstance(doc["key_id"], str) and _KEY_ID_RE.fullmatch(doc["key_id"])
    ):
        raise BadRequest("malformed_key_id")
    return doc


# ─────────────────────────────────────────────────────────────────────────
# BSON (the subset the commands and their answers use)
# ─────────────────────────────────────────────────────────────────────────


class ObjectId(bytes):
    """A 12-byte object id."""

    def __new__(cls, value: bytes) -> Self:
        if len(value) != 12:
            raise ValueError("an object id has 12 bytes")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"ObjectId({self.hex()})"


class Binary(bytes):
    """Binary data of subtype 0 (the SASL payloads)."""


_INT32 = range(-(1 << 31), 1 << 31)


def _cstring(text: str) -> bytes:
    data = text.encode("utf-8")
    if b"\x00" in data:
        raise ValueError("a BSON key holds no NUL")
    return data + b"\x00"


def _element(key: str, value: object) -> bytes:
    name = _cstring(key)
    if isinstance(value, bool):
        return b"\x08" + name + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        if value in _INT32:
            return b"\x10" + name + struct.pack("<i", value)
        return b"\x12" + name + struct.pack("<q", value)
    if isinstance(value, float):
        return b"\x01" + name + struct.pack("<d", value)
    if isinstance(value, str):
        data = value.encode("utf-8") + b"\x00"
        return b"\x02" + name + struct.pack("<i", len(data)) + data
    if isinstance(value, ObjectId):
        return b"\x07" + name + bytes(value)
    if isinstance(value, bytes):
        return b"\x05" + name + struct.pack("<i", len(value)) + b"\x00" + bytes(value)
    if isinstance(value, dict):
        return b"\x03" + name + bson_encode(value)
    if isinstance(value, (list, tuple)):
        return b"\x04" + name + bson_encode({str(i): v for i, v in enumerate(value)})
    if value is None:
        return b"\x0a" + name
    raise TypeError(f"no BSON form for {type(value).__name__}")


def bson_encode(doc: dict) -> bytes:
    body = b"".join(_element(k, v) for k, v in doc.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _read_cstring(data: bytes, pos: int) -> tuple[str, int]:
    end = data.index(b"\x00", pos)
    return data[pos:end].decode("utf-8"), end + 1


def _decode(data: bytes, pos: int, end: int, depth: int) -> dict:
    if depth > 32:
        raise ValueError("BSON nested too deep")
    doc: dict = {}
    while pos < end - 1:
        kind = data[pos]
        key, pos = _read_cstring(data, pos + 1)
        if kind == 0x01:
            doc[key] = struct.unpack_from("<d", data, pos)[0]
            pos += 8
        elif kind == 0x02:
            (size,) = struct.unpack_from("<i", data, pos)
            if size < 1 or pos + 4 + size > end:
                raise ValueError("BSON string out of bounds")
            doc[key] = data[pos + 4 : pos + 3 + size].decode("utf-8")
            pos += 4 + size
        elif kind in (0x03, 0x04):
            (size,) = struct.unpack_from("<i", data, pos)
            if size < 5 or pos + size > end:
                raise ValueError("BSON document out of bounds")
            sub = _decode(data, pos + 4, pos + size, depth + 1)
            doc[key] = sub if kind == 0x03 else list(sub.values())
            pos += size
        elif kind == 0x05:
            (size,) = struct.unpack_from("<i", data, pos)
            if size < 0 or pos + 5 + size > end:
                raise ValueError("BSON binary out of bounds")
            doc[key] = Binary(data[pos + 5 : pos + 5 + size])
            pos += 5 + size
        elif kind == 0x07:
            doc[key] = ObjectId(data[pos : pos + 12])
            pos += 12
        elif kind == 0x08:
            doc[key] = data[pos] == 1
            pos += 1
        elif kind in (0x09, 0x12):
            doc[key] = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        elif kind == 0x11:
            doc[key] = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
        elif kind == 0x10:
            doc[key] = struct.unpack_from("<i", data, pos)[0]
            pos += 4
        elif kind == 0x13:
            doc[key] = bytes(data[pos : pos + 16])
            pos += 16
        elif kind in (0x0A, 0x06, 0x7F, 0xFF):
            doc[key] = None
        else:
            raise ValueError(f"BSON type 0x{kind:02x} is not read")
    if pos != end - 1 or data[end - 1] != 0:
        raise ValueError("BSON document is malformed")
    return doc


def bson_decode(data: bytes) -> dict:
    if len(data) < 5:
        raise ValueError("BSON document too short")
    (size,) = struct.unpack_from("<i", data, 0)
    if size != len(data):
        raise ValueError("BSON size does not match")
    return _decode(data, 4, size, 0)


# ─────────────────────────────────────────────────────────────────────────
# chat database: OP_MSG and SCRAM-SHA-256
# ─────────────────────────────────────────────────────────────────────────

OP_MSG = 2013
MAX_MESSAGE_BYTES = 16 << 20


def op_msg(request_id: int, doc: dict) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + bson_encode(doc)
    return struct.pack("<iiii", 16 + len(body), request_id, 0, OP_MSG) + body


def read_op_msg(recv) -> dict:
    """The body of one OP_MSG answer; `recv(n)` returns exactly n bytes."""
    length, _, _, opcode = struct.unpack("<iiii", recv(16))
    if opcode != OP_MSG or not 21 <= length <= MAX_MESSAGE_BYTES:
        raise ReplayError("chat database: unexpected answer")
    payload = recv(length - 16)
    (flags,) = struct.unpack_from("<I", payload, 0)
    if flags & 1:  # checksumPresent: the last four bytes
        payload = payload[:-4]
    if payload[4] != 0:
        raise ReplayError("chat database: unexpected answer section")
    try:
        return bson_decode(payload[5:])
    except (ValueError, struct.error, UnicodeDecodeError):
        raise ReplayError("chat database: malformed answer") from None


class Scram:
    """The client side of SCRAM-SHA-256 (RFC 5802, RFC 7677)."""

    def __init__(self, user: str, password: str, nonce: str | None = None) -> None:
        if not password.isascii() or not password.isprintable():
            # SASLprep is the identity for printable ASCII; nothing else is accepted.
            raise ReplayError("the chat password must be printable ASCII")
        self.user = user.replace("=", "=3D").replace(",", "=2C")
        self.password = password.encode()
        self.nonce = nonce or base64.b64encode(secrets.token_bytes(24)).decode()
        self.bare = f"n={self.user},r={self.nonce}"
        self.server_signature = b""

    def first(self) -> bytes:
        return f"n,,{self.bare}".encode()

    def final(self, server_first: bytes) -> bytes:
        text = server_first.decode()
        fields = dict(part.split("=", 1) for part in text.split(",") if "=" in part)
        if not fields.get("r", "").startswith(self.nonce) or "s" not in fields:
            raise ReplayError("chat database: SCRAM nonce mismatch")
        iterations = int(fields.get("i", "0"))
        if not 4096 <= iterations <= 1_000_000:
            raise ReplayError("chat database: SCRAM iteration count refused")
        salted = hashlib.pbkdf2_hmac(
            "sha256", self.password, base64.b64decode(fields["s"]), iterations
        )
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        without_proof = f"c=biws,r={fields['r']}"
        message = f"{self.bare},{text},{without_proof}".encode()
        signature = hmac.new(stored, message, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        self.server_signature = hmac.new(server_key, message, hashlib.sha256).digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}".encode()

    def verify(self, server_final: bytes) -> None:
        text = server_final.decode()
        if not text.startswith("v=") or not hmac.compare_digest(
            base64.b64decode(text[2:]), self.server_signature
        ):
            raise ReplayError("chat database: the server signature does not verify")


class Mongo:
    """One connection to the chat database as `papaia-replay-chat`, opened per job."""

    def __init__(self, host: str, port: int, password_file: Path, *, timeout: float = 15) -> None:
        self.host, self.port, self.password_file, self.timeout = host, port, password_file, timeout
        self._sock: socket.socket | None = None
        self._id = 0

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ReplayError("chat database: connection closed")
            buf += chunk
        return buf

    def _raw(self, doc: dict) -> dict:
        self._id += 1
        self._sock.sendall(op_msg(self._id, doc))
        return read_op_msg(self._recv)

    def _password(self) -> str:
        try:
            text = self.password_file.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            raise ReplayError("chat database: the password file cannot be read") from None
        if not 16 <= len(text) <= 256:
            raise ReplayError("chat database: the password file is malformed")
        return text

    def open(self) -> None:
        self.close()
        try:
            self._sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as exc:
            raise ReplayError(f"chat database not reachable ({exc.__class__.__name__})") from None
        scram = Scram(CHAT_LOGIN, self._password())
        answer = self._raw({
            "saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": scram.first(),
            "options": {"skipEmptyExchange": True}, "$db": "admin",
        })  # fmt: skip
        self._ok(answer, "sign-in")
        answer = self._raw({
            "saslContinue": 1, "conversationId": answer.get("conversationId"),
            "payload": scram.final(bytes(answer.get("payload") or b"")), "$db": "admin",
        })  # fmt: skip
        self._ok(answer, "sign-in")
        scram.verify(bytes(answer.get("payload") or b""))
        while not answer.get("done"):
            answer = self._raw({"saslContinue": 1, "conversationId": answer.get("conversationId"),
                                "payload": b"", "$db": "admin"})
            self._ok(answer, "sign-in")

    @staticmethod
    def _ok(answer: dict, what: str) -> None:
        if answer.get("ok") != 1 and answer.get("ok") != 1.0:
            code = answer.get("codeName") if isinstance(answer.get("codeName"), str) else "error"
            raise ReplayError(f"chat database refused the {what} ({code[:64]})")

    def command(self, doc: dict) -> dict:
        if self._sock is None:
            self.open()
        try:
            answer = self._raw({**doc, "$db": CHAT_DATABASE})
        except OSError as exc:
            self.close()
            raise ReplayError(f"chat database: {exc.__class__.__name__}") from None
        self._ok(answer, next(iter(doc)))
        return answer

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class Chat:
    """The core adapter `core-chat`: finds a person's chat accounts by the `sub` and
    removes them with everything filed under them. Reads `_id` only."""

    def __init__(self, db) -> None:
        self.db = db

    def accounts(self, sub: str) -> list[ObjectId]:
        answer = self.db.command({
            "find": ACCOUNTS, "filter": {ACCOUNT_SUB_FIELD: sub}, "projection": {"_id": 1},
            "limit": MAX_ACCOUNTS + 1, "singleBatch": True,
        })  # fmt: skip
        batch = (answer.get("cursor") or {}).get("firstBatch") or []
        ids = [row.get("_id") for row in batch if isinstance(row, dict)]
        if len(ids) > MAX_ACCOUNTS or not all(isinstance(i, ObjectId) for i in ids):
            raise ReplayError("chat database: unexpected accounts for one person")
        return ids

    def _delete(self, collection: str, flt: dict) -> int:
        answer = self.db.command(
            {"delete": collection, "deletes": [{"q": flt, "limit": 0}], "ordered": True}
        )
        if answer.get("writeErrors"):
            raise ReplayError(f"chat database refused a delete in {collection}")
        count = answer.get("n")
        if not isinstance(count, int) or count < 0:
            raise ReplayError("chat database: a delete answered without a count")
        return count

    def erase(self, accounts: list[ObjectId]) -> dict[str, int]:
        if not accounts:
            return {name: 0 for _, _, name in CHAT_OBJECTS} | {"chat_accounts": 0}
        # LibreChat files some objects under the id as a string, others as an object id.
        refs = [*accounts, *(a.hex() for a in accounts)]
        counts = {name: self._delete(coll, {field: {"$in": refs}})
                  for coll, field, name in CHAT_OBJECTS}
        counts["chat_accounts"] = self._delete(ACCOUNTS, {"_id": {"$in": list(accounts)}})
        return counts

    def reset_sessions(self) -> dict[str, int]:
        return {"chat_sessions": self._delete(SESSIONS, {})}

    def close(self) -> None:
        close = getattr(self.db, "close", None)
        if close is not None:
            close()


# ─────────────────────────────────────────────────────────────────────────
# model gateway
# ─────────────────────────────────────────────────────────────────────────


class Gateway:
    """The core adapter `model-gateway`: the gateway's management routes for end-user
    usage and keys, nothing else."""

    PATHS = ("/customer/info?", "/customer/delete", "/key/delete")

    def __init__(self, base_url: str, key_file: Path) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in (
            "", "/"
        ) or parts.query or parts.username:
            raise ValueError("the gateway URL must be http(s)://host:port")
        self.base, self.key_file = base_url.rstrip("/"), key_file
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _key(self) -> str:
        try:
            key = self.key_file.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            raise ReplayError("gateway: the key file cannot be read") from None
        if not 8 <= len(key) <= 512 or not key.isprintable() or " " in key:
            raise ReplayError("gateway: the key file is malformed")
        return key

    def _call(self, method: str, path: str, body: dict | None = None) -> int:
        if not path.startswith(self.PATHS):
            raise ReplayError("gateway: route not allowed")
        req = urllib.request.Request(
            self.base + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={"Authorization": f"Bearer {self._key()}",
                     "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(req, timeout=30) as resp:
                resp.read(MAX_ANSWER_BYTES)  # drained, never read further or kept
                return resp.status
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code
        except OSError as exc:
            raise ReplayError(f"gateway not reachable ({exc.__class__.__name__})") from None

    def erase(self, end_users: list[str]) -> dict[str, int]:
        found = []
        for user in end_users:
            status = self._call("GET", "/customer/info?" + urllib.parse.urlencode(
                {"end_user_id": user}))
            if status == 200:
                found.append(user)
            elif status not in (400, 404):
                raise ReplayError(f"gateway refused to look up an end user ({status})")
        if found:
            status = self._call("POST", "/customer/delete", {"user_ids": found})
            if status != 200:
                raise ReplayError(f"gateway refused to delete end users ({status})")
        return {"gateway_end_users": len(found)}

    def revoke_key(self, key_id: str) -> dict[str, int]:
        status = self._call("POST", "/key/delete", {"keys": [key_id]})
        if status == 200:
            return {"gateway_keys": 1}
        if status == 404:  # gone already
            return {"gateway_keys": 0}
        raise ReplayError(f"gateway refused to delete a key ({status})")


# ─────────────────────────────────────────────────────────────────────────
# jobs, audit, server
# ─────────────────────────────────────────────────────────────────────────


class Replayer:
    """Runs one job; `chat` and `gateway` are None where the installation has neither
    (the profile is off): there is nothing of it to delete."""

    def __init__(self, chat_factory, gateway, out=None) -> None:
        self.chat_factory, self.gateway = chat_factory, gateway
        self.out = out or sys.stdout

    def run(self, job: dict) -> dict[str, int]:
        kind = job["kind"]
        counts: dict[str, int] = {}
        if kind == "key_revoke":
            if self.gateway is not None:
                counts |= self.gateway.revoke_key(job["key_id"])
            return counts
        chat = self.chat_factory() if self.chat_factory is not None else None
        try:
            if kind == "chat_sessions_reset":
                if chat is not None:
                    counts |= chat.reset_sessions()
                return counts
            accounts = chat.accounts(job["sub"]) if chat is not None else []
            # The gateway first: once the chat account is gone, its id is not known.
            if self.gateway is not None:
                counts |= self.gateway.erase([job["sub"], *(a.hex() for a in accounts)])
            if chat is not None:
                counts |= chat.erase(accounts)
            return counts
        finally:
            if chat is not None:
                chat.close()

    def audit(self, correlation: str, job: dict | None, caller: str | None, *,
              result: str = "allowed", error_code: str | None = None,
              counts: dict | None = None) -> None:
        now = time.time()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        kind = job["kind"] if job else None
        ref = None
        if job and "sub" in job:
            ref = {"type": "user", "id": job["sub"]}
        elif job and "key_id" in job:
            ref = {"type": "model_key", "id": job["key_id"]}
        row = {
            "format": "papaia.audit/1",
            "time": f"{stamp}.{int(now % 1 * 1000):03d}Z",
            "correlation_id": correlation,
            "writer": WRITER,
            "role": "caller",
            "sub": WRITER,
            "identity_kind": "service",
            "service_account": WRITER,
            "azp": caller,
            "aud": None,
            "catalog_id": None,
            "operation": f"replay.{kind or 'request'}",
            "effect": "delete",
            "object_ref": ref,
            "data_class": None,
            "result": result,
            "error_code": error_code,
            "detail": {"kind": kind, "counts": counts} if counts is not None else {"kind": kind},
            "event": "operation",
        }
        print(json.dumps(row, sort_keys=True), file=self.out, flush=True)


def _peer_name(cert: dict | None) -> str | None:
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def server_context(tls_dir: Path) -> ssl.SSLContext:
    """Server side of the mutual TLS: the platform CA, a client certificate required."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(tls_dir / "ca.crt"))
    ctx.load_cert_chain(str(tls_dir / "tls.crt"), str(tls_dir / "tls.key"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_server(host: str, port: int, ctx: ssl.SSLContext, replayer: Replayer):
    """A one-request-at-a-time HTTPS server: jobs run in order, never in parallel."""

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = WRITER
        sys_version = ""
        timeout = 30
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, doc: dict) -> None:
            body = json.dumps(doc, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_POST(self) -> None:
            correlation = self.headers.get(CORRELATION_HEADER, "")
            if not _CORRELATION_RE.fullmatch(correlation):
                correlation = str(uuid.uuid4())
            caller = _peer_name(self.connection.getpeercert())
            if caller != CALLER:
                replayer.audit(correlation, None, caller, result="denied",
                               error_code="caller_not_allowed")
                self._send(403, {"error": "caller_not_allowed"})
                return
            if self.path != "/replay":
                self._send(404, {"error": "not_found"})
                return
            try:
                if self.headers.get_content_type() != "application/json":
                    raise BadRequest("content_type")
                length = int(self.headers.get("Content-Length", ""))
                if not 0 < length <= MAX_BODY_BYTES:
                    raise BadRequest("too_large")
                job = parse_job(self.rfile.read(length))
            except ValueError:
                job, code = None, "length"
            except BadRequest as exc:
                job, code = None, exc.code
            if job is None:
                replayer.audit(correlation, None, caller, result="denied", error_code=code)
                self._send(400, {"error": code})
                return
            try:
                counts = replayer.run(job)
            except ReplayError as exc:
                _log(f"{job['kind']} failed: {exc}")
                replayer.audit(correlation, job, caller, result="error",
                               error_code="backend_failed")
                self._send(502, {"error": "backend_failed"})
                return
            replayer.audit(correlation, job, caller, counts=counts)
            self._send(200, {"counts": counts})

        def _refuse(self) -> None:
            self._send(405, {"error": "method_not_allowed"})

        do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = _refuse

        def log_message(self, format: str, *args) -> None:
            return

    class Server(http.server.HTTPServer):
        def get_request(self):
            sock, addr = self.socket.accept()
            sock.settimeout(30)
            try:
                return ctx.wrap_socket(sock, server_side=True), addr
            except (OSError, ssl.SSLError):
                sock.close()
                raise

    return Server((host, port), Handler)


def _listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError("--listen takes host:port")
    return host, int(port)


def _host_port(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host) or not port.isdigit():
        raise argparse.ArgumentTypeError("--chat-db takes host:port")
    return host, int(port)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="replay.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--listen", type=_listen, default=("0.0.0.0", 8443))
    serve.add_argument("--tls-dir", type=Path, required=True)
    serve.add_argument("--secret-dir", type=Path, required=True)
    serve.add_argument("--chat-db", type=_host_port, default=("librechat-mongodb", 27017))
    serve.add_argument("--gateway-url", default="http://litellm:4000")
    args = parser.parse_args(argv)

    password = args.secret_dir / "chat-password"
    key = args.secret_dir / "gateway-key"
    # papaia-ctl writes each file only while its profile is on (docs/replay.md).
    chat_factory = None
    if password.is_file():
        host, port = args.chat_db

        def chat_factory():
            return Chat(Mongo(host, port, password))

    gateway = Gateway(args.gateway_url, key) if key.is_file() else None
    _log(f"chat {'on' if chat_factory else 'off'}, gateway {'on' if gateway else 'off'}")
    server = make_server(*args.listen, server_context(args.tls_dir), Replayer(chat_factory, gateway))
    _log("running")
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
