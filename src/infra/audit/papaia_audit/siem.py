"""papaia-audit SIEM export: the one way audit events leave the stack (docs/audit.md, "SIEM").

- Target `PAPAIA_AUDIT_SIEM_TARGET`, one of
  - `syslog-tls://host[:6514]`: syslog RFC 5424 over TLS RFC 5425 (octet counting),
    `APP-NAME` papaia, `MSGID` the event name, structured data
    `[papaia@<PEN> source="…" seq="…"]`, the message the event as JSON;
  - `https://host[:port]/path`: `POST` of up to 500 events as JSON lines; 2xx means taken.
- The queue is the store itself: a read position per target and source
  (`audit.export_cursor`). It moves only after the target took the events, so after a
  restart or an outage the export resumes from there; an event may arrive twice, never
  not at all. Receivers recognise a repeat by `source` and `seq`.
- Persons: by default (`PAPAIA_AUDIT_SIEM_IDENTITY=pseudonym`) `sub` and person ids in
  `object_ref` leave as a pseudonym. `sub` in clear text only with
  `PAPAIA_AUDIT_SIEM_IDENTITY=sub`; the upstream provider's ids only with `upstream_oid`
  (parameters `tid` and `oid` in the structured data of the syslog header, next to the
  pseudonym in the message, from the identity map; only for `syslog-tls://` targets).
  Both need a basis (`PAPAIA_AUDIT_SIEM_BASIS`, the works agreement it rests on).
  `client_ip` leaves with sign-in events only (and with every event under `sub`). `hash`
  and `prev_hash` stay those of the stored event.
- The message is always the stored form of `papaia.audit/1` (audit.v1.schema.json, which
  rejects unknown fields): nothing is added to it in any identity.
- The connection goes through `PAPAIA_AUDIT_SIEM_PROXY` (papaia-egress, HTTP CONNECT) when
  set; TLS stays end to end.
- A syslog connection is reused only while it is alive: before each batch it is opened
  again when the receiver or papaia-egress closed it, or when it was idle for
  `IDLE_SECONDS` (shorter than the 300 s after which papaia-egress closes an idle tunnel).
  RFC 5425 has no acknowledgement: a batch written into a connection that breaks while
  it is underway counts as taken. Receivers that must not miss one use `https://`.

Logs carry the target's name, sources and counts, never an event.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import re
import select
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import urlsplit

from papaia_audit import core

DEFAULT_PEN = 32473
SYSLOG_PORT = 6514
BATCH = 500
TIMEOUT_SECONDS = 15
# A syslog connection idle for longer is opened again before the next batch; papaia-egress
# closes an idle tunnel after 300 s (src/infra/egress/egress.py IDLE_TIMEOUT_SECONDS).
IDLE_SECONDS = 240
IDENTITIES = ("pseudonym", "sub", "upstream_oid")
# Events whose client address the SOC correlates with the sign-in logs of the provider.
SIGN_IN_EVENTS = frozenset({"login_failed", "breakglass_login"})
MAX_BASIS = 200
PERSON_REF_TYPES = frozenset({"user", "person", "member", "account", "subject", "principal"})
# Facility 13 (log audit); severity 6 (informational), 5 (notice) for denied or error.
_FACILITY = 13
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,62})"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")
_BASIS_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")


class ExportError(Exception):
    """The target did not take a batch; the message names the cause, never an event."""


@dataclass(frozen=True)
class Target:
    kind: str  # "syslog" or "https"
    host: str
    port: int
    path: str = "/"

    @property
    def name(self) -> str:
        """The target's key of its read positions."""
        if self.kind == "syslog":
            return f"syslog-tls://{self.host}:{self.port}"
        return f"https://{self.host}:{self.port}{self.path}"


def parse_target(text: str | None) -> Target | None:
    """`PAPAIA_AUDIT_SIEM_TARGET`; None when empty, ValueError when malformed."""
    value = (text or "").strip()
    if not value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("PAPAIA_AUDIT_SIEM_TARGET is not a valid address") from None
    host = parts.hostname or ""
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("PAPAIA_AUDIT_SIEM_TARGET must not carry credentials, query or fragment")
    if not _HOST_RE.match(host):
        raise ValueError("PAPAIA_AUDIT_SIEM_TARGET needs a host name or IPv4 address")
    if parts.scheme == "syslog-tls" and parts.path in ("", "/"):
        return Target("syslog", host.lower(), port or SYSLOG_PORT)
    if parts.scheme == "https":
        path = parts.path or "/"
        if not _PATH_RE.match(path) or "/../" in path + "/":
            raise ValueError("PAPAIA_AUDIT_SIEM_TARGET has an unusable path")
        return Target("https", host.lower(), port or 443, path)
    raise ValueError("PAPAIA_AUDIT_SIEM_TARGET must start with syslog-tls:// or https://")


def parse_pen(text: str | None) -> int:
    value = (text or "").strip()
    if not value:
        return DEFAULT_PEN
    if not value.isascii() or not value.isdigit() or len(value) > 9 or int(value) < 1:
        raise ValueError("PAPAIA_AUDIT_SIEM_PEN must be a private enterprise number")
    return int(value)


def parse_identity(identity: str | None, basis: str | None) -> tuple[str, str]:
    """(identity, basis); `sub` and `upstream_oid` only with a basis, which is otherwise
    ignored."""
    value = (identity or "").strip() or "pseudonym"
    if value not in IDENTITIES:
        raise ValueError("PAPAIA_AUDIT_SIEM_IDENTITY must be pseudonym, sub or upstream_oid")
    reason = (basis or "").strip()
    if value != "pseudonym":
        if not _BASIS_RE.match(reason):
            raise ValueError(
                f"PAPAIA_AUDIT_SIEM_IDENTITY={value} needs PAPAIA_AUDIT_SIEM_BASIS (1 to 200"
                " characters, the agreement it rests on)"
            )
        return value, reason
    return value, ""


def check_identity_target(identity: str, target: Target | None) -> None:
    """`upstream_oid` travels in the syslog header: a JSON lines target has no place for
    `tid` and `oid` outside the `papaia.audit/1` document, which allows no further field."""
    if identity == "upstream_oid" and target is not None and target.kind != "syslog":
        raise ValueError(
            "PAPAIA_AUDIT_SIEM_IDENTITY=upstream_oid needs a syslog-tls:// target (tid and oid"
            " travel in the syslog header, never in the papaia.audit/1 document)"
        )


def pseudonym(key: bytes, sub: str) -> str:
    """`P-` and 8 characters of base32(HMAC-SHA-256(key, sub)): stable per installation."""
    digest = hmac.new(key, sub.encode("utf-8"), hashlib.sha256).digest()
    return "P-" + base64.b32encode(digest).decode("ascii")[:8]


@dataclass(frozen=True)
class Row:
    source: str
    seq: int
    prev_hash: bytes
    hash: bytes
    body: dict[str, Any]


def present(row: Row, identity: str, key: bytes) -> dict[str, Any]:
    """The event as it leaves: stored form of `papaia.audit/1`, persons per `identity`."""
    body = dict(row.body)
    sub = body.get("sub")
    if identity != "sub":
        if isinstance(sub, str):
            body["sub"] = pseudonym(key, sub)
        ref = body.get("object_ref")
        if isinstance(ref, dict) and isinstance(ref.get("id"), str):
            if ref.get("type") in PERSON_REF_TYPES or ref["id"] == sub:
                body["object_ref"] = {**ref, "id": pseudonym(key, ref["id"])}
        if body.get("client_ip") is not None and body.get("event") not in SIGN_IN_EVENTS:
            body["client_ip"] = None
    body.update(
        source=row.source,
        seq=row.seq,
        prev_hash=core.hash_text(row.prev_hash),
        hash=core.hash_text(row.hash),
    )
    return body


def _sd_value(value: str) -> str:
    # RFC 5424 §6.3.3: '"', '\' and ']' are escaped inside a PARAM-VALUE.
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def syslog_message(
    document: dict[str, Any], *, msgid: str, pen: int, hostname: str, now: datetime,
    source: str | None = None, seq: int | None = None, severity: int = 6,
    upstream: tuple[str, str] | None = None,
) -> bytes:
    """One RFC 5424 message with RFC 5425 octet-counting framing (`LEN SP MSG`)."""
    stamp = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    params = ""
    if source is not None and seq is not None:
        params = f' source="{_sd_value(source)}" seq="{seq}"'
    if upstream is not None:
        params += f' tid="{_sd_value(upstream[0])}" oid="{_sd_value(upstream[1])}"'
    structured = f"[papaia@{pen}{params}]"
    message = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    header = f"<{_FACILITY * 8 + severity}>1 {stamp} {hostname} papaia - {msgid}"
    text = f"{header} {structured} {message}"
    data = text.encode("utf-8")
    return str(len(data)).encode("ascii") + b" " + data


def event_message(document: dict[str, Any], pen: int, hostname: str, now: datetime,
                  upstream: tuple[str, str] | None = None) -> bytes:
    severity = 6 if document.get("result") == "allowed" else 5
    return syslog_message(
        document, msgid=str(document["event"]), pen=pen, hostname=hostname, now=now,
        source=str(document["source"]), seq=int(document["seq"]), severity=severity,
        upstream=upstream,
    )


# ─────────────────────────────────────────────────────────────────────────
# senders
# ─────────────────────────────────────────────────────────────────────────


def _connect(target: Target, proxy: tuple[str, int] | None) -> socket.socket:
    if proxy is None:
        return socket.create_connection((target.host, target.port), timeout=TIMEOUT_SECONDS)
    sock = socket.create_connection(proxy, timeout=TIMEOUT_SECONDS)
    try:
        authority = f"{target.host}:{target.port}"
        sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = sock.recv(1024)
            if not chunk or len(reply) > 8192:
                raise ExportError("the proxy closed the connection")
            reply += chunk
        status = reply.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            raise ExportError("the proxy refused the connection to the target")
    except BaseException:
        sock.close()
        raise
    return sock


def parse_proxy(text: str | None) -> tuple[str, int] | None:
    value = (text or "").strip()
    if not value:
        return None
    parts = urlsplit(value)
    if parts.scheme != "http" or not parts.hostname or parts.port is None or parts.username:
        raise ValueError("PAPAIA_AUDIT_SIEM_PROXY must be http://host:port")
    return parts.hostname, parts.port


class Sender(Protocol):
    def send(self, messages: Sequence[bytes]) -> None:
        """Hand the messages to the target; ExportError when it did not take them all."""
        ...

    def close(self) -> None: ...


def _peer_closed(sock: ssl.SSLSocket) -> bool:
    """True when the receiver (or the tunnel) closed the connection or sent something a
    syslog receiver never sends. Writing into such a connection would still succeed once,
    into the kernel's buffer, and the batch would be lost."""
    if sock.pending():
        return True
    try:
        readable, _, failed = select.select([sock], [], [sock], 0)
    except (OSError, ValueError):
        return True
    if failed:
        return True
    if not readable:
        return False
    sock.setblocking(False)
    try:
        sock.recv(1)
    except ssl.SSLWantReadError:
        # Only part of a TLS record (such as a ticket) arrived; the connection is open.
        return False
    except OSError:
        return True
    finally:
        try:
            sock.settimeout(TIMEOUT_SECONDS)
        except OSError:
            pass
    # Either the end of the stream (b"") or data a receiver does not send: start afresh.
    return True


class SyslogSender:
    def __init__(self, target: Target, context: ssl.SSLContext,
                 proxy: tuple[str, int] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.target, self.context, self.proxy = target, context, proxy
        self.clock = clock
        self._sock: ssl.SSLSocket | None = None
        self._used = 0.0

    def _usable(self) -> bool:
        assert self._sock is not None
        if self.clock() - self._used > IDLE_SECONDS:
            return False
        return not _peer_closed(self._sock)

    def send(self, messages: Sequence[bytes]) -> None:
        try:
            if self._sock is not None and not self._usable():
                self.close()
            if self._sock is None:
                raw = _connect(self.target, self.proxy)
                self._sock = self.context.wrap_socket(raw, server_hostname=self.target.host)
            self._sock.sendall(b"".join(messages))
            self._used = self.clock()
        except (OSError, ExportError) as error:
            self.close()
            raise ExportError(f"syslog target not reachable ({type(error).__name__})") from None

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class HttpsSender:
    def __init__(self, target: Target, context: ssl.SSLContext,
                 proxy: tuple[str, int] | None = None) -> None:
        self.target, self.context, self.proxy = target, context, proxy

    def send(self, messages: Sequence[bytes]) -> None:
        if self.proxy is not None:
            conn = http.client.HTTPSConnection(
                self.proxy[0], self.proxy[1], timeout=TIMEOUT_SECONDS, context=self.context
            )
            conn.set_tunnel(self.target.host, self.target.port)
        else:
            conn = http.client.HTTPSConnection(
                self.target.host, self.target.port, timeout=TIMEOUT_SECONDS, context=self.context
            )
        try:
            conn.request(
                "POST", self.target.path, body=b"".join(messages),
                headers={"Content-Type": "application/x-ndjson"},
            )
            status = conn.getresponse().status
        except OSError as error:
            raise ExportError(f"https target not reachable ({type(error).__name__})") from None
        finally:
            conn.close()
        if not 200 <= status < 300:
            raise ExportError(f"https target answered {status}")

    def close(self) -> None:
        return


# ─────────────────────────────────────────────────────────────────────────
# export
# ─────────────────────────────────────────────────────────────────────────


class ExportStore(Protocol):
    def sources(self) -> list[str]: ...

    def position(self, target: str, source: str) -> int:
        """The last seq of `source` the target has taken; 0 for none."""
        ...

    def rows_after(self, source: str, seq: int, limit: int) -> list[Row]: ...

    def advance(self, target: str, source: str, seq: int) -> None: ...

    def delivery(self, target: str, ok: bool) -> None:
        """Record a cycle: the target took everything (`ok`) or a batch failed; the
        first failure of a run of them is kept as the time the target began failing."""
        ...

    def upstream(self, subs: set[str]) -> dict[str, tuple[str, str]]:
        """The provider's (`tid`, `oid`) of those persons the identity map knows."""
        ...


@dataclass(frozen=True)
class Settings:
    target: Target
    pen: int = DEFAULT_PEN
    identity: str = "pseudonym"
    hostname: str = "papaia-audit"


def _upstream_of(row: Row, upstream: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    sub = row.body.get("sub")
    return upstream.get(sub) if isinstance(sub, str) else None


class Exporter:
    def __init__(self, store: ExportStore, sender: Sender, settings: Settings, key: bytes,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.store, self.sender, self.settings, self.key = store, sender, settings, key
        self.clock = clock

    def encode(self, rows: Sequence[Row]) -> list[bytes]:
        upstream: dict[str, tuple[str, str]] = {}
        if self.settings.identity == "upstream_oid":
            subs = {r.body["sub"] for r in rows if isinstance(r.body.get("sub"), str)}
            upstream = self.store.upstream(subs) if subs else {}
        documents = [present(row, self.settings.identity, self.key) for row in rows]
        if self.settings.target.kind == "syslog":
            now = self.clock()
            return [
                event_message(d, self.settings.pen, self.settings.hostname, now,
                              _upstream_of(row, upstream))
                for row, d in zip(rows, documents, strict=True)
            ]
        return [json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                + b"\n" for d in documents]

    def run_once(self) -> int:
        """Send what every source has beyond the target's read position, batch by batch.
        Returns the number of events taken; ExportError stops at the failing batch, whose
        position stays where it was."""
        name, sent = self.settings.target.name, 0
        try:
            for source in self.store.sources():
                position = self.store.position(name, source)
                while True:
                    rows = self.store.rows_after(source, position, BATCH)
                    if not rows:
                        break
                    self.sender.send(self.encode(rows))
                    position = rows[-1].seq
                    self.store.advance(name, source, position)
                    sent += len(rows)
        except ExportError:
            self.store.delivery(name, False)
            raise
        self.store.delivery(name, True)
        return sent

    def send_heads(self, document: dict[str, Any]) -> None:
        """A signed heads document (GV-07) as one message of its own."""
        if self.settings.target.kind == "syslog":
            message = syslog_message(document, msgid="chain_head", pen=self.settings.pen,
                                     hostname=self.settings.hostname, now=self.clock())
        else:
            message = json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n"
        self.sender.send([message])
