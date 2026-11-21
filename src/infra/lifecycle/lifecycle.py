"""papaia-lifecycle: revocation on account deactivation and the signed revocation list.

Every 10 s the service reads the admin events of the `papaia` realm (account updated or
deleted). For an account that is now deactivated it

  1. puts the person on the revocation list (`since` = time of the event),
  2. ends every session (`POST /users/{id}/logout`) and
  3. removes the consent of every client the person consented to
     (`GET /users/{id}/consents`, then `DELETE /users/{id}/consents/{client}`):
     logout alone leaves offline sessions, and with them delegations, alive, and a
     reactivated account would get them back.

A deleted account goes on the list; Keycloak removed its sessions with it. An account
the service may not read (outside the group `papaia-persons`, 403) cannot be revoked: it
is recorded as skipped, with one audit row, and counted in health. An event whose
handling keeps failing is parked after `MAX_EVENT_ATTEMPTS` polls, so later events go
ahead; it is tried again on every poll and health warns while one is parked.

The revocation list `revocations.json` = {seq, issued_at, global_since?, entries:
[{sub, since, reason}]} is written to the security state volume, which every module
mounts read-only, together with its Ed25519 signature (`revocations.json.sig`, the 64
raw signature bytes over the exact file) and the public key (`revocations.pub.pem`). It
is issued again every 15 s, also without a change, so a module can tell from
`issued_at` that the service is alive (`revocations_age_seconds`). A token whose `iat`
is before `global_since`, or before `since` of its `sub`, is refused with
`identity_revoked`. `global-since` (a second process, run with `docker compose exec`)
only records the new value in the state; the running service publishes it and writes
the audit rows, so they reach the container log.

The signing key and the service's own state live in a volume of their own, which is
not backed up. The service signs in as `svc-papaia-lifecycle` with a client assertion
(private_key_jwt, ES256); the key is mounted read-only from the configuration
directory. Every write to Keycloak, and every change of the list's content, is one
`papaia.audit/1` line on stdout with one correlation id per handled event; tokens,
assertions and response bodies are never printed. Operational messages go to stderr.

Standard library and the `openssl` command line only; runs as an unprivileged user on
a read-only file system.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

REALM = "papaia"
CLIENT_ID = "svc-papaia-lifecycle"
LIST_FILE = "revocations.json"
SIG_FILE = "revocations.json.sig"
PUB_FILE = "revocations.pub.pem"
KEY_FILE = "signing-key.pem"
STATE_FILE = "state.json"
LOCK_FILE = "state.lock"
ACCOUNT_KEY_FILE = "private-key.pem"
STATE_FORMAT = "papaia.lifecycle-state/1"

POLL_SECONDS = 10
REISSUE_SECONDS = 15
WARN_AGE_SECONDS = 60
FAIL_AGE_SECONDS = 300
# On the very first start, events this far back are read as well (clock skew between
# the host and Keycloak); handling an event twice changes nothing.
FIRST_LOOKBACK_MS = 60_000
# Longest life of a delegation (offline session, at most 180 days) plus one day: older
# entries can no longer match a token.
ENTRY_RETENTION_SECONDS = 181 * 24 * 3600
EVENT_PAGE = 100
MAX_EVENT_PAGES = 20
MAX_ENTRIES = 100_000
MAX_RESPONSE_BYTES = 4 << 20
ASSERTION_SECONDS = 60
# Polls an event may fail before it is parked and later events go ahead.
MAX_EVENT_ATTEMPTS = 3
MAX_PARKED = 1000
# `global-since --at` may lie at most this far ahead (clock skew): it never moves back.
GLOBAL_SINCE_SKEW_SECONDS = 300
# How long `global-since` waits for the running service to publish the new value.
GLOBAL_SINCE_WAIT_SECONDS = 20
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")

_USER_PATH_RE = re.compile(r"^users/([A-Za-z0-9-]{1,64})$")
_SUB_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_STATE_KEYS = {
    "format",
    "seq",
    "digest",
    "issued_at",
    "global_since",
    "audited_global_since",
    "entries",
    "skipped",
    "attempts",
    "parked",
    "mark_ms",
    "mark_ids",
    "last_poll",
}
_PARKED_KEYS = {"time", "sub", "op"}


class LifecycleError(Exception):
    """A configuration, key or state file that cannot be used."""


class HttpError(Exception):
    """Keycloak answered with an error status (the body is never kept)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


# What a poll or a revocation can fail with; the event is tried again.
RETRYABLE = (HttpError, LifecycleError, OSError, ValueError, http.client.HTTPException)


def _log(message: str) -> None:
    print(f"papaia-lifecycle: {message}", file=sys.stderr, flush=True)


def canonical(doc: object) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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
        raise LifecycleError("the Keycloak URL must be scheme://host[:port]")
    if not parts.hostname:
        raise LifecycleError("the Keycloak URL has no host")
    if parts.scheme == "https":
        return value.rstrip("/")
    if parts.scheme == "http":
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(parts.hostname).is_loopback:
                return value.rstrip("/")
    raise LifecycleError("the Keycloak URL must use https (http only on a loopback address)")


# ─────────────────────────────────────────────────────────────────────────
# files and openssl
# ─────────────────────────────────────────────────────────────────────────


def _openssl(args: list[str]) -> bytes:
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, timeout=30, check=False)
    except FileNotFoundError:
        raise LifecycleError("openssl not found") from None
    if result.returncode != 0:
        raise LifecycleError(f"openssl {args[0]} failed")
    return result.stdout


def _read_private(path: Path, limit: int = 16384) -> bytes:
    """A key file: regular, not a link, not readable by group or others."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise LifecycleError(f"{path} does not exist") from None
    except OSError as exc:
        raise LifecycleError(f"{path} cannot be opened safely: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
            raise LifecycleError(f"{path} must be a regular file with mode 0600")
        return fh.read(limit)


def _write_atomic(folder: Path, name: str, data: bytes, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=folder)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, folder / name)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _scratch(data: bytes, name: str, folder: str) -> str:
    path = os.path.join(folder, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class Signer:
    """The Ed25519 key of the revocation list in the key volume; made on first use."""

    def __init__(self, key_dir: Path) -> None:
        self.path = key_dir / KEY_FILE

    def ensure(self) -> None:
        if os.path.lexists(self.path):
            _read_private(self.path)
            return
        pem = _openssl(["genpkey", "-algorithm", "ed25519"])
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        _log("new signing key for the revocation list")

    def sign(self, data: bytes) -> bytes:
        _read_private(self.path)
        with tempfile.TemporaryDirectory() as folder:
            message = _scratch(data, "message", folder)
            sig = _openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(self.path), "-in", message])
        if len(sig) != 64:
            raise LifecycleError("unexpected signature from openssl")
        return sig

    def public_pem(self) -> bytes:
        return _openssl(["pkey", "-in", str(self.path), "-pubout"])


def verify(data: bytes, sig: bytes, public_pem: bytes) -> bool:
    """True when `sig` is the Ed25519 signature of `data` under `public_pem`."""
    if len(sig) != 64 or b"PRIVATE" in public_pem:
        return False
    with tempfile.TemporaryDirectory() as folder:
        args = [
            "pkeyutl",
            "-verify",
            "-pubin",
            "-rawin",
            "-inkey",
            _scratch(public_pem, "key.pem", folder),
            "-in",
            _scratch(data, "message", folder),
            "-sigfile",
            _scratch(sig, "sig", folder),
        ]
        try:
            _openssl(args)
        except LifecycleError:
            return False
    return True


class Publisher:
    """Writes the list, its signature and the public key into the security state
    volume (0644: modules run as other users). The list is replaced first, then the
    signature: a reader that sees a pair that does not verify keeps its previous list
    and reads again."""

    def __init__(self, state_dir: Path, signer: Signer) -> None:
        self.state_dir, self.signer = state_dir, signer

    def publish(self, doc: dict) -> None:
        self.signer.ensure()
        data = canonical(doc)
        sig = self.signer.sign(data)
        pub = self.signer.public_pem()
        try:
            current = (self.state_dir / PUB_FILE).read_bytes()
        except FileNotFoundError:
            current = None
        if current != pub:
            _write_atomic(self.state_dir, PUB_FILE, pub, 0o644)
        _write_atomic(self.state_dir, LIST_FILE, data, 0o644)
        _write_atomic(self.state_dir, SIG_FILE, sig, 0o644)


# ─────────────────────────────────────────────────────────────────────────
# state
# ─────────────────────────────────────────────────────────────────────────


def _int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LifecycleError(f"state: {name} must be a non-negative integer")
    return value


def _new_state() -> dict:
    return {
        "format": STATE_FORMAT,
        "seq": 0,
        "digest": "",
        "issued_at": 0,
        "global_since": None,
        "audited_global_since": None,
        "entries": {},
        "skipped": {},
        "attempts": {},
        "parked": {},
        "mark_ms": None,
        "mark_ids": [],
        "last_poll": 0,
    }


def _check_state(doc: object) -> dict:
    if not isinstance(doc, dict) or set(doc) != _STATE_KEYS or doc["format"] != STATE_FORMAT:
        raise LifecycleError("state: unknown format or fields")
    for name in ("seq", "issued_at", "last_poll"):
        _int(doc[name], name)
    for name in ("global_since", "audited_global_since"):
        if doc[name] is not None:
            _int(doc[name], name)
    if doc["mark_ms"] is not None:
        _int(doc["mark_ms"], "mark_ms")
    if not isinstance(doc["digest"], str) or len(doc["digest"]) > 64:
        raise LifecycleError("state: digest is malformed")
    ids = doc["mark_ids"]
    if not isinstance(ids, list) or not all(
        isinstance(i, str) and _EVENT_ID_RE.match(i) for i in ids
    ):
        raise LifecycleError("state: mark_ids is malformed")
    entries = doc["entries"]
    if not isinstance(entries, dict) or len(entries) > MAX_ENTRIES:
        raise LifecycleError("state: entries is malformed")
    for sub, entry in entries.items():
        if (
            not _SUB_RE.match(sub)
            or not isinstance(entry, dict)
            or set(entry) != {"since", "reason"}
            or not isinstance(entry["reason"], str)
            or not _REASON_RE.match(entry["reason"])
        ):
            raise LifecycleError("state: an entry is malformed")
        _int(entry["since"], "since")
    skipped = doc["skipped"]
    if not isinstance(skipped, dict) or len(skipped) > MAX_ENTRIES:
        raise LifecycleError("state: skipped is malformed")
    for sub, since in skipped.items():
        if not _SUB_RE.match(sub):
            raise LifecycleError("state: skipped is malformed")
        _int(since, "skipped")
    attempts = doc["attempts"]
    if not isinstance(attempts, dict) or len(attempts) > MAX_PARKED:
        raise LifecycleError("state: attempts is malformed")
    for eid, count in attempts.items():
        if not _EVENT_ID_RE.match(eid):
            raise LifecycleError("state: attempts is malformed")
        _int(count, "attempts")
    parked = doc["parked"]
    if not isinstance(parked, dict) or len(parked) > MAX_PARKED:
        raise LifecycleError("state: parked is malformed")
    for eid, item in parked.items():
        if (
            not _EVENT_ID_RE.match(eid)
            or not isinstance(item, dict)
            or set(item) != _PARKED_KEYS
            or not isinstance(item["sub"], str)
            or not _SUB_RE.match(item["sub"])
            or item["op"] not in ("UPDATE", "DELETE")
        ):
            raise LifecycleError("state: parked is malformed")
        _int(item["time"], "parked time")
    return doc


class Store:
    """The service's own state in the key volume (0600), changed under a lock so a
    `global-since` call and the running service never overwrite each other."""

    def __init__(self, key_dir: Path) -> None:
        self.key_dir = key_dir
        self.path = key_dir / STATE_FILE

    def load(self) -> dict:
        try:
            raw = _read_private(self.path, 64 << 20)
        except LifecycleError:
            if not os.path.lexists(self.path):
                return _new_state()
            raise
        try:
            return _check_state(json.loads(raw))
        except ValueError:
            raise LifecycleError("state: not JSON") from None

    def save(self, doc: dict) -> None:
        _write_atomic(self.key_dir, STATE_FILE, canonical(_check_state(doc)), 0o600)

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.key_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


# ─────────────────────────────────────────────────────────────────────────
# Keycloak
# ─────────────────────────────────────────────────────────────────────────


class AccountKey:
    """The P-256 key of `svc-papaia-lifecycle`, mounted from the configuration dir."""

    def __init__(self, folder: Path) -> None:
        self.path = folder / ACCOUNT_KEY_FILE
        _read_private(self.path)
        der = _openssl(["pkey", "-in", str(self.path), "-pubout", "-outform", "DER"])
        if len(der) != len(P256_SPKI_PREFIX) + 64 or not der.startswith(P256_SPKI_PREFIX):
            raise LifecycleError("the account key is not a P-256 key")
        jwk = {"crv": "P-256", "kty": "EC", "x": b64(der[-64:-32]), "y": b64(der[-32:])}
        self.kid = b64(hashlib.sha256(canonical(jwk)).digest())

    def assertion(self, audience: str, *, now: float | None = None) -> str:
        issued = int(time.time() if now is None else now)
        header = {"alg": "ES256", "kid": self.kid, "typ": "JWT"}
        claims = {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": issued,
            "exp": issued + ASSERTION_SECONDS,
        }
        signing_input = ".".join(b64(canonical(part)) for part in (header, claims))
        _read_private(self.path)
        with tempfile.TemporaryDirectory() as folder:
            message = _scratch(signing_input.encode("ascii"), "message", folder)
            der = _openssl(["dgst", "-sha256", "-sign", str(self.path), message])
        return f"{signing_input}.{b64(_raw_signature(der))}"


def _raw_signature(der: bytes) -> bytes:
    """ECDSA DER (SEQUENCE of two INTEGERs) as JOSE wants it: r || s."""
    if len(der) < 8 or der[0] != 0x30 or der[1] & 0x80:
        raise LifecycleError("unexpected signature from openssl")
    pos, parts = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise LifecycleError("unexpected signature from openssl")
        length = der[pos + 1]
        value = der[pos + 2 : pos + 2 + length].lstrip(b"\0")
        if len(value) > 32:
            raise LifecycleError("unexpected signature from openssl")
        parts.append(value.rjust(32, b"\0"))
        pos += 2 + length
    return parts[0] + parts[1]


class AccountClient:
    """The `papaia` realm's Admin API as `svc-papaia-lifecycle`."""

    def __init__(self, base_url: str, ctx: ssl.SSLContext | None, account_dir: Path) -> None:
        self.base_url = keycloak_url(base_url)
        self.ctx = ctx
        self.account_dir = account_dir
        self._token: str | None = None
        self._until = 0.0

    def _open(self, req: urllib.request.Request):
        try:
            with urllib.request.urlopen(req, timeout=15, context=self.ctx) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise HttpError(exc.code) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LifecycleError("answer of Keycloak too large")
        return json.loads(raw) if raw else None

    def token(self) -> str:
        if self._token and time.monotonic() < self._until:
            return self._token
        realm = f"{self.base_url}/realms/{REALM}"
        issuer = self._open(urllib.request.Request(f"{realm}/.well-known/openid-configuration"))
        if not isinstance(issuer, dict) or not isinstance(issuer.get("issuer"), str):
            raise LifecycleError("discovery document without issuer")
        key = AccountKey(self.account_dir)
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": key.assertion(issuer["issuer"]),
            }
        ).encode()
        body = self._open(
            urllib.request.Request(f"{realm}/protocol/openid-connect/token", data=form)
        )
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise LifecycleError("token answer without access token")
        lifetime = body.get("expires_in")
        lifetime = lifetime if isinstance(lifetime, int) and lifetime > 0 else 60
        self._token = body["access_token"]
        self._until = time.monotonic() + max(5, lifetime - 30)
        return self._token

    def call(self, method: str, path: str, body: object = None):
        req = urllib.request.Request(
            f"{self.base_url}/admin/realms/{REALM}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"},
        )
        try:
            return self._open(req)
        except HttpError as exc:
            if exc.status == 401:
                self._token = None
            raise


# ─────────────────────────────────────────────────────────────────────────
# the service
# ─────────────────────────────────────────────────────────────────────────


class Lifecycle:
    def __init__(self, api, store: Store, publisher: Publisher, *, out=None, clock=time.time):
        self.api, self.store, self.publisher = api, store, publisher
        self.out = out or sys.stdout
        self.clock = clock
        self._next_poll = 0.0

    # audit ------------------------------------------------------------
    def _audit(
        self,
        operation: str,
        effect: str,
        event: str,
        correlation: str,
        object_ref: dict | None,
        result: str = "allowed",
        error_code: str | None = None,
        detail: dict | None = None,
    ) -> None:
        now = time.time()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        row = {
            "format": "papaia.audit/1",
            "time": f"{stamp}.{int(now % 1 * 1000):03d}Z",
            "correlation_id": correlation,
            "writer": "papaia-lifecycle",
            "role": "caller",
            "sub": CLIENT_ID,
            "identity_kind": "service",
            "service_account": CLIENT_ID,
            "azp": CLIENT_ID,
            "aud": None,
            "catalog_id": None,
            "operation": f"lifecycle.{operation}",
            "effect": effect,
            "object_ref": object_ref,
            "data_class": None,
            "result": result,
            "error_code": error_code,
            "detail": detail,
            "event": event,
        }
        print(json.dumps(row, sort_keys=True), file=self.out, flush=True)

    def _write(self, method, path, operation, event, correlation, sub, detail=None) -> None:
        ref = {"type": "user", "id": sub}
        try:
            self.api.call(method, path)
        except HttpError as exc:
            self._audit(
                operation, "delete", event, correlation, ref, "error", f"http_{exc.status}", detail
            )
            raise
        except Exception:
            self._audit(operation, "delete", event, correlation, ref, "error", "transport", detail)
            raise
        self._audit(operation, "delete", event, correlation, ref, detail=detail)

    # list -------------------------------------------------------------
    def start(self) -> None:
        """Make the key, set the first read position, publish a list at once."""
        self.publisher.signer.ensure()
        with self.store.locked():
            state = self.store.load()
            if state["mark_ms"] is None:
                state["mark_ms"] = max(0, int(self.clock() * 1000) - FIRST_LOOKBACK_MS)
            # last_poll is left alone: a restart must not hide a poll that keeps failing
            # (the health check's start period covers the first poll).
            self._issue(state, force=True)

    def _issue(self, state: dict, *, force: bool = False) -> None:
        now = int(self.clock())
        horizon = now - ENTRY_RETENTION_SECONDS
        state["entries"] = {s: e for s, e in state["entries"].items() if e["since"] >= horizon}
        state["skipped"] = {s: t for s, t in state["skipped"].items() if t >= horizon}
        content = {
            "entries": [
                {"sub": sub, "since": e["since"], "reason": e["reason"]}
                for sub, e in sorted(state["entries"].items())
            ]
        }
        if state["global_since"] is not None:
            content["global_since"] = state["global_since"]
        digest = hashlib.sha256(canonical(content)).hexdigest()
        changed = digest != state["digest"]
        if not (force or changed or now - state["issued_at"] >= REISSUE_SECONDS):
            self.store.save(state)
            return
        state["seq"] += 1
        state["issued_at"] = now
        state["digest"] = digest
        self.publisher.publish({"seq": state["seq"], "issued_at": now, **content})
        # A global_since recorded by `global-since` is audited here, by the service.
        since_changed = state["global_since"] != state["audited_global_since"]
        state["audited_global_since"] = state["global_since"]
        self.store.save(state)
        if since_changed:
            self._audit(
                "global_since",
                "write",
                "config_changed",
                _uuid7(),
                {"type": "revocation_list", "id": LIST_FILE},
                detail={"global_since": state["global_since"]},
            )
        if changed:
            self._audit(
                "revocation_list",
                "write",
                "config_changed",
                _uuid7(),
                {"type": "revocation_list", "id": LIST_FILE},
                detail={"seq": state["seq"], "entries": len(content["entries"])},
            )

    def reissue(self) -> None:
        with self.store.locked():
            self._issue(self.store.load())

    def set_global_since(self, at: int) -> bool:
        """Every token issued before `at` is refused from now on. Never moves back, so a
        value more than GLOBAL_SINCE_SKEW_SECONDS ahead is refused. Only recorded in the
        state: the running service publishes it and writes the audit rows."""
        _int(at, "global_since")
        now = int(self.clock())
        if at > now + GLOBAL_SINCE_SKEW_SECONDS:
            raise LifecycleError(
                f"global_since {at} is more than {GLOBAL_SINCE_SKEW_SECONDS} s in the future "
                f"(now {now}); it never moves back, so it is refused"
            )
        with self.store.locked():
            state = self.store.load()
            if state["global_since"] is not None and at <= state["global_since"]:
                return False
            state["global_since"] = at
            self.store.save(state)
        return True

    # events -----------------------------------------------------------
    def _events(self, since_ms: int) -> list[dict]:
        rows: list[dict] = []
        for page in range(MAX_EVENT_PAGES):
            query = urllib.parse.urlencode(
                [
                    ("resourceTypes", "USER"),
                    ("operationTypes", "UPDATE"),
                    ("operationTypes", "DELETE"),
                    ("dateFrom", str(since_ms)),
                    ("direction", "asc"),
                    ("first", str(page * EVENT_PAGE)),
                    ("max", str(EVENT_PAGE)),
                ]
            )
            batch = self.api.call("GET", f"/admin-events?{query}")
            if not isinstance(batch, list):
                raise LifecycleError("admin events: not a list")
            rows.extend(batch)
            if len(batch) < EVENT_PAGE:
                break
        return rows

    def poll(self) -> None:
        with self.store.locked():
            state = self.store.load()
        mark = state["mark_ms"] or 0
        seen = set(state["mark_ids"])
        for event in sorted(self._events(mark), key=lambda e: _event_time(e) or 0):
            when = _event_time(event)
            eid = event.get("id") if isinstance(event, dict) else None
            if when is None or not isinstance(eid, str) or not _EVENT_ID_RE.match(eid):
                continue
            if when < mark or (when == mark and eid in seen):
                continue
            try:
                self._handle(event, when)
            except RETRYABLE as exc:
                if not self._failed(eid, event, when, exc):
                    raise
            with self.store.locked():
                state = self.store.load()
                if when > (state["mark_ms"] or 0):
                    state["mark_ms"], state["mark_ids"] = when, []
                state["mark_ids"] = sorted(set(state["mark_ids"]) | {eid})[-500:]
                state["attempts"].pop(eid, None)
                self.store.save(state)
            mark, seen = when, set(state["mark_ids"])
        self._retry_parked()
        with self.store.locked():
            state = self.store.load()
            state["last_poll"] = int(self.clock())
            self.store.save(state)

    def _failed(self, eid: str, event: dict, when_ms: int, exc: Exception) -> bool:
        """Count a failed attempt; after MAX_EVENT_ATTEMPTS park the event (True) so the
        poll goes on with later events. False: the poll stops and tries it again."""
        match = _USER_PATH_RE.match(str(event.get("resourcePath", "")))
        op = event.get("operationType")
        with self.store.locked():
            state = self.store.load()
            count = state["attempts"].get(eid, 0) + 1
            if (
                count < MAX_EVENT_ATTEMPTS
                or not match
                or op not in ("UPDATE", "DELETE")
                or len(state["parked"]) >= MAX_PARKED
            ):
                state["attempts"][eid] = min(count, MAX_EVENT_ATTEMPTS)
                self.store.save(state)
                return False
            state["attempts"].pop(eid, None)
            state["parked"][eid] = {"time": when_ms, "sub": match.group(1), "op": op}
            self.store.save(state)
        _log(f"event {eid} failed {count} times ({exc}); parked, later events go ahead")
        self._audit(
            "revocation_parked",
            "write",
            "operation",
            _uuid7(),
            {"type": "user", "id": match.group(1)},
            "error",
            "retries_exhausted",
            {"attempts": count},
        )
        return True

    def _retry_parked(self) -> None:
        with self.store.locked():
            parked = dict(self.store.load()["parked"])
        for eid, item in sorted(parked.items(), key=lambda kv: (kv[1]["time"], kv[0])):
            event = {
                "id": eid,
                "time": item["time"],
                "operationType": item["op"],
                "resourceType": "USER",
                "resourcePath": f"users/{item['sub']}",
            }
            try:
                self._handle(event, item["time"])
            except RETRYABLE as exc:
                _log(f"parked event {eid} failed again ({exc})")
                continue
            with self.store.locked():
                state = self.store.load()
                state["parked"].pop(eid, None)
                self.store.save(state)
            _log(f"parked event {eid} handled")

    def _skipped(self, sub: str, since: int) -> None:
        """An account the service may not read: not revoked. One audit row and a count
        in health make the gap visible (CORE-046 reconciles)."""
        with self.store.locked():
            state = self.store.load()
            if state["skipped"].get(sub, -1) >= since or len(state["skipped"]) >= MAX_ENTRIES:
                return
            state["skipped"][sub] = since
            self.store.save(state)
        _log(f"account {sub} is outside the group of persons; not revoked")
        self._audit(
            "revoke",
            "delete",
            "operation",
            _uuid7(),
            {"type": "user", "id": sub},
            "denied",
            "http_403",
        )

    def _handle(self, event: dict, when_ms: int) -> None:
        match = _USER_PATH_RE.match(str(event.get("resourcePath", "")))
        if event.get("resourceType") != "USER" or not match:
            return
        sub, op = match.group(1), event.get("operationType")
        since = math.ceil(when_ms / 1000)
        if op == "DELETE":
            self._list(sub, since, "account_deleted")
            return
        if op != "UPDATE":
            return
        try:
            user = self.api.call("GET", f"/users/{sub}")
        except HttpError as exc:
            if exc.status == 404:
                self._list(sub, since, "account_deleted")
            elif exc.status == 403:
                self._skipped(sub, since)
            else:
                raise
            return
        if isinstance(user, dict) and user.get("enabled") is False:
            self.revoke(sub, since, "account_disabled")

    def _list(self, sub: str, since: int, reason: str) -> None:
        with self.store.locked():
            state = self.store.load()
            current = state["entries"].get(sub)
            if current is None or current["since"] < since:
                state["entries"][sub] = {"since": since, "reason": reason}
            self._issue(state)

    def revoke(self, sub: str, since: int, reason: str) -> None:
        """List first (modules refuse the person's tokens within 15 s even if a call
        below fails), then end the sessions and remove every consent."""
        if not _SUB_RE.match(sub):
            raise LifecycleError("malformed account id")
        self._list(sub, since, reason)
        correlation = _uuid7()
        self._write("POST", f"/users/{sub}/logout", "logout", "operation", correlation, sub)
        consents = self.api.call("GET", f"/users/{sub}/consents") or []
        for consent in consents if isinstance(consents, list) else []:
            client = consent.get("clientId") if isinstance(consent, dict) else None
            if not isinstance(client, str) or not _CLIENT_ID_RE.match(client) or ".." in client:
                _log(f"consent of account {sub} with a malformed client id skipped")
                continue
            self._write(
                "DELETE",
                f"/users/{sub}/consents/{urllib.parse.quote(client, safe='')}",
                "consent_delete",
                "delegation_revoked",
                correlation,
                sub,
                {"client": client},
            )

    # loop -------------------------------------------------------------
    def step(self, *, force_poll: bool = False) -> None:
        now = self.clock()
        if force_poll or now >= self._next_poll:
            self._next_poll = now + POLL_SECONDS
            try:
                self.poll()
            except RETRYABLE as exc:
                _log(f"reading the events failed ({exc!r}); trying again")
        self.reissue()


def _event_time(event: object) -> int | None:
    if not isinstance(event, dict):
        return None
    when = event.get("time")
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        return None
    return when


# ─────────────────────────────────────────────────────────────────────────
# health and entry point
# ─────────────────────────────────────────────────────────────────────────


def health(state_dir: Path, key_dir: Path, *, now: float | None = None) -> tuple[int, dict]:
    """`revocations_age_seconds` of the published list; 1 when it is older than 60 s,
    does not verify, Keycloak has not been read for 60 s, or an event is parked.
    `skipped_revocations` counts accounts that could not be read (outside the group)."""
    now = time.time() if now is None else now
    report: dict = {"status": "fail", "revocations_age_seconds": None}
    try:
        data = (state_dir / LIST_FILE).read_bytes()
        sig = (state_dir / SIG_FILE).read_bytes()
        pub = (state_dir / PUB_FILE).read_bytes()
        doc = json.loads(data)
        issued = _int(doc.get("issued_at"), "issued_at")
    except (OSError, ValueError, LifecycleError, AttributeError):
        return 1, report
    if not verify(data, sig, pub):
        return 1, report
    age = max(0, int(now - issued))
    report["revocations_age_seconds"] = age
    report["seq"] = doc.get("seq")
    try:
        state = Store(key_dir).load()
    except LifecycleError:
        state = _new_state()
    report["last_poll_age_seconds"] = max(0, int(now - state["last_poll"]))
    report["parked_revocations"] = len(state["parked"])
    report["skipped_revocations"] = len(state["skipped"])
    worst = max(age, report["last_poll_age_seconds"])
    if worst > FAIL_AGE_SECONDS:
        return 1, report
    if worst > WARN_AGE_SECONDS or state["parked"]:
        report["status"] = "warn"
        return 1, report
    report["status"] = "ok"
    return 0, report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lifecycle.py")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "health", "global-since"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--key-dir", type=Path, required=True)
        cmd.add_argument("--state-dir", type=Path, required=True)
        if name == "run":
            cmd.add_argument("--keycloak-url", required=True)
            cmd.add_argument("--ca-file", type=Path)
            cmd.add_argument("--account-dir", type=Path, required=True)
            cmd.add_argument("--once", action="store_true")
        if name == "global-since":
            cmd.add_argument("--at", type=int)
    return parser


def _published_global_since(state_dir: Path) -> int | None:
    try:
        value = json.loads((state_dir / LIST_FILE).read_bytes()).get("global_since")
    except (OSError, ValueError, AttributeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _global_since(service: Lifecycle, args) -> int:
    at = int(time.time()) if args.at is None else args.at
    try:
        changed = service.set_global_since(at)
    except LifecycleError as exc:
        _log(f"refused: {exc}")
        return 1
    if not changed:
        print("global_since unchanged (not later than the current value)")
        return 0
    deadline = time.monotonic() + GLOBAL_SINCE_WAIT_SECONDS
    while True:
        published = _published_global_since(args.state_dir)
        if published is not None and published >= at:
            print(f"global_since {at} set and published")
            return 0
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    print(
        f"global_since {at} set, not yet published: papaia-lifecycle publishes it and "
        "writes the audit rows on its next cycle (is it running?)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "health":
        code, report = health(args.state_dir, args.key_dir)
        print(json.dumps(report, sort_keys=True))
        return code
    store, publisher = Store(args.key_dir), Publisher(args.state_dir, Signer(args.key_dir))
    if args.command == "global-since":
        return _global_since(Lifecycle(None, store, publisher), args)
    ctx = None
    if urllib.parse.urlsplit(keycloak_url(args.keycloak_url)).scheme == "https":
        ctx = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    service = Lifecycle(AccountClient(args.keycloak_url, ctx, args.account_dir), store, publisher)
    service.start()
    if args.once:
        service.step(force_poll=True)
        return 0
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    _log("running")
    while not stopping:
        try:
            service.step()
        except RETRYABLE as exc:
            _log(f"issuing the revocation list failed ({exc!r})")
        time.sleep(1)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LifecycleError as exc:
        _log(str(exc))
        sys.exit(1)
