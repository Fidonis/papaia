"""papaia-lifecycle: revocation on account deactivation and the signed revocation list.

Every 10 s the service reads the admin events of the `papaia` realm (account updated or
deleted, and the changes journaled below) and its user events (below). For an account
that is now deactivated it

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

Events can be missed: the service was stopped, Keycloak no longer keeps them, or the
deactivation came from a directory behind Keycloak and has no event at all. So at start
and every hour the service also reconciles without events: every deactivated account it
can see is revoked unless it already was, and every consent such an account still
holds is removed. An account it saw deactivated that is active again loses the
consents from before (the person grants anew). When the last successful read of the
events is older than Keycloak's event retention, nothing tells a deactivation and
reactivation inside that gap apart from an active account: every consent at a holder
client (`flow-engine`, `assist-gate`) is removed (`lifecycle_gap_revoke`).

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

Every deactivation and deletion, and every removed role or group membership, ended
session and reset credential of a person is one line of the erasure journal `identity`
(`<backup target>/erasure-journal/identity.jsonl`, local copy in the key volume), in the
format of the modules' erasure journals: `seq` gap-free per source, the person named only
as `subject_ref` = HMAC-SHA256(erasure-hmac, sub). The service reads them from the admin
events and, for what a person does on their own account (password change, removed
second factor, "sign out all devices"), from the user events of the realm. Only persons
are journaled: an account the service may not read (outside `papaia-persons`) writes no
entry. A restored snapshot therefore cannot bring an account state back unnoticed.

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
import hmac
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
# The id of papaia-persons, written next to the key by the realm sync
# (lib/lifecycle_account.py): the group permission lets the account list the group's
# members, but neither search accounts nor look the group up.
GROUP_FILE = "persons-group"
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
# Reconciliation independent of events (security 1.12 no. 2): at start, then hourly; a
# failed one is tried again after a minute. Older than two hours is `fail` in health.
RECONCILE_SECONDS = 3600
RECONCILE_RETRY_SECONDS = 60
RECONCILE_FAIL_SECONDS = 2 * 3600
# How long Keycloak keeps admin events (lib/lifecycle_account.py sets 7 days). A gap
# between two successful reads longer than that may hide events.
EVENT_RETENTION_SECONDS = 7 * 24 * 3600
# An event normally reaches the service within one poll. One read later than this (the
# service was stopped, or Keycloak could not be read) may hide a deactivation that was
# undone before the read: the account then reads active (security 1.12 no. 2).
LATE_EVENT_SECONDS = 60
# The clients that hold delegations (offline sessions): Flow and the assistant.
HOLDER_CLIENTS = frozenset({"assist-gate", "flow-engine"})
USER_PAGE = 100
MAX_USER_PAGES = 1000
# Polls an event may fail before it is parked and later events go ahead.
MAX_EVENT_ATTEMPTS = 3
MAX_PARKED = 1000
# `global-since --at` may lie at most this far ahead (clock skew): it never moves back.
GLOBAL_SINCE_SKEW_SECONDS = 300
# How long `global-since` waits for the running service to publish the new value.
GLOBAL_SINCE_WAIT_SECONDS = 20
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")

_ID = r"[A-Za-z0-9-]{1,64}"
_USER_PATH_RE = re.compile(rf"users/({_ID})")
_USER_ACTION_RE = re.compile(rf"users/({_ID})/(logout|reset-password)")
_CREDENTIAL_PATH_RE = re.compile(rf"users/({_ID})/credentials/({_ID})")
_REALM_ROLES_RE = re.compile(rf"users/({_ID})/role-mappings/realm")
_CLIENT_ROLES_RE = re.compile(rf"users/({_ID})/role-mappings/clients/({_ID})")
_GROUP_PATH_RE = re.compile(rf"users/({_ID})/groups/({_ID})")
_OWN_PASSWORD_RE = re.compile(rf"users/({_ID})/password")
_OWN_CREDENTIAL_RE = re.compile(rf"users/({_ID})/credentials(?:/({_ID}))?")
_OWN_SESSIONS_RE = re.compile(rf"users/({_ID})/sessions")
_SUB_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_GROUP_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
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
    "journal_disabled",
    "disabled",
    "last_reconcile",
    "disabled_with_consent",
    "gap_pending",
    "gap_revoke_at",
    "started_at",
}
# Added with the reconciliation; a state written before it gets them on load.
_RECONCILE_DEFAULTS = {
    "disabled": {},
    "last_reconcile": 0,
    "disabled_with_consent": 0,
    "gap_pending": False,
    "gap_revoke_at": None,
    # The first start of a version with the reconciliation (seconds); health counts from
    # it while no round has succeeded.
    "started_at": None,
}
_PARKED_KEYS = {"time", "op", "type", "path"}
# A parked event as CORE-012 stored it (account events only).
_LEGACY_PARKED_KEYS = {"time", "sub", "op"}
# Admin events the service reads: account changes, ended sessions and reset credentials
# of an account, removed roles and group memberships.
EVENT_RESOURCE_TYPES = ("USER", "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING", "GROUP_MEMBERSHIP")
EVENT_OPERATION_TYPES = ("UPDATE", "DELETE", "ACTION")
# User events the service reads (sicherheit §1.12 Nr. 1, RE-103): what a person does on
# their own account. Measured against Keycloak 26.7.0: a password change in the sign-in
# form is UPDATE_PASSWORD (and UPDATE_CREDENTIAL, not read: one entry per change), a
# removed second factor REMOVE_CREDENTIAL (and REMOVE_TOTP, not read), and "sign out all
# devices" one LOGOUT per session of the account API's client `account`. The realm sync
# makes the realm store these types (lib/lifecycle_account.py).
USER_EVENT_TYPES = ("UPDATE_PASSWORD", "REMOVE_CREDENTIAL", "LOGOUT")
ACCOUNT_API_CLIENT = "account"
# LOGOUTs of one account this close together are one "sign out all devices": Keycloak
# ends the sessions one after another, which can cross milliseconds and event pages.
SIGN_OUT_MERGE_MS = 5000
# A user event as the service keeps it (resourceType of the normalised event).
USER_EVENT = "USER_EVENT"
# Reason code of each identity journal entry.
JOURNAL_REASONS = {
    "account_disable": "account_disabled",
    "account_delete": "account_deleted",
    "role_revoke": "role_removed",
    "session_revoke": "sessions_ended",
    "credential_reset": "credential_changed",
}


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
# erasure journal
# ─────────────────────────────────────────────────────────────────────────

IDENTITY_SOURCE = "identity"
# Kinds per core source (sicherheit §4.9 (1)); a module journal never holds these.
JOURNAL_KINDS = {
    "identity": frozenset(
        {"account_disable", "account_delete", "role_revoke", "session_revoke", "credential_reset"}
    ),
    "core-chat": frozenset({"erase", "erase_subject"}),
    "model-gateway": frozenset({"erase", "erase_subject", "key_revoke"}),
}
_JOURNAL_FIELDS = ("id", "module", "seq", "kind", "object_ref", "subject_ref", "at", "reason")
MAX_JOURNAL_LINE = 4096
MAX_JOURNAL_SEQ = 2**53 - 1  # exact in every JSON reader
_OBJECT_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+#=-]{0,255}")
_JOURNAL_REASON_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_SUBJECT_REF_RE = re.compile(r"[0-9a-f]{64}")
_UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_AT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_KEY_TEXT_RE = re.compile(rb"([0-9A-Fa-f]+)(?:\r?\n)?")


class JournalError(LifecycleError):
    """The local copy of the journal cannot be read or written; no entry is safe."""


def read_erasure_key(path: Path) -> bytes:
    """The installation key `erasure-hmac`: hex text of 32 to 1024 bytes, optionally
    followed by one line break, in a file only its owner can read."""
    match = _KEY_TEXT_RE.fullmatch(_read_private(path, 4100))
    if match is None or len(match.group(1)) % 2 or not 64 <= len(match.group(1)) <= 2048:
        raise LifecycleError(f"{path} must hold the key as 64 to 2048 hex digits")
    return bytes.fromhex(match.group(1).decode("ascii"))


def _journal_line(entry: dict) -> bytes:
    record = {name: entry[name] for name in _JOURNAL_FIELDS}
    if "provisional_seq" in entry:
        record["provisional_seq"] = entry["provisional_seq"]
    return json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"


def _unique_keys(pairs: list) -> dict:
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("duplicate field")
    return record


def _seq(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_JOURNAL_SEQ


def _check_entry(record: object, source: str) -> dict:
    """One decoded line in the format of the kit's erasure-journal-entry.v1 schema."""
    if not isinstance(record, dict):
        raise ValueError("entry is not an object")
    if set(record) - {"provisional_seq"} != set(_JOURNAL_FIELDS):
        raise ValueError("entry has unknown or missing fields")
    if record["module"] != source or not _seq(record["seq"]):
        raise ValueError("entry of another journal or without a valid seq")
    if "provisional_seq" in record and (
        not _seq(record["provisional_seq"]) or record["provisional_seq"] == record["seq"]
    ):
        raise ValueError("provisional_seq must be a positive integer other than seq")
    checks = (
        ("id", _UUID4_RE),
        ("object_ref", _OBJECT_REF_RE),
        ("subject_ref", _SUBJECT_REF_RE),
        ("at", _AT_RE),
        ("reason", _JOURNAL_REASON_RE),
    )
    for name, pattern in checks:
        if not isinstance(record[name], str) or not pattern.fullmatch(record[name]):
            raise ValueError(f"{name} is malformed")
    if not isinstance(record["kind"], str) or record["kind"] not in JOURNAL_KINDS[source]:
        raise ValueError("kind is not allowed in this journal")
    time.strptime(record["at"], "%Y-%m-%dT%H:%M:%S.%fZ")  # a valid date
    return record


def _same_entry(a: dict, b: dict) -> bool:
    """Both lines describe one entry, whatever seq they carry."""
    return all(a[name] == b[name] for name in _JOURNAL_FIELDS if name != "seq")


def _merged(entries: dict, lines: list[dict]) -> dict:
    """Entries by id after taking `lines` in: the last line of an id wins, and one seq
    never holds two entries."""
    merged = dict(entries)
    for line in lines:
        known = merged.get(line["id"])
        if known is not None and not _same_entry(known, line):
            raise ValueError("different entries for one id")
        merged[line["id"]] = line
    if len({e["seq"] for e in merged.values()}) != len(merged):
        raise ValueError("different entries for one seq")
    return merged


class _Place:
    """The journal file of one source in one folder, read once."""

    def __init__(self, name: str, folder: Path, source: str) -> None:
        self.name, self.folder, self.path = name, folder, folder / f"{source}.jsonl"
        self.state, self.lines, self.entries = "ok", [], {}
        if not folder.is_dir() or not os.access(folder, os.R_OK | os.W_OK | os.X_OK):
            self.state = "unreachable"
            return
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        except OSError:
            self.state = "unreachable"
            return
        with os.fdopen(fd, "rb") as fh:
            data = fh.read()
        # A last line without a line break is a write that never completed: it is
        # ignored here and cut off by the next append.
        try:
            lines = []
            for raw in data[: data.rfind(b"\n") + 1].splitlines():
                if len(raw) > MAX_JOURNAL_LINE:
                    raise ValueError("line too long")
                lines.append(_check_entry(json.loads(raw, object_pairs_hook=_unique_keys), source))
            # All lines at once: a later line of an id may move it off a shared seq.
            self.add(lines)
        except (ValueError, RecursionError):  # json.JSONDecodeError is a ValueError
            self.state, self.lines, self.entries = "corrupt", [], {}

    def add(self, lines: list[dict]) -> None:
        self.entries = _merged(self.entries, lines)
        self.lines.extend(lines)

    def end(self) -> int:
        return max((e["seq"] for e in self.entries.values()), default=0)

    def append(self, lines: list[dict]) -> None:
        """Append complete lines (cutting off a torn last line first), fsync, then take
        them in. Raises OSError when the place cannot be written."""
        _merged(self.entries, lines)  # ValueError: the lines would damage the place
        created = not self.path.exists()
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        try:
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b"\n":
                os.ftruncate(fd, os.pread(fd, size, 0).rfind(b"\n") + 1)
            payload = memoryview(b"".join(_journal_line(e) for e in lines))
            while payload:
                payload = payload[os.write(fd, payload) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        if created:
            dir_fd = os.open(self.folder, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        self.add(lines)


class ErasureJournal:
    """Writer of the journal of one core source (`identity`, `core-chat`,
    `model-gateway`) in the format of the kit's erasure journal (erasure-journal-entry.v1).

    `target_dir` is `<backup target>/erasure-journal`, `local_dir` the local copy in the
    service's own volume (not backed up). An entry is written to the local copy first and
    then delivered to the target; the target assigns the final `seq`, gap-free per source.
    An unreachable or damaged target keeps the entry in the local copy until a later
    `record` or `flush` delivers it. An entry that reaches the target under another `seq`
    than first handed out (the local copy was older than the target, for example restored
    from a VM backup) carries that first number as `provisional_seq`. The writer never
    creates the target folder: a missing mount shows as unreachable, not as an empty
    journal. Lines name the person by `subject_ref` = HMAC-SHA256(erasure-hmac, sub)
    only; they never carry content.
    """

    def __init__(
        self,
        source: str,
        *,
        key: bytes,
        target_dir: Path,
        local_dir: Path,
        clock=time.time,
    ) -> None:
        if source not in JOURNAL_KINDS:
            raise LifecycleError(f"unknown journal source {source!r}")
        if not isinstance(key, bytes) or not 32 <= len(key) <= 1024:
            raise LifecycleError("the erasure key needs 32 to 1024 bytes")
        self.source, self._key = source, key
        self.target_dir, self.local_dir = Path(target_dir), Path(local_dir)
        self.clock = clock

    def __repr__(self) -> str:
        return f"ErasureJournal({self.source!r}, key=<redacted>)"

    def subject_ref(self, sub: str) -> str:
        if not isinstance(sub, str) or not 0 < len(sub) <= 255 or _CONTROL_RE.search(sub):
            raise LifecycleError("subject must be 1 to 255 characters without control characters")
        return hmac.new(self._key, sub.encode("utf-8"), hashlib.sha256).hexdigest()

    @contextlib.contextmanager
    def _locked(self):
        # One writer at a time, also across processes: seq stays gap-free and unique.
        try:
            self.local_dir.mkdir(mode=0o700, exist_ok=True)
            fd = os.open(
                self.local_dir / f".{self.source}.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise JournalError(f"local copy of the journal: {exc.strerror}") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _load(self) -> tuple[_Place, _Place]:
        local = _Place("local copy", self.local_dir, self.source)
        if local.state != "ok":
            raise JournalError(f"local copy of the journal {self.source} is {local.state}")
        return local, _Place("target", self.target_dir, self.source)

    def _deliver(self, local: _Place, target: _Place) -> None:
        """Bring the target, then the local copy, up to date; the target's lines are final."""
        if target.state == "ok":
            end, delivered = target.end(), []
            pending = [e for e in local.entries.values() if e["id"] not in target.entries]
            for entry in sorted(pending, key=lambda e: e["seq"]):
                end += 1
                first = entry.get("provisional_seq", entry["seq"])
                line = {name: entry[name] for name in _JOURNAL_FIELDS} | {"seq": end}
                if end != first:
                    line["provisional_seq"] = first
                delivered.append(line)
            if delivered:
                try:
                    target.append(delivered)
                except (OSError, ValueError):
                    target.state = "unreachable"
        if target.state != "ok":
            return
        wanted = [e for e in target.entries.values() if local.entries.get(e["id"]) != e]
        if wanted:
            try:
                local.append(sorted(wanted, key=lambda e: e["seq"]))
            except (OSError, ValueError) as exc:
                raise JournalError(f"local copy of the journal {self.source}: {exc}") from None

    def record(self, kind: str, *, object_ref: str, sub: str, reason: str) -> dict:
        """Write one entry and return it (with its final seq once delivered)."""
        if not isinstance(kind, str) or kind not in JOURNAL_KINDS[self.source]:
            raise LifecycleError(f"kind {kind!r} is not allowed in the journal {self.source}")
        if not isinstance(object_ref, str) or not _OBJECT_REF_RE.fullmatch(object_ref):
            raise LifecycleError("object_ref must be an identifier of 1 to 256 characters")
        if not isinstance(reason, str) or not _JOURNAL_REASON_RE.fullmatch(reason):
            raise LifecycleError("reason must be a short code, never free text")
        subject_ref = self.subject_ref(sub)
        now = self.clock()
        at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1000):03d}Z"
        with self._locked():
            local, target = self._load()
            self._deliver(local, target)
            # Final while the target is usable (every entry is there now); provisional
            # otherwise: the highest number either place knows.
            entry = {
                "id": str(uuid.uuid4()),
                "module": self.source,
                "seq": max(local.end(), target.end()) + 1,
                "kind": kind,
                "object_ref": object_ref,
                "subject_ref": subject_ref,
                "at": at,
                "reason": reason,
            }
            try:
                local.append([entry])
            except (OSError, ValueError) as exc:
                raise JournalError(f"local copy of the journal {self.source}: {exc}") from None
            self._deliver(local, target)
            return dict(target.entries.get(entry["id"], entry))

    def flush(self) -> None:
        """Deliver buffered entries to the target."""
        with self._locked():
            self._deliver(*self._load())

    def status(self) -> dict:
        return JournalView(self.source, self.target_dir, self.local_dir).status()


class JournalView:
    """Reads a journal without its key, for the health check."""

    def __init__(self, source: str, target_dir: Path, local_dir: Path) -> None:
        self.source, self.target_dir, self.local_dir = source, Path(target_dir), Path(local_dir)

    def status(self) -> dict:
        """State of both places and the number of entries the target lacks; writes nothing
        and takes no lock."""
        local = _Place("local copy", self.local_dir, self.source)
        target = _Place("target", self.target_dir, self.source)
        missing = set(local.entries) - (set(target.entries) if target.state == "ok" else set())
        return {"local": local.state, "target": target.state, "pending": len(missing)}


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
        "journal_disabled": [],
        **json.loads(json.dumps(_RECONCILE_DEFAULTS)),
    }


def _check_state(doc: object) -> dict:
    if isinstance(doc, dict) and "journal_disabled" not in doc:
        doc["journal_disabled"] = []  # a state written before the journal knew it
    if not isinstance(doc, dict) or set(doc) != _STATE_KEYS or doc["format"] != STATE_FORMAT:
        raise LifecycleError("state: unknown format or fields")
    disabled = doc["journal_disabled"]
    if (
        not isinstance(disabled, list)
        or len(disabled) > MAX_ENTRIES
        or not all(isinstance(s, str) and _SUB_RE.match(s) for s in disabled)
    ):
        raise LifecycleError("state: journal_disabled is malformed")
    for name in ("seq", "issued_at", "last_poll"):
        _int(doc[name], name)
    for name in ("global_since", "audited_global_since"):
        if doc[name] is not None:
            _int(doc[name], name)
    if doc["mark_ms"] is not None:
        _int(doc["mark_ms"], "mark_ms")
    for name in ("last_reconcile", "disabled_with_consent"):
        _int(doc[name], name)
    for name in ("gap_revoke_at", "started_at"):
        if doc[name] is not None:
            _int(doc[name], name)
    if not isinstance(doc["gap_pending"], bool):
        raise LifecycleError("state: gap_pending must be true or false")
    disabled = doc["disabled"]
    if not isinstance(disabled, dict) or len(disabled) > MAX_ENTRIES:
        raise LifecycleError("state: disabled is malformed")
    for sub, seen in disabled.items():
        if not _SUB_RE.match(sub):
            raise LifecycleError("state: disabled is malformed")
        _int(seen, "disabled")
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
    for eid, item in list(parked.items()):
        if isinstance(item, dict) and set(item) == _LEGACY_PARKED_KEYS:
            item = parked[eid] = {
                "time": item["time"],
                "op": item["op"],
                "type": "USER",
                "path": f"users/{item['sub']}",
            }
        if (
            not _EVENT_ID_RE.match(eid)
            or not isinstance(item, dict)
            or set(item) != _PARKED_KEYS
            or classify(_parked_event(eid, item)) is None
        ):
            raise LifecycleError("state: parked is malformed")
        _int(item["time"], "parked time")
    return doc


def _parked_event(eid: str, item: dict) -> dict:
    return {
        "id": eid,
        "time": item["time"],
        "operationType": item["op"],
        "resourceType": item["type"],
        "resourcePath": item["path"],
    }


def user_event(row: object) -> dict | None:
    """A user event of the realm (GET /events) in the form of an admin event, so it is
    classified, ordered and parked like one. A row the service does not journal (a plain
    sign-out of one application, a malformed row) keeps only its id and time: it still
    moves the read position, or a full page of such rows would hold it back for ever.
    Only the type, the account, the time, the id and a removed credential's id are
    kept: no address, session, user name or other detail. None for a row that is no
    object."""
    if not isinstance(row, dict):
        return None
    position_only = {
        "id": row.get("id"),
        "time": row.get("time"),
        "operationType": "NONE",
        "resourceType": USER_EVENT,
        "resourcePath": "",
    }
    etype, uid = row.get("type"), row.get("userId")
    if etype not in USER_EVENT_TYPES or not isinstance(uid, str) or not _SUB_RE.fullmatch(uid):
        return position_only
    if etype == "UPDATE_PASSWORD":
        path = f"users/{uid}/password"
    elif etype == "REMOVE_CREDENTIAL":
        details = row.get("details")
        cid = details.get("selected_credential_id") if isinstance(details, dict) else None
        valid = isinstance(cid, str) and re.fullmatch(_ID, cid)
        path = f"users/{uid}/credentials/{cid}" if valid else f"users/{uid}/credentials"
    elif row.get("clientId") == ACCOUNT_API_CLIENT:
        path = f"users/{uid}/sessions"  # sessions ended in the account console
    else:
        return position_only  # a plain sign-out of one application
    return {
        "id": row.get("id"),
        "time": row.get("time"),
        "operationType": etype,
        "resourceType": USER_EVENT,
        "resourcePath": path,
    }


def classify(event: object) -> tuple[str, str, str] | None:
    """(action, account id, object_ref) of an admin event, or of a user event in the form
    `user_event` gives it, that the service acts on, else None.

    `account_update` is a changed account (revoked when it is now disabled); every other
    action is the kind of its identity journal entry. Paths are matched in full, so a
    deleted credential is never taken for a deleted account."""
    if not isinstance(event, dict):
        return None
    rtype, op = event.get("resourceType"), event.get("operationType")
    path = event.get("resourcePath")
    if not isinstance(path, str):
        return None
    if rtype == USER_EVENT:
        if op == "UPDATE_PASSWORD" and (m := _OWN_PASSWORD_RE.fullmatch(path)):
            return "credential_reset", m[1], "password"
        if op == "REMOVE_CREDENTIAL" and (m := _OWN_CREDENTIAL_RE.fullmatch(path)):
            return "credential_reset", m[1], f"credential:{m[2]}" if m[2] else "credential"
        if op == "LOGOUT" and (m := _OWN_SESSIONS_RE.fullmatch(path)):
            return "session_revoke", m[1], "sessions"
        return None
    if rtype == "USER":
        if (m := _USER_PATH_RE.fullmatch(path)) and op in ("UPDATE", "DELETE"):
            return ("account_update" if op == "UPDATE" else "account_delete", m[1], "account")
        if (m := _USER_ACTION_RE.fullmatch(path)) and op == "ACTION":
            if m[2] == "logout":
                return "session_revoke", m[1], "sessions"
            return "credential_reset", m[1], "password"
        if (m := _CREDENTIAL_PATH_RE.fullmatch(path)) and op in ("DELETE", "ACTION"):
            return "credential_reset", m[1], f"credential:{m[2]}"
        return None
    if op != "DELETE":
        return None
    if rtype == "REALM_ROLE_MAPPING" and (m := _REALM_ROLES_RE.fullmatch(path)):
        return "role_revoke", m[1], "realm-roles"
    if rtype == "CLIENT_ROLE_MAPPING" and (m := _CLIENT_ROLES_RE.fullmatch(path)):
        return "role_revoke", m[1], f"client-roles:{m[2]}"
    if rtype == "GROUP_MEMBERSHIP" and (m := _GROUP_PATH_RE.fullmatch(path)):
        return "role_revoke", m[1], f"group:{m[2]}"
    return None


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
            doc = json.loads(raw)
        except ValueError:
            raise LifecycleError("state: not JSON") from None
        if isinstance(doc, dict):
            for key, value in _RECONCILE_DEFAULTS.items():
                doc.setdefault(key, json.loads(json.dumps(value)))
        return _check_state(doc)

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


def _token_sub(token: str) -> str | None:
    """`sub` of an access token Keycloak just issued to this service (read, not checked:
    it only tells the service which admin events it caused itself)."""
    try:
        claims = json.loads(b64decode(token.split(".")[1]))
    except (IndexError, ValueError):
        return None
    sub = claims.get("sub") if isinstance(claims, dict) else None
    return sub if isinstance(sub, str) and _SUB_RE.fullmatch(sub) else None


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
        # User id of the service account (`sub` of its token): its own logouts show in
        # the admin events and are not journaled a second time.
        self.actor_id: str | None = None

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

    def persons_group(self) -> str:
        """The id of papaia-persons from the account folder, read on every round so a
        realm sync that recreated the group takes effect without a restart."""
        path = self.account_dir / GROUP_FILE
        if not os.path.lexists(path):
            raise LifecycleError(
                "the id of the persons group is missing; run `papaia-ctl realm sync`"
            )
        raw = _read_private(path, 256)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise LifecycleError("the id of the persons group is malformed") from None
        text = text[:-1] if text.endswith("\n") else text
        if not _GROUP_ID_RE.fullmatch(text):
            raise LifecycleError("the id of the persons group is malformed")
        return text

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
        self.actor_id = _token_sub(self._token)
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
    def __init__(
        self,
        api,
        store: Store,
        publisher: Publisher,
        *,
        out=None,
        clock=time.time,
        journal: ErasureJournal | None = None,
    ) -> None:
        self.api, self.store, self.publisher = api, store, publisher
        self.out = out or sys.stdout
        self.clock = clock
        # The journal `identity` (sicherheit §4.9 (1)); only `global-since` runs without.
        self.journal = journal
        self._next_poll = 0.0
        # 0: reconcile on the first step (at start), then every RECONCILE_SECONDS.
        self._next_reconcile = 0.0
        # account -> time of its last LOGOUT of "sign out all devices": Keycloak writes
        # one LOGOUT per session, the journal one entry (see SIGN_OUT_MERGE_MS).
        self._sign_outs: dict[str, int] = {}

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

    def _journal(self, kind: str, sub: str, object_ref: str, correlation: str) -> None:
        """One entry in the journal `identity`, one audit row with the event's correlation
        id. A local copy that cannot be written raises: the event is tried again."""
        if self.journal is None:
            raise LifecycleError("no erasure journal configured")
        try:
            entry = self.journal.record(
                kind, object_ref=object_ref, sub=sub, reason=JOURNAL_REASONS[kind]
            )
        except LifecycleError:
            self._audit(
                "journal",
                "write",
                "operation",
                correlation,
                {"type": "erasure_journal", "id": self.journal.source},
                "error",
                "journal_unavailable",
                {"kind": kind},
            )
            raise
        self._audit(
            "journal",
            "write",
            "operation",
            correlation,
            {"type": "erasure_journal", "id": f"{entry['module']}:{entry['seq']}"},
            detail={"kind": kind},
        )

    def _flush_journal(self) -> None:
        """Deliver entries the target did not take yet (it was unreachable)."""
        if self.journal is None:
            return
        try:
            self.journal.flush()
        except RETRYABLE as exc:
            _log(f"delivering the erasure journal failed ({exc}); trying again")

    # list -------------------------------------------------------------
    def start(self) -> None:
        """Make the key, set the first read position, publish a list at once."""
        self.publisher.signer.ensure()
        self._flush_journal()
        with self.store.locked():
            state = self.store.load()
            if state["mark_ms"] is None:
                state["mark_ms"] = max(0, int(self.clock() * 1000) - FIRST_LOOKBACK_MS)
            if state["started_at"] is None:
                state["started_at"] = int(self.clock())
            # last_poll is left alone: a restart must not hide a poll that keeps failing
            # (the health check's start period covers the first poll).
            self._note_gap(state)
            self._issue(state, force=True)

    def _note_gap(self, state: dict) -> None:
        """Mark a gap revoke as due when the last successful read of the events is older
        than Keycloak keeps them. Kept in the state until the gap revoke succeeded, so a
        successful poll in between cannot make the service forget it."""
        # A gap revoke covers everything up to the time it ran.
        last = max(state["last_poll"], state["gap_revoke_at"] or 0)
        if last and int(self.clock()) - last > EVENT_RETENTION_SECONDS and not state["gap_pending"]:
            state["gap_pending"] = True
            self._next_reconcile = 0.0
            _log(
                f"no events read for {int(self.clock()) - last} s, longer than Keycloak keeps "
                "them: every consent at a holder client is removed"
            )

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
    def _read(self, path: str, params: list[tuple[str, str]]) -> tuple[list, bool]:
        """The rows of one event stream, oldest first; True when more rows wait than one
        poll reads."""
        rows: list = []
        for page in range(MAX_EVENT_PAGES):
            query = urllib.parse.urlencode(
                [
                    *params,
                    ("direction", "asc"),
                    ("first", str(page * EVENT_PAGE)),
                    ("max", str(EVENT_PAGE)),
                ]
            )
            batch = self.api.call("GET", f"{path}?{query}")
            if not isinstance(batch, list):
                raise LifecycleError(f"{path.strip('/')}: not a list")
            rows.extend(batch)
            if len(batch) < EVENT_PAGE:
                return rows, False
        return rows, True

    def _events(self, since_ms: int) -> list[dict]:
        """Admin and user events from `since_ms` (both share one read position). While a
        stream holds more than one poll reads, events after its last row read wait for
        the next poll, so the position never passes an event not read yet."""
        since = ("dateFrom", str(since_ms))
        admin = self._read(
            "/admin-events",
            [
                *(("resourceTypes", t) for t in EVENT_RESOURCE_TYPES),
                *(("operationTypes", o) for o in EVENT_OPERATION_TYPES),
                since,
            ],
        )
        users = self._read("/events", [*(("type", t) for t in USER_EVENT_TYPES), since])
        limits = [
            max((t for t in map(_event_time, rows) if t is not None), default=since_ms)
            for rows, more in (admin, users)
            if more
        ]
        events = admin[0] + [e for e in map(user_event, users[0]) if e is not None]
        if limits:
            events = [e for e in events if (_event_time(e) or 0) <= min(limits)]
        return events

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
            self._note_gap(state)
            state["last_poll"] = int(self.clock())
            self.store.save(state)

    def _failed(self, eid: str, event: dict, when_ms: int, exc: Exception) -> bool:
        """Count a failed attempt; after MAX_EVENT_ATTEMPTS park the event (True) so the
        poll goes on with later events. False: the poll stops and tries it again."""
        action = classify(event)
        with self.store.locked():
            state = self.store.load()
            count = state["attempts"].get(eid, 0) + 1
            if count < MAX_EVENT_ATTEMPTS or action is None or len(state["parked"]) >= MAX_PARKED:
                state["attempts"][eid] = min(count, MAX_EVENT_ATTEMPTS)
                self.store.save(state)
                return False
            state["attempts"].pop(eid, None)
            state["parked"][eid] = {
                "time": when_ms,
                "op": event["operationType"],
                "type": event["resourceType"],
                "path": event["resourcePath"],
            }
            self.store.save(state)
        _log(f"event {eid} failed {count} times ({exc}); parked, later events go ahead")
        self._audit(
            "revocation_parked",
            "write",
            "operation",
            _uuid7(),
            {"type": "user", "id": action[1]},
            "error",
            "retries_exhausted",
            {"attempts": count},
        )
        return True

    def _retry_parked(self) -> None:
        with self.store.locked():
            parked = dict(self.store.load()["parked"])
        for eid, item in sorted(parked.items(), key=lambda kv: (kv[1]["time"], kv[0])):
            try:
                self._handle(_parked_event(eid, item), item["time"])
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
        in health make the gap visible; the reconciliation looks at it again."""
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
        """Act on one event; every identity change of a person it stands for is one
        journal entry, written after the revocation (a failure retries both, which
        repeat harmlessly)."""
        action = classify(event)
        if action is None:
            return
        kind, sub, object_ref = action
        since = math.ceil(when_ms / 1000)
        correlation = _uuid7()
        if kind == "account_update":
            try:
                user = self.api.call("GET", f"/users/{sub}")
            except HttpError as exc:
                if exc.status == 403:
                    self._skipped(sub, since)
                    return
                if exc.status != 404:
                    raise
                kind = "account_delete"
            else:
                if not isinstance(user, dict) or user.get("enabled") is not False:
                    # Not (or no longer) disabled: a later deactivation is journaled anew.
                    self._disabled(sub, False)
                if not isinstance(user, dict):
                    return
                if user.get("enabled") is True:
                    self._activated(sub)
                    if int(self.clock() * 1000) - when_ms > LATE_EVENT_SECONDS * 1000:
                        self._late_update(sub, when_ms, correlation)
                    return
                if user.get("enabled") is not False:
                    return
                with self.store.locked():
                    seen = self.store.load()["disabled"].get(sub, -1)
                if seen < when_ms:  # else the reconciliation revoked it after this event
                    self.revoke(sub, since, "account_disabled", correlation)
                    self._seen_disabled(sub, int(self.clock() * 1000))
                if not self._disabled(sub, None):
                    self._journal("account_disable", sub, object_ref, correlation)
                    self._disabled(sub, True)
                return
        if kind == "account_delete":
            self._list(sub, since, "account_deleted")
            self._journal(kind, sub, object_ref, correlation)
            self._disabled(sub, False)
            return
        auth = event.get("authDetails")
        actor = auth.get("userId") if isinstance(auth, dict) else None
        own = getattr(self.api, "actor_id", None)
        if kind == "session_revoke" and own is not None and actor == own:
            return  # the service's own logout, covered by the entry that caused it
        sign_out = kind == "session_revoke" and event.get("resourceType") == USER_EVENT
        if sign_out and self._same_sign_out(sub, when_ms):
            return  # one more session of the same "sign out all devices"
        if not self._person(sub, kind):
            return
        self._journal(kind, sub, object_ref, correlation)
        if sign_out:
            self._sign_outs[sub] = when_ms

    def _same_sign_out(self, sub: str, when_ms: int) -> bool:
        """Whether a LOGOUT of the account console follows one of the same account within
        SIGN_OUT_MERGE_MS (the window slides with every merged LOGOUT). Kept in memory
        only: after a restart or for a parked retry a second entry is possible, which a
        replay repeats harmlessly (sessions that are gone stay gone)."""
        horizon = when_ms - SIGN_OUT_MERGE_MS
        self._sign_outs = {s: t for s, t in self._sign_outs.items() if t >= horizon}
        last = self._sign_outs.get(sub)
        if last is None or when_ms < last:
            return False
        self._sign_outs[sub] = when_ms
        return True

    def _person(self, sub: str, kind: str) -> bool:
        """Only persons are journaled: an account the service may not read (outside
        papaia-persons, 403: service and admin accounts) writes no entry, nor does one
        that is gone (404: its deletion is an entry of its own)."""
        try:
            self.api.call("GET", f"/users/{sub}")
        except HttpError as exc:
            if exc.status == 403:
                _log(f"account {sub} is outside the group of persons; {kind} not journaled")
                return False
            if exc.status == 404:
                return False
            raise
        return True

    def _disabled(self, sub: str, value: bool | None) -> bool:
        """Whether the journal already holds the deactivation of `sub` (value None), or
        record that it does (True) or no longer does (False). An account that stays
        disabled is revoked again on every change, but journaled once."""
        with self.store.locked():
            state = self.store.load()
            known = sub in state["journal_disabled"]
            if value is None or value == known:
                return known
            if value and len(state["journal_disabled"]) >= MAX_ENTRIES:
                return known
            rest = set(state["journal_disabled"]) - {sub}
            state["journal_disabled"] = sorted(rest | ({sub} if value else set()))
            self.store.save(state)
        return value

    def _list(self, sub: str, since: int, reason: str) -> None:
        with self.store.locked():
            state = self.store.load()
            current = state["entries"].get(sub)
            if current is None or current["since"] < since:
                state["entries"][sub] = {"since": since, "reason": reason}
            self._issue(state)

    def revoke(self, sub: str, since: int, reason: str, correlation: str | None = None) -> None:
        """List first (modules refuse the person's tokens within 15 s even if a call
        below fails), then end the sessions and remove every consent."""
        if not _SUB_RE.fullmatch(sub):
            raise LifecycleError("malformed account id")
        self._list(sub, since, reason)
        correlation = correlation or _uuid7()
        self._write("POST", f"/users/{sub}/logout", "logout", "operation", correlation, sub)
        for client, _ in self._consents(sub):
            self._delete_consent(sub, client, correlation)

    # reconciliation ---------------------------------------------------
    def _users(self, *, enabled: bool | None) -> list[str]:
        """Ids of the members of the persons group (the accounts the service may see),
        all of them or by state. The members endpoint has no filter by state."""
        group = urllib.parse.quote(self.api.persons_group(), safe="-")
        ids: list[str] = []
        for page in range(MAX_USER_PAGES):
            params = [
                ("briefRepresentation", "true"),
                ("first", str(page * USER_PAGE)),
                ("max", str(USER_PAGE)),
            ]
            batch = self.api.call(
                "GET", f"/groups/{group}/members?{urllib.parse.urlencode(params)}"
            )
            if not isinstance(batch, list):
                raise LifecycleError("users: not a list")
            for user in batch:
                uid = user.get("id") if isinstance(user, dict) else None
                if not isinstance(uid, str) or not _SUB_RE.match(uid):
                    continue
                if enabled is not None and user.get("enabled") is not enabled:
                    continue
                ids.append(uid)
            if len(batch) < USER_PAGE:
                return list(dict.fromkeys(ids))
        raise LifecycleError(f"more than {MAX_USER_PAGES * USER_PAGE} accounts")

    def _consents(self, sub: str) -> list[tuple[str, int]]:
        """(client id, created in ms) of every consent; malformed client ids are left out
        and never put into a path."""
        rows = self.api.call("GET", f"/users/{sub}/consents") or []
        found: list[tuple[str, int]] = []
        for consent in rows if isinstance(rows, list) else []:
            client = consent.get("clientId") if isinstance(consent, dict) else None
            if not isinstance(client, str) or not _CLIENT_ID_RE.match(client) or ".." in client:
                _log(f"consent of account {sub} with a malformed client id skipped")
                continue
            created = consent.get("createdDate")
            if isinstance(created, bool) or not isinstance(created, int) or created < 0:
                created = 0
            found.append((client, created))
        return found

    def _delete_consent(self, sub: str, client: str, correlation: str) -> None:
        self._write(
            "DELETE",
            f"/users/{sub}/consents/{urllib.parse.quote(client, safe='')}",
            "consent_delete",
            "delegation_revoked",
            correlation,
            sub,
            {"client": client},
        )

    def _seen_disabled(self, sub: str, at_ms: int) -> None:
        """Record that the deactivated account `sub` was revoked at `at_ms`."""
        with self.store.locked():
            state = self.store.load()
            if len(state["disabled"]) < MAX_ENTRIES or sub in state["disabled"]:
                state["disabled"][sub] = max(at_ms, state["disabled"].get(sub, 0))
                self.store.save(state)

    def _activated(self, sub: str) -> None:
        """An account known as deactivated is active again: the consents from before the
        deactivation go (they survived only if a removal failed); a consent granted
        since stays. Known: revoked by this service (`disabled`, the time in ms) or
        listed as deactivated (`since` of its entry)."""
        with self.store.locked():
            state = self.store.load()
        seen = state["disabled"].get(sub)
        entry = state["entries"].get(sub)
        if entry is not None and entry["reason"] == "account_disabled":
            seen = max(seen or 0, entry["since"] * 1000)
        if seen is None:
            return
        correlation = _uuid7()
        for client, created in self._consents(sub):
            if created < seen:
                self._delete_consent(sub, client, correlation)
        with self.store.locked():
            state = self.store.load()
            if state["disabled"].pop(sub, None) is not None:
                self.store.save(state)

    def _late_update(self, sub: str, when_ms: int, correlation: str) -> None:
        """An update of an active account read late: it may have been a deactivation
        undone before the read, which the account no longer shows. Every consent at a
        holder client created before the event goes; a grant after it stays."""
        old = [c for c, created in self._consents(sub) if c in HOLDER_CLIENTS and created < when_ms]
        if not old:
            return
        _log(
            f"update of account {sub} read {int(self.clock() - when_ms / 1000)} s late: "
            f"{len(old)} delegation(s) from before it removed"
        )
        for client in old:
            self._delete_consent(sub, client, correlation)

    def _gap_revoke(self) -> None:
        """Every consent at a holder client of every account the service can see."""
        correlation, count, persons = _uuid7(), 0, 0
        for sub in self._users(enabled=None):
            held = [c for c, _ in self._consents(sub) if c in HOLDER_CLIENTS]
            for client in held:
                self._delete_consent(sub, client, correlation)
            count += len(held)
            persons += 1 if held else 0
        with self.store.locked():
            state = self.store.load()
            state["gap_pending"] = False
            state["gap_revoke_at"] = int(self.clock())
            self.store.save(state)
        _log(f"gap revoke: {count} consent(s) of {persons} account(s) removed")
        self._audit(
            "gap_revoke",
            "delete",
            "delegation_revoked",
            correlation,
            {"type": "realm", "id": REALM},
            detail={"count": count, "persons": persons, "reason": "lifecycle_gap_revoke"},
        )

    def reconcile(self) -> None:
        """Independent of events: the gap revoke when due, then every deactivated account
        revoked once and stripped of every consent it still holds, accounts seen
        deactivated and active again stripped of their old consents, and accounts that
        could not be read (outside the group) looked at again."""
        with self.store.locked():
            state = self.store.load()
        if state["gap_pending"]:
            self._gap_revoke()
        now = int(self.clock())
        now_ms = int(self.clock() * 1000)
        disabled = self._users(enabled=False)
        still_holding = 0
        for sub in disabled:
            with self.store.locked():
                known = sub in self.store.load()["disabled"]
            try:
                consents = self._consents(sub)
                if consents or not known:
                    self.revoke(sub, now, "account_disabled")
            except RETRYABLE as exc:
                # Not marked as revoked: the next round and a later event try again.
                _log(f"reconciling account {sub} failed ({exc})")
                # Counted unless a read shows that nothing is left.
                try:
                    still_holding += 1 if self._consents(sub) else 0
                except RETRYABLE:
                    still_holding += 1
                continue
            self._seen_disabled(sub, now_ms)
        current = set(disabled)
        with self.store.locked():
            state = self.store.load()
        for sub in sorted(set(state["disabled"]) - current):
            self._recheck(sub, now)
        for sub in sorted(set(state["skipped"]) - current):
            self._recheck(sub, now)
        with self.store.locked():
            state = self.store.load()
            for sub in current:
                state["skipped"].pop(sub, None)
            state["last_reconcile"] = now
            state["disabled_with_consent"] = still_holding
            self.store.save(state)

    def _recheck(self, sub: str, now: int) -> None:
        """An account that left the deactivated set, or one the service could not read
        before: deleted, active again, or still out of reach."""
        try:
            user = self.api.call("GET", f"/users/{sub}")
        except HttpError as exc:
            if exc.status not in (403, 404):
                raise
            if exc.status == 404:
                self._list(sub, now, "account_deleted")
            with self.store.locked():
                state = self.store.load()
                state["disabled"].pop(sub, None)
                if exc.status == 404:
                    state["skipped"].pop(sub, None)
                self.store.save(state)
            return
        if not isinstance(user, dict):
            return
        if user.get("enabled") is True:
            with self.store.locked():
                state = self.store.load()
                since = state["skipped"].pop(sub, None)
                if since is not None and sub not in state["disabled"]:
                    # A deactivation it could not act on: consents from before go.
                    state["disabled"][sub] = since * 1000
                self.store.save(state)
            self._activated(sub)

    # loop -------------------------------------------------------------
    def _reconcile_now(self, now: float) -> None:
        try:
            self.reconcile()
        except RETRYABLE as exc:
            self._next_reconcile = now + RECONCILE_RETRY_SECONDS
            _log(f"reconciliation failed ({exc!r}); trying again in {RECONCILE_RETRY_SECONDS} s")
            return
        self._next_reconcile = now + RECONCILE_SECONDS

    def step(self, *, force_poll: bool = False) -> None:
        now = self.clock()
        if now >= self._next_reconcile:
            self._reconcile_now(now)
        if force_poll or now >= self._next_poll:
            self._next_poll = now + POLL_SECONDS
            try:
                self.poll()
            except RETRYABLE as exc:
                _log(f"reading the events failed ({exc!r}); trying again")
            if self._next_reconcile == 0.0:  # the poll found a gap
                self._reconcile_now(now)
            self._flush_journal()
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


def health(
    state_dir: Path, key_dir: Path, *, now: float | None = None, journal=None
) -> tuple[int, dict]:
    """`revocations_age_seconds` of the published list; 1 when it is older than 60 s,
    does not verify, Keycloak has not been read for 60 s, or an event is parked; `fail`
    also when the last reconciliation is older than 2 h or a deactivated account still
    holds a consent (`disabled_with_consent`). `skipped_revocations` counts accounts that
    could not be read (outside the group); `gap_revoke_age_seconds` tells since when the
    last gap revoke ran (it does not make the container unhealthy: `doctor lifecycle`
    warns about it). With the journal: `journal_pending` entries not at the backup target
    yet and `journal_target` (ok, unreachable, corrupt) warn; a damaged local copy fails."""
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
    report["last_reconcile_age_seconds"] = (
        max(0, int(now - state["last_reconcile"])) if state["last_reconcile"] else None
    )
    report["disabled_with_consent"] = state["disabled_with_consent"]
    report["gap_revoke_age_seconds"] = (
        max(0, int(now - state["gap_revoke_at"])) if state["gap_revoke_at"] is not None else None
    )
    journal_ok = True
    if journal is not None:
        place = journal.status()
        report["journal_pending"] = place["pending"]
        report["journal_target"] = place["target"]
        if place["local"] != "ok":
            return 1, report
        journal_ok = place["pending"] == 0 and place["target"] == "ok"
    worst = max(age, report["last_poll_age_seconds"])
    reconcile_age = report["last_reconcile_age_seconds"]
    if reconcile_age is None and state["started_at"] is not None:
        # No round has succeeded yet: counted from the first start, so a round that never
        # works is not healthy forever (events read in between do not change that).
        reconcile_age = max(0, int(now - state["started_at"]))
    if (
        worst > FAIL_AGE_SECONDS
        or state["disabled_with_consent"]
        or (reconcile_age is not None and reconcile_age > RECONCILE_FAIL_SECONDS)
    ):
        return 1, report
    if worst > WARN_AGE_SECONDS or state["parked"] or not journal_ok:
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
        if name in ("run", "health"):
            cmd.add_argument("--journal-dir", type=Path, required=name == "run")
            cmd.add_argument("--journal-local-dir", type=Path, required=name == "run")
        if name == "run":
            cmd.add_argument("--erasure-key", type=Path, required=True)
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
        view = None
        if args.journal_dir is not None and args.journal_local_dir is not None:
            view = JournalView(IDENTITY_SOURCE, args.journal_dir, args.journal_local_dir)
        code, report = health(args.state_dir, args.key_dir, journal=view)
        print(json.dumps(report, sort_keys=True))
        return code
    store, publisher = Store(args.key_dir), Publisher(args.state_dir, Signer(args.key_dir))
    if args.command == "global-since":
        return _global_since(Lifecycle(None, store, publisher), args)
    ctx = None
    if urllib.parse.urlsplit(keycloak_url(args.keycloak_url)).scheme == "https":
        ctx = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    journal = ErasureJournal(
        IDENTITY_SOURCE,
        key=read_erasure_key(args.erasure_key),
        target_dir=args.journal_dir,
        local_dir=args.journal_local_dir,
    )
    service = Lifecycle(
        AccountClient(args.keycloak_url, ctx, args.account_dir), store, publisher, journal=journal
    )
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
