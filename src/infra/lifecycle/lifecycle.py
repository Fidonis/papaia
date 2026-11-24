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

A sign-in (user event `LOGIN`) of the emergency account (its id in `breakglass-ids`
next to the account key, written by `papaia-ctl breakglass`) is one audit row
`breakglass_login` and an alert line in the log (security 1.15); any other sign-in is
only read past.

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
import calendar
import contextlib
import email.message
import fcntl
import hashlib
import hmac
import html
import http.client
import http.server
import ipaddress
import json
import math
import os
import re
import signal
import smtplib
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
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
# The ids of the emergency account, one per line, next to the account key.
BREAKGLASS_FILE = "breakglass-ids"
STATE_FORMAT = "papaia.lifecycle-state/1"

POLL_SECONDS = 10
REISSUE_SECONDS = 15
WARN_AGE_SECONDS = 60
FAIL_AGE_SECONDS = 300
# On the very first start, events this far back are read as well (clock skew between
# the host and Keycloak); handling an event twice changes nothing.
FIRST_LOOKBACK_MS = 60_000
# Longest life of a delegation (offline session; delegations.max_days, at most 365 days)
# plus one day: older entries can no longer match a token.
ENTRY_RETENTION_SECONDS = 366 * 24 * 3600
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
# Status sync with the upstream directory (federation, security 1.13): every 60 s; failing
# for longer than 300 s is `fail`, one `status_sync_failed` row and one warning mail.
STATUS_SYNC_SECONDS = 60
STATUS_SYNC_FAIL_SECONDS = 300
# Accounts found not federated are looked at again once a day (with the full refresh).
FULL_SYNC_SECONDS = 24 * 3600
STATUS_FILE = "status-sync.json"
FEDERATION_ALIAS = "upstream"
STATUS_FORMAT = "papaia.status-sync/1"
MAX_MAPPED_GROUPS = 500
# Marker roles of the last federated sign-in (lib/federation.py sets the mappers).
GROUPS_ROLE = "papaia-idp-groups"
OVERAGE_ROLE = "papaia-idp-group-overage"
MAX_REFUSALS_KEPT = 1000
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
_OWN_LOGIN_RE = re.compile(rf"users/({_ID})/login")
_SUB_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_GROUP_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_MAIL_RE = re.compile(r"[^@\s,;<>\"']{1,64}@[A-Za-z0-9.-]{1,253}")
# Keycloak's id of one sign-in attempt (`code_id` of an event).
_ATTEMPT_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
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
    "federation",
    "names",
    "tombstones",
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
    # The status sync with the upstream directory (federation); see StatusSync.
    "federation": {
        "configured": False,
        "started": None,
        "last_ok": 0,
        "failing_since": None,
        "reported": False,
        "links": {},
        "disabled": {},
        "not_before": {},
        "members": {},
        "last_full": 0,
    },
    # Name index of the persons (security 1.14 no. 2b): sub -> HMAC of the normalized
    # user name and mail, last seen state, day of the last sign-in. Never a clear name.
    "names": {},
    # Tombstones of deleted accounts: sub -> the two HMACs and the time of deletion. They
    # stay like the erasure journal; a new account with the name of one is disabled.
    "tombstones": {},
}
_PARKED_KEYS = {"time", "op", "type", "path"}
_NAME_KEYS = {"name", "mail", "enabled", "login", "locked"}
_TOMBSTONE_KEYS = {"name", "mail", "deleted"}
_REF_RE = re.compile(r"^[0-9a-f]{64}$")
DAY_SECONDS = 24 * 3600
# `find` answers at most this many persons for one name or mail.
FIND_MAX = 20
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
# A sign-in (`LOGIN`) is read for the emergency account only (security 1.15).
USER_EVENT_TYPES = ("UPDATE_PASSWORD", "REMOVE_CREDENTIAL", "LOGOUT", "LOGIN")
# A sign-in through the upstream provider that the post sign-in flow refused (federation,
# docs/federation.md): read to write `idp_group_overflow`, never journaled.
IDP_ERROR_TYPES = ("IDENTITY_PROVIDER_POST_LOGIN_ERROR",)
IDP_REFUSED = "IDP_REFUSED"
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
    _check_federation(doc["federation"])
    _check_names(doc["names"], doc["tombstones"])
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


def _ref_or_none(value: object) -> bool:
    return value is None or (isinstance(value, str) and bool(_REF_RE.match(value)))


def _check_names(names: object, tombstones: object) -> None:
    if not isinstance(names, dict) or len(names) > MAX_ENTRIES:
        raise LifecycleError("state: names is malformed")
    for sub, item in names.items():
        if (
            not _SUB_RE.match(sub)
            or not isinstance(item, dict)
            or set(item) != _NAME_KEYS
            or not _ref_or_none(item["name"])
            or not _ref_or_none(item["mail"])
            or item["enabled"] not in (True, False, None)
            or not isinstance(item["locked"], bool)
        ):
            raise LifecycleError("state: names is malformed")
        if item["login"] is not None:
            _int(item["login"], "login")
    if not isinstance(tombstones, dict) or len(tombstones) > MAX_ENTRIES:
        raise LifecycleError("state: tombstones is malformed")
    for sub, item in tombstones.items():
        if (
            not _SUB_RE.match(sub)
            or not isinstance(item, dict)
            or set(item) != _TOMBSTONE_KEYS
            or not _ref_or_none(item["name"])
            or not _ref_or_none(item["mail"])
        ):
            raise LifecycleError("state: tombstones is malformed")
        _int(item["deleted"], "deleted")


def normalized(value: str) -> str:
    """User names and mail addresses as compared: NFKC, no outer blanks, case folded."""
    return unicodedata.normalize("NFKC", value).strip().casefold()


def name_ref(key: bytes, value: object) -> str | None:
    """HMAC-SHA256(erasure-hmac, normalized value) of a user name or mail address; None
    for no value. `papaia-ctl person find` hashes its input with the same function."""
    if not isinstance(value, str) or not normalized(value):
        return None
    text = normalized(value)
    if len(text) > 320 or _CONTROL_RE.search(text):
        return None
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def find(store: Store, name: str | None, mail: str | None) -> list[dict]:
    """The persons whose user name or mail has the HMAC `name` or `mail`, from the name
    index and the tombstones: sub, status (active, disabled, deleted or unknown), day of
    the last sign-in and day of the deletion. Never a name, never content."""
    if not (name or mail) or not _ref_or_none(name) or not _ref_or_none(mail):
        raise LifecycleError("find needs the HMAC of a name or of a mail address")
    with store.locked():
        state = store.load()

    def hit(item: dict) -> bool:
        return bool((name and item["name"] == name) or (mail and item["mail"] == mail))

    def day(seconds: int | None) -> str | None:
        return None if seconds is None else time.strftime("%Y-%m-%d", time.gmtime(seconds))

    found: dict[str, dict] = {}
    for sub, item in sorted(state["tombstones"].items()):
        if hit(item):
            found[sub] = {"sub": sub, "status": "deleted", "last_login": None,
                          "deleted": day(item["deleted"])}
    for sub, item in sorted(state["names"].items()):
        if hit(item) and sub not in found:
            status = {True: "active", False: "disabled", None: "unknown"}[item["enabled"]]
            found[sub] = {"sub": sub, "status": status, "last_login": day(item["login"]),
                          "deleted": None}
    return list(found.values())[:FIND_MAX]


# `papaia-ctl person export|erase` through `docker exec` (security 1.14 no. 2, 2a; RE-100):
# the identity provider's part of a confirmed request, run as svc-papaia-lifecycle, the one
# account that may end sessions and delete persons. The host audits every call with the
# request id; the running service journals the deactivation and the deletion from their
# admin events and keeps the tombstone.
PERSON_OPERATIONS = ("export", "revoke", "delete", "check")
PERSON_ACCOUNT_FIELDS = (
    "id", "username", "firstName", "lastName", "email", "emailVerified", "enabled",
    "createdTimestamp", "attributes", "requiredActions",
)
PERSON_EVENT_FIELDS = ("time", "type", "clientId", "ipAddress")
PERSON_CONSENT_FIELDS = ("clientId", "createdDate", "lastUpdatedDate", "grantedClientScopes")
PERSON_LINK_FIELDS = ("identityProvider", "userId", "userName")
PERSON_MAX_EVENTS = 1000


def person_request(client, request: object) -> dict:
    """One operation for one person: `export` (account, groups, realm roles, linked
    upstream identity, consents and stored sign-in events; never credentials), `revoke`
    (disable, end every session, remove every consent), `delete`, `check` (does the
    account still exist). An account that is gone answers `found: false` or a count of 0."""
    if not isinstance(request, dict) or set(request) != {"operation", "sub"}:
        raise LifecycleError("the request must hold exactly operation and sub")
    operation, sub = request["operation"], request["sub"]
    if operation not in PERSON_OPERATIONS:
        raise LifecycleError(f"operation must be one of {', '.join(PERSON_OPERATIONS)}")
    if not isinstance(sub, str) or not _SUB_RE.fullmatch(sub):
        raise LifecycleError("malformed account id")

    def get(path: str):
        try:
            return client.call("GET", path)
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise

    account = get(f"/users/{sub}")
    if account is not None and not isinstance(account, dict):
        raise LifecycleError("the identity provider answered no account")
    if operation == "check":
        return {"counts": {"identity_accounts": int(account is not None)}}
    if operation == "delete":
        if account is None:
            return {"counts": {"identity_accounts": 0}}
        try:
            client.call("DELETE", f"/users/{sub}")
        except HttpError as exc:
            if exc.status != 404:
                raise
            return {"counts": {"identity_accounts": 0}}
        return {"counts": {"identity_accounts": 1}}
    if account is None:
        empty: dict = {"found": False, "mails": []}
        return empty | ({"data": {"account": None}} if operation == "export" else {"counts": {}})
    mail = account.get("email")
    mails = [mail] if isinstance(mail, str) and _MAIL_RE.fullmatch(mail) else []
    consents = [c for c in get(f"/users/{sub}/consents") or [] if isinstance(c, dict)]
    if operation == "export":

        def pick(row: object, fields: tuple) -> dict:
            return {k: row[k] for k in fields if k in row} if isinstance(row, dict) else {}

        query = urllib.parse.urlencode({"user": sub, "max": PERSON_MAX_EVENTS})
        data = {
            "account": pick(account, PERSON_ACCOUNT_FIELDS),
            "groups": [g.get("path") for g in get(f"/users/{sub}/groups") or []
                       if isinstance(g, dict)],
            "roles": [r.get("name") for r in get(f"/users/{sub}/role-mappings/realm") or []
                      if isinstance(r, dict)],
            "links": [pick(x, PERSON_LINK_FIELDS)
                      for x in get(f"/users/{sub}/federated-identity") or []],
            "consents": [pick(c, PERSON_CONSENT_FIELDS) for c in consents],
            "events": [pick(e, PERSON_EVENT_FIELDS) for e in get(f"/events?{query}") or []],
        }
        return {"found": True, "mails": mails, "data": data}
    counts = {"accounts_disabled": 0, "sessions_ended": 0, "consents_removed": 0}
    if account.get("enabled") is not False:
        client.call("PUT", f"/users/{sub}", {"enabled": False})
        counts["accounts_disabled"] = 1
    client.call("POST", f"/users/{sub}/logout")
    counts["sessions_ended"] = 1
    for consent in consents:
        holder = consent.get("clientId")
        if not isinstance(holder, str) or not _CLIENT_ID_RE.fullmatch(holder):
            raise LifecycleError("the identity provider answered a malformed client id")
        client.call("DELETE", f"/users/{sub}/consents/{urllib.parse.quote(holder, safe='')}")
        counts["consents_removed"] += 1
    return {"found": True, "mails": mails, "counts": counts}


def _check_federation(fed: object) -> None:
    keys = set(_RECONCILE_DEFAULTS["federation"])
    if not isinstance(fed, dict) or set(fed) != keys:
        raise LifecycleError("state: federation is malformed")
    for name in ("configured", "reported"):
        if not isinstance(fed[name], bool):
            raise LifecycleError(f"state: federation.{name} must be true or false")
    for name in ("last_ok", "last_full"):
        _int(fed[name], f"federation.{name}")
    for name in ("started", "failing_since"):
        if fed[name] is not None:
            _int(fed[name], f"federation.{name}")
    links = fed["links"]
    if not isinstance(links, dict) or len(links) > MAX_ENTRIES:
        raise LifecycleError("state: federation.links is malformed")
    for sub, upstream in links.items():
        if not _SUB_RE.match(sub) or not (upstream == "" or _SUB_RE.match(str(upstream))):
            raise LifecycleError("state: federation.links is malformed")
    for name in ("disabled", "not_before"):
        if not isinstance(fed[name], dict) or len(fed[name]) > MAX_ENTRIES:
            raise LifecycleError(f"state: federation.{name} is malformed")
        for sub, value in fed[name].items():
            if not _SUB_RE.match(sub):
                raise LifecycleError(f"state: federation.{name} is malformed")
            _int(value, f"federation.{name}")
    members = fed["members"]
    if not isinstance(members, dict) or len(members) > MAX_MAPPED_GROUPS:
        raise LifecycleError("state: federation.members is malformed")
    for gid, ids in members.items():
        if (
            not _SUB_RE.match(gid)
            or not isinstance(ids, list)
            or len(ids) > MAX_ENTRIES
            or not all(isinstance(i, str) and _SUB_RE.match(i) for i in ids)
        ):
            raise LifecycleError("state: federation.members is malformed")


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
    if etype in IDP_ERROR_TYPES:
        return _idp_refusal(row, position_only)
    if etype not in USER_EVENT_TYPES or not isinstance(uid, str) or not _SUB_RE.fullmatch(uid):
        return position_only
    if etype == "UPDATE_PASSWORD":
        path = f"users/{uid}/password"
    elif etype == "REMOVE_CREDENTIAL":
        details = row.get("details")
        cid = details.get("selected_credential_id") if isinstance(details, dict) else None
        valid = isinstance(cid, str) and re.fullmatch(_ID, cid)
        path = f"users/{uid}/credentials/{cid}" if valid else f"users/{uid}/credentials"
    elif etype == "LOGIN":
        path = f"users/{uid}/login"
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


def _idp_refusal(row: dict, position_only: dict) -> dict:
    """A sign-in through the upstream provider that the post sign-in flow refused
    (`access_denied`): the upstream user name and the attempt's id are kept in memory
    for StatusSync.refused, nothing else. Any other broker error moves the position."""
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    name, code = details.get("identity_provider_identity"), details.get("code_id")
    if (
        row.get("error") != "access_denied"
        or details.get("identity_provider") != FEDERATION_ALIAS
        or not isinstance(name, str)
        or not 0 < len(name) <= 255
        or _CONTROL_RE.search(name)
    ):
        return position_only
    return dict(
        position_only,
        operationType=IDP_REFUSED,
        identity=name,
        attempt=code if isinstance(code, str) and _ATTEMPT_RE.fullmatch(code) else None,
    )


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
        if op == "LOGIN" and (m := _OWN_LOGIN_RE.fullmatch(path)):
            return "breakglass_login", m[1], "login"
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
    """The P-256 key of `svc-papaia-lifecycle` (or of the status sync account at the
    upstream provider), mounted from the configuration dir."""

    def __init__(self, folder: Path, client_id: str = CLIENT_ID) -> None:
        self.client_id = client_id
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
            "iss": self.client_id,
            "sub": self.client_id,
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


def _open_json(req: urllib.request.Request, ctx: ssl.SSLContext | None):
    """One request; the JSON answer, None for an empty one. The body of an error answer
    is never read."""
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise HttpError(exc.code) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise LifecycleError("answer too large")
    return json.loads(raw) if raw else None


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
        return _open_json(req, self.ctx)

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

    def breakglass_ids(self) -> frozenset[str]:
        """The ids of the emergency account, read on every sign-in event; none without
        the file (no emergency account yet)."""
        path = self.account_dir / BREAKGLASS_FILE
        if not os.path.lexists(path):
            return frozenset()
        try:
            lines = _read_private(path, 1024).decode("ascii").splitlines()
        except UnicodeDecodeError:
            raise LifecycleError("the ids of the emergency account are malformed") from None
        if not all(_SUB_RE.match(line) for line in lines):
            raise LifecycleError("the ids of the emergency account are malformed")
        return frozenset(lines)

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
        federation: StatusSync | None = None,
    ) -> None:
        self.api, self.store, self.publisher = api, store, publisher
        # The core start gate (sicherheit §4.9 (2a)); StartGate sets itself here.
        self.gate: StartGate | None = None
        # The status sync with the upstream directory; None without federation.
        self.federation = federation
        if federation is not None:
            federation.service = self
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

    def _write(
        self, method, path, operation, event, correlation, sub, detail=None, *,
        body=None, effect="delete",
    ) -> None:
        ref = {"type": "user", "id": sub}
        try:
            if body is None:
                self.api.call(method, path)
            else:
                self.api.call(method, path, body)
        except HttpError as exc:
            self._audit(
                operation, effect, event, correlation, ref, "error", f"http_{exc.status}", detail
            )
            raise
        except Exception:
            self._audit(operation, effect, event, correlation, ref, "error", "transport", detail)
            raise
        self._audit(operation, effect, event, correlation, ref, detail=detail)

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
        """Close the gate and compare (before the journal is flushed: the flush copies the
        target's entries into the local copy), make the key, set the first read position,
        publish a list at once."""
        if self.gate is not None:
            self.gate.begin()
            self._gate_step(self.gate.check)
        self.publisher.signer.ensure()
        self._flush_journal()
        with self.store.locked():
            state = self.store.load()
            if state["mark_ms"] is None:
                state["mark_ms"] = max(0, int(self.clock() * 1000) - FIRST_LOOKBACK_MS)
            if state["started_at"] is None:
                state["started_at"] = int(self.clock())
            if self.federation is None and state["federation"] != _RECONCILE_DEFAULTS["federation"]:
                # Started without the federation folder (idp.yaml removed): the status
                # sync state goes, so health does not wait for a sync that no longer runs.
                state["federation"] = json.loads(json.dumps(_RECONCILE_DEFAULTS["federation"]))
                _log("no federation: the status sync state is removed")
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
        types = USER_EVENT_TYPES + (IDP_ERROR_TYPES if self.federation is not None else ())
        users = self._read("/events", [*(("type", t) for t in types), since])
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
            if event.get("operationType") == IDP_REFUSED and self.federation is not None:
                try:
                    self.federation.refused(event)
                except RETRYABLE as exc:
                    _log(f"a refused federated sign-in could not be told apart ({exc!r})")
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
        if kind == "breakglass_login":
            self._note_login(sub, when_ms)
            ids = getattr(self.api, "breakglass_ids", None)
            if ids is not None and sub in ids():
                self._audit(
                    "breakglass_login",
                    "check",
                    "breakglass_login",
                    correlation,
                    {"type": "user", "id": sub},
                )
                _log(
                    "ALERT: the emergency account signed in; rotate its password afterwards "
                    "(papaia-ctl breakglass rotate)"
                )
            return
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
                self._note_users([{**user, "id": sub}], complete=False)
                with self.store.locked():
                    if self.store.load()["names"].get(sub, {}).get("enabled") is False:
                        user = {**user, "enabled": False}  # locked by its name just now
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
            self._tombstone(sub, since)
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

    # name index and tombstones (security 1.14 no. 2b) ---------------
    def _refs(self, user: dict) -> tuple[str | None, str | None]:
        if self.journal is None:
            return None, None
        key = self.journal._key
        return name_ref(key, user.get("username")), name_ref(key, user.get("email"))

    def _note_users(self, users: list[dict], *, complete: bool) -> None:
        """Record the HMACs of name and mail of the listed persons; disable a new account
        that carries the name or mail of a deleted one (name lock), once per account.
        With the complete list of members (`complete`), a person that is no longer
        listed is looked up: deleted (404) becomes a tombstone, outside the group (403)
        leaves the index."""
        if self.journal is None:
            return
        listed: dict[str, dict] = {}
        for user in users:
            uid = user.get("id") if isinstance(user, dict) else None
            if isinstance(uid, str) and _SUB_RE.match(uid):
                listed[uid] = user
        locks: list[str] = []
        with self.store.locked():
            state = self.store.load()
            names, tombstones = state["names"], state["tombstones"]
            dead_names = {t["name"] for t in tombstones.values() if t["name"]}
            dead_mails = {t["mail"] for t in tombstones.values() if t["mail"]}
            changed = False
            for uid, user in listed.items():
                name, mail = self._refs(user)
                enabled = user.get("enabled")
                enabled = enabled if isinstance(enabled, bool) else None
                old = names.get(uid)
                item = {
                    "name": name, "mail": mail, "enabled": enabled,
                    "login": old["login"] if old else None,
                    "locked": old["locked"] if old else False,
                }
                if uid not in tombstones and enabled is True and not item["locked"] and (
                    (name and name in dead_names) or (mail and mail in dead_mails)
                ):
                    item["locked"], item["enabled"] = True, False
                    locks.append(uid)
                if item != old and (old is not None or len(names) < MAX_ENTRIES):
                    names[uid] = item
                    changed = True
            gone = sorted(set(names) - set(listed)) if complete else []
            if changed:
                self.store.save(state)
        for uid in locks:
            self._name_lock(uid)
        for uid in gone:
            try:
                self.api.call("GET", f"/users/{uid}")
            except HttpError as exc:
                if exc.status == 404:
                    self._tombstone(uid, int(self.clock()))
                elif exc.status == 403:
                    with self.store.locked():
                        state = self.store.load()
                        state["names"].pop(uid, None)
                        self.store.save(state)

    def _name_lock(self, uid: str) -> None:
        """The name or mail of a deleted account came back: the new account is disabled
        and reported; an administrator who enables it again is not overruled."""
        correlation = _uuid7()
        self._write(
            "PUT",
            f"/users/{uid}",
            "account_name_locked",
            "operation",
            correlation,
            uid,
            body={"enabled": False},
            effect="write",
        )
        _log(
            f"ALERT: account {uid} carries the user name or mail of a deleted account and "
            "was disabled; enable it again in Keycloak only after checking who it is"
        )

    def _tombstone(self, sub: str, deleted: int) -> None:
        """A deleted person: the two HMACs move from the index to the tombstones."""
        with self.store.locked():
            state = self.store.load()
            item = state["names"].pop(sub, None)
            if item is None or sub in state["tombstones"]:
                if item is not None:
                    self.store.save(state)
                return
            if len(state["tombstones"]) < MAX_ENTRIES and (item["name"] or item["mail"]):
                state["tombstones"][sub] = {
                    "name": item["name"], "mail": item["mail"], "deleted": deleted,
                }
            self.store.save(state)

    def _note_login(self, sub: str, when_ms: int) -> None:
        """The day of the last sign-in of a person in the index (`find` shows it)."""
        day = when_ms // 1000 // DAY_SECONDS * DAY_SECONDS
        with self.store.locked():
            state = self.store.load()
            item = state["names"].get(sub)
            if item is None or (item["login"] is not None and item["login"] >= day):
                return
            item["login"] = day
            self.store.save(state)

    # reconciliation ---------------------------------------------------
    def _users(self, *, enabled: bool | None) -> list[str]:
        """Ids of the members of the persons group (the accounts the service may see),
        all of them or by state. The members endpoint has no filter by state."""
        return [
            uid for uid, on in self.members() if enabled is None or on is enabled
        ]

    def members(self) -> list[tuple[str, bool | None]]:
        """(id, enabled) of every member of the persons group, in the order listed."""
        group = urllib.parse.quote(self.api.persons_group(), safe="-")
        found: dict[str, bool | None] = {}
        listed: list[dict] = []
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
                on = user.get("enabled")
                found.setdefault(uid, on if isinstance(on, bool) else None)
                listed.append(user)
            if len(batch) < USER_PAGE:
                self._note_users(listed, complete=True)
                return list(found.items())
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
        if self.gate is not None:
            self.gate.account_enabled(sub)
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
                self._tombstone(sub, now)
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

    def _gate_step(self, action) -> None:
        try:
            action()
        except RETRYABLE as exc:
            _log(f"start gate: {exc!r}; the lease runs out unless renewed")

    def step(self, *, force_poll: bool = False) -> None:
        if self.gate is not None:
            self._gate_step(self.gate.step)
        now = self.clock()
        if now >= self._next_reconcile:
            self._reconcile_now(now)
        if self.federation is not None and (force_poll or self.federation.due(now)):
            self.federation.run()
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


# ─────────────────────────────────────────────────────────────────────────
# status sync with the upstream directory (federation)
# ─────────────────────────────────────────────────────────────────────────


def read_status_file(folder: Path) -> dict:
    """`status-sync.json` as lib/federation.py writes it, checked field by field."""
    try:
        doc = json.loads(_read_private(folder / STATUS_FILE, 1 << 20))
    except ValueError:
        raise LifecycleError("status-sync.json: not JSON") from None
    keys = {"format", "alias", "kind", "url", "realm", "client_id", "groups"}
    if not isinstance(doc, dict) or set(doc) != keys or doc["format"] != STATUS_FORMAT:
        raise LifecycleError("status-sync.json: unknown format or fields")
    if doc["alias"] != FEDERATION_ALIAS or doc["kind"] != "keycloak":
        raise LifecycleError("status-sync.json: only the kind keycloak is supported")
    keycloak_url(doc["url"])
    if not isinstance(doc["realm"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
                                                           doc["realm"]):
        raise LifecycleError("status-sync.json: realm is malformed")
    if not isinstance(doc["client_id"], str) or not _CLIENT_ID_RE.match(doc["client_id"]):
        raise LifecycleError("status-sync.json: client_id is malformed")
    groups = doc["groups"]
    if (
        not isinstance(groups, list)
        or len(groups) > MAX_MAPPED_GROUPS
        or not all(isinstance(g, str) and _SUB_RE.match(g) for g in groups)
    ):
        raise LifecycleError("status-sync.json: groups is malformed")
    return doc


class UpstreamDirectory:
    """The directory of the upstream provider, read with the status sync account: a
    Keycloak realm's Admin API (RS-F), where the account holds `view-users` and
    `query-groups` and nothing else. Lists only, no request per account: every user
    (state and "sessions valid from") and the members of every mapped group, by id."""

    def __init__(self, folder: Path, ctx: ssl.SSLContext | None) -> None:
        self.folder, self.ctx = folder, ctx
        doc = read_status_file(folder)
        self.base_url = keycloak_url(doc["url"])
        self.realm, self.client_id = doc["realm"], doc["client_id"]
        self.groups = list(doc["groups"])
        self._token: str | None = None
        self._until = 0.0

    def _realm(self) -> str:
        return f"{self.base_url}/realms/{urllib.parse.quote(self.realm)}"

    def token(self) -> str:
        if self._token and time.monotonic() < self._until:
            return self._token
        issuer = _open_json(
            urllib.request.Request(f"{self._realm()}/.well-known/openid-configuration"), self.ctx
        )
        if not isinstance(issuer, dict) or not isinstance(issuer.get("issuer"), str):
            raise LifecycleError("upstream discovery document without issuer")
        key = AccountKey(self.folder, self.client_id)
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": key.assertion(issuer["issuer"]),
            }
        ).encode()
        body = _open_json(
            urllib.request.Request(f"{self._realm()}/protocol/openid-connect/token", data=form),
            self.ctx,
        )
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise LifecycleError("upstream token answer without access token")
        lifetime = body.get("expires_in")
        lifetime = lifetime if isinstance(lifetime, int) and lifetime > 0 else 60
        self._token, self._until = body["access_token"], time.monotonic() + max(5, lifetime - 30)
        return self._token

    def _get(self, path: str):
        req = urllib.request.Request(
            f"{self.base_url}/admin/realms/{urllib.parse.quote(self.realm)}{path}",
            headers={"Authorization": f"Bearer {self.token()}"},
        )
        try:
            return _open_json(req, self.ctx)
        except HttpError as exc:
            if exc.status == 401:
                self._token = None
            raise

    def _paged(self, path: str) -> list:
        rows: list = []
        sep = "&" if "?" in path else "?"
        for page in range(MAX_USER_PAGES):
            batch = self._get(f"{path}{sep}first={page * USER_PAGE}&max={USER_PAGE}")
            if not isinstance(batch, list):
                raise LifecycleError("upstream directory: not a list")
            rows.extend(batch)
            if len(batch) < USER_PAGE:
                return rows
        raise LifecycleError(f"upstream directory: more than {MAX_USER_PAGES * USER_PAGE} rows")

    def snapshot(self) -> dict:
        """{"users": {id: {"enabled", "not_before", "username"}}, "members": {group: set}}.
        A mapped group the directory no longer knows has no members."""
        users: dict[str, dict] = {}
        for row in self._paged("/users?briefRepresentation=false"):
            uid = row.get("id") if isinstance(row, dict) else None
            if not isinstance(uid, str) or not _SUB_RE.match(uid):
                continue
            nb = row.get("notBefore")
            name = row.get("username")
            users[uid] = {
                "enabled": row.get("enabled") is True,
                "not_before": nb if isinstance(nb, int) and not isinstance(nb, bool) and nb > 0
                else 0,
                "username": name if isinstance(name, str) and len(name) <= 255 else None,
            }
        members: dict[str, set[str]] = {}
        for gid in self.groups:
            try:
                rows = self._paged(f"/groups/{gid}/members?briefRepresentation=true")
            except HttpError as exc:
                if exc.status != 404:
                    raise
                _log(f"mapped upstream group {gid} does not exist; it has no members")
                rows = []
            members[gid] = {
                r["id"] for r in rows if isinstance(r, dict) and _SUB_RE.match(str(r.get("id")))
            }
        return {"users": users, "members": members}


class Mailer:
    """The warning mail to the operations address through the mail relay of the stack
    (plain SMTP inside the stack, no login, as every service sends)."""

    def __init__(self, relay: str, to: str, sender: str) -> None:
        host, _, port = relay.rpartition(":")
        if not host or not port.isdigit() or not to or not sender:
            raise LifecycleError("the mail relay must be host:port, with a sender and a recipient")
        # Each address goes into a header line: one address, no line break, no list.
        for value in (to, sender):
            if not _MAIL_RE.fullmatch(value):
                raise LifecycleError("the warning mail needs one plain address per field")
        self.host, self.port, self.to, self.sender = host, int(port), to, sender

    def send(self, subject: str, text: str) -> None:
        message = email.message.EmailMessage()
        message["From"], message["To"], message["Subject"] = self.sender, self.to, subject
        message.set_content(text)
        with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
            smtp.send_message(message, from_addr=self.sender, to_addrs=[self.to])


class StatusSync:
    """Compares the federated persons of the realm with the upstream directory every
    60 s (security 1.13). The link between an account of the realm and its person
    upstream is Keycloak's federated identity (the provider's `sub`), read once per
    account and kept. A person disabled or deleted upstream is disabled here and revoked
    (list, sessions, consents); enabled upstream again, the account is enabled again,
    and its consents from before go. A newer "sessions valid from" upstream revokes the
    sessions and delegations without disabling. A changed membership of a mapped group
    ends the sessions, so the next sign-in maps anew; a removed one is journaled. A round
    that fails (an error, a refused or throttled request) leaves the state as it was;
    failing for longer than 300 s writes one `status_sync_failed` row, sends one warning
    mail and makes health `fail` until a round succeeds."""

    def __init__(self, directory, *, mailer: Mailer | None = None, clock=time.time) -> None:
        self.directory, self.mailer, self.clock = directory, mailer, clock
        self.service: Lifecycle | None = None
        self._next = 0.0
        # Upstream user name -> id, from the last snapshot; only in memory.
        self._names: dict[str, str] = {}
        # A refused sign-in by a name the map lacks reads the directory again at most
        # once between two rounds.
        self._names_refreshed = False
        self._attempts: list[str] = []

    def due(self, now: float) -> bool:
        return now >= self._next

    # state ------------------------------------------------------------
    def _update(self, change) -> dict:
        svc = self.service
        with svc.store.locked():
            state = svc.store.load()
            change(state["federation"])
            svc.store.save(state)
            return state["federation"]

    # links ------------------------------------------------------------
    def _links(self, members: list[tuple[str, bool | None]], now: int) -> dict[str, str]:
        """Account id of the realm -> id of its person upstream ("" when not federated:
        the break-glass account, an account made before the federation)."""
        svc = self.service
        with svc.store.locked():
            fed = svc.store.load()["federation"]
        links = dict(fed["links"])
        full = now - fed["last_full"] >= FULL_SYNC_SECONDS
        current = {uid for uid, _ in members}
        links = {uid: up for uid, up in links.items() if uid in current and (up or not full)}
        for uid in current - set(links):
            rows = svc.api.call("GET", f"/users/{uid}/federated-identity") or []
            found = ""
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict) and row.get("identityProvider") == FEDERATION_ALIAS:
                    value = row.get("userId")
                    found = value if isinstance(value, str) and _SUB_RE.match(value) else ""
            links[uid] = found

        def keep(f: dict) -> None:
            f["links"] = links
            if full:
                f["last_full"] = now

        self._update(keep)
        return links

    # round ------------------------------------------------------------
    def run(self) -> None:
        now = int(self.clock())
        self._next = self.clock() + STATUS_SYNC_SECONDS

        def configured(f: dict) -> None:
            f["configured"] = True
            if f["started"] is None:
                f["started"] = now

        self._update(configured)
        try:
            snap = self.directory.snapshot()
            members = self.service.members()
            links = self._links(members, now)
            self._compare(snap, members, links, now)
        except RETRYABLE as exc:
            self._failed(now, exc)
            return
        self._names = {
            u["username"]: uid for uid, u in snap["users"].items() if u["username"] is not None
        }
        self._names_refreshed = False

        def ok(f: dict) -> None:
            if f["failing_since"] is not None:
                _log("status sync with the upstream directory works again")
            f["last_ok"], f["failing_since"], f["reported"] = now, None, False

        self._update(ok)

    def _compare(self, snap: dict, members, links: dict[str, str], now: int) -> None:
        svc = self.service
        with svc.store.locked():
            fed = svc.store.load()["federation"]
        disabled = dict(fed["disabled"])
        before = dict(fed["not_before"])
        was = {gid: set(ids) for gid, ids in fed["members"].items()}
        seen_nb: dict[str, int] = {}
        done: set[str] = set()
        current = set(links)
        try:
            for uid, enabled in members:
                upstream = links.get(uid)
                if not upstream:
                    continue
                self._account(uid, enabled, upstream, snap, disabled, before, was, seen_nb, now)
                done.add(upstream)
        except Exception:
            # A round that breaks off keeps what it did for the accounts it finished, so
            # the next round does not disable, revoke and audit them again.
            def partial(f: dict) -> None:
                f["disabled"] = {u: t for u, t in disabled.items() if u in current}
                f["not_before"] = {
                    u: t for u, t in before.items() if u not in done
                } | seen_nb
                kept = {gid: set(ids) for gid, ids in was.items()}
                for gid, ids in snap["members"].items():
                    if gid not in kept:
                        kept[gid] = set(ids)
                        continue
                    for up in done:
                        if up in ids:
                            kept[gid].add(up)
                        else:
                            kept[gid].discard(up)
                f["members"] = {gid: sorted(ids) for gid, ids in kept.items()}

            self._update(partial)
            raise

        def keep(f: dict) -> None:
            f["disabled"] = {u: t for u, t in disabled.items() if u in current}
            f["not_before"] = seen_nb
            f["members"] = {gid: sorted(ids) for gid, ids in snap["members"].items()}

        self._update(keep)

    def _account(
        self, uid: str, enabled: bool | None, upstream: str, snap: dict, disabled: dict,
        before: dict, was: dict, seen_nb: dict, now: int,
    ) -> None:
        """One federated account against its person upstream. `disabled` holds the
        accounts the status sync disabled itself: only those it enables again."""
        svc = self.service
        person = snap["users"].get(upstream)
        correlation = _uuid7()
        if person is None or not person["enabled"]:
            if enabled is False and uid not in disabled:
                # Deactivated by papaia's own administration (PLT-60-A2): not a lock of
                # the status sync, so it is neither revoked again nor lifted from upstream.
                return
            if uid not in disabled or enabled:
                self._enable(uid, False, correlation)
                # Recorded as the sync's own lock as soon as the account is disabled: a
                # revocation that fails after this must not turn it into a local
                # deactivation that is never lifted. The revocation itself is still
                # covered by reconcile() and the admin-event path.
                disabled[uid] = now
                reason = "upstream_deleted" if person is None else "upstream_disabled"
                svc.revoke(uid, now, reason, correlation)
            return
        if uid in disabled:
            # Dropped only once the account is enabled and its old consents are gone, so
            # a round that breaks off on the way back retries it.
            since = disabled[uid]
            if enabled is False:
                self._enable(uid, True, correlation)
            for client, created in svc._consents(uid):
                if created < since * 1000:
                    svc._delete_consent(uid, client, correlation)
            del disabled[uid]
        nb = person["not_before"]
        seen_nb[upstream] = nb
        if upstream in before and nb > before[upstream]:
            svc.revoke(uid, nb, "upstream_sessions_revoked", correlation)
        changed = [
            gid
            for gid, ids in snap["members"].items()
            if gid in was and (upstream in was[gid]) != (upstream in ids)
        ]
        if changed:
            svc._write(
                "POST", f"/users/{uid}/logout", "logout", "role_changed", correlation, uid,
                {"upstream_groups": len(changed)},
            )
            for gid in changed:
                if upstream in was[gid]:
                    svc._journal("role_revoke", uid, f"upstream-group:{gid}", correlation)

    def _enable(self, uid: str, on: bool, correlation: str) -> None:
        self.service._write(
            "PUT",
            f"/users/{uid}",
            "account_enable" if on else "account_disable",
            "operation",
            correlation,
            uid,
            {"source": "upstream_directory"},
            body={"enabled": on},
            effect="write",
        )

    def _failed(self, now: int, exc: Exception) -> None:
        _log(f"status sync with the upstream directory failed ({exc!r})")
        state = self._update(
            lambda f: f.update(failing_since=f["failing_since"] if f["failing_since"] else now)
        )
        since = state["failing_since"]
        if now - since <= STATUS_SYNC_FAIL_SECONDS or state["reported"]:
            return
        self._update(lambda f: f.update(reported=True))
        code = f"http_{exc.status}" if isinstance(exc, HttpError) else "unreachable"
        self.service._audit(
            "status_sync",
            "check",
            "status_sync_failed",
            _uuid7(),
            {"type": "identity_provider", "id": FEDERATION_ALIAS},
            "error",
            code,
            {"failing_seconds": now - since},
        )
        self._alert(now - since, code)

    def _alert(self, seconds: int, code: str) -> None:
        if self.mailer is None:
            _log("no mail relay or operations address: no warning mail sent")
            return
        correlation = _uuid7()
        ref = {"type": "mail", "id": "operations"}
        try:
            self.mailer.send(
                "papaia: Statusabgleich mit dem Firmenverzeichnis gestört",
                f"Der Statusabgleich von papaia-lifecycle mit dem vorgelagerten Verzeichnis "
                f"scheitert seit {seconds // 60} Minuten (Ursache: {code}). Sperren im "
                "Firmenverzeichnis wirken in papaia erst wieder, wenn der Abgleich gelingt. "
                "'papaia-ctl doctor' zeigt den Zustand; docs/federation.md beschreibt die "
                "Störung.",
            )
        except (OSError, smtplib.SMTPException) as exc:
            _log(f"warning mail not sent ({exc!r})")
            self.service._audit("alert_mail", "send", "operation", correlation, ref, "error",
                                "mail_failed")
            return
        self.service._audit("alert_mail", "send", "operation", correlation, ref)

    # refused sign-ins -------------------------------------------------
    def refused(self, event: dict) -> None:
        """A federated sign-in the post sign-in flow refused: `idp_group_overflow` when
        the marker roles of the account show no groups claim or an overage reference,
        else (the `acr` check) a denied sign-in row. Keycloak writes one event per
        attempt more than once; an attempt is counted once."""
        attempt = event.get("attempt")
        if attempt is not None:
            if attempt in self._attempts:
                return
            self._attempts = [*self._attempts, attempt][-MAX_REFUSALS_KEPT:]
        svc = self.service
        upstream = self._names.get(event["identity"])
        if upstream is None and not self._names_refreshed:
            self._names_refreshed = True
            self._names = {
                u["username"]: uid
                for uid, u in self.directory.snapshot()["users"].items()
                if u["username"] is not None
            }
            upstream = self._names.get(event["identity"])
        uid = None
        if upstream is not None:
            links = self._links(svc.members(), int(self.clock()))
            uid = next((u for u, up in links.items() if up == upstream), None)
        if uid is None:
            _log("a refused federated sign-in names no account of the realm")
            return
        roles = svc.api.call("GET", f"/users/{uid}/role-mappings/realm") or []
        names = {r.get("name") for r in roles if isinstance(r, dict)}
        overflow = OVERAGE_ROLE in names or GROUPS_ROLE not in names
        svc._audit(
            "sign_in",
            "check",
            "idp_group_overflow" if overflow else "operation",
            _uuid7(),
            {"type": "user", "id": uid},
            "denied",
            "idp_group_overflow" if overflow else "idp_acr_refused",
        )


def _event_time(event: object) -> int | None:
    if not isinstance(event, dict):
        return None
    when = event.get("time")
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        return None
    return when


# ─────────────────────────────────────────────────────────────────────────
# core start gate (sicherheit §4.9 (2a))
# ─────────────────────────────────────────────────────────────────────────

# The lease the edge reads (security state volume, written by this service alone).
GATE_FILE = "startgate.json"
GATE_FORMAT = "papaia.startgate/1"
# The gate's own state next to the service's state (key volume, not backed up).
GATE_STATE_FILE = "startgate-state.json"
GATE_STATE_FORMAT = "papaia.startgate-state/1"
GATE_LOCK_FILE = "startgate.lock"
GATE_LEASE_SECONDS = 90
GATE_RENEW_SECONDS = 30
GATE_CHECK_SECONDS = 60
# A lease issued this far in the future (clock skew between containers) still counts.
GATE_SKEW_SECONDS = 5
MAX_GATE_BYTES = 16384
EPOCH_FILE = "epoch"
EPOCH_FORMAT = "papaia.erasure-epoch/1"
MAX_EPOCH_BYTES = 64 * 1024
MAX_EPOCH_SOURCES = 256
MAX_MODULE_JOURNAL_BYTES = 64 << 20
CORE_SOURCES = ("identity", "core-chat", "model-gateway")
# The key the edge names a public host by: `identity`, `core-chat`, `model-gateway`, a
# module's name, `core` for every other public host, and `admin` for the proxy's own
# administration host, which the gate never closes.
GATE_ADMIN_KEY = "admin"
GATE_STATUSES = ("checking", "open", "behind", "unverified", "replay_failed", "override")
GATE_CODES = ("CHECK", "BLOCKED")
REPLAY_KINDS = ("erase_subject", "chat_sessions_reset", "key_revoke")
MODULE_ACTIONS = ("erasure-replay", "post-restore")
OVERRIDE_WAIT_SECONDS = 20
CORRELATION_HEADER = "X-Papaia-Correlation-Id"
GATE_SERVICE_HEADER = "X-Papaia-Gate-Service"
GATE_CONTACT_HEADER = "X-Papaia-Gate-Contact"
# The original request URI of a request the edge asks about (`$request_uri`).
GATE_URI_HEADER = "X-Papaia-Gate-Uri"
# The administration path (sicherheit §1.7, §4.9 (2a)) signs in at the identity
# provider: the proxy admin host (key `admin`, never closed) sends the browser to the
# realm's sign-in with the client of its login sidecar, which redeems the code inside
# the platform network. Those sign-in requests pass a closed gate on the identity
# provider's host (key `identity`); nothing else there does: no token, account or admin
# endpoint, no other realm or client.
GATE_SIGNIN_KEY = "identity"
GATE_SIGNIN_REALM = "papaia"
GATE_SIGNIN_CLIENT = "oauth2-proxy"
MAX_GATE_URI = 4096
_GATE_SIGNIN_PATH_RE = re.compile(
    rf"^/realms/{GATE_SIGNIN_REALM}/(?:protocol/openid-connect/auth"
    r"|login-actions/(?:authenticate|required-action|restart))$"
)
_GATE_RESOURCE_RE = re.compile(r"^/resources(?:/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}){1,12}$")
_GATE_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_MODULE_JOURNAL_RE = re.compile(r"^([a-z][a-z0-9-]{0,39})\.jsonl$")
_OVERRIDE_REASON_RE = re.compile(r"^[^\x00-\x1f\x7f-\x9f]{1,500}$")
_KEY_REF_RE = re.compile(r"^key:([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
_ROLE_GROUP_RE = re.compile(rf"^group:({_ID})$")
_CONTACT_RE = re.compile(r"^[^\x00-\x1f\x7f-\x9f]{1,200}$")

# Pattern 8 (betrieb BE-16a Nr. 2a): what happened, one action; the id follows.
GATE_PAGE_TEXT = {
    "CHECK": (
        "Die Plattform prüft nach einem Neustart ihren Datenstand und ist kurz nicht "
        "erreichbar. Es wurde nichts ausgeführt.",
        "Versuchen Sie es in einigen Minuten erneut.",
    ),
    "BLOCKED": (
        "Die Plattform ist nach einem Neustart gesperrt, bis ihr Datenstand geprüft ist. "
        "Es wurde nichts ausgeführt.",
        "Fragen Sie {contact}.",
    ),
}
GATE_MAIL_TEXT = {
    "CORE-STARTGATE-UNVERIFIED": (
        "Das Löschjournal am Sicherungsziel ist nicht erreichbar; die Plattform bleibt "
        "geschlossen.",
        "Stellen Sie die Verbindung zum Sicherungsziel wieder her (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-REPLAY-FAILED": (
        "Das Nachspielen ist für {services} fehlgeschlagen; {services} bleibt geschlossen.",
        "Prüfen Sie {services} mit papaia-ctl doctor (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-OVERRIDE": (
        "Die Plattform ist ohne Prüfung gegen das Löschjournal geöffnet (Übersteuerung "
        "durch {first} und {second} um {at}).",
        "Stellen Sie die Verbindung zum Sicherungsziel wieder her; die Prüfung läuft jede "
        "Minute.",
    ),
    "CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR": (
        "Die Übersteuerung wurde von {person} bestätigt, deren Konto danach gesperrt oder "
        "geändert wurde.",
        "Prüfen Sie die Übersteuerung mit der zweiten Person und bestätigen Sie die "
        "Prüfung mit papaia-ctl startgate acknowledge (siehe Handbuch §S-10).",
    ),
}


class EpochError(LifecycleError):
    """The journal at the backup target cannot be compared: `unreachable` or `corrupt`."""

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state


class OverrideDenied(LifecycleError):
    """`startgate open --unverified` refused: one person where two are needed, or no
    closed gate to open."""


def _plain_count(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_JOURNAL_SEQ


def _refuse_constant(name: str) -> object:
    raise ValueError("not plain JSON")


def _strict_json(data: bytes) -> object:
    return json.loads(
        data.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_refuse_constant
    )


def read_epoch(target_dir: Path) -> dict | None:
    """`<backup target>/erasure-journal/epoch` (the kit's erasure-epoch.v1): None while
    the folder holds none. A missing folder (an unmounted target) is never taken for a
    fresh one, and a malformed file is never repeated in a message."""
    target_dir = Path(target_dir)
    if not target_dir.is_dir():
        raise EpochError("unreachable", "the journal folder at the backup target is missing")
    try:
        fd = os.open(target_dir / EPOCH_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EpochError("unreachable", f"epoch: {exc.strerror}") from None
    try:
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_EPOCH_BYTES + 1)
    except OSError as exc:
        raise EpochError("unreachable", f"epoch: {exc.strerror}") from None
    try:
        if len(data) > MAX_EPOCH_BYTES:
            raise ValueError("too large")
        doc = _strict_json(data)
        if (
            not isinstance(doc, dict)
            or set(doc) != {"format", "generation", "seq"}
            or doc["format"] != EPOCH_FORMAT
            or not _plain_count(doc["generation"])
            or not isinstance(doc["seq"], dict)
            or len(doc["seq"]) > MAX_EPOCH_SOURCES
            or not all(_GATE_KEY_RE.match(k) and _plain_count(v) for k, v in doc["seq"].items())
        ):
            raise ValueError("not an epoch")
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise EpochError("corrupt", "epoch: not a valid papaia.erasure-epoch/1 file") from None
    return {"generation": doc["generation"], "seq": dict(doc["seq"])}


def write_epoch(target_dir: Path, generation: int, seq: dict) -> None:
    """Replace `epoch` atomically; the core alone writes it, the modules read it."""
    if not _plain_count(generation) or len(seq) > MAX_EPOCH_SOURCES:
        raise LifecycleError("epoch: generation or seq out of range")
    if not all(_GATE_KEY_RE.match(k) and _plain_count(v) for k, v in seq.items()):
        raise LifecycleError("epoch: malformed source or seq")
    target_dir = Path(target_dir)
    if not target_dir.is_dir():
        raise EpochError("unreachable", "the journal folder at the backup target is missing")
    doc = {"format": EPOCH_FORMAT, "generation": generation, "seq": dict(sorted(seq.items()))}
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
    _write_atomic(target_dir, EPOCH_FILE, data, 0o640)


_LEASE_KEYS = {
    "format", "state", "generation", "hosts", "issued_at", "expires_at", "code", "correlation_id",
}


def _valid_lease(doc: object) -> bool:
    if not isinstance(doc, dict) or set(doc) != _LEASE_KEYS or doc["format"] != GATE_FORMAT:
        return False
    if doc["state"] not in ("open", "closed") or doc["code"] not in (None, *GATE_CODES):
        return False
    if not all(_plain_count(doc[k]) for k in ("generation", "issued_at", "expires_at")):
        return False
    if not 0 < doc["expires_at"] - doc["issued_at"] <= GATE_LEASE_SECONDS:
        return False
    hosts = doc["hosts"]
    if not isinstance(hosts, list) or len(hosts) > MAX_EPOCH_SOURCES:
        return False
    if not all(isinstance(h, str) and _GATE_KEY_RE.match(h) for h in hosts):
        return False
    cid = doc["correlation_id"]
    return isinstance(cid, str) and bool(_EVENT_ID_RE.match(cid))


def read_gate(state_dir: Path) -> dict | None:
    """The lease `startgate.json`, or None when it is missing, not a regular file, too
    large or not exactly a lease: the edge then stays closed."""
    try:
        fd = os.open(Path(state_dir) / GATE_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            data = fh.read(MAX_GATE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_GATE_BYTES:
        return None
    try:
        doc = _strict_json(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return doc if _valid_lease(doc) else None


def gate_allows(doc: dict | None, key: object, now: int) -> bool:
    """Whether the edge forwards a request to the public host named `key`: the lease
    says `open`, has not expired, and does not hold this host back."""
    if key == GATE_ADMIN_KEY:
        return True
    if doc is None or not isinstance(key, str) or not _GATE_KEY_RE.match(key):
        return False
    if doc["state"] != "open" or key in doc["hosts"]:
        return False
    return doc["issued_at"] - GATE_SKEW_SECONDS <= now < doc["expires_at"]


def gate_signin_allowed(key: object, uri: object) -> bool:
    """Whether a request is the administrators' sign-in at the identity provider, which
    passes a closed gate (the administration path stays open, sicherheit §4.9 (2a)):
    the realm's authorization endpoint or a sign-in step for the client of the proxy
    admin host's login sidecar, or a static resource of the sign-in page. The raw URI
    is matched: no encoded character, dot segment or empty segment in the path."""
    if key != GATE_SIGNIN_KEY or not isinstance(uri, str) or not 0 < len(uri) <= MAX_GATE_URI:
        return False
    path, _, query = uri.partition("?")
    if "%" in path or "\\" in path:
        return False
    if _GATE_RESOURCE_RE.match(path):
        return not query and not any(seg in (".", "..") for seg in path.split("/"))
    if not _GATE_SIGNIN_PATH_RE.match(path):
        return False
    try:
        params = urllib.parse.parse_qs(query, strict_parsing=True, max_num_fields=32)
    except ValueError:
        return False
    return params.get("client_id") == [GATE_SIGNIN_CLIENT]


def gate_code(doc: dict | None, now: int) -> str:
    """CHECK (the platform checks after a start, or no valid lease at all) or BLOCKED
    (closed until the operator acts) for the maintenance page."""
    if doc is not None and doc["code"] == "BLOCKED" and now < doc["expires_at"]:
        return "BLOCKED"
    return "CHECK"


_GATE_STATE_KEYS = {
    "format",
    "generation",
    "applied",
    "status",
    "failed",
    "correlation_id",
    "pending",
    "pending_core",
    "chat_built",
    "chat_jobs",
    "credential_replay",
    "role_replay",
    "override",
    "request",
    "acknowledge",
    "revoked_actors",
    "announced",
}
_REQUEST_KEYS = {"reason", "requested_by", "confirmed_by", "single_person", "correlation_id"}
_OVERRIDE_KEYS = _REQUEST_KEYS | {"at", "active"}
_ACKNOWLEDGE_KEYS = {"reason", "by", "correlation_id"}
_JOB_KEYS = {"kind", "sub", "key_id", "service"}
# Written by `papaia-ctl` through `docker exec` (another process): the service keeps
# what is on disk for these when it saves a state it loaded earlier.
_GATE_EXTERNAL_KEYS = ("request", "acknowledge")


def _new_gate_state() -> dict:
    return {
        "format": GATE_STATE_FORMAT,
        # None until the first comparison recorded one: a state that went missing is
        # then behind every epoch the target holds.
        "generation": None,
        "applied": {},
        "status": "checking",
        "failed": [],
        "correlation_id": _uuid7(),
        # Entries of the journal `identity` still to replay, kept from the comparison
        # that found them (the next flush copies them into the local copy).
        "pending": [],
        "pending_core": False,
        "chat_built": True,
        "chat_jobs": [],
        "credential_replay": [],
        "role_replay": [],
        "override": None,
        "request": None,
        "acknowledge": None,
        "revoked_actors": [],
        "announced": [],
    }


def _subs(value: object, name: str) -> None:
    if (
        not isinstance(value, list)
        or len(value) > MAX_ENTRIES
        or not all(isinstance(s, str) and _SUB_RE.match(s) for s in value)
    ):
        raise LifecycleError(f"startgate state: {name} is malformed")


def _check_request(value: object, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleError("startgate state: override is malformed")
    if not isinstance(value["reason"], str) or not _OVERRIDE_REASON_RE.match(value["reason"]):
        raise LifecycleError("startgate state: override reason is malformed")
    _subs([value["requested_by"], value["confirmed_by"]], "override")
    if not isinstance(value["single_person"], bool):
        raise LifecycleError("startgate state: override is malformed")
    if not isinstance(value["correlation_id"], str) or not _EVENT_ID_RE.match(
        value["correlation_id"]
    ):
        raise LifecycleError("startgate state: override is malformed")
    if "at" in keys and (not _plain_count(value["at"]) or not isinstance(value["active"], bool)):
        raise LifecycleError("startgate state: override is malformed")


def _check_job(job: object) -> None:
    if (
        not isinstance(job, dict)
        or set(job) != _JOB_KEYS
        or job["kind"] not in REPLAY_KINDS
        or job["service"] not in ("core-chat", "model-gateway")
        or not (job["sub"] is None or (isinstance(job["sub"], str) and _SUB_RE.match(job["sub"])))
        or not (
            job["key_id"] is None
            or (isinstance(job["key_id"], str) and _KEY_REF_RE.match(f"key:{job['key_id']}"))
        )
    ):
        raise LifecycleError("startgate state: a replay job is malformed")


def _check_gate_state(doc: object) -> dict:
    if not isinstance(doc, dict) or set(doc) != _GATE_STATE_KEYS:
        raise LifecycleError("startgate state: unknown format or fields")
    if doc["format"] != GATE_STATE_FORMAT or doc["status"] not in GATE_STATUSES:
        raise LifecycleError("startgate state: unknown format or status")
    if doc["generation"] is not None and not _plain_count(doc["generation"]):
        raise LifecycleError("startgate state: generation is malformed")
    applied = doc["applied"]
    if (
        not isinstance(applied, dict)
        or len(applied) > MAX_EPOCH_SOURCES
        or not all(_GATE_KEY_RE.match(k) and _plain_count(v) for k, v in applied.items())
    ):
        raise LifecycleError("startgate state: applied is malformed")
    failed = doc["failed"]
    if not isinstance(failed, list) or len(failed) > MAX_EPOCH_SOURCES or not all(
        isinstance(k, str) and _GATE_KEY_RE.match(k) for k in failed
    ):
        raise LifecycleError("startgate state: failed is malformed")
    if not isinstance(doc["correlation_id"], str) or not _EVENT_ID_RE.match(doc["correlation_id"]):
        raise LifecycleError("startgate state: correlation_id is malformed")
    pending = doc["pending"]
    if not isinstance(pending, list) or len(pending) > MAX_ENTRIES:
        raise LifecycleError("startgate state: pending is malformed")
    try:
        for entry in pending:
            _check_entry(entry, IDENTITY_SOURCE)
    except ValueError:
        raise LifecycleError("startgate state: pending is malformed") from None
    for name in ("pending_core", "chat_built"):
        if not isinstance(doc[name], bool):
            raise LifecycleError(f"startgate state: {name} is malformed")
    jobs = doc["chat_jobs"]
    if not isinstance(jobs, list) or len(jobs) > MAX_ENTRIES:
        raise LifecycleError("startgate state: chat_jobs is malformed")
    for job in jobs:
        _check_job(job)
    for name in ("credential_replay", "role_replay", "revoked_actors"):
        _subs(doc[name], name)
    if doc["override"] is not None:
        _check_request(doc["override"], _OVERRIDE_KEYS)
    if doc["request"] is not None:
        _check_request(doc["request"], _REQUEST_KEYS)
    ack = doc["acknowledge"]
    if ack is not None and (
        not isinstance(ack, dict)
        or set(ack) != _ACKNOWLEDGE_KEYS
        or not isinstance(ack["reason"], str)
        or not _OVERRIDE_REASON_RE.match(ack["reason"])
        or not isinstance(ack["by"], str)
        or not _SUB_RE.match(ack["by"])
        or not isinstance(ack["correlation_id"], str)
        or not _EVENT_ID_RE.match(ack["correlation_id"])
    ):
        raise LifecycleError("startgate state: acknowledge is malformed")
    announced = doc["announced"]
    if not isinstance(announced, list) or not all(a in GATE_MAIL_TEXT for a in announced):
        raise LifecycleError("startgate state: announced is malformed")
    return doc


class GateStore:
    """The gate's own state (0600) in the key volume. It is part of what a VM snapshot
    rolls back, which is the point: the target's `epoch` is not."""

    def __init__(self, key_dir: Path) -> None:
        self.key_dir = Path(key_dir)
        self.path = self.key_dir / GATE_STATE_FILE

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def load(self) -> dict:
        if not self.exists():
            return _new_gate_state()
        raw = _read_private(self.path, MAX_RESPONSE_BYTES * 16)
        try:
            doc = _strict_json(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise LifecycleError("startgate state: not JSON") from None
        return _check_gate_state(doc)

    def save(self, doc: dict) -> None:
        _write_atomic(self.key_dir, GATE_STATE_FILE, canonical(_check_gate_state(doc)), 0o600)

    def merge_save(self, doc: dict) -> None:
        """Save `doc`, loaded before the lock was let go, under the lock: the fields
        `papaia-ctl` writes from another process meanwhile are taken from disk."""
        with self.locked():
            if self.exists():
                current = self.load()
                for name in _GATE_EXTERNAL_KEYS:
                    doc[name] = current[name]
            self.save(doc)

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.key_dir / GATE_LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


def _module_end(path: Path, module: str) -> int:
    """The highest seq of a module's journal at the target. Lines that do not parse are
    left out (the module's own start check deals with a damaged journal); a file that
    cannot be read makes the comparison impossible."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_MODULE_JOURNAL_BYTES + 1)
    except OSError as exc:
        raise EpochError("unreachable", f"journal {module}: {exc.strerror}") from None
    if len(data) > MAX_MODULE_JOURNAL_BYTES:
        raise EpochError("corrupt", f"journal {module}: too large to compare")
    end = 0
    for raw in data[: data.rfind(b"\n") + 1].splitlines():
        try:
            line = _strict_json(raw) if len(raw) <= MAX_JOURNAL_LINE else None
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if isinstance(line, dict) and line.get("module") == module and _seq(line.get("seq")):
            end = max(end, line["seq"])
    return end


def _entry_seconds(entry: dict) -> int:
    return calendar.timegm(time.strptime(entry["at"][:19], "%Y-%m-%dT%H:%M:%S"))


class StartGate:
    """The core start gate: closed after every start, open only while this service's own
    state is not older than the journal at the backup target (sicherheit §4.9 (2a)).

    The comparison runs at start and every 60 s. `epoch` at the target holds the
    generation of the installation and the last seq per journal; this service keeps the
    generation and the seqs it confirmed in its own volume, and its local copy of the
    journal `identity`. A VM or volume snapshot rolls both back, the target does not: a
    higher generation or seq at the target, or an entry of `identity` missing in the
    local copy, is a backlog. The service then keeps the edge closed, replays in
    Keycloak, logs every account out, publishes `global_since`, has papaia-replay
    delete in chat and model gateway and every module apply its journal, raises the
    generation and opens.
    """

    def __init__(
        self,
        service: Lifecycle,
        *,
        state_dir: Path,
        key_dir: Path,
        target_dir: Path,
        local_dir: Path,
        replay=None,
        modules=None,
        mailer=None,
        clock=time.time,
    ) -> None:
        self.service = service
        service.gate = self
        self.state_dir, self.target_dir = Path(state_dir), Path(target_dir)
        self.local_dir = Path(local_dir)
        self.store = GateStore(Path(key_dir))
        self.replay, self.modules, self.mailer, self.clock = replay, modules, mailer, clock
        self._next_check = 0.0
        self._next_renew = 0.0

    # lease ------------------------------------------------------------
    def _lease(self, st: dict | None, *, closed_code: str | None = None) -> None:
        if st is None:
            state, hosts, code, generation, cid = "closed", [], closed_code or "CHECK", 0, _uuid7()
        else:
            core_failed = [k for k in st["failed"] if k in CORE_SOURCES]
            generation, cid = st["generation"] or 0, st["correlation_id"]
            if st["status"] in ("open", "override") or (
                st["status"] == "replay_failed" and not core_failed
            ):
                state, code = "open", None
                hosts = sorted(st["failed"]) if st["status"] == "replay_failed" else []
            else:
                state, hosts = "closed", []
                code = "BLOCKED" if st["status"] in ("unverified", "replay_failed") else "CHECK"
        now = int(self.clock())
        lease = {
            "format": GATE_FORMAT,
            "state": state,
            "generation": generation,
            "hosts": hosts,
            "issued_at": now,
            "expires_at": now + GATE_LEASE_SECONDS,
            "code": code,
            "correlation_id": cid,
        }
        _write_atomic(self.state_dir, GATE_FILE, canonical(lease), 0o644)
        self._next_renew = self.clock() + GATE_RENEW_SECONDS

    def begin(self) -> None:
        """At every start, before anything else: `closed`."""
        self._lease(None)
        try:
            with self.store.locked():
                st = self.store.load()
                st["status"] = "checking"
                st["correlation_id"] = _uuid7()
                self.store.save(st)
        except LifecycleError as exc:
            _log(f"start gate: own state unreadable ({exc}); the edge stays closed")
            return
        self._lease(st)

    def renew(self) -> None:
        with self.store.locked():
            st = self.store.load()
        self._lease(st)

    def step(self) -> None:
        self._take_request()
        now = self.clock()
        if now >= self._next_check:
            self.check()
        elif now >= self._next_renew:
            self.renew()

    def status(self) -> dict:
        with self.store.locked():
            st = self.store.load()
        return gate_report(st, read_gate(self.state_dir), int(self.clock()))

    # audit and mail -----------------------------------------------------
    def _audit(self, operation, effect, event, cid, ref, result="allowed", code=None, detail=None):
        self.service._audit(operation, effect, event, cid, ref, result, code, detail)

    def _mail(self, code: str, cid: str, **values) -> None:
        first, second = GATE_MAIL_TEXT[code]
        text = f"{first.format(**values)}\n{second.format(**values)}\nKennung: {code} {cid}\n"
        if self.mailer is None:
            _log(f"ALERT: {text.strip()} (no mail relay configured)")
            return
        try:
            self.mailer.send(f"papaia: {code}", text)
        except (OSError, smtplib.SMTPException) as exc:
            _log(f"the warning mail {code} could not be sent ({exc!r})")

    def _announce(self, st: dict, code: str, **values) -> None:
        """One mail per code until the gate is open again, not one per check."""
        if code not in st["announced"]:
            st["announced"].append(code)
            self._mail(code, st["correlation_id"], **values)

    # comparison -------------------------------------------------------
    def check(self) -> None:
        self._next_check = self.clock() + GATE_CHECK_SECONDS
        now = int(self.clock())
        try:
            with self.store.locked():
                st = self.store.load()
        except LifecycleError as exc:
            _log(f"start gate: own state unreadable ({exc}); the edge stays closed")
            self._lease(None, closed_code="BLOCKED")
            return
        try:
            epoch = read_epoch(self.target_dir)
            target = _Place("target", self.target_dir, IDENTITY_SOURCE)
            if target.state != "ok":
                raise EpochError(target.state, f"journal identity at the target is {target.state}")
            self.local_dir.mkdir(mode=0o700, exist_ok=True)
            local = _Place("local copy", self.local_dir, IDENTITY_SOURCE)
            if local.state != "ok":
                raise EpochError(local.state, f"local copy of journal identity is {local.state}")
            ends = self._journal_ends(target)
        except EpochError as exc:
            self._unverified(st, exc)
            return
        except OSError as exc:
            self._unverified(st, EpochError("unreachable", f"backup target: {exc.strerror}"))
            return
        missing = [e for e in target.entries.values() if e["id"] not in local.entries]
        self._check_actors(st, target, missing)
        if st["generation"] is None and epoch is None:
            # A new installation, or the first start of a version with the gate: nothing
            # to compare yet. Record what the journals hold now.
            st.update(generation=0, applied=dict(ends), status="open", failed=[], announced=[])
            self._save_and_record(st, {"generation": 0, "seq": {}})
            _log("start gate: epoch recorded at the backup target")
            return
        if epoch is None:
            # A new or emptied target: the own state is the reference.
            epoch = {"generation": st["generation"], "seq": dict(st["applied"])}
        own = -1 if st["generation"] is None else st["generation"]
        applied = st["applied"]
        core_behind = (
            epoch["generation"] > own
            or bool(missing)
            or any(epoch["seq"].get(s, 0) > applied.get(s, 0) for s in CORE_SOURCES)
        )
        modules = sorted(
            m for m, v in epoch["seq"].items() if m not in CORE_SOURCES and v > applied.get(m, 0)
        )
        due = core_behind or st["pending_core"] or not st["chat_built"] or bool(st["chat_jobs"])
        if not due and not modules:
            if st["status"] == "override":
                _log("start gate: the target is back without backlog; the override ends")
            if st["override"] is not None:
                st["override"]["active"] = False
            st.update(status="open", failed=[], announced=[])
            for source, end in ends.items():
                applied[source] = max(applied.get(source, 0), end)
            generation = max(own, epoch["generation"])
            st["generation"] = generation
            self._save_and_record(st, epoch)
            return
        cid = _uuid7()
        if core_behind:
            known = {e["id"]: e for e in st["pending"]}
            for entry in target.entries.values():
                done = applied.get(IDENTITY_SOURCE, 0)
                if entry["id"] not in local.entries or entry["seq"] > done:
                    known[entry["id"]] = entry
            st["pending"] = sorted(known.values(), key=lambda e: e["seq"])
            st.update(pending_core=True, chat_built=False)
        if st["override"] is not None and st["override"]["active"]:
            st["override"]["active"] = False
            _log("start gate: backlog found; the override ends")
        st.update(status="behind", correlation_id=cid, failed=[])
        self.store.merge_save(st)
        self._lease(st)
        self._audit(
            "startgate",
            "check",
            "state_epoch_behind",
            cid,
            {"type": "erasure_journal", "id": EPOCH_FILE},
            "denied",
            None,
            {
                "generation": epoch["generation"],
                "identity_entries": len(st["pending"]),
                "modules": modules,
            },
        )
        _log(
            "CORE-STARTGATE-BEHIND: Der Datenstand ist älter als das Löschjournal; "
            "Kontosperren und Löschungen werden nachgespielt, die Plattform bleibt bis dahin "
            f"geschlossen. Kennung: CORE-STARTGATE-BEHIND {cid}"
        )
        self._replay(st, epoch, ends, modules, own, now)

    def _journal_ends(self, target: _Place) -> dict[str, int]:
        ends = {IDENTITY_SOURCE: target.end()}
        for source in CORE_SOURCES[1:]:
            place = _Place("target", self.target_dir, source)
            if place.state != "ok":
                raise EpochError(place.state, f"journal {source} at the target is {place.state}")
            ends[source] = place.end()
        for name in sorted(os.listdir(self.target_dir)):
            match = _MODULE_JOURNAL_RE.match(name)
            if match and match[1] not in CORE_SOURCES:
                ends[match[1]] = _module_end(self.target_dir / name, match[1])
        return {source: end for source, end in ends.items() if end}

    def _save_and_record(self, st: dict, epoch: dict) -> None:
        """The own state first, then `epoch`: a stop in between leaves the own state ahead,
        which is never read as a backlog."""
        self.store.merge_save(st)
        seq = dict(epoch["seq"])
        for source, value in st["applied"].items():
            seq[source] = max(seq.get(source, 0), value)
        write_epoch(self.target_dir, max(st["generation"], epoch["generation"]), seq)
        self._lease(st)

    def _unverified(self, st: dict, exc: EpochError) -> None:
        """Nothing to compare with: closed, retried every 60 s; an override keeps it open."""
        _log(f"start gate: {exc}; the edge stays closed")
        if st["override"] is not None and st["override"]["active"]:
            st["status"] = "override"
        else:
            if st["status"] != "unverified":
                st["correlation_id"] = _uuid7()
                self._audit(
                    "startgate",
                    "check",
                    "state_epoch_unverified",
                    st["correlation_id"],
                    {"type": "erasure_journal", "id": EPOCH_FILE},
                    "denied",
                    None,
                    {"target": exc.state},
                )
            st["status"] = "unverified"
            self._announce(st, "CORE-STARTGATE-UNVERIFIED")
        self.store.merge_save(st)
        self._lease(st)

    def _check_actors(self, st: dict, target: _Place, missing: list[dict]) -> None:
        """RE-107: an identity entry about a person of an override, known only after it."""
        override = st["override"]
        journal = self.service.journal
        if override is None or journal is None:
            return
        fresh = {e["id"] for e in missing} | {
            e["id"] for e in target.entries.values() if _entry_seconds(e) >= override["at"]
        }
        actors = {
            journal.subject_ref(override[k]): override[k] for k in ("requested_by", "confirmed_by")
        }
        for entry in target.entries.values():
            sub = actors.get(entry["subject_ref"])
            if entry["id"] not in fresh or sub is None or sub in st["revoked_actors"]:
                continue
            st["revoked_actors"].append(sub)
            self._audit(
                "startgate_override_revoked_actor",
                "check",
                "operation",
                override["correlation_id"],
                {"type": "user", "id": sub},
                "allowed",
                None,
                {"kind": entry["kind"], "seq": entry["seq"]},
            )
            self._mail(
                "CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR", override["correlation_id"], person=sub
            )
        self.store.merge_save(st)

    # replay -----------------------------------------------------------
    def _replay(
        self, st: dict, epoch: dict, ends: dict, modules: list[str], own: int, now: int
    ) -> None:
        cid = st["correlation_id"]
        core_due = st["pending_core"] or not st["chat_built"] or bool(st["chat_jobs"])
        failed = self._replay_core(st, cid, now)
        if not failed:
            if core_due:
                # Every core entry is applied: the generation rises (sicherheit §4.9 (1)).
                for source in CORE_SOURCES:
                    st["applied"][source] = max(
                        st["applied"].get(source, 0), ends.get(source, 0),
                        epoch["seq"].get(source, 0),
                    )  # fmt: skip
                st["generation"] = max(own, epoch["generation"]) + 1
            for module in modules:
                if self._replay_module(module, epoch["seq"][module], cid):
                    st["applied"][module] = epoch["seq"][module]
                else:
                    failed.append(module)
            for source, end in ends.items():
                if source not in modules:
                    st["applied"][source] = max(st["applied"].get(source, 0), end)
        st["failed"] = sorted(set(failed))
        if failed:
            st["status"] = "replay_failed"
            self._announce(st, "CORE-STARTGATE-REPLAY-FAILED", services=", ".join(st["failed"]))
            _log(f"CORE-STARTGATE-REPLAY-FAILED: replay failed for {', '.join(st['failed'])}")
        else:
            st.update(status="open", announced=[])
        if any(k in CORE_SOURCES for k in failed):
            self.store.merge_save(st)
            self._lease(st)
            return
        self._save_and_record(st, {"generation": epoch["generation"], "seq": epoch["seq"]})
        self._audit(
            "startgate",
            "write",
            "operation",
            cid,
            {"type": "startgate", "id": GATE_FILE},
            detail={"generation": st["generation"], "closed": st["failed"]},
        )

    def _replay_core(self, st: dict, cid: str, now: int) -> list[str]:
        """Keycloak, then chat and model gateway; each finished step is kept, so a failure
        repeats only what is left."""
        service = self.service
        try:
            if st["pending_core"] or not st["chat_built"]:
                members = service.members()
                refs = {service.journal.subject_ref(uid): uid for uid, _ in members}
            if not st["chat_built"]:
                # Before the identity steps: an account deleted by them can no longer be
                # resolved, its chat data still has to go.
                st["chat_jobs"] = self._chat_jobs(st, refs)
                st["chat_built"] = True
                self.store.merge_save(st)
            if st["pending_core"]:
                handled: set[str] = set()  # deleted, or logged out by the revocation
                for entry in st["pending"]:
                    sub = refs.get(entry["subject_ref"])
                    if sub is not None and self._replay_identity(entry, sub, st, cid, now):
                        handled.add(sub)
                # Every account (sicherheit §4.9 (2a) (iii)): sessions and the consents at
                # the holder clients, instead of the realm-wide not-before.
                for uid, _ in members:
                    if uid in handled:
                        continue
                    service._write(
                        "POST", f"/users/{uid}/logout", "startgate_replay", "operation", cid, uid,
                        {"kind": "logout_all"},
                    )  # fmt: skip
                    for client, _ in service._consents(uid):
                        if client in HOLDER_CLIENTS:
                            service._delete_consent(uid, client, cid)
                service.set_global_since(now)
                service.reissue()
                st.update(pending=[], pending_core=False)
                self.store.merge_save(st)
        except RETRYABLE as exc:
            _log(f"start gate: replay in Keycloak failed ({exc!r}); tried again in 60 s")
            return ["identity"]
        failed: set[str] = set()
        for job in list(st["chat_jobs"]):
            try:
                if self.replay is None:
                    raise LifecycleError("papaia-replay is not configured")
                counts = self.replay.run(job["kind"], cid, sub=job["sub"], key_id=job["key_id"])
            except RETRYABLE as exc:
                failed.add(job["service"])
                self._audit(
                    "startgate_replay", "delete", "operation", cid,
                    {"type": "replay_job", "id": job["kind"]}, "error", "replay_failed",
                    {"kind": job["kind"]},
                )  # fmt: skip
                _log(f"start gate: papaia-replay {job['kind']} failed ({exc})")
                continue
            self._audit(
                "startgate_replay", "delete", "operation", cid,
                {"type": "replay_job", "id": job["kind"]}, detail={"kind": job["kind"], **counts},
            )  # fmt: skip
            st["chat_jobs"].remove(job)
            self.store.merge_save(st)
        return sorted(failed)

    def _chat_jobs(self, st: dict, refs: dict[str, str]) -> list[dict]:
        jobs = list(st["chat_jobs"])

        def add(kind: str, service: str, sub=None, key_id=None) -> None:
            job = {"kind": kind, "sub": sub, "key_id": key_id, "service": service}
            if job not in jobs:
                jobs.append(job)

        for source in CORE_SOURCES[1:]:
            place = _Place("target", self.target_dir, source)
            for entry in sorted(place.entries.values(), key=lambda e: e["seq"]):
                if entry["seq"] <= st["applied"].get(source, 0):
                    continue
                if entry["kind"] == "key_revoke":
                    match = _KEY_REF_RE.match(entry["object_ref"])
                    if match is None:
                        _log(f"start gate: {source} seq {entry['seq']} names no key; skipped")
                        continue
                    add("key_revoke", "model-gateway", key_id=match[1])
                    continue
                sub = refs.get(entry["subject_ref"])
                if sub is None:
                    _log(f"start gate: {source} seq {entry['seq']}: the person is not in the realm")
                    continue
                add("erase_subject", source, sub=sub)
        add("chat_sessions_reset", "core-chat")
        return jobs

    def _replay_identity(self, entry: dict, sub: str, st: dict, cid: str, now: int) -> bool:
        """One entry of the journal `identity` in Keycloak; True when the account is gone
        or was revoked (logged out, consents removed) here."""
        service, kind = self.service, entry["kind"]
        detail = {"kind": kind, "seq": entry["seq"]}

        def disable(reason: str) -> None:
            service._write(
                "PUT", f"/users/{sub}", "startgate_replay", "operation", cid, sub,
                {**detail, "reason": reason}, body={"enabled": False}, effect="write",
            )  # fmt: skip

        try:
            if kind == "account_delete":
                service._list(sub, now, "account_deleted")
                service._write(
                    "DELETE", f"/users/{sub}", "startgate_replay", "operation", cid, sub, detail
                )
                return True
            if kind == "account_disable":
                disable("account_disabled")
                reason = "account_disabled"
            elif kind == "credential_reset":
                # The credentials of the snapshot are older than the change (RE-103): the
                # administration sets new ones and activates the account.
                disable("credential_replay")
                reason = "credential_replay"
                if sub not in st["credential_replay"]:
                    st["credential_replay"].append(sub)
            elif kind == "role_revoke":
                group = _ROLE_GROUP_RE.match(entry["object_ref"])
                if group is not None:
                    service._write(
                        "DELETE", f"/users/{sub}/groups/{group[1]}", "startgate_replay",
                        "operation", cid, sub, detail,
                    )  # fmt: skip
                    reason = "role_removed"
                else:
                    # The journal names the kind of mapping, not the role (admin events
                    # carry no representation): the account is deactivated instead.
                    disable("role_replay")
                    reason = "role_replay"
                    if sub not in st["role_replay"]:
                        st["role_replay"].append(sub)
            else:  # session_revoke: every account is logged out below
                return False
        except HttpError as exc:
            if exc.status == 404:
                return True
            raise
        service.revoke(sub, now, reason, cid)
        return True

    def _replay_module(self, module: str, seq: int, cid: str) -> bool:
        try:
            if self.modules is None:
                raise LifecycleError("no module endpoint configured")
            answer = self.modules.run(module, "erasure-replay", cid)
            applied = answer.get("applied_seq") if isinstance(answer, dict) else None
            if not _plain_count(applied) or applied < seq:
                raise LifecycleError(f"{module} reports seq {applied!r}, the journal holds {seq}")
            self.modules.run(module, "post-restore", cid)
        except RETRYABLE as exc:
            self._audit(
                "startgate_replay", "write", "operation", cid, {"type": "module", "id": module},
                "error", "replay_failed", {"kind": "erasure-replay"},
            )  # fmt: skip
            _log(f"start gate: module {module} failed ({exc}); its host stays closed")
            return False
        self._audit(
            "startgate_replay", "write", "operation", cid, {"type": "module", "id": module},
            detail={"kind": "erasure-replay", "seq": seq},
        )  # fmt: skip
        return True

    # override ---------------------------------------------------------
    def request_override(
        self, reason: str, requested_by: str, confirmed_by: str, *, single_person: bool
    ) -> str:
        return request_override(
            self.store, reason, requested_by, confirmed_by, single_person=single_person
        )

    def request_acknowledge(self, reason: str, by: str) -> str:
        return request_acknowledge(self.store, reason, by)

    def _take_request(self) -> None:
        self._take_acknowledge()
        with self.store.locked():
            st = self.store.load()
            request = st["request"]
            if request is None:
                return
            st["request"] = None
            if st["status"] != "unverified":
                # Only an unreachable target (sicherheit §4.9 (2a) (v)): after a failed
                # replay the backlog is still due and the next comparison would end the
                # override at once.
                self.store.save(st)
                applied = False
            else:
                st["override"] = {**request, "at": int(self.clock()), "active": True}
                st.update(status="override", announced=[])
                self.store.save(st)
                applied = True
        if not applied:
            self._audit(
                "startgate_override", "write", "operation", request["correlation_id"],
                {"type": "startgate", "id": GATE_FILE}, "denied", "not_closed",
            )  # fmt: skip
            return
        keys = ("requested_by", "confirmed_by", "reason", "single_person")
        detail = {k: request[k] for k in keys}
        self._audit(
            "startgate_override", "write", "operation", request["correlation_id"],
            {"type": "startgate", "id": GATE_FILE}, detail=detail,
        )  # fmt: skip
        at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(self.clock()))
        self._mail(
            "CORE-STARTGATE-OVERRIDE",
            request["correlation_id"],
            first=request["requested_by"],
            second=request["confirmed_by"],
            at=at,
        )
        self._lease(st)

    def _take_acknowledge(self) -> None:
        """`papaia-ctl startgate acknowledge`: an administrator reviewed the override of
        persons locked afterwards; the alarm (`doctor startgate` fail) ends."""
        with self.store.locked():
            st = self.store.load()
            ack = st["acknowledge"]
            if ack is None:
                return
            st["acknowledge"] = None
            actors = list(st["revoked_actors"])
            applied = bool(actors) and ack["by"] not in actors
            if applied:
                st["revoked_actors"] = []
            self.store.save(st)
        ref = {"type": "startgate", "id": GATE_FILE}
        if not applied:
            self._audit(
                "startgate_override_acknowledged", "write", "operation", ack["correlation_id"],
                ref, "denied", "nothing_to_acknowledge" if not actors else "revoked_actor",
                {"by": ack["by"]},
            )  # fmt: skip
            return
        self._audit(
            "startgate_override_acknowledged", "write", "operation", ack["correlation_id"],
            ref, detail={"by": ack["by"], "reason": ack["reason"], "actors": actors},
        )  # fmt: skip

    def account_enabled(self, sub: str) -> None:
        """The administration activated an account the replay deactivated: it leaves the
        lists `doctor startgate` shows."""
        with self.store.locked():
            if not self.store.exists():
                return
            st = self.store.load()
            changed = False
            for name in ("credential_replay", "role_replay"):
                if sub in st[name]:
                    st[name].remove(sub)
                    changed = True
            if changed:
                self.store.save(st)


def request_override(
    store: GateStore, reason: str, requested_by: str, confirmed_by: str, *, single_person: bool
) -> str:
    """Record `papaia-ctl startgate open --unverified` (through `docker exec`); the running
    service applies it, audits and mails. Two different persons unless the four-eyes rule
    is off (never in `kritis`): papaia-ctl decides that from the installation's settings
    and checks role and fresh sign-in of both in Keycloak."""
    if not isinstance(reason, str) or not _OVERRIDE_REASON_RE.match(reason):
        raise LifecycleError("the reason must be 1 to 500 characters on one line")
    for sub in (requested_by, confirmed_by):
        if not isinstance(sub, str) or not _SUB_RE.match(sub):
            raise LifecycleError("requested-by and confirmed-by must be account ids")
    if requested_by == confirmed_by and not single_person:
        raise OverrideDenied(
            "Die Übersteuerung wurde nicht ausgeführt; sie braucht eine zweite Person mit "
            "papaia-admin."
        )
    cid = _uuid7()
    with store.locked():
        st = store.load()
        if st["status"] != "unverified":
            raise OverrideDenied(
                f"the gate is {st['status']}: an override opens only a gate held closed by "
                "an unreachable backup target"
            )
        st["request"] = {
            "reason": reason,
            "requested_by": requested_by,
            "confirmed_by": confirmed_by,
            "single_person": bool(single_person),
            "correlation_id": cid,
        }
        store.save(st)
    return cid


def request_acknowledge(store: GateStore, reason: str, by: str) -> str:
    """Record `papaia-ctl startgate acknowledge` (through `docker exec`): `by` reviewed
    the override whose persons a later journal entry locked. papaia-ctl checks role and
    fresh sign-in of `by` in Keycloak; here: something to acknowledge, and `by` is not
    one of the locked persons."""
    if not isinstance(reason, str) or not _OVERRIDE_REASON_RE.match(reason):
        raise LifecycleError("the reason must be 1 to 500 characters on one line")
    if not isinstance(by, str) or not _SUB_RE.match(by):
        raise LifecycleError("by must be an account id")
    cid = _uuid7()
    with store.locked():
        st = store.load()
        if not st["revoked_actors"]:
            raise OverrideDenied("no override of a person locked afterwards to acknowledge")
        if by in st["revoked_actors"]:
            raise OverrideDenied("a person locked after the override cannot acknowledge it")
        st["acknowledge"] = {"reason": reason, "by": by, "correlation_id": cid}
        store.save(st)
    return cid


def gate_report(st: dict, lease: dict | None, now: int) -> dict:
    """The gate in the health report (`doctor startgate`): no content, account ids only."""
    override = st["override"]
    return {
        "status": st["status"],
        "lease": "open" if gate_allows(lease, "core", now) else "closed",
        "failed": list(st["failed"]),
        "credential_replay": list(st["credential_replay"]),
        "role_replay": list(st["role_replay"]),
        "override": (
            {k: override[k] for k in ("requested_by", "confirmed_by", "at")}
            if override is not None and override["active"]
            else None
        ),
        "revoked_actors": list(st["revoked_actors"]),
        "correlation_id": st["correlation_id"],
    }


# ─────────────────────────────────────────────────────────────────────────
# papaia-replay and the module endpoints (mTLS)
# ─────────────────────────────────────────────────────────────────────────


def _https_base(url: object) -> str:
    if not isinstance(url, str):
        raise LifecycleError("an endpoint must be an https URL")
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.query
        or parts.fragment
        or parts.username
        or parts.path not in ("", "/")
    ):
        raise LifecycleError("an endpoint must be https://host[:port] without a path")
    return url.rstrip("/")


def mtls_context(ca_file: Path, cert_file: Path, key_file: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca_file))
    ctx.load_cert_chain(str(cert_file), str(key_file))
    return ctx


class ReplayClient:
    """papaia-replay (core adapters `core-chat` and `model-gateway`): one job per request
    over mTLS, the answer holds counts only. It gets the account id, never the HMAC key."""

    def __init__(self, url: str, ctx: ssl.SSLContext) -> None:
        self.url, self.ctx = _https_base(url), ctx

    def run(self, kind: str, correlation: str, *, sub=None, key_id=None) -> dict:
        if kind not in REPLAY_KINDS:
            raise LifecycleError(f"unknown replay job {kind!r}")
        body: dict = {"kind": kind}
        if sub is not None:
            if not _SUB_RE.match(sub):
                raise LifecycleError("malformed account id")
            body["sub"] = sub
        if key_id is not None:
            if not _KEY_REF_RE.match(f"key:{key_id}"):
                raise LifecycleError("malformed key id")
            body["key_id"] = key_id
        answer = _open_json(
            urllib.request.Request(
                f"{self.url}/replay",
                data=json.dumps(body).encode(),
                method="POST",
                headers={"Content-Type": "application/json", CORRELATION_HEADER: correlation},
            ),
            self.ctx,
        )
        counts = answer.get("counts") if isinstance(answer, dict) else None
        if not isinstance(counts, dict) or len(counts) > 32 or not all(
            isinstance(k, str) and _REASON_RE.match(k) and _plain_count(v)
            for k, v in counts.items()
        ):
            raise LifecycleError("papaia-replay answered without counts")
        return counts


class ModuleClient:
    """`POST /internal/lifecycle` of each module over mTLS (the kit's LifecycleHandler)."""

    def __init__(self, targets: dict, ctx: ssl.SSLContext) -> None:
        if not isinstance(targets, dict) or len(targets) > MAX_EPOCH_SOURCES:
            raise LifecycleError("the module endpoints must map module names to URLs")
        self.targets = {}
        for module, url in targets.items():
            if not isinstance(module, str) or not _GATE_KEY_RE.match(module):
                raise LifecycleError("malformed module name in the module endpoints")
            self.targets[module] = _https_base(url)
        self.ctx = ctx

    @classmethod
    def from_file(cls, path: Path, ctx: ssl.SSLContext) -> ModuleClient:
        try:
            doc = _strict_json(Path(path).read_bytes()[:65537])
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            raise LifecycleError(f"{path}: not a JSON file of module endpoints") from None
        if not isinstance(doc, dict) or set(doc) != {"modules"}:
            raise LifecycleError(f"{path}: must hold exactly the key modules")
        return cls(doc["modules"], ctx)

    def run(self, module: str, action: str, correlation: str) -> dict:
        if action not in MODULE_ACTIONS:
            raise LifecycleError(f"unknown module action {action!r}")
        url = self.targets.get(module)
        if url is None:
            raise LifecycleError(f"no endpoint known for module {module}")
        answer = _open_json(
            urllib.request.Request(
                f"{url}/internal/lifecycle",
                data=json.dumps({"action": action}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", CORRELATION_HEADER: correlation},
            ),
            self.ctx,
        )
        if not isinstance(answer, dict) or answer.get("module") != module:
            raise LifecycleError(f"{module} answered for another module")
        return answer


# ─────────────────────────────────────────────────────────────────────────
# the check service of the edge (no secret, the lease read-only)
# ─────────────────────────────────────────────────────────────────────────


def _header(headers, name: str) -> str | None:
    found = [v for k, v in headers.items() if k.lower() == name.lower()]
    return found[0] if len(found) == 1 and isinstance(found[0], str) else None


def _maintenance_page(doc: dict | None, now: int, contact: str | None) -> bytes:
    code = gate_code(doc, now)
    first, second = GATE_PAGE_TEXT[code]
    who = "Ihre Ansprechstelle"
    if contact is not None:
        text = urllib.parse.unquote(contact, errors="strict")[:200]
        if _CONTACT_RE.match(text):
            who = text
    cid = doc["correlation_id"] if doc is not None else f"CORE-STARTGATE-{code}"
    lines = (
        html.escape(first),
        html.escape(second.format(contact=who)),
        html.escape(f"Kennung: {cid}"),
    )
    body = (
        '<!doctype html><html lang="de"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Wartung</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;"
        "margin:4rem auto;padding:0 1rem;line-height:1.5}small{color:#555}</style></head>"
        f"<body><h1>Wartung</h1><p>{lines[0]}</p><p>{lines[1]}</p><p><small>{lines[2]}"
        "</small></p></body></html>"
    )
    return body.encode("utf-8")


def gate_check_response(
    state_dir: Path, method: str, path: str, headers, now: int
) -> tuple[int, dict, bytes]:
    """The answer of the check service: `GET /check` 204 (forward) or 401 (maintenance)
    for the host key the edge names, `GET /maintenance` the page with status 503."""
    if path not in ("/check", "/maintenance"):
        return 404, {}, b""
    if method != "GET":
        return 405, {"Allow": "GET"}, b""
    doc = read_gate(state_dir)
    if path == "/check":
        key = _header(headers, GATE_SERVICE_HEADER)
        if gate_allows(doc, key, now) or gate_signin_allowed(
            key, _header(headers, GATE_URI_HEADER)
        ):
            return 204, {}, b""
        return 401, {"X-Papaia-Gate-Code": gate_code(doc, now)}, b""
    try:
        body = _maintenance_page(doc, now, _header(headers, GATE_CONTACT_HEADER))
    except UnicodeDecodeError:
        body = _maintenance_page(doc, now, None)
    return (
        503,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Retry-After": str(GATE_CHECK_SECONDS),
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
        body,
    )


def gate_check_server(state_dir: Path, host: str, port: int, *, clock=time.time):
    """A small HTTP server for the edge's `auth_request`; it reads the lease on every
    request and writes nothing."""

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "papaia-startgate-check"
        sys_version = ""
        timeout = 10

        def _answer(self) -> None:
            status, headers, body = gate_check_response(
                state_dir, self.command, self.path, self.headers, int(clock())
            )
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _answer

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - base signature
            return

    return http.server.ThreadingHTTPServer((host, port), Handler)


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
    # The start gate is reported, not part of the container's health: a closed gate is
    # the service doing its job (`doctor startgate` reads it).
    gate_store = GateStore(key_dir)
    if gate_store.exists():
        try:
            report["startgate"] = gate_report(gate_store.load(), read_gate(state_dir), int(now))
        except LifecycleError:
            report["startgate"] = {"status": "unreadable"}
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
    fed = state["federation"]
    federation_failing = False
    if fed["configured"]:
        failing = max(0, int(now - fed["failing_since"])) if fed["failing_since"] else 0
        since = fed["last_ok"] or fed["started"] or 0
        report["status_sync_age_seconds"] = max(0, int(now - since)) if since else None
        report["status_sync_failing_seconds"] = failing
        # Failing for longer than 300 s, or no round at all for that long (the service
        # hangs): new locks upstream do not reach papaia.
        federation_failing = failing > STATUS_SYNC_FAIL_SECONDS or (
            bool(since) and now - since > STATUS_SYNC_FAIL_SECONDS + STATUS_SYNC_SECONDS
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
        or federation_failing
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
            # Federation (docs/federation.md): the status sync folder, the mail relay and
            # the operations address for the warning mail.
            cmd.add_argument("--federation-dir", type=Path)
            cmd.add_argument("--mail-relay")
            cmd.add_argument("--alert-to")
            cmd.add_argument("--alert-from")
            # The start gate's mTLS calls: papaia-replay and the modules' endpoints
            # (`{"modules": {name: "https://host:port"}}`), with the client certificate
            # of the platform PKI. Without them a backlog in chat, gateway or a module
            # cannot be replayed and keeps that part closed.
            cmd.add_argument("--replay-url")
            cmd.add_argument("--modules-file", type=Path)
            cmd.add_argument("--pki-ca", type=Path)
            cmd.add_argument("--client-cert", type=Path)
            cmd.add_argument("--client-key", type=Path)
        if name == "global-since":
            cmd.add_argument("--at", type=int)
    # `papaia-ctl startgate open --unverified` through `docker exec` (sicherheit §4.9 (2a) (v)).
    # The request is one JSON object on stdin: {reason, requested_by, confirmed_by,
    # single_person}; nothing a person typed becomes part of the command line.
    cmd = sub.add_parser("startgate-override")
    cmd.add_argument("--key-dir", type=Path, required=True)
    # `papaia-ctl startgate acknowledge` the same way: {reason, by} on stdin.
    cmd = sub.add_parser("startgate-acknowledge")
    cmd.add_argument("--key-dir", type=Path, required=True)
    # The check service of the edge: reads the lease, holds no secret.
    cmd = sub.add_parser("gate-check")
    cmd.add_argument("--state-dir", type=Path, required=True)
    cmd.add_argument("--listen", default="0.0.0.0:8080")
    # `papaia-ctl person run` through `docker exec`: {operation, sub} on stdin.
    cmd = sub.add_parser("person")
    cmd.add_argument("--keycloak-url", required=True)
    cmd.add_argument("--ca-file", type=Path)
    cmd.add_argument("--account-dir", type=Path, required=True)
    # `papaia-ctl person find` through `docker exec`: the HMACs only, never a name.
    cmd = sub.add_parser("find")
    cmd.add_argument("--key-dir", type=Path, required=True)
    cmd.add_argument("--name-ref")
    cmd.add_argument("--mail-ref")
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


def _startgate_override(args) -> int:
    """Record the override read from stdin and wait until the running service applied it."""
    store = GateStore(args.key_dir)
    try:
        try:
            request = _strict_json(sys.stdin.buffer.read(8193)[:8192])
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise LifecycleError("the override request on stdin is not JSON") from None
        keys = {"reason", "requested_by", "confirmed_by", "single_person"}
        if not isinstance(request, dict) or set(request) != keys:
            raise LifecycleError(f"the override request must hold exactly {sorted(keys)}")
        if not isinstance(request["single_person"], bool):
            raise LifecycleError("single_person must be true or false")
        cid = request_override(
            store, request["reason"], request["requested_by"], request["confirmed_by"],
            single_person=request["single_person"],
        )  # fmt: skip
    except OverrideDenied as exc:
        _log(f"refused: {exc}")
        return 3
    except LifecycleError as exc:
        _log(f"refused: {exc}")
        return 2
    deadline = time.monotonic() + OVERRIDE_WAIT_SECONDS
    while time.monotonic() < deadline:
        with store.locked():
            st = store.load()
        if st["request"] is None:
            applied = st["status"] == "override" and (st["override"] or {}).get(
                "correlation_id"
            ) == cid
            print(json.dumps({"applied": applied, "correlation_id": cid}, sort_keys=True))
            return 0 if applied else 3
        time.sleep(1)
    print(json.dumps({"applied": False, "correlation_id": cid, "pending": True}, sort_keys=True))
    return 4


def _startgate_acknowledge(args) -> int:
    """Record the acknowledgement read from stdin and wait until the service applied it."""
    store = GateStore(args.key_dir)
    try:
        try:
            request = _strict_json(sys.stdin.buffer.read(8193)[:8192])
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise LifecycleError("the acknowledgement on stdin is not JSON") from None
        if not isinstance(request, dict) or set(request) != {"reason", "by"}:
            raise LifecycleError("the acknowledgement must hold exactly ['by', 'reason']")
        cid = request_acknowledge(store, request["reason"], request["by"])
    except OverrideDenied as exc:
        _log(f"refused: {exc}")
        return 3
    except LifecycleError as exc:
        _log(f"refused: {exc}")
        return 2
    deadline = time.monotonic() + OVERRIDE_WAIT_SECONDS
    while time.monotonic() < deadline:
        with store.locked():
            st = store.load()
        if st["acknowledge"] is None:
            applied = not st["revoked_actors"]
            print(json.dumps({"applied": applied, "correlation_id": cid}, sort_keys=True))
            return 0 if applied else 3
        time.sleep(1)
    print(json.dumps({"applied": False, "correlation_id": cid, "pending": True}, sort_keys=True))
    return 4


def _person(args) -> int:
    """One `person_request` read from stdin; the answer is one JSON line on stdout. A
    refusal or a failed call is exit 1 with a code, never a response body."""
    try:
        try:
            request = _strict_json(sys.stdin.buffer.read(4097)[:4096])
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise LifecycleError("the request on stdin is not JSON") from None
        ctx = None
        if urllib.parse.urlsplit(keycloak_url(args.keycloak_url)).scheme == "https":
            ctx = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
        answer = person_request(AccountClient(args.keycloak_url, ctx, args.account_dir), request)
    except RETRYABLE as exc:
        _log(f"person: refused or failed ({exc.__class__.__name__})")
        print(json.dumps({"error": "failed"}))
        return 1
    print(json.dumps(answer, sort_keys=True))
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
    if args.command == "person":
        return _person(args)
    if args.command == "find":
        persons = find(Store(args.key_dir), args.name_ref, args.mail_ref)
        print(json.dumps({"persons": persons}, sort_keys=True))
        return 0
    if args.command == "gate-check":
        host, _, port = args.listen.rpartition(":")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise LifecycleError("--listen must be host:port")
        _log(f"start gate check listening on {host}:{port}")
        gate_check_server(args.state_dir, host, int(port)).serve_forever()
        return 0
    if args.command == "startgate-override":
        return _startgate_override(args)
    if args.command == "startgate-acknowledge":
        return _startgate_acknowledge(args)
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
    federation = None
    mailer = None
    if args.mail_relay and args.alert_to and args.alert_from:
        mailer = Mailer(args.mail_relay, args.alert_to, args.alert_from)
    if args.federation_dir is not None:
        # The upstream directory is outside the stack: the system's trust store.
        federation = StatusSync(
            UpstreamDirectory(args.federation_dir, ssl.create_default_context()), mailer=mailer
        )
    service = Lifecycle(
        AccountClient(args.keycloak_url, ctx, args.account_dir),
        store,
        publisher,
        journal=journal,
        federation=federation,
    )
    replay = modules = None
    if args.replay_url or args.modules_file:
        if not (args.pki_ca and args.client_cert and args.client_key):
            raise LifecycleError("--replay-url and --modules-file need the PKI files")
        mtls = mtls_context(args.pki_ca, args.client_cert, args.client_key)
        replay = ReplayClient(args.replay_url, mtls) if args.replay_url else None
        modules = ModuleClient.from_file(args.modules_file, mtls) if args.modules_file else None
    StartGate(
        service,
        state_dir=args.state_dir,
        key_dir=args.key_dir,
        target_dir=args.journal_dir,
        local_dir=args.journal_local_dir,
        replay=replay,
        modules=modules,
        mailer=mailer,
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
