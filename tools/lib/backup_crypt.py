"""Encryption, recipients and the confirmed target of `papaia-ctl backup` (BE-14, BE-15).

* Recipients: the public keys every archive is encrypted to, in the root `.env` as
  `PAPAIA_BACKUP_RECIPIENTS=<name>:<age1...>,...` (one for operations, one for emergencies
  is the intended set). A backup without a recipient is refused, never written in clear.
  The private keys are never stored by papaia-ctl: not in the configuration directory, not
  in an archive, not at the target.
* Target: there is no default. A directory is a backup target once `backup target init`
  wrote `.papaia-target` with this installation's id into it; `backup` refuses a directory
  without that file (also an unmounted share) and one that belongs to another installation.
* Sealing: bash streams each tar.gz archive in; it is encrypted to the recipients on the
  way to the target, and the stream is read once more to refuse key material that never
  goes into a backup (the rollback keys, an age identity, the hosted model's key).
* Key check: `backup key-check --identity=-` opens the header of the newest point with a
  key, without restoring anything, and records the date per recipient.
* Restore: `restore --identity=FILE|-` checks before it changes anything that the key opens
  every archive it will restore and that each file still has the SHA-256 the manifest
  recorded; it then decrypts each archive into the stream bash unpacks, so the plain
  archive is never on disk either. Without a key an encrypted point is refused, never
  started with new keys in its place (STU-37-A6).
"""

from __future__ import annotations

import getpass
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

import yaml

from . import age, common, images
from .backup import (
    CHECKSUMS_NAME,
    BackupError,
    EncryptedRestorePointError,
    Recipient,
    load_index,
    read_manifest,
    snapshot_path,
)

RECIPIENTS_VAR = "PAPAIA_BACKUP_RECIPIENTS"
MAX_RECIPIENTS = 8
INSTALLATION_ID_FILE = "installation-id"
TARGET_FILE = ".papaia-target"
TARGET_SCHEMA = "papaia.backup-target/1"
KEY_CHECK_FILE = "backup-key-check.yaml"
SCAN_BLOCK = 1024 * 1024
MAX_IDENTITY_BYTES = 64 * 1024

_NAME_RE = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")
_UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")

# Paths inside an archive (relative to its root) that never go into a backup: the rollback
# keys of an upgrade (BE-11, RE-11) and the key of the test stack's hosted model. bash
# leaves them out of the tar stream; finding one here means that exclusion failed.
FORBIDDEN_PATHS = ("state/rollback", "ai/litellm/test-hosted.env")
# Content that is a private key of the backup itself: an age identity (operator, emergency
# or rollback key). Found in any regular file of the archive, in any case (bech32 allows
# an all-lowercase identity), the artifact is refused. The scan reads each member as
# stored: a key inside a nested archive or compressed file is not seen. It backs up the
# exclusion by volume and path, which is the primary defence, and does not replace it.
KEY_MARKERS = (b"age-secret-key-1",)


class KeyMaterialError(BackupError):
    """An archive stream that holds key material a backup must never contain."""


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


# Made on the first row of a process that got no correlation id from its caller.
_RUN_CORRELATION: str | None = None


def _correlation() -> str:
    """The caller's correlation id, or one made here and kept for the rest of the process,
    so every row of one run (a backup and its retention) shares it."""
    value = os.environ.get("PAPAIA_CORRELATION_ID", "")
    try:
        return images.correlation_id(value or None) if value else _own_correlation()
    except images.ImageError:
        return _own_correlation()


def _own_correlation() -> str:
    global _RUN_CORRELATION
    if _RUN_CORRELATION is None:
        _RUN_CORRELATION = images.correlation_id(None)
    return _RUN_CORRELATION


def audit(config_dir: Path, operation: str, event: str, detail: dict,
          effect: str = "write", result: str = "allowed") -> None:
    """One `papaia.audit/1` row for a write of the backup commands. Public keys, ids and
    counts only; never a private key or archive content."""
    now = time.time()
    row = {
        "format": "papaia.audit/1",
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int(now % 1 * 1000):03d}Z",
        "correlation_id": _correlation(),
        "writer": "papaia-ctl",
        "role": "operator",
        "sub": None,
        "identity_kind": "host",
        "azp": None,
        "catalog_id": None,
        "operation": operation,
        "effect": effect,
        "result": result,
        "error_code": None,
        "event": event,
        "detail": {**detail, "confirmed_by": images.confirming_user()},
    }
    images.append_audit(config_dir, row)


# ─────────────────────────────────────────────────────────────────────────
# recipients
# ─────────────────────────────────────────────────────────────────────────


def _check_name(name: object) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise BackupError(
            f"Recipient name {name!r}: lowercase letters, digits and '-', starting with a letter"
        )
    return name


def _check_key(key: object) -> str:
    try:
        age.parse_recipient(key if isinstance(key, str) else "")
    except age.AgeError:
        raise BackupError(
            "A recipient is a public age key (age1...); a private key is never configured"
        ) from None
    return key


def parse_recipients(value: str) -> list[Recipient]:
    items = [item.strip() for item in (value or "").split(",") if item.strip()]
    if len(items) > MAX_RECIPIENTS:
        raise BackupError(f"At most {MAX_RECIPIENTS} backup recipients")
    found: list[Recipient] = []
    for item in items:
        name, sep, key = item.partition(":")
        if not sep:
            raise BackupError(f"{RECIPIENTS_VAR}: expected NAME:age1..., got {item[:40]!r}")
        recipient = Recipient(_check_name(name.strip()), _check_key(key.strip()))
        if any(r.name == recipient.name for r in found):
            raise BackupError(f"{RECIPIENTS_VAR}: name {recipient.name!r} is given twice")
        if any(r.key == recipient.key for r in found):
            raise BackupError(f"{RECIPIENTS_VAR}: the key of {recipient.name!r} is given twice")
        found.append(recipient)
    return found


def format_recipients(recipients: list[Recipient]) -> str:
    return ",".join(f"{r.name}:{r.key}" for r in recipients)


def load_recipients(config_dir: Path) -> list[Recipient]:
    return parse_recipients(common.parse_env_file(config_dir / ".env").get(RECIPIENTS_VAR, ""))


def require_recipients(config_dir: Path) -> list[Recipient]:
    recipients = load_recipients(config_dir)
    if not recipients:
        raise BackupError(
            f"No backup recipient is configured ({RECIPIENTS_VAR}); a backup is never written "
            "unencrypted. Generate a pair with 'papaia-ctl backup keys generate' or add a "
            "public key with 'papaia-ctl backup recipients add --name=NAME --key=age1...'."
        )
    return recipients


def _store(config_dir: Path, recipients: list[Recipient]) -> None:
    common.write_env_file(config_dir / ".env", {RECIPIENTS_VAR: format_recipients(recipients)})


def add_recipient(config_dir: Path, name: str, key: str) -> list[Recipient]:
    current = load_recipients(config_dir)
    updated = parse_recipients(format_recipients([*current, Recipient(name, key)]))
    _store(config_dir, updated)
    audit(config_dir, "backup-recipients", "backup_recipient_added",
          {"name": name, "key": key, "recipients": len(updated)})
    return updated


def remove_recipient(config_dir: Path, name: str) -> Recipient:
    current = load_recipients(config_dir)
    match = [r for r in current if r.name == name]
    if not match:
        raise BackupError(f"No backup recipient named {name!r}")
    if len(current) == 1:
        raise BackupError(
            "Refusing to remove the last recipient: the next backup would have no key. "
            "Add the new recipient first."
        )
    _store(config_dir, [r for r in current if r.name != name])
    audit(config_dir, "backup-recipients", "backup_recipient_removed",
          {"name": name, "key": match[0].key, "recipients": len(current) - 1})
    return match[0]


def points_for_key(backup_dir: Path, key: str) -> list[tuple[str, str]]:
    """(id, created_at) of the catalogued points encrypted to `key`, oldest first: they
    stay readable with it until retention or `backup-delete` removes them."""
    found = [
        (str(entry.get("id")), str(entry.get("created_at") or ""))
        for entry in load_index(backup_dir).get("backups") or []
        if any(isinstance(r, dict) and r.get("key") == key for r in entry.get("recipients") or [])
    ]
    return sorted(found, key=lambda point: point[1])


def generate_pair() -> tuple[str, str]:
    return age.generate_identity()


# ─────────────────────────────────────────────────────────────────────────
# the confirmed target
# ─────────────────────────────────────────────────────────────────────────


def installation_id(config_dir: Path, *, create: bool = False) -> str | None:
    """This installation's id, from `<config>/installation-id`. It travels with the
    configuration directory, so a restore on another host finds the same target."""
    path = config_dir / INSTALLATION_ID_FILE
    if path.is_file() and not path.is_symlink():
        value = path.read_text(encoding="utf-8")[:64].strip()
        if not _UUID_RE.match(value):
            raise BackupError(f"{path} does not hold an installation id")
        return value
    if not create:
        return None
    value = str(uuid.uuid4())
    common.atomic_write(path, value + "\n")
    return value


def _read_target(backup_dir: Path) -> str | None:
    path = backup_dir / TARGET_FILE
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise BackupError(f"{path} is not a regular file")
    if not path.is_file():
        return None
    raw = path.read_bytes()
    if len(raw) > 4096:
        raise BackupError(f"{path} is too large to be an id file")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        data = None
    if not isinstance(data, dict) or set(data) - {"schema", "installation_id", "created_at"}:
        raise BackupError(f"{path} is not a backup target id file")
    if data.get("schema") != TARGET_SCHEMA:
        raise BackupError(f"{path}: schema {TARGET_SCHEMA} expected")
    value = data.get("installation_id")
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise BackupError(f"{path} holds no valid installation id")
    return value


def _require_dir(backup_dir: Path) -> None:
    if not backup_dir.is_dir():
        raise BackupError(
            f"Backup target {backup_dir} does not exist or is not mounted. There is no default "
            "target: name an existing directory (local disk, NFS or SMB share)."
        )


def check_target(config_dir: Path, backup_dir: Path) -> str:
    """The installation id when `backup_dir` is this installation's confirmed target."""
    _require_dir(backup_dir)
    found = _read_target(backup_dir)
    if found is None:
        raise BackupError(
            f"{backup_dir} is not a confirmed backup target (no {TARGET_FILE}); there is no "
            "default target. Confirm it once with "
            f"'papaia-ctl backup target init --backup-dir={backup_dir}'. An unmounted share "
            "looks like this as well."
        )
    own = installation_id(config_dir)
    if own != found:
        raise BackupError(
            f"{backup_dir} is the backup target of another installation ({found}); this "
            f"installation is {own or 'not yet confirmed anywhere'}. Refusing to write into it."
        )
    return own


def init_target(config_dir: Path, backup_dir: Path) -> str:
    """Write `.papaia-target` with this installation's id; a no-op on its own target."""
    _require_dir(backup_dir)
    found = _read_target(backup_dir)
    own = installation_id(config_dir, create=True)
    if found == own:
        return own
    if found is not None:
        raise BackupError(
            f"{backup_dir} is the backup target of another installation ({found}). "
            "Refusing to take it over; choose another directory."
        )
    content = yaml.safe_dump(
        {
            "schema": TARGET_SCHEMA,
            "installation_id": own,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        sort_keys=False,
    )
    common.atomic_write(backup_dir / TARGET_FILE, content)
    audit(config_dir, "backup-target", "backup_target_confirmed",
          {"target": str(backup_dir), "installation_id": own})
    return own


def check_free_space(backup_dir: Path, *, free_bytes: int | None = None) -> None:
    """Refuse when the target has less room than twice the last complete point."""
    points = [
        b for b in load_index(backup_dir).get("backups") or []
        if b.get("result") == "ok" and not b.get("scope")
    ]
    if not points:
        return
    last = sorted(points, key=lambda b: str(b.get("created_at", "")))[-1]
    try:
        needed = int(float(last.get("size_mb") or 0) * 2 * 1024 * 1024)
    except (TypeError, ValueError):
        return
    free = free_bytes if free_bytes is not None else shutil.disk_usage(backup_dir).free
    if free < needed:
        raise BackupError(
            f"Backup target {backup_dir} has {free // (1024 * 1024)} MB free; twice the last "
            f"point ({needed // (1024 * 1024)} MB) is needed."
        )


# ─────────────────────────────────────────────────────────────────────────
# sealing
# ─────────────────────────────────────────────────────────────────────────


class _Hashing:
    def __init__(self, handle: BinaryIO) -> None:
        self.handle = handle
        self.digest = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.digest.update(data)
        return self.handle.write(data)


class _Tee:
    """Reads from `source` and hands every byte read to `sink` as well."""

    def __init__(self, source: BinaryIO, sink) -> None:
        self.source, self.sink = source, sink

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        if data:
            self.sink.write(data)
        return data


def _forbidden(name: str) -> str | None:
    rel = name.lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    for path in FORBIDDEN_PATHS:
        if rel == path or rel.startswith(path + "/"):
            return path
    return None


def _scan_member(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
    handle = tar.extractfile(member)
    if handle is None:
        return False
    keep = max(len(m) for m in KEY_MARKERS) - 1
    tail = b""
    while True:
        block = handle.read(SCAN_BLOCK)
        if not block:
            return False
        window = tail + block
        folded = window.lower()
        if any(marker in folded for marker in KEY_MARKERS):
            return True
        tail = window[-keep:]


def seal(stream: BinaryIO, target: Path, recipients: list[str]) -> str:
    """Encrypt a tar.gz stream to `target` and return the SHA-256 of the written file.

    The file is written as `<target>.part` and renamed only after the whole stream was
    read, encrypted and found free of key material; on any failure nothing is left."""
    if not recipients:
        raise BackupError("No recipient: a backup is never written unencrypted")
    common.ensure_dir(target.parent)
    part = target.with_name(target.name + ".part")
    try:
        with open(part, "wb") as raw:
            hashing = _Hashing(raw)
            with age.Encryptor(hashing, recipients) as encryptor:
                tee = _Tee(stream, encryptor)
                try:
                    with tarfile.open(fileobj=tee, mode="r|gz") as tar:
                        for member in tar:
                            hit = _forbidden(member.name)
                            if hit:
                                raise KeyMaterialError(
                                    f"{target.name}: holds {hit}, which never goes into a backup"
                                )
                            if member.isfile() and _scan_member(tar, member):
                                raise KeyMaterialError(
                                    f"{target.name}: {member.name} holds a private age key, "
                                    "which never goes into a backup"
                                )
                except (tarfile.TarError, OSError, EOFError) as exc:
                    raise BackupError(f"{target.name}: not a tar.gz stream ({exc})") from exc
                # The end-of-archive blocks and the gzip trailer: every byte is sealed.
                while tee.read(SCAN_BLOCK):
                    pass
        os.replace(part, target)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return hashing.digest.hexdigest()


def seal_output(
    produce: Callable[[BinaryIO], bool], target: Path, recipients: list[str]
) -> tuple[bool, str | None, BackupError | None]:
    """Run `produce(writer)` (a command writing a tar.gz stream to `writer`) and seal what it
    writes, through a pipe, so the stream is never on disk in clear.

    Returns (produced, sha256 or None, the sealing error or None). After a sealing error the
    rest of the stream is read and dropped, so the producer never blocks on a full pipe."""
    read_fd, write_fd = os.pipe()
    outcome: dict = {}

    def consume() -> None:
        with os.fdopen(read_fd, "rb") as reader:
            try:
                outcome["digest"] = seal(reader, target, recipients)
            except BackupError as exc:
                outcome["error"] = exc
            except Exception as exc:  # reported as the failure of this one artifact
                outcome["error"] = BackupError(f"{target.name}: {exc}")
            while reader.read(SCAN_BLOCK):
                pass

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    try:
        with os.fdopen(write_fd, "wb") as writer:
            produced = produce(writer)
    finally:
        worker.join()
    return produced, outcome.get("digest"), outcome.get("error")


def record_checksum(snapshot: Path, archive: str, digest: str) -> None:
    with open(snapshot / CHECKSUMS_NAME, "a", encoding="utf-8") as handle:
        handle.write(f"{archive}\t{digest}\n")


# ─────────────────────────────────────────────────────────────────────────
# identities and the key check
# ─────────────────────────────────────────────────────────────────────────


def read_identities(source: str) -> list[str]:
    """Identities from a file or `-` (standard input). They stay in memory.

    A passphrase-protected identity file (itself an age file) is opened with a passphrase
    read from the terminal."""
    if source == "-":
        raw = sys.stdin.buffer.read(MAX_IDENTITY_BYTES + 1) if hasattr(sys.stdin, "buffer") \
            else sys.stdin.read(MAX_IDENTITY_BYTES + 1).encode("utf-8")
    else:
        path = Path(source)
        if not path.is_file():
            raise BackupError(f"Identity file {source} not found")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_IDENTITY_BYTES + 1)
    if len(raw) > MAX_IDENTITY_BYTES:
        raise BackupError("The identity input is too large to be a key file")
    if raw.startswith(age.VERSION_LINE + b"\n"):
        try:
            passphrase = getpass.getpass("Passphrase of the identity file: ")
        except (EOFError, OSError):
            raise BackupError("A passphrase-protected identity file needs a terminal") from None
        out = io.BytesIO()
        try:
            age.decrypt_with_passphrase(io.BytesIO(raw), out, passphrase)
        except age.AgeError as exc:
            raise BackupError(f"The identity file could not be opened: {exc}") from None
        raw = out.getvalue()
    try:
        return age.parse_identity_file(raw.decode("utf-8"))
    except (UnicodeDecodeError, age.AgeError):
        raise BackupError("No age identity (AGE-SECRET-KEY-1...) in the input") from None


def key_check(
    config_dir: Path, backup_dir: Path, identities: list[str], restore_point: str | None = None
) -> tuple[str, list[str]]:
    """Open the header of one archive of a point with the given keys, without restoring.

    Returns (point id, recipient names the keys belong to) and records the date of the
    check per recipient key in KEY_CHECK_FILE. The 180-day reminder that reads it is the
    `doctor` check `backup_keys` (BE-14 c), which this module does not implement."""
    entries = [
        e for e in load_index(backup_dir).get("backups") or []
        if e.get("recipients") and e.get("result") != "failed"
    ]
    if restore_point:
        entries = [e for e in entries if str(e.get("id")) == restore_point]
    if not entries:
        raise BackupError(f"No encrypted restore point in {backup_dir} to check a key against")
    entry = sorted(entries, key=lambda e: str(e.get("created_at", "")))[-1]
    snapshot = snapshot_path(backup_dir, entry)
    manifest = read_manifest(snapshot)
    archives = [a.get("archive") for a in manifest.get("artifacts") or [] if a.get("archive")]
    if not archives:
        raise BackupError(f"Restore point {entry.get('id')} holds no archive")
    try:
        mine = {age.recipient_of(i) for i in identities}
    except age.AgeError as exc:
        raise BackupError(str(exc)) from None
    named = {
        r.get("key"): r.get("name")
        for r in (manifest.get("encryption") or {}).get("recipients") or []
        if isinstance(r, dict)
    }
    archive = snapshot / str(archives[0])
    if not archive.resolve().is_relative_to(snapshot.resolve()):
        raise BackupError(f"Refusing archive path {archives[0]!r} from the manifest")
    try:
        with open(archive, "rb") as handle:
            age.open_header(handle, identities)
    except age.NoIdentityError:
        raise BackupError(
            f"The key is not a recipient of restore point {entry.get('id')} "
            f"(recipients: {', '.join(f'{n} {k}' for k, n in named.items())})"
        ) from None
    except (OSError, age.AgeError) as exc:
        raise BackupError(f"{archive}: {exc}") from None
    matched = sorted(str(named[k]) for k in mine if k in named)
    record_path = config_dir / KEY_CHECK_FILE
    record = {}
    if record_path.is_file():
        try:
            record = yaml.safe_load(record_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            record = {}
    checked = record.get("checked") if isinstance(record.get("checked"), dict) else {}
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for key in mine:
        if key in named:
            checked[key] = stamp
    common.atomic_write(record_path, yaml.safe_dump({"checked": checked}, sort_keys=True))
    return str(entry.get("id")), matched


# ─────────────────────────────────────────────────────────────────────────
# restore
# ─────────────────────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def _recipient_names(manifest: dict) -> str:
    return ", ".join(
        f"{r.get('name')} {r.get('key')}"
        for r in (manifest.get("encryption") or {}).get("recipients") or []
        if isinstance(r, dict)
    ) or "none recorded"


def require_key(manifest: dict, identities: list[str] | None) -> bool:
    """Whether the point is encrypted; refuses an encrypted point without a key."""
    if not manifest.get("encryption"):
        return False
    if not identities:
        raise EncryptedRestorePointError(
            f"The key for restore point {manifest.get('id')} is missing (recipients: "
            f"{_recipient_names(manifest)}). Pass --identity=FILE or --identity=- (the key "
            "on standard input); nothing was changed."
        )
    return True


def _archive(snapshot: Path, manifest: dict, archive: str) -> tuple[Path, str]:
    """The file of an archive the manifest lists, and the SHA-256 it recorded for it."""
    entry = next(
        (a for a in manifest.get("artifacts") or []
         if isinstance(a, dict) and a.get("archive") == archive),
        None,
    )
    if entry is None:
        raise BackupError(f"{archive!r} is not an archive of restore point {manifest.get('id')}")
    path = snapshot / archive
    if not path.resolve().is_relative_to(snapshot.resolve()):
        raise BackupError(f"Refusing archive path {archive!r} from the manifest")
    digest = entry.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise BackupError(f"{archive}: the manifest records no checksum; nothing was changed.")
    return path, digest


class _HashingReader:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self.digest.update(data)
        return data

    def readline(self, size: int = -1) -> bytes:
        data = self._handle.readline(size)
        self.digest.update(data)
        return data


def verify_archives(
    snapshot: Path, manifest: dict, archives: list[str], identities: list[str]
) -> None:
    """Before a restore touches anything: every archive is there, unchanged (SHA-256 of
    the manifest) and opened by one of the keys."""
    for archive in archives:
        path, expected = _archive(snapshot, manifest, archive)
        try:
            with open(path, "rb") as handle:
                age.open_header(handle, identities)
                handle.seek(0)
                digest = hashlib.sha256()
                for block in iter(lambda: handle.read(SCAN_BLOCK), b""):
                    digest.update(block)
        except age.NoIdentityError:
            raise EncryptedRestorePointError(
                f"The key for restore point {manifest.get('id')} is missing: the key given "
                f"is not a recipient (recipients: {_recipient_names(manifest)}). Nothing was "
                "changed."
            ) from None
        except FileNotFoundError:
            raise BackupError(f"{archive}: missing in the restore point; nothing was changed.") \
                from None
        except (OSError, age.AgeError) as exc:
            raise BackupError(f"{archive}: {exc}; nothing was changed.") from None
        if digest.hexdigest() != expected:
            raise BackupError(
                f"{archive}: the checksum does not match the manifest, the file was changed;"
                " nothing was changed."
            )


def open_archive(
    snapshot: Path, manifest: dict, archive: str, identities: list[str], out: BinaryIO
) -> int:
    """Decrypt one archive to `out` (the tar.gz stream bash unpacks). Fails when the file
    differs from the manifest's checksum; the caller then discards what it unpacked."""
    path, expected = _archive(snapshot, manifest, archive)
    try:
        with open(path, "rb") as handle:
            reader = _HashingReader(handle)
            size = age.decrypt(reader, out, identities)
            while reader.read(SCAN_BLOCK):
                pass
    except age.NoIdentityError:
        raise EncryptedRestorePointError(
            f"The key for restore point {manifest.get('id')} is missing"
        ) from None
    except (OSError, age.AgeError) as exc:
        raise BackupError(f"{archive}: {exc}") from None
    if reader.digest.hexdigest() != expected:
        raise BackupError(f"{archive}: the checksum does not match the manifest")
    return size
