"""The rollback key of an upgrade: the way back without the operator's backup key.

Stage 0 of `papaia-ctl upgrade` makes a one-off age key pair for the run. Restore point R0
is encrypted to the backup recipients and to this key, so `papaia-ctl rollback` can open
R0 without the operator's private key. The private key lives on this host only:

    $PAPAIA_CONFIG_DIR/state/rollback/<upgrade-id>.key   (folder 0700, file 0600)

`backup` leaves `state/` out of every archive and refuses an archive that holds an age
identity (lib/backup_crypt.py), so the key never reaches the backup target. It opens R0
only, that is data that lies on this host in clear anyway; the delegation and revocation
list keys are not in R0. Somebody holding only the backup target still cannot read R0.

The key is deleted
* with `papaia-ctl upgrade --finalize`,
* when the run ends without the upgrade (`rollback`, `upgrade --release-lock`),
* otherwise once its window has passed: PAPAIA_ROLLBACK_WINDOW_HOURS (default 72,
  24 to 168) after the upgrade finished. `backup`, `upgrade` and `rollback` remove keys
  past their window; `doctor rollback_window` reports the time left and fails for a key
  still there after its window.

Without a key (window over, `--no-rollback-key`, or no key could be made) the way back
needs the operator's key: `rollback --identity=FILE|-`, checked before any change.
"""

from __future__ import annotations

import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import age, backup_crypt, common, halt
from .backup import Recipient

KEY_DIR = "rollback"
KEY_SUFFIX = ".key"
WINDOW_VAR = "PAPAIA_ROLLBACK_WINDOW_HOURS"
DEFAULT_HOURS = 72
MIN_HOURS = 24
MAX_HOURS = 168
MAX_KEY_BYTES = 4096
# A key without a run that names it (stage 1 never began) is removed once it is older
# than the longest window.
ORPHAN_SECONDS = MAX_HOURS * 3600

_UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


class RollbackKeyError(Exception):
    """A refusal; the message is shown as it is."""


def _audit(config_dir: Path, event: str, detail: dict, effect: str = "write") -> None:
    """One `papaia.audit/1` row per write; ids and the public key only."""
    backup_crypt.audit(config_dir, "rollback-key", event, detail, effect=effect)


def check_id(value: object) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise RollbackKeyError("The upgrade id of a rollback key is a UUID")
    return value


def key_dir(config_dir: Path) -> Path:
    return halt.state_dir(config_dir) / KEY_DIR


def key_path(config_dir: Path, upgrade_id: str) -> Path:
    return key_dir(config_dir) / f"{check_id(upgrade_id)}{KEY_SUFFIX}"


def window_hours(config_dir: Path) -> int:
    """The window after a finished upgrade, in hours (PAPAIA_ROLLBACK_WINDOW_HOURS)."""
    raw = common.parse_env_file(config_dir / ".env").get(WINDOW_VAR, "").strip()
    if not raw:
        return DEFAULT_HOURS
    if not re.fullmatch(r"[0-9]{1,4}", raw) or not MIN_HOURS <= int(raw) <= MAX_HOURS:
        raise RollbackKeyError(
            f"{WINDOW_VAR} must be a whole number of hours from {MIN_HOURS} to {MAX_HOURS} "
            f"(got {raw[:20]!r})"
        )
    return int(raw)


def recipient_name(upgrade_id: str) -> str:
    """The name the rollback key carries among the recipients of R0."""
    return f"rollback-{check_id(upgrade_id)[:8]}"


def _own_dir(config_dir: Path) -> Path:
    halt.ensure_dir(config_dir)
    folder = key_dir(config_dir)
    folder.mkdir(mode=0o700, exist_ok=True)
    st = os.lstat(folder)
    if not stat.S_ISDIR(st.st_mode):
        raise RollbackKeyError(f"{folder} is not a folder")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(folder, 0o700)
    return folder


def create(config_dir: Path) -> tuple[str, str]:
    """A new key pair for one upgrade run: (upgrade id, public key). The private key is
    written once, 0600, and never shown."""
    upgrade_id = str(uuid.uuid4())
    secret, public = age.generate_identity()
    _own_dir(config_dir)
    path = key_path(config_dir, upgrade_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"# rollback key of upgrade {upgrade_id}\n{secret}\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)
    _audit(config_dir, "rollback_key_created", {"upgrade_id": upgrade_id, "key": public})
    return upgrade_id, public


def _read(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise RollbackKeyError(f"There is no rollback key {path.name}") from None
    except OSError as exc:
        raise RollbackKeyError(f"{path} cannot be read ({exc.strerror})") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RollbackKeyError(f"{path} is not a regular file")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise RollbackKeyError(f"{path} is readable by others than its owner; refused")
        raw = handle.read(MAX_KEY_BYTES + 1)
    if len(raw) > MAX_KEY_BYTES:
        raise RollbackKeyError(f"{path} is too large to be a key file")
    return raw


def identity(config_dir: Path, upgrade_id: str) -> str:
    """The private rollback key of a run, for the restore of R0 (kept in memory)."""
    raw = _read(key_path(config_dir, upgrade_id))
    try:
        found = age.parse_identity_file(raw.decode("utf-8"))
    except (UnicodeDecodeError, age.AgeError):
        found = []
    if len(found) != 1:
        raise RollbackKeyError(f"The rollback key of upgrade {upgrade_id} is not usable")
    return found[0]


def recipient(config_dir: Path, upgrade_id: str) -> Recipient:
    try:
        public = age.recipient_of(identity(config_dir, upgrade_id))
    except age.AgeError:
        raise RollbackKeyError(
            f"The rollback key of upgrade {upgrade_id} is not usable"
        ) from None
    return Recipient(recipient_name(upgrade_id), public)


def exists(config_dir: Path, upgrade_id: str) -> bool:
    return key_path(config_dir, upgrade_id).is_file()


def delete(config_dir: Path, upgrade_id: str, reason: str) -> bool:
    """Remove the key of a run; True when there was one. Audited."""
    path = key_path(config_dir, upgrade_id)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    _audit(config_dir, "rollback_key_deleted", {"upgrade_id": upgrade_id, "reason": reason},
           effect="delete")
    return True


def purge(config_dir: Path, reason: str) -> int:
    """Remove every file of the key folder, whatever its run (`recover-snapshot`: the keys
    came back with a VM snapshot, BE-16a Nr. 4). Each removal is audited; a symlink is
    removed, never followed. Returns how many were removed."""
    removed = 0
    for entry in list_keys(config_dir):
        try:
            entry.path.unlink()
        except FileNotFoundError:
            continue
        _audit(config_dir, "rollback_key_deleted",
               {"upgrade_id": entry.upgrade_id, "reason": reason}, effect="delete")
        removed += 1
    return removed


@dataclass(frozen=True)
class KeyFile:
    path: Path
    upgrade_id: str | None  # None for a file whose name is no upgrade id
    mtime: float
    mode: int


def list_keys(config_dir: Path) -> list[KeyFile]:
    folder = key_dir(config_dir)
    if not folder.is_dir():
        return []
    found = []
    for path in sorted(folder.iterdir()):
        st = os.lstat(path)
        name = path.name[: -len(KEY_SUFFIX)] if path.name.endswith(KEY_SUFFIX) else ""
        found.append(KeyFile(path, name if _UUID_RE.match(name) else None, st.st_mtime,
                             stat.S_IMODE(st.st_mode)))
    return found


@dataclass(frozen=True)
class KeyStatus:
    upgrade_id: str | None
    path: Path
    # running: the upgrade is not over; open: finished, inside the window; expired:
    # finished and past it; ended: the run ended without the upgrade; orphan: no run
    # names it; bad: not a key file of this folder.
    kind: str
    deadline: int | None


def deadline(state: dict, hours: int) -> int | None:
    """When the key of a finished run must be gone; None while the run is not over."""
    if state.get("finished") is None or state.get("abandoned") is not None:
        return None
    return int(state["finished"]) + hours * 3600


def classify(config_dir: Path, state: dict | None, hours: int,
             now: float | None = None) -> list[KeyStatus]:
    moment = time.time() if now is None else now
    result = []
    for key in list_keys(config_dir):
        if key.upgrade_id is None:
            result.append(KeyStatus(None, key.path, "bad", None))
            continue
        if state is None or state.get("id") != key.upgrade_id:
            kind = "orphan"
            result.append(KeyStatus(key.upgrade_id, key.path, kind,
                                    int(key.mtime + ORPHAN_SECONDS)))
            continue
        if state.get("abandoned") is not None:
            result.append(KeyStatus(key.upgrade_id, key.path, "ended", None))
            continue
        end = deadline(state, hours)
        if end is None:
            result.append(KeyStatus(key.upgrade_id, key.path, "running", None))
        else:
            result.append(KeyStatus(key.upgrade_id, key.path,
                                    "expired" if moment >= end else "open", end))
    return result


def sweep(config_dir: Path, state: dict | None, *, keep: str | None = None,
          now: float | None = None) -> list[str]:
    """Delete the keys whose time is over: past the window, of a run that ended without
    the upgrade, and keys no run names that are older than the longest window. `keep`
    names a key just made for a run that has not begun yet."""
    moment = time.time() if now is None else now
    hours = window_hours(config_dir)
    removed = []
    for entry in classify(config_dir, state, hours, moment):
        if entry.upgrade_id is None or entry.upgrade_id == keep:
            continue
        due = entry.kind in ("expired", "ended") or (
            entry.kind == "orphan" and entry.deadline is not None and moment >= entry.deadline
        )
        if due and delete(config_dir, entry.upgrade_id, f"{entry.kind}"):
            removed.append(entry.upgrade_id)
    return removed


def discard_unbegun(config_dir: Path, upgrade_id: str, state: dict | None) -> bool:
    """Remove a key made in stage 0 whose run never began (R0 failed or the run stopped);
    a key a run names is left alone."""
    if state is not None and state.get("id") == upgrade_id:
        return False
    return delete(config_dir, upgrade_id, "not used")
