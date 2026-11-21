"""`papaia-ctl halt`: the platform-wide emergency halt.

One host command stops every write, send and delete of the platform. It needs neither
Keycloak nor any other service: it writes the state file

    $PAPAIA_CONFIG_DIR/state/halt.json  =  {"active", "since", "reason", "by"}

and every service that acts mounts the folder `state/` read-only (docs/halt.md). Readers
check the file before each write, send, delete, model call, flow step and delivery (one
stat call, no network) and in addition every POLL_SECONDS, so the halt takes effect
within 10 s for writes, sends and deletes and within 60 s for everything else. The file
lives on the host, so it outlasts a restart of every container.

The folder is mounted, never the file itself: the file is replaced by a rename, and a
container that mounted the file would keep seeing the old one.

Setting the halt never waits for anything but the file: the audit row follows the write,
because the core's audit outbox may be locked by a running realm sync. Lifting it needs a
reason, and its audit row is secured before the file changes.

A reader treats a file it cannot read or that does not match the format as an active
halt (fails closed); a missing file is no halt.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import realm_sync as rs

STATE_DIR = "state"
STATE_FILE = "halt.json"
LOCK_FILE = ".halt.lock"
WRITER = "papaia-ctl/halt"
# Readers re-check at least this often, also without an effect to guard.
POLL_SECONDS = 5.0
MAX_REASON = 500
MAX_FILE_BYTES = 4096
_FIELDS = ("active", "since", "reason", "by")
_BY_MAX = 255


class HaltError(Exception):
    """An input the command refuses; nothing was changed."""


@dataclass(frozen=True)
class HaltState:
    active: bool
    since: int | None = None
    reason: str = ""
    by: str = ""
    # Why the file could not be used; such a state counts as active.
    problem: str | None = None


def state_dir(config_dir: Path) -> Path:
    return config_dir / STATE_DIR


def state_path(config_dir: Path) -> Path:
    return state_dir(config_dir) / STATE_FILE


def check_reason(raw: str | None, *, required: bool) -> str:
    """The reason as given, or a HaltError: printable text of at most MAX_REASON
    characters, never only whitespace when one is required."""
    reason = "" if raw is None else raw
    if not isinstance(reason, str):
        raise HaltError("the reason must be text")
    if len(reason) > MAX_REASON:
        raise HaltError(f"the reason is longer than {MAX_REASON} characters")
    if any(not ch.isprintable() for ch in reason):
        raise HaltError("the reason must not contain control characters or line breaks")
    if required and not reason.strip():
        raise HaltError("lifting the halt needs a reason (--reason)")
    return reason.strip()


def parse(data: bytes) -> HaltState:
    """The state in `data`; an unusable document is an active halt with `problem` set."""
    if len(data) > MAX_FILE_BYTES:
        return HaltState(True, problem="the halt file is larger than expected")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return HaltState(True, problem="the halt file is not JSON")
    if not isinstance(doc, dict) or set(doc) != set(_FIELDS):
        fields = ", ".join(_FIELDS)
        return HaltState(True, problem=f"the halt file does not have the fields {fields}")
    active, since, reason, by = (doc[k] for k in _FIELDS)
    if not isinstance(active, bool):
        return HaltState(True, problem="active is not true or false")
    if isinstance(since, bool) or not isinstance(since, int) or since < 0:
        return HaltState(True, problem="since is not a time in seconds")
    if not isinstance(reason, str) or len(reason) > MAX_REASON:
        return HaltState(True, problem="reason is not a text of at most 500 characters")
    if not isinstance(by, str) or not 0 < len(by) <= _BY_MAX:
        return HaltState(True, problem="by is not a name")
    return HaltState(active, since, reason, by)


def read(path: Path) -> HaltState:
    """The state at `path`. No file: no halt. A file that cannot be read: active."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if path.parent.is_dir():
            return HaltState(False)
        return HaltState(True, problem=f"the folder {path.parent} is missing")
    except OSError as exc:
        return HaltState(True, problem=f"the halt file cannot be read ({exc.strerror})")
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return HaltState(True, problem="the halt file is not a regular file")
        return parse(fh.read(MAX_FILE_BYTES + 1))


class HaltWatch:
    """The reader side, as every service holds it: `check()` before each effect costs one
    stat call and parses the file only when it changed; `poll()` from a timer every
    POLL_SECONDS covers the paths that have no effect to guard (a banner, a waiting run)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._key: tuple | None = None
        self._state = HaltState(False)

    def check(self) -> HaltState:
        try:
            st = os.stat(self.path, follow_symlinks=False)
            key: tuple | None = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        except FileNotFoundError:
            key = ("missing", self.path.parent.is_dir())
        except OSError:
            key = None  # unreadable: read() reports it, never cached
        if key is None or key != self._key:
            self._state = read(self.path)
            self._key = key
        return self._state

    poll = check

    def halted(self) -> bool:
        return self.check().active


def _write_atomic(folder: Path, doc: dict) -> None:
    data = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".halt.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchmod(fh.fileno(), 0o644)
            os.fsync(fh.fileno())
        os.replace(tmp, folder / STATE_FILE)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dir_fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def ensure_dir(config_dir: Path) -> Path:
    """`state/`, readable for the services that mount it (0755); `render` makes it before
    `up`, because Compose must not create it."""
    folder = state_dir(config_dir)
    folder.mkdir(mode=0o755, parents=True, exist_ok=True)
    st = os.lstat(folder)
    if not stat.S_ISDIR(st.st_mode):
        raise HaltError(f"{folder} is not a folder")
    if stat.S_IMODE(st.st_mode) != 0o755:
        os.chmod(folder, 0o755)
    return folder


@contextlib.contextmanager
def _locked(folder: Path):
    """Serialises two halt commands; held for the file change only, never while waiting
    for the audit outbox."""
    fd = os.open(folder / LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _change(operation: str, event: str) -> rs.Change:
    return rs.Change("platform-halt", "platform", operation, operation, event=event)


def _audit(config_dir: Path, correlation: str) -> rs.AuditLog:
    return rs.AuditLog(rs.audit_path(config_dir), correlation, writer=WRITER)


def set_halt(config_dir: Path, reason_raw: str | None, *, now=time.time) -> tuple[bool, HaltState]:
    """Activate the halt. Returns (changed, state); an active halt stays as it is."""
    reason = check_reason(reason_raw, required=False)
    folder = ensure_dir(config_dir)
    by = rs._host_account()
    with _locked(folder):
        current = read(folder / STATE_FILE)
        if current.active and current.problem is None:
            return False, current
        state = HaltState(True, int(now()), reason, by)
        _write_atomic(folder, {k: getattr(state, k) for k in _FIELDS})
    with _audit(config_dir, rs.new_correlation_id()) as audit:
        audit.write(_change("set", "emergency_stop_set"), "allowed", host=True)
    return True, state


def clear_halt(
    config_dir: Path, reason_raw: str | None, *, now=time.time
) -> tuple[bool, HaltState]:
    """Lift the halt; needs a reason. A refused attempt is an audit row too."""
    folder = ensure_dir(config_dir)
    with _audit(config_dir, rs.new_correlation_id()) as audit:
        try:
            reason = check_reason(reason_raw, required=True)
        except HaltError:
            audit.write(
                _change("clear", "emergency_stop_lifted"), "denied", "reason_required", host=True
            )
            raise
        with _locked(folder):
            current = read(folder / STATE_FILE)
            if not current.active:
                return False, current
            state = HaltState(False, int(now()), reason, rs._host_account())
            _write_atomic(folder, {k: getattr(state, k) for k in _FIELDS})
        audit.write(_change("clear", "emergency_stop_lifted"), "allowed", host=True)
    return True, state


def _describe(state: HaltState) -> dict:
    out: dict = {"active": state.active}
    if state.problem:
        out["problem"] = state.problem
    else:
        out.update(since=state.since, reason=state.reason, by=state.by)
    return out


def _since_text(state: HaltState) -> str:
    if state.since is None:
        return ""
    return time.strftime(" since %Y-%m-%d %H:%M:%S UTC", time.gmtime(state.since))


def main(config_dir: Path, action: str, reason: str | None, *, as_json: bool = False) -> int:
    """0: done or nothing to change, 1: the file or the audit row could not be written,
    2: refused input, nothing changed."""
    try:
        if action == "status":
            state = read(state_path(config_dir))
            if as_json:
                print(json.dumps(_describe(state), sort_keys=True))
            elif state.problem:
                print(f"Platform halt: ACTIVE (the file is unusable: {state.problem})")
            elif state.active:
                print(f"Platform halt: ACTIVE{_since_text(state)}, set by {state.by}")
            else:
                print("Platform halt: not active")
            return 0
        if action == "set":
            changed, state = set_halt(config_dir, reason)
            if changed:
                print(
                    "Platform halt set: writes, sends and deletes stop within 10 s, model "
                    "calls and everything else within 60 s. Lift it with "
                    "'papaia-ctl halt clear --reason=TEXT'."
                )
            else:
                print(f"Platform halt already active{_since_text(state)}; nothing changed.")
            return 0
        if action == "clear":
            changed, state = clear_halt(config_dir, reason)
            if changed:
                print(
                    "Platform halt lifted. Write steps are not repeated without a new "
                    "confirmation of the person."
                )
            else:
                print("Platform halt is not active; nothing changed.")
            return 0
    except HaltError as exc:
        print(f"Halt refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    except (rs.RealmSyncError, OSError) as exc:
        state = read(state_path(config_dir))
        where = "is active" if state.active else "is not active"
        print(f"Halt failed: {exc}. The platform halt {where}.", file=sys.stderr, flush=True)
        return 1
    print(f"Halt refused: unknown action {action!r}.", file=sys.stderr, flush=True)
    return 2
