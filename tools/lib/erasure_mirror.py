"""The mirror of the erasure journal and the offsite retention (sicherheit §4.9 "Kopien außer
Haus", betrieb BE-16, RE-86).

A copy of the backup target kept outside the house (3-2-1) carries an erasure journal that
ends on the day of the copy. Restored from it, every deletion after that day would come
back. The journal is therefore kept in a second place the operator names:

    PAPAIA_ERASURE_MIRROR_DIR       folder holding the mirrored `<module>.jsonl` files
                                    (a mounted share outside the house; empty: no mirror)
    PAPAIA_OFFSITE_RETENTION_DAYS   the longest time a copy is kept outside the house
                                    (default 90, 0 to 3650)

`papaia-ctl backup mirror` sets both in the root `.env`. What this module does with them:

* `sync_to_mirror` after every backup: the entries of the target the mirror lacks are
  appended to it. The mirror is never rewritten for that, so an append-only store works.
  Entries only the mirror holds stay there (the target may be an older copy).
* `union_into_target` in `restore` and `recover-snapshot`, before any module applies its
  journal: the entries only the mirror holds go to the target, so the modules' replay sees
  the union. An entry the target holds under the same id is not taken again; one whose
  `seq` the target gave to another entry gets the next free `seq` and keeps the first one
  as `provisional_seq` (the kit's renumbering, so a replay rewinds behind it). Entries
  older than the cutoff a retention run recorded at the target (`.<module>.retained`)
  stay out; a recorded cutoff later than 30 days ago never comes from a real run and is
  ignored. One entry id with two contents stops the union: nothing is written.
* `retain_mirror` after every backup: the mirror keeps every entry younger than the
  oldest restore point minus 30 days and younger than the offsite retention plus 30 days
  (the kit's rule; the offsite rule never shortens the other one). Only a prefix by `seq`
  goes and the newest entry stays, so the mirror never has a gap a replay would refuse.

The journal's own writers (the modules through the kit, papaia-lifecycle for the core
sources) write the target; the retention of the target is theirs. The reader is the kit's
strict one: a missing folder is never an empty journal, a malformed line stops the step.

`confirm_generation` records the generation of `epoch` at the target that the last
`recover-snapshot` (or `restore`) confirmed, in `state/state-epoch.json` (not backed up,
so a restore never brings an older one back while a VM snapshot does). `doctor
state_epoch` warns while the start gate has raised the generation beyond it.

Every write is one `papaia.audit/1` row with counts only, never journal content.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from papaia_kit.erasure import (
    JournalEntry,
    JournalError,
    JournalUnavailableError,
    read_epoch,
    read_journal,
)
from papaia_kit.erasure._retention import (
    check_offsite_days,
    parse_floor,
    removable_through,
    retention_cutoff,
)

from . import common, images

MIRROR_VAR = "PAPAIA_ERASURE_MIRROR_DIR"
OFFSITE_VAR = "PAPAIA_OFFSITE_RETENTION_DAYS"
OFFSITE_DEFAULT = 90
JOURNAL_FOLDER = "erasure-journal"
CONFIRMED_FILE = Path("state") / "state-epoch.json"
CONFIRMED_FORMAT = "papaia.state-epoch-confirmed/1"
# Older than this a recorded retention cutoff cannot be: a run keeps 30 days at least.
FLOOR_MARGIN = timedelta(days=30)
MAX_PATH = 1024
MAX_JOURNAL_FILES = 256
# betrieb BE-16, word for word: the operator text when no mirror is set.
HANDBOOK_SENTENCE = (
    "Wird von einer Kopie außer Haus wiederhergestellt, kehren Löschungen nach dem Tag "
    "dieser Kopie zurück. Führen Sie danach für jede Person aus der Liste der "
    "Löschnachweise seit diesem Tag `person erase` erneut aus."
)

_MODULE_FILE_RE = re.compile(r"\A([a-z][a-z0-9-]{0,39})\.jsonl\Z")
_DAYS_RE = re.compile(r"\A(0|[1-9][0-9]{0,3})\Z")
_BY = ("recover-snapshot", "restore")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class MirrorError(Exception):
    """A setting, a place or a journal the step cannot act on safely."""


@dataclass(frozen=True)
class Settings:
    mirror: Path | None
    offsite_days: int


# ── settings ────────────────────────────────────────────────────────────────


def _backup_dir(config_dir: Path) -> str:
    return common.parse_env_file(Path(config_dir) / ".env").get("PAPAIA_BACKUP_DIR", "")


def check_mirror(value: str, backup_dir: str = "") -> Path | None:
    """The mirror folder: an absolute, normalised path of one line, outside the backup
    target. Empty or `none` is no mirror. A URL is refused: mount the place first."""
    if value in ("", "none"):
        return None
    if (
        len(value) > MAX_PATH
        or not value.isprintable()
        or not value.startswith("/")
        or "://" in value
        or os.path.normpath(value) != value
    ):
        raise MirrorError(
            f"{MIRROR_VAR} must be an absolute path of at most {MAX_PATH} characters without "
            "'..' (a share outside the house, mounted on this host), or none"
        )
    if backup_dir:
        target = os.path.normpath(backup_dir)
        if value == target or value.startswith(target.rstrip("/") + "/"):
            raise MirrorError(
                f"{MIRROR_VAR} must be a second place, not the backup target or a folder in it"
            )
    return Path(value)


def check_offsite(value: object) -> int:
    if isinstance(value, str):
        if not _DAYS_RE.match(value):
            raise MirrorError(f"{OFFSITE_VAR} must be a whole number of days from 0 to 3650")
        value = int(value)
    try:
        return check_offsite_days(value)
    except ValueError:
        raise MirrorError(f"{OFFSITE_VAR} must be a whole number of days from 0 to 3650") from None


def load_settings(config_dir: Path) -> Settings:
    env = common.parse_env_file(Path(config_dir) / ".env")
    days = env.get(OFFSITE_VAR, "")
    return Settings(
        mirror=check_mirror(env.get(MIRROR_VAR, ""), env.get("PAPAIA_BACKUP_DIR", "")),
        offsite_days=OFFSITE_DEFAULT if days == "" else check_offsite(days),
    )


def configure(config_dir: Path, *, mirror: str | None, offsite: str | None) -> Settings:
    """Set the mirror (`none` removes it) and/or the offsite retention; both are checked
    before anything is written. Audited as `config_changed`."""
    config_dir = Path(config_dir)
    current = load_settings(config_dir)
    new_mirror = current.mirror if mirror is None else check_mirror(mirror,
                                                                     _backup_dir(config_dir))
    new_days = current.offsite_days if offsite is None else check_offsite(offsite)
    common.write_env_file(config_dir / ".env", {
        MIRROR_VAR: "" if new_mirror is None else str(new_mirror),
        OFFSITE_VAR: str(new_days),
    })
    _audit(config_dir, "erasure_mirror", "config_changed", "write",
           {"mirror": new_mirror is not None, "offsite_retention_days": new_days})
    return Settings(new_mirror, new_days)


# ── reading and writing a place ─────────────────────────────────────────────


def _require_dir(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise MirrorError(
            f"the {label} {path} is not reachable (not mounted?); it is never created here"
        )
    return path


def _modules(*folders: Path) -> list[str]:
    names: set[str] = set()
    for folder in folders:
        for path in folder.iterdir():
            match = _MODULE_FILE_RE.match(path.name)
            if match:
                names.add(match.group(1))
    if len(names) > MAX_JOURNAL_FILES:
        raise MirrorError(f"more than {MAX_JOURNAL_FILES} journals: not an erasure journal folder")
    return sorted(names)


def _read(module: str, folder: Path, label: str) -> list[JournalEntry]:
    path = folder / f"{module}.jsonl"
    if path.is_symlink():
        raise MirrorError(f"{label}: {path.name} is a symbolic link")
    try:
        return read_journal(module, [folder])
    except JournalError as exc:
        raise MirrorError(f"{label}: {module}: {exc}") from None


def _union(primary: list[JournalEntry], secondary: Iterable[JournalEntry],
           module: str) -> list[JournalEntry]:
    """The entries of `secondary` that `primary` lacks, with a free `seq` each."""
    by_id = {e.id: e for e in primary}
    used = {e.seq for e in primary}
    top = max(used, default=0)
    added: list[JournalEntry] = []
    for entry in sorted(secondary, key=lambda e: e.seq):
        known = by_id.get(entry.id)
        if known is not None:
            if not known.same_entry(entry):
                raise MirrorError(f"{module}: one entry with two different contents; "
                                  "nothing was written")
            continue
        if entry.seq in used:
            top += 1
            entry = dataclasses.replace(entry, seq=top, provisional_seq=entry.seq)
        used.add(entry.seq)
        top = max(top, entry.seq)
        by_id[entry.id] = entry
        added.append(entry)
    return added


def _append(path: Path, entries: list[JournalEntry]) -> None:
    payload = "".join(e.to_line() for e in entries).encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW, 0o640)
    try:
        if os.fstat(fd).st_size:
            # A torn last line (a writer died mid-line) must not swallow the first new one.
            with open(path, "rb") as fh:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    payload = b"\n" + payload
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace(path: Path, entries: list[JournalEntry]) -> None:
    data = "".join(e.to_line() for e in sorted(entries, key=lambda e: e.seq)).encode("ascii")
    tmp = path.with_name(path.name + ".mirror.tmp")
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o640)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _store(path: Path, present: list[JournalEntry], added: list[JournalEntry]) -> None:
    """Append when every new entry lies behind the place's last seq, else rewrite."""
    top = max((e.seq for e in present), default=0)
    if all(e.seq > top for e in added):
        _append(path, added)
    else:
        _replace(path, present + added)


def _floor(target: Path, module: str, now: datetime) -> str | None:
    path = target / f".{module}.retained"
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        value = parse_floor(fh.read(64))
    if value is None:
        return None
    latest = (now - FLOOR_MARGIN).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return value if value <= latest else None


# ── the three steps ─────────────────────────────────────────────────────────


def union_into_target(config_dir: Path, target_dir: Path, mirror_dir: Path, *,
                      now: datetime | None = None) -> dict[str, int]:
    """Bring the entries only the mirror holds to the target; {module: added}."""
    target = _require_dir(Path(target_dir), "journal folder at the backup target")
    mirror = _require_dir(Path(mirror_dir), "erasure journal mirror")
    now = now or datetime.now(timezone.utc)
    plan: list[tuple[str, list[JournalEntry], list[JournalEntry]]] = []
    for module in _modules(target, mirror):
        present = _read(module, target, "backup target")
        floor = _floor(target, module, now)
        candidates = [e for e in _read(module, mirror, "mirror")
                      if floor is None or e.at >= floor]
        added = _union(present, candidates, module)
        if added:
            plan.append((module, present, added))
    # Every journal is read and checked before the first write.
    try:
        for module, present, added in plan:
            _store(target / f"{module}.jsonl", present, added)
    except OSError as exc:
        _audit(config_dir, "erasure_mirror_union", "erasure_journal_flushed", "write",
               {"added": 0, "modules": 0}, error="journal_unavailable")
        raise MirrorError(f"the backup target cannot be written: {exc.strerror}") from None
    result = {module: len(added) for module, _present, added in plan}
    if result:
        _audit(config_dir, "erasure_mirror_union", "erasure_journal_flushed", "write",
               {"added": sum(result.values()), "modules": len(result)})
    return result


def sync_to_mirror(config_dir: Path, target_dir: Path, mirror_dir: Path) -> dict[str, int]:
    """Append to the mirror what the target holds and the mirror lacks; {module: added}."""
    target = _require_dir(Path(target_dir), "journal folder at the backup target")
    mirror = _require_dir(Path(mirror_dir), "erasure journal mirror")
    result: dict[str, int] = {}
    for module in _modules(target):
        at_mirror = _read(module, mirror, "mirror")
        missing = _union(at_mirror, _read(module, target, "backup target"), module)
        if not missing:
            continue
        try:
            _store(mirror / f"{module}.jsonl", at_mirror, missing)
        except OSError as exc:
            _audit(config_dir, "erasure_mirror_sync", "erasure_journal_flushed", "write",
                   {"added": sum(result.values()), "modules": len(result)},
                   error="journal_unavailable")
            raise MirrorError(f"the mirror cannot be written: {exc.strerror}") from None
        result[module] = len(missing)
    if result:
        _audit(config_dir, "erasure_mirror_sync", "erasure_journal_flushed", "write",
               {"added": sum(result.values()), "modules": len(result)})
    return result


def retain_mirror(config_dir: Path, mirror_dir: Path, *, oldest_point: datetime | None,
                  offsite_days: int, now: datetime | None = None) -> dict[str, int]:
    """The retention run of the mirror; {module: removed}. Without a restore point
    nothing goes (the kit's rule: the point is what an old state can come back from)."""
    mirror = _require_dir(Path(mirror_dir), "erasure journal mirror")
    days = check_offsite(offsite_days)
    if oldest_point is None:
        return {}
    now = now or datetime.now(timezone.utc)
    cutoff = retention_cutoff(now, min(oldest_point, now), days)
    result: dict[str, int] = {}
    for module in _modules(mirror):
        entries = _read(module, mirror, "mirror")
        through = removable_through(entries, cutoff)
        if not through:
            continue
        try:
            _replace(mirror / f"{module}.jsonl", [e for e in entries if e.seq > through])
        except OSError as exc:
            raise MirrorError(
                f"the mirror cannot be rewritten for the retention run ({exc.strerror}); an "
                "append-only store keeps its entries"
            ) from None
        result[module] = sum(1 for e in entries if e.seq <= through)
    if result:
        _audit(config_dir, "erasure_mirror_retention", "retention_run", "delete",
               {"removed": sum(result.values()), "modules": len(result), "cutoff": cutoff,
                "offsite_retention_days": days})
    return result


# ── the generation recover-snapshot confirmed ───────────────────────────────


def confirm_generation(config_dir: Path, target_dir: Path, *, by: str) -> int | None:
    """Record the generation of `epoch` at the target; None (nothing written) when the
    target has no journal folder or no epoch yet."""
    if by not in _BY:
        raise MirrorError("confirmed by recover-snapshot or restore only")
    if not Path(target_dir).exists():
        # No journal on this installation (the lifecycle profile never ran): nothing to
        # confirm. An unmounted target shows in `doctor state_epoch` itself.
        return None
    try:
        epoch = read_epoch(Path(target_dir))
    except JournalUnavailableError as exc:
        raise MirrorError(f"the backup target is not reachable: {exc}") from None
    except JournalError as exc:
        raise MirrorError(f"epoch at the backup target: {exc}") from None
    if epoch is None:
        return None
    common.atomic_write_private(Path(config_dir) / CONFIRMED_FILE, json.dumps({
        "format": CONFIRMED_FORMAT, "generation": epoch.generation, "by": by,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, sort_keys=True) + "\n")
    return epoch.generation


def confirmed_generation(config_dir: Path) -> int | None:
    path = Path(config_dir) / CONFIRMED_FILE
    try:
        if path.is_symlink():
            return None
        with open(path, encoding="utf-8") as handle:
            doc = json.loads(handle.read(4096))
    except (OSError, ValueError):
        return None
    value = doc.get("generation") if isinstance(doc, dict) else None
    if doc.get("format") != CONFIRMED_FORMAT or type(value) is not int or value < 0:
        return None
    return value


# ── audit ───────────────────────────────────────────────────────────────────


def _audit(config_dir: Path, operation: str, event: str, effect: str, detail: dict,
           *, error: str | None = None) -> None:
    now = time.time()
    images.append_audit(Path(config_dir), {
        "format": "papaia.audit/1",
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int(now % 1 * 1000):03d}Z",
        "correlation_id": images.correlation_id(os.environ.get("PAPAIA_CORRELATION_ID") or None),
        "writer": "papaia-ctl",
        "role": "operator",
        "sub": None,
        "identity_kind": "host",
        "azp": None,
        "catalog_id": None,
        "operation": operation,
        "effect": effect,
        "result": "error" if error else "allowed",
        "error_code": error,
        "event": event,
        "detail": {**detail, "confirmed_by": images.confirming_user()},
    })
