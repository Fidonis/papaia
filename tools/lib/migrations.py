"""Release migrations: discovery, selection, and the applied-ledger.

Migrations live in `tools/migrations/` of the core repo, so every release
carries the full set up to its own version. That is what makes a jump work:
after checking out `v1.5.0` the tree still holds the 1.1.0 … 1.4.0 scripts,
and `pending()` returns all of them in order. A migration directory that only
ever held "the next step" could not do this.

The ledger in `$PAPAIA_CONFIG_DIR/migrations/applied.json` is what makes the
run idempotent and resumable: an upgrade aborted by a failing migration can be
re-run once the cause is fixed, and the ones that already succeeded are not
replayed. A fresh install never has a ledger and never needs one -- its bundle
is seeded in the shape of the version it was installed at, so the migrations
up to that version are correctly skipped by the `from < version` bound.

The contract migration authors program against is documented in
tools/migrations/README.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path

from . import common, semver

MIGRATIONS_SUBPATH = "tools/migrations"
STATE_SUBPATH = "migrations/applied.json"

# <x.y.z>__<slug>.(sh|py) -- the double underscore keeps the version parseable
# without a delimiter that also occurs inside a SemVer pre-release.
_FILENAME_PATTERN = "<x.y.z>__<slug>.sh|.py"
_SUFFIXES = (".sh", ".py")


@dataclass(frozen=True)
class Migration:
    id: str  # file name without suffix, e.g. "1.1.0__npm-binds-to-config-dir"
    version: str
    slug: str
    kind: str  # "sh" or "py"
    path: Path


def migrations_dir(repo_root: Path) -> Path:
    return repo_root / "tools" / "migrations"


def _parse_name(path: Path) -> Migration:
    stem, _, suffix = path.name.rpartition(".")
    version, sep, slug = stem.partition("__")
    if not sep or not slug:
        raise ValueError(
            f"Malformed migration file name: {path.name}"
            f" (expected {_FILENAME_PATTERN})"
        )
    try:
        semver.parse_version(version)
    except ValueError as exc:
        raise ValueError(
            f"Malformed migration file name: {path.name}"
            f" ({exc}; expected {_FILENAME_PATTERN})"
        ) from exc
    return Migration(id=stem, version=version, slug=slug, kind=suffix, path=path)


def _sort_key(migration: Migration):
    return (
        cmp_to_key(semver.compare)(migration.version),
        migration.slug,
    )


def discover(repo_root: Path) -> list[Migration]:
    """Every migration shipped by this checkout, in execution order.

    Only `.sh` and `.py` files directly in the directory are considered, so the
    README and any future subdirectory (e.g. a post-start phase) are ignored.
    A script whose *name* does not parse raises: a migration that silently never
    runs because of a typo is the one failure mode this must not have."""
    directory = migrations_dir(repo_root)
    if not directory.is_dir():
        return []
    found = [
        _parse_name(path)
        for path in sorted(directory.iterdir())
        if path.is_file() and path.suffix in _SUFFIXES
    ]
    return sorted(found, key=_sort_key)


def pending(
    migrations: list[Migration],
    from_version: str,
    to_version: str,
    applied: set[str] | None = None,
) -> list[Migration]:
    """The migrations to run for `from_version` -> `to_version`, in order.

    Half-open on the left: the version already installed brought its own
    migrations with it, so only what lies *above* it and up to (including) the
    target is due."""
    already = applied or set()
    return [
        migration
        for migration in migrations
        if migration.id not in already
        and semver.compare(migration.version, from_version) > 0
        and semver.compare(migration.version, to_version) <= 0
    ]


# ─────────────────────────────────────────────────────────────────────────
# Ledger
# ─────────────────────────────────────────────────────────────────────────


def state_path(config_dir: Path) -> Path:
    return config_dir / "migrations" / "applied.json"


def load_state(config_dir: Path) -> dict:
    """The applied-ledger, or an empty one when nothing ran yet.

    A corrupt ledger is not silently reset: replaying migrations that already
    ran is exactly what the file exists to prevent, so the caller must see the
    error and decide."""
    path = state_path(config_dir)
    if not path.is_file():
        return {"applied": []}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Migration ledger is not valid JSON: {path} ({exc})") from exc
    if not isinstance(state, dict) or not isinstance(state.get("applied"), list):
        raise ValueError(f"Migration ledger has an unexpected shape: {path}")
    return state


def applied_ids(state: dict) -> set[str]:
    return {
        str(entry.get("id"))
        for entry in state.get("applied") or []
        if isinstance(entry, dict) and entry.get("id")
    }


def record(config_dir: Path, migration: Migration, *, duration_s: int = 0) -> None:
    """Append one successful migration to the ledger.

    Written after every single migration rather than once at the end, so an
    upgrade interrupted half-way (failure, Ctrl-C, power loss) still knows
    exactly which scripts already ran."""
    state = load_state(config_dir)
    entries = [
        entry
        for entry in state.get("applied") or []
        if not (isinstance(entry, dict) and entry.get("id") == migration.id)
    ]
    entries.append(
        {
            "id": migration.id,
            "version": migration.version,
            "applied_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "duration_s": duration_s,
        }
    )
    state["applied"] = entries
    common.ensure_dir(state_path(config_dir).parent)
    common.atomic_write(state_path(config_dir), json.dumps(state, indent=2) + "\n")
