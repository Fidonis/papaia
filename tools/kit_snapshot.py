"""Snapshots of the vendored papaia-kit release: write them or check them.

papaia-ctl runs on Python 3.10 and cannot import the kit (Python 3.12, a development
dependency only). It therefore reads copies of what it needs from the vendored release:

- `schemas/kit/*.schema.json`, the contract schemas the catalog and the add-on checks
  validate against, with `schemas/kit/snapshot.json` (release and sha256 of each file);
- `lib/names_register.json`, the naming register with the exchange scope of every
  audience as the kit builds it.

This tool writes those files from the installed kit, and only from it: the release named
in `kit.lock` must be the installed one. After vendoring a new release:

    cd tools && uv run --locked --extra dev python kit_snapshot.py write

`check` (the tests run it) exits 1 and names every file that differs from what the
installed kit builds; 2 means the tool could not run (wrong kit, unreadable lock).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
PACKAGE = "papaia-kit"
SCHEMAS = (
    "exposes.v1.schema.json",
    "platform-groups.v1.schema.json",
    "platform-services.v1.schema.json",
)
SCHEMA_DIR = "schemas/kit"
SCHEMA_SNAPSHOT = f"{SCHEMA_DIR}/snapshot.json"
REGISTER = "lib/names_register.json"
OUTPUTS = (*(f"{SCHEMA_DIR}/{name}" for name in SCHEMAS), SCHEMA_SNAPSHOT, REGISTER)

_VERSION_RE = re.compile(r"\A\d{1,6}\.\d{1,6}\.\d{1,6}\Z")
_COMMIT_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_MAX_LOCK_BYTES = 64 * 1024


class SnapshotError(RuntimeError):
    """The snapshots cannot be built: no kit, another kit or an unusable lock."""


def _release(root: Path) -> dict[str, str]:
    """Package, version and commit of the release named in `<root>/kit.lock`."""
    import tomllib

    path = root / "kit.lock"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc.strerror}") from None
    if len(raw) > _MAX_LOCK_BYTES:
        raise SnapshotError(f"{path} is larger than {_MAX_LOCK_BYTES} bytes")
    try:
        lock = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SnapshotError(f"{path} is not valid TOML: {exc}") from None
    version, commit = lock.get("version"), lock.get("commit")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise SnapshotError(f"{path}: version must be X.Y.Z")
    if not isinstance(commit, str) or not _COMMIT_RE.match(commit):
        raise SnapshotError(f"{path}: commit must be 40 hex digits")
    return {"package": PACKAGE, "version": version, "commit": commit}


def _kit(version: str) -> Any:
    """The installed kit package, refused unless it is the locked release."""
    try:
        import papaia_kit
    except ImportError:
        raise SnapshotError(
            "papaia-kit is not installed: uv sync --locked --extra dev (Python 3.12)"
        ) from None
    if papaia_kit.__version__ != version:
        raise SnapshotError(
            f"installed papaia-kit {papaia_kit.__version__} is not the locked release {version}"
        )
    return papaia_kit


def _json_line(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def _register_text(release: dict[str, str], names: Any) -> str:
    """The register in the layout of `lib/names_register.json`: one object per line."""
    entries = []
    for entry in names.REGISTER:
        row: dict[str, object] = {
            "name": entry.name, "kind": entry.kind.value, "owner": entry.owner,
        }  # fmt: skip
        if entry.token_exchange:
            row["token_exchange"] = True
        if entry.test_profile_only:
            row["test_profile_only"] = True
        entries.append(row)
    builtin = [{"name": e.name, "kind": e.kind.value} for e in names.BUILTIN]
    removed = []
    for gone in names.REMOVED:
        row = {"name": gone.name, "successor": gone.successor}
        if gone.until_stage is not None:
            row["until_stage"] = gone.until_stage
        if gone.kinds is not None:
            row["kinds"] = sorted(kind.value for kind in gone.kinds)
        removed.append(row)
    audiences = [e.name for e in names.REGISTER if e.kind.value == "audience"]
    scopes = [{"audience": a, "scope": names.exchange_scope(a)} for a in audiences]
    prefixes = {row["scope"][: -len(row["audience"])] for row in scopes}
    if len(prefixes) != 1 or not all(r["scope"].endswith(r["audience"]) for r in scopes):
        raise SnapshotError("the kit builds exchange scopes without one common prefix")

    def block(rows: list[dict[str, object]], indent: str) -> str:
        return ",\n".join(indent + _json_line(row) for row in rows)

    return (
        "{\n"
        '  "format": "papaia.names-register-snapshot/1",\n'
        f'  "source": {_json_line(release)},\n'
        f'  "entries": [\n{block(entries, "    ")}\n  ],\n'
        f'  "builtin": [\n{block(builtin, "    ")}\n  ],\n'
        f'  "removed": [\n{block(removed, "    ")}\n  ],\n'
        '  "exchange_scopes": {\n'
        f'    "kit": {_json_line(release["version"])},\n'
        f'    "prefix": {_json_line(prefixes.pop())},\n'
        f'    "scopes": [\n{block(scopes, "      ")}\n    ]\n'
        "  }\n"
        "}\n"
    )


def build(root: Path = TOOLS) -> dict[str, bytes]:
    """Every snapshot file (path relative to `root`) as the installed kit builds it."""
    release = _release(root)
    kit = _kit(release["version"])
    from importlib import resources

    schemas = resources.files(kit) / "_data" / "schemas"
    files: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    for name in SCHEMAS:
        data = (schemas / name).read_bytes()
        files[f"{SCHEMA_DIR}/{name}"] = data
        digests[name] = hashlib.sha256(data).hexdigest()
    snapshot = {"format": "papaia.kit-schema-snapshot/1", "source": release, "files": digests}
    files[SCHEMA_SNAPSHOT] = (json.dumps(snapshot, indent=2) + "\n").encode("utf-8")
    from papaia_kit import names

    files[REGISTER] = _register_text(release, names).encode("utf-8")
    return files


def stale(root: Path = TOOLS) -> list[str]:
    """The snapshot files under `root` that differ from what the installed kit builds."""
    differing = []
    for rel, data in build(root).items():
        path = root / rel
        if not path.is_file() or path.read_bytes() != data:
            differing.append(rel)
    return differing


def write(root: Path = TOOLS) -> list[str]:
    """Write every snapshot file under `root`; return the ones that changed."""
    changed = []
    for rel, data in build(root).items():
        path = root / rel
        if path.is_file() and path.read_bytes() == data:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        changed.append(rel)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kit_snapshot.py", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "write"))
    parser.add_argument("--root", type=Path, default=TOOLS, help="tools directory holding kit.lock")
    args = parser.parse_args(argv)
    root: Path = args.root
    if not root.is_dir():
        print(f"kit_snapshot: {root} is not a directory", file=sys.stderr)
        return 2
    try:
        if args.command == "write":
            for rel in write(root):
                print(f"wrote {rel}")
            return 0
        differing = stale(root)
    except SnapshotError as exc:
        print(f"kit_snapshot: {exc}", file=sys.stderr)
        return 2
    for rel in differing:
        print(f"kit_snapshot: {rel} differs from the vendored kit", file=sys.stderr)
    if differing:
        print("refresh with: uv run --locked --extra dev python kit_snapshot.py write",
              file=sys.stderr)  # fmt: skip
        return 1
    print(f"kit snapshots match papaia-kit {_release(root)['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
