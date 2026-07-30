"""Backup/restore planning, catalogue keeping and retention.

Pure logic: works out *what* has to be archived and keeps the on-disk
catalogue in order. Every `docker` invocation stays in tools/lib/sh/backup.sh,
per the bash/Python split documented in cli.py.

Three things are archived:

  * `$PAPAIA_CONFIG_DIR` in full -- this also covers state that is not a named
    volume at all, most importantly the Nginx Proxy Manager database and the
    Let's Encrypt certificates, which are bind mounts underneath it.
  * every named volume of the core stack, resolved from the compose files and
    prefixed with the configured COMPOSE_PROJECT_NAME.
  * every named volume of an active add-on, plus the host directories it
    bind-mounts for user data.

An add-on that only talks to an *existing external* instance (connector style,
e.g. paperless-connect) declares no volumes and no data bind mounts of its own,
so iterating what an add-on declares excludes the external instance by
construction -- there is deliberately no "is this a connector?" predicate.

Timestamps: the restore-point id uses *local* time, because that is what an
operator reads off `ls` and correlates with an incident. `created_at` in the
catalogue is UTC so sorting and retention stay unambiguous across DST.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import common, compat, deployment

INDEX_NAME = "backup.yaml"
LOG_NAME = "backup.log"
MANIFEST_NAME = "manifest.yaml"
PLAN_NAME = "plan.yaml"
RESULTS_NAME = "results.tsv"

CONFIG_ARCHIVE = "papaia-config.tar.gz"

_ID_FORMAT = "%Y-%m-%d_%H-%M-%S"


class BackupError(Exception):
    """Raised for operator-facing failures; cli.py turns it into exit 3."""


# ─────────────────────────────────────────────────────────────────────────
# Plan model
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Artifact:
    kind: str  # "configdir" | "volume" | "binddir"
    archive: str  # path relative to the snapshot dir
    source: str  # docker volume name, or absolute host path
    owner: str  # "core" | "addon:<name>"
    project: str = ""  # compose project the source belongs to


@dataclass
class BackupPlan:
    snapshot: Path
    backup_id: str
    core_project: str
    config_dir: Path
    artifacts: list[Artifact] = field(default_factory=list)
    addons: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# Compose introspection
# ─────────────────────────────────────────────────────────────────────────


def _top_level_volumes(compose_path: Path) -> list[str]:
    if not compose_path.is_file():
        return []
    doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    return list((doc.get("volumes") or {}).keys())


def resolve_core_volumes(repo_root: Path) -> list[str]:
    """Every named volume key declared by the core stack, walking the root
    compose's `include:` list. Mirrors compat.resolve_core_services.

    Returns [] when src/docker-compose.yml is absent (synthetic contexts such
    as minimal test repos), so callers degrade to "nothing declared" instead
    of raising."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return []
    volumes: list[str] = []
    for compose_path in compat.compose_files(root_compose):
        for key in _top_level_volumes(compose_path):
            if key not in volumes:
                volumes.append(key)
    return volumes


_VAR_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


def expand(value: str, env: dict[str, str]) -> str:
    """Expand ${VAR}, ${VAR:-default} and $VAR against `env`, following
    Compose semantics: the `:-` default applies when the variable is unset
    *or* empty."""

    def _sub(match: re.Match[str]) -> str:
        if match.group(3):
            return env.get(match.group(3), "")
        name = match.group(1)
        current = env.get(name, "")
        if current:
            return current
        return match.group(2) or ""

    return _VAR_RE.sub(_sub, value)


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _split_mount(entry: str) -> tuple[str, str, str]:
    """Split a short-syntax bind entry into (source, target, mode).

    Must be called on an already-interpolated entry: `${VAR:-./data}` contains
    a colon of its own, so splitting before expansion mangles the source.
    Splitting on ":" also breaks on Windows sources like C:/data:/target, so a
    leading drive letter is consumed before the separator search."""
    rest = entry
    prefix = ""
    if _WINDOWS_DRIVE.match(entry):
        prefix, rest = entry[:2], entry[2:]
    parts = rest.split(":")
    source = prefix + parts[0]
    target = parts[1] if len(parts) > 1 else ""
    mode = parts[2] if len(parts) > 2 else ""
    return source, target, mode


def _is_host_path(source: str) -> bool:
    return (
        source.startswith(("/", "./", "../", "~"))
        or bool(_WINDOWS_DRIVE.match(source))
    )


def addon_bind_dirs(addon_path: Path, env: dict[str, str], config_dir: Path) -> list[Path]:
    """Host directories an add-on bind-mounts for its own user data.

    Excluded, in this order: read-only mounts (config handed *to* the add-on,
    never its data store), anything under $PAPAIA_CONFIG_DIR (already covered
    by the config archive), sockets, and paths that do not exist or are not
    directories."""
    compose_path = addon_path / "docker-compose.yml"
    if not compose_path.is_file():
        return []
    doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    resolved_config = config_dir.resolve()
    found: list[Path] = []
    for service in (doc.get("services") or {}).values():
        for entry in (service or {}).get("volumes") or []:
            if isinstance(entry, dict):
                if entry.get("type") not in (None, "bind"):
                    continue
                source = expand(str(entry.get("source") or ""), env)
                mode = "ro" if entry.get("read_only") else ""
            elif isinstance(entry, str):
                # Interpolate first: Compose does, and `${VAR:-./data/media}`
                # carries a colon that would otherwise split in the wrong place.
                source, _target, mode = _split_mount(expand(entry, env))
            else:
                continue
            if not source or "ro" in mode.split(","):
                continue
            if source.endswith(".sock") or not _is_host_path(source):
                continue
            path = Path(source)
            if not path.is_absolute():
                path = addon_path / path
            try:
                path = path.resolve()
            except OSError:
                continue
            if path == resolved_config or resolved_config in path.parents:
                continue
            if not path.is_dir():
                continue
            if path not in found:
                found.append(path)
    return found


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower() or "dir"


# ─────────────────────────────────────────────────────────────────────────
# Plan construction
# ─────────────────────────────────────────────────────────────────────────


def parse_existing_volumes(path: Path | None) -> list[tuple[str, str]]:
    """Read the `PROJECT<TAB>VOLUME` listing bash produces from a single
    `docker volume ls` call. A missing file means "docker could not be
    queried" -- planning then falls back to what the compose files declare."""
    if path is None or not path.is_file():
        return []
    rows: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        project, _, name = line.partition("\t")
        if name:
            rows.append((project.strip(), name.strip()))
    return rows


def _project_volumes(
    project: str, declared: list[str], existing: list[tuple[str, str]]
) -> tuple[list[str], list[str]]:
    """Resolve the volumes to archive for one compose project.

    Union of two sources, deliberately asymmetric:
      * volumes carrying this project's compose label -- catches volumes from a
        profile that has since been disabled, whose data still matters.
      * declared-and-existing names -- catches volumes created outside compose
        (restored by hand, pre-seeded) that carry no label.
    A declared volume that does not exist at all is reported as skipped rather
    than attempted, so an inactive profile does not fail the run."""
    declared_names = [f"{project}_{key}" for key in declared] if project else list(declared)
    if not existing:
        return declared_names, []
    all_names = {name for _proj, name in existing}
    labelled = [name for proj, name in existing if proj == project]
    selected = list(labelled)
    skipped: list[str] = []
    for name in declared_names:
        if name in selected:
            continue
        if name in all_names:
            selected.append(name)
        else:
            skipped.append(name)
    return sorted(selected), skipped


def build_plan(
    config_dir: Path,
    repo_root: Path,
    backup_dir: Path,
    *,
    existing: list[tuple[str, str]] | None = None,
    now: datetime | None = None,
) -> BackupPlan:
    existing = existing or []
    root_env = common.parse_env_file(config_dir / ".env")
    core_project = root_env.get("COMPOSE_PROJECT_NAME") or "papaia"

    stamp = (now or datetime.now()).strftime(_ID_FORMAT)
    plan = BackupPlan(
        snapshot=backup_dir / stamp,
        backup_id=stamp,
        core_project=core_project,
        config_dir=config_dir,
    )

    plan.artifacts.append(
        Artifact(
            kind="configdir",
            archive=CONFIG_ARCHIVE,
            source=str(config_dir),
            owner="core",
            project=core_project,
        )
    )

    core_names, core_skipped = _project_volumes(
        core_project, resolve_core_volumes(repo_root), existing
    )
    for name in core_names:
        plan.artifacts.append(
            Artifact(
                kind="volume",
                archive=f"volumes/{name}.tar.gz",
                source=name,
                owner="core",
                project=core_project,
            )
        )
    plan.skipped.extend(core_skipped)

    used_slugs: set[str] = set()
    for entry in deployment.active_addons(deployment.load(config_dir)):
        name = entry.get("name") or ""
        addon_path = deployment.resolve_addon_path(entry, repo_root)
        # The compose project of an add-on is the directory basename, not the
        # manifest name -- that is how sh/addon.sh brings it up, and volume
        # names are derived from the project.
        project = addon_path.name
        plan.addons.append(name)
        owner = f"addon:{name}"

        volume_names, skipped = _project_volumes(
            project, _top_level_volumes(addon_path / "docker-compose.yml"), existing
        )
        for volume in volume_names:
            plan.artifacts.append(
                Artifact(
                    kind="volume",
                    archive=f"volumes/{volume}.tar.gz",
                    source=volume,
                    owner=owner,
                    project=project,
                )
            )
        plan.skipped.extend(skipped)

        addon_env = dict(root_env)
        addon_env.update(common.parse_env_file(config_dir / "addons" / name / ".env"))
        addon_env.update(common.parse_env_file(addon_path / ".env"))
        for bind in addon_bind_dirs(addon_path, addon_env, config_dir):
            try:
                rel = bind.relative_to(addon_path).as_posix()
            except ValueError:
                rel = bind.as_posix()
            slug = f"{_slug(name)}--{_slug(rel)}"
            suffix = 2
            while slug in used_slugs:
                slug = f"{_slug(name)}--{_slug(rel)}-{suffix}"
                suffix += 1
            used_slugs.add(slug)
            plan.artifacts.append(
                Artifact(
                    kind="binddir",
                    archive=f"binds/{slug}.tar.gz",
                    source=str(bind),
                    owner=owner,
                    project=project,
                )
            )

    return plan


# ─────────────────────────────────────────────────────────────────────────
# Snapshot manifest
# ─────────────────────────────────────────────────────────────────────────


def write_plan(plan: BackupPlan) -> None:
    """Persist the plan inside the snapshot so `backup-finish` reports on the
    same run rather than recomputing one (which would mint a new id and could
    see a different add-on set if something changed mid-run)."""
    common.atomic_write(
        plan.snapshot / PLAN_NAME,
        yaml.safe_dump(
            {
                "id": plan.backup_id,
                "snapshot": str(plan.snapshot),
                "core_project": plan.core_project,
                "config_dir": str(plan.config_dir),
                "addons": plan.addons,
                "skipped": plan.skipped,
                "artifacts": [
                    {
                        "kind": a.kind,
                        "archive": a.archive,
                        "source": a.source,
                        "owner": a.owner,
                        "project": a.project,
                    }
                    for a in plan.artifacts
                ],
            },
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        ),
    )


def read_plan(snapshot: Path) -> BackupPlan:
    plan_path = snapshot / PLAN_NAME
    if not plan_path.is_file():
        raise BackupError(f"No {PLAN_NAME} in {snapshot} -- run 'papaia-ctl backup' instead.")
    try:
        data = yaml.safe_load(plan_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise BackupError(f"{plan_path} is not valid YAML: {exc}") from exc
    return BackupPlan(
        snapshot=Path(data.get("snapshot") or snapshot),
        backup_id=str(data.get("id") or snapshot.name),
        core_project=str(data.get("core_project") or ""),
        config_dir=Path(data.get("config_dir") or ""),
        artifacts=[
            Artifact(
                kind=str(a.get("kind", "")),
                archive=str(a.get("archive", "")),
                source=str(a.get("source", "")),
                owner=str(a.get("owner", "")),
                project=str(a.get("project", "")),
            )
            for a in (data.get("artifacts") or [])
        ],
        addons=list(data.get("addons") or []),
        skipped=list(data.get("skipped") or []),
    )


def read_results(snapshot: Path) -> dict[str, str]:
    """Per-artifact outcome bash accumulated during the run: ARCHIVE<TAB>STATUS."""
    results: dict[str, str] = {}
    results_path = snapshot / RESULTS_NAME
    if not results_path.is_file():
        return results
    for line in results_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        archive, _, status = line.partition("\t")
        if archive:
            results[archive.strip()] = status.strip() or "failed"
    return results


def write_manifest(
    snapshot: Path, plan: BackupPlan, results: dict[str, str], *, papaia_version: str
) -> dict:
    """Write the snapshot's self-describing manifest.

    Only artifacts that actually succeeded are listed: the manifest is what
    restore iterates, so a half-written archive must never be offered as
    restorable."""
    artifacts = [
        {
            "kind": a.kind,
            "archive": a.archive,
            "target": a.source,
            "owner": a.owner,
        }
        for a in plan.artifacts
        if results.get(a.archive, "failed") == "ok"
    ]
    manifest = {
        "version": 1,
        "id": plan.backup_id,
        "created_at": _utc_now(),
        "papaia_version": papaia_version,
        "core_project": plan.core_project,
        "config_dir": str(plan.config_dir),
        "addons": plan.addons,
        "artifacts": artifacts,
    }
    common.atomic_write(
        snapshot / MANIFEST_NAME,
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False, allow_unicode=True),
    )
    return manifest


def read_manifest(snapshot: Path) -> dict:
    manifest_path = snapshot / MANIFEST_NAME
    if not manifest_path.is_file():
        raise BackupError(f"No {MANIFEST_NAME} in {snapshot} -- not a usable restore point.")
    try:
        return yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise BackupError(f"{manifest_path} is not valid YAML: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────
# Catalogue
# ─────────────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def load_index(backup_dir: Path) -> dict:
    index_path = backup_dir / INDEX_NAME
    if not index_path.is_file():
        return {"version": 1, "backups": []}
    try:
        data = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise BackupError(f"{index_path} is not valid YAML: {exc}") from exc
    data.setdefault("version", 1)
    data.setdefault("backups", [])
    return data


def save_index(backup_dir: Path, index: dict) -> None:
    common.atomic_write(
        backup_dir / INDEX_NAME,
        yaml.safe_dump(index, sort_keys=False, default_flow_style=False, allow_unicode=True),
    )


def dir_size_mb(path: Path) -> float:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError:
                continue
    return round(total / (1024 * 1024), 1)


def record_backup(backup_dir: Path, plan: BackupPlan, manifest: dict, result: str) -> dict:
    """Append this run to backup.yaml, replacing any entry with the same id."""
    entry = {
        "id": plan.backup_id,
        "path": str(plan.snapshot),
        "created_at": manifest.get("created_at", _utc_now()),
        "papaia_version": manifest.get("papaia_version", ""),
        "project": plan.core_project,
        "size_mb": dir_size_mb(plan.snapshot),
        "result": result,
        "artifacts": len(manifest.get("artifacts") or []),
        "addons": plan.addons,
    }
    index = load_index(backup_dir)
    index["backups"] = [b for b in index["backups"] if b.get("id") != plan.backup_id]
    index["backups"].append(entry)
    index["backups"].sort(key=lambda b: str(b.get("created_at", "")))
    save_index(backup_dir, index)
    return entry


def prune(backup_dir: Path, retention_days: int, *, now: datetime | None = None) -> list[str]:
    """Delete restore points older than `retention_days` and drop their
    catalogue entries.

    Only directories recorded in backup.yaml *and* located inside backup_dir
    are removed -- anything an operator put in the backup location by hand is
    never touched, and a doctored `path` cannot escape the backup directory."""
    if retention_days < 0:
        raise BackupError("--retention-period-days must be 0 or greater.")
    index = load_index(backup_dir)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=retention_days)
    resolved_root = backup_dir.resolve()
    kept: list[dict] = []
    removed: list[str] = []
    for entry in index["backups"]:
        created = _parse_ts(str(entry.get("created_at", "")))
        if created is None or created >= cutoff:
            kept.append(entry)
            continue
        target = Path(str(entry.get("path") or ""))
        if target.is_dir():
            try:
                resolved = target.resolve()
            except OSError:
                resolved = target
            if resolved_root in resolved.parents:
                shutil.rmtree(resolved, ignore_errors=True)
        removed.append(str(entry.get("id", "")))
    if removed:
        index["backups"] = kept
        save_index(backup_dir, index)
    return removed


def resolve_restore_point(
    backup_dir: Path, restore_point: str | None = None
) -> tuple[dict, list[str]]:
    """Pick the restore point to restore from. Returns (entry, warnings).

    Without an explicit id the most recent usable backup wins; a `failed`
    entry is never selected implicitly, since restoring from one would replace
    live data with a knowingly incomplete snapshot."""
    index = load_index(backup_dir)
    backups = index.get("backups") or []
    if not backups:
        raise BackupError(
            f"No restore points found in {backup_dir}. Run 'papaia-ctl backup' first."
        )
    if restore_point:
        for entry in backups:
            if str(entry.get("id")) == restore_point:
                return entry, []
        available = ", ".join(str(b.get("id")) for b in backups)
        raise BackupError(f"Unknown restore point '{restore_point}'. Available: {available}")

    usable = [b for b in backups if b.get("result") != "failed"]
    if not usable:
        raise BackupError(
            "Every recorded backup failed. Pass --restore-point=ID to force one anyway."
        )
    entry = sorted(usable, key=lambda b: str(b.get("created_at", "")))[-1]
    warnings: list[str] = []
    if entry.get("result") == "partial":
        warnings.append(
            f"Restore point {entry.get('id')} is marked 'partial' -- some archives failed"
            " during that backup. Check backup.log before relying on it."
        )
    return entry, warnings
