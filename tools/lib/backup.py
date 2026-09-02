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
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

import yaml

from . import common, compat, deployment

INDEX_NAME = "backup.yaml"
LOG_NAME = "backup.log"
MANIFEST_NAME = "manifest.yaml"
PLAN_NAME = "plan.yaml"
RESULTS_NAME = "results.tsv"

CONFIG_ARCHIVE = "papaia-config.tar.gz"

# v2 added the per-artifact grouping fields a partial restore selects on.
# v1 snapshots stay readable and restorable, but only as a whole.
MANIFEST_VERSION = 2

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
    # Grouping, for a restore that touches only part of the snapshot. `module`
    # is the unit an operator picks; `profiles` is the only thing the scoped
    # teardown can act on. Empty on a configdir artifact, which is never
    # selectable on its own.
    module: str = ""
    services: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)


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


# The module label is namespaced by product; the prefix carries no information
# once volumes are grouped by it, so selectors read `module:librechat`.
_MODULE_PREFIX = "papaia-"


@dataclass(frozen=True)
class VolumeOwner:
    """Who mounts one core volume: the services, their `de.fidonis.module`
    labels, and the union of their compose profiles."""

    services: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()


def module_name(label: str) -> str:
    """The `de.fidonis.module` label as a selector name."""
    return label[len(_MODULE_PREFIX):] if label.startswith(_MODULE_PREFIX) else label


def _service_labels(body: dict) -> dict[str, str]:
    """Container labels, from either Compose spelling. The papAIa fragments use
    the mapping form; `- key=value` is equally valid Compose."""
    raw = (body or {}).get("labels")
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    if isinstance(raw, list):
        pairs = (str(item).partition("=") for item in raw)
        return {key.strip(): value.strip() for key, _, value in pairs if key.strip()}
    return {}


def _mounted_volume_keys(body: dict, declared: set[str]) -> list[str]:
    """The named volumes one service mounts, in both mount notations.

    A source counts only when it is a declared top-level key. That is what
    separates a named volume from a bind mount here, and it is the same test
    `addon_bind_dirs` makes from the other side."""
    keys: list[str] = []
    for entry in (body or {}).get("volumes") or []:
        if isinstance(entry, dict):
            if entry.get("type") not in (None, "volume"):
                continue
            source = str(entry.get("source") or "")
        elif isinstance(entry, str):
            source, _target, _mode = _split_mount(entry)
        else:
            continue
        if not source or _is_host_path(source) or source not in declared:
            continue
        if source not in keys:
            keys.append(source)
    return keys


def _extend_unique(bucket: list[str], values) -> None:
    for value in values:
        if value and value not in bucket:
            bucket.append(value)


def resolve_core_volume_owners(repo_root: Path) -> dict[str, VolumeOwner]:
    """Undecorated core volume key -> the services mounting it, their module
    labels and the union of their profiles.

    `resolve_core_volumes` reads only the top-level `volumes:` keys, which says
    *that* a volume exists but never *who* uses it. A restore that touches part
    of the snapshot needs the second half: the profile set is the only thing
    `_require_profiles_resolve` and `cmd_start --profiles=` accept, so it is
    what decides which containers have to be bounced.

    Deriving the grouping from the volume name instead is not an option:
    `litellm-postgresql` is mounted by `litellm-db`, `keycloak-postgresql` by
    `keycloak-postgres`, and `searxng_config` is the only key spelled with an
    underscore. The prefixes line up by coincidence, not by contract.

    A volume can have more than one mounter -- `localai-models` is mounted by
    both `localai-model-init` and `localai` -- which is why `services` is a
    list and the service name is not the grouping key.

    Returns {} when src/docker-compose.yml is absent, matching
    resolve_core_volumes' degradation contract."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return {}
    declared = set(resolve_core_volumes(repo_root))
    services: dict[str, list[str]] = {}
    modules: dict[str, list[str]] = {}
    profiles: dict[str, list[str]] = {}
    for compose_path in compat.compose_files(root_compose):
        if not compose_path.is_file():
            continue
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        for service, body in (doc.get("services") or {}).items():
            label = _service_labels(body).get("de.fidonis.module", "")
            declared_profiles = list((body or {}).get("profiles") or [])
            for key in _mounted_volume_keys(body, declared):
                _extend_unique(services.setdefault(key, []), [service])
                _extend_unique(modules.setdefault(key, []), [module_name(label)])
                _extend_unique(profiles.setdefault(key, []), declared_profiles)
    return {
        key: VolumeOwner(
            services=tuple(services.get(key, ())),
            modules=tuple(modules.get(key, ())),
            profiles=tuple(profiles.get(key, ())),
        )
        for key in sorted(declared | set(services))
    }


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
    owners = resolve_core_volume_owners(repo_root)
    prefix = f"{core_project}_" if core_project else ""
    for name in core_names:
        # A volume that carries the project label but is no longer declared has
        # no owner record. It keeps its data and stays restorable by name; it is
        # simply not reachable through a module selector, which is honest.
        key = name[len(prefix):] if prefix and name.startswith(prefix) else name
        owner_record = owners.get(key, VolumeOwner())
        plan.artifacts.append(
            Artifact(
                kind="volume",
                archive=f"volumes/{name}.tar.gz",
                source=name,
                owner="core",
                project=core_project,
                module=owner_record.modules[0] if owner_record.modules else "",
                services=list(owner_record.services),
                profiles=list(owner_record.profiles),
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
        # An add-on groups under its own name and carries no profiles: the
        # teardown unit is the whole add-on compose project, so per-service
        # precision would buy nothing a scoped restore could act on.
        for volume in volume_names:
            plan.artifacts.append(
                Artifact(
                    kind="volume",
                    archive=f"volumes/{volume}.tar.gz",
                    source=volume,
                    owner=owner,
                    project=project,
                    module=name,
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
                    module=name,
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
                        "module": a.module,
                        "services": a.services,
                        "profiles": a.profiles,
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
                module=str(a.get("module", "")),
                services=[str(s) for s in (a.get("services") or [])],
                profiles=[str(p) for p in (a.get("profiles") or [])],
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
            "project": a.project,
            "module": a.module,
            "services": a.services,
            "profiles": a.profiles,
        }
        for a in plan.artifacts
        if results.get(a.archive, "failed") == "ok"
    ]
    manifest = {
        "version": MANIFEST_VERSION,
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
# Partial restore: selection
# ─────────────────────────────────────────────────────────────────────────

# Prefixes are mandatory. `librechat` is at once a module, a service, a profile
# and the prefix of six volume names, so a bare word cannot be resolved without
# guessing. `profile:` is deliberately absent from the grammar: a profile is
# the teardown unit, not something an operator picks, and offering it would
# invite `profile:manager` -- the one profile a restore must never bounce,
# because it serves the request.
SELECTOR_KINDS = ("module", "volume", "addon")
MAX_SELECTORS = 32

_MODULE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# The profile papaia-manager runs under. A selection that resolved to it would
# tear down the container serving the operation.
SELF_PROFILE = "manager"


def _artifact_of(entry: dict) -> Artifact:
    return Artifact(
        kind=str(entry.get("kind", "")),
        archive=str(entry.get("archive", "")),
        source=str(entry.get("target", "")),
        owner=str(entry.get("owner", "")),
        project=str(entry.get("project", "")),
        module=str(entry.get("module", "")),
        services=[str(s) for s in (entry.get("services") or [])],
        profiles=[str(p) for p in (entry.get("profiles") or [])],
    )


def manifest_artifacts(manifest: dict) -> list[Artifact]:
    """Artifacts of a manifest of either version.

    A v1 manifest carries none of the grouping fields. They stay empty rather
    than being reconstructed from the volume name -- see
    resolve_core_volume_owners for why the name is not a reliable source."""
    return [_artifact_of(entry) for entry in (manifest.get("artifacts") or [])]


def selectors(manifest: dict) -> list[dict]:
    """The selectable units of a restore point, for a picker.

    Empty for a v1 manifest: without a module on the artifacts there is no
    honest grouping to offer, and the restore point stays restorable only as a
    whole. Empty is also the correct answer for a snapshot whose every artifact
    failed."""
    grouped: dict[str, dict] = {}
    for artifact in manifest_artifacts(manifest):
        if artifact.kind == "configdir" or not artifact.module:
            continue
        is_addon = artifact.owner.startswith("addon:")
        selector = f"{'addon' if is_addon else 'module'}:{artifact.module}"
        entry = grouped.setdefault(
            selector,
            {
                "selector": selector,
                "name": artifact.module,
                "kind": "addon" if is_addon else "module",
                "owner": artifact.owner,
                "archives": [],
                "volumes": [],
                "profiles": [],
                "services": [],
            },
        )
        entry["archives"].append(artifact.archive)
        if artifact.kind == "volume":
            entry["volumes"].append(artifact.source)
        _extend_unique(entry["profiles"], artifact.profiles)
        _extend_unique(entry["services"], artifact.services)
    return list(grouped.values())


def parse_selectors(raw: str) -> list[tuple[str, str]]:
    """Split and validate a `--only` value into (kind, name) pairs.

    Validation is a refusal, never a repair: every name reaches an argv and a
    path join further down, so an unrecognised shape must not be normalised
    into something that happens to parse."""
    parts = [part.strip() for part in (raw or "").split(",")]
    parts = [part for part in parts if part]
    if not parts:
        raise BackupError("Empty selection: --only needs at least one selector.")
    if len(parts) > MAX_SELECTORS:
        raise BackupError(f"Too many selectors ({len(parts)}); at most {MAX_SELECTORS}.")
    parsed: list[tuple[str, str]] = []
    for part in parts:
        kind, sep, name = part.partition(":")
        if not sep or kind not in SELECTOR_KINDS:
            raise BackupError(
                f"Invalid selector {part!r}: expected one of "
                f"{', '.join(k + ':NAME' for k in SELECTOR_KINDS)}."
            )
        pattern = _VOLUME_NAME_RE if kind == "volume" else _MODULE_NAME_RE
        if not pattern.match(name):
            raise BackupError(f"Invalid selector name in {part!r}.")
        if kind == "module" and name == SELF_PROFILE:
            raise BackupError(
                f"Refusing selector {part!r}: the manager cannot restore over itself."
            )
        if (kind, name) not in parsed:
            parsed.append((kind, name))
    return parsed


def _matches(artifact: Artifact, kind: str, name: str) -> bool:
    if kind == "volume":
        return artifact.kind == "volume" and artifact.source == name
    if kind == "addon":
        return artifact.owner == f"addon:{name}"
    return not artifact.owner.startswith("addon:") and artifact.module == name


@dataclass
class Selection:
    """What a `--only` value resolves to against one snapshot."""

    artifacts: list[Artifact] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    # Add-on *names*, not compose projects: `_addon_path` resolves a name
    # through deployment.yaml, and the two differ by design -- the project is
    # the directory basename. Bash needs the name to find either.
    addons: list[str] = field(default_factory=list)


def resolve_selection(manifest: dict, raw: str) -> Selection:
    """Filter a manifest's artifacts to a selection, and work out what has to
    be bounced for it.

    The profile set is resolved here rather than in bash because it comes out
    of the compose files, and the bash/Python split documented in cli.py puts
    compose parsing on this side. Bash receives it pre-resolved."""
    parsed = parse_selectors(raw)
    available = sorted(entry["selector"] for entry in selectors(manifest))
    all_artifacts = manifest_artifacts(manifest)

    unknown = [
        f"{kind}:{name}"
        for kind, name in parsed
        if not any(_matches(a, kind, name) for a in all_artifacts)
    ]
    if unknown:
        hint = ", ".join(available) if available else "none -- this snapshot predates selection"
        raise BackupError(
            f"No artifact matches {', '.join(unknown)}. Available selectors: {hint}"
        )

    selection = Selection()
    for artifact in all_artifacts:
        if not any(_matches(artifact, kind, name) for kind, name in parsed):
            continue
        # Unreachable through the grammar -- a configdir artifact carries no
        # module and no volume name to match on. Asserted anyway: this is the
        # invariant that lets a scoped restore run in-process at all.
        if artifact.kind == "configdir":
            raise BackupError(
                "A selection cannot contain the configuration directory; "
                "restore the point as a whole instead."
            )
        selection.artifacts.append(artifact)
        if artifact.owner.startswith("addon:"):
            _extend_unique(selection.addons, [artifact.owner.split(":", 1)[1]])
        else:
            _extend_unique(selection.profiles, artifact.profiles)

    if not selection.artifacts:
        raise BackupError(f"Selection matched no artifact. Available selectors: {available}")
    if SELF_PROFILE in selection.profiles:
        raise BackupError(
            f"Refusing a selection that resolves to the {SELF_PROFILE!r} profile."
        )
    selection.profiles.sort()
    selection.addons.sort()
    return selection


def _is_absolute_target(value: str) -> bool:
    """Absolute in either platform's spelling.

    `Path.is_absolute()` answers only for the platform currently running:
    '/srv/papaia-config' is not absolute on Windows, and 'C:\\papaia-config' is
    not absolute on Linux. A snapshot is routinely written on one and read on
    the other -- the manager reads a manifest its host wrote, and the catalogue
    already carries both spellings -- so this has to accept both or it would
    reject every well-formed manifest on the wrong side."""
    return value.startswith("/") or bool(_WINDOWS_DRIVE.match(value))


def _pure_path(value: str) -> PurePath:
    """Interpret a path in the flavour it was written in, without touching the
    filesystem -- the target may well not exist on the reading host."""
    if _WINDOWS_DRIVE.match(value):
        return PureWindowsPath(value)
    return PurePosixPath(value.replace("\\", "/"))


def validate_target(artifact: Artifact, config_dir: Path) -> None:
    """Refuse a manifest target that must not reach `docker run -v`.

    The manifest is a plain file on a mounted path, and partial restore turns
    it into an operator-visible index of selectable things. A volume name has
    to look like one; a directory target has to be absolute and must not be an
    ancestor of the config directory, since restoring wipes the target first."""
    if artifact.kind == "volume":
        if not _VOLUME_NAME_RE.match(artifact.source):
            raise BackupError(f"Refusing volume target {artifact.source!r} from the manifest.")
        return
    if not _is_absolute_target(artifact.source):
        raise BackupError(f"Refusing relative target {artifact.source!r} from the manifest.")
    target_path = _pure_path(artifact.source)
    config_path = _pure_path(str(config_dir))
    if target_path.__class__ is not config_path.__class__:
        # The snapshot was written on the other platform. Containment cannot be
        # decided across flavours, and guessing would be worse than not asking;
        # the absoluteness check above still applies.
        return
    if target_path == config_path or target_path in config_path.parents:
        raise BackupError(
            f"Refusing target {artifact.source!r}: it is or contains the config directory."
        )


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


def snapshot_path(backup_dir: Path, entry: dict) -> Path:
    """Locate a catalogued restore point on disk.

    Derived from the backup directory and the id rather than taken from the
    entry's recorded `path`: a snapshot always lives at <backup_dir>/<id>, and
    the recorded absolute path does not survive being read from a different
    environment than it was written in (a bundle on /mnt/c written from WSL is
    C:\\... from Windows, and vice versa). The recorded path stays as the
    fallback so a hand-moved snapshot is still found."""
    candidate = backup_dir / str(entry.get("id") or "")
    if candidate.is_dir():
        return candidate
    return Path(str(entry.get("path") or ""))


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
        target = snapshot_path(backup_dir, entry)
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
