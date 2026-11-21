"""Backup/restore planning, catalogue keeping and retention.

Pure logic: works out *what* has to be archived and keeps the on-disk
catalogue in order. Every `docker` invocation stays in tools/lib/sh/backup.sh,
per the bash/Python split documented in cli.py.

Every archive is an age file encrypted to the operator's recipients (lib/backup_crypt.py,
BE-14); a backup is never written unencrypted. Three things are archived:

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

CHECKSUMS_NAME = "checksums.tsv"

# Every archive is a gzip tar stream encrypted to the recipients (lib/age.py).
ARCHIVE_SUFFIX = ".tar.gz.age"
CONFIG_ARCHIVE = "papaia-config" + ARCHIVE_SUFFIX
ENCRYPTION_FORMAT = "age-encryption.org/v1"

# v2 added the per-artifact grouping fields a partial restore selects on.
# v1 snapshots stay readable and restorable, but only as a whole.
MANIFEST_VERSION = 2

_ID_FORMAT = "%Y-%m-%d_%H-%M-%S"


class BackupError(Exception):
    """Raised for operator-facing failures; cli.py turns it into exit 3."""


class SelectionError(BackupError):
    """A `--only` value that is malformed or matches nothing.

    The caller asked for something that cannot be done, so cli.py turns this
    into exit 2 where the selection is part of a `backup`, like any other bad
    argument."""


class ScopedRestorePointError(BackupError):
    """A restore of the whole stack was asked for from a scoped backup.

    Exit 2 like a bad argument: nothing is wrong with the restore point, the
    request does not fit it."""


class EncryptedRestorePointError(BackupError):
    """A restore of an encrypted point without the operator's key.

    Exit 2: the point is fine, the key to open it was not given. Nothing is touched."""


# ─────────────────────────────────────────────────────────────────────────
# Plan model
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Recipient:
    """One public key a backup is encrypted to, with the operator's name for it."""

    name: str
    key: str


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
    # The node the source lives on, in a distributed installation only. Written into the
    # plan and the manifest only when set, so a single-host manifest reads as before.
    node: str = ""


def _artifact_fields(artifact: Artifact) -> dict:
    """The grouping fields a plan and a manifest record, `node` only where it is set."""
    fields: dict = {
        "owner": artifact.owner,
        "project": artifact.project,
        "module": artifact.module,
        "services": artifact.services,
        "profiles": artifact.profiles,
    }
    if artifact.node:
        fields["node"] = artifact.node
    return fields


@dataclass
class BackupPlan:
    snapshot: Path
    backup_id: str
    core_project: str
    config_dir: Path
    artifacts: list[Artifact] = field(default_factory=list)
    addons: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    # The `--only` selectors this plan was narrowed to, normalised to
    # `kind:name`. Empty for a plan of the whole stack.
    scope: list[str] = field(default_factory=list)
    # Volumes deliberately left out, each as {"volume", "reason"} (RE-05, `volumes[].backup`).
    excluded: list[dict] = field(default_factory=list)
    recipients: list[Recipient] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# Compose introspection
# ─────────────────────────────────────────────────────────────────────────


def _top_level_volumes(compose_path: Path) -> list[str]:
    if not compose_path.is_file():
        return []
    doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    return list((doc.get("volumes") or {}).keys())


# Volumes no backup ever contains, core or add-on, whatever a manifest declares (BE-14,
# RE-05): a restore must not bring back a key that signs delegations or revocation lists,
# and the erasure journal lives at the backup target, not in an archive. A restored
# installation makes new keys, so old delegations and lists stop being valid.
KEY_VOLUMES: dict[str, str] = {
    "assist-delegation-key": "delegation signing key of the assistant (RE-05)",
    "flow-delegation-key": "delegation signing key of flow (RE-05)",
    "papaia-lifecycle-key": "signing key of the revocation list (RE-05)",
    "papaia-erasure": "local copy of the erasure journal; the journal is kept at the target",
}
EXCLUDED_CORE_VOLUMES = frozenset(KEY_VOLUMES)


def _key_volume(name: str) -> str | None:
    """The reason a volume key or a project-prefixed volume name is a key volume."""
    for key, reason in KEY_VOLUMES.items():
        if name == key or name.endswith(f"_{key}"):
            return reason
    return None


_DECLARATION_FIELDS = {"name", "backup", "reason"}
MAX_VOLUME_DECLARATIONS = 64


def addon_volume_exclusions(addon_path: Path, declared_keys: list[str]) -> dict[str, str]:
    """Volume key -> reason for every volume of an add-on a backup leaves out: the ones its
    manifest declares as `volumes: [{name, backup: exclude, reason}]` (contract generation
    13) and the key volumes of BE-14.

    A declaration that does not parse stops the backup rather than being skipped: a typo in
    the name of a key volume would otherwise put the key into the archive."""
    excluded = {key: KEY_VOLUMES[key] for key in declared_keys if key in KEY_VOLUMES}
    manifest_path = addon_path / "papaia-app.yaml"
    if not manifest_path.is_file():
        return excluded
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise BackupError(f"{manifest_path} is not valid YAML: {exc}") from exc
    entries = manifest.get("volumes") if isinstance(manifest, dict) else None
    if entries is None:
        return excluded
    where = f"{manifest_path}: volumes"
    if not isinstance(entries, list) or len(entries) > MAX_VOLUME_DECLARATIONS:
        raise BackupError(f"{where} must be a list of at most {MAX_VOLUME_DECLARATIONS} entries")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        at = f"{where}[{index}]"
        if not isinstance(entry, dict):
            raise BackupError(f"{at} must be a mapping with name and backup")
        unknown = sorted(str(k) for k in set(entry) - _DECLARATION_FIELDS)
        if unknown:
            raise BackupError(f"{at} has unknown field(s): {', '.join(unknown)}")
        name, choice, reason = entry.get("name"), entry.get("backup"), entry.get("reason")
        if not isinstance(name, str) or not _VOLUME_NAME_RE.match(name):
            raise BackupError(f"{at}.name is not a volume name")
        if name not in declared_keys:
            raise BackupError(f"{at}.name {name!r} is not a volume of the add-on's compose file")
        if name in seen:
            raise BackupError(f"{at}.name {name!r} is declared twice")
        seen.add(name)
        if choice not in ("include", "exclude"):
            raise BackupError(f"{at}.backup must be include or exclude")
        if reason is not None and (not isinstance(reason, str) or not 0 < len(reason) <= 200):
            raise BackupError(f"{at}.reason must be a text of at most 200 characters")
        if choice == "exclude":
            if reason is None:
                raise BackupError(f"{at}: an excluded volume needs a reason")
            excluded[name] = reason
        elif name in KEY_VOLUMES:
            raise BackupError(f"{at}: {name} never goes into a backup ({KEY_VOLUMES[name]})")
    return excluded


def _top_level_core_keys(repo_root: Path) -> list[str]:
    """Every named volume key the core declares, the excluded ones included."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return []
    keys: list[str] = []
    for compose_path in compat.compose_files(root_compose):
        _extend_unique(keys, _top_level_volumes(compose_path))
    return keys


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
            if key not in volumes and key not in EXCLUDED_CORE_VOLUMES:
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


_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _closing_brace(value: str, start: int) -> int:
    """Index of the `}` that closes the default starting at `start`, skipping nested
    `${...}`; -1 when there is none."""
    depth = 0
    i = start
    while i < len(value):
        if value.startswith("${", i):
            depth += 1
            i += 2
            continue
        if value[i] == "}":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return -1


def expand(value: str, env: dict[str, str]) -> str:
    """Expand ${VAR}, ${VAR:-default} and $VAR against `env`, following
    Compose semantics: the `:-` default applies when the variable is unset
    *or* empty, and a default may itself hold a ${...} (nested defaults such as
    `${INGRESS_HOST_IP:-${HOST_IP:-0.0.0.0}}`). Substituted values are not
    expanded again. Anything that is not a well-formed reference stays as is."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] != "$":
            out.append(value[i])
            i += 1
            continue
        if value.startswith("${", i):
            name = _NAME_RE.match(value, i + 2)
            if name:
                after = name.end()
                if value.startswith("}", after):
                    out.append(env.get(name.group(0), ""))
                    i = after + 1
                    continue
                if value.startswith(":-", after):
                    close = _closing_brace(value, after + 2)
                    if close != -1:
                        current = env.get(name.group(0), "")
                        out.append(current or expand(value[after + 2 : close], env))
                        i = close + 1
                        continue
            out.append("$")
            i += 1
            continue
        name = _NAME_RE.match(value, i + 1)
        if name:
            out.append(env.get(name.group(0), ""))
            i = name.end()
            continue
        out.append("$")
        i += 1
    return "".join(out)


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
    # Declared key volumes never reach the plan (resolve_core_volumes); the project label
    # would bring one back in, so the found names are checked as well.
    for key in _top_level_core_keys(repo_root):
        if key in KEY_VOLUMES:
            plan.excluded.append({"volume": f"{prefix}{key}", "reason": KEY_VOLUMES[key]})
    labelled_keys = [n for n in core_names if _key_volume(n)]
    for name in labelled_keys:
        if not any(e["volume"] == name for e in plan.excluded):
            plan.excluded.append({"volume": name, "reason": _key_volume(name)})
    core_names = [n for n in core_names if n not in labelled_keys]
    for name in core_names:
        # A volume that carries the project label but is no longer declared has
        # no owner record. It keeps its data and stays restorable by name; it is
        # simply not reachable through a module selector, which is honest.
        key = name[len(prefix):] if prefix and name.startswith(prefix) else name
        owner_record = owners.get(key, VolumeOwner())
        plan.artifacts.append(
            Artifact(
                kind="volume",
                archive=f"volumes/{name}{ARCHIVE_SUFFIX}",
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

        declared_keys = _top_level_volumes(addon_path / "docker-compose.yml")
        excluded = addon_volume_exclusions(addon_path, declared_keys)
        volume_names, skipped = _project_volumes(
            project, [k for k in declared_keys if k not in excluded], existing
        )
        left_out = {f"{project}_{key}": reason for key, reason in excluded.items()}
        # A volume found through the project label is held to the same list.
        for volume in volume_names:
            reason = _key_volume(volume)
            if reason and volume not in left_out:
                left_out[volume] = reason
        volume_names = [v for v in volume_names if v not in left_out]
        skipped = [v for v in skipped if v not in left_out]
        plan.excluded.extend({"volume": v, "reason": r} for v, r in left_out.items())
        # An add-on groups under its own name and carries no profiles: the
        # teardown unit is the whole add-on compose project, so per-service
        # precision would buy nothing a scoped restore could act on.
        for volume in volume_names:
            plan.artifacts.append(
                Artifact(
                    kind="volume",
                    archive=f"volumes/{volume}{ARCHIVE_SUFFIX}",
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
                    archive=f"binds/{slug}{ARCHIVE_SUFFIX}",
                    source=str(bind),
                    owner=owner,
                    project=project,
                    module=name,
                )
            )

    return plan


def scope_plan(plan: BackupPlan, raw: str) -> BackupPlan:
    """Narrow a plan of the whole stack to the `--only` selectors.

    Same grammar and matching as `restore --only`, so whatever a scoped backup
    holds a scoped restore can name. The configuration directory is never part
    of a scoped plan: `restore-scoped` does not touch it either, and an
    add-on's configuration bundle is only ever extended, never replaced.

    A selector that matches no artifact is a refusal. An empty archive would
    look like a restore point and restore nothing."""
    parsed = parse_selectors(raw)
    candidates = [a for a in plan.artifacts if a.kind != "configdir"]
    unmatched = [
        f"{kind}:{name}"
        for kind, name in parsed
        if not any(_matches(a, kind, name) for a in candidates)
    ]
    if unmatched:
        raise SelectionError(
            f"No volume or data directory matches {', '.join(unmatched)}: nothing to back up."
        )
    chosen = [a for a in candidates if any(_matches(a, kind, name) for kind, name in parsed)]
    profiles: list[str] = []
    for artifact in chosen:
        _extend_unique(profiles, artifact.profiles)
    if SELF_PROFILE in profiles:
        raise SelectionError(
            f"Refusing a selection that resolves to the {SELF_PROFILE!r} profile."
        )

    plan.artifacts = chosen
    plan.addons = sorted(
        {a.owner.split(":", 1)[1] for a in chosen if a.owner.startswith("addon:")}
    )
    plan.scope = [f"{kind}:{name}" for kind, name in parsed]
    # Warnings about volumes of other projects would only be noise here.
    projects = {a.project for a in chosen if a.owner.startswith("addon:")}
    plan.skipped = [
        name for name in plan.skipped if any(name.startswith(f"{p}_") for p in projects)
    ]
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
                "scope": plan.scope,
                "excluded": plan.excluded,
                "recipients": [{"name": r.name, "key": r.key} for r in plan.recipients],
                "artifacts": [
                    {
                        "kind": a.kind,
                        "archive": a.archive,
                        "source": a.source,
                        **_artifact_fields(a),
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
                node=str(a.get("node", "")),
            )
            for a in (data.get("artifacts") or [])
        ],
        addons=list(data.get("addons") or []),
        skipped=list(data.get("skipped") or []),
        scope=[str(s) for s in (data.get("scope") or [])],
        excluded=[
            {"volume": str(e.get("volume", "")), "reason": str(e.get("reason", ""))}
            for e in (data.get("excluded") or [])
            if isinstance(e, dict)
        ],
        recipients=[
            Recipient(name=str(r.get("name", "")), key=str(r.get("key", "")))
            for r in (data.get("recipients") or [])
            if isinstance(r, dict)
        ],
    )


def read_checksums(snapshot: Path) -> dict[str, str]:
    """SHA-256 of each sealed archive, as `backup-seal` recorded it: ARCHIVE<TAB>HEX."""
    sums: dict[str, str] = {}
    path = snapshot / CHECKSUMS_NAME
    if not path.is_file():
        return sums
    for line in path.read_text(encoding="utf-8").splitlines():
        archive, _, digest = line.strip().partition("\t")
        if archive and re.fullmatch(r"[0-9a-f]{64}", digest.strip()):
            sums[archive] = digest.strip()
    return sums


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
    restorable. Each one carries the SHA-256 of its encrypted file (BE-14)."""
    sums = read_checksums(snapshot)
    artifacts = [
        {
            "kind": a.kind,
            "archive": a.archive,
            "target": a.source,
            **_artifact_fields(a),
            **({"sha256": sums[a.archive]} if a.archive in sums else {}),
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
    if plan.recipients:
        # Public keys only: which keys open this point, and the names the operator gave them.
        manifest["encryption"] = {
            "format": ENCRYPTION_FORMAT,
            "recipients": [{"name": r.name, "key": r.key} for r in plan.recipients],
        }
    if plan.excluded:
        manifest["excluded"] = plan.excluded
    if plan.scope:
        # A partial snapshot says so, because a restore of the whole stack
        # replaces the configuration directory from it and has none to use.
        manifest["scope"] = plan.scope
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
        node=str(entry.get("node", "")),
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


def parse_selectors(
    raw: str, kinds: tuple[str, ...] = SELECTOR_KINDS
) -> list[tuple[str, str]]:
    """Split and validate a `--only` value into (kind, name) pairs.

    Validation is a refusal, never a repair: every name reaches an argv and a
    path join further down, so an unrecognised shape must not be normalised
    into something that happens to parse."""
    parts = [part.strip() for part in (raw or "").split(",")]
    parts = [part for part in parts if part]
    if not parts:
        raise SelectionError("Empty selection: --only needs at least one selector.")
    if len(parts) > MAX_SELECTORS:
        raise SelectionError(f"Too many selectors ({len(parts)}); at most {MAX_SELECTORS}.")
    parsed: list[tuple[str, str]] = []
    for part in parts:
        kind, sep, name = part.partition(":")
        if not sep or kind not in kinds:
            raise SelectionError(
                f"Invalid selector {part!r}: expected one of "
                f"{', '.join(k + ':NAME' for k in kinds)}."
            )
        pattern = _VOLUME_NAME_RE if kind == "volume" else _MODULE_NAME_RE
        if not pattern.match(name):
            raise SelectionError(f"Invalid selector name in {part!r}.")
        if kind == "module" and name == SELF_PROFILE:
            raise SelectionError(
                f"Refusing selector {part!r}: the manager cannot restore over itself."
            )
        if (kind, name) not in parsed:
            parsed.append((kind, name))
    return parsed


def _matches(artifact: Artifact, kind: str, name: str) -> bool:
    if kind == "node":
        return artifact.node == name
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
    if artifact.kind == "configdir":
        # Its target *is* the config directory, so the containment rule below
        # refused every whole-stack restore. The recorded source is never used:
        # restore-resolve redirects it to the config dir the stack reads now.
        return
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
    if plan.scope:
        entry["scope"] = plan.scope
    if plan.recipients:
        entry["recipients"] = [{"name": r.name, "key": r.key} for r in plan.recipients]
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


def prune_keep(backup_dir: Path, keep: int) -> list[str]:
    """Keep the `keep` newest usable restore points and delete everything older.

    Usable means not `failed`: a row of failed runs must not push the last good points
    out. A failed run older than the oldest kept point goes with the rest; newer ones stay
    for the operator to read. The same guard as prune(): only catalogued directories
    inside backup_dir are removed."""
    if keep < 1:
        raise BackupError("--keep must be 1 or greater.")
    index = load_index(backup_dir)
    ordered = sorted(index["backups"], key=lambda b: str(b.get("created_at", "")))
    usable = [b for b in ordered if b.get("result") != "failed"]
    if len(usable) <= keep:
        return []
    oldest_kept = str(usable[-keep].get("created_at", ""))
    doomed = [b for b in ordered if str(b.get("created_at", "")) < oldest_kept]
    if not doomed:
        return []
    resolved_root = backup_dir.resolve()
    for entry in doomed:
        target = snapshot_path(backup_dir, entry)
        if target.is_dir():
            try:
                resolved = target.resolve()
            except OSError:
                resolved = target
            if resolved_root in resolved.parents:
                shutil.rmtree(resolved, ignore_errors=True)
    gone = {id(entry) for entry in doomed}
    index["backups"] = [b for b in index["backups"] if id(b) not in gone]
    save_index(backup_dir, index)
    return [str(entry.get("id", "")) for entry in doomed]


def entry_scope(entry: dict) -> list[str]:
    """The selectors a catalogue entry or manifest was narrowed to; empty for a
    backup of the whole stack, including every one made before scoping existed."""
    return [str(s) for s in (entry.get("scope") or [])]


def require_whole_stack(manifest: dict) -> None:
    """Refuse to restore a scoped backup as a whole.

    A restore of the whole stack takes the stack down and replaces the
    configuration directory from the snapshot. A scoped one holds neither the
    directory nor the other modules, so the restore would remove what it cannot
    bring back."""
    scope = entry_scope(manifest)
    if scope:
        raise ScopedRestorePointError(
            f"Restore point {manifest.get('id')} only holds {', '.join(scope)}. "
            f"Restore it with 'papaia-ctl restore-scoped --only={','.join(scope)}'."
        )


def require_plain(manifest: dict) -> None:
    """Refuse to hand an encrypted point to a restore that reads archives as plain tar.

    The point names its recipients; restoring it needs the private key of one of them,
    and nothing starts with new keys in its place (BE-14)."""
    encryption = manifest.get("encryption")
    if not encryption:
        return
    recipients = ", ".join(
        f"{r.get('name')} {r.get('key')}"
        for r in encryption.get("recipients") or []
        if isinstance(r, dict)
    )
    raise EncryptedRestorePointError(
        f"The key for restore point {manifest.get('id')} is missing (recipients: {recipients})."
        " This restore reads unencrypted points only; nothing was changed."
    )


def resolve_restore_point(
    backup_dir: Path, restore_point: str | None = None, *, whole_stack: bool = False
) -> tuple[dict, list[str]]:
    """Pick the restore point to restore from. Returns (entry, warnings).

    Without an explicit id the most recent usable backup wins; a `failed`
    entry is never selected implicitly, since restoring from one would replace
    live data with a knowingly incomplete snapshot. `whole_stack` skips scoped
    backups in that choice, because the newest backup being one add-on's
    restore point must not turn a plain `restore` into a refusal."""
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
    if whole_stack:
        usable = [b for b in usable if not entry_scope(b)]
    if not usable:
        raise BackupError(
            "Every recorded backup failed. Pass --restore-point=ID to force one anyway."
            if not whole_stack
            else "No backup of the whole stack is recorded. Pass --restore-point=ID,"
            " or use 'restore-scoped --only=...' for a scoped one."
        )
    entry = sorted(usable, key=lambda b: str(b.get("created_at", "")))[-1]
    warnings: list[str] = []
    if entry.get("result") == "partial":
        warnings.append(
            f"Restore point {entry.get('id')} is marked 'partial' -- some archives failed"
            " during that backup. Check backup.log before relying on it."
        )
    return entry, warnings


def delete_backups(backup_dir: Path, restore_point_ids: list[str]) -> list[str]:
    """Delete one or more restore points: remove each snapshot directory and
    drop its catalogue entry.

    Every id is checked against the catalogue before anything is removed, so a
    single unknown id fails the whole call and leaves every restore point in
    place. Ids are de-duplicated; the returned list is the ids actually removed,
    in the order given.

    The same guard as prune(): a directory is deleted only when it is recorded
    in backup.yaml *and* located inside backup_dir -- a snapshot an operator
    moved out of the backup location, or a doctored `path`, loses its catalogue
    entry but is never removed from disk."""
    wanted: list[str] = list(dict.fromkeys(restore_point_ids))
    if not wanted:
        raise BackupError("No restore point id given.")
    index = load_index(backup_dir)
    by_id = {str(entry.get("id")): entry for entry in index["backups"]}
    unknown = [rp for rp in wanted if rp not in by_id]
    if unknown:
        available = ", ".join(by_id) or "(none)"
        raise BackupError(
            f"Unknown restore point(s): {', '.join(unknown)}. Available: {available}"
        )
    resolved_root = backup_dir.resolve()
    for rp in wanted:
        target = snapshot_path(backup_dir, by_id[rp])
        if target.is_dir():
            try:
                resolved = target.resolve()
            except OSError:
                resolved = target
            if resolved_root in resolved.parents:
                shutil.rmtree(resolved, ignore_errors=True)
    dropped = set(wanted)
    index["backups"] = [b for b in index["backups"] if str(b.get("id")) not in dropped]
    save_index(backup_dir, index)
    return wanted
