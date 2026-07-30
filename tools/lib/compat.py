"""Core-addon compatibility evaluation and gating.

The core declares the addon-contract window it serves in the static
`ADDON_API` file at the repo root (sibling of `VERSION`); addons declare
the generation they are built against via `requires.addon_api` in
papaia-app.yaml. Evaluation precedence per addon:

  1. `requires.addon_api` present and the core exposes a window
     -> integer window-intersection check (authoritative).
  2. else `papaia_compat` present and the core's platform version known
     -> SemVer range check (keeps pre-contract addons working).
  3. else -> UNKNOWN: warn, never hard-fail. A manifest that predates the
     contract cannot be allowed to break the install path, and this is
     what lets core and addon repos release independently.

Both resolvers read plain static files, so they work identically against
the running checkout and against an update candidate (`addon check
--target-core=PATH`, a git worktree or unpacked tarball).

Additionally, `networks.attach` entries are validated structurally against
the core compose's service names -- the one seam break that has actually
happened (a core service rename) is detectable without any version number.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import semver

STATUS_OK = "OK"
STATUS_INCOMPATIBLE = "INCOMPATIBLE"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_ERROR = "ERROR"

MODE_ENFORCE = "enforce"
MODE_WARN = "warn"

# deployment.yaml speaks operator vocabulary (production/dev), the env var
# speaks policy vocabulary (enforce/warn); both map onto the same two modes.
_MODE_SYNONYMS = {
    "enforce": MODE_ENFORCE,
    "production": MODE_ENFORCE,
    "prod": MODE_ENFORCE,
    "warn": MODE_WARN,
    "dev": MODE_WARN,
    "development": MODE_WARN,
}


@dataclass(frozen=True)
class CoreTarget:
    """The compatibility-relevant surface of one core (current or candidate).

    Any field may be unknown (None): a manual `--target-version` knows no
    addon_api window, `--target-addon-api` knows no platform version, and a
    synthetic repo may ship no compose file. Unknown axes are skipped, never
    guessed."""

    platform_version: str | None = None
    addon_api: tuple[int, int] | None = None  # (min, current)
    services: dict[str, list[str]] | None = None  # service name -> profiles


@dataclass(frozen=True)
class CompatResult:
    name: str
    status: str
    axis: str | None = None
    requirement: object = None
    core_value: object = None
    reason: str | None = None
    warnings: tuple[str, ...] = ()


def resolve_addon_api_window(repo_root: Path) -> tuple[int, int] | None:
    """Read the served contract window from <repo_root>/ADDON_API as
    (min, current).

    Returns None when the file is absent (a core predating the contract, or
    a downgrade target) so callers skip the addon_api axis and fall back to
    `papaia_compat`. A present-but-malformed file raises ValueError: unlike
    an old core, a broken window declaration is a bug worth surfacing."""
    path = repo_root / "ADDON_API"
    if not path.is_file():
        return None
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.split("#", 1)[0].strip()
    try:
        current = int(values["current"])
        minimum = int(values.get("min", values["current"]))
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Malformed ADDON_API file: {path} ({exc})") from exc
    if minimum > current:
        raise ValueError(f"Malformed ADDON_API file: {path} (min {minimum} > current {current})")
    return (minimum, current)


def compose_files(root_compose: Path) -> list[Path]:
    doc = yaml.safe_load(root_compose.read_text(encoding="utf-8")) or {}
    files = [root_compose]
    for entry in doc.get("include") or []:
        if isinstance(entry, str):
            rel_paths = [entry]
        elif isinstance(entry, dict):
            path_value = entry.get("path")
            rel_paths = path_value if isinstance(path_value, list) else [path_value or ""]
        else:
            rel_paths = []
        files.extend(root_compose.parent / rel for rel in rel_paths if rel)
    return files


def resolve_core_services(repo_root: Path) -> dict[str, list[str]] | None:
    """Map every core compose service to its `profiles` list, walking the
    root compose's `include:` entries.

    Returns None when src/docker-compose.yml is absent (synthetic contexts
    such as minimal test repos), so callers skip the structural check
    instead of reporting false incompatibilities. A dangling include entry
    is tolerated: the remaining files still describe the core."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return None
    services: dict[str, list[str]] = {}
    for compose_path in compose_files(root_compose):
        if not compose_path.is_file():
            continue
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        for name, service in (doc.get("services") or {}).items():
            profiles = (service or {}).get("profiles") or []
            services[name] = list(profiles)
    return services


def resolve_core_target(repo_root: Path) -> CoreTarget:
    """Snapshot one core checkout's compatibility surface. Works equally
    for the running checkout and for a `--target-core` candidate."""
    from . import envtree

    return CoreTarget(
        platform_version=envtree.resolve_platform_version(repo_root),
        addon_api=resolve_addon_api_window(repo_root),
        services=resolve_core_services(repo_root),
    )


def resolve_mode(deployment: dict | None) -> str:
    """Gate policy precedence: PAPAIA_COMPAT_MODE env var, then
    deployment.yaml's `mode:`, then enforce. Unrecognized values fall
    through to the next source rather than failing a start path."""
    for candidate in (os.environ.get("PAPAIA_COMPAT_MODE"), (deployment or {}).get("mode")):
        if isinstance(candidate, str) and candidate.lower() in _MODE_SYNONYMS:
            return _MODE_SYNONYMS[candidate.lower()]
    return MODE_ENFORCE


def _normalize_generations(value: object) -> list[int]:
    items = value if isinstance(value, list) else [value]
    if not items:
        raise ValueError("requires.addon_api must not be empty")
    generations: list[int] = []
    for item in items:
        # bool is an int subclass; `addon_api: true` must still be rejected.
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"requires.addon_api entries must be integers, got {item!r}")
        generations.append(item)
    return sorted(set(generations))


def _fmt_generations(generations: list[int]) -> str:
    return ",".join(str(g) for g in generations)


def evaluate_addon(
    name: str,
    manifest: object,
    core: CoreTarget,
    *,
    active_profiles: list[str] | None = None,
) -> CompatResult:
    """Evaluate one addon manifest against one core target.

    Returns ERROR only for malformed manifests -- those are bugs, not
    policy calls, and `gate()` treats them as fatal even under --force."""
    if not isinstance(manifest, dict):
        return CompatResult(name, STATUS_ERROR, reason="papaia-app.yaml is not a mapping")

    requires = manifest.get("requires")
    if requires is not None and not isinstance(requires, dict):
        return CompatResult(name, STATUS_ERROR, reason="requires: must be a mapping")
    api_requirement = (requires or {}).get("addon_api")
    compat_range = manifest.get("papaia_compat")
    if compat_range is not None and not isinstance(compat_range, str):
        return CompatResult(name, STATUS_ERROR, reason="papaia_compat: must be a string range")

    generations: list[int] | None = None
    if api_requirement is not None:
        try:
            generations = _normalize_generations(api_requirement)
        except ValueError as exc:
            return CompatResult(name, STATUS_ERROR, reason=str(exc))

    status = STATUS_UNKNOWN
    axis: str | None = None
    requirement: object = None
    core_value: object = None
    reason: str | None = None

    if generations is not None and core.addon_api is not None:
        window_min, window_current = core.addon_api
        axis = "addon_api"
        requirement = generations
        core_value = [window_min, window_current]
        if any(window_min <= generation <= window_current for generation in generations):
            status = STATUS_OK
        else:
            status = STATUS_INCOMPATIBLE
            if all(generation < window_min for generation in generations):
                reason = (
                    f"core no longer serves addon_api {_fmt_generations(generations)}"
                    f" (min {window_min})"
                )
            else:
                reason = (
                    f"core serves addon_api [{window_min}..{window_current}], addon is built"
                    f" against {_fmt_generations(generations)}"
                )
    elif compat_range is not None and core.platform_version is not None:
        axis = "papaia_compat"
        requirement = compat_range
        core_value = core.platform_version
        try:
            if semver.satisfies(core.platform_version, compat_range):
                status = STATUS_OK
            else:
                status = STATUS_INCOMPATIBLE
                reason = (
                    f"core version {core.platform_version} does not satisfy '{compat_range}'"
                )
        except ValueError as exc:
            return CompatResult(
                name, STATUS_ERROR, axis="papaia_compat", requirement=compat_range,
                reason=str(exc),
            )
    elif generations is not None or compat_range is not None:
        reason = (
            "core does not expose an addon_api window"
            if generations is not None and compat_range is None
            else "core platform version unknown; papaia_compat range not evaluated"
        )
    else:
        reason = "manifest declares no compatibility requirement"

    warnings: list[str] = []
    attach = (manifest.get("networks") or {}).get("attach") or []
    if attach and not isinstance(attach, list):
        return CompatResult(name, STATUS_ERROR, reason="networks.attach must be a list")
    if attach and core.services is not None and status in (STATUS_OK, STATUS_UNKNOWN):
        unknown = [service for service in attach if service not in core.services]
        if unknown:
            status = STATUS_INCOMPATIBLE
            axis = "attach"
            requirement = list(attach)
            core_value = None
            reason = "core has no service " + ", ".join(f"'{service}'" for service in unknown)
        elif active_profiles is not None:
            active = set(active_profiles)
            for service in attach:
                profiles = core.services.get(service) or []
                if profiles and not active.intersection(profiles):
                    warnings.append(
                        f"service '{service}' belongs to inactive profile(s):"
                        f" {', '.join(profiles)}"
                    )

    return CompatResult(
        name,
        status,
        axis=axis,
        requirement=requirement,
        core_value=core_value,
        reason=reason,
        warnings=tuple(warnings),
    )


def gate(results: list[CompatResult], *, mode: str, force: bool = False) -> int:
    """Exit code (0 or 2) for a set of results under the given policy.

    ERROR is always fatal -- a malformed manifest is a bug, not a policy
    call, so not even --force degrades it. INCOMPATIBLE is fatal in enforce
    mode unless --force (or warn mode) degrades it. UNKNOWN never fails: a
    manifest predating the contract cannot break anything."""
    exit_code = 0
    for result in results:
        if result.status == STATUS_ERROR:
            return 2
        if result.status == STATUS_INCOMPATIBLE and mode != MODE_WARN and not force:
            exit_code = 2
    return exit_code


def _fmt_requirement(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _fmt_core_value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return f"[{value[0]}..{value[1]}]"
    return str(value)


def format_table(results: list[CompatResult], *, core_label: str = "CORE") -> str:
    """Render results as an aligned table; reasons and warnings become
    indented continuation lines under their row."""
    header = ("ADDON", "AXIS", "REQUIRES", core_label, "STATUS")
    rows = [
        (
            result.name,
            result.axis or "-",
            _fmt_requirement(result.requirement),
            _fmt_core_value(result.core_value),
            result.status,
        )
        for result in results
    ]
    widths = [
        max(len(header[column]), *(len(row[column]) for row in rows))
        if rows
        else len(header[column])
        for column in range(len(header))
    ]
    lines = ["  ".join(header[i].ljust(widths[i]) for i in range(len(header))).rstrip()]
    for result, row in zip(results, rows, strict=True):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(row))).rstrip())
        if result.reason:
            lines.append(f"  reason: {result.reason}")
        for warning in result.warnings:
            lines.append(f"  warning: {warning}")
    return "\n".join(lines)


def to_json(results: list[CompatResult]) -> str:
    return json.dumps(
        [
            {
                "name": result.name,
                "axis": result.axis,
                "requirement": result.requirement,
                "core_value": result.core_value,
                "status": result.status,
                "reason": result.reason,
            }
            for result in results
        ]
    )
