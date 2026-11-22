"""Single owner of $PAPAIA_CONFIG_DIR/deployment.yaml.

Every production read or write of the deployment manifest goes through this
module. Before it existed the file was parsed independently in cli.py,
gen_override.py, render_core.py and inline python in the bash dispatcher --
four parsers with subtly different fallback behaviour is exactly the drift
risk this module removes.

Also owns the two lookups that hang off deployment entries: resolving an
addon's checkout path and loading its papaia-app.yaml manifest.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from . import common, compat


def load(config_dir: Path) -> dict:
    """Parse deployment.yaml, or {} when the config dir has none yet."""
    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return {}
    return yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}


def save(config_dir: Path, deployment: dict) -> None:
    common.atomic_write(
        config_dir / "deployment.yaml",
        yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )


def active_addons(deployment: dict) -> list[dict]:
    """The deployment entries of all addons currently marked active."""
    return [a for a in (deployment.get("addons") or []) if a.get("active")]


def resolve_addon_path(addon: dict, repo_root: Path) -> Path:
    p = Path(addon["path"])
    if not p.is_absolute():
        p = repo_root / p
    return p.resolve()


ADDON_OVERRIDES = Path("overrides") / "addons"


def addon_override_files(config_dir: Path, name: str, deployed: dict | None = None) -> list[Path]:
    """The overrides/addons/ compose files of one add-on, the files `addon start` hands
    docker compose after its own docker-compose.yml.

    Files there are named docker-compose.<segment>.override.yml, where <segment> is the
    add-on name, optionally followed by a "-<suffix>" tag (the generated "-ssl-cert", or
    an operator's own e.g. "-ports"). Add-on names contain hyphens themselves, so a bare
    "<name>-*" glob cannot tell add-on "qdrant" apart from "qdrant-ingest". Each file is
    attributed to the longest registered add-on name that equals <segment> or is a
    prefix of it before a "-"; only the files owned by `name` are returned."""
    folder = config_dir / ADDON_OVERRIDES
    if not folder.is_dir():
        return []
    if deployed is None:
        deployed = load(config_dir) or {}
    names = {a.get("name") for a in (deployed.get("addons") or []) if a.get("name")}
    # The add-on being started is registered by then, but tolerate a caller that races
    # an install.
    names.add(name)
    prefix, suffix = "docker-compose.", ".override.yml"
    owned = []
    for path in sorted(folder.glob(f"{prefix}*{suffix}")):
        segment = path.name[len(prefix) : -len(suffix)]
        owner = max(
            (n for n in names if segment == n or segment.startswith(f"{n}-")),
            key=len,
            default=None,
        )
        if owner == name:
            owned.append(path)
    return owned


def load_addon_manifest(addon_path: Path) -> tuple[dict | None, str | None]:
    """Load an addon's papaia-app.yaml. Returns (manifest, None) on success,
    (None, reason) when the file is missing or not valid YAML."""
    manifest_path = addon_path / "papaia-app.yaml"
    if not manifest_path.is_file():
        return None, f"{manifest_path} not found."
    try:
        return yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}, None
    except yaml.YAMLError as exc:
        return None, f"{manifest_path} is not valid YAML: {exc}"


def seed(deployment_path: Path, repo_root: Path, env_name: str) -> None:
    """Seed a fresh deployment.yaml from tools/deployment.template.yaml."""
    # Local import: envtree-side code calls seed() during init, so a
    # top-level import here would be circular.
    from . import envtree

    template_path = repo_root / "tools" / "deployment.template.yaml"
    manifest = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    manifest["customer"] = env_name
    manifest["platform_version"] = envtree.resolve_platform_version(repo_root)
    common.atomic_write(
        deployment_path,
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False),
    )


def sync_manifest(config_dir: Path, tree, repo_root: Path) -> None:
    """Mirror the resolved core state (profiles, platform version, served
    addon-api generation) into deployment.yaml after a setup run. `tree` is
    the resolved env tree (see envtree.EnvTree)."""
    # Local import: see seed().
    from . import envtree

    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    root = tree.get("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    manifest.setdefault("core", {})["profiles"] = profiles
    manifest["platform_version"] = envtree.resolve_platform_version(repo_root)
    # Display only -- the compatibility gate always reads the live ADDON_API
    # file of the core it evaluates, never this stamped copy.
    window = compat.resolve_addon_api_window(repo_root)
    if window is not None:
        manifest["core"]["addon_api"] = window[1]
    common.atomic_write(
        deployment_path, yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False)
    )
