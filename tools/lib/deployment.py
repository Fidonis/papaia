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
