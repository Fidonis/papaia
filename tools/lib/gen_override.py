"""Seam-1 (network) Docker Compose override generation.

For each active extension, attaches the core containers it declares to its
own bridge network via a generated override file at
$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml. The core
compose itself is never mutated.

On the lean core, `deployment.yaml`'s `extensions` list is always empty, so
`generate_overrides()` produces zero files -- a real, generically correct
no-op rather than a special case.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from . import common


def generate_override(extension_manifest: dict, config_dir: Path) -> Path | None:
    """Generate a single extension's network-attachment override.

    `extension_manifest` is the parsed papaia-app.yaml-shaped dict for one
    active extension, expected to carry:
        networks:
          app_network: papaia-<name>-net
          attach: [nginx, librechat, ...]

    Returns the written path, or None if the manifest declares no networks
    section (nothing to attach).
    """
    name = extension_manifest.get("name")
    networks = extension_manifest.get("networks") or {}
    app_network = networks.get("app_network")
    attach = networks.get("attach") or []
    if not name or not app_network or not attach:
        return None

    override = {
        "services": {service: {"networks": [app_network]} for service in attach},
        "networks": {app_network: {"external": True}},
    }

    out_path = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )
    return out_path


def generate_overrides(config_dir: Path) -> list[Path]:
    """Read deployment.yaml's active extensions and (re-)generate every
    Seam-1 override. Always empty on the lean core today."""
    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return []
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    active_extensions = [e for e in (deployment.get("extensions") or []) if e.get("active")]

    written: list[Path] = []
    for ext in active_extensions:
        manifest_path = Path(ext["path"]) / "papaia-app.yaml"
        if not manifest_path.is_file():
            continue
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        result = generate_override(manifest, config_dir)
        if result is not None:
            written.append(result)
    return written
