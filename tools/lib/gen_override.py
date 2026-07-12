"""Seam-1 (network) and auth-provider Docker Compose override generation.

For each active addon, attaches the core containers it declares to its
own bridge network via a generated override file at
$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml. The core
compose itself is never mutated.

On the lean core, `deployment.yaml`'s `addons` list is always empty, so
`generate_overrides()` produces zero files -- a real, generically correct
no-op rather than a special case.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from . import common


def generate_override(addon_manifest: dict, config_dir: Path) -> Path | None:
    """Generate a single addon's network-attachment override.

    `addon_manifest` is the parsed papaia-app.yaml-shaped dict for one
    active addon, expected to carry:
        networks:
          app_network: papaia-<name>-net
          attach: [nginx, librechat, ...]

    Returns the written path, or None if the manifest declares no networks
    section (nothing to attach).
    """
    name = addon_manifest.get("name")
    networks = addon_manifest.get("networks") or {}
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


def generate_overrides(config_dir: Path, repo_root: Path | None = None) -> list[Path]:
    """Read deployment.yaml's active addons and (re-)generate every
    Seam-1 override. Always empty on the lean core today.

    `repo_root` is used as the base when resolving relative addon paths
    from deployment.yaml (matching render_core.render's behaviour). When
    omitted, Path.cwd() is used — kept for backwards compatibility but
    callers should always supply repo_root.
    """
    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return []
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    active_addons = [a for a in (deployment.get("addons") or []) if a.get("active")]

    base = repo_root if repo_root is not None else Path.cwd()
    written: list[Path] = []
    for addon in active_addons:
        manifest_path = (base / addon["path"]) / "papaia-app.yaml"
        if not manifest_path.is_file():
            continue
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        result = generate_override(manifest, config_dir)
        if result is not None:
            written.append(result)
    return written


# Services that mount the local Keycloak CA cert via SSL_CERT_FILE.  For
# external OIDC the cert file is absent, so SSL_CERT_FILE must be cleared to
# let Python's ssl module fall back to the system CA bundle.
_SSL_CERT_SERVICES = ("litellm", "oauth2-proxy", "localai")


def generate_paperless_addon_ssl_cert_override(config_dir: Path, auth_provider: str) -> None:
    """Write or remove the paperless addon SSL cert override for external OIDC.

    With external OIDC, certs/ is empty — REQUESTS_CA_BUNDLE and SSL_CERT_FILE
    must be cleared so requests/httpx fall back to the system CA bundle instead
    of failing on the absent local-ca.crt.  The file lives in overrides/addons/
    so the core compose loop (which globs overrides/docker-compose.*.override.yml)
    does not pick it up and try to apply it to core services.
    """
    out_path = config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"

    deployment_path = config_dir / "deployment.yaml"
    if deployment_path.is_file():
        deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    else:
        deployment = {}
    addons = deployment.get("addons") or []
    paperless_active = any(
        a.get("name") == "paperless" and a.get("active") for a in addons
    )

    if not paperless_active or auth_provider != "external_oidc":
        out_path.unlink(missing_ok=True)
        return

    override = {
        "services": {
            "paperless":     {"environment": {"REQUESTS_CA_BUNDLE": ""}},
            "paperless-mcp": {"environment": {"SSL_CERT_FILE": ""}},
        }
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


def generate_ssl_cert_override(config_dir: Path, auth_provider: str) -> None:
    """Write or remove the SSL_CERT_FILE override for external OIDC.

    With external OIDC, $PAPAIA_CONFIG_DIR/certs/ is empty (the local CA cert
    is only generated for bundled Keycloak).  Setting SSL_CERT_FILE to an empty
    string is falsy in Python's ssl.create_default_context, so it skips
    load_verify_locations and uses system CAs instead of crashing on the
    missing file path.
    """
    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    if auth_provider != "external_oidc":
        out_path.unlink(missing_ok=True)
        return

    override = {
        "services": {
            svc: {"environment": {"SSL_CERT_FILE": ""}}
            for svc in _SSL_CERT_SERVICES
        }
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )
