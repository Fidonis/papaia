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

from . import common, deployment


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
    deployed = deployment.load(config_dir)
    if not deployed:
        return []

    base = repo_root if repo_root is not None else Path.cwd()
    written: list[Path] = []
    for addon in deployment.active_addons(deployed):
        manifest, _ = deployment.load_addon_manifest(deployment.resolve_addon_path(addon, base))
        if manifest is None:
            continue
        result = generate_override(manifest, config_dir)
        if result is not None:
            written.append(result)
    return written


def external_networks(override_path: Path) -> list[str]:
    """The names of all `external: true` networks declared in one override
    file. The bash dispatcher uses this to skip overrides whose addon
    networks don't exist yet (the addon isn't running)."""
    if not override_path.is_file():
        return []
    doc = yaml.safe_load(override_path.read_text(encoding="utf-8")) or {}
    return [
        name
        for name, cfg in (doc.get("networks") or {}).items()
        if (cfg or {}).get("external")
    ]


# Services that mount the local Keycloak CA cert via SSL_CERT_FILE.  For
# external OIDC the cert file is absent, so SSL_CERT_FILE must be cleared to
# let Python's ssl module fall back to the system CA bundle.
_SSL_CERT_SERVICES = ("litellm", "oauth2-proxy", "localai")


def _load_addon_local_ca_env(addon: dict, repo_root: Path) -> dict:
    """Return the manifest's local_ca_env mapping (service -> list of env
    vars) for one deployment.yaml addon entry, or {} when the manifest is
    missing or declares none."""
    if not addon.get("path"):
        return {}
    manifest, _ = deployment.load_addon_manifest(deployment.resolve_addon_path(addon, repo_root))
    if manifest is None:
        return {}
    return manifest.get("local_ca_env") or {}


def generate_addon_ssl_cert_overrides(
    config_dir: Path, auth_provider: str, repo_root: Path
) -> None:
    """Write or remove the per-addon SSL cert overrides for external OIDC.

    Addons whose services mount the bundled Keycloak CA cert declare the
    affected env vars in their manifest:

        local_ca_env:
          <service>: [REQUESTS_CA_BUNDLE, ...]

    With external OIDC, certs/ is empty — those vars must be cleared so
    requests/httpx fall back to the system CA bundle instead of failing on
    the absent local-ca.crt.  The files live in overrides/addons/ so the
    core compose loop (which globs overrides/docker-compose.*.override.yml)
    does not pick them up; the addon compose loop applies
    overrides/addons/docker-compose.<name>-*.override.yml instead.
    """
    deployed = deployment.load(config_dir)

    for addon in deployed.get("addons") or []:
        name = addon.get("name")
        if not name:
            continue
        out_path = (
            config_dir / "overrides" / "addons" / f"docker-compose.{name}-ssl-cert.override.yml"
        )
        local_ca_env = _load_addon_local_ca_env(addon, repo_root)
        if not addon.get("active") or auth_provider != "external_oidc" or not local_ca_env:
            out_path.unlink(missing_ok=True)
            continue

        override = {
            "services": {
                service: {
                    "environment": {
                        var: ""
                        for var in ([env] if isinstance(env, str) else env)
                    }
                }
                for service, env in local_ca_env.items()
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
