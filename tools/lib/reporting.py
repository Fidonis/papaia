"""Operator-facing checklists ("views") printed by papaia-ctl.

Pure rendering over already-resolved state -- no file mutation, no
resolution logic. Kept out of cli.py so the checklist content is directly
unit-testable without argparse plumbing.
"""

from __future__ import annotations

from pathlib import Path

from . import common, envtree, secrets


def print_external_oidc_checklist(config_dir: Path, tree: envtree.EnvTree) -> None:
    """Print a step-by-step operator checklist for completing an external OIDC
    setup. Called after persist_tree so all resolved values are available."""
    root = tree.get("", {})
    librechat = tree.get("ai/librechat", {})
    litellm = tree.get("ai/litellm", {})

    issuer = root.get("OIDC_ISSUER", "<OIDC_ISSUER>")
    app_host = root.get("PAPAIA_HOST", "<PAPAIA_HOST>")
    librechat_url = librechat.get("DOMAIN_SERVER") or app_host
    litellm_redirect = litellm.get("GENERIC_REDIRECT_URI", "")

    # Collect env files that still contain REPLACE_WITH_VALID_SECRET
    placeholder = secrets._EXTERNAL_SECRET_PLACEHOLDER
    needs_edit: list[tuple[str, str]] = []
    for rel_dir, values in sorted(tree.items()):
        for key, value in sorted(values.items()):
            if value == placeholder:
                env_file = f"{rel_dir}.env" if rel_dir else ".env"
                needs_edit.append((env_file, key))

    clients = [
        ("librechat", f"{librechat_url}/oauth/openid/callback"),
        ("litellm", litellm_redirect or f"{app_host}/sso/callback"),
        ("oauth2-proxy", f"{app_host}/oauth2/callback"),
    ]

    sep = "─" * 65
    print()
    print("External OIDC — manual steps required before 'papaia-ctl start'")
    print(sep)
    print()
    print(f"1. Register these OIDC clients on {issuer}:")
    print()
    id_w = max(len(c[0]) for c in clients) + 2
    for client_id, redirect_uri in clients:
        print(f"   {client_id:<{id_w}} {redirect_uri}")
    print()
    if needs_edit:
        print("2. Replace REPLACE_WITH_VALID_SECRET in:")
        print()
        path_w = max(len(e[0]) for e in needs_edit) + 2
        for env_file, key in needs_edit:
            print(f"   {env_file:<{path_w}} {key}")
        print()
    print("3. Apply and start the stack:")
    print()
    print("   papaia-ctl setup -y && papaia-ctl start")
    print()
    print(
        "See src/infra/keycloak/README.md"
        " 'Switching to an External OIDC Provider' for details."
    )


def print_keycloak_checklist(
    name: str, manifest: dict, addon_path: Path, config_dir: Path
) -> None:
    integration = manifest.get("integration") or {}
    keycloak_cfg = integration.get("keycloak") or {}
    clients = keycloak_cfg.get("clients") or []
    mappers = keycloak_cfg.get("client_mappers") or {}
    replace_secret_cfg = manifest.get("env_replace_secrets") or {}

    bundle_env = config_dir / "addons" / name / ".env"
    bundle_vals = common.parse_env_file(bundle_env)
    replace_keys = [k for k, v in bundle_vals.items() if v.startswith("REPLACE_WITH_")]

    if not clients and not mappers and not replace_keys:
        return

    sep = "─" * 65
    print()
    print(f"Addon '{name}' — manual steps required before 'papaia-ctl addon start'")
    print(sep)
    print()
    step = 1
    if clients:
        print(f"{step}. Import these OIDC clients in the 'papaia' realm:")
        print()
        for rel in clients:
            print(f"   {addon_path / rel}")
        print()
        print("   Keycloak Admin UI → Clients → Import client.")
        print()
        step += 1
    if mappers:
        print(f"{step}. Add protocol mappers to these existing clients:")
        print()
        for client_name, mapper_paths in mappers.items():
            for rel in mapper_paths:
                print(f"   {client_name}: {addon_path / rel}")
        print()
        print("   Clients → <client> → Client scopes → Dedicated → Add mapper → By configuration.")
        print()
        step += 1
    if replace_keys:
        print(f"{step}. After importing, enter the client secrets in:")
        print(f"   {bundle_env}")
        print()
        key_w = max(len(k) for k in replace_keys) + 2
        for key in replace_keys:
            hint = (replace_secret_cfg.get(key) or {}).get("hint", "")
            suffix = f"  {hint}" if hint else ""
            print(f"   {key:<{key_w}}{suffix}")
        print()
