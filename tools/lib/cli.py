"""Python entry point invoked by the `tools/papaia-ctl` bash dispatcher.

Bash owns interactive prompting (per the issue's stated split: "bash
handles arg-parsing, interactive prompts and docker compose calls; Python
handles all YAML / JSON / env / secret manipulation"). The flow is:

  1. bash calls `defaults` to learn sticky/derived values for its prompts.
  2. bash prompts the user (or reads flags / sticky values straight through
     in --non-interactive mode) and resolves every value itself.
  3. bash calls `setup` with the fully-resolved flags; this module never
     blocks on stdin -- it raises SetupError (exit code 3) if something
     required is still missing.

Invoked as `python3 -m lib.cli <subcommand> ...` with `tools/` on
PYTHONPATH (the bash dispatcher sets this up).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import bootstrap, common, gen_override, render_core


def _tristate(value: str | None) -> bool | None:
    if value is None:
        return None
    return value == "true"



def cmd_defaults(args: argparse.Namespace) -> int:
    """Print sticky/derived values as shell-safe KEY=VALUE lines, one per
    line, so the bash dispatcher can read them without a JSON parser."""
    repo_root = Path(args.repo_root)
    config_dir = Path(args.config_dir)
    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    root = tree.get("", {})
    librechat = tree.get("ai/librechat", {})
    app_host = root.get("PAPAIA_HOST", "")
    keycloak_port = root.get("KEYCLOAK_EXT_PORT", "8110")
    auth_host_sticky = root.get("AUTH_HOST", "")
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    # Only surface a sticky LibreChat URL once the config dir is actually seeded:
    # on a fresh checkout the tree falls back to the shipped .env.example, whose
    # DOMAIN_SERVER (host.docker.internal:8000) differs from the localhost-based
    # default bash should prefill -- gating avoids a wrong sticky prefill.
    config_seeded = (config_dir / ".env").is_file()
    librechat_sticky = librechat.get("DOMAIN_SERVER", "") if config_seeded else ""
    if common.is_placeholder(librechat_sticky):
        librechat_sticky = ""
    localai_sticky = root.get("LOCALAI_PUBLIC_URL", "") if config_seeded else ""
    if common.is_placeholder(localai_sticky):
        localai_sticky = ""
    jinaai = tree.get("ai/jinaai", {})
    reranker_model_sticky = jinaai.get("RERANKER_MODEL", "") if config_seeded else ""
    if common.is_placeholder(reranker_model_sticky):
        reranker_model_sticky = ""
    out = {
        "APP_HOST_STICKY": app_host,
        "AUTH_HOST_STICKY": auth_host_sticky,
        "AUTH_HOST_DERIVED": bootstrap.derive_auth_host_default(
            app_host or "http://host.docker.internal", keycloak_port
        ),
        "LIBRECHAT_HOST_STICKY": librechat_sticky,
        "LIBRECHAT_EXT_PORT": root.get("LIBRECHAT_EXT_PORT", "8000"),
        "LOCALAI_HOST_STICKY": localai_sticky,
        "LOCALAI_EXT_PORT": root.get("LOCALAI_EXT_PORT", "8080"),
        "LOCAL_AI_STICKY": (
            ("true" if "localai" in profiles else "false") if config_seeded else ""
        ),
        "AUTH_PROVIDER_STICKY": root.get("AUTH_PROVIDER", ""),
        "REVERSE_PROXY_PROVIDER_STICKY": root.get("REVERSE_PROXY_PROVIDER", ""),
        "NPM_ADMIN_HOST_STICKY": root.get("NPM_ADMIN_HOST", "") if config_seeded else "",
        "NPM_ADMIN_HOST_DERIVED": bootstrap.derive_npm_admin_host_default(
            app_host or "http://host.docker.internal",
            root.get("NPM_ADMIN_EXT_PORT", "8100"),
        ),
        "EXTERNAL_REVERSE_PROXY_STICKY": (
            "false" if "nginx" in profiles else ("true" if profiles else "")
        ),
        "WEB_SEARCH_STICKY": (
            (
                "true"
                if "librechat-websearch" in profiles
                or any(p in bootstrap._WEB_SEARCH_LEGACY_PROFILES for p in profiles)
                else "false"
            )
            if config_seeded
            else ""
        ),
        "RERANKER_MODEL_STICKY": reranker_model_sticky,
        "COMPOSE_PROFILES_STICKY": ",".join(profiles),
        "PLATFORM_VERSION": bootstrap.resolve_platform_version(repo_root),
        "CONFIG_SEEDED": "true" if config_seeded else "false",
    }
    for key, value in out.items():
        print(f"{key}={value}")
    return 0


def _print_external_oidc_checklist(config_dir: Path, tree: bootstrap.EnvTree) -> None:
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
    placeholder = bootstrap._EXTERNAL_SECRET_PLACEHOLDER
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


def cmd_setup(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    config_dir = Path(args.config_dir)

    fresh_init = not (config_dir / ".env").is_file()
    bootstrap.init(config_dir, repo_root, env_name=args.env, force=False)

    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    setup_args = bootstrap.SetupArgs(
        config_dir=config_dir,
        env_name=args.env,
        host_ip=args.host_ip,
        app_host=args.app_host,
        auth_host=args.auth_host,
        librechat_host=args.librechat_host,
        localai_host=args.localai_host,
        npm_admin_host=args.npm_admin_host,
        auth_provider=args.auth_provider,
        oidc_issuer=args.oidc_issuer,
        reverse_proxy_provider=args.reverse_proxy_provider or None,
        external_reverse_proxy=_tristate(args.external_reverse_proxy),
        enable_web_search=_tristate(args.enable_web_search),
        enable_local_ai=_tristate(args.enable_local_ai),
        reranker_model=args.reranker_model or None,
        allow_direct_port_access=args.allow_direct_port_access,
        non_interactive=True,
        force=args.force,
        fresh_init=fresh_init,
    )

    effective_auth_provider = args.auth_provider or tree.get("", {}).get(
        "AUTH_PROVIDER", "internal_keycloak"
    )

    seed = bootstrap.load_seed_tree(repo_root)
    try:
        tree = bootstrap.generate_missing_secrets(
            tree, seed, force=args.force, auth_provider=effective_auth_provider
        )
        tree = bootstrap.resolve_multi_env(tree, setup_args)
        tree = bootstrap.resolve_hostnames(tree, setup_args)
        tree = bootstrap.resolve_reverse_proxy(tree, setup_args)
        tree = bootstrap.migrate_web_search_profiles(tree)
        tree = bootstrap.resolve_web_search(tree, setup_args)
        tree = bootstrap.resolve_local_ai(tree, setup_args)
        tree = bootstrap.resolve_reranker_model(tree, setup_args)
    except bootstrap.SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    tree = bootstrap.stamp_platform_version(tree, repo_root)
    tree = bootstrap.stamp_config_dir(tree, config_dir)
    bootstrap.persist_tree(tree, config_dir, repo_root)
    _sync_deployment_manifest(config_dir, tree, repo_root)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    gen_override.generate_ssl_cert_override(config_dir, effective_auth_provider)
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, effective_auth_provider)

    bootstrap.write_run_summary(config_dir, tree, fresh_init=fresh_init, force=args.force)
    print(f"Setup complete. Run 'papaia-ctl start' to bring up the stack. PAPAIA_CONFIG_DIR={config_dir}")
    if effective_auth_provider == "external_oidc":
        _print_external_oidc_checklist(config_dir, tree)
    return 0


def _sync_deployment_manifest(config_dir: Path, tree, repo_root: Path) -> None:
    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    root = tree.get("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    manifest.setdefault("core", {})["profiles"] = profiles
    manifest["platform_version"] = bootstrap.resolve_platform_version(repo_root)
    common.atomic_write(
        deployment_path, yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False)
    )


def cmd_materialize(args: argparse.Namespace) -> int:
    bootstrap.materialize_core_env(Path(args.config_dir), Path(args.repo_root))
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_ssl_cert_override(config_dir, auth_provider)
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, auth_provider)
    print("Rendered.")
    return 0


def _load_deployment(config_dir: Path) -> dict:
    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file():
        return {}
    return yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}


def _save_deployment(config_dir: Path, deployment: dict) -> None:
    common.atomic_write(
        config_dir / "deployment.yaml",
        yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )


def _resolve_addon_path(addon: dict, repo_root: Path) -> Path:
    p = Path(addon["path"])
    if not p.is_absolute():
        p = repo_root / p
    return p.resolve()


def _print_keycloak_checklist(
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


def cmd_addon_install(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployment = _load_deployment(config_dir)
    if not deployment:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addons: list[dict] = deployment.setdefault("addons", [])
    existing = next((a for a in addons if a.get("name") == name), None)

    if existing:
        if args.path:
            existing["path"] = str(Path(args.path).resolve())
        if args.version:
            existing["version"] = args.version
        existing["active"] = True
        addon_path = _resolve_addon_path(existing, repo_root)
    else:
        if not args.path:
            print(
                f"ERROR: --path is required when installing a new addon '{name}'.",
                file=sys.stderr,
            )
            return 2
        addon_path = Path(args.path).resolve()
        entry: dict = {"name": name, "path": str(addon_path), "active": True}
        if args.version:
            entry["version"] = args.version
        addons.append(entry)

    manifest_path = addon_path / "papaia-app.yaml"
    if not manifest_path.is_file():
        print(f"ERROR: {manifest_path} not found.", file=sys.stderr)
        return 2
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}

    bootstrap.seed_addon_env(addon_path, config_dir)

    bundle_env_path = config_dir / "addons" / name / ".env"
    updates = bootstrap.prompt_change_me_vars(bundle_env_path, manifest, config_dir)
    if updates:
        env_vals = common.parse_env_file(bundle_env_path)
        env_vals.update(updates)
        common.write_env_file(bundle_env_path, env_vals)

    _save_deployment(config_dir, deployment)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, auth_provider)

    _print_keycloak_checklist(name, manifest, addon_path, config_dir)
    print(f"Addon installed: {name}")
    return 0


def cmd_addon_start(args: argparse.Namespace) -> int:
    """Materialize .env into checkout and re-render. Docker compose up is done by bash."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployment = _load_deployment(config_dir)
    addons: list[dict] = deployment.get("addons") or []
    entry = next((a for a in addons if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2
    if not entry.get("active"):
        print(f"ERROR: addon '{name}' is not active. Run 'papaia-ctl addon install {name}' first.", file=sys.stderr)
        return 2

    addon_path = _resolve_addon_path(entry, repo_root)
    bootstrap.materialize_addon_env(config_dir, addon_path, name)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    return 0


def cmd_addon_remove(args: argparse.Namespace) -> int:
    """Remove integration only: override gone, active=false, re-render. Bundle kept."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployment = _load_deployment(config_dir)
    if not deployment:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addons: list[dict] = deployment.get("addons") or []
    entry = next((a for a in addons if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    entry["active"] = False
    _save_deployment(config_dir, deployment)

    override_file = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    override_file.unlink(missing_ok=True)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, auth_provider)

    print(f"Addon removed: {name}")
    return 0


def cmd_addon_uninstall(args: argparse.Namespace) -> int:
    """Remove integration + delete config bundle + deployment entry. Docker down done by bash."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployment = _load_deployment(config_dir)
    if not deployment:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addons: list[dict] = deployment.get("addons") or []
    entry = next((a for a in addons if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    override_file = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    override_file.unlink(missing_ok=True)

    bundle_dir = config_dir / "addons" / name
    if bundle_dir.is_dir():
        import shutil
        shutil.rmtree(bundle_dir)

    deployment["addons"] = [a for a in addons if a.get("name") != name]
    _save_deployment(config_dir, deployment)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, auth_provider)

    print(f"Addon uninstalled: {name}")
    return 0


def cmd_addon_networks(args: argparse.Namespace) -> int:
    """Print the Docker network name for each active addon (one per line).

    Used by papaia-ctl start to pre-create external networks before the core
    compose starts, so the stack comes up cleanly even when no addon container
    is running yet.
    """
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    deployment = _load_deployment(config_dir)
    active_addons = [a for a in (deployment.get("addons") or []) if a.get("active")]
    for addon in active_addons:
        manifest_path = _resolve_addon_path(addon, repo_root) / "papaia-app.yaml"
        if manifest_path.is_file():
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
            net = (manifest.get("networks") or {}).get("app_network")
            if net:
                print(net)
    return 0


def cmd_addon_path(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployment = _load_deployment(config_dir)
    addons: list[dict] = deployment.get("addons") or []
    entry = next((a for a in addons if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    print(_resolve_addon_path(entry, repo_root))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="papaia-ctl-py")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--config-dir", required=True)
    sub = parser.add_subparsers(dest="command", required=True)

    p_materialize = sub.add_parser("materialize-core")
    p_materialize.set_defaults(func=cmd_materialize)

    p_defaults = sub.add_parser("defaults")
    p_defaults.set_defaults(func=cmd_defaults)

    p_setup = sub.add_parser("setup")
    p_setup.add_argument("--env", default="papaia")
    p_setup.add_argument("--host-ip")
    p_setup.add_argument("--app-host")
    p_setup.add_argument("--auth-host")
    p_setup.add_argument("--librechat-host")
    p_setup.add_argument("--localai-host")
    p_setup.add_argument("--npm-admin-host")
    p_setup.add_argument(
        "--auth-provider", choices=["internal_keycloak", "external_oidc"], default=None
    )
    p_setup.add_argument("--oidc-issuer")
    p_setup.add_argument(
        "--reverse-proxy-provider",
        choices=["internal_nginx", "external_proxy", "no_proxy"],
        default=None,
    )
    p_setup.add_argument("--external-reverse-proxy", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-web-search", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-local-ai", choices=["true", "false"], default=None)
    p_setup.add_argument("--reranker-model", default=None)
    p_setup.add_argument("--allow-direct-port-access", action="store_true")
    p_setup.add_argument("--force", action="store_true")
    p_setup.set_defaults(func=cmd_setup)

    p_render = sub.add_parser("render")
    p_render.set_defaults(func=cmd_render)

    p_addon_install = sub.add_parser("addon-install")
    p_addon_install.add_argument("--name", required=True)
    p_addon_install.add_argument("--path", default=None)
    p_addon_install.add_argument("--version", default=None)
    p_addon_install.set_defaults(func=cmd_addon_install)

    p_addon_start = sub.add_parser("addon-start")
    p_addon_start.add_argument("--name", required=True)
    p_addon_start.set_defaults(func=cmd_addon_start)

    p_addon_remove = sub.add_parser("addon-remove")
    p_addon_remove.add_argument("--name", required=True)
    p_addon_remove.set_defaults(func=cmd_addon_remove)

    p_addon_uninstall = sub.add_parser("addon-uninstall")
    p_addon_uninstall.add_argument("--name", required=True)
    p_addon_uninstall.set_defaults(func=cmd_addon_uninstall)

    p_addon_networks = sub.add_parser("addon-networks")
    p_addon_networks.set_defaults(func=cmd_addon_networks)

    p_addon_path = sub.add_parser("addon-path")
    p_addon_path.add_argument("--name", required=True)
    p_addon_path.set_defaults(func=cmd_addon_path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
