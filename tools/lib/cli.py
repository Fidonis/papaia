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


def cmd_init(args: argparse.Namespace) -> int:
    bootstrap.init(Path(args.config_dir), Path(args.repo_root), env_name=args.env, force=args.force)
    print(f"Seeded {args.config_dir}")
    return 0


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
        "EXTERNAL_REVERSE_PROXY_STICKY": (
            "false" if "nginx" in profiles else ("true" if profiles else "")
        ),
        "WEB_SEARCH_STICKY": (
            ("true" if "searxng" in profiles else "false") if config_seeded else ""
        ),
        "COMPOSE_PROFILES_STICKY": ",".join(profiles),
        "PLATFORM_VERSION": bootstrap.resolve_platform_version(repo_root),
        "CONFIG_SEEDED": "true" if config_seeded else "false",
    }
    for key, value in out.items():
        print(f"{key}={value}")
    return 0


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
        auth_provider=args.auth_provider,
        oidc_issuer=args.oidc_issuer,
        external_reverse_proxy=_tristate(args.external_reverse_proxy),
        enable_web_search=_tristate(args.enable_web_search),
        enable_local_ai=_tristate(args.enable_local_ai),
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
        tree = bootstrap.resolve_web_search(tree, setup_args)
        tree = bootstrap.resolve_local_ai(tree, setup_args)
    except bootstrap.SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    tree = bootstrap.stamp_platform_version(tree, repo_root)
    tree = bootstrap.stamp_config_dir(tree, config_dir)
    bootstrap.persist_tree(tree, config_dir, repo_root)
    _sync_deployment_manifest(config_dir, tree, repo_root)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir)

    bootstrap.write_run_summary(config_dir, tree, fresh_init=fresh_init, force=args.force)
    print(f"Setup complete. PAPAIA_CONFIG_DIR={config_dir}")
    if effective_auth_provider == "external_oidc":
        print(
            "External OIDC provider selected -- see "
            "src/infra/keycloak/README.md 'Switching to an External OIDC "
            "Provider' for the client/realm configuration you still need to "
            "set up on your provider's side."
        )
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


def cmd_render(args: argparse.Namespace) -> int:
    render_core.render(Path(args.config_dir), Path(args.repo_root))
    gen_override.generate_overrides(Path(args.config_dir))
    print("Rendered.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="papaia-ctl-py")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--config-dir", required=True)
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--env", default="papaia")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_defaults = sub.add_parser("defaults")
    p_defaults.set_defaults(func=cmd_defaults)

    p_setup = sub.add_parser("setup")
    p_setup.add_argument("--env", default="papaia")
    p_setup.add_argument("--host-ip")
    p_setup.add_argument("--app-host")
    p_setup.add_argument("--auth-host")
    p_setup.add_argument("--librechat-host")
    p_setup.add_argument("--localai-host")
    p_setup.add_argument(
        "--auth-provider", choices=["internal_keycloak", "external_oidc"], default=None
    )
    p_setup.add_argument("--oidc-issuer")
    p_setup.add_argument("--external-reverse-proxy", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-web-search", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-local-ai", choices=["true", "false"], default=None)
    p_setup.add_argument("--allow-direct-port-access", action="store_true")
    p_setup.add_argument("--force", action="store_true")
    p_setup.set_defaults(func=cmd_setup)

    p_render = sub.add_parser("render")
    p_render.set_defaults(func=cmd_render)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
