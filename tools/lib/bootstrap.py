"""Seeding and resolution logic for `papaia-ctl init` / `papaia-ctl setup`.

Operates on an "env tree": a dict mapping a service's directory (relative to
`src/`, POSIX-style, "" for the repo-root `src/.env`) to that service's flat
key/value dict. Using (dir, key) pairs rather than one flat global dict is
required because a few key names (e.g. LITELLM_API_KEY) are reused, with
independent meaning, across more than one service's .env file.

See docs/configuration.md for the user-facing description of the algorithms
implemented here (secret stickiness, hostname derivation).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import common

EnvTree = dict[str, dict[str, str]]

# (dir, key) -> [(dir, key), ...] -- secrets that must hold the *same* value
# across more than one service's .env file. Generating/forcing only the
# canonical (first) entry and fanning the value out to its aliases avoids
# the "stale copy silently breaks OIDC" failure mode sync-config.sh's own
# comments warn about.
SECRET_ALIASES: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("infra/keycloak", "KC_LIBRECHAT_CLIENT_SECRET"): [("ai/librechat", "OPENID_CLIENT_SECRET")],
    ("infra/keycloak", "KC_LITELLM_CLIENT_SECRET"): [("ai/litellm", "GENERIC_CLIENT_SECRET")],
    ("infra/keycloak", "KC_OAUTH2_PROXY_CLIENT_SECRET"): [("", "OAUTH2_PROXY_CLIENT_SECRET")],
    ("ai/litellm", "LITELLM_MASTER_KEY"): [
        ("ai/librechat", "LITELLM_API_KEY"),
        ("ai/jinaai", "LITELLM_API_KEY"),
    ],
    ("ai/jinaai", "JINAAI_RERANKER_API_KEY"): [("ai/librechat", "JINA_API_KEY")],
}

_HOSTLIKE_NO_FQDN = {"localhost", "127.0.0.1", "host.docker.internal"}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class SetupError(Exception):
    """A user-facing, non-traceback-worthy setup failure."""


def discover_env_examples(repo_root: Path) -> dict[str, Path]:
    """Map every service directory (relative to src/, "" = root) to its
    .env.example file."""
    src = repo_root / "src"
    result: dict[str, Path] = {}
    for example in sorted(src.rglob(".env.example")):
        rel_dir = example.parent.relative_to(src).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        result[rel_dir] = example
    return result


def load_seed_tree(repo_root: Path) -> EnvTree:
    """Build the env tree from every shipped .env.example."""
    tree: EnvTree = {}
    for rel_dir, example_path in discover_env_examples(repo_root).items():
        tree[rel_dir] = common.parse_env_file(example_path)
    return tree


def load_config_dir_tree(config_dir: Path, repo_root: Path) -> EnvTree:
    """Load the current state of the config dir's .env files, falling back
    to the shipped seed for any directory not yet materialized there."""
    seed = load_seed_tree(repo_root)
    tree: EnvTree = {}
    for rel_dir in seed:
        target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        if target.is_file():
            tree[rel_dir] = common.parse_env_file(target)
        else:
            tree[rel_dir] = dict(seed[rel_dir])
    return tree


def init(
    config_dir: Path, repo_root: Path, *, env_name: str = "papaia", force: bool = False
) -> None:
    """Create and seed $PAPAIA_CONFIG_DIR. Does not generate secrets or
    touch src/**/.env -- purely seeds the config dir from shipped defaults."""
    (config_dir / "overlay").mkdir(parents=True, exist_ok=True)
    (config_dir / "overrides").mkdir(parents=True, exist_ok=True)

    seed = load_seed_tree(repo_root)
    for rel_dir, values in seed.items():
        target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        if target.is_file() and not force:
            continue
        common.atomic_write(target, _render_env_lines(values))

    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file() or force:
        _seed_deployment_yaml(deployment_path, repo_root, env_name)


def _render_env_lines(values: dict[str, str]) -> str:
    return "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"


def _seed_deployment_yaml(deployment_path: Path, repo_root: Path, env_name: str) -> None:
    import yaml

    template_path = repo_root / "tools" / "deployment.template.yaml"
    manifest = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    manifest["customer"] = env_name
    manifest["platform_version"] = resolve_platform_version(repo_root)
    common.atomic_write(
        deployment_path,
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False),
    )


def resolve_platform_version(repo_root: Path) -> str:
    """Latest released version per CHANGELOG.md's first `## [x.y.z]`
    header, falling back to "0.0.0-dev" (e.g. on a branch whose only
    section is still [Unreleased])."""
    changelog = repo_root / "CHANGELOG.md"
    if not changelog.is_file():
        return "0.0.0-dev"
    match = re.search(
        r"^## \[(\d+\.\d+\.\d+)\]", changelog.read_text(encoding="utf-8"), re.MULTILINE
    )
    return match.group(1) if match else "0.0.0-dev"


def stamp_platform_version(tree: EnvTree, repo_root: Path) -> EnvTree:
    """Populate the root .env's PAPAIA_VERSION (a blank, "do not edit"
    placeholder in src/.env.example) with the resolved platform version, so
    it always reflects the checkout setup last ran against."""
    tree.setdefault("", {})["PAPAIA_VERSION"] = resolve_platform_version(repo_root)
    return tree


def stamp_config_dir(tree: EnvTree, config_dir: Path) -> EnvTree:
    """Populate the root .env's PAPAIA_CONFIG_DIR with the actually-resolved
    config directory, so docker compose's ${PAPAIA_CONFIG_DIR} bind mounts
    resolve to the same place render_core just wrote to, instead of the
    placeholder shipped in src/.env.example."""
    tree.setdefault("", {})["PAPAIA_CONFIG_DIR"] = str(config_dir)
    return tree


# ─────────────────────────────────────────────────────────────────────────
# Secret generation
# ─────────────────────────────────────────────────────────────────────────


def generate_missing_secrets(tree: EnvTree, *, force: bool = False) -> EnvTree:
    """Sticky secret-fill pass: generate a value for every secret-shaped
    key that's still a placeholder (or, with force=True, for every
    secret-shaped key unconditionally), then fan canonical values out to
    their declared aliases."""
    for values in tree.values():
        for key, value in list(values.items()):
            if not common.is_secret_key(key):
                continue
            if force or common.is_placeholder(value):
                values[key] = common.generate_secret(key)

    for (canon_dir, canon_key), aliases in SECRET_ALIASES.items():
        canon_values = tree.get(canon_dir)
        if canon_values is None or canon_key not in canon_values:
            continue
        canonical_value = canon_values[canon_key]
        for alias_dir, alias_key in aliases:
            alias_values = tree.get(alias_dir)
            if alias_values is not None and alias_key in alias_values:
                alias_values[alias_key] = canonical_value

    return tree


# ─────────────────────────────────────────────────────────────────────────
# Hostname / OIDC / reverse-proxy / multi-env resolution
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class SetupArgs:
    config_dir: Path
    env_name: str = "papaia"
    host_ip: str | None = None
    app_host: str | None = None
    auth_host: str | None = None
    external_reverse_proxy: bool | None = None  # None = unset / auto-detect
    allow_direct_port_access: bool = False
    non_interactive: bool = False
    force: bool = False
    # Whether $PAPAIA_CONFIG_DIR/.env existed before this invocation. A
    # *fresh* config dir's tree is seeded straight from .env.example, whose
    # PAPAIA_HOST already holds a real-looking illustrative default
    # (http://host.docker.internal) rather than a GENERATE_*-style
    # placeholder -- so it must NOT be treated as a genuine sticky value
    # from a prior papaia-ctl run, or the --app-host requirement below
    # would be silently bypassed on every first run.
    fresh_init: bool = True
    prompt: callable[[str, str], str] | None = None  # injected for testability
    confirm: callable[[str, bool], bool] | None = None
    extra: dict[str, str] = field(default_factory=dict)


def _is_https(url: str) -> bool:
    return url.startswith("https://")


def _strip_scheme(url: str) -> str:
    return urlsplit(url).netloc or url


def derive_auth_host_default(app_host: str, keycloak_ext_port: str) -> str:
    """FQDN -> <scheme>://auth.<domain> (no port); IP/localhost/
    host.docker.internal -> same host + KEYCLOAK_EXT_PORT (today's shipped
    default shape)."""
    parts = urlsplit(app_host)
    hostname = parts.hostname or ""
    scheme = parts.scheme or "http"
    is_fqdn = hostname not in _HOSTLIKE_NO_FQDN and not _IPV4_RE.match(hostname) and "." in hostname
    if is_fqdn:
        return f"{scheme}://auth.{hostname}"
    return f"{scheme}://{hostname}:{keycloak_ext_port}"


def resolve_hostnames(tree: EnvTree, args: SetupArgs) -> EnvTree:
    root = tree.setdefault("", {})
    keycloak = tree.setdefault("infra/keycloak", {})
    librechat = tree.setdefault("ai/librechat", {})
    litellm = tree.setdefault("ai/litellm", {})

    if root.get("AUTH_PROVIDER", "internal_keycloak") == "external_oidc":
        # Advanced user manages their own IdP -- never clobber their config.
        return tree

    # --- PAPAIA_HOST ---
    sticky_app_host = "" if args.fresh_init else root.get("PAPAIA_HOST", "")
    if sticky_app_host and common.is_placeholder(sticky_app_host):
        sticky_app_host = ""
    app_host = args.app_host or sticky_app_host
    if not args.app_host:
        if not args.non_interactive and args.prompt is not None:
            app_host = args.prompt(
                "Public URL of this server (PAPAIA_HOST)",
                sticky_app_host or "http://host.docker.internal",
            )
        elif not sticky_app_host:
            raise SetupError(
                "--app-host is required: no prior PAPAIA_HOST value to reuse and "
                "no interactive terminal to prompt in."
            )
    root["PAPAIA_HOST"] = app_host

    # --- AUTH_HOST + KC_HOSTNAME ---
    keycloak_port = root.get("KEYCLOAK_EXT_PORT", "8110")
    derived_auth_host = derive_auth_host_default(app_host, keycloak_port)
    auth_host = args.auth_host or derived_auth_host
    if not args.auth_host and not args.non_interactive and args.prompt is not None:
        auth_host = args.prompt("Public Keycloak URL (AUTH_HOST)", derived_auth_host)
    root["AUTH_HOST"] = auth_host
    keycloak["KC_HOSTNAME"] = auth_host

    # --- OIDC issuer + split endpoints ---
    root["OIDC_ISSUER"] = f"{auth_host}/realms/papaia"
    root["OIDC_ISSUER_KC_AUTH"] = f"{auth_host}/realms/papaia/protocol/openid-connect/auth"
    root["OIDC_ISSUER_KC_TOKEN"] = (
        "http://keycloak:8080/realms/papaia/protocol/openid-connect/token"
    )
    root["OIDC_ISSUER_KC_CERTS"] = (
        "http://keycloak:8080/realms/papaia/protocol/openid-connect/certs"
    )

    # --- LibreChat ---
    librechat_port = root.get("LIBRECHAT_EXT_PORT", "8000")
    librechat["OPENID_ISSUER"] = root["OIDC_ISSUER"]
    librechat["DOMAIN_SERVER"] = f"{app_host}:{librechat_port}"
    librechat["DOMAIN_CLIENT"] = f"{app_host}:{librechat_port}"
    # TRUST_PROXY is intentionally left untouched: it's a static value (1)
    # correct for every topology this repo supports.

    # --- LiteLLM ---
    litellm_port = root.get("LITELLM_EXT_PORT", "8200")
    litellm["GENERIC_AUTHORIZATION_ENDPOINT"] = root["OIDC_ISSUER_KC_AUTH"]
    litellm["GENERIC_TOKEN_ENDPOINT"] = root["OIDC_ISSUER_KC_TOKEN"]
    litellm["GENERIC_USERINFO_ENDPOINT"] = (
        "http://keycloak:8080/realms/papaia/protocol/openid-connect/userinfo"
    )
    litellm["GENERIC_REDIRECT_URI"] = f"{app_host}:{litellm_port}/sso/callback"
    litellm["PROXY_LOGOUT_URL"] = (
        f"{auth_host}/realms/papaia/protocol/openid-connect/logout"
        f"?client_id=litellm&post_logout_redirect_uri={app_host}:{litellm_port}/sso/key/generate"
    )

    # --- Homepage / LocalAI / SearXNG: oauth2-proxy sidecar redirect URLs ---
    # These vars are consumed directly by docker compose's ${VAR} expansion
    # in each service's docker-compose.yml `command:` block, so (like
    # OIDC_ISSUER*) they belong in the root .env, not a per-service one.
    homepage_port = root.get("HOMEPAGE_EXT_PORT", "8300")
    localai_port = root.get("LOCALAI_EXT_PORT", "8080")
    searxng_port = root.get("SEARXNG_EXT_PORT", "8500")
    root["HOMEPAGE_PUBLIC_URL"] = f"{app_host}:{homepage_port}"
    root["LOCALAI_PUBLIC_URL"] = f"{app_host}:{localai_port}"
    root["SEARXNG_PUBLIC_URL"] = f"{app_host}:{searxng_port}"

    homepage = tree.setdefault("services/homepage", {})
    if "HP_ALLOWED_HOSTS" in homepage:
        homepage["HP_ALLOWED_HOSTS"] = f"{_strip_scheme(app_host)}:{homepage_port}"

    # --- Cookie-secure: always re-derived, never sticky ---
    root["OAUTH2_PROXY_COOKIE_SECURE"] = "true" if _is_https(app_host) else "false"

    return tree


def resolve_multi_env(tree: EnvTree, args: SetupArgs) -> EnvTree:
    root = tree.setdefault("", {})
    env_name = args.env_name or "papaia"
    if env_name == "papaia":
        root.setdefault("COMPOSE_PROJECT_NAME", "papaia")
        root.setdefault("DOCKER_NETWORK", "papaia-net")
    else:
        root["COMPOSE_PROJECT_NAME"] = f"papaia-{env_name}"
        root["DOCKER_NETWORK"] = f"papaia-{env_name}-net"
    if args.host_ip:
        root["HOST_IP"] = args.host_ip
    else:
        root.setdefault("HOST_IP", "0.0.0.0")
    return tree


def resolve_reverse_proxy(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Decide whether the bundled Nginx Proxy Manager (`nginx` Compose
    profile) is included.

    `nginx` is excluded only via an explicit opt-in: either
    `--external-reverse-proxy` (the operator has their own edge proxy) or
    `--allow-direct-port-access` (the operator wants raw ports, no proxy at
    all). Every other combination defaults to bundling `nginx`, so there is
    no flag combination that *accidentally* leaves the stack with no proxy
    in front of it. The interactive confirmation below is therefore reached
    only via the explicit `--allow-direct-port-access` escape hatch -- a
    last safety net against a copy-pasted flag, not a way to discover the
    unsafe state by surprise.
    """
    root = tree.setdefault("", {})
    app_host = root.get("PAPAIA_HOST", "")
    auth_host = root.get("AUTH_HOST", "")
    auto_external = _is_https(app_host) or _is_https(auth_host)
    external = (
        args.external_reverse_proxy if args.external_reverse_proxy is not None else auto_external
    )

    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    if not profiles:
        profiles = ["keycloak", "oauth2-proxy", "librechat", "litellm"]
    profiles = [p for p in profiles if p != "nginx"]

    bundle_nginx = not external and not args.allow_direct_port_access
    if bundle_nginx:
        profiles.append("nginx")

    no_proxy_anywhere = not external and "nginx" not in profiles
    if no_proxy_anywhere and not _is_https(app_host):
        if not args.non_interactive and args.confirm is not None:
            ok = args.confirm(
                "No reverse proxy and no TLS detected -- services will be reachable "
                "on plain HTTP ports directly. Continue?",
                False,
            )
            if not ok:
                raise SetupError("Aborted: direct port access was not confirmed.")

    root["COMPOSE_PROFILES"] = ",".join(profiles)
    return tree


# ─────────────────────────────────────────────────────────────────────────
# Run summary
# ─────────────────────────────────────────────────────────────────────────


def write_run_summary(config_dir: Path, tree: EnvTree, *, fresh_init: bool, force: bool) -> None:
    root = tree.get("", {})
    summary = {
        "papaia_version": root.get("PAPAIA_VERSION", ""),
        "deployed_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "config_dir": str(config_dir),
        "env": root.get("COMPOSE_PROJECT_NAME", "papaia"),
        "app_host": root.get("PAPAIA_HOST", ""),
        "auth_host": root.get("AUTH_HOST", ""),
        "external_reverse_proxy": "nginx" not in root.get("COMPOSE_PROFILES", "").split(","),
        "fresh_init": fresh_init,
        "force": force,
    }
    common.atomic_write(
        config_dir / "deployed.lock", json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )


# ─────────────────────────────────────────────────────────────────────────
# Persistence: write the tree to both $PAPAIA_CONFIG_DIR and src/**/.env
# ─────────────────────────────────────────────────────────────────────────


def persist_tree(tree: EnvTree, config_dir: Path, repo_root: Path) -> None:
    seed = load_seed_tree(repo_root)
    for rel_dir, values in tree.items():
        template = seed.get(rel_dir)
        template_path = (
            (repo_root / "src" / rel_dir / ".env.example")
            if rel_dir
            else (repo_root / "src" / ".env.example")
        )
        config_target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        repo_target = (
            repo_root / "src" / rel_dir / ".env" if rel_dir else repo_root / "src" / ".env"
        )
        if template is None:
            continue
        common.write_env_file(
            config_target, values, template_path=template_path if template_path.is_file() else None
        )
        common.write_env_file(
            repo_target, values, template_path=template_path if template_path.is_file() else None
        )
