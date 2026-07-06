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
    ("infra/keycloak", "KC_LOCALAI_CLIENT_SECRET"): [("ai/localai", "LOCALAI_OIDC_CLIENT_SECRET")],
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
    common.ensure_dir(config_dir / "overlay")
    common.ensure_dir(config_dir / "overrides")
    common.ensure_dir(config_dir / "certs")

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


def generate_missing_secrets(
    tree: EnvTree, seed: EnvTree, *, force: bool = False, auth_provider: str | None = None
) -> EnvTree:
    """Sticky secret-fill pass: generate a value for every key the shipped
    `seed` marks with the GENERATE_ convention that's still a placeholder (or,
    with force=True, for every GENERATE_-marked key unconditionally), then fan
    canonical values out to their declared aliases.

    Using the seed's GENERATE_ marker -- not a key-name heuristic -- as the
    source of truth means literals shipped without the marker (e.g.
    KC_DB_PASSWORD=keycloak, empty third-party API keys) are never touched, and
    an unconventionally-named secret (e.g. CREDS_IV) is never missed.

    `auth_provider` mirrors the effective AUTH_PROVIDER this run resolves
    to (falling back to the tree's current on-disk value when omitted) --
    when it's "external_oidc", the infra/keycloak directory is skipped
    entirely, since nothing consumes those secrets once the bundled
    Keycloak isn't started.
    """
    effective_auth_provider = auth_provider or tree.get("", {}).get(
        "AUTH_PROVIDER", "internal_keycloak"
    )
    skip_dirs = {"infra/keycloak"} if effective_auth_provider == "external_oidc" else set()

    for rel_dir, values in tree.items():
        if rel_dir in skip_dirs:
            continue
        seed_values = seed.get(rel_dir, {})
        for key, value in list(values.items()):
            if not common.marks_generated_secret(seed_values.get(key, "")):
                continue
            if force or common.is_placeholder(value):
                values[key] = common.generate_secret(key)

    for (canon_dir, canon_key), aliases in SECRET_ALIASES.items():
        if canon_dir in skip_dirs:
            continue
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
    librechat_host: str | None = None  # public LibreChat URL (DOMAIN_SERVER/DOMAIN_CLIENT)
    localai_host: str | None = None  # public LocalAI URL (LOCALAI_PUBLIC_URL)
    auth_provider: str | None = None  # None = unset/sticky; "internal_keycloak" | "external_oidc"
    oidc_issuer: str | None = None  # explicit external issuer; only used for external_oidc
    external_reverse_proxy: bool | None = None  # None = unset / auto-detect
    enable_web_search: bool | None = None  # None = sticky / no change
    enable_local_ai: bool | None = None  # None = sticky / no change
    reranker_model: str | None = None  # None = sticky / no change
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
    host.docker.internal -> https://<host>:<KEYCLOAK_EXT_PORT>.

    Local hostnames always get https:// because Keycloak now terminates TLS
    natively and the locally-generated CA cert covers these SANs. For FQDNs the
    scheme is preserved from app_host -- the operator already has a real cert."""
    parts = urlsplit(app_host)
    hostname = parts.hostname or ""
    scheme = parts.scheme or "http"
    is_fqdn = hostname not in _HOSTLIKE_NO_FQDN and not _IPV4_RE.match(hostname) and "." in hostname
    if is_fqdn:
        return f"{scheme}://auth.{hostname}"
    return f"https://{hostname}:{keycloak_ext_port}"


def derive_librechat_url_default(app_host: str, librechat_port: str) -> str:
    """Default browser-facing LibreChat URL (DOMAIN_SERVER/DOMAIN_CLIENT):
    the public host plus the external LibreChat port.

    host.docker.internal over plain HTTP is rewritten to localhost, because
    LibreChat marks its OIDC session cookie Secure for any host other than
    localhost/127.0.0.1/::1 -- served over plain HTTP the browser then drops
    that cookie and OIDC login fails. Everything else keeps app_host as-is (the
    OIDC issuer still uses app_host so the container reaches the bundled
    Keycloak for discovery)."""
    parts = urlsplit(app_host)
    host = app_host
    if parts.scheme == "http" and parts.hostname == "host.docker.internal":
        host = app_host.replace("host.docker.internal", "localhost", 1)
    return f"{host}:{librechat_port}"


def derive_localai_url_default(app_host: str, localai_port: str) -> str:
    """Default browser-facing LocalAI URL: the public host plus the external LocalAI port."""
    return f"{app_host}:{localai_port}"


def _resolve_external_oidc_issuer(args: SetupArgs) -> str:
    """Resolve the real external issuer URL on a first-time transition into
    external_oidc. Never falls back to the bundled-Keycloak-shaped seed
    default -- that value is real-looking, not a GENERATE_* placeholder, so
    silently keeping it would misconfigure the stack against a customer's
    real IdP without any signal that something is wrong."""
    issuer = args.oidc_issuer
    if issuer:
        return issuer
    if not args.non_interactive and args.prompt is not None:
        issuer = args.prompt("External OIDC issuer URL (OIDC_ISSUER)", "")
        if issuer:
            return issuer
    raise SetupError(
        "--oidc-issuer is required when selecting external_oidc for the first "
        "time: no real issuer URL was provided and there is no interactive "
        "terminal to prompt in."
    )


def resolve_hostnames(tree: EnvTree, args: SetupArgs) -> EnvTree:
    root = tree.setdefault("", {})
    keycloak = tree.setdefault("infra/keycloak", {})
    librechat = tree.setdefault("ai/librechat", {})
    litellm = tree.setdefault("ai/litellm", {})
    localai = tree.setdefault("ai/localai", {})

    prior_auth_provider = root.get("AUTH_PROVIDER", "internal_keycloak")
    auth_provider = args.auth_provider or prior_auth_provider

    if auth_provider == "external_oidc" and prior_auth_provider == "external_oidc":
        # Already sticky from a prior run -- advanced user manages their own
        # IdP config by hand. Never clobber it, regardless of what
        # args.auth_provider says this run (re-passing the same value is a
        # no-op; nothing to prompt for).
        return tree

    root["AUTH_PROVIDER"] = auth_provider

    # --- PAPAIA_HOST (provider-independent) ---
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

    if auth_provider == "external_oidc":
        # First-time transition (fresh init, or switching this run). The
        # seed/prior OIDC_ISSUER is bundled-Keycloak-shaped -- never kept
        # silently. AUTH_HOST / KC_HOSTNAME / split KC_* endpoints / litellm
        # GENERIC_* are Keycloak-specific and meaningless without the
        # bundled Keycloak, so they are left untouched.
        root["OIDC_ISSUER"] = _resolve_external_oidc_issuer(args)
        librechat["OPENID_ISSUER"] = root["OIDC_ISSUER"]
    else:
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
            "https://keycloak:8443/realms/papaia/protocol/openid-connect/token"
        )
        root["OIDC_ISSUER_KC_CERTS"] = (
            "https://keycloak:8443/realms/papaia/protocol/openid-connect/certs"
        )

        # --- LibreChat ---
        # OPENID_ISSUER is provider-specific (bundled-Keycloak issuer here); the
        # browser-facing DOMAIN_SERVER/DOMAIN_CLIENT are resolved below, outside
        # this branch, since LibreChat is served for either auth provider.
        librechat["OPENID_ISSUER"] = root["OIDC_ISSUER"]
        # TRUST_PROXY is intentionally left untouched: it's a static value (1)
        # correct for every topology this repo supports.

        # --- LiteLLM ---
        litellm_port = root.get("LITELLM_EXT_PORT", "8200")
        litellm["GENERIC_AUTHORIZATION_ENDPOINT"] = root["OIDC_ISSUER_KC_AUTH"]
        litellm["GENERIC_TOKEN_ENDPOINT"] = root["OIDC_ISSUER_KC_TOKEN"]
        litellm["GENERIC_USERINFO_ENDPOINT"] = (
            "https://keycloak:8443/realms/papaia/protocol/openid-connect/userinfo"
        )
        litellm["GENERIC_REDIRECT_URI"] = f"{app_host}:{litellm_port}/sso/callback"
        litellm["PROXY_LOGOUT_URL"] = (
            f"{auth_host}/realms/papaia/protocol/openid-connect/logout"
            f"?client_id=litellm&post_logout_redirect_uri={app_host}:{litellm_port}/sso/key/generate"
        )

    # --- LibreChat browser URL (DOMAIN_SERVER/DOMAIN_CLIENT) ---
    # Provider-independent: LibreChat is served regardless of the IdP, so its
    # public URL is resolved for both internal_keycloak and external_oidc.
    # --librechat-host wins, else a prior run's sticky value, else the derived
    # default -- same arg/sticky/prompt shape as PAPAIA_HOST, including the
    # fresh_init guard (the seed default http://host.docker.internal:8000 is a
    # real-looking illustrative value, not a GENERATE_* placeholder, so it must
    # not be reused as sticky).
    librechat_port = root.get("LIBRECHAT_EXT_PORT", "8000")
    derived_librechat = derive_librechat_url_default(app_host, librechat_port)
    sticky_librechat = "" if args.fresh_init else librechat.get("DOMAIN_SERVER", "")
    if sticky_librechat and common.is_placeholder(sticky_librechat):
        sticky_librechat = ""
    librechat_url = args.librechat_host or sticky_librechat or derived_librechat
    if not args.librechat_host and not args.non_interactive and args.prompt is not None:
        librechat_url = args.prompt(
            "Public URL of LibreChat (DOMAIN_SERVER)",
            sticky_librechat or derived_librechat,
        )
    librechat["DOMAIN_SERVER"] = librechat_url
    librechat["DOMAIN_CLIENT"] = librechat_url

    # --- Homepage: oauth2-proxy sidecar redirect URL ---
    # Belongs in the root .env (consumed by docker compose ${VAR} expansion).
    # Independent of AUTH_PROVIDER -- this is a server-reachability URL.
    homepage_port = root.get("HOMEPAGE_EXT_PORT", "8300")
    root["HOMEPAGE_PUBLIC_URL"] = f"{app_host}:{homepage_port}"

    # --- LocalAI public URL + native OIDC config ---
    # LOCALAI_PUBLIC_URL is exposed in the root .env (docker compose ${VAR}
    # expansion in localai/docker-compose.yml). Per-service OIDC vars go into
    # the ai/localai env node, which is written to $PAPAIA_CONFIG_DIR/ai/localai/.env.
    localai_port = root.get("LOCALAI_EXT_PORT", "8080")
    derived_localai = derive_localai_url_default(app_host, localai_port)
    sticky_localai = "" if args.fresh_init else root.get("LOCALAI_PUBLIC_URL", "")
    if sticky_localai and common.is_placeholder(sticky_localai):
        sticky_localai = ""
    localai_url = args.localai_host or sticky_localai or derived_localai
    if not args.localai_host and not args.non_interactive and args.prompt is not None:
        localai_url = args.prompt(
            "Public URL of LocalAI (LOCALAI_PUBLIC_URL)",
            sticky_localai or derived_localai,
        )
    root["LOCALAI_PUBLIC_URL"] = localai_url
    localai["LOCALAI_OIDC_ISSUER"] = root["OIDC_ISSUER"]
    localai["LOCALAI_OIDC_CLIENT_ID"] = "localai"
    localai["LOCALAI_BASE_URL"] = localai_url

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
    if root.get("AUTH_PROVIDER", "internal_keycloak") == "external_oidc":
        # Nothing to start -- the bundled Keycloak (+ its Postgres, which
        # shares the same `keycloak` compose profile) is not part of this
        # topology when an external IdP is in use. Switching back to
        # internal_keycloak later does not re-add it here (out of scope --
        # only the forward transition is required).
        profiles = [p for p in profiles if p != "keycloak"]
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


def resolve_web_search(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Add or remove the `searxng` and `firecrawl` Compose profiles based on
    the operator's web-search choice.

    When `enable_web_search` is None the call is a no-op -- whatever was
    already written to COMPOSE_PROFILES on a prior run is preserved (sticky)."""
    if args.enable_web_search is None:
        return tree
    root = tree.setdefault("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    profiles = [p for p in profiles if p not in ("searxng", "firecrawl", "jinaai")]
    if args.enable_web_search:
        profiles.extend(["searxng", "firecrawl", "jinaai"])
    root["COMPOSE_PROFILES"] = ",".join(profiles)
    return tree


def resolve_local_ai(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Add or remove the `localai` Compose profile based on the operator's choice.

    When `enable_local_ai` is None the call is a no-op — whatever was
    already written to COMPOSE_PROFILES on a prior run is preserved (sticky)."""
    if args.enable_local_ai is None:
        return tree
    root = tree.setdefault("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    profiles = [p for p in profiles if p != "localai"]
    if args.enable_local_ai:
        profiles.append("localai")
    root["COMPOSE_PROFILES"] = ",".join(profiles)
    return tree


def resolve_reranker_model(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Write RERANKER_MODEL into ai/jinaai when the operator supplied a value.

    When reranker_model is None the call is a no-op — whatever was already
    written on a prior run is preserved (sticky)."""
    if args.reranker_model is None:
        return tree
    tree.setdefault("ai/jinaai", {})["RERANKER_MODEL"] = args.reranker_model
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
        "auth_provider": root.get("AUTH_PROVIDER", "internal_keycloak"),
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
