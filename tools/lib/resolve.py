"""Setup resolution: hostnames, OIDC, reverse proxy, profiles.

The heart of `papaia-ctl setup`: every derive_*/resolve_*/migrate_* pass
takes the env tree plus the operator's SetupArgs and returns the tree with
one concern resolved. All passes honour the sticky-reuse contract -- a
value from a prior run is never clobbered unless the operator explicitly
overrides it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import common
from .envtree import EnvTree

_HOSTLIKE_NO_FQDN = {"localhost", "127.0.0.1", "host.docker.internal"}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class SetupError(Exception):
    """A user-facing, non-traceback-worthy setup failure."""


@dataclass
class SetupArgs:
    config_dir: Path
    env_name: str = "papaia"
    host_ip: str | None = None
    app_host: str | None = None
    auth_host: str | None = None
    librechat_host: str | None = None  # public LibreChat URL (DOMAIN_SERVER/DOMAIN_CLIENT)
    localai_host: str | None = None  # public LocalAI URL (LOCALAI_PUBLIC_URL)
    manager_host: str | None = None  # public papaia-manager URL (MANAGER_PUBLIC_URL)
    npm_admin_host: str | None = None  # public NPM admin URL (NPM_ADMIN_HOST)
    auth_provider: str | None = None  # None = unset/sticky; "internal_keycloak" | "external_oidc"
    oidc_issuer: str | None = None  # explicit external issuer; only used for external_oidc
    external_reverse_proxy: bool | None = None  # None = unset / auto-detect (legacy alias)
    # None = sticky; "internal_nginx" | "external_proxy" | "no_proxy"
    reverse_proxy_provider: str | None = None
    enable_web_search: bool | None = None  # None = sticky / no change
    enable_local_ai: bool | None = None  # None = sticky / no change
    enable_manager: bool | None = None  # None = sticky / no change
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


def derive_manager_url_default(app_host: str, manager_port: str) -> str:
    """Default browser-facing papaia-manager URL: the public host plus the external manager port."""
    return f"{app_host}:{manager_port}"


def derive_npm_admin_host_default(app_host: str, npm_admin_ext_port: str) -> str:
    """Default browser-facing NPM admin URL.

    Mirrors derive_librechat_url_default: plain-HTTP host.docker.internal is
    rewritten to localhost so the oauth2-proxy CSRF cookie is scoped to the
    same origin the browser uses. Without this, the callback from Keycloak
    (which uses the redirect_url hostname) doesn't match the origin that set
    the CSRF cookie, and browsers refuse to send it."""
    parts = urlsplit(app_host)
    host = app_host
    if parts.scheme == "http" and parts.hostname == "host.docker.internal":
        host = app_host.replace("host.docker.internal", "localhost", 1)
    return f"{host}:{npm_admin_ext_port}"


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
        # silently. AUTH_HOST / KC_HOSTNAME / KC_* split endpoints are
        # Keycloak-specific; they are left untouched since the bundled
        # Keycloak isn't started for this provider.
        root["OIDC_ISSUER"] = _resolve_external_oidc_issuer(args)
        librechat["OPENID_ISSUER"] = root["OIDC_ISSUER"]

        # Derive LiteLLM OIDC endpoints from the external issuer. The path
        # suffix (/protocol/openid-connect/*) follows RFC 8414 and matches
        # Keycloak and most other providers; operators using a non-standard path
        # layout can adjust these values manually after setup.
        issuer = root["OIDC_ISSUER"]
        litellm_port = root.get("LITELLM_EXT_PORT", "8200")
        litellm["GENERIC_AUTHORIZATION_ENDPOINT"] = (
            f"{issuer}/protocol/openid-connect/auth"
        )
        litellm["GENERIC_TOKEN_ENDPOINT"] = (
            f"{issuer}/protocol/openid-connect/token"
        )
        litellm["GENERIC_USERINFO_ENDPOINT"] = (
            f"{issuer}/protocol/openid-connect/userinfo"
        )
        litellm["GENERIC_REDIRECT_URI"] = f"{app_host}:{litellm_port}/sso/callback"
        litellm["PROXY_LOGOUT_URL"] = (
            f"{issuer}/protocol/openid-connect/logout"
            f"?client_id=litellm&post_logout_redirect_uri="
            f"{app_host}:{litellm_port}/sso/key/generate"
        )
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
        root["OIDC_AUTH_URL"] = f"{auth_host}/realms/papaia/protocol/openid-connect/auth"
        root["OIDC_TOKEN_URL"] = (
            "https://keycloak:8443/realms/papaia/protocol/openid-connect/token"
        )
        root["OIDC_JWKS_URL"] = (
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
        litellm["GENERIC_AUTHORIZATION_ENDPOINT"] = root["OIDC_AUTH_URL"]
        litellm["GENERIC_TOKEN_ENDPOINT"] = root["OIDC_TOKEN_URL"]
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
    # NOTE: LOCALAI_BASE_URL is intentionally NOT written to ai/localai/.env —
    # docker-compose.yml injects it via `environment: LOCALAI_BASE_URL: ${LOCALAI_PUBLIC_URL}`
    # (environment: wins over env_file:), so a per-service copy would be dead code
    # that misleads operators into editing the wrong file.
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

    # --- papaia-manager public URL ---
    # MANAGER_PUBLIC_URL is exposed in the root .env (consumed by docker compose
    # ${VAR} expansion in manager/docker-compose.yml). Always derived and stored
    # so the sticky value survives profile changes.
    manager_port = root.get("MANAGER_EXT_PORT", "8120")
    derived_manager = derive_manager_url_default(app_host, manager_port)
    sticky_manager = "" if args.fresh_init else root.get("MANAGER_PUBLIC_URL", "")
    if sticky_manager and common.is_placeholder(sticky_manager):
        sticky_manager = ""
    manager_url = args.manager_host or sticky_manager or derived_manager
    if not args.manager_host and not args.non_interactive and args.prompt is not None:
        manager_url = args.prompt(
            "Public URL of papaia-manager (MANAGER_PUBLIC_URL)",
            sticky_manager or derived_manager,
        )
    root["MANAGER_PUBLIC_URL"] = manager_url

    homepage = tree.setdefault("services/homepage", {})
    if "HP_ALLOWED_HOSTS" in homepage:
        homepage["HP_ALLOWED_HOSTS"] = f"{_strip_scheme(app_host)}:{homepage_port}"

    # --- NPM admin public URL ---
    # Always derived regardless of REVERSE_PROXY_PROVIDER: resolve_reverse_proxy
    # runs after resolve_hostnames and the value is only read by docker compose
    # when the nginx profile is active. Storing it unconditionally lets the
    # sticky value survive a temporary switch to external_proxy and back.
    npm_admin_port = root.get("NPM_ADMIN_EXT_PORT", "8100")
    derived_npm_admin = derive_npm_admin_host_default(app_host, npm_admin_port)
    sticky_npm_admin = "" if args.fresh_init else root.get("NPM_ADMIN_HOST", "")
    if sticky_npm_admin and common.is_placeholder(sticky_npm_admin):
        sticky_npm_admin = ""
    npm_admin_url = args.npm_admin_host or sticky_npm_admin or derived_npm_admin
    if not args.npm_admin_host and not args.non_interactive and args.prompt is not None:
        npm_admin_url = args.prompt(
            "Public URL of NPM admin UI (NPM_ADMIN_HOST)",
            sticky_npm_admin or derived_npm_admin,
        )
    root["NPM_ADMIN_HOST"] = npm_admin_url

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
    profile) is included, and persist the choice as REVERSE_PROXY_PROVIDER.

    Provider resolution order (highest wins):
      1. args.reverse_proxy_provider  — explicit new-style flag
      2. args.external_reverse_proxy  — legacy bool flag (translated to string)
      3. stored REVERSE_PROXY_PROVIDER in the current tree (sticky re-run)
      4. migration: derive from current COMPOSE_PROFILES when variable absent
      5. first-run auto-detect: HTTPS app/auth host → external_proxy, else → internal_nginx

    `nginx` is excluded for `external_proxy` (operator has their own proxy) and
    `no_proxy` (explicit direct-port-access choice), but never accidentally: the
    default is always `internal_nginx` when neither flag is given and no sticky
    value exists.
    """
    root = tree.setdefault("", {})
    app_host = root.get("PAPAIA_HOST", "")

    # --- Resolve effective provider ---
    prior_provider = root.get("REVERSE_PROXY_PROVIDER", "")

    # Migration: derive from COMPOSE_PROFILES for installs without the variable
    if not prior_provider:
        existing_profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
        if "nginx" in existing_profiles:
            prior_provider = "internal_nginx"

    if args.reverse_proxy_provider:
        provider = args.reverse_proxy_provider
    elif args.external_reverse_proxy is not None:
        provider = "external_proxy" if args.external_reverse_proxy else "internal_nginx"
    elif prior_provider:
        provider = prior_provider
    else:
        # First run, no stored value: auto-detect from URL scheme
        auth_host = root.get("AUTH_HOST", "")
        auto_external = _is_https(app_host) or _is_https(auth_host)
        provider = "external_proxy" if auto_external else "internal_nginx"

    root["REVERSE_PROXY_PROVIDER"] = provider
    # Both external_proxy and no_proxy exclude the bundled nginx profile.
    # no_proxy is an explicit operator choice, so unlike allow_direct_port_access
    # it never triggers the "no proxy and no TLS" confirmation prompt.
    external = provider in ("external_proxy", "no_proxy")

    # --- Profile manipulation ---
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    if not profiles:
        profiles = ["keycloak", "oauth2-proxy", "librechat", "litellm"]
    if root.get("AUTH_PROVIDER", "internal_keycloak") == "external_oidc":
        # Bundled Keycloak (+ its Postgres) is not started with an external IdP.
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


_WEB_SEARCH_PROFILE = "librechat-websearch"
_WEB_SEARCH_LEGACY_PROFILES = {"searxng", "firecrawl", "jinaai"}

# (dir, old_key) -> (dir, new_key). Renames and relocations of env keys that
# shipped in earlier releases. Values carry over; the old key is dropped.
_RENAMED_KEYS: dict[tuple[str, str], tuple[str, str]] = {
    # The KC_ infix wrongly implied these were Keycloak-only and collided
    # visually with the real KC_* vars in infra/keycloak/.env.
    ("", "OIDC_ISSUER_KC_AUTH"): ("", "OIDC_AUTH_URL"),
    ("", "OIDC_ISSUER_KC_TOKEN"): ("", "OIDC_TOKEN_URL"),
    ("", "OIDC_ISSUER_KC_CERTS"): ("", "OIDC_JWKS_URL"),
    # Single-consumer host paths: they belong to the service that reads them.
    ("", "LIBRECHAT_AGENTS_DIR"): ("ai/librechat", "LIBRECHAT_AGENTS_DIR"),
    ("", "LIBRECHAT_PROMPTS_DIR"): ("ai/librechat", "LIBRECHAT_PROMPTS_DIR"),
}

# (dir, key) pairs dropped outright -- nothing in the repo ever read them.
# Addon client secrets are included: addons register their own OIDC client and
# generate their own secret at install time, so the core value was never used.
_REMOVED_KEYS: set[tuple[str, str]] = {
    ("", "TIMEZONE"),
    ("", "OIDC_CLIENT_ID"),
    ("", "OIDC_ROLE_CLAIM"),
    ("", "OIDC_USERNAME_CLAIM"),
    ("", "OIDC_EMAIL_CLAIM"),
    ("", "LITELLM_EXT_PG_PORT"),
    ("", "LITELLM_EXT_PROMETHEUS_PORT"),
    ("", "JINAAI_EXT_PORT"),
    ("infra/keycloak", "KC_PAPERLESS_CLIENT_SECRET"),
    ("infra/keycloak", "KC_QDRANT_RAG_CLIENT_SECRET"),
}


def migrate_env_keys(tree: EnvTree) -> EnvTree:
    """Rename, relocate and drop env keys that changed shape between releases.

    Runs unconditionally on every `papaia-ctl setup` so an existing config
    bundle upgrades without operator action -- a no-op once migrated. A rename
    never clobbers an already-present destination: if both keys exist the newer
    one wins, since it is what the current code path writes."""
    for (old_dir, old_key), (new_dir, new_key) in _RENAMED_KEYS.items():
        source = tree.get(old_dir)
        if source is None or old_key not in source:
            continue
        value = source.pop(old_key)
        destination = tree.setdefault(new_dir, {})
        destination.setdefault(new_key, value)

    for rel_dir, key in _REMOVED_KEYS:
        values = tree.get(rel_dir)
        if values is not None:
            values.pop(key, None)

    return tree


def migrate_web_search_profiles(tree: EnvTree) -> EnvTree:
    """Replace legacy per-component web search profiles with the unified
    `librechat-websearch` profile.  Runs unconditionally so that existing
    config dirs are migrated transparently on the next `papaia-ctl setup`."""
    root = tree.setdefault("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    legacy_present = any(p in _WEB_SEARCH_LEGACY_PROFILES for p in profiles)
    if not legacy_present:
        return tree
    profiles = [p for p in profiles if p not in _WEB_SEARCH_LEGACY_PROFILES]
    if _WEB_SEARCH_PROFILE not in profiles:
        profiles.append(_WEB_SEARCH_PROFILE)
    root["COMPOSE_PROFILES"] = ",".join(profiles)
    return tree


def resolve_web_search(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Add or remove the `librechat-websearch` Compose profile based on the
    operator's web-search choice.

    When `enable_web_search` is None the call is a no-op — whatever was
    already written to COMPOSE_PROFILES on a prior run is preserved (sticky)."""
    if args.enable_web_search is None:
        return tree
    root = tree.setdefault("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    profiles = [
        p for p in profiles
        if p != _WEB_SEARCH_PROFILE and p not in _WEB_SEARCH_LEGACY_PROFILES
    ]
    if args.enable_web_search:
        profiles.append(_WEB_SEARCH_PROFILE)
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


def resolve_manager(tree: EnvTree, args: SetupArgs) -> EnvTree:
    """Add or remove the `manager` Compose profile based on the operator's choice.

    When `enable_manager` is None the call is a no-op — whatever was
    already written to COMPOSE_PROFILES on a prior run is preserved (sticky)."""
    if args.enable_manager is None:
        return tree
    root = tree.setdefault("", {})
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    profiles = [p for p in profiles if p != "manager"]
    if args.enable_manager:
        profiles.append("manager")
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
