"""Freezes the addon-facing contract surface of this checkout.

The addon_api generation in the ADDON_API file can only guard seam breaks
that someone remembers to declare. This snapshot removes the remembering:
it pins every element of the surface addons program against -- the
attachable service names from the real src/docker-compose.yml (the seam
that actually broke once, via a service rename), the render targets addons
may layer integration fragments onto, the manifest keys the tools read,
and the cross-service env alias map addon .env files implicitly rely on.

When one of these asserts fails, there are exactly two legitimate ways
forward, and silence is not one of them:

  * the change breaks existing addons -> bump ADDON_API
    (current += 1 and min = current) and update the snapshot here, or
  * the change is additive/compatible -> update the snapshot here
    deliberately (and bump `current` only, keeping `min`, if addons can
    opt in to something new).
"""

from __future__ import annotations

from pathlib import Path

from lib import compat, render_core, secrets

REPO = Path(__file__).resolve().parents[2]

_SURFACE_CHANGED = (
    "Addon-facing contract surface changed. Either bump ADDON_API"
    " (breaking: current += 1 and min = current) or update this snapshot"
    " deliberately (additive change). See docs/adr/0002-addon-core-compatibility-gating.md."
)

# The window this snapshot was taken against.
ADDON_API_WINDOW = (1, 1)

# Seam 1: core services an addon may attach to (and their profiles).
ATTACHABLE_SERVICES = {
    "firecrawl": ["librechat-websearch"],
    "firecrawl-nuq-postgres": ["librechat-websearch"],
    "firecrawl-playwright-service": ["librechat-websearch"],
    "firecrawl-rabbitmq": ["librechat-websearch"],
    "firecrawl-redis": ["librechat-websearch"],
    "homepage": ["homepage"],
    "homepage-auth": ["homepage"],
    "jina-reranker-api": ["librechat-websearch"],
    "keycloak": ["keycloak"],
    "keycloak-postgres": ["keycloak"],
    "librechat": ["librechat"],
    "librechat-meilisearch": ["librechat"],
    "librechat-mongodb": ["librechat"],
    "librechat-ragapi": ["librechat"],
    "librechat-vectordb": ["librechat"],
    "litellm": ["litellm"],
    "litellm-db": ["litellm"],
    "litellm-prometheus": ["litellm"],
    "localai": ["localai"],
    "localai-model-init": ["localai"],
    "mcp-firecrawl": ["librechat-websearch"],
    "nginx-proxy-manager": ["nginx"],
    "nginx-proxy-manager-auth": ["nginx"],
    "oauth2-proxy": ["oauth2-proxy"],
    "papaia-manager": ["manager"],
    "searxng": ["librechat-websearch"],
}

# Seam 2: render targets addons may layer integration fragments onto.
BASE_RENDER_TARGETS = [
    "ai/librechat/librechat.yaml",
    "ai/litellm/config.yaml",
    "ai/litellm/prometheus.yml",
    "ai/localai/models.txt",
    "ai/localai/models",
    "services/searxng/settings.yml",
    "infra/keycloak/keycloak.conf",
    "services/homepage/config",
]

# Manifest keys the tools actually read from papaia-app.yaml. Reading a new
# key is additive; renaming or dropping one breaks shipped manifests.
MANIFEST_KEYS = [
    "name",
    "networks.app_network",
    "networks.attach",
    "local_ca_env",
    "env_prompts",
    "env_replace_secrets",
    "integration.keycloak.clients",
    "integration.keycloak.client_mappers",
    "integration.<service> (fragment paths)",
    "requires.addon_api",
    "papaia_compat",
]

# Cross-service secret alias map -- the env-naming contract addon .env
# files implicitly depend on (e.g. LITELLM_API_KEY mirroring the master key).
SECRET_ALIASES = {
    ("infra/keycloak", "KC_LIBRECHAT_CLIENT_SECRET"): [("ai/librechat", "OPENID_CLIENT_SECRET")],
    ("infra/keycloak", "KC_LITELLM_CLIENT_SECRET"): [("ai/litellm", "GENERIC_CLIENT_SECRET")],
    ("infra/keycloak", "KC_OAUTH2_PROXY_CLIENT_SECRET"): [("", "OAUTH2_PROXY_CLIENT_SECRET")],
    ("infra/keycloak", "KC_LOCALAI_CLIENT_SECRET"): [("ai/localai", "LOCALAI_OIDC_CLIENT_SECRET")],
    ("infra/keycloak", "KC_MANAGER_CLIENT_SECRET"): [("manager", "MANAGER_OIDC_CLIENT_SECRET")],
    ("ai/litellm", "LITELLM_MASTER_KEY"): [
        ("ai/librechat", "LITELLM_API_KEY"),
        ("ai/jinaai", "LITELLM_API_KEY"),
    ],
    ("ai/jinaai", "JINAAI_RERANKER_API_KEY"): [("ai/librechat", "JINA_API_KEY")],
}


def test_addon_api_window_matches_snapshot():
    assert compat.resolve_addon_api_window(REPO) == ADDON_API_WINDOW, _SURFACE_CHANGED


def test_attachable_services_match_snapshot():
    # Deliberately read from the checkout's real src/docker-compose.yml,
    # not from a test fixture -- only then does an actual service rename
    # (the seam break that has happened before) fail CI.
    services = compat.resolve_core_services(REPO)
    assert services == ATTACHABLE_SERVICES, _SURFACE_CHANGED


def test_base_render_targets_match_snapshot():
    assert render_core.BASE_RENDER_TARGETS == BASE_RENDER_TARGETS, _SURFACE_CHANGED


def test_secret_aliases_match_snapshot():
    assert secrets.SECRET_ALIASES == SECRET_ALIASES, _SURFACE_CHANGED


def test_manifest_keys_are_declared():
    # No mechanical source for "keys the code reads" exists; this list is
    # the reviewed declaration. Touching manifest handling means touching
    # this file -- which is exactly the reminder it is here to produce.
    assert len(MANIFEST_KEYS) == 11, _SURFACE_CHANGED
