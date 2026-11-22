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
#
# Gen 2 (additive): `networks.app_network` may carry a
# `${PAPAIA_PROJECT:-papaia}-<name>-net` template that gen_override.py and
# `py_cli addon-networks` resolve against the rendered core .env, so add-on
# bridges are scoped per deployment. A plain literal still works, so `min`
# stays 1; add-ons that adopt the template declare `requires.addon_api: 2`.
#
# Gen 3 (additive): the mail relay `smtp-relay` (profile `smtp`) is a core service an
# add-on may list under `networks.attach` to send mail without holding the mail
# server's credentials. Nothing existing changed, so `min` stays 1; add-ons that
# attach it declare `requires.addon_api: 3`, and an older core reports them
# incompatible instead of failing on an unknown service.
#
# Gen 4 (additive): `requires.addons` names other add-ons an add-on builds on;
# install, start, upgrade and `addon check` refuse it while one of them is not
# active or too old. `networks.join_addons` lets listed services of an add-on
# join a required add-on's network. `exports` lists bundle keys an add-on lets
# others read, and `env_prompts.<key>.default_from_addon` fills a prompt from one.
# `actions` declares maintenance actions that `papaia-ctl addon run` executes.
# Manifests without these keys are unchanged, so `min` stays 1; add-ons that
# use them declare `requires.addon_api: 4`, and an older core reports
# them incompatible instead of ignoring the requirement.
#
# Gen 5 (additive): the voice profile's engines `speaches` and `chatterbox` are
# core services an add-on may list under `networks.attach`, and
# `ai/voice/chatterbox.yaml` is a render target add-ons may layer fragments
# onto. Nothing existing changed, so `min` stays 1; add-ons that attach the
# engines or layer that target declare `requires.addon_api: 5`.
#
# Gen 6 (additive): the `knowledge` manifest key (ADR 0014) lets an add-on declare
# the knowledge sources it contributes to the knowledge-map profile (ADR 0013).
# Older cores ignore the key, so `min` stays 1; add-ons that declare it include 6
# in `requires.addon_api` to document the dependency. Note the gate's any-match
# semantics: an add-on listing [2, 6] still installs on a gen-2..5 core (the 2
# matches), which is wanted here because the key is additive — a core below
# gen 6 simply renders no map entry for it.
#
# Gen 7 to 12 (additive) are fixed together as one binding table (ADDON_API_GENERATIONS
# below, mirrored in the comment table of the ADDON_API file). Each one adds a manifest
# key or an attachable seam and nothing existing changes, so `min` stays 1. Unlike
# gen 6, a manifest that uses a key of gen 7 or later is never silently accepted by a
# core below that generation: `addon check` reports it INCOMPATIBLE and names the
# missing generation, whatever `requires.addon_api` lists (GENERATION_FEATURES).
#
# Gen 7 (additive): `exposes:` (also `exposes.yaml` of core profiles), rendering of
# `services.json` and `groups.json`, declared roles, exchange scopes `aud-<addon>`,
# service accounts and `models.needs` inside `exposes`; `keycloak`, `litellm`,
# `papaia-audit` and `papaia-egress` attachable. ADR 0017 (contract), 0018 (identity).
#
# Gen 8 (additive): `personal_settings:`; `me-web` and `prefs` attachable. ADR 0020.
#
# Gen 9 (additive): `connections` attachable with a registry client. ADR 0021.
#
# Gen 10 (additive): install-time approval hook -- approval at install up to the
# highest declared class. ADR 0017 (addendum).
#
# Gen 11 (additive): `pki:` -- internal TLS under the `kritis` security profile.
# ADR 0019 (PKI), 0022 (security profile).
#
# Gen 12 (additive): add-on ingress `integration.nginx` as a list of entries
# `{host_key, service, port, websocket, max_body}`. The fragment path form of
# `integration.nginx` stays generation 1. ADR 0023 (ingress and delivery).
#
# Gen 13 (additive): `volumes[]` `{name, backup: include|exclude, reason}`; `backup` leaves
# an excluded volume out of every archive (BE-14, RE-05).
ADDON_API_WINDOW = (1, 13)

# The binding meaning of every generation the core serves. Changing a line here is a
# contract change, not a wording fix.
ADDON_API_GENERATIONS = {
    1: (
        "base contract: `networks.app_network`, `networks.attach`, `integration.<service>`"
        " fragments, Keycloak clients, `env_prompts`, `requires.addon_api`"
    ),
    2: "`networks.app_network` may be the `${PAPAIA_PROJECT:-papaia}-<name>-net` template",
    3: "`smtp-relay` (profile `smtp`) attachable",
    4: (
        "`requires.addons`, `networks.join_addons`, `exports`,"
        " `env_prompts.<key>.default_from_addon`, `actions`, LibreChat agents and prompts,"
        " managed Keycloak clients"
    ),
    5: (
        "`speaches` and `chatterbox` (profile `voice`) attachable, render target"
        " `ai/voice/chatterbox.yaml`"
    ),
    6: "`knowledge:` (ADR 0014)",
    7: (
        "`exposes:` (also `exposes.yaml` of core profiles), rendering of `services.json` and"
        " `groups.json`, declared roles, exchange scopes `aud-<addon>`, service accounts,"
        " `models.needs`; `keycloak`, `litellm`, `papaia-audit`, `papaia-egress` attachable"
        " (ADR 0017, 0018)"
    ),
    8: "`personal_settings:`; `me-web` and `prefs` attachable (ADR 0020)",
    9: "`connections` attachable, registry client (ADR 0021)",
    10: (
        "install-time approval hook: approval at install up to the highest declared class"
        " (ADR 0017 addendum)"
    ),
    11: "`pki:`, internal TLS under the `kritis` security profile (ADR 0019, 0022)",
    12: "add-on ingress `integration.nginx` (ADR 0023)",
    13: "`volumes[]` with `backup: include|exclude` and a reason, read by `backup`",
}

# Manifest keys whose use requires a core of at least this generation.
# `integration.nginx` counts only in its list form (ingress entries).
GENERATION_FEATURES = {
    "exposes": 7,
    "networks.egress": 7,
    "personal_settings": 8,
    "pki": 11,
    "integration.nginx": 12,
    "volumes": 13,
}

# Seam 1: core services an addon may attach to (and their profiles).
ATTACHABLE_SERVICES = {
    "chatterbox": ["voice"],
    "firecrawl": ["librechat-websearch"],
    "firecrawl-nuq-postgres": ["librechat-websearch"],
    "firecrawl-playwright-service": ["librechat-websearch"],
    "firecrawl-rabbitmq": ["librechat-websearch"],
    "firecrawl-redis": ["librechat-websearch"],
    "jina-reranker-api": ["librechat-websearch"],
    "keycloak": ["keycloak"],
    "knowledge-map-mcp": ["knowledge-map"],
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
    # Mein Bereich and the preference store (addon_api 8, ADR 0020). Add-ons attach
    # `prefs` or `me-web`; the database is on papaia-prefs-db-net with prefs alone
    # (compat.NEVER_ATTACHABLE).
    "me-web": ["me"],
    "nginx-proxy-manager": ["nginx"],
    "nginx-proxy-manager-auth": ["nginx"],
    "oauth2-proxy": ["oauth2-proxy"],
    # The audit store (always on). Sources deliver to papaia-audit; its database is on
    # papaia-audit-net only; no add-on may attach it or the one-shot schema step
    # (compat.NEVER_ATTACHABLE).
    "papaia-audit": ["audit"],
    "papaia-audit-db": ["audit"],
    "papaia-audit-schema": ["audit"],
    # The manager's Docker socket broker (docs/docker-gate.md); never attachable
    # (compat.NEVER_ATTACHABLE): its network holds the manager and the gate only.
    "papaia-docker-gate": ["manager"],
    "papaia-manager": ["manager"],
    # The single exit (always on). An add-on reaches it through `networks.egress`,
    # which joins it to the add-on's egress network; see lib/egress.py.
    "papaia-egress": ["egress"],
    # Account revocation (optional). Add-ons read its list from the volume
    # papaia-security-state; they do not attach to the service itself.
    "papaia-lifecycle": ["lifecycle"],
    "papaia-lifecycle-init": ["lifecycle"],
    # People lookup (optional, additive). Only `assist-gate` may call it (token audience
    # papaia-people); `networks.attach` is checked against the core's services, so an
    # older core refuses an add-on that attaches it.
    "papaia-people": ["people"],
    "prefs": ["me"],
    "prefs-db": ["me"],
    "qdrant": ["rag"],
    "qdrant-ingest": ["rag"],
    "qdrant-ingest-tika": ["rag"],
    "qdrant-mcp": ["rag"],
    "searxng": ["librechat-websearch"],
    "smtp-relay": ["smtp"],
    "speaches": ["voice"],
    "speaches-model-init": ["voice"],
}

# Seam 2: render targets addons may layer integration fragments onto.
#
# `services/homepage/config` is deliberately absent: the Homepage dashboard was
# superseded by papaia-manager and removed from the stack, which retires the
# Homepage seam with it. Updated as an additive-style snapshot change without an
# ADDON_API bump -- 1.0.0 is still an open milestone, so the contract generation
# is being finalised rather than broken for a released core.
BASE_RENDER_TARGETS = [
    "ai/librechat/librechat.yaml",
    "ai/litellm/config.yaml",
    "ai/litellm/prometheus.yml",
    "ai/localai/models.txt",
    "ai/localai/models",
    "ai/voice/chatterbox.yaml",
    "services/searxng/settings.yml",
    "infra/keycloak/keycloak.conf",
    "infra/keycloak/themes/papaia",
]

# Manifest keys the tools actually read from papaia-app.yaml. Reading a new
# key is additive; renaming or dropping one breaks shipped manifests.
# `version` and `components` are read by `addon upgrade`, `addon list` and
# `addon components` for display and for the delta between two versions; no
# gate decision depends on either.
# `networks.app_network` may be a literal name or, since addon_api 2, a
# `${PAPAIA_PROJECT:-papaia}-<name>-net` template resolved against the core .env
# (gen_override.resolve_app_network).
MANIFEST_KEYS = [
    "name",
    "version",
    "components",
    "networks.app_network",
    "networks.attach",
    "networks.join_addons",
    "local_ca_env",
    "env_prompts",
    "env_prompts.<key>.default_from_addon",
    "exports",
    "actions",
    "env_replace_secrets",
    "integration.keycloak.clients",
    "integration.keycloak.client_mappers",
    "integration.<service> (fragment paths)",
    "requires.addon_api",
    "requires.addons",
    "papaia_compat",
    # Display only: printed after the core's own steps in the install checklist. An older
    # core ignores the key and an add-on has nothing to gate on, so no ADDON_API bump.
    "install_notes",
    # Since addon_api 6: declares the knowledge sources an add-on contributes to the
    # knowledge-map profile (ADR 0014). Read by knowledge_map.collect_sources.
    "knowledge",
    # Since addon_api 7, 8, 11 and 12: read by compat.manifest_generation_features so that
    # a core below the generation reports the add-on instead of ignoring the key.
    "exposes",
    "personal_settings",
    "pki",
    "integration.nginx (ingress entries)",
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
        ("ai/rag", "QDRANT_MCP_EMBEDDING_API_KEY"),
        ("ai/rag", "QI_EMBEDDING_API_KEY"),
        ("ai/knowledge-map", "KM_EMBEDDING_API_KEY"),
    ],
    ("ai/jinaai", "JINAAI_RERANKER_API_KEY"): [("ai/librechat", "JINA_API_KEY")],
    ("ai/localai", "LOCALAI_API_KEY"): [("ai/litellm", "LOCALAI_API_KEY")],
    ("ai/voice", "VOICE_API_KEY"): [("ai/litellm", "VOICE_API_KEY")],
}


def test_addon_api_window_matches_snapshot():
    assert compat.resolve_addon_api_window(REPO) == ADDON_API_WINDOW, _SURFACE_CHANGED


def test_generation_table_matches_snapshot():
    assert compat.ADDON_API_GENERATIONS == ADDON_API_GENERATIONS, _SURFACE_CHANGED


def test_generation_table_covers_the_served_window():
    minimum, current = ADDON_API_WINDOW
    assert sorted(ADDON_API_GENERATIONS) == list(range(minimum, current + 1)), _SURFACE_CHANGED


def _addon_api_file_table() -> dict[int, str]:
    """The comment table of the ADDON_API file: `#   <n>  <meaning>` with the meaning
    continued on indented comment lines."""
    table: dict[int, str] = {}
    number = None
    in_table = False
    for raw in (REPO / "ADDON_API").read_text(encoding="utf-8").splitlines():
        if raw.startswith("# Generations"):
            in_table = True
            continue
        if not in_table:
            continue
        if not raw.startswith("#") or raw.strip() == "#":
            break
        head = raw[1:].split(maxsplit=1)
        if head and head[0].isdigit() and raw[1:].startswith("  "):
            number = int(head[0])
            table[number] = head[1].strip()
        elif number is not None:
            table[number] += " " + raw[1:].strip()
    return table


def test_addon_api_file_states_the_same_table():
    # The file operators read and the table the tools enforce must not drift apart.
    assert _addon_api_file_table() == ADDON_API_GENERATIONS, _SURFACE_CHANGED


def test_generation_features_match_snapshot():
    assert compat.GENERATION_FEATURES == GENERATION_FEATURES, _SURFACE_CHANGED
    for generation in GENERATION_FEATURES.values():
        assert generation in ADDON_API_GENERATIONS, _SURFACE_CHANGED


def test_attachable_services_match_snapshot():
    # Deliberately read from the checkout's real src/docker-compose.yml,
    # not from a test fixture -- only then does an actual service rename
    # (the seam break that has happened before) fail CI.
    services = compat.resolve_core_services(REPO)
    assert services == ATTACHABLE_SERVICES, _SURFACE_CHANGED


# Seam 2b (addon_api 4): directories under <addon>/integration/ an add-on drops
# LibreChat agents and prompts into, and where they are rendered.
LIBRECHAT_ADDON_CONTENT = {
    "agents": ("addon-agents", (".yaml", ".yml")),
    "prompts": ("addon-prompts", (".md", ".markdown")),
}


def test_librechat_addon_content_matches_snapshot():
    assert render_core.LIBRECHAT_ADDON_CONTENT == LIBRECHAT_ADDON_CONTENT, _SURFACE_CHANGED


def test_base_render_targets_match_snapshot():
    assert render_core.BASE_RENDER_TARGETS == BASE_RENDER_TARGETS, _SURFACE_CHANGED


def test_secret_aliases_match_snapshot():
    assert secrets.SECRET_ALIASES == SECRET_ALIASES, _SURFACE_CHANGED


def test_manifest_keys_are_declared():
    # No mechanical source for "keys the code reads" exists; this list is
    # the reviewed declaration. Touching manifest handling means touching
    # this file -- which is exactly the reminder it is here to produce.
    assert len(MANIFEST_KEYS) == 24, _SURFACE_CHANGED
