"""Secret generation over the env tree: sticky fill + cross-file aliasing.

Higher-level than common.py's secret primitives -- this module knows which
keys are secrets (via the seed's GENERATE_ marker) and which values must
stay identical across more than one service's .env file.
"""

from __future__ import annotations

from . import common
from .envtree import EnvTree

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

# Written to consumer secrets whose canonical lives in a skipped directory
# (e.g. KC_*_CLIENT_SECRET when external_oidc skips infra/keycloak). A
# recognisable string is better than a random hex value because a random value
# silently breaks OIDC while a placeholder makes the gap obvious.
_EXTERNAL_SECRET_PLACEHOLDER = "REPLACE_WITH_VALID_SECRET"


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

    # Consumer variables whose canonical lives in a skipped dir (e.g.
    # KC_*_CLIENT_SECRET when external_oidc skips infra/keycloak) must not be
    # auto-generated -- the operator must supply the real value from the external
    # provider. Track them here so the loop below can write a recognisable
    # placeholder instead of a random hex string that silently breaks OIDC.
    skip_generated: set[tuple[str, str]] = set()
    for (canon_dir, _), aliases in SECRET_ALIASES.items():
        if canon_dir in skip_dirs:
            skip_generated.update(aliases)

    for rel_dir, values in tree.items():
        if rel_dir in skip_dirs:
            continue
        seed_values = seed.get(rel_dir, {})
        for key, value in list(values.items()):
            if not common.marks_generated_secret(seed_values.get(key, "")):
                continue
            if (rel_dir, key) in skip_generated:
                if force or common.is_placeholder(value):
                    values[key] = _EXTERNAL_SECRET_PLACEHOLDER
            elif force or common.is_placeholder(value):
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
