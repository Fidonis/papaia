from __future__ import annotations

from lib import common, envtree, secrets


def test_generate_missing_secrets_is_sticky(repo_root):
    # JWT_SECRET has no cross-file alias, so it's a clean stickiness check.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree["ai/librechat"]["JWT_SECRET"] = "already-customized"

    secrets.generate_missing_secrets(tree, seed)

    assert tree["ai/librechat"]["JWT_SECRET"] == "already-customized"
    assert not common.is_placeholder(tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"])


def test_generate_missing_secrets_alias_overwrites_drifted_value(repo_root):
    # A canonical secret's aliases are force-synced even if they'd drifted
    # to a different value -- this is what prevents the "stale copy
    # silently breaks OIDC" failure mode.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "stale-drifted-value"

    secrets.generate_missing_secrets(tree, seed)

    assert (
        tree[""]["OAUTH2_PROXY_CLIENT_SECRET"]
        == tree["infra/keycloak"]["KC_OAUTH2_PROXY_CLIENT_SECRET"]
    )
    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "stale-drifted-value"


def test_generate_missing_secrets_force_regenerates(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "already-customized"

    secrets.generate_missing_secrets(tree, seed, force=True)

    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "already-customized"


def test_generate_missing_secrets_fans_out_aliases(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    secrets.generate_missing_secrets(tree, seed)

    assert (
        tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"]
        == tree["ai/librechat"]["OPENID_CLIENT_SECRET"]
    )
    assert (
        tree["infra/keycloak"]["KC_LITELLM_CLIENT_SECRET"]
        == tree["ai/litellm"]["GENERIC_CLIENT_SECRET"]
    )
    assert (
        tree["infra/keycloak"]["KC_OAUTH2_PROXY_CLIENT_SECRET"]
        == tree[""]["OAUTH2_PROXY_CLIENT_SECRET"]
    )
    # LITELLM_MASTER_KEY fans out to two different files that both happen to
    # be named LITELLM_API_KEY -- this is exactly the case that rules out a
    # single flat key->value dict for the whole tree.
    assert tree["ai/litellm"]["LITELLM_MASTER_KEY"] == tree["ai/librechat"]["LITELLM_API_KEY"]
    assert tree["ai/litellm"]["LITELLM_MASTER_KEY"] == tree["ai/jinaai"]["LITELLM_API_KEY"]
    assert tree["ai/jinaai"]["JINAAI_RERANKER_API_KEY"] == tree["ai/librechat"]["JINA_API_KEY"]


def test_generate_missing_secrets_skips_keycloak_dir_for_external_oidc(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"

    secrets.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

    # infra/keycloak's own GENERATE_* placeholders are left untouched --
    # nothing consumes them once the bundled Keycloak isn't started.
    assert (
        tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"]
        == "GENERATE_KC_LIBRECHAT_CLIENT_SECRET"
    )
    assert tree["infra/keycloak"]["KC_LITELLM_CLIENT_SECRET"] == "GENERATE_KC_LITELLM_CLIENT_SECRET"
    assert (
        tree["infra/keycloak"]["KC_OAUTH2_PROXY_CLIENT_SECRET"]
        == "GENERATE_KC_OAUTH2_PROXY_CLIENT_SECRET"
    )
    # Other services' own secrets are still generated as normal.
    assert not common.is_placeholder(tree["ai/librechat"]["JWT_SECRET"])


def test_generate_missing_secrets_external_oidc_placeholder_for_kc_aliases(repo_root):
    # When the bundled Keycloak is skipped, every consumer variable whose
    # canonical is a KC_* secret must get the explicit placeholder rather than
    # a random generated value that silently breaks OIDC.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)

    secrets.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

    placeholder = secrets._EXTERNAL_SECRET_PLACEHOLDER
    assert tree["ai/librechat"]["OPENID_CLIENT_SECRET"] == placeholder
    assert tree["ai/litellm"]["GENERIC_CLIENT_SECRET"] == placeholder
    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] == placeholder
    # Non-KC-aliased secrets (JWT_SECRET, LITELLM_MASTER_KEY, …) are still
    # generated normally.
    assert not common.is_placeholder(tree["ai/librechat"]["JWT_SECRET"])
    assert not common.is_placeholder(tree["ai/litellm"]["LITELLM_MASTER_KEY"])


def test_generate_missing_secrets_external_oidc_preserves_operator_set_value(repo_root):
    # An operator who has already replaced the placeholder with a real secret
    # must not have that value overwritten on a subsequent sticky re-run.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree["ai/librechat"]["OPENID_CLIENT_SECRET"] = "real-operator-supplied-secret"

    secrets.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

    assert tree["ai/librechat"]["OPENID_CLIENT_SECRET"] == "real-operator-supplied-secret"


def test_generate_missing_secrets_external_oidc_force_resets_to_placeholder(repo_root):
    # --force on an external OIDC setup must reset KC-aliased consumer secrets
    # back to the placeholder (not to a random generated value, since the
    # operator must supply the real secret from their IdP).
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree["ai/librechat"]["OPENID_CLIENT_SECRET"] = "real-operator-supplied-secret"

    secrets.generate_missing_secrets(tree, seed, auth_provider="external_oidc", force=True)

    assert tree["ai/librechat"]["OPENID_CLIENT_SECRET"] == secrets._EXTERNAL_SECRET_PLACEHOLDER


def test_generate_missing_secrets_reads_auth_provider_from_tree_when_arg_omitted(repo_root):
    # Direct callers that don't pass auth_provider= explicitly still get
    # correct skip behavior purely from the tree's own on-disk AUTH_PROVIDER
    # value.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"

    secrets.generate_missing_secrets(tree, seed)

    assert (
        tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"]
        == "GENERATE_KC_LIBRECHAT_CLIENT_SECRET"
    )


def test_generate_missing_secrets_generates_keycloak_secrets_by_default(repo_root):
    # internal_keycloak (default / absent AUTH_PROVIDER) must remain
    # byte-for-byte unchanged from today.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    secrets.generate_missing_secrets(tree, seed)
    assert not common.is_placeholder(tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"])


def test_generate_missing_secrets_fills_creds_iv(repo_root):
    # CREDS_IV carries no SECRET/KEY/... substring, so the old key-name
    # heuristic skipped it entirely; the GENERATE_ marker now selects it and
    # its exact-length generator fills 16 bytes (32 hex chars).
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    assert tree["ai/librechat"]["CREDS_IV"] == "GENERATE_CREDS_IV"  # sanity

    secrets.generate_missing_secrets(tree, seed)

    iv = tree["ai/librechat"]["CREDS_IV"]
    assert not common.is_placeholder(iv)
    assert len(bytes.fromhex(iv)) == 16


def test_generate_missing_secrets_ignores_keys_without_generate_marker(repo_root):
    # A secret-*named* key whose seed value lacks the GENERATE_ marker is never
    # generated -- not even when empty (which is_placeholder would otherwise
    # flag) -- so shipped literals / third-party keys are left as delivered.
    tree = envtree.load_seed_tree(repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree["ai/librechat"]["EXTERNAL_API_KEY"] = ""
    seed["ai/librechat"]["EXTERNAL_API_KEY"] = ""
    tree["ai/librechat"]["STATIC_TOKEN"] = "keep-me"
    seed["ai/librechat"]["STATIC_TOKEN"] = "keep-me"

    secrets.generate_missing_secrets(tree, seed, force=True)

    assert tree["ai/librechat"]["EXTERNAL_API_KEY"] == ""
    assert tree["ai/librechat"]["STATIC_TOKEN"] == "keep-me"
