from __future__ import annotations

import re
from pathlib import Path

import pytest

from lib import bootstrap, common, semver


def test_resolve_platform_version_prefers_version_file(repo_root):
    # The fixture ships VERSION=0.8.0 next to a CHANGELOG whose first
    # released header is 0.7.0 -- the VERSION file must win.
    assert bootstrap.resolve_platform_version(repo_root) == "0.8.0"


def test_resolve_platform_version_falls_back_to_changelog(repo_root):
    (repo_root / "VERSION").unlink()
    assert bootstrap.resolve_platform_version(repo_root) == "0.7.0"


def test_resolve_platform_version_ignores_malformed_version_file(repo_root):
    (repo_root / "VERSION").write_text("not-a-version\n", encoding="utf-8")
    assert bootstrap.resolve_platform_version(repo_root) == "0.7.0"


def test_resolve_platform_version_falls_back_without_changelog(tmp_path):
    assert bootstrap.resolve_platform_version(tmp_path) == "0.0.0-dev"


def test_version_file_not_behind_changelog():
    # Consistency guard for the real checkout: the manually-bumped VERSION
    # file must never fall behind the newest released CHANGELOG header.
    repo = Path(__file__).resolve().parents[2]
    version_text = (repo / "VERSION").read_text(encoding="utf-8").strip()
    match = re.search(
        r"^## \[(\d+\.\d+\.\d+)\]",
        (repo / "CHANGELOG.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        pytest.skip("CHANGELOG.md has no released section yet")
    assert semver.compare(version_text, match.group(1)) >= 0


def test_stamp_platform_version_populates_papaia_version(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_VERSION"] == ""
    bootstrap.stamp_platform_version(tree, repo_root)
    assert tree[""]["PAPAIA_VERSION"] == "0.8.0"


def test_stamp_config_dir_populates_papaia_config_dir(repo_root, config_dir):
    tree = bootstrap.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_CONFIG_DIR"] != str(config_dir)
    bootstrap.stamp_config_dir(tree, config_dir)
    assert tree[""]["PAPAIA_CONFIG_DIR"] == str(config_dir)


def test_init_seeds_config_dir_without_touching_repo_tree(repo_root, config_dir):
    src_files_before = sorted(
        p.relative_to(repo_root) for p in (repo_root / "src").rglob("*") if p.is_file()
    )

    bootstrap.init(config_dir, repo_root, env_name="papaia")

    assert (config_dir / ".env").is_file()
    assert (config_dir / "deployment.yaml").is_file()
    assert (config_dir / "overlay").is_dir()
    assert (config_dir / "overrides").is_dir()
    assert (config_dir / "infra" / "keycloak" / ".env").is_file()

    src_files_after = sorted(
        p.relative_to(repo_root) for p in (repo_root / "src").rglob("*") if p.is_file()
    )
    assert src_files_before == src_files_after


def test_init_is_idempotent_without_force(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    (config_dir / ".env").write_text("CUSTOM=1\n", encoding="utf-8")
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    assert (config_dir / ".env").read_text(encoding="utf-8") == "CUSTOM=1\n"


def test_init_force_reseeds(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    (config_dir / ".env").write_text("CUSTOM=1\n", encoding="utf-8")
    bootstrap.init(config_dir, repo_root, env_name="papaia", force=True)
    assert "CUSTOM=1" not in (config_dir / ".env").read_text(encoding="utf-8")


def test_generate_missing_secrets_is_sticky(repo_root):
    # JWT_SECRET has no cross-file alias, so it's a clean stickiness check.
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree["ai/librechat"]["JWT_SECRET"] = "already-customized"

    bootstrap.generate_missing_secrets(tree, seed)

    assert tree["ai/librechat"]["JWT_SECRET"] == "already-customized"
    assert not common.is_placeholder(tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"])


def test_generate_missing_secrets_alias_overwrites_drifted_value(repo_root):
    # A canonical secret's aliases are force-synced even if they'd drifted
    # to a different value -- this is what prevents the "stale copy
    # silently breaks OIDC" failure mode.
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "stale-drifted-value"

    bootstrap.generate_missing_secrets(tree, seed)

    assert (
        tree[""]["OAUTH2_PROXY_CLIENT_SECRET"]
        == tree["infra/keycloak"]["KC_OAUTH2_PROXY_CLIENT_SECRET"]
    )
    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "stale-drifted-value"


def test_generate_missing_secrets_force_regenerates(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "already-customized"

    bootstrap.generate_missing_secrets(tree, seed, force=True)

    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "already-customized"


def test_generate_missing_secrets_fans_out_aliases(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    bootstrap.generate_missing_secrets(tree, seed)

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
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"

    bootstrap.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

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
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)

    bootstrap.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

    placeholder = bootstrap._EXTERNAL_SECRET_PLACEHOLDER
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
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree["ai/librechat"]["OPENID_CLIENT_SECRET"] = "real-operator-supplied-secret"

    bootstrap.generate_missing_secrets(tree, seed, auth_provider="external_oidc")

    assert tree["ai/librechat"]["OPENID_CLIENT_SECRET"] == "real-operator-supplied-secret"


def test_generate_missing_secrets_external_oidc_force_resets_to_placeholder(repo_root):
    # --force on an external OIDC setup must reset KC-aliased consumer secrets
    # back to the placeholder (not to a random generated value, since the
    # operator must supply the real secret from their IdP).
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree["ai/librechat"]["OPENID_CLIENT_SECRET"] = "real-operator-supplied-secret"

    bootstrap.generate_missing_secrets(tree, seed, auth_provider="external_oidc", force=True)

    assert tree["ai/librechat"]["OPENID_CLIENT_SECRET"] == bootstrap._EXTERNAL_SECRET_PLACEHOLDER


def test_generate_missing_secrets_reads_auth_provider_from_tree_when_arg_omitted(repo_root):
    # Direct callers that don't pass auth_provider= explicitly still get
    # correct skip behavior purely from the tree's own on-disk AUTH_PROVIDER
    # value.
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"

    bootstrap.generate_missing_secrets(tree, seed)

    assert (
        tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"]
        == "GENERATE_KC_LIBRECHAT_CLIENT_SECRET"
    )


def test_generate_missing_secrets_generates_keycloak_secrets_by_default(repo_root):
    # internal_keycloak (default / absent AUTH_PROVIDER) must remain
    # byte-for-byte unchanged from today.
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    bootstrap.generate_missing_secrets(tree, seed)
    assert not common.is_placeholder(tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"])


def test_generate_missing_secrets_fills_creds_iv(repo_root):
    # CREDS_IV carries no SECRET/KEY/... substring, so the old key-name
    # heuristic skipped it entirely; the GENERATE_ marker now selects it and
    # its exact-length generator fills 16 bytes (32 hex chars).
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    assert tree["ai/librechat"]["CREDS_IV"] == "GENERATE_CREDS_IV"  # sanity

    bootstrap.generate_missing_secrets(tree, seed)

    iv = tree["ai/librechat"]["CREDS_IV"]
    assert not common.is_placeholder(iv)
    assert len(bytes.fromhex(iv)) == 16


def test_generate_missing_secrets_ignores_keys_without_generate_marker(repo_root):
    # A secret-*named* key whose seed value lacks the GENERATE_ marker is never
    # generated -- not even when empty (which is_placeholder would otherwise
    # flag) -- so shipped literals / third-party keys are left as delivered.
    tree = bootstrap.load_seed_tree(repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree["ai/librechat"]["EXTERNAL_API_KEY"] = ""
    seed["ai/librechat"]["EXTERNAL_API_KEY"] = ""
    tree["ai/librechat"]["STATIC_TOKEN"] = "keep-me"
    seed["ai/librechat"]["STATIC_TOKEN"] = "keep-me"

    bootstrap.generate_missing_secrets(tree, seed, force=True)

    assert tree["ai/librechat"]["EXTERNAL_API_KEY"] == ""
    assert tree["ai/librechat"]["STATIC_TOKEN"] == "keep-me"


@pytest.mark.parametrize(
    "app_host,expected",
    [
        # Local hostnames always resolve to https because Keycloak now terminates
        # TLS natively and the locally-generated CA cert covers these SANs.
        ("http://host.docker.internal", "https://host.docker.internal:8110"),
        ("http://localhost", "https://localhost:8110"),
        ("http://192.168.1.50", "https://192.168.1.50:8110"),
        # FQDNs keep the scheme from app_host (operator supplies the cert).
        ("https://papaia.example.com", "https://auth.papaia.example.com"),
    ],
)
def test_derive_auth_host_default(app_host, expected):
    assert bootstrap.derive_auth_host_default(app_host, "8110") == expected


@pytest.mark.parametrize(
    "app_host,expected",
    [
        # host.docker.internal over plain HTTP -> localhost (LibreChat's
        # Secure-cookie logic drops the OIDC session cookie otherwise).
        ("http://host.docker.internal", "http://localhost:8000"),
        # Everything else keeps the app host, with the LibreChat port appended.
        ("http://localhost", "http://localhost:8000"),
        ("http://192.168.1.50", "http://192.168.1.50:8000"),
        ("https://papaia.example.com", "https://papaia.example.com:8000"),
        # https on host.docker.internal is a Secure context -> no rewrite.
        ("https://host.docker.internal", "https://host.docker.internal:8000"),
    ],
)
def test_derive_librechat_url_default(app_host, expected):
    assert bootstrap.derive_librechat_url_default(app_host, "8000") == expected


def test_resolve_hostnames_librechat_host_arg_wins(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        librechat_host="https://chat.example.com",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://chat.example.com"
    assert tree["ai/librechat"]["DOMAIN_CLIENT"] == "https://chat.example.com"


def test_resolve_hostnames_librechat_default_prefers_localhost(repo_root):
    # No arg, interactive prompt returns the default -> host.docker.internal
    # becomes localhost so LibreChat's OIDC cookie survives plain HTTP.
    tree = bootstrap.load_seed_tree(repo_root)
    captured = {}

    def fake_prompt(message, default):
        captured[message] = default
        return default

    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        prompt=fake_prompt,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:8000"
    assert captured["Public URL of LibreChat (DOMAIN_SERVER)"] == "http://localhost:8000"


def test_resolve_hostnames_librechat_prompt_answer_used(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)

    def fake_prompt(message, default):
        if message.startswith("Public URL of LibreChat"):
            return "http://localhost:9999"
        return default

    args = bootstrap.SetupArgs(
        config_dir=repo_root, app_host="http://host.docker.internal", prompt=fake_prompt
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:9999"


def test_resolve_hostnames_librechat_sticky_reused_when_not_fresh(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree["ai/librechat"]["DOMAIN_SERVER"] = "http://prior-run.example.com:8000"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=False,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://prior-run.example.com:8000"


def test_resolve_hostnames_derives_oidc_and_domain_vars(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root, app_host="https://papaia.example.com", non_interactive=True
    )

    tree = bootstrap.resolve_hostnames(tree, args)

    assert tree[""]["PAPAIA_HOST"] == "https://papaia.example.com"
    assert tree[""]["AUTH_HOST"] == "https://auth.papaia.example.com"
    assert tree["infra/keycloak"]["KC_HOSTNAME"] == "https://auth.papaia.example.com"
    assert tree[""]["OIDC_ISSUER"] == "https://auth.papaia.example.com/realms/papaia"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://papaia.example.com:8000"
    assert (
        tree["ai/litellm"]["GENERIC_REDIRECT_URI"] == "https://papaia.example.com:8200/sso/callback"
    )
    assert tree[""]["HOMEPAGE_PUBLIC_URL"] == "https://papaia.example.com:8300"
    assert tree[""]["LOCALAI_PUBLIC_URL"] == "https://papaia.example.com:8080"
    assert tree[""]["OAUTH2_PROXY_COOKIE_SECURE"] == "true"
    # internal Docker DNS endpoints use https because Keycloak now terminates
    # TLS natively (port 8443); they must never be derived from the public host
    assert (
        tree[""]["OIDC_ISSUER_KC_TOKEN"]
        == "https://keycloak:8443/realms/papaia/protocol/openid-connect/token"
    )
    # TRUST_PROXY is a static value bootstrap.py must never touch
    assert tree["ai/librechat"]["TRUST_PROXY"] == "1"


def test_resolve_hostnames_cookie_secure_false_for_plain_http(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["OAUTH2_PROXY_COOKIE_SECURE"] == "false"


def test_resolve_hostnames_raises_without_app_host_non_interactive(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = ""
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=False)
    with pytest.raises(bootstrap.SetupError):
        bootstrap.resolve_hostnames(tree, args)


def test_resolve_hostnames_raises_on_fresh_init_even_with_seeded_example_default(repo_root):
    # Regression test: a *fresh* config dir's tree is seeded straight from
    # .env.example, whose PAPAIA_HOST already holds a real-looking
    # illustrative default (http://host.docker.internal) rather than an
    # empty/GENERATE_* placeholder. Without the fresh_init guard, that
    # shipped example value was silently treated as a genuine sticky value
    # from a prior run, bypassing --app-host validation entirely.
    tree = bootstrap.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_HOST"] == "http://host.docker.internal"  # sanity: not empty/placeholder
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=True)
    with pytest.raises(bootstrap.SetupError):
        bootstrap.resolve_hostnames(tree, args)


def test_resolve_hostnames_reuses_sticky_value_when_not_fresh(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://prior-run.example.com"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=False)
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["PAPAIA_HOST"] == "https://prior-run.example.com"


def test_resolve_hostnames_skips_external_oidc(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    args = bootstrap.SetupArgs(
        config_dir=repo_root, app_host="https://papaia.example.com", non_interactive=True
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"


def test_resolve_hostnames_external_oidc_first_time_prompts_for_issuer(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    prompts = []

    def fake_prompt(message, default):
        # Message-aware: the issuer and the LibreChat URL are distinct prompts,
        # so returning the issuer for both would mask a mis-wired DOMAIN_SERVER.
        prompts.append(message)
        if "issuer" in message.lower():
            return "https://idp.customer.com/realms/foo"
        return default

    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        prompt=fake_prompt,
    )
    tree = bootstrap.resolve_hostnames(tree, args)

    assert tree[""]["AUTH_PROVIDER"] == "external_oidc"
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"
    assert tree["ai/librechat"]["OPENID_ISSUER"] == "https://idp.customer.com/realms/foo"
    assert any("issuer" in m.lower() for m in prompts)
    # LibreChat is provider-independent: its URL is prompted and resolved even
    # under external OIDC (derived default kept here).
    assert any("librechat" in m.lower() for m in prompts)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://papaia.example.com:8000"
    # AUTH_HOST is Keycloak-specific and meaningless without the bundled
    # Keycloak -- left untouched (still the seed default).
    assert tree[""]["AUTH_HOST"] == "http://host.docker.internal:8110"


def test_resolve_hostnames_external_oidc_first_time_non_interactive_requires_issuer(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        non_interactive=True,
    )
    with pytest.raises(bootstrap.SetupError):
        bootstrap.resolve_hostnames(tree, args)


def test_resolve_hostnames_external_oidc_first_time_non_interactive_with_flag_succeeds(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"
    assert tree[""]["AUTH_PROVIDER"] == "external_oidc"


def test_resolve_hostnames_external_oidc_resolves_librechat_domain(repo_root):
    # DOMAIN_SERVER/DOMAIN_CLIENT are resolved for external OIDC too: derived
    # by default, and overridable via --librechat-host.
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:8000"
    assert tree["ai/librechat"]["DOMAIN_CLIENT"] == "http://localhost:8000"

    tree2 = bootstrap.load_seed_tree(repo_root)
    args2 = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        librechat_host="https://chat.example.com",
        non_interactive=True,
    )
    tree2 = bootstrap.resolve_hostnames(tree2, args2)
    assert tree2["ai/librechat"]["DOMAIN_SERVER"] == "https://chat.example.com"


def test_resolve_hostnames_sticky_external_oidc_with_flag_still_preserved(repo_root):
    # Re-passing --auth-provider=external_oidc on a sticky re-run (not just
    # omitting the flag) must still never clobber the existing issuer --
    # confirms the guard checks the tree's prior state, not just whether
    # args.auth_provider happens to be unset.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"


def test_resolve_hostnames_external_oidc_derives_litellm_endpoints(repo_root):
    # LiteLLM OIDC endpoints must be derived from the external issuer URL, not
    # left at the bundled-Keycloak seed values (keycloak:8443 / host.docker…).
    issuer = "https://idp.customer.com/realms/foo"
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        oidc_issuer=issuer,
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)

    assert tree["ai/litellm"]["GENERIC_AUTHORIZATION_ENDPOINT"] == (
        f"{issuer}/protocol/openid-connect/auth"
    )
    assert tree["ai/litellm"]["GENERIC_TOKEN_ENDPOINT"] == (
        f"{issuer}/protocol/openid-connect/token"
    )
    assert tree["ai/litellm"]["GENERIC_USERINFO_ENDPOINT"] == (
        f"{issuer}/protocol/openid-connect/userinfo"
    )
    assert tree["ai/litellm"]["GENERIC_REDIRECT_URI"] == (
        "https://papaia.example.com:8200/sso/callback"
    )
    assert "idp.customer.com" in tree["ai/litellm"]["PROXY_LOGOUT_URL"]
    # Bundled-Keycloak internals must not appear in any of these values
    assert "keycloak:8443" not in tree["ai/litellm"]["GENERIC_TOKEN_ENDPOINT"]
    assert "keycloak:8443" not in tree["ai/litellm"]["GENERIC_USERINFO_ENDPOINT"]


def test_resolve_hostnames_internal_keycloak_explicit_matches_default(repo_root):
    # Explicitly requesting internal_keycloak (e.g. via --auth-provider=
    # internal_keycloak) must be byte-for-byte identical to omitting the
    # flag entirely.
    tree_explicit = bootstrap.load_seed_tree(repo_root)
    tree_omitted = bootstrap.load_seed_tree(repo_root)
    args_explicit = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="internal_keycloak",
        non_interactive=True,
    )
    args_omitted = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        non_interactive=True,
    )
    tree_explicit = bootstrap.resolve_hostnames(tree_explicit, args_explicit)
    tree_omitted = bootstrap.resolve_hostnames(tree_omitted, args_omitted)
    assert tree_explicit == tree_omitted


def test_resolve_multi_env_default_identity_unchanged(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(config_dir=repo_root, env_name="papaia")
    tree = bootstrap.resolve_multi_env(tree, args)
    assert tree[""]["COMPOSE_PROJECT_NAME"] == "papaia"
    assert tree[""]["DOCKER_NETWORK"] == "papaia-net"


def test_resolve_multi_env_named_env(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(config_dir=repo_root, env_name="stage", host_ip="10.0.0.5")
    tree = bootstrap.resolve_multi_env(tree, args)
    assert tree[""]["COMPOSE_PROJECT_NAME"] == "papaia-stage"
    assert tree[""]["DOCKER_NETWORK"] == "papaia-stage-net"
    assert tree[""]["HOST_IP"] == "10.0.0.5"


def test_resolve_reverse_proxy_excludes_nginx_when_external(repo_root):
    # Explicit provider choice wins regardless of PAPAIA_HOST scheme.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="external_proxy",
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "nginx" not in profiles


def test_resolve_reverse_proxy_includes_nginx_by_default_on_http(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_accidental_no_proxy_state(repo_root):
    # external_reverse_proxy=False without allow_direct_port_access must
    # always fall back to bundling nginx -- there is no flag combination
    # that accidentally leaves the stack with no proxy in front of it.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
        allow_direct_port_access=False,
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_allow_direct_port_access_excludes_nginx_non_interactive(repo_root):
    # The flag itself is the authorization in non-interactive mode -- no
    # confirmation prompt, no error.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
        allow_direct_port_access=True,
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_allow_direct_port_access_interactive_confirm(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        external_reverse_proxy=False,
        allow_direct_port_access=True,
        confirm=lambda _msg, _default: False,
    )
    with pytest.raises(bootstrap.SetupError):
        bootstrap.resolve_reverse_proxy(tree, args)


def test_resolve_reverse_proxy_excludes_keycloak_when_external_oidc(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "keycloak" not in profiles
    # oauth2-proxy / librechat / litellm still bundled as usual.
    assert "oauth2-proxy" in profiles


def test_resolve_reverse_proxy_includes_keycloak_by_default(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    # AUTH_PROVIDER absent -> defaults to internal_keycloak.
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "keycloak" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_external_skips_direct_access_confirmation(repo_root):
    # external_reverse_proxy=True means the operator vouches for an edge
    # proxy elsewhere -- never treated as "no proxy anywhere", even on
    # plain HTTP, so no confirmation should be triggered.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        external_reverse_proxy=True,
        confirm=lambda _msg, _default: (_ for _ in ()).throw(
            AssertionError("should not be called")
        ),
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_stores_provider_in_tree(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_external_proxy_provider_excludes_nginx(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="external_proxy",
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_sticky_reused_when_arg_absent(repo_root):
    # A value stored from a prior run is reused when no explicit arg is given.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_arg_wins_over_sticky(repo_root):
    # An explicit --reverse-proxy-provider flag overrides the stored sticky value.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_legacy_bool_flag_translates_to_provider(repo_root):
    # The old --external-reverse-proxy flag is preserved as an alias.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=True,
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_legacy_bool_false_translates_to_internal(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"  # prior sticky
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_arg_wins_over_legacy_bool(repo_root):
    # New-style --reverse-proxy-provider takes precedence over legacy bool flag.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
        external_reverse_proxy=True,  # conflicting legacy flag — new style wins
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_migrates_from_profile_only_state(repo_root):
    # Existing installs that have nginx in COMPOSE_PROFILES but no
    # REVERSE_PROXY_PROVIDER are migrated to internal_nginx automatically.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm,nginx"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_autodetects_external_on_https_first_run(repo_root):
    # First run with no stored value and no nginx in profiles: HTTPS host auto-detects external_proxy.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    # Clear nginx from profiles too so the migration path doesn't set internal_nginx
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_autodetects_internal_on_http_first_run(repo_root):
    # First run with no stored value and no nginx in profiles: HTTP host auto-detects internal_nginx.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_derive_npm_admin_host_default_rewrites_docker_internal_to_localhost(repo_root):
    # Plain-HTTP host.docker.internal → localhost so the oauth2-proxy CSRF
    # cookie is scoped to the same origin the browser uses.
    result = bootstrap.derive_npm_admin_host_default("http://host.docker.internal", "8100")
    assert result == "http://localhost:8100"


def test_derive_npm_admin_host_default_keeps_https_docker_internal(repo_root):
    result = bootstrap.derive_npm_admin_host_default("https://host.docker.internal", "8100")
    assert result == "https://host.docker.internal:8100"


def test_derive_npm_admin_host_default_keeps_fqdn(repo_root):
    result = bootstrap.derive_npm_admin_host_default("https://proxy.example.com", "8100")
    assert result == "https://proxy.example.com:8100"


def test_resolve_hostnames_npm_admin_host_derived_from_app_host(repo_root):
    # host.docker.internal over plain HTTP is rewritten to localhost
    # (same pattern as derive_librechat_url_default).
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "http://localhost:8100"


def test_resolve_hostnames_npm_admin_host_arg_wins(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        npm_admin_host="https://proxy-admin.example.com",
        non_interactive=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "https://proxy-admin.example.com"


def test_resolve_hostnames_npm_admin_host_sticky_reused_when_not_fresh(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["NPM_ADMIN_HOST"] = "https://prior-npm.example.com"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=False,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "https://prior-npm.example.com"


def test_resolve_hostnames_npm_admin_host_fresh_init_uses_derived(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["NPM_ADMIN_HOST"] = "https://prior-npm.example.com"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=True,
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    # host.docker.internal over plain HTTP is rewritten to localhost
    assert tree[""]["NPM_ADMIN_HOST"] == "http://localhost:8100"


def test_resolve_reverse_proxy_no_proxy_excludes_nginx(repo_root):
    # Explicit no_proxy choice removes the nginx profile, same as external_proxy.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="no_proxy",
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "no_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_proxy_skips_confirmation(repo_root):
    # no_proxy is an explicit operator choice — the "no proxy and no TLS"
    # confirmation prompt must never fire (unlike allow_direct_port_access).
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        reverse_proxy_provider="no_proxy",
        confirm=lambda _msg, _default: (_ for _ in ()).throw(
            AssertionError("confirmation prompt must not be called for no_proxy")
        ),
    )
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_proxy_sticky_reused(repo_root):
    # A stored no_proxy value is reused on a re-run without an explicit arg.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "no_proxy"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "no_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_web_search_adds_unified_profile_when_enabled(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm,nginx"
    args = bootstrap.SetupArgs(config_dir=repo_root, enable_web_search=True)
    tree = bootstrap.resolve_web_search(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" in profiles
    assert "searxng" not in profiles
    assert "firecrawl" not in profiles
    assert "jinaai" not in profiles


def test_resolve_web_search_removes_unified_profile_when_disabled(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm,nginx,librechat-websearch"
    args = bootstrap.SetupArgs(config_dir=repo_root, enable_web_search=False)
    tree = bootstrap.resolve_web_search(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" not in profiles


def test_resolve_web_search_preserves_profiles_when_sticky(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    original = "keycloak,oauth2-proxy,librechat,litellm,nginx,librechat-websearch"
    tree[""]["COMPOSE_PROFILES"] = original
    args = bootstrap.SetupArgs(config_dir=repo_root, enable_web_search=None)
    tree = bootstrap.resolve_web_search(tree, args)
    assert tree[""]["COMPOSE_PROFILES"] == original


def test_migrate_web_search_profiles_replaces_legacy_names(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,nginx,searxng,firecrawl,jinaai,librechat"
    tree = bootstrap.migrate_web_search_profiles(tree)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" in profiles
    assert "searxng" not in profiles
    assert "firecrawl" not in profiles
    assert "jinaai" not in profiles


def test_migrate_web_search_profiles_noop_when_already_migrated(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    original = "keycloak,nginx,librechat-websearch,librechat"
    tree[""]["COMPOSE_PROFILES"] = original
    tree = bootstrap.migrate_web_search_profiles(tree)
    assert tree[""]["COMPOSE_PROFILES"] == original


def test_resolve_reranker_model_writes_value(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    args = bootstrap.SetupArgs(
        config_dir=repo_root,
        reranker_model="rerank/jina-reranker-v2-base-multilingual",
    )
    tree = bootstrap.resolve_reranker_model(tree, args)
    assert tree["ai/jinaai"]["RERANKER_MODEL"] == "rerank/jina-reranker-v2-base-multilingual"


def test_resolve_reranker_model_sticky_when_none(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree.setdefault("ai/jinaai", {})["RERANKER_MODEL"] = "existing-model"
    args = bootstrap.SetupArgs(config_dir=repo_root, reranker_model=None)
    tree = bootstrap.resolve_reranker_model(tree, args)
    assert tree["ai/jinaai"]["RERANKER_MODEL"] == "existing-model"


def test_persist_tree_writes_both_locations(repo_root, config_dir):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"

    bootstrap.persist_tree(tree, config_dir, repo_root)

    assert (config_dir / ".env").is_file()
    assert (repo_root / "src" / ".env").is_file()
    assert "PAPAIA_HOST=https://papaia.example.com" in (repo_root / "src" / ".env").read_text(
        encoding="utf-8"
    )
    assert "PAPAIA_HOST=https://papaia.example.com" in (config_dir / ".env").read_text(
        encoding="utf-8"
    )


# ── materialize_core_env ──────────────────────────────────────────────────────


def test_materialize_core_env_copies_bundle_to_checkout(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    # Write a distinctive value into the config bundle
    bundle_env = config_dir / ".env"
    bundle_env.write_text("PAPAIA_HOST=https://restored.example.com\n", encoding="utf-8")

    # Remove the checkout copy to simulate a git-clean scenario
    checkout_env = repo_root / "src" / ".env"
    checkout_env.unlink(missing_ok=True)
    assert not checkout_env.is_file()

    bootstrap.materialize_core_env(config_dir, repo_root)

    assert checkout_env.is_file()
    assert "PAPAIA_HOST=https://restored.example.com" in checkout_env.read_text(encoding="utf-8")


def test_materialize_core_env_matches_bundle_content(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    # Overwrite checkout with stale content
    checkout_env = repo_root / "src" / ".env"
    checkout_env.write_text("PAPAIA_HOST=stale\n", encoding="utf-8")
    bundle_env = config_dir / ".env"
    bundle_env.write_text("PAPAIA_HOST=fresh\n", encoding="utf-8")

    bootstrap.materialize_core_env(config_dir, repo_root)

    assert checkout_env.read_text(encoding="utf-8") == "PAPAIA_HOST=fresh\n"


def test_materialize_core_env_skips_missing_bundle_files(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    # Remove a bundle .env for a sub-directory — materialize must not crash
    keycloak_bundle = config_dir / "infra" / "keycloak" / ".env"
    keycloak_bundle.unlink(missing_ok=True)

    bootstrap.materialize_core_env(config_dir, repo_root)

    # Root .env should still be restored from its bundle copy
    assert (repo_root / "src" / ".env").is_file()
