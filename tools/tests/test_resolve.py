from __future__ import annotations

import pytest

from lib import envtree, resolve


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
    assert resolve.derive_auth_host_default(app_host, "8110") == expected


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
    assert resolve.derive_librechat_url_default(app_host, "8000") == expected


def test_resolve_hostnames_librechat_host_arg_wins(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        librechat_host="https://chat.example.com",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://chat.example.com"
    assert tree["ai/librechat"]["DOMAIN_CLIENT"] == "https://chat.example.com"


def test_resolve_hostnames_librechat_default_prefers_localhost(repo_root):
    # No arg, interactive prompt returns the default -> host.docker.internal
    # becomes localhost so LibreChat's OIDC cookie survives plain HTTP.
    tree = envtree.load_seed_tree(repo_root)
    captured = {}

    def fake_prompt(message, default):
        captured[message] = default
        return default

    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        prompt=fake_prompt,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:8000"
    assert captured["Public URL of LibreChat (DOMAIN_SERVER)"] == "http://localhost:8000"


def test_resolve_hostnames_librechat_prompt_answer_used(repo_root):
    tree = envtree.load_seed_tree(repo_root)

    def fake_prompt(message, default):
        if message.startswith("Public URL of LibreChat"):
            return "http://localhost:9999"
        return default

    args = resolve.SetupArgs(
        config_dir=repo_root, app_host="http://host.docker.internal", prompt=fake_prompt
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:9999"


def test_resolve_hostnames_librechat_sticky_reused_when_not_fresh(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree["ai/librechat"]["DOMAIN_SERVER"] = "http://prior-run.example.com:8000"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=False,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://prior-run.example.com:8000"


def test_resolve_hostnames_derives_oidc_and_domain_vars(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root, app_host="https://papaia.example.com", non_interactive=True
    )

    tree = resolve.resolve_hostnames(tree, args)

    assert tree[""]["PAPAIA_HOST"] == "https://papaia.example.com"
    assert tree[""]["AUTH_HOST"] == "https://auth.papaia.example.com"
    assert tree["infra/keycloak"]["KC_HOSTNAME"] == "https://auth.papaia.example.com"
    assert tree[""]["OIDC_ISSUER"] == "https://auth.papaia.example.com/realms/papaia"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://papaia.example.com:8000"
    assert (
        tree["ai/litellm"]["GENERIC_REDIRECT_URI"] == "https://papaia.example.com:8200/sso/callback"
    )
    assert tree[""]["LOCALAI_PUBLIC_URL"] == "https://papaia.example.com:8080"
    assert tree[""]["OAUTH2_PROXY_COOKIE_SECURE"] == "true"
    # internal Docker DNS endpoints use https because Keycloak now terminates
    # TLS natively (port 8443); they must never be derived from the public host
    assert (
        tree[""]["OIDC_TOKEN_URL"]
        == "https://keycloak:8443/realms/papaia/protocol/openid-connect/token"
    )
    # TRUST_PROXY is a static value resolve.py must never touch
    assert tree["ai/librechat"]["TRUST_PROXY"] == "1"


@pytest.mark.parametrize(
    "app_host,expected",
    [
        ("http://host.docker.internal", "http://host.docker.internal:8200"),
        ("http://localhost", "http://localhost:8200"),
        ("http://192.168.1.50", "http://192.168.1.50:8200"),
        ("https://papaia.example.com", "https://papaia.example.com:8200"),
    ],
)
def test_derive_litellm_url_default(app_host, expected):
    assert resolve.derive_litellm_url_default(app_host, "8200") == expected


def test_resolve_hostnames_litellm_host_arg_wins(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        litellm_host="https://llm.example.com",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["LITELLM_PUBLIC_URL"] == "https://llm.example.com"
    assert tree["ai/litellm"]["GENERIC_REDIRECT_URI"] == "https://llm.example.com/sso/callback"


def test_resolve_hostnames_litellm_oidc_uses_litellm_url(repo_root):
    # GENERIC_REDIRECT_URI must be derived from LITELLM_PUBLIC_URL, not app_host:port.
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        litellm_host="https://llmproxy.example.com",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/litellm"]["GENERIC_REDIRECT_URI"] == "https://llmproxy.example.com/sso/callback"
    assert "llmproxy.example.com" in tree["ai/litellm"]["PROXY_LOGOUT_URL"]
    assert "papaia.example.com:8200" not in tree["ai/litellm"]["GENERIC_REDIRECT_URI"]


def test_resolve_hostnames_litellm_sticky_reused_when_not_fresh(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["LITELLM_PUBLIC_URL"] = "https://prior-llm.example.com"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=False,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["LITELLM_PUBLIC_URL"] == "https://prior-llm.example.com"


def test_resolve_hostnames_cookie_secure_false_for_plain_http(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["OAUTH2_PROXY_COOKIE_SECURE"] == "false"


def test_resolve_hostnames_raises_without_app_host_non_interactive(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = ""
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=False)
    with pytest.raises(resolve.SetupError):
        resolve.resolve_hostnames(tree, args)


def test_resolve_hostnames_raises_on_fresh_init_even_with_seeded_example_default(repo_root):
    # Regression test: a *fresh* config dir's tree is seeded straight from
    # .env.example, whose PAPAIA_HOST already holds a real-looking
    # illustrative default (http://host.docker.internal) rather than an
    # empty/GENERATE_* placeholder. Without the fresh_init guard, that
    # shipped example value was silently treated as a genuine sticky value
    # from a prior run, bypassing --app-host validation entirely.
    tree = envtree.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_HOST"] == "http://host.docker.internal"  # sanity: not empty/placeholder
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=True)
    with pytest.raises(resolve.SetupError):
        resolve.resolve_hostnames(tree, args)


def test_resolve_hostnames_reuses_sticky_value_when_not_fresh(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://prior-run.example.com"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True, fresh_init=False)
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["PAPAIA_HOST"] == "https://prior-run.example.com"


def test_resolve_hostnames_skips_external_oidc(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    args = resolve.SetupArgs(
        config_dir=repo_root, app_host="https://papaia.example.com", non_interactive=True
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"


def test_resolve_hostnames_external_oidc_first_time_prompts_for_issuer(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    prompts = []

    def fake_prompt(message, default):
        # Message-aware: the issuer and the LibreChat URL are distinct prompts,
        # so returning the issuer for both would mask a mis-wired DOMAIN_SERVER.
        prompts.append(message)
        if "issuer" in message.lower():
            return "https://idp.customer.com/realms/foo"
        return default

    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        prompt=fake_prompt,
    )
    tree = resolve.resolve_hostnames(tree, args)

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
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        non_interactive=True,
    )
    with pytest.raises(resolve.SetupError):
        resolve.resolve_hostnames(tree, args)


def test_resolve_hostnames_external_oidc_first_time_non_interactive_with_flag_succeeds(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"
    assert tree[""]["AUTH_PROVIDER"] == "external_oidc"


def test_resolve_hostnames_external_oidc_resolves_librechat_domain(repo_root):
    # DOMAIN_SERVER/DOMAIN_CLIENT are resolved for external OIDC too: derived
    # by default, and overridable via --librechat-host.
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:8000"
    assert tree["ai/librechat"]["DOMAIN_CLIENT"] == "http://localhost:8000"

    tree2 = envtree.load_seed_tree(repo_root)
    args2 = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        auth_provider="external_oidc",
        oidc_issuer="https://idp.customer.com/realms/foo",
        librechat_host="https://chat.example.com",
        non_interactive=True,
    )
    tree2 = resolve.resolve_hostnames(tree2, args2)
    assert tree2["ai/librechat"]["DOMAIN_SERVER"] == "https://chat.example.com"


def test_resolve_hostnames_sticky_external_oidc_with_flag_still_preserved(repo_root):
    # Re-passing --auth-provider=external_oidc on a sticky re-run (not just
    # omitting the flag) must still never clobber the existing issuer --
    # confirms the guard checks the tree's prior state, not just whether
    # args.auth_provider happens to be unset.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["OIDC_ISSUER"] == "https://idp.customer.com/realms/foo"


def test_resolve_hostnames_external_oidc_derives_litellm_endpoints(repo_root):
    # LiteLLM OIDC endpoints must be derived from the external issuer URL, not
    # left at the bundled-Keycloak seed values (keycloak:8443 / host.docker…).
    issuer = "https://idp.customer.com/realms/foo"
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="external_oidc",
        oidc_issuer=issuer,
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)

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
    tree_explicit = envtree.load_seed_tree(repo_root)
    tree_omitted = envtree.load_seed_tree(repo_root)
    args_explicit = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        auth_provider="internal_keycloak",
        non_interactive=True,
    )
    args_omitted = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="https://papaia.example.com",
        non_interactive=True,
    )
    tree_explicit = resolve.resolve_hostnames(tree_explicit, args_explicit)
    tree_omitted = resolve.resolve_hostnames(tree_omitted, args_omitted)
    assert tree_explicit == tree_omitted


def test_resolve_multi_env_default_identity_unchanged(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(config_dir=repo_root, env_name="papaia")
    tree = resolve.resolve_multi_env(tree, args)
    assert tree[""]["COMPOSE_PROJECT_NAME"] == "papaia"
    assert tree[""]["DOCKER_NETWORK"] == "papaia-net"


def test_resolve_multi_env_named_env(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(config_dir=repo_root, env_name="stage", host_ip="10.0.0.5")
    tree = resolve.resolve_multi_env(tree, args)
    assert tree[""]["COMPOSE_PROJECT_NAME"] == "papaia-stage"
    assert tree[""]["DOCKER_NETWORK"] == "papaia-stage-net"
    assert tree[""]["HOST_IP"] == "10.0.0.5"


def test_resolve_reverse_proxy_excludes_nginx_when_external(repo_root):
    # Explicit provider choice wins regardless of PAPAIA_HOST scheme.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="external_proxy",
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "nginx" not in profiles


def test_resolve_reverse_proxy_includes_nginx_by_default_on_http(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_accidental_no_proxy_state(repo_root):
    # external_reverse_proxy=False without allow_direct_port_access must
    # always fall back to bundling nginx -- there is no flag combination
    # that accidentally leaves the stack with no proxy in front of it.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
        allow_direct_port_access=False,
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_allow_direct_port_access_excludes_nginx_non_interactive(repo_root):
    # The flag itself is the authorization in non-interactive mode -- no
    # confirmation prompt, no error.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
        allow_direct_port_access=True,
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_allow_direct_port_access_interactive_confirm(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        external_reverse_proxy=False,
        allow_direct_port_access=True,
        confirm=lambda _msg, _default: False,
    )
    with pytest.raises(resolve.SetupError):
        resolve.resolve_reverse_proxy(tree, args)


def test_resolve_reverse_proxy_excludes_keycloak_when_external_oidc(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "keycloak" not in profiles
    # oauth2-proxy / librechat / litellm still bundled as usual.
    assert "oauth2-proxy" in profiles


def test_resolve_reverse_proxy_includes_keycloak_by_default(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    # AUTH_PROVIDER absent -> defaults to internal_keycloak.
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "keycloak" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_external_skips_direct_access_confirmation(repo_root):
    # external_reverse_proxy=True means the operator vouches for an edge
    # proxy elsewhere -- never treated as "no proxy anywhere", even on
    # plain HTTP, so no confirmation should be triggered.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["AUTH_HOST"] = "http://host.docker.internal:8110"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        external_reverse_proxy=True,
        confirm=lambda _msg, _default: (_ for _ in ()).throw(
            AssertionError("should not be called")
        ),
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_stores_provider_in_tree(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_external_proxy_provider_excludes_nginx(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="external_proxy",
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_sticky_reused_when_arg_absent(repo_root):
    # A value stored from a prior run is reused when no explicit arg is given.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_arg_wins_over_sticky(repo_root):
    # An explicit --reverse-proxy-provider flag overrides the stored sticky value.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_legacy_bool_flag_translates_to_provider(repo_root):
    # The old --external-reverse-proxy flag is preserved as an alias.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=True,
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_legacy_bool_false_translates_to_internal(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "external_proxy"  # prior sticky
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        external_reverse_proxy=False,
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_provider_arg_wins_over_legacy_bool(repo_root):
    # New-style --reverse-proxy-provider takes precedence over legacy bool flag.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="internal_nginx",
        external_reverse_proxy=True,  # conflicting legacy flag — new style wins
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_migrates_from_profile_only_state(repo_root):
    # Existing installs that have nginx in COMPOSE_PROFILES but no
    # REVERSE_PROXY_PROVIDER are migrated to internal_nginx automatically.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm,nginx"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_autodetects_external_on_https_first_run(repo_root):
    # First run with no stored value and no nginx in profiles: HTTPS host
    # auto-detects external_proxy.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    # Clear nginx from profiles too so the migration path doesn't set internal_nginx
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "external_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_autodetects_internal_on_http_first_run(repo_root):
    # First run with no stored value and no nginx in profiles: HTTP host
    # auto-detects internal_nginx.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    del tree[""]["REVERSE_PROXY_PROVIDER"]
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"
    assert "nginx" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_derive_npm_admin_host_default_rewrites_docker_internal_to_localhost(repo_root):
    # Plain-HTTP host.docker.internal → localhost so the oauth2-proxy CSRF
    # cookie is scoped to the same origin the browser uses.
    result = resolve.derive_npm_admin_host_default("http://host.docker.internal", "8100")
    assert result == "http://localhost:8100"


def test_derive_npm_admin_host_default_keeps_https_docker_internal(repo_root):
    result = resolve.derive_npm_admin_host_default("https://host.docker.internal", "8100")
    assert result == "https://host.docker.internal:8100"


def test_derive_npm_admin_host_default_keeps_fqdn(repo_root):
    result = resolve.derive_npm_admin_host_default("https://proxy.example.com", "8100")
    assert result == "https://proxy.example.com:8100"


def test_resolve_hostnames_npm_admin_host_derived_from_app_host(repo_root):
    # host.docker.internal over plain HTTP is rewritten to localhost
    # (same pattern as derive_librechat_url_default).
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "http://localhost:8100"


def test_resolve_hostnames_npm_admin_host_arg_wins(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        npm_admin_host="https://proxy-admin.example.com",
        non_interactive=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "https://proxy-admin.example.com"


def test_resolve_hostnames_npm_admin_host_sticky_reused_when_not_fresh(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["NPM_ADMIN_HOST"] = "https://prior-npm.example.com"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=False,
    )
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["NPM_ADMIN_HOST"] == "https://prior-npm.example.com"


def test_resolve_hostnames_npm_admin_host_fresh_init_uses_derived(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["NPM_ADMIN_HOST"] = "https://prior-npm.example.com"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        app_host="http://host.docker.internal",
        non_interactive=True,
        fresh_init=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    # host.docker.internal over plain HTTP is rewritten to localhost
    assert tree[""]["NPM_ADMIN_HOST"] == "http://localhost:8100"


def test_resolve_reverse_proxy_no_proxy_excludes_nginx(repo_root):
    # Explicit no_proxy choice removes the nginx profile, same as external_proxy.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=True,
        reverse_proxy_provider="no_proxy",
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "no_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_proxy_skips_confirmation(repo_root):
    # no_proxy is an explicit operator choice — the "no proxy and no TLS"
    # confirmation prompt must never fire (unlike allow_direct_port_access).
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    args = resolve.SetupArgs(
        config_dir=repo_root,
        non_interactive=False,
        reverse_proxy_provider="no_proxy",
        confirm=lambda _msg, _default: (_ for _ in ()).throw(
            AssertionError("confirmation prompt must not be called for no_proxy")
        ),
    )
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_reverse_proxy_no_proxy_sticky_reused(repo_root):
    # A stored no_proxy value is reused on a re-run without an explicit arg.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "http://host.docker.internal"
    tree[""]["REVERSE_PROXY_PROVIDER"] = "no_proxy"
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True)
    tree = resolve.resolve_reverse_proxy(tree, args)
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "no_proxy"
    assert "nginx" not in tree[""]["COMPOSE_PROFILES"].split(",")


def test_resolve_web_search_adds_unified_profile_when_enabled(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,oauth2-proxy,librechat,litellm,nginx"
    args = resolve.SetupArgs(config_dir=repo_root, enable_web_search=True)
    tree = resolve.resolve_web_search(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" in profiles
    assert "searxng" not in profiles
    assert "firecrawl" not in profiles
    assert "jinaai" not in profiles


def test_resolve_web_search_removes_unified_profile_when_disabled(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = (
        "keycloak,oauth2-proxy,librechat,litellm,nginx,librechat-websearch"
    )
    args = resolve.SetupArgs(config_dir=repo_root, enable_web_search=False)
    tree = resolve.resolve_web_search(tree, args)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" not in profiles


def test_resolve_web_search_preserves_profiles_when_sticky(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    original = "keycloak,oauth2-proxy,librechat,litellm,nginx,librechat-websearch"
    tree[""]["COMPOSE_PROFILES"] = original
    args = resolve.SetupArgs(config_dir=repo_root, enable_web_search=None)
    tree = resolve.resolve_web_search(tree, args)
    assert tree[""]["COMPOSE_PROFILES"] == original


def test_migrate_web_search_profiles_replaces_legacy_names(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,nginx,searxng,firecrawl,jinaai,librechat"
    tree = resolve.migrate_web_search_profiles(tree)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "librechat-websearch" in profiles
    assert "searxng" not in profiles
    assert "firecrawl" not in profiles
    assert "jinaai" not in profiles


def test_migrate_web_search_profiles_noop_when_already_migrated(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    original = "keycloak,nginx,librechat-websearch,librechat"
    tree[""]["COMPOSE_PROFILES"] = original
    tree = resolve.migrate_web_search_profiles(tree)
    assert tree[""]["COMPOSE_PROFILES"] == original


def test_migrate_removed_profiles_drops_homepage(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,nginx,homepage,librechat"
    tree = resolve.migrate_removed_profiles(tree)
    profiles = tree[""]["COMPOSE_PROFILES"].split(",")
    assert "homepage" not in profiles
    assert profiles == ["keycloak", "nginx", "librechat"]


def test_migrate_removed_profiles_noop_without_removed_entry(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    original = "keycloak,nginx,librechat,litellm"
    tree[""]["COMPOSE_PROFILES"] = original
    tree = resolve.migrate_removed_profiles(tree)
    assert tree[""]["COMPOSE_PROFILES"] == original


def test_migrate_env_keys_drops_homepage_keys(repo_root):
    # The shape a v0.6.0 - v0.8.0 bundle carries into a 1.0.0 upgrade: all four
    # keys lived in the root .env, HOMEPAGE_IMAGE and HP_ALLOWED_HOSTS included.
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["HOMEPAGE_IMAGE"] = "ghcr.io/gethomepage/homepage:v1.12.3"
    tree[""]["HOMEPAGE_EXT_PORT"] = "8300"
    tree[""]["HOMEPAGE_PUBLIC_URL"] = "http://host.docker.internal:8300"
    tree[""]["HP_ALLOWED_HOSTS"] = "localhost:8300"

    tree = resolve.migrate_env_keys(tree)

    assert "HOMEPAGE_IMAGE" not in tree[""]
    assert "HOMEPAGE_EXT_PORT" not in tree[""]
    assert "HOMEPAGE_PUBLIC_URL" not in tree[""]
    assert "HP_ALLOWED_HOSTS" not in tree[""]


def test_migrate_env_keys_renames_oidc_endpoints(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    for new_key in ("OIDC_AUTH_URL", "OIDC_TOKEN_URL", "OIDC_JWKS_URL"):
        tree[""].pop(new_key, None)
    tree[""]["OIDC_ISSUER_KC_AUTH"] = "https://idp.example.com/auth"
    tree[""]["OIDC_ISSUER_KC_TOKEN"] = "https://idp.example.com/token"
    tree[""]["OIDC_ISSUER_KC_CERTS"] = "https://idp.example.com/certs"

    tree = resolve.migrate_env_keys(tree)

    assert tree[""]["OIDC_AUTH_URL"] == "https://idp.example.com/auth"
    assert tree[""]["OIDC_TOKEN_URL"] == "https://idp.example.com/token"
    assert tree[""]["OIDC_JWKS_URL"] == "https://idp.example.com/certs"
    assert "OIDC_ISSUER_KC_AUTH" not in tree[""]
    assert "OIDC_ISSUER_KC_TOKEN" not in tree[""]
    assert "OIDC_ISSUER_KC_CERTS" not in tree[""]


def test_migrate_env_keys_relocates_librechat_dirs(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["LIBRECHAT_AGENTS_DIR"] = "/srv/my-agents"
    tree[""]["LIBRECHAT_PROMPTS_DIR"] = "/srv/my-prompts"

    tree = resolve.migrate_env_keys(tree)

    assert tree["ai/librechat"]["LIBRECHAT_AGENTS_DIR"] == "/srv/my-agents"
    assert tree["ai/librechat"]["LIBRECHAT_PROMPTS_DIR"] == "/srv/my-prompts"
    assert "LIBRECHAT_AGENTS_DIR" not in tree[""]
    assert "LIBRECHAT_PROMPTS_DIR" not in tree[""]


def test_migrate_env_keys_relocates_npm_admin_keys(repo_root):
    """The generated NPM password must survive the move: NPM honours
    INITIAL_ADMIN_* on first boot only, so regenerating it would lock
    papaia-ctl out of the API of an already-initialised instance."""
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["NPM_ADMIN_EMAIL"] = "admin@papaia.local"
    tree[""]["NPM_ADMIN_PASSWORD"] = "already-generated-value"
    tree[""]["NPM_API_LOCAL_PORT"] = "9181"

    tree = resolve.migrate_env_keys(tree)

    assert tree["infra/nginx"]["NPM_ADMIN_EMAIL"] == "admin@papaia.local"
    assert tree["infra/nginx"]["NPM_ADMIN_PASSWORD"] == "already-generated-value"
    assert tree["infra/nginx"]["NPM_API_LOCAL_PORT"] == "9181"
    assert "NPM_ADMIN_PASSWORD" not in tree[""]


def test_migrate_env_keys_drops_dead_keys(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["TIMEZONE"] = "Europe/Berlin"
    tree[""]["OIDC_CLIENT_ID"] = "librechat"
    tree[""]["JINAAI_EXT_PORT"] = "8600"
    tree.setdefault("infra/keycloak", {})["KC_QDRANT_RAG_CLIENT_SECRET"] = "deadbeef"

    tree = resolve.migrate_env_keys(tree)

    assert "TIMEZONE" not in tree[""]
    assert "OIDC_CLIENT_ID" not in tree[""]
    assert "JINAAI_EXT_PORT" not in tree[""]
    assert "KC_QDRANT_RAG_CLIENT_SECRET" not in tree["infra/keycloak"]


def test_migrate_env_keys_relocates_manager_admin_role(repo_root):
    """A stale root-level copy never reached the container (env_file: only
    pulls from the manager node) -- migration must move it there instead of
    leaving a value the operator could mistake for effective."""
    tree = envtree.load_seed_tree(repo_root)
    tree.setdefault("manager", {}).pop("MANAGER_ADMIN_ROLE", None)
    tree[""]["MANAGER_ADMIN_ROLE"] = "custom-admin"

    tree = resolve.migrate_env_keys(tree)

    assert tree["manager"]["MANAGER_ADMIN_ROLE"] == "custom-admin"
    assert "MANAGER_ADMIN_ROLE" not in tree[""]


def test_migrate_env_keys_drops_manager_image_tag(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["MANAGER_IMAGE_TAG"] = "0.1.0"

    tree = resolve.migrate_env_keys(tree)

    assert "MANAGER_IMAGE_TAG" not in tree[""]


def test_migrate_env_keys_keeps_existing_destination(repo_root):
    """A half-migrated bundle must not lose the value the current code writes."""
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["OIDC_AUTH_URL"] = "https://new.example.com/auth"
    tree[""]["OIDC_ISSUER_KC_AUTH"] = "https://stale.example.com/auth"

    tree = resolve.migrate_env_keys(tree)

    assert tree[""]["OIDC_AUTH_URL"] == "https://new.example.com/auth"
    assert "OIDC_ISSUER_KC_AUTH" not in tree[""]


def test_migrate_env_keys_is_noop_on_current_seed(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    before = {d: dict(v) for d, v in tree.items()}
    tree = resolve.migrate_env_keys(tree)
    assert tree == before


def test_resolve_reranker_model_writes_value(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    args = resolve.SetupArgs(
        config_dir=repo_root,
        reranker_model="rerank/jina-reranker-v2-base-multilingual",
    )
    tree = resolve.resolve_reranker_model(tree, args)
    assert tree["ai/jinaai"]["RERANKER_MODEL"] == "rerank/jina-reranker-v2-base-multilingual"


def test_resolve_reranker_model_sticky_when_none(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree.setdefault("ai/jinaai", {})["RERANKER_MODEL"] = "existing-model"
    args = resolve.SetupArgs(config_dir=repo_root, reranker_model=None)
    tree = resolve.resolve_reranker_model(tree, args)
    assert tree["ai/jinaai"]["RERANKER_MODEL"] == "existing-model"
