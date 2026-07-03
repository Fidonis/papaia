from __future__ import annotations

import pytest

from lib import bootstrap, common


def test_resolve_platform_version_reads_latest_changelog_header(repo_root):
    assert bootstrap.resolve_platform_version(repo_root) == "0.7.0"


def test_resolve_platform_version_falls_back_without_changelog(tmp_path):
    assert bootstrap.resolve_platform_version(tmp_path) == "0.0.0-dev"


def test_stamp_platform_version_populates_papaia_version(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_VERSION"] == ""
    bootstrap.stamp_platform_version(tree, repo_root)
    assert tree[""]["PAPAIA_VERSION"] == "0.7.0"


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
    tree["ai/librechat"]["JWT_SECRET"] = "already-customized"

    bootstrap.generate_missing_secrets(tree)

    assert tree["ai/librechat"]["JWT_SECRET"] == "already-customized"
    assert not common.is_placeholder(tree["infra/keycloak"]["KC_LIBRECHAT_CLIENT_SECRET"])


def test_generate_missing_secrets_alias_overwrites_drifted_value(repo_root):
    # A canonical secret's aliases are force-synced even if they'd drifted
    # to a different value -- this is what prevents the "stale copy
    # silently breaks OIDC" failure mode.
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "stale-drifted-value"

    bootstrap.generate_missing_secrets(tree)

    assert (
        tree[""]["OAUTH2_PROXY_CLIENT_SECRET"]
        == tree["infra/keycloak"]["KC_OAUTH2_PROXY_CLIENT_SECRET"]
    )
    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "stale-drifted-value"


def test_generate_missing_secrets_force_regenerates(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "already-customized"

    bootstrap.generate_missing_secrets(tree, force=True)

    assert tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] != "already-customized"


def test_generate_missing_secrets_fans_out_aliases(repo_root):
    tree = bootstrap.load_seed_tree(repo_root)
    bootstrap.generate_missing_secrets(tree)

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


@pytest.mark.parametrize(
    "app_host,expected",
    [
        ("http://host.docker.internal", "http://host.docker.internal:8110"),
        ("http://localhost", "http://localhost:8110"),
        ("http://192.168.1.50", "http://192.168.1.50:8110"),
        ("https://papaia.example.com", "https://auth.papaia.example.com"),
    ],
)
def test_derive_auth_host_default(app_host, expected):
    assert bootstrap.derive_auth_host_default(app_host, "8110") == expected


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
    assert tree[""]["SEARXNG_PUBLIC_URL"] == "https://papaia.example.com:8500"
    assert tree[""]["OAUTH2_PROXY_COOKIE_SECURE"] == "true"
    # internal Docker DNS endpoints must never be derived from the public host
    assert (
        tree[""]["OIDC_ISSUER_KC_TOKEN"]
        == "http://keycloak:8080/realms/papaia/protocol/openid-connect/token"
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
    tree = bootstrap.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    args = bootstrap.SetupArgs(config_dir=repo_root, non_interactive=True)
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
