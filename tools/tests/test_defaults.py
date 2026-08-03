from __future__ import annotations

from lib import common, defaults, envtree


def test_compute_defaults_unseeded_config_dir_gates_sticky_values(repo_root, config_dir):
    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["CONFIG_SEEDED"] == "false"
    # Seed-example values must not leak as sticky prefills before the first
    # setup run actually seeded the config dir.
    assert out["LIBRECHAT_HOST_STICKY"] == ""
    assert out["LOCALAI_HOST_STICKY"] == ""
    assert out["LITELLM_HOST_STICKY"] == ""
    assert out["LOCAL_AI_STICKY"] == ""
    assert out["NPM_ADMIN_HOST_STICKY"] == ""
    assert out["WEB_SEARCH_STICKY"] == ""
    assert out["RERANKER_MODEL_STICKY"] == ""
    assert out["LITELLM_EXT_PORT"] == "8200"
    # Derived values still work off the seed's PAPAIA_HOST.
    assert out["AUTH_HOST_DERIVED"] == "https://host.docker.internal:8110"
    assert out["NPM_ADMIN_HOST_DERIVED"] == "http://localhost:8100"
    assert out["PLATFORM_VERSION"] == "0.8.0"


def test_compute_defaults_seeded_config_dir_surfaces_sticky_values(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")

    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["CONFIG_SEEDED"] == "true"
    assert out["APP_HOST_STICKY"] == "http://host.docker.internal"
    assert out["AUTH_HOST_STICKY"] == "http://host.docker.internal:8110"
    assert out["AUTH_PROVIDER_STICKY"] == "internal_keycloak"
    assert out["REVERSE_PROXY_PROVIDER_STICKY"] == "internal_nginx"
    assert out["NPM_ADMIN_HOST_STICKY"] == "http://host.docker.internal:8100"
    assert out["LIBRECHAT_HOST_STICKY"] == "http://host.docker.internal:8000"
    assert out["COMPOSE_PROFILES_STICKY"] == "keycloak,nginx,oauth2-proxy,librechat,litellm"
    # nginx in profiles -> bundled proxy -> not external
    assert out["EXTERNAL_REVERSE_PROXY_STICKY"] == "false"
    assert out["WEB_SEARCH_STICKY"] == "false"
    assert out["LOCAL_AI_STICKY"] == "false"


def test_compute_defaults_placeholder_values_are_not_sticky(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    librechat_env = config_dir / "ai" / "librechat" / ".env"
    values = common.parse_env_file(librechat_env)
    values["DOMAIN_SERVER"] = "GENERATE_DOMAIN_SERVER"
    common.write_env_file(librechat_env, values)

    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["LIBRECHAT_HOST_STICKY"] == ""


def test_compute_defaults_web_search_sticky_recognizes_legacy_profiles(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    root_env = config_dir / ".env"
    values = common.parse_env_file(root_env)
    values["COMPOSE_PROFILES"] = "keycloak,nginx,searxng,firecrawl"
    common.write_env_file(root_env, values)

    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["WEB_SEARCH_STICKY"] == "true"


def test_compute_defaults_surfaces_sticky_localai_variant(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    root_env = config_dir / ".env"
    values = common.parse_env_file(root_env)
    values["LOCALAI_IMAGE_VARIANT"] = "hipblas"
    common.write_env_file(root_env, values)

    out = defaults.compute_defaults(config_dir, repo_root)
    assert out["LOCALAI_VARIANT_STICKY"] == "hipblas"


def test_compute_defaults_localai_variant_not_sticky_before_seeding(repo_root, config_dir):
    out = defaults.compute_defaults(config_dir, repo_root)
    assert out["LOCALAI_VARIANT_STICKY"] == ""
