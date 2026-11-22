"""The local host scheme of `setup` (E-35, RE-83).

A local installation behind the bundled proxy gets `<service>.<env>.papaia.localhost`
with the edge port instead of `host.docker.internal` with a port per service; browsers
resolve names below `localhost` without an `/etc/hosts` entry. `host.docker.internal`
with ports stays for `no_proxy` and direct port access. Behind the edge no service
publishes a port (CORE-007b), so the port addresses an earlier release derived move to the
edge, and a LAN address or a bare host name needs INGRESS_DOMAIN.
"""

from __future__ import annotations

import pytest

from lib import cli, common, defaults, envtree, resolve

EDGE = "57143"


def _setup(repo_root, *, fresh=True, env="itest", stored=None, **kwargs):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["INGRESS_HTTPS_EXT_PORT"] = EDGE
    for (node, key), value in (stored or {}).items():
        tree.setdefault(node, {})[key] = value
    args = resolve.SetupArgs(
        config_dir=repo_root,
        env_name=env,
        app_host=kwargs.pop("app_host", "http://host.docker.internal"),
        non_interactive=True,
        fresh_init=fresh,
        **kwargs,
    )
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_hostnames(tree, args)
    return resolve.resolve_reverse_proxy(tree, args)


def test_local_default_install_renders_the_issuer_on_the_edge(repo_root):
    tree = _setup(repo_root)
    assert tree[""]["AUTH_HOST"] == f"https://auth.itest.papaia.localhost:{EDGE}"
    assert tree[""]["OIDC_ISSUER"] == f"https://auth.itest.papaia.localhost:{EDGE}/realms/papaia"
    assert tree["infra/keycloak"]["KC_HOSTNAME"] == tree[""]["AUTH_HOST"]
    assert tree["ai/librechat"]["OPENID_ISSUER"] == tree[""]["OIDC_ISSUER"]
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == f"https://chat.itest.papaia.localhost:{EDGE}"
    assert tree[""]["MANAGER_PUBLIC_URL"] == f"https://manager.itest.papaia.localhost:{EDGE}"
    assert tree[""]["REVERSE_PROXY_PROVIDER"] == "internal_nginx"


def test_the_default_env_has_no_env_label(repo_root):
    tree = _setup(repo_root, env="papaia")
    assert tree[""]["AUTH_HOST"] == f"https://auth.papaia.localhost:{EDGE}"


@pytest.mark.parametrize(
    "kwargs",
    [{"reverse_proxy_provider": "no_proxy"}, {"allow_direct_port_access": True}],
)
def test_without_the_edge_the_ports_stay(repo_root, kwargs):
    tree = _setup(repo_root, **kwargs)
    assert tree[""]["AUTH_HOST"] == "https://host.docker.internal:8110"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "http://localhost:8000"


@pytest.mark.parametrize("app_host", ["http://192.168.50.20", "http://myhost"])
def test_a_lan_address_without_a_domain_is_refused(repo_root, app_host):
    # Other machines reach it, `.localhost` would point them at themselves, and no
    # service publishes a port of its own any more: the edge needs host names.
    with pytest.raises(resolve.SetupError, match="INGRESS_DOMAIN"):
        _setup(repo_root, app_host=app_host)


@pytest.mark.parametrize("app_host", ["http://192.168.50.20", "http://myhost"])
def test_a_lan_address_keeps_its_ports_with_direct_port_access(repo_root, app_host):
    tree = _setup(repo_root, app_host=app_host, allow_direct_port_access=True)
    assert tree[""]["AUTH_HOST"] == resolve.derive_auth_host_default(app_host, "8110")


def test_a_server_domain_keeps_its_own_derivation(repo_root):
    tree = _setup(repo_root, app_host="http://example.org", reverse_proxy_provider="internal_nginx")
    assert tree[""]["AUTH_HOST"] == "http://auth.example.org"


def test_an_installation_with_the_earlier_port_addresses_moves_to_the_edge(repo_root):
    # Those ports are no longer published: the addresses would lead nowhere.
    tree = _setup(
        repo_root,
        fresh=False,
        stored={
            ("", "PAPAIA_HOST"): "http://host.docker.internal",
            ("", "AUTH_HOST"): "https://host.docker.internal:8110",
            ("", "REVERSE_PROXY_PROVIDER"): "internal_nginx",
            ("ai/librechat", "DOMAIN_SERVER"): "http://localhost:8000",
            ("", "MANAGER_PUBLIC_URL"): "http://host.docker.internal:8120",
        },
    )
    assert tree[""]["AUTH_HOST"] == f"https://auth.itest.papaia.localhost:{EDGE}"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == f"https://chat.itest.papaia.localhost:{EDGE}"
    assert tree[""]["MANAGER_PUBLIC_URL"] == f"https://manager.itest.papaia.localhost:{EDGE}"


def test_an_address_the_operator_chose_is_kept(repo_root):
    tree = _setup(
        repo_root,
        fresh=False,
        stored={
            ("", "PAPAIA_HOST"): "http://host.docker.internal",
            ("", "REVERSE_PROXY_PROVIDER"): "internal_nginx",
            ("ai/librechat", "DOMAIN_SERVER"): "https://chat.customer.example",
        },
    )
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == "https://chat.customer.example"


def test_an_edge_address_follows_a_changed_edge_port(repo_root):
    # `setup --env-only` first, then the operator sets the edge port and runs setup again.
    tree = _setup(
        repo_root,
        fresh=False,
        stored={
            ("", "PAPAIA_HOST"): "http://host.docker.internal",
            ("", "AUTH_HOST"): "https://auth.itest.papaia.localhost",
            ("", "REVERSE_PROXY_PROVIDER"): "internal_nginx",
            ("ai/librechat", "DOMAIN_SERVER"): "https://chat.itest.papaia.localhost",
        },
    )
    assert tree[""]["AUTH_HOST"] == f"https://auth.itest.papaia.localhost:{EDGE}"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == f"https://chat.itest.papaia.localhost:{EDGE}"


def test_an_explicit_auth_host_wins(repo_root):
    tree = _setup(repo_root, auth_host="https://login.example.org")
    assert tree[""]["AUTH_HOST"] == "https://login.example.org"


def test_the_prompt_prefill_uses_the_same_scheme(repo_root, config_dir, capsys):
    base = ["--repo-root", str(repo_root), "--config-dir", str(config_dir)]
    assert cli.main([*base, "derive-edge-url", "auth", "http://host.docker.internal", "itest"]) == 0
    assert capsys.readouterr().out.strip() == "https://auth.itest.papaia.localhost"
    assert (
        cli.main(
            [*base, "derive-edge-url", "auth", "http://host.docker.internal", "itest", "no_proxy"]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == ""


def test_the_prompt_does_not_keep_an_earlier_edge_address(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="itest")
    common.atomic_write(
        config_dir / ".env",
        "PAPAIA_HOST=http://host.docker.internal\n"
        "COMPOSE_PROJECT_NAME=papaia-itest\n"
        f"INGRESS_HTTPS_EXT_PORT={EDGE}\n"
        "AUTH_HOST=https://auth.itest.papaia.localhost\n"
        "MANAGER_PUBLIC_URL=https://manager.itest.papaia.localhost\n",
    )
    found = defaults.compute_defaults(config_dir, repo_root)
    assert found["AUTH_HOST_STICKY"] == ""
    assert found["AUTH_HOST_DERIVED"] == f"https://auth.itest.papaia.localhost:{EDGE}"
    assert found["MANAGER_HOST_STICKY"] == ""
