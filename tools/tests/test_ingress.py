"""Add-on ingress (contract generation 12) and the host scheme (PLT-33, PLT-74).

An add-on declares its web interfaces in `integration.nginx`; the core gives each one a
host name of the installation's scheme, renders the bundled proxy's hosts from it
(`internal_nginx`) and prints the list "host name -> internal target" for an external
proxy (`papaia-ctl proxy list`). Host names never come from the manifest, and an
operator's rename is a single DNS label, so no address outside the installation gets in.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from lib import cli, common, deployment, gen_override, ingress, npm_provision, paperless_gate

FIXTURES = Path(__file__).parent / "fixtures"
GEN12 = FIXTURES / "addon-generation-12"
APPS = FIXTURES / "addon-ingress-apps"


def _manifest(path: Path) -> dict:
    return yaml.safe_load((path / "papaia-app.yaml").read_text(encoding="utf-8"))


def _root(**extra: str) -> dict[str, str]:
    root = {
        "PAPAIA_HOST": "http://host.docker.internal",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "COMPOSE_PROJECT_NAME": "papaia-itest",
        "PAPAIA_PROJECT": "papaia-itest",
        "DOCKER_NETWORK": "papaia-itest-net",
        "INGRESS_HTTPS_EXT_PORT": "57143",
        "COMPOSE_PROFILES": "keycloak,nginx,librechat,litellm,manager",
        "AUTH_HOST": "https://auth.itest.papaia.localhost:57143",
        "MANAGER_PUBLIC_URL": "https://manager.itest.papaia.localhost:57143",
        "LITELLM_PUBLIC_URL": "http://host.docker.internal:8200",
    }
    root.update(extra)
    return root


def _tree(**extra: str) -> dict[str, dict[str, str]]:
    return {
        "": _root(**extra),
        "ai/librechat": {"DOMAIN_SERVER": "https://chat.itest.papaia.localhost:57143"},
    }


def _install(tmp_path: Path, *fixtures: Path) -> tuple[Path, Path]:
    """A config dir whose deployment.yaml lists the fixture add-ons as active."""
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "repo", repo)
    config = tmp_path / "config"
    config.mkdir()
    entries = []
    for fixture in fixtures:
        target = repo / "addons" / fixture.name
        shutil.copytree(fixture, target)
        entries.append({"name": _manifest(fixture)["name"], "path": str(target), "active": True})
    deployment.save(config, {"addons": entries})
    common.atomic_write(
        config / ".env", "".join(f"{k}={v}\n" for k, v in _root().items())
    )
    return repo, config


# ── host scheme ──────────────────────────────────────────────────────────────


def test_local_default_scheme_uses_the_env_and_the_edge_port():
    scheme = ingress.host_scheme(_root())
    assert scheme.domain == "itest.papaia.localhost"
    assert scheme.app_domain == "itest.papaia-apps.localhost"
    assert scheme.url("auth") == "https://auth.itest.papaia.localhost:57143"


def test_default_project_has_no_env_label_and_the_default_port_is_left_out():
    scheme = ingress.host_scheme(
        _root(COMPOSE_PROJECT_NAME="papaia", INGRESS_HTTPS_EXT_PORT="443")
    )
    assert scheme.url("auth") == "https://auth.papaia.localhost"
    assert scheme.app_domain == "papaia-apps.localhost"


def test_fqdn_scheme_uses_the_server_domain():
    scheme = ingress.host_scheme(
        _root(
            PAPAIA_HOST="https://example.org",
            INGRESS_APP_DOMAIN="example-apps.org",
            INGRESS_HTTPS_EXT_PORT="443",
        )
    )
    assert scheme.url("flow") == "https://flow.example.org"
    assert scheme.app_domain == "example-apps.org"


def test_a_lan_address_needs_a_domain_for_add_on_interfaces():
    # `.localhost` would point the other machines of the LAN at themselves.
    lan = _root(PAPAIA_HOST="http://192.168.50.20")
    assert ingress.host_scheme(lan).domain is None
    with pytest.raises(ingress.IngressError, match="INGRESS_DOMAIN"):
        ingress.addon_routes(_manifest(GEN12), lan)
    # The interfaces follow the scheme of PAPAIA_HOST and the edge port for it.
    (route,) = ingress.addon_routes(_manifest(GEN12), {**lan, "INGRESS_DOMAIN": "lan.example"})
    assert route.public_url == "http://gen12.lan.example"


def test_no_proxy_has_no_host_names():
    scheme = ingress.host_scheme(_root(REVERSE_PROXY_PROVIDER="no_proxy"))
    assert scheme.domain is None
    assert ingress.addon_routes(_manifest(GEN12), _root(REVERSE_PROXY_PROVIDER="no_proxy")) == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("INGRESS_DOMAIN", "example.org/evil"),
        ("INGRESS_DOMAIN", "-example.org"),
        ("INGRESS_APP_DOMAIN", "https://example-apps.org"),
        ("INGRESS_HTTPS_EXT_PORT", "70000"),
        ("INGRESS_HTTPS_EXT_PORT", "443x"),
    ],
)
def test_unusable_scheme_values_are_refused(key, value):
    with pytest.raises(ingress.IngressError, match=key):
        ingress.host_scheme(_root(**{key: value}))


def test_the_app_domain_is_a_site_of_its_own():
    # Cookies of the platform domain must never reach the app host (E-20).
    with pytest.raises(ingress.IngressError, match="INGRESS_APP_DOMAIN"):
        ingress.host_scheme(
            _root(PAPAIA_HOST="https://example.org", INGRESS_APP_DOMAIN="apps.example.org")
        )


# ── routes from the manifest ─────────────────────────────────────────────────


def test_rendered_route_of_the_generation_12_sample():
    (route,) = ingress.addon_routes(_manifest(GEN12), _root())
    assert route.module == "gen12"
    assert route.hostnames == ("gen12.itest.papaia.localhost",)
    assert route.public_url == "https://gen12.itest.papaia.localhost:57143"
    assert route.target == "http://gen12-web:8080"
    assert route.network == "papaia-gen12-net"
    assert route.websocket is True
    assert route.max_body == "10m"


def test_the_app_host_lands_on_the_second_domain_with_its_subdomains():
    console, apps = ingress.addon_routes(_manifest(APPS), _root())
    assert console.hostnames == ("appdemo.itest.papaia.localhost",)
    assert apps.hostnames == (
        "itest.papaia-apps.localhost",
        "*.itest.papaia-apps.localhost",
    )
    assert apps.public_url == "https://itest.papaia-apps.localhost:57143"
    # The templated network resolves against the installation's project name.
    assert apps.network == "papaia-itest-appdemo-net"


def test_the_app_host_needs_a_second_domain_on_a_server_domain():
    with pytest.raises(ingress.IngressError, match="INGRESS_APP_DOMAIN"):
        ingress.addon_routes(_manifest(APPS), _root(PAPAIA_HOST="https://example.org"))


def test_the_operator_renames_a_host_key():
    (route,) = ingress.addon_routes(_manifest(GEN12), _root(INGRESS_HOST_GEN12="portal"))
    assert route.public_url == "https://portal.itest.papaia.localhost:57143"


@pytest.mark.parametrize(
    "value", ["example.org", "//example.org", "https://example.org", "unbekannt:x:1", "a b"]
)
def test_a_rename_to_a_foreign_address_is_refused(value):
    with pytest.raises(ingress.IngressError, match="INGRESS_HOST_GEN12"):
        ingress.addon_routes(_manifest(GEN12), _root(INGRESS_HOST_GEN12=value))


def test_a_manifest_cannot_name_its_own_host():
    manifest = _manifest(GEN12)
    manifest["integration"]["nginx"][0]["public_url"] = "https://example.org"
    with pytest.raises(ingress.IngressError, match="unknown field"):
        ingress.addon_routes(manifest, _root())


def test_ingress_without_an_app_network_is_refused():
    manifest = _manifest(GEN12)
    del manifest["networks"]
    with pytest.raises(ingress.IngressError, match="app_network"):
        ingress.addon_routes(manifest, _root())


def test_a_host_name_taken_by_the_core_is_refused(tmp_path):
    repo, config = _install(tmp_path, GEN12)
    tree = _tree(INGRESS_HOST_GEN12="auth")
    with pytest.raises(ingress.IngressError, match="auth.itest.papaia.localhost"):
        ingress.routes(tree, config, repo)


def test_a_host_name_declared_by_two_add_ons_is_refused(tmp_path):
    repo, config = _install(tmp_path, GEN12, APPS)
    tree = _tree(INGRESS_HOST_APPDEMO="gen12")
    with pytest.raises(ingress.IngressError, match="gen12.itest.papaia.localhost"):
        ingress.routes(tree, config, repo)


# ── no address outside the installation ──────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "https://example.org",
        "//example.org",
        "unbekannt:x:1",
        "https://gen12.itest.papaia.localhost.example.org:57143/",
        "https://user@gen12.itest.papaia.localhost:57143/",
        "https://gen12.itest.papaia.localhost:8443/",
        "javascript:alert(1)",
        "/relative/path",
        "",
    ],
)
def test_addresses_outside_the_installation_are_refused(tmp_path, value):
    repo, config = _install(tmp_path, GEN12, APPS)
    routes = ingress.routes(_tree(), config, repo)
    assert ingress.is_installation_url(value, routes) is False


@pytest.mark.parametrize(
    "value",
    [
        "https://gen12.itest.papaia.localhost:57143/tasks/01J",
        "https://auth.itest.papaia.localhost:57143/realms/papaia",
        "https://board.itest.papaia-apps.localhost:57143/",
    ],
)
def test_addresses_of_the_installation_are_accepted(tmp_path, value):
    repo, config = _install(tmp_path, GEN12, APPS)
    routes = ingress.routes(_tree(), config, repo)
    assert ingress.is_installation_url(value, routes) is True


# ── bundled proxy (internal_nginx) ───────────────────────────────────────────


def test_rendered_proxy_host_of_the_generation_12_sample():
    (route,) = ingress.addon_routes(_manifest(GEN12), _root())
    body = npm_provision.route_body(route)
    assert body["domain_names"] == ["gen12.itest.papaia.localhost"]
    assert (body["forward_scheme"], body["forward_host"], body["forward_port"]) == (
        "http",
        "gen12-web",
        8080,
    )
    assert body["allow_websocket_upgrade"] is True
    assert "client_max_body_size 10m;" in body["advanced_config"]
    # Like every host the core creates, it clears the identity and the gate header.
    assert paperless_gate.strip_config() in body["advanced_config"]


def test_rendered_proxy_host_of_the_app_host():
    _, apps = ingress.addon_routes(_manifest(APPS), _root())
    body = npm_provision.route_body(apps)
    assert body["domain_names"] == ["itest.papaia-apps.localhost", "*.itest.papaia-apps.localhost"]
    assert body["forward_host"] == "appdemo-app-host"
    assert "client_max_body_size 25m;" in body["advanced_config"]


@pytest.mark.parametrize(
    "url,edge,expected",
    [
        ("https://auth.itest.papaia.localhost:57143", (57143, 57180), True),
        ("http://auth.itest.papaia.localhost:57180", (57143, 57180), True),
        ("https://auth.itest.papaia.localhost:8443", (57143, 57180), False),
        ("https://papaia.example.com:8200", (57143, 57180), False),
        ("http://host.docker.internal:57143", (57143, 57180), False),
    ],
)
def test_subdomain_urls_with_the_edge_port_are_provisioned(url, edge, expected):
    assert npm_provision._is_subdomain_url(url, edge) is expected


class _FakeNpm:
    def __init__(self, hosts: list[dict]):
        self.hosts = hosts
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, base_url, token, path, method, body=None):
        self.calls.append((method, path, body))
        if method == "GET":
            return self.hosts
        return None


def _provision(monkeypatch, tree, config, repo, hosts):
    fake = _FakeNpm(hosts)
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_send", fake)
    monkeypatch.setattr(npm_provision, "_gate_steps", lambda *a, **k: True)
    tree["infra/nginx"] = {"NPM_ADMIN_PASSWORD": "x" * 32}
    assert npm_provision.provision_npm_hosts(tree, config, repo) is True
    return fake


def test_provisioning_creates_a_host_per_interface_without_manual_steps(
    tmp_path, monkeypatch
):
    repo, config = _install(tmp_path, GEN12, APPS)
    fake = _provision(monkeypatch, _tree(), config, repo, hosts=[])
    created = {tuple(body["domain_names"]) for method, _, body in fake.calls if method == "POST"}
    assert ("gen12.itest.papaia.localhost",) in created
    assert ("appdemo.itest.papaia.localhost",) in created
    assert ("itest.papaia-apps.localhost", "*.itest.papaia-apps.localhost") in created
    # The core hosts on the edge port are provisioned too (auth, chat, manager).
    assert ("auth.itest.papaia.localhost",) in created
    assert ("chat.itest.papaia.localhost",) in created


def test_provisioning_corrects_a_drifted_interface_host(tmp_path, monkeypatch):
    repo, config = _install(tmp_path, GEN12)
    (route,) = ingress.addon_routes(_manifest(GEN12), _root())
    drifted = {**npm_provision.route_body(route), "id": 7, "forward_port": 9999}
    fake = _provision(monkeypatch, _tree(), config, repo, hosts=[drifted])
    puts = [(path, body) for method, path, body in fake.calls if method == "PUT"]
    assert puts == [(f"{npm_provision._PROXY_HOSTS_PATH}/7", npm_provision.route_body(route))]


def test_provisioning_leaves_a_matching_interface_host_alone(tmp_path, monkeypatch):
    repo, config = _install(tmp_path, GEN12)
    (route,) = ingress.addon_routes(_manifest(GEN12), _root())
    fake = _provision(
        monkeypatch, _tree(), config, repo, hosts=[{**npm_provision.route_body(route), "id": 3}]
    )
    assert not [c for c in fake.calls if c[0] in ("PUT", "POST") and "gen12" in json.dumps(c[2])]


def test_the_proxy_joins_the_network_of_an_add_on_with_ingress(tmp_path):
    repo, config = _install(tmp_path, APPS)
    out = gen_override.generate_override(_manifest(APPS), config, repo / "addons" / APPS.name)
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert doc["services"] == {"nginx-proxy-manager": {"networks": ["papaia-itest-appdemo-net"]}}


# ── external proxy: the list of forwards ─────────────────────────────────────


def _external(tmp_path: Path) -> tuple[Path, Path, dict]:
    repo, config = _install(tmp_path, GEN12, APPS)
    root = _root(
        PAPAIA_HOST="https://example.org",
        REVERSE_PROXY_PROVIDER="external_proxy",
        INGRESS_APP_DOMAIN="example-apps.org",
        COMPOSE_PROFILES="keycloak,librechat,litellm,manager",
        AUTH_HOST="https://auth.example.org",
        MANAGER_PUBLIC_URL="https://manager.example.org",
        LITELLM_PUBLIC_URL="https://llm.example.org",
    )
    tree = {"": root, "ai/librechat": {"DOMAIN_SERVER": "https://chat.example.org"}}
    return repo, config, tree


def test_proxy_list_of_an_external_proxy_is_complete(tmp_path):
    repo, config, tree = _external(tmp_path)
    rows = {r.hostnames: r for r in ingress.routes(tree, config, repo)}
    assert rows[("auth.example.org",)].target == "https://keycloak:8443"
    assert rows[("chat.example.org",)].target == "http://librechat:3080"
    assert rows[("manager.example.org",)].target == "http://papaia-manager:8000"
    assert rows[("llm.example.org",)].target == "http://litellm:4000"
    assert rows[("gen12.example.org",)].target == "http://gen12-web:8080"
    assert rows[("appdemo.example.org",)].target == "http://appdemo-console:8080"
    # The second domain of the app host, with its subdomains.
    apps = rows[("example-apps.org", "*.example-apps.org")]
    assert apps.target == "http://appdemo-app-host:8090"
    assert apps.network == "papaia-itest-appdemo-net"


def test_proxy_list_command_prints_every_forward(tmp_path, capsys):
    repo, config, tree = _external(tmp_path)
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in tree[""].items()))
    librechat = config / "ai" / "librechat"
    librechat.mkdir(parents=True)
    common.atomic_write(librechat / ".env", "DOMAIN_SERVER=https://chat.example.org\n")
    base = ["--repo-root", str(repo), "--config-dir", str(config), "proxy-list"]

    assert cli.main(base) == 0
    table = capsys.readouterr().out
    for line in (
        "auth.example.org",
        "https://keycloak:8443",
        "*.example-apps.org",
        "http://appdemo-app-host:8090",
        "papaia-itest-appdemo-net",
    ):
        assert line in table

    assert cli.main([*base, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["provider"] == "external_proxy"
    assert {"hostnames": ["gen12.example.org"], "target": "http://gen12-web:8080"}.items() <= next(
        r for r in doc["routes"] if r["module"] == "gen12"
    ).items()


def test_proxy_list_without_a_proxy_says_so(tmp_path, capsys):
    repo, config = _install(tmp_path, GEN12)
    common.atomic_write(
        config / ".env",
        "".join(f"{k}={v}\n" for k, v in _root(REVERSE_PROXY_PROVIDER="no_proxy").items()),
    )
    base = ["--repo-root", str(repo), "--config-dir", str(config), "proxy-list"]
    assert cli.main(base) == 0
    assert "no_proxy" in capsys.readouterr().out
