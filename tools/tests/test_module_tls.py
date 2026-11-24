"""TLS to the module services under the `kritis` security profile (PLT-23, FLO-44, ME-24).

Under `kritis` every upstream the core renders for a module service (Flow, the
assistant, Me, the connection registry) is https with a certificate of the platform PKI,
checked against the platform CA: the proxy hosts of their interfaces and the catalog
addresses other modules call (Me calls the assistant at the catalog address). A module
service without a server certificate for the name it is reached under is refused when
the configuration is rendered. Under `standard` the render is unchanged.

The golden files under tests/golden/module-tls/ hold the rendered upstreams of one
installation with Flow, the assistant, Me and the registry in both profiles; refresh
them with PAPAIA_UPDATE_GOLDEN=1 after a deliberate change.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from lib import (
    catalog,
    common,
    deployment,
    gen_override,
    ingress,
    module_tls,
    npm_provision,
    paperless_gate,
    pki,
    security_profile,
    sign_in,
)

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "module-tls"
GOLDEN = Path(__file__).parent / "golden" / "module-tls"
UPDATE = os.environ.get("PAPAIA_UPDATE_GOLDEN") == "1"
PROFILES = "keycloak,nginx,me,connections"
EDGE = 57143


def _root(profile: str, **extra: str) -> dict[str, str]:
    root = {
        "PAPAIA_HOST": "http://host.docker.internal",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "COMPOSE_PROJECT_NAME": "papaia-itest",
        "PAPAIA_PROJECT": "papaia-itest",
        "DOCKER_NETWORK": "papaia-itest-net",
        "INGRESS_HTTPS_EXT_PORT": str(EDGE),
        "COMPOSE_PROFILES": PROFILES,
        "AUTH_HOST": f"https://auth.itest.papaia.localhost:{EDGE}",
        "ME_PUBLIC_URL": f"https://me.itest.papaia.localhost:{EDGE}",
        "OIDC_ISSUER": f"https://auth.itest.papaia.localhost:{EDGE}/realms/papaia",
        "OIDC_TOKEN_URL": "https://keycloak:8443/realms/papaia/protocol/openid-connect/token",
        "OIDC_JWKS_URL": "https://keycloak:8443/realms/papaia/protocol/openid-connect/certs",
        "PAPAIA_SECURITY_PROFILE": profile,
    }
    root.update(extra)
    return root


def _install(tmp_path: Path, profile: str, *names: str) -> tuple[Path, dict]:
    """A config dir with the fixture add-ons `names` active; returns it and the tree."""
    config = tmp_path / "config"
    config.mkdir()
    entries = []
    for name in names:
        target = tmp_path / "addons" / name
        shutil.copytree(FIXTURES / name, target)
        manifest = yaml.safe_load((target / "papaia-app.yaml").read_text(encoding="utf-8"))
        entries.append(
            {"name": manifest["name"], "path": str(target), "active": True, "state": "running"}
        )
    deployment.save(config, {"addons": entries})
    root = _root(profile)
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in root.items()))
    return config, {"": root}


def _manifest(name: str) -> dict:
    return yaml.safe_load((FIXTURES / name / "papaia-app.yaml").read_text(encoding="utf-8"))


def _addresses(config: Path) -> dict[str, str]:
    doc = catalog.build(config, REPO)
    assert doc is not None
    return {e["id"]: e["address"] for e in doc["services"] if "address" in e}


def _route(route: ingress.Route) -> dict:
    body = npm_provision.route_body(route)
    return {
        "hostnames": list(route.hostnames),
        "target": route.target,
        "advanced_config": body["advanced_config"],
    }


def _rendered(tmp_path: Path, profile: str) -> dict:
    """Everything the core renders that points at a module service, in one document."""
    config, tree = _install(tmp_path, profile, "papaia-flow", "papaia-assist")
    routes = ingress.routes(tree, config, REPO)
    gen_override.generate_overrides(config, REPO)
    override = config / "overrides" / module_tls.OVERRIDE
    me_host = npm_provision.core_route_body(tree[""], "me")
    return {
        "profile": profile,
        "routes": {f"{r.module}:{r.host_key}": _route(r) for r in routes},
        "core_hosts": {"me": me_host},
        "catalog": _addresses(config),
        "override": yaml.safe_load(override.read_text()) if override.is_file() else None,
    }


# ── the profile ──────────────────────────────────────────────────────────────


def test_only_kritis_asks_for_tls_to_the_module_services():
    assert security_profile.PROFILES["kritis"].module_tls is True
    assert security_profile.PROFILES["standard"].module_tls is False
    assert module_tls.required({"PAPAIA_SECURITY_PROFILE": "kritis"}) is True
    assert module_tls.required({}) is False


# ── golden render for both profiles ──────────────────────────────────────────


@pytest.mark.parametrize("profile", ["standard", "kritis"])
def test_render_matches_the_golden_upstreams(tmp_path, profile):
    rendered = _rendered(tmp_path, profile)
    path = GOLDEN / f"{profile}.json"
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")
    assert rendered == json.loads(path.read_text())


def test_no_plain_http_upstream_to_a_module_under_kritis(tmp_path):
    rendered = _rendered(tmp_path, "kritis")
    module_routes = {k: v for k, v in rendered["routes"].items() if k.split(":")[0] != "core"}
    assert set(module_routes) == {"papaia-flow:flow", "papaia-assist:assistant"}
    upstreams = [r["target"] for r in module_routes.values()]
    upstreams.append(
        f"{rendered['core_hosts']['me']['forward_scheme']}://"
        f"{rendered['core_hosts']['me']['forward_host']}"
    )
    upstreams += rendered["catalog"].values()
    assert upstreams and all(u.startswith("https://") for u in upstreams), upstreams
    for route in [*module_routes.values(), rendered["core_hosts"]["me"]]:
        config = route["advanced_config"]
        # Verified against the platform CA under the service's own name, never switched off.
        assert "proxy_ssl_verify on;" in config
        assert "proxy_ssl_verify off" not in config
        assert f"proxy_ssl_trusted_certificate {module_tls.EDGE_TLS_DIR}/ca.crt;" in config
        assert "proxy_ssl_name " in config and "proxy_ssl_server_name on;" in config


def test_standard_keeps_plain_http_on_the_module_networks(tmp_path):
    rendered = _rendered(tmp_path, "standard")
    assert rendered["routes"]["papaia-flow:flow"]["target"] == "http://flow-api:8080"
    assert rendered["core_hosts"]["me"]["forward_scheme"] == "http"
    assert rendered["catalog"]["assist.me"] == "http://assist-api:8080/api/v2/me"
    assert rendered["override"] is None


# ── the proxy ────────────────────────────────────────────────────────────────


def test_the_proxy_checks_the_certificate_of_the_flow_way_in():
    (route,) = ingress.addon_routes(_manifest("papaia-flow"), _root("kritis"))
    assert route.target == "https://flow-api:8080"
    body = npm_provision.route_body(route)
    assert body["forward_scheme"] == "https"
    assert paperless_gate.strip_config() in body["advanced_config"]
    assert "proxy_ssl_name flow-api;" in body["advanced_config"]
    assert "client_max_body_size 2m;" in body["advanced_config"]


def test_a_module_interface_without_a_server_certificate_is_refused_under_kritis():
    manifest = _manifest("papaia-assist-plain")
    with pytest.raises(ingress.IngressError, match="assist-api.*refused"):
        ingress.addon_routes(manifest, _root("kritis"))
    # Under standard the same bundle is forwarded as before.
    (route,) = ingress.addon_routes(manifest, _root("standard"))
    assert route.target == "http://assist-api:8080"


def test_other_add_ons_are_not_touched_by_kritis():
    gen12 = yaml.safe_load(
        (Path(__file__).parent / "fixtures" / "addon-generation-12" / "papaia-app.yaml")
        .read_text(encoding="utf-8")
    )
    (route,) = ingress.addon_routes(gen12, _root("kritis"))
    assert route.target == "http://gen12-web:8080"
    assert "proxy_ssl" not in npm_provision.route_body(route)["advanced_config"]


class _FakeNpm:
    def __init__(self, hosts: list[dict]):
        self.hosts = hosts
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, base_url, token, path, method, body=None):
        self.calls.append((method, path, body))
        return self.hosts if method == "GET" else None


def _provision(monkeypatch, tree: dict, hosts: list[dict]) -> _FakeNpm:
    fake = _FakeNpm(hosts)
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_send", fake)
    tree["infra/nginx"] = {"NPM_ADMIN_PASSWORD": "x" * 32}
    assert npm_provision.provision_npm_hosts(tree) is True
    return fake


def test_a_plain_me_host_is_corrected_to_tls_when_the_profile_becomes_kritis(monkeypatch):
    plain = {**npm_provision.core_route_body(_root("standard"), "me"), "id": 4}
    fake = _provision(monkeypatch, {"": _root("kritis")}, [plain])
    puts = [body for method, path, body in fake.calls if method == "PUT" and path.endswith("/4")]
    assert len(puts) == 1
    assert puts[0]["forward_scheme"] == "https" and puts[0]["forward_host"] == "me-web"
    assert "proxy_ssl_name me-web;" in puts[0]["advanced_config"]


def test_a_matching_me_host_is_left_alone(monkeypatch):
    current = {**npm_provision.core_route_body(_root("kritis"), "me"), "id": 4}
    fake = _provision(monkeypatch, {"": _root("kritis")}, [current])
    me = "me.itest.papaia.localhost"
    writes = [c for c in fake.calls if c[0] in ("PUT", "POST")]
    assert not [c for c in writes if c[1].endswith("/4") or me in c[2].get("domain_names", [])]


def test_the_main_address_redirects_from_a_tls_upstream_under_kritis():
    tree = {"": _root("kritis")}
    body = npm_provision.entry_host_body(sign_in.entry(tree), tree[""])
    assert body["forward_scheme"] == "https" and body["forward_host"] == "me-web"
    advanced = body["advanced_config"]
    assert "proxy_ssl_verify on;" in advanced and "proxy_ssl_verify off" not in advanced
    assert "proxy_ssl_name me-web;" in advanced
    assert advanced.endswith(f"return 302 https://me.itest.papaia.localhost:{EDGE}/;\n")
    plain = npm_provision.entry_host_body(sign_in.entry({"": _root("standard")}), _root("standard"))
    assert plain["forward_scheme"] == "http" and "proxy_ssl" not in plain["advanced_config"]


# ── the identity provider: the back-channel sign-out of Mein Bereich ─────────


def test_mein_bereich_hears_of_a_sign_out_through_the_proxy_under_kritis():
    """Under kritis me-web listens with TLS of the platform PKI only, which the identity
    provider does not trust; it calls Me's public address through the proxy instead of
    the plain stack-network address."""
    public = f"https://me.itest.papaia.localhost:{EDGE}/auth/backchannel-logout"
    kritis = {"": _root("kritis")}
    assert sign_in.backchannel_targets(kritis, []) == {"papaia-me": public}
    assert sign_in.owned_addresses(kritis) == {"papaia-me": public}
    internal = "http://me-web:8000/auth/backchannel-logout"
    standard = {"": _root("standard")}
    assert sign_in.backchannel_targets(standard, []) == {"papaia-me": internal}
    assert sign_in.owned_addresses(standard) == {"papaia-me": internal}
    assert sign_in.backchannel_targets({"": _root("kritis", ME_PUBLIC_URL="")}, []) == {}


# ── the catalog: what Me and the other modules call ──────────────────────────


def test_me_calls_the_assistant_over_tls_under_kritis(tmp_path):
    config, _ = _install(tmp_path, "kritis", "papaia-assist")
    addresses = _addresses(config)
    assert addresses["assist.me"] == "https://assist-api:8080/api/v2/me"
    assert addresses["connections"] == "https://connections:8080/"


def test_the_flow_relay_is_named_by_the_alias_its_certificate_covers(tmp_path):
    config, _ = _install(tmp_path, "kritis", "papaia-flow")
    addresses = _addresses(config)
    assert addresses["flow.runs"] == "https://papaia-flow-api:8080/"
    assert addresses["flow.me"] == "https://flow-api:8444/api/v1/me/settings"


def test_a_plain_module_address_is_refused_and_the_catalog_stays(tmp_path):
    config, _ = _install(tmp_path, "standard", "papaia-assist-plain")
    assert catalog.render(config, REPO) is True
    before = (config / "platform" / "services.json").read_bytes()
    env = common.parse_env_file(config / ".env")
    env["PAPAIA_SECURITY_PROFILE"] = "kritis"
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in env.items()))
    with pytest.raises(catalog.CatalogError, match="assist-api.*refused"):
        catalog.render(config, REPO)
    assert (config / "platform" / "services.json").read_bytes() == before


# ── the containers: certificates and the override ────────────────────────────


def test_me_web_and_the_proxy_request_their_certificates_with_their_profiles():
    on = {r.label: (r.dns, r.client, r.uid) for r in pki.core_requests(REPO, {"me", "nginx"})}
    assert on["core/me-web"] == (("me-web",), False, 10001)
    assert on["core/nginx-proxy-manager"] == ((), True, None)
    off = {r.label for r in pki.core_requests(REPO, set())}
    assert not off & {"core/me-web", "core/nginx-proxy-manager"}


def test_the_override_mounts_the_certificates_and_checks_the_name(tmp_path):
    config, _ = _install(tmp_path, "kritis")
    gen_override.generate_overrides(config, REPO)
    path = config / "overrides" / module_tls.OVERRIDE
    override = yaml.safe_load(path.read_text())
    me = override["services"]["me-web"]
    assert "${PAPAIA_PKI_DIR}/core/me-web:/run/papaia/tls:ro" in me["volumes"]
    assert me["environment"]["UVICORN_SSL_CERTFILE"] == "/run/papaia/tls/tls.crt"
    assert me["environment"]["ME_MODULE_CA_FILE"] == "/run/papaia/tls/ca.crt"
    probe = " ".join(me["healthcheck"]["test"])
    assert "https://me-web:8000/readyz" in probe and "cafile='/run/papaia/tls/ca.crt'" in probe
    assert "CERT_NONE" not in probe and "check_hostname" not in probe
    edge = override["services"]["nginx-proxy-manager"]
    assert edge["volumes"] == ["${PAPAIA_PKI_DIR}/core/nginx-proxy-manager:/run/papaia/tls:ro"]
    # Only names the core compose files define; no new network or volume.
    assert set(override) == {"services"}


def test_the_override_follows_the_profile_and_the_active_services(tmp_path):
    config, _ = _install(tmp_path, "kritis")
    path = config / "overrides" / module_tls.OVERRIDE
    env = common.parse_env_file(config / ".env")
    env["COMPOSE_PROFILES"] = "keycloak,nginx"
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in env.items()))
    gen_override.generate_overrides(config, REPO)
    assert set(yaml.safe_load(path.read_text())["services"]) == {"nginx-proxy-manager"}
    env["PAPAIA_SECURITY_PROFILE"] = "standard"
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in env.items()))
    gen_override.generate_overrides(config, REPO)
    assert not path.exists()
