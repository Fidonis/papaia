"""Sign-in addresses of add-on clients from the manifest (addon_api 18, ADR 0028).

An add-on names, for a confidential client it owns in the names register, the paths of its
sign-in addresses on one of its own interfaces (`integration.nginx`):

    client_addresses:
      - client: flow-console
        host_key: flow
        redirects: [/auth/callback]
        post_logout: [/]
        backchannel_logout: /auth/backchannel-logout
        web_origin: true

The realm sync sets exactly these addresses on the add-on's host (scheme and port of the
edge), removes those the manifest no longer declares, and leaves a client without the key
as it was. Realm hardening takes them as the client's configured hosts. A client the
add-on does not own, a core client, a client that signs nobody in through the browser, an
unknown host key and every path that is not absolute and exact are refused; an older core
refuses the key through the generation gate.

The same flows run against a real Keycloak in tests/test_client_addresses_live.py.
"""

from __future__ import annotations

import json
import re

import pytest
import yaml

from lib import client_addresses as ca
from lib import compat
from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import (
    DELEGATION,
    REGISTER,
    _run,
    _studio,
    _tree,
    connected,  # noqa: F401  (fixture)
)

HOST = "https://flow.example.org"
CONSOLE = {
    "client": "flow-console",
    "host_key": "flow",
    "redirects": ["/auth/callback"],
    "post_logout": ["/"],
    "backchannel_logout": "/auth/backchannel-logout",
    "web_origin": True,
}
ENGINE = {
    "client": "flow-engine",
    "host_key": "flow",
    "redirects": ["/engine/test-run/callback"],
}
INGRESS = [{"host_key": "flow", "service": "flow-console", "port": 8080}]


def _flow(addresses=None, hosts=None) -> rs.Module:
    entry = {
        "id": "flow.runs",
        "kind": "rest",
        "audience": "flow",
        "identity": ["person"],
        "roles": [{"name": "flow-member"}, {"name": "flow-admin"}],
        "delegation": DELEGATION,
    }
    return rs.Module(
        "papaia-flow",
        [entry],
        {},
        client_addresses=addresses,
        host_keys=frozenset({"flow"}),
        hosts={"flow": HOST} if hosts is None else hosts,
    )


def _plan(*modules: rs.Module) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), [])


def _addresses(realm: FakeRealm, client_id: str) -> dict:
    client = realm.by_client_id(client_id)
    attributes = client.get("attributes") or {}
    return {
        "redirects": sorted(client.get("redirectUris") or []),
        "origins": sorted(client.get("webOrigins") or []),
        "post_logout": sorted(u for u in (attributes.get(rh.POST_LOGOUT) or "").split("##") if u),
        "backchannel": attributes.get(rh.BACKCHANNEL) or None,
    }


NONE = {"redirects": [], "origins": [], "post_logout": [], "backchannel": None}


def _manifest(addresses=None, **extra) -> dict:
    manifest = {
        "name": "papaia-flow",
        "version": "0.1.0",
        "requires": {"addon_api": [18]},
        "networks": {"app_network": "${PAPAIA_PROJECT:-papaia}-papaia-flow-net"},
        "integration": {"nginx": INGRESS},
        "client_addresses": [CONSOLE] if addresses is None else addresses,
    }
    manifest.update(extra)
    return manifest


def _core(current: int = 18) -> compat.CoreTarget:
    return compat.CoreTarget(platform_version="1.10.0", addon_api=(1, current))


# ─────────────────────────────────────────────────────────────────────────
# realm sync: what is planned and written
# ─────────────────────────────────────────────────────────────────────────


def test_the_sync_sets_exactly_the_declared_addresses_on_the_addon_host():
    realm = FakeRealm()
    plan = _plan(_flow([CONSOLE, ENGINE]))
    assert plan.client_addresses["flow-console"] == rh.ClientUris(
        (f"{HOST}/auth/callback",),
        (HOST,),
        post_logout=(f"{HOST}/",),
        backchannel=f"{HOST}/auth/backchannel-logout",
        declared=True,
    )
    _run(realm, plan)
    assert _addresses(realm, "flow-console") == {
        "redirects": [f"{HOST}/auth/callback"],
        "origins": [HOST],
        "post_logout": [f"{HOST}/"],
        "backchannel": f"{HOST}/auth/backchannel-logout",
    }
    # Without web_origin, post_logout and backchannel_logout: only the redirect.
    assert _addresses(realm, "flow-engine") == dict(
        NONE, redirects=[f"{HOST}/engine/test-run/callback"]
    )
    for client_id in ("flow-console", "flow-engine"):
        assert realm.by_client_id(client_id)["attributes"][rh.DECLARED] == rh.DECLARED_VALUE
    # Clients of the module without a declaration get no address.
    assert _addresses(realm, "papaia-flow-mcp-chat") == NONE


def test_a_second_sync_changes_nothing():
    realm = FakeRealm()
    plan = _plan(_flow([CONSOLE, ENGINE]))
    assert _run(realm, plan)
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_the_host_follows_the_scheme_and_port_of_the_edge():
    realm = FakeRealm()
    local = "https://flow.itest.papaia.localhost:8443"
    _run(realm, _plan(_flow([ENGINE], hosts={"flow": local})))
    assert _addresses(realm, "flow-engine")["redirects"] == [
        f"{local}/engine/test-run/callback"
    ]


def test_addresses_a_client_carried_before_are_replaced_by_the_declared_ones():
    realm = FakeRealm()
    _run(realm, _plan(_flow()))
    console = realm.by_client_id("flow-console")
    realm.call(
        "PUT",
        f"/clients/{console['id']}",
        {
            "redirectUris": ["https://flow.example.org/*", "https://elsewhere.example.org/cb"],
            "webOrigins": ["https://elsewhere.example.org"],
            "attributes": {**console["attributes"], rh.POST_LOGOUT: "https://flow.example.org/*"},
        },
    )
    _run(realm, _plan(_flow([CONSOLE])))
    assert _addresses(realm, "flow-console") == {
        "redirects": [f"{HOST}/auth/callback"],
        "origins": [HOST],
        "post_logout": [f"{HOST}/"],
        "backchannel": f"{HOST}/auth/backchannel-logout",
    }


def test_a_removed_entry_removes_its_addresses():
    realm = FakeRealm()
    _run(realm, _plan(_flow([CONSOLE, ENGINE])))
    _run(realm, _plan(_flow([ENGINE])))
    assert _addresses(realm, "flow-console") == NONE
    assert rh.DECLARED not in realm.by_client_id("flow-console")["attributes"]
    assert _addresses(realm, "flow-engine")["redirects"] == [f"{HOST}/engine/test-run/callback"]
    # The key gone altogether: no address stays.
    _run(realm, _plan(_flow()))
    assert _addresses(realm, "flow-engine") == NONE
    assert _run(realm, _plan(_flow())) == []


def test_a_removed_path_is_removed_and_check_reports_the_deviation_first():
    realm = FakeRealm()
    _run(realm, _plan(_flow([dict(ENGINE, redirects=["/a", "/b"])])))
    plan = _plan(_flow([dict(ENGINE, redirects=["/a"])]))
    changes = _run(realm, plan, apply=False)
    assert [(c.name, c.operation) for c in changes] == [("flow-engine", "harden_client")]
    _run(realm, plan)
    assert _addresses(realm, "flow-engine")["redirects"] == [f"{HOST}/a"]


def test_a_manifest_without_the_key_plans_no_change():
    """The client keeps what it carries; the golden realm-sync.json pins the rest."""
    realm = FakeRealm()
    _run(realm, _plan(_flow()))
    console = realm.by_client_id("flow-console")
    by_hand = {"redirectUris": [f"{HOST}/by-hand"], "webOrigins": [HOST]}
    realm.call("PUT", f"/clients/{console['id']}", by_hand)
    plan = _plan(_flow())
    assert plan.client_addresses == {}
    assert _run(realm, plan) == []
    assert _addresses(realm, "flow-console")["redirects"] == [f"{HOST}/by-hand"]


def test_a_disabled_addon_keeps_its_client_but_no_address():
    realm = FakeRealm()
    _run(realm, _plan(_flow([CONSOLE]), _studio()))
    _run(realm, _plan(_studio()))
    assert realm.by_client_id("flow-console")
    assert _addresses(realm, "flow-console") == NONE


def test_an_uninstalled_addon_takes_its_clients_and_their_addresses_along():
    realm = FakeRealm()
    _run(realm, _plan(_flow([CONSOLE]), _studio()))
    plan = _plan(_studio())
    plan.uninstalled = frozenset({"flow"})
    _run(realm, plan)
    remaining = {c["clientId"] for c in realm.clients.values()}
    assert not {"flow-console", "flow-engine"} & remaining
    for client in realm.clients.values():
        uris = [*(client.get("redirectUris") or []), *(client.get("webOrigins") or [])]
        assert not any(u.startswith(HOST) for u in uris), client["clientId"]


def test_without_a_host_name_the_client_gets_no_address_and_a_note():
    """`no_proxy`: the interfaces have no host names, so there is nothing to sign in at."""
    realm = FakeRealm()
    plan = _plan(_flow([CONSOLE], hosts={}))
    assert any("flow-console" in note and "no host name" in note for note in plan.notes)
    _run(realm, plan)
    assert _addresses(realm, "flow-console") == NONE


def test_every_write_leaves_one_audit_row_without_a_secret(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, _plan(_flow([CONSOLE])), audit=audit)
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert len(rows) == len(realm.writes)
    hardened = [r for r in rows if r["object_ref"]["id"] == "flow-console"
                and r["operation"].endswith(".harden_client")]
    assert len(hardened) == 1
    assert hardened[0]["format"] == "papaia.audit/1"
    assert hardened[0]["correlation_id"] == "run-1"
    assert "generated-by-keycloak" not in (tmp_path / "audit.jsonl").read_text()


# ─────────────────────────────────────────────────────────────────────────
# realm hardening keeps the declared addresses
# ─────────────────────────────────────────────────────────────────────────


HOSTS = {"PAPAIA_HOST": "https://papaia.example.org"}


def test_a_hardening_run_after_the_sync_keeps_declared_and_removes_undeclared_addresses():
    realm = FakeRealm()
    plan = _plan(_flow([CONSOLE]))
    plan.hardening = rh.load(HOSTS)
    _run(realm, plan)
    console = realm.by_client_id("flow-console")
    realm.call(
        "PUT",
        f"/clients/{console['id']}",
        {
            "redirectUris": [f"{HOST}/auth/callback", "https://evil.example.org/cb"],
            "webOrigins": [HOST, "*"],
            "attributes": {**console["attributes"], rh.BACKCHANNEL: "https://evil.example.org/"},
        },
    )
    later = _plan(_flow([CONSOLE]))
    later.hardening = rh.load(HOSTS)
    assert _run(realm, later, apply=False)
    _run(realm, later)
    assert _addresses(realm, "flow-console") == {
        "redirects": [f"{HOST}/auth/callback"],
        "origins": [HOST],
        "post_logout": [f"{HOST}/"],
        "backchannel": f"{HOST}/auth/backchannel-logout",
    }
    assert _run(realm, later) == []


def test_hardening_takes_the_declared_addresses_as_configured_hosts():
    declared = {"flow-engine": rh.ClientUris((f"{HOST}/cb",), (), post_logout=(), declared=True)}
    hardening = rh.with_declared(rh.load(HOSTS), declared)
    assert hardening.clients["flow-engine"] == declared["flow-engine"]
    client = {
        "clientId": "flow-engine",
        "redirectUris": [f"{HOST}/cb", f"{HOST}/*"],
        "attributes": {rh.MANAGED: "true"},
    }
    body, _ = rh.harden_client(client, hardening, uris_only=True)
    assert body["redirectUris"] == [f"{HOST}/cb"]


def test_the_kritis_profile_refuses_a_declared_plain_http_host():
    declared = {"flow-engine": rh.ClientUris(("http://flow.example.org/cb",), (), declared=True)}
    with pytest.raises(rh.HardeningError, match="flow-engine"):
        rh.with_declared(rh.load({rh.PROFILE_KEY: "kritis"}), declared)
    standard = rh.with_declared(rh.load({}), declared)
    assert any("flow-engine" in note for note in standard.notes)


def test_a_declared_client_cannot_take_over_a_client_of_the_realm_template():
    declared = {"librechat": rh.ClientUris((f"{HOST}/cb",), (), declared=True)}
    env = {"LITELLM_PUBLIC_URL": "https://llm.example.org"}
    hardening = rh.load(env, {"DOMAIN_CLIENT": "https://chat.example.org"})
    with pytest.raises(rh.HardeningError, match="librechat"):
        rh.with_declared(hardening, declared)


# ─────────────────────────────────────────────────────────────────────────
# refusals: compat (manifest error naming the entry) and realm sync
# ─────────────────────────────────────────────────────────────────────────


REFUSALS = [
    # a client the add-on does not own
    ([dict(CONSOLE, client="papaia-studio-gateway")], "belongs to papaia-studio"),
    # a core client
    ([dict(CONSOLE, client="librechat")], "client of the core"),
    ([dict(CONSOLE, client="papaia-people")], "client of the core"),
    ([dict(CONSOLE, client="papaia-manager")], "client of the core"),
    ([dict(CONSOLE, client="papaia-me")], "client of the core"),
    # a client that is not registered
    ([dict(CONSOLE, client="flow-hand-made")], "not a registered client"),
    # a public client and a bearer-only one
    ([dict(CONSOLE, client="flow-cli")], "public client"),
    ([dict(CONSOLE, client="flow")], "bearer-only"),
    # an unknown host key
    ([dict(CONSOLE, host_key="admin")], "host_key 'admin'"),
    # paths outside the rules
    ([dict(CONSOLE, redirects=["/auth/*"])], "wildcard"),
    ([dict(CONSOLE, redirects=["/auth/callback?next=/"])], "query"),
    ([dict(CONSOLE, redirects=["/auth/callback#frag"])], "fragment"),
    ([dict(CONSOLE, redirects=["/auth/../admin"])], r"'\.\.'"),
    ([dict(CONSOLE, redirects=["/auth//callback"])], "'//'"),
    ([dict(CONSOLE, redirects=["https://evil.example.org/cb"])], "absolute path"),
    ([dict(CONSOLE, redirects=["auth/callback"])], "absolute path"),
    ([dict(CONSOLE, redirects=["/auth/%2e%2e/admin"])], "characters"),
    ([dict(CONSOLE, post_logout=["/*"])], "wildcard"),
    ([dict(CONSOLE, backchannel_logout="/logout?x=1")], "query"),
    ([dict(CONSOLE, redirects=[f"/r{i}" for i in range(9)])], "at most 8"),
    ([dict(CONSOLE, redirects=[])], "at least one"),
    # shape
    ([dict(CONSOLE, scopes=["openid"])], "unknown field"),
    ([{k: v for k, v in CONSOLE.items() if k != "host_key"}], "missing field"),
    ([dict(CONSOLE, web_origin="yes")], "web_origin"),
    ([CONSOLE, CONSOLE], "declared twice"),
]


@pytest.mark.parametrize(("addresses", "message"), REFUSALS)
def test_compat_refuses_the_entry_and_names_it(addresses, message):
    result = compat.evaluate_addon("papaia-flow", _manifest(addresses), _core())
    assert result.status == compat.STATUS_ERROR
    assert result.axis == compat.CLIENT_ADDRESSES_AXIS
    assert re.search(r"client_addresses\[[01]\]", result.reason), result.reason
    assert re.search(message, result.reason), result.reason
    # An error is a malformed manifest: neither --force nor warn mode lets it in.
    assert compat.gate([result], mode=compat.MODE_WARN, force=True) == 2


@pytest.mark.parametrize(("addresses", "message"), REFUSALS)
def test_the_realm_sync_refuses_the_entry_before_any_write(addresses, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan(_flow(addresses))


def test_the_entry_names_the_index_and_the_client():
    result = compat.evaluate_addon(
        "papaia-flow", _manifest([ENGINE, dict(CONSOLE, redirects=["/x/*"])]), _core()
    )
    assert "client_addresses[1]" in result.reason
    assert "flow-console" in result.reason


def test_the_key_must_be_a_list_of_at_most_eight_entries():
    for value, message in (({"client": "flow-console"}, "must be a list"),
                           ([ENGINE] * 9, "at most 8")):
        result = compat.evaluate_addon("papaia-flow", _manifest(value), _core())
        assert result.status == compat.STATUS_ERROR
        assert message in result.reason


def test_a_host_key_needs_the_list_form_of_integration_nginx():
    manifest = _manifest([ENGINE], integration={"nginx": "nginx/flow.conf"})
    result = compat.evaluate_addon("papaia-flow", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert "host_key 'flow'" in result.reason


def test_a_valid_declaration_passes_compat():
    result = compat.evaluate_addon("papaia-flow", _manifest([CONSOLE, ENGINE]), _core())
    assert result.status == compat.STATUS_OK, result.reason


def test_the_exchange_only_chain_holder_is_refused():
    manifest = _manifest([dict(CONSOLE, client="papaia-data")], name="papaia-data")
    result = compat.evaluate_addon("papaia-data", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert "signs nobody in" in result.reason


def test_the_owner_is_the_manifest_name():
    manifest = _manifest([CONSOLE], name="not-flow")
    result = compat.evaluate_addon("papaia-flow", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert "belongs to papaia-flow" in result.reason


# ─────────────────────────────────────────────────────────────────────────
# generation gate
# ─────────────────────────────────────────────────────────────────────────


def test_the_key_is_a_generation_18_feature():
    assert compat.GENERATION_FEATURES["client_addresses"] == 18
    assert ("client_addresses", 18) in compat.manifest_generation_features(_manifest())


def test_an_older_core_refuses_the_key_through_the_generation_gate():
    result = compat.evaluate_addon(
        "papaia-flow", _manifest(requires={"addon_api": [12, 18]}), _core(17)
    )
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "missing generation 18" in result.reason
    assert "`client_addresses` (addon_api 18)" in result.reason
    assert compat.gate([result], mode=compat.MODE_ENFORCE) == 2


def test_a_manifest_that_names_an_older_generation_only_is_warned():
    result = compat.evaluate_addon(
        "papaia-flow", _manifest(requires={"addon_api": [12]}), _core()
    )
    assert result.status == compat.STATUS_OK
    assert any("client_addresses" in w and "18" in w for w in result.warnings)


def test_a_manifest_without_the_key_is_evaluated_as_before():
    manifest = _manifest()
    del manifest["client_addresses"]
    manifest["requires"] = {"addon_api": [12]}
    result = compat.evaluate_addon("papaia-flow", manifest, _core(17))
    assert result.status == compat.STATUS_OK
    assert result.warnings == ()


# ─────────────────────────────────────────────────────────────────────────
# the parser
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    ["/", "/auth/callback", "/auth/callback/", "/a-b_c.d~e/f", "/oauth2/callback"],
)
def test_exact_absolute_paths_pass(path):
    assert ca.path_problem(path) is None


def test_the_parser_returns_the_declarations_in_manifest_order():
    (console, engine) = ca.parse([CONSOLE, ENGINE], frozenset({"flow"}))
    assert console == ca.Declaration(
        "flow-console", "flow", ("/auth/callback",), ("/",), "/auth/backchannel-logout", True, 0
    )
    assert engine.post_logout == () and engine.backchannel_logout is None
    assert engine.web_origin is False and engine.index == 1


# ─────────────────────────────────────────────────────────────────────────
# installed add-ons: host names from the installation, the command
# ─────────────────────────────────────────────────────────────────────────


def _installed(tmp_path, addresses=None, *, active=True):
    repo_root, config_dir = tmp_path / "repo", tmp_path / "config"
    flow = repo_root / "papaia-flow"
    flow.mkdir(parents=True)
    manifest = _manifest([CONSOLE] if addresses is None else addresses)
    manifest["exposes"] = [_flow().exposes[0]]
    (flow / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    (config_dir / "addons" / "papaia-flow").mkdir(parents=True)
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "papaia-flow", "path": str(flow), "active": active}]})
    )
    return config_dir, repo_root


def test_an_installed_addon_gets_the_host_name_of_its_interface(tmp_path):
    config_dir, repo_root = _installed(tmp_path)
    root = {"PAPAIA_HOST": "https://papaia.example.org"}
    (module,) = rs.load_modules(config_dir, repo_root, root)
    assert module.client_addresses == [CONSOLE]
    assert module.host_keys == frozenset({"flow"})
    assert module.hosts == {"flow": "https://flow.papaia.example.org"}
    # A local installation: the edge's port and the .localhost names.
    local = {"PAPAIA_HOST": "https://localhost", "INGRESS_HTTPS_EXT_PORT": "8443",
             "COMPOSE_PROJECT_NAME": "papaia-itest"}
    (module,) = rs.load_modules(config_dir, repo_root, local)
    assert module.hosts == {"flow": "https://flow.itest.papaia.localhost:8443"}
    # The operator renamed the interface.
    renamed = dict(root, INGRESS_HOST_FLOW="ablaeufe")
    (module,) = rs.load_modules(config_dir, repo_root, renamed)
    assert module.hosts == {"flow": "https://ablaeufe.papaia.example.org"}


def test_an_addon_with_only_the_key_is_a_module(tmp_path):
    config_dir, repo_root = _installed(tmp_path)
    manifest_path = repo_root / "papaia-flow" / "papaia-app.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    del manifest["exposes"]
    manifest_path.write_text(yaml.safe_dump(manifest))
    (module,) = rs.load_modules(config_dir, repo_root, {"PAPAIA_HOST": "https://papaia.example.org"})
    assert module.client_addresses == [CONSOLE]


def test_without_a_proxy_the_addon_has_no_host_names(tmp_path):
    config_dir, repo_root = _installed(tmp_path)
    root = {"PAPAIA_HOST": "https://papaia.example.org", "REVERSE_PROXY_PROVIDER": "no_proxy"}
    (module,) = rs.load_modules(config_dir, repo_root, root)
    assert module.hosts == {}


def test_a_host_scheme_that_names_no_domain_refuses_the_sync(tmp_path):
    config_dir, repo_root = _installed(tmp_path)
    with pytest.raises(rs.RealmSyncError, match="papaia-flow"):
        rs.load_modules(config_dir, repo_root, {"PAPAIA_HOST": "http://192.168.1.20"})


def test_the_sync_command_sets_the_addresses_and_check_then_reports_ok(
    tmp_path, connected, capsys  # noqa: F811
):
    config_dir, repo_root = _installed(tmp_path, [CONSOLE, ENGINE])
    tree = _tree()
    tree[""].update(HOSTS)
    assert rs.sync(tree, config_dir, repo_root) == 0
    host = "https://flow.papaia.example.org"
    assert _addresses(connected, "flow-engine")["redirects"] == [
        f"{host}/engine/test-run/callback"
    ]
    assert _addresses(connected, "flow-console")["backchannel"] == (
        f"{host}/auth/backchannel-logout"
    )
    capsys.readouterr()
    assert rs.sync(tree, config_dir, repo_root, check=True) == 0
    assert "Realm check: ok (0 deviation(s))" in capsys.readouterr().out


def test_a_refused_declaration_stops_the_command_before_keycloak_is_contacted(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("Keycloak contacted")
    )
    config_dir, repo_root = _installed(tmp_path, [dict(CONSOLE, client="librechat")])
    tree = _tree()
    tree[""].update(HOSTS)
    assert rs.sync(tree, config_dir, repo_root) == 2
    err = capsys.readouterr().err
    assert "client_addresses[0]" in err and "Nothing was changed" in err
    assert not rs.audit_path(config_dir).exists()


def test_the_kritis_profile_refuses_the_command_for_a_plain_http_edge(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("Keycloak contacted")
    )
    config_dir, repo_root = _installed(tmp_path, [ENGINE])
    # Under kritis the proxy reaches Flow's interface over TLS only (lib/module_tls.py):
    # the add-on requests the server certificate of its interface's service.
    manifest_path = repo_root / "papaia-flow" / "papaia-app.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    manifest["pki"] = {
        "services": [{"name": "flow-console", "uid": 10001, "server": {"dns": ["flow-console"]}}]
    }
    manifest_path.write_text(yaml.safe_dump(manifest))
    tree = _tree()
    tree[""].update({"PAPAIA_HOST": "http://papaia.example.org", rh.PROFILE_KEY: "kritis"})
    assert rs.sync(tree, config_dir, repo_root) == 2
    assert "flow-engine" in capsys.readouterr().err


def test_a_disabled_addon_is_no_module(tmp_path):
    config_dir, repo_root = _installed(tmp_path, active=False)
    assert rs.load_modules(config_dir, repo_root, HOSTS) == []
