"""One sign-in, one sign-out and one entry page for every module (PLT-29, PLT-71).

Interface spec 2.3 and 2.6, security spec 1.7: the login theme comes from the kit's token
values, a sign-out in one module ends the sessions of every module within 300 s (the
back channel at once, otherwise the 240 s access token), and the main address of the
installation leads to the overview of Mein Bereich.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

import kit_snapshot
from lib import cli, ingress, npm_provision, paperless_gate, sign_in
from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import (
    _config,
    _flow,
    _plan,
    _run,
    _studio,
    _tree,
    connected,  # noqa: F401  (fixture)
)

TOOLS = Path(__file__).resolve().parents[1]
THEME = TOOLS.parent / "src/infra/keycloak/themes/papaia/login"
needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")

# The five modules of PLT-29-A1 and the client each signs persons in with.
MODULE_CLIENTS = {
    "me": "papaia-me",
    "papaia-flow": "flow-console",
    "papaia-studio": "papaia-studio-gateway",
    "papaia-assist": "assist-api",
    "papaia-data": "papaia-data-ui",
}


def _route(module: str, host_key: str, url: str) -> ingress.Route:
    return ingress.Route(module, host_key, (url.split("//")[1],), url, "svc", 8080, "http", "n")


ROUTES = [
    _route("papaia-flow", "flow", "https://flow.example.org"),
    _route("papaia-studio", "studio", "https://studio.example.org"),
    _route("papaia-studio", "apps", "https://apps.example.net"),
    _route("papaia-assist", "assistant", "https://assistant.example.org"),
    _route("papaia-data", "data", "https://data.example.org"),
]
ME_TREE = {"": {"COMPOSE_PROFILES": "keycloak,nginx,me"}}


# ─────────────────────────────────────────────────────────────────────────
# sign-out: one session end for every module
# ─────────────────────────────────────────────────────────────────────────


def test_every_module_names_one_registered_sign_in_client():
    register = rs.load_register()
    assert {c.module: c.client_id for c in sign_in.SIGN_IN_CLIENTS} == MODULE_CLIENTS
    for client in sign_in.SIGN_IN_CLIENTS:
        assert client.client_id in register.product_clients(), client.client_id


def test_mein_bereich_hears_of_a_sign_out_on_the_stack_network():
    assert sign_in.backchannel_targets(ME_TREE, []) == {
        "papaia-me": "http://me-web:8000/auth/backchannel-logout"
    }
    assert sign_in.backchannel_targets({"": {"COMPOSE_PROFILES": "keycloak"}}, []) == {}


def test_an_add_on_hears_of_a_sign_out_on_its_public_host():
    assert sign_in.backchannel_targets({"": {}}, ROUTES) == {
        "flow-console": "https://flow.example.org/auth/backchannel-logout",
        "papaia-studio-gateway": "https://studio.example.org/gw/v1/auth/backchannel-logout",
        "assist-api": "https://assistant.example.org/signin/backchannel-logout",
    }


def test_a_module_that_is_not_installed_gets_no_address():
    found = [r for r in ROUTES if r.module != "papaia-assist"]
    assert "assist-api" not in sign_in.backchannel_targets({"": {}}, found)


def _hardening(**sign_out: str) -> rh.Hardening:
    hardening = rh.load({})
    hardening.sign_out = dict(sign_out)
    hardening.sign_in_clients = sign_in.client_ids()
    return hardening


def test_a_sign_in_client_gets_the_back_channel_and_no_front_channel():
    url = "https://flow.example.org/auth/backchannel-logout"
    client = {"clientId": "flow-console", "frontchannelLogout": True, "attributes": {}}
    body, drift = rh.harden_client(client, _hardening(**{"flow-console": url}), uris_only=True)
    assert body["frontchannelLogout"] is False
    assert body["attributes"][rh.BACKCHANNEL_URL] == url
    assert body["attributes"][rh.BACKCHANNEL_SESSION] == "true"
    assert body["attributes"][rh.BACKCHANNEL_OFFLINE] == "false"
    assert body["attributes"][rh.LOGIN_THEME] == "papaia"
    assert {"frontchannelLogout", rh.BACKCHANNEL_URL} <= set(drift)


def test_a_client_in_line_is_left_alone_and_an_operators_theme_stays():
    url = "https://flow.example.org/auth/backchannel-logout"
    attributes = {
        rh.BACKCHANNEL_URL: url, rh.BACKCHANNEL_SESSION: "true", rh.BACKCHANNEL_OFFLINE: "false",
        rh.LOGIN_THEME: "own-theme",
    }  # fmt: skip
    client = {"clientId": "flow-console", "frontchannelLogout": False, "attributes": attributes}
    assert rh.harden_client(client, _hardening(**{"flow-console": url}), uris_only=True) == ({}, [])


def test_other_clients_get_neither_back_channel_nor_theme():
    client = {"clientId": "mcp-qdrant", "attributes": {}}
    assert rh.harden_client(client, _hardening(), uris_only=True) == ({}, [])


@pytest.mark.parametrize(
    "url",
    [
        "https://*.example.org/logout",
        "https://flow.example.org/auth/*",
        "/auth/backchannel-logout",
        "https://user@flow.example.org/x",
        "https://flow.example.org/x?next=1",
        "https://flow.example.org/x y",
        "https://flow.example.org/" + "a" * 2048,
    ],
)
def test_an_unusable_back_channel_address_is_refused(url):
    assert rh.backchannel_problem(url) is not None
    client = {"clientId": "flow-console", "attributes": {}}
    with pytest.raises(rh.HardeningError):
        rh.harden_client(client, _hardening(**{"flow-console": url}), uris_only=True)


def _sign_in_client(client_id: str, owner: str) -> dict:
    return {
        "clientId": client_id,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": True,
        "frontchannelLogout": True,
        "attributes": {rs.MANAGED: "true", rs.OWNER: owner, rh.PKCE: "S256"},
    }


def _session_end(client: dict, realm: dict) -> int:
    """Seconds after a sign-out elsewhere until this client's sessions are gone: at once
    with a back channel the provider calls (session id required, no front channel),
    otherwise when the access token runs out and the refresh fails."""
    attributes = client.get("attributes") or {}
    if (
        attributes.get(rh.BACKCHANNEL_URL)
        and attributes.get(rh.BACKCHANNEL_SESSION) == "true"
        and client.get("frontchannelLogout") is False
    ):
        return 0
    return int(realm["accessTokenLifespan"])


def test_sign_out_in_one_module_ends_the_sessions_of_all_modules_within_the_deadline():
    realm = FakeRealm()
    for owner, client_id in MODULE_CLIENTS.items():
        realm.call("POST", "/clients", _sign_in_client(client_id, owner))
    plan = _plan([_flow(), _studio()], [])
    plan.hardening = _hardening(**sign_in.backchannel_targets(ME_TREE, ROUTES))
    _run(realm, plan)
    ends = {
        client_id: _session_end(realm.by_client_id(client_id), realm.realm)
        for client_id in MODULE_CLIENTS.values()
    }
    assert max(ends.values()) < sign_in.DEADLINE, ends
    assert [c for c, end in ends.items() if end] == ["papaia-data-ui"]
    for client_id in MODULE_CLIENTS.values():
        assert realm.by_client_id(client_id)["attributes"][rh.LOGIN_THEME] == "papaia"
    assert _run(realm, plan) == []


def test_realm_sync_sets_the_back_channel_of_mein_bereich(tmp_path, connected):  # noqa: F811
    config_dir, repo_root = _config(tmp_path)
    connected.call("POST", "/clients", _sign_in_client("papaia-me", "papaia-me"))
    tree = _tree()
    tree[""]["COMPOSE_PROFILES"] = "keycloak,me"
    assert rs.sync(tree, config_dir, repo_root) == 0
    me = connected.by_client_id("papaia-me")
    assert me["attributes"][rh.BACKCHANNEL_URL] == "http://me-web:8000/auth/backchannel-logout"
    assert me["frontchannelLogout"] is False
    assert rs.sync(tree, config_dir, repo_root, check=True) == 0


def test_realm_sync_goes_on_when_the_add_on_hosts_cannot_be_listed(
    tmp_path, connected, monkeypatch, capsys  # noqa: F811
):
    def broken(*args):
        raise ingress.IngressError("PAPAIA_HOST names no domain")

    monkeypatch.setattr(ingress, "routes", broken)
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert "sign-out: add-on addresses not set" in capsys.readouterr().out


def test_realm_sync_goes_on_when_the_add_on_data_cannot_be_read(
    tmp_path, connected, monkeypatch, capsys  # noqa: F811
):
    def unreadable(*args):
        raise PermissionError("deployment.yaml: permission denied")

    monkeypatch.setattr(ingress, "routes", unreadable)
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert "sign-out: add-on addresses not set" in capsys.readouterr().out


def test_local_add_on_addresses_come_with_a_note_on_the_token_fallback(monkeypatch):
    root = {
        "PAPAIA_HOST": "http://localhost", "COMPOSE_PROJECT_NAME": "papaia-itest",
        "COMPOSE_PROFILES": "keycloak,nginx",
    }  # fmt: skip
    local = [_route("papaia-flow", "flow", "https://flow.itest.papaia.localhost:57143")]
    monkeypatch.setattr(ingress, "routes", lambda tree, config_dir, repo_root: local)
    targets, notes = sign_in.installation_targets({"": root}, Path("."), Path("."))
    assert targets == {
        "flow-console": "https://flow.itest.papaia.localhost:57143/auth/backchannel-logout"
    }
    assert len(notes) == 1 and "240 s" in notes[0] and "flow-console" in notes[0]
    server = [_route("papaia-flow", "flow", "https://flow.example.org")]
    monkeypatch.setattr(ingress, "routes", lambda tree, config_dir, repo_root: server)
    tree = {"": dict(root, PAPAIA_HOST="https://papaia.example.org")}
    assert sign_in.installation_targets(tree, Path("."), Path("."))[1] == []


def test_mein_bereich_turned_off_loses_the_back_channel_the_core_set():
    internal = "http://me-web:8000/auth/backchannel-logout"
    hardening = _hardening()
    hardening.sign_out_owned = sign_in.owned_addresses(ME_TREE)
    attributes = {rh.BACKCHANNEL_URL: internal, rh.LOGIN_THEME: "papaia"}
    client = {"clientId": "papaia-me", "frontchannelLogout": False, "attributes": attributes}
    body, drift = rh.harden_client(client, hardening, uris_only=True)
    assert body["attributes"][rh.BACKCHANNEL_URL] == ""
    assert drift == [rh.BACKCHANNEL_URL]
    cleared = dict(client, attributes=body["attributes"])
    assert rh.harden_client(cleared, hardening, uris_only=True) == ({}, [])
    own = dict(client, attributes=dict(attributes, **{rh.BACKCHANNEL_URL: "https://me.example.org/own"}))
    assert rh.harden_client(own, hardening, uris_only=True) == ({}, [])


# ─────────────────────────────────────────────────────────────────────────
# entry page
# ─────────────────────────────────────────────────────────────────────────


def _entry_tree(**root: str) -> dict:
    values = {
        "PAPAIA_HOST": "https://papaia.example.org",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "COMPOSE_PROFILES": "keycloak,nginx,me",
        "ME_PUBLIC_URL": "https://me.papaia.example.org",
    }
    values.update(root)
    return {"": values}


def test_the_main_address_leads_to_the_overview_of_mein_bereich():
    entry = sign_in.entry(_entry_tree())
    assert entry == sign_in.Entry(
        "papaia.example.org", "https://papaia.example.org", "https://me.papaia.example.org/"
    )


def test_the_local_scheme_has_an_entry_page_on_the_edge_port():
    entry = sign_in.entry(
        _entry_tree(
            PAPAIA_HOST="http://localhost",
            COMPOSE_PROJECT_NAME="papaia-itest",
            INGRESS_HTTPS_EXT_PORT="57143",
            ME_PUBLIC_URL="https://me.itest.papaia.localhost:57143",
        )
    )
    assert entry is not None
    assert entry.hostname == "itest.papaia.localhost"
    assert entry.target == "https://me.itest.papaia.localhost:57143/"


@pytest.mark.parametrize(
    "root",
    [
        {"COMPOSE_PROFILES": "keycloak,nginx"},
        {"REVERSE_PROXY_PROVIDER": "no_proxy"},
        {"PAPAIA_HOST": "http://192.168.1.20"},
        {"ME_PUBLIC_URL": ""},
        {"ME_PUBLIC_URL": "https://papaia.example.org:8443"},
        {"ME_PUBLIC_URL": "https://papaia.example.org"},
    ],
)
def test_without_a_served_mein_bereich_there_is_no_entry_page(root):
    assert sign_in.entry(_entry_tree(**root)) is None


def test_only_the_host_name_of_the_value_reaches_the_redirect():
    entry = sign_in.entry(_entry_tree(ME_PUBLIC_URL="https://me.papaia.example.org/;return 200"))
    assert entry is not None and entry.target == "https://me.papaia.example.org/"


@pytest.mark.parametrize(
    "target",
    ["https://me.example.org/x", "https://me.example.org/;", "javascript:x", "https://me.example.org"],
)
def test_the_redirect_takes_an_origin_only(target):
    with pytest.raises(ValueError):
        sign_in.redirect_config(target)


def test_the_proxy_host_of_the_main_address_redirects_before_forwarding():
    body = npm_provision.entry_host_body(sign_in.entry(_entry_tree()), _entry_tree()[""])
    assert body["domain_names"] == ["papaia.example.org"]
    advanced = body["advanced_config"]
    assert advanced.startswith(paperless_gate.strip_config())
    assert advanced.endswith("return 302 https://me.papaia.example.org/;\n")


def _provision(monkeypatch, tree: dict, hosts: list[dict]) -> list[tuple[str, object, dict]]:
    writes: list[tuple[str, object, dict]] = []
    tree = dict(tree, **{"infra/nginx": {"NPM_ADMIN_PASSWORD": "not-a-real-password"}})
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_list_proxy_hosts", lambda base_url, token: hosts)
    monkeypatch.setattr(
        npm_provision, "_put_proxy_host",
        lambda base_url, token, host_id, body: writes.append(("PUT", host_id, body)),
    )  # fmt: skip
    monkeypatch.setattr(
        npm_provision, "_post_proxy_host",
        lambda base_url, token, body: writes.append(("POST", None, body)),
    )  # fmt: skip
    assert npm_provision.provision_npm_hosts(tree) is True
    return writes


def _me_host(tree: dict) -> dict:
    """Mein Bereich's proxy host as setup creates it (npm-provision corrects a drifted one)."""
    return {**npm_provision.core_route_body(tree[""], "me"), "id": 1}


def test_the_bundled_proxy_gets_the_main_address(monkeypatch):
    tree = _entry_tree()
    existing = [{"id": 1, "domain_names": ["me.papaia.example.org"]}]
    writes = _provision(monkeypatch, tree, existing)
    entry = [w for w in writes if "papaia.example.org" in w[2].get("domain_names", [])]
    assert entry == [("POST", None, npm_provision.entry_host_body(sign_in.entry(tree), tree[""]))]


def test_a_drifted_main_address_gets_back_its_redirect_and_keeps_its_certificate(monkeypatch):
    tree = _entry_tree()
    wanted = npm_provision.entry_host_body(sign_in.entry(tree), tree[""])
    me = _me_host(tree)
    host = dict(wanted, id=7, certificate_id=3, advanced_config="")
    writes = _provision(monkeypatch, tree, [host, me])
    assert writes == [("PUT", 7, {k: wanted[k] for k in npm_provision.ENTRY_OWNED_FIELDS})]
    assert _provision(monkeypatch, tree, [dict(wanted, id=7), me]) == []


def test_without_mein_bereich_the_proxy_gets_no_main_address(monkeypatch):
    tree = _entry_tree(COMPOSE_PROFILES="keycloak,nginx")
    assert _provision(monkeypatch, tree, []) == []


def test_proxy_list_names_the_redirect_of_the_main_address():
    found = [_route("core", "me", "https://me.papaia.example.org")]
    entry = ("papaia.example.org", "https://me.papaia.example.org/")
    table = ingress.format_table("external_proxy", found, entry)
    row = r"^papaia\.example\.org\s+redirect 302 https://me\.papaia\.example\.org/"
    assert re.search(row, table, re.M)
    doc = json.loads(ingress.to_json("external_proxy", found, ("papaia.example.org", "https://x.org/")))
    assert doc["entry"] == {"hostname": "papaia.example.org", "redirect": "https://x.org/"}
    assert "entry" not in json.loads(ingress.to_json("external_proxy", found))


def test_the_proxy_list_command_prints_the_entry_page(tmp_path, monkeypatch, capsys):
    root = dict(_entry_tree()[""], REVERSE_PROXY_PROVIDER="external_proxy")
    monkeypatch.setattr(cli.envtree, "load_config_dir_tree", lambda config_dir, repo: {"": root})
    monkeypatch.setattr(ingress, "routes", lambda tree, config_dir, repo_root: [])
    args = cli.argparse.Namespace(
        config_dir=str(tmp_path), repo_root=str(tmp_path), if_external=False, json=False
    )
    assert cli.cmd_proxy_list(args) == 0
    assert "redirect 302 https://me.papaia.example.org/" in capsys.readouterr().out


def _chat_at_the_domain(**root: str) -> dict:
    tree = _entry_tree(COMPOSE_PROFILES="keycloak,nginx,me,librechat", **root)
    tree["ai/librechat"] = {"DOMAIN_SERVER": "https://papaia.example.org"}
    return tree


def test_a_main_address_served_by_another_interface_has_no_entry_page():
    found, note = sign_in.entry_and_note(_chat_at_the_domain())
    assert found is None
    assert "papaia.example.org" in note and "core:chat" in note
    addon = [_route("papaia-flow", "flow", "https://papaia.example.org")]
    found, note = sign_in.entry_and_note(_entry_tree(), addon)
    assert found is None and "papaia-flow:flow" in note
    assert sign_in.entry_and_note(_entry_tree(), ROUTES) == (sign_in.entry(_entry_tree()), None)


def test_chat_at_the_main_address_keeps_its_proxy_host(monkeypatch, capsys):
    tree = _chat_at_the_domain()
    chat = {
        "id": 4, "domain_names": ["papaia.example.org"], "forward_host": "librechat",
        "forward_port": 3080, "advanced_config": "",
    }  # fmt: skip
    me = {"id": 1, "domain_names": ["me.papaia.example.org"]}
    keycloak = {"id": 2, "domain_names": ["auth.papaia.example.org"]}
    hosts = [chat, me, keycloak]
    before = json.dumps(hosts, sort_keys=True)
    writes = _provision(monkeypatch, tree, hosts)
    main = [w for w in writes if w[1] == 4 or "papaia.example.org" in w[2].get("domain_names", [])]
    assert main == []
    assert json.dumps(hosts, sort_keys=True) == before
    assert "core:chat" in capsys.readouterr().err


def _record_deletes(monkeypatch) -> list[int]:
    deleted: list[int] = []
    monkeypatch.setattr(
        npm_provision, "_delete_proxy_host", lambda url, token, host_id: deleted.append(host_id)
    )
    return deleted


def test_an_operators_host_at_the_main_address_is_not_overwritten(monkeypatch, capsys):
    own = {
        "id": 9, "domain_names": ["papaia.example.org"], "forward_host": "intranet",
        "forward_port": 80, "advanced_config": "",
    }  # fmt: skip
    me = _me_host(_entry_tree())
    deleted = _record_deletes(monkeypatch)
    assert _provision(monkeypatch, _entry_tree(), [own, me]) == []
    assert deleted == []
    assert "papaia.example.org" in capsys.readouterr().err


def test_without_mein_bereich_the_entry_host_setup_created_is_removed(monkeypatch):
    wanted = npm_provision.entry_host_body(sign_in.entry(_entry_tree()), _entry_tree()[""])
    deleted = _record_deletes(monkeypatch)
    tree = _entry_tree(COMPOSE_PROFILES="keycloak,nginx")
    own = {"id": 9, "domain_names": ["papaia.example.org"], "forward_host": "intranet"}
    assert _provision(monkeypatch, tree, [own]) == [] and deleted == []
    assert _provision(monkeypatch, tree, [dict(wanted, id=7)]) == []
    assert deleted == [7]


def test_proxy_list_leaves_out_a_main_address_another_interface_serves(
    tmp_path, monkeypatch, capsys
):
    tree = _chat_at_the_domain(REVERSE_PROXY_PROVIDER="external_proxy")
    monkeypatch.setattr(cli.envtree, "load_config_dir_tree", lambda config_dir, repo: tree)
    monkeypatch.setattr(
        ingress, "routes", lambda tree, config_dir, repo_root: ingress.core_routes(tree)
    )
    args = cli.argparse.Namespace(
        config_dir=str(tmp_path), repo_root=str(tmp_path), if_external=False, json=False
    )
    assert cli.cmd_proxy_list(args) == 0
    out = capsys.readouterr()
    assert "redirect 302" not in out.out
    assert len(re.findall(r"^papaia\.example\.org\s", out.out, re.M)) == 1
    assert "core:chat" in out.err


# ─────────────────────────────────────────────────────────────────────────
# login theme from the kit's token values
# ─────────────────────────────────────────────────────────────────────────


def _properties(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return dict(
        line.split("=", 1) for line in lines if "=" in line and not line.startswith("#")
    )


@needs_kit
def test_the_login_theme_loads_the_kits_styles_first_and_the_brand_layer_last():
    from importlib import resources

    import papaia_kit

    kit = resources.files(papaia_kit).joinpath(*kit_snapshot.KIT_THEME[:-1], "theme.properties")
    kit_props = dict(
        line.split("=", 1)
        for line in kit.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )
    core = _properties(THEME / "theme.properties")
    assert core["parent"] == kit_props["parent"]
    styles = core["styles"].split()
    assert styles[: len(kit_props["styles"].split())] == kit_props["styles"].split()
    assert styles[-1] == "css/papaia.css"


def test_every_kit_theme_file_is_in_the_core_theme():
    for rel in kit_snapshot.THEME_OUTPUTS:
        assert (TOOLS / rel).resolve().is_file(), rel
    assert (THEME / "resources/css/tokens.css").read_bytes().startswith(b"/* Generated")


def test_the_brand_layer_takes_its_values_from_the_kit_tokens():
    css = (THEME / "resources/css/papaia.css").read_text(encoding="utf-8")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgb\(|hsl\(", css)
    assert "var(--pk-color-primary)" in css



def test_rendering_copies_the_theme_fonts_byte_for_byte_and_honours_the_overlay(tmp_path):
    from lib import render_core

    repo, config = tmp_path / "repo", tmp_path / "config"
    theme = "infra/keycloak/themes/papaia"
    font = f"{theme}/login/resources/fonts/manrope-latin-700-normal.woff2"
    (repo / "src" / font).parent.mkdir(parents=True)
    data = (TOOLS.parent / "src" / font).read_bytes()
    (repo / "src" / font).write_bytes(data)
    (repo / "src" / theme / "login/theme.properties").write_text("parent=keycloak.v2\n")
    render_core._render_dir(theme, repo, config, [])
    assert (config / font).read_bytes() == data
    (config / "overlay" / font).parent.mkdir(parents=True)
    (config / "overlay" / font).write_bytes(b"\x00\xffown")
    render_core._render_dir(theme, repo, config, [])
    assert (config / font).read_bytes() == b"\x00\xffown"
    assert (config / theme / "login/theme.properties").read_text() == "parent=keycloak.v2\n"
