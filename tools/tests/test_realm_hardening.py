"""Realm hardening: realm settings, sign-in clients and the client policy (security 1.7).

The settings come from the security profile (`standard` or `kritis`) and two optional
offline-session settings; the redirect URIs and web origins of the realm template's
clients come from the configured hosts. The same target is baked into the rendered realm
for a new installation and applied by `papaia-ctl realm sync` to an existing one.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from lib import realm_hardening as rh
from lib import realm_sync as rs
from lib import render_core
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import (
    DELEGATION,
    _config,
    _flow,
    _pairings,
    _paperless,
    _plan,
    _run,
    _studio,
    _tree,
    connected,  # noqa: F401  (fixture)
)

REAL_REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REAL_REPO / "src/infra/keycloak/realm-import/papaia-realm.json.template"
DAY = 86400

HOSTS = {
    "PAPAIA_HOST": "https://papaia.example.org",
    "OAUTH2_PROXY_EXT_PORT": "4180",
    "LITELLM_PUBLIC_URL": "https://llm.example.org",
    "LOCALAI_PUBLIC_URL": "https://localai.example.org",
    "MANAGER_PUBLIC_URL": "https://manager.example.org/",
    "NPM_ADMIN_HOST": "https://npm.example.org",
}
LIBRECHAT = {
    "DOMAIN_CLIENT": "https://chat.example.org",
    "DOMAIN_SERVER": "https://chat.example.org",
}


# ─────────────────────────────────────────────────────────────────────────
# settings per profile
# ─────────────────────────────────────────────────────────────────────────


def test_the_standard_profile_hardens_the_realm():
    realm = rh.load({}).settings.realm()
    assert realm["sslRequired"] == "external"
    assert realm["registrationAllowed"] is False
    assert realm["editUsernameAllowed"] is False
    assert realm["accessTokenLifespan"] <= 300
    assert realm["revokeRefreshToken"] is True
    assert realm["refreshTokenMaxReuse"] == 0
    assert realm["bruteForceProtected"] is True
    assert realm["permanentLockout"] is False
    assert realm["failureFactor"] == 5
    assert realm["waitIncrementSeconds"] == 60
    assert realm["maxFailureWaitSeconds"] == 900
    assert realm["ssoSessionIdleTimeout"] == 1800
    assert realm["ssoSessionMaxLifespan"] == 36000
    assert realm["offlineSessionIdleTimeout"] == 30 * DAY
    assert realm["offlineSessionMaxLifespanEnabled"] is True
    assert realm["offlineSessionMaxLifespan"] == 180 * DAY


def test_the_kritis_profile_requires_tls_everywhere_and_shortens_offline_sessions():
    realm = rh.load({rh.PROFILE_KEY: "kritis"}).settings.realm()
    assert realm["sslRequired"] == "all"
    assert realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert realm["offlineSessionMaxLifespanEnabled"] is True
    assert realm["offlineSessionMaxLifespan"] == 30 * DAY


@pytest.mark.parametrize(
    ("env", "idle", "age"),
    [
        ({rh.PROFILE_KEY: "kritis", rh.IDLE_KEY: "3", rh.MAX_KEY: "14"}, 3, 14),
        # the handbook's recommendation for every federated installation
        ({rh.PROFILE_KEY: "standard", rh.IDLE_KEY: "7", rh.MAX_KEY: "30"}, 7, 30),
        ({rh.IDLE_KEY: '"10"'}, 10, 180),
        ({rh.IDLE_KEY: "", rh.MAX_KEY: ""}, 30, 180),
    ],
)
def test_offline_session_limits_are_a_setting_without_code_change(env, idle, age):
    settings = rh.load(env).settings
    assert (settings.idle_days, settings.max_days) == (idle, age)
    assert settings.realm()["offlineSessionIdleTimeout"] == idle * DAY
    assert settings.realm()["offlineSessionMaxLifespan"] == age * DAY


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({rh.PROFILE_KEY: "strict"}, "standard or kritis"),
        ({rh.IDLE_KEY: "31"}, "1 to 30"),
        ({rh.MAX_KEY: "181"}, "1 to 180"),
        ({rh.PROFILE_KEY: "kritis", rh.IDLE_KEY: "8"}, "1 to 7"),
        ({rh.PROFILE_KEY: "kritis", rh.MAX_KEY: "31"}, "1 to 30"),
        ({rh.IDLE_KEY: "0"}, "1 to 30"),
        ({rh.IDLE_KEY: "-1"}, "1 to 30"),
        ({rh.IDLE_KEY: "7.5"}, "whole number"),
        ({rh.MAX_KEY: "abc"}, "whole number"),
        ({rh.IDLE_KEY: "20", rh.MAX_KEY: "10"}, "below"),
    ],
)
def test_settings_outside_the_profile_are_refused(env, message):
    with pytest.raises(rh.HardeningError, match=message):
        rh.load(env)


# ─────────────────────────────────────────────────────────────────────────
# redirect URIs and web origins
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("uri", "https_only", "problem"),
    [
        ("https://chat.example.org/*", True, None),
        ("https://chat.example.org/oauth/openid/callback", True, None),
        ("https://chat.example.org/cb*", True, None),
        ("http://host.docker.internal:8000/*", False, None),
        ("http://host.docker.internal:8000/*", True, "https"),
        ("*", False, "wildcard"),
        ("+", False, "wildcard"),
        ("/*", False, "absolute"),
        ("chat.example.org/cb", False, "absolute"),
        ("https://*.example.org/cb", False, "host"),
        ("https://*/cb", False, "host"),
        ("https:///cb", False, "host"),
        ("*://chat.example.org/cb", False, "absolute"),
        ("https://chat.example.org/*/cb", False, "last character"),
        ("https://chat.example.org/cb?next=*", False, "query"),
        ("https://user@chat.example.org/cb", False, "user"),
    ],
)
def test_a_redirect_uri_names_a_full_host_and_a_wildcard_only_at_the_end(uri, https_only, problem):
    found = rh.redirect_problem(uri, https_only=https_only)
    if problem is None:
        assert found is None
    else:
        assert found is not None and problem in found


def test_redirect_uris_and_origins_follow_the_configured_hosts():
    clients = rh.load(HOSTS, LIBRECHAT).clients
    assert clients["librechat"] == rh.ClientUris(
        ("https://chat.example.org/*",), ("https://chat.example.org",)
    )
    assert clients["litellm"] == rh.ClientUris(
        ("https://llm.example.org/*",), ("https://llm.example.org",)
    )
    assert clients["localai"].redirects == ("https://localai.example.org/*",)
    assert clients["papaia-manager"].redirects == ("https://manager.example.org/*",)
    assert clients["oauth2-proxy"] == rh.ClientUris(
        (
            "https://papaia.example.org:4180/oauth2/callback",
            "https://npm.example.org/oauth2/callback",
        ),
        ("https://papaia.example.org:4180", "https://npm.example.org"),
    )
    for uris in clients.values():
        for uri in uris.redirects:
            assert rh.redirect_problem(uri, https_only=True) is None
        for origin in uris.origins:
            assert origin.startswith("https://") and origin.count("/") == 2


def test_a_service_on_a_sub_path_gets_redirects_below_that_path():
    clients = rh.load({"LITELLM_PUBLIC_URL": "https://papaia.example.org/llm/"}).clients
    assert clients["litellm"].redirects == ("https://papaia.example.org/llm/*",)
    assert clients["litellm"].origins == ("https://papaia.example.org",)


def test_a_host_that_is_not_set_gives_its_client_no_redirect():
    clients = rh.load({"LITELLM_PUBLIC_URL": "", "MANAGER_PUBLIC_URL": "CHANGE_ME"}).clients
    assert "litellm" not in clients
    assert "papaia-manager" not in clients


@pytest.mark.parametrize("value", ["not a url", "https://*.example.org", "ftp://x.example.org"])
def test_a_host_that_is_no_url_is_refused(value):
    with pytest.raises(rh.HardeningError, match="LITELLM_PUBLIC_URL"):
        rh.load({"LITELLM_PUBLIC_URL": value})


def test_the_kritis_profile_refuses_a_plain_http_host():
    with pytest.raises(rh.HardeningError, match="https"):
        rh.load({rh.PROFILE_KEY: "kritis", "LITELLM_PUBLIC_URL": "http://llm.example.org"})


def test_a_plain_http_host_is_noted_in_the_standard_profile():
    hardening = rh.load({"LITELLM_PUBLIC_URL": "http://host.docker.internal:8200"})
    assert hardening.clients["litellm"].redirects == ("http://host.docker.internal:8200/*",)
    assert any("http://host.docker.internal:8200" in note for note in hardening.notes)


# ─────────────────────────────────────────────────────────────────────────
# one client
# ─────────────────────────────────────────────────────────────────────────


def _template_client(client_id: str) -> dict:
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    return next(c for c in template["clients"] if c["clientId"] == client_id)


def test_a_template_client_gets_exactly_the_uris_of_its_host():
    hardening = rh.load(HOSTS, LIBRECHAT)
    client = {
        "clientId": "litellm",
        "publicClient": False,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "implicitFlowEnabled": True,
        "redirectUris": ["*"],
        "webOrigins": ["+"],
        "attributes": {"post.logout.redirect.uris": "*", "login_theme": "papaia"},
    }
    body, drift = rh.harden_client(client, hardening)
    assert body["directAccessGrantsEnabled"] is False
    assert body["implicitFlowEnabled"] is False
    assert body["redirectUris"] == ["https://llm.example.org/*"]
    assert body["webOrigins"] == ["https://llm.example.org"]
    assert body["attributes"] == {
        "post.logout.redirect.uris": "https://llm.example.org/*",
        "login_theme": "papaia",
    }
    assert set(drift) >= {"directAccessGrantsEnabled", "implicitFlowEnabled", "redirectUris"}
    client.update(body)
    assert rh.harden_client(client, hardening) == ({}, [])


def test_wildcards_of_a_client_without_a_configured_host_are_dropped():
    hardening = rh.load({})
    client = {
        "clientId": "customer-app",
        "publicClient": False,
        "standardFlowEnabled": True,
        "rootUrl": "https://app.example.org",
        "redirectUris": ["*", "/login", "https://app.example.org/cb", "https://*.example.org/x"],
        "webOrigins": ["+", "*", "https://app.example.org"],
        "attributes": {"post.logout.redirect.uris": "+##*"},
    }
    body, drift = rh.harden_client(client, hardening)
    assert sorted(body["redirectUris"]) == ["/login", "https://app.example.org/cb"]
    assert body["webOrigins"] == ["https://app.example.org"]
    assert body["attributes"]["post.logout.redirect.uris"] == "/login##https://app.example.org/cb"
    assert "redirectUris" in drift
    client.update(body)
    assert rh.harden_client(client, hardening) == ({}, [])


def test_a_relative_redirect_without_an_absolute_root_url_is_dropped():
    client = {"clientId": "x", "standardFlowEnabled": True, "redirectUris": ["/cb"]}
    body, _ = rh.harden_client(client, rh.load({}))
    assert body["redirectUris"] == []


def test_a_public_client_with_the_code_flow_gets_pkce_s256():
    client = {"clientId": "cli", "publicClient": True, "standardFlowEnabled": True}
    body, drift = rh.harden_client(client, rh.load({}))
    assert body["attributes"]["pkce.code.challenge.method"] == "S256"
    assert "pkce.code.challenge.method" in drift


def test_a_public_client_never_carries_standard_token_exchange():
    """PLT-21-A8: only confidential clients may exchange tokens."""
    client = {
        "clientId": "cli",
        "publicClient": True,
        "standardFlowEnabled": False,
        "attributes": {"standard.token.exchange.enabled": "true"},
    }
    body, drift = rh.harden_client(client, rh.load({}))
    assert body["attributes"]["standard.token.exchange.enabled"] == "false"
    assert "standard.token.exchange.enabled" in drift
    confidential = dict(client, publicClient=False)
    assert rh.harden_client(confidential, rh.load({})) == ({}, [])


def test_keycloaks_own_clients_lose_the_password_grant_but_keep_their_uris():
    admin_cli = {
        "clientId": "admin-cli",
        "publicClient": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "redirectUris": [],
    }
    body, drift = rh.harden_client(admin_cli, rh.load({}))
    assert drift == ["directAccessGrantsEnabled"]
    assert body["directAccessGrantsEnabled"] is False
    assert "redirectUris" not in body
    console = {
        "clientId": "security-admin-console",
        "publicClient": True,
        "standardFlowEnabled": True,
        "rootUrl": "${authAdminUrl}",
        "redirectUris": ["/admin/papaia/console/*"],
        "webOrigins": ["+"],
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+"},
    }
    assert rh.harden_client(console, rh.load({})) == ({}, [])


def test_an_update_names_the_switches_and_all_attributes():
    """The client policy checks switches and PKCE method on every update of a managed
    client (Keycloak 26.7.0 answers 400, or 500 for a missing switch, otherwise)."""
    client = {
        "clientId": "flow-engine",
        "publicClient": False,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "redirectUris": ["*"],
        "attributes": {"papaia.managed": "true", "pkce.code.challenge.method": "S256"},
    }
    body, drift = rh.harden_client(client, rh.load({}), uris_only=True)
    assert drift == ["redirectUris"]
    assert body == {
        "redirectUris": [],
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "attributes": client["attributes"],
    }
    del client["attributes"]["pkce.code.challenge.method"]
    body, _ = rh.harden_client(client, rh.load({}), uris_only=True)
    assert body["attributes"]["pkce.code.challenge.method"] == "S256"


def test_a_bearer_only_client_is_left_alone():
    client = {"clientId": "broker", "bearerOnly": True, "directAccessGrantsEnabled": True}
    assert rh.harden_client(client, rh.load({})) == ({}, [])


# ─────────────────────────────────────────────────────────────────────────
# the realm template and the rendered realm
# ─────────────────────────────────────────────────────────────────────────


def test_the_realm_template_carries_the_settings_of_the_standard_profile():
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    for key, value in rh.Settings().realm().items():
        assert template.get(key) == value, key


def test_the_realm_template_has_no_wildcard_and_no_password_grant():
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    for client in template["clients"]:
        label = client["clientId"]
        assert client.get("directAccessGrantsEnabled") is False, label
        assert client.get("implicitFlowEnabled") is False, label
        assert client.get("redirectUris", []) == [], label
        assert client.get("webOrigins", []) == [], label
        assert "post.logout.redirect.uris" not in (client.get("attributes") or {}), label


def test_the_realm_template_ships_no_test_user_and_no_known_password():
    """PLT-21-A3: no `testuser`; the realm's `admin` gets no password from the template,
    only the forced change; the password is generated at setup and baked in."""
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    users = {u["username"]: u for u in template.get("users") or []}
    assert set(users) == {"admin"}
    assert "credentials" not in users["admin"]
    assert users["admin"]["requiredActions"] == ["UPDATE_PASSWORD"]
    assert rh.user_problems(template) == []


def _bake(tmp_path: Path, env: dict, librechat: dict, keycloak: dict | None = None) -> dict:
    repo_root, config_dir = tmp_path / "repo", tmp_path / "config"
    target = repo_root / "src/infra/keycloak/realm-import/papaia-realm.json.template"
    target.parent.mkdir(parents=True)
    shutil.copy(TEMPLATE, target)
    secrets = {
        key: "not-a-real-secret"
        for key in (
            "KC_LIBRECHAT_CLIENT_SECRET",
            "KC_LITELLM_CLIENT_SECRET",
            "KC_OAUTH2_PROXY_CLIENT_SECRET",
            "KC_LOCALAI_CLIENT_SECRET",
            "KC_MANAGER_CLIENT_SECRET",
            rh.REALM_ADMIN_PASSWORD_KEY,
        )
    }
    secrets.update(keycloak or {})
    (config_dir / "infra/keycloak").mkdir(parents=True)
    (config_dir / "ai/librechat").mkdir(parents=True)
    (config_dir / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    (config_dir / "infra/keycloak/.env").write_text(
        "".join(f"{k}={v}\n" for k, v in secrets.items())
    )
    (config_dir / "ai/librechat/.env").write_text(
        "".join(f"{k}={v}\n" for k, v in librechat.items())
    )
    render_core.bake_realm_secrets(repo_root, config_dir)
    rendered = config_dir / "infra/keycloak/realm-import/papaia-realm.json"
    return json.loads(rendered.read_text(encoding="utf-8"))


def test_the_rendered_realm_has_the_settings_and_the_uris_of_the_hosts(tmp_path):
    realm = _bake(tmp_path, {"AUTH_HOST": "https://auth.example.org", **HOSTS}, LIBRECHAT)
    for key, value in rh.Settings().realm().items():
        assert realm[key] == value, key
    clients = {c["clientId"]: c for c in realm["clients"]}
    assert clients["librechat"]["redirectUris"] == ["https://chat.example.org/*"]
    assert clients["librechat"]["webOrigins"] == ["https://chat.example.org"]
    assert clients["oauth2-proxy"]["redirectUris"] == [
        "https://papaia.example.org:4180/oauth2/callback",
        "https://npm.example.org/oauth2/callback",
    ]
    assert clients["litellm"]["attributes"]["post.logout.redirect.uris"] == (
        "https://llm.example.org/*"
    )
    for client in realm["clients"]:
        for uri in client.get("redirectUris") or []:
            assert rh.redirect_problem(uri, https_only=True) is None, client["clientId"]


def test_the_rendered_realm_of_the_kritis_profile(tmp_path):
    env = {"AUTH_HOST": "https://auth.example.org", rh.PROFILE_KEY: "kritis", **HOSTS}
    realm = _bake(tmp_path, env, LIBRECHAT)
    assert realm["sslRequired"] == "all"
    assert realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert realm["offlineSessionMaxLifespan"] == 30 * DAY
    assert realm["offlineSessionMaxLifespanEnabled"] is True


def test_rendering_refuses_a_profile_it_does_not_know(tmp_path):
    with pytest.raises(render_core.RenderError, match=rh.PROFILE_KEY):
        _bake(tmp_path, {rh.PROFILE_KEY: "strict"}, {})


def test_the_rendered_realm_has_no_account_with_a_known_password(tmp_path):
    realm = _bake(tmp_path, HOSTS, LIBRECHAT)
    (admin,) = realm["users"]
    assert admin["username"] == "admin"
    assert admin["credentials"] == [
        {"type": "password", "value": "not-a-real-secret", "temporary": True}
    ]
    assert admin["requiredActions"] == ["UPDATE_PASSWORD"]
    assert rh.user_problems(realm) == []


@pytest.mark.parametrize("value", ["", "GENERATE_KC_REALM_ADMIN_PASSWORD"])
def test_without_a_generated_password_the_admin_account_gets_none(tmp_path, value):
    """External OIDC leaves the Keycloak secrets unset; the account then has no password
    at all (no sign-in until one is set in the admin console), never a known one."""
    realm = _bake(tmp_path, HOSTS, LIBRECHAT, {rh.REALM_ADMIN_PASSWORD_KEY: value})
    (admin,) = realm["users"]
    assert "credentials" not in admin


@pytest.mark.parametrize("value", ["admin", "short"])
def test_a_realm_admin_password_that_is_no_generated_value_is_refused(tmp_path, value):
    with pytest.raises(render_core.RenderError, match=rh.REALM_ADMIN_PASSWORD_KEY):
        _bake(tmp_path, HOSTS, LIBRECHAT, {rh.REALM_ADMIN_PASSWORD_KEY: value})


@pytest.mark.parametrize(
    "credential, actions, problem",
    [
        ({"type": "password", "value": "x" * 32, "temporary": False}, ["UPDATE_PASSWORD"], "temp"),
        ({"type": "password", "value": "testuser", "temporary": True}, ["UPDATE_PASSWORD"], "own"),
        ({"type": "password", "value": "x" * 32, "temporary": True}, [], "UPDATE_PASSWORD"),
    ],
)
def test_a_realm_user_with_a_fixed_password_is_a_problem(credential, actions, problem):
    realm = {
        "users": [
            {"username": "testuser", "credentials": [credential], "requiredActions": actions}
        ]
    }
    (found,) = rh.user_problems(realm)
    assert "testuser" in found and problem in found


def test_rendering_refuses_a_realm_user_with_a_fixed_password(tmp_path, monkeypatch):
    fixed = {
        "username": "testuser",
        "credentials": [{"type": "password", "value": "testuser", "temporary": False}],
    }
    original = rh.apply_to_realm

    def with_test_user(realm, hardening):
        realm["users"].append(fixed)
        original(realm, hardening)

    monkeypatch.setattr(rh, "apply_to_realm", with_test_user)
    with pytest.raises(render_core.RenderError, match="testuser"):
        _bake(tmp_path, HOSTS, LIBRECHAT)


# ─────────────────────────────────────────────────────────────────────────
# realm sync against the in-memory Admin API
# ─────────────────────────────────────────────────────────────────────────


def _hardened_plan(env: dict | None = None, librechat: dict | None = None) -> rs.Plan:
    plan = _plan(
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(("flow-engine", "mcp-paperless", ["r"], "confirmed")),
    )
    plan.hardening = rh.load(env or {}, librechat)
    return plan


def _template_realm() -> FakeRealm:
    """A realm as the 1.9.0 template left it: LibreChat with wildcards."""
    realm = FakeRealm()
    client = _template_client("librechat")
    client = dict(client, redirectUris=["*"], webOrigins=["+"])
    client["attributes"] = dict(client["attributes"], **{"post.logout.redirect.uris": "*"})
    realm.call("POST", "/clients", client)
    realm.writes.clear()
    return realm


def test_the_sync_hardens_the_realm_and_a_second_run_changes_nothing():
    realm = _template_realm()
    plan = _hardened_plan(HOSTS, LIBRECHAT)
    changes = _run(realm, plan)
    assert changes
    for key, value in rh.Settings().realm().items():
        assert realm.realm[key] == value, key
    librechat = realm.by_client_id("librechat")
    assert librechat["redirectUris"] == ["https://chat.example.org/*"]
    assert librechat["webOrigins"] == ["https://chat.example.org"]
    assert realm.by_client_id("admin-cli")["directAccessGrantsEnabled"] is False
    for client in realm.clients.values():
        if not client.get("bearerOnly"):
            assert client["directAccessGrantsEnabled"] is False, client["clientId"]
            assert client["implicitFlowEnabled"] is False, client["clientId"]
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_the_sync_applies_the_values_of_the_kritis_profile():
    realm = FakeRealm()
    assert _run(realm, _hardened_plan()) != []
    assert realm.realm["sslRequired"] == "external"
    plan = _hardened_plan({rh.PROFILE_KEY: "kritis"})
    changes = _run(realm, plan)
    assert [c.operation for c in changes] == ["update_realm"]
    assert realm.realm["sslRequired"] == "all"
    assert realm.realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert realm.realm["offlineSessionMaxLifespan"] == 30 * DAY
    assert realm.realm["offlineSessionMaxLifespanEnabled"] is True
    assert _run(realm, plan) == []


def test_an_offline_session_setting_is_applied_without_code_change():
    realm = FakeRealm()
    _run(realm, _hardened_plan({rh.PROFILE_KEY: "kritis"}))
    plan = _hardened_plan({rh.PROFILE_KEY: "kritis", rh.IDLE_KEY: "5", rh.MAX_KEY: "20"})
    _run(realm, plan)
    assert realm.realm["offlineSessionIdleTimeout"] == 5 * DAY
    assert realm.realm["offlineSessionMaxLifespan"] == 20 * DAY


def test_drift_in_a_realm_setting_is_reported_and_corrected():
    realm = FakeRealm()
    plan = _hardened_plan()
    _run(realm, plan)
    realm.realm.update(editUsernameAllowed=True, sslRequired="none")
    changes = _run(realm, plan, apply=False)
    assert [(c.kind, c.action) for c in changes] == [
        ("realm", "settings corrected (editUsernameAllowed, sslRequired)")
    ]
    _run(realm, plan)
    assert realm.realm["editUsernameAllowed"] is False
    assert realm.realm["sslRequired"] == "external"


def test_managed_clients_get_pkce_and_the_policy_enforces_it():
    realm = FakeRealm()
    plan = _hardened_plan()
    _run(realm, plan)
    for client_id, spec in plan.clients.items():
        attributes = realm.by_client_id(client_id)["attributes"]
        assert attributes["pkce.code.challenge.method"] == "S256", (client_id, spec.kind)
    assert [p["name"] for p in realm.profiles] == [rh.CLIENT_POLICY]
    executors = {e["executor"] for e in realm.profiles[0]["executors"]}
    assert executors == {"pkce-enforcer", "reject-implicit-grant", "reject-ropc-grant"}
    policy = realm.policies[0]
    assert policy["enabled"] is True
    assert policy["profiles"] == [rh.CLIENT_POLICY]
    condition = policy["conditions"][0]
    assert condition["condition"] == "client-attributes"
    assert json.loads(condition["configuration"]["attributes"]) == [
        {"key": "papaia.managed", "value": "true"}
    ]


def test_a_realm_from_before_the_policy_is_upgraded_in_one_run():
    """Managed clients of an earlier sync carry no PKCE method; the policy that refuses
    their update without one is set only after they have it."""
    realm = FakeRealm()
    plan = _hardened_plan()
    _run(realm, plan)
    realm.policies.clear()
    realm.profiles.clear()
    for client_id in plan.clients:
        realm.by_client_id(client_id)["attributes"].pop("pkce.code.challenge.method")
        realm.by_client_id(client_id)["fullScopeAllowed"] = True
    _run(realm, plan)
    assert _run(realm, plan) == []


def test_other_client_policies_of_the_realm_stay():
    realm = FakeRealm()
    other_profile = {"name": "pair-flow", "executors": []}
    other_policy = {"name": "pair-flow", "enabled": True, "conditions": [], "profiles": []}
    realm.profiles.append(other_profile)
    realm.policies.append(other_policy)
    plan = _hardened_plan()
    _run(realm, plan)
    assert [p["name"] for p in realm.profiles] == ["pair-flow", rh.CLIENT_POLICY]
    assert [p["name"] for p in realm.policies] == ["pair-flow", rh.CLIENT_POLICY]
    realm.policies[1]["enabled"] = False
    changes = _run(realm, plan, apply=False)
    assert [c.operation for c in changes] == ["set_client_policy"]
    _run(realm, plan)
    assert realm.policies[1]["enabled"] is True
    assert realm.policies[0] == other_policy


def test_every_hardening_write_leaves_one_audit_row(tmp_path):
    realm = _template_realm()
    outbox = tmp_path / "audit" / "outbox" / "papaia-ctl.jsonl"
    with rs.AuditLog(outbox, rs.new_correlation_id(), host_account="host:test") as audit:
        _run(realm, _hardened_plan(HOSTS, LIBRECHAT), audit=audit)
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    assert len(rows) == len(realm.writes)
    operations = {row["operation"] for row in rows}
    assert {
        "realm_sync.update_realm",
        "realm_sync.harden_client",
        "realm_sync.set_client_profile",
        "realm_sync.set_client_policy",
    } <= operations
    text = outbox.read_text()
    assert "not-a-real-secret" not in text


# ─────────────────────────────────────────────────────────────────────────
# the template's accounts of an existing installation (PLT-21-A3)
# ─────────────────────────────────────────────────────────────────────────

GENERATED = "generated-realm-admin-password-0123456789"


def _old_installation() -> tuple[FakeRealm, str, str]:
    """A realm imported from the 1.9.0 template: admin/admin and testuser/testuser,
    passwords stored with the accounts and never changed."""
    realm = FakeRealm()
    admin = realm.add_user("admin", email="admin@papaia.lan", password="admin")
    test = realm.add_user("testuser", email="testuser@papaia.lan", password="testuser")
    realm.writes.clear()
    return realm, admin, test


def _users(realm: FakeRealm, password: str | None = GENERATED, *, apply=True, audit=None):
    hardening = rh.load({rh.REALM_ADMIN_PASSWORD_KEY: password} if password else {})
    return rs.sync_template_users(realm.call, hardening, apply=apply, audit=audit)


def test_the_template_accounts_lose_their_known_passwords():
    realm, admin, test = _old_installation()
    drift = _users(realm, apply=False)
    assert {(c.kind, c.name) for c in drift} == {("user", "admin"), ("user", "testuser")}
    assert realm.writes == []
    changes = _users(realm)
    assert [c.operation for c in changes] == ["reset_template_password", "disable_template_user"]
    assert realm.users[admin]["_password"] == GENERATED
    assert realm.users[admin]["requiredActions"] == ["UPDATE_PASSWORD"]
    assert realm.users[admin]["enabled"] is True
    assert realm.users[test]["enabled"] is False
    assert realm.users[test]["_password"] == "testuser"  # disabled: no sign-in at all
    assert _users(realm) == []
    assert _users(realm, apply=False) == []


def test_without_a_generated_password_the_admin_account_is_disabled():
    realm, admin, _ = _old_installation()
    changes = _users(realm, password=None)
    assert [c.operation for c in changes] == ["disable_template_user", "disable_template_user"]
    assert realm.users[admin]["enabled"] is False


def test_accounts_whose_password_was_changed_or_that_are_not_the_templates_stay():
    realm = FakeRealm()
    realm.add_user("admin", email="admin@papaia.lan", password="changed", password_changed=True)
    realm.add_user("testuser", email="someone@example.org", password="own")
    realm.add_user("testuser2", email="testuser@papaia.lan", password="testuser")
    realm.add_user("testuser", email="testuser@papaia.lan", password="x", enabled=False)
    realm.writes.clear()
    assert _users(realm) == []
    assert realm.writes == []


def test_an_imported_admin_with_its_forced_change_pending_stays():
    """A new installation: the generated password, the change still due."""
    realm = FakeRealm()
    realm.add_user(
        "admin",
        email="admin@papaia.lan",
        password=GENERATED,
        required_actions=("UPDATE_PASSWORD",),
    )
    realm.writes.clear()
    assert _users(realm) == []


def test_each_template_account_change_leaves_one_audit_row_without_the_password(tmp_path):
    realm, _, _ = _old_installation()
    outbox = tmp_path / "audit" / "outbox" / "papaia-ctl.jsonl"
    with rs.AuditLog(outbox, rs.new_correlation_id(), host_account="host:test") as audit:
        _users(realm, audit=audit)
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    assert [r["operation"] for r in rows] == [
        "realm_sync.reset_template_password",
        "realm_sync.disable_template_user",
    ]
    assert all(r["azp"] == "admin-cli" for r in rows)  # made with the master admin
    assert GENERATED not in outbox.read_text()


def test_the_sync_command_removes_the_known_passwords(tmp_path, connected, capsys):  # noqa: F811
    config_dir, repo_root = _config(tmp_path)
    tree = _tree()
    tree["infra/keycloak"][rh.REALM_ADMIN_PASSWORD_KEY] = GENERATED
    assert rs.sync(tree, config_dir, repo_root) == 0  # the sync account exists
    admin = connected.add_user("admin", email="admin@papaia.lan", password="admin")
    connected.add_user("testuser", email="testuser@papaia.lan", password="testuser")
    capsys.readouterr()
    assert rs.sync(tree, config_dir, repo_root, check=True) == 1
    out = capsys.readouterr().out
    assert "fail: user admin:" in out and "fail: user testuser:" in out
    assert rs.sync(tree, config_dir, repo_root) == 0
    assert connected.users[admin]["_password"] == GENERATED
    assert GENERATED not in capsys.readouterr().out
    assert rs.sync(tree, config_dir, repo_root, check=True) == 0


# ─────────────────────────────────────────────────────────────────────────
# the command
# ─────────────────────────────────────────────────────────────────────────


def test_an_unknown_profile_refuses_the_sync_before_keycloak_is_contacted(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("contacted"))
    config_dir, repo_root = _config(tmp_path)
    tree = _tree()
    tree[""][rh.PROFILE_KEY] = "strict"
    assert rs.sync(tree, config_dir, repo_root) == 2
    assert "Nothing was changed" in capsys.readouterr().err
    assert not rs.audit_path(config_dir).exists()


def test_the_sync_shows_the_current_offline_session_limits(tmp_path, connected, capsys):  # noqa: F811
    config_dir, repo_root = _config(tmp_path)
    tree = _tree()
    tree[""][rh.PROFILE_KEY] = "kritis"
    assert rs.sync(tree, config_dir, repo_root) == 0
    assert "offline sessions: idle 7 d, max age 30 d (profile kritis)" in capsys.readouterr().out
    connected.realm["offlineSessionIdleTimeout"] = 10 * DAY
    assert rs.sync(tree, config_dir, repo_root, check=True) == 1
    out = capsys.readouterr().out
    assert "offline sessions: idle 10 d, max age 30 d (profile kritis)" in out
    assert "fail: realm papaia: settings corrected (offlineSessionIdleTimeout)" in out


def test_offline_limits_for_the_permission_report():
    rep = {
        "offlineSessionIdleTimeout": 7 * DAY,
        "offlineSessionMaxLifespan": 30 * DAY,
        "offlineSessionMaxLifespanEnabled": True,
    }
    assert rh.offline_limits(rep) == {"idle_days": 7, "max_age_days": 30}
    assert rh.offline_limits(dict(rep, offlineSessionMaxLifespanEnabled=False)) == {
        "idle_days": 7,
        "max_age_days": None,
    }
