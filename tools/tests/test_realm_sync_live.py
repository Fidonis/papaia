"""papaia-ctl realm sync against a throwaway Keycloak of the pinned version.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation.
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from tests.test_realm_sync import DELEGATION, REGISTER, _flow, _pairings, _paperless, _studio

URL = os.environ.get("PAPAIA_TEST_KEYCLOAK_URL", "")
PASSWORD = os.environ.get("PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD", "")

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)


def _master_token() -> str:
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": PASSWORD,
        }
    ).encode()
    req = urllib.request.Request(f"{URL}/realms/master/protocol/openid-connect/token", data=form)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def _admin(method: str, path: str, body=None):
    req = urllib.request.Request(
        f"{URL}/admin/realms{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {_master_token()}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def _client(client_id: str) -> dict:
    return _admin("GET", f"/papaia/clients?clientId={client_id}")[0]


def _clients_without_secrets() -> str:
    clients = [
        {k: v for k, v in c.items() if k != "secret"} for c in _admin("GET", "/papaia/clients")
    ]
    return json.dumps(clients, sort_keys=True)


def _scopes(client: dict, kind: str) -> set[str]:
    return {
        s["name"] for s in _admin("GET", f"/papaia/clients/{client['id']}/{kind}-client-scopes")
    }


@pytest.fixture(scope="module")
def realm():
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    secret = secrets.token_hex(24)
    token = rs.sync_token(URL, None, PASSWORD, secret)
    return rs.AdminApi(URL, None, token), secret


def _plan():
    return rs.build_plan(
        REGISTER,
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(
            ("flow-engine", "mcp-paperless", ["r", "w", "d"], "confirmed"),
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "pending"),
        ),
    )


def test_the_sync_account_has_only_its_realm_management_rights(realm):
    sync_client = _client(rs.SYNC_CLIENT)
    assert sync_client["serviceAccountsEnabled"] is True
    assert sync_client["standardFlowEnabled"] is False
    assert sync_client["directAccessGrantsEnabled"] is False
    assert sync_client["attributes"]["papaia.managed"] == "true"
    user = _admin("GET", f"/papaia/clients/{sync_client['id']}/service-account-user")
    mappings = _admin("GET", f"/papaia/users/{user['id']}/role-mappings")
    granted = {r["name"] for r in mappings["clientMappings"]["realm-management"]["mappings"]}
    assert granted == set(rs.SYNC_RIGHTS)
    assert "master" not in json.dumps(mappings)


def test_the_sync_account_secret_is_realigned_after_a_change(realm):
    _, secret = realm
    new_secret = secrets.token_hex(24)
    assert rs.sync_token(URL, None, PASSWORD, new_secret)
    with pytest.raises(urllib.error.HTTPError):
        rs._client_credentials(URL, None, secret)
    # put the fixture's secret back for the tests that follow
    assert rs.sync_token(URL, None, PASSWORD, secret)


def test_first_run_creates_second_run_reports_no_change(realm):
    api, _ = realm
    first = rs.reconcile(api.call, _plan(), apply=True)
    assert len(first) > 10
    assert rs.reconcile(api.call, _plan(), apply=True) == []
    assert rs.reconcile(api.call, _plan(), apply=False) == []

    engine = _client("flow-engine")
    assert engine["fullScopeAllowed"] is False
    assert engine["attributes"]["papaia.managed"] == "true"
    assert engine["attributes"]["standard.token.exchange.enabled"] == "true"
    assert _scopes(engine, "optional") == {"aud-mcp-paperless", "offline_access"}
    gateway = _client("papaia-studio-gateway")
    assert _scopes(gateway, "optional") == {"aud-mcp-paperless", "aud-flow"}
    assert not {s for s in _scopes(gateway, "default") if s.startswith("aud-")}
    assert _client("flow")["bearerOnly"] is True


def test_manual_drift_is_detected_and_repaired(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    engine = {k: v for k, v in _client("flow-engine").items() if k != "secret"}
    # The client policy of the realm hardening checks every update of a managed client
    # against its full representation.
    _admin("PUT", f"/papaia/clients/{engine['id']}", dict(engine, fullScopeAllowed=True))
    gateway = _client("papaia-studio-gateway")
    scope_id = next(
        s["id"] for s in _admin("GET", "/papaia/client-scopes") if s["name"] == "address"
    )
    _admin("PUT", f"/papaia/clients/{gateway['id']}/optional-client-scopes/{scope_id}")

    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert {("client", "flow-engine"), ("client", "papaia-studio-gateway")} <= {
        (c.kind, c.name) for c in drift
    }
    assert all(c.action for c in drift)
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    assert _client("flow-engine")["fullScopeAllowed"] is False


def test_only_the_holders_have_offline_access_after_a_sync(realm):
    api, _ = realm
    assist = rs.Module(
        "papaia-assist",
        [
            {
                "id": "assist.api",
                "kind": "rest",
                "audience": "assist-api",
                "delegation": {"purposes": ["assist.tools"]},
            }
        ],
        {},
    )
    plan = rs.build_plan(REGISTER, [_flow(delegation=DELEGATION), assist, _studio()], [])
    rs.reconcile(api.call, plan, apply=True)
    # every client that can obtain a token; bearer-only clients (realm-management, the
    # resource servers) never get one
    holders = {
        c["clientId"]
        for c in _admin("GET", "/papaia/clients")
        if not c.get("bearerOnly")
        and "offline_access" in _scopes(c, "default") | _scopes(c, "optional")
    }
    assert holders == {"flow-engine", "assist-gate"}
    defaults = {s["name"] for s in _admin("GET", "/papaia/default-optional-client-scopes")}
    assert "offline_access" not in defaults


def test_rejected_manifests_leave_the_realm_unchanged(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    before = _clients_without_secrets()
    addon = rs.Module(
        "papaia-studio",
        [{"id": "studio.ui", "kind": "ui", "delegation": {"purposes": ["flow.run"]}}],
        {},
    )
    flow = _flow(delegation=dict(DELEGATION, purposes=["flow.run", "assist.tools"]))
    for modules in ([addon], [flow]):
        with pytest.raises(rs.RealmSyncError):
            rs.reconcile(api.call, rs.build_plan(REGISTER, modules, []), apply=True)
    assert _clients_without_secrets() == before


def _role(name: str) -> dict:
    return _admin("GET", f"/papaia/roles/{urllib.parse.quote(name)}")


def _example_token(client: dict, user_id: str, scope: str = "openid") -> dict:
    query = urllib.parse.urlencode({"scope": scope, "userId": user_id})
    return _admin(
        "GET",
        f"/papaia/clients/{client['id']}/evaluate-scopes/generate-example-access-token?{query}",
    )


def _admin_user() -> dict:
    """A person holding papaia-admin, which includes realm-management's manage-users as
    in the realm template."""
    rm = _client("realm-management")
    manage_users = _admin("GET", f"/papaia/clients/{rm['id']}/roles/manage-users")
    _admin("POST", "/papaia/roles/papaia-admin/composites", [manage_users])
    try:
        _admin("POST", "/papaia/users", {"username": "admin-anna", "enabled": True})
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
    (user,) = _admin("GET", "/papaia/users?username=admin-anna&exact=true")
    _admin("POST", f"/papaia/users/{user['id']}/role-mappings/realm", [_role("papaia-admin")])
    return user


def test_an_admin_token_from_each_sign_in_client_carries_no_admin_rights(realm):
    api, _ = realm
    plan = _plan()
    rs.reconcile(api.call, plan, apply=True)
    # papaia-admin as in the realm template: it includes realm-management roles
    rm = _client("realm-management")
    manage_users = _admin("GET", f"/papaia/clients/{rm['id']}/roles/manage-users")
    _admin("POST", "/papaia/roles/papaia-admin/composites", [manage_users])
    # a hand-made mapping of papaia-admin into a module client is taken out again
    cli = _client("flow-cli")
    _admin("POST", f"/papaia/clients/{cli['id']}/scope-mappings/realm", [_role("papaia-admin")])
    rs.reconcile(api.call, plan, apply=True)

    user = _admin_user()

    checked = 0
    for client_id, spec in sorted(plan.clients.items()):
        if spec.kind == "bearer":
            continue
        token = _example_token(_client(client_id), user["id"])
        roles = set((token.get("realm_access") or {}).get("roles", []))
        allowed = spec.role_scope
        assert roles <= allowed, (client_id, roles - allowed)
        assert "papaia-admin" not in roles
        assert "realm-management" not in (token.get("resource_access") or {}), client_id
        own_admin = {r for r in spec.role_scope if r.endswith("-admin")}
        assert {r for r in roles if r.endswith("-admin")} == own_admin, client_id
        checked += 1
    assert checked >= 5


def test_a_fixed_audience_mapper_on_a_managed_client_fails_the_check(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    engine = _client("flow-engine")
    _admin(
        "POST",
        f"/papaia/clients/{engine['id']}/protocol-mappers/models",
        {
            "name": "fixed audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "mcp-paperless", "access.token.claim": "true"},
        },
    )
    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "flow-engine")]
    rs.reconcile(api.call, _plan(), apply=True)
    assert not _client("flow-engine").get("protocolMappers")
    assert rs.reconcile(api.call, _plan(), apply=False) == []


def test_visible_for_roles_of_a_module_that_is_not_installed_is_harmless(realm):
    api, _ = realm
    studio = _studio()
    studio.exposes[0]["ui"][0]["visible_for_roles"] = ["studio-member", "data-member"]
    plan = rs.build_plan(REGISTER, [studio], [])
    rs.reconcile(api.call, plan, apply=True)
    assert rs.reconcile(api.call, plan, apply=True) == []
    assert rs.reconcile(api.call, plan, apply=False) == []
    # back to the plan of the other tests
    rs.reconcile(api.call, _plan(), apply=True)


def test_extra_rights_of_the_sync_account_fail_the_check_and_are_removed(realm):
    _, secret = realm
    master = rs.AdminApi(URL, None, _master_token()).call
    assert rs.align_sync_account(master, None, apply=False) == []
    sync_client = _client(rs.SYNC_CLIENT)
    rm = _client("realm-management")
    realm_admin = _admin("GET", f"/papaia/clients/{rm['id']}/roles/realm-admin")
    _admin(
        "POST",
        f"/papaia/clients/{sync_client['id']}/scope-mappings/clients/{rm['id']}",
        [realm_admin],
    )
    user = _admin("GET", f"/papaia/clients/{sync_client['id']}/service-account-user")
    _admin("POST", f"/papaia/users/{user['id']}/role-mappings/clients/{rm['id']}", [realm_admin])

    drift = rs.align_sync_account(master, None, apply=False)
    assert len(drift) == 2
    assert all("realm-admin" in c.action for c in drift)
    rs.align_sync_account(master, secret, apply=True)
    assert rs.align_sync_account(master, None, apply=False) == []
    mappings = _admin("GET", f"/papaia/users/{user['id']}/role-mappings")
    granted = {r["name"] for r in mappings["clientMappings"]["realm-management"]["mappings"]}
    assert granted == set(rs.SYNC_RIGHTS)


def test_an_unmanaged_exchange_scope_is_adopted_and_its_attributes_corrected(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    scope = next(s for s in _admin("GET", "/papaia/client-scopes") if s["name"] == "aud-flow")
    _admin(
        "PUT",
        f"/papaia/client-scopes/{scope['id']}",
        {
            "name": "aud-flow",
            "protocol": "openid-connect",
            "attributes": {"papaia.managed": "false", "include.in.token.scope": "false"},
        },
    )
    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client-scope", "aud-flow")]
    rs.reconcile(api.call, _plan(), apply=True)
    scope = next(s for s in _admin("GET", "/papaia/client-scopes") if s["name"] == "aud-flow")
    assert scope["attributes"]["papaia.managed"] == "true"
    assert scope["attributes"]["include.in.token.scope"] == "true"
    assert rs.reconcile(api.call, _plan(), apply=False) == []


def _scope_id(name: str) -> str:
    return next(s["id"] for s in _admin("GET", "/papaia/client-scopes") if s["name"] == name)


def _assert_clean(token: dict, label: str) -> None:
    roles = set((token.get("realm_access") or {}).get("roles", []))
    assert "papaia-admin" not in roles, (label, roles)
    assert "realm-management" not in (token.get("resource_access") or {}), label
    assert "realm-management" not in (token.get("aud") or []), label


def test_roles_mapped_into_client_scopes_fail_the_check_and_are_removed(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    user = _admin_user()
    rm = _client("realm-management")
    realm_admin = _admin("GET", f"/papaia/clients/{rm['id']}/roles/realm-admin")
    for scope in ("roles", "aud-mcp-paperless", "offline_access"):
        sid = _scope_id(scope)
        _admin("POST", f"/papaia/client-scopes/{sid}/scope-mappings/realm", [_role("papaia-admin")])
    _admin(
        "POST",
        f"/papaia/client-scopes/{_scope_id('aud-mcp-paperless')}/scope-mappings/clients/{rm['id']}",
        [realm_admin],
    )
    engine = _client("flow-engine")
    # the gap this test closes: the scope mappings put admin rights into the token
    leaked = _example_token(engine, user["id"], "openid aud-mcp-paperless")
    assert "papaia-admin" in leaked["realm_access"]["roles"]

    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert {c.name for c in drift} == {"roles", "aud-mcp-paperless", "offline_access"}
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    offline = _admin("GET", f"/papaia/client-scopes/{_scope_id('offline_access')}/scope-mappings")
    assert {r["name"] for r in offline.get("realmMappings", [])} == {"offline_access"}

    for client, scope in (
        (_client("flow-cli"), "openid"),
        (engine, "openid aud-mcp-paperless"),
        (engine, "openid offline_access"),
    ):
        _assert_clean(_example_token(client, user["id"], scope), (client["clientId"], scope))


def test_a_role_adding_mapper_on_a_managed_client_fails_the_check_and_is_removed(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    user = _admin_user()
    cli = _client("flow-cli")
    _admin(
        "POST",
        f"/papaia/clients/{cli['id']}/protocol-mappers/models",
        {
            "name": "hardcoded admin",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-role-mapper",
            "config": {"role": "realm-management.realm-admin"},
        },
    )
    leaked = _example_token(cli, user["id"])
    assert "realm-management" in leaked.get("resource_access", {})

    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "flow-cli")]
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    _assert_clean(_example_token(_client("flow-cli"), user["id"]), "flow-cli")


def test_an_exchange_scope_reaches_no_unmanaged_client_or_realm_default(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    _admin("PUT", f"/papaia/default-default-client-scopes/{_scope_id('aud-flow')}")
    try:
        _admin("POST", "/papaia/clients", {"clientId": "librechat", "publicClient": False})
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
    other = _client("librechat")
    _admin(
        "PUT",
        f"/papaia/clients/{other['id']}/optional-client-scopes/{_scope_id('aud-mcp-paperless')}",
    )
    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert {(c.kind, c.name) for c in drift} == {("realm", "papaia"), ("client", "librechat")}
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    defaults = {s["name"] for s in _admin("GET", "/papaia/default-default-client-scopes")}
    assert "aud-flow" not in defaults
    assert not {
        s for s in _scopes(other, "optional") | _scopes(other, "default") if s.startswith("aud-")
    }
    _admin("DELETE", f"/papaia/clients/{other['id']}")


def test_a_composite_that_widens_the_sync_rights_fails_the_check(realm):
    master = rs.AdminApi(URL, None, _master_token()).call
    rm = _client("realm-management")
    view_users = _admin("GET", f"/papaia/clients/{rm['id']}/roles/view-users")
    # Keycloak refuses to change the composites of its own realm-management roles ...
    with pytest.raises(urllib.error.HTTPError) as refused:
        _admin("POST", f"/papaia/clients/{rm['id']}/roles/manage-clients/composites", [view_users])
    assert refused.value.code == 403
    # ... but the realm's default roles, which the account holds, can grow
    path = "/papaia/roles/default-roles-papaia/composites"
    _admin("POST", path, [view_users])
    try:
        drift = rs.align_sync_account(master, None, apply=False)
        assert drift and all("view-users" in c.action for c in drift)
        with pytest.raises(rs.RealmSyncError):
            rs.align_sync_account(master, None, apply=True)
    finally:
        _admin("DELETE", path, [view_users])
    assert rs.align_sync_account(master, None, apply=False) == []


def _aud(token: dict) -> set[str]:
    aud = token.get("aud") or []
    return {aud} if isinstance(aud, str) else set(aud)


def test_an_audience_mapper_on_a_shared_scope_fails_the_check_and_is_removed(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    user = _admin_user()
    _admin(
        "POST",
        f"/papaia/client-scopes/{_scope_id('profile')}/protocol-mappers/models",
        {
            "name": "fixed audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "mcp-paperless", "access.token.claim": "true"},
        },
    )
    cli = _client("flow-cli")
    # the gap this test closes: every managed client's token carries the foreign audience
    assert "mcp-paperless" in _aud(_example_token(cli, user["id"]))

    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client-scope", "profile")]
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    assert "mcp-paperless" not in _aud(_example_token(cli, user["id"]))
    # Keycloak's own audience resolve mapper of `roles` is left in place
    roles = next(s for s in _admin("GET", "/papaia/client-scopes") if s["name"] == "roles")
    assert "oidc-audience-resolve-mapper" in {
        m["protocolMapper"] for m in roles.get("protocolMappers", [])
    }


def test_a_composite_client_role_of_a_managed_client_fails_the_check_and_is_stripped(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    user = _admin_user()
    cli = _client("flow-cli")
    rm = _client("realm-management")
    try:
        _admin("POST", f"/papaia/clients/{cli['id']}/roles", {"name": "boss"})
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
    boss = _admin("GET", f"/papaia/clients/{cli['id']}/roles/boss")
    realm_admin = _admin("GET", f"/papaia/clients/{rm['id']}/roles/realm-admin")
    _admin("POST", f"/papaia/roles-by-id/{boss['id']}/composites", [realm_admin])
    _admin("POST", "/papaia/roles/papaia-admin/composites", [boss])
    # the gap this test closes: the client's own role carries realm-admin into its token
    leaked = _example_token(cli, user["id"])
    assert "realm-management" in (leaked.get("resource_access") or {})

    drift = rs.reconcile(api.call, _plan(), apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "flow-cli")]
    assert "realm-admin" in drift[0].action
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    _assert_clean(_example_token(_client("flow-cli"), user["id"]), "flow-cli")
    assert not _admin("GET", f"/papaia/roles-by-id/{boss['id']}/composites")


def test_a_group_or_service_account_scope_role_of_the_sync_account_is_removed(realm):
    _, secret = realm
    master = rs.AdminApi(URL, None, _master_token()).call
    assert rs.align_sync_account(master, None, apply=False) == []
    sync_client = _client(rs.SYNC_CLIENT)
    rm = _client("realm-management")
    view_users = _admin("GET", f"/papaia/clients/{rm['id']}/roles/view-users")
    try:
        _admin("POST", "/papaia/groups", {"name": "realm-sync-extra"})
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
    (group,) = [g for g in _admin("GET", "/papaia/groups") if g["name"] == "realm-sync-extra"]
    _admin("POST", f"/papaia/groups/{group['id']}/role-mappings/clients/{rm['id']}", [view_users])
    user = _admin("GET", f"/papaia/clients/{sync_client['id']}/service-account-user")
    _admin("PUT", f"/papaia/users/{user['id']}/groups/{group['id']}")
    sa_scope = _scope_id("service_account")
    _admin(
        "POST", f"/papaia/client-scopes/{sa_scope}/scope-mappings/clients/{rm['id']}", [view_users]
    )

    drift = rs.align_sync_account(master, None, apply=False)
    text = " ".join(c.action for c in drift)
    assert "realm-sync-extra" in text and "view-users" in text
    rs.align_sync_account(master, secret, apply=True)
    assert rs.align_sync_account(master, None, apply=False) == []
    assert _admin("GET", f"/papaia/users/{user['id']}/groups") == []
    assert not _admin("GET", f"/papaia/client-scopes/{sa_scope}/scope-mappings").get(
        "clientMappings"
    )
    _admin("DELETE", f"/papaia/groups/{group['id']}")


def _ensure(method: str, path: str, body) -> None:
    try:
        _admin(method, path, body)
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise


def _person(username: str, *, enabled: bool = True) -> str:
    _ensure("POST", "/papaia/users", {"username": username, "enabled": enabled})
    (user,) = _admin("GET", f"/papaia/users?username={username}&exact=true")
    return user["id"]


def test_the_paperless_name_list_follows_the_realm(realm):
    """Effective roles as Keycloak computes them: direct, through a group and through a
    composite; deactivated accounts, service accounts and deleted accounts are not listed."""
    for name in ("paperless-member", "paperless-admin", "pl-bundle"):
        _ensure("POST", "/papaia/roles", {"name": name})
    _admin("POST", "/papaia/roles/pl-bundle/composites", [_role("paperless-member")])
    _ensure("POST", "/papaia/groups", {"name": "pl-archive"})
    (group,) = [g for g in _admin("GET", "/papaia/groups") if g["name"] == "pl-archive"]
    _admin("POST", f"/papaia/groups/{group['id']}/role-mappings/realm", [_role("paperless-member")])
    anna = _person("pl-anna")
    _admin("POST", f"/papaia/users/{anna}/role-mappings/realm", [_role("paperless-member")])
    ben = _person("pl-ben")
    _admin("PUT", f"/papaia/users/{ben}/groups/{group['id']}")
    carla = _person("pl-carla")
    _admin("POST", f"/papaia/users/{carla}/role-mappings/realm", [_role("pl-bundle")])
    dora = _person("pl-dora")
    _admin("POST", f"/papaia/users/{dora}/role-mappings/realm", [_role("paperless-admin")])
    _person("pl-erik")
    frida = _person("pl-frida", enabled=False)
    _admin("POST", f"/papaia/users/{frida}/role-mappings/realm", [_role("paperless-member")])
    sync_client = _client(rs.SYNC_CLIENT)
    service_user = _admin("GET", f"/papaia/clients/{sync_client['id']}/service-account-user")
    _admin(
        "POST",
        f"/papaia/users/{service_user['id']}/role-mappings/realm",
        [_role("paperless-member")],
    )

    master = rs.AdminApi(URL, None, _master_token()).call
    roles = frozenset({"paperless-member", "paperless-admin"})
    listed = [n for n in rs.paperless_users(master, roles) if n.startswith(("pl-", "service-"))]
    assert listed == ["pl-anna", "pl-ben", "pl-carla", "pl-dora"]

    _admin("DELETE", f"/papaia/users/{anna}")
    listed = [n for n in rs.paperless_users(master, roles) if n.startswith(("pl-", "service-"))]
    assert listed == ["pl-ben", "pl-carla", "pl-dora"]

    # the sync account cannot read accounts (no view-users): the list is read as master
    _, secret = realm
    api = rs.AdminApi(URL, None, rs._client_credentials(URL, None, secret))
    with pytest.raises(urllib.error.HTTPError) as refused:
        api.call("GET", "/users?first=0&max=1")
    assert refused.value.code == 403

    _admin(
        "DELETE",
        f"/papaia/users/{service_user['id']}/role-mappings/realm",
        [_role("paperless-member")],
    )
    for user in (ben, carla, dora, frida, _person("pl-erik")):
        _admin("DELETE", f"/papaia/users/{user}")
    _admin("DELETE", f"/papaia/groups/{group['id']}")
    for name in ("pl-bundle", "paperless-member", "paperless-admin"):
        _admin("DELETE", f"/papaia/roles/{name}")
