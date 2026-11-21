"""Declarative service accounts against a throwaway Keycloak of the pinned version.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from lib import service_account_keys as sak
from lib import service_accounts as sa
from tests.test_realm_sync_live import PASSWORD, URL, _admin, _client
from tests.test_service_accounts import _account, _flow, _me, _paperless, _plan, _qdrant

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)

TOKEN_URL = f"{URL}/realms/papaia/protocol/openid-connect/token"


def _master_call(method: str, path: str, body=None):
    return _admin(method, f"/papaia{path}", body)


def _declared() -> rs.Plan:
    return _plan(
        _flow(
            _account(),
            _account(
                id="svc-flow-notify",
                purpose={"en": "Notification preferences"},
                roles=["prefs-read"],
                audiences=["papaia-prefs"],
            ),
        ),
        _paperless(),
        _qdrant(),
        _me(),
    )


@pytest.fixture(scope="module")
def realm(tmp_path_factory):
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    api = rs.AdminApi(URL, None, rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24)))
    keys = rs.keystore(tmp_path_factory.mktemp("config"))
    rs.reconcile(api.call, _declared(), apply=True, keys=keys, master=_master_call)
    return api, keys


def _sync(realm, plan=None, *, apply=True) -> list[rs.Change]:
    api, keys = realm
    return rs.reconcile(api.call, plan or _declared(), apply=apply, keys=keys, master=_master_call)


def _token(keys, client_id: str, *, scope: str | None = None, jwk=None, key_path=None):
    jwk = jwk or keys.public_jwk(client_id)
    key_path = key_path or keys.key_path(client_id)
    form = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": sak.client_assertion(key_path, jwk, client_id, TOKEN_URL),
    }
    if scope:
        form["scope"] = scope
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            token = json.loads(resp.read())["access_token"]
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")
    claims = token.split(".")[1]
    return 200, json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))


def _service_clients() -> set[str]:
    return {
        c["clientId"] for c in _admin("GET", "/papaia/clients") if c.get("serviceAccountsEnabled")
    }


def test_the_clients_with_a_service_account_are_exactly_the_declared_ones(realm):
    """PLT-15-A1: only declared accounts, each with only its declared roles and `aud-*`
    scopes, none with a realm-management role (the sync account is the realm sync's own,
    its rights are checked on every run)."""
    assert _service_clients() == {"svc-flow-events", "svc-flow-notify", rs.SYNC_CLIENT}
    for client_id, roles, scopes in (
        ("svc-flow-events", set(), {"aud-mcp-paperless"}),
        ("svc-flow-notify", {"prefs-read"}, {"aud-papaia-prefs"}),
    ):
        client = _client(client_id)
        assert client["standardFlowEnabled"] is False
        assert client["directAccessGrantsEnabled"] is False
        assert client["implicitFlowEnabled"] is False
        assert client["fullScopeAllowed"] is False
        assert client["clientAuthenticatorType"] == "client-jwt"
        assert client["attributes"]["standard.token.exchange.enabled"] == "false"
        optional = _admin("GET", f"/papaia/clients/{client['id']}/optional-client-scopes")
        assert {s["name"] for s in optional} == scopes
        user = _admin("GET", f"/papaia/clients/{client['id']}/service-account-user")
        mappings = _admin("GET", f"/papaia/users/{user['id']}/role-mappings")
        assert "clientMappings" not in mappings or not mappings["clientMappings"]
        assert {r["name"] for r in mappings["realmMappings"]} == roles | {"default-roles-papaia"}
        assert _admin("GET", f"/papaia/users/{user['id']}/groups") == []
        scope = _admin("GET", f"/papaia/clients/{client['id']}/scope-mappings")
        assert {r["name"] for r in scope.get("realmMappings") or []} == roles


def test_a_token_carries_only_the_declared_audience_and_roles(realm):
    """PLT-15-A2 (Keycloak side): the declared audience is granted, an undeclared one is
    not assigned and Keycloak refuses it; no session id, so targets can tell a service
    account from a person."""
    _, keys = realm
    status, claims = _token(keys, "svc-flow-events", scope="aud-mcp-paperless")
    assert status == 200, claims
    assert claims["aud"] == "mcp-paperless"
    assert claims["azp"] == "svc-flow-events"
    assert "sid" not in claims
    assert not (claims.get("realm_access") or {}).get("roles")
    status, error = _token(keys, "svc-flow-events", scope="aud-mcp-qdrant")
    assert status == 400 and error["error"] == "invalid_scope"
    status, claims = _token(keys, "svc-flow-events")
    assert status == 200 and "aud" not in claims
    status, claims = _token(keys, "svc-flow-notify", scope="aud-papaia-prefs")
    assert status == 200, claims
    assert claims["aud"] == "papaia-prefs"
    assert set(claims["realm_access"]["roles"]) == {"prefs-read"}
    assert "resource_access" not in claims


def test_a_client_secret_or_a_password_grant_is_refused(realm):
    _, keys = realm
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": "svc-flow-events", "client_secret": "x"}
    ).encode()
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=form), timeout=10)
    assert refused.value.code in (400, 401)
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "svc-flow-events",
            "username": "service-account-svc-flow-events",
            "password": "x",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": sak.client_assertion(
                keys.key_path("svc-flow-events"),
                keys.public_jwk("svc-flow-events"),
                "svc-flow-events",
                TOKEN_URL,
            ),
        }
    ).encode()
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=form), timeout=10)
    assert refused.value.code in (400, 401)


def test_the_second_run_reports_no_change(realm):
    assert _sync(realm) == []
    assert _sync(realm, apply=False) == []


def test_drift_of_an_account_is_reported_and_repaired(realm):
    client = _client("svc-flow-events")
    user = _admin("GET", f"/papaia/clients/{client['id']}/service-account-user")
    rm = _client("realm-management")
    view_users = _admin("GET", f"/papaia/clients/{rm['id']}/roles/view-users")
    _admin("POST", f"/papaia/users/{user['id']}/role-mappings/clients/{rm['id']}", [view_users])
    qdrant = next(
        s for s in _admin("GET", "/papaia/client-scopes") if s["name"] == "aud-papaia-prefs"
    )
    _admin("PUT", f"/papaia/clients/{client['id']}/optional-client-scopes/{qdrant['id']}")

    drift = _sync(realm, apply=False)
    text = "\n".join(c.action for c in drift)
    assert "view-users" in text and "aud-papaia-prefs" in text
    _sync(realm)
    assert _sync(realm, apply=False) == []
    mappings = _admin("GET", f"/papaia/users/{user['id']}/role-mappings")
    assert not mappings.get("clientMappings")


def test_rotation_refuses_the_old_key_within_60_seconds(realm):
    """PLT-15-A6 / MN-13: the old key is refused at most 60 s after the rotation."""
    api, keys = realm
    old_jwk = keys.public_jwk("svc-flow-events")
    old_copy = keys.key_path("svc-flow-events").with_name("kept-for-the-test.pem")
    old_copy.write_bytes(keys.key_path("svc-flow-events").read_bytes())
    old_copy.chmod(0o600)
    assert _token(keys, "svc-flow-events")[0] == 200
    started = time.monotonic()
    refused_after = sa.rotate_key(
        api.call,
        keys,
        "svc-flow-events",
        audit=None,
        grace=0,
        try_sign_in=sa._sign_in_check(URL, None),
    )
    assert refused_after <= 60
    assert time.monotonic() - started <= 60
    status, error = _token(keys, "svc-flow-events", jwk=old_jwk, key_path=old_copy)
    assert status in (400, 401), error
    assert _token(keys, "svc-flow-events", scope="aud-mcp-paperless")[0] == 200
    old_copy.unlink()
    assert _sync(realm, apply=False) == []


def test_during_a_grace_period_both_keys_sign_in_and_after_it_only_the_new_one(realm):
    api, keys = realm
    old_jwk = keys.public_jwk("svc-flow-notify")
    old_copy = keys.key_path("svc-flow-notify").with_name("kept-for-the-test.pem")
    old_copy.write_bytes(keys.key_path("svc-flow-notify").read_bytes())
    old_copy.chmod(0o600)
    seen: list[tuple[str, bool]] = []
    check = sa._sign_in_check(URL, None)

    def watching(client_id, key_path, jwk):
        accepted = check(client_id, key_path, jwk)
        seen.append((jwk["kid"], accepted))
        return accepted

    refused_after = sa.rotate_key(
        api.call, keys, "svc-flow-notify", audit=None, grace=3, try_sign_in=watching
    )
    assert 3 <= refused_after <= 60
    new_kid = keys.public_jwk("svc-flow-notify")["kid"]
    assert (new_kid, True) in seen
    assert (old_jwk["kid"], False) in seen
    status, _ = _token(keys, "svc-flow-notify", jwk=old_jwk, key_path=old_copy)
    assert status in (400, 401)
    old_copy.unlink()


def test_an_undeclared_account_is_removed_and_its_key_folder_with_it(realm):
    _, keys = realm
    folder = keys.key_path("svc-flow-notify").parent
    plan = _plan(_flow(_account()), _paperless(), _qdrant(), _me())
    drift = _sync(realm, plan, apply=False)
    assert ("service-account", "svc-flow-notify") in {(c.kind, c.name) for c in drift}
    assert "svc-flow-notify" in _service_clients()
    _sync(realm, plan)
    assert _service_clients() == {"svc-flow-events", rs.SYNC_CLIENT}
    assert not folder.exists()
    # restore the declared state for any test that follows
    _sync(realm)
    assert _service_clients() == {"svc-flow-events", "svc-flow-notify", rs.SYNC_CLIENT}


def test_sign_ins_are_recorded_and_listed_as_last_use(realm):
    _, keys = realm
    assert _token(keys, "svc-flow-events")[0] == 200
    rows = {r["id"]: r for r in sa.describe(_master_call)}
    assert rows["svc-flow-events"]["last_used"] is not None
    assert rows["svc-flow-events"]["owner_sub"] == "dora"
    assert rows["svc-flow-events"]["rotation_due"] is False
