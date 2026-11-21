"""papaia-lifecycle against a throwaway Keycloak of the pinned version (RE-05a, S0-13).

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. The holder client and the persons
below exist only in that throwaway realm.
"""

from __future__ import annotations

import io
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import lifecycle_account as la
from lib import realm_sync as rs
from tests.test_lifecycle import lc
from tests.test_realm_sync_live import PASSWORD, URL, _admin, _client
from tests.test_service_accounts import _plan

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)

TOKEN_URL = f"{URL}/realms/papaia/protocol/openid-connect/token"
HOLDER_SECRET = secrets.token_hex(16)
PERSON_PASSWORD = secrets.token_hex(16)


def _master_call(method: str, path: str, body=None):
    return _admin(method, f"/papaia{path}", body)


def _token(form: dict) -> tuple[int, dict]:
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _offline_token(username: str) -> str:
    status, body = _token(
        {
            "grant_type": "password",
            "client_id": "flow-engine",
            "client_secret": HOLDER_SECRET,
            "username": username,
            "password": PERSON_PASSWORD,
            "scope": "openid offline_access",
        }
    )
    assert status == 200, body
    return body["refresh_token"]


def _refresh(refresh_token: str) -> int:
    return _token(
        {
            "grant_type": "refresh_token",
            "client_id": "flow-engine",
            "client_secret": HOLDER_SECRET,
            "refresh_token": refresh_token,
        }
    )[0]


def _person(username: str) -> str:
    _master_call(
        "POST",
        "/users",
        {
            "username": username,
            "enabled": True,
            "email": f"{username}@example.org",
            "emailVerified": True,
            "firstName": username,
            "lastName": "Test",
            "credentials": [{"type": "password", "value": PERSON_PASSWORD, "temporary": False}],
        },
    )
    return _master_call("GET", f"/users?username={username}&exact=true")[0]["id"]


def _enabled(uid: str, value: bool) -> None:
    user = _master_call("GET", f"/users/{uid}")
    user["enabled"] = value
    _master_call("PUT", f"/users/{uid}", user)


@pytest.fixture(scope="module")
def realm(tmp_path_factory):
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    # The holder of delegations; in the product realm Flow's own client.
    _master_call(
        "POST",
        "/clients",
        {
            "clientId": "flow-engine",
            "publicClient": False,
            "secret": HOLDER_SECRET,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True,
        },
    )
    config = tmp_path_factory.mktemp("config")
    keys = rs.keystore(config)
    first = la.align(_master_call, keys, enabled=True, apply=True)
    return {"keys": keys, "first": first, "config": config}


@pytest.fixture
def service(realm, tmp_path):
    key_dir, state_dir = tmp_path / "key", tmp_path / "state"
    key_dir.mkdir(mode=0o700)
    state_dir.mkdir()
    api = lc.AccountClient(URL, None, realm["keys"].folder(la.CLIENT_ID))
    out = io.StringIO()
    svc = lc.Lifecycle(api, lc.Store(key_dir), lc.Publisher(state_dir, lc.Signer(key_dir)), out=out)
    svc.start()
    svc.state_dir, svc.key_dir, svc.out = state_dir, key_dir, out
    return svc


def test_the_account_is_set_up_and_a_second_run_changes_nothing(realm):
    assert realm["first"], "the first run creates the account"
    assert la.align(_master_call, realm["keys"], enabled=True, apply=False) == []
    client = _client(la.CLIENT_ID)
    assert client["clientAuthenticatorType"] == "client-jwt"
    assert client["serviceAccountsEnabled"] is True
    assert client["standardFlowEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert _master_call("GET", "")["adminPermissionsEnabled"] is True
    assert _master_call("GET", "/events/config")["adminEventsEnabled"] is True
    attributes = _master_call("GET", "").get("attributes") or {}
    assert attributes.get("adminEventsExpiration") == str(la.ADMIN_EVENTS_EXPIRATION)


def test_the_account_holds_only_view_events_and_the_group_permission(realm):
    """S0-08 result: no manage-users; logout and consent removal through the group."""
    client = _client(la.CLIENT_ID)
    user = _master_call("GET", f"/clients/{client['id']}/service-account-user")["id"]
    mappings = _master_call("GET", f"/users/{user}/role-mappings")
    client_roles = {
        name: {r["name"] for r in entry["mappings"]}
        for name, entry in (mappings.get("clientMappings") or {}).items()
    }
    assert client_roles == {"realm-management": {"view-events"}}
    realm_roles = {r["name"] for r in mappings.get("realmMappings") or []}
    assert realm_roles <= {"default-roles-papaia"}
    assert _master_call("GET", f"/users/{user}/groups") == []


def test_deactivation_ends_the_offline_session_and_reactivation_revives_nothing(realm, service):
    """RE-05a / S0-13: logout plus consent removal; the delegation stays dead."""
    anna = _person("anna")
    offline = _offline_token("anna")
    assert _refresh(offline) == 200
    _enabled(anna, False)
    service.step(force_poll=True)

    assert _master_call("GET", f"/users/{anna}/consents") == []
    _enabled(anna, True)
    assert _refresh(offline) == 400
    assert _master_call("GET", f"/users/{anna}/consents") == []

    data = (service.state_dir / lc.LIST_FILE).read_bytes()
    sig = (service.state_dir / lc.SIG_FILE).read_bytes()
    pub = (service.state_dir / lc.PUB_FILE).read_bytes()
    assert lc.verify(data, sig, pub)
    entries = json.loads(data)["entries"]
    assert [(e["sub"], e["reason"]) for e in entries] == [(anna, "account_disabled")]
    assert all(lc.verify(data, sig, pub) for _ in range(1))
    assert "refresh_token" not in service.out.getvalue()
    assert offline not in service.out.getvalue()


def test_the_account_cannot_reach_a_person_outside_the_group(realm, service):
    olga = _person("olga")
    group = _master_call("GET", f"/groups?search={la.PERSONS_GROUP}&exact=true")[0]["id"]
    _master_call("DELETE", f"/users/{olga}/groups/{group}")
    with pytest.raises(lc.HttpError) as exc:
        service.api.call("POST", f"/users/{olga}/logout")
    assert exc.value.status == 403
    with pytest.raises(lc.HttpError) as exc:
        service.api.call("POST", "/users", {"username": "mallory", "enabled": True})
    assert exc.value.status == 403
    # The realm sync puts every person back into the group.
    changes = la.align(_master_call, realm["keys"], enabled=True, apply=True)
    assert any(c.name == olga for c in changes)


def test_the_realm_sync_leaves_the_account_and_the_permission_client_alone(realm):
    api = rs.AdminApi(URL, None, rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24)))
    rs.reconcile(api.call, _plan(), apply=True, keys=realm["keys"], master=_master_call)
    assert _client(la.CLIENT_ID)["serviceAccountsEnabled"] is True
    assert _client("admin-permissions")["serviceAccountsEnabled"] is True
    assert la.align(_master_call, realm["keys"], enabled=True, apply=False) == []


def test_without_the_profile_the_account_is_removed(realm):
    changes = la.align(_master_call, realm["keys"], enabled=False, apply=True)
    assert changes
    assert _admin("GET", f"/papaia/clients?clientId={la.CLIENT_ID}") == []
    assert realm["keys"].public_jwk(la.CLIENT_ID) is None
    assert la.align(_master_call, realm["keys"], enabled=False, apply=False) == []
