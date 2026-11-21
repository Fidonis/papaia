"""papaia-lifecycle against a throwaway Keycloak of the pinned version (RE-05a, S0-13).

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. The holder client and the persons
below exist only in that throwaway realm.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import time
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
    target = tmp_path / "erasure-journal"
    target.mkdir()
    erasure_key = os.urandom(32)
    journal = lc.ErasureJournal(
        "identity", key=erasure_key, target_dir=target, local_dir=key_dir / "erasure-journal"
    )
    api = lc.AccountClient(URL, None, realm["keys"].folder(la.CLIENT_ID))
    out = io.StringIO()
    svc = lc.Lifecycle(
        api,
        lc.Store(key_dir),
        lc.Publisher(state_dir, lc.Signer(key_dir)),
        out=out,
        journal=journal,
    )
    svc.start()
    svc.state_dir, svc.key_dir, svc.out = state_dir, key_dir, out
    svc.target, svc.erasure_key = target, erasure_key
    return svc


def _journal(service, sub: str) -> list[tuple[str, str]]:
    """(kind, object_ref) of the journal lines of one account."""
    ref = hmac.new(service.erasure_key, sub.encode(), hashlib.sha256).hexdigest()
    path = service.target / "identity.jsonl"
    lines = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return [(e["kind"], e["object_ref"]) for e in lines if e["subject_ref"] == ref]


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
    # One journal entry; the service's own logout is not a second one.
    service.step(force_poll=True)
    assert _journal(service, anna) == [("account_disable", "account")]


def test_removed_roles_ended_sessions_and_reset_credentials_are_journaled(realm, service):
    """The admin events of the pinned Keycloak, as the master admin causes them."""
    bert = _person("bert")
    _master_call("POST", "/roles", {"name": "journal-probe"})
    role = _master_call("GET", "/roles/journal-probe")
    _master_call("POST", f"/users/{bert}/role-mappings/realm", [role])
    _master_call("DELETE", f"/users/{bert}/role-mappings/realm", [role])
    _master_call("POST", "/groups", {"name": "journal-probe"})
    group = _master_call("GET", "/groups?search=journal-probe&exact=true")[0]["id"]
    _master_call("PUT", f"/users/{bert}/groups/{group}")
    _master_call("DELETE", f"/users/{bert}/groups/{group}")
    _master_call("POST", f"/users/{bert}/logout")
    _master_call(
        "PUT",
        f"/users/{bert}/reset-password",
        {"type": "password", "value": secrets.token_hex(16), "temporary": False},
    )
    credential = _master_call("GET", f"/users/{bert}/credentials")[0]["id"]
    _master_call("DELETE", f"/users/{bert}/credentials/{credential}")
    service.step(force_poll=True)
    assert _journal(service, bert) == [
        ("role_revoke", "realm-roles"),
        ("role_revoke", f"group:{group}"),
        ("session_revoke", "sessions"),
        ("credential_reset", "password"),
        ("credential_reset", f"credential:{credential}"),
    ]


def _clear_admin_events() -> None:
    """What the service finds after an outage longer than the event retention, or for a
    deactivation that came from a directory behind Keycloak: no event."""
    _master_call("DELETE", "/admin-events")


def test_a_deactivation_the_service_missed_is_revoked_at_start(realm, service):
    """CORE-046: service stopped, person deactivated, service started: the offline
    session ends with the reconciliation at start; reactivation revives nothing."""
    berta = _person("berta")
    offline = _offline_token("berta")
    assert _refresh(offline) == 200
    _enabled(berta, False)
    _clear_admin_events()
    service.step(force_poll=True)

    assert _master_call("GET", f"/users/{berta}/consents") == []
    _enabled(berta, True)
    _clear_admin_events()
    service.step(force_poll=True)
    assert _refresh(offline) == 400
    assert _master_call("GET", f"/users/{berta}/consents") == []
    entries = json.loads((service.state_dir / lc.LIST_FILE).read_bytes())["entries"]
    assert (berta, "account_disabled") in [(e["sub"], e["reason"]) for e in entries]
    assert offline not in service.out.getvalue()


def test_a_gap_longer_than_the_event_retention_ends_every_delegation(realm, service):
    """Deactivated and activated again during an outage longer than the retention:
    every consent at a holder client goes, with the gap audit row."""
    carla = _person("carla")
    offline = _offline_token("carla")
    assert _refresh(offline) == 200
    service.step(force_poll=True)
    with service.store.locked():
        state = service.store.load()
        state["last_poll"] -= lc.EVENT_RETENTION_SECONDS + 3600
        service.store.save(state)
    out = io.StringIO()
    again = lc.Lifecycle(service.api, service.store, service.publisher, out=out)
    again.start()
    again.step(force_poll=True)

    assert _refresh(offline) == 400
    assert _master_call("GET", f"/users/{carla}")["enabled"] is True
    rows = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    gap = [r for r in rows if r["operation"] == "lifecycle.gap_revoke"]
    assert len(gap) == 1 and gap[0]["detail"]["reason"] == "lifecycle_gap_revoke"
    assert offline not in out.getvalue()


def test_deactivated_and_reactivated_while_stopped_ends_the_delegation(realm, service):
    """sicherheit §1.12 no. 2: service stopped, account deactivated and activated again
    (both admin events kept), service started: the old delegation is invalid after the
    first round, a delegation granted after the start works."""
    dora = _person("dora")
    offline = _offline_token("dora")
    assert _refresh(offline) == 200
    service.step(force_poll=True)
    # Stopped: no step while the account is switched off and on again.
    _enabled(dora, False)
    _enabled(dora, True)
    # Started later than the usual poll delay: the clock of the new process runs ahead.
    ahead = lc.LATE_EVENT_SECONDS + 5
    out = io.StringIO()
    again = lc.Lifecycle(
        service.api, service.store, service.publisher, out=out,
        clock=lambda: time.time() + ahead,
    )
    again.start()
    again.step(force_poll=True)

    assert _master_call("GET", f"/users/{dora}")["enabled"] is True
    assert _refresh(offline) == 400
    assert _master_call("GET", f"/users/{dora}/consents") == []
    rows = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    deleted = [r for r in rows if r["operation"] == "lifecycle.consent_delete"]
    assert [r["detail"]["client"] for r in deleted] == ["flow-engine"]
    assert offline not in out.getvalue()

    fresh = _offline_token("dora")
    again.step(force_poll=True)
    assert _refresh(fresh) == 200


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

