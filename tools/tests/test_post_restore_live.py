"""`post-restore` against a throwaway Keycloak of the pinned version (RE-05a, BE-17).

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. The holder clients and the persons below
exist only in that throwaway realm.

The restore is simulated: the grants made before `since` are what a restore point brings
back; the realm itself is not replaced.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import post_restore as pr
from lib import realm_sync as rs
from tests.test_realm_sync_live import PASSWORD, URL, _admin

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)

TOKEN_URL = f"{URL}/realms/papaia/protocol/openid-connect/token"
SECRET = secrets.token_hex(16)
PERSON_PASSWORD = secrets.token_hex(16)
CLIENTS = ("flow-engine", "assist-gate", "other-app")


def _call(method: str, path: str, body=None):
    return _admin(method, f"/papaia{path}", body)


def _token(form: dict) -> tuple[int, dict]:
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _offline(client: str, username: str) -> str:
    status, body = _token(
        {
            "grant_type": "password",
            "client_id": client,
            "client_secret": SECRET,
            "username": username,
            "password": PERSON_PASSWORD,
            "scope": "openid offline_access",
        }
    )
    assert status == 200, body
    return body["refresh_token"]


def _refresh(client: str, refresh_token: str) -> int:
    return _token(
        {
            "grant_type": "refresh_token",
            "client_id": client,
            "client_secret": SECRET,
            "refresh_token": refresh_token,
        }
    )[0]


def _person(username: str) -> str:
    _call(
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
    return _call("GET", f"/users?username={username}&exact=true")[0]["id"]


def _granted(uid: str) -> set[str]:
    return {c["clientId"] for c in _call("GET", f"/users/{uid}/consents")}


@pytest.fixture(scope="module")
def realm():
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    for client in CLIENTS:
        _call(
            "POST",
            "/clients",
            {
                "clientId": client,
                "publicClient": False,
                "secret": SECRET,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": True,
            },
        )
    return {"anna": _person("anna"), "ben": _person("ben")}


def test_after_a_simulated_restore_old_grants_are_dead_and_a_second_run_is_a_no_op(realm, tmp_path):
    anna, ben = realm["anna"], realm["ben"]
    flow = _offline("flow-engine", "anna")
    assist = _offline("assist-gate", "ben")
    other = _offline("other-app", "anna")
    assert _refresh("flow-engine", flow) == 200
    assert _refresh("assist-gate", assist) == 200
    assert _granted(anna) == {"flow-engine", "other-app"}
    time.sleep(1.1)
    since = int(time.time())

    audit = rs.AuditLog(
        tmp_path / "outbox.jsonl", rs.new_correlation_id(), writer="papaia-ctl/post-restore"
    )
    with audit:
        changes = pr.run(_call, since, audit=audit)

    assert [c.operation for c in changes] == ["not_before", "consent_delete", "consent_delete"]
    assert _call("GET", "")["notBefore"] > since
    assert _refresh("flow-engine", flow) == 400
    assert _refresh("assist-gate", assist) == 400
    assert _refresh("other-app", other) == 400, "realm-wide not before reaches every client"
    assert _granted(anna) == {"other-app"}
    assert _granted(ben) == set()
    rows = [json.loads(line) for line in (tmp_path / "outbox.jsonl").read_text().splitlines()]
    assert len(rows) == 3 and {r["result"] for r in rows} == {"allowed"}
    text = (tmp_path / "outbox.jsonl").read_text()
    assert flow not in text and assist not in text and SECRET not in text

    # Second run: nothing to do, nothing written.
    assert pr.run(_call, since, audit=None) == []

    # A delegation granted after the restore works and survives another run.
    time.sleep(2.1)
    fresh = _offline("flow-engine", "anna")
    assert _refresh("flow-engine", fresh) == 200
    assert pr.run(_call, since, audit=None) == []
    assert _refresh("flow-engine", fresh) == 200
    assert "flow-engine" in _granted(anna)
