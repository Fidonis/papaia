"""The exchange of Mein Bereich for the connection registry, enforced by a throwaway Keycloak
of the pinned version: real sign-ins and token exchanges against the realm the sync built.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it, as for
tests/test_realm_sync_live.py:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. Token values are never printed, only
decoded claims are compared.

While the pairing `papaia-me` -> `papaia-connections` waits for the second person, Me gets no
token for the registry; once approved, Me's exchanged token carries `azp` `papaia-me` and
exactly the audience `papaia-connections`, and no other client gets one.
"""

from __future__ import annotations

import secrets
import urllib.error

import pytest

from lib import realm_sync as rs
from tests.test_me_connections import _modules
from tests.test_realm_sync import REGISTER, TWO_PERSONS, _pairings
from tests.test_realm_sync_live import URL, _admin, _client, pytestmark, realm  # noqa: F401
from tests.test_realm_sync_policies_live import USER, _exchange, _token_request

AUDIENCE = "papaia-connections"
SCOPE = "aud-papaia-connections"


def _plan(state: str) -> rs.Plan:
    persons = TWO_PERSONS if state == "confirmed" else {"requested_by": "host:anna"}
    return rs.build_plan(
        REGISTER,
        _modules("me", "connections"),
        _pairings(("papaia-me", AUDIENCE, ["r", "d"], state, persons)),
    )


def _person(password: str) -> None:
    try:
        _admin(
            "POST",
            "/papaia/users",
            {
                "username": USER,
                "enabled": True,
                "email": "anna-live@example.invalid",
                "emailVerified": True,
                "firstName": "Anna",
                "lastName": "Live",
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            raise
        (user,) = _admin("GET", f"/papaia/users?username={USER}&exact=true")
        _admin(
            "PUT",
            f"/papaia/users/{user['id']}/reset-password",
            {"type": "password", "value": password, "temporary": False},
        )


def _person_token(client_id: str, password: str) -> str:
    """A person's own token of `client_id`. The password grant is switched on for this one
    request, with the policy `papaia-hardening` (which refuses it) set aside meanwhile;
    both are put back before the test goes on."""
    path = "/papaia/client-policies/policies"
    policies = _admin("GET", path)["policies"]
    _admin("PUT", path, {"policies": [p for p in policies if p["name"] != "papaia-hardening"]})
    client = {k: v for k, v in _client(client_id).items() if k != "secret"}
    try:
        opened = dict(client, directAccessGrantsEnabled=True)
        _admin("PUT", f"/papaia/clients/{client['id']}", opened)
        status, body = _token_request(
            client_id,
            {"grant_type": "password", "username": USER, "password": password, "scope": "openid"},
        )
    finally:
        _admin("PUT", f"/papaia/clients/{client['id']}", client)
        _admin("PUT", path, {"policies": policies})
    assert status == 200, body.get("error")
    return body["access_token"]


@pytest.fixture(scope="module")
def password(realm):  # noqa: F811
    api, _ = realm
    rs.reconcile(api.call, _plan("pending"), apply=True)
    value = secrets.token_urlsafe(24)
    _person(value)
    return value


def test_a_pairing_waiting_for_approval_gives_me_no_registry_token(realm, password):  # noqa: F811
    api, _ = realm
    assert rs.reconcile(api.call, _plan("pending"), apply=False) == []
    own = _person_token("papaia-me", password)

    status, result = _exchange("papaia-me", own, SCOPE, AUDIENCE)

    assert status in (400, 403), result["claims"]
    assert result["token"] is None


def test_the_approved_pairing_gives_me_exactly_the_registry_audience(realm, password):  # noqa: F811
    api, _ = realm
    rs.reconcile(api.call, _plan("confirmed"), apply=True)
    assert rs.reconcile(api.call, _plan("confirmed"), apply=False) == []
    own = _person_token("papaia-me", password)

    status, result = _exchange("papaia-me", own, SCOPE, AUDIENCE)

    assert status == 200, result["error"]
    claims = result["claims"]
    assert claims["aud"] == AUDIENCE  # one audience, as a single value
    assert claims["azp"] == "papaia-me"
    assert claims["sub"] and claims["sid"]


def test_no_other_client_reaches_the_registry_audience(realm, password):  # noqa: F811
    api, _ = realm
    rs.reconcile(api.call, _plan("confirmed"), apply=True)
    holders = [
        c["clientId"]
        for c in _admin("GET", "/papaia/clients")
        if SCOPE in (c.get("optionalClientScopes") or []) + (c.get("defaultClientScopes") or [])
    ]
    assert holders == ["papaia-me"]
