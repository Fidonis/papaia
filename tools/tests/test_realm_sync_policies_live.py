"""Client policies of papaia-ctl realm sync, enforced by a throwaway Keycloak of the pinned
version: real token exchanges against the realm the sync built.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it, as
for tests/test_realm_sync_live.py:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. Token values are never printed; only
decoded claims are compared.
"""

from __future__ import annotations

import base64
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from tests.test_realm_sync import REGISTER, _flow, _pairings, _paperless, _studio
from tests.test_realm_sync_live import URL, _admin, _client, pytestmark, realm  # noqa: F401
from tests.test_realm_sync_policies import _assist, _data

TE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
USER = "anna-live"
PROBE = "svc-live-probe"


def _plan() -> rs.Plan:
    return rs.build_plan(
        REGISTER,
        [_studio(), _flow(), _paperless(), _data(), _assist()],
        _pairings(
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"),
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            # not in the RS matrix; confirmed here so the refused chains can be tried
            ("assist-gate", "papaia-data", ["r"], "confirmed"),
            ("flow-engine", "papaia-data", ["r"], "confirmed"),
            ("flow-engine", "mcp-paperless", ["r"], "confirmed"),
        ),
    )


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _secret(client_id: str) -> str:
    return _admin("GET", f"/papaia/clients/{_client(client_id)['id']}/client-secret")["value"]


def _token_request(client_id: str, form: dict) -> tuple[int, dict]:
    data = urllib.parse.urlencode(
        dict(form, client_id=client_id, client_secret=_secret(client_id))
    ).encode()
    req = urllib.request.Request(
        f"{URL}/realms/papaia/protocol/openid-connect/token", data=data, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _person_token(client_id: str, password: str) -> str:
    """A person's own token of `client_id`. The managed clients have no password grant;
    it is switched on for this one request and off again (the sync would remove it)."""
    client = _client(client_id)
    _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": True})
    try:
        status, body = _token_request(
            client_id,
            {"grant_type": "password", "username": USER, "password": password, "scope": "openid"},
        )
    finally:
        _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": False})
    assert status == 200, body.get("error")
    return body["access_token"]


def _exchange(client_id: str, subject: str, scope: str, audience=None) -> tuple[int, dict]:
    form = {
        "grant_type": TE,
        "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "scope": scope,
    }
    if audience:
        form["audience"] = audience
    status, body = _token_request(client_id, form)
    claims = _claims(body["access_token"]) if status == 200 else {}
    return status, {"claims": claims, "error": body.get("error"), "token": body.get("access_token")}


@pytest.fixture(scope="module")
def synced(realm):  # noqa: F811
    api, _ = realm
    plan = _plan()
    first = rs.reconcile(api.call, plan, apply=True)
    second = rs.reconcile(api.call, plan, apply=True)
    check = rs.reconcile(api.call, plan, apply=False)
    password = secrets.token_urlsafe(24)
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
    return api, plan, first, second, check, password


def test_the_second_sync_reports_no_change(synced):
    _, _, first, second, check, _ = synced
    assert any(c.kind == "client-policy" for c in first)
    assert second == []
    assert check == []
    names = {p["name"] for p in _admin("GET", "/papaia/client-policies/policies")["policies"]}
    assert {"data-chain", "papaia-person-papaia-data-exchange"} <= names
    assert "papaia-one-aud-flow-mcp-paperless" in names


def test_an_exchange_for_two_audiences_is_refused(synced):
    *_, password = synced
    subject = _person_token("papaia-studio-gateway", password)
    for scope, audience in (
        ("aud-mcp-paperless aud-flow", None),
        ("aud-mcp-paperless aud-flow", "mcp-paperless"),
        ("aud-mcp-paperless aud-flow aud-papaia-data", None),
    ):
        status, result = _exchange("papaia-studio-gateway", subject, scope, audience)
        assert status == 400, (scope, audience, result["claims"])
    status, result = _exchange(
        "papaia-studio-gateway", subject, "aud-mcp-paperless", "mcp-paperless"
    )
    assert status == 200, result["error"]
    assert result["claims"]["aud"] == "mcp-paperless"
    assert result["claims"]["azp"] == "papaia-studio-gateway"


def test_the_chain_runs_only_from_studio(synced):
    *_, password = synced
    studio = _person_token("papaia-studio-gateway", password)
    status, hop1 = _exchange("papaia-studio-gateway", studio, "aud-papaia-data", "papaia-data")
    assert status == 200, hop1["error"]
    assert hop1["claims"]["aud"] == "papaia-data"
    status, hop2 = _exchange("papaia-data", hop1["token"], "aud-mcp-paperless", "mcp-paperless")
    assert status == 200, hop2["error"]
    assert (hop2["claims"]["aud"], hop2["claims"]["azp"]) == ("mcp-paperless", "papaia-data")
    assert hop2["claims"]["sub"] == hop1["claims"]["sub"]

    for origin in ("assist-gate", "flow-engine"):
        own = _person_token(origin, password)
        status, first = _exchange(origin, own, "aud-papaia-data", "papaia-data")
        assert status == 200, (origin, first["error"])
        assert first["claims"]["azp"] == origin
        status, second = _exchange(
            "papaia-data", first["token"], "aud-mcp-paperless", "mcp-paperless"
        )
        assert status == 400, (origin, second["claims"])

    # a third hop over Data's own token
    status, hop3 = _exchange("papaia-data", hop2["token"], "aud-mcp-paperless", "mcp-paperless")
    assert status == 400, hop3["claims"]


def test_a_service_account_cannot_reach_a_person_only_audience(synced):
    try:
        _admin(
            "POST",
            "/papaia/clients",
            {
                "clientId": PROBE,
                "publicClient": False,
                "standardFlowEnabled": False,
                "serviceAccountsEnabled": True,
                "attributes": {"standard.token.exchange.enabled": "true"},
                "defaultClientScopes": ["basic"],
                "optionalClientScopes": ["aud-papaia-data", "aud-mcp-paperless"],
            },
        )
        status, body = _token_request(
            PROBE, {"grant_type": "client_credentials", "scope": "aud-papaia-data"}
        )
        assert status == 400, body.get("error")
        status, body = _token_request(
            PROBE, {"grant_type": "client_credentials", "scope": "aud-mcp-paperless"}
        )
        assert status == 200, body.get("error")
        assert _claims(body["access_token"])["aud"] == "mcp-paperless"
        status, body = _token_request(PROBE, {"grant_type": "client_credentials"})
        assert status == 200, body.get("error")
        assert "sid" not in _claims(body["access_token"])
        status, result = _exchange(PROBE, body["access_token"], "aud-papaia-data", "papaia-data")
        assert status == 400, result["claims"]
    finally:
        _admin("DELETE", f"/papaia/clients/{_client(PROBE)['id']}")


def test_flow_engine_is_no_audience_anywhere(synced):
    *_, password = synced
    scopes = _admin("GET", "/papaia/client-scopes")
    assert "aud-flow-engine" not in {s["name"] for s in scopes}
    mappers = [m for s in scopes for m in s.get("protocolMappers", [])]
    mappers += [m for c in _admin("GET", "/papaia/clients") for m in c.get("protocolMappers", [])]
    assert not [
        m
        for m in mappers
        if (m.get("config") or {}).get("included.client.audience") == "flow-engine"
    ]
    subject = _person_token("papaia-studio-gateway", password)
    status, _ = _exchange("papaia-studio-gateway", subject, "openid", "flow-engine")
    assert status == 400


def test_a_claims_parameter_mapper_is_removed_and_the_realm_is_back_in_line(synced):
    api, plan, *_ = synced
    gateway = _client("papaia-studio-gateway")
    _admin(
        "POST",
        f"/papaia/clients/{gateway['id']}/protocol-mappers/models",
        {
            "name": "claims parameter",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-claims-param-token-mapper",
            "config": {"access.token.claim": "true"},
        },
    )
    drift = rs.reconcile(api.call, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "papaia-studio-gateway")]
    rs.reconcile(api.call, plan, apply=True)
    assert not _client("papaia-studio-gateway").get("protocolMappers")
    assert rs.reconcile(api.call, plan, apply=True) == []
    assert rs.reconcile(api.call, plan, apply=False) == []
