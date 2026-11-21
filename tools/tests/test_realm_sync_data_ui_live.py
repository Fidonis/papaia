"""Data's own interface client and the chain holder against a throwaway Keycloak of the
pinned version: real sign-ins and token exchanges in the realm the sync built.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it, as
for tests/test_realm_sync_live.py:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. `papaia-data-ui` authenticates with
`private_key_jwt`: the test makes a throwaway key pair with `openssl` in a temporary
directory and registers its certificate at the client. Token values are never printed;
only decoded claims are compared.
"""

from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from tests.test_realm_sync import REGISTER, _flow, _pairings, _paperless
from tests.test_realm_sync_data_ui import _studio_with_handover
from tests.test_realm_sync_live import URL, _admin, _client, pytestmark, realm  # noqa: F401
from tests.test_realm_sync_policies import _data
from tests.test_realm_sync_policies_live import ACCESS_TOKEN, TE, USER, _claims, _secret

UI = "papaia-data-ui"
TOKEN_PATH = "/realms/papaia/protocol/openid-connect/token"

if not shutil.which("openssl"):
    pytestmark = [pytestmark, pytest.mark.skip(reason="openssl is needed for private_key_jwt")]


def _plan() -> rs.Plan:
    return rs.build_plan(
        REGISTER,
        [_studio_with_handover(), _flow(), _paperless(), _data()],
        _pairings(
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"),
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data-ui", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data-ui", "papaia-studio", ["x"], "confirmed"),
        ),
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class _Key:
    """A throwaway RSA key of `papaia-data-ui` in a temporary directory."""

    def __init__(self, directory) -> None:
        self.key = directory / "ui.key"
        cert = directory / "ui.crt"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN={UI}", "-keyout", str(self.key), "-out", str(cert),
            ],
            check=True,
            capture_output=True,
        )  # fmt: skip
        der = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        self.certificate = base64.b64encode(der).decode()

    def assertion(self) -> str:
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = {
            "iss": UI,
            "sub": UI,
            "aud": f"{URL}/realms/papaia",
            "jti": secrets.token_hex(16),
            "iat": now,
            "exp": now + 60,
        }
        signing_input = f"{header}.{_b64url(json.dumps(claims).encode())}"
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key)],
            input=signing_input.encode(),
            check=True,
            capture_output=True,
        ).stdout
        return f"{signing_input}.{_b64url(signature)}"


def _token_request(client_id: str, form: dict, key: _Key) -> tuple[int, dict]:
    if client_id == UI:
        auth = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": key.assertion(),
        }
    else:
        auth = {"client_secret": _secret(client_id)}
    data = urllib.parse.urlencode(dict(form, client_id=client_id, **auth)).encode()
    req = urllib.request.Request(f"{URL}{TOKEN_PATH}", data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _person_token(client_id: str, password: str, key: _Key, scope: str = "openid") -> str:
    """A person's own token of `client_id`; the password grant is switched on for this one
    request and off again (the sync would remove it)."""
    client = _client(client_id)
    _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": True})
    try:
        status, body = _token_request(
            client_id,
            {"grant_type": "password", "username": USER, "password": password, "scope": scope},
            key,
        )
    finally:
        _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": False})
    assert status == 200, body.get("error")
    return body["access_token"]


def _exchange(client_id: str, subject: str, scope: str, audience: str, key: _Key):
    form = {
        "grant_type": TE,
        "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "scope": scope,
        "audience": audience,
    }
    status, body = _token_request(client_id, form, key)
    claims = _claims(body["access_token"]) if status == 200 else {}
    return status, {"claims": claims, "error": body.get("error"), "token": body.get("access_token")}


@pytest.fixture(scope="module")
def synced(realm, tmp_path_factory):  # noqa: F811
    api, _ = realm
    plan = _plan()
    first = rs.reconcile(api.call, plan, apply=True)
    key = _Key(tmp_path_factory.mktemp("data-ui-key"))
    # the module's own setup registers its public key; the sync leaves it in place
    ui = _client(UI)
    attributes = dict(ui["attributes"], **{"jwt.credential.certificate": key.certificate})
    _admin("PUT", f"/papaia/clients/{ui['id']}", {"attributes": attributes})
    second = rs.reconcile(api.call, plan, apply=True)
    check = rs.reconcile(api.call, plan, apply=False)
    password = secrets.token_urlsafe(24)
    user = {
        "username": USER,
        "enabled": True,
        "email": "anna-live@example.invalid",
        "emailVerified": True,
        "firstName": "Anna",
        "lastName": "Live",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    _admin("POST", "/papaia/users", user)
    return api, plan, first, second, check, password, key


def test_the_second_sync_reports_no_change(synced):
    _, _, first, second, check, *_ = synced
    assert first
    assert second == []
    assert check == []
    names = {p["name"] for p in _admin("GET", "/papaia/client-policies/policies")["policies"]}
    assert {"data-chain", "data-self", "data-handover"} <= names


def test_data_ui_is_configured_as_its_row_in_the_client_table(synced):
    ui = _client(UI)
    assert ui["clientAuthenticatorType"] == "client-jwt"
    assert (ui["publicClient"], ui["bearerOnly"], ui["standardFlowEnabled"]) == (
        False,
        False,
        True,
    )
    assert ui["fullScopeAllowed"] is False
    assert ui["attributes"]["standard.token.exchange.enabled"] == "true"
    assert "papaia.chain-holder" not in ui["attributes"]
    assert _client("papaia-data")["attributes"]["papaia.chain-holder"] == "true"
    optional = {
        s["name"] for s in _admin("GET", f"/papaia/clients/{ui['id']}/optional-client-scopes")
    }
    default = {
        s["name"] for s in _admin("GET", f"/papaia/clients/{ui['id']}/default-client-scopes")
    }
    assert optional == {"aud-mcp-paperless", "aud-papaia-studio"}
    assert "offline_access" not in optional | default
    assert not [s for s in default if s.startswith("aud-")]


def test_data_ui_reaches_a_connection_in_one_hop_with_a_single_audience(synced):
    *_, password, key = synced
    session = _person_token(UI, password, key)
    assert _claims(session)["azp"] == UI
    status, hop = _exchange(UI, session, "aud-mcp-paperless", "mcp-paperless", key)
    assert status == 200, hop["error"]
    assert hop["claims"]["aud"] == "mcp-paperless"  # a single string, not a list
    assert hop["claims"]["azp"] == UI
    assert hop["claims"]["sub"] == _claims(session)["sub"]
    assert "offline_access" not in hop["claims"].get("scope", "").split()

    # a second hop over its own exchanged token is refused (data-self)
    status, again = _exchange(UI, hop["token"], "aud-mcp-paperless", "mcp-paperless", key)
    assert status == 400, again["claims"]


def test_data_ui_hands_over_to_studio_with_its_session_token(synced):
    *_, password, key = synced
    session = _person_token(UI, password, key)
    status, handover = _exchange(UI, session, "aud-papaia-studio", "papaia-studio", key)
    assert status == 200, handover["error"]
    assert handover["claims"]["aud"] == "papaia-studio"
    assert handover["claims"]["azp"] == UI


def test_the_chain_holder_never_re_exchanges_a_token_of_data_ui(synced):
    *_, password, key = synced
    session = _person_token(UI, password, key)
    status, hop = _exchange(UI, session, "aud-mcp-paperless", "mcp-paperless", key)
    assert status == 200, hop["error"]
    for subject in (session, hop["token"]):
        status, result = _exchange(
            "papaia-data", subject, "aud-mcp-paperless", "mcp-paperless", key
        )
        assert status == 400, result["claims"]


def test_data_ui_never_exchanges_a_received_token(synced):
    *_, password, key = synced
    studio = _person_token("papaia-studio-gateway", password, key)
    status, for_data = _exchange(
        "papaia-studio-gateway", studio, "aud-papaia-data", "papaia-data", key
    )
    assert status == 200, for_data["error"]
    for scope, audience in (
        ("aud-mcp-paperless", "mcp-paperless"),
        ("aud-papaia-studio", "papaia-studio"),
    ):
        status, result = _exchange(UI, for_data["token"], scope, audience, key)
        assert status == 400, (scope, result["claims"])


def test_the_chain_from_studio_still_runs_through_the_holder(synced):
    *_, password, key = synced
    studio = _person_token("papaia-studio-gateway", password, key)
    status, hop1 = _exchange("papaia-studio-gateway", studio, "aud-papaia-data", "papaia-data", key)
    assert status == 200, hop1["error"]
    status, hop2 = _exchange(
        "papaia-data", hop1["token"], "aud-mcp-paperless", "mcp-paperless", key
    )
    assert status == 200, hop2["error"]
    assert (hop2["claims"]["aud"], hop2["claims"]["azp"]) == ("mcp-paperless", "papaia-data")
    # a third hop over Data's own token stays refused
    status, hop3 = _exchange(
        "papaia-data", hop2["token"], "aud-mcp-paperless", "mcp-paperless", key
    )
    assert status == 400, hop3["claims"]


def test_data_ui_is_no_audience(synced):
    *_, password, key = synced
    assert "aud-papaia-data-ui" not in {s["name"] for s in _admin("GET", "/papaia/client-scopes")}
    studio = _person_token("papaia-studio-gateway", password, key)
    status, _ = _exchange("papaia-studio-gateway", studio, "openid", UI, key)
    assert status == 400


def test_the_mark_on_another_client_is_reported_and_removed(synced):
    api, plan, *_ = synced
    gateway = _client("papaia-studio-gateway")
    attributes = dict(gateway["attributes"], **{"papaia.chain-holder": "true"})
    _admin("PUT", f"/papaia/clients/{gateway['id']}", {"attributes": attributes})
    drift = rs.reconcile(api.call, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "papaia-studio-gateway")]
    rs.reconcile(api.call, plan, apply=True)
    assert "papaia.chain-holder" not in _client("papaia-studio-gateway")["attributes"]
    assert rs.reconcile(api.call, plan, apply=True) == []
    assert rs.reconcile(api.call, plan, apply=False) == []
