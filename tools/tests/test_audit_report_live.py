"""The permission report of papaia-audit against a throwaway Keycloak of the pinned
version: the realm sync gives `svc-papaia-audit-report` exactly `view-users` (a second
sync changes nothing), the account signs in with its key and reads what the report needs
and nothing else (the client list and the realm settings are refused), two builds give
the same checksum and taking a role from Ben changes his row only, and `papaia-manager`
alone exchanges a person's token for `papaia-audit` (one audience, with `sid`), which the
read API accepts; a service account gets no token for it.

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
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "infra" / "audit"))

from papaia_audit import idp, read  # noqa: E402
from papaia_audit import report as rp  # noqa: E402

from lib import access_report as ar  # noqa: E402
from lib import audit_report_account as ara  # noqa: E402
from lib import realm_sync as rs  # noqa: E402
from tests.test_realm_sync_live import PASSWORD, URL, _admin  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)

REGISTER = rs.load_register()
TREE = {"": {"COMPOSE_PROFILES": "keycloak,audit"}}
NOW = datetime(2026, 11, 22, 9, 0, tzinfo=timezone.utc)
# Throwaway credentials of this test realm only (sign-in of the seeded persons).
BEN_PASSWORD = secrets.token_urlsafe(18)
MANAGER_SECRET = secrets.token_urlsafe(24)
OTHER_SECRET = secrets.token_urlsafe(24)


def _call(method: str, path: str, body=None):
    return _admin(method, f"/papaia{path}", body)


def _token(client: str, secret: str, **form):
    data = urllib.parse.urlencode({"client_id": client, "client_secret": secret, **form}).encode()
    request = urllib.request.Request(
        f"{URL}/realms/papaia/protocol/openid-connect/token", data=data
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def _claims(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _rows(doc: dict) -> dict[str, dict]:
    return {row["key"]: row for row in doc["rows"]}


@pytest.fixture(scope="module")
def realm(tmp_path_factory):
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    for role in ("user", "flow-author"):
        _call("POST", "/roles", {"name": role})
    # The manager as the realm template creates it (keycloak_role_sync), and one other
    # confidential client with token exchange switched on.
    _call("POST", "/clients", {
        "clientId": "papaia-manager", "secret": MANAGER_SECRET, "publicClient": False,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "fullScopeAllowed": True, "attributes": {"login_theme": "papaia"},
    })
    _call("POST", "/clients", {
        "clientId": "other-client", "secret": OTHER_SECRET, "publicClient": False,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "attributes": {rs.TOKEN_EXCHANGE: "true"},
    })
    config = tmp_path_factory.mktemp("config")
    keys = rs.keystore(config)
    token = rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24))
    api = rs.AdminApi(URL, None, token)
    plan = rs.build_plan(
        REGISTER, [], [],
        core_audiences=ara.core_audiences(TREE),
        platform_pairings=ara.platform_pairings(TREE),
    )
    rs.reconcile(api.call, plan, apply=True, keys=keys, master=_call)
    for role in ("papaia-auditor", "papaia-admin"):
        assert _call("GET", f"/roles/{role}")["name"] == role
    for name, roles in (("ben", ["user", "flow-author", "papaia-auditor"]), ("dora", ["user"])):
        _call("POST", "/users", {
            "username": name, "enabled": True, "firstName": name.title(), "lastName": "Test",
            "email": f"{name}@example.test", "emailVerified": True,
            "credentials": [{"type": "password", "value": BEN_PASSWORD, "temporary": False}],
        })
        uid = _call("GET", f"/users?username={name}&exact=true")[0]["id"]
        _call("POST", f"/users/{uid}/role-mappings/realm",
              [_call("GET", f"/roles/{r}") for r in roles])
    return {"keys": keys, "config": config, "api": api, "plan": plan}


def test_the_sync_keeps_exactly_view_users_and_a_second_run_changes_nothing(realm):
    assert ara.align(_call, realm["keys"], enabled=True, apply=True)
    client = _call("GET", f"/clients?clientId={ara.CLIENT_ID}")[0]
    user = _call("GET", f"/clients/{client['id']}/service-account-user")
    mappings = _call("GET", f"/users/{user['id']}/role-mappings")
    granted = {r["name"] for r in mappings["clientMappings"]["realm-management"]["mappings"]}
    assert granted == {"view-users"}
    assert ara.align(_call, realm["keys"], enabled=True, apply=True) == []
    assert ara.align(_call, realm["keys"], enabled=True, apply=False) == []


def _reader(realm) -> idp.AdminReader:
    folder = realm["config"] / "security" / "service-accounts" / ara.CLIENT_ID
    return idp.AdminReader(URL, None, idp.AccountKey(folder))


def _inputs(realm) -> rp.Inputs:
    document = ar.build_inputs(
        _call,
        pairings=ara.platform_pairings(TREE),
        delegations={"idle_days": 30, "max_days": 365, "source": "default"},
        breakglass_ids=frozenset(),
        period=180,
    )
    return rp.parse_inputs(document)


def test_the_account_reads_the_report_and_nothing_beyond_it(realm):
    reader = _reader(realm)
    inputs = _inputs(realm)
    first = rp.build(rp.collect(reader, inputs), "person", [], NOW)
    second = rp.build(rp.collect(reader, inputs), "person", [], NOW)
    assert first["checksum"] == second["checksum"]
    names = {row["username"] for row in first["rows"]}
    assert {"ben", "dora"} <= names

    ben = _call("GET", "/users?username=ben&exact=true")[0]
    _call("DELETE", f"/users/{ben['id']}/role-mappings/realm",
          [_call("GET", "/roles/flow-author")])
    third = rp.build(rp.collect(reader, inputs), "person", [], NOW)
    before, after = _rows(first), _rows(third)
    assert first["checksum"] != third["checksum"]
    assert [key for key in before if before[key] != after[key]] == [f"person:{ben['id']}"]

    # The account's own token reaches nothing outside the report's reads.
    token = reader._bearer()
    for path in ("", "/clients", "/roles", "/groups"):
        request = urllib.request.Request(
            f"{URL}/admin/realms/papaia{path}", headers={"Authorization": f"Bearer {token}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read())
            # With view-users alone the realm answers without its settings.
            assert path == "" and "offlineSessionIdleTimeout" not in body
        except urllib.error.HTTPError as error:
            assert error.code == 403, (path, error.code)


def test_the_manager_alone_exchanges_for_papaia_audit_and_the_read_api_accepts_it(realm):
    manager = _call("GET", "/clients?clientId=papaia-manager")[0]
    assert manager["attributes"][rs.TOKEN_EXCHANGE] == "true"
    # Password grant for this test only, to get a person's session token.
    for client_id in ("papaia-manager", "other-client"):
        client = _call("GET", f"/clients?clientId={client_id}")[0]
        _call("PUT", f"/clients/{client['id']}",
              {"clientId": client_id, "directAccessGrantsEnabled": True})
    secrets_of = {"papaia-manager": MANAGER_SECRET, "other-client": OTHER_SECRET}
    answers = {}
    for client_id, secret in secrets_of.items():
        status, session = _token(client_id, secret, grant_type="password", username="ben",
                                 password=BEN_PASSWORD, scope="openid")
        assert status == 200, session
        answers[client_id] = _token(
            client_id, secret,
            grant_type=rs.TOKEN_EXCHANGE_GRANT,
            subject_token=session["access_token"],
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience="papaia-audit",
            scope="aud-papaia-audit",
        )
    status, exchanged = answers["papaia-manager"]
    assert status == 200, exchanged
    claims = _claims(exchanged["access_token"])
    assert claims["aud"] in ("papaia-audit", ["papaia-audit"])
    assert isinstance(claims.get("sid"), str) and claims["azp"] == "papaia-manager"
    assert answers["other-client"][0] in (400, 403)

    discovery = json.loads(urllib.request.urlopen(
        f"{URL}/realms/papaia/.well-known/openid-configuration", timeout=10).read())
    jwks = json.loads(urllib.request.urlopen(discovery["jwks_uri"], timeout=10).read())
    keys = read.TokenKeys.parse({
        "format": read.TOKEN_KEYS_FORMAT,
        "issuer": discovery["issuer"],
        "keys": [k for k in jwks["keys"] if k.get("alg") == "RS256" and k.get("use") == "sig"],
    })
    identity = read.check_token(f"Bearer {exchanged['access_token']}", keys, time.time())
    assert "papaia-auditor" in identity.roles and "papaia-admin" not in identity.roles


def test_a_service_account_gets_no_token_for_papaia_audit(realm):
    client = _call("GET", "/clients?clientId=other-client")[0]
    _call("PUT", f"/clients/{client['id']}",
          {"clientId": "other-client", "serviceAccountsEnabled": True})
    status, answer = _token("other-client", OTHER_SECRET, grant_type="client_credentials",
                            scope="aud-papaia-audit")
    if status == 200:
        # Without the scope on the client Keycloak drops it: no papaia-audit audience.
        assert "papaia-audit" not in json.dumps(_claims(answer["access_token"]).get("aud"))
    else:
        assert status in (400, 403)
