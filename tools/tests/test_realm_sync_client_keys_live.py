"""Module client keys (`client_keys[]`) against a throwaway Keycloak of the pinned version.

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from lib import service_account_keys as sak
from tests.test_realm_sync_client_keys import CONSOLE, ENGINE, _module, _plan, _write
from tests.test_realm_sync_live import PASSWORD, URL, _admin, _client

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)

TOKEN_URL = f"{URL}/realms/papaia/protocol/openid-connect/token"


class _Keys:
    """Private keys of the test, in a 0700 folder of their own (the module's volume);
    only the public JWK sets go to the add-on configuration folder."""

    def __init__(self, root) -> None:
        self.store = sak.KeyStore(root / "module-volume")

    def new(self, name: str) -> dict:
        return self.store.generate(f"svc-test-{name}")

    def path(self, name: str):
        return self.store.key_path(f"svc-test-{name}")


def _request(client_id: str, form: dict) -> tuple[int, dict]:
    form = {"grant_type": "client_credentials", "client_id": client_id, **form}
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _signed(client_id: str, keys: _Keys, name: str, jwk: dict) -> int:
    assertion = sak.client_assertion(keys.path(name), jwk, client_id, TOKEN_URL)
    form = {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    return _request(client_id, form)[0]


@pytest.fixture(scope="module")
def realm(tmp_path_factory):
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    api = rs.AdminApi(URL, None, rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24)))
    root = tmp_path_factory.mktemp("host")
    folder = root / "addons" / "papaia-flow"
    keys = _Keys(root)
    jwks = {ENGINE: keys.new("engine"), CONSOLE: keys.new("console")}
    _write(folder, [jwks[ENGINE]])
    _write(folder, [jwks[CONSOLE]], "console.jwks.json")
    rs.reconcile(api.call, _plan(_module(folder)), apply=True)
    # client_credentials only to prove the client authentication itself.
    for client_id in (ENGINE, CONSOLE):
        client = _client(client_id)
        client["serviceAccountsEnabled"] = True
        _admin("PUT", f"/papaia/clients/{client['id']}", client)
    return api, folder, keys, jwks


def _sync(realm, *, apply=True) -> list[rs.Change]:
    api, folder, _, _ = realm
    return rs.reconcile(api.call, _plan(_module(folder)), apply=apply)


def test_both_flow_clients_sign_in_with_private_key_jwt_only(realm):
    _, _, keys, jwks = realm
    assert _signed(ENGINE, keys, "engine", jwks[ENGINE]) == 200
    assert _signed(CONSOLE, keys, "console", jwks[CONSOLE]) == 200
    for client_id in (ENGINE, CONSOLE):
        assert _client(client_id)["clientAuthenticatorType"] == "client-jwt"
        status, _ = _request(client_id, {"client_secret": "a-guessed-secret"})
        assert status in (400, 401)


def test_the_second_run_reports_no_change(realm):
    assert _sync(realm) == []
    assert _sync(realm, apply=False) == []


def test_rotation_refuses_the_old_key_within_60_seconds(realm):
    """MN-13: the old key is refused at most 60 s after the new file is applied."""
    _, folder, keys, jwks = realm
    old = jwks[ENGINE]
    new = keys.new("engine-next")
    _write(folder, [new])
    started = time.monotonic()
    assert [c.operation for c in _sync(realm)] == ["rotate_client_key"]
    while _signed(ENGINE, keys, "engine", old) == 200:
        assert time.monotonic() - started <= 60, "old key still accepted after 60 s"
        time.sleep(2)
    assert _signed(ENGINE, keys, "engine-next", new) == 200
    assert _sync(realm, apply=False) == []


def test_a_manual_key_change_fails_the_check_and_is_repaired(realm):
    client = _client(CONSOLE)
    client["attributes"]["jwks.string"] = json.dumps({"keys": []})
    _admin("PUT", f"/papaia/clients/{client['id']}", client)
    assert [c.name for c in _sync(realm, apply=False)] == [CONSOLE]
    _sync(realm)
    assert _sync(realm, apply=False) == []
