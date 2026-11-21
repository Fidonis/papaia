"""Task sources and the own-token exchange of Flow's console, enforced by a throwaway
Keycloak of the pinned version: real sign-ins and token exchanges against the realm the
sync built (security 1.4 "Aufgabenquellen", cases (a) to (d); (e) is a module route).

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it, as
for tests/test_realm_sync_live.py:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation. `flow-console` signs its requests with
a key pair made for the run by the local openssl (the private key stays in a temporary
directory); token values are never printed, only decoded claims are compared.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_sync as rs
from tests.test_realm_sync import REGISTER, _flow, _pairings, _paperless
from tests.test_realm_sync_live import URL, _admin, _client, pytestmark, realm  # noqa: F401
from tests.test_realm_sync_policies import _assist, _data
from tests.test_realm_sync_policies_live import ACCESS_TOKEN, TE, USER, _claims, _secret
from tests.test_realm_sync_task_sources import CONSOLE, TASK_SOURCES, _me, _studio_api

REDIRECT = "https://flow.example.invalid/auth/callback"
# Clients that hold a pairing on `flow` and whose `flow` tokens are tried at the console.
FLOW_HOLDERS = ("papaia-studio-gateway", "assist-gate", "papaia-me", "papaia-manager")


def _plan() -> rs.Plan:
    return rs.build_plan(
        REGISTER,
        [
            _flow(),
            _studio_api(),
            _data(),
            _me(),
            _paperless(),
            _assist(),
            rs.Module("papaia-manager", [], {}),
        ],
        _pairings(
            *TASK_SOURCES,
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            ("assist-gate", "flow", ["x"], "confirmed"),
            ("papaia-manager", "flow", ["x"], "confirmed"),
        ),
    )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class ConsoleKey:
    """An RSA key pair of the run, made and used by the local openssl: Keycloak gets the
    public key as a JWK set, every request of `flow-console` carries a fresh assertion
    (RFC 7523)."""

    def __init__(self, directory) -> None:
        self.path = directory / "console.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(self.path), "2048"], check=True, capture_output=True
        )
        self.path.chmod(0o600)
        out = subprocess.run(
            ["openssl", "rsa", "-in", str(self.path), "-noout", "-modulus"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        modulus = bytes.fromhex(out.strip().split("=", 1)[1])
        self.jwk = {
            "kty": "RSA",
            "kid": "live-console",
            "use": "sig",
            "alg": "RS256",
            "n": _b64(modulus),
            "e": "AQAB",
        }

    def assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.jwk["kid"]}
        claims = {
            "iss": CONSOLE,
            "sub": CONSOLE,
            "aud": f"{URL}/realms/papaia",
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "exp": now + 60,
        }
        signing_input = ".".join(
            _b64(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
        ).encode()
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.path)],
            input=signing_input,
            check=True,
            capture_output=True,
        ).stdout
        return f"{signing_input.decode()}.{_b64(signature)}"


def _post(form: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"{URL}/realms/papaia/protocol/openid-connect/token",
        data=urllib.parse.urlencode(form).encode(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _request(key: ConsoleKey, client_id: str, form: dict) -> tuple[int, dict]:
    if client_id == CONSOLE:
        auth = {
            "client_id": CONSOLE,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": key.assertion(),
        }
    else:
        auth = {"client_id": client_id, "client_secret": _secret(client_id)}
    return _post(dict(form, **auth))


def _person_token(key: ConsoleKey, client_id: str, password: str, scope: str = "openid") -> dict:
    """A person's own token of `client_id`. The managed clients have no password grant;
    it is switched on for this one request and off again (the sync would remove it)."""
    client = _client(client_id)
    _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": True})
    try:
        status, body = _request(
            key,
            client_id,
            {"grant_type": "password", "username": USER, "password": password, "scope": scope},
        )
    finally:
        _admin("PUT", f"/papaia/clients/{client['id']}", {"directAccessGrantsEnabled": False})
    assert status == 200, (client_id, body.get("error"))
    return body


def _exchange(key: ConsoleKey, client_id: str, subject: str, scope: str, audience=None):
    form = {
        "grant_type": TE,
        "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "scope": scope,
    }
    if audience:
        form["audience"] = audience
    status, body = _request(key, client_id, form)
    claims = _claims(body["access_token"]) if status == 200 else {}
    return status, {"claims": claims, "error": body.get("error"), "token": body.get("access_token")}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _authorize(scope: str) -> tuple[int, str]:
    """The authorization request of the console's sign-in (code flow, PKCE S256): the
    status and, for a redirect, the error the redirect carries."""
    verifier = secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    query = urllib.parse.urlencode(
        {
            "client_id": CONSOLE,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(8),
        }
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(f"{URL}/realms/papaia/protocol/openid-connect/auth?{query}", timeout=10):
            return 200, ""
    except urllib.error.HTTPError as exc:
        location = urllib.parse.urlsplit(exc.headers.get("Location") or "")
        error = urllib.parse.parse_qs(location.query).get("error", [""])[0]
        return exc.code, error


@pytest.fixture(scope="module")
def synced(realm, tmp_path_factory):  # noqa: F811
    api, _ = realm
    plan = _plan()
    first = rs.reconcile(api.call, plan, apply=True)
    key = ConsoleKey(tmp_path_factory.mktemp("console-key"))
    # What Flow registers itself: its public key and its redirect address. The sync
    # leaves both alone.
    console = _client(CONSOLE)
    attributes = dict(console.get("attributes") or {})
    attributes.update({"use.jwks.string": "true", "jwks.string": json.dumps({"keys": [key.jwk]})})
    _admin(
        "PUT",
        f"/papaia/clients/{console['id']}",
        {"attributes": attributes, "redirectUris": [REDIRECT]},
    )
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
    return key, first, second, check, password


def test_the_realm_is_in_line_after_flow_registered_its_key(synced):
    _, first, second, check, _ = synced
    assert first
    assert second == []
    assert check == []
    console = _client(CONSOLE)
    assert console["clientAuthenticatorType"] == "client-jwt"
    assert console["defaultClientScopes"] == ["papaia-person"]
    assert set(console["optionalClientScopes"]) == {
        "aud-flow",
        "aud-papaia-data",
        "aud-papaia-studio",
    }
    names = {p["name"] for p in _admin("GET", "/papaia/client-policies/policies")["policies"]}
    assert {
        "papaia-one-aud-flow-papaia-data",
        "papaia-one-aud-flow-papaia-studio",
        "papaia-one-aud-papaia-data-papaia-studio",
    } <= names


def test_the_console_signs_in_with_its_key_and_not_with_a_secret(synced):
    key, *_, password = synced
    body = _person_token(key, CONSOLE, password, "openid aud-flow")
    claims = _claims(body["access_token"])
    assert (claims["aud"], claims["azp"]) == ("flow", CONSOLE)
    assert claims["sub"] and claims["sid"]
    assert claims["person_id"] == claims["sub"]
    assert "papaia-person" in claims["scope"].split()
    # without the optional scope the sign-in token has no audience: no aud-* default
    plain = _claims(_person_token(key, CONSOLE, password)["access_token"])
    assert "aud" not in plain
    status, body = _post(
        {
            "grant_type": "client_credentials",
            "client_id": CONSOLE,
            "client_secret": "not-the-key",
        }
    )
    # a client secret is no way in: Keycloak asks for the assertion
    assert (status, body.get("error")) == (400, "invalid_client")


def test_a_foreign_flow_token_is_never_exchanged_by_the_console(synced):
    """(a): Flow's console exchanges only its own tokens."""
    key, *_, password = synced
    for holder in FLOW_HOLDERS:
        own = _person_token(key, holder, password)["access_token"]
        status, flow = _exchange(key, holder, own, "aud-flow", "flow")
        assert status == 200, (holder, flow["error"])
        assert (flow["claims"]["aud"], flow["claims"]["azp"]) == ("flow", holder)
        for scope, audience in (
            ("aud-papaia-data", "papaia-data"),
            ("aud-papaia-studio", "papaia-studio"),
        ):
            status, result = _exchange(key, CONSOLE, flow["token"], scope, audience)
            # the console is not in the subject token's audience nor its azp
            assert (status, result["error"]) == (403, "access_denied"), (holder, scope)
            assert result["token"] is None


def test_the_console_reads_the_task_sources_with_its_own_token(synced):
    key, *_, password = synced
    own = _person_token(key, CONSOLE, password, "openid aud-flow")["access_token"]
    for scope, audience in (
        ("aud-papaia-data", "papaia-data"),
        ("aud-papaia-studio", "papaia-studio"),
    ):
        status, result = _exchange(key, CONSOLE, own, scope, audience)
        assert status == 200, (scope, result["error"])
        # exactly one audience, as a single value
        assert result["claims"]["aud"] == audience
        assert result["claims"]["azp"] == CONSOLE
        assert result["claims"]["sub"] == _claims(own)["sub"]


def test_data_never_re_exchanges_a_console_or_me_token(synced):
    """(b): only Studio is an origin of the chain."""
    key, *_, password = synced
    for client_id in (CONSOLE, "papaia-me"):
        own = _person_token(key, client_id, password)["access_token"]
        status, data = _exchange(key, client_id, own, "aud-papaia-data", "papaia-data")
        assert status == 200, (client_id, data["error"])
        status, result = _exchange(
            key, "papaia-data", data["token"], "aud-mcp-paperless", "mcp-paperless"
        )
        assert status == 400, (client_id, result["claims"])


def test_the_console_reaches_no_connection(synced):
    """(c): no aud-mcp-* scope at the console."""
    key, *_, password = synced
    own = _person_token(key, CONSOLE, password)["access_token"]
    for scope, audience in (("aud-mcp-paperless", None), ("aud-mcp-paperless", "mcp-paperless")):
        status, result = _exchange(key, CONSOLE, own, scope, audience)
        assert status == 400, (scope, audience, result["claims"])


def test_two_audiences_are_refused_at_sign_in_and_in_an_exchange(synced):
    """(d): exactly one aud-* scope per request."""
    key, *_, password = synced
    own = _person_token(key, CONSOLE, password)["access_token"]
    for scope in (
        "aud-papaia-data aud-papaia-studio",
        "aud-flow aud-papaia-data",
        "aud-flow aud-papaia-studio",
    ):
        status, result = _exchange(key, CONSOLE, own, scope)
        assert status == 400, (scope, result["claims"])
    assert _authorize("openid aud-flow") == (200, "")
    for scope in ("openid aud-flow aud-papaia-data", "openid aud-flow aud-papaia-studio"):
        assert _authorize(scope) == (302, "invalid_request"), scope
    # the same rule for Me, the other task-source reader with three scopes
    me = _person_token(key, "papaia-me", password)["access_token"]
    status, result = _exchange(key, "papaia-me", me, "aud-papaia-data aud-papaia-studio")
    assert status == 400, result["claims"]


def test_neither_console_nor_engine_is_an_audience(synced):
    key, *_, password = synced
    subject = _person_token(key, "papaia-studio-gateway", password)["access_token"]
    for audience in (CONSOLE, "flow-engine"):
        status, _ = _exchange(key, "papaia-studio-gateway", subject, "openid", audience)
        assert status == 400, audience
    scopes = _admin("GET", "/papaia/client-scopes")
    assert not {"aud-flow-console", "aud-flow-engine"} & {s["name"] for s in scopes}
