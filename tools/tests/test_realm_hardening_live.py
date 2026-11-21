"""Realm hardening against a throwaway Keycloak of the pinned version.

Same throwaway Keycloak as tests/test_realm_sync_live.py (PAPAIA_TEST_KEYCLOAK_URL,
PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD); without both the tests are skipped. They replace the
realm `papaia` of that Keycloak, so never point them at an installation.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.test_realm_hardening import HOSTS, LIBRECHAT, _template_client
from tests.test_realm_sync import DELEGATION, REGISTER, _flow, _pairings, _paperless, _studio
from tests.test_realm_sync_live import (  # noqa: F401
    PASSWORD,
    URL,
    _admin,
    _client,
    _master_token,
    pytestmark,
)

DAY = 86400
REDIRECT = "https://chat.example.org/oauth/openid/callback"


@pytest.fixture(scope="module")
def realm():
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    # LibreChat's client as the 1.9.0 realm template created it: wildcards everywhere.
    client = _template_client("librechat")
    client = dict(client, secret=secrets.token_hex(24), redirectUris=["*"], webOrigins=["+"])
    client["attributes"] = dict(client["attributes"], **{"post.logout.redirect.uris": "*"})
    client.pop("protocolMappers")
    _admin("POST", "/papaia/clients", client)
    password = secrets.token_urlsafe(18)
    _admin(
        "POST",
        "/papaia/users",
        {
            "username": "hardening-person",
            "enabled": True,
            "email": "hardening-person@example.org",
            "emailVerified": True,
            "firstName": "Hardening",
            "lastName": "Person",
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    token = rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24))
    return rs.AdminApi(URL, None, token), password


def _plan(env: dict | None = None) -> rs.Plan:
    plan = rs.build_plan(
        REGISTER,
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(("flow-engine", "mcp-paperless", ["r"], "confirmed")),
    )
    plan.hardening = rh.load({**HOSTS, **(env or {})}, LIBRECHAT)
    return plan


def _password_grant(client_id: str, password: str) -> tuple[int, str]:
    form = {
        "grant_type": "password",
        "client_id": client_id,
        "username": "hardening-person",
        "password": password,
    }
    req = urllib.request.Request(
        f"{URL}/realms/papaia/protocol/openid-connect/token",
        data=urllib.parse.urlencode(form).encode(),
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _authorize(client_id: str, redirect_uri: str, **params) -> tuple[int, str]:
    """Start a sign-in; the status and, for a redirect, its target (an error goes back to
    a valid redirect URI, an invalid redirect URI gets an error page)."""
    query = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": "openid", **params}
    url = f"{URL}/realms/papaia/protocol/openid-connect/auth?{urllib.parse.urlencode(query)}"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=10) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location") or exc.read().decode()


def _s256() -> str:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_the_sync_hardens_the_realm_and_a_second_run_changes_nothing(realm):
    api, _ = realm
    assert rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=True) == []
    assert rs.reconcile(api.call, _plan(), apply=False) == []

    settings = _admin("GET", "/papaia")
    assert settings["sslRequired"] == "external"
    assert settings["accessTokenLifespan"] <= 300
    assert settings["revokeRefreshToken"] is True
    assert settings["refreshTokenMaxReuse"] == 0
    assert settings["bruteForceProtected"] is True
    assert settings["editUsernameAllowed"] is False
    assert settings["registrationAllowed"] is False
    assert settings["offlineSessionIdleTimeout"] <= 30 * DAY
    assert settings["offlineSessionMaxLifespanEnabled"] is True
    assert settings["offlineSessionMaxLifespan"] <= 180 * DAY


def test_no_client_has_a_wildcard_redirect_or_the_password_grant(realm):
    for client in _admin("GET", "/papaia/clients"):
        label = client["clientId"]
        if client.get("bearerOnly"):
            continue
        assert client["directAccessGrantsEnabled"] is False, label
        assert client["implicitFlowEnabled"] is False, label
        post_logout = (client.get("attributes") or {}).get("post.logout.redirect.uris", "")
        for uri in client.get("redirectUris") or []:
            assert uri != "*", label
            if not uri.startswith("/"):
                assert rh.redirect_problem(uri, https_only=True) is None, (label, uri)
        for origin in client.get("webOrigins") or []:
            assert origin not in ("*", "+") or not client.get("rootUrl", "").startswith("http")
        assert "*" not in post_logout.split("##"), label
    librechat = _client("librechat")
    assert librechat["redirectUris"] == ["https://chat.example.org/*"]
    assert librechat["webOrigins"] == ["https://chat.example.org"]


def test_the_password_grant_is_refused_at_every_client(realm):
    _, password = realm
    for client_id in ("admin-cli", "flow-cli", "librechat", "flow-console"):
        status, body = _password_grant(client_id, password)
        assert status in (400, 401), (client_id, body)


def test_a_foreign_redirect_uri_is_refused(realm):
    status, body = _authorize(
        "librechat",
        "https://evil.example.net/cb",
        response_type="code",
        code_challenge=_s256(),
        code_challenge_method="S256",
    )
    assert status == 400 and "redirect_uri" in body.lower()
    status, _ = _authorize(
        "librechat",
        REDIRECT,
        response_type="code",
        code_challenge=_s256(),
        code_challenge_method="S256",
    )
    assert status == 200


def test_a_public_client_without_pkce_or_with_plain_is_refused(realm):
    cli = _client("flow-cli")
    assert cli["publicClient"] is True
    # An update of a managed client names its switches and attributes: the client policy
    # checks them on every update.
    _admin(
        "PUT",
        f"/papaia/clients/{cli['id']}",
        {
            "redirectUris": ["https://cli.example.org/cb"],
            "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False,
            "attributes": cli["attributes"],
        },
    )
    for params in ({}, {"code_challenge": "a" * 43, "code_challenge_method": "plain"}):
        status, location = _authorize(
            "flow-cli", "https://cli.example.org/cb", response_type="code", **params
        )
        assert status == 302 and "error=invalid_request" in location, params
    status, location = _authorize("flow-cli", "https://cli.example.org/cb", response_type="token")
    assert "error=" in location, location
    status, _ = _authorize(
        "flow-cli",
        "https://cli.example.org/cb",
        response_type="code",
        code_challenge=_s256(),
        code_challenge_method="S256",
    )
    assert status == 200


def test_the_policy_keeps_the_password_grant_and_implicit_flow_off_at_managed_clients(realm):
    _, password = realm
    engine = {k: v for k, v in _client("flow-engine").items() if k != "secret"}
    for switch, refusal in (
        ("directAccessGrantsEnabled", "password credentials grant enabled"),
        ("implicitFlowEnabled", "implicit flow enabled"),
    ):
        with pytest.raises(urllib.error.HTTPError) as refused:
            _admin("PUT", f"/papaia/clients/{engine['id']}", dict(engine, **{switch: True}))
        assert refused.value.code == 400
        assert refusal in refused.value.read().decode()
    # Keycloak does not check a new client; the policy still refuses its password grant.
    _admin(
        "POST",
        "/papaia/clients",
        {
            "clientId": "hardening-probe",
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "attributes": {"papaia.managed": "true", "pkce.code.challenge.method": "S256"},
        },
    )
    probe = _client("hardening-probe")
    try:
        status, body = _password_grant("hardening-probe", password)
        assert status == 400 and "prohibited" in body
    finally:
        _admin("DELETE", f"/papaia/clients/{probe['id']}")


def test_drift_fails_the_check_and_is_repaired(realm):
    api, _ = realm
    librechat = _client("librechat")
    _admin("PUT", f"/papaia/clients/{librechat['id']}", {"redirectUris": ["*"]})
    _admin("PUT", "/papaia", {"editUsernameAllowed": True})
    changes = rs.reconcile(api.call, _plan(), apply=False)
    assert {(c.kind, c.name) for c in changes} == {("realm", "papaia"), ("client", "librechat")}
    rs.reconcile(api.call, _plan(), apply=True)
    assert rs.reconcile(api.call, _plan(), apply=False) == []
    assert _client("librechat")["redirectUris"] == ["https://chat.example.org/*"]


def test_the_kritis_profile_values_are_applied_by_the_sync(realm):
    api, _ = realm
    plan = _plan({rh.PROFILE_KEY: "kritis"})
    changes = rs.reconcile(api.call, plan, apply=True)
    assert [c.operation for c in changes] == ["update_realm"]
    settings = _admin("GET", "/papaia")
    assert settings["sslRequired"] == "all"
    assert settings["offlineSessionIdleTimeout"] == 7 * DAY
    assert settings["offlineSessionMaxLifespan"] == 30 * DAY
    assert settings["offlineSessionMaxLifespanEnabled"] is True
    assert rh.offline_limits(settings) == {"idle_days": 7, "max_age_days": 30}


# ─────────────────────────────────────────────────────────────────────────
# the template's accounts (PLT-21-A3)
# ─────────────────────────────────────────────────────────────────────────


def _sign_in(username: str, password: str, *, realm: str = "papaia", client_id="librechat"):
    """A browser sign-in at the login form: "signed-in" (redirected back with a code),
    "change-password" (the forced change of a temporary password) or "refused"."""
    opener = urllib.request.build_opener(_NoRedirect)
    query = {
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "response_type": "code",
        "code_challenge": _s256(),
        "code_challenge_method": "S256",
    }
    url = f"{URL}/realms/{realm}/protocol/openid-connect/auth?{urllib.parse.urlencode(query)}"
    with opener.open(url, timeout=10) as resp:
        page = resp.read().decode()
        # Keycloak marks its cookies Secure; the throwaway Keycloak speaks plain http on
        # the loopback address, so they are handed back by hand.
        cookies = "; ".join(c.split(";", 1)[0] for c in resp.headers.get_all("Set-Cookie") or [])
    match = re.search(r'<form[^>]*id="kc-form-login"[^>]*>', page)
    assert match, "no login form"
    action = re.search(r'action="([^"]+)"', match.group(0))
    form = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(html.unescape(action.group(1)), data=form)
    req.add_header("Cookie", cookies)
    try:
        with opener.open(req, timeout=10) as resp:
            page = resp.read().decode()
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location") or ""
        if exc.code != 302:
            raise
        if location.startswith(REDIRECT):
            assert "code=" in location
            return "signed-in"
        # Keycloak's own next step (a required action) on the same login session.
        assert location.startswith(URL), location
        more = "; ".join(c.split(";", 1)[0] for c in exc.headers.get_all("Set-Cookie") or [])
        req = urllib.request.Request(location)
        req.add_header("Cookie", "; ".join(filter(None, (cookies, more))))
        with opener.open(req, timeout=10) as resp:
            page = resp.read().decode()
    return "change-password" if 'name="password-new"' in page else "refused"


def _template_user(username: str, password: str) -> str:
    """An account as the 1.9.0 realm template created it: its password stored with it."""
    _admin(
        "POST",
        "/papaia/users",
        {
            "username": username,
            "email": f"{username}@papaia.lan",
            "firstName": "Template",
            "lastName": "Account",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    (user,) = _admin("GET", f"/papaia/users?username={username}&exact=true")
    return user["id"]


def test_the_template_accounts_of_an_old_installation_cannot_sign_in(realm):
    api, _ = realm
    rs.reconcile(api.call, _plan(), apply=True)
    ids = [_template_user("admin", "admin"), _template_user("testuser", "testuser")]
    try:
        assert _sign_in("admin", "admin") == "signed-in"  # the gap this closes
        generated = secrets.token_urlsafe(24)
        hardening = rh.load({rh.REALM_ADMIN_PASSWORD_KEY: generated})
        master = rs.AdminApi(URL, None, _master_token())
        drift = rs.sync_template_users(master.call, hardening, apply=False)
        assert {c.name for c in drift} == {"admin", "testuser"}
        rs.sync_template_users(master.call, hardening, apply=True)
        assert rs.sync_template_users(master.call, hardening, apply=False) == []
        assert _sign_in("admin", "admin") == "refused"
        assert _sign_in("testuser", "testuser") == "refused"
        assert _sign_in("admin", generated) == "change-password"
    finally:
        for uid in ids:
            _admin("DELETE", f"/papaia/users/{uid}")


def test_the_admin_of_a_new_installation_has_only_its_generated_forced_password(tmp_path):
    from tests.test_realm_hardening import _bake

    rendered = _bake(tmp_path, HOSTS, LIBRECHAT)  # KC_REALM_ADMIN_PASSWORD: not-a-real-secret
    roles = {r for u in rendered["users"] for r in u.get("realmRoles") or []}
    try:
        _admin("DELETE", "/papaia-a3")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin(
        "POST",
        "",
        {
            "realm": "papaia-a3",
            "enabled": True,
            "roles": {"realm": [{"name": r} for r in sorted(roles)]},
            "clients": [
                {
                    "clientId": "a3-probe",
                    "publicClient": True,
                    "standardFlowEnabled": True,
                    "redirectUris": [REDIRECT],
                }
            ],
            "users": rendered["users"],
        },
    )
    try:
        assert [u["username"] for u in _admin("GET", "/papaia-a3/users")] == ["admin"]
        for username, password in (("admin", "admin"), ("testuser", "testuser")):
            assert _sign_in(username, password, realm="papaia-a3", client_id="a3-probe") == (
                "refused"
            )
        assert (
            _sign_in("admin", "not-a-real-secret", realm="papaia-a3", client_id="a3-probe")
            == "change-password"
        )
    finally:
        _admin("DELETE", "/papaia-a3")
