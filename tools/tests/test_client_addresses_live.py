"""Sign-in addresses of add-on clients against a throwaway Keycloak of the pinned version.

Same throwaway Keycloak as tests/test_realm_sync_live.py (PAPAIA_TEST_KEYCLOAK_URL,
PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD); without both the tests are skipped. They replace the
realm `papaia` of that Keycloak, so never point them at an installation.

A sample add-on is installed in a temporary configuration directory with a
`client_addresses` declaration; its client signs a synthetic person in at the declared
callback without a manual step, a sign-in with any other `redirect_uri` is refused
(PLT-21-A2), and after the add-on is uninstalled the client and its addresses are gone.
"""

from __future__ import annotations

import html
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

import pytest

from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.test_client_addresses import ENGINE, HOSTS, _installed
from tests.test_realm_hardening_live import _authorize, _NoRedirect, _s256
from tests.test_realm_sync import REGISTER
from tests.test_realm_sync_live import (  # noqa: F401
    PASSWORD,
    URL,
    _admin,
    _client,
    pytestmark,
)

PERSON = "addresses-person"
HOST = "https://flow.papaia.example.org"
CALLBACK = f"{HOST}/engine/test-run/callback"


@pytest.fixture(scope="module")
def realm():
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    password = secrets.token_urlsafe(18)
    _admin(
        "POST",
        "/papaia/users",
        {
            "username": PERSON,
            "enabled": True,
            "email": f"{PERSON}@example.org",
            "emailVerified": True,
            "firstName": "Addresses",
            "lastName": "Person",
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    token = rs.sync_token(URL, None, PASSWORD, secrets.token_hex(24))
    return rs.AdminApi(URL, None, token), password


def _plan(config_dir, repo_root) -> rs.Plan:
    plan = rs.build_plan(REGISTER, rs.load_modules(config_dir, repo_root, HOSTS), [])
    plan.hardening = rh.with_declared(rh.load(HOSTS), plan.client_addresses)
    return plan


def _sign_in(client_id: str, redirect_uri: str, password: str) -> str:
    """A browser sign-in at the login form: the Location Keycloak sends the browser to
    afterwards, or "refused" when it shows no login form."""
    opener = urllib.request.build_opener(_NoRedirect)
    query = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "response_type": "code",
        "code_challenge": _s256(),
        "code_challenge_method": "S256",
    }
    url = f"{URL}/realms/papaia/protocol/openid-connect/auth?{urllib.parse.urlencode(query)}"
    try:
        with opener.open(url, timeout=10) as resp:
            page = resp.read().decode()
            cookies = "; ".join(
                c.split(";", 1)[0] for c in resp.headers.get_all("Set-Cookie") or []
            )
    except urllib.error.HTTPError:
        return "refused"
    match = re.search(r'<form[^>]*id="kc-form-login"[^>]*>', page)
    if not match:
        return "refused"
    action = re.search(r'action="([^"]+)"', match.group(0))
    form = urllib.parse.urlencode({"username": PERSON, "password": password}).encode()
    req = urllib.request.Request(html.unescape(action.group(1)), data=form)
    req.add_header("Cookie", cookies)
    try:
        with opener.open(req, timeout=10):
            return "no redirect"
    except urllib.error.HTTPError as exc:
        return exc.headers.get("Location") or f"http {exc.code}"


def test_the_installed_addon_signs_a_person_in_at_the_declared_callback(realm, tmp_path):
    api, password = realm
    config_dir, repo_root = _installed(tmp_path, [ENGINE])
    plan = _plan(config_dir, repo_root)
    assert rs.reconcile(api.call, plan, apply=True)
    assert rs.reconcile(api.call, plan, apply=True) == []
    assert rs.reconcile(api.call, plan, apply=False) == []

    engine = _client("flow-engine")
    assert engine["redirectUris"] == [CALLBACK]
    assert engine.get("webOrigins") in ([], None)
    assert not (engine.get("attributes") or {}).get(rh.POST_LOGOUT)

    location = _sign_in("flow-engine", CALLBACK, password)
    assert location.startswith(f"{CALLBACK}?"), location
    assert "code=" in location

    # PLT-21-A2: any other redirect_uri is refused before the login form.
    for other in (
        f"{HOST}/engine/test-run/callback/../admin",
        f"{HOST}/engine/test-run/callback?next=x",
        f"{HOST}/",
        "https://evil.example.org/engine/test-run/callback",
        "http://flow.papaia.example.org/engine/test-run/callback",
    ):
        status, _ = _authorize(
            "flow-engine", other, response_type="code", code_challenge=_s256(),
            code_challenge_method="S256",
        )
        assert status == 400, other
        assert _sign_in("flow-engine", other, password) == "refused", other


def test_after_the_uninstall_the_client_and_its_addresses_are_gone(realm, tmp_path):
    api, _ = realm
    config_dir, repo_root = _installed(tmp_path, [ENGINE])
    rs.reconcile(api.call, _plan(config_dir, repo_root), apply=True)
    assert _client("flow-engine")["redirectUris"] == [CALLBACK]

    # A disabled add-on: the client stays without an address.
    disabled, _ = _installed(tmp_path / "disabled", [ENGINE], active=False)
    plan = _plan(disabled, repo_root)
    rs.reconcile(api.call, plan, apply=True)
    engine = _client("flow-engine")
    assert engine["redirectUris"] == []
    assert not (engine.get("attributes") or {}).get(rh.DECLARED)

    # Uninstalled: the managed clients of the module are deleted with their addresses.
    plan.uninstalled = frozenset({"flow"})
    rs.reconcile(api.call, plan, apply=True)
    remaining = _admin("GET", "/papaia/clients")
    assert not any(c["clientId"].startswith("flow") for c in remaining)
    for client in remaining:
        for uri in (client.get("redirectUris") or []) + (client.get("webOrigins") or []):
            assert not uri.startswith(HOST), client["clientId"]
