"""Federation against a second Keycloak as the upstream provider (RS-F, OPS-16).

Start both with tests/fixtures/keycloak-federation/docker-compose.yml and point the tests
at them:

    export PAPAIA_TEST_FEDERATION_URL=http://127.0.0.1:60800
    export PAPAIA_TEST_FEDERATION_UPSTREAM_URL=http://127.0.0.1:60801
    export PAPAIA_TEST_FEDERATION_ADMIN_PASSWORD=<the bootstrap admin password of both>

Without all three the tests are skipped. They replace the realms `papaia` and `firma`
of those Keycloaks, so never point them at an installation.

The upstream realm stands in for the company directory (governance GV-32): its persons
exist only there, its client puts the immutable group ids into the `groups` claim (the
attribute `group_ids` stands in for the directory's membership claim, as Entra ID sends
object ids), and the status sync reads it with an account that holds `view-users` and
`query-groups` alone. papaia-lifecycle runs here in the test process against both.
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.cookiejar
import io
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

from lib import federation as fd
from lib import lifecycle_account as la
from lib import realm_sync as rs
from tests.test_lifecycle import lc

URL = os.environ.get("PAPAIA_TEST_FEDERATION_URL", "")
UPSTREAM = os.environ.get("PAPAIA_TEST_FEDERATION_UPSTREAM_URL", "")
PASSWORD = os.environ.get("PAPAIA_TEST_FEDERATION_ADMIN_PASSWORD", "")

pytestmark = pytest.mark.skipif(
    not (URL and UPSTREAM and PASSWORD),
    reason="no throwaway Keycloaks (PAPAIA_TEST_FEDERATION_URL, "
    "PAPAIA_TEST_FEDERATION_UPSTREAM_URL, PAPAIA_TEST_FEDERATION_ADMIN_PASSWORD)",
)

# The back channel inside the fixture's shared network (its docker-compose.yml).
UPSTREAM_INSIDE = "http://127.0.0.1:8080"
PAPAIA_INSIDE = "http://127.0.0.1:8081"
ISSUER = f"{UPSTREAM}/realms/firma"
APP = "test-app"
CALLBACK = "http://127.0.0.1:9/cb"
PERSON_PASSWORD = secrets.token_hex(16)
CONTACT = "IT-Service, Durchwahl 100"


def _token(base: str) -> str:
    form = urllib.parse.urlencode(
        {"grant_type": "password", "client_id": "admin-cli", "username": "admin",
         "password": PASSWORD}
    ).encode()
    req = urllib.request.Request(f"{base}/realms/master/protocol/openid-connect/token", data=form)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def _admin(base: str, method: str, path: str, body=None):
    req = urllib.request.Request(
        f"{base}/admin/realms{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {_token(base)}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def _papaia(method: str, path: str, body=None):
    return _admin(URL, method, f"/papaia{path}", body)


def _firma(method: str, path: str, body=None):
    return _admin(UPSTREAM, method, f"/firma{path}", body)


# ─────────────────────────────────────────────────────────────────────────
# a browser
# ─────────────────────────────────────────────────────────────────────────


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def sign_in(username: str, password: str = PERSON_PASSWORD) -> dict:
    """The authorisation code flow of `test-app` in the `papaia` realm, as a browser walks
    it: the sign-in page leads to the upstream provider, its form is filled in, the way
    back ends at the callback. Returns the tokens, or {"refused": <page text>}."""
    jar = http.cookiejar.CookieJar()
    jar._policy.return_ok_secure = lambda cookie, request: True  # plain http on loopback
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect)
    verifier = secrets.token_urlsafe(40)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    query = {
        "client_id": APP,
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "scope": "openid",
        "state": "s",
        "code_challenge": challenge.rstrip(b"=").decode(),
        "code_challenge_method": "S256",
    }
    url = f"{URL}/realms/papaia/protocol/openid-connect/auth?{urllib.parse.urlencode(query)}"
    data = None
    for _ in range(20):
        try:
            resp = opener.open(urllib.request.Request(url, data=data), timeout=15)
            location, body = None, resp.read().decode()
        except urllib.error.HTTPError as exc:
            location, body = exc.headers.get("Location"), exc.read().decode(errors="replace")
        if location and location.startswith(CALLBACK):
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]
            form = urllib.parse.urlencode(
                {"grant_type": "authorization_code", "client_id": APP, "code": code,
                 "redirect_uri": CALLBACK, "code_verifier": verifier}
            ).encode()
            with urllib.request.urlopen(
                f"{URL}/realms/papaia/protocol/openid-connect/token", data=form, timeout=10
            ) as answer:
                return json.loads(answer.read())
        if location:
            url, data = urllib.parse.urljoin(url, location), None
            continue
        form = re.search(r'<form[^>]*action="([^"]+)"', body)
        if form and 'name="password"' in body and data is None:
            url = html.unescape(form.group(1))
            data = urllib.parse.urlencode({"username": username, "password": password}).encode()
            continue
        text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body)))
        return {"refused": text}
    raise AssertionError("the sign-in did not end")


def _refresh(tokens: dict) -> int:
    form = urllib.parse.urlencode(
        {"grant_type": "refresh_token", "client_id": APP, "refresh_token": tokens["refresh_token"]}
    ).encode()
    try:
        with urllib.request.urlopen(
            f"{URL}/realms/papaia/protocol/openid-connect/token", data=form, timeout=10
        ):
            return 200
    except urllib.error.HTTPError as exc:
        return exc.code


def _claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


# ─────────────────────────────────────────────────────────────────────────
# realms
# ─────────────────────────────────────────────────────────────────────────


def _fresh(base: str, realm: str) -> None:
    try:
        _admin(base, "DELETE", f"/{realm}")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin(base, "POST", "", {"realm": realm, "enabled": True})


def _upstream_person(name: str, groups: list[str]) -> str:
    _firma(
        "POST",
        "/users",
        {
            "username": name,
            "enabled": True,
            "email": f"{name}@firma.example",
            "emailVerified": True,
            "firstName": name.title(),
            "lastName": "Test",
            "credentials": [{"type": "password", "value": PERSON_PASSWORD, "temporary": False}],
            "attributes": {"group_ids": groups},
        },
    )
    uid = _firma("GET", f"/users?username={name}&exact=true")[0]["id"]
    for gid in groups:
        _firma("PUT", f"/users/{uid}/groups/{gid}")
    return uid


def _attribute(uid: str, name: str, values: list[str] | None) -> None:
    user = _firma("GET", f"/users/{uid}")
    attributes = dict(user.get("attributes") or {})
    if values is None:
        attributes.pop(name, None)
    else:
        attributes[name] = values
    user["attributes"] = attributes
    _firma("PUT", f"/users/{uid}", user)


def _upstream(status_jwk: dict) -> dict:
    _fresh(UPSTREAM, "firma")
    profile = _firma("GET", "/users/profile")
    profile["unmanagedAttributePolicy"] = "ENABLED"
    _firma("PUT", "/users/profile", profile)
    for name in ("buchhaltung", "vertrieb"):
        _firma("POST", "/groups", {"name": name})
    groups = {g["name"]: g["id"] for g in _firma("GET", "/groups")}

    def attribute_mapper(name: str, attribute: str, claim: str, multivalued: bool) -> dict:
        return {
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": attribute,
                "claim.name": claim,
                "multivalued": str(multivalued).lower(),
                "id.token.claim": "true",
                "access.token.claim": "true",
                "jsonType.label": "String",
            },
        }

    _firma(
        "POST",
        "/clients",
        {
            "clientId": "papaia-broker",
            "publicClient": False,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-jwt",
            "redirectUris": [f"{URL}/realms/papaia/broker/{fd.ALIAS}/endpoint"],
            "attributes": {
                "use.jwks.url": "true",
                "jwks.url": f"{PAPAIA_INSIDE}/realms/papaia/protocol/openid-connect/certs",
                "token.endpoint.auth.signing.alg": "RS256",
            },
            "protocolMappers": [
                attribute_mapper("group ids", "group_ids", "groups", True),
                attribute_mapper("overage", "overage", "_claim_names.groups", False),
            ],
        },
    )
    _firma(
        "POST",
        "/clients",
        {
            "clientId": "papaia-status-sync",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-jwt",
            "attributes": {
                "use.jwks.string": "true",
                "use.jwks.url": "false",
                "jwks.string": json.dumps({"keys": [status_jwk]}),
                "token.endpoint.auth.signing.alg": "ES256",
            },
        },
    )
    client = _firma("GET", "/clients?clientId=papaia-status-sync")[0]
    account = _firma("GET", f"/clients/{client['id']}/service-account-user")["id"]
    management = _firma("GET", "/clients?clientId=realm-management")[0]["id"]
    rights = [_firma("GET", f"/clients/{management}/roles/{r}") for r in ("view-users",
                                                                           "query-groups")]
    _firma("POST", f"/users/{account}/role-mappings/clients/{management}", rights)
    return {"groups": groups, "status_account": account}


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    path.chmod(0o600)


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    config = tmp_path_factory.mktemp("config")
    config.chmod(0o700)
    _fresh(URL, "papaia")
    for name in ("buchhaltung", "vertrieb", "dateneinsicht"):
        _papaia("POST", "/groups", {"name": name})
    _papaia(
        "POST",
        "/clients",
        {"clientId": APP, "publicClient": True, "standardFlowEnabled": True,
         "directAccessGrantsEnabled": False, "redirectUris": [CALLBACK]},
    )
    keys = rs.keystore(config)
    la.align(lambda m, p, b=None: _papaia(m, p, b), keys, enabled=True, apply=True)
    # The provider's endpoints as a company would enter them: the issuer and the
    # authorisation endpoint for browsers, token and keys on the back channel.
    status_jwk = fd.status_keys(config).generate(fd.STATUS_ACCOUNT)
    upstream = _upstream(status_jwk)
    _write(
        config / fd.IDP_FILE,
        {
            "format": fd.IDP_FORMAT,
            "issuer": ISSUER,
            "authorization_url": f"{ISSUER}/protocol/openid-connect/auth",
            "token_url": f"{UPSTREAM_INSIDE}/realms/firma/protocol/openid-connect/token",
            "jwks_url": f"{UPSTREAM_INSIDE}/realms/firma/protocol/openid-connect/certs",
            "client_id": "papaia-broker",
            "client_assertion_audience": ISSUER,
            "acr_values": ["1", "2"],
            "contact": CONTACT,
            "status_sync": {"kind": "keycloak", "url": UPSTREAM, "realm": "firma",
                            "client_id": "papaia-status-sync"},
        },
    )
    _write(
        config / fd.MAP_FILE,
        {
            "format": fd.MAP_FORMAT,
            "groups": [
                {"upstream_id": upstream["groups"]["buchhaltung"], "group": "buchhaltung"},
                {"upstream_id": upstream["groups"]["vertrieb"], "group": "vertrieb"},
            ],
        },
    )
    fed = fd.load(config)
    first = fd.align(lambda m, p, b=None: _papaia(m, p, b), fed, apply=True)
    assert fd.render(config) == status_jwk
    return {"config": config, "keys": keys, "fed": fed, "first": first, **upstream}


@pytest.fixture
def service(setup, tmp_path):
    key_dir, state_dir = tmp_path / "key", tmp_path / "state"
    key_dir.mkdir(mode=0o700)
    state_dir.mkdir()
    target = tmp_path / "erasure-journal"
    target.mkdir()
    journal = lc.ErasureJournal(
        "identity", key=os.urandom(32), target_dir=target, local_dir=key_dir / "erasure-journal"
    )
    out = io.StringIO()
    folder = fd.status_keys(setup["config"]).folder(fd.STATUS_ACCOUNT)
    svc = lc.Lifecycle(
        lc.AccountClient(URL, None, setup["keys"].folder(la.CLIENT_ID)),
        lc.Store(key_dir),
        lc.Publisher(state_dir, lc.Signer(key_dir)),
        out=out,
        journal=journal,
        federation=lc.StatusSync(lc.UpstreamDirectory(folder, None)),
    )
    svc.start()
    svc.state_dir, svc.key_dir, svc.out = state_dir, key_dir, out
    return svc


def _local(name: str) -> dict:
    return _papaia("GET", f"/users?username={name}&exact=true")[0]


def _groups(uid: str) -> set[str]:
    return {g["name"] for g in _papaia("GET", f"/users/{uid}/groups")}


def _rows(service, event: str) -> list[dict]:
    rows = [json.loads(line) for line in service.out.getvalue().splitlines()]
    return [r for r in rows if r["event"] == event]


def _listed(service) -> dict[str, str]:
    doc = json.loads((service.state_dir / lc.LIST_FILE).read_bytes())
    return {e["sub"]: e["reason"] for e in doc["entries"]}


# ─────────────────────────────────────────────────────────────────────────
# tests
# ─────────────────────────────────────────────────────────────────────────


def test_the_realm_is_set_up_and_a_second_run_changes_nothing(setup):
    assert setup["first"]
    call = lambda m, p, b=None: _papaia(m, p, b)  # noqa: E731
    assert fd.align(call, setup["fed"], apply=False) == []
    provider = _papaia("GET", f"/identity-provider/instances/{fd.ALIAS}")
    assert provider["trustEmail"] is False
    assert provider["firstBrokerLoginFlowAlias"] == fd.FIRST_FLOW
    assert provider["postBrokerLoginFlowAlias"] == fd.CHECK_FLOW
    assert provider["config"]["clientAuthMethod"] == "private_key_jwt"
    assert provider["config"]["syncMode"] == "FORCE"
    assert "clientSecret" not in provider["config"]


def test_a_person_of_the_directory_signs_in_without_a_local_password(setup):
    """PLT-58-A1, GV-32 F1: the account appears at the first sign-in, mapped by group id;
    `sub` is the same at the second sign-in; no password is stored here."""
    _upstream_person("anna", [setup["groups"]["buchhaltung"]])
    first = sign_in("anna")
    assert "access_token" in first, first
    anna = _local("anna")
    assert _groups(anna["id"]) >= {"buchhaltung"}
    assert "vertrieb" not in _groups(anna["id"])
    assert _papaia("GET", f"/users/{anna['id']}/credentials") == []
    second = sign_in("anna")
    assert _claims(second["access_token"])["sub"] == _claims(first["access_token"])["sub"]


def test_the_status_sync_account_holds_exactly_two_read_rights(setup):
    """GV-32 F8: view-users and query-groups, nothing else."""
    mappings = _firma("GET", f"/users/{setup['status_account']}/role-mappings")
    rights = {
        name: {r["name"] for r in entry["mappings"]}
        for name, entry in (mappings.get("clientMappings") or {}).items()
    }
    assert rights == {"realm-management": {"view-users", "query-groups"}}


def test_a_renamed_group_stays_mapped_and_ends_no_session(setup, service):
    """The mapping binds to the immutable id: a rename upstream changes nothing."""
    gid = setup["groups"]["vertrieb"]
    cem = _upstream_person("cem", [gid])
    tokens = sign_in("cem")
    service.step(force_poll=True)
    group = _firma("GET", f"/groups/{gid}")
    group["name"] = "vertrieb-sued"
    _firma("PUT", f"/groups/{gid}", group)
    service.federation._next = 0
    service.step(force_poll=True)
    assert _refresh(tokens) == 200
    again = sign_in("cem")
    assert "access_token" in again, again
    assert "vertrieb" in _groups(_local("cem")["id"])
    assert cem


def test_a_person_locked_upstream_loses_access_within_300_seconds(setup, service):
    """PLT-58-A4, GV-32 F3: one status sync round after the lock, the account here is
    disabled, listed, its sessions and consents are gone; enabled upstream again, it
    is enabled here and no old session comes back."""
    ben = _upstream_person("ben", [setup["groups"]["buchhaltung"]])
    tokens = sign_in("ben")
    local = _local("ben")["id"]
    service.step(force_poll=True)
    started = time.monotonic()
    user = _firma("GET", f"/users/{ben}")
    user["enabled"] = False
    _firma("PUT", f"/users/{ben}", user)
    service.federation._next = 0
    service.step(force_poll=True)
    assert time.monotonic() - started < 300
    assert _refresh(tokens) == 400
    assert _papaia("GET", f"/users/{local}")["enabled"] is False
    # Listed by the status sync, then again by the event of its own deactivation.
    assert _listed(service)[local] in ("upstream_disabled", "account_disabled")
    assert "refused" in sign_in("ben")
    user["enabled"] = True
    _firma("PUT", f"/users/{ben}", user)
    service.federation._next = 0
    service.step(force_poll=True)
    assert _papaia("GET", f"/users/{local}")["enabled"] is True
    assert _refresh(tokens) == 400
    assert "access_token" in sign_in("ben")


def test_sessions_revoked_upstream_end_here_without_a_lock(setup, service):
    """GV-32 F11: a newer "sessions valid from" upstream ends sessions here."""
    carla = _upstream_person("carla", [setup["groups"]["buchhaltung"]])
    tokens = sign_in("carla")
    service.step(force_poll=True)
    time.sleep(1.1)  # notBefore counts in seconds
    _firma("POST", f"/users/{carla}/logout")
    service.federation._next = 0
    service.step(force_poll=True)
    assert _refresh(tokens) == 400
    local = _local("carla")["id"]
    assert _papaia("GET", f"/users/{local}")["enabled"] is True
    assert _listed(service)[local] == "upstream_sessions_revoked"
    assert "access_token" in sign_in("carla")


def test_a_group_removed_upstream_ends_the_sessions_and_is_gone_at_the_next_sign_in(
    setup, service
):
    """PLT-58-A2, GV-32 F2: no assignment per person; the removal reaches the realm."""
    gid = setup["groups"]["buchhaltung"]
    emil = _upstream_person("emil", [gid])
    tokens = sign_in("emil")
    local = _local("emil")["id"]
    assert "buchhaltung" in _groups(local)
    service.step(force_poll=True)
    _firma("DELETE", f"/users/{emil}/groups/{gid}")
    _attribute(emil, "group_ids", [setup["groups"]["vertrieb"]])
    service.federation._next = 0
    service.step(force_poll=True)
    assert _refresh(tokens) == 400
    assert "access_token" in sign_in("emil")
    assert "buchhaltung" not in _groups(local)
    assert "vertrieb" in _groups(local)


def test_an_overage_reference_or_a_missing_groups_claim_refuses_the_sign_in(setup, service):
    """GV-33, GV-32 F4: refused with the fixed text, `idp_group_overflow` in the audit."""
    dora = _upstream_person("dora", [setup["groups"]["buchhaltung"]])
    _attribute(dora, "overage", ["src1"])
    refused = sign_in("dora")
    assert "access_token" not in refused
    assert fd.OVERFLOW_TEXT.format(contact=CONTACT) in refused["refused"]
    service.step(force_poll=True)
    rows = _rows(service, "idp_group_overflow")
    assert [r["object_ref"]["id"] for r in rows] == [_local("dora")["id"]]
    _attribute(dora, "overage", None)
    _attribute(dora, "group_ids", None)
    assert "access_token" not in sign_in("dora")
    _attribute(dora, "group_ids", [setup["groups"]["buchhaltung"]])
    assert "access_token" in sign_in("dora")


def test_a_sign_in_below_the_accepted_strength_is_refused(setup):
    """GV-32 F5: an `acr` outside the accepted values is refused."""
    _upstream_person("fatma", [setup["groups"]["buchhaltung"]])
    strict = fd.Federation(**{**setup["fed"].__dict__, "acr_values": ("mfa",)})
    call = lambda m, p, b=None: _papaia(m, p, b)  # noqa: E731
    fd.align(call, strict, apply=True)
    try:
        refused = sign_in("fatma")
    finally:
        fd.align(call, setup["fed"], apply=True)
    assert "access_token" not in refused
    assert "Anmeldestärke" in refused["refused"]
    assert "access_token" in sign_in("fatma")


def test_a_failing_status_sync_is_reported_after_300_seconds(setup, service):
    """GV-32 F7: the directory refuses the account; after 300 s one
    `status_sync_failed` row and health `fail`."""
    directory = service.federation.directory
    directory.client_id, directory._token = "no-such-client", None
    service.federation._next = 0
    service.step(force_poll=True)
    now = time.time()
    clock = service.federation.clock
    service.federation.clock = lambda: now + 301
    try:
        service.federation._next = 0
        service.federation.run()
    finally:
        service.federation.clock = clock
    assert len(_rows(service, "status_sync_failed")) == 1
    code, report = lc.health(service.state_dir, service.key_dir, now=now + 301)
    assert code == 1 and report["status"] == "fail"
    assert report["status_sync_failing_seconds"] > 300
