"""Declarative service accounts: `service_accounts[]` of the installed modules.

The realm sync creates one client `svc-<module>-<purpose>` per declared account with a
service account and nothing else: no sign-in flow, no token exchange, `private_key_jwt`
with a key pair the core keeps in the configuration directory, only the declared
audiences as optional `aud-*` scopes and only the declared roles. Undeclared service
accounts are reported by `--check` and removed by the sync. `papaia-ctl service-account
rotate` replaces the key pair; the old key is refused within 60 seconds.

The sync runs against an in-memory Admin API (tests/realm_fake.py); the same flows run
against a real Keycloak in tests/test_service_accounts_live.py.
"""

from __future__ import annotations

import base64
import json
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from lib import realm_sync as rs
from lib import service_account_keys as sak
from lib import service_accounts as sa
from tests.realm_fake import FakeRealm
from tests.test_ctl_standalone_commands import BASH, CTL, _call, _seeded, needs_bash

REGISTER = rs.load_register()


def _account(**changes) -> dict:
    account = {
        "id": "svc-flow-events",
        "purpose": {"de": "Rechnungseingang", "en": "Incoming invoices"},
        "owner_sub": "dora",
        "deputy_sub": "anna",
        "roles": [],
        "audiences": ["mcp-paperless"],
        "effects": ["read"],
        "realm_management_roles": [],
        "credential": "private_key_jwt",
    }
    account.update(changes)
    return {k: v for k, v in account.items() if v is not None}


def _flow(*accounts: dict) -> rs.Module:
    entry = {
        "id": "flow.runs",
        "kind": "rest",
        "audience": "flow",
        "identity": ["person"],
        "roles": [{"name": "flow-member"}, {"name": "flow-admin"}],
        "service_accounts": list(accounts) or [_account()],
    }
    return rs.Module("papaia-flow", [entry], {})


def _paperless(identity=("person", "service")) -> rs.Module:
    entry = {"id": "paperless.mcp", "kind": "mcp", "audience": "mcp-paperless"}
    if identity is not None:
        entry["identity"] = list(identity)
    return rs.Module("paperless", [entry], {})


def _qdrant() -> rs.Module:
    entry = {
        "id": "qdrant.mcp",
        "kind": "mcp",
        "audience": "mcp-qdrant",
        "identity": ["person", "service"],
    }
    return rs.Module("qdrant", [entry], {})


def _me() -> rs.Module:
    entry = {
        "id": "me.prefs",
        "kind": "rest",
        "audience": "papaia-prefs",
        "identity": ["service"],
        "roles": [{"name": "prefs-read"}],
    }
    return rs.Module("papaia-me", [entry], {})


def _plan(*modules: rs.Module) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), [])


def _keys(tmp_path) -> sak.KeyStore:
    return rs.keystore(tmp_path / "config")


def _run(realm: FakeRealm, plan: rs.Plan, keys, *, apply=True, audit=None) -> list[rs.Change]:
    return rs.reconcile(realm.call, plan, apply=apply, audit=audit, keys=keys, master=realm.call)


def _b64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _verify(assertion: str, jwk: dict) -> bool:
    """ES256 check of a JWT with openssl: the public key from the JWK's point, the raw
    r||s signature turned into DER."""
    head, body, sig = assertion.split(".")
    spki = bytes.fromhex(sak.P256_SPKI_PREFIX) + _b64(jwk["x"]) + _b64(jwk["y"])
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + base64.encodebytes(spki).decode()
        + "-----END PUBLIC KEY-----\n"
    )

    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        return bytes([2, len(value)]) + value

    raw = _b64(sig)
    seq = integer(raw[:32]) + integer(raw[32:])
    der = bytes([0x30, len(seq)]) + seq
    with tempfile.TemporaryDirectory() as folder:
        key, signature = Path(folder) / "pub.pem", Path(folder) / "sig.der"
        key.write_text(pem)
        signature.write_bytes(der)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature)],
            input=f"{head}.{body}".encode(),
            capture_output=True,
            check=False,
        )
    return result.returncode == 0


def _service_clients(realm: FakeRealm) -> set[str]:
    return {c["clientId"] for c in realm.clients.values() if c.get("serviceAccountsEnabled")}


def _user_roles(realm: FakeRealm, client_id: str) -> tuple[set, dict]:
    user = realm.service_account_user(client_id)
    return set(user["_realm"]), {k: v for k, v in user["_clients"].items() if v}


def _jwks(realm: FakeRealm, client_id: str) -> list[dict]:
    return json.loads(realm.by_client_id(client_id)["attributes"]["jwks.string"])["keys"]


# ─────────────────────────────────────────────────────────────────────────
# declaration
# ─────────────────────────────────────────────────────────────────────────


def test_a_declared_account_is_planned_with_only_its_declared_rights():
    plan = _plan(_flow(_account(roles=["prefs-read"], audiences=["mcp-paperless"])), _paperless())
    spec = plan.clients["svc-flow-events"]
    assert spec.kind == "service-account"
    assert spec.owner == "papaia-flow"
    assert spec.token_exchange is False
    assert spec.optional_scopes == {"aud-mcp-paperless"}
    assert spec.default_scopes == {"basic", "roles", "service_account"}
    assert spec.role_scope == {"prefs-read"}
    assert plan.exchange_scopes == {"aud-mcp-paperless": "mcp-paperless"}
    rep = spec.representation()
    assert rep["serviceAccountsEnabled"] is True
    assert rep["standardFlowEnabled"] is False
    assert rep["directAccessGrantsEnabled"] is False
    assert rep["implicitFlowEnabled"] is False
    assert rep["publicClient"] is False
    assert rep["bearerOnly"] is False
    assert rep["fullScopeAllowed"] is False
    assert rep["clientAuthenticatorType"] == "client-jwt"
    attributes = rep["attributes"]
    assert attributes["papaia.kind"] == "service-account"
    assert attributes["standard.token.exchange.enabled"] == "false"
    assert attributes["papaia.owner_sub"] == "dora"
    assert attributes["papaia.deputy_sub"] == "anna"
    assert attributes["papaia.rotation_days"] == str(rs.ROTATION_DAYS)
    assert attributes["papaia.effects"] == "read"
    assert attributes["use.jwks.string"] == "true"
    assert attributes["use.jwks.url"] == "false"
    assert attributes["token.endpoint.auth.signing.alg"] == "ES256"
    assert "oauth2.device.authorization.grant.enabled" not in attributes


def test_an_audience_that_is_not_installed_assigns_nothing_and_is_noted():
    plan = _plan(_flow())
    assert plan.clients["svc-flow-events"].optional_scopes == set()
    assert plan.exchange_scopes == {}
    assert any("svc-flow-events" in n and "mcp-paperless" in n for n in plan.notes)


def test_owner_placeholders_are_resolved_from_the_install_input():
    module = _flow(_account(owner_sub="${FLOW_OWNER}", deputy_sub="${FLOW_DEPUTY}"))
    module.install_input.update({"FLOW_OWNER": "dora", "FLOW_DEPUTY": "anna"})
    attributes = _plan(module).clients["svc-flow-events"].representation()["attributes"]
    assert (attributes["papaia.owner_sub"], attributes["papaia.deputy_sub"]) == ("dora", "anna")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"credential": "client_secret"}, "private_key_jwt"),
        ({"credential": None}, "missing field credential"),
        ({"purpose": None}, "missing field purpose"),
        ({"audiences": None}, "missing field audiences"),
        ({"effects": None}, "missing field effects"),
        ({"owner_sub": None}, "owner_sub"),
        ({"secret": "x"}, "unknown field secret"),
        ({"effects": []}, "effects"),
        ({"effects": ["read", "read"]}, "effects"),
        ({"effects": ["r"]}, "effects"),
        ({"purpose": "Incoming invoices"}, "purpose"),
        ({"purpose": {}}, "purpose"),
        ({"purpose": {"fr": "Factures"}}, "purpose"),
        ({"purpose": {"en": "x" * 81}}, "purpose"),
        ({"purpose": {"en": "see https://example.org"}}, "purpose"),
        ({"purpose": {"en": "<b>bold</b>"}}, "purpose"),
        ({"purpose": {"en": "line\nbreak"}}, "purpose"),
        ({"roles": "prefs-read"}, "roles"),
        ({"roles": ["prefs-read", "prefs-read"]}, "roles"),
        ({"roles": ["no-such-role"]}, "not a registered role"),
        ({"roles": ["papaia-admin"]}, "papaia-admin"),
        ({"roles": ["papaia-confirm"]}, "papaia-confirm"),
        ({"roles": ["flow-admin"]}, "flow-admin"),
        ({"audiences": ["mcp-nowhere"]}, "not a registered audience"),
        ({"audiences": ["mcp-paperless", "mcp-paperless"]}, "audiences"),
        ({"audiences": ["flow-engine"]}, "audience"),
        ({"audiences": ["mcp-paperless"] * 13}, "audiences"),
        ({"realm_management_roles": ["view-users"]}, "realm-management"),
        ({"id": "svc-flow-prefs"}, "svc-flow-notify"),
        ({"id": "svc-studio-notify"}, "belongs to papaia-studio"),
        ({"id": "flow-directory"}, "svc-<module>-<purpose>"),
    ],
)
def test_a_malformed_account_declaration_is_refused(changes, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan(_flow(_account(**changes)), _paperless())


def test_an_account_declared_twice_is_refused():
    with pytest.raises(rs.RealmSyncError, match="declared twice"):
        _plan(_flow(_account(), _account()), _paperless())


def test_an_account_for_an_audience_that_accepts_persons_only_is_refused():
    with pytest.raises(rs.RealmSyncError, match="persons only"):
        _plan(_flow(_account()), _paperless(identity=("person",)))
    with pytest.raises(rs.RealmSyncError, match="persons only"):
        _plan(_flow(_account()), _paperless(identity=None))


def test_a_refused_account_changes_nothing_in_the_realm(tmp_path):
    realm = FakeRealm()
    with pytest.raises(rs.RealmSyncError):
        _run(realm, _plan(_flow(_account(credential="client_secret"))), _keys(tmp_path))
    assert realm.writes == []
    assert not (tmp_path / "config").exists()


# ─────────────────────────────────────────────────────────────────────────
# reconcile
# ─────────────────────────────────────────────────────────────────────────


def _full_plan() -> rs.Plan:
    return _plan(
        _flow(
            _account(),
            _account(
                id="svc-flow-notify",
                purpose={"en": "Notification preferences"},
                roles=["prefs-read"],
                audiences=["papaia-prefs"],
            ),
        ),
        _paperless(),
        _qdrant(),
        _me(),
    )


def test_the_first_run_creates_each_account_with_only_its_declared_rights(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    assert _run(realm, _full_plan(), keys)
    events = realm.by_client_id("svc-flow-events")
    assert events["serviceAccountsEnabled"] is True
    assert events["standardFlowEnabled"] is False
    assert events["directAccessGrantsEnabled"] is False
    assert events["clientAuthenticatorType"] == "client-jwt"
    assert events["attributes"]["standard.token.exchange.enabled"] == "false"
    assert realm.scope_names("svc-flow-events", "optional") == {"aud-mcp-paperless"}
    assert realm.scope_names("svc-flow-events", "default") == {"basic", "roles", "service_account"}
    assert events["_role_scope"] == set()
    assert _user_roles(realm, "svc-flow-events") == ({"default-roles-papaia"}, {})
    notify = realm.by_client_id("svc-flow-notify")
    assert realm.scope_names("svc-flow-notify", "optional") == {"aud-papaia-prefs"}
    assert notify["_role_scope"] == {"prefs-read"}
    assert _user_roles(realm, "svc-flow-notify") == ({"default-roles-papaia", "prefs-read"}, {})
    # the qdrant audience is installed, but no account declares it
    assert "aud-mcp-qdrant" not in {s["name"] for s in realm.scopes.values()}
    assert _service_clients(realm) == {"svc-flow-events", "svc-flow-notify"}


def test_the_second_run_reports_no_change(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    assert _run(realm, _full_plan(), keys) == []
    assert _run(realm, _full_plan(), keys, apply=False) == []


def test_each_account_signs_in_with_its_own_key_pair_from_the_config_dir(tmp_path, capsys):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    folder = tmp_path / "config" / "security" / "service-accounts"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    for account in ("svc-flow-events", "svc-flow-notify"):
        key = keys.key_path(account)
        assert key.parent == folder / account
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
        (jwk,) = _jwks(realm, account)
        assert jwk == keys.public_jwk(account)
        assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["alg"] == "ES256"
        assert "d" not in jwk
    a, b = (keys.public_jwk(n)["kid"] for n in ("svc-flow-events", "svc-flow-notify"))
    assert a != b
    out = capsys.readouterr()
    assert "PRIVATE KEY" not in out.out + out.err


def test_a_lost_key_file_is_reported_and_replaced(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    old = keys.public_jwk("svc-flow-events")
    keys.key_path("svc-flow-events").unlink()
    drift = _run(realm, _full_plan(), keys, apply=False)
    assert [(c.name, c.event) for c in drift] == [("svc-flow-events", "service_account_rotated")]
    _run(realm, _full_plan(), keys)
    assert _jwks(realm, "svc-flow-events") == [keys.public_jwk("svc-flow-events")] != [old]


def test_an_extra_registered_key_is_reported_and_removed(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    client = realm.by_client_id("svc-flow-events")
    stranger = dict(keys.public_jwk("svc-flow-notify"))
    client["attributes"]["jwks.string"] = json.dumps(
        {"keys": [keys.public_jwk("svc-flow-events"), stranger]}
    )
    drift = _run(realm, _full_plan(), keys, apply=False)
    assert {(c.name, c.operation) for c in drift} == {("svc-flow-events", "set_key")}
    _run(realm, _full_plan(), keys)
    assert _jwks(realm, "svc-flow-events") == [keys.public_jwk("svc-flow-events")]


def test_drift_of_an_account_is_reported_and_repaired(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    plan = _full_plan()
    _run(realm, plan, keys)
    client = realm.by_client_id("svc-flow-events")
    client["standardFlowEnabled"] = True
    client["clientAuthenticatorType"] = "client-secret"
    client["attributes"]["standard.token.exchange.enabled"] = "true"
    client["attributes"]["papaia.owner_sub"] = "mallory"
    client["_optional"].append(realm._scope_id("aud-papaia-prefs"))
    client["_role_scope"].add("flow-member")
    user = realm.service_account_user("svc-flow-events")
    user["_realm"].add("flow-member")
    rm = realm.by_client_id("realm-management")
    user["_clients"][rm["id"]] = {"view-users"}
    user["_groups"].add(realm.add_group("helpers"))
    writes = len(realm.writes)

    drift = _run(realm, plan, keys, apply=False)
    assert len(realm.writes) == writes
    text = "\n".join(c.action for c in drift if c.name == "svc-flow-events")
    for needle in (
        "standardFlowEnabled",
        "clientAuthenticatorType",
        "standard.token.exchange.enabled",
        "papaia.owner_sub",
        "aud-papaia-prefs",
        "flow-member",
        "view-users",
        "helpers",
    ):
        assert needle in text

    _run(realm, plan, keys)
    assert _run(realm, plan, keys, apply=False) == []
    client = realm.by_client_id("svc-flow-events")
    assert client["standardFlowEnabled"] is False
    assert client["clientAuthenticatorType"] == "client-jwt"
    assert client["attributes"]["papaia.owner_sub"] == "dora"
    assert realm.scope_names("svc-flow-events", "optional") == {"aud-mcp-paperless"}
    assert client["_role_scope"] == set()
    assert _user_roles(realm, "svc-flow-events") == ({"default-roles-papaia"}, {})
    assert realm.service_account_user("svc-flow-events")["_groups"] == set()


def test_an_undeclared_managed_account_is_reported_first_then_removed(tmp_path, capsys):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    folder = keys.key_path("svc-flow-notify").parent
    plan = _plan(_flow(_account()), _paperless(), _me())

    drift = _run(realm, plan, keys, apply=False)
    removal = {(c.kind, c.effect) for c in drift if c.name == "svc-flow-notify"}
    assert removal == {("service-account", "delete")}
    assert "fail: service-account svc-flow-notify" in capsys.readouterr().out
    assert "svc-flow-notify" in _service_clients(realm)
    assert folder.exists()

    _run(realm, plan, keys)
    assert _service_clients(realm) == {"svc-flow-events"}
    assert not folder.exists()
    assert _run(realm, plan, keys) == []


def test_the_accounts_of_a_removed_module_are_removed(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    _run(realm, _plan(_paperless(), _me()), keys)
    assert _service_clients(realm) == set()


def test_an_unmanaged_client_with_a_service_account_loses_it(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    realm.call(
        "POST",
        "/clients",
        {"clientId": "hand-made", "publicClient": False, "serviceAccountsEnabled": True},
    )
    drift = _run(realm, _full_plan(), keys, apply=False)
    assert ("client", "hand-made") in {(c.kind, c.name) for c in drift}
    _run(realm, _full_plan(), keys)
    assert realm.by_client_id("hand-made")["serviceAccountsEnabled"] is False
    assert _service_clients(realm) == {"svc-flow-events", "svc-flow-notify"}


def test_a_registered_legacy_account_of_a_modules_own_setup_is_named_not_changed(tmp_path, capsys):
    # flow-directory is registered, but outside svc-<module>-<purpose>: Flow's own setup
    # creates it and service_accounts[] cannot declare it yet.
    realm, keys = FakeRealm(), _keys(tmp_path)
    realm.call(
        "POST",
        "/clients",
        {
            "clientId": "flow-directory",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "optionalClientScopes": [],
        },
    )
    # Only the realm hardening, which applies to every client that can obtain a token,
    # touches it; the service-account sync leaves it alone.
    found = _run(realm, _full_plan(), keys, apply=False)
    assert {c.operation for c in found if c.name == "flow-directory"} <= {"harden_client"}
    _run(realm, _full_plan(), keys)
    assert realm.by_client_id("flow-directory")["serviceAccountsEnabled"] is True
    assert not realm.by_client_id("flow-directory").get("directAccessGrantsEnabled")
    assert "service account flow-directory is created by its module" in capsys.readouterr().out


def test_the_sync_account_keeps_its_service_account(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    rs.align_sync_account(realm.call, "not-a-real-secret", apply=True)
    _run(realm, _full_plan(), keys)
    assert rs.SYNC_CLIENT in _service_clients(realm)


def test_no_account_holds_a_role_beyond_its_declaration_through_a_composite(tmp_path, capsys):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    realm.add_client_composite("prefs-read", "realm-management", "view-users")
    _run(realm, _full_plan(), keys)
    assert realm.by_client_id("svc-flow-notify")["_role_scope"] == set()
    assert _user_roles(realm, "svc-flow-notify") == ({"default-roles-papaia"}, {})
    assert "view-users" in capsys.readouterr().out


def test_sign_ins_of_service_accounts_are_recorded_as_events(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    config = realm.events_config
    assert config["eventsEnabled"] is True
    assert config["enabledEventTypes"] == ["CLIENT_LOGIN"]
    assert config["eventsExpiration"] == rs.EVENTS_EXPIRATION
    assert config["eventsListeners"] == ["jboss-logging"]


def test_event_types_an_operator_chose_are_kept(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    realm.events_config.update(
        eventsEnabled=True, enabledEventTypes=["LOGIN_ERROR"], eventsExpiration=3600
    )
    _run(realm, _full_plan(), keys)
    assert realm.events_config["enabledEventTypes"] == ["CLIENT_LOGIN", "LOGIN_ERROR"]
    assert realm.events_config["eventsExpiration"] == 3600
    realm.events_config["enabledEventTypes"] = []  # every type is stored
    assert _run(realm, _full_plan(), keys) == []


def test_without_declared_accounts_the_event_settings_are_left_alone(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _plan(_paperless()), keys)
    assert realm.events_config["eventsEnabled"] is False


def test_every_account_write_leaves_one_audit_row(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    outbox = tmp_path / "audit.jsonl"
    with rs.AuditLog(outbox, "run-1") as audit:
        _run(realm, _full_plan(), keys, audit=audit)
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    assert len(rows) == len(realm.writes)
    keyed = [r for r in rows if r["event"] == "service_account_rotated"]
    assert {r["object_ref"]["id"] for r in keyed} == {"svc-flow-events", "svc-flow-notify"}
    created = [r for r in rows if r["operation"] == "realm_sync.create_client"]
    assert {"svc-flow-events", "svc-flow-notify"} <= {r["object_ref"]["id"] for r in created}
    # the service-account users' role mappings are written by the master admin
    granted = [r for r in rows if r["operation"] == "realm_sync.grant_service_account_role"]
    assert granted and all(r["azp"] == "admin-cli" for r in granted)
    assert all(r["identity_kind"] is None for r in granted)
    text = outbox.read_text()
    assert "PRIVATE" not in text and '"d"' not in text


# ─────────────────────────────────────────────────────────────────────────
# the command: realm sync with service accounts
# ─────────────────────────────────────────────────────────────────────────


def _tree(secret: str = "not-a-real-secret") -> dict:
    return {
        "": {"AUTH_PROVIDER": "internal_keycloak"},
        "infra/keycloak": {"KC_ADMIN_PASSWORD": "admin-pw", rs.SYNC_SECRET_KEY: secret},
    }


@pytest.fixture
def connected(monkeypatch):
    realm = FakeRealm()

    def sign_in(base_url, ctx, secret):
        client = next((c for c in realm.clients.values() if c["clientId"] == rs.SYNC_CLIENT), None)
        if client is None or client.get("secret") != secret:
            raise rs.urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        return "sync-token"

    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: None)
    monkeypatch.setattr(rs.kcs, "_get_admin_token", lambda *a: "master-token")
    monkeypatch.setattr(rs.kcs, "_admin_connection", lambda *a: ("http://kc.invalid", None))
    monkeypatch.setattr(rs, "_client_credentials", sign_in)
    monkeypatch.setattr(rs.AdminApi, "call", lambda self, *a: realm.call(*a))
    return realm


def _config(tmp_path, *addons: tuple[str, dict]):
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    config_dir.mkdir()
    entries = []
    for name, manifest in addons:
        path = repo_root / name
        path.mkdir(parents=True)
        (path / "papaia-app.yaml").write_text(yaml.safe_dump(dict(manifest, name=name)))
        entries.append({"name": name, "path": str(path), "active": True})
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries}))
    return config_dir, repo_root


def _addons() -> list[tuple[str, dict]]:
    return [
        ("papaia-flow", {"exposes": _flow().exposes}),
        ("paperless", {"exposes": _paperless().exposes}),
    ]


def test_sync_creates_the_accounts_and_check_then_reports_ok(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path, *_addons())
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert "svc-flow-events" in _service_clients(connected)
    key = config_dir / "security" / "service-accounts" / "svc-flow-events" / "private-key.pem"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    _, user_clients = _user_roles(connected, "svc-flow-events")
    assert user_clients == {}
    capsys.readouterr()
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0
    assert "Realm check: ok (0 deviation(s))" in capsys.readouterr().out


def test_check_writes_no_key_file(tmp_path, connected):
    config_dir, repo_root = _config(tmp_path, *_addons())
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 1
    assert not (config_dir / "security" / "service-accounts").exists()
    assert "svc-flow-events" not in _service_clients(connected)


# ─────────────────────────────────────────────────────────────────────────
# keys
# ─────────────────────────────────────────────────────────────────────────


def test_a_public_jwk_is_the_p256_point_of_the_key_with_its_thumbprint(tmp_path):
    keys = sak.KeyStore(tmp_path / "keys")
    jwk = keys.generate("svc-flow-events")
    assert set(jwk) == {"kty", "crv", "x", "y", "kid", "use", "alg"}
    for coordinate in ("x", "y"):
        assert len(base64.urlsafe_b64decode(jwk[coordinate] + "=")) == 32
    thumbprint = sak.thumbprint({k: jwk[k] for k in ("crv", "kty", "x", "y")})
    assert jwk["kid"] == thumbprint
    assert keys.public_jwk("svc-flow-events") == jwk


def test_a_client_assertion_is_an_es256_jwt_for_the_token_endpoint(tmp_path):
    keys = sak.KeyStore(tmp_path / "keys")
    jwk = keys.generate("svc-flow-events")
    token_url = "http://kc.invalid/realms/papaia/protocol/openid-connect/token"
    assertion = sak.client_assertion(
        keys.key_path("svc-flow-events"), jwk, "svc-flow-events", token_url
    )
    header, claims, signature = assertion.split(".")

    def decode(part: str) -> dict:
        return json.loads(_b64(part))

    assert decode(header) == {"alg": "ES256", "kid": jwk["kid"], "typ": "JWT"}
    body = decode(claims)
    assert body["iss"] == body["sub"] == "svc-flow-events"
    assert body["aud"] == token_url
    assert 0 < body["exp"] - body["iat"] <= 60
    assert len(_b64(signature)) == 64
    assert _verify(assertion, jwk)
    other = keys.generate("svc-flow-notify")
    assert not _verify(assertion, other)


@pytest.mark.parametrize("name", ["../x", "svc-flow-events/../../x", "", "svc", "SVC-FLOW-X"])
def test_a_key_path_is_built_only_from_an_account_name(tmp_path, name):
    with pytest.raises(ValueError):
        sak.KeyStore(tmp_path / "keys").key_path(name)


def test_a_key_folder_behind_a_symlink_is_refused(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "keys").symlink_to(target)
    with pytest.raises(sak.KeyFileError):
        sak.KeyStore(tmp_path / "keys").generate("svc-flow-events")


def test_a_key_file_readable_by_others_is_refused(tmp_path):
    keys = sak.KeyStore(tmp_path / "keys")
    keys.generate("svc-flow-events")
    keys.key_path("svc-flow-events").chmod(0o644)
    with pytest.raises(sak.KeyFileError, match="0600"):
        keys.public_jwk("svc-flow-events")


# ─────────────────────────────────────────────────────────────────────────
# rotation and the account list
# ─────────────────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _sign_in_against(realm: FakeRealm):
    """A sign-in check as Keycloak does it: the assertion's key must be registered."""

    def try_sign_in(client_id: str, key_path, jwk: dict) -> bool:
        assertion = sak.client_assertion(key_path, jwk, client_id, "http://kc.invalid/token")
        registered = json.loads(realm.by_client_id(client_id)["attributes"]["jwks.string"])
        return any(_verify(assertion, k) for k in registered["keys"])

    return try_sign_in


def _synced(tmp_path):
    realm, keys = FakeRealm(), _keys(tmp_path)
    _run(realm, _full_plan(), keys)
    return realm, keys


@pytest.mark.parametrize("grace", [0, 30])
def test_rotation_registers_a_new_key_and_the_old_one_is_refused_within_60s(tmp_path, grace):
    realm, keys = _synced(tmp_path)
    old = keys.public_jwk("svc-flow-events")
    old_pem = keys.key_path("svc-flow-events").read_bytes()
    clock = _Clock()
    outbox = tmp_path / "audit.jsonl"
    with rs.AuditLog(outbox, "rotate-1", writer="papaia-ctl/service-account") as audit:
        refused_after = sa.rotate_key(
            realm.call,
            keys,
            "svc-flow-events",
            audit=audit,
            grace=grace,
            try_sign_in=_sign_in_against(realm),
            clock=clock,
        )
    new = keys.public_jwk("svc-flow-events")
    assert new["kid"] != old["kid"]
    assert _jwks(realm, "svc-flow-events") == [new]
    assert keys.key_path("svc-flow-events").read_bytes() != old_pem
    assert grace <= refused_after <= sa.MAX_REFUSAL_SECONDS
    assert not list(keys.key_path("svc-flow-events").parent.glob("*.old.pem"))
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    assert {r["event"] for r in rows} == {"service_account_rotated"}
    assert all(r["writer"] == "papaia-ctl/service-account" for r in rows)
    assert all(r["operation"].startswith("service_account.") for r in rows)
    assert len(rows) == (2 if grace else 1)
    rotated = realm.by_client_id("svc-flow-events")["attributes"]["papaia.key_rotated_at"]
    assert rotated.endswith("Z")
    # the rest of the realm stays as the sync left it
    assert _run(realm, _full_plan(), keys, apply=False) == []


def test_rotation_fails_when_the_old_key_is_still_accepted_after_60s(tmp_path):
    realm, keys = _synced(tmp_path)
    clock = _Clock()
    with pytest.raises(sa.RotationError, match="still accepted"):
        sa.rotate_key(
            realm.call,
            keys,
            "svc-flow-events",
            audit=None,
            grace=0,
            try_sign_in=lambda *a: True,
            clock=clock,
        )
    assert clock.now <= sa.MAX_REFUSAL_SECONDS + sa.POLL_SECONDS


def test_rotation_fails_when_the_new_key_is_not_accepted(tmp_path):
    realm, keys = _synced(tmp_path)
    with pytest.raises(sa.RotationError, match="new key"):
        sa.rotate_key(
            realm.call,
            keys,
            "svc-flow-events",
            audit=None,
            grace=0,
            try_sign_in=lambda *a: False,
            clock=_Clock(),
        )


@pytest.mark.parametrize("grace", [-1, 61])
def test_a_grace_period_beyond_60s_is_refused(tmp_path, grace):
    realm, keys = _synced(tmp_path)
    with pytest.raises(sa.RotationError, match="0 to 60"):
        sa.rotate_key(
            realm.call, keys, "svc-flow-events", audit=None, grace=grace, try_sign_in=None
        )
    assert _jwks(realm, "svc-flow-events") == [keys.public_jwk("svc-flow-events")]


@pytest.mark.parametrize("name", ["flow-engine", "svc-flow-d1", "hand-made"])
def test_only_a_declared_account_can_be_rotated(tmp_path, name):
    realm, keys = _synced(tmp_path)
    realm.call("POST", "/clients", {"clientId": "hand-made", "serviceAccountsEnabled": True})
    with pytest.raises(sa.RotationError, match="not a declared service account"):
        sa.rotate_key(realm.call, keys, name, audit=None, grace=0, try_sign_in=None)


def test_the_list_names_owner_rotation_and_last_use(tmp_path):
    realm, keys = _synced(tmp_path)
    realm.sign_in("svc-flow-events", 1_700_000_000_000)
    rows = {r["id"]: r for r in sa.describe(realm.call, now=1_700_000_100.0)}
    assert set(rows) == {"svc-flow-events", "svc-flow-notify"}
    events = rows["svc-flow-events"]
    assert events["module"] == "flow"
    assert events["owner_sub"] == "dora"
    assert events["deputy_sub"] == "anna"
    assert events["purpose"] == {"de": "Rechnungseingang", "en": "Incoming invoices"}
    assert events["audiences"] == ["mcp-paperless"]
    assert events["roles"] == []
    assert events["effects"] == ["read"]
    assert events["rotation_days"] == rs.ROTATION_DAYS
    assert events["key_rotated_at"].endswith("Z")
    assert events["rotation_due"] is False
    assert events["last_used"] == "2023-11-14T22:13:20Z"
    assert rows["svc-flow-notify"]["last_used"] is None
    assert rows["svc-flow-notify"]["roles"] == ["prefs-read"]


def test_an_account_past_its_rotation_interval_is_due(tmp_path):
    realm, _ = _synced(tmp_path)
    realm.by_client_id("svc-flow-events")["attributes"]["papaia.key_rotated_at"] = (
        "2020-01-01T00:00:00Z"
    )
    rows = {r["id"]: r for r in sa.describe(realm.call)}
    assert rows["svc-flow-events"]["rotation_due"] is True


def test_the_list_command_prints_no_key_material(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path, *_addons())
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    capsys.readouterr()
    assert sa.list_accounts(_tree(), config_dir) == 0
    out = capsys.readouterr().out
    assert "svc-flow-events" in out and "dora" in out and "never" in out
    assert "PRIVATE" not in out and '"x"' not in out
    assert sa.list_accounts(_tree(), config_dir, as_json=True) == 0
    (row,) = json.loads(capsys.readouterr().out)
    assert row["id"] == "svc-flow-events"


def test_the_rotate_command_audits_and_keeps_the_key_in_the_config_dir(
    tmp_path, connected, monkeypatch, capsys
):
    config_dir, repo_root = _config(tmp_path, *_addons())
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    monkeypatch.setattr(sa, "_sign_in_check", lambda *a: _sign_in_against(connected))
    before = len(rs.audit_path(config_dir).read_text().splitlines())
    assert sa.rotate(_tree(), config_dir, "svc-flow-events", grace=0) == 0
    rows = [json.loads(x) for x in rs.audit_path(config_dir).read_text().splitlines()[before:]]
    assert [r["event"] for r in rows] == ["service_account_rotated"]
    assert "refused" in capsys.readouterr().out
    assert sa.rotate(_tree(), config_dir, "svc-flow-nothing", grace=0) == 2


# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl service-account
# ─────────────────────────────────────────────────────────────────────────


@needs_bash
@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (("list",), "py_cli service-account-list "),
        (("list", "--json"), "py_cli service-account-list --json "),
        (("rotate", "svc-flow-events"), "py_cli service-account-rotate --id svc-flow-events "),
        (
            ("rotate", "svc-flow-events", "--grace=30"),
            "py_cli service-account-rotate --id svc-flow-events --grace 30 ",
        ),
    ],
)
def test_the_service_account_command_hands_its_arguments_to_py_cli(tmp_path, args, expected):
    config_dir = _seeded(tmp_path / "c")
    result = _call("cmd_service_account", *args, f"--config-dir={config_dir}")
    assert result.returncode == 0, result.stderr
    assert f"{expected}CONFIG_DIR={config_dir}" in result.stdout


@needs_bash
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("rotate",), "service-account rotate needs an account"),
        (("rotate", "a", "b"), "Unknown argument for service-account rotate: b"),
        (("rotate", "svc-flow-events", "--grace=abc"), "--grace must be 0 to 60"),
        (("rotate", "svc-flow-events", "--grace=61"), "--grace must be 0 to 60"),
        (("list", "--bogus"), "Unknown option for service-account list: --bogus"),
        (("export",), "Unknown 'service-account' subcommand: 'export'. Valid: list, rotate."),
    ],
)
def test_the_service_account_command_refuses_bad_arguments(tmp_path, args, message):
    result = _call("cmd_service_account", *args, default=_seeded(tmp_path / "c"))
    assert result.returncode == 2
    assert message in result.stderr


@needs_bash
def test_the_dispatcher_and_help_know_the_service_account_command():
    import subprocess

    assert BASH is not None
    help_text = subprocess.run(
        [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False
    ).stdout
    assert "papaia-ctl service-account list   [--json] [--config-dir=PATH]" in help_text
    assert (
        "papaia-ctl service-account rotate <id> [--grace=SECONDS] [--config-dir=PATH]" in help_text
    )


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["service-account-list"], ("list", False, None, None)),
        (["service-account-list", "--json"], ("list", True, None, None)),
        (
            ["service-account-rotate", "--id", "svc-flow-events"],
            ("rotate", None, "svc-flow-events", 30),
        ),
        (
            ["service-account-rotate", "--id", "svc-flow-events", "--grace", "0"],
            ("rotate", None, "svc-flow-events", 0),
        ),
    ],
)
def test_the_python_cli_dispatches_the_service_account_commands(
    tmp_path, monkeypatch, argv, expected
):
    from lib import cli

    calls = []
    monkeypatch.setattr(cli.envtree, "load_config_dir_tree", lambda *a: {})
    monkeypatch.setattr(
        cli.service_accounts,
        "list_accounts",
        lambda tree, config_dir, as_json=False: calls.append(("list", as_json, None, None)) or 0,
    )
    monkeypatch.setattr(
        cli.service_accounts,
        "rotate",
        lambda tree, config_dir, account, grace: (
            calls.append(("rotate", None, account, grace)) or 0
        ),
    )
    args = cli.build_parser().parse_args(
        ["--config-dir", str(tmp_path), "--repo-root", str(tmp_path), *argv]
    )
    assert args.func(args) == 0
    assert calls == [expected]
