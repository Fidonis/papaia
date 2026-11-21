"""papaia-ctl realm sync: task sources and the own-token exchange of Flow's console.

- `flow-console` signs in with `private_key_jwt`, its only default scope is
  `papaia-person`, `aud-flow` is an optional sign-in scope, and it exchanges its own
  tokens only for the task sources `papaia-data` and `papaia-studio`;
- the task-source pairings (Me -> Flow, Data, Studio; Studio -> Flow, Data; Flow's console
  -> Data, Studio) yield the pair policies (`aud-flow`, `aud-papaia-data`),
  (`aud-flow`, `aud-papaia-studio`), (`aud-papaia-data`, `aud-papaia-studio`), which refuse
  two `aud-*` scopes at sign-in as well as in an exchange;
- no client with token exchange holds an `aud-*` default scope, in the sync and in
  `--check`; `flow-console` and `flow-engine` are never audiences.

The same flows run against a real Keycloak in tests/test_realm_sync_task_sources_live.py.
"""

from __future__ import annotations

import json

import pytest

from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import REGISTER, _flow, _pairings, _paperless, _plan, _run, _studio
from tests.test_realm_sync_policies import _data

CONSOLE = "flow-console"
PAIR_POLICIES = {
    "papaia-one-aud-flow-papaia-data",
    "papaia-one-aud-flow-papaia-studio",
    "papaia-one-aud-papaia-data-papaia-studio",
}


def _studio_api() -> rs.Module:
    studio = _studio()
    studio.exposes.append(
        {"id": "studio.api", "kind": "rest", "audience": "papaia-studio", "identity": ["person"]}
    )
    return studio


def _me() -> rs.Module:
    return rs.Module("papaia-me", [{"id": "me.ui", "kind": "ui", "identity": ["person"]}], {})


TASK_SOURCES = (
    ("papaia-me", "flow", ["x"], "confirmed"),
    ("papaia-me", "papaia-data", ["x"], "confirmed"),
    ("papaia-me", "papaia-studio", ["x"], "confirmed"),
    ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
    ("papaia-studio-gateway", "papaia-data", ["x"], "confirmed"),
    (CONSOLE, "papaia-data", ["x"], "confirmed"),
    (CONSOLE, "papaia-studio", ["x"], "confirmed"),
)


def _task_plan(*extra) -> rs.Plan:
    return _plan(
        [_flow(), _studio_api(), _data(), _me(), _paperless()],
        _pairings(*TASK_SOURCES, *extra),
    )


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# flow-console: private_key_jwt, papaia-person, aud-flow at sign-in
# ─────────────────────────────────────────────────────────────────────────


def test_flow_console_authenticates_with_a_signed_assertion_only():
    realm = FakeRealm()
    _run(realm, _plan([_flow()]))
    console = realm.by_client_id(CONSOLE)
    assert console["clientAuthenticatorType"] == "client-jwt"
    assert console["publicClient"] is False
    assert console["standardFlowEnabled"] is True
    assert console["directAccessGrantsEnabled"] is False
    assert console["attributes"]["pkce.code.challenge.method"] == "S256"
    assert console["attributes"]["standard.token.exchange.enabled"] == "true"
    # other clients keep the authenticator Keycloak gives them
    assert "clientAuthenticatorType" not in realm.by_client_id("flow-engine")


def test_a_client_secret_on_flow_console_is_reported_and_replaced(tmp_path):
    realm = FakeRealm()
    plan = _plan([_flow()])
    _run(realm, plan)
    realm.by_client_id(CONSOLE)["clientAuthenticatorType"] = "client-secret"
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", CONSOLE)]
    assert "clientAuthenticatorType" in drift[0].action
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert row["object_ref"] == {"type": "client", "id": CONSOLE}
    assert realm.by_client_id(CONSOLE)["clientAuthenticatorType"] == "client-jwt"
    assert _run(realm, plan, apply=False) == []


def test_the_public_key_flow_registers_survives_the_sync():
    realm = FakeRealm()
    plan = _plan([_flow()])
    _run(realm, plan)
    jwks = json.dumps({"keys": [{"kty": "EC", "kid": "console-1", "crv": "P-256"}]})
    realm.by_client_id(CONSOLE)["attributes"].update(
        {"use.jwks.string": "true", "jwks.string": jwks}
    )
    assert _run(realm, plan, apply=False) == []
    assert _run(realm, plan) == []
    assert realm.by_client_id(CONSOLE)["attributes"]["jwks.string"] == jwks


def test_flow_console_has_papaia_person_as_its_only_default_scope():
    realm = FakeRealm()
    _run(realm, _plan([_flow()]))
    assert realm.scope_names(CONSOLE, "default") == {"papaia-person"}
    # the other sign-in clients keep Keycloak's default scopes
    assert realm.scope_names("flow-engine", "default") == set(rs.DEFAULT_SCOPES)


def test_the_papaia_person_scope_carries_the_shared_person_claims_and_no_role():
    realm = FakeRealm()
    plan = _plan([_flow()])
    _run(realm, plan)
    scope = realm.scope_by_name("papaia-person")
    assert scope["protocol"] == "openid-connect"
    assert scope["attributes"]["papaia.managed"] == "true"
    assert scope["attributes"]["include.in.token.scope"] == "true"
    mappers = {m["name"]: m for m in scope["protocolMappers"]}
    assert set(mappers) == {
        "sub",
        "auth_time",
        "person_id",
        "roles",
        "groups",
        "email",
        "email verified",
    }
    assert mappers["sub"]["protocolMapper"] == "oidc-sub-mapper"
    assert mappers["person_id"]["config"]["user.attribute"] == "id"
    assert mappers["roles"]["protocolMapper"] == "oidc-usermodel-realm-role-mapper"
    assert mappers["roles"]["config"]["claim.name"] == "roles"
    assert mappers["groups"]["config"]["full.path"] == "true"
    # no audience, no role of its own
    assert not [m for m in scope["protocolMappers"] if "audience" in m["protocolMapper"]]
    assert not scope["_role_scope"] and not scope["_client_scope"]
    assert _run(realm, plan) == []


def test_drift_on_the_papaia_person_scope_is_reported_and_repaired(tmp_path):
    realm = FakeRealm()
    plan = _plan([_flow()])
    _run(realm, plan)
    scope = realm.scope_by_name("papaia-person")
    realm.call(
        "POST",
        f"/client-scopes/{scope['id']}/protocol-mappers/models",
        {
            "name": "aud",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "mcp-paperless", "access.token.claim": "true"},
        },
    )
    groups = next(m for m in scope["protocolMappers"] if m["name"] == "groups")
    groups["config"]["full.path"] = "false"
    scope["_role_scope"].add("offline_access")
    drift = _run(realm, plan, apply=False)
    assert drift and {(c.kind, c.name) for c in drift} == {("client-scope", "papaia-person")}
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    rows = _rows(tmp_path / "audit.jsonl")
    # the foreign mapper and the role mapping out, the changed mapper out and in again
    assert len(rows) == len(drift) == 4
    assert any("adds an audience" in c.action for c in drift)
    assert {r["event"] for r in rows} == {"exchange_right_changed", "config_changed"}
    scope = realm.scope_by_name("papaia-person")
    assert {m["name"] for m in scope["protocolMappers"]} == {
        "sub",
        "auth_time",
        "person_id",
        "roles",
        "groups",
        "email",
        "email verified",
    }
    assert (
        next(m for m in scope["protocolMappers"] if m["name"] == "groups")["config"]["full.path"]
        == "true"
    )
    assert not scope["_role_scope"]
    assert _run(realm, plan, apply=False) == []


def test_without_flow_there_is_no_papaia_person_scope_to_manage():
    realm = FakeRealm()
    _run(realm, _plan([_studio()]))
    assert "papaia-person" not in {s["name"] for s in realm.scopes.values()}


def test_aud_flow_is_an_optional_sign_in_scope_of_flow_console_without_a_pairing():
    realm = FakeRealm()
    plan = _plan([_flow()])
    _run(realm, plan)
    assert realm.scope_names(CONSOLE, "optional") == {"aud-flow"}
    (mapper,) = realm.scope_by_name("aud-flow")["protocolMappers"]
    assert mapper["config"]["included.client.audience"] == "flow"
    assert not {n for n in realm.scope_names(CONSOLE, "default") if n.startswith("aud-")}


# ─────────────────────────────────────────────────────────────────────────
# task sources: pairings and pair policies
# ─────────────────────────────────────────────────────────────────────────


def test_the_task_source_pairings_assign_their_scopes():
    realm = FakeRealm()
    plan = _task_plan()
    _run(realm, plan)
    assert realm.scope_names(CONSOLE, "optional") == {
        "aud-flow",
        "aud-papaia-data",
        "aud-papaia-studio",
    }
    assert realm.scope_names("papaia-me", "optional") == {
        "aud-flow",
        "aud-papaia-data",
        "aud-papaia-studio",
    }
    assert realm.scope_names("papaia-studio-gateway", "optional") == {"aud-flow", "aud-papaia-data"}
    for client_id in (CONSOLE, "papaia-me", "papaia-studio-gateway", "flow-engine"):
        assert not {n for n in realm.scope_names(client_id, "default") if n.startswith("aud-")}
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_the_task_sources_yield_the_three_pair_policies():
    realm = FakeRealm()
    _run(realm, _task_plan())
    names = {p["name"] for p in realm.policies}
    assert PAIR_POLICIES <= names
    policy = realm.policy("papaia-one-aud-flow-papaia-data")
    scopes = [
        c["configuration"]["scopes"]
        for c in policy["conditions"]
        if c["condition"] == "client-scopes"
    ]
    assert scopes == [["aud-flow"], ["aud-papaia-data"]]
    assert realm.profile(policy["profiles"][0])["executors"] == [
        {"executor": "reject-request", "configuration": {}}
    ]


def test_pair_policies_apply_at_sign_in_as_well_as_in_an_exchange():
    """No grant-type condition: a sign-in (authorization request, code or refresh) that
    asks for two `aud-*` scopes is refused like an exchange."""
    realm = FakeRealm()
    _run(realm, _task_plan())
    for name in PAIR_POLICIES:
        conditions = realm.policy(name)["conditions"]
        assert [c["condition"] for c in conditions] == ["client-scopes", "client-scopes"]


def test_pair_policies_of_an_existing_realm_are_widened_to_sign_in(tmp_path):
    realm = FakeRealm()
    plan = _task_plan()
    _run(realm, plan)
    grant = {
        "condition": "grant-type",
        "configuration": {"grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    }
    realm.policy("papaia-one-aud-flow-papaia-data")["conditions"].insert(0, grant)
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [
        ("client-policy", "papaia-one-aud-flow-papaia-data")
    ]
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert row["event"] == "exchange_right_changed"
    assert _run(realm, plan, apply=False) == []


@pytest.mark.parametrize(
    "audience",
    ["mcp-paperless", "mcp-qdrant", "flow", "assist-api", "papaia-connections", "papaia-prefs"],
)
def test_flow_console_exchanges_only_for_the_task_sources(audience):
    with pytest.raises(rs.RealmSyncError, match="only for papaia-data, papaia-studio"):
        _pairings((CONSOLE, audience, ["r"], "confirmed"))


def test_a_pending_task_source_pairing_assigns_nothing():
    realm = FakeRealm()
    plan = _plan(
        [_flow(), _studio_api(), _data()],
        _pairings(
            (CONSOLE, "papaia-data", ["x"], "confirmed"),
            (CONSOLE, "papaia-studio", ["x"], "pending"),
        ),
    )
    _run(realm, plan)
    assert realm.scope_names(CONSOLE, "optional") == {"aud-flow", "aud-papaia-data"}
    assert "papaia-one-aud-papaia-data-papaia-studio" not in {p["name"] for p in realm.policies}


# ─────────────────────────────────────────────────────────────────────────
# general rules: no aud-* default scope at an exchange client, never an audience
# ─────────────────────────────────────────────────────────────────────────


def test_an_aud_default_scope_on_a_managed_exchange_client_is_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _task_plan()
    _run(realm, plan)
    data = realm.scope_by_name("aud-papaia-data")
    realm.call(
        "PUT", f"/clients/{realm.by_client_id(CONSOLE)['id']}/default-client-scopes/{data['id']}"
    )
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", CONSOLE)]
    assert "exchange client" in drift[0].action
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert (row["event"], row["effect"]) == ("exchange_right_changed", "delete")
    assert realm.scope_names(CONSOLE, "default") == {"papaia-person"}


@pytest.mark.parametrize("bearer", [False, True])
def test_an_aud_default_scope_on_any_other_exchange_client_is_removed(bearer):
    realm = FakeRealm()
    plan = _task_plan()
    _run(realm, plan)
    realm.call(
        "POST",
        "/clients",
        {
            "clientId": "site-exchange",
            "publicClient": False,
            "bearerOnly": bearer,
            # in line with the realm hardening, so the aud-* scope is the only drift
            "directAccessGrantsEnabled": False,
            "attributes": {"standard.token.exchange.enabled": "true"},
            "defaultClientScopes": ["basic", "aud-papaia-data"],
            "optionalClientScopes": [],
        },
    )
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "site-exchange")]
    assert "exchange client" in drift[0].action
    _run(realm, plan)
    assert realm.scope_names("site-exchange", "default") == {"basic"}
    assert _run(realm, plan, apply=False) == []


def test_flow_console_and_flow_engine_are_never_audiences():
    plan = _task_plan()
    assert {CONSOLE, "flow-engine"} <= plan.never_audiences
    for audience in (CONSOLE, "flow-engine"):
        with pytest.raises(rs.RealmSyncError, match="not a registered audience"):
            _pairings(("papaia-me", audience, ["x"], "confirmed"))
    realm = FakeRealm()
    _run(realm, plan)
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-flow-console",
            "protocol": "openid-connect",
            "protocolMappers": [
                {
                    "name": "audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {"included.client.audience": CONSOLE},
                }
            ],
        },
    )
    _run(realm, plan)
    names = {s["name"] for s in realm.scopes.values()}
    assert not {"aud-flow-console", "aud-flow-engine"} & names
    mappers = [m for s in realm.scopes.values() for m in s["protocolMappers"]]
    mappers += [m for c in realm.clients.values() for m in c["protocolMappers"]]
    assert not [
        m
        for m in mappers
        if (m.get("config") or {}).get("included.client.audience") in (CONSOLE, "flow-engine")
    ]


def test_every_write_of_the_task_source_setup_is_one_audit_row(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, _task_plan(), audit=audit)
    rows = _rows(tmp_path / "audit.jsonl")
    assert len(rows) == len(realm.writes)
    assert {r["correlation_id"] for r in rows} == {"run-1"}
    assert ("client_scope", "papaia-person") in {
        (r["object_ref"]["type"], r["object_ref"]["id"]) for r in rows
    }
    assert "eyJ" not in (tmp_path / "audit.jsonl").read_text()


def test_the_register_keeps_flow_console_an_exchange_client_that_is_no_audience():
    assert REGISTER.clients[CONSOLE].token_exchange is True
    assert CONSOLE not in REGISTER.audiences
    assert REGISTER.successor("papaia-flow-console") == CONSOLE
