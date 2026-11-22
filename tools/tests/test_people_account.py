"""The realm side of the people lookup: `svc-papaia-people` and the audience `papaia-people`.

While the Compose profile `people` is active, the realm sync keeps the service account
with exactly `realm-management` `query-users` and `view-users` (sicherheit §1.9, RE-51),
serves the audience `papaia-people` as a bearer-only resource server for persons only, and
lets only `assist-gate` exchange for it (sicherheit §1.4). Runs against the in-memory Admin
API of tests/realm_fake.py.
"""

from __future__ import annotations

import json

import pytest

from lib import people_account as pa
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm

REGISTER = rs.load_register()


def _keys(tmp_path):
    return rs.keystore(tmp_path / "config")


def _align(fake, keys, *, enabled=True, apply=True):
    return pa.align(fake.call, keys, enabled=enabled, apply=apply)


def _account_roles(fake) -> tuple[set, dict]:
    user = fake.service_account_user(pa.CLIENT_ID)
    clients = {
        fake.clients[cid]["clientId"]: set(roles)
        for cid, roles in user["_clients"].items()
        if roles
    }
    return set(user["_realm"]), clients


# ─────────────────────────────────────────────────────────────────────────
# service account
# ─────────────────────────────────────────────────────────────────────────


def test_the_account_holds_exactly_query_users_and_view_users(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    changes = _align(fake, keys)
    assert changes
    client = fake.by_client_id(pa.CLIENT_ID)
    assert client["serviceAccountsEnabled"] is True
    assert client["clientAuthenticatorType"] == "client-jwt"
    for flag in ("standardFlowEnabled", "directAccessGrantsEnabled", "implicitFlowEnabled",
                 "publicClient", "fullScopeAllowed"):
        assert client[flag] is False, flag
    assert client["attributes"][rs.TOKEN_EXCHANGE] == "false"
    (jwk,) = json.loads(client["attributes"]["jwks.string"])["keys"]
    assert jwk == keys.public_jwk(pa.CLIENT_ID)
    realm_roles, client_roles = _account_roles(fake)
    assert realm_roles == {"default-roles-papaia"}
    assert client_roles == {"realm-management": {"query-users", "view-users"}}
    rm = fake.by_client_id("realm-management")["id"]
    scope = client["_client_scope"].get(rm, set())
    assert {fake._client_role(fake.clients[rm], n)["name"] for n in scope} == {
        "query-users",
        "view-users",
    }
    assert _align(fake, keys, apply=False) == []


def test_a_wider_right_is_reported_then_removed(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    _align(fake, keys)
    user = fake.service_account_user(pa.CLIENT_ID)
    rm = fake.by_client_id("realm-management")["id"]
    user["_clients"][rm] |= {"manage-users"}
    user["_realm"] |= {"offline_access"}
    found = _align(fake, keys, apply=False)
    assert any("manage-users" in c.action for c in found)
    assert any("offline_access" in c.action for c in found)
    _align(fake, keys)
    assert _account_roles(fake) == (
        {"default-roles-papaia"},
        {"realm-management": {"query-users", "view-users"}},
    )
    assert _align(fake, keys, apply=False) == []


def test_a_group_of_the_account_is_left(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    _align(fake, keys)
    fake.groups["g-1"] = {"id": "g-1", "name": "admins", "path": "/admins"}
    fake.service_account_user(pa.CLIENT_ID)["_groups"].add("g-1")
    _align(fake, keys)
    assert fake.service_account_user(pa.CLIENT_ID)["_groups"] == set()


def test_without_the_profile_the_account_and_its_key_are_removed(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    _align(fake, keys)
    assert keys.public_jwk(pa.CLIENT_ID) is not None
    found = _align(fake, keys, enabled=False, apply=False)
    assert [c.action for c in found] == ["removed, profile people is off", "key folder left"]
    _align(fake, keys, enabled=False)
    assert not [c for c in fake.clients.values() if c["clientId"] == pa.CLIENT_ID]
    assert keys.public_jwk(pa.CLIENT_ID) is None
    assert _align(fake, keys, enabled=False, apply=False) == []


def test_the_profile_switch_follows_compose_profiles():
    assert pa.enabled({"": {"COMPOSE_PROFILES": "keycloak, people"}})
    assert not pa.enabled({"": {"COMPOSE_PROFILES": "keycloak,peoplex"}})
    assert pa.core_audiences({"": {"COMPOSE_PROFILES": "people"}}) == frozenset({pa.AUDIENCE})
    assert pa.core_audiences({"": {}}) == frozenset()


def test_the_realm_sync_leaves_the_core_account_alone():
    assert pa.CLIENT_ID in rs.CORE_ACCOUNTS


# ─────────────────────────────────────────────────────────────────────────
# audience and pairing
# ─────────────────────────────────────────────────────────────────────────


def _assist() -> rs.Module:
    return rs.Module(
        "papaia-assist",
        [
            {
                "id": "assist.api",
                "kind": "rest",
                "audience": "assist-api",
                "identity": ["person"],
                "roles": [{"name": "assist-member"}, {"name": "assist-admin"}],
            }
        ],
        {},
    )


def _pairings(*rows) -> list[rs.Pairing]:
    doc = {
        "format": "papaia.pairings/1",
        "pairings": [{"client": c, "audience": a, "effects": e, "state": "confirmed"}
                     for c, a, e in rows],
    }
    return rs.parse_pairings(doc, REGISTER)


def test_the_register_carries_the_audience_of_the_core():
    assert "papaia-people" in REGISTER.audiences
    assert REGISTER.clients["papaia-people"].owner == "papaia"
    assert not REGISTER.clients["papaia-people"].token_exchange
    assert REGISTER.service_accounts["svc-papaia-people"].owner == "papaia"


def test_the_audience_is_a_bearer_client_for_persons_only_and_paired_with_the_gate():
    plan = rs.build_plan(
        REGISTER,
        [_assist()],
        _pairings(("assist-gate", "papaia-people", ["x"])),
        core_audiences=pa.core_audiences({"": {"COMPOSE_PROFILES": "people"}}),
    )
    spec = plan.clients["papaia-people"]
    assert (spec.kind, spec.owner, spec.token_exchange) == ("bearer", "papaia", False)
    assert spec.role_scope == set() and spec.optional_scopes == set()
    assert "aud-papaia-people" in plan.clients["assist-gate"].optional_scopes
    assert plan.exchange_scopes["aud-papaia-people"] == "papaia-people"
    person_policies = [n for n in plan.policies if n.startswith(rs.PERSON_POLICY_PREFIX)]
    assert any("papaia-people" in n for n in person_policies)


def test_without_the_profile_the_pairing_waits():
    plan = rs.build_plan(
        REGISTER, [_assist()], _pairings(("assist-gate", "papaia-people", ["x"]))
    )
    assert "papaia-people" not in plan.clients
    assert "aud-papaia-people" not in plan.clients["assist-gate"].optional_scopes
    assert any("papaia-people" in note and "inactive" in note for note in plan.notes)


@pytest.mark.parametrize(
    "client, effects, message",
    [
        ("papaia-studio-gateway", ["x"], "only assist-gate"),
        ("flow-engine", ["x"], "only assist-gate"),
        ("assist-gate", ["r"], "effect x only"),
        ("assist-gate", ["x", "r"], "effect x only"),
    ],
)
def test_only_the_gate_exchanges_for_the_lookup_with_effect_x(client, effects, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _pairings((client, "papaia-people", effects))


def test_the_reconcile_creates_the_bearer_client_and_the_scope(tmp_path):
    fake = FakeRealm()
    plan = rs.build_plan(
        REGISTER,
        [_assist()],
        _pairings(("assist-gate", "papaia-people", ["x"])),
        core_audiences=frozenset({pa.AUDIENCE}),
    )
    rs.reconcile(fake.call, plan, apply=True, keys=_keys(tmp_path), master=fake.call)
    client = fake.by_client_id("papaia-people")
    assert client["bearerOnly"] is True
    assert client["attributes"][rs.OWNER] == "papaia"
    scope = fake.scope_by_name("aud-papaia-people")
    gate = fake.by_client_id("assist-gate")
    assert scope["id"] in gate["_optional"]
    assert scope["id"] not in gate["_default"]
    assert rs.reconcile(fake.call, plan, apply=False, keys=_keys(tmp_path), master=fake.call) == []
