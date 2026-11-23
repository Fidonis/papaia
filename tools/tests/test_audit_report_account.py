"""The realm side of the permission report in papaia-audit (lib/audit_report_account.py):
the report account `svc-papaia-audit-report` with `realm-management` `view-users` and
nothing else, the audience `papaia-audit` for persons only, and its one exchange right,
the platform pairing `papaia-manager -> papaia-audit`, which the realm sync sets on the
manager's template client and lists in the inputs file of the report. Runs against the
in-memory Admin API of tests/realm_fake.py.
"""

from __future__ import annotations

import json

import pytest

from lib import access_report as ar
from lib import audit_report_account as ara
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm

REGISTER = rs.load_register()
TREE = {"": {"COMPOSE_PROFILES": "keycloak,audit"}}


def _keys(tmp_path):
    return rs.keystore(tmp_path / "config")


def _align(fake, keys, *, enabled=True, apply=True):
    return ara.align(fake.call, keys, enabled=enabled, apply=apply)


def _account_roles(fake) -> tuple[set, dict]:
    user = fake.service_account_user(ara.CLIENT_ID)
    clients = {
        fake.clients[cid]["clientId"]: set(roles)
        for cid, roles in user["_clients"].items()
        if roles
    }
    return set(user["_realm"]), clients


# ─────────────────────────────────────────────────────────────────────────
# the report account
# ─────────────────────────────────────────────────────────────────────────


def test_after_the_sync_the_account_holds_exactly_view_users(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    assert _align(fake, keys)
    client = fake.by_client_id(ara.CLIENT_ID)
    assert client["serviceAccountsEnabled"] is True
    assert client["clientAuthenticatorType"] == "client-jwt"
    for flag in ("standardFlowEnabled", "directAccessGrantsEnabled", "implicitFlowEnabled",
                 "publicClient", "fullScopeAllowed"):
        assert client[flag] is False, flag
    assert client["attributes"][rs.TOKEN_EXCHANGE] == "false"
    assert client["attributes"]["token.endpoint.auth.signing.alg"] == "ES256"
    (jwk,) = json.loads(client["attributes"]["jwks.string"])["keys"]
    assert jwk == keys.public_jwk(ara.CLIENT_ID)
    assert "secret" not in client or client.get("clientAuthenticatorType") == "client-jwt"
    assert _account_roles(fake) == ({"default-roles-papaia"}, {"realm-management": {"view-users"}})
    rm = fake.by_client_id("realm-management")["id"]
    scope = client["_client_scope"].get(rm, set())
    assert {fake._client_role(fake.clients[rm], n)["name"] for n in scope} == {"view-users"}
    # A second sync changes nothing.
    assert _align(fake, keys, apply=False) == []
    assert _align(fake, keys) == []


def test_a_wider_right_is_reported_then_removed(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    _align(fake, keys)
    user = fake.service_account_user(ara.CLIENT_ID)
    rm = fake.by_client_id("realm-management")["id"]
    user["_clients"][rm] |= {"view-realm", "view-clients", "query-users", "manage-users"}
    found = _align(fake, keys, apply=False)
    for right in ("view-realm", "view-clients", "query-users", "manage-users"):
        assert any(right in c.action for c in found), right
    assert all(c.operation.startswith("audit_report_") for c in found)
    _align(fake, keys)
    assert _account_roles(fake) == ({"default-roles-papaia"}, {"realm-management": {"view-users"}})


def test_without_the_profile_the_account_and_its_key_are_removed(tmp_path):
    fake, keys = FakeRealm(), _keys(tmp_path)
    _align(fake, keys)
    found = _align(fake, keys, enabled=False, apply=False)
    assert [c.action for c in found] == ["removed, profile audit is off", "key folder left"]
    _align(fake, keys, enabled=False)
    assert not [c for c in fake.clients.values() if c["clientId"] == ara.CLIENT_ID]
    assert keys.public_jwk(ara.CLIENT_ID) is None


def test_the_people_account_keeps_its_three_roles(tmp_path):
    from lib import people_account as pa

    fake, keys = FakeRealm(), _keys(tmp_path)
    pa.align(fake.call, keys, enabled=True, apply=True)
    _align(fake, keys)
    people = fake.service_account_user(pa.CLIENT_ID)
    rm = fake.by_client_id("realm-management")["id"]
    assert people["_clients"][rm] == {"query-users", "view-users", "query-groups"}
    assert pa.align(fake.call, keys, enabled=True, apply=False) == []


def test_the_realm_sync_leaves_the_core_account_alone():
    assert ara.CLIENT_ID in rs.CORE_ACCOUNTS
    assert ara.enabled(TREE) and not ara.enabled({"": {"COMPOSE_PROFILES": "keycloak"}})


# ─────────────────────────────────────────────────────────────────────────
# the audience and its one exchange right
# ─────────────────────────────────────────────────────────────────────────


def _plan(modules=(), pairings=(), tree=TREE) -> rs.Plan:
    return rs.build_plan(
        REGISTER,
        list(modules),
        list(pairings),
        core_audiences=ara.core_audiences(tree),
        platform_pairings=ara.platform_pairings(tree),
    )


def test_the_audience_is_a_bearer_client_for_persons_only():
    plan = _plan()
    spec = plan.clients["papaia-audit"]
    assert (spec.kind, spec.owner, spec.token_exchange) == ("bearer", "papaia", False)
    assert plan.exchange_scopes["aud-papaia-audit"] == "papaia-audit"
    policies = set(plan.policies)
    assert "papaia-person-papaia-audit-client-credentials" in policies
    assert "papaia-person-papaia-audit-exchange" in policies


def test_the_manager_alone_exchanges_for_papaia_audit_as_a_platform_pairing():
    plan = _plan()
    assert plan.template_scopes == {"papaia-manager": {"aud-papaia-audit"}}
    (pairing,) = ara.platform_pairings(TREE)
    assert (pairing.client, pairing.audience, pairing.effects) == (
        "papaia-manager",
        "papaia-audit",
        ("r",),
    )
    assert pairing.requested_by == pairing.confirmed_by == "platform"
    assert ara.platform_pairings({"": {"COMPOSE_PROFILES": "keycloak"}}) == []
    assert _plan(tree={"": {}}).template_scopes == {}


@pytest.mark.parametrize("client", ["papaia-manager", "flow-engine", "assist-gate"])
def test_pairings_yaml_cannot_name_papaia_audit(client):
    doc = {
        "format": "papaia.pairings/1",
        "pairings": [
            {"client": client, "audience": "papaia-audit", "effects": ["r"],
             "state": "confirmed"}
        ],
    }
    with pytest.raises(rs.RealmSyncError, match="paired by the realm sync itself"):
        rs.parse_pairings(doc, REGISTER)


def test_a_platform_pairing_for_another_audience_is_refused():
    with pytest.raises(rs.RealmSyncError, match="not one the realm sync sets"):
        rs.build_plan(
            REGISTER,
            [],
            [],
            core_audiences=ara.core_audiences(TREE),
            platform_pairings=[
                rs.Pairing("papaia-manager", "papaia-people", ("x",), True, "platform", "platform")
            ],
        )


def _manager(fake: FakeRealm) -> dict:
    fake._add_client(
        {
            "clientId": "papaia-manager",
            "publicClient": False,
            "directAccessGrantsEnabled": False,
            "attributes": {"login_theme": "papaia"},
        }
    )
    return fake.by_client_id("papaia-manager")


def test_the_sync_gives_the_template_manager_exactly_the_one_exchange_right():
    fake = FakeRealm()
    manager = _manager(fake)
    fake._add_client(
        {"clientId": "other-client", "publicClient": False,
         "attributes": {rs.TOKEN_EXCHANGE: "true"}}
    )
    plan = _plan()
    rs.reconcile(fake.call, plan, apply=True)
    # The audience scope exists before another client could be given it by hand.
    other = fake.by_client_id("other-client")
    fake.call(
        "PUT",
        f"/clients/{other['id']}/optional-client-scopes/"
        f"{fake.scope_by_name('aud-papaia-audit')['id']}",
    )

    changes = rs.reconcile(fake.call, plan, apply=True)

    assert fake.scope_names("papaia-manager", "optional") >= {"aud-papaia-audit"}
    assert manager["attributes"][rs.TOKEN_EXCHANGE] == "true"
    assert manager["attributes"]["login_theme"] == "papaia"  # nothing else changed
    assert manager["fullScopeAllowed"] is True and manager["publicClient"] is False
    assert "aud-papaia-audit" not in fake.scope_names("other-client", "optional")
    assert any(c.name == "other-client" and "aud-papaia-audit" in c.action for c in changes)
    assert rs.reconcile(fake.call, plan, apply=False) == []


def test_a_missing_template_client_is_noted_not_created(capsys):
    fake = FakeRealm()
    rs.reconcile(fake.call, _plan(), apply=True)
    assert not [c for c in fake.clients.values() if c["clientId"] == "papaia-manager"]
    assert "platform pairing waits for client papaia-manager" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────
# the inputs file written by the sync
# ─────────────────────────────────────────────────────────────────────────


def test_the_sync_writes_the_inputs_file_with_the_platform_pairing(tmp_path):
    config = tmp_path / "config"
    fake = FakeRealm()
    _manager(fake)
    rs.reconcile(fake.call, _plan(), apply=True)

    path = rs.write_report_inputs(fake.call, TREE, config)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["format"] == "papaia.access-report-inputs/1"
    assert {"client": "papaia-manager", "audience": "papaia-audit", "effects": ["r"],
            "requested_by": "platform", "confirmed_by": "platform"} in document["pairings"]
    assert document["sessions"]["offline"] == {"idle_days": 90, "max_age_days": 180}
    assert document["recertification_days"] == ar.PERIOD_DEFAULT
    assert "secret" not in path.read_text(encoding="utf-8")


def test_a_bad_period_stops_the_inputs_file(tmp_path):
    tree = {"": {"COMPOSE_PROFILES": "audit", ar.PERIOD_KEY: "5"}}
    with pytest.raises(rs.RealmSyncError, match="permission report inputs"):
        rs.write_report_inputs(FakeRealm().call, tree, tmp_path / "config")
