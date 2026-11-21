"""papaia-ctl realm sync: client policies that the identity provider enforces.

- pair policies `papaia-one-aud-<x>-<y>`: a token exchange that asks for two `aud-*`
  scopes of one client is rejected (`reject-request`);
- `data-chain` / `data-handover`: Data re-exchanges only tokens of the declared upstream
  origins with exactly the audience `papaia-data`;
- person-only audiences: `client_credentials` is rejected and an exchange needs a
  subject token with `sid`;
- no `oidc-claims-param-token-mapper` on a managed client, and `flow-engine` (like every
  exchange client but the chain holder) is never an audience.

The same flows run against a real Keycloak in tests/test_realm_sync_policies_live.py.
"""

from __future__ import annotations

import json

import pytest

from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import REGISTER, _flow, _pairings, _paperless, _plan, _run, _studio

TE = "urn:ietf:params:oauth:grant-type:token-exchange"


def _data(**extra) -> rs.Module:
    entry = {
        "id": "data.api",
        "kind": "rest",
        "audience": "papaia-data",
        "identity": ["person"],
        "downstream": ["paperless.mcp"],
    }
    entry.update(extra)
    return rs.Module("papaia-data", [entry], {})


def _assist() -> rs.Module:
    return rs.Module(
        "papaia-assist",
        [{"id": "assist.api", "kind": "rest", "audience": "assist-api", "identity": ["person"]}],
        {},
    )


def _gateway_plan(*extra_pairings) -> rs.Plan:
    return _plan(
        [_studio(), _flow(), _paperless(), _data()],
        _pairings(
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"),
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            *extra_pairings,
        ),
    )


def _managed_policies(realm: FakeRealm) -> set[str]:
    return {p["name"] for p in realm.policies}


def _scopes_of(policy: dict) -> list[list[str]]:
    return [
        c["configuration"]["scopes"]
        for c in policy["conditions"]
        if c["condition"] == "client-scopes"
    ]


def _grants(policy: dict) -> list[str]:
    (grant,) = [c for c in policy["conditions"] if c["condition"] == "grant-type"]
    return grant["configuration"]["grant_types"]


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# pair policies: exactly one audience per exchange
# ─────────────────────────────────────────────────────────────────────────


def test_one_pair_policy_per_pair_of_exchange_scopes_of_a_client():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    pairs = sorted(n for n in _managed_policies(realm) if n.startswith("papaia-one-aud-"))
    # the gateway holds three aud-* scopes -> 3 pairs; papaia-data holds one -> none
    assert pairs == [
        "papaia-one-aud-flow-mcp-paperless",
        "papaia-one-aud-flow-papaia-data",
        "papaia-one-aud-mcp-paperless-papaia-data",
    ]
    policy = realm.policy("papaia-one-aud-flow-mcp-paperless")
    assert policy["enabled"] is True
    assert _grants(policy) == [TE]
    assert _scopes_of(policy) == [["aud-flow"], ["aud-mcp-paperless"]]
    assert all(
        c["configuration"]["type"] == "Optional"
        for c in policy["conditions"]
        if c["condition"] == "client-scopes"
    )
    (profile,) = policy["profiles"]
    assert realm.profile(profile)["executors"] == [
        {"executor": "reject-request", "configuration": {}}
    ]


def test_pair_policies_of_several_clients_are_merged_without_duplicates():
    realm = FakeRealm()
    plan = _gateway_plan(
        ("flow-engine", "mcp-paperless", ["r"], "confirmed"),
        ("flow-engine", "flow", ["x"], "confirmed"),
    )
    # flow-engine has no aud-flow pairing in the RS matrix; a confirmed one still pairs
    _run(realm, plan)
    names = [p["name"] for p in realm.policies if p["name"].startswith("papaia-one-aud-")]
    assert len(names) == len(set(names)) == 3


def test_no_profile_of_the_sync_uses_the_downscope_executor():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    executors = {
        e["executor"]
        for p in realm.profiles
        if p["name"] != rh.CLIENT_POLICY  # the realm hardening's own profile
        for e in p["executors"]
    }
    assert "downscope-assertion-grant-enforcer" not in executors
    assert executors == {"reject-request", "jwt-claim-enforcer"}


def test_a_revoked_pairing_removes_its_pair_policies_before_its_scope():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    revoked = _plan(
        [_studio(), _flow(), _paperless(), _data()],
        _pairings(
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "pending"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"),
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
        ),
    )
    realm.writes.clear()
    changes = _run(realm, revoked)
    assert {n for n in _managed_policies(realm) if n.startswith("papaia-one-aud-")} == {
        "papaia-one-aud-mcp-paperless-papaia-data"
    }
    assert "aud-flow" not in {s["name"] for s in realm.scopes.values()}
    order = [(c.kind, c.name) for c in changes]
    assert order.index(("client-policy", "papaia-one-aud-flow-papaia-data")) < order.index(
        ("client-scope", "aud-flow")
    )
    assert _run(realm, revoked) == []


def test_policies_name_only_scopes_that_exist_when_they_are_written():
    # FakeRealm refuses a policy naming a missing scope, like Keycloak (HTTP 400)
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    assert realm.policies


def test_the_second_run_reports_no_change_and_check_reports_none():
    realm = FakeRealm()
    plan = _gateway_plan()
    assert _run(realm, plan)
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_check_reports_a_missing_a_changed_and_an_extra_policy_without_writing(capsys):
    realm = FakeRealm()
    plan = _gateway_plan()
    _run(realm, plan)
    realm.policies = [p for p in realm.policies if p["name"] != "papaia-one-aud-flow-papaia-data"]
    realm.policy("data-chain")["enabled"] = False
    realm.policies.append(
        {
            "name": "papaia-one-aud-mcp-qdrant-papaia-data",
            "description": "",
            "enabled": True,
            "conditions": [],
            "profiles": [],
        }
    )
    realm.writes.clear()
    drift = _run(realm, plan, apply=False)
    assert realm.writes == []
    assert {(c.kind, c.name) for c in drift} == {
        ("client-policy", "papaia-one-aud-flow-papaia-data"),
        ("client-policy", "data-chain"),
        ("client-policy", "papaia-one-aud-mcp-qdrant-papaia-data"),
    }
    out = capsys.readouterr().out
    assert "fail: client-policy papaia-one-aud-flow-papaia-data: created" in out
    _run(realm, plan)
    assert _run(realm, plan, apply=False) == []


def test_a_policy_or_profile_the_sync_does_not_manage_is_left_alone():
    realm = FakeRealm()
    foreign_profile = {"name": "site-rule", "description": "", "executors": []}
    foreign = {
        "name": "site-rule",
        "description": "",
        "enabled": True,
        "conditions": [{"condition": "client-access-type", "configuration": {"type": ["public"]}}],
        "profiles": ["site-rule"],
    }
    realm.profiles = [dict(foreign_profile)]
    realm.policies = [dict(foreign)]
    plan = _gateway_plan()
    _run(realm, plan)
    assert realm.policy("site-rule") == foreign
    assert realm.profile("site-rule") == foreign_profile
    assert _run(realm, plan) == []


def test_a_profile_the_sync_no_longer_needs_is_removed_after_its_policies():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    # Studio alone: no Data, no pairing -> no managed policy, no managed profile
    plan = _plan([_studio()])
    changes = _run(realm, plan)
    # only the realm hardening's own profile and policy stay
    assert [p["name"] for p in realm.policies] == [rh.CLIENT_POLICY]
    assert [p["name"] for p in realm.profiles] == [rh.CLIENT_POLICY]
    kinds = [c.kind for c in changes if c.kind in ("client-policy", "client-profile")]
    last_policy = max(i for i, k in enumerate(kinds) if k == "client-policy")
    first_profile_removal = min(i for i, k in enumerate(kinds) if k == "client-profile")
    assert last_policy < first_profile_removal
    assert _run(realm, plan) == []


# ─────────────────────────────────────────────────────────────────────────
# chain exchange: Studio -> Data -> connection
# ─────────────────────────────────────────────────────────────────────────


def _executors(realm: FakeRealm, policy: str) -> list[dict]:
    return [e for p in realm.policy(policy)["profiles"] for e in realm.profile(p)["executors"]]


def test_data_chain_admits_only_studio_as_origin_and_a_single_data_audience():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    policy = realm.policy("data-chain")
    assert _grants(policy) == [TE]
    (holder,) = [c for c in policy["conditions"] if c["condition"] == "client-attributes"]
    assert json.loads(holder["configuration"]["attributes"]) == [
        {"key": "papaia.chain-holder", "value": "true"}
    ]
    assert not holder["configuration"].get("is-negative-logic")
    claims = {
        e["configuration"]["claim-name"]: e["configuration"]["allowed-value"]
        for e in _executors(realm, "data-chain")
    }
    assert claims == {"azp": "^papaia-studio-gateway$", "aud": "^papaia-data$"}
    assert {e["executor"] for e in _executors(realm, "data-chain")} == {"jwt-claim-enforcer"}


def test_upstream_origins_come_from_the_data_manifest():
    realm = FakeRealm()
    plan = _plan(
        [_studio(), _paperless(), _data(upstream_origins=["papaia-studio-gateway"])],
        _pairings(("papaia-data", "mcp-paperless", ["r"], "confirmed")),
    )
    _run(realm, plan)
    claims = {
        e["configuration"]["claim-name"]: e["configuration"]["allowed-value"]
        for e in _executors(realm, "data-chain")
    }
    assert claims["azp"] == "^papaia-studio-gateway$"


@pytest.mark.parametrize(
    ("origins", "message"),
    [
        (["assist-gate"], "not a chain origin"),
        (["flow-engine"], "not a chain origin"),
        (["papaia-data"], "Data client"),
        (["papaia-data-ui"], "Data client"),
        (["mcp-paperless"], "not a chain origin"),
        (["nobody"], "not a registered client"),
        ([], "at least one"),
        ("papaia-studio-gateway", "list"),
        (["papaia-studio-gateway", "papaia-studio-gateway"], "twice"),
    ],
)
def test_upstream_origins_outside_the_first_delivery_are_refused(origins, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan([_studio(), _data(upstream_origins=origins)])


def test_only_the_chain_holder_declares_downstream_or_upstream_origins():
    for key, value in (("downstream", ["paperless.mcp"]), ("upstream_origins", ["x"])):
        with pytest.raises(rs.RealmSyncError, match="chain holder"):
            _plan([_flow(**{key: value})])


def test_data_handover_needs_its_own_session_token_and_exists_only_with_its_scope():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    assert "data-handover" not in _managed_policies(realm)
    studio = _studio()
    studio.exposes.append(
        {"id": "studio.api", "kind": "rest", "audience": "papaia-studio", "identity": ["person"]}
    )
    plan = _plan(
        [studio, _flow(), _paperless(), _data()],
        _pairings(
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data", "papaia-studio", ["x"], "confirmed"),
        ),
    )
    _run(realm, plan)
    policy = realm.policy("data-handover")
    assert _grants(policy) == [TE]
    assert _scopes_of(policy) == [["aud-papaia-studio"]]
    claims = {
        e["configuration"]["claim-name"]: e["configuration"]["allowed-value"]
        for e in _executors(realm, "data-handover")
    }
    assert claims == {"azp": "^papaia-data-ui$"}
    assert _run(realm, plan) == []


def test_without_data_there_is_no_chain_policy():
    realm = FakeRealm()
    plan = _plan(
        [_studio(), _paperless()],
        _pairings(("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed")),
    )
    _run(realm, plan)
    assert not {"data-chain", "data-handover"} & _managed_policies(realm)


# ─────────────────────────────────────────────────────────────────────────
# person-only audiences
# ─────────────────────────────────────────────────────────────────────────


def test_a_person_only_audience_refuses_client_credentials_and_exchanges_without_sid():
    realm = FakeRealm()
    _run(realm, _gateway_plan())
    cc = realm.policy("papaia-person-papaia-data-client-credentials")
    assert _grants(cc) == ["client_credentials"]
    (scope,) = [c for c in cc["conditions"] if c["condition"] == "client-scopes"]
    assert scope["configuration"] == {"type": "Any", "scopes": ["aud-papaia-data"]}
    assert [e["executor"] for e in _executors(realm, cc["name"])] == ["reject-request"]

    te = realm.policy("papaia-person-papaia-data-exchange")
    assert _grants(te) == [TE]
    (scope,) = [c for c in te["conditions"] if c["condition"] == "client-scopes"]
    assert scope["configuration"] == {"type": "Any", "scopes": ["aud-papaia-data"]}
    assert _executors(realm, te["name"]) == [
        {
            "executor": "jwt-claim-enforcer",
            "configuration": {"claim-name": "sid", "allowed-value": ""},
        }
    ]


def test_flow_declared_for_person_and_service_gets_no_person_policy():
    realm = FakeRealm()
    plan = _plan(
        [_studio(), _flow(identity=["person", "service"])],
        _pairings(("papaia-studio-gateway", "flow", ["x"], "confirmed")),
    )
    _run(realm, plan)
    assert not [n for n in _managed_policies(realm) if n.startswith("papaia-person-")]


def test_a_module_api_for_me_and_the_knowledge_map_are_person_only():
    realm = FakeRealm()
    studio = _studio()
    studio.exposes.append(
        {"id": "studio.me", "kind": "me", "audience": "papaia-studio-me", "identity": ["person"]}
    )
    km = rs.Module(
        "papaia-knowledge-map",
        [{"id": "km.mcp", "kind": "mcp", "audience": "mcp-knowledge-map", "identity": ["person"]}],
        {},
    )
    plan = _plan(
        [studio, km],
        _pairings(
            ("papaia-me", "papaia-studio-me", ["x"], "confirmed"),
            ("papaia-studio-gateway", "mcp-knowledge-map", ["r"], "confirmed"),
        ),
    )
    _run(realm, plan)
    person = {n for n in _managed_policies(realm) if n.startswith("papaia-person-")}
    assert person == {
        "papaia-person-mcp-knowledge-map-client-credentials",
        "papaia-person-mcp-knowledge-map-exchange",
    }
    # papaia-me is not installed, so its pairing assigns nothing and names no scope yet


@pytest.mark.parametrize(
    "module",
    [
        lambda: _data(identity=["person", "service"]),
        lambda: rs.Module(
            "papaia-knowledge-map",
            [{"id": "km", "kind": "mcp", "audience": "mcp-knowledge-map", "identity": ["service"]}],
            {},
        ),
        lambda: rs.Module(
            "papaia-studio",
            [{"id": "s.me", "kind": "me", "audience": "papaia-studio-me", "identity": ["service"]}],
            {},
        ),
    ],
)
def test_a_person_only_audience_declared_for_services_is_refused(module):
    with pytest.raises(rs.RealmSyncError, match="person"):
        _plan([module()])


@pytest.mark.parametrize(
    "identity",
    [[], ["person", "person"], ["robot"], "person", None],
)
def test_a_malformed_identity_is_refused(identity):
    with pytest.raises(rs.RealmSyncError, match="identity"):
        _plan([_flow(identity=identity)])


# ─────────────────────────────────────────────────────────────────────────
# mappers and audiences that must not exist
# ─────────────────────────────────────────────────────────────────────────


def _claims_param_mapper() -> dict:
    return {
        "name": "claims parameter",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-claims-param-token-mapper",
        "config": {"userinfo.token.claim": "true", "id.token.claim": "true"},
    }


def test_a_claims_parameter_mapper_on_a_managed_client_is_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _gateway_plan()
    _run(realm, plan)
    realm.call(
        "POST",
        f"/clients/{realm.by_client_id('papaia-studio-gateway')['id']}/protocol-mappers/models",
        _claims_param_mapper(),
    )
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "papaia-studio-gateway")]
    assert "claims" in drift[0].action
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert row["event"] == "exchange_right_changed"
    assert row["effect"] == "delete"
    assert not realm.by_client_id("papaia-studio-gateway")["protocolMappers"]
    assert _run(realm, plan, apply=False) == []


def test_a_claims_parameter_mapper_on_a_shared_scope_is_reported_and_removed():
    realm = FakeRealm()
    plan = _gateway_plan()
    _run(realm, plan)
    profile = realm.scope_by_name("profile")
    realm.call(
        "POST", f"/client-scopes/{profile['id']}/protocol-mappers/models", _claims_param_mapper()
    )
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client-scope", "profile")]
    _run(realm, plan)
    assert not realm.scope_by_name("profile")["protocolMappers"]


def _audience_mapper(audience: str) -> dict:
    return {
        "name": f"audience {audience}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": audience, "access.token.claim": "true"},
    }


def test_flow_engine_is_never_an_audience_scope_or_mapper(tmp_path):
    realm = FakeRealm()
    plan = _gateway_plan()
    _run(realm, plan)
    # a scope aud-flow-engine (for example from a module's own setup) ...
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-flow-engine",
            "protocol": "openid-connect",
            "protocolMappers": [_audience_mapper("flow-engine")],
        },
    )
    # ... an audience mapper on another scope and on an unmanaged client
    email = realm.scope_by_name("microprofile-jwt")
    realm.call(
        "POST",
        f"/client-scopes/{email['id']}/protocol-mappers/models",
        _audience_mapper("assist-gate"),
    )
    realm.call("POST", "/clients", {"clientId": "librechat", "publicClient": False})
    librechat = realm.by_client_id("librechat")
    realm.call(
        "POST",
        f"/clients/{librechat['id']}/protocol-mappers/models",
        _audience_mapper("flow-engine"),
    )
    # LibreChat's fixed audience mappers on resource servers stay
    realm.call(
        "POST",
        f"/clients/{librechat['id']}/protocol-mappers/models",
        _audience_mapper("mcp-paperless"),
    )

    drift = _run(realm, plan, apply=False)
    assert {(c.kind, c.name) for c in drift} >= {
        ("client-scope", "aud-flow-engine"),
        ("client-scope", "microprofile-jwt"),
        ("client", "librechat"),
    }
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    assert "aud-flow-engine" not in {s["name"] for s in realm.scopes.values()}
    assert not realm.scope_by_name("microprofile-jwt")["protocolMappers"]
    remaining = realm.by_client_id("librechat")["protocolMappers"]
    assert [m["config"]["included.client.audience"] for m in remaining] == ["mcp-paperless"]
    # the realm hardening of the bare client is a row of its own
    rows = _rows(tmp_path / "audit.jsonl")
    rows = [r for r in rows if r["operation"] != "realm_sync.harden_client"]
    assert all(r["event"] == "exchange_right_changed" for r in rows)
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def test_every_policy_change_is_one_audit_row_and_one_write(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, _gateway_plan(), audit=audit)
    rows = _rows(tmp_path / "audit.jsonl")
    assert len(rows) == len(realm.writes)
    policy_rows = [
        r for r in rows if r["object_ref"]["type"] in ("client_policy", "client_profile")
    ]
    assert {r["object_ref"]["id"] for r in policy_rows} >= {
        "papaia-one-aud-flow-mcp-paperless",
        "data-chain",
        "papaia-person-papaia-data-exchange",
        "papaia-reject",
    }
    assert all(r["event"] == "exchange_right_changed" for r in policy_rows)
    assert all(r["correlation_id"] == "run-1" for r in policy_rows)
    assert "eyJ" not in (tmp_path / "audit.jsonl").read_text()


def test_a_refused_policy_write_is_audited_as_an_error(tmp_path):
    realm = FakeRealm()

    def refusing(method, path, body=None):
        if method == "PUT" and path == "/client-policies/policies":
            raise rs.urllib.error.HTTPError(path, 400, "Bad Request", {}, None)
        return realm.call(method, path, body)

    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        with pytest.raises(rs.urllib.error.HTTPError):
            rs.reconcile(refusing, _gateway_plan(), apply=True, audit=audit)
    last = _rows(tmp_path / "audit.jsonl")[-1]
    assert last["object_ref"]["type"] == "client_policy"
    assert (last["result"], last["error_code"]) == ("error", "http_400")


def test_the_registered_exchange_clients_are_never_audiences():
    plan = _gateway_plan()
    assert "flow-engine" in plan.never_audiences
    assert "assist-gate" in plan.never_audiences
    assert rs.CHAIN_HOLDER not in plan.never_audiences
    assert plan.never_audiences == REGISTER.exchange_clients() - {rs.CHAIN_HOLDER}
