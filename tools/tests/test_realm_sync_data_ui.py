"""papaia-ctl realm sync: Data's own interface client and the chain holder.

- `papaia-data-ui` signs persons in for Data's own interface: confidential, client
  authentication `private_key_jwt`, code flow, token exchange only for its own tokens,
  never an audience, no `offline_access`, no `aud-*` default scope;
- `data-self`: every exchange of a Data client that is not the chain holder admits only a
  subject token of `papaia-data-ui` that carries no exchange scope yet (one hop);
- `data-handover`: the handover to Studio only with that session token;
- `data-chain` names the chain holder by the client attribute `papaia.chain-holder=true`,
  which the sync sets on `papaia-data` alone and removes from every other client.

The same flows run against a real Keycloak in tests/test_realm_sync_data_ui_live.py.
"""

from __future__ import annotations

import json
import re

import pytest

from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import _flow, _pairings, _paperless, _plan, _run, _studio
from tests.test_realm_sync_policies import _data

TE = "urn:ietf:params:oauth:grant-type:token-exchange"
HOLDER = {"key": "papaia.chain-holder", "value": "true"}


def _studio_with_handover() -> rs.Module:
    studio = _studio()
    studio.exposes.append(
        {"id": "studio.api", "kind": "rest", "audience": "papaia-studio", "identity": ["person"]}
    )
    return studio


def _full_plan() -> rs.Plan:
    return _plan(
        [_studio_with_handover(), _flow(), _paperless(), _data()],
        _pairings(
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"),
            ("papaia-data", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data-ui", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-data-ui", "papaia-studio", ["x"], "confirmed"),
        ),
    )


def _attributes(condition: dict) -> list[dict]:
    return json.loads(condition["configuration"]["attributes"])


def _conditions(policy: dict, kind: str) -> list[dict]:
    return [c for c in policy["conditions"] if c["condition"] == kind]


def _claims(realm: FakeRealm, policy: str) -> dict[str, str]:
    executors = [e for p in realm.policy(policy)["profiles"] for e in realm.profile(p)["executors"]]
    assert {e["executor"] for e in executors} == {"jwt-claim-enforcer"}
    return {
        e["configuration"]["claim-name"]: e["configuration"]["allowed-value"] for e in executors
    }


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# the client papaia-data-ui
# ─────────────────────────────────────────────────────────────────────────


def test_data_ui_is_a_confidential_sign_in_client_with_private_key_jwt():
    realm = FakeRealm()
    _run(realm, _full_plan())
    ui = realm.by_client_id("papaia-data-ui")
    assert ui["clientAuthenticatorType"] == "client-jwt"
    assert ui["publicClient"] is False
    assert ui["bearerOnly"] is False
    assert ui["standardFlowEnabled"] is True
    assert ui["implicitFlowEnabled"] is False
    assert ui["directAccessGrantsEnabled"] is False
    assert ui["serviceAccountsEnabled"] is False
    assert ui["fullScopeAllowed"] is False
    assert ui["attributes"]["standard.token.exchange.enabled"] == "true"
    assert ui["attributes"]["pkce.code.challenge.method"] == "S256"
    assert ui["attributes"]["papaia.owner"] == "data"


def test_data_ui_has_no_offline_access_and_no_exchange_scope_as_default():
    realm = FakeRealm()
    _run(realm, _full_plan())
    default = realm.scope_names("papaia-data-ui", "default")
    optional = realm.scope_names("papaia-data-ui", "optional")
    assert not [s for s in default if s.startswith("aud-")]
    assert "offline_access" not in default | optional
    assert optional == {"aud-mcp-paperless", "aud-papaia-studio"}


def test_data_ui_is_never_an_audience_and_carries_no_chain_holder_mark():
    plan = _full_plan()
    assert "papaia-data-ui" in plan.never_audiences
    realm = FakeRealm()
    _run(realm, plan)
    assert "aud-papaia-data-ui" not in {s["name"] for s in realm.scopes.values()}
    assert "papaia.chain-holder" not in realm.by_client_id("papaia-data-ui")["attributes"]


def test_the_chain_holder_and_only_it_carries_the_mark():
    realm = FakeRealm()
    _run(realm, _full_plan())
    assert realm.by_client_id("papaia-data")["attributes"]["papaia.chain-holder"] == "true"
    marked = sorted(
        c["clientId"]
        for c in realm.clients.values()
        if "papaia.chain-holder" in (c.get("attributes") or {})
    )
    assert marked == ["papaia-data"]


def test_a_client_secret_on_data_ui_is_switched_to_private_key_jwt():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.by_client_id("papaia-data-ui")["clientAuthenticatorType"] = "client-secret"
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "papaia-data-ui")]
    assert "clientAuthenticatorType" in drift[0].action
    _run(realm, plan)
    assert realm.by_client_id("papaia-data-ui")["clientAuthenticatorType"] == "client-jwt"
    assert _run(realm, plan) == []


def test_offline_access_added_to_data_ui_by_hand_is_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    ui = realm.by_client_id("papaia-data-ui")
    ui["_optional"].append(realm.scope_by_name("offline_access")["id"])
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name, c.action) for c in drift] == [
        ("client", "papaia-data-ui", "optional scope offline_access removed")
    ]
    _run(realm, plan)
    assert "offline_access" not in realm.scope_names("papaia-data-ui", "optional")


# ─────────────────────────────────────────────────────────────────────────
# policies: data-chain, data-self, data-handover
# ─────────────────────────────────────────────────────────────────────────


def test_data_chain_names_the_holder_by_its_attribute_without_a_negative_condition():
    realm = FakeRealm()
    _run(realm, _full_plan())
    policy = realm.policy("data-chain")
    (grant,) = _conditions(policy, "grant-type")
    assert grant["configuration"]["grant_types"] == [TE]
    (holder,) = _conditions(policy, "client-attributes")
    assert _attributes(holder) == [HOLDER]
    assert not holder["configuration"].get("is-negative-logic")
    assert not _conditions(policy, "client-scopes")
    assert {c["condition"] for c in policy["conditions"]} == {"grant-type", "client-attributes"}
    assert _claims(realm, "data-chain") == {
        "azp": "^papaia-studio-gateway$",
        "aud": "^papaia-data$",
    }


def test_data_self_admits_only_the_own_session_token_of_data_ui():
    realm = FakeRealm()
    _run(realm, _full_plan())
    policy = realm.policy("data-self")
    (grant,) = _conditions(policy, "grant-type")
    assert grant["configuration"]["grant_types"] == [TE]
    owner, holder = _conditions(policy, "client-attributes")
    assert _attributes(owner) == [{"key": "papaia.owner", "value": "data"}]
    assert not owner["configuration"].get("is-negative-logic")
    # every Data client but the chain holder: the holder is named, never a scope
    assert _attributes(holder) == [HOLDER]
    assert holder["configuration"]["is-negative-logic"] is True
    assert not _conditions(policy, "client-scopes")
    claims = _claims(realm, "data-self")
    assert claims["azp"] == "^papaia-data-ui$"
    # one hop: a token that already carries an exchange scope is no subject token
    assert set(claims) == {"azp", "scope"}


@pytest.mark.parametrize(
    ("scope", "admitted"),
    [
        ("openid profile email", True),
        ("openid email profile", True),
        ("profile aud-mcp-paperless email", False),
        ("aud-papaia-studio", False),
        ("openid aud-mcp-qdrant", False),
    ],
)
def test_the_one_hop_pattern_refuses_every_exchanged_token(scope, admitted):
    realm = FakeRealm()
    _run(realm, _full_plan())
    pattern = _claims(realm, "data-self")["scope"]
    # jwt-claim-enforcer matches the whole value (Java Pattern.matches)
    assert bool(re.fullmatch(pattern, scope)) is admitted


def test_data_handover_holds_for_the_studio_scope_with_the_ui_session_token():
    realm = FakeRealm()
    _run(realm, _full_plan())
    policy = realm.policy("data-handover")
    (scope,) = _conditions(policy, "client-scopes")
    assert scope["configuration"] == {"type": "Optional", "scopes": ["aud-papaia-studio"]}
    assert _claims(realm, "data-handover") == {"azp": "^papaia-data-ui$"}


def test_data_self_exists_while_data_is_installed_without_any_pairing():
    realm = FakeRealm()
    _run(realm, _plan([_studio(), _data()]))
    assert {"data-chain", "data-self"} <= {p["name"] for p in realm.policies}
    realm2 = FakeRealm()
    _run(realm2, _plan([_studio()]))
    assert not {"data-chain", "data-self", "data-handover"} & {p["name"] for p in realm2.policies}


def test_a_profile_tampered_to_name_a_data_client_as_origin_is_corrected():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.profile("data-chain")["executors"][0]["configuration"]["allowed-value"] = (
        "^(papaia-studio-gateway|papaia-data-ui)$"
    )
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client-profile", "data-chain")]
    _run(realm, plan)
    assert _claims(realm, "data-chain")["azp"] == "^papaia-studio-gateway$"


@pytest.mark.parametrize("origin", ["papaia-data", "papaia-data-ui"])
def test_a_data_client_as_upstream_origin_is_refused(origin):
    with pytest.raises(rs.RealmSyncError, match="Data client"):
        _plan([_studio(), _data(upstream_origins=["papaia-studio-gateway", origin])])


# ─────────────────────────────────────────────────────────────────────────
# the chain-holder mark on any other client
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("client_id", ["papaia-data-ui", "papaia-studio-gateway", "librechat"])
def test_the_mark_on_another_client_fails_the_check_and_is_removed(client_id, tmp_path, capsys):
    realm = FakeRealm()
    plan = _full_plan()
    if client_id == "librechat":
        realm.call("POST", "/clients", {"clientId": "librechat", "publicClient": False})
    _run(realm, plan)
    realm.by_client_id(client_id)["attributes"]["papaia.chain-holder"] = "true"
    realm.writes.clear()
    capsys.readouterr()
    drift = _run(realm, plan, apply=False)
    assert realm.writes == []
    assert [(c.kind, c.name) for c in drift] == [("client", client_id)]
    assert "papaia.chain-holder" in drift[0].action
    assert f"fail: client {client_id}:" in capsys.readouterr().out
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert row["event"] == "exchange_right_changed"
    assert row["correlation_id"] == "run-1"
    assert "papaia.chain-holder" not in realm.by_client_id(client_id)["attributes"]
    assert realm.by_client_id("papaia-data")["attributes"]["papaia.chain-holder"] == "true"
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_any_value_of_the_mark_on_another_client_is_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.by_client_id("papaia-data-ui")["attributes"]["papaia.chain-holder"] = "TRUE"
    assert [(c.kind, c.name) for c in _run(realm, plan)] == [("client", "papaia-data-ui")]
    assert "papaia.chain-holder" not in realm.by_client_id("papaia-data-ui")["attributes"]


def test_the_mark_is_removed_from_every_client_when_data_is_not_installed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    without_data = _plan([_studio()])
    _run(realm, without_data)
    # the holder's client stays (left in place, see the warning), but loses the mark
    assert "papaia.chain-holder" not in realm.by_client_id("papaia-data")["attributes"]
    assert _run(realm, without_data) == []


def test_another_value_of_the_mark_on_the_holder_is_corrected():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.by_client_id("papaia-data")["attributes"]["papaia.chain-holder"] = "false"
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client", "papaia-data")]
    _run(realm, plan)
    assert realm.by_client_id("papaia-data")["attributes"]["papaia.chain-holder"] == "true"


def test_the_second_run_reports_no_change():
    realm = FakeRealm()
    plan = _full_plan()
    assert _run(realm, plan)
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []
