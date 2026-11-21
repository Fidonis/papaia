"""papaia-ctl realm sync: clients, roles and exchange scopes from declarations.

The sync runs against an in-memory Admin API (tests/realm_fake.py); the same flows run
against a real Keycloak in tests/test_realm_sync_live.py.
"""

from __future__ import annotations

import json
import subprocess

import pytest
import yaml

from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_ctl_standalone_commands import BASH, CTL, _call, _seeded, needs_bash

REGISTER = rs.load_register()


def _flow(**extra) -> rs.Module:
    entry = {
        "id": "flow.runs",
        "kind": "rest",
        "audience": "flow",
        "identity": ["person"],
        "roles": [{"name": "flow-member"}, {"name": "flow-admin"}],
    }
    entry.update(extra)
    return rs.Module("papaia-flow", [entry], {})


def _studio() -> rs.Module:
    return rs.Module(
        "papaia-studio",
        [
            {
                "id": "studio.ui",
                "kind": "ui",
                "identity": ["person"],
                "ui": [{"id": "studio", "visible_for_roles": ["studio-member"]}],
                "roles": [{"name": "studio-member"}, {"name": "studio-admin"}],
            }
        ],
        {},
    )


def _paperless() -> rs.Module:
    return rs.Module(
        "paperless",
        [{"id": "paperless.mcp", "kind": "mcp", "audience": "mcp-paperless"}],
        {},
    )


def _pairings(*rows) -> list[rs.Pairing]:
    doc = {
        "format": "papaia.pairings/1",
        "pairings": [{"client": c, "audience": a, "effects": e, "state": s} for c, a, e, s in rows],
    }
    return rs.parse_pairings(doc, REGISTER)


def _plan(modules, pairings=()) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), list(pairings))


def _run(realm: FakeRealm, plan: rs.Plan, *, apply=True, audit=None) -> list[rs.Change]:
    return rs.reconcile(realm.call, plan, apply=apply, audit=audit)


DELEGATION = {"purposes": ["flow.run"], "max_idle_days": 30, "max_age_days": 180}


# ─────────────────────────────────────────────────────────────────────────
# register snapshot
# ─────────────────────────────────────────────────────────────────────────


def test_the_register_snapshot_names_the_kit_release_it_was_taken_from():
    data = json.loads(rs.REGISTER_PATH.read_text(encoding="utf-8"))
    assert data["format"] == "papaia.names-register-snapshot/1"
    assert data["source"]["package"] == "papaia-kit"
    assert len(data["source"]["commit"]) == 40


def test_the_register_knows_exchange_clients_audiences_and_removed_names():
    assert REGISTER.clients["flow-engine"].token_exchange
    assert not REGISTER.clients["flow"].token_exchange
    assert REGISTER.clients["flow"].owner == "papaia-flow"
    assert "mcp-paperless" in REGISTER.audiences
    assert REGISTER.successor("wiki-mcp") == "mcp-wiki"
    assert "papaia-kit-testclient" not in REGISTER.product_clients()


# ─────────────────────────────────────────────────────────────────────────
# pairings.yaml at the boundary
# ─────────────────────────────────────────────────────────────────────────


def test_pairings_are_read_from_the_security_directory(tmp_path):
    path = tmp_path / "security" / "pairings.yaml"
    path.parent.mkdir()
    path.write_text(
        yaml.safe_dump(
            {
                "format": "papaia.pairings/1",
                "pairings": [
                    {
                        "client": "flow-engine",
                        "audience": "mcp-paperless",
                        "effects": ["r", "w"],
                        "state": "confirmed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (pairing,) = rs.load_pairings(rs.pairings_path(tmp_path), REGISTER)
    assert (pairing.client, pairing.audience, pairing.effects, pairing.confirmed) == (
        "flow-engine",
        "mcp-paperless",
        ("r", "w"),
        True,
    )


def test_a_missing_pairings_file_pairs_nothing(tmp_path):
    assert rs.load_pairings(rs.pairings_path(tmp_path), REGISTER) == []


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ({"format": "papaia.pairings/1", "pairings": [], "extra": 1}, "unknown field"),
        ({"format": "papaia.pairings/2", "pairings": []}, "format"),
        ({"format": "papaia.pairings/1", "pairings": {}}, "list"),
        (
            {
                "format": "papaia.pairings/1",
                "pairings": [
                    {
                        "client": "flow-engine",
                        "audience": "mcp-paperless",
                        "effects": ["r"],
                        "state": "confirmed",
                        "note": "x",
                    }
                ],
            },
            "unknown field",
        ),
    ],
)
def test_the_pairings_file_rejects_unknown_fields_and_shapes(doc, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        rs.parse_pairings(doc, REGISTER)


@pytest.mark.parametrize(
    ("client", "audience", "effects", "state", "message"),
    [
        ("flow-enginex", "mcp-paperless", ["r"], "confirmed", "not a registered client"),
        ("librechat", "mcp-paperless", ["r"], "confirmed", "no token exchange"),
        ("papaia-kit-testclient", "mcp-paperless", ["r"], "confirmed", "test profile"),
        ("flow-engine", "wiki-mcp", ["r"], "confirmed", "use 'mcp-wiki'"),
        ("flow-engine", "data", ["r"], "confirmed", "use 'papaia-data'"),
        ("flow-engine", "mcp-nothing", ["r"], "confirmed", "not a registered audience"),
        ("papaia-me", "flow-engine", ["x"], "confirmed", "not a registered audience"),
        ("flow-engine", "mcp-paperless", [], "confirmed", "effects"),
        ("flow-engine", "mcp-paperless", ["r", "r"], "confirmed", "effects"),
        ("flow-engine", "mcp-paperless", ["read"], "confirmed", "effects"),
        ("flow-engine", "mcp-paperless", ["r"], "approved", "state"),
        ("flow-engine", "mcp-paperless", "r", "confirmed", "effects"),
        ("flow-engine", "x" * 300, ["r"], "confirmed", "audience"),
    ],
)
def test_each_pairing_is_checked_against_the_register(client, audience, effects, state, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _pairings((client, audience, effects, state))


def test_a_pairing_listed_twice_is_rejected():
    with pytest.raises(rs.RealmSyncError, match="twice"):
        _pairings(
            ("flow-engine", "mcp-paperless", ["r"], "confirmed"),
            ("flow-engine", "mcp-paperless", ["r", "w"], "pending"),
        )


def test_the_chain_holder_is_the_only_exchange_client_that_is_an_audience():
    (pairing,) = _pairings(("papaia-studio-gateway", "papaia-data", ["r", "x"], "confirmed"))
    assert pairing.audience == "papaia-data"


def test_more_than_twelve_confirmed_exchange_scopes_per_client_stop_the_sync():
    audiences = sorted(REGISTER.audiences - REGISTER.exchange_clients())[:13]
    assert len(audiences) == 13
    with pytest.raises(rs.RealmSyncError, match="at most 12"):
        _pairings(*[("papaia-me", a, ["x"], "confirmed") for a in audiences])
    # twelve confirmed and one waiting for approval are fine
    rows = [("papaia-me", a, ["x"], "confirmed") for a in audiences[:12]]
    rows.append(("papaia-me", audiences[12], ["x"], "pending"))
    assert len(_pairings(*rows)) == 13


# ─────────────────────────────────────────────────────────────────────────
# declarations of the installed modules
# ─────────────────────────────────────────────────────────────────────────


def test_modules_are_the_active_addons_with_an_exposes_section(tmp_path):
    repo_root = tmp_path / "repo"
    config_dir = tmp_path / "config"
    for name, manifest in (
        ("papaia-flow", {"name": "papaia-flow", "exposes": [{"id": "flow.runs", "kind": "rest"}]}),
        ("old", {"name": "old"}),
        ("gone", {"name": "gone", "exposes": [{"id": "gone.ui", "kind": "ui"}]}),
    ):
        (repo_root / name).mkdir(parents=True)
        (repo_root / name / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    (config_dir / "addons" / "papaia-flow").mkdir(parents=True)
    (config_dir / "addons" / "papaia-flow" / ".env").write_text("OWNER_SUB=anna\n")
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump(
            {
                "addons": [
                    {"name": "papaia-flow", "path": str(repo_root / "papaia-flow"), "active": True},
                    {"name": "old", "path": str(repo_root / "old"), "active": True},
                    {"name": "gone", "path": str(repo_root / "gone"), "active": False},
                ]
            }
        )
    )
    (module,) = rs.load_modules(config_dir, repo_root)
    assert module.name == "papaia-flow"
    assert module.install_input == {"OWNER_SUB": "anna"}


def test_an_exposes_section_that_is_not_a_list_is_rejected():
    with pytest.raises(rs.RealmSyncError, match="exposes"):
        _plan([rs.Module("papaia-flow", {"id": "x"}, {})])


@pytest.mark.parametrize(
    ("roles", "message"),
    [
        ([{"name": "studio-member"}], "belongs to papaia-studio"),
        ([{"name": "flow-wizard"}], "not a registered role"),
        ([{"name": "flow-member", "grants": "all"}], "unknown field"),
        (["flow-member"], "mapping"),
    ],
)
def test_a_module_declares_only_its_own_registered_roles(roles, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan([_flow(roles=roles)])


def test_a_role_in_visible_for_roles_must_be_registered():
    module = _studio()
    module.exposes[0]["ui"][0]["visible_for_roles"] = ["studio-chief"]
    with pytest.raises(rs.RealmSyncError, match="studio-chief"):
        _plan([module])


def test_the_owner_of_a_module_is_its_manifest_name():
    plan = _plan([_flow(), _paperless()])
    flow_clients = {c for c, spec in plan.clients.items() if spec.owner == "papaia-flow"}
    assert flow_clients == {
        "flow",
        "flow-engine",
        "flow-console",
        "flow-cli",
        "papaia-flow-mcp-chat",
    }
    # an add-on outside the register brings only the resource server of its audience
    assert plan.clients["mcp-paperless"].kind == "bearer"
    assert plan.clients["mcp-paperless"].owner == "paperless"
    assert not any(c.startswith("papaia-studio") for c in plan.clients)


def test_core_clients_of_the_realm_template_are_not_managed():
    plan = _plan([_flow()])
    assert "librechat" not in plan.clients
    assert "papaia-audit" not in plan.clients


# ─────────────────────────────────────────────────────────────────────────
# delegation and offline_access (KIT-002)
# ─────────────────────────────────────────────────────────────────────────


def test_offline_access_follows_the_delegation_of_the_holder():
    without = _plan([_flow()])
    assert "offline_access" not in without.clients["flow-engine"].optional_scopes
    plan = _plan([_flow(delegation=DELEGATION)])
    assert "offline_access" in plan.clients["flow-engine"].optional_scopes
    holders = {c for c, spec in plan.clients.items() if "offline_access" in spec.optional_scopes}
    assert holders == {"flow-engine"}


def test_an_addon_manifest_that_declares_a_delegation_is_rejected_without_a_realm_change():
    realm = FakeRealm()
    addon = rs.Module(
        "papaia-studio",
        [{"id": "studio.ui", "kind": "ui", "delegation": {"purposes": ["flow.run"]}}],
        {},
    )
    with pytest.raises(rs.RealmSyncError, match="delegation"):
        _run(realm, _plan([addon]))
    assert realm.writes == []


def test_a_flow_manifest_with_a_purpose_of_the_assistant_is_rejected():
    realm = FakeRealm()
    delegation = dict(DELEGATION, purposes=["flow.run", "assist.tools"])
    with pytest.raises(rs.RealmSyncError, match="assist.tools"):
        _run(realm, _plan([_flow(delegation=delegation)]))
    assert realm.writes == []


@pytest.mark.parametrize(
    "delegation",
    [
        {"purposes": ["flow.fly"]},
        {"purposes": []},
        {"purposes": ["flow.run"], "max_idle_days": 31},
        {"purposes": ["flow.run"], "max_idle_days": 30, "max_age_days": 20},
        {"purposes": ["flow.run"], "max_age_days": 181},
        {"purposes": ["flow.run"], "holder": "flow-console"},
    ],
)
def test_a_malformed_delegation_is_rejected(delegation):
    with pytest.raises(rs.RealmSyncError, match="delegation"):
        _plan([_flow(delegation=delegation)])


def test_after_a_sync_only_the_holders_have_offline_access():
    realm = FakeRealm()
    assist = rs.Module(
        "papaia-assist",
        [
            {
                "id": "assist.api",
                "kind": "rest",
                "audience": "assist-api",
                "delegation": {"purposes": ["assist.tools"]},
            }
        ],
        {},
    )
    _run(realm, _plan([_flow(delegation=DELEGATION), assist, _studio()]))
    holders = {
        c["clientId"]
        for c in realm.clients.values()
        if not c["bearerOnly"]
        and "offline_access"
        in realm.scope_names(c["clientId"], "default")
        | realm.scope_names(c["clientId"], "optional")
    }
    assert holders == {"flow-engine", "assist-gate"}
    assert realm.default_optional == [
        i for i in realm.default_optional if realm.scopes[i]["name"] != "offline_access"
    ]
    assert "offline_access" not in {realm.scopes[i]["name"] for i in realm.default_optional}


# ─────────────────────────────────────────────────────────────────────────
# service account placeholders (KIT-002, E-43)
# ─────────────────────────────────────────────────────────────────────────


def _with_account(owner: str, deputy: str, install_input: dict) -> rs.Module:
    module = _flow(
        service_accounts=[
            {
                "id": "svc-flow-events",
                "purpose": {"en": "Event runs"},
                "owner_sub": owner,
                "deputy_sub": deputy,
                "audiences": ["mcp-paperless"],
                "effects": ["read"],
                "credential": "private_key_jwt",
            }
        ]
    )
    module.install_input.update(install_input)
    return module


def test_an_unresolved_owner_placeholder_is_rejected_without_a_realm_change():
    realm = FakeRealm()
    module = _with_account("${FLOW_OWNER}", "${FLOW_DEPUTY}", {"FLOW_DEPUTY": "dora"})
    with pytest.raises(rs.RealmSyncError, match="FLOW_OWNER"):
        _run(realm, _plan([module]))
    assert realm.writes == []


@pytest.mark.parametrize("value", ["", "CHANGE_ME", "GENERATE_FLOW_OWNER"])
def test_a_placeholder_value_still_counts_as_unresolved(value):
    module = _with_account("${FLOW_OWNER}", "dora", {"FLOW_OWNER": value})
    with pytest.raises(rs.RealmSyncError, match="FLOW_OWNER"):
        _plan([module])


def test_owner_and_deputy_resolving_to_the_same_person_are_rejected():
    realm = FakeRealm()
    module = _with_account("${FLOW_OWNER}", "anna", {"FLOW_OWNER": "anna"})
    with pytest.raises(rs.RealmSyncError, match="same person"):
        _run(realm, _plan([module]))
    assert realm.writes == []


def test_resolved_owner_and_deputy_pass():
    module = _with_account(
        "${FLOW_OWNER}", "${FLOW_DEPUTY}", {"FLOW_OWNER": "anna", "FLOW_DEPUTY": "dora"}
    )
    assert _plan([module]).clients["flow-engine"]


def test_a_service_account_outside_the_register_rule_is_rejected():
    module = _with_account("anna", "dora", {})
    module.exposes[0]["service_accounts"][0]["id"] = "svc-flow-prefs"
    with pytest.raises(rs.RealmSyncError, match="svc-flow-notify"):
        _plan([module])


# ─────────────────────────────────────────────────────────────────────────
# reconcile against the Admin API
# ─────────────────────────────────────────────────────────────────────────


def _full_plan() -> rs.Plan:
    return _plan(
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(
            ("flow-engine", "mcp-paperless", ["r", "w", "d"], "confirmed"),
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
            ("flow-engine", "mcp-qdrant", ["r"], "confirmed"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "pending"),
        ),
    )


def test_the_first_run_creates_and_the_second_run_reports_no_change():
    realm = FakeRealm()
    plan = _full_plan()
    first = _run(realm, plan)
    assert first
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_managed_clients_carry_the_fixed_attribute_and_no_full_scope():
    realm = FakeRealm()
    _run(realm, _full_plan())
    for client_id in ("flow", "flow-engine", "papaia-studio-gateway", "mcp-paperless"):
        client = realm.by_client_id(client_id)
        assert client["attributes"]["papaia.managed"] == "true"
        assert client["fullScopeAllowed"] is False
        assert client["implicitFlowEnabled"] is False
        assert client["directAccessGrantsEnabled"] is False
    engine = realm.by_client_id("flow-engine")
    assert engine["attributes"]["standard.token.exchange.enabled"] == "true"
    assert engine["attributes"]["papaia.owner"] == "flow"
    assert engine["attributes"]["pkce.code.challenge.method"] == "S256"
    api = realm.by_client_id("flow")
    assert api["bearerOnly"] is True
    assert api["attributes"]["standard.token.exchange.enabled"] == "false"
    cli = realm.by_client_id("flow-cli")
    assert cli["publicClient"] is True
    assert cli["attributes"]["standard.token.exchange.enabled"] == "false"


def test_optional_scopes_are_exactly_the_confirmed_pairings_of_installed_audiences():
    realm = FakeRealm()
    _run(realm, _full_plan())
    assert realm.scope_names("flow-engine", "optional") == {"aud-mcp-paperless", "offline_access"}
    assert realm.scope_names("papaia-studio-gateway", "optional") == {
        "aud-mcp-paperless",
        "aud-flow",
    }
    # pending pairing: no scope at all; mcp-qdrant is not installed: no scope either
    names = {s["name"] for s in realm.scopes.values()}
    assert "aud-papaia-data" not in names
    assert "aud-mcp-qdrant" not in names
    for client_id in ("flow-engine", "papaia-studio-gateway"):
        assert not {n for n in realm.scope_names(client_id, "default") if n.startswith("aud-")}


def test_each_exchange_scope_has_exactly_one_audience_mapper():
    realm = FakeRealm()
    _run(realm, _full_plan())
    scope = next(s for s in realm.scopes.values() if s["name"] == "aud-mcp-paperless")
    (mapper,) = scope["protocolMappers"]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.client.audience"] == "mcp-paperless"
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["id.token.claim"] == "false"
    assert scope["attributes"]["papaia.managed"] == "true"


def test_module_and_platform_roles_are_created_and_admins_join_papaia_admin():
    realm = FakeRealm()
    _run(realm, _full_plan())
    for role in ("flow-member", "flow-admin", "studio-member", "studio-admin"):
        assert realm.roles[role]["attributes"]["papaia.managed"] == ["true"]
    for role in ("papaia-admin", "papaia-auditor", "papaia-confirm"):
        assert role in realm.roles
    assert realm.roles["papaia-admin"]["_composites"] == {"flow-admin", "studio-admin"}
    assert "studio-member" not in realm.roles["papaia-admin"]["_composites"]
    assert "papaia-auditor" not in realm.roles["papaia-admin"]["_composites"]


def test_sign_in_clients_see_their_roles_the_visible_roles_and_papaia_confirm_only():
    realm = FakeRealm()
    _run(realm, _full_plan())
    console = realm.by_client_id("flow-console")
    # papaia-admin is a composite of every module's admin role (and, in the realm
    # template, of realm-management roles): it never enters a module client's scope.
    # An admin still gets flow-admin in a Flow token through the composite.
    assert console["_role_scope"] == {
        "flow-member",
        "flow-admin",
        "studio-member",
        "papaia-confirm",
    }
    gateway = realm.by_client_id("papaia-studio-gateway")
    assert gateway["_role_scope"] == {"studio-member", "studio-admin", "papaia-confirm"}
    assert realm.by_client_id("flow")["_role_scope"] == set()


def test_check_reports_manual_drift_and_the_sync_repairs_it():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    engine = realm.by_client_id("flow-engine")
    engine["fullScopeAllowed"] = True
    engine["attributes"]["papaia.managed"] = "false"
    gateway = realm.by_client_id("papaia-studio-gateway")
    gateway["_optional"].append(realm._scope_id("address"))
    gateway["_default"].append(realm._scope_id("aud-flow"))
    console = realm.by_client_id("flow-console")
    console["_optional"].append(realm._scope_id("offline_access"))
    scope = next(s for s in realm.scopes.values() if s["name"] == "aud-flow")
    scope["protocolMappers"][0]["config"]["included.client.audience"] = "mcp-paperless"
    writes = len(realm.writes)

    drift = _run(realm, plan, apply=False)
    assert len(realm.writes) == writes
    described = {(c.kind, c.name) for c in drift}
    assert ("client", "flow-engine") in described
    assert ("client", "papaia-studio-gateway") in described
    assert ("client", "flow-console") in described
    assert ("client-scope", "aud-flow") in described

    assert _run(realm, plan)
    assert _run(realm, plan, apply=False) == []
    assert realm.by_client_id("flow-engine")["fullScopeAllowed"] is False
    assert realm.scope_names("papaia-studio-gateway", "default") & {"aud-flow"} == set()


def test_a_revoked_pairing_loses_its_scope():
    realm = FakeRealm()
    _run(realm, _full_plan())
    plan = _plan(
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(("papaia-studio-gateway", "flow", ["x"], "confirmed")),
    )
    changes = _run(realm, plan)
    assert ("client-scope", "aud-mcp-paperless") in {(c.kind, c.name) for c in changes}
    assert "aud-mcp-paperless" not in {s["name"] for s in realm.scopes.values()}
    assert realm.scope_names("papaia-studio-gateway", "optional") == {"aud-flow"}
    assert realm.scope_names("flow-engine", "optional") == {"offline_access"}


def test_a_scope_or_client_the_sync_does_not_manage_is_left_alone():
    realm = FakeRealm()
    realm.call("POST", "/client-scopes", {"name": "aud-hand-made", "protocol": "openid-connect"})
    realm.call("POST", "/clients", {"clientId": "hand-made", "fullScopeAllowed": True})
    _run(realm, _full_plan())
    assert "aud-hand-made" in {s["name"] for s in realm.scopes.values()}
    hand = realm.by_client_id("hand-made")
    assert hand["fullScopeAllowed"] is True
    # ... except that no client other than a holder keeps offline_access
    assert "offline_access" not in realm.scope_names("hand-made", "optional")


def test_a_managed_client_of_a_removed_module_is_reported_not_deleted(capsys):
    realm = FakeRealm()
    _run(realm, _full_plan())
    plan = _plan([_studio(), _paperless()])
    _run(realm, plan)
    assert realm.by_client_id("flow-engine")
    assert "flow-engine" in capsys.readouterr().err


def test_every_write_leaves_one_audit_row_with_the_run_correlation_id(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, _full_plan(), audit=audit)
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert len(rows) == len(realm.writes)
    assert [r["source_seq"] for r in rows] == list(range(1, len(rows) + 1))
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["correlation_id"] == "run-1"
        assert row["writer"] == "papaia-ctl/realm-sync"
        assert row["identity_kind"] == "service"
        assert row["service_account"] == rs.SYNC_CLIENT
        assert row["result"] == "allowed"
        assert row["effect"] in ("write", "delete")
        assert row["event"] in ("config_changed", "exchange_right_changed")
    exchange = [r for r in rows if r["event"] == "exchange_right_changed"]
    assert {r["object_ref"]["id"] for r in exchange} >= {"flow-engine", "papaia-studio-gateway"}
    assert "secret" not in (tmp_path / "audit.jsonl").read_text()

    # a second run continues the counter and writes nothing when nothing changed
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-2") as audit:
        assert _run(realm, _full_plan(), audit=audit) == []
        assert audit.next_seq() == len(rows) + 1
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == len(rows)


def test_no_client_secret_reaches_the_output(capsys):
    realm = FakeRealm()
    _run(realm, _full_plan())
    _run(realm, _full_plan(), apply=False)
    out = capsys.readouterr()
    assert "generated-by-keycloak" not in out.out + out.err


# ─────────────────────────────────────────────────────────────────────────
# the command: papaia-ctl realm sync [--check]
# ─────────────────────────────────────────────────────────────────────────


def _tree(secret: str = "not-a-real-secret") -> dict:
    return {
        "": {"AUTH_PROVIDER": "internal_keycloak"},
        "infra/keycloak": {"KC_ADMIN_PASSWORD": "admin-pw", rs.SYNC_SECRET_KEY: secret},
    }


@pytest.fixture
def connected(monkeypatch):
    """sync() against a FakeRealm: no Keycloak, no network. The master admin and the sync
    account both reach the fake; the sync account signs in only with the secret the fake
    holds for it."""
    realm = FakeRealm()

    def sign_in(base_url, ctx, secret):
        client = next((c for c in realm.clients.values() if c["clientId"] == rs.SYNC_CLIENT), None)
        if client is None or client.get("secret") != secret:
            raise rs.urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        return "sync-token"

    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: None)
    monkeypatch.setattr(rs.kcs, "_get_admin_token", lambda *a: "master-token")
    monkeypatch.setattr(rs, "_client_credentials", sign_in)
    monkeypatch.setattr(rs.AdminApi, "call", lambda self, *a: realm.call(*a))
    return realm


def _config(tmp_path, pairings: dict | None = None):
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    flow = repo_root / "papaia-flow"
    flow.mkdir(parents=True)
    manifest = {"name": "papaia-flow", "exposes": [_flow(delegation=DELEGATION).exposes[0]]}
    (flow / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    config_dir.mkdir()
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "papaia-flow", "path": str(flow), "active": True}]})
    )
    if pairings is not None:
        (config_dir / "security").mkdir()
        rs.pairings_path(config_dir).write_text(yaml.safe_dump(pairings))
    return config_dir, repo_root


def test_sync_applies_audits_and_check_then_reports_ok(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert "Realm sync complete" in capsys.readouterr().out
    outbox = rs.audit_path(config_dir)
    assert outbox.stat().st_mode & 0o777 == 0o600
    # One row per Keycloak write, and one for the group list next to the catalog.
    assert len(outbox.read_text().splitlines()) == len(connected.writes) + 1

    writes = len(connected.writes)
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0
    assert "Realm check: ok (0 deviation(s))" in capsys.readouterr().out
    connected.by_client_id("flow-engine")["fullScopeAllowed"] = True
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 1
    out = capsys.readouterr().out
    assert "fail: client flow-engine: settings corrected (fullScopeAllowed)" in out
    assert "Realm check: fail (1 deviation(s))" in out
    assert len(connected.writes) == writes


def test_a_refused_declaration_stops_before_keycloak_is_contacted(tmp_path, monkeypatch, capsys):
    def unreachable(*args, **kwargs):
        raise AssertionError("Keycloak contacted")

    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", unreachable)
    config_dir, repo_root = _config(tmp_path, {"format": "papaia.pairings/1", "pairings": [1]})
    assert rs.sync(_tree(), config_dir, repo_root) == 2
    assert "Nothing was changed" in capsys.readouterr().err
    assert not rs.audit_path(config_dir).exists()


def test_without_its_secret_the_sync_does_not_start(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("contacted"))
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree("GENERATE_KC_REALM_SYNC_CLIENT_SECRET"), config_dir, repo_root) == 1
    assert rs.SYNC_SECRET_KEY in capsys.readouterr().err


def test_an_external_identity_provider_is_left_alone(tmp_path):
    tree = {"": {"AUTH_PROVIDER": "external_oidc"}}
    assert rs.sync(tree, tmp_path, tmp_path) == 0


def test_the_keycloak_role_sync_step_runs_the_realm_sync(tmp_path, monkeypatch):
    from lib import cli

    calls = []
    monkeypatch.setattr(
        cli.keycloak_role_sync, "sync_roles", lambda *a: calls.append("roles") or True
    )
    monkeypatch.setattr(cli.realm_sync, "sync", lambda *a, **k: calls.append("realm") or 2)
    monkeypatch.setattr(cli.envtree, "load_config_dir_tree", lambda *a: {})
    args = cli.build_parser().parse_args(
        ["--config-dir", str(tmp_path), "--repo-root", str(tmp_path), "keycloak-role-sync"]
    )
    assert args.func(args) == 1
    assert calls == ["roles", "realm"]


@needs_bash
@pytest.mark.parametrize(
    ("flags", "expected"),
    [((), "py_cli realm-sync "), (("--check",), "py_cli realm-sync --check ")],
)
def test_the_realm_sync_command_hands_check_and_the_config_dir_to_py_cli(tmp_path, flags, expected):
    config_dir = _seeded(tmp_path / "c")
    result = _call("cmd_realm_sync", *flags, f"--config-dir={config_dir}")
    assert result.returncode == 0, result.stderr
    assert f"{expected}CONFIG_DIR={config_dir}" in result.stdout


@needs_bash
def test_the_realm_sync_command_refuses_an_unknown_option(tmp_path):
    result = _call("cmd_realm_sync", "--bogus", default=_seeded(tmp_path / "c"))
    assert result.returncode == 2
    assert "Unknown option for realm sync: --bogus" in result.stderr


@needs_bash
def test_the_dispatcher_knows_realm_sync_only():
    assert BASH is not None
    result = subprocess.run(
        [BASH, str(CTL), "realm", "export"], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 2
    assert "Unknown 'realm' subcommand: 'export'. Valid: sync, keys." in result.stderr
    assert (
        "papaia-ctl realm sync    [--check] [--config-dir=PATH]"
        in subprocess.run(
            [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False
        ).stdout
    )


def test_a_damaged_audit_outbox_stops_the_sync(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("contacted"))
    config_dir, repo_root = _config(tmp_path)
    rs.audit_path(config_dir).parent.mkdir(parents=True)
    rs.audit_path(config_dir).write_text("not json\n")
    assert rs.sync(_tree(), config_dir, repo_root) == 2
    assert "not an audit row" in capsys.readouterr().err


def test_check_never_creates_the_sync_account(connected):
    token, deviations, _ = rs.sync_account_token("https://kc", None, "pw", "secret", apply=False)
    assert token is None
    assert ("client", rs.SYNC_CLIENT) in {(c.kind, c.name) for c in deviations}
    assert connected.writes == []


@pytest.mark.parametrize(
    "entry",
    [
        {"id": "x", "kind": "ui", "roles": {"name": "flow-member"}},
        {"id": "x", "kind": "ui", "ui": "flow"},
        {"id": "x", "kind": "ui", "ui": ["flow"]},
        {"id": "x", "kind": "ui", "ui": [{"visible_for_roles": "flow-member"}]},
        {"id": "x", "kind": "rest", "delegation": {"purposes": [{"flow": "run"}]}},
    ],
)
def test_malformed_parts_of_a_declaration_are_refused_not_crashed_on(entry):
    with pytest.raises(rs.RealmSyncError):
        _plan([rs.Module("papaia-flow", [entry], {})])


# ─────────────────────────────────────────────────────────────────────────
# token scope of module clients: no composite reaches beyond the module
# ─────────────────────────────────────────────────────────────────────────


def _sign_in_clients(realm: FakeRealm, plan: rs.Plan) -> list[str]:
    return sorted(c for c, spec in plan.clients.items() if spec.kind != "bearer")


def test_papaia_admin_mapped_into_a_module_client_by_hand_is_reported_and_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.by_client_id("flow-cli")["_role_scope"] |= {"papaia-admin", "papaia-auditor"}
    drift = _run(realm, plan, apply=False)
    assert any(c.name == "flow-cli" and "papaia-admin" in c.action for c in drift)
    _run(realm, plan)
    for client_id in _sign_in_clients(realm, plan):
        assert "papaia-admin" not in realm.by_client_id(client_id)["_role_scope"]
    assert _run(realm, plan, apply=False) == []


def test_a_role_whose_composite_reaches_beyond_the_token_scope_is_not_mapped(capsys):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    # flow-admin now carries a realm-management role; studio-member carries papaia-admin
    realm.add_client_composite("flow-admin", "realm-management", "manage-users")
    realm.call("POST", "/roles/studio-member/composites", [{"name": "papaia-admin"}])
    assert _run(realm, plan, apply=False)
    _run(realm, plan)
    console = realm.by_client_id("flow-console")["_role_scope"]
    assert "flow-admin" not in console
    assert "studio-member" not in console
    assert "flow-member" in console
    assert "studio-member" not in realm.by_client_id("papaia-studio-gateway")["_role_scope"]
    assert "manage-users" in capsys.readouterr().out
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_client_roles_in_the_scope_of_a_managed_client_are_reported_and_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    rm = realm.by_client_id("realm-management")["id"]
    realm.by_client_id("flow-engine")["_client_scope"][rm] = {"manage-users"}
    drift = _run(realm, plan, apply=False)
    assert any(c.name == "flow-engine" and "realm-management" in c.action for c in drift)
    _run(realm, plan)
    assert realm.by_client_id("flow-engine")["_client_scope"].get(rm, set()) == set()
    assert _run(realm, plan, apply=False) == []


def test_visible_for_roles_of_a_module_that_is_not_installed_is_harmless(capsys):
    realm = FakeRealm()
    studio = _studio()
    studio.exposes[0]["ui"][0]["visible_for_roles"] = ["studio-member", "data-member"]
    plan = _plan([studio])
    assert any("data-member" in note for note in plan.notes)
    assert _run(realm, plan)
    assert "data-member" not in realm.roles
    assert "data-member" not in realm.by_client_id("papaia-studio-gateway")["_role_scope"]
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []
    # once the role exists (its module was installed), it enters the scope
    realm.call("POST", "/roles", {"name": "data-member"})
    _run(realm, plan)
    assert "data-member" in realm.by_client_id("papaia-studio-gateway")["_role_scope"]


# ─────────────────────────────────────────────────────────────────────────
# no fixed audience on a managed client (PLT-11-A1)
# ─────────────────────────────────────────────────────────────────────────


def _fixed_audience(audience: str) -> dict:
    return {
        "name": "fixed audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": audience, "access.token.claim": "true"},
    }


def test_a_fixed_audience_mapper_on_a_managed_client_is_reported_and_removed(tmp_path):
    realm = FakeRealm()
    # the add-on's own Keycloak JSON created flow-engine with a hardcoded audience
    harmless = {
        "name": "locale",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {"claim.name": "locale", "user.attribute": "locale"},
    }
    realm.call(
        "POST",
        "/clients",
        {
            "clientId": "flow-engine",
            "protocolMappers": [
                _fixed_audience("mcp-qdrant"),
                {"name": "resolve", "protocolMapper": "oidc-audience-resolve-mapper"},
                {
                    "name": "aud claim",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "config": {"claim.name": "aud", "claim.value": "mcp-qdrant"},
                },
                harmless,
            ],
        },
    )
    plan = _full_plan()
    drift = _run(realm, plan, apply=False)
    removed = [c for c in drift if c.name == "flow-engine" and "mapper" in c.action]
    assert len(removed) == 3
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    mappers = realm.by_client_id("flow-engine")["protocolMappers"]
    assert [m["name"] for m in mappers] == ["locale"]
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    mapper_rows = [r for r in rows if r["operation"] == "realm_sync.remove_client_mapper"]
    assert len(mapper_rows) == 3
    assert {r["event"] for r in mapper_rows} == {"exchange_right_changed"}
    assert _run(realm, plan, apply=False) == []


def test_a_mapper_added_later_fails_the_check():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    uid = realm.by_client_id("papaia-studio-gateway")["id"]
    realm.call("POST", f"/clients/{uid}/protocol-mappers/models", _fixed_audience("flow"))
    assert [c.name for c in _run(realm, plan, apply=False)] == ["papaia-studio-gateway"]


# ─────────────────────────────────────────────────────────────────────────
# papaia-admin: separation of duties (security 1.3)
# ─────────────────────────────────────────────────────────────────────────


def test_papaia_admin_never_includes_auditor_operator_or_admin_roles_of_removed_modules():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.call("POST", "/roles", {"name": "papaia-operator"})
    realm.call("POST", "/roles", {"name": "manager-admin"})
    realm.call(
        "POST",
        "/roles",
        {
            "name": "data-admin",
            "attributes": {"papaia.managed": ["true"], "papaia.owner": ["data"]},
        },
    )
    extra = [
        {"name": n} for n in ("papaia-auditor", "papaia-operator", "data-admin", "manager-admin")
    ]
    realm.call("POST", "/roles/papaia-admin/composites", extra)

    drift = _run(realm, plan, apply=False)
    actions = " ".join(c.action for c in drift if c.name == "papaia-admin")
    for name in ("papaia-auditor", "papaia-operator", "data-admin"):
        assert name in actions
    assert "manager-admin" not in actions

    _run(realm, plan)
    assert realm.roles["papaia-admin"]["_composites"] == {
        "flow-admin",
        "studio-admin",
        "manager-admin",
    }
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# offline_access only at an installed holder that declares delegation
# ─────────────────────────────────────────────────────────────────────────


def _offline(realm: FakeRealm, client_id: str) -> bool:
    return "offline_access" in realm.scope_names(client_id, "default") | realm.scope_names(
        client_id, "optional"
    )


def test_a_holder_client_without_an_installed_module_loses_offline_access():
    realm = FakeRealm()
    realm.call("POST", "/clients", {"clientId": "assist-gate"})  # by hand, left over
    assert _offline(realm, "assist-gate")
    plan = _full_plan()
    drift = _run(realm, plan, apply=False)
    assert any(c.name == "assist-gate" and "offline_access" in c.action for c in drift)
    _run(realm, plan)
    assert not _offline(realm, "assist-gate")


def test_flow_engine_loses_offline_access_when_flow_is_removed_or_stops_delegating():
    realm = FakeRealm()
    _run(realm, _full_plan())
    assert _offline(realm, "flow-engine")
    _run(realm, _plan([_flow(), _studio(), _paperless()]))
    assert not _offline(realm, "flow-engine")
    _run(realm, _full_plan())
    assert _offline(realm, "flow-engine")
    _run(realm, _plan([_studio(), _paperless()]))
    assert not _offline(realm, "flow-engine")


# ─────────────────────────────────────────────────────────────────────────
# exchange scopes: attributes, protocol and adoption
# ─────────────────────────────────────────────────────────────────────────


def _scope(realm: FakeRealm, name: str) -> dict:
    return next(s for s in realm.scopes.values() if s["name"] == name)


def test_exchange_scope_attribute_and_protocol_drift_is_corrected():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    scope = _scope(realm, "aud-flow")
    scope["protocol"] = "saml"
    scope["attributes"]["include.in.token.scope"] = "false"
    scope["attributes"]["display.on.consent.screen"] = "true"
    drift = _run(realm, plan, apply=False)
    assert [(c.kind, c.name) for c in drift] == [("client-scope", "aud-flow")]
    _run(realm, plan)
    scope = _scope(realm, "aud-flow")
    assert scope["protocol"] == "openid-connect"
    assert scope["attributes"]["include.in.token.scope"] == "true"
    assert scope["attributes"]["display.on.consent.screen"] == "false"
    assert _run(realm, plan, apply=False) == []


def test_an_existing_unmanaged_exchange_scope_is_adopted_and_removed_on_revocation(tmp_path):
    realm = FakeRealm()
    # a module's own setup created aud-flow without the managed attribute
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-flow",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
            "protocolMappers": [rs._audience_mapper("flow")],
        },
    )
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, _full_plan(), audit=audit)
    assert _scope(realm, "aud-flow")["attributes"]["papaia.managed"] == "true"
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(
        r["object_ref"] == {"type": "client_scope", "id": "aud-flow"}
        and r["operation"] == "realm_sync.update_scope"
        for r in rows
    )
    # without Flow, aud-flow is no sign-in scope of its console either
    revoked = _plan(
        [_studio(), _paperless()],
        _pairings(("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed")),
    )
    _run(realm, revoked)
    assert "aud-flow" not in {s["name"] for s in realm.scopes.values()}


# ─────────────────────────────────────────────────────────────────────────
# audit rows: papaia.audit/1 submission form, UUIDv7, a counter of its own
# ─────────────────────────────────────────────────────────────────────────

SUBMISSION_FIELDS = {
    "format",
    "time",
    "source_seq",
    "correlation_id",
    "writer",
    "role",
    "sub",
    "identity_kind",
    "service_account",
    "azp",
    "aud",
    "origin_azp",
    "origin_source",
    "origin_asserted_by",
    "context",
    "catalog_id",
    "operation",
    "effect",
    "object_ref",
    "data_class",
    "result",
    "error_code",
    "client_ip",
    "detail",
    "event",
}


def test_a_new_correlation_id_is_a_uuid7():
    import time
    import uuid

    value = uuid.UUID(rs.new_correlation_id())
    assert value.version == 7
    assert value.variant == uuid.RFC_4122
    assert abs((value.int >> 80) - time.time() * 1000) < 5000
    assert rs.new_correlation_id() != rs.new_correlation_id()


def test_audit_rows_carry_every_field_of_the_submission_form_and_the_host_account(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", rs.new_correlation_id()) as audit:
        _run(realm, _full_plan(), audit=audit)
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    for row in rows:
        # source, seq, prev_hash and hash are assigned by papaia-audit at delivery
        assert set(row) == SUBMISSION_FIELDS
        assert row["sub"].startswith("host:")
        assert row["role"] == "caller"
        assert row["origin_azp"] is None and row["context"] is None
        assert set(row["object_ref"]) == {"type", "id"}
    assert len({r["correlation_id"] for r in rows}) == 1


def test_the_sequence_survives_a_drained_outbox(tmp_path):
    outbox = tmp_path / "outbox" / "papaia-ctl.jsonl"
    change = rs.Change("role", "flow-member", "created", "create_role")
    with rs.AuditLog(outbox, "run-1") as audit:
        audit.write(change, "allowed")
        audit.write(change, "allowed")
    outbox.unlink()  # delivered to papaia-audit and removed
    with rs.AuditLog(outbox, "run-2") as audit:
        audit.write(change, "allowed")
    (row,) = [json.loads(line) for line in outbox.read_text().splitlines()]
    assert row["source_seq"] == 3


def test_a_second_writer_waits_for_the_first_and_gives_up(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "LOCK_TIMEOUT", 0.2)
    outbox = tmp_path / "papaia-ctl.jsonl"
    with rs.AuditLog(outbox, "run-1"):
        with pytest.raises(rs.RealmSyncError, match="another papaia-ctl run"):
            rs.AuditLog(outbox, "run-2")
    with rs.AuditLog(outbox, "run-3"):
        pass


def test_an_existing_outbox_and_counter_are_tightened_to_0600(tmp_path):
    outbox = tmp_path / "papaia-ctl.jsonl"
    outbox.write_text("")
    outbox.chmod(0o644)
    with rs.AuditLog(outbox, "run-1") as audit:
        audit.write(rs.Change("role", "x", "created", "create_role"), "allowed")
    assert outbox.stat().st_mode & 0o777 == 0o600
    assert rs.seq_path(outbox).stat().st_mode & 0o777 == 0o600


# ─────────────────────────────────────────────────────────────────────────
# the sync account: exactly SYNC_RIGHTS, checked on every run
# ─────────────────────────────────────────────────────────────────────────


def _account_rights(realm: FakeRealm) -> tuple[set, set, set, set]:
    rm = realm.by_client_id("realm-management")["id"]
    client = realm.by_client_id(rs.SYNC_CLIENT)
    user = realm.service_account_user(rs.SYNC_CLIENT)
    return (
        user["_clients"].get(rm, set()),
        client["_client_scope"].get(rm, set()),
        user["_realm"],
        client["_role_scope"],
    )


def test_the_sync_account_is_created_with_exactly_its_rights(tmp_path):
    realm = FakeRealm()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        created = rs.align_sync_account(realm.call, "s3cr3t-value", apply=True, audit=audit)
    assert created
    roles, scope, realm_roles, realm_scope = _account_rights(realm)
    assert roles == scope == set(rs.SYNC_RIGHTS)
    assert realm_roles == {"default-roles-papaia"}
    assert realm_scope == set()
    assert realm.by_client_id(rs.SYNC_CLIENT)["fullScopeAllowed"] is False
    assert rs.align_sync_account(realm.call, "s3cr3t-value", apply=True) == []
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert len(rows) == len(realm.writes)
    assert {r["azp"] for r in rows} == {"admin-cli"}
    assert "s3cr3t-value" not in (tmp_path / "audit.jsonl").read_text()


def test_extra_rights_of_the_sync_account_are_reported_and_removed():
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    rm = realm.by_client_id("realm-management")["id"]
    client = realm.by_client_id(rs.SYNC_CLIENT)
    user = realm.service_account_user(rs.SYNC_CLIENT)
    client["_client_scope"][rm].add("realm-admin")
    user["_clients"][rm].add("realm-admin")
    user["_realm"].add("offline_access")
    client["_role_scope"].add("offline_access")
    client["fullScopeAllowed"] = True
    writes = len(realm.writes)

    drift = rs.align_sync_account(realm.call, None, apply=False)
    assert len(realm.writes) == writes
    text = " ".join(c.action for c in drift)
    assert "realm-admin" in text and "fullScopeAllowed" in text and "offline_access" in text

    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    roles, scope, realm_roles, realm_scope = _account_rights(realm)
    assert roles == scope == set(rs.SYNC_RIGHTS)
    assert realm_roles == {"default-roles-papaia"}
    assert realm_scope == set()
    assert rs.align_sync_account(realm.call, None, apply=False) == []


def test_a_failed_bootstrap_write_is_audited_as_an_error(tmp_path):
    realm = FakeRealm()

    def refusing(method, path, body=None):
        if method == "POST" and path == "/clients":
            raise rs.urllib.error.HTTPError(path, 403, "forbidden", {}, None)
        return realm.call(method, path, body)

    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        with pytest.raises(rs.urllib.error.HTTPError):
            rs.align_sync_account(refusing, "s3cr3t-value", apply=True, audit=audit)
    (row,) = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert (row["result"], row["error_code"]) == ("error", "http_403")


def test_check_reports_extra_rights_of_the_sync_account(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    capsys.readouterr()
    rm = connected.by_client_id("realm-management")["id"]
    connected.by_client_id(rs.SYNC_CLIENT)["_client_scope"][rm].add("realm-admin")
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 1
    out = capsys.readouterr().out
    assert f"fail: client {rs.SYNC_CLIENT}" in out and "realm-admin" in out
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0


def test_a_changed_secret_realigns_the_sync_account(tmp_path, connected):
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree("first-secret"), config_dir, repo_root) == 0
    assert rs.sync(_tree("second-secret"), config_dir, repo_root, check=True) == 1
    assert rs.sync(_tree("second-secret"), config_dir, repo_root) == 0
    assert connected.by_client_id(rs.SYNC_CLIENT)["secret"] == "second-secret"


# ─────────────────────────────────────────────────────────────────────────
# the module identity is bound to the deployment entry
# ─────────────────────────────────────────────────────────────────────────


def _deployment(tmp_path, entry_name: str, manifest: dict):
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    addon = repo_root / "addon"
    addon.mkdir(parents=True)
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    config_dir.mkdir()
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": entry_name, "path": str(addon), "active": True}]})
    )
    return config_dir, repo_root


def test_a_manifest_name_that_differs_from_the_deployment_entry_is_refused(tmp_path):
    exposes = [_flow(delegation=DELEGATION).exposes[0]]
    config_dir, repo_root = _deployment(
        tmp_path, "foo", {"name": "papaia-flow", "exposes": exposes}
    )
    with pytest.raises(rs.RealmSyncError, match="papaia-flow.*foo|foo.*papaia-flow"):
        rs.load_modules(config_dir, repo_root)


def test_a_manifest_with_exposes_but_no_name_is_refused(tmp_path):
    config_dir, repo_root = _deployment(tmp_path, "papaia-flow", {"exposes": []})
    with pytest.raises(rs.RealmSyncError, match="name"):
        rs.load_modules(config_dir, repo_root)


def test_a_foreign_module_name_stops_the_sync_before_keycloak(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("contacted"))
    exposes = [_flow(delegation=DELEGATION).exposes[0]]
    config_dir, repo_root = _deployment(
        tmp_path, "foo", {"name": "papaia-flow", "exposes": exposes}
    )
    assert rs.sync(_tree(), config_dir, repo_root) == 2
    assert "Nothing was changed" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────
# pairings.yaml grants exchange rights: owner and mode are checked
# ─────────────────────────────────────────────────────────────────────────


def _pairings_file(tmp_path):
    path = rs.pairings_path(tmp_path)
    path.parent.mkdir(mode=0o700)
    path.write_text(yaml.safe_dump({"format": "papaia.pairings/1", "pairings": []}))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o620, 0o602])
def test_a_pairings_file_writable_by_group_or_others_is_refused(tmp_path, mode):
    path = _pairings_file(tmp_path)
    path.chmod(mode)
    with pytest.raises(rs.RealmSyncError, match="writable"):
        rs.load_pairings(path, REGISTER)


def test_a_pairings_directory_writable_by_others_is_refused(tmp_path):
    path = _pairings_file(tmp_path)
    path.parent.chmod(0o777)
    with pytest.raises(rs.RealmSyncError, match="writable"):
        rs.load_pairings(path, REGISTER)


def test_a_pairings_file_of_another_user_is_refused(tmp_path, monkeypatch):
    path = _pairings_file(tmp_path)
    monkeypatch.setattr(rs.os, "geteuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(rs.RealmSyncError, match="owned"):
        rs.load_pairings(path, REGISTER)


def test_a_pairings_file_behind_a_symlink_is_refused(tmp_path):
    path = _pairings_file(tmp_path)
    target = tmp_path / "elsewhere.yaml"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(rs.RealmSyncError):
        rs.load_pairings(path, REGISTER)


# ─────────────────────────────────────────────────────────────────────────
# role scope mappings of client scopes: no role enters a token through a scope
# ─────────────────────────────────────────────────────────────────────────


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _map_into_scope(realm: FakeRealm, scope: str, *, realm_role=None, client_role=None):
    sid = realm.scope_by_name(scope)["id"]
    if realm_role:
        realm.call("POST", f"/client-scopes/{sid}/scope-mappings/realm", [{"name": realm_role}])
    if client_role:
        cid = realm.by_client_id(client_role[0])["id"]
        realm.call(
            "POST", f"/client-scopes/{sid}/scope-mappings/clients/{cid}", [{"name": client_role[1]}]
        )


def _scope_roles(realm: FakeRealm, scope: str) -> tuple[set, set]:
    held = realm.scope_by_name(scope)
    return set(held["_role_scope"]), {n for v in held["_client_scope"].values() for n in v}


def test_role_mappings_on_an_exchange_scope_are_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    _map_into_scope(
        realm,
        "aud-mcp-paperless",
        realm_role="papaia-admin",
        client_role=("realm-management", "realm-admin"),
    )
    _map_into_scope(realm, "aud-mcp-paperless", realm_role="flow-admin")
    drift = _run(realm, plan, apply=False)
    text = " ".join(c.action for c in drift if c.name == "aud-mcp-paperless")
    assert "papaia-admin" in text and "flow-admin" in text and "realm-admin" in text
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    assert _scope_roles(realm, "aud-mcp-paperless") == (set(), set())
    rows = [
        r for r in _rows(tmp_path / "audit.jsonl") if r["object_ref"]["id"] == "aud-mcp-paperless"
    ]
    assert len(rows) == 3
    assert {r["event"] for r in rows} == {"exchange_right_changed"}
    assert {r["effect"] for r in rows} == {"delete"}
    assert _run(realm, plan, apply=False) == []


def test_an_adopted_exchange_scope_is_stripped_of_its_role_mappings(tmp_path):
    realm = FakeRealm()
    realm.call("POST", "/roles", {"name": "papaia-admin"})
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-flow",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
            "protocolMappers": [rs._audience_mapper("flow")],
        },
    )
    _map_into_scope(
        realm,
        "aud-flow",
        realm_role="papaia-admin",
        client_role=("realm-management", "manage-users"),
    )
    plan = _full_plan()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    assert _scope_roles(realm, "aud-flow") == (set(), set())
    ops = [
        r["operation"]
        for r in _rows(tmp_path / "audit.jsonl")
        if r["object_ref"]["id"] == "aud-flow"
    ]
    assert ops.count("realm_sync.remove_scope_role") == 2
    assert _run(realm, plan, apply=False) == []


def test_role_mappings_on_the_shared_default_scopes_are_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    _map_into_scope(realm, "roles", realm_role="papaia-admin")
    _map_into_scope(realm, "profile", client_role=("realm-management", "manage-users"))
    _map_into_scope(realm, "offline_access", realm_role="papaia-admin")
    drift = _run(realm, plan, apply=False)
    assert {c.name for c in drift} == {"roles", "profile", "offline_access"}
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    assert _scope_roles(realm, "roles") == (set(), set())
    assert _scope_roles(realm, "profile") == (set(), set())
    # Keycloak's own mapping stays
    assert _scope_roles(realm, "offline_access") == ({"offline_access"}, set())
    assert len(_rows(tmp_path / "audit.jsonl")) == 3
    assert _run(realm, plan, apply=False) == []


def test_a_composite_on_the_offline_access_role_is_reported_and_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.call("POST", "/roles/offline_access/composites", [{"name": "papaia-admin"}])
    realm.add_client_composite("offline_access", "realm-management", "realm-admin")
    drift = _run(realm, plan, apply=False)
    text = " ".join(c.action for c in drift if c.name == "offline_access")
    assert "papaia-admin" in text and "realm-admin" in text
    _run(realm, plan)
    assert realm.roles["offline_access"]["composite"] is False
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# no client-level mapper on a managed client adds a role
# ─────────────────────────────────────────────────────────────────────────


ROLE_MAPPERS = [
    {
        "name": "hardcoded",
        "protocolMapper": "oidc-hardcoded-role-mapper",
        "config": {"role": "realm-management.realm-admin"},
    },
    {
        "name": "renamed",
        "protocolMapper": "oidc-role-name-mapper",
        "config": {"role": "flow-member", "new.role.name": "papaia-admin"},
    },
    {"name": "script", "protocolMapper": "script-roles.js", "config": {}},
    {
        "name": "claim",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "realm_access.roles", "claim.value": "papaia-admin"},
    },
    {
        "name": "resource",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {"claim.name": "resource_access", "user.attribute": "x"},
    },
    {
        "name": "roles claim",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "roles", "claim.value": "papaia-admin"},
    },
]


def test_role_adding_mappers_on_a_managed_client_are_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    uid = realm.by_client_id("flow-cli")["id"]
    for mapper in ROLE_MAPPERS:
        realm.call("POST", f"/clients/{uid}/protocol-mappers/models", mapper)
    # the role mapper of Keycloak's `roles` scope only shows roles already in scope
    realm.call(
        "POST",
        f"/clients/{uid}/protocol-mappers/models",
        {
            "name": "realm roles",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {"claim.name": "roles", "multivalued": "true"},
        },
    )
    drift = _run(realm, plan, apply=False)
    assert len([c for c in drift if c.name == "flow-cli"]) == len(ROLE_MAPPERS)
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    assert [m["name"] for m in realm.by_client_id("flow-cli")["protocolMappers"]] == ["realm roles"]
    rows = [r for r in _rows(tmp_path / "audit.jsonl") if r["object_ref"]["id"] == "flow-cli"]
    assert len(rows) == len(ROLE_MAPPERS)
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# an aud-* scope reaches no client without a confirmed pairing
# ─────────────────────────────────────────────────────────────────────────


def test_an_exchange_scope_among_the_realm_defaults_is_reported_and_removed():
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    sid = realm.scope_by_name("aud-flow")["id"]
    realm.default_default.append(sid)
    realm.default_optional.append(realm.scope_by_name("aud-mcp-paperless")["id"])
    drift = _run(realm, plan, apply=False)
    assert {c.name for c in drift} == {"papaia"}
    assert len(drift) == 2
    _run(realm, plan)
    names = {realm.scopes[i]["name"] for i in realm.default_default + realm.default_optional}
    assert not {n for n in names if n.startswith("aud-")}
    assert _run(realm, plan, apply=False) == []


def test_an_exchange_scope_on_an_unmanaged_client_is_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    # a hardened client of the realm template (realm_hardening owns its switches)
    librechat = {
        "clientId": "librechat",
        "publicClient": False,
        "directAccessGrantsEnabled": False,
        "defaultClientScopes": ["aud-flow"],
    }
    realm.call("POST", "/clients", librechat)
    uid = realm.by_client_id("librechat")["id"]
    sid = realm.scope_by_name("aud-mcp-paperless")["id"]
    realm.call("PUT", f"/clients/{uid}/optional-client-scopes/{sid}")
    # a bearer-only client never obtains a token; it is left alone
    realm.call("POST", "/clients", {"clientId": "rag-api", "bearerOnly": True})
    rag = realm.by_client_id("rag-api")["id"]
    realm.call("PUT", f"/clients/{rag}/optional-client-scopes/{sid}")
    drift = _run(realm, plan, apply=False)
    assert {c.name for c in drift} == {"librechat"}
    assert len(drift) == 2
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    scopes = realm.scope_names("librechat", "default") | realm.scope_names("librechat", "optional")
    assert not {s for s in scopes if s.startswith("aud-")}
    assert {r["event"] for r in _rows(tmp_path / "audit.jsonl")} == {"exchange_right_changed"}
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# a scope that cannot be resolved is skipped, never addressed as None
# ─────────────────────────────────────────────────────────────────────────


def test_a_scope_that_does_not_exist_is_skipped_and_fails_the_check(capsys):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.call("DELETE", f"/client-scopes/{realm.scope_by_name('acr')['id']}")
    writes = len(realm.writes)
    reconciler = rs._Reconciler(realm.call, plan, True, None)
    reconciler.run()
    assert not any("None" in path for _, path in realm.writes[writes:])
    assert reconciler.skipped
    assert "acr" in capsys.readouterr().out
    drift = _run(realm, plan, apply=False)
    assert any("acr" in c.action for c in drift)


def test_sync_reports_a_skipped_scope_as_incomplete(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    connected.call("DELETE", f"/client-scopes/{connected.scope_by_name('acr')['id']}")
    capsys.readouterr()
    assert rs.sync(_tree(), config_dir, repo_root) == 1
    assert "acr" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────
# the sync account: composites are expanded
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "grow",
    [
        lambda r: r.add_client_role_composite(
            "realm-management", "manage-clients", client=("realm-management", "realm-admin")
        ),
        lambda r: r.add_client_role_composite(
            "realm-management", "manage-realm", client=("realm-management", "manage-users")
        ),
        lambda r: r.add_client_composite("default-roles-papaia", "realm-management", "view-users"),
    ],
    ids=["manage-clients>realm-admin", "manage-realm>manage-users", "default-roles>view-users"],
)
def test_a_right_reached_through_a_composite_fails_the_account_check(grow):
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    assert rs.align_sync_account(realm.call, None, apply=False) == []
    grow(realm)
    drift = rs.align_sync_account(realm.call, None, apply=False)
    assert drift and all(c.name == rs.SYNC_CLIENT for c in drift)
    assert any("composite" in c.action for c in drift)
    writes = len(realm.writes)
    with pytest.raises(rs.RealmSyncError, match="composite"):
        rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    assert len(realm.writes) == writes


# ─────────────────────────────────────────────────────────────────────────
# audit: a write that fails in transport is audited; the outbox is checked first
# ─────────────────────────────────────────────────────────────────────────


def test_a_write_that_fails_in_transport_is_audited_as_an_error(tmp_path):
    realm = FakeRealm()

    def broken(method, path, body=None):
        if method == "POST" and path == "/clients":
            raise rs.urllib.error.URLError("connection reset")
        return realm.call(method, path, body)

    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        with pytest.raises(rs.urllib.error.URLError):
            rs.align_sync_account(broken, "s3cr3t-value", apply=True, audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert (row["result"], row["error_code"]) == ("error", "transport")


def test_an_outbox_that_cannot_be_written_stops_the_run_before_any_change(tmp_path):
    outbox = tmp_path / "outbox" / "papaia-ctl.jsonl"
    outbox.parent.mkdir()
    rs.seq_path(outbox).write_text("0\n")
    rs.seq_path(outbox).chmod(0o600)
    outbox.parent.chmod(0o500)
    try:
        with pytest.raises(OSError):
            rs.AuditLog(outbox, "run-1")
    finally:
        outbox.parent.chmod(0o700)


# ─────────────────────────────────────────────────────────────────────────
# the module name is checked before it is used in a path
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["../x", "a/b", "Flow", ""])
def test_a_module_name_with_path_segments_is_refused_before_any_file_is_read(
    tmp_path, monkeypatch, name
):
    monkeypatch.setattr(rs.common, "parse_env_file", lambda *a: pytest.fail("read"))
    config_dir, repo_root = _deployment(tmp_path, name, {"name": name, "exposes": []})
    with pytest.raises(rs.RealmSyncError, match="module name"):
        rs.load_modules(config_dir, repo_root)


# ─────────────────────────────────────────────────────────────────────────
# a skipped correction of the sync account ends the sync incomplete
# ─────────────────────────────────────────────────────────────────────────


def _hide_scope(realm: FakeRealm, name: str, *, token: str | None = None):
    """An Admin API whose `/client-scopes` listing leaves out `name` (for the given bearer
    token only, when one is named)."""

    def call(self, method, path, body=None):
        result = realm.call(method, path, body)
        if method == "GET" and path == "/client-scopes" and token in (None, self.token):
            result = [s for s in result if s["name"] != name]
        return result

    return call


def test_a_scope_of_the_sync_account_that_does_not_resolve_is_skipped():
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    client = realm.by_client_id(rs.SYNC_CLIENT)
    client["_optional"].append(realm.scope_by_name("address")["id"])
    api = rs.AdminApi("http://kc", None, "master-token")
    skipped: list[rs.Change] = []
    writes = len(realm.writes)
    rs.align_sync_account(
        lambda *a: _hide_scope(realm, "address")(api, *a),
        "s3cr3t-value",
        apply=True,
        skipped=skipped,
    )
    assert len(realm.writes) == writes
    assert [c.name for c in skipped] == [rs.SYNC_CLIENT]
    assert "address" in skipped[0].action


def test_sync_reports_a_skipped_correction_of_the_sync_account_as_incomplete(
    tmp_path, connected, monkeypatch, capsys
):
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    client = connected.by_client_id(rs.SYNC_CLIENT)
    client["_optional"].append(connected.scope_by_name("address")["id"])
    hidden = _hide_scope(connected, "address", token="master-token")
    monkeypatch.setattr(rs.AdminApi, "call", hidden)
    capsys.readouterr()
    assert rs.sync(_tree(), config_dir, repo_root) == 1
    out = capsys.readouterr().out
    assert "Realm sync incomplete" in out and "address" in out
    assert "Realm sync complete" not in out


# ─────────────────────────────────────────────────────────────────────────
# the shared scopes add no audience
# ─────────────────────────────────────────────────────────────────────────


def _resolve_mapper() -> dict:
    return {
        "name": "audience resolve",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-resolve-mapper",
        "config": {"access.token.claim": "true"},
    }


def test_audience_mappers_on_the_shared_scopes_are_reported_and_removed(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    base = "/client-scopes/{}/protocol-mappers/models"
    realm.call("POST", base.format(realm.scope_by_name("profile")["id"]), _fixed_audience("x"))
    realm.call(
        "POST",
        base.format(realm.scope_by_name("email")["id"]),
        {
            "name": "aud claim",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": "aud", "claim.value": "mcp-paperless"},
        },
    )
    realm.call("POST", base.format(realm.scope_by_name("basic")["id"]), _resolve_mapper())
    # Keycloak's own audience resolve mapper of the `roles` scope stays
    realm.call("POST", base.format(realm.scope_by_name("roles")["id"]), _resolve_mapper())
    realm.call(
        "POST",
        base.format(realm.scope_by_name("offline_access")["id"]),
        _fixed_audience("mcp-paperless"),
    )
    drift = _run(realm, plan, apply=False)
    assert {c.name for c in drift} == {"profile", "email", "basic", "offline_access"}
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    for name in ("profile", "email", "basic", "offline_access"):
        assert not realm.scope_by_name(name)["protocolMappers"], name
    assert [m["name"] for m in realm.scope_by_name("roles")["protocolMappers"]] == [
        "audience resolve"
    ]
    rows = _rows(tmp_path / "audit.jsonl")
    assert len(rows) == 4
    assert {r["event"] for r in rows} == {"exchange_right_changed"}
    assert {r["effect"] for r in rows} == {"delete"}
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# a managed client's own client roles reach nothing beyond themselves
# ─────────────────────────────────────────────────────────────────────────


def test_composites_of_a_managed_clients_own_roles_are_reported_and_stripped(tmp_path):
    realm = FakeRealm()
    plan = _full_plan()
    _run(realm, plan)
    realm.add_client_role("flow-cli", "boss")
    realm.add_client_role_composite(
        "flow-cli", "boss", realm="papaia-admin", client=("realm-management", "realm-admin")
    )
    realm.add_client_role("flow-cli", "viewer")
    realm.add_client_role("flow-cli", "lead")
    # a composite of the client's own roles stays
    realm.add_client_role_composite("flow-cli", "lead", client=("flow-cli", "viewer"))
    realm.add_client_composite("papaia-admin", "flow-cli", "boss")

    drift = _run(realm, plan, apply=False)
    flow_cli = [c for c in drift if c.name == "flow-cli"]
    text = " ".join(c.action for c in flow_cli)
    assert "realm-admin" in text and "papaia-admin" in text and "boss" in text
    assert "viewer" not in text and "lead" not in text
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    roles = realm.by_client_id("flow-cli")["_roles"]
    assert roles["boss"]["composite"] is False
    assert roles["lead"]["_client_composites"] == {("flow-cli", "viewer")}
    rows = [r for r in _rows(tmp_path / "audit.jsonl") if r["object_ref"]["id"] == "flow-cli"]
    assert len(rows) == 2
    assert {r["effect"] for r in rows} == {"delete"}
    assert _run(realm, plan, apply=False) == []


# ─────────────────────────────────────────────────────────────────────────
# the sync account: no group, no role through the service_account scope, the composite
# check comes before any write
# ─────────────────────────────────────────────────────────────────────────


def test_a_group_of_the_sync_account_is_reported_and_removed(tmp_path):
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    gid = realm.add_group("admins", {"offline_access"})
    realm.service_account_user(rs.SYNC_CLIENT)["_groups"].add(gid)
    drift = rs.align_sync_account(realm.call, None, apply=False)
    assert [c.name for c in drift] == [rs.SYNC_CLIENT]
    assert "admins" in drift[0].action
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        rs.align_sync_account(realm.call, "s3cr3t-value", apply=True, audit=audit)
    assert realm.service_account_user(rs.SYNC_CLIENT)["_groups"] == set()
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert (row["effect"], row["azp"]) == ("delete", "admin-cli")
    assert rs.align_sync_account(realm.call, None, apply=False) == []


def test_roles_mapped_into_the_service_account_scope_are_reported_and_removed(tmp_path):
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    _map_into_scope(
        realm,
        "service_account",
        realm_role="offline_access",
        client_role=("realm-management", "realm-admin"),
    )
    drift = rs.align_sync_account(realm.call, None, apply=False)
    text = " ".join(f"{c.name} {c.action}" for c in drift)
    assert "service_account" in text and "realm-admin" in text and "offline_access" in text
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        rs.align_sync_account(realm.call, "s3cr3t-value", apply=True, audit=audit)
    assert _scope_roles(realm, "service_account") == (set(), set())
    assert len(_rows(tmp_path / "audit.jsonl")) == 2
    assert rs.align_sync_account(realm.call, None, apply=False) == []


def test_a_composite_that_widens_the_sync_rights_stops_before_any_correction():
    realm = FakeRealm()
    rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    realm.add_client_composite("default-roles-papaia", "realm-management", "view-users")
    # corrections that would otherwise run first
    realm.by_client_id(rs.SYNC_CLIENT)["fullScopeAllowed"] = True
    realm.service_account_user(rs.SYNC_CLIENT)["_realm"].add("offline_access")
    writes = len(realm.writes)
    with pytest.raises(rs.RealmSyncError, match="composite"):
        rs.align_sync_account(realm.call, "s3cr3t-value", apply=True)
    assert len(realm.writes) == writes
