"""Token exchange with exactly one audience: scopes, optional scopes and client policies.

The realm sync gives `papaia-me` one optional scope `aud-<audience>` per module of the
personal-settings registry and `papaia-manager` the scope `aud-flow`, and adds per
audience a client policy that refuses a token exchange asking for that scope together
with another managed audience scope. The behaviour of the policies themselves was run
against a local Keycloak 26.7.0; these tests pin what the sync sends."""

from __future__ import annotations

import json
import re

import pytest

from lib import keycloak_role_sync as kcs


class FakeRealm:
    """The parts of the Admin REST API the exchange sync touches."""

    def __init__(self, clients=("papaia-me", "papaia-manager")):
        self.scopes: dict[str, dict] = {}  # id -> rep
        self.clients: dict[str, dict] = {
            f"uuid-{cid}": {
                "id": f"uuid-{cid}",
                "clientId": cid,
                "attributes": {"login_theme": "papaia"},
            }
            for cid in clients
        }
        self.optional: dict[str, set[str]] = {uuid: set() for uuid in self.clients}
        self.profiles: list[dict] = [{"name": "operator-profile", "executors": []}]
        self.policies: list[dict] = [{"name": "operator-policy", "conditions": [], "profiles": []}]
        self.writes: list[tuple[str, str]] = []

    def __call__(self, base_url, ctx, token, method, path, body=None):
        if method != "GET":
            self.writes.append((method, path))
        if path == "/client-scopes" and method == "GET":
            return list(self.scopes.values())
        if path == "/client-scopes" and method == "POST":
            sid = f"scope-{body['name']}"
            self.scopes[sid] = {**body, "id": sid}
            return None
        m = re.fullmatch(r"/clients\?clientId=(.+)", path)
        if m:
            return [c for c in self.clients.values() if c["clientId"] == m.group(1)]
        m = re.fullmatch(r"/clients/([^/]+)", path)
        if m and method == "GET":
            return json.loads(json.dumps(self.clients[m.group(1)]))
        if m and method == "PUT":
            self.clients[m.group(1)].update(json.loads(json.dumps(body)))
            return None
        m = re.fullmatch(r"/clients/([^/]+)/optional-client-scopes", path)
        if m:
            return [self.scopes[s] for s in sorted(self.optional[m.group(1)])]
        m = re.fullmatch(r"/clients/([^/]+)/optional-client-scopes/([^/]+)", path)
        if m and method == "PUT":
            self.optional[m.group(1)].add(m.group(2))
            return None
        if m and method == "DELETE":
            self.optional[m.group(1)].discard(m.group(2))
            return None
        if path == "/client-policies/profiles" and method == "GET":
            return {"profiles": json.loads(json.dumps(self.profiles))}
        if path == "/client-policies/profiles" and method == "PUT":
            self.profiles = body["profiles"]
            return None
        if path == "/client-policies/policies" and method == "GET":
            return {"policies": json.loads(json.dumps(self.policies))}
        if path == "/client-policies/policies" and method == "PUT":
            self.policies = body["policies"]
            return None
        raise AssertionError((method, path))

    def optional_names(self, client_id: str) -> set[str]:
        return {self.scopes[s]["name"] for s in self.optional[f"uuid-{client_id}"]}

    def ours(self) -> dict[str, dict]:
        return {
            p["name"]: p for p in self.policies if p["name"].startswith(kcs.ONE_AUDIENCE_PREFIX)
        }


def _run(fake, wanted):
    return kcs._sync_token_exchange("https://kc", None, "t", wanted, api=fake)


def _registry(config_dir, audiences):
    path = config_dir / "personal-settings" / "registry.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    modules = [{"module": f"m{i}", "endpoint": {"audience": a}} for i, a in enumerate(audiences)]
    path.write_text(json.dumps({"registry": 1, "modules": modules}), encoding="utf-8")


def test_the_wanted_audiences_follow_the_profiles_and_the_registry(tmp_path):
    _registry(tmp_path, ["flow", "assist-api", "flow"])
    root = {"COMPOSE_PROFILES": "keycloak,me,manager"}
    assert kcs.exchange_audiences(root, tmp_path) == {
        "papaia-me": ["assist-api", "flow"],
        "papaia-manager": ["flow"],
    }
    assert kcs.exchange_audiences({"COMPOSE_PROFILES": "keycloak"}, tmp_path) == {}
    assert kcs.exchange_audiences({"COMPOSE_PROFILES": "me"}, tmp_path / "none") == {
        "papaia-me": []
    }


def test_an_audience_of_a_tampered_registry_is_ignored(tmp_path):
    _registry(tmp_path, ["flow", 'x"}]', "../admin"])
    assert kcs.registry_audiences(tmp_path) == ["flow"]


def test_scopes_optional_scopes_and_policies_are_created():
    fake = FakeRealm()
    _run(fake, {"papaia-me": ["assist-api", "flow"], "papaia-manager": ["flow"]})

    assert {s["name"] for s in fake.scopes.values()} == {"aud-assist-api", "aud-flow"}
    mapper = fake.scopes["scope-aud-flow"]["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.client.audience"] == "flow"
    assert mapper["config"]["access.token.claim"] == "true"
    assert fake.optional_names("papaia-me") == {"aud-assist-api", "aud-flow"}
    assert fake.optional_names("papaia-manager") == {"aud-flow"}
    for client in fake.clients.values():
        assert client["attributes"]["standard.token.exchange.enabled"] == "true"
        assert client["attributes"]["login_theme"] == "papaia", "other attributes stay"

    ours = fake.ours()
    assert set(ours) == {"papaia-one-audience-assist-api", "papaia-one-audience-flow"}
    flow = ours["papaia-one-audience-flow"]
    assert flow["enabled"] is True
    assert flow["profiles"] == [kcs.ONE_AUDIENCE_PROFILE]
    conditions = flow["conditions"]
    assert conditions[0] == {
        "condition": "grant-type",
        "configuration": {"grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    }
    assert conditions[1]["configuration"]["scopes"] == ["aud-flow"]
    assert conditions[2]["configuration"]["scopes"] == ["aud-assist-api"]
    profile = [p for p in fake.profiles if p["name"] == kcs.ONE_AUDIENCE_PROFILE]
    assert profile[0]["executors"] == [{"executor": "reject-request", "configuration": {}}]
    assert any(p["name"] == "operator-policy" for p in fake.policies), "foreign policies stay"
    assert any(p["name"] == "operator-profile" for p in fake.profiles), "foreign profiles stay"


def test_a_second_run_changes_nothing():
    fake = FakeRealm()
    wanted = {"papaia-me": ["assist-api", "flow"], "papaia-manager": ["flow"]}
    _run(fake, wanted)
    fake.writes.clear()
    assert _run(fake, wanted) == 0
    assert fake.writes == []


def test_one_audience_alone_needs_no_policy_and_old_policies_are_pruned():
    fake = FakeRealm()
    _run(fake, {"papaia-me": ["assist-api", "flow"], "papaia-manager": ["flow"]})
    _run(fake, {"papaia-me": [], "papaia-manager": ["flow"]})

    assert fake.ours() == {}
    assert fake.optional_names("papaia-me") == set(), "the scope of a removed module is detached"
    assert fake.optional_names("papaia-manager") == {"aud-flow"}
    assert {s["name"] for s in fake.scopes.values()} == {"aud-assist-api", "aud-flow"}, (
        "scopes are never deleted"
    )


def test_a_missing_client_is_reported_and_the_rest_still_runs(capsys):
    fake = FakeRealm(clients=("papaia-manager",))
    _run(fake, {"papaia-me": ["flow", "docs"], "papaia-manager": ["flow"]})
    assert "papaia-me" in capsys.readouterr().err
    assert fake.optional_names("papaia-manager") == {"aud-flow"}
    assert set(fake.ours()) == {"papaia-one-audience-docs", "papaia-one-audience-flow"}


def test_nothing_is_touched_when_no_profile_wants_an_exchange():
    fake = FakeRealm()
    assert _run(fake, {}) == 0
    assert fake.writes == []


@pytest.mark.parametrize("profiles", ["keycloak,me", "manager"])
def test_the_template_clients_are_created_for_existing_realms(profiles):
    wanted = kcs._active_profile_clients({"COMPOSE_PROFILES": profiles})
    if "me" in profiles:
        assert "papaia-me" in wanted
    else:
        assert "papaia-me" not in wanted


def test_the_realm_template_lets_both_clients_exchange():
    from pathlib import Path

    template = Path(__file__).resolve().parents[2] / (
        "src/infra/keycloak/realm-import/papaia-realm.json.template"
    )
    clients = {c["clientId"]: c for c in json.loads(template.read_text("utf-8"))["clients"]}
    me = clients["papaia-me"]
    assert me["attributes"]["standard.token.exchange.enabled"] == "true"
    assert me["attributes"]["pkce.code.challenge.method"] == "S256"
    assert me["publicClient"] is False and me["directAccessGrantsEnabled"] is False
    assert "optionalClientScopes" not in me and "defaultClientScopes" not in me, (
        "scopes come from the sync; naming them here would drop the realm defaults"
    )
    manager = clients["papaia-manager"]["attributes"]
    assert manager["standard.token.exchange.enabled"] == "true"
