"""papaia-ctl realm sync: the client of the core chat relay `papaia-chat-relay` (ADR 0029).

- the relay's client exists only while at least one opt-in (a confirmed pairing of
  `papaia-chat-relay` with an add-on's audience) is confirmed: token exchange,
  `fullScopeAllowed: false`, no sign-in of persons, no `client_credentials`,
  `private_key_jwt` with the key of the configuration directory, no refresh token;
- its optional scopes are exactly the `aud-*` scopes of the opted-in add-ons, never the
  scope of a suite server, a core audience or the relay itself;
- the audience mapper `papaia-chat-relay-audience` sits on `librechat` only while an
  opt-in is confirmed; nowhere else, never as a scope;
- the realm policy `chat-relay` lets the relay exchange only subject tokens of
  `librechat`; the one-audience policies apply to it like to every managed client.

The sync runs against the in-memory Admin API (tests/realm_fake.py).
"""

from __future__ import annotations

import json

import pytest

from lib import chat_relay
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import REGISTER, _pairings, _run

RELAY = "papaia-chat-relay"
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWKS = [
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "relay-key",
        "use": "sig",
        "alg": "ES256",
    }
]


def _connect() -> rs.Module:
    """An add-on outside the suite with a tool server for persons."""
    return rs.Module(
        "paperless-connect",
        [
            {
                "id": "paperless-connect.mcp",
                "kind": "mcp",
                "audience": "mcp-paperless",
                "identity": ["person"],
            }
        ],
        {},
    )


def _wiki() -> rs.Module:
    return rs.Module(
        "wiki-connect",
        [{"id": "wiki-connect.mcp", "kind": "mcp", "audience": "mcp-wiki", "identity": ["person"]}],
        {},
    )


def _map() -> rs.Module:
    """A suite module: its tool server reaches the chat directly, never through the relay."""
    return rs.Module(
        "papaia-knowledge-map",
        [
            {
                "id": "knowledge-map.mcp",
                "kind": "mcp",
                "audience": "mcp-knowledge-map",
                "identity": ["person"],
            }
        ],
        {},
    )


ELIGIBLE = {"mcp-paperless": "paperless-connect", "mcp-wiki": "wiki-connect"}


def _plan(modules, pairings=(), *, eligible=None, jwks=JWKS, **kwargs) -> rs.Plan:
    return rs.build_plan(
        REGISTER,
        list(modules),
        list(pairings),
        relay_eligible=ELIGIBLE if eligible is None else eligible,
        relay_jwks=jwks,
        **kwargs,
    )


def _opt_in(*audiences, state="confirmed"):
    return _pairings(*((RELAY, audience, ["r"], state) for audience in audiences))


def _realm() -> FakeRealm:
    realm = FakeRealm()
    # The chat's client comes from the realm template, never from the sync.
    realm.call(
        "POST",
        "/clients",
        {"clientId": "librechat", "publicClient": False, "standardFlowEnabled": True},
    )
    return realm


def _relay_mappers(realm: FakeRealm) -> list[dict]:
    return [
        mapper
        for client in realm.clients.values()
        for mapper in client["protocolMappers"]
        if (mapper.get("config") or {}).get("included.client.audience") == RELAY
    ]


# ─────────────────────────────────────────────────────────────────────────
# plan
# ─────────────────────────────────────────────────────────────────────────


def test_without_an_opt_in_no_relay_client_is_planned():
    plan = _plan([_connect()])
    assert RELAY not in plan.clients
    assert "chat-relay" not in plan.policies


def test_a_pending_opt_in_plans_no_relay_client():
    plan = _plan([_connect()], _opt_in("mcp-paperless", state="pending"))
    assert RELAY not in plan.clients


def test_an_opt_in_for_an_add_on_that_is_not_installed_plans_nothing():
    plan = _plan([], _opt_in("mcp-paperless"))
    assert RELAY not in plan.clients


def test_a_confirmed_opt_in_plans_the_relay_with_exactly_the_opted_in_audiences():
    plan = _plan([_connect(), _wiki()], _opt_in("mcp-paperless"))
    spec = plan.clients[RELAY]
    assert spec.owner == "papaia"
    assert spec.kind == "exchange-only"
    assert spec.token_exchange is True
    assert spec.optional_scopes == {"aud-mcp-paperless"}
    assert not {s for s in spec.default_scopes if s.startswith("aud-")}
    assert spec.authenticator == "client-jwt"
    assert spec.jwks == JWKS
    assert spec.key_file == "security/chat-relay/private-key.pem"

    both = _plan([_connect(), _wiki()], _opt_in("mcp-paperless", "mcp-wiki"))
    assert both.clients[RELAY].optional_scopes == {"aud-mcp-paperless", "aud-mcp-wiki"}


def test_no_scope_for_a_suite_audience():
    with pytest.raises(rs.RealmSyncError, match="not eligible for the chat relay"):
        _plan([_connect(), _map()], _opt_in("mcp-knowledge-map"))


def test_no_scope_for_a_core_audience():
    # The core's own audiences are paired by the realm sync alone, or with named clients.
    for audience in ("papaia-people", "papaia-audit"):
        with pytest.raises(rs.RealmSyncError):
            _opt_in(audience)


def test_the_relay_is_never_paired_as_an_audience():
    with pytest.raises(rs.RealmSyncError, match="never an audience"):
        _opt_in(RELAY)


def test_an_opt_in_with_two_persons_is_the_only_way_to_write():
    with pytest.raises(rs.RealmSyncError, match="second person"):
        _pairings((RELAY, "mcp-paperless", ["r", "w"], "confirmed"))


def test_a_missing_key_file_leaves_the_relay_without_a_key():
    plan = _plan([_connect()], _opt_in("mcp-paperless"), jwks=None)
    assert plan.clients[RELAY].key_missing is True
    assert any("chat relay" in note for note in plan.notes)


def test_the_policy_lets_the_relay_exchange_only_tokens_of_the_chat():
    plan = _plan([_connect()], _opt_in("mcp-paperless"))
    policy = plan.policies["chat-relay"]
    assert {c["condition"] for c in policy["conditions"]} == {"grant-type", "client-attributes"}
    grant = next(c for c in policy["conditions"] if c["condition"] == "grant-type")
    assert grant["configuration"]["grant_types"] == [TE]
    attribute = next(c for c in policy["conditions"] if c["condition"] == "client-attributes")
    assert json.loads(attribute["configuration"]["attributes"]) == [
        {"key": "papaia.chat-relay", "value": "true"}
    ]
    assert policy["profiles"] == ["chat-relay"]
    (executor,) = plan.profiles["chat-relay"]["executors"]
    assert executor == {
        "executor": "jwt-claim-enforcer",
        "configuration": {"claim-name": "azp", "allowed-value": "^librechat$"},
    }


def test_two_opt_ins_are_never_exchanged_together():
    plan = _plan([_connect(), _wiki()], _opt_in("mcp-paperless", "mcp-wiki"))
    assert "papaia-one-aud-mcp-paperless-mcp-wiki" in plan.policies


# ─────────────────────────────────────────────────────────────────────────
# realm
# ─────────────────────────────────────────────────────────────────────────


def test_the_relay_client_exchanges_for_its_audiences_and_signs_nobody_in():
    realm = _realm()
    _run(realm, _plan([_connect()], _opt_in("mcp-paperless")))
    client = realm.by_client_id(RELAY)
    assert client["standardFlowEnabled"] is False
    assert client["serviceAccountsEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert client["implicitFlowEnabled"] is False
    assert client["fullScopeAllowed"] is False
    assert client["publicClient"] is False
    assert client["clientAuthenticatorType"] == "client-jwt"
    attributes = client["attributes"]
    assert attributes["standard.token.exchange.enabled"] == "true"
    assert attributes["standard.token.exchange.enableRefreshRequestedTokenType"] == "NO"
    assert attributes["papaia.chat-relay"] == "true"
    assert attributes["papaia.owner"] == "papaia"
    assert json.loads(attributes["jwks.string"]) == {"keys": JWKS}
    assert realm.scope_names(RELAY, "optional") == {"aud-mcp-paperless"}
    assert not {n for n in realm.scope_names(RELAY, "default") if n.startswith("aud-")}
    assert "offline_access" not in realm.scope_names(RELAY, "optional")
    assert "aud-papaia-chat-relay" not in {s["name"] for s in realm.scopes.values()}


def test_the_mapper_sits_on_the_chat_client_only_while_an_opt_in_exists():
    realm = _realm()
    _run(realm, _plan([_connect()]))
    assert _relay_mappers(realm) == []

    _run(realm, _plan([_connect()], _opt_in("mcp-paperless")))
    (mapper,) = _relay_mappers(realm)
    assert mapper in realm.by_client_id("librechat")["protocolMappers"]
    assert mapper["name"] == "papaia-chat-relay-audience"
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["id.token.claim"] == "false"
    assert _run(realm, _plan([_connect()], _opt_in("mcp-paperless"))) == []

    # The last opt-in goes: mapper, client and policy go with it.
    changes = _run(realm, _plan([_connect()]))
    assert _relay_mappers(realm) == []
    assert RELAY not in {c["clientId"] for c in realm.clients.values()}
    assert "chat-relay" not in {p["name"] for p in realm.policies}
    assert {"remove_mapper", "delete_client"} <= {c.operation for c in changes}
    assert _run(realm, _plan([_connect()])) == []


def test_a_relay_mapper_elsewhere_is_removed():
    realm = _realm()
    realm.call("POST", "/clients", {"clientId": "hand-made", "publicClient": False})
    hand = realm.by_client_id("hand-made")
    realm.call(
        "POST",
        f"/clients/{hand['id']}/protocol-mappers/models",
        {
            "name": "relay",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": RELAY, "access.token.claim": "true"},
        },
    )
    _run(realm, _plan([_connect()], _opt_in("mcp-paperless")))
    (mapper,) = _relay_mappers(realm)
    assert mapper in realm.by_client_id("librechat")["protocolMappers"]


def test_the_relay_mark_stays_with_the_relay_client():
    realm = _realm()
    realm.call(
        "POST",
        "/clients",
        {
            "clientId": "hand-made",
            "publicClient": False,
            "attributes": {"papaia.chat-relay": "true"},
        },
    )
    _run(realm, _plan([_connect()], _opt_in("mcp-paperless")))
    assert realm.by_client_id("hand-made")["attributes"].get("papaia.chat-relay", "") == ""
    assert realm.by_client_id(RELAY)["attributes"]["papaia.chat-relay"] == "true"


def test_a_revoked_opt_in_loses_its_scope_at_the_next_sync():
    realm = _realm()
    _run(realm, _plan([_connect(), _wiki()], _opt_in("mcp-paperless", "mcp-wiki")))
    assert realm.scope_names(RELAY, "optional") == {"aud-mcp-paperless", "aud-mcp-wiki"}
    _run(realm, _plan([_connect(), _wiki()], _opt_in("mcp-wiki")))
    assert realm.scope_names(RELAY, "optional") == {"aud-mcp-wiki"}


# ─────────────────────────────────────────────────────────────────────────
# eligibility from the catalog
# ─────────────────────────────────────────────────────────────────────────


def _entry(**extra) -> dict:
    entry = {
        "id": "connect.mcp",
        "provider": "paperless-connect",
        "kind": "mcp",
        "trust": "addon",
        "identity": ["person"],
        "audience": "mcp-paperless",
        "address": "http://paperless-connect:8000/mcp",
    }
    entry.update(extra)
    return entry


@pytest.mark.parametrize(
    "extra",
    [
        {"trust": "platform"},
        {"provider": "core:rag"},
        {"kind": "rest"},
        {"identity": ["service"]},
        {"address": None},
        {"audience": None},
    ],
)
def test_only_person_tool_servers_of_add_ons_outside_the_suite_are_eligible(extra):
    assert chat_relay.eligible_entries({"services": [_entry()]}, set()) == {
        "mcp-paperless": "paperless-connect"
    }
    assert chat_relay.eligible_entries({"services": [_entry(**extra)]}, set()) == {}


def test_an_add_on_that_attaches_the_chat_is_not_eligible():
    assert chat_relay.eligible_entries({"services": [_entry()]}, {"paperless-connect"}) == {}
    assert chat_relay.attaches_chat({"networks": {"attach": ["librechat"]}})
    assert chat_relay.attaches_chat(
        {"networks": {"isolated": [{"network": "x", "attach": ["librechat"]}]}}
    )
    assert not chat_relay.attaches_chat({"networks": {"attach": ["litellm"]}})
    assert not chat_relay.attaches_chat({})


def test_render_makes_the_key_once_and_the_list_folder(tmp_path):
    chat_relay.render(tmp_path)
    first = chat_relay.public_jwks(tmp_path)
    assert first and first[0]["crv"] == "P-256" and "d" not in first[0]
    key = tmp_path / "security" / "chat-relay" / "private-key.pem"
    assert key.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "security" / "chat-relay").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "chat-relay").is_dir()
    assert not (tmp_path / "chat-relay" / "servers.json").exists()
    chat_relay.render(tmp_path)
    assert chat_relay.public_jwks(tmp_path) == first
