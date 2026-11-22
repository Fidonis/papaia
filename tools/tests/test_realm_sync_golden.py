"""Golden output of the realm sync: what it writes and reports for fixed declarations.

The realm sync builds and recognises exchange scopes through the platform kit
(`lib/kit_names.py`). This snapshot pins its observable output — every change it
reports and the clients, scopes and realm defaults it leaves behind — for a fresh
realm, a realm with manual drift around exchange scopes, and declared service
accounts, so a change in how scope names are built cannot change what the sync does.

Regenerate only for an intended change of the sync's output:
`PAPAIA_UPDATE_GOLDEN=1 uv run --locked --extra dev python -m pytest
tests/test_realm_sync_golden.py`, and review the diff of `golden/realm-sync.json`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from lib import realm_sync as rs
from lib import service_accounts as sa
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import DELEGATION, TWO_PERSONS, _flow, _pairings, _paperless, _studio
from tests.test_service_accounts import _full_plan as _accounts_plan
from tests.test_service_accounts import _keys

GOLDEN = Path(__file__).parent / "golden" / "realm-sync.json"
REGISTER = rs.load_register()


def _plan(modules, pairings=()) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), list(pairings))


def _full_plan() -> rs.Plan:
    return _plan(
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(
            ("flow-engine", "mcp-paperless", ["r", "w", "d"], "confirmed", TWO_PERSONS),
            ("papaia-studio-gateway", "mcp-paperless", ["r"], "confirmed"),
            ("papaia-studio-gateway", "flow", ["x"], "confirmed"),
            ("flow-engine", "mcp-qdrant", ["r"], "confirmed"),
            ("papaia-studio-gateway", "papaia-data", ["r", "x"], "pending"),
        ),
    )


def _changes(changes: list[rs.Change]) -> list[dict]:
    return [
        {
            "kind": c.kind,
            "name": c.name,
            "action": c.action,
            "operation": c.operation,
            "event": c.event,
            "effect": c.effect,
        }
        for c in changes
    ]


def _mapper(mapper: dict) -> dict:
    return {k: mapper[k] for k in ("name", "protocolMapper", "config") if k in mapper}


def _state(realm: FakeRealm) -> dict:
    """The parts of the realm the sync manages, without generated ids and key material."""
    clients = {}
    for client in realm.clients.values():
        attributes = {
            k: v for k, v in (client.get("attributes") or {}).items() if k != "jwks.string"
        }
        attributes.pop(rs.ROTATED_AT, None)
        clients[client["clientId"]] = {
            "default": sorted(realm.scope_names(client["clientId"], "default")),
            "optional": sorted(realm.scope_names(client["clientId"], "optional")),
            "attributes": dict(sorted(attributes.items())),
            "mappers": sorted(
                (_mapper(m) for m in client.get("protocolMappers") or []),
                key=lambda m: json.dumps(m, sort_keys=True),
            ),
        }
    scopes = {
        scope["name"]: {
            "attributes": dict(sorted((scope.get("attributes") or {}).items())),
            "mappers": sorted(
                (_mapper(m) for m in scope.get("protocolMappers") or []),
                key=lambda m: json.dumps(m, sort_keys=True),
            ),
        }
        for scope in realm.scopes.values()
    }
    return {
        "clients": dict(sorted(clients.items())),
        "scopes": dict(sorted(scopes.items())),
        "realm_default_default": sorted(realm.scopes[i]["name"] for i in realm.default_default),
        "realm_default_optional": sorted(realm.scopes[i]["name"] for i in realm.default_optional),
    }


def _audience_mapper(audience: str) -> dict:
    return {
        "name": f"audience {audience}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": audience, "access.token.claim": "true"},
    }


def _fresh() -> dict:
    realm = FakeRealm()
    plan = _full_plan()
    first = rs.reconcile(realm.call, plan, apply=True)
    second = rs.reconcile(realm.call, plan, apply=False)
    return {"changes": _changes(first), "again": _changes(second), "realm": _state(realm)}


def _drift() -> dict:
    """Exchange scopes where they do not belong: on a default list, among the realm's
    defaults, a stale managed one, one of an exchange client, one on an unmanaged client."""
    realm = FakeRealm()
    plan = _full_plan()
    rs.reconcile(realm.call, plan, apply=True)
    gateway = realm.by_client_id("papaia-studio-gateway")
    gateway["_default"].append(realm._scope_id("aud-flow"))
    realm.default_default.append(realm.scope_by_name("aud-flow")["id"])
    realm.default_optional.append(realm.scope_by_name("aud-mcp-paperless")["id"])
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-mcp-wiki",
            "protocol": "openid-connect",
            "attributes": {"papaia.managed": "true"},
            "protocolMappers": [_audience_mapper("mcp-wiki")],
        },
    )
    realm.call(
        "POST",
        "/client-scopes",
        {
            "name": "aud-flow-engine",
            "protocol": "openid-connect",
            "protocolMappers": [_audience_mapper("flow-engine")],
        },
    )
    realm.call("POST", "/client-scopes", {"name": "aud-hand-made", "protocol": "openid-connect"})
    realm.call(
        "POST",
        "/clients",
        {
            "clientId": "librechat",
            "publicClient": False,
            "directAccessGrantsEnabled": False,
            "defaultClientScopes": ["aud-flow"],
            "optionalClientScopes": ["aud-mcp-paperless", "aud-hand-made"],
        },
    )
    drift = rs.reconcile(realm.call, plan, apply=False)
    repair = rs.reconcile(realm.call, plan, apply=True)
    after = rs.reconcile(realm.call, plan, apply=False)
    return {
        "drift": _changes(drift),
        "repair": _changes(repair),
        "again": _changes(after),
        "realm": _state(realm),
    }


def _revoked() -> dict:
    realm = FakeRealm()
    rs.reconcile(realm.call, _full_plan(), apply=True)
    plan = _plan(
        [_flow(delegation=DELEGATION), _studio(), _paperless()],
        _pairings(("papaia-studio-gateway", "flow", ["x"], "confirmed")),
    )
    changes = rs.reconcile(realm.call, plan, apply=True)
    return {"changes": _changes(changes), "realm": _state(realm)}


def _accounts(tmp_path: Path) -> dict:
    realm, keys = FakeRealm(), _keys(tmp_path)
    plan = _accounts_plan()
    changes = rs.reconcile(realm.call, plan, apply=True, keys=keys, master=realm.call)
    rows = sa.describe(realm.call, now=1_790_000_000.0)
    listed = [
        {k: row[k] for k in ("id", "module", "audiences", "roles", "effects")} for row in rows
    ]
    return {
        "changes": _changes(changes),
        "plan": {
            name: {"default": sorted(spec.default_scopes), "optional": sorted(spec.optional_scopes)}
            for name, spec in sorted(plan.clients.items())
        },
        "exchange_scopes": dict(sorted(plan.exchange_scopes.items())),
        "list": listed,
        "realm": _state(realm),
    }


def _output(tmp_path: Path) -> dict:
    plan = _full_plan()
    return {
        "plan": {
            "exchange_scopes": dict(sorted(plan.exchange_scopes.items())),
            "clients": {
                name: {
                    "default": sorted(spec.default_scopes),
                    "optional": sorted(spec.optional_scopes),
                }
                for name, spec in sorted(plan.clients.items())
            },
        },
        "fresh": _fresh(),
        "drift": _drift(),
        "revoked": _revoked(),
        "accounts": _accounts(tmp_path),
    }


def test_the_realm_sync_output_matches_the_golden_snapshot(tmp_path):
    output = json.loads(json.dumps(_output(tmp_path), sort_keys=True))
    if os.environ.get("PAPAIA_UPDATE_GOLDEN"):
        GOLDEN.write_text(json.dumps(output, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert output == golden
