"""Consistency of the knowledge-map module, read from the real checkout.

The module's names cross five files that nothing else ties together: the
compose file, its .env.example, the realm template, the LibreChat fragment and
the secret alias map. A rename in one of them breaks sign-in or the MCP wiring
only at runtime, so the contract is pinned here — mirroring the rag module's
test for the same reason.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from lib import keycloak_role_sync, render_core, secrets

REPO = Path(__file__).resolve().parents[2]
KM_DIR = REPO / "src" / "ai" / "knowledge-map"
AUDIENCE = "mcp-knowledge-map"


def _compose() -> dict:
    return yaml.safe_load((KM_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def _realm() -> dict:
    template = (REPO / "src/infra/keycloak/realm-import/papaia-realm.json.template").read_text(
        encoding="utf-8"
    )
    return json.loads(re.sub(r"\$\{env\.([^}]+)\}", r"secret-of-\1", template))


def test_compose_ships_one_service_on_the_profile():
    services = _compose()["services"]
    assert set(services) == {"knowledge-map-mcp"}
    assert services["knowledge-map-mcp"]["profiles"] == ["knowledge-map"]
    # The own audience comes first and is fixed (the realm template and the
    # LibreChat fragment depend on it); operator extras may only follow.
    audiences = services["knowledge-map-mcp"]["environment"]["OIDC_AUDIENCE"].split(",")
    assert audiences == [AUDIENCE, "${KM_EXTRA_AUDIENCES:-}"]


def test_compose_mounts_the_operator_directory_read_only():
    service = _compose()["services"]["knowledge-map-mcp"]
    assert "${PAPAIA_CONFIG_DIR}/overlay/knowledge-map:/overlay:ro" in service["volumes"]
    assert service["environment"]["KM_GOLDSET_PATH"] == "/overlay/goldset.yaml"
    assert service["environment"]["KM_ADMIN_TOKEN"] == "${KM_ADMIN_TOKEN}"


def test_realm_template_ships_the_resource_server_and_mapper():
    realm = _realm()
    clients = {c["clientId"]: c for c in realm["clients"]}
    for client_id in keycloak_role_sync.PROFILE_CLIENTS["knowledge-map"]:
        assert client_id in clients, client_id
    client = clients[AUDIENCE]
    assert client["standardFlowEnabled"] is False
    assert client["fullScopeAllowed"] is False
    assert "secret" not in client

    audiences = {
        m["config"]["included.client.audience"]
        for m in clients["librechat"]["protocolMappers"]
        if m["protocolMapper"] == "oidc-audience-mapper"
    }
    assert AUDIENCE in audiences


def test_librechat_fragment_matches_the_compose_wiring():
    fragment = yaml.safe_load(
        (KM_DIR / "integration/ai/librechat/librechat.yaml").read_text(encoding="utf-8")
    )
    server = fragment["mcpServers"]["KnowledgeMap"]
    # Lazy init is load-bearing: without it LibreChat burns 120 s per retry in
    # OAuth discovery against a server that only validates bearer tokens.
    assert server["startup"] is False
    assert server["url"] == "http://knowledge-map-mcp:8200/mcp"
    assert server["url"].rsplit("/", 1)[0] in fragment["mcpSettings"]["allowedDomains"]


def test_profile_fragment_and_module_knowledge_are_registered():
    assert render_core.PROFILE_FRAGMENTS["knowledge-map"] == "src/ai/knowledge-map"
    # The rag module feeds the map; its declaration must parse and carry ids.
    from lib import knowledge_map

    assert knowledge_map.MODULE_KNOWLEDGE["rag"] == "src/ai/rag"
    data = yaml.safe_load((REPO / "src/ai/rag/knowledge.yaml").read_text(encoding="utf-8"))
    assert all(s.get("id") for s in data["sources"])


def test_embedding_key_is_aliased_from_the_litellm_master_key():
    aliases = secrets.SECRET_ALIASES[("ai/litellm", "LITELLM_MASTER_KEY")]
    assert ("ai/knowledge-map", "KM_EMBEDDING_API_KEY") in aliases
    example = (KM_DIR / ".env.example").read_text(encoding="utf-8")
    assert "KM_EMBEDDING_API_KEY=GENERATE_KM_EMBEDDING_API_KEY" in example


def test_root_compose_includes_the_module():
    root = yaml.safe_load((REPO / "src/docker-compose.yml").read_text(encoding="utf-8"))
    assert {"path": "./ai/knowledge-map/docker-compose.yml"} in root["include"]


def test_governance_example_loads_without_unknown_keys(tmp_path):
    from lib import knowledge_map

    target = tmp_path / knowledge_map.GOVERNANCE_REL_PATH
    target.parent.mkdir(parents=True)
    target.write_text(
        (KM_DIR / "governance.yaml.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    governance = knowledge_map.load_governance(tmp_path)
    assert governance["unknown_keys"] == []
    assert governance["models"]["nomic-embed-text"]["tier"] == "local"
    assert governance["exceptions"][0]["risk_ref"] == "RISK-12"
