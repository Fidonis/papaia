"""Consistency of the rag module, read from the real checkout.

The module's names cross five files that nothing else ties together: the compose
file, its .env.example, the realm template, the LibreChat fragment and the
secret alias map. A rename in one of them breaks sign-in or the MCP wiring only
at runtime, so the contract is pinned here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from lib import common, compat, envtree, keycloak_role_sync, render_core, resolve, secrets

REPO = Path(__file__).resolve().parents[2]
RAG_DIR = REPO / "src" / "ai" / "rag"
RAG_SERVICES = {"qdrant", "qdrant-mcp", "qdrant-ingest", "qdrant-ingest-tika"}

# Variables docker compose takes from the root .env or the environment of the
# process, not from the module's own .env.
PLATFORM_VARS = {"HOST_IP", "PAPAIA_CONFIG_DIR", "UID", "GID", "OIDC_ISSUER"}


def _compose() -> dict:
    return yaml.safe_load((RAG_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def _realm() -> dict:
    template = (REPO / "src/infra/keycloak/realm-import/papaia-realm.json.template").read_text(
        encoding="utf-8"
    )
    return json.loads(re.sub(r"\$\{env\.([^}]+)\}", r"secret-of-\1", template))


def _documented_keys(example: Path) -> set[str]:
    """Keys of an .env.example, set or only documented in a `# KEY=value` line."""
    keys = set(common.parse_env_file(example))
    for line in example.read_text(encoding="utf-8").splitlines():
        match = re.match(r"#\s*([A-Z][A-Z0-9_]*)=", line)
        if match:
            keys.add(match.group(1))
    return keys


def test_the_root_compose_includes_the_module_under_the_rag_profile():
    services = compat.resolve_core_services(REPO)
    assert {name for name in services if name in RAG_SERVICES} == RAG_SERVICES
    assert all(services[name] == ["rag"] for name in RAG_SERVICES)


def test_every_service_is_labelled_for_the_module_and_joins_papaia_net():
    for name, service in _compose()["services"].items():
        assert service["labels"]["de.fidonis.module"] == "papaia-rag", name
        assert service["labels"]["de.fidonis.role"], name
        assert service["networks"] == ["papaia-net"], name
        assert service["profiles"] == ["rag"], name


def test_every_interpolated_variable_is_documented():
    # Comments are skipped: the file's own header explains the `${VAR}` syntax.
    code = "\n".join(
        re.sub(r"\s#.*$", "", line)
        for line in (RAG_DIR / "docker-compose.yml").read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", code))
    assert used, "the module interpolates at least its ports and secrets"
    documented = _documented_keys(RAG_DIR / ".env.example") | _documented_keys(
        REPO / "src" / ".env.example"
    )
    assert used - documented == set()
    # The platform variables must exist in the root .env.example, not just by name.
    root = _documented_keys(REPO / "src" / ".env.example")
    assert PLATFORM_VARS & used <= root


def test_ingest_environment_does_not_repeat_a_key_of_its_env_file():
    """environment: wins over env_file: and resolves through compose
    interpolation, which would blank a value set only in ai/rag/.env."""
    environment = set(_compose()["services"]["qdrant-ingest"]["environment"])
    active = set(common.parse_env_file(RAG_DIR / ".env.example"))
    assert environment & active == set()


def test_the_other_services_do_not_receive_the_whole_env_file():
    services = _compose()["services"]
    for name in ("qdrant", "qdrant-mcp", "qdrant-ingest-tika"):
        assert "env_file" not in services[name], name


def test_only_the_two_documented_ports_are_published():
    published = {
        name: service["ports"]
        for name, service in _compose()["services"].items()
        if service.get("ports")
    }
    assert published == {
        "qdrant": ["${HOST_IP:-127.0.0.1}:${QDRANT_EXT_PORT:-6333}:6333"],
        "qdrant-ingest": ["${HOST_IP:-127.0.0.1}:${QDRANT_INGEST_EXT_PORT:-8300}:8300"],
    }


def test_root_env_example_carries_the_derivable_urls_and_ports():
    root = common.parse_env_file(REPO / "src" / ".env.example")
    assert root["QDRANT_EXT_PORT"] == "6333"
    assert root["QDRANT_INGEST_EXT_PORT"] == "8300"
    assert root["QDRANT_PUBLIC_URL"].endswith(":" + root["QDRANT_EXT_PORT"])
    # The ingester has no web interface, so there is no browser-facing URL for it.
    assert "QDRANT_INGEST_PUBLIC_URL" not in root


def test_alias_targets_in_the_module_are_generated_placeholders():
    """An alias fan-out only writes into a key that exists, and the external
    OIDC path only recognises a GENERATE_ marker as a value to replace."""
    seed = envtree.load_seed_tree(REPO)["ai/rag"]
    targets = [
        key
        for aliases in secrets.SECRET_ALIASES.values()
        for alias_dir, key in aliases
        if alias_dir == "ai/rag"
    ]
    assert sorted(targets) == ["QDRANT_MCP_EMBEDDING_API_KEY", "QI_EMBEDDING_API_KEY"]
    for key in targets:
        assert common.marks_generated_secret(seed[key]), key


def test_every_secret_of_the_module_is_generated_by_setup():
    seed = envtree.load_seed_tree(REPO)["ai/rag"]
    generated = {key for key, value in seed.items() if common.marks_generated_secret(value)}
    assert {"QDRANT_JWT_SECRET", "QI_CONNECTIONS_SECRET", "QI_API_TOKEN"} <= generated


def test_no_key_of_the_module_is_deleted_by_the_removed_keys_cleanup():
    """resolve._REMOVED_KEYS drops keys of the retired qdrant-rag module on every
    setup; a new key with a retired name would vanish on the next run."""
    seed = envtree.load_seed_tree(REPO)
    for node, key in resolve._REMOVED_KEYS:
        assert key not in seed.get(node, {}), (node, key)


def test_realm_template_ships_the_rag_clients_roles_and_mappers():
    realm = _realm()
    clients = {c["clientId"]: c for c in realm["clients"]}
    for client_id in keycloak_role_sync.PROFILE_CLIENTS["rag"]:
        assert client_id in clients, client_id

    for resource_server in ("mcp-qdrant", "mcp-qdrant-ingest"):
        client = clients[resource_server]
        assert client["standardFlowEnabled"] is False
        assert client["fullScopeAllowed"] is False
        assert "secret" not in client

    roles = {r["name"]: r for r in realm["roles"]["realm"]}
    assert {"qdrant-admin", "qdrant-ingest-operator"} <= set(roles)
    composite = set(roles["papaia-admin"]["composites"]["realm"])
    assert {"qdrant-admin", "qdrant-ingest-operator"} <= composite

    audiences = {
        m["config"]["included.client.audience"]
        for m in clients["librechat"]["protocolMappers"]
        if m["protocolMapper"] == "oidc-audience-mapper"
    }
    assert audiences == {"mcp-qdrant", "mcp-qdrant-ingest"}


def test_the_removed_ingest_web_interface_leaves_nothing_behind():
    """qdrant-ingest 1.0.0 serves no web interface (`/ui` answers 404) and ignores its
    settings, so none of its client, secrets or URLs may stay in the module."""
    seed = envtree.load_seed_tree(REPO)
    assert not [key for key in seed["ai/rag"] if key.startswith("QI_UI_")]
    assert "KC_QDRANT_INGEST_UI_CLIENT_SECRET" not in seed["infra/keycloak"]

    clients = {c["clientId"] for c in _realm()["clients"]}
    assert "qdrant-ingest-ui" not in clients

    ingest = _compose()["services"]["qdrant-ingest"]
    assert not [key for key in ingest["environment"] if key.startswith("QI_UI_")]
    assert "QDRANT_INGEST_PUBLIC_URL" not in (RAG_DIR / "docker-compose.yml").read_text(
        encoding="utf-8"
    )


def test_the_ingester_only_reads_the_catalog_papaia_manager_writes():
    volumes = _compose()["services"]["qdrant-ingest"]["volumes"]
    catalog = [v for v in volumes if ":/config/catalog" in v]
    assert catalog == ["${PAPAIA_CONFIG_DIR}/ai/rag/catalog:/config/catalog:ro"]


def test_compose_constants_match_the_realm_and_the_librechat_fragment():
    realm = _realm()
    services = _compose()["services"]
    mcp = services["qdrant-mcp"]["environment"]
    role_names = {r["name"] for r in realm["roles"]["realm"]}
    client_ids = {c["clientId"] for c in realm["clients"]}

    assert mcp["OIDC_AUDIENCE"] in client_ids
    assert mcp["RBAC_ADMIN_ROLE"] in role_names

    fragment = yaml.safe_load(
        (RAG_DIR / "integration/ai/librechat/librechat.yaml").read_text(encoding="utf-8")
    )
    servers = fragment["mcpServers"]
    assert servers["Qdrant"]["url"] == f"http://qdrant-mcp:{mcp['MCP_PORT']}{mcp['MCP_PATH']}"
    ingest_port = services["qdrant-ingest"]["environment"]["QI_HTTP_PORT"]
    assert servers["QdrantIngest"]["url"] == f"http://qdrant-ingest:{ingest_port}/mcp"
    allowed = set(fragment["mcpSettings"]["allowedDomains"])
    assert allowed == {f"http://qdrant-mcp:{mcp['MCP_PORT']}", f"http://qdrant-ingest:{ingest_port}"}


def test_the_profile_fragment_registered_with_render_core_exists():
    path = REPO / render_core.PROFILE_FRAGMENTS["rag"]
    assert (path / "integration/ai/librechat/librechat.yaml").is_file()
