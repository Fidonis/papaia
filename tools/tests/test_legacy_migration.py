"""Migration of the legacy descriptions (V-10 steps 2, 3 and 13): the core generates the
LibreChat entry and the audience mapper of a platform tool server from its `exposes:`
declaration, and `knowledge:` key tools name operations of `exposes`."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest
import yaml
from install_helpers import REPO, Installation

from lib import (
    catalog,
    chat_servers,
    cli_addon,
    compat,
    exposes,
    keycloak_role_sync,
    knowledge_map,
    realm_sync,
    reporting,
)

FIXTURES = Path(__file__).parent / "fixtures" / "catalog"
LIBRECHAT = Path("ai/librechat/librechat.yaml")
REALM = Path("infra/keycloak/realm-import/papaia-realm.json")


# ─────────────────────────────────────────────────────────────────────────
# an installation with the probe add-on
# ─────────────────────────────────────────────────────────────────────────


def _with_probe_in_the_suite(repo: Path) -> None:
    """The checkout's compatibility matrix names the probe in every suite, so the catalog
    marks it `trust: platform` whatever the checkout's version (the core never takes
    trust from the add-on)."""
    matrix = yaml.safe_load((REPO / "compat" / "suite.yaml").read_text(encoding="utf-8"))
    matrix["components"].append("probe")
    for row in matrix["suites"]:
        row["versions"]["probe"] = ">=0.3.0,<0.4.0"
    (repo / "compat").mkdir(exist_ok=True)
    (repo / "compat" / "suite.yaml").write_text(yaml.safe_dump(matrix, sort_keys=False))


def _probe(tmp_path: Path, **manifest_changes) -> Path:
    path = tmp_path / "addons" / "probe"
    shutil.copytree(FIXTURES / "addon-probe", path)
    if manifest_changes:
        manifest_path = path / "papaia-app.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest.update(manifest_changes)
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def _installation(tmp_path: Path, *, in_suite: bool = True) -> Installation:
    inst = Installation(tmp_path, ["--app-host=https://papaia.example.org"])
    if in_suite:
        _with_probe_in_the_suite(inst.repo)
    inst.setup(*inst.flags)
    return inst


def _install(inst: Installation, path: Path) -> int:
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="probe", path=str(path),
        version=None, force=False, node=None,
    )
    return cli_addon.cmd_addon_install(args)


def _librechat(inst: Installation) -> dict:
    return yaml.safe_load((inst.config / LIBRECHAT).read_text(encoding="utf-8"))


def _librechat_mappers(inst: Installation) -> dict[str, dict]:
    realm = json.loads((inst.config / REALM).read_text(encoding="utf-8"))
    client = next(c for c in realm["clients"] if c["clientId"] == "librechat")
    return {m["name"]: m for m in client.get("protocolMappers", [])}


def _catalog_entry(inst: Installation, catalog_id: str) -> dict:
    doc = json.loads((inst.config / "platform" / "services.json").read_text(encoding="utf-8"))
    return next(e for e in doc["services"] if e["id"] == catalog_id)


def test_installing_the_probe_addon_yields_the_chat_entry_and_the_mapper(tmp_path, capsys):
    inst = _installation(tmp_path)
    probe = _probe(tmp_path)
    assert not (probe / "integration").exists()  # the add-on ships no chat fragment

    assert _install(inst, probe) == 0
    out = capsys.readouterr().out

    entry = _catalog_entry(inst, "probe.echo")
    assert entry["trust"] == "platform"
    server = _librechat(inst)["mcpServers"][entry["audience"]]
    assert server == {
        "title": "Probe connection",
        "description": "Echoes the input and writes notes.",
        "type": "streamable-http",
        "url": entry["address"],
        "headers": {"Authorization": "Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}"},
        "startup": False,
    }
    assert "http://probe-mcp:8080" in _librechat(inst)["mcpSettings"]["allowedDomains"]

    mapper = _librechat_mappers(inst)["mcp-probe-audience"]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.client.audience"] == "mcp-probe"
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["id.token.claim"] == "false"

    # No file of the old format: no hand-made fragment, no second manifest folder, and
    # the operator is not asked to import a mapper by hand.
    assert not list(inst.config.rglob("addon-manifests"))
    assert not (inst.config / "addons" / "probe" / "integration").exists()
    assert "Add protocol mappers" not in out


def test_the_chat_entry_and_the_mapper_go_with_the_addon(tmp_path):
    inst = _installation(tmp_path)
    assert _install(inst, _probe(tmp_path)) == 0
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="probe", purge=False,
        force=False, yes=True,
    )
    assert cli_addon.cmd_addon_remove(args) == 0

    assert "mcp-probe" not in (_librechat(inst).get("mcpServers") or {})
    assert "http://probe-mcp:8080" not in (
        (_librechat(inst).get("mcpSettings") or {}).get("allowedDomains") or []
    )
    assert "mcp-probe-audience" not in _librechat_mappers(inst)


def test_a_tool_server_outside_the_suite_gets_neither_chat_entry_nor_mapper(tmp_path):
    # LibreChat passes one token with every audience it carries; only a module of the
    # suite may receive it.
    inst = _installation(tmp_path, in_suite=False)
    assert _install(inst, _probe(tmp_path)) == 0

    assert _catalog_entry(inst, "probe.echo")["trust"] == "addon"
    assert "mcp-probe" not in (_librechat(inst).get("mcpServers") or {})
    assert "mcp-probe-audience" not in _librechat_mappers(inst)


def test_an_addon_with_its_own_chat_fragment_keeps_it_and_gets_the_mapper(tmp_path, capsys):
    inst = _installation(tmp_path)
    probe = _probe(
        tmp_path,
        integration={
            "keycloak": {
                "client_mappers": {"librechat": ["integration/infra/keycloak/aud.json"]},
            },
            "librechat": "integration/ai/librechat/librechat.yaml",
        },
    )
    fragment = probe / "integration" / "ai" / "librechat" / "librechat.yaml"
    fragment.parent.mkdir(parents=True)
    fragment.write_text(yaml.safe_dump({
        "mcpServers": {"Probe": {"type": "streamable-http", "url": "http://probe-mcp:8080/mcp"}}
    }))
    mapper = probe / "integration" / "infra" / "keycloak" / "aud.json"
    mapper.parent.mkdir(parents=True)
    mapper.write_text(json.dumps({
        "name": "mcp-probe-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": "mcp-probe"},
    }))

    assert _install(inst, probe) == 0
    out = capsys.readouterr().out

    servers = _librechat(inst)["mcpServers"]
    assert "Probe" in servers and "mcp-probe" not in servers
    assert "mcp-probe-audience" in _librechat_mappers(inst)
    # The core makes the mapper; the add-on's copy is no longer a manual step.
    assert "Add protocol mappers" not in out


def test_the_core_profile_keeps_its_own_fragment_and_mapper(tmp_path):
    inst = Installation(
        tmp_path,
        ["--app-host=https://papaia.example.org", "--enable-rag=true",
         "--qdrant-host=https://qdrant.example.org"],
    )
    inst.setup(*inst.flags)

    servers = _librechat(inst)["mcpServers"]
    assert "Qdrant" in servers and "mcp-qdrant" not in servers
    mappers = _librechat_mappers(inst)
    audiences = [
        m["config"]["included.client.audience"]
        for m in mappers.values()
        if m["protocolMapper"] == "oidc-audience-mapper"
    ]
    assert audiences.count("mcp-qdrant") == 1


@pytest.mark.parametrize(
    ("provider", "listed"), [("internal_keycloak", False), ("external_oidc", True)]
)
def test_the_checklist_names_the_audiences_to_map_only_for_an_external_provider(
    tmp_path, capsys, provider, listed
):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(f"AUTH_PROVIDER={provider}\n")
    manifest = yaml.safe_load((FIXTURES / "addon-probe" / "papaia-app.yaml").read_text())

    reporting.print_keycloak_checklist(
        "probe", manifest, tmp_path, config_dir, generated={"mcp-probe"}
    )

    out = capsys.readouterr().out
    assert ("mcp-probe" in out) is listed
    assert ("audience mapper" in out) is listed


# ─────────────────────────────────────────────────────────────────────────
# the mapper on an existing realm
# ─────────────────────────────────────────────────────────────────────────


def test_a_mapper_created_on_an_existing_realm_leaves_an_audit_row(tmp_path, monkeypatch):
    realm = {
        "roles": {"realm": []},
        "clients": [{
            "clientId": "librechat",
            "protocolMappers": [chat_servers.audience_mapper("mcp-probe")],
        }],
    }
    path = tmp_path / REALM
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(realm))
    calls: list[tuple[str, str]] = []

    def api(base_url, ctx, token, method, sub, body=None):
        calls.append((method, sub))
        if sub == "/clients?clientId=librechat":
            return [{"id": "uuid-librechat"}]
        if sub == "/clients/uuid-librechat/protocol-mappers/models":
            return [] if method == "GET" else None
        return []

    monkeypatch.setattr(keycloak_role_sync, "_api", api)
    with _audit(tmp_path) as audit:
        assert keycloak_role_sync._sync_protocol_mappers("", None, "t", realm, audit) == 1

    assert ("POST", "/clients/uuid-librechat/protocol-mappers/models") in calls
    rows = [
        json.loads(line)
        for line in (tmp_path / "audit" / "outbox" / "papaia-ctl.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 1
    row = rows[0]
    assert row["format"] == "papaia.audit/1"
    assert row["operation"] == "keycloak_role_sync.protocol_mapper_create"
    assert row["object_ref"] == {"type": "protocol_mapper", "id": "librechat/mcp-probe-audience"}
    assert row["result"] == "allowed"
    assert row["correlation_id"]
    assert row["azp"] == "admin-cli"


def _audit(config_dir: Path) -> realm_sync.AuditLog:
    return realm_sync.AuditLog(
        realm_sync.audit_path(config_dir),
        realm_sync.new_correlation_id(),
        writer=keycloak_role_sync.AUDIT_WRITER,
    )


# ─────────────────────────────────────────────────────────────────────────
# knowledge: key tools are operations of exposes
# ─────────────────────────────────────────────────────────────────────────


def _probe_manifest(key_tools: list[str]) -> dict:
    manifest = yaml.safe_load((FIXTURES / "addon-probe" / "papaia-app.yaml").read_text())
    manifest["requires"]["addon_api"] = [7]
    manifest["knowledge"] = {
        "sources": [{
            "id": "probe.notes",
            "system": "Probe notes",
            "coverage": "Notes written through the probe.",
            "access": [{"via": "mcp", "target": "mcp-probe", "key_tools": key_tools}],
        }]
    }
    return manifest


def test_addon_check_refuses_key_tools_that_are_no_operation_of_exposes():
    core = compat.resolve_core_target(REPO)
    result = compat.evaluate_addon("probe", _probe_manifest(["echo", "search_notes"]), core)
    assert result.status == compat.STATUS_ERROR
    assert result.axis == "knowledge"
    assert "knowledge/sources/0/access/0/key_tools/1" in result.reason
    assert "search_notes" in result.reason
    assert compat.gate([result], mode=compat.MODE_ENFORCE, force=True) == 2


def test_addon_check_accepts_key_tools_named_in_exposes():
    core = compat.resolve_core_target(REPO)
    result = compat.evaluate_addon("probe", _probe_manifest(["echo", "write_note"]), core)
    assert result.status != compat.STATUS_ERROR, result.reason


def test_the_rag_profile_names_only_operations_of_its_own_exposes():
    section = yaml.safe_load((REPO / "src/ai/rag/exposes.yaml").read_text())["exposes"]
    knowledge = yaml.safe_load((REPO / "src/ai/rag/knowledge.yaml").read_text())
    exposes.check_key_tools(knowledge, section, "core:rag")


def test_the_knowledge_map_refuses_key_tools_outside_the_module_exposes(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(REPO / "src" / "ai" / "rag", repo / "src" / "ai" / "rag")
    path = repo / "src" / "ai" / "rag" / "knowledge.yaml"
    knowledge = yaml.safe_load(path.read_text())
    knowledge["sources"][0]["access"][0]["key_tools"] = ["search_everything"]
    path.write_text(yaml.safe_dump(knowledge))
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    with pytest.raises(knowledge_map.KnowledgeMapError, match="search_everything"):
        knowledge_map.collect_sources(repo, config_dir, {"rag"}, [])


def test_the_catalog_entries_are_the_source_of_the_chat_entries(tmp_path):
    inst = _installation(tmp_path)
    assert _install(inst, _probe(tmp_path)) == 0

    servers = chat_servers.servers(inst.config, inst.repo)
    doc = catalog.build(inst.config, inst.repo)
    assert doc is not None
    by_audience = {s.audience: s for s in servers}
    entry = next(e for e in doc["services"] if e["id"] == "probe.echo")
    assert by_audience["mcp-probe"].url == entry["address"]
    assert by_audience["mcp-probe"].catalog_id == "probe.echo"
