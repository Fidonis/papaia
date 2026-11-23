"""`addon install` of an add-on whose create tools leave out `resource.id_field`
(papaia-kit 0.1.0): the catalog lists the entry and the chat gets the add-on's fragment;
an update without `id_field` is still refused and leaves the installation unchanged.

The fixture is the Paperless add-on of the papaia-addons 1.4.0 milestone (`paperless/` at
208dd13): manifest, chat fragment, realm fragments and `.env.example`, unchanged. Its
create tools name no existing object yet, so they declare no `id_field`."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import yaml
from install_helpers import Installation

from lib import cli_addon, schema_check

FIXTURE = Path(__file__).parent / "fixtures" / "catalog" / "addon-paperless-exposes"
SCHEMAS = Path(__file__).resolve().parents[1] / "schemas" / "kit"
LIBRECHAT = Path("ai/librechat/librechat.yaml")
CREATES = {"upload_document", "create_tag", "create_correspondent"}


def _installation(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, ["--app-host=https://papaia.example.org"])
    inst.setup(*inst.flags)
    return inst


def _paperless(tmp_path: Path) -> Path:
    """The milestone add-on with a compose file of the services the core reads: the gate
    shares the network of paperless, the tool server is the catalog entry's address."""
    path = tmp_path / "addons" / "paperless"
    shutil.copytree(FIXTURE, path)
    services = {
        "paperless": {"image": "example.invalid/paperless:2.0.0"},
        "paperless-gate": {
            "image": "example.invalid/gate:1.0.0", "network_mode": "service:paperless"
        },
        "paperless-mcp": {"image": "example.invalid/paperless-mcp:1.0.0"},
    }
    (path / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
    return path


def _install(inst: Installation, path: Path) -> int:
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="paperless",
        path=str(path), version=None, force=False, node=None,
    )
    return cli_addon.cmd_addon_install(args)


def _services(inst: Installation) -> dict:
    return json.loads((inst.config / "platform" / "services.json").read_text(encoding="utf-8"))


def test_paperless_with_create_operations_installs_with_catalog_entry_and_chat_fragment(
    tmp_path, capsys
):
    inst = _installation(tmp_path)
    paperless = _paperless(tmp_path)

    assert _install(inst, paperless) == 0, capsys.readouterr().err

    doc = _services(inst)
    schema = json.loads((SCHEMAS / "platform-services.v1.schema.json").read_text())
    schema_check.validate(doc, schema)
    entry = next(e for e in doc["services"] if e["id"] == "paperless.documents")
    operations = {o["name"]: o for o in entry["operations"]}
    without_id = {
        name
        for name, o in operations.items()
        if "resource" in o and "id_field" not in o["resource"]
    }
    assert without_id == CREATES
    for name in CREATES:
        assert (operations[name]["effect"], operations[name]["retry"]) == ("write", "at_most_once")
    assert operations["update_document"]["resource"] == {"type": "document", "id_field": "id"}

    chat = yaml.safe_load((inst.config / LIBRECHAT).read_text(encoding="utf-8"))
    assert chat["mcpServers"]["Paperless"]["url"] == "http://paperless-mcp:8000/mcp"
    assert "http://paperless-mcp:8000" in chat["mcpSettings"]["allowedDomains"]


def test_paperless_with_an_update_without_id_field_is_refused_and_changes_nothing(
    tmp_path, capsys
):
    inst = _installation(tmp_path)
    paperless = _paperless(tmp_path)
    manifest = yaml.safe_load((paperless / "papaia-app.yaml").read_text(encoding="utf-8"))
    operations = manifest["exposes"][0]["operations"]
    number = next(i for i, o in enumerate(operations) if o["name"] == "update_document")
    del operations[number]["resource"]["id_field"]
    (paperless / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    deployment = inst.config / "deployment.yaml"
    chat = inst.config / LIBRECHAT
    before = deployment.read_bytes(), chat.read_bytes()

    assert _install(inst, paperless) == 2

    assert f"exposes/0/operations/{number}/resource/id_field" in capsys.readouterr().err
    assert (deployment.read_bytes(), chat.read_bytes()) == before
    assert not (inst.config / "addons" / "paperless").exists()
