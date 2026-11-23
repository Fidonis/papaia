"""The platform services catalogue (issue #435): `exposes.yaml` of the core modules and
`exposes:` of add-ons, rendered into $PAPAIA_CONFIG_DIR/platform/services.json."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

import jsonschema
import pytest
import yaml

from lib import envtree, platform_services, render_core
from lib.cli_addon import cmd_addon_install, cmd_addon_remove

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REAL_REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (REAL_REPO / "tools" / "schemas" / "platform-services.schema.json").read_text(encoding="utf-8")
)


def entry(**overrides) -> dict:
    base = {
        "id": "notes.mcp",
        "kind": "mcp",
        "title": {"de": "Notizen", "en": "Notes"},
        "url": "http://notes-mcp:8000/mcp",
        "auth": "oidc_bearer",
        "audience": "mcp-notes",
        "max_class": "internal",
        "consumable": True,
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def _core_modules(repo_root: Path) -> None:
    """The real exposes.yaml of the core modules in the synthetic repo."""
    for _profile, module in platform_services.MODULE_EXPOSES:
        target = repo_root / module
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy(REAL_REPO / module / "exposes.yaml", target / "exposes.yaml")


def _addon(tmp_path: Path, name: str, exposes: list[dict] | None) -> Path:
    path = tmp_path / f"addon-{name}"
    shutil.copytree(FIXTURES_DIR / "addon-paperless", path)
    manifest = yaml.safe_load((path / "papaia-app.yaml").read_text(encoding="utf-8"))
    manifest["name"] = name
    if exposes is not None:
        manifest["exposes"] = exposes
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return path


def _set_profiles(config_dir: Path, profiles: str) -> None:
    env = config_dir / ".env"
    lines = [
        line
        for line in env.read_text(encoding="utf-8").splitlines()
        if not line.startswith("COMPOSE_PROFILES=")
    ]
    lines.append(f"COMPOSE_PROFILES={profiles}")
    env.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _install(config_dir: Path, repo_root: Path, path: Path, name: str) -> int:
    return cmd_addon_install(
        argparse.Namespace(
            config_dir=str(config_dir),
            repo_root=str(repo_root),
            name=name,
            path=str(path),
            version=None,
            force=False,
        )
    )


def _catalogue(config_dir: Path) -> dict:
    return json.loads((config_dir / "platform" / "services.json").read_text(encoding="utf-8"))


# --- entries ---------------------------------------------------------------------------------


def test_a_valid_entry_keeps_its_fields():
    tool = {"name": "search", "access": "read", "class": "internal"}
    checked = platform_services.validate_entry(
        entry(token_exchange=True, suggested_tools=[tool]), "test"
    )
    assert checked["audience"] == "mcp-notes"
    assert checked["token_exchange"] is True
    assert checked["suggested_tools"][0]["name"] == "search"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"audience": None}, "needs an audience"),
        ({"auth": "own_oauth", "audience": None}, "cannot be consumable"),
        ({"consumable": False}, "needs a reason"),
        ({"kind": "chat"}, "kind must be one of"),
        ({"url": "ftp://notes"}, "http(s) address"),
        ({"title": {"en": "Notes"}}, "'de' is required"),
        ({"id": "Notes MCP"}, "must match"),
        ({"max_class": "secret"}, "max_class must be one of"),
        ({"headers": {"X": "y"}}, "unknown field"),
    ],
)
def test_invalid_entries_are_refused(overrides, message):
    with pytest.raises(platform_services.ServicesError, match=re.escape(message)):
        platform_services.validate_entry(entry(**overrides), "test")


def test_own_oauth_is_listed_when_not_consumable():
    checked = platform_services.validate_entry(
        entry(auth="own_oauth", audience=None, consumable=False, reason="signs people in itself"),
        "test",
    )
    assert checked["consumable"] is False


def test_the_core_modules_declare_valid_entries():
    """The shipped exposes.yaml files load and their ids are unique."""
    services = platform_services.collect(REAL_REPO, {"rag", "knowledge-map"}, [])
    ids = [s["id"] for s in services]
    assert ids == sorted(ids) == ["firecrawl.web", "knowledge-map", "rag.ingest", "rag.qdrant"]
    assert {s["addon"] for s in services} == {"core"}
    by_id = {s["id"]: s for s in services}
    assert by_id["rag.qdrant"]["audience"] == "mcp-qdrant"
    assert by_id["rag.qdrant"]["profile"] == "rag"
    assert "profile" not in by_id["firecrawl.web"]


# --- rendering -------------------------------------------------------------------------------


def test_render_lists_profile_entries_only_while_active(repo_root, config_dir):
    _core_modules(repo_root)
    envtree.init(config_dir, repo_root, env_name="papaia")
    _set_profiles(config_dir, "")
    render_core.render(config_dir, repo_root)
    catalogue = _catalogue(config_dir)
    jsonschema.validate(catalogue, SCHEMA)
    assert catalogue["format"] == "papaia.platform-services/1"
    assert [s["id"] for s in catalogue["services"]] == ["firecrawl.web"]

    _set_profiles(config_dir, "rag,knowledge-map")
    render_core.render(config_dir, repo_root)
    ids = [s["id"] for s in _catalogue(config_dir)["services"]]
    assert ids == ["firecrawl.web", "knowledge-map", "rag.ingest", "rag.qdrant"]


def test_render_without_changes_is_byte_identical(repo_root, config_dir):
    _core_modules(repo_root)
    envtree.init(config_dir, repo_root, env_name="papaia")
    render_core.render(config_dir, repo_root)
    first = (config_dir / "platform" / "services.json").read_bytes()
    render_core.render(config_dir, repo_root)
    assert (config_dir / "platform" / "services.json").read_bytes() == first
    assert not list((config_dir / "platform").glob("*.tmp"))


def test_addon_entries_follow_install_and_removal(repo_root, config_dir, tmp_path):
    _core_modules(repo_root)
    envtree.init(config_dir, repo_root, env_name="papaia")
    path = _addon(tmp_path, "notes", [entry()])
    assert _install(config_dir, repo_root, path, "notes") == 0
    catalogue = _catalogue(config_dir)
    jsonschema.validate(catalogue, SCHEMA)
    notes = next(s for s in catalogue["services"] if s["id"] == "notes.mcp")
    assert (notes["addon"], notes["version"]) == ("notes", "1.0.0")
    first_digest = catalogue["digest"]

    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name="notes", force=False
    )
    removed = cmd_addon_remove(args)
    assert removed == 0
    catalogue = _catalogue(config_dir)
    assert "notes.mcp" not in {s["id"] for s in catalogue["services"]}
    assert catalogue["digest"] != first_digest


def test_install_refuses_invalid_exposes(repo_root, config_dir, tmp_path, capsys):
    envtree.init(config_dir, repo_root, env_name="papaia")
    path = _addon(tmp_path, "notes", [entry(audience=None)])
    assert _install(config_dir, repo_root, path, "notes") == 2
    assert "needs an audience" in capsys.readouterr().err
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert not deployment.get("addons")


def test_install_refuses_an_id_another_addon_uses(repo_root, config_dir, tmp_path, capsys):
    envtree.init(config_dir, repo_root, env_name="papaia")
    assert _install(config_dir, repo_root, _addon(tmp_path, "notes", [entry()]), "notes") == 0
    clash = _addon(tmp_path, "other", [entry(url="http://other:8000/mcp")])
    assert _install(config_dir, repo_root, clash, "other") == 2
    assert "duplicate service id 'notes.mcp'" in capsys.readouterr().err


def test_render_fails_with_a_named_error_for_a_broken_core_module(repo_root, config_dir):
    _core_modules(repo_root)
    (repo_root / "src" / "ai" / "mcp-firecrawl" / "exposes.yaml").write_text(
        "exposes:\n  - id: broken\n", encoding="utf-8"
    )
    envtree.init(config_dir, repo_root, env_name="papaia")
    with pytest.raises(render_core.RenderError, match="platform services catalogue"):
        render_core.render(config_dir, repo_root)


def test_librechat_configuration_is_unchanged_by_the_catalogue(repo_root, config_dir):
    """The catalogue sits beside LibreChat's configuration; it never feeds into it."""
    envtree.init(config_dir, repo_root, env_name="papaia")
    render_core.render(config_dir, repo_root)
    before = (config_dir / "ai" / "librechat" / "librechat.yaml").read_bytes()
    _core_modules(repo_root)
    render_core.render(config_dir, repo_root)
    assert (config_dir / "ai" / "librechat" / "librechat.yaml").read_bytes() == before
