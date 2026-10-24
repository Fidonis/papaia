from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import yaml

from lib import components, envtree
from lib.cli_addon import cmd_addon_components, cmd_addon_install

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ADDON_PAPERLESS = FIXTURES_DIR / "addon-paperless"


def _entry(ident: str = "paperless-ngx", **extra) -> dict:
    entry = {
        "id": ident,
        "name": "Paperless-ngx",
        "role": "primary",
        "kind": "upstream",
        "image_var": "PAPERLESS_IMAGE",
        "version": "3.0.5",
        "source": "https://github.com/paperless-ngx/paperless-ngx",
    }
    entry.update(extra)
    return entry


# ── parse ─────────────────────────────────────────────────────────────────────


def test_a_manifest_without_components_has_none():
    assert components.parse(None) == []
    assert components.parse({}) == []
    assert components.parse({"components": "paperless"}) == []


def test_a_well_formed_entry_is_read_as_written():
    (found,) = components.parse({"components": [_entry(pinned=False)]})
    assert found["id"] == "paperless-ngx"
    assert found["role"] == "primary"
    assert found["version"] == "3.0.5"
    assert found["image_var"] == "PAPERLESS_IMAGE"
    assert found["floating"] is True


def test_entries_that_cannot_be_listed_are_skipped():
    declared = [
        "not a mapping",
        _entry("no-version", version=None),
        _entry("number", version=18),  # an unquoted `18` is a number, not a tag
        _entry("no-name", name=""),
        _entry("ok"),
        _entry("ok"),  # a repeated id
    ]
    assert [c["id"] for c in components.parse({"components": declared})] == ["ok"]


def test_an_unknown_role_counts_as_a_sidecar():
    (found,) = components.parse({"components": [_entry(role="main")]})
    assert found["role"] == "sidecar"


def test_only_an_https_source_is_kept():
    kept = components.parse({"components": [_entry(source="https://example.com/x")]})
    dropped = components.parse({"components": [_entry(source="javascript:alert(1)")]})
    assert kept[0]["source"] == "https://example.com/x"
    assert dropped[0]["source"] is None


def test_control_characters_do_not_reach_the_terminal():
    (found,) = components.parse({"components": [_entry(name="Evil\x1b[31m red\x07")]})
    assert "\x1b" not in found["name"]
    assert "\x07" not in found["name"]


def test_the_list_is_capped():
    many = [_entry(f"c{i}") for i in range(100)]
    assert len(components.parse({"components": many})) == 32


def test_image_tag():
    assert components.image_tag("ghcr.io/o/n:0.3.0") == "0.3.0"
    assert components.image_tag("localhost:5000/n:1.0.0@sha256:abc") == "1.0.0"
    assert components.image_tag("localhost:5000/n") == "latest"


# ── describe ──────────────────────────────────────────────────────────────────


def test_a_tag_pinned_in_the_env_is_an_override():
    manifest = {"version": "1.1.0", "components": [_entry()]}
    env = {"PAPERLESS_IMAGE": "registry.example/paperless:3.0.7"}
    described = components.describe("paperless", manifest, active=True, bundle_env=env)
    (found,) = described["components"]
    assert found["override_version"] == "3.0.7"
    assert found["override_ref"] == "registry.example/paperless:3.0.7"


def test_an_env_value_equal_to_the_catalog_tag_is_not_an_override():
    manifest = {"components": [_entry()]}
    env = {"PAPERLESS_IMAGE": "ghcr.io/paperless-ngx/paperless-ngx:3.0.5"}
    (found,) = components.describe("paperless", manifest, active=True, bundle_env=env)["components"]
    assert found["override_version"] is None


# ── the command ───────────────────────────────────────────────────────────────


def _addon_with_components(tmp_path: Path) -> Path:
    """The paperless fixture, with a components list and a floating sidecar."""
    addon = tmp_path / "addon-paperless"
    shutil.copytree(ADDON_PAPERLESS, addon)
    manifest = yaml.safe_load((addon / "papaia-app.yaml").read_text(encoding="utf-8"))
    manifest["components"] = [
        _entry(),
        _entry(
            "postgres",
            name="PostgreSQL",
            role="sidecar",
            image_var="PAPERLESS_DB_IMAGE",
            version="18",
            pinned=False,
            source="https://www.postgresql.org",
        ),
    ]
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return addon


def _install(addon: Path, repo_root: Path, config_dir: Path) -> int:
    envtree.init(config_dir, repo_root, env_name="papaia")
    return cmd_addon_install(
        argparse.Namespace(
            config_dir=str(config_dir),
            repo_root=str(repo_root),
            name="paperless",
            path=str(addon),
            version=None,
            force=False,
        )
    )


def _components_args(config_dir: Path, repo_root: Path, **overrides) -> argparse.Namespace:
    values = {
        "config_dir": str(config_dir),
        "repo_root": str(repo_root),
        "name": None,
        "json": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_install_prints_what_the_addon_bundles(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    assert _install(addon, repo_root, config_dir) == 0
    out = capsys.readouterr().out
    assert "Addon installed: paperless" in out
    assert "Paperless-ngx" in out
    assert "PAPERLESS_IMAGE" in out
    assert "floating" in out


def test_install_of_an_addon_without_components_prints_nothing_extra(
    repo_root, config_dir, capsys
):
    assert _install(ADDON_PAPERLESS, repo_root, config_dir) == 0
    out = capsys.readouterr().out
    assert out.rstrip().endswith("Addon installed: paperless")


def test_the_listing_names_components_and_marks_floating_and_overridden(
    repo_root, config_dir, tmp_path, capsys
):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    env = config_dir / "addons" / "paperless" / ".env"
    env.write_text(
        env.read_text(encoding="utf-8") + "\nPAPERLESS_DB_IMAGE=docker.io/library/postgres:18.3\n",
        encoding="utf-8",
    )
    capsys.readouterr()

    assert cmd_addon_components(_components_args(config_dir, repo_root)) == 0
    out = capsys.readouterr().out
    assert "paperless 1.0.0 (active)" in out
    assert "Paperless-ngx" in out
    assert "3.0.5" in out
    assert "(floating, overridden in .env: 18.3)" in out


def test_json_output_is_stable(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    capsys.readouterr()

    assert cmd_addon_components(_components_args(config_dir, repo_root, json=True)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    (paperless,) = payload["addons"]
    assert set(paperless) == {"name", "version", "active", "components", "error"}
    assert paperless["active"] is True
    assert paperless["error"] is None
    assert set(paperless["components"][0]) == {
        "id",
        "name",
        "role",
        "kind",
        "version",
        "image_var",
        "source",
        "floating",
        "override_version",
        "override_ref",
    }
    assert [c["id"] for c in paperless["components"]] == ["paperless-ngx", "postgres"]


def test_an_addon_without_components_is_listed_without_any(repo_root, config_dir, capsys):
    _install(ADDON_PAPERLESS, repo_root, config_dir)
    capsys.readouterr()
    assert cmd_addon_components(_components_args(config_dir, repo_root)) == 0
    assert "(no components declared)" in capsys.readouterr().out


def test_an_inactive_addon_is_still_listed(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    deployment_file = config_dir / "deployment.yaml"
    deployed = yaml.safe_load(deployment_file.read_text(encoding="utf-8"))
    deployed["addons"][0]["active"] = False
    deployment_file.write_text(yaml.safe_dump(deployed), encoding="utf-8")
    capsys.readouterr()

    assert cmd_addon_components(_components_args(config_dir, repo_root)) == 0
    assert "paperless 1.0.0 (inactive)" in capsys.readouterr().out


def test_a_missing_manifest_is_reported_not_raised(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    (addon / "papaia-app.yaml").unlink()
    capsys.readouterr()

    assert cmd_addon_components(_components_args(config_dir, repo_root)) == 0
    assert "cannot read the manifest" in capsys.readouterr().out


def test_an_unknown_name_exits_2(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    capsys.readouterr()
    assert cmd_addon_components(_components_args(config_dir, repo_root, name="nope")) == 2
    assert "not registered" in capsys.readouterr().err


def test_a_name_narrows_the_listing(repo_root, config_dir, tmp_path, capsys):
    addon = _addon_with_components(tmp_path)
    _install(addon, repo_root, config_dir)
    capsys.readouterr()
    assert cmd_addon_components(_components_args(config_dir, repo_root, name="paperless")) == 0
    assert "paperless 1.0.0" in capsys.readouterr().out


def test_without_a_deployment_the_command_asks_for_setup(repo_root, config_dir, capsys):
    assert cmd_addon_components(_components_args(config_dir, repo_root)) == 2
    assert "setup" in capsys.readouterr().err
