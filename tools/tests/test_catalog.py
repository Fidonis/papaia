"""Platform catalog: `platform/services.json` and `platform/groups.json` rendered from the
`exposes:` declarations of the installed add-ons and the active core profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from lib import catalog, cli_addon, compat, exposes, schema_check

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "catalog"
GOLDEN = Path(__file__).parent / "golden" / "catalog"
KIT_SCHEMAS = REPO / "tools" / "schemas" / "kit"
NOW = datetime(2026, 11, 21, 9, 30, 0, tzinfo=timezone.utc)

ROOT_ENV = {
    "OIDC_ISSUER": "https://auth.papaia.example/realms/papaia",
    "OIDC_TOKEN_URL": "https://keycloak:8443/realms/papaia/protocol/openid-connect/token",
    "OIDC_JWKS_URL": "https://keycloak:8443/realms/papaia/protocol/openid-connect/certs",
    "PAPAIA_SECURITY_PROFILE": "standard",
    "FLOW_HOST": "https://flow.papaia.example",
    "KC_ADMIN_PASSWORD": "not-a-real-password-value",
}


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))


def _install(tmp_path: Path, profiles: str, addons: list[tuple[str, str, str | None]]) -> Path:
    """A configuration directory: root .env with `profiles` and one deployment entry
    per (fixture, name, state)."""
    config_dir = tmp_path / "papaia-config"
    _write_env(config_dir / ".env", {**ROOT_ENV, "COMPOSE_PROFILES": profiles})
    entries = []
    for fixture, name, state in addons:
        path = tmp_path / "addons" / fixture
        if not path.exists():
            shutil.copytree(FIXTURES / fixture, path)
        entry = {"name": name, "path": str(path), "active": True}
        if state is not None:
            entry["state"] = state
        entries.append(entry)
        _write_env(config_dir / "addons" / name / ".env", {"PROBE_TOKEN": "s3cr3t-probe-token"})
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries}))
    return config_dir


def _services(config_dir: Path) -> dict:
    return json.loads((config_dir / "platform" / "services.json").read_text())


def _schema(name: str) -> dict:
    return json.loads((KIT_SCHEMAS / name).read_text())


# ─────────────────────────────────────────────────────────────────────────
# vendored kit schemas
# ─────────────────────────────────────────────────────────────────────────


def test_the_vendored_kit_schemas_match_their_snapshot_digests():
    snapshot = json.loads((KIT_SCHEMAS / "snapshot.json").read_text())
    assert snapshot["format"] == "papaia.kit-schema-snapshot/1"
    assert snapshot["source"]["package"] == "papaia-kit"
    files = {p.name for p in KIT_SCHEMAS.glob("*.schema.json")}
    assert files == set(snapshot["files"])
    for name, digest in snapshot["files"].items():
        assert hashlib.sha256((KIT_SCHEMAS / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")
def test_the_core_copies_of_kit_files_are_those_of_the_vendored_kit_release():
    """The schema snapshot, the audit schema of papaia-audit and the audit vectors are the
    files of the kit release in kit.lock, byte for byte."""
    from importlib import metadata, resources

    import tomllib

    lock = tomllib.loads((REPO / "tools" / "kit.lock").read_text(encoding="utf-8"))
    snapshot = json.loads((KIT_SCHEMAS / "snapshot.json").read_text())
    assert metadata.version("papaia-kit") == lock["version"] == snapshot["source"]["version"]
    assert snapshot["source"]["commit"] == lock["commit"]
    data = resources.files("papaia_kit") / "_data"
    copies = {
        **{KIT_SCHEMAS / name: data / "schemas" / name for name in snapshot["files"]},
        REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json":
            data / "schemas" / "audit.v1.schema.json",
        Path(__file__).parent / "fixtures/audit/audit.v1.json": data / "vectors" / "audit.v1.json",
    }
    for copy, original in copies.items():
        assert copy.read_bytes() == original.read_bytes(), copy.name


# ─────────────────────────────────────────────────────────────────────────
# schema check (JSON Schema 2020-12, the keywords the kit schemas use)
# ─────────────────────────────────────────────────────────────────────────


def test_schema_check_names_the_place_and_the_rule_of_an_unknown_field():
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "integer"}},
    }
    with pytest.raises(schema_check.SchemaError) as err:
        schema_check.validate({"a": 1, "b": 2}, schema)
    assert err.value.path == "/b"
    assert "unknown field" in str(err.value)


@pytest.mark.parametrize(
    ("instance", "schema", "path"),
    [
        (True, {"type": "integer"}, ""),  # a boolean is no integer
        (1.5, {"type": "integer"}, ""),
        ("abc\n", {"type": "string", "pattern": "^[a-z]+$(?![\\s\\S])"}, ""),
        ([1, 1], {"type": "array", "uniqueItems": True}, "/1"),
        ({"k": "x"}, {"properties": {"k": {"enum": ["y"]}}}, "/k"),
        ([{"a": 1}], {"items": {"$ref": "#/$defs/A"}, "$defs": {"A": {"required": ["b"]}}}, "/0/b"),
        ({"kind": "ui"}, {"if": {"properties": {"kind": {"const": "ui"}}},
                          "then": {"required": ["ui"]}}, "/ui"),
        ("x", {"anyOf": [{"type": "integer"}, {"minLength": 2}]}, ""),
        ("x", {"not": {"type": "string"}}, ""),
        ({"Bad": 1}, {"propertyNames": {"pattern": "^[a-z]+$"}}, "/Bad"),
        ([1, 2], {"contains": {"const": 3}}, ""),
        ({}, {"minProperties": 1}, ""),
    ],
)
def test_schema_check_rejects(instance, schema, path):
    with pytest.raises(schema_check.SchemaError) as err:
        schema_check.validate(instance, schema)
    assert err.value.path == path


def test_schema_check_accepts_equal_numbers_of_different_type_as_duplicates_only_when_equal():
    schema_check.validate([1, True, "1"], {"uniqueItems": True})
    with pytest.raises(schema_check.SchemaError):
        schema_check.validate([1, 1.0], {"uniqueItems": True})


def test_schema_check_refuses_a_keyword_it_does_not_implement():
    with pytest.raises(ValueError, match="unsupported keyword"):
        schema_check.validate(1, {"dependentRequired": {}})


def test_the_vendored_schemas_use_only_implemented_keywords():
    for path in KIT_SCHEMAS.glob("*.schema.json"):
        schema_check.check_supported(json.loads(path.read_text()))


# ─────────────────────────────────────────────────────────────────────────
# exposes: validation at the boundary
# ─────────────────────────────────────────────────────────────────────────


def _manifest(fixture: str) -> dict:
    return yaml.safe_load((FIXTURES / fixture / "papaia-app.yaml").read_text())


def test_valid_exposes_sections_pass():
    exposes.check(_manifest("addon-probe")["exposes"], "probe")
    exposes.check(_manifest("addon-console")["exposes"], "papaia-flow")
    core = yaml.safe_load((REPO / "src/ai/rag/exposes.yaml").read_text())
    exposes.check(core["exposes"], "core:rag")


def test_an_exposes_field_the_core_sets_is_refused_with_field_and_reason():
    with pytest.raises(exposes.ExposesError) as err:
        exposes.check(_manifest("addon-bad-exposes")["exposes"], "bad")
    message = str(err.value)
    assert message.startswith("bad: exposes/0/trust: ")
    assert "unknown field" in message


@pytest.mark.parametrize(
    ("patch", "where"),
    [
        (lambda e: e[0].update(kind="tool"), "exposes/0/kind"),
        (lambda e: e[0]["address"].update(port=0), "exposes/0/address/port"),
        (lambda e: e[0].update(id="Probe"), "exposes/0/id"),
        (lambda e: e[0]["title"].update(de="<b>x</b>"), "exposes/0/title/de"),
        (lambda e: e[0]["operations"][0]["input_schema"].update({"$id": "x"}),
         "exposes/0/operations/0/input_schema"),
        (lambda e: e[0]["operations"][1]["resource"].update(id_field="missing"),
         "exposes/0/operations/1/resource/id_field"),
        (lambda e: e.append(dict(e[0])), "exposes/1/id"),
    ],
)
def test_invalid_exposes_sections_are_refused(patch, where):
    section = _manifest("addon-probe")["exposes"]
    patch(section)
    with pytest.raises(exposes.ExposesError) as err:
        exposes.check(section, "probe")
    assert f"probe: {where}" in str(err.value)


def test_addon_check_reports_an_invalid_exposes_section_as_error():
    core = compat.resolve_core_target(REPO)
    result = compat.evaluate_addon("bad", _manifest("addon-bad-exposes"), core)
    assert result.status == compat.STATUS_ERROR
    assert result.axis == "exposes"
    assert "exposes/0/trust" in result.reason and "unknown field" in result.reason
    assert compat.gate([result], mode=compat.MODE_ENFORCE, force=True) == 2


def test_addon_install_with_an_invalid_exposes_section_changes_nothing(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    before = (config_dir / "platform" / "services.json").read_bytes()
    deployment_before = (config_dir / "deployment.yaml").read_bytes()
    bad = tmp_path / "addons" / "addon-bad-exposes"
    shutil.copytree(FIXTURES / "addon-bad-exposes", bad)
    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(REPO), name="bad", path=str(bad),
        version=None, force=True, node=None,
    )
    assert cli_addon.cmd_addon_install(args) == 2
    assert "exposes/0/trust" in capsys.readouterr().err
    assert (config_dir / "platform" / "services.json").read_bytes() == before
    assert (config_dir / "deployment.yaml").read_bytes() == deployment_before


def _install_args(config_dir: Path, name: str, path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(REPO), name=name, path=str(path),
        version=None, force=False, node=None,
    )


def _unchanged_after(config_dir: Path, run) -> None:
    """`run` leaves deployment.yaml and services.json byte-identical."""
    services = config_dir / "platform" / "services.json"
    before = (config_dir / "deployment.yaml").read_bytes(), services.read_bytes()
    run()
    assert ((config_dir / "deployment.yaml").read_bytes(), services.read_bytes()) == before


def test_addon_install_with_a_colliding_id_changes_nothing(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    second = tmp_path / "addons" / "probe2"
    shutil.copytree(FIXTURES / "addon-probe", second)
    manifest = yaml.safe_load((second / "papaia-app.yaml").read_text())
    manifest["name"] = "probe2"
    (second / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))

    def run() -> None:
        assert cli_addon.cmd_addon_install(_install_args(config_dir, "probe2", second)) == 2

    _unchanged_after(config_dir, run)
    assert "'probe.echo' is declared by probe and probe2" in capsys.readouterr().err
    catalog.render(config_dir, REPO, now=NOW)  # the installation still renders


def test_addon_install_of_a_ui_addon_without_its_public_host_changes_nothing(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [])
    _write_env(config_dir / ".env", {
        **{k: v for k, v in ROOT_ENV.items() if k != "FLOW_HOST"}, "COMPOSE_PROFILES": "rag"
    })
    catalog.render(config_dir, REPO, now=NOW)
    console = tmp_path / "addons" / "addon-console"
    shutil.copytree(FIXTURES / "addon-console", console)

    def run() -> None:
        assert cli_addon.cmd_addon_install(_install_args(config_dir, "papaia-flow", console)) == 2

    _unchanged_after(config_dir, run)
    assert "FLOW_HOST" in capsys.readouterr().err
    catalog.render(config_dir, REPO, now=NOW)


def test_addon_start_refused_by_the_catalog_keeps_the_recorded_state(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [("addon-console", "papaia-flow", "stopped")])
    catalog.render(config_dir, REPO, now=NOW)
    _write_env(config_dir / ".env", {
        **{k: v for k, v in ROOT_ENV.items() if k != "FLOW_HOST"}, "COMPOSE_PROFILES": "rag"
    })
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(REPO),
                              name="papaia-flow", force=False, no_keycloak=True)

    def run() -> None:
        assert cli_addon.cmd_addon_start(args) == 2

    _unchanged_after(config_dir, run)
    assert "FLOW_HOST" in capsys.readouterr().err


def _probe_copy(target: Path, name: str, catalog_id: str, version: str) -> Path:
    shutil.copytree(FIXTURES / "addon-probe", target)
    manifest = yaml.safe_load((target / "papaia-app.yaml").read_text())
    manifest.update(name=name, version=version)
    manifest["exposes"][0]["id"] = catalog_id
    (target / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    return target


def test_addon_upgrade_to_a_colliding_id_changes_nothing(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    current = _probe_copy(tmp_path / "v1" / "other", "other", "other.echo", "1.0.0")
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text())
    deployed["addons"].append(
        {"name": "other", "path": str(current), "active": True, "state": "running"}
    )
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed))
    _write_env(config_dir / "addons" / "other" / ".env", {"PROBE_TOKEN": "other-probe-token"})
    catalog.render(config_dir, REPO, now=NOW)
    new = _probe_copy(tmp_path / "v2" / "other", "other", "probe.echo", "1.1.0")
    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(REPO), name="other", path=str(new),
        force=False, answers_file=None, restore_point=None,
    )

    def run() -> None:
        assert cli_addon.cmd_addon_upgrade_apply(args) == 2

    _unchanged_after(config_dir, run)
    assert "'probe.echo' is declared by probe and other" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────
# create operations without resource.id_field (kit 0.1.0)
# ─────────────────────────────────────────────────────────────────────────

def test_a_create_operation_without_id_field_passes_the_exposes_check():
    section = _manifest("addon-probe")["exposes"]
    write_note = section[0]["operations"][1]
    assert (write_note["effect"], write_note["retry"]) == ("write", "at_most_once")
    del write_note["resource"]["id_field"]
    exposes.check(section, "probe")


@pytest.mark.parametrize(
    ("effect", "retry"),
    [("write", "idempotent"), ("write", "safe"), ("delete", "idempotent"), ("check", "safe")],
)
def test_an_operation_other_than_a_create_without_id_field_is_refused(effect, retry):
    section = _manifest("addon-probe")["exposes"]
    operation = section[0]["operations"][1]
    operation.update(effect=effect, retry=retry)
    del operation["resource"]["id_field"]
    with pytest.raises(exposes.ExposesError) as err:
        exposes.check(section, "probe")
    assert "probe: exposes/0/operations/1/resource/id_field" in str(err.value)


def test_the_catalog_schema_accepts_a_create_without_id_field_and_nothing_else():
    """platform-services.v1 states the same rule as exposes.v1 for the rendered entry."""
    schema = _schema("platform-services.v1.schema.json")
    operation = {
        "name": "create_tag", "version": 1, "title": {"de": "Tag anlegen", "en": "Create tag"},
        "via": "tools", "effect": "write", "retry": "at_most_once",
        "input_schema": {"type": "object"}, "output_schema": {"type": "object"},
        "data_class_max": "internal", "resource": {"type": "tag"}, "rights_check": "server",
    }
    rule = {**schema["$defs"]["Operation"], "$defs": schema["$defs"]}
    schema_check.validate(operation, rule)
    with pytest.raises(schema_check.SchemaError) as err:
        schema_check.validate({**operation, "retry": "idempotent"}, rule)
    assert err.value.path == "/resource/id_field"


# ─────────────────────────────────────────────────────────────────────────
# canonical form and content hash (RFC 8785)
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"b": 1, "a": [True, None, "x"]}, '{"a":[true,null,"x"],"b":1}'),
        ({"\U0001f600": 2, "\u20ac": 1, "z": 3}, '{"z":3,"\u20ac":1,"\U0001f600":2}'),
        (1000.0, "1000"),
        (0.5, "0.5"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (-0.0, "0"),
        ("a \"\\\n\u001f", '"a \\"\\\\\\n\\u001f"'),
    ],
)
def test_canonical_json_follows_rfc_8785(value, expected):
    assert catalog.canonical_json(value) == expected.encode("utf-8")


def test_canonical_json_refuses_values_without_a_canonical_form():
    with pytest.raises(ValueError):
        catalog.canonical_json(float("nan"))
    with pytest.raises(ValueError):
        catalog.canonical_json(2**60 + 1)


# ─────────────────────────────────────────────────────────────────────────
# render: golden catalogs of sample installs
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("case", "profiles", "addons"),
    [
        ("core-rag", "rag", []),
        (
            "rag-probe-flow",
            "rag,knowledge-map",
            [("addon-probe", "probe", "running"), ("addon-console", "papaia-flow", "stopped")],
        ),
    ],
)
def test_render_matches_the_golden_catalog(tmp_path, case, profiles, addons):
    config_dir = _install(tmp_path, profiles, addons)
    assert catalog.render(config_dir, REPO, now=NOW) is True
    rendered = _services(config_dir)
    golden = json.loads((GOLDEN / f"{case}.services.json").read_text())
    assert rendered == golden
    schema_check.validate(rendered, _schema("platform-services.v1.schema.json"))
    for entry in rendered["services"]:
        assert entry["content_hash"] == catalog.content_hash(entry)


def test_the_catalog_carries_no_secret_and_no_core_only_field(tmp_path):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    text = (config_dir / "platform" / "services.json").read_text()
    for secret in ("s3cr3t-probe-token", ROOT_ENV["KC_ADMIN_PASSWORD"], "PROBE_TOKEN"):
        assert secret not in text
    for field in ("service_accounts", "owner_sub", "storage", "requires", "delegation"):
        assert f'"{field}"' not in text


def test_the_files_are_written_atomically_and_readable_by_the_modules(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    catalog.render(config_dir, REPO, now=NOW)
    platform = config_dir / "platform"
    assert sorted(p.name for p in platform.iterdir()) == ["groups.json", "services.json"]
    for name in ("services.json", "groups.json"):
        mode = stat.S_IMODE(os.stat(platform / name).st_mode)
        assert mode == 0o644, name
    assert stat.S_IMODE(os.stat(platform).st_mode) == 0o755
    groups = json.loads((platform / "groups.json").read_text())
    assert groups == {"format": "papaia.platform-groups/1", "generated_at": "2026-11-21T09:30:00Z",
                      "groups": []}


def test_an_unchanged_catalog_is_not_rewritten(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    assert catalog.render(config_dir, REPO, now=NOW) is True
    first = (config_dir / "platform" / "services.json").read_bytes()
    later = datetime(2026, 11, 22, 9, 30, 0, tzinfo=timezone.utc)
    assert catalog.render(config_dir, REPO, now=later) is False
    assert (config_dir / "platform" / "services.json").read_bytes() == first


def test_every_write_leaves_one_audit_row(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    catalog.render(config_dir, REPO, now=NOW)
    catalog.render(config_dir, REPO, now=NOW)  # unchanged: no row
    outbox = config_dir / "audit" / "outbox" / "papaia-ctl.jsonl"
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    # The empty group list seeded on the first render is a write of its own.
    assert [(r["operation"], r["object_ref"]["id"]) for r in rows] == [
        ("catalog.platform_groups.write", "platform/groups.json"),
        ("catalog.services_write", "platform/services.json"),
    ]
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["writer"] == "papaia-ctl/catalog"
        assert row["event"] == "config_changed"
        assert row["effect"] == "write"
        assert row["object_ref"]["type"] == "file"
        assert row["result"] == "allowed"
        assert row["identity_kind"] is None and row["azp"] is None
    assert rows[0]["correlation_id"] == rows[1]["correlation_id"]


def test_the_brand_logo_write_and_removal_are_audited(tmp_path):
    config_dir = _install(tmp_path, "", [])
    overlay = config_dir / "overlay" / "platform"
    overlay.mkdir(parents=True)
    (overlay / "brand-logo").write_bytes(b"\x89PNG\r\n\x1a\n fake logo")
    catalog.render(config_dir, REPO, now=NOW)
    (overlay / "brand-logo").unlink()
    catalog.render(config_dir, REPO, now=NOW)
    catalog.render(config_dir, REPO, now=NOW)  # nothing left to change: no row
    outbox = config_dir / "audit" / "outbox" / "papaia-ctl.jsonl"
    rows = [json.loads(line) for line in outbox.read_text().splitlines()]
    logo_rows = [r for r in rows if r["object_ref"]["id"] == "platform/brand-logo"]
    assert [(r["operation"], r["effect"]) for r in logo_rows] == [
        ("catalog.brand_logo_write", "write"),
        ("catalog.brand_logo_delete", "delete"),
    ]
    assert all(r["azp"] is None and r["result"] == "allowed" for r in logo_rows)
    assert not (config_dir / "platform" / "brand-logo").exists()


def test_an_invalid_declaration_keeps_the_catalog_unchanged(tmp_path):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    before = (config_dir / "platform" / "services.json").read_bytes()
    manifest_path = tmp_path / "addons" / "addon-probe" / "papaia-app.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    manifest["exposes"][0]["kind"] = "tool"
    manifest_path.write_text(yaml.safe_dump(manifest))
    with pytest.raises(catalog.CatalogError, match="probe: exposes/0/kind"):
        catalog.render(config_dir, REPO, now=NOW)
    assert (config_dir / "platform" / "services.json").read_bytes() == before


def test_two_modules_declaring_the_same_id_are_refused(tmp_path):
    config_dir = _install(
        tmp_path, "rag", [("addon-probe", "probe", "running"), ("addon-probe", "probe2", None)]
    )
    with pytest.raises(catalog.CatalogError, match="'probe.echo' is declared by probe and probe2"):
        catalog.render(config_dir, REPO, now=NOW)


def test_an_address_service_must_exist_in_the_compose_file(tmp_path):
    config_dir = _install(tmp_path, "", [("addon-probe", "probe", "running")])
    compose = tmp_path / "addons" / "addon-probe" / "docker-compose.yml"
    compose.write_text("services:\n  other: {image: x}\n")
    with pytest.raises(catalog.CatalogError, match="exposes/0/address/service"):
        catalog.render(config_dir, REPO, now=NOW)


def test_a_ui_surface_without_a_public_host_is_refused(tmp_path):
    config_dir = _install(tmp_path, "", [("addon-console", "papaia-flow", "running")])
    env = {k: v for k, v in ROOT_ENV.items() if k != "FLOW_HOST"}
    _write_env(config_dir / ".env", env)
    with pytest.raises(catalog.CatalogError, match="exposes/0/ui/0/host_key.*FLOW_HOST"):
        catalog.render(config_dir, REPO, now=NOW)


def test_without_an_identity_provider_no_catalog_is_rendered(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    _write_env(config_dir / ".env", {"COMPOSE_PROFILES": "rag"})
    assert catalog.render(config_dir, REPO, now=NOW) is False
    assert not (config_dir / "platform").exists()


def test_the_platform_notice_shows_the_test_mode(tmp_path):
    config_dir = _install(tmp_path, "", [])
    _write_env(config_dir / ".env", {**ROOT_ENV, "PAPAIA_TEST_EXTERNAL_MODEL": "1"})
    catalog.render(config_dir, REPO, now=NOW)
    notices = _services(config_dir)["platform_notices"]
    assert [n["id"] for n in notices] == ["test-mode"]
    assert notices[0]["level"] == "warning"


def test_branding_comes_from_the_overlay(tmp_path):
    config_dir = _install(tmp_path, "", [])
    overlay = config_dir / "overlay" / "platform"
    overlay.mkdir(parents=True)
    (overlay / "branding.yaml").write_text(
        "name: Beispiel GmbH\nsuffix: Arbeitsplattform\ncontact: {name: IT-Service}\n"
    )
    (overlay / "brand-logo").write_bytes(b"\x89PNG\r\n\x1a\n fake logo")
    catalog.render(config_dir, REPO, now=NOW)
    branding = _services(config_dir)["branding"]
    assert branding == {
        "name": "Beispiel GmbH",
        "suffix": "Arbeitsplattform",
        "contact": {"name": "IT-Service"},
        "logo_sha256": hashlib.sha256(b"\x89PNG\r\n\x1a\n fake logo").hexdigest(),
    }
    assert (config_dir / "platform" / "brand-logo").read_bytes() == b"\x89PNG\r\n\x1a\n fake logo"


def test_an_unknown_branding_field_is_refused(tmp_path):
    config_dir = _install(tmp_path, "", [])
    overlay = config_dir / "overlay" / "platform"
    overlay.mkdir(parents=True)
    (overlay / "branding.yaml").write_text("name: X\ncolor: red\n")
    with pytest.raises(catalog.CatalogError, match="branding.yaml: /color: unknown field"):
        catalog.render(config_dir, REPO, now=NOW)


# ─────────────────────────────────────────────────────────────────────────
# addon stop / start: state, hashes of the other entries
# ─────────────────────────────────────────────────────────────────────────


def _hashes(config_dir: Path) -> dict[str, str]:
    return {e["id"]: e["content_hash"] for e in _services(config_dir)["services"]}


def _states(config_dir: Path) -> dict[str, str]:
    return {e["id"]: e["state"] for e in _services(config_dir)["services"]}


def test_stop_keeps_the_entry_as_stopped_and_start_restores_it(tmp_path):
    config_dir = _install(
        tmp_path, "rag",
        [("addon-probe", "probe", "running"), ("addon-console", "papaia-flow", "running")],
    )
    catalog.render(config_dir, REPO, now=NOW)
    running = _hashes(config_dir)

    state = argparse.Namespace(config_dir=str(config_dir), repo_root=str(REPO), name="probe",
                               state="stopped", all=False)
    assert cli_addon.cmd_addon_state(state) == 0
    stopped = _hashes(config_dir)
    assert _states(config_dir)["probe.echo"] == "stopped"
    assert stopped.keys() == running.keys()
    assert stopped["probe.echo"] != running["probe.echo"]
    assert {k: v for k, v in stopped.items() if k != "probe.echo"} == {
        k: v for k, v in running.items() if k != "probe.echo"
    }

    state.state = "running"
    assert cli_addon.cmd_addon_state(state) == 0
    assert _hashes(config_dir) == running


def test_stop_of_all_addons_marks_every_addon_stopped(tmp_path):
    config_dir = _install(
        tmp_path, "rag",
        [("addon-probe", "probe", "running"), ("addon-console", "papaia-flow", "running")],
    )
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(REPO), name=None,
                              state="stopped", all=True)
    assert cli_addon.cmd_addon_state(args) == 0
    states = _states(config_dir)
    assert states["qdrant.collections"] == "running"
    assert {states["probe.echo"], states["flow.console"], states["flow.api"]} == {"stopped"}


def test_an_unknown_state_or_addon_is_refused(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [])
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(REPO), name="nope",
                              state="stopped", all=False)
    assert cli_addon.cmd_addon_state(args) == 2
    assert "not registered" in capsys.readouterr().err


def test_a_removed_addon_disappears_from_the_catalog(tmp_path):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text())
    deployed["addons"][0]["active"] = False
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed))
    catalog.render(config_dir, REPO, now=NOW)
    assert list(_hashes(config_dir)) == ["qdrant.collections"]


# ─────────────────────────────────────────────────────────────────────────
# groups.json: no member data, no personal data
# ─────────────────────────────────────────────────────────────────────────


class _Groups:
    """The Admin API's group routes of a realm with a small hierarchy."""

    def __init__(self) -> None:
        self.tree = {
            None: [
                {"id": "a1", "name": "vertrieb", "path": "/vertrieb", "subGroupCount": 1,
                 "attributes": {"papaia.display_name.de": ["Vertrieb"],
                                "papaia.display_name.en": ["Sales"]}},
                {"id": "b2", "name": "studio-autorin", "path": "/studio-autorin",
                 "subGroupCount": 0, "attributes": {"papaia.technical": ["true"]}},
                {"id": "bad id", "name": "weird", "path": "/weird", "subGroupCount": 0},
            ],
            "a1": [
                {"id": "c3", "name": "sued", "path": "/vertrieb/sued", "subGroupCount": 0,
                 "attributes": {"owner": ["anna@example.org"]}},
            ],
        }
        self.calls: list[str] = []

    def call(self, method: str, path: str, body=None):
        assert method == "GET"
        self.calls.append(path)
        if path.startswith("/groups?"):
            parent = None
        else:
            parent = path.split("/")[2]
        first = int(path.split("first=")[1].split("&")[0])
        return [dict(g, members=["x"]) for g in self.tree.get(parent, [])[first:first + 2]]


def test_groups_from_the_realm_carry_only_the_four_fields(capsys):
    fake = _Groups()
    groups = catalog.groups_from_realm(fake.call, page=2)
    assert groups == [
        {"id": "b2", "path": "/studio-autorin",
         "display_name": {"de": "studio-autorin", "en": "studio-autorin"}, "technical": True},
        {"id": "a1", "path": "/vertrieb",
         "display_name": {"de": "Vertrieb", "en": "Sales"}, "technical": False},
        {"id": "c3", "path": "/vertrieb/sued",
         "display_name": {"de": "sued", "en": "sued"}, "technical": False},
    ]
    assert "not in the group list" in capsys.readouterr().out
    assert all("briefRepresentation=false" in c for c in fake.calls)


def test_the_group_list_is_written_only_when_it_changed(tmp_path):
    groups = [{"id": "a1", "path": "/a", "display_name": {"de": "A", "en": "A"},
               "technical": False}]
    assert catalog.write_groups(tmp_path, groups, now=NOW) is True
    path = tmp_path / "platform" / "groups.json"
    first = path.read_bytes()
    doc = json.loads(first)
    schema_check.validate(doc, _schema("platform-groups.v1.schema.json"))
    assert catalog.write_groups(tmp_path, groups, now=datetime.now(timezone.utc)) is False
    assert path.read_bytes() == first
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644


def test_realm_sync_writes_the_group_list_once_and_audits_it(tmp_path):
    from lib import realm_sync as rs

    fake = _Groups()
    with rs.AuditLog(rs.audit_path(tmp_path), rs.new_correlation_id()) as audit:
        changes = rs.sync_platform_groups(fake.call, tmp_path, apply=True, audit=audit)
        assert [c.operation for c in changes] == ["platform_groups.write"]
        assert rs.sync_platform_groups(fake.call, tmp_path, apply=True, audit=audit) == []
    doc = json.loads((tmp_path / "platform" / "groups.json").read_text())
    assert [g["id"] for g in doc["groups"]] == ["b2", "a1", "c3"]
    rows = [json.loads(x) for x in rs.audit_path(tmp_path).read_text().splitlines()]
    assert [r["operation"] for r in rows] == ["realm_sync.platform_groups.write"]
    # A file of the configuration directory, written on the host: no token, no client.
    assert rows[0]["azp"] is None and rows[0]["identity_kind"] is None
    assert "anna" not in (tmp_path / "platform" / "groups.json").read_text()

    fake.tree[None].pop(0)
    changes = rs.sync_platform_groups(fake.call, tmp_path, apply=False)
    assert [c.operation for c in changes] == ["platform_groups.write"]
    assert [g["id"] for g in json.loads(
        (tmp_path / "platform" / "groups.json").read_text())["groups"]] == ["b2", "a1", "c3"]


def test_the_catalog_render_command_writes_and_then_reports_unchanged(tmp_path, capsys):
    from lib import cli

    config_dir = _install(tmp_path, "rag", [])
    argv = ["--config-dir", str(config_dir), "--repo-root", str(REPO), "catalog-render"]
    assert cli.main(argv) == 0
    assert "Platform catalog written" in capsys.readouterr().out
    assert cli.main(argv) == 0
    assert "Platform catalog unchanged" in capsys.readouterr().out


def test_the_catalog_render_command_names_why_there_is_no_catalog(tmp_path, capsys):
    from lib import cli

    config_dir = _install(tmp_path, "rag", [])
    env = config_dir / ".env"
    env.write_text(
        "\n".join(line for line in env.read_text().splitlines() if "OIDC_ISSUER" not in line)
        + "\n"
    )
    argv = ["--config-dir", str(config_dir), "--repo-root", str(REPO), "catalog-render"]
    assert cli.main(argv) == 3
    assert "OIDC_ISSUER is not set" in capsys.readouterr().err
    assert not (config_dir / catalog.CATALOG_DIR / catalog.SERVICES_FILE).exists()


def test_papaia_ctl_dispatches_catalog_render():
    script = (REPO / "tools" / "papaia-ctl").read_text()
    assert "render)    cmd_catalog_render" in script
    assert "papaia-ctl catalog render" in script
