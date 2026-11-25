"""The data class of a model route (ADR 0031, first step): render, route file, catalog,
module keys and the start rule.

* Render: every alias of LiteLLM's configuration carries `model_info.papaia_max_class`, a
  class of the kit scale: the overlay value, else `PAPAIA_MODEL_MAX_CLASS` (root `.env`),
  else `internal`. A hosted test backend is capped at `internal`; a value outside the scale
  stops the render; a value from a layer below the overlay is dropped and reported; an alias
  with several deployments or fallbacks gets the lowest class it can reach.
* Route file: `ai/litellm/model-routes.json` (alias -> class, format, generation time),
  mode 0644, mounted read-only into the gateway; a changed class is one `config_changed`
  audit row.
* Catalog: the `models` block lists every alias as a kit `ModelAlias`.
* Keys: a need's `max_class` must be on the kit scale; the key stores the declared classes
  (`metadata.papaia_need_classes`) and is replaced when they change.
* Start rule: `addon start` and `doctor model_gateway_classes` report a need above its route;
  `doctor` fails when the route file is missing or differs from the configuration.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import (
    catalog,
    cli_addon,
    common,
    deployment,
    doctor,
    exposes,
    hosted_model,
    model_gateway,
    model_routes,
    render_core,
    schema_check,
)
from tests import test_hosted_model as hosted
from tests.test_catalog import ROOT_ENV
from tests.test_model_gateway import (
    REAL_REPO,
    FakeLiteLLM,
    _addon_args,
    _journal_lines,
    _key_config,
    _need,
    _write_module,
)

NOW = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
GOLDEN = Path(__file__).parent / "golden" / "catalog"
AUDIT_SCHEMA = json.loads(
    (REAL_REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text("utf-8")
)
SCALE = (
    "public", "internal", "partner_contact", "personal", "employee", "confidential",
    "special", "professional_secret",
)


# ── helpers ────────────────────────────────────────────────────────────────


def _model(name: str, **info) -> dict:
    """A model entry that routes to the stack service `checker`."""
    entry: dict = {
        "model_name": name,
        "litellm_params": {
            "model": f"hosted_vllm/{name}",
            "api_base": "http://checker:8080/v1",
            "api_key": "os.environ/CHECKER_API_KEY",
        },
    }
    if info:
        entry["model_info"] = info
    return entry


def _install(repo_root: Path, config_dir: Path, *entries: dict, extra: dict | None = None,
             **root: str) -> None:
    """A rendered-ready installation with the gateway profile, the stack service `checker`
    and an overlay of LiteLLM's configuration with `entries` (plus `extra` top-level keys)."""
    hosted._setup(repo_root, config_dir)
    hosted._stack_service(repo_root, "checker")
    hosted._set_root(config_dir, COMPOSE_PROFILES="litellm", **root)
    overlay = {"model_list": list(entries), **(extra or {})}
    path = config_dir / "overlay" / "ai" / "litellm" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(overlay), encoding="utf-8")


def _rendered(config_dir: Path) -> list[dict]:
    text = (config_dir / render_core.LITELLM_CONFIG).read_text(encoding="utf-8")
    return yaml.safe_load(text).get("model_list") or []


def _classes(config_dir: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for entry in _rendered(config_dir):
        value = (entry.get("model_info") or {}).get("papaia_max_class")
        found.setdefault(entry["model_name"], set()).add(value)
    return found


def _route_file(config_dir: Path) -> dict:
    return json.loads((config_dir / model_routes.ROUTES_FILE).read_text(encoding="utf-8"))


def _outbox(config_dir: Path) -> list[dict]:
    path = config_dir / "audit" / "outbox" / "papaia-ctl.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _route_rows(config_dir: Path) -> list[dict]:
    return [r for r in _outbox(config_dir) if r.get("operation") == "model_route.class"]


def _valid_audit(row: dict) -> None:
    validator = Draft202012Validator({"$defs": AUDIT_SCHEMA["$defs"],
                                      "$ref": "#/$defs/submission"})
    assert [e.message for e in validator.iter_errors(row)] == []


# ── the scale comes from the kit ───────────────────────────────────────────


def test_the_scale_is_the_vendored_kit_list():
    schema = exposes.load_schema(exposes.SERVICES_SCHEMA)
    assert model_routes.scale() == tuple(schema["$defs"]["DataClass"]["enum"]) == SCALE


def test_no_own_enumeration_of_the_scale_in_the_route_code():
    for name in ("model_routes.py", "model_gateway.py"):
        text = (REAL_REPO / "tools" / "lib" / name).read_text(encoding="utf-8")
        assert "partner_contact" not in text, name
        assert "professional_secret" not in text, name


# ── render ─────────────────────────────────────────────────────────────────


def test_without_a_decision_every_alias_is_internal(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model",
             PAPAIA_DEFAULT_EMBED_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    for alias in ("papaia-chat", "papaia-structured", "papaia-embed"):
        assert classes[alias] == {"internal"}, alias


def test_the_root_setting_applies_to_every_alias(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model",
             PAPAIA_MODEL_MAX_CLASS="confidential")
    render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    assert classes["papaia-chat"] == classes["papaia-structured"] == {"confidential"}


def test_the_overlay_value_of_an_alias_wins(repo_root, config_dir):
    own = _model("papaia-chat", papaia_max_class="personal")
    _install(repo_root, config_dir, _model("checker-model"), own,
             PAPAIA_DEFAULT_MODEL="checker-model", PAPAIA_MODEL_MAX_CLASS="confidential")
    render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    assert classes["papaia-chat"] == {"personal"}
    assert classes["papaia-structured"] == {"confidential"}


def test_a_hosted_test_backend_is_capped_at_internal(repo_root, config_dir, caplog):
    entry = hosted._hosted_entry()
    entry["model_info"] = {"papaia_max_class": "professional_secret"}
    hosted._test_stack(repo_root, config_dir, entry)
    hosted._set_root(config_dir, COMPOSE_PROFILES="litellm",
                     PAPAIA_DEFAULT_MODEL=hosted.HOSTED["model_name"],
                     PAPAIA_MODEL_MAX_CLASS="professional_secret")
    with caplog.at_level(logging.WARNING):
        render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    assert classes["papaia-chat"] == {"internal"}
    assert classes[hosted.HOSTED["model_name"]] == {"internal"}
    assert "internal" in caplog.text and "test" in caplog.text


@pytest.mark.parametrize(
    "value",
    ["secret", "", "internal ", " internal", "Internal", "internal\n", "internal,personal",
     "confidential-ish", 3, True, None, ["internal"]],
)
def test_an_overlay_value_outside_the_scale_stops_the_render(repo_root, config_dir, value):
    own = _model("papaia-chat", papaia_max_class=value)
    _install(repo_root, config_dir, own)
    with pytest.raises(render_core.RenderError, match="papaia-chat") as caught:
        render_core.render(config_dir, repo_root)
    assert "papaia_max_class" in str(caught.value)


@pytest.mark.parametrize("value", ["secret", "", "internal x", "INTERNAL"])
def test_a_root_value_outside_the_scale_stops_the_render(repo_root, config_dir, value):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model",
             PAPAIA_MODEL_MAX_CLASS=value)
    with pytest.raises(render_core.RenderError, match="PAPAIA_MODEL_MAX_CLASS"):
        render_core.render(config_dir, repo_root)


def test_a_value_below_the_overlay_is_dropped_and_reported(repo_root, config_dir, caplog):
    base = repo_root / "src" / "ai" / "litellm" / "config.yaml"
    doc = yaml.safe_load(base.read_text(encoding="utf-8"))
    doc["model_list"] = [_model("base-model", papaia_max_class="professional_secret")]
    base.write_text(yaml.safe_dump(doc), encoding="utf-8")
    _install(repo_root, config_dir, PAPAIA_DEFAULT_MODEL="base-model")
    with caplog.at_level(logging.WARNING):
        render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    assert classes["base-model"] == {"internal"}
    assert classes["papaia-chat"] == {"internal"}
    assert "base-model" in caplog.text and "papaia_max_class" in caplog.text


def test_several_deployments_of_an_alias_get_the_lowest_class(repo_root, config_dir):
    _install(repo_root, config_dir,
             _model("papaia-chat", papaia_max_class="confidential"),
             {**_model("papaia-chat", papaia_max_class="personal"),
              "litellm_params": {**_model("x")["litellm_params"], "model": "hosted_vllm/other"}})
    render_core.render(config_dir, repo_root)
    assert _classes(config_dir)["papaia-chat"] == {"personal"}


@pytest.mark.parametrize("section", ["router_settings", "litellm_settings"])
@pytest.mark.parametrize("key", ["fallbacks", "context_window_fallbacks",
                                 "content_policy_fallbacks"])
def test_a_fallback_lowers_the_class_of_the_alias(repo_root, config_dir, section, key):
    _install(repo_root, config_dir,
             _model("papaia-chat", papaia_max_class="confidential"),
             _model("low-model", papaia_max_class="public"),
             extra={section: {key: [{"papaia-chat": ["low-model"]}]}})
    render_core.render(config_dir, repo_root)
    classes = _classes(config_dir)
    assert classes["papaia-chat"] == {"public"}
    assert classes["low-model"] == {"public"}


def test_a_default_fallback_lowers_every_alias(repo_root, config_dir):
    _install(repo_root, config_dir,
             _model("papaia-chat", papaia_max_class="confidential"),
             _model("low-model", papaia_max_class="partner_contact"),
             extra={"router_settings": {"default_fallbacks": ["low-model"]}})
    render_core.render(config_dir, repo_root)
    assert _classes(config_dir)["papaia-chat"] == {"partner_contact"}


# ── route file ─────────────────────────────────────────────────────────────


def test_the_route_file_holds_the_rendered_aliases(repo_root, config_dir):
    own = _model("papaia-chat", papaia_max_class="employee")
    _install(repo_root, config_dir, _model("checker-model"), own,
             PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    doc = _route_file(config_dir)
    assert set(doc) == {"format", "generated_at", "routes"}
    assert doc["format"] == model_routes.FORMAT
    assert doc["routes"] == {"papaia-chat": "employee", "papaia-structured": "internal"}
    datetime.strptime(doc["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
    path = config_dir / model_routes.ROUTES_FILE
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    text = path.read_text(encoding="utf-8")
    for secret in ("sk-", "CHECKER_API_KEY", "api_key", "checker:8080"):
        assert secret not in text
    assert model_routes.read_route_file(config_dir) == doc["routes"]


def test_the_route_file_is_rewritten_only_when_a_class_changes(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    first = (config_dir / model_routes.ROUTES_FILE).read_bytes()
    rows = _route_rows(config_dir)
    assert sorted(r["object_ref"]["id"] for r in rows) == ["papaia-chat", "papaia-structured"]

    render_core.render(config_dir, repo_root)
    assert (config_dir / model_routes.ROUTES_FILE).read_bytes() == first
    assert _route_rows(config_dir) == rows

    hosted._set_root(config_dir, PAPAIA_MODEL_MAX_CLASS="personal")
    render_core.render(config_dir, repo_root)
    assert _route_file(config_dir)["routes"] == {"papaia-chat": "personal",
                                                 "papaia-structured": "personal"}
    new = _route_rows(config_dir)[len(rows):]
    assert sorted(r["object_ref"]["id"] for r in new) == ["papaia-chat", "papaia-structured"]
    assert {r["data_class"] for r in new} == {"personal"}


def test_a_changed_route_class_is_one_config_changed_row(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    for row in _route_rows(config_dir):
        assert row["format"] == "papaia.audit/1"
        assert row["writer"] == "papaia-ctl"
        assert row["event"] == "config_changed"
        assert row["effect"] == "write"
        assert row["result"] == "allowed"
        assert row["object_ref"]["type"] == "model_alias"
        assert row["data_class"] == "internal"
        assert row["detail"] is None
        _valid_audit(row)
    assert len({r["correlation_id"] for r in _route_rows(config_dir)}) == 1


def test_without_the_gateway_profile_there_is_no_route_file(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    hosted._set_root(config_dir, COMPOSE_PROFILES="")
    render_core.render(config_dir, repo_root)
    assert not (config_dir / model_routes.ROUTES_FILE).exists()
    assert _route_rows(config_dir) == []


@pytest.mark.parametrize(
    "text",
    ["", "{", "[]", json.dumps({"format": "other/1", "generated_at": "x", "routes": {}}),
     json.dumps({"format": "papaia.model-routes/1", "generated_at": "2026-11-25T10:00:00Z",
                 "routes": {"papaia-chat": "secret"}}),
     json.dumps({"format": "papaia.model-routes/1", "generated_at": "2026-11-25T10:00:00Z",
                 "routes": {"gpt-4o": "internal"}}),
     json.dumps({"format": "papaia.model-routes/1", "generated_at": "2026-11-25T10:00:00Z",
                 "routes": {}, "extra": 1})],
)
def test_a_malformed_route_file_is_refused(config_dir, text):
    path = config_dir / model_routes.ROUTES_FILE
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(model_routes.ModelRoutesError):
        model_routes.read_route_file(config_dir)


def test_the_route_file_is_mounted_read_only_into_the_gateway():
    compose = yaml.safe_load(
        (REAL_REPO / "src/ai/litellm/docker-compose.yml").read_text(encoding="utf-8")
    )
    volumes = compose["services"]["litellm"]["volumes"]
    (mount,) = [v for v in volumes if isinstance(v, dict)
                and v.get("source") == "${PAPAIA_CONFIG_DIR}/ai/litellm/model-routes.json"]
    assert mount["read_only"] is True
    assert mount["type"] == "bind"
    assert mount["bind"]["create_host_path"] is False
    for service, body in compose["services"].items():
        if service != "litellm":
            assert "model-routes" not in json.dumps(body), service


def test_the_root_template_documents_the_route_class():
    text = (REAL_REPO / "src" / ".env.example").read_text(encoding="utf-8")
    assert "PAPAIA_MODEL_MAX_CLASS" in text
    template = common.parse_env_file(REAL_REPO / "src" / ".env.example")
    assert template.get("PAPAIA_MODEL_MAX_CLASS", "internal") == "internal"


# ── catalog ────────────────────────────────────────────────────────────────


GATEWAY_CONFIG = {
    "model_list": [
        {"model_name": "qwen2.5-1.5b-instruct",
         "litellm_params": {"model": "hosted_vllm/qwen2.5-1.5b-instruct",
                            "api_base": "http://localai:8080/v1"},
         "model_info": {"papaia_max_class": "internal"}},
        {"model_name": "papaia-chat",
         "litellm_params": {"model": "hosted_vllm/qwen2.5-7b-instruct-q4",
                            "api_base": "http://localai:8080/v1"},
         "model_info": {"papaia_max_class": "confidential"}},
        {"model_name": "papaia-structured",
         "litellm_params": {"model": "hosted_vllm/qwen2.5-1.5b-instruct",
                            "api_base": "http://localai:8080/v1"},
         "model_info": {"papaia_max_class": "personal"}},
        {"model_name": "papaia-embed",
         "litellm_params": {"model": "hosted_vllm/own-embedder", "api_base": "http://localai:8080/v1"},
         "model_info": {"mode": "embedding", "papaia_max_class": "internal"}},
        {"model_name": "papaia-vision",
         "litellm_params": {"model": "hosted_vllm/reference-chat",
                            "api_base": "https://api.example.org/v1"},
         "model_info": {"papaia_max_class": "internal", "test_backend": True,
                        "papaia_features": ["chat", "stream"], "papaia_context": 32768}},
    ],
}


def _gateway_install(tmp_path: Path, profiles: str = "litellm", config: dict | None = None
                     ) -> Path:
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in {**ROOT_ENV, "COMPOSE_PROFILES": profiles}.items()),
        encoding="utf-8",
    )
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": []}), "utf-8")
    path = config_dir / render_core.LITELLM_CONFIG
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(GATEWAY_CONFIG if config is None else config), "utf-8")
    return config_dir


def _models(config_dir: Path) -> list[dict]:
    catalog.render(config_dir, REAL_REPO, now=NOW)
    return json.loads((config_dir / "platform" / "services.json").read_text())["models"]


def test_the_catalog_lists_every_alias_with_its_route_class(tmp_path):
    models = _models(_gateway_install(tmp_path))
    assert models == [
        {"alias": "papaia-chat", "features": ["chat", "tools", "stream"], "context": 8192,
         "max_class": "confidential", "test_backend": False},
        {"alias": "papaia-embed", "features": ["embeddings"], "context": 4096,
         "max_class": "internal", "test_backend": False},
        {"alias": "papaia-structured",
         "features": ["chat", "json_schema", "json_object", "stream"], "context": 4096,
         "max_class": "personal", "test_backend": False},
        {"alias": "papaia-vision", "features": ["chat", "stream"], "context": 32768,
         "max_class": "internal", "test_backend": True},
    ]
    schema = exposes.load_schema(exposes.SERVICES_SCHEMA)
    for model in models:
        schema_check.validate(model, schema, "#/$defs/ModelAlias")


def test_the_catalog_with_the_gateway_matches_its_golden_file(tmp_path):
    config_dir = _gateway_install(tmp_path)
    assert catalog.render(config_dir, REAL_REPO, now=NOW) is True
    rendered = json.loads((config_dir / "platform" / "services.json").read_text())
    golden = json.loads((GOLDEN / "core-gateway.services.json").read_text())
    assert rendered == golden
    schema_check.validate(rendered, exposes.load_schema(exposes.SERVICES_SCHEMA))


def test_without_the_gateway_the_models_block_is_empty(tmp_path):
    assert _models(_gateway_install(tmp_path, profiles="rag")) == []


def test_the_lowest_class_of_an_alias_is_published(tmp_path):
    config = {"model_list": [
        {"model_name": "papaia-chat", "litellm_params": {"model": "hosted_vllm/a"},
         "model_info": {"papaia_max_class": "special"}},
        {"model_name": "papaia-chat", "litellm_params": {"model": "hosted_vllm/b"},
         "model_info": {"papaia_max_class": "employee"}},
    ]}
    (model,) = _models(_gateway_install(tmp_path, config=config))
    assert model["max_class"] == "employee"


@pytest.mark.parametrize(
    "info",
    [{}, {"papaia_max_class": "secret"}, {"papaia_max_class": "internal",
                                          "papaia_features": ["telepathy"]},
     {"papaia_max_class": "internal", "papaia_context": 100},
     {"papaia_max_class": "internal", "papaia_context": "8192"}],
)
def test_a_rendered_alias_without_a_valid_class_stops_the_catalog(tmp_path, info):
    config = {"model_list": [{"model_name": "papaia-chat",
                              "litellm_params": {"model": "hosted_vllm/a"}, "model_info": info}]}
    config_dir = _gateway_install(tmp_path, config=config)
    with pytest.raises(catalog.CatalogError, match="papaia-chat"):
        catalog.render(config_dir, REAL_REPO, now=NOW)
    assert not (config_dir / "platform" / "services.json").exists()


def test_the_rendered_catalog_carries_the_classes_of_the_render(repo_root, config_dir):
    shutil.copy(REAL_REPO / "ADDON_API", repo_root / "ADDON_API")
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model",
             PAPAIA_MODEL_MAX_CLASS="employee", OIDC_ISSUER=ROOT_ENV["OIDC_ISSUER"])
    render_core.render(config_dir, repo_root)
    services = json.loads((config_dir / "platform" / "services.json").read_text())
    assert [(m["alias"], m["max_class"]) for m in services["models"]] == [
        ("papaia-chat", "employee"), ("papaia-structured", "employee")
    ]


# ── module keys ────────────────────────────────────────────────────────────


def _manifest(*needs: dict) -> dict:
    return {"name": "flow", "exposes": [{"id": "flow.api", "models": {"needs": list(needs)}}]}


@pytest.mark.parametrize("value", ["secret", "Internal", "internal ", "", "top_secret"])
def test_a_need_class_outside_the_scale_is_refused_with_its_name(value):
    manifest = _manifest({**_need("papaia-chat"), "max_class": value})
    with pytest.raises(model_gateway.ModelGatewayError, match="max_class") as caught:
        model_gateway.module_aliases(manifest)
    assert repr(value) in str(caught.value)
    with pytest.raises(model_gateway.ModelGatewayError):
        model_gateway.module_need_classes(manifest)


def test_the_declared_classes_are_the_highest_per_alias():
    manifest = _manifest(
        {**_need("papaia-chat"), "max_class": "personal"},
        {**_need("papaia-chat"), "max_class": "confidential"},
        {**_need("papaia-structured"), "max_class": "public"},
        {"alias": "papaia-embed"},
    )
    assert model_gateway.module_need_classes(manifest) == {
        "papaia-chat": "confidential", "papaia-structured": "public",
    }


def test_a_need_without_a_class_leaves_its_alias_undeclared():
    manifest = _manifest({**_need("papaia-chat"), "max_class": "personal"},
                         {"alias": "papaia-chat"})
    assert model_gateway.module_need_classes(manifest) == {}


def test_the_key_stores_the_declared_classes(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway,
        need_classes={"papaia-chat": "personal"},
    )
    assert outcome == "created"
    (row,) = gateway.keys.values()
    assert row["metadata"] == {"tags": ["module:flow"],
                               "papaia_need_classes": {"papaia-chat": "personal"}}
    gateway.calls.clear()
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway,
        need_classes={"papaia-chat": "personal"},
    ) == "unchanged"
    assert [c[0] for c in gateway.calls] == ["GET"]


def test_a_changed_declaration_replaces_the_key_with_a_journal_row(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway,
                                    need_classes={"papaia-chat": "personal"})
    old = common.parse_env_file(config_dir / "addons/flow/.env")["PAPAIA_MODEL_KEY"]
    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway,
        need_classes={"papaia-chat": "confidential"},
    )
    assert outcome == "replaced"
    (row,) = gateway.keys.values()
    assert row["metadata"]["papaia_need_classes"] == {"papaia-chat": "confidential"}
    (entry,) = _journal_lines(target)
    assert (entry["kind"], entry["reason"]) == ("key_revoke", "key_replaced")
    assert entry["object_ref"] == hashlib.sha256(old.encode()).hexdigest()


def test_a_key_made_before_the_classes_is_replaced(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    (row,) = gateway.keys.values()
    del row["metadata"]["papaia_need_classes"]  # as an older core made it
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway
    ) == "replaced"
    (row,) = gateway.keys.values()
    assert row["metadata"]["papaia_need_classes"] == {}


def test_sync_stores_the_classes_of_the_manifest(repo_root, config_dir, tmp_path):
    hosted._setup(repo_root, config_dir)
    hosted._set_root(config_dir, COMPOSE_PROFILES="litellm")
    addon = _write_module(tmp_path, [{**_need("papaia-chat"), "max_class": "employee"}])
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "flow", "path": str(addon), "active": True}]
    deployment.save(config_dir, deployed)
    (config_dir / "addons" / "flow").mkdir(parents=True)
    (config_dir / "addons" / "flow" / ".env").write_text("X=1\n", encoding="utf-8")
    gateway = FakeLiteLLM()
    assert model_gateway.sync(config_dir, repo_root, gateway) == (["flow"], [])
    (row,) = gateway.keys.values()
    assert row["metadata"]["papaia_need_classes"] == {"papaia-chat": "employee"}


def _start_module(repo_root, config_dir, tmp_path, monkeypatch, needs, **root):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model",
             **root)
    addon = _write_module(tmp_path, needs)
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "flow", "path": str(addon), "active": True}]
    deployment.save(config_dir, deployed)
    (config_dir / "addons" / "flow").mkdir(parents=True)
    (config_dir / "addons" / "flow" / ".env").write_text(
        "FLOW_SETTING=1\nFLOW_HOST=https://flow.example.org\n", encoding="utf-8"
    )
    gateway = FakeLiteLLM()
    monkeypatch.setattr(model_gateway, "connect", lambda *a, **k: gateway)
    return gateway


def test_addon_start_refuses_a_need_class_outside_the_scale(
    repo_root, config_dir, tmp_path, monkeypatch, capsys
):
    gateway = _start_module(repo_root, config_dir, tmp_path, monkeypatch,
                            [{**_need("papaia-chat"), "max_class": "top_secret"}])
    assert cli_addon.cmd_addon_start(_addon_args(config_dir, repo_root)) == 2
    err = capsys.readouterr().err
    assert "top_secret" in err and "max_class" in err
    assert gateway.keys == {}


def test_addon_start_reports_a_need_above_its_route(
    repo_root, config_dir, tmp_path, monkeypatch, capsys
):
    gateway = _start_module(repo_root, config_dir, tmp_path, monkeypatch,
                            [{**_need("papaia-chat"), "max_class": "confidential"},
                             {**_need("papaia-structured"), "max_class": "public"}])
    assert cli_addon.cmd_addon_start(_addon_args(config_dir, repo_root)) == 0
    err = capsys.readouterr().err
    assert "flow" in err and "papaia-chat" in err
    assert "confidential" in err and "internal" in err
    assert "papaia-structured" not in err
    (row,) = gateway.keys.values()  # the key is still made
    assert row["metadata"]["papaia_need_classes"] == {
        "papaia-chat": "confidential", "papaia-structured": "public"}


# ── doctor model_gateway_classes ──────────────────────────────────────────


def _doctor(config_dir: Path, repo_root: Path) -> doctor.CheckResult:
    return doctor.check_model_gateway_classes_file(config_dir, repo_root)


def test_doctor_passes_when_the_route_file_matches(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    result = _doctor(config_dir, repo_root)
    assert result.status == doctor.PASS, result.summary
    assert "model_gateway_classes" in doctor.CHECK_NAMES
    names = list(doctor.CHECK_NAMES)
    assert names.index("model_gateway_classes") == names.index("model_gateway_content") + 1


def test_doctor_fails_without_the_route_file(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    (config_dir / model_routes.ROUTES_FILE).unlink()
    result = _doctor(config_dir, repo_root)
    assert result.status == doctor.FAIL
    assert "missing" in result.summary


@pytest.mark.parametrize(
    "routes",
    [{"papaia-chat": "internal"},
     {"papaia-chat": "confidential", "papaia-structured": "internal"},
     {"papaia-chat": "internal", "papaia-structured": "internal", "papaia-embed": "internal"}],
)
def test_doctor_fails_when_the_route_file_differs(repo_root, config_dir, routes):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    doc = _route_file(config_dir)
    doc["routes"] = routes
    (config_dir / model_routes.ROUTES_FILE).write_text(json.dumps(doc), encoding="utf-8")
    result = _doctor(config_dir, repo_root)
    assert result.status == doctor.FAIL
    assert "differ" in result.summary


def test_doctor_fails_for_a_malformed_route_file(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"), PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    (config_dir / model_routes.ROUTES_FILE).write_text("{", encoding="utf-8")
    assert _doctor(config_dir, repo_root).status == doctor.FAIL


def test_doctor_reports_a_need_above_its_route(repo_root, config_dir, tmp_path, monkeypatch):
    _start_module(repo_root, config_dir, tmp_path, monkeypatch,
                  [{**_need("papaia-chat"), "max_class": "special"}])
    render_core.render(config_dir, repo_root)
    result = _doctor(config_dir, repo_root)
    assert result.status == doctor.WARN
    assert "flow" in result.summary and "papaia-chat" in result.summary
    assert "special" in result.summary and "internal" in result.summary
    assert result.details["above_route"] == [
        {"module": "flow", "alias": "papaia-chat", "need_class": "special",
         "route_class": "internal"}
    ]


def test_doctor_skips_without_the_gateway(repo_root, config_dir):
    _install(repo_root, config_dir, _model("checker-model"))
    hosted._set_root(config_dir, COMPOSE_PROFILES="")
    render_core.render(config_dir, repo_root)
    assert _doctor(config_dir, repo_root).status == doctor.SKIP


def test_the_hosted_route_rules_stay_in_force(repo_root, config_dir):
    # The class is a mark on the entry like test_backend: a layer cannot set test_backend.
    entry = _model("checker-model", test_backend=True, papaia_max_class="personal")
    _install(repo_root, config_dir, entry, PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    (rendered,) = [e for e in _rendered(config_dir) if e["model_name"] == "checker-model"]
    assert hosted_model.MARK not in rendered["model_info"]
    assert rendered["model_info"]["papaia_max_class"] == "personal"
