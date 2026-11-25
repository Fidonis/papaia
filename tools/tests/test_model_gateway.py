"""The model gateway: aliases only, one key per module, no stored contents.

* Render (M-01, M-06): LiteLLM's configuration carries the aliases `papaia-chat`,
  `papaia-structured` (and `papaia-embed`) mapped onto the named default model, and the
  settings that keep request and response contents out of its database and logs. A layer
  that switches them off, or registers a logging callback, is refused.
* Setup (E-32): `--local-ai` names the default model, which the render downloads and
  registers without a hand-made entry.
* Keys (M-02): every module that declares `models.needs` gets a virtual key of its own
  (`module-<name>`, its aliases only, budget tag `module:<name>`) in its `.env` as
  `PAPAIA_MODEL_KEY`. Revoking or replacing a key writes `key_revoke` into the erasure
  journal `model-gateway` (key id, never the key) before the key is deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import cli_addon, common, deployment, envtree, model_gateway, render_core, resolve
from lib import secrets as core_secrets

REAL_REPO = Path(__file__).resolve().parents[2]
LOCALAI = REAL_REPO / "src" / "ai" / "localai"

# Synthetic values only.
CORRELATION = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"


# ── render ─────────────────────────────────────────────────────────────────


def _setup(repo_root: Path, config_dir: Path, **root: str) -> None:
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree = core_secrets.generate_missing_secrets(tree, envtree.load_seed_tree(repo_root))
    args = resolve.SetupArgs(
        config_dir=config_dir, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_reverse_proxy(tree, args)
    envtree.persist_tree(tree, config_dir, repo_root)
    _set_root(config_dir, **root)


def _set_root(config_dir: Path, **values: str) -> None:
    path = config_dir / ".env"
    current = common.parse_env_file(path)
    current.update(values)
    path.write_text("".join(f"{k}={v}\n" for k, v in current.items()), encoding="utf-8")


def _install_localai(repo_root: Path) -> None:
    """The shipped LocalAI models (YAMLs and list) in the synthetic repo, and the LocalAI
    service in its compose file, as in the real repo."""
    target = repo_root / "src" / "ai" / "localai"
    for path in (LOCALAI / "models").glob("*.yaml"):
        shutil.copy(path, target / "models" / path.name)
    shutil.copy(LOCALAI / "models.txt", target / "models.txt")
    root = repo_root / "src" / "docker-compose.yml"
    doc = yaml.safe_load(root.read_text(encoding="utf-8")) or {}
    doc.setdefault("include", []).append({"path": "./ai/localai/docker-compose.yml"})
    root.write_text(yaml.safe_dump(doc), encoding="utf-8")


def _overlay(config_dir: Path, doc: dict) -> None:
    path = config_dir / "overlay" / "ai" / "litellm" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")


def _rendered(config_dir: Path) -> dict:
    return yaml.safe_load((config_dir / "ai/litellm/config.yaml").read_text(encoding="utf-8"))


def _entries(config_dir: Path, name: str) -> list[dict]:
    return [e for e in _rendered(config_dir).get("model_list") or [] if e["model_name"] == name]


def test_the_shipped_gateway_configuration_stores_no_contents():
    config = yaml.safe_load((REAL_REPO / "src/ai/litellm/config.yaml").read_text("utf-8"))
    assert config["general_settings"]["store_prompts_in_spend_logs"] is False
    assert config["litellm_settings"]["turn_off_message_logging"] is True
    assert config["litellm_settings"]["redact_user_api_key_info"] is True
    assert set(config["litellm_settings"]["callbacks"]) <= model_gateway.ALLOWED_CALLBACKS
    for key in ("success_callback", "failure_callback", "service_callback"):
        assert key not in config["litellm_settings"]


def test_the_gateway_logs_without_payload():
    compose = yaml.safe_load((REAL_REPO / "src/ai/litellm/docker-compose.yml").read_text("utf-8"))
    env = compose["services"]["litellm"]["environment"]
    assert str(env.get("LITELLM_LOG", "INFO")).upper() != "DEBUG"
    template = common.parse_env_file(REAL_REPO / "src/ai/litellm/.env.example")
    assert template.get("LITELLM_LOG", "INFO").upper() != "DEBUG"


@pytest.mark.parametrize("level", ["DEBUG", "debug"])
def test_a_log_level_that_prints_bodies_is_refused(repo_root, config_dir, level):
    _setup(repo_root, config_dir)
    env = config_dir / "ai" / "litellm" / ".env"
    env.parent.mkdir(parents=True, exist_ok=True)
    with env.open("a", encoding="utf-8") as fh:
        fh.write(f"LITELLM_LOG={level}\n")
    with pytest.raises(render_core.RenderError, match="model gateway"):
        render_core.render(config_dir, repo_root)


def test_the_render_keeps_the_no_content_settings(repo_root, config_dir):
    _setup(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    rendered = _rendered(config_dir)
    assert rendered["general_settings"]["store_prompts_in_spend_logs"] is False
    assert rendered["litellm_settings"]["turn_off_message_logging"] is True
    assert rendered["litellm_settings"]["redact_user_api_key_info"] is True


@pytest.mark.parametrize(
    "overlay",
    [
        {"general_settings": {"store_prompts_in_spend_logs": True}},
        {"litellm_settings": {"turn_off_message_logging": False}},
        {"litellm_settings": {"redact_user_api_key_info": None}},
        {"litellm_settings": {"callbacks": ["prometheus", "langfuse"]}},
        {"litellm_settings": {"success_callback": ["s3"]}},
        {"litellm_settings": {"failure_callback": "langfuse"}},
        {"litellm_settings": {"service_callback": ["datadog"]}},
        {"litellm_settings": {"set_verbose": True}},
        {"litellm_settings": {"cache": True}},
        {"litellm_settings": {"cache": True, "cache_params": {"type": "redis"}}},
        {"litellm_settings": {"cache_params": {"type": "disk"}}},
        {"litellm_settings": {"cache_params": {"type": "s3"}}},
        {"litellm_settings": {"cache_params": "disk"}},
        {"general_settings": {"alerting": ["slack"]}},
        {"general_settings": {"alerting": "email"}},
    ],
)
def test_a_layer_that_would_store_or_ship_contents_is_refused(repo_root, config_dir, overlay):
    _setup(repo_root, config_dir)
    _overlay(config_dir, overlay)
    with pytest.raises(render_core.RenderError, match="model gateway"):
        render_core.render(config_dir, repo_root)


@pytest.mark.parametrize(
    "overlay",
    [
        {"litellm_settings": {"cache": False}},
        {"litellm_settings": {"cache": True, "cache_params": {"type": "local"}}},
        {"general_settings": {"alerting": []}},
    ],
)
def test_a_layer_that_keeps_nothing_beyond_the_process_is_accepted(repo_root, config_dir, overlay):
    _setup(repo_root, config_dir)
    _overlay(config_dir, overlay)
    render_core.render(config_dir, repo_root)


def test_the_halt_hook_is_an_allowed_callback():
    # A pre-call hook that refuses requests while the platform halt is active; it logs nothing.
    assert "papaia_hooks.papaia_platform_halt" in model_gateway.ALLOWED_CALLBACKS


def test_with_local_ai_the_default_model_is_downloaded_and_carries_the_aliases(
    repo_root, config_dir
):
    _install_localai(repo_root)
    _setup(
        repo_root,
        config_dir,
        COMPOSE_PROFILES="litellm,localai",
        PAPAIA_DEFAULT_MODEL=model_gateway.CPU_DEFAULT,
    )
    render_core.render(config_dir, repo_root)

    models_txt = (config_dir / "ai/localai/models.txt").read_text(encoding="utf-8")
    active = [line for line in models_txt.splitlines() if line and not line.startswith("#")]
    assert active == [model_gateway.LOCAL_DEFAULTS[model_gateway.CPU_DEFAULT]]

    params = {
        "model": f"openai/{model_gateway.CPU_DEFAULT}",
        "api_base": "http://localai:8080/v1",
        "api_key": "os.environ/LOCALAI_API_KEY",
    }
    # Every route carries its data class; without a decision of the operator `internal`.
    info = {"papaia_max_class": "internal"}
    assert _entries(config_dir, model_gateway.CPU_DEFAULT) == [
        {"model_name": model_gateway.CPU_DEFAULT, "litellm_params": params, "model_info": info}
    ]
    for alias in ("papaia-chat", "papaia-structured"):
        assert _entries(config_dir, alias) == [
            {"model_name": alias, "litellm_params": params, "model_info": info}
        ]
    assert _entries(config_dir, "papaia-embed") == []


def test_the_embedding_alias_follows_its_own_default(repo_root, config_dir):
    _install_localai(repo_root)
    _setup(
        repo_root,
        config_dir,
        COMPOSE_PROFILES="litellm,localai",
        PAPAIA_DEFAULT_MODEL=model_gateway.CPU_DEFAULT,
        PAPAIA_DEFAULT_EMBED_MODEL="nomic-embed-text",
    )
    overlay = config_dir / "overlay/ai/localai/models.txt"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(
        "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/"
        "nomic-embed-text-v1.5.Q8_0.gguf\n",
        encoding="utf-8",
    )
    render_core.render(config_dir, repo_root)
    (embed,) = _entries(config_dir, "papaia-embed")
    assert embed["litellm_params"]["model"] == "openai/nomic-embed-text"
    assert embed["model_info"] == {"mode": "embedding", "papaia_max_class": "internal"}


def test_an_overlay_model_can_be_the_default(repo_root, config_dir):
    _install_localai(repo_root)
    _setup(repo_root, config_dir, COMPOSE_PROFILES="litellm,localai",
           PAPAIA_DEFAULT_MODEL="reference")
    entry = {
        "model_name": "reference",
        "litellm_params": {"model": "openai/reference", "api_base": "http://localai:8080/v1"},
    }
    _overlay(config_dir, {"model_list": [entry]})
    render_core.render(config_dir, repo_root)
    info = {"papaia_max_class": "internal"}
    for alias in ("papaia-chat", "papaia-structured"):
        assert _entries(config_dir, alias) == [{**entry, "model_name": alias, "model_info": info}]


def test_an_alias_the_overlay_defines_itself_is_kept(repo_root, config_dir):
    _install_localai(repo_root)
    _setup(
        repo_root,
        config_dir,
        COMPOSE_PROFILES="litellm,localai",
        PAPAIA_DEFAULT_MODEL=model_gateway.CPU_DEFAULT,
    )
    own = {
        "model_name": "papaia-chat",
        "litellm_params": {"model": "openai/checker", "api_base": "http://localai:8080/v1"},
    }
    _overlay(config_dir, {"model_list": [own]})
    render_core.render(config_dir, repo_root)
    assert _entries(config_dir, "papaia-chat") == [
        {**own, "model_info": {"papaia_max_class": "internal"}}
    ]
    (structured,) = _entries(config_dir, "papaia-structured")
    assert structured["litellm_params"]["model"] == f"openai/{model_gateway.CPU_DEFAULT}"


def test_an_unknown_default_model_gives_no_alias_and_a_warning(repo_root, config_dir, caplog):
    _setup(repo_root, config_dir, PAPAIA_DEFAULT_MODEL="missing-model")
    with caplog.at_level(logging.WARNING):
        render_core.render(config_dir, repo_root)
    assert _entries(config_dir, "papaia-chat") == []
    assert "missing-model" in caplog.text


def test_every_shipped_default_has_its_model_description():
    for name, url in model_gateway.LOCAL_DEFAULTS.items():
        assert url.startswith("https://huggingface.co/"), name
        described = {
            yaml.safe_load(p.read_text("utf-8"))["name"]: yaml.safe_load(p.read_text("utf-8"))
            for p in (LOCALAI / "models").glob("*.yaml")
        }
        assert name in described, name
        assert described[name]["parameters"]["model"] == url.rsplit("/", 1)[-1]
    assert model_gateway.CPU_DEFAULT.startswith("qwen2.5-7b-instruct")
    assert "Q4_K_M" in model_gateway.LOCAL_DEFAULTS[model_gateway.CPU_DEFAULT]
    assert "Q8_0" in model_gateway.LOCAL_DEFAULTS[model_gateway.GPU_DEFAULT]


def test_the_root_template_documents_the_default_models():
    template = common.parse_env_file(REAL_REPO / "src" / ".env.example")
    assert template["PAPAIA_DEFAULT_MODEL"] == ""
    assert template["PAPAIA_DEFAULT_EMBED_MODEL"] == ""


# ── setup ──────────────────────────────────────────────────────────────────


def _local_ai(tree: dict, **kwargs) -> dict:
    args = resolve.SetupArgs(config_dir=Path("/nonexistent"), non_interactive=True, **kwargs)
    tree = resolve.resolve_local_ai(tree, args)
    tree = resolve.resolve_localai_variant(tree, args)
    return resolve.resolve_default_model(tree, args)


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        (None, model_gateway.CPU_DEFAULT),
        ("cpu", model_gateway.CPU_DEFAULT),
        ("nvidia-cuda-12", model_gateway.GPU_DEFAULT),
        ("hipblas", model_gateway.GPU_DEFAULT),
    ],
)
def test_local_ai_names_the_default_model(variant, expected):
    tree = _local_ai({"": {"COMPOSE_PROFILES": "litellm"}}, enable_local_ai=True,
                     localai_variant=variant)
    assert tree[""]["PAPAIA_DEFAULT_MODEL"] == expected


def test_a_chosen_default_model_stays():
    tree = {"": {"COMPOSE_PROFILES": "litellm", "PAPAIA_DEFAULT_MODEL": "mine"}}
    assert _local_ai(tree, enable_local_ai=True)[""]["PAPAIA_DEFAULT_MODEL"] == "mine"


def test_without_the_flag_nothing_is_named():
    tree = _local_ai({"": {"COMPOSE_PROFILES": "litellm,localai"}})
    assert tree[""].get("PAPAIA_DEFAULT_MODEL", "") == ""


def test_no_local_ai_drops_a_shipped_default_but_keeps_an_own_one():
    shipped = {
        "": {"COMPOSE_PROFILES": "localai", "PAPAIA_DEFAULT_MODEL": model_gateway.CPU_DEFAULT}
    }
    assert _local_ai(shipped, enable_local_ai=False)[""]["PAPAIA_DEFAULT_MODEL"] == ""
    own = {"": {"COMPOSE_PROFILES": "localai", "PAPAIA_DEFAULT_MODEL": "mine"}}
    assert _local_ai(own, enable_local_ai=False)[""]["PAPAIA_DEFAULT_MODEL"] == "mine"


# ── what a module needs ─────────────────────────────────────────────────────


def _need(alias: str, *features: str) -> dict:
    return {"alias": alias, "features": list(features or ("chat",)), "min_context": 8192,
            "max_class": "internal"}


def _manifest(*needs: dict, name: str = "flow") -> dict:
    entry: dict = {"id": f"{name}.api", "kind": "rest"}
    if needs:
        entry["models"] = {"needs": list(needs)}
    return {"name": name, "exposes": [entry, {"id": f"{name}.ui", "kind": "ui"}]}


def test_the_aliases_of_a_module_come_from_its_model_needs():
    manifest = _manifest(_need("papaia-structured", "chat", "json_schema"), _need("papaia-chat"))
    manifest["exposes"][1]["models"] = {"needs": [_need("papaia-chat", "tools")]}
    assert model_gateway.module_aliases(manifest) == ["papaia-chat", "papaia-structured"]


def test_a_module_without_needs_has_no_aliases():
    assert model_gateway.module_aliases(_manifest()) == []
    assert model_gateway.module_aliases({"name": "x"}) == []


@pytest.mark.parametrize(
    "need",
    [
        {"alias": "gpt-4o", "features": ["chat"], "min_context": 8192, "max_class": "internal"},
        {"alias": "papaia-Chat", "features": ["chat"], "min_context": 8192,
         "max_class": "internal"},
        {"alias": "papaia-chat\n", "features": ["chat"], "min_context": 8192,
         "max_class": "internal"},
        {"alias": 7},
        "papaia-chat",
        {**_need("papaia-chat"), "model": "gpt-4o"},
        {**_need("papaia-chat"), "api_base": "http://elsewhere"},
        {**_need("papaia-chat"), "features": "chat"},
        {**_need("papaia-chat"), "features": ["chat", "telepathy"]},
        {**_need("papaia-chat"), "min_context": "8192"},
        {**_need("papaia-chat"), "min_context": True},
        {**_need("papaia-chat"), "min_context": 512},
        {**_need("papaia-chat"), "max_class": 3},
        {**_need("papaia-chat"), "max_class": "Internal\n"},
    ],
)
def test_a_malformed_need_is_refused(need):
    manifest = {"name": "flow", "exposes": [{"id": "a", "models": {"needs": [need]}}]}
    with pytest.raises(model_gateway.ModelGatewayError):
        model_gateway.module_aliases(manifest)


@pytest.mark.parametrize("field", ["model", "api_base"])
def test_an_unknown_field_of_a_need_is_named(field):
    need = {**_need("papaia-chat"), field: "x"}
    manifest = {"name": "flow", "exposes": [{"id": "a", "models": {"needs": [need]}}]}
    with pytest.raises(model_gateway.ModelGatewayError, match=field):
        model_gateway.module_aliases(manifest)


@pytest.mark.parametrize(
    "models",
    [
        {"needs": [], "keys": ["sk-x"]},
        {"needs": [], "provider": "openai"},
        {"need": []},
    ],
)
def test_an_unknown_field_of_the_models_mapping_is_refused(models):
    manifest = {"name": "flow", "exposes": [{"id": "a", "models": models}]}
    with pytest.raises(model_gateway.ModelGatewayError, match="models"):
        model_gateway.module_aliases(manifest)


def test_a_need_with_only_an_alias_is_enough():
    manifest = {"name": "flow", "exposes": [{"id": "a", "models": {"needs": [
        {"alias": "papaia-chat"}]}}]}
    assert model_gateway.module_aliases(manifest) == ["papaia-chat"]


# ── keys ───────────────────────────────────────────────────────────────────


class FakeLiteLLM:
    """The part of LiteLLM's key management API the core uses, in memory."""

    def __init__(self) -> None:
        self.keys: dict[str, dict] = {}  # token -> key row
        self.calls: list[tuple[str, str, object]] = []
        self.counter = 0

    def call(self, method: str, path: str, body: object = None) -> tuple[int, object]:
        self.calls.append((method, path, body))
        if method == "POST" and path == "/key/generate":
            assert isinstance(body, dict)
            if any(k["key_alias"] == body["key_alias"] for k in self.keys.values()):
                return 400, {"error": {"type": "bad_request_error"}}
            self.counter += 1
            key = f"sk-synthetic-{self.counter:04d}"
            token = hashlib.sha256(key.encode()).hexdigest()
            self.keys[token] = {"token": token, **body}
            return 200, {"key": key, "token": token, "key_alias": body["key_alias"]}
        if method == "GET" and path.startswith("/key/list?"):
            alias = path.split("key_alias=", 1)[1].split("&", 1)[0]
            rows = [k for k in self.keys.values() if k["key_alias"] == alias]
            return 200, {"keys": rows, "total_count": len(rows)}
        if method == "POST" and path == "/key/delete":
            assert isinstance(body, dict)
            found = [t for t in body["keys"] if t in self.keys]
            if not found:
                return 404, {"error": {"message": "No keys found"}}
            for token in found:
                del self.keys[token]
            return 200, {"deleted_keys": found}
        raise AssertionError(f"unexpected call {method} {path}")


class DownLiteLLM:
    def call(self, method, path, body=None):
        raise model_gateway.Unavailable("LiteLLM does not run")


class StopsBeforeGenerate(FakeLiteLLM):
    """Answers the listing and the deletion, then stops answering."""

    def call(self, method, path, body=None):
        if method == "POST" and path == "/key/generate":
            raise model_gateway.Unavailable("LiteLLM stopped")
        return super().call(method, path, body)


def _key_config(config_dir: Path, tmp_path: Path, *, journal: bool = True) -> Path:
    """A configuration dir with the add-on bundle of `flow`, and with the lifecycle profile
    and its erasure key when `journal` is set."""
    (config_dir / "addons" / "flow").mkdir(parents=True)
    (config_dir / "addons" / "flow" / ".env").write_text("FLOW_SETTING=1\n", encoding="utf-8")
    backup = tmp_path / "backup"
    backup.mkdir()
    profiles = "litellm,lifecycle" if journal else "litellm"
    (config_dir / ".env").write_text(
        f"COMPOSE_PROFILES={profiles}\nPAPAIA_BACKUP_DIR={backup}\n", encoding="utf-8"
    )
    if journal:
        render_core.ensure_lifecycle_journal(config_dir)
    return backup / "erasure-journal"


def _env(config_dir: Path) -> dict[str, str]:
    return common.parse_env_file(config_dir / "addons" / "flow" / ".env")


def _journal_lines(target: Path) -> list[dict]:
    path = target / "model-gateway.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _audit(config_dir: Path) -> list[dict]:
    path = config_dir / "audit" / "papaia-ctl.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_a_module_gets_its_own_key_for_its_aliases_only(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-structured"], gateway, correlation=CORRELATION
    )
    assert outcome == "created"
    (row,) = gateway.keys.values()
    assert row["key_alias"] == "module-flow"
    assert row["models"] == ["papaia-structured"]
    assert row["metadata"] == {"tags": ["module:flow"], "papaia_need_classes": {}}
    env = _env(config_dir)
    assert env["FLOW_SETTING"] == "1"
    assert hashlib.sha256(env["PAPAIA_MODEL_KEY"].encode()).hexdigest() == row["token"]
    mode = stat.S_IMODE(os.stat(config_dir / "addons" / "flow" / ".env").st_mode)
    assert mode == 0o600
    (audit,) = _audit(config_dir)
    assert audit["format"] == "papaia.audit/1"
    assert audit["event"] == "model_key_created"
    assert audit["correlation_id"] == CORRELATION
    assert audit["detail"] == {"module": "flow", "key_alias": "module-flow",
                               "key_id": row["token"], "models": ["papaia-structured"]}
    assert env["PAPAIA_MODEL_KEY"] not in json.dumps(audit)


def test_a_valid_key_is_kept(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    key = _env(config_dir)["PAPAIA_MODEL_KEY"]
    gateway.calls.clear()
    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway
    )
    assert outcome == "unchanged"
    assert [c[1] for c in gateway.calls] == [
        "/key/list?key_alias=module-flow&return_full_object=true"
    ]
    assert _env(config_dir)["PAPAIA_MODEL_KEY"] == key


def test_new_needs_replace_the_key_and_journal_the_old_one(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    old = _env(config_dir)["PAPAIA_MODEL_KEY"]
    old_token = hashlib.sha256(old.encode()).hexdigest()

    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat", "papaia-structured"], gateway
    )
    assert outcome == "replaced"
    assert old_token not in gateway.keys
    (row,) = gateway.keys.values()
    assert row["models"] == ["papaia-chat", "papaia-structured"]
    assert _env(config_dir)["PAPAIA_MODEL_KEY"] != old
    (entry,) = _journal_lines(target)
    assert entry["module"] == "model-gateway"
    assert entry["kind"] == "key_revoke"
    assert entry["object_ref"] == old_token
    assert entry["reason"] == "key_replaced"
    assert entry["seq"] == 1
    assert old not in (target / "model-gateway.jsonl").read_text(encoding="utf-8")


def test_one_replacement_shares_one_correlation_id(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat", "papaia-structured"], gateway
    )
    rows = _audit(config_dir)[1:]
    assert [r["event"] for r in rows] == ["model_key_revoked", "model_key_created"]
    assert rows[0]["correlation_id"] == rows[1]["correlation_id"]


def test_a_gateway_that_stops_after_the_revocation_leaves_no_dead_key(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    stopping = StopsBeforeGenerate()
    stopping.keys = gateway.keys
    outcome = model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat", "papaia-structured"], stopping
    )
    assert outcome == "unavailable"
    assert stopping.keys == {}
    assert "PAPAIA_MODEL_KEY" not in _env(config_dir), "the deleted key is not handed out"
    assert _env(config_dir)["FLOW_SETTING"] == "1"


def test_a_key_the_gateway_does_not_know_is_replaced(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    common.write_env_file(
        config_dir / "addons" / "flow" / ".env",
        {"FLOW_SETTING": "1", "PAPAIA_MODEL_KEY": "sk-from-an-older-database"},
    )
    gateway = FakeLiteLLM()
    assert (
        model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
        == "created"
    )
    assert _env(config_dir)["PAPAIA_MODEL_KEY"].startswith("sk-synthetic-")


def test_uninstall_revokes_the_key_and_journals_it_first(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    key = _env(config_dir)["PAPAIA_MODEL_KEY"]
    token = hashlib.sha256(key.encode()).hexdigest()

    outcome = model_gateway.revoke_module_key(
        config_dir, REAL_REPO, "flow", gateway, reason="addon_uninstall", correlation=CORRELATION
    )
    assert outcome == "revoked"
    assert gateway.keys == {}
    (entry,) = _journal_lines(target)
    assert (entry["kind"], entry["object_ref"], entry["reason"]) == (
        "key_revoke", token, "addon_uninstall"
    )
    assert "PAPAIA_MODEL_KEY" not in _env(config_dir)
    revoked = [r for r in _audit(config_dir) if r["event"] == "model_key_revoked"]
    assert len(revoked) == 1
    assert revoked[0]["correlation_id"] == CORRELATION
    assert revoked[0]["detail"]["key_id"] == token
    assert revoked[0]["detail"]["journal"] == f"model-gateway:{entry['seq']}"
    assert key not in json.dumps(_audit(config_dir))


def test_a_revocation_while_the_gateway_is_down_waits_for_the_next_sync(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    token = hashlib.sha256(_env(config_dir)["PAPAIA_MODEL_KEY"].encode()).hexdigest()

    outcome = model_gateway.revoke_module_key(
        config_dir, REAL_REPO, "flow", DownLiteLLM(), reason="addon_uninstall"
    )
    assert outcome == "pending"
    assert token in gateway.keys
    assert [e["object_ref"] for e in _journal_lines(target)] == [token]

    assert model_gateway.pending_revocations(config_dir) == [{"key_id": token, "module": "flow"}]

    assert model_gateway.sync(config_dir, REAL_REPO, gateway) == ([], [])
    assert token not in gateway.keys
    assert model_gateway.pending_revocations(config_dir) == []
    assert len(_journal_lines(target)) == 1, "the revocation is journaled once"
    (done,) = [r for r in _audit(config_dir) if r["detail"].get("reason") == "pending_revocation"]
    assert done["detail"] == {"module": "flow", "key_alias": "module-flow", "key_id": token,
                              "reason": "pending_revocation"}


@pytest.mark.parametrize("doc", [{"tokens": ["0" * 64]}, {"tokens": [{"key_id": "0" * 64}]},
                                 {"tokens": [{"key_id": "x", "module": "flow"}]},
                                 {"tokens": [{"key_id": "0" * 64, "module": "flow", "y": 1}]}])
def test_a_malformed_pending_file_is_refused(config_dir, doc):
    path = config_dir / model_gateway.PENDING_FILE
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(model_gateway.ModelGatewayError):
        model_gateway.pending_revocations(config_dir)


def test_without_the_lifecycle_profile_there_is_no_journal_but_the_key_goes(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path, journal=False)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    assert model_gateway.revoke_module_key(
        config_dir, REAL_REPO, "flow", gateway, reason="addon_uninstall"
    ) == "revoked"
    assert gateway.keys == {}
    assert not target.exists()


def test_a_journal_that_cannot_be_written_stops_the_revocation(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    (config_dir / "security" / "erasure-hmac").unlink()
    with pytest.raises(model_gateway.ModelGatewayError):
        model_gateway.revoke_module_key(
            config_dir, REAL_REPO, "flow", gateway, reason="addon_uninstall"
        )
    assert len(gateway.keys) == 1, "no key is deleted without its journal entry"


def test_a_module_that_no_longer_needs_a_model_loses_its_key(config_dir, tmp_path):
    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    assert model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", [], gateway) == "revoked"
    assert gateway.keys == {}
    assert _journal_lines(target)[0]["reason"] == "model_need_removed"
    assert "PAPAIA_MODEL_KEY" not in _env(config_dir)


def test_a_module_without_needs_and_key_costs_no_call(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", [], DownLiteLLM()
    ) == "none"


def test_a_key_cannot_be_made_while_the_gateway_is_down(config_dir, tmp_path):
    _key_config(config_dir, tmp_path)
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], DownLiteLLM()
    ) == "unavailable"
    assert "PAPAIA_MODEL_KEY" not in _env(config_dir)


@pytest.mark.parametrize("name", ["", "Flow", "../x", "a" * 65, "flow\n"])
def test_only_module_names_get_a_key(config_dir, tmp_path, name):
    _key_config(config_dir, tmp_path)
    with pytest.raises(model_gateway.ModelGatewayError):
        model_gateway.ensure_module_key(config_dir, REAL_REPO, name, ["papaia-chat"],
                                        FakeLiteLLM())


# ── the admin connection ──────────────────────────────────────────────────


class Recorder:
    def __init__(self, *results: subprocess.CompletedProcess) -> None:
        self.results = list(results)
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, argv, stdin, timeout):
        self.calls.append((argv, stdin))
        return self.results.pop(0)


def _done(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, stdout, "")


def test_the_admin_calls_run_inside_the_gateway_container(config_dir):
    config_dir.mkdir(parents=True)
    (config_dir / ".env").write_text("COMPOSE_PROJECT_NAME=acme\n", encoding="utf-8")
    runner = Recorder(
        _done("4f1c\n"),
        _done(json.dumps({"status": 200, "body": json.dumps({"keys": []})}) + "\n"),
    )
    admin = model_gateway.connect(config_dir, runner=runner)
    status, body = admin.call("GET", "/key/list?key_alias=module-flow")
    assert (status, body) == (200, {"keys": []})

    lookup, _ = runner.calls[0]
    assert lookup[:2] == ["docker", "ps"]
    assert "label=com.docker.compose.project=acme" in lookup
    assert "label=com.docker.compose.service=litellm" in lookup
    argv, stdin = runner.calls[1]
    assert argv[:4] == ["docker", "exec", "-i", "4f1c"]
    assert argv[4:7] == ["python", "-I", "-c"]
    # The master key is read inside the container; neither argv nor the request carry it.
    assert "LITELLM_MASTER_KEY" in argv[7]
    assert json.loads(stdin) == {"method": "GET", "path": "/key/list?key_alias=module-flow",
                                 "body": None}


def test_no_running_gateway_is_unavailable(config_dir):
    config_dir.mkdir(parents=True)
    (config_dir / ".env").write_text("COMPOSE_PROJECT_NAME=acme\n", encoding="utf-8")
    with pytest.raises(model_gateway.Unavailable):
        model_gateway.connect(config_dir, runner=Recorder(_done("")))


def test_a_path_outside_the_key_management_is_refused(config_dir):
    config_dir.mkdir(parents=True)
    (config_dir / ".env").write_text("COMPOSE_PROJECT_NAME=acme\n", encoding="utf-8")
    admin = model_gateway.connect(config_dir, runner=Recorder(_done("4f1c\n")))
    with pytest.raises(model_gateway.ModelGatewayError):
        admin.call("POST", "/config/update", {})


# ── addon start and uninstall ─────────────────────────────────────────────


def _write_module(tmp_path: Path, needs: list[dict], name: str = "flow") -> Path:
    # The core of the synthetic repo serves the generations of the real one.
    shutil.copy(REAL_REPO / "ADDON_API", tmp_path / "repo" / "ADDON_API")
    addon = tmp_path / f"{name}-addon"
    addon.mkdir()
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            {
                "name": name,
                "version": "0.1.0",
                "requires": {"addon_api": [7]},
                "networks": {"app_network": "papaia-flow-net"},
                # The smallest entry the kit exposes schema accepts, plus the needs.
                "exposes": [
                    {
                        "id": f"{name}.ui",
                        "kind": "ui",
                        "title": {"en": name},
                        "identity": ["person"],
                        "ui": [
                            {
                                "id": name,
                                "title": {"en": name},
                                "summary": {"en": name},
                                "icon": name,
                                "order": 1,
                                "host_key": name,
                                "path": "/",
                                "visible_for_roles": [f"{name}-user"],
                            }
                        ],
                        "models": {"needs": needs},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (addon / ".env.example").write_text("FLOW_SETTING=1\n", encoding="utf-8")
    return addon


def _addon_args(config_dir: Path, repo_root: Path, **extra) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name="flow", force=False,
        no_keycloak=True, **extra,
    )


def test_addon_start_puts_the_module_key_into_the_started_env(
    repo_root, config_dir, tmp_path, monkeypatch
):
    _setup(repo_root, config_dir)
    addon = _write_module(tmp_path, [_need("papaia-chat")])
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "flow", "path": str(addon), "active": True}]
    deployment.save(config_dir, deployed)
    (config_dir / "addons" / "flow").mkdir(parents=True)
    (config_dir / "addons" / "flow" / ".env").write_text(
        "FLOW_SETTING=1\nFLOW_HOST=https://flow.example.org\n", encoding="utf-8"
    )
    gateway = FakeLiteLLM()
    monkeypatch.setattr(model_gateway, "connect", lambda *a, **k: gateway)

    assert cli_addon.cmd_addon_start(_addon_args(config_dir, repo_root)) == 0
    started = common.parse_env_file(addon / ".env")
    assert started["PAPAIA_MODEL_KEY"].startswith("sk-synthetic-")
    assert stat.S_IMODE(os.stat(addon / ".env").st_mode) == 0o600
    (row,) = gateway.keys.values()
    assert row["models"] == ["papaia-chat"]


def test_addon_uninstall_revokes_the_module_key(repo_root, config_dir, tmp_path, monkeypatch):
    _setup(repo_root, config_dir)
    addon = _write_module(tmp_path, [_need("papaia-chat")])
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "flow", "path": str(addon), "active": True}]
    deployment.save(config_dir, deployed)
    (config_dir / "addons" / "flow").mkdir(parents=True)
    (config_dir / "addons" / "flow" / ".env").write_text(
        "FLOW_SETTING=1\nFLOW_HOST=https://flow.example.org\n", encoding="utf-8"
    )
    gateway = FakeLiteLLM()
    monkeypatch.setattr(model_gateway, "connect", lambda *a, **k: gateway)
    assert cli_addon.cmd_addon_start(_addon_args(config_dir, repo_root)) == 0
    assert len(gateway.keys) == 1

    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root), name="flow")
    assert cli_addon.cmd_addon_uninstall(args) == 0
    assert gateway.keys == {}
    assert any(r["event"] == "model_key_revoked" for r in _audit(config_dir))


def test_sync_goes_on_past_a_malformed_module_and_reports_it(
    repo_root, config_dir, tmp_path, monkeypatch, capsys
):
    _setup(repo_root, config_dir)
    _set_root(config_dir, COMPOSE_PROFILES="litellm")
    broken = _write_module(tmp_path, [{**_need("papaia-chat"), "model": "gpt-4o"}], name="aaa")
    good = _write_module(tmp_path, [_need("papaia-chat")], name="flow")
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "aaa", "path": str(broken), "active": True},
                          {"name": "flow", "path": str(good), "active": True}]
    deployment.save(config_dir, deployed)
    for name in ("aaa", "flow"):
        (config_dir / "addons" / name).mkdir(parents=True)
        (config_dir / "addons" / name / ".env").write_text("X=1\n", encoding="utf-8")
    gateway = FakeLiteLLM()

    assert model_gateway.sync(config_dir, repo_root, gateway) == (["flow"], ["aaa"])
    (row,) = gateway.keys.values()
    assert row["key_alias"] == "module-flow"

    gateway.keys.clear()
    (config_dir / "addons" / "flow" / ".env").write_text("X=1\n", encoding="utf-8")
    monkeypatch.setattr(model_gateway, "connect", lambda *a, **k: gateway)
    monkeypatch.setattr(model_gateway, "wait_ready", lambda *a, **k: None)
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root), timeout=1)
    from lib import cli

    assert cli.cmd_model_keys_sync(args) == 1
    out = capsys.readouterr()
    assert "MODEL_KEY_CHANGED=flow" in out.out
    assert "aaa" in out.err and "model" in out.err
    created = [r for r in _audit(config_dir) if r["event"] == "model_key_created"]
    assert len({r["correlation_id"] for r in created[-1:]}) == 1
