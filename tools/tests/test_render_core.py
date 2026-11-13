from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from lib import common, envtree, render_core, resolve, secrets

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REAL_REPO = Path(__file__).resolve().parents[2]


def _setup_minimal(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    seed = envtree.load_seed_tree(repo_root)
    tree = secrets.generate_missing_secrets(tree, seed)
    args = resolve.SetupArgs(
        config_dir=config_dir, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_reverse_proxy(tree, args)
    envtree.persist_tree(tree, config_dir, repo_root)
    return tree


def test_render_writes_base_layer_files(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)

    assert (config_dir / "ai/librechat/librechat.yaml").is_file()
    assert (config_dir / "ai/litellm/config.yaml").is_file()
    assert (config_dir / "ai/litellm/prometheus.yml").is_file()
    assert (config_dir / "infra/keycloak/keycloak.conf").is_file()
    assert (config_dir / "ai/localai/models.txt").is_file()
    assert (config_dir / "ai/localai/models/stub.yaml").is_file()


def test_render_is_idempotent(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    first = (config_dir / "ai/librechat/librechat.yaml").read_bytes()
    first_realm = (config_dir / "infra/keycloak/realm-import/papaia-realm.json").read_bytes()

    render_core.render(config_dir, repo_root)
    second = (config_dir / "ai/librechat/librechat.yaml").read_bytes()
    second_realm = (config_dir / "infra/keycloak/realm-import/papaia-realm.json").read_bytes()

    assert first == second
    assert first_realm == second_realm


def test_render_overlay_wins_over_base(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    overlay_path = config_dir / "overlay" / "ai/litellm/config.yaml"
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_text(
        yaml.safe_dump({"model_list": [{"model_name": "custom"}]}), encoding="utf-8"
    )

    render_core.render(config_dir, repo_root)

    rendered = yaml.safe_load((config_dir / "ai/litellm/config.yaml").read_text(encoding="utf-8"))
    assert rendered["model_list"] == [{"model_name": "custom"}]


def test_render_merges_active_addon_fragment(repo_root, config_dir):
    addon_dst = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(FIXTURES_DIR / "addon-paperless", addon_dst)

    _setup_minimal(repo_root, config_dir)
    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["addons"] = [
        {
            "name": "paperless",
            "path": "addons/papaia-addon-paperless",
            "version": "1.0.0",
            "active": True,
        }
    ]
    deployment_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    render_core.render(config_dir, repo_root)

    rendered = yaml.safe_load(
        (config_dir / "ai/librechat/librechat.yaml").read_text(encoding="utf-8")
    )
    assert "FirecrawlMCP" in rendered["mcpServers"]
    assert "PaperlessMCP" in rendered["mcpServers"]


def test_render_merges_addon_allowed_domains(repo_root, config_dir):
    """allowedDomains from an addon fragment is appended to the base list, not replaced."""
    addon_dst = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(FIXTURES_DIR / "addon-paperless", addon_dst)

    _setup_minimal(repo_root, config_dir)
    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["addons"] = [
        {
            "name": "paperless",
            "path": "addons/papaia-addon-paperless",
            "version": "1.0.0",
            "active": True,
        }
    ]
    deployment_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    render_core.render(config_dir, repo_root)

    rendered = yaml.safe_load(
        (config_dir / "ai/librechat/librechat.yaml").read_text(encoding="utf-8")
    )
    domains = rendered["mcpSettings"]["allowedDomains"]
    assert "http://mcp-firecrawl:8080" in domains, "base domain must be preserved"
    assert "http://paperless-mcp:8000" in domains, "addon domain must be appended"


def test_render_idempotent_list_merge(repo_root, config_dir):
    """Running render twice with an active addon must not duplicate list entries."""
    addon_dst = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(FIXTURES_DIR / "addon-paperless", addon_dst)

    _setup_minimal(repo_root, config_dir)
    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["addons"] = [
        {
            "name": "paperless",
            "path": "addons/papaia-addon-paperless",
            "version": "1.0.0",
            "active": True,
        }
    ]
    deployment_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    render_core.render(config_dir, repo_root)
    render_core.render(config_dir, repo_root)

    rendered = yaml.safe_load(
        (config_dir / "ai/librechat/librechat.yaml").read_text(encoding="utf-8")
    )
    domains = rendered["mcpSettings"]["allowedDomains"]
    assert domains.count("http://paperless-mcp:8000") == 1, "domain must not be duplicated"


def test_render_lean_core_addons_list_is_empty_noop(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["addons"] == []
    render_core.render(config_dir, repo_root)  # must not raise on an empty addon list


def test_bake_realm_secrets_resolves_all_placeholders(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)

    realm = (config_dir / "infra/keycloak/realm-import/papaia-realm.json").read_text(
        encoding="utf-8"
    )
    assert "${env." not in realm
    parsed = json.loads(realm)
    secret = parsed["clients"][0]["secret"]
    assert secret and not secret.startswith("GENERATE_")


def _install_rag_fragment(repo_root):
    """The real rag module's integration fragments, not a stand-in, so the test
    breaks when the fragment and the render layering drift apart."""
    shutil.copytree(
        REAL_REPO / "src" / "ai" / "rag" / "integration",
        repo_root / "src" / "ai" / "rag" / "integration",
    )


def _set_profiles(config_dir, profiles):
    env_path = config_dir / ".env"
    values = common.parse_env_file(env_path)
    values["COMPOSE_PROFILES"] = profiles
    env_path.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")


def _rendered_librechat(config_dir):
    return yaml.safe_load((config_dir / "ai/librechat/librechat.yaml").read_text(encoding="utf-8"))


def test_render_merges_the_rag_fragment_only_while_the_profile_is_active(repo_root, config_dir):
    _install_rag_fragment(repo_root)
    _setup_minimal(repo_root, config_dir)

    _set_profiles(config_dir, "keycloak,librechat,rag")
    render_core.render(config_dir, repo_root)
    rendered = _rendered_librechat(config_dir)

    assert rendered["mcpServers"]["Qdrant"]["url"] == "http://qdrant-mcp:8000/mcp"
    assert rendered["mcpServers"]["QdrantIngest"]["url"] == "http://qdrant-ingest:8300/mcp"
    assert "FirecrawlMCP" in rendered["mcpServers"], "base servers must be preserved"
    domains = rendered["mcpSettings"]["allowedDomains"]
    assert "http://mcp-firecrawl:8080" in domains
    assert "http://qdrant-mcp:8000" in domains
    assert "http://qdrant-ingest:8300" in domains


def test_render_drops_the_rag_servers_again_when_the_profile_is_removed(repo_root, config_dir):
    _install_rag_fragment(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "librechat,rag")
    render_core.render(config_dir, repo_root)
    assert "Qdrant" in _rendered_librechat(config_dir)["mcpServers"]

    _set_profiles(config_dir, "librechat")
    render_core.render(config_dir, repo_root)

    rendered = _rendered_librechat(config_dir)
    assert set(rendered["mcpServers"]) == {"FirecrawlMCP"}
    assert rendered["mcpSettings"]["allowedDomains"] == ["http://mcp-firecrawl:8080"]


def test_render_rag_fragment_is_idempotent_and_loses_to_the_overlay(repo_root, config_dir):
    _install_rag_fragment(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "librechat,rag")
    overlay = config_dir / "overlay" / "ai/librechat/librechat.yaml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(
        yaml.safe_dump({"mcpServers": {"Qdrant": {"title": "Company search"}}}), encoding="utf-8"
    )

    render_core.render(config_dir, repo_root)
    first = (config_dir / "ai/librechat/librechat.yaml").read_bytes()
    render_core.render(config_dir, repo_root)

    assert (config_dir / "ai/librechat/librechat.yaml").read_bytes() == first
    rendered = _rendered_librechat(config_dir)
    assert rendered["mcpServers"]["Qdrant"]["title"] == "Company search"
    assert rendered["mcpServers"]["Qdrant"]["url"] == "http://qdrant-mcp:8000/mcp"
    assert rendered["mcpSettings"]["allowedDomains"].count("http://qdrant-mcp:8000") == 1


# ── the mail relay's block in the realm (profile smtp) ────────────────────────


def _realm_file(config_dir) -> Path:
    return config_dir / "infra/keycloak/realm-import/papaia-realm.json"


def _enable_smtp(config_dir, *, host="smtp.example.org", sender="noreply@example.org"):
    values = common.parse_env_file(config_dir / ".env")
    values["COMPOSE_PROFILES"] = "keycloak,smtp"
    common.atomic_write(
        config_dir / ".env", "".join(f"{key}={value}\n" for key, value in values.items())
    )
    module = config_dir / "infra" / "smtp-relay"
    module.mkdir(parents=True, exist_ok=True)
    common.atomic_write(
        module / ".env",
        f"SMTP_RELAY_UPSTREAM_HOST={host}\nSMTP_RELAY_FROM_ADDRESS={sender}\n"
        "SMTP_RELAY_FROM_NAME=Café Mail\n",
    )


def test_render_leaves_the_realm_without_a_mail_server_while_the_relay_is_off(
    repo_root, config_dir
):
    _setup_minimal(repo_root, config_dir)

    render_core.render(config_dir, repo_root)

    realm = json.loads(_realm_file(config_dir).read_text(encoding="utf-8"))
    assert "smtpServer" not in realm
    assert "resetPasswordAllowed" not in realm


def test_render_adds_the_relay_block_and_the_reset_link_while_the_relay_is_on(
    repo_root, config_dir
):
    _setup_minimal(repo_root, config_dir)
    _enable_smtp(config_dir)

    render_core.render(config_dir, repo_root)

    text = _realm_file(config_dir).read_text(encoding="utf-8")
    realm = json.loads(text)
    assert realm["smtpServer"]["host"] == "smtp-relay"
    assert realm["smtpServer"]["fromDisplayName"] == "Café Mail"
    assert "Café" in text, "non-ASCII is written as it is, not escaped"
    assert realm["resetPasswordAllowed"] is True
    assert "verifyEmail" not in realm or realm["verifyEmail"] is False
    assert "password" not in realm["smtpServer"]
    assert "baked-secret" not in text and "${env." not in text


def test_render_adds_nothing_while_the_relay_is_on_but_not_configured(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    _enable_smtp(config_dir, host="", sender="")

    render_core.render(config_dir, repo_root)

    assert "smtpServer" not in json.loads(_realm_file(config_dir).read_text(encoding="utf-8"))


def test_render_of_the_relay_block_is_idempotent(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    _enable_smtp(config_dir)

    render_core.render(config_dir, repo_root)
    first = _realm_file(config_dir).read_bytes()
    render_core.render(config_dir, repo_root)

    assert _realm_file(config_dir).read_bytes() == first


def test_render_switching_the_relay_off_restores_the_plain_realm(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    plain = _realm_file(config_dir).read_bytes()
    _enable_smtp(config_dir)
    render_core.render(config_dir, repo_root)
    assert _realm_file(config_dir).read_bytes() != plain

    values = common.parse_env_file(config_dir / ".env")
    values["COMPOSE_PROFILES"] = "keycloak"
    common.atomic_write(
        config_dir / ".env", "".join(f"{key}={value}\n" for key, value in values.items())
    )
    render_core.render(config_dir, repo_root)

    assert _realm_file(config_dir).read_bytes() == plain


def test_render_ships_the_login_theme_and_the_overlay_replaces_a_file(repo_root, config_dir):
    shutil.copytree(
        REAL_REPO / "src/infra/keycloak/themes", repo_root / "src/infra/keycloak/themes"
    )
    _setup_minimal(repo_root, config_dir)
    overlay = config_dir / "overlay" / "infra/keycloak/themes/papaia/login/resources/css/papaia.css"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text("/* customer */", encoding="utf-8")

    render_core.render(config_dir, repo_root)

    theme = config_dir / "infra/keycloak/themes/papaia/login"
    assert "parent=keycloak.v2" in (theme / "theme.properties").read_text(encoding="utf-8")
    assert (theme / "resources/img/papaia-logo.svg").is_file()
    assert (theme / "resources/css/papaia.css").read_text(encoding="utf-8") == "/* customer */"


def test_the_realm_template_themes_the_login_clients_but_not_the_realm():
    template = json.loads(
        (REAL_REPO / "src/infra/keycloak/realm-import/papaia-realm.json.template").read_text(
            encoding="utf-8"
        )
    )
    assert "loginTheme" not in template, "a realm theme would brand the direct login as well"
    for client in template["clients"]:
        theme = (client.get("attributes") or {}).get("login_theme")
        if client.get("standardFlowEnabled"):
            assert theme == "papaia", client["clientId"]
        else:
            assert theme is None, client["clientId"]


# -- LocalAI: the generated model_list in LiteLLM ---------------------------------------------

_LOCALAI_MODELS = (
    "# a comment\n"
    "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/"
    "qwen2.5-1.5b-instruct-q4_k_m.gguf\n"
    "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/"
    "nomic-embed-text-v1.5.Q8_0.gguf\n"
)


def _install_localai(repo_root, models: str = _LOCALAI_MODELS) -> None:
    """The real model YAMLs next to the fixture's stub, and `models` as the shipped list."""
    target = repo_root / "src" / "ai" / "localai"
    for path in (REAL_REPO / "src" / "ai" / "localai" / "models").glob("*.yaml"):
        shutil.copy(path, target / "models" / path.name)
    (target / "models.txt").write_text(models, encoding="utf-8")


def _rendered_litellm(config_dir):
    return yaml.safe_load((config_dir / "ai/litellm/config.yaml").read_text(encoding="utf-8"))


def _model_names(config_dir) -> list[str]:
    return [e["model_name"] for e in _rendered_litellm(config_dir).get("model_list") or []]


def _localai_overlay(config_dir, rel: str, text: str) -> None:
    path = config_dir / "overlay" / "ai" / "localai" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_localai_models_are_registered_while_the_profile_is_active(repo_root, config_dir):
    _install_localai(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    render_core.render(config_dir, repo_root)

    assert _rendered_litellm(config_dir)["model_list"] == [
        {
            "model_name": "nomic-embed-text",
            "litellm_params": {
                "model": "openai/nomic-embed-text",
                "api_base": "http://localai:8080/v1",
                "api_key": "os.environ/LOCALAI_API_KEY",
            },
            "model_info": {"mode": "embedding"},
        },
        {
            "model_name": "qwen2.5-1.5b-instruct",
            "litellm_params": {
                "model": "openai/qwen2.5-1.5b-instruct",
                "api_base": "http://localai:8080/v1",
                "api_key": "os.environ/LOCALAI_API_KEY",
            },
        },
    ]


def test_with_the_localai_profile_off_litellm_renders_as_the_base(repo_root, config_dir):
    _install_localai(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm")
    render_core.render(config_dir, repo_root)
    base = (repo_root / "src/ai/litellm/config.yaml").read_text(encoding="utf-8")
    rendered = (config_dir / "ai/litellm/config.yaml").read_text(encoding="utf-8")
    assert yaml.safe_load(rendered) == yaml.safe_load(base)


def test_only_models_whose_file_is_downloaded_are_registered(repo_root, config_dir):
    _install_localai(repo_root, "# https://example.org/qwen2.5-1.5b-instruct-q4_k_m.gguf\n")
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    render_core.render(config_dir, repo_root)
    assert _model_names(config_dir) == []


def test_the_models_overlay_drives_the_list_and_a_removed_line_is_gone(repo_root, config_dir):
    _install_localai(repo_root, "")
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    _localai_overlay(config_dir, "models.txt", _LOCALAI_MODELS)
    render_core.render(config_dir, repo_root)
    assert _model_names(config_dir) == ["nomic-embed-text", "qwen2.5-1.5b-instruct"]

    _localai_overlay(config_dir, "models.txt", _LOCALAI_MODELS.splitlines(True)[-1])
    render_core.render(config_dir, repo_root)
    assert _model_names(config_dir) == ["nomic-embed-text"]


def test_an_overlay_entry_with_the_same_name_replaces_the_generated_one(repo_root, config_dir):
    _install_localai(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    overlay = config_dir / "overlay" / "ai" / "litellm" / "config.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(
        "model_list:\n"
        "  - model_name: qwen2.5-1.5b-instruct\n"
        "    litellm_params:\n"
        "      model: openai/gpt-4o-mini\n"
        "      api_key: os.environ/OPENAI_API_KEY\n"
    )
    render_core.render(config_dir, repo_root)

    entries = _rendered_litellm(config_dir)["model_list"]
    assert [e["model_name"] for e in entries] == ["nomic-embed-text", "qwen2.5-1.5b-instruct"]
    assert entries[1]["litellm_params"]["model"] == "openai/gpt-4o-mini"


def test_an_overlay_only_model_yaml_is_rendered_and_registered(repo_root, config_dir):
    _install_localai(repo_root, "")
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    own = "name: my-model\nbackend: llama-cpp\nparameters:\n  model: my-model.gguf\n"
    _localai_overlay(config_dir, "models/my-model.yaml", own)
    _localai_overlay(config_dir, "models.txt", "https://example.org/files/my-model.gguf\n")
    render_core.render(config_dir, repo_root)

    assert (config_dir / "ai/localai/models/my-model.yaml").read_text(encoding="utf-8") == own
    assert (config_dir / "ai/localai/models/stub.yaml").is_file()
    assert _model_names(config_dir) == ["my-model"]


def test_an_overlay_only_model_yaml_that_does_not_parse_is_named(repo_root, config_dir):
    _install_localai(repo_root, "")
    _setup_minimal(repo_root, config_dir)
    _localai_overlay(config_dir, "models/broken.yaml", "name: [unclosed\n")
    with pytest.raises(render_core.RenderError, match="overlay/ai/localai/models/broken.yaml"):
        render_core.render(config_dir, repo_root)


def test_the_localai_key_is_named_but_never_written(repo_root, config_dir):
    _install_localai(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    key = "localai-key-must-not-be-rendered"
    for rel in ("ai/localai", "ai/litellm"):
        env = config_dir / rel / ".env"
        env.parent.mkdir(parents=True, exist_ok=True)
        with env.open("a", encoding="utf-8") as handle:
            handle.write(f"LOCALAI_API_KEY={key}\n")
    render_core.render(config_dir, repo_root)

    rendered = (config_dir / "ai/litellm/config.yaml").read_text(encoding="utf-8")
    assert "os.environ/LOCALAI_API_KEY" in rendered
    assert key not in rendered
    result = render_core.preview(config_dir, repo_root, "ai/litellm/config.yaml", "")
    assert key not in result["current"] + result["preview"]


def test_the_preview_of_litellm_shows_the_generated_models_before_any_render(
    repo_root, config_dir
):
    _install_localai(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "litellm,localai")
    assert not (config_dir / "ai/litellm/config.yaml").exists()

    draft = (
        "model_list:\n  - model_name: nomic-embed-text\n    litellm_params:\n"
        "      model: openai/x\n"
    )
    result = render_core.preview(config_dir, repo_root, "ai/litellm/config.yaml", draft)
    assert "openai/qwen2.5-1.5b-instruct" in result["current"]
    preview = yaml.safe_load(result["preview"])
    assert [e["model_name"] for e in preview["model_list"]] == [
        "qwen2.5-1.5b-instruct",
        "nomic-embed-text",
    ]
    assert preview["model_list"][1]["litellm_params"]["model"] == "openai/x"


def test_every_shipped_model_yaml_matches_a_line_of_the_shipped_list():
    """Each YAML is named after its `name` (LocalAI loads it under that file name on the first
    request) and points at a file the list downloads once its line is active."""
    localai = REAL_REPO / "src" / "ai" / "localai"
    files = {
        line.lstrip("# ").strip().rsplit("/", 1)[-1]
        for line in (localai / "models.txt").read_text(encoding="utf-8").splitlines()
        if line.lstrip("# ").startswith("https://")
    }
    yamls = sorted((localai / "models").glob("*.yaml"))
    assert len(yamls) == len(files) == 5
    for path in yamls:
        model = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert path.name == f"{model['name']}.yaml"
        assert model["parameters"]["model"] in files, path.name


# ── LibreChat agents and prompts of add-ons ───────────────────────────────────


def _librechat_addon(repo_root: Path, config_dir: Path, *, active: bool = True) -> Path:
    """The paperless fixture (which adds the PaperlessMCP server) plus one agent and
    one prompt, registered in deployment.yaml."""
    addon = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(FIXTURES_DIR / "addon-paperless", addon)
    content = addon / "integration" / "ai" / "librechat"
    (content / "agents").mkdir(parents=True)
    (content / "agents" / "assistant.yaml").write_text(
        "id: agent_docs\nname: Docs\nprovider: Private-LLM\nmodel: m\n"
        "mcpServers: [PaperlessMCP]\n",
        encoding="utf-8",
    )
    (content / "prompts").mkdir()
    (content / "prompts" / "summary.md").write_text(
        "---\nname: Summary\ncategory: Docs\ncommand: summary\noneliner: Sum up\n---\nSum up.\n",
        encoding="utf-8",
    )
    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["addons"] = [
        {"name": "paperless", "path": "addons/papaia-addon-paperless", "active": active}
    ]
    deployment_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return addon


def _override(config_dir: Path) -> dict | None:
    path = config_dir / render_core.LIBRECHAT_ADDON_OVERRIDE
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None


def test_render_mounts_addon_agents_and_prompts(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    _librechat_addon(repo_root, config_dir)

    render_core.render(config_dir, repo_root)

    agents = config_dir / "ai/librechat/addon-agents"
    prompts = config_dir / "ai/librechat/addon-prompts"
    assert [p.name for p in agents.iterdir()] == ["paperless__assistant.yaml"]
    assert [p.name for p in prompts.iterdir()] == ["paperless__summary.md"]
    librechat = _override(config_dir)["services"]["librechat"]
    assert {v["target"]: v["source"] for v in librechat["volumes"]} == {
        "/app/api/data/addon-agents": str(agents),
        "/app/api/data/addon-prompts": str(prompts),
    }
    assert all(v["read_only"] for v in librechat["volumes"])
    assert len(librechat["labels"]["org.papaia.addon-content"]) == 16


def test_changed_content_changes_the_label(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    addon = _librechat_addon(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    before = _override(config_dir)["services"]["librechat"]["labels"]
    render_core.render(config_dir, repo_root)
    assert _override(config_dir)["services"]["librechat"]["labels"] == before

    prompt = addon / "integration/ai/librechat/prompts/summary.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "More.\n", encoding="utf-8")
    render_core.render(config_dir, repo_root)
    assert _override(config_dir)["services"]["librechat"]["labels"] != before


def test_an_inactive_addon_removes_content_and_override(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    _librechat_addon(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    assert _override(config_dir) is not None

    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["addons"][0]["active"] = False
    deployment_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    render_core.render(config_dir, repo_root)

    assert _override(config_dir) is None
    assert not (config_dir / "ai/librechat/addon-agents").exists()


def test_an_agent_with_an_unknown_mcp_server_is_skipped(repo_root, config_dir, capsys):
    _setup_minimal(repo_root, config_dir)
    addon = _librechat_addon(repo_root, config_dir)
    agent = addon / "integration/ai/librechat/agents/assistant.yaml"
    agent.write_text(agent.read_text(encoding="utf-8").replace("PaperlessMCP", "NoSuchMCP"))

    render_core.render(config_dir, repo_root)

    assert not (config_dir / "ai/librechat/addon-agents").exists()
    assert "NoSuchMCP" in capsys.readouterr().err
    # The prompt still renders, so the override stays.
    volumes = _override(config_dir)["services"]["librechat"]["volumes"]
    assert [v["target"] for v in volumes] == ["/app/api/data/addon-prompts"]


@pytest.mark.parametrize(
    "servers",
    ["mcpServers: PaperlessMCP", "mcpServers: [{name: PaperlessMCP}]", "mcpServers: [1]"],
)
def test_an_agent_whose_mcp_servers_are_not_names_is_skipped(
    repo_root, config_dir, capsys, servers
):
    _setup_minimal(repo_root, config_dir)
    addon = _librechat_addon(repo_root, config_dir)
    agent = addon / "integration/ai/librechat/agents/assistant.yaml"
    agent.write_text(
        agent.read_text(encoding="utf-8").replace("mcpServers: [PaperlessMCP]", servers)
    )

    render_core.render(config_dir, repo_root)

    assert not (config_dir / "ai/librechat/addon-agents").exists()
    assert "not a list of server names" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["agents/assistant.yaml", "prompts/summary.md"])
def test_a_file_that_is_not_utf8_is_skipped(repo_root, config_dir, capsys, kind):
    _setup_minimal(repo_root, config_dir)
    addon = _librechat_addon(repo_root, config_dir)
    (addon / "integration/ai/librechat" / kind).write_bytes(b"name: \xff\xfe\n")

    render_core.render(config_dir, repo_root)

    assert "cannot be read" in capsys.readouterr().err
    rendered = list((config_dir / "ai/librechat").glob("addon-*/*"))
    assert len(rendered) == 1
    assert Path(kind).name not in rendered[0].name


def test_no_addon_content_writes_no_override(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    assert _override(config_dir) is None
