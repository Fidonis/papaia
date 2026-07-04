from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from lib import bootstrap, render_core

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _setup_minimal(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    tree = bootstrap.load_config_dir_tree(config_dir, repo_root)
    seed = bootstrap.load_seed_tree(repo_root)
    tree = bootstrap.generate_missing_secrets(tree, seed)
    args = bootstrap.SetupArgs(
        config_dir=config_dir, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = bootstrap.resolve_hostnames(tree, args)
    tree = bootstrap.resolve_multi_env(tree, args)
    tree = bootstrap.resolve_reverse_proxy(tree, args)
    bootstrap.persist_tree(tree, config_dir, repo_root)
    return tree


def test_render_writes_base_layer_files(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)

    assert (config_dir / "ai/librechat/librechat.yaml").is_file()
    assert (config_dir / "ai/litellm/config.yaml").is_file()
    assert (config_dir / "ai/litellm/prometheus.yml").is_file()
    assert (config_dir / "infra/keycloak/keycloak.conf").is_file()
    assert (config_dir / "services/homepage/config/services.yaml").is_file()
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


def test_render_merges_active_extension_fragment(repo_root, config_dir):
    ext_dst = repo_root / "extensions" / "papaia-ext-paperless"
    shutil.copytree(FIXTURES_DIR / "ext-paperless", ext_dst)

    _setup_minimal(repo_root, config_dir)
    deployment_path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    manifest["extensions"] = [
        {
            "name": "paperless",
            "path": "extensions/papaia-ext-paperless",
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


def test_render_lean_core_extensions_list_is_empty_noop(repo_root, config_dir):
    _setup_minimal(repo_root, config_dir)
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["extensions"] == []
    render_core.render(config_dir, repo_root)  # must not raise on an empty extension list


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
