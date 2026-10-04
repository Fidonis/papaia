from __future__ import annotations

import json
import shutil
from pathlib import Path

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
