from __future__ import annotations

import re
import types
from pathlib import Path

import pytest

from lib import envtree, semver


def test_resolve_platform_version_prefers_version_file(repo_root):
    # The fixture ships VERSION=0.8.0 next to a CHANGELOG whose first
    # released header is 0.7.0 -- the VERSION file must win.
    assert envtree.resolve_platform_version(repo_root) == "0.8.0"


def test_resolve_platform_version_falls_back_to_changelog(repo_root):
    (repo_root / "VERSION").unlink()
    assert envtree.resolve_platform_version(repo_root) == "0.7.0"


def test_resolve_platform_version_ignores_malformed_version_file(repo_root):
    (repo_root / "VERSION").write_text("not-a-version\n", encoding="utf-8")
    assert envtree.resolve_platform_version(repo_root) == "0.7.0"


def test_resolve_platform_version_falls_back_without_changelog(tmp_path):
    assert envtree.resolve_platform_version(tmp_path) == "0.0.0-dev"


def test_version_file_not_behind_changelog():
    # Consistency guard for the real checkout: the manually-bumped VERSION
    # file must never fall behind the newest released CHANGELOG header.
    repo = Path(__file__).resolve().parents[2]
    version_text = (repo / "VERSION").read_text(encoding="utf-8").strip()
    match = re.search(
        r"^## \[(\d+\.\d+\.\d+)\]",
        (repo / "CHANGELOG.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        pytest.skip("CHANGELOG.md has no released section yet")
    assert semver.compare(version_text, match.group(1)) >= 0


def test_stamp_platform_version_populates_papaia_version(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_VERSION"] == ""
    envtree.stamp_platform_version(tree, repo_root)
    assert tree[""]["PAPAIA_VERSION"] == "0.8.0"


def test_stamp_config_dir_populates_papaia_config_dir(repo_root, config_dir):
    tree = envtree.load_seed_tree(repo_root)
    assert tree[""]["PAPAIA_CONFIG_DIR"] != str(config_dir)
    envtree.stamp_config_dir(tree, config_dir)
    assert tree[""]["PAPAIA_CONFIG_DIR"] == str(config_dir)


def test_stamp_workspace_dir_derives_parent_of_papaia_checkout(tmp_path):
    checkout = tmp_path / "workspace" / "papaia"
    checkout.mkdir(parents=True)
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/srv/papaia/workspace"}}
    envtree.stamp_workspace_dir(tree, checkout)
    assert tree[""]["PAPAIA_WORKSPACE_DIR"] == str(tmp_path / "workspace")


def test_stamp_workspace_dir_derives_when_value_empty(tmp_path):
    checkout = tmp_path / "workspace" / "papaia"
    checkout.mkdir(parents=True)
    tree: dict = {"": {}}
    envtree.stamp_workspace_dir(tree, checkout)
    assert tree[""]["PAPAIA_WORKSPACE_DIR"] == str(tmp_path / "workspace")


def test_stamp_workspace_dir_keeps_operator_customised_value(tmp_path):
    checkout = tmp_path / "workspace" / "papaia"
    checkout.mkdir(parents=True)
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/opt/custom/workspace"}}
    envtree.stamp_workspace_dir(tree, checkout)
    assert tree[""]["PAPAIA_WORKSPACE_DIR"] == "/opt/custom/workspace"


def test_stamp_workspace_dir_skips_when_checkout_not_named_papaia(tmp_path):
    checkout = tmp_path / "workspace" / "papaia-fork"
    checkout.mkdir(parents=True)
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/srv/papaia/workspace"}}
    envtree.stamp_workspace_dir(tree, checkout)
    # Left as the placeholder -- no correct parent-derivation is possible.
    assert tree[""]["PAPAIA_WORKSPACE_DIR"] == "/srv/papaia/workspace"


def test_stamp_docker_gid_detects_socket_gid_over_placeholder(monkeypatch):
    tree = {"": {"DOCKER_GID": "999"}}
    monkeypatch.setattr(envtree.os, "stat", lambda p: types.SimpleNamespace(st_gid=1001))
    envtree.stamp_docker_gid(tree)
    assert tree[""]["DOCKER_GID"] == "1001"


def test_stamp_docker_gid_detects_when_value_empty(monkeypatch):
    tree: dict = {"": {}}
    monkeypatch.setattr(envtree.os, "stat", lambda p: types.SimpleNamespace(st_gid=1001))
    envtree.stamp_docker_gid(tree)
    assert tree[""]["DOCKER_GID"] == "1001"


def test_stamp_docker_gid_keeps_operator_customised_value(monkeypatch):
    tree = {"": {"DOCKER_GID": "1234"}}
    # A real, non-placeholder value stays sticky even when a socket is present.
    monkeypatch.setattr(envtree.os, "stat", lambda p: types.SimpleNamespace(st_gid=1001))
    envtree.stamp_docker_gid(tree)
    assert tree[""]["DOCKER_GID"] == "1234"


def test_stamp_docker_gid_keeps_value_when_socket_absent(monkeypatch):
    tree = {"": {"DOCKER_GID": "999"}}

    def _raise(_path):
        raise OSError("no socket")

    monkeypatch.setattr(envtree.os, "stat", _raise)
    envtree.stamp_docker_gid(tree)
    # No local socket to probe -- the existing value is left untouched.
    assert tree[""]["DOCKER_GID"] == "999"


def test_init_seeds_config_dir_without_touching_repo_tree(repo_root, config_dir):
    src_files_before = sorted(
        p.relative_to(repo_root) for p in (repo_root / "src").rglob("*") if p.is_file()
    )

    envtree.init(config_dir, repo_root, env_name="papaia")

    assert (config_dir / ".env").is_file()
    assert (config_dir / "deployment.yaml").is_file()
    assert (config_dir / "overlay").is_dir()
    assert (config_dir / "overrides").is_dir()
    assert (config_dir / "infra" / "keycloak" / ".env").is_file()

    src_files_after = sorted(
        p.relative_to(repo_root) for p in (repo_root / "src").rglob("*") if p.is_file()
    )
    assert src_files_before == src_files_after


def test_init_is_idempotent_without_force(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    (config_dir / ".env").write_text("CUSTOM=1\n", encoding="utf-8")
    envtree.init(config_dir, repo_root, env_name="papaia")
    assert (config_dir / ".env").read_text(encoding="utf-8") == "CUSTOM=1\n"


def test_init_force_reseeds(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    (config_dir / ".env").write_text("CUSTOM=1\n", encoding="utf-8")
    envtree.init(config_dir, repo_root, env_name="papaia", force=True)
    assert "CUSTOM=1" not in (config_dir / ".env").read_text(encoding="utf-8")



def test_persist_tree_writes_both_locations(repo_root, config_dir):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"

    envtree.persist_tree(tree, config_dir, repo_root)

    assert (config_dir / ".env").is_file()
    assert (repo_root / "src" / ".env").is_file()
    assert "PAPAIA_HOST=https://papaia.example.com" in (repo_root / "src" / ".env").read_text(
        encoding="utf-8"
    )
    assert "PAPAIA_HOST=https://papaia.example.com" in (config_dir / ".env").read_text(
        encoding="utf-8"
    )


# ── materialize_core_env ──────────────────────────────────────────────────────


def test_materialize_core_env_copies_bundle_to_checkout(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    # Write a distinctive value into the config bundle
    bundle_env = config_dir / ".env"
    bundle_env.write_text("PAPAIA_HOST=https://restored.example.com\n", encoding="utf-8")

    # Remove the checkout copy to simulate a git-clean scenario
    checkout_env = repo_root / "src" / ".env"
    checkout_env.unlink(missing_ok=True)
    assert not checkout_env.is_file()

    envtree.materialize_core_env(config_dir, repo_root)

    assert checkout_env.is_file()
    assert "PAPAIA_HOST=https://restored.example.com" in checkout_env.read_text(encoding="utf-8")


def test_materialize_core_env_matches_bundle_content(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    # Overwrite checkout with stale content
    checkout_env = repo_root / "src" / ".env"
    checkout_env.write_text("PAPAIA_HOST=stale\n", encoding="utf-8")
    bundle_env = config_dir / ".env"
    bundle_env.write_text("PAPAIA_HOST=fresh\n", encoding="utf-8")

    envtree.materialize_core_env(config_dir, repo_root)

    assert checkout_env.read_text(encoding="utf-8") == "PAPAIA_HOST=fresh\n"


def test_materialize_core_env_skips_missing_bundle_files(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    # Remove a bundle .env for a sub-directory — materialize must not crash
    keycloak_bundle = config_dir / "infra" / "keycloak" / ".env"
    keycloak_bundle.unlink(missing_ok=True)

    envtree.materialize_core_env(config_dir, repo_root)

    # Root .env should still be restored from its bundle copy
    assert (repo_root / "src" / ".env").is_file()
