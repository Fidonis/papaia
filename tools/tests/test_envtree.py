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


# ── sync_new_env_keys ─────────────────────────────────────────────────────────


def _bundle(config_dir: Path, rel_dir: str = "") -> Path:
    return config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"


def _drop_key(path: Path, key: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if not line.startswith(f"{key}=")]
    assert len(kept) == len(lines) - 1, f"{key} not found in {path}"
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")


def _add_example_lines(repo_root: Path, rel_dir: str, lines: list[str]) -> None:
    example = repo_root / "src" / rel_dir / ".env.example" if rel_dir else (
        repo_root / "src" / ".env.example"
    )
    text = example.read_text(encoding="utf-8")
    example.write_text(text + "\n".join(lines) + "\n", encoding="utf-8")


def test_sync_new_env_keys_appends_only_the_missing_key(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    bundle = _bundle(config_dir, "ai/librechat")
    _drop_key(bundle, "TRUST_PROXY")
    bundle.write_text(
        "# my own note\n" + bundle.read_text(encoding="utf-8").replace(
            "OPENID_CLIENT_ID=librechat", "OPENID_CLIENT_ID=custom"
        ),
        encoding="utf-8",
    )
    before = bundle.read_text(encoding="utf-8")

    added = envtree.sync_new_env_keys(config_dir, repo_root)

    assert added == {"ai/librechat": ["TRUST_PROXY"]}
    after = bundle.read_text(encoding="utf-8")
    assert after.startswith(before), "existing content must stay byte-identical"
    assert "TRUST_PROXY=1" in after[len(before):]
    assert "OPENID_CLIENT_ID=custom" in after
    assert after.count("# --- Added by papaia-ctl during release upgrade ---") == 1


def test_sync_new_env_keys_is_idempotent(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _drop_key(_bundle(config_dir, "ai/librechat"), "TRUST_PROXY")
    envtree.sync_new_env_keys(config_dir, repo_root)
    snapshot = {p: p.read_bytes() for p in config_dir.rglob(".env")}

    assert envtree.sync_new_env_keys(config_dir, repo_root) == {}
    assert {p: p.read_bytes() for p in config_dir.rglob(".env")} == snapshot


def test_sync_new_env_keys_does_nothing_on_a_complete_bundle(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    assert envtree.sync_new_env_keys(config_dir, repo_root) == {}


def test_sync_new_env_keys_carries_the_example_comment_block(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _add_example_lines(
        repo_root,
        "ai/librechat",
        [
            "",
            "# Grants the admin role.",
            "# Independent of the login gate.",
            "NEW_ROLE=admin",
            "OTHER=1",
        ],
    )

    added = envtree.sync_new_env_keys(config_dir, repo_root)

    assert added == {"ai/librechat": ["NEW_ROLE", "OTHER"]}
    text = _bundle(config_dir, "ai/librechat").read_text(encoding="utf-8")
    assert (
        "# Grants the admin role.\n# Independent of the login gate.\nNEW_ROLE=admin\nOTHER=1\n"
        in text
    )


def test_sync_new_env_keys_generates_a_new_secret(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _add_example_lines(repo_root, "ai/librechat", ["NEW_TOKEN=GENERATE_NEW_TOKEN"])

    envtree.sync_new_env_keys(config_dir, repo_root)

    value = re.search(
        r"^NEW_TOKEN=(.*)$", _bundle(config_dir, "ai/librechat").read_text(encoding="utf-8"), re.M
    ).group(1)
    assert value and not value.startswith("GENERATE_")


def test_sync_new_env_keys_gives_a_new_alias_the_canonical_value(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    keycloak = _bundle(config_dir, "infra/keycloak")
    keycloak.write_text(
        keycloak.read_text(encoding="utf-8").replace(
            "KC_LIBRECHAT_CLIENT_SECRET=GENERATE_KC_LIBRECHAT_CLIENT_SECRET",
            "KC_LIBRECHAT_CLIENT_SECRET=shared-secret",
        ),
        encoding="utf-8",
    )
    _drop_key(_bundle(config_dir, "ai/librechat"), "OPENID_CLIENT_SECRET")

    envtree.sync_new_env_keys(config_dir, repo_root)

    assert "OPENID_CLIENT_SECRET=shared-secret" in _bundle(
        config_dir, "ai/librechat"
    ).read_text(encoding="utf-8")


def test_sync_new_env_keys_never_changes_an_existing_key(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _drop_key(_bundle(config_dir, "ai/librechat"), "TRUST_PROXY")
    # Drifted from its canonical value: `setup` would overwrite it, `start` must not.
    librechat = _bundle(config_dir, "ai/librechat")
    librechat.write_text(
        librechat.read_text(encoding="utf-8").replace(
            "OPENID_CLIENT_SECRET=GENERATE_LIBRECHAT_CLIENT_SECRET",
            "OPENID_CLIENT_SECRET=hand-set",
        ),
        encoding="utf-8",
    )

    envtree.sync_new_env_keys(config_dir, repo_root)

    assert "OPENID_CLIENT_SECRET=hand-set" in librechat.read_text(encoding="utf-8")


def test_sync_new_env_keys_leaves_a_rename_target_to_setup(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    root = _bundle(config_dir)
    _drop_key(root, "OIDC_AUTH_URL")
    root.write_text(
        root.read_text(encoding="utf-8") + "OIDC_ISSUER_KC_AUTH=https://old.example/auth\n",
        encoding="utf-8",
    )

    added = envtree.sync_new_env_keys(config_dir, repo_root)

    assert "OIDC_AUTH_URL" not in added.get("", [])
    assert "OIDC_AUTH_URL" not in root.read_text(encoding="utf-8")

    _drop_key(root, "OIDC_ISSUER_KC_AUTH")
    assert envtree.sync_new_env_keys(config_dir, repo_root) == {"": ["OIDC_AUTH_URL"]}


def test_sync_new_env_keys_skips_keycloak_for_an_external_provider(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    root = _bundle(config_dir)
    root.write_text(
        root.read_text(encoding="utf-8").replace(
            "AUTH_PROVIDER=internal_keycloak", "AUTH_PROVIDER=external_oidc"
        ),
        encoding="utf-8",
    )
    _drop_key(_bundle(config_dir, "infra/keycloak"), "KC_HOSTNAME")

    assert envtree.sync_new_env_keys(config_dir, repo_root) == {}

    root.write_text(
        root.read_text(encoding="utf-8").replace("external_oidc", "internal_keycloak"),
        encoding="utf-8",
    )
    assert envtree.sync_new_env_keys(config_dir, repo_root) == {"infra/keycloak": ["KC_HOSTNAME"]}


def test_sync_new_env_keys_ignores_a_service_without_a_bundle(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _bundle(config_dir, "infra/keycloak").unlink()
    _drop_key(_bundle(config_dir, "ai/librechat"), "TRUST_PROXY")

    assert envtree.sync_new_env_keys(config_dir, repo_root) == {"ai/librechat": ["TRUST_PROXY"]}
    assert not _bundle(config_dir, "infra/keycloak").exists()


def test_sync_env_command_reports_what_it_added(repo_root, config_dir, capsys):
    from lib import cli

    envtree.init(config_dir, repo_root, env_name="papaia")
    _drop_key(_bundle(config_dir, "ai/librechat"), "TRUST_PROXY")

    args = types.SimpleNamespace(config_dir=str(config_dir), repo_root=str(repo_root))
    assert cli.cmd_sync_env(args) == 0
    assert (
        "Added 1 new variable(s) to ai/librechat/.env: TRUST_PROXY" in capsys.readouterr().out
    )

    assert cli.cmd_sync_env(args) == 0
    assert capsys.readouterr().out == ""
