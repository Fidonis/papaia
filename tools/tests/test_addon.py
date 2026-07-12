from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest
import yaml

from lib import bootstrap, common, gen_override
from lib.cli import cmd_addon_install, cmd_addon_networks, cmd_addon_remove, cmd_addon_uninstall, cmd_addon_start, cmd_addon_path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ADDON_PAPERLESS = FIXTURES_DIR / "addon-paperless"


def _install_args(config_dir: Path, repo_root: Path, *, path: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
        path=path or str(ADDON_PAPERLESS),
        version=None,
    )


def _name_args(config_dir: Path, repo_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
    )


def _setup(repo_root: Path, config_dir: Path) -> None:
    bootstrap.init(config_dir, repo_root, env_name="papaia")


# ── install ───────────────────────────────────────────────────────────────────


def test_install_creates_deployment_entry(repo_root, config_dir):
    _setup(repo_root, config_dir)
    result = cmd_addon_install(_install_args(config_dir, repo_root))
    assert result == 0

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    addons = deployment.get("addons", [])
    assert len(addons) == 1
    entry = addons[0]
    assert entry["name"] == "paperless"
    assert entry["active"] is True
    assert Path(entry["path"]).is_absolute()


def test_install_seeds_env_into_config_bundle(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    # .env must be in the config bundle, not in the addon checkout
    bundle_env = config_dir / "addons" / "paperless" / ".env"
    assert bundle_env.is_file(), "config bundle .env must be created by install"
    checkout_env = ADDON_PAPERLESS / ".env"
    assert not checkout_env.exists(), "addon checkout must stay git-pristine after install"

    parsed = common.parse_env_file(bundle_env)
    # GENERATE_* keys must receive a real secret
    assert "PAPERLESS_DBPASS" in parsed
    assert not common.marks_generated_secret(parsed["PAPERLESS_DBPASS"])
    assert parsed["PAPERLESS_DBPASS"] != ""
    # KC secrets use REPLACE_WITH_* (imported from Keycloak, not generated)
    assert parsed["KC_PAPERLESS_CLIENT_SECRET"] == "REPLACE_WITH_KC_PAPERLESS_CLIENT_SECRET"
    # Literal defaults are copied verbatim
    assert parsed["PAPERLESS_EXT_PORT"] == "8010"
    assert parsed["PAPERLESS_DBUSER"] == "paperless"
    # CHANGE_ME keys stay as-is
    assert parsed["PAPERLESS_PUBLIC_URL"] == "CHANGE_ME"
    # Section banner is present
    env_content = bundle_env.read_text(encoding="utf-8")
    assert "Addon: paperless" in env_content


def test_install_is_idempotent(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    secret_after_first = common.parse_env_file(bundle_env)["PAPERLESS_DBPASS"]

    cmd_addon_install(_install_args(config_dir, repo_root))
    secret_after_second = common.parse_env_file(bundle_env)["PAPERLESS_DBPASS"]

    assert secret_after_first == secret_after_second


def test_install_reactivates_inactive_entry(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    cmd_addon_remove(_name_args(config_dir, repo_root))

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["addons"][0]["active"] is False

    cmd_addon_install(_install_args(config_dir, repo_root))
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["addons"][0]["active"] is True
    assert len(deployment["addons"]) == 1


def test_install_requires_path_for_new_addon(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
        path=None,
        version=None,
    )
    result = cmd_addon_install(args)
    assert result == 2


# ── start ─────────────────────────────────────────────────────────────────────


def test_start_materializes_env_into_checkout(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    checkout_env = ADDON_PAPERLESS / ".env"
    assert not checkout_env.exists()

    result = cmd_addon_start(_name_args(config_dir, repo_root))
    assert result == 0
    assert checkout_env.is_file(), "start must materialize .env into checkout"

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    assert checkout_env.read_text(encoding="utf-8") == bundle_env.read_text(encoding="utf-8")

    # cleanup: remove the materialized .env so the fixture stays clean
    checkout_env.unlink(missing_ok=True)


def test_start_returns_2_for_unregistered_addon(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="unknown",
    )
    result = cmd_addon_start(args)
    assert result == 2


# ── remove ────────────────────────────────────────────────────────────────────


def test_remove_marks_inactive_and_removes_override(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    override = config_dir / "overrides" / "docker-compose.paperless.override.yml"
    assert override.is_file()

    result = cmd_addon_remove(_name_args(config_dir, repo_root))
    assert result == 0

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["addons"][0]["active"] is False
    assert not override.exists()


def test_remove_keeps_config_bundle(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    assert bundle_env.is_file()

    cmd_addon_remove(_name_args(config_dir, repo_root))
    assert bundle_env.is_file(), "remove must not delete the config bundle"


def test_remove_unknown_addon_returns_2(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="unknown",
    )
    result = cmd_addon_remove(args)
    assert result == 2


# ── uninstall ─────────────────────────────────────────────────────────────────


def test_uninstall_deletes_bundle_and_deployment_entry(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_dir = config_dir / "addons" / "paperless"
    assert bundle_dir.is_dir()

    result = cmd_addon_uninstall(_name_args(config_dir, repo_root))
    assert result == 0

    assert not bundle_dir.exists(), "uninstall must delete the config bundle"
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert all(a.get("name") != "paperless" for a in deployment.get("addons", []))


def test_uninstall_removes_override(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    override = config_dir / "overrides" / "docker-compose.paperless.override.yml"
    assert override.is_file()

    cmd_addon_uninstall(_name_args(config_dir, repo_root))
    assert not override.exists()


def test_uninstall_unknown_addon_returns_2(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="unknown",
    )
    result = cmd_addon_uninstall(args)
    assert result == 2


# ── addon-networks ────────────────────────────────────────────────────────────


def test_addon_networks_returns_network_for_active_addon(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    addon_dst = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(ADDON_PAPERLESS, addon_dst)

    cmd_addon_install(
        argparse.Namespace(
            config_dir=str(config_dir),
            repo_root=str(repo_root),
            name="paperless",
            path=str(addon_dst),
            version=None,
        )
    )

    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root))
    result = cmd_addon_networks(args)
    assert result == 0
    out = capsys.readouterr().out
    assert "papaia-paperless-net" in out


def test_addon_networks_empty_when_no_active_addons(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root))
    result = cmd_addon_networks(args)
    assert result == 0
    assert capsys.readouterr().out.strip() == ""


# ── addon-path ────────────────────────────────────────────────────────────────


def test_addon_path_returns_registered_path(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    result = cmd_addon_path(_name_args(config_dir, repo_root))
    assert result == 0


def test_addon_path_unknown_returns_2(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="unknown",
    )
    result = cmd_addon_path(args)
    assert result == 2


# ── gen_override repo_root fix ───────────────────────────────────────────────


def test_generate_overrides_uses_repo_root(repo_root, config_dir):
    """generate_overrides() must resolve addon paths via repo_root, not CWD."""
    bootstrap.init(config_dir, repo_root, env_name="papaia")

    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["addons"] = [
        {"name": "paperless", "path": str(ADDON_PAPERLESS), "active": True}
    ]
    import yaml as _yaml

    common.atomic_write(
        deployment_path,
        _yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )

    written = gen_override.generate_overrides(config_dir, repo_root)
    assert len(written) == 1
    override = yaml.safe_load(written[0].read_text(encoding="utf-8"))
    assert override["services"]["nginx-proxy-manager"]["networks"] == ["papaia-paperless-net"]
    assert override["networks"]["papaia-paperless-net"]["external"] is True


def test_generate_overrides_absolute_path_without_repo_root(repo_root, config_dir):
    """Absolute addon paths work even without passing repo_root."""
    bootstrap.init(config_dir, repo_root, env_name="papaia")

    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["addons"] = [
        {"name": "paperless", "path": str(ADDON_PAPERLESS), "active": True}
    ]
    import yaml as _yaml

    common.atomic_write(
        deployment_path,
        _yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )

    written = gen_override.generate_overrides(config_dir)
    assert len(written) == 1


# ── CHANGE_ME prompts ────────────────────────────────────────────────────────


def test_install_warns_about_change_me_in_noninteractive_mode(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    err = capsys.readouterr().err
    assert "CHANGE_ME" in err
    assert "OIDC_ISSUER" in err
    assert "PAPERLESS_PUBLIC_URL" in err

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["OIDC_ISSUER"] == "CHANGE_ME"
    assert parsed["PAPERLESS_PUBLIC_URL"] == "CHANGE_ME"


def test_install_applies_prompted_values(repo_root, config_dir, monkeypatch):
    _setup(repo_root, config_dir)

    answers = iter(["https://kc.example.com/realms/papaia", "http://localhost:8010"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["OIDC_ISSUER"] == "https://kc.example.com/realms/papaia"
    assert parsed["PAPERLESS_PUBLIC_URL"] == "http://localhost:8010"


def test_install_uses_default_when_input_is_empty(repo_root, config_dir, monkeypatch):
    _setup(repo_root, config_dir)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["PAPERLESS_PUBLIC_URL"] == "http://host.docker.internal:8010"


# ── REPLACE_WITH hints ───────────────────────────────────────────────────────


def test_install_prints_replace_with_hints(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    out = capsys.readouterr().out
    assert "KC_PAPERLESS_CLIENT_SECRET" in out
    assert "Keycloak → Clients → paperless → Credentials → Client Secret" in out


def test_install_replace_with_values_preserved_in_bundle(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["KC_PAPERLESS_CLIENT_SECRET"] == "REPLACE_WITH_KC_PAPERLESS_CLIENT_SECRET"
