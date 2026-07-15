from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest
import yaml

from lib import common, envtree, gen_override
from lib.cli import cmd_override_external_nets
from lib.cli_addon import (
    cmd_active_addons,
    cmd_addon_check,
    cmd_addon_install,
    cmd_addon_networks,
    cmd_addon_path,
    cmd_addon_remove,
    cmd_addon_start,
    cmd_addon_uninstall,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ADDON_PAPERLESS = FIXTURES_DIR / "addon-paperless"
ADDON_INCOMPATIBLE = FIXTURES_DIR / "addon-incompatible"
REPO_NEXT = FIXTURES_DIR / "repo-next"


def _install_args(
    config_dir: Path,
    repo_root: Path,
    *,
    name: str = "paperless",
    path: str | None = None,
    force: bool = False,
) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name=name,
        path=path or str(ADDON_PAPERLESS),
        version=None,
        force=force,
    )


def _name_args(
    config_dir: Path, repo_root: Path, *, name: str = "paperless", force: bool = False
) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name=name,
        force=force,
    )


def _check_args(config_dir: Path, repo_root: Path, **overrides) -> argparse.Namespace:
    defaults = dict(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        target_core=None,
        target_version=None,
        target_addon_api=None,
        target_min_addon_api=None,
        json=False,
        force=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _setup(repo_root: Path, config_dir: Path) -> None:
    envtree.init(config_dir, repo_root, env_name="papaia")


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
    # CHANGE_ME keys stay as-is until prompted
    assert parsed["PAPAIA_CONFIG_DIR"] == "CHANGE_ME"
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
        force=False,
    )
    result = cmd_addon_install(args)
    assert result == 2


# ── compatibility gate ────────────────────────────────────────────────────────


def test_install_rejects_incompatible_addon(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    deployment_before = (config_dir / "deployment.yaml").read_text(encoding="utf-8")

    result = cmd_addon_install(
        _install_args(config_dir, repo_root, name="broken", path=str(ADDON_INCOMPATIBLE))
    )
    assert result == 2
    assert "incompatible" in capsys.readouterr().err

    # A refused install must leave no trace: deployment.yaml untouched,
    # nothing seeded into the config bundle.
    deployment_after = (config_dir / "deployment.yaml").read_text(encoding="utf-8")
    assert deployment_after == deployment_before
    assert "broken" not in deployment_after
    assert not (config_dir / "addons" / "broken").exists()


def test_install_force_overrides_incompatible(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)

    result = cmd_addon_install(
        _install_args(
            config_dir, repo_root, name="broken", path=str(ADDON_INCOMPATIBLE), force=True
        )
    )
    assert result == 0
    assert "WARNING" in capsys.readouterr().err

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert any(a["name"] == "broken" and a["active"] for a in deployment["addons"])


def test_install_warn_mode_degrades_incompatible(repo_root, config_dir, monkeypatch):
    _setup(repo_root, config_dir)
    monkeypatch.setenv("PAPAIA_COMPAT_MODE", "warn")

    result = cmd_addon_install(
        _install_args(config_dir, repo_root, name="broken", path=str(ADDON_INCOMPATIBLE))
    )
    assert result == 0


def test_addon_start_rechecks_after_core_upgrade(repo_root, config_dir):
    _setup(repo_root, config_dir)
    assert cmd_addon_install(_install_args(config_dir, repo_root)) == 0

    # Simulate the core moving under the installed addon: without the
    # VERSION file the fixture core resolves to 0.7.0 again, which no
    # longer satisfies the addon's ">=0.8.0".
    (repo_root / "VERSION").unlink()

    assert cmd_addon_start(_name_args(config_dir, repo_root)) == 2
    assert cmd_addon_start(_name_args(config_dir, repo_root, force=True)) == 0

    # cleanup: remove the .env materialized into the shared fixture checkout
    (ADDON_PAPERLESS / ".env").unlink(missing_ok=True)


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
    result = cmd_addon_start(_name_args(config_dir, repo_root, name="unknown"))
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

    cmd_addon_install(_install_args(config_dir, repo_root, path=str(addon_dst)))

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


# ── active-addons ─────────────────────────────────────────────────────────────


def test_active_addons_lists_only_active_entries(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    addon_dst = repo_root / "addons" / "papaia-addon-paperless"
    shutil.copytree(ADDON_PAPERLESS, addon_dst)
    cmd_addon_install(_install_args(config_dir, repo_root, path=str(addon_dst)))
    capsys.readouterr()

    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root))
    assert cmd_active_addons(args) == 0
    assert capsys.readouterr().out.split() == ["paperless"]

    # remove deactivates the entry -> no longer listed
    cmd_addon_remove(_name_args(config_dir, repo_root))
    capsys.readouterr()
    assert cmd_active_addons(args) == 0
    assert capsys.readouterr().out.strip() == ""


def test_active_addons_empty_without_deployment(repo_root, config_dir, capsys):
    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root))
    assert cmd_active_addons(args) == 0
    assert capsys.readouterr().out.strip() == ""


# ── override-external-nets ────────────────────────────────────────────────────


def test_override_external_nets_prints_external_networks(tmp_path, capsys):
    override = tmp_path / "docker-compose.paperless.override.yml"
    override.write_text(
        yaml.safe_dump(
            {
                "services": {"nginx": {"networks": ["papaia-paperless-net"]}},
                "networks": {
                    "papaia-paperless-net": {"external": True},
                    "papaia-net": None,
                },
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        config_dir=str(tmp_path), repo_root=str(tmp_path), file=str(override)
    )
    assert cmd_override_external_nets(args) == 0
    assert capsys.readouterr().out.split() == ["papaia-paperless-net"]


def test_override_external_nets_missing_file_is_empty(tmp_path, capsys):
    args = argparse.Namespace(
        config_dir=str(tmp_path), repo_root=str(tmp_path), file=str(tmp_path / "nope.yml")
    )
    assert cmd_override_external_nets(args) == 0
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
    envtree.init(config_dir, repo_root, env_name="papaia")

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
    envtree.init(config_dir, repo_root, env_name="papaia")

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
    assert "PAPAIA_CONFIG_DIR" in err
    assert "OIDC_ISSUER" in err
    assert "PAPERLESS_PUBLIC_URL" in err

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["PAPAIA_CONFIG_DIR"] == "CHANGE_ME"
    assert parsed["OIDC_ISSUER"] == "CHANGE_ME"
    assert parsed["PAPERLESS_PUBLIC_URL"] == "CHANGE_ME"


def test_install_applies_prompted_values(repo_root, config_dir, monkeypatch):
    _setup(repo_root, config_dir)

    # Three CHANGE_ME keys in fixture order: PAPAIA_CONFIG_DIR, OIDC_ISSUER, PAPERLESS_PUBLIC_URL
    answers = iter(["/opt/papaia-config", "https://kc.example.com/realms/papaia", "http://localhost:8010"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    cmd_addon_install(_install_args(config_dir, repo_root))

    bundle_env = config_dir / "addons" / "paperless" / ".env"
    parsed = common.parse_env_file(bundle_env)
    assert parsed["PAPAIA_CONFIG_DIR"] == "/opt/papaia-config"
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


# ── addon-check ───────────────────────────────────────────────────────────────


def test_addon_check_reports_ok_for_installed_addon(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    capsys.readouterr()

    result = cmd_addon_check(_check_args(config_dir, repo_root))
    assert result == 0
    out = capsys.readouterr().out
    assert "paperless" in out
    assert "OK" in out


def test_addon_check_without_setup_returns_2(repo_root, config_dir):
    result = cmd_addon_check(_check_args(config_dir, repo_root))
    assert result == 2


def test_addon_check_no_active_addons_passes(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    result = cmd_addon_check(_check_args(config_dir, repo_root))
    assert result == 0
    assert "No active addons." in capsys.readouterr().out


def test_addon_check_target_addon_api_detects_drop(repo_root, config_dir, tmp_path):
    _setup(repo_root, config_dir)
    # An addon that declares the contract generation it is built against.
    addon_dir = tmp_path / "addon-apized"
    addon_dir.mkdir()
    (addon_dir / "papaia-app.yaml").write_text(
        "name: apized\nrequires:\n  addon_api: 1\n", encoding="utf-8"
    )
    assert (
        cmd_addon_install(_install_args(config_dir, repo_root, name="apized", path=str(addon_dir)))
        == 0
    )

    # The current core serves [1..1].
    assert cmd_addon_check(_check_args(config_dir, repo_root)) == 0
    # A target serving only generation 2 drops the addon; without an
    # explicit min the window is assumed closed (pessimistic).
    assert cmd_addon_check(_check_args(config_dir, repo_root, target_addon_api=2)) == 2
    # The escape hatch degrades the refusal to a warning.
    assert (
        cmd_addon_check(_check_args(config_dir, repo_root, target_addon_api=2, force=True)) == 0
    )


def test_addon_check_target_core_detects_service_rename(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    capsys.readouterr()

    # repo-next renamed nginx-proxy-manager; paperless still attaches to it.
    result = cmd_addon_check(_check_args(config_dir, repo_root, target_core=str(REPO_NEXT)))
    assert result == 2
    out = capsys.readouterr().out
    assert "core has no service 'nginx-proxy-manager'" in out


def test_addon_check_json_shape(repo_root, config_dir, capsys):
    import json

    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    capsys.readouterr()

    assert cmd_addon_check(_check_args(config_dir, repo_root, json=True)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["name"] == "paperless"
    assert payload[0]["status"] == "OK"
    assert set(payload[0]) == {"name", "axis", "requirement", "core_value", "status", "reason"}


def test_addon_check_json_emitted_even_on_exit_2(repo_root, config_dir, capsys):
    import json

    _setup(repo_root, config_dir)
    cmd_addon_install(_install_args(config_dir, repo_root))
    capsys.readouterr()

    result = cmd_addon_check(
        _check_args(config_dir, repo_root, target_core=str(REPO_NEXT), json=True)
    )
    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["status"] == "INCOMPATIBLE"
    assert payload[0]["reason"]
