from __future__ import annotations

import argparse
from pathlib import Path

import pytest
import yaml

from lib import bootstrap, gen_override
from lib.cli import cmd_deintegrate, cmd_integrate

FIXTURES_DIR = Path(__file__).parent / "fixtures"
EXT_PAPERLESS = FIXTURES_DIR / "ext-paperless"


def _integrate_args(config_dir: Path, repo_root: Path, *, path: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
        path=path or str(EXT_PAPERLESS),
        version=None,
    )


def _deintegrate_args(config_dir: Path, repo_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
    )


def _setup(repo_root: Path, config_dir: Path) -> None:
    bootstrap.init(config_dir, repo_root, env_name="papaia")


# ── integrate ────────────────────────────────────────────────────────────────


def test_integrate_creates_deployment_entry(repo_root, config_dir):
    _setup(repo_root, config_dir)
    result = cmd_integrate(_integrate_args(config_dir, repo_root))
    assert result == 0

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    extensions = deployment.get("extensions", [])
    assert len(extensions) == 1
    entry = extensions[0]
    assert entry["name"] == "paperless"
    assert entry["active"] is True
    assert Path(entry["path"]).is_absolute()


def test_integrate_seeds_env_generates_secrets(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_integrate(_integrate_args(config_dir, repo_root))

    # Extension env is written to ext_path/.env, not config_dir/.env
    ext_env_path = EXT_PAPERLESS / ".env"
    assert ext_env_path.is_file(), "ext_path/.env must be created by integrate"
    env_content = ext_env_path.read_text(encoding="utf-8")
    from lib import common

    parsed = common.parse_env_file(ext_env_path)
    # GENERATE_* keys must receive a real secret (non-placeholder, non-empty)
    assert "PAPERLESS_DBPASS" in parsed
    assert not common.marks_generated_secret(parsed["PAPERLESS_DBPASS"])
    assert parsed["PAPERLESS_DBPASS"] != ""
    assert "KC_PAPERLESS_CLIENT_SECRET" in parsed
    assert not common.marks_generated_secret(parsed["KC_PAPERLESS_CLIENT_SECRET"])
    # Literal defaults are copied verbatim
    assert parsed["PAPERLESS_EXT_PORT"] == "8010"
    assert parsed["PAPERLESS_DBUSER"] == "paperless"
    # CHANGE_ME keys stay as-is
    assert parsed["PAPERLESS_PUBLIC_URL"] == "CHANGE_ME"
    # Section banner is present
    assert "Extension: paperless" in env_content


def test_integrate_is_idempotent(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_integrate(_integrate_args(config_dir, repo_root))

    from lib import common

    ext_env = EXT_PAPERLESS / ".env"
    secret_after_first = common.parse_env_file(ext_env)["PAPERLESS_DBPASS"]

    cmd_integrate(_integrate_args(config_dir, repo_root))
    secret_after_second = common.parse_env_file(ext_env)["PAPERLESS_DBPASS"]

    assert secret_after_first == secret_after_second


def test_integrate_reactivates_inactive_entry(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_integrate(_integrate_args(config_dir, repo_root))
    cmd_deintegrate(_deintegrate_args(config_dir, repo_root))

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["extensions"][0]["active"] is False

    cmd_integrate(_integrate_args(config_dir, repo_root))
    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["extensions"][0]["active"] is True
    assert len(deployment["extensions"]) == 1


def test_integrate_requires_path_for_new_extension(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
        path=None,
        version=None,
    )
    result = cmd_integrate(args)
    assert result == 2


# ── deintegrate ──────────────────────────────────────────────────────────────


def test_deintegrate_marks_inactive_and_removes_override(repo_root, config_dir):
    _setup(repo_root, config_dir)
    cmd_integrate(_integrate_args(config_dir, repo_root))

    override = config_dir / "overrides" / "docker-compose.paperless.override.yml"
    assert override.is_file()

    result = cmd_deintegrate(_deintegrate_args(config_dir, repo_root))
    assert result == 0

    deployment = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["extensions"][0]["active"] is False
    assert not override.exists()


def test_deintegrate_unknown_extension_returns_2(repo_root, config_dir):
    _setup(repo_root, config_dir)
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="unknown",
    )
    result = cmd_deintegrate(args)
    assert result == 2


# ── gen_override repo_root fix ───────────────────────────────────────────────


def test_generate_overrides_uses_repo_root(repo_root, config_dir):
    """generate_overrides() must resolve ext paths via repo_root, not CWD."""
    bootstrap.init(config_dir, repo_root, env_name="papaia")

    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["extensions"] = [
        {"name": "paperless", "path": str(EXT_PAPERLESS), "active": True}
    ]
    import yaml as _yaml
    from lib import common
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
    """Absolute ext paths work even without passing repo_root."""
    bootstrap.init(config_dir, repo_root, env_name="papaia")

    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["extensions"] = [
        {"name": "paperless", "path": str(EXT_PAPERLESS), "active": True}
    ]
    import yaml as _yaml
    from lib import common
    common.atomic_write(
        deployment_path,
        _yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )

    # No repo_root supplied — absolute path must still resolve correctly.
    written = gen_override.generate_overrides(config_dir)
    assert len(written) == 1
