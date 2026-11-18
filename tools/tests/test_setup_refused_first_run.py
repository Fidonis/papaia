"""A refused first `setup` leaves nothing behind that the next run would take for an
existing installation (#400, #402).

The arguments of a first setup are resolved and checked before the config directory is
seeded. What a check stores on its way (the relay's password file) is removed again when
the run is refused, and only that: a file that was there before stays as it was."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from install_helpers import checkout
from test_topology import FULL

from lib import cli, common, envtree, smtp

APP_HOST = "https://papaia.example.test"

# Every value the app host derives that a seeded template would have pinned to
# http://host.docker.internal:<port>.
DERIVED = {
    "": ("LITELLM_PUBLIC_URL", "LOCALAI_PUBLIC_URL", "MANAGER_PUBLIC_URL", "NPM_ADMIN_HOST"),
    "ai/librechat": ("DOMAIN_CLIENT", "DOMAIN_SERVER"),
    "ai/litellm": ("GENERIC_REDIRECT_URI", "PROXY_LOGOUT_URL"),
}

# One refusal per stage of a first setup: a value resolve rejects, a value it rejects
# only after looking at the stored password, and a topology refused after the relay's
# password file has been written.
REFUSALS = {
    "smtp-without-host": (
        ["--enable-smtp=true", "--smtp-from=noreply@example.org"],
        3,
        "--smtp-host is required",
    ),
    "smtp-login-without-password": (
        [
            "--enable-smtp=true",
            "--smtp-host=smtp.example.org",
            "--smtp-from=noreply@example.org",
            "--smtp-user=mailer",
        ],
        3,
        "PAPAIA_SMTP_PASSWORD",
    ),
    "placement-after-the-password-file": (
        [
            *FULL[1:],
            "--topology=distributed",
            "--node=internal=10.0.2.10",
            "--node=edge=10.0.1.10,ssh=papaia@10.0.1.10",
            "--place=manager=edge",
        ],
        cli.SETUP_REFUSED,
        "'manager' must run on the controller",
    ),
}


@pytest.fixture(autouse=True)
def _no_password_in_the_environment(monkeypatch):
    monkeypatch.delenv("PAPAIA_SMTP_PASSWORD", raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return checkout(tmp_path)


def _setup(repo: Path, config: Path, *flags: str) -> int:
    return cli.main(
        ["--repo-root", str(repo), "--config-dir", str(config), "setup", "--env=papaia", *flags]
    )


def _files(config: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(config)): p.read_bytes() for p in sorted(config.rglob("*")) if p.is_file()
    }


def _template_hosts(config: Path, repo: Path) -> set[tuple[str, str]]:
    tree = envtree.load_config_dir_tree(config, repo)
    return {
        (rel_dir, key)
        for rel_dir, values in tree.items()
        for key, value in values.items()
        if "host.docker.internal" in value
    }


@pytest.fixture
def reference(repo: Path, tmp_path: Path) -> Path:
    """The same setup on a config directory nothing has touched before."""
    config = tmp_path / "reference-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    return config


@pytest.mark.parametrize("state", ["empty", "missing"])
@pytest.mark.parametrize("refusal", sorted(REFUSALS))
def test_a_refused_first_setup_leaves_nothing_and_the_next_one_derives_every_url(
    repo, reference, tmp_path, capsys, state, refusal
):
    flags, code, message = REFUSALS[refusal]
    config = tmp_path / "workspace" / "papaia-config"
    if state == "empty":
        config.mkdir()

    assert _setup(repo, config, f"--app-host={APP_HOST}", *flags) == code
    assert message in capsys.readouterr().err
    if state == "empty":
        assert list(config.iterdir()) == []
    else:
        assert not config.exists()

    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    for rel_dir, keys in DERIVED.items():
        stored = common.parse_env_file(config / rel_dir / ".env")
        expected = common.parse_env_file(reference / rel_dir / ".env")
        for key in keys:
            assert APP_HOST in stored[key], (rel_dir, key, stored[key])
            assert stored[key] == expected[key], (rel_dir, key)
    # Nothing else kept a template host either.
    assert _template_hosts(config, repo) == _template_hosts(reference, repo)


def test_files_that_were_there_before_a_refused_first_setup_stay(repo, tmp_path, capsys):
    config = tmp_path / "papaia-config"
    (config / "overlay" / "ai" / "librechat").mkdir(parents=True)
    (config / "overlay" / "ai" / "librechat" / "librechat.yaml").write_text("version: 1\n")
    (config / "overrides").mkdir()
    (config / "notes.txt").write_text("kept\n")
    before = _files(config)
    dirs = sorted(p for p in config.rglob("*") if p.is_dir())

    flags, code, _ = REFUSALS["placement-after-the-password-file"]
    assert _setup(repo, config, *FULL[:1], *flags) == code
    capsys.readouterr()

    assert _files(config) == before
    assert sorted(p for p in config.rglob("*") if p.is_dir()) == dirs
    assert not smtp.password_path(config).exists()


def test_a_refused_setup_of_an_existing_installation_is_not_taken_back(repo, tmp_path, capsys):
    config = tmp_path / "papaia-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    before = _files(config)
    capsys.readouterr()

    flags, code, _ = REFUSALS["smtp-without-host"]
    assert _setup(repo, config, *flags) == code
    assert _files(config) == before


def test_a_failure_after_the_configuration_is_written_keeps_it(
    repo, tmp_path, capsys, monkeypatch
):
    # Past persist_tree the run is no longer refused: what it wrote is a configuration the
    # next setup completes, not template files.
    monkeypatch.setattr(cli, "_project_bundles", lambda config_dir, repo_root: 3)
    config = tmp_path / "papaia-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 3
    root = common.parse_env_file(config / ".env")
    assert root["PAPAIA_VERSION"]
    assert APP_HOST in root["LITELLM_PUBLIC_URL"]


BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_the_reproduction_through_papaia_ctl(repo, tmp_path):
    tools = Path(__file__).resolve().parents[1]
    shutil.copytree(
        tools,
        repo / "tools",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("tests", "__pycache__", ".venv"),
    )
    config = tmp_path / "cfg"
    base = [
        BASH,
        str(repo / "tools" / "papaia-ctl"),
        "setup",
        "-y",
        f"--config-dir={config}",
        "--host-ip=127.0.0.1",
        f"--app-host={APP_HOST}",
    ]
    refused = subprocess.run(
        [*base, "--smtp"], capture_output=True, text=True, timeout=180, check=False
    )
    assert refused.returncode == 3, refused.stderr
    assert "--smtp-host is required" in refused.stderr
    assert not config.exists() or list(config.iterdir()) == []

    done = subprocess.run(base, capture_output=True, text=True, timeout=180, check=False)
    assert done.returncode == 0, done.stderr
    root = common.parse_env_file(config / ".env")
    for key in DERIVED[""]:
        assert root[key].startswith(APP_HOST), (key, root[key])
    librechat = common.parse_env_file(config / "ai" / "librechat" / ".env")
    assert librechat["DOMAIN_CLIENT"].startswith(APP_HOST)
