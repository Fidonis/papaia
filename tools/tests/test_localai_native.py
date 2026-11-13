"""The native LocalAI runtime of an Apple Silicon Mac (lib/localai_native.py, ADR 0012).

Nothing is downloaded: the release files come from a fake opener.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import subprocess
import urllib.error
from pathlib import Path

import pytest

from lib import common, localai_native

BINARY = b"\x7fELF-not-really-a-local-ai-binary" * 64
VERSION = "v9.9.9"  # the pin of the fixture repo's LocalAI compose file


def _checksums(version: str = VERSION, digest: str | None = None) -> bytes:
    digest = digest or hashlib.sha256(BINARY).hexdigest()
    return (
        f"{'0' * 64}  LocalAI-{version}-source.tar.gz\n"
        f"{digest}  local-ai-{version}-darwin-arm64\n"
        f"{'1' * 64}  local-ai-{version}-linux-amd64\n"
    ).encode()


class FakeOpener:
    """Answers the two release URLs; records what was asked."""

    def __init__(self, *, checksums: bytes | None = None, binary: bytes = BINARY, fail=None):
        self.checksums = _checksums() if checksums is None else checksums
        self.binary = binary
        self.fail = fail
        self.calls: list[str] = []

    def __call__(self, url: str):
        self.calls.append(url)
        if self.fail is not None:
            raise self.fail
        if url.endswith("-checksums.txt"):
            return io.BytesIO(self.checksums)
        return io.BytesIO(self.binary)


def _root(tmp_path: Path, **extra: str) -> dict[str, str]:
    values = {
        "PAPAIA_WORKSPACE_DIR": str(tmp_path / "workspace"),
        "COMPOSE_PROJECT_NAME": "papaia",
        "LOCALAI_EXT_PORT": "8200",
        "LOCALAI_RUNTIME": "native",
    }
    values.update(extra)
    return values


# ── settings ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value, expected",
    [("native", "native"), (" native ", "native"), ("container", "container"), ("", "container"),
     ("gpu", "container")],
)  # fmt: skip
def test_only_native_selects_the_native_runtime(value, expected):
    assert localai_native.runtime({"LOCALAI_RUNTIME": value}) == expected
    assert localai_native.runtime({}) == "container"


def test_the_home_is_derived_per_project(tmp_path):
    first = localai_native.localai_home(_root(tmp_path))
    second = localai_native.localai_home(_root(tmp_path, COMPOSE_PROJECT_NAME="papaia-second"))
    assert first == tmp_path / "workspace" / "localai" / "papaia"
    assert second == tmp_path / "workspace" / "localai" / "papaia-second"


def test_a_home_needs_a_workspace(tmp_path):
    with pytest.raises(localai_native.InstallError, match="PAPAIA_WORKSPACE_DIR"):
        localai_native.localai_home(_root(tmp_path, PAPAIA_WORKSPACE_DIR=""))


def test_the_urls_follow_the_port(tmp_path):
    root = _root(tmp_path)
    assert localai_native.public_url(root) == "http://localhost:8200"
    assert localai_native.api_base(root) == "http://host.docker.internal:8200/v1"
    assert localai_native.probe_url(root, inside_container=False) == "http://127.0.0.1:8200/readyz"
    assert (
        localai_native.probe_url(root, inside_container=True)
        == "http://host.docker.internal:8200/readyz"
    )


def test_the_version_is_the_pin_of_the_compose_file(repo_root):
    assert localai_native.pinned_version(repo_root) == VERSION
    assert localai_native.binary_url(VERSION) == (
        "https://github.com/mudler/LocalAI/releases/download/v9.9.9/local-ai-v9.9.9-darwin-arm64"
    )
    assert localai_native.checksums_url(VERSION).endswith("/v9.9.9/LocalAI-v9.9.9-checksums.txt")


def test_an_unpinned_image_has_no_version(repo_root):
    compose = repo_root / "src" / "ai" / "localai" / "docker-compose.yml"
    compose.write_text(compose.read_text().replace("localai/localai:v9.9.9", "localai/localai"))
    with pytest.raises(localai_native.InstallError, match="not pinned"):
        localai_native.pinned_version(repo_root)


# ── install ─────────────────────────────────────────────────────────────────


def test_install_verifies_and_puts_the_binary_in_place(tmp_path):
    home = tmp_path / "home"
    opener = FakeOpener()
    path, changed, replaced = localai_native.install(home, VERSION, opener=opener)

    assert path == home / "bin" / "local-ai-v9.9.9"
    assert path.read_bytes() == BINARY
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert changed is True and replaced is None
    assert [u.rsplit("/", 1)[-1] for u in opener.calls] == [
        "LocalAI-v9.9.9-checksums.txt",
        "local-ai-v9.9.9-darwin-arm64",
    ]
    assert list((home / "bin").iterdir()) == [path]


def test_a_second_install_downloads_nothing(tmp_path):
    home = tmp_path / "home"
    localai_native.install(home, VERSION, opener=FakeOpener())
    opener = FakeOpener()
    _, changed, _ = localai_native.install(home, VERSION, opener=opener)
    assert changed is False
    assert opener.calls == []


def test_a_new_pin_replaces_the_old_binary(tmp_path):
    home = tmp_path / "home"
    localai_native.install(home, "v1.0.0", opener=FakeOpener(checksums=_checksums("v1.0.0")))
    path, changed, replaced = localai_native.install(home, VERSION, opener=FakeOpener())
    assert changed is True and replaced == "v1.0.0"
    assert sorted(p.name for p in (home / "bin").iterdir()) == [path.name]


def test_a_checksum_mismatch_installs_nothing(tmp_path):
    home = tmp_path / "home"
    opener = FakeOpener(binary=BINARY + b"tampered")
    with pytest.raises(localai_native.InstallError, match="does not match its published checksum"):
        localai_native.install(home, VERSION, opener=opener)
    assert list((home / "bin").iterdir()) == []


def test_a_checksum_file_without_the_asset_is_refused(tmp_path):
    opener = FakeOpener(checksums=b"abc  local-ai-v9.9.9-linux-amd64\n")
    with pytest.raises(localai_native.InstallError, match="has no checksum for"):
        localai_native.install(tmp_path / "home", VERSION, opener=opener)
    assert not (tmp_path / "home" / "bin" / "local-ai-v9.9.9").exists()


def test_a_network_error_is_reported_and_leaves_nothing(tmp_path):
    opener = FakeOpener(fail=urllib.error.URLError("no route to host"))
    with pytest.raises(localai_native.InstallError, match="could not download LocalAI v9.9.9"):
        localai_native.install(tmp_path / "home", VERSION, opener=opener)
    assert not any((tmp_path / "home").rglob("local-ai-*"))


def test_an_interrupted_download_leaves_no_partial_file(tmp_path):
    class Broken(io.BytesIO):
        def read(self, size=-1):
            raise OSError("connection reset")

    def opener(url):
        return io.BytesIO(_checksums()) if url.endswith(".txt") else Broken()

    with pytest.raises(localai_native.InstallError):
        localai_native.install(tmp_path / "home", VERSION, opener=opener)
    assert list((tmp_path / "home" / "bin").iterdir()) == []


# ── start script ────────────────────────────────────────────────────────────


def _config_with_key(tmp_path: Path, key: str = "sk-local-test-value") -> Path:
    config = tmp_path / "config"
    (config / "ai" / "localai").mkdir(parents=True)
    (config / "ai" / "localai" / ".env").write_text(
        f"LOCALAI_LOG_LEVEL=info\nLOCALAI_API_KEY={key}\n", encoding="utf-8"
    )
    return config


def test_the_script_is_private_and_holds_no_key(tmp_path):
    config = _config_with_key(tmp_path)
    home = tmp_path / "home"
    binary = home / "bin" / "local-ai-v9.9.9"
    path = localai_native.write_run_script(home, binary, config, "8200")

    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    text = path.read_text(encoding="utf-8")
    assert "sk-local-test-value" not in text
    assert "LOCALAI_AUTH" not in text
    assert "LOCALAI_ADDRESS=127.0.0.1:8200" in text
    assert "LOCALAI_EXTERNAL_BACKENDS=llama-cpp" in text


@pytest.mark.skipif(shutil.which("sh") is None, reason="sh is not available")
def test_the_script_reads_the_key_when_it_runs_and_starts_in_the_home(tmp_path):
    config = _config_with_key(tmp_path)
    home = tmp_path / "home"
    binary = home / "bin" / "local-ai-v9.9.9"
    binary.parent.mkdir(parents=True)
    binary.write_text(
        '#!/bin/sh\necho "$1|$LOCALAI_API_KEY|$LOCALAI_ADDRESS|$LOCALAI_MODELS_PATH|$(pwd -P)"\n'
    )
    binary.chmod(0o755)
    path = localai_native.write_run_script(home, binary, config, "8200")

    done = subprocess.run([str(path)], capture_output=True, text=True, check=True)
    command, key, address, models, cwd = done.stdout.strip().split("|")
    assert (command, key, address) == ("run", "sk-local-test-value", "127.0.0.1:8200")
    assert models == str(home / "models")
    assert Path(cwd) == home.resolve()

    (config / "ai" / "localai" / ".env").write_text("LOCALAI_API_KEY=\n", encoding="utf-8")
    missing = subprocess.run([str(path)], capture_output=True, text=True, check=False)
    assert missing.returncode == 1
    assert "LOCALAI_API_KEY is missing" in missing.stderr


def test_install_for_prepares_the_home_of_the_installation(tmp_path, repo_root):
    config = _config_with_key(tmp_path)
    (config / ".env").write_text(
        "\n".join(f"{k}={v}" for k, v in _root(tmp_path).items()) + "\n", encoding="utf-8"
    )
    result = localai_native.install_for(config, repo_root, opener=FakeOpener())
    home = tmp_path / "workspace" / "localai" / "papaia"
    assert result.version == VERSION and result.changed
    assert result.script == home / "run-localai"
    assert (home / "models").is_dir() and (home / "backends").is_dir()
    assert localai_native.installed_version(home) == VERSION


# ── host ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "system, machine, desktop, ok",
    [
        ("Darwin", "arm64", True, True),
        ("Darwin", "arm64", False, False),
        ("Darwin", "x86_64", True, False),
        ("Linux", "aarch64", True, False),
        ("Linux", "x86_64", True, False),
    ],
)
def test_only_an_apple_silicon_mac_with_docker_desktop_is_supported(
    monkeypatch, system, machine, desktop, ok
):
    monkeypatch.setattr(common, "in_container", lambda: False)
    supported, why = localai_native.host_supported(
        system=system, machine=machine, docker_desktop=lambda: desktop
    )
    assert supported is ok
    assert bool(why) is not ok


def test_inside_a_container_the_host_is_never_supported(monkeypatch):
    monkeypatch.setattr(common, "in_container", lambda: True)
    supported, why = localai_native.host_supported(
        system="Darwin", machine="arm64", docker_desktop=lambda: True
    )
    assert not supported and "inside a container" in why


# ── models ──────────────────────────────────────────────────────────────────


def test_the_model_list_is_seeded_once_with_the_defaults(tmp_path, repo_root):
    config = tmp_path / "config"
    path = localai_native.seed_models(config, repo_root)
    assert path == config / "overlay" / "ai" / "localai" / "models.txt"
    text = path.read_text(encoding="utf-8")
    assert text.startswith((repo_root / "src" / "ai" / "localai" / "models.txt").read_text())
    active = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert active[-2:] == list(localai_native.NATIVE_DEFAULT_MODELS)

    path.write_text("# my own list\n", encoding="utf-8")
    assert localai_native.seed_models(config, repo_root) is None
    assert path.read_text(encoding="utf-8") == "# my own list\n"


def test_the_default_models_have_shipped_yamls():
    """Every seeded line is registered in LiteLLM: a shipped YAML points at its file."""
    import yaml

    repo = Path(__file__).resolve().parents[2]
    files = {
        yaml.safe_load(p.read_text(encoding="utf-8"))["parameters"]["model"]
        for p in (repo / "src" / "ai" / "localai" / "models").glob("*.yaml")
    }
    for url in localai_native.NATIVE_DEFAULT_MODELS:
        assert url.rsplit("/", 1)[-1] in files, url


# ── probe ───────────────────────────────────────────────────────────────────


def test_the_probe_reads_readyz():
    class Answer(io.BytesIO):
        status = 200

    assert localai_native.probe("http://127.0.0.1:1/readyz", opener=lambda url: Answer(b"ok"))

    def refused(url):
        raise urllib.error.URLError(ConnectionRefusedError())

    assert not localai_native.probe("http://127.0.0.1:1/readyz", opener=refused)


def test_installed_version_ignores_partial_downloads(tmp_path):
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "local-ai-v2.0.0.part").write_bytes(b"x")
    assert localai_native.installed_version(home) is None
    (home / "bin" / "local-ai-v1.0.0").write_bytes(b"x")
    assert localai_native.installed_version(home) == "v1.0.0"
    assert os.access(home / "bin", os.W_OK)


# ── setup and render ────────────────────────────────────────────────────────


@pytest.fixture
def papaia_repo(repo_root: Path, tmp_path: Path) -> Path:
    """The fixture checkout under the name `papaia`, so setup derives the workspace."""
    target = tmp_path / "workspace" / "papaia"
    target.parent.mkdir()
    shutil.move(str(repo_root), target)
    return target


def _setup(papaia_repo: Path, config_dir: Path, *flags: str) -> int:
    from lib import cli

    return cli.main(
        [
            "--repo-root",
            str(papaia_repo),
            "--config-dir",
            str(config_dir),
            "setup",
            "--app-host=https://papaia.example.com",
            "--enable-local-ai=true",
            *flags,
        ]
    )


def test_setup_switches_to_native_and_back(papaia_repo, config_dir, capsys):
    override = config_dir / "overrides" / "docker-compose.localai-runtime.override.yml"
    overlay = config_dir / "overlay" / "ai" / "localai" / "models.txt"

    assert _setup(papaia_repo, config_dir) == 0
    assert not override.exists() and not overlay.exists()

    assert _setup(papaia_repo, config_dir, "--localai-runtime=native") == 0
    stored = common.parse_env_file(config_dir / ".env")
    assert stored["LOCALAI_RUNTIME"] == "native"
    assert stored["LOCALAI_PUBLIC_URL"] == f"http://localhost:{stored['LOCALAI_EXT_PORT']}"
    home = localai_native.localai_home(stored)
    assert str(home / "models") in override.read_text(encoding="utf-8")
    assert localai_native.NATIVE_DEFAULT_MODELS[0] in overlay.read_text(encoding="utf-8")
    # The render that followed the seeding has the list in the config dir.
    rendered = (config_dir / "ai" / "localai" / "models.txt").read_text(encoding="utf-8")
    assert localai_native.NATIVE_DEFAULT_MODELS[0] in rendered
    assert "Seeded the LocalAI model list" in capsys.readouterr().out

    assert _setup(papaia_repo, config_dir, "--localai-runtime=container") == 0
    stored = common.parse_env_file(config_dir / ".env")
    assert stored["LOCALAI_RUNTIME"] == "container"
    assert (
        stored["LOCALAI_PUBLIC_URL"] == f"https://papaia.example.com:{stored['LOCALAI_EXT_PORT']}"
    )
    assert not override.exists()
    assert overlay.exists(), "going back to the container leaves the seeded list in place"


def test_install_command_is_quiet_for_the_container_runtime(papaia_repo, config_dir, capsys):
    from lib import cli

    assert _setup(papaia_repo, config_dir) == 0
    capsys.readouterr()
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    assert cli.main([*argv, "localai-native-install"]) == 0
    assert capsys.readouterr().out == "LOCALAI_NATIVE=off\n"


def test_install_command_skips_an_unsupported_host(papaia_repo, config_dir, capsys, monkeypatch):
    from lib import cli

    assert _setup(papaia_repo, config_dir, "--localai-runtime=native") == 0
    capsys.readouterr()
    monkeypatch.setattr(localai_native, "host_supported", lambda: (False, "not a Mac"))
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    assert cli.main([*argv, "localai-native-install"]) == 0
    out = capsys.readouterr()
    assert out.out == "LOCALAI_NATIVE=skipped\n"
    assert "native LocalAI skipped: not a Mac" in out.err


def test_install_command_reports_an_install(papaia_repo, config_dir, capsys, monkeypatch):
    from lib import cli

    assert _setup(papaia_repo, config_dir, "--localai-runtime=native") == 0
    capsys.readouterr()
    monkeypatch.setattr(localai_native, "host_supported", lambda: (True, ""))
    monkeypatch.setattr(localai_native, "_open", FakeOpener())
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    assert cli.main([*argv, "localai-native-install"]) == 0
    lines = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert lines["LOCALAI_NATIVE"] == "installed"
    assert lines["LOCALAI_NATIVE_VERSION"] == VERSION
    assert lines["LOCALAI_NATIVE_SCRIPT"].endswith("/run-localai")

    monkeypatch.setattr(localai_native, "_open", FakeOpener(fail=AssertionError("no download")))
    assert cli.main([*argv, "localai-native-install"]) == 0
    assert "LOCALAI_NATIVE=unchanged" in capsys.readouterr().out


def test_install_command_fails_on_a_bad_download(papaia_repo, config_dir, capsys, monkeypatch):
    from lib import cli

    assert _setup(papaia_repo, config_dir, "--localai-runtime=native") == 0
    capsys.readouterr()
    monkeypatch.setattr(localai_native, "host_supported", lambda: (True, ""))
    monkeypatch.setattr(localai_native, "_open", FakeOpener(binary=b"tampered"))
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    assert cli.main([*argv, "localai-native-install"]) == 1
    assert "does not match its published checksum" in capsys.readouterr().err


def test_setup_refuses_native_without_a_workspace(repo_root, config_dir, capsys):
    # The fixture checkout is not named `papaia`, so no workspace is derived.
    assert _setup(repo_root, config_dir, "--localai-runtime=native") == 3
    assert "LOCALAI_RUNTIME=native: PAPAIA_WORKSPACE_DIR is not set" in capsys.readouterr().err
    assert not (config_dir / "overrides" / "docker-compose.localai-runtime.override.yml").exists()
