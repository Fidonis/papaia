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
from lib.status import CommandResult

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
    assert localai_native.write_run_script(home, binary, config, "8200") is True
    path = localai_native.script_path(home)

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
    localai_native.write_run_script(home, binary, config, "8200")
    path = localai_native.script_path(home)

    done = subprocess.run([str(path)], capture_output=True, text=True, check=True)
    command, key, address, models, cwd = done.stdout.strip().split("|")
    assert (command, key, address) == ("run", "sk-local-test-value", "127.0.0.1:8200")
    assert models == str(home / "models")
    assert Path(cwd) == home.resolve()

    (config / "ai" / "localai" / ".env").write_text("LOCALAI_API_KEY=\n", encoding="utf-8")
    missing = subprocess.run([str(path)], capture_output=True, text=True, check=False)
    assert missing.returncode == 1
    assert "LOCALAI_API_KEY is missing" in missing.stderr


def test_the_script_reports_whether_it_changed(tmp_path):
    config = _config_with_key(tmp_path)
    home = tmp_path / "home"
    binary = home / "bin" / "local-ai-v9.9.9"
    assert localai_native.write_run_script(home, binary, config, "8200") is True
    assert localai_native.write_run_script(home, binary, config, "8200") is False
    assert localai_native.write_run_script(home, binary, config, "8300") is True


def test_install_for_prepares_the_home_of_the_installation(tmp_path, repo_root):
    config = _config_with_key(tmp_path)
    (config / ".env").write_text(
        "\n".join(f"{k}={v}" for k, v in _root(tmp_path).items()) + "\n", encoding="utf-8"
    )
    result = localai_native.install_for(config, repo_root, opener=FakeOpener())
    home = tmp_path / "workspace" / "localai" / "papaia"
    assert result.version == VERSION and result.changed and result.script_changed
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


# ── launchd ─────────────────────────────────────────────────────────────────

LAUNCHCTL_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "launchctl"
# What `launchctl print` says on macOS for a job that is not loaded (exit 113).
NOT_LOADED = (
    'Bad request.\nCould not find service "de.fidonis.papaia.papaia.localai" in domain for'
    " user gui: 501\n"
)
LABEL = "de.fidonis.papaia.papaia.localai"
UID = 501
TARGET = f"gui/{UID}/{LABEL}"


class FakeLaunchctl:
    """launchd of one user, as far as `launchctl` shows it: answers print from the recorded
    output, refuses to bootstrap a disabled job, records every call."""

    def __init__(self, *, loaded=False, running=True, disabled=False, fail=None):
        self.loaded = loaded
        self.running = running
        self.disabled = disabled
        # {verb: CommandResult} for a call that fails.
        self.fail = fail or {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        assert cmd[0] == "launchctl", cmd
        self.calls.append(cmd[1:])
        verb = cmd[1]
        if verb in self.fail:
            return self.fail[verb]
        if verb == "print":
            if not self.loaded:
                return CommandResult(113, "", NOT_LOADED)
            name = "print-running.txt" if self.running else "print-crashed.txt"
            return CommandResult(0, (LAUNCHCTL_FIXTURES / name).read_text(encoding="utf-8"), "")
        if verb == "enable":
            self.disabled = False
        elif verb == "disable":
            self.disabled = True
        elif verb == "bootstrap":
            if self.disabled:
                return CommandResult(5, "", "Bootstrap failed: 5: Input/output error\n")
            if self.loaded:
                return CommandResult(5, "", "Bootstrap failed: 5: Input/output error\n")
            self.loaded = self.running = True
        elif verb == "kickstart":
            if not self.loaded:
                return CommandResult(113, "", NOT_LOADED)
            self.running = True
        elif verb == "bootout":
            if not self.loaded:
                return CommandResult(3, "", "Boot-out failed: 3: No such process\n")
            self.loaded = self.running = False
        else:
            raise AssertionError(f"unexpected launchctl call: {cmd}")
        return CommandResult(0, "", "")

    def verbs(self) -> list[str]:
        return [" ".join(call) for call in self.calls if call[0] != "print"]


def _job_home(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "workspace" / "localai" / "papaia"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / f"local-ai-{VERSION}").write_bytes(b"binary")
    (home / "run-localai").write_text("#!/bin/sh\n", encoding="utf-8")
    for sub in ("models", "backends", "data", "configuration"):
        (home / sub).mkdir()
    (home / "models" / "qwen.gguf").write_bytes(b"model")
    return home, tmp_path / "LaunchAgents" / f"{LABEL}.plist"


def _start(home, plist, fake, **kwargs):
    return localai_native.start_job(
        home, LABEL, plist, run=fake, uid=UID, sleep=lambda s: None, **kwargs
    )


def test_the_label_and_the_plist_are_per_installation(tmp_path):
    assert localai_native.label("papaia") == LABEL
    assert localai_native.label_for({"COMPOSE_PROJECT_NAME": "papaia-two"}) == (
        "de.fidonis.papaia.papaia-two.localai"
    )
    assert localai_native.label_for({}) == LABEL
    assert localai_native.plist_path(LABEL, user_home=tmp_path) == (
        tmp_path / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    )
    with pytest.raises(localai_native.LaunchdError):
        localai_native.label("../evil")


def test_the_plist_runs_the_script_and_holds_no_key(tmp_path):
    import plistlib

    config = _config_with_key(tmp_path)
    home, plist = _job_home(tmp_path)
    localai_native.write_run_script(home, home / "bin" / f"local-ai-{VERSION}", config, "8200")
    assert localai_native.write_plist(plist, localai_native.plist_document(LABEL, home))

    text = plist.read_text(encoding="utf-8")
    assert "sk-local-test-value" not in text and "LOCALAI_API_KEY" not in text
    document = plistlib.loads(plist.read_bytes())
    assert document["Label"] == LABEL
    assert document["ProgramArguments"] == [str(home / "run-localai")]
    assert document["RunAtLoad"] is True
    assert document["KeepAlive"] == {"SuccessfulExit": False}
    assert document["ThrottleInterval"] == 10
    assert document["StandardOutPath"] == str(home / "logs" / "localai.log")
    assert document["StandardErrorPath"] == document["StandardOutPath"]
    assert "EnvironmentVariables" not in document
    # The same document again is no change.
    assert not localai_native.write_plist(plist, localai_native.plist_document(LABEL, home))


def test_the_state_is_read_from_launchctl_print():
    running = localai_native.state(LABEL, run=FakeLaunchctl(loaded=True), uid=UID)
    assert running == localai_native.JobState(True, "running", 70027, "(never exited)")
    assert running.running

    crashed = localai_native.state(LABEL, run=FakeLaunchctl(loaded=True, running=False), uid=UID)
    assert crashed.loaded and not crashed.running
    assert (crashed.state, crashed.pid, crashed.last_exit) == ("not running", None, "1")

    absent = localai_native.state(LABEL, run=FakeLaunchctl(), uid=UID)
    assert absent == localai_native.JobState(loaded=False)


def test_the_nested_blocks_of_print_do_not_override_the_job_state():
    text = (LAUNCHCTL_FIXTURES / "print-running.txt").read_text(encoding="utf-8")
    # The coalition blocks further down say `state = active`.
    assert "\t\tstate = active" in text
    assert localai_native.parse_print(text).state == "running"


def test_a_first_start_enables_and_loads_the_job(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    result = _start(home, plist, fake, restart=True)

    assert result.action == "loaded"
    assert fake.verbs() == [f"enable {TARGET}", f"bootstrap gui/{UID} {plist}"]
    assert plist.is_file()
    assert (home / "logs").is_dir(), "launchd opens the log but does not create its directory"
    assert result.log == home / "logs" / "localai.log"


def test_a_running_job_with_nothing_new_is_left_alone(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    fake.calls.clear()

    result = _start(home, plist, fake)
    assert result.action == "running"
    assert fake.verbs() == [f"enable {TARGET}"]


def test_a_new_binary_restarts_the_running_job(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    fake.calls.clear()

    result = _start(home, plist, fake, restart=True)
    assert result.action == "restarted"
    assert fake.verbs() == [f"enable {TARGET}", f"kickstart -k {TARGET}"]


def test_a_loaded_job_that_exited_is_started_again(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    fake.running = False
    fake.calls.clear()

    assert _start(home, plist, fake).action == "started"
    assert fake.verbs() == [f"enable {TARGET}", f"kickstart {TARGET}"]


def test_a_changed_plist_is_loaded_anew(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    plist.write_text("<plist>an older version</plist>\n", encoding="utf-8")
    fake.calls.clear()

    assert _start(home, plist, fake).action == "loaded"
    assert fake.verbs() == [
        f"enable {TARGET}",
        f"bootout {TARGET}",
        f"bootstrap gui/{UID} {plist}",
    ]


def test_a_stopped_job_is_enabled_before_it_is_loaded(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    localai_native.stop_job(LABEL, run=fake, uid=UID, sleep=lambda s: None)
    assert fake.disabled and not fake.loaded

    assert _start(home, plist, fake).action == "loaded"
    assert fake.loaded and not fake.disabled


def test_a_failed_bootstrap_says_what_launchctl_said(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl(
        fail={"bootstrap": CommandResult(5, "", "Bootstrap failed: 5: Input/output error\n")}
    )
    with pytest.raises(localai_native.LaunchdError, match="bootstrap .* Input/output error"):
        _start(home, plist, fake)


def test_a_missing_launchctl_is_an_error(tmp_path):
    home, plist = _job_home(tmp_path)

    def missing(cmd, timeout):
        return CommandResult(127, "", "launchctl: command not found")

    with pytest.raises(localai_native.LaunchdError, match="not found"):
        _start(home, plist, missing)


def test_launchctl_goes_through_the_status_runner(tmp_path, monkeypatch):
    from lib import status

    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    localai_native.start_job(home, LABEL, plist, uid=UID)
    assert fake.verbs()[-1].startswith("bootstrap")


def test_stop_unloads_and_disables_the_job(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)
    fake.calls.clear()

    assert localai_native.stop_job(LABEL, run=fake, uid=UID, sleep=lambda s: None) is True
    assert fake.verbs() == [f"bootout {TARGET}", f"disable {TARGET}"]
    assert not fake.loaded and fake.disabled


def test_stopping_a_job_that_is_not_loaded_only_disables_it():
    fake = FakeLaunchctl()
    assert localai_native.stop_job(LABEL, run=fake, uid=UID, sleep=lambda s: None) is False
    assert fake.verbs() == [f"disable {TARGET}"]


def test_a_job_that_went_away_during_bootout_is_no_error():
    class Racing(FakeLaunchctl):
        def __call__(self, cmd, timeout):
            if cmd[1] == "bootout":
                self.calls.append(list(cmd[1:]))
                self.loaded = False
                return CommandResult(3, "", "Boot-out failed: 3: No such process\n")
            return super().__call__(cmd, timeout)

    fake = Racing(loaded=True)
    assert localai_native.stop_job(LABEL, run=fake, uid=UID, sleep=lambda s: None) is True
    assert fake.disabled


def test_a_job_that_does_not_unload_is_an_error():
    fake = FakeLaunchctl(loaded=True, fail={"bootout": CommandResult(0, "", "")})
    with pytest.raises(localai_native.LaunchdError, match="still loaded"):
        localai_native.stop_job(LABEL, run=fake, uid=UID, sleep=lambda s: None)


def test_readiness_is_awaited_and_times_out():
    now = [0.0]
    asked: list[str] = []

    def never(url):
        asked.append(url)
        return False

    def sleep(seconds):
        now[0] += seconds

    url = "http://127.0.0.1:8200/readyz"
    assert not localai_native.wait_ready(url, 60, ready=never, sleep=sleep, clock=lambda: now[0])
    assert now[0] == 60 and len(asked) == 61

    answers = iter([False, False, True])
    assert localai_native.wait_ready(
        url, 60, ready=lambda u: next(answers), sleep=sleep, clock=lambda: now[0]
    )


def test_uninstall_keeps_the_models(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)

    removed = localai_native.uninstall(home, LABEL, plist, run=fake, uid=UID, sleep=lambda s: None)
    assert not fake.loaded and fake.disabled
    assert set(removed) == {plist, home / "run-localai", home / "bin"}
    assert (home / "models" / "qwen.gguf").is_file()
    assert (home / "backends").is_dir() and (home / "logs").is_dir()


def test_uninstall_with_purge_removes_the_directory(tmp_path):
    home, plist = _job_home(tmp_path)
    fake = FakeLaunchctl()
    _start(home, plist, fake)

    localai_native.uninstall(
        home, LABEL, plist, purge=True, run=fake, uid=UID, sleep=lambda s: None
    )
    assert not plist.exists()
    assert not home.exists()
    assert not home.parent.exists(), "the empty localai/ directory goes too"
    assert (tmp_path / "workspace").is_dir()


def test_uninstall_with_purge_leaves_files_it_does_not_know(tmp_path):
    home, plist = _job_home(tmp_path)
    (home / "notes.txt").write_text("mine\n", encoding="utf-8")
    localai_native.uninstall(
        home, LABEL, plist, purge=True, run=FakeLaunchctl(), uid=UID, sleep=lambda s: None
    )
    assert (home / "notes.txt").is_file()
    assert not (home / "models").exists()


def test_purge_data_deletes_models_and_backends_only(tmp_path):
    home, _ = _job_home(tmp_path)
    assert localai_native.purge_data(home) == [home / "models", home / "backends"]
    assert (home / "bin").is_dir() and (home / "data").is_dir()
    assert localai_native.purge_data(home) == []


@pytest.mark.parametrize(
    "below, folder",
    [("Documents", "~/Documents"), ("Desktop", "~/Desktop"), ("Downloads", "~/Downloads"),
     ("papaia-workspace", None)],
)  # fmt: skip
def test_the_protected_folders_are_recognised(tmp_path, below, folder):
    home = tmp_path / below / "work" / "localai" / "papaia"
    assert localai_native.protected_folder(home, user_home=tmp_path) == folder


def test_launchd_is_only_at_hand_on_a_mac_outside_a_container(monkeypatch):
    monkeypatch.setattr(common, "in_container", lambda: False)
    assert localai_native.launchd_host(system="Darwin") == (True, "")
    assert not localai_native.launchd_host(system="Linux")[0]
    monkeypatch.setattr(common, "in_container", lambda: True)
    available, why = localai_native.launchd_host(system="Darwin")
    assert not available and "inside a container" in why


# ── the launchd commands ────────────────────────────────────────────────────


@pytest.fixture
def native_install(papaia_repo, config_dir, tmp_path, monkeypatch, capsys):
    """A native installation after `start`'s install step, with HOME in tmp_path."""
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    assert _setup(papaia_repo, config_dir, "--localai-runtime=native") == 0
    monkeypatch.setattr(localai_native, "host_supported", lambda: (True, ""))
    monkeypatch.setattr(localai_native, "launchd_host", lambda: (True, ""))
    monkeypatch.setattr(localai_native, "_open", FakeOpener())
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    from lib import cli

    assert cli.main([*argv, "localai-native-install"]) == 0
    capsys.readouterr()
    home = localai_native.localai_home(common.parse_env_file(config_dir / ".env"))
    return argv, home


def _cli(argv, *args):
    from lib import cli

    return cli.main([*argv, *args])


def test_start_command_loads_the_job_and_waits_for_readyz(native_install, monkeypatch, capsys):
    from lib import status

    argv, home = native_install
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    asked: list[str] = []
    monkeypatch.setattr(
        localai_native, "wait_ready", lambda url, timeout: asked.append(url) or True
    )

    assert _cli(argv, "localai-native-start") == 0
    out = capsys.readouterr().out
    assert fake.loaded
    assert f"log: {home / 'logs' / 'localai.log'}" in out
    assert asked and asked[0].endswith("/readyz") and "127.0.0.1" in asked[0]
    plist = localai_native.plist_path(LABEL)
    assert plist.is_relative_to(Path(os.environ["HOME"]))


def test_start_command_warns_on_a_readiness_timeout(native_install, monkeypatch, capsys):
    from lib import status

    argv, home = native_install
    monkeypatch.setattr(status, "run_command", FakeLaunchctl())
    monkeypatch.setattr(localai_native, "probe", lambda url, opener=None: False)

    assert _cli(argv, "localai-native-start", "--wait=0") == 0
    err = capsys.readouterr().err
    assert "does not answer" in err
    assert str(home / "logs" / "localai.log") in err
    assert "launchctl print gui/" in err


def test_start_command_fails_when_launchctl_does(native_install, monkeypatch, capsys):
    from lib import status

    argv, _ = native_install
    fail = {"bootstrap": CommandResult(5, "", "Bootstrap failed: 5: Input/output error\n")}
    monkeypatch.setattr(status, "run_command", FakeLaunchctl(fail=fail))
    assert _cli(argv, "localai-native-start", "--wait=0") == 1
    assert "Input/output error" in capsys.readouterr().err


def test_start_command_skips_a_container_or_an_unsupported_host(
    native_install, monkeypatch, capsys
):
    from lib import status

    argv, _ = native_install
    monkeypatch.setattr(
        localai_native, "host_supported", lambda: (False, "papaia-ctl runs inside a container")
    )
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    assert _cli(argv, "localai-native-start") == 0
    assert "not started: papaia-ctl runs inside a container" in capsys.readouterr().err
    assert fake.calls == []


def test_stop_command_unloads_the_job(native_install, monkeypatch, capsys):
    from lib import status

    argv, home = native_install
    fake = FakeLaunchctl(loaded=True)
    monkeypatch.setattr(status, "run_command", fake)
    assert _cli(argv, "localai-native-stop") == 0
    assert "Stopped the native LocalAI" in capsys.readouterr().out
    target = f"gui/{os.getuid()}/{LABEL}"
    assert fake.verbs() == [f"bootout {target}", f"disable {target}"]
    assert (home / "models").is_dir()


def test_stop_command_with_purge_deletes_the_models(native_install, monkeypatch, capsys):
    from lib import status

    argv, home = native_install
    monkeypatch.setattr(status, "run_command", FakeLaunchctl(loaded=True))
    assert _cli(argv, "localai-native-stop", "--purge-models") == 0
    assert not (home / "models").exists() and not (home / "backends").exists()
    assert (home / "bin").is_dir()


def test_stop_command_in_a_container_warns_and_still_deletes_the_models(
    native_install, monkeypatch, capsys
):
    from lib import status

    argv, home = native_install
    monkeypatch.setattr(
        localai_native, "launchd_host", lambda: (False, "papaia-ctl runs inside a container")
    )
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    assert _cli(argv, "localai-native-stop", "--purge-models") == 0
    assert "not stopped: papaia-ctl runs inside a container" in capsys.readouterr().err
    assert fake.calls == []
    # The workspace is mounted into the manager at the same path.
    assert not (home / "models").exists()


def test_stop_command_is_silent_for_the_container_runtime(
    papaia_repo, config_dir, tmp_path, monkeypatch, capsys
):
    from lib import status

    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    assert _setup(papaia_repo, config_dir) == 0
    capsys.readouterr()
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    argv = ["--repo-root", str(papaia_repo), "--config-dir", str(config_dir)]
    assert _cli(argv, "localai-native-stop") == 0
    assert _cli(argv, "localai-native-uninstall", "--purge") == 0
    assert fake.calls == []
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_state_command_prints_the_job(native_install, monkeypatch, capsys):
    from lib import status

    argv, _ = native_install
    monkeypatch.setattr(status, "run_command", FakeLaunchctl(loaded=True))
    assert _cli(argv, "localai-native-state") == 0
    lines = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert lines["LABEL"] == LABEL
    assert (lines["LOADED"], lines["STATE"], lines["PID"]) == ("yes", "running", "70027")


@pytest.mark.parametrize("purge", [False, True])
def test_uninstall_command_removes_the_job(native_install, monkeypatch, capsys, purge):
    from lib import status

    argv, home = native_install
    fake = FakeLaunchctl()
    monkeypatch.setattr(status, "run_command", fake)
    monkeypatch.setattr(localai_native, "wait_ready", lambda url, timeout: True)
    assert _cli(argv, "localai-native-start") == 0
    plist = localai_native.plist_path(LABEL)
    assert plist.is_file()

    assert _cli(argv, "localai-native-uninstall", *(["--purge"] if purge else [])) == 0
    assert not fake.loaded
    assert not plist.exists()
    assert not (home / "bin").exists() and not (home / "run-localai").exists()
    assert (home / "models").is_dir() is not purge
    assert home.exists() is not purge


def test_setup_warns_when_the_home_is_in_a_protected_folder(tmp_path, monkeypatch, capsys):
    from lib import cli

    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(
        f"LOCALAI_RUNTIME=native\nPAPAIA_WORKSPACE_DIR={tmp_path / 'Documents' / 'work'}\n",
        encoding="utf-8",
    )
    cli._warn_protected_localai_home(config)
    err = capsys.readouterr().err
    assert "below ~/Documents" in err and "macOS may deny" in err

    (config / ".env").write_text(
        f"LOCALAI_RUNTIME=native\nPAPAIA_WORKSPACE_DIR={tmp_path / 'work'}\n", encoding="utf-8"
    )
    cli._warn_protected_localai_home(config)
    assert capsys.readouterr().err == ""
