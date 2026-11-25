"""The runtime environment of papaia-ctl (lib/ctl_runtime.py, lib/sh/runtime.sh).

A host with exactly the documented prerequisites -- Python 3.12 with venv, no PyYAML, no
kit, a wheel directory instead of the package index -- runs `setup` to the end, and every
lib.cli command afterwards runs from tools/.runtime/current whatever comes first on PATH.
The hashes are checked before pip runs; a stale, unsafe or half-built environment is never
used. Each checkout here is a copy of this working tree without its tests.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from runtime_helpers import checkout_copy, pip_offline

from lib import ctl_runtime, doctor
from lib.doctor import Context, Probes

SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# The flags of the golden single-node fixture `default` (test_golden_single_node.py).
SETUP_FLAGS = ["setup", "-y", "--app-host=https://papaia.example.org"]
# The ports of this ticket's test stack (an index that never answers).
SILENT_INDEX_PORT = 53440


def _bare_python(folder: Path) -> Path:
    """A Python 3.12+ without any package: no PyYAML, no kit."""
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(folder)], check=True)
    return folder / "bin"


def _openssl_dir(folder: Path) -> Path:
    """The OpenSSL the test runner uses, alone in a directory: the system LibreSSL of macOS
    cannot make the platform's P-256 keys (on Linux this is the system OpenSSL anyway)."""
    folder.mkdir()
    found = shutil.which("openssl")
    assert found, "openssl is needed for setup"
    (folder / "openssl").symlink_to(found)
    return folder


class Host:
    """One checkout and the PATH shapes of the accounts that run it."""

    def __init__(self, root: Path, house: Path):
        self.root = root
        self.repo = checkout_copy(root / "workspace" / "papaia")
        self.tools = self.repo / "tools"
        self.config = root / "workspace" / "papaia-config"
        self.bare = _bare_python(root / "bare")
        self.openssl = _openssl_dir(root / "openssl")
        self.house = house

    @property
    def runtime(self) -> Path:
        return self.tools / ".runtime"

    def current(self) -> str:
        return os.readlink(self.runtime / "current")

    def env(self, *, path: str | None = None, **extra: str) -> dict[str, str]:
        env = {
            "HOME": str(self.root),
            "PATH": path or f"{self.bare}:{self.openssl}:{SYSTEM_PATH}",
            **pip_offline(self.house),
        }
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def ctl(self, *args: str, path: str | None = None, **extra: str):
        return subprocess.run(
            ["/bin/bash", str(self.tools / "papaia-ctl"), *args],
            cwd=self.root, env=self.env(path=path, **extra), capture_output=True, text=True,
            timeout=600, check=False,
        )


@pytest.fixture(scope="module")
def host(tmp_path_factory, ctl_wheelhouse) -> Host:
    """A host after `papaia-ctl setup`: the environment built from the wheel directory."""
    host = Host(tmp_path_factory.mktemp("host"), ctl_wheelhouse)
    done = host.ctl(*SETUP_FLAGS)
    assert done.returncode == 0, done.stdout + done.stderr
    host.setup_output = done.stdout + done.stderr
    return host


# --- PLT-32-A1: the documented prerequisites suffice -----------------------------------


def test_setup_runs_to_the_end_with_only_the_documented_prerequisites(host):
    assert "setup complete" in host.setup_output
    assert "Building the runtime environment of papaia-ctl" in host.setup_output
    digest = ctl_runtime.lock_digest(str(host.tools))
    assert host.current() == digest
    marker = json.loads((host.runtime / digest / ctl_runtime.MARKER).read_text())
    assert marker["format"] == "papaia.ctl-runtime/1"
    assert marker["lock_sha256"] == digest
    assert marker["base"] == str(host.bare / "python3")
    assert marker["python"].startswith("3.")
    # The bare interpreter still has neither package: the environment carries them.
    probe = subprocess.run([str(host.bare / "python3"), "-c", "import yaml"],
                           capture_output=True, check=False)
    assert probe.returncode != 0


@pytest.mark.parametrize("command", [["pairing", "list"], ["backup", "mirror"]])
def test_lib_cli_runs_from_the_environment_with_a_wrong_python_first_on_path(host, command):
    done = host.ctl(*command, f"--config-dir={host.config}")
    assert done.returncode == 0, done.stderr
    assert "papaia_kit" not in done.stderr


def test_a_second_account_needs_nothing_on_its_path(host):
    # The shape of sudo's secure_path: the system directories only.
    done = host.ctl("pairing", "list", f"--config-dir={host.config}", path=SYSTEM_PATH,
                    PAPAIA_CTL_DEBUG="1")
    assert done.returncode == 0, done.stderr
    expected = f"[debug] lib.cli pairing-list runs on {host.tools}/.runtime/current/bin/python"
    assert expected in done.stderr


def test_a_command_other_than_setup_never_builds(host, tmp_path):
    shutil.rmtree(host.runtime)
    try:
        done = host.ctl("pairing", "list", f"--config-dir={host.config}")
        assert done.returncode == 2
        assert "runtime environment of papaia-ctl is missing" in done.stderr
        assert "run 'papaia-ctl setup'" in done.stderr
        assert len(done.stderr.strip().splitlines()) == 1
        assert not host.runtime.exists()
    finally:
        assert host.ctl(*SETUP_FLAGS).returncode == 0


# --- hashes ------------------------------------------------------------------------------


def _wheel(host: Host) -> Path:
    path, _ = ctl_runtime.kit_lock_wheel(str(host.tools))
    return host.tools / path


def _assert_nothing_installed(host: Host, before: set[str], current: str) -> None:
    assert host.current() == current
    assert {p.name for p in host.runtime.iterdir()} == before


def test_a_kit_wheel_that_differs_from_kit_lock_stops_setup_before_anything_is_installed(host):
    wheel = _wheel(host)
    original = wheel.read_bytes()
    # Another lock too, so a reusable environment cannot hide the check.
    lock = host.tools / "runtime.lock"
    lock_text = lock.read_text()
    current, before = host.current(), {p.name for p in host.runtime.iterdir()}
    try:
        wheel.write_bytes(original + b"\0")
        lock.write_text(lock_text + "# another lock\n")
        done = host.ctl(*SETUP_FLAGS)
        assert done.returncode == 2
        assert "does not match its sha256 in kit.lock" in done.stderr
        assert "Building" not in done.stderr
        _assert_nothing_installed(host, before, current)
    finally:
        wheel.write_bytes(original)
        lock.write_text(lock_text)


def test_a_lock_line_without_a_hash_stops_setup_before_anything_is_installed(host):
    lock = host.tools / "runtime.lock"
    text = lock.read_text()
    current, before = host.current(), {p.name for p in host.runtime.iterdir()}
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith("pyyaml=="))
    end = start + 1
    while end < len(lines) and lines[end].startswith("    --hash="):
        end += 1
    try:
        lock.write_text("".join([*lines[:start], "pyyaml==6.0.3\n", *lines[end:]]))
        done = host.ctl(*SETUP_FLAGS)
        assert done.returncode == 2
        assert "pyyaml==6.0.3 has no hash" in done.stderr
        _assert_nothing_installed(host, before, current)
    finally:
        lock.write_text(text)


def test_lock_options_are_refused():
    with pytest.raises(ctl_runtime.RuntimeEnvError, match="only requirements with hashes"):
        ctl_runtime.parse_lock("--index-url https://example.org/simple\n")
    with pytest.raises(ctl_runtime.RuntimeEnvError, match="unexpected option"):
        ctl_runtime.parse_lock("pyyaml==6.0.3 --trusted-host example.org\n")
    with pytest.raises(ctl_runtime.RuntimeEnvError, match="neither a pinned package"):
        ctl_runtime.parse_lock("pyyaml>=6 --hash=sha256:" + "0" * 64 + "\n")


# --- stale, unsafe and interrupted ---------------------------------------------------------


def test_a_changed_runtime_lock_stops_every_other_command(host):
    lock = host.tools / "runtime.lock"
    text = lock.read_text()
    try:
        lock.write_text(text + "# another lock\n")
        done = host.ctl("pairing", "list", f"--config-dir={host.config}")
        assert done.returncode == 2
        assert "is stale: it was built for another runtime.lock" in done.stderr
        assert "run 'papaia-ctl setup'" in done.stderr
    finally:
        lock.write_text(text)


@pytest.mark.parametrize("target", ["env", "runtime"])
def test_a_group_writable_environment_is_refused(host, target):
    path = host.runtime / host.current() if target == "env" else host.runtime
    mode = stat.S_IMODE(path.stat().st_mode)
    try:
        path.chmod(mode | stat.S_IWGRP)
        done = host.ctl("pairing", "list", f"--config-dir={host.config}")
        assert done.returncode == 2
        assert "group- or world-writable" in done.stderr
        assert "refused" in done.stderr
    finally:
        path.chmod(mode)
    assert host.ctl("pairing", "list", f"--config-dir={host.config}").returncode == 0


def test_an_interrupted_build_leaves_the_previous_environment_usable(host):
    lock = host.tools / "runtime.lock"
    text = lock.read_text()
    current = host.current()
    silent = socket.socket()
    silent.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    silent.bind(("127.0.0.1", SILENT_INDEX_PORT))
    silent.listen(8)
    try:
        lock.write_text(text + "# another lock\n")
        env = host.env(PIP_FIND_LINKS=None, PIP_NO_INDEX=None,
                       PIP_INDEX_URL=f"http://127.0.0.1:{SILENT_INDEX_PORT}/simple")
        proc = subprocess.Popen(
            ["/bin/bash", str(host.tools / "papaia-ctl"), *SETUP_FLAGS], cwd=host.root,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            builds = list(host.runtime.glob(".build-*/bin/pip"))
            if builds:
                break
            time.sleep(0.2)
        assert builds, "the build did not start"
        time.sleep(1)  # pip is waiting for the index now
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=30)
    finally:
        silent.close()
        lock.write_text(text)
    assert host.current() == current
    done = host.ctl("pairing", "list", f"--config-dir={host.config}")
    assert done.returncode == 0, done.stderr
    # The next setup reuses the environment and removes what the killed build left.
    assert host.ctl(*SETUP_FLAGS).returncode == 0
    assert not list(host.runtime.glob(".build-*"))


# --- upgrade and rollback ----------------------------------------------------------------

_HARNESS = """
set -euo pipefail
REPO_ROOT="@REPO@"
source "$REPO_ROOT/tools/lib/sh/log.sh"; source "$REPO_ROOT/tools/lib/sh/python.sh"
source "$REPO_ROOT/tools/lib/sh/runtime.sh"; source "$REPO_ROOT/tools/lib/sh/upgrade.sh"
CONFIG_DIR="@CONFIG@"
"""


def _harness(host: Host, body: str):
    script = _HARNESS.replace("@REPO@", str(host.repo)).replace("@CONFIG@", str(host.config))
    return subprocess.run(["/bin/bash", "-c", script + body], cwd=host.root, env=host.env(),
                          capture_output=True, text=True, timeout=600, check=False)


def test_upgrade_runs_the_target_environment_and_rollback_returns_to_the_previous(host):
    lock = host.tools / "runtime.lock"
    text = lock.read_text()
    previous = host.current()
    target = host.root / "target"
    (target / "tools").mkdir(parents=True)
    for rel in ("kit.lock", "vendor"):
        source = host.tools / rel
        if source.is_dir():
            shutil.copytree(source, target / "tools" / rel)
        else:
            shutil.copyfile(source, target / "tools" / rel)
    (target / "tools" / "runtime.lock").write_text(text + "# the target release\n")
    next_digest = ctl_runtime.lock_digest(str(target / "tools"))
    try:
        # Stage 0: the target's environment, built before the plan; `current` stays.
        done = _harness(host, f'ctl_runtime_require; _py_cli_at "{target}" new-correlation-id'
                              ' >/dev/null; echo "AT=$CTL_RUNTIME_AT_PYTHON"\n')
        assert done.returncode == 0, done.stderr
        assert f"AT={host.runtime}/{next_digest}/bin/python" in done.stdout
        assert host.current() == previous
        # Phase 2 runs from the target checkout: its upgrade switches to that environment.
        lock.write_text(text + "# the target release\n")
        done = _harness(host, "ctl_runtime_preflight upgrade; echo \"BIN=$PYTHON_BIN\"\n")
        assert done.returncode == 0, done.stderr
        assert "Building" not in done.stderr, "built in stage 0 already"
        assert host.current() == next_digest
        # rollback checks out the previous release: its environment is current again.
        lock.write_text(text)
        done = _harness(host, "ctl_runtime_preflight rollback\n")
        assert done.returncode == 0, done.stderr
        assert "Building" not in done.stderr
        assert host.current() == previous
        # upgrade --finalize: no restore point needs the other environment.
        assert ctl_runtime.prune(str(host.runtime), set()) == [next_digest]
        assert not (host.runtime / next_digest).exists()
    finally:
        lock.write_text(text)


# --- doctor ------------------------------------------------------------------------------


def _doctor(repo: Path, config: Path) -> doctor.CheckResult:
    ctx = Context(config, repo, run=lambda cmd, timeout: None, probes=Probes(),
                  now=doctor.datetime.now(doctor.timezone.utc))
    return doctor.check_ctl_runtime(ctx)


def test_doctor_reports_the_environment(host, tmp_path):
    result = _doctor(host.repo, host.config)
    assert result.status == doctor.PASS, result.summary
    assert host.current()[:12] in result.summary
    lock = host.tools / "runtime.lock"
    text = lock.read_text()
    try:
        lock.write_text(text + "# another lock\n")
        result = _doctor(host.repo, host.config)
        assert result.status == doctor.FAIL
        assert "papaia-ctl setup" in result.summary
    finally:
        lock.write_text(text)
    missing = tmp_path / "repo"
    (missing / "tools").mkdir(parents=True)
    shutil.copyfile(host.tools / "runtime.lock", missing / "tools" / "runtime.lock")
    result = _doctor(missing, host.config)
    assert result.status == doctor.FAIL
    assert "missing" in result.summary
