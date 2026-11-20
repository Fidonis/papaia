"""The interactive papaia-manager question of `setup` (`_prompt_manager`, #288)."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _ask(
    system: str,
    answer: str = "",
    sticky: str = "",
    engine: str = "Ubuntu 24.04 LTS",
    docker_delay: int = 0,
    timeout: int = 15,
) -> subprocess.CompletedProcess:
    assert BASH is not None
    delay = f"sleep {docker_delay}; " if docker_delay else ""
    script = (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "setup.sh"}"\n'
        f"_DOCKER_INFO_TIMEOUT_SECONDS={timeout}\n"
        f'uname() {{ echo "{system}"; }}\n'
        f'docker() {{ {delay}echo "{engine}"; }}\n'
        f'MANAGER_STICKY="{sticky}"\n'
        'printf "MANAGER=%s\\n" "$(_prompt_manager)"\n'
    )
    return subprocess.run(
        [BASH, "-c", script], input=answer + "\n", capture_output=True, text=True, check=False
    )


def test_linux_defaults_to_the_manager():
    done = _ask("Linux")
    assert done.returncode == 0, done.stderr
    assert "MANAGER=true" in done.stdout
    assert "addons (default)" in done.stderr
    assert "needs Docker Desktop" not in done.stderr


def test_macos_with_docker_desktop_defaults_to_the_manager():
    done = _ask("Darwin", engine="Docker Desktop")
    assert done.returncode == 0, done.stderr
    assert "MANAGER=true" in done.stdout
    assert "addons (default)" in done.stderr
    assert "needs Docker Desktop" not in done.stderr


def test_macos_with_docker_desktop_keeps_a_previous_no():
    assert "MANAGER=false" in _ask("Darwin", sticky="false", engine="Docker Desktop").stdout


def test_macos_without_docker_desktop_defaults_to_no_manager_and_says_why():
    done = _ask("Darwin")
    assert done.returncode == 0, done.stderr
    assert "MANAGER=false" in done.stdout
    assert "without it) (default)" in done.stderr
    assert "On macOS papaia-manager needs Docker Desktop" in done.stderr


def test_macos_still_takes_an_explicit_yes():
    assert "MANAGER=true" in _ask("Darwin", answer="1").stdout


def test_macos_keeps_a_previous_yes_as_the_default():
    done = _ask("Darwin", sticky="true")
    assert "MANAGER=true" in done.stdout
    assert "needs Docker Desktop" not in done.stderr


def test_a_previous_no_stays_the_default_on_linux():
    assert "MANAGER=false" in _ask("Linux", sticky="false").stdout


def test_a_docker_daemon_that_does_not_answer_does_not_hold_the_prompt():
    started = time.monotonic()
    done = _ask("Darwin", engine="Docker Desktop", docker_delay=30, timeout=1)
    assert done.returncode == 0, done.stderr
    assert time.monotonic() - started < 10
    # No answer is no Docker Desktop: the default stays no, with the hint.
    assert "MANAGER=false" in done.stdout
    assert "On macOS papaia-manager needs Docker Desktop" in done.stderr


def test_a_slow_docker_daemon_inside_the_limit_still_counts():
    done = _ask("Darwin", engine="Docker Desktop", docker_delay=1, timeout=5)
    assert done.returncode == 0, done.stderr
    assert "MANAGER=true" in done.stdout


def test_linux_does_not_ask_docker():
    started = time.monotonic()
    done = _ask("Linux", docker_delay=30)
    assert done.returncode == 0, done.stderr
    assert time.monotonic() - started < 10
    assert "MANAGER=true" in done.stdout
