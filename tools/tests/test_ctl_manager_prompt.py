"""The interactive papaia-manager question of `setup` (`_prompt_manager`, #288)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _ask(system: str, answer: str = "", sticky: str = "") -> subprocess.CompletedProcess:
    assert BASH is not None
    script = (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "setup.sh"}"\n'
        f'uname() {{ echo "{system}"; }}\n'
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
    assert "Linux host" not in done.stderr


def test_macos_defaults_to_no_manager_and_says_why():
    done = _ask("Darwin")
    assert done.returncode == 0, done.stderr
    assert "MANAGER=false" in done.stdout
    assert "without it) (default)" in done.stderr
    assert "papaia-manager needs a Linux host" in done.stderr


def test_macos_still_takes_an_explicit_yes():
    assert "MANAGER=true" in _ask("Darwin", answer="1").stdout


def test_macos_keeps_a_previous_yes_as_the_default():
    done = _ask("Darwin", sticky="true")
    assert "MANAGER=true" in done.stdout
    assert "Linux host" not in done.stderr


def test_a_previous_no_stays_the_default_on_linux():
    assert "MANAGER=false" in _ask("Linux", sticky="false").stdout
