"""The preflight's choice of Python interpreter (`find_python` in tools/lib/sh/python.sh, #286)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

# Answers both probes of find_python like a Python 3.9 would.
_OLD_PYTHON = """#!/bin/sh
case "$2" in
  *exit*) exit 1 ;;
  *) echo 3.9.6 ;;
esac
"""


def _old(bin_dir: Path, name: str) -> None:
    path = bin_dir / name
    path.write_text(_OLD_PYTHON, encoding="utf-8")
    path.chmod(0o755)


def _new(bin_dir: Path, name: str) -> None:
    (bin_dir / name).symlink_to(sys.executable)


def _find_python(bin_dir: Path) -> subprocess.CompletedProcess:
    assert BASH is not None
    script = (
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "python.sh"}"; '
        'find_python; rc=$?; echo "BIN=$PYTHON_BIN"; exit "$rc"'
    )
    return subprocess.run(
        [BASH, "-c", script],
        env={"PATH": str(bin_dir)},
        capture_output=True,
        text=True,
        check=False,
    )


@needs_bash
def test_a_current_python3_is_taken(tmp_path):
    _new(tmp_path, "python3")
    done = _find_python(tmp_path)
    assert done.returncode == 0
    assert "BIN=python3" in done.stdout


@needs_bash
def test_a_too_old_python3_is_rejected_with_its_version(tmp_path):
    _old(tmp_path, "python3")
    done = _find_python(tmp_path)
    assert done.returncode == 1
    assert "BIN=\n" in done.stdout
    assert "requires Python 3.10 or newer; found python3 3.9.6" in done.stderr
    assert "brew install python" in done.stderr


@needs_bash
def test_a_versioned_interpreter_stands_in_for_a_too_old_python3(tmp_path):
    # macOS: the Command Line Tools' python3 first on PATH, Homebrew's as python3.12.
    _old(tmp_path, "python3")
    _new(tmp_path, "python3.12")
    done = _find_python(tmp_path)
    assert done.returncode == 0
    assert "BIN=python3.12" in done.stdout


@needs_bash
def test_no_interpreter_at_all(tmp_path):
    done = _find_python(tmp_path)
    assert done.returncode == 1
    assert "python3 not found on PATH" in done.stderr
