"""The choice of the base Python interpreter (`find_python` in tools/lib/sh/python.sh, #286).

The base interpreter builds the runtime environment of papaia-ctl (lib/sh/runtime.sh); the
floor is Python 3.12, and PAPAIA_PYTHON names it by absolute path instead of PATH."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

# Answers both probes of find_python like an older Python would.
_OLD_PYTHON = """#!/bin/sh
case "$2" in
  *exit*) exit 1 ;;
  *) echo @VERSION@ ;;
esac
"""


def _old(bin_dir: Path, name: str, version: str = "3.9.6") -> None:
    path = bin_dir / name
    path.write_text(_OLD_PYTHON.replace("@VERSION@", version), encoding="utf-8")
    path.chmod(0o755)


def _new(bin_dir: Path, name: str) -> None:
    (bin_dir / name).symlink_to(sys.executable)


def _find_python(bin_dir: Path, **extra: str) -> subprocess.CompletedProcess:
    assert BASH is not None
    script = (
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "python.sh"}"; '
        'find_python; rc=$?; echo "BIN=$PYTHON_BIN"; exit "$rc"'
    )
    return subprocess.run(
        [BASH, "-c", script],
        env={"PATH": str(bin_dir), **extra},
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
    assert "requires Python 3.12 or newer with the venv module; found python3 3.9.6" in done.stderr
    assert "brew install python" in done.stderr
    assert "python3-venv" in done.stderr
    assert "PAPAIA_PYTHON=/absolute/path" in done.stderr
    assert "yaml" not in done.stderr.lower()


@needs_bash
@pytest.mark.parametrize("version", ["3.10.12", "3.11.9"])
def test_python_below_3_12_is_rejected(tmp_path, version):
    # The kit, which every lib.cli command imports, needs 3.12 (datetime.UTC, StrEnum).
    _old(tmp_path, "python3", version)
    done = _find_python(tmp_path)
    assert done.returncode == 1
    assert f"found python3 {version}" in done.stderr


@needs_bash
def test_papaia_python_names_the_interpreter_by_absolute_path(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    _new(other, "python3")
    _old(tmp_path, "python3")
    done = _find_python(tmp_path, PAPAIA_PYTHON=str(other / "python3"))
    assert done.returncode == 0, done.stderr
    assert f"BIN={other / 'python3'}" in done.stdout


@needs_bash
@pytest.mark.parametrize("value", ["python3", "bin/python3", "./python3"])
def test_papaia_python_refuses_a_name_or_relative_path(tmp_path, value):
    _new(tmp_path, "python3")
    done = _find_python(tmp_path, PAPAIA_PYTHON=value)
    assert done.returncode == 1
    assert "BIN=\n" in done.stdout
    assert "PAPAIA_PYTHON must be an absolute path" in done.stderr


@needs_bash
def test_papaia_python_below_the_floor_is_rejected(tmp_path):
    _old(tmp_path, "old-python", "3.11.2")
    done = _find_python(tmp_path, PAPAIA_PYTHON=str(tmp_path / "old-python"))
    assert done.returncode == 1
    assert "requires Python 3.12 or newer" in done.stderr


@needs_bash
def test_a_versioned_interpreter_stands_in_for_a_too_old_python3(tmp_path):
    # macOS: the Command Line Tools' python3 first on PATH, Homebrew's as python3.12.
    _old(tmp_path, "python3")
    _new(tmp_path, "python3.12")
    done = _find_python(tmp_path)
    assert done.returncode == 0
    assert "BIN=python3.12" in done.stdout


@needs_bash
def test_a_minor_release_beyond_any_fixed_list_is_found(tmp_path):
    # Homebrew's python is python@3.15 now; any later one has to be found the same way.
    _old(tmp_path, "python3")
    _new(tmp_path, "python3.15")
    done = _find_python(tmp_path)
    assert done.returncode == 0
    assert "BIN=python3.15" in done.stdout


@needs_bash
def test_the_newest_versioned_interpreter_is_tried_first(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    _old(first, "python3")
    _new(first, "python3.12")
    _new(second, "python3.15")
    _new(second, "python3.9")
    (second / "python3.15-config").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (second / "python3.15-config").chmod(0o755)
    assert BASH is not None
    script = (
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "python.sh"}"; '
        'echo "LIST=$(_versioned_pythons)"; find_python; echo "BIN=$PYTHON_BIN"'
    )
    done = subprocess.run(
        [BASH, "-c", script],
        env={"PATH": f"{first}:{second}:{first}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert "LIST=python3.15 python3.12 python3.9 \n" in done.stdout
    assert "BIN=python3.15" in done.stdout


@needs_bash
def test_no_interpreter_at_all(tmp_path):
    done = _find_python(tmp_path)
    assert done.returncode == 1
    assert "python3 not found on PATH" in done.stderr
