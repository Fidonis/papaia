"""The company CA bundle question of `setup` (`_prompt_ca_bundle`, docs/pki.md).

The answer is checked at once. A file that cannot be used is asked for once more, and a
second unusable answer stops setup; an empty answer means no company CA. Checked
hermetically: `py_cli` is a stub that accepts a file containing GOOD.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_STUB = (
    "py_cli() {\n"
    '  echo "CHECK $*" >&2\n'
    '  case "$*" in *pki-check-bundle*) ;; *) return 9 ;; esac\n'
    '  local file="${2#--file=}"\n'
    '  grep -q GOOD "$file" 2>/dev/null && return 0\n'
    '  echo "ERROR: $file: not a CA certificate" >&2; return 3\n'
    "}\n"
)


def _ask(answers: list[str]) -> subprocess.CompletedProcess:
    assert BASH is not None
    script = (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "setup.sh"}"\n'
        + _STUB
        + 'rc=0; value="$(_prompt_ca_bundle)" || rc=$?\n'
        'printf "BUNDLE=<%s> RC=%s\\n" "$value" "$rc"\n'
    )
    return subprocess.run(
        [BASH, "-c", script],
        input="".join(f"{a}\n" for a in answers),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def files(tmp_path: Path) -> dict[str, str]:
    good, bad = tmp_path / "good.pem", tmp_path / "bad.pem"
    good.write_text("GOOD\n", encoding="utf-8")
    bad.write_text("a server certificate\n", encoding="utf-8")
    return {"good": str(good), "bad": str(bad)}


def test_an_empty_answer_means_no_company_ca_and_checks_nothing():
    done = _ask([""])

    assert "BUNDLE=<> RC=0" in done.stdout
    assert "CHECK" not in done.stderr


def test_a_usable_file_is_taken_at_the_first_answer(files):
    done = _ask([files["good"]])

    assert f"BUNDLE=<{files['good']}> RC=0" in done.stdout
    assert done.stderr.count("CHECK") == 1


def test_an_unusable_file_is_asked_for_once_more(files):
    done = _ask([files["bad"], files["good"]])

    assert f"BUNDLE=<{files['good']}> RC=0" in done.stdout
    assert done.stderr.count("CHECK") == 2
    assert "not a CA certificate" in done.stderr
    assert "once more" in done.stderr


def test_a_second_unusable_file_stops_without_a_third_question(files):
    done = _ask([files["bad"], files["bad"], files["good"]])

    assert "BUNDLE=<> RC=1" in done.stdout
    assert done.stderr.count("CHECK") == 2
    assert done.stderr.count("Company CA certificates") == 2


def test_the_flag_is_checked_before_anything_is_written(files):
    assert BASH is not None
    script = (
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "setup.sh"}"\n'
        + _STUB
        + f'_check_ca_bundle_flag "{files["bad"]}"; echo "RC=$?"\n'
        + f'_check_ca_bundle_flag "{files["good"]}"; echo "RC=$?"\n'
    )
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, check=False)

    assert done.stdout.splitlines() == ["RC=1", "RC=0"]
    assert "--ca-bundle" in done.stderr
