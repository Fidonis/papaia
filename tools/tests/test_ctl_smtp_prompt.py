"""The mail relay's part of the `setup` shell code: the silent password prompt and the
way the password reaches Python.

The password must not be echoed, must not end up in an argument (the process list shows
those) and must not be inherited by anything but the one `setup` call. Checked
hermetically: `py_cli` is a stub that reports what it received.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
PROMPT = TOOLS / "lib" / "sh" / "prompt.sh"
SETUP = TOOLS / "lib" / "sh" / "setup.sh"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

SECRET = "p@ss $w0rd #\"'\\x"


def _run(script: str, stdin: str = "") -> subprocess.CompletedProcess:
    assert BASH is not None
    # Bytes in and out: text mode would turn the "\n" of the input into "\r\n" on Windows,
    # and `read` would keep the "\r" as part of the answer.
    done = subprocess.run(
        [BASH, "-c", script],
        input=stdin.encode("utf-8"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    return subprocess.CompletedProcess(
        done.args, done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")
    )


def _quote(value: str) -> str:
    """The value as one single-quoted bash word."""
    return "'" + value.replace("'", "'\\''") + "'"


@needs_bash
def test_the_secret_prompt_returns_the_typed_value_unchanged_and_prints_it_nowhere():
    script = (
        f'source "{PROMPT.as_posix()}"\n'
        'value="$(prompt_secret "  Password" "hint")"\n'
        'printf "VALUE=<%s>\\n" "$value"\n'
    )

    done = _run(script, stdin=SECRET + "\n")

    assert f"VALUE=<{SECRET}>" in done.stdout
    assert SECRET not in done.stderr, "the prompt text goes to stderr and carries no secret"


@needs_bash
def test_an_empty_answer_stays_empty():
    script = (
        f'source "{PROMPT.as_posix()}"\n'
        'value="$(prompt_secret "Password" "Enter keeps it")"\n'
        'printf "VALUE=<%s>" "$value"\n'
    )

    assert "VALUE=<>" in _run(script, stdin="\n").stdout


# Positional arguments of _run_setup_py: all empty except the env name and the "0" flags.
_NO_ARGS = 'papaia "" "" "" 0 "" 0 "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" ""'


@needs_bash
def test_the_password_reaches_python_in_the_environment_and_never_as_an_argument():
    script = (
        "set -euo pipefail\n"
        'py_cli() { echo "ARGS=$*"; echo "ENV=${PAPAIA_SMTP_PASSWORD-unset}"; }\n'
        f'source "{SETUP.as_posix()}"\n'
        "SETUP_SMTP_ARGS=(--enable-smtp=true --smtp-host=smtp.example.org)\n"
        f"SETUP_SMTP_PASSWORD={_quote(SECRET)}\n"
        f"_run_setup_py {_NO_ARGS}\n"
        'echo "AFTER=${PAPAIA_SMTP_PASSWORD-unset}"\n'
    )

    done = _run(script)

    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    args = next(line for line in lines if line.startswith("ARGS="))
    assert "--enable-smtp=true" in args and "--smtp-host=smtp.example.org" in args
    assert SECRET not in args, "an argument would show up in the process list"
    assert f"ENV={SECRET}" in lines
    assert "AFTER=unset" in lines, "the variable exists for that one call only"


@needs_bash
def test_a_re_render_passes_no_mail_arguments_and_an_empty_password():
    script = (
        "set -euo pipefail\n"
        'py_cli() { echo "ARGS=$*"; echo "ENV=<${PAPAIA_SMTP_PASSWORD-unset}>"; }\n'
        f'source "{SETUP.as_posix()}"\n'
        "export PAPAIA_SMTP_PASSWORD=from-the-callers-environment\n"
        "SETUP_SMTP_ARGS=()\n"
        f"_run_setup_py {_NO_ARGS}\n"
    )

    done = _run(script)

    assert "--enable-smtp" not in done.stdout and "--smtp-" not in done.stdout
    assert "ENV=<>" in done.stdout, "a re-render must not apply a leftover password"
