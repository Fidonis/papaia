"""The "Local inference" question of `setup` on Apple Silicon (`_prompt_local_inference`)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_RUNNER = (
    "MODEL_RUNNER_AVAILABLE=true",
    "MODEL_RUNNER_LABEL=Docker Desktop 4.95.0, engines: llama.cpp, vllm",
    "MODEL_RUNNER_WARN=",
)
_NO_RUNNER = (
    "MODEL_RUNNER_AVAILABLE=false",
    "MODEL_RUNNER_LABEL=Docker Model Runner is switched off; enable it in Settings > AI",
    "MODEL_RUNNER_WARN=",
)


def _ask(
    detection: tuple[str, ...],
    answer: str = "",
    *,
    local_ai: str = "",
    sticky_runner: str = "",
    sticky_localai: str = "",
) -> subprocess.CompletedProcess:
    assert BASH is not None
    lines = "\\n".join(detection)
    script = (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "setup.sh"}"\n'
        # The detection is py_cli's; stand in for it with its KEY=VALUE output.
        f"py_cli() {{ printf '{lines}\\n'; }}\n"
        f'MODEL_RUNNER_STICKY="{sticky_runner}"; LOCAL_AI_STICKY="{sticky_localai}"\n'
        f'model_runner=""; local_ai="{local_ai}"\n'
        "_prompt_local_inference\n"
        'printf "RUNNER=%s LOCALAI=%s\\n" "$model_runner" "$local_ai"\n'
    )
    return subprocess.run(
        [BASH, "-c", script], input=answer + "\n", capture_output=True, text=True, check=False
    )


def test_the_runner_is_the_recommended_default_and_localai_goes_off():
    done = _ask(_RUNNER)
    assert done.returncode == 0, done.stderr
    assert "RUNNER=true LOCALAI=false" in done.stdout
    assert "Docker Model Runner — models on the Apple GPU" in done.stderr
    assert "engines: llama.cpp, vllm" in done.stderr


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("2", "RUNNER=false LOCALAI=true"),
        ("3", "RUNNER=true LOCALAI=true"),
        ("4", "RUNNER=false LOCALAI=false"),
    ],
)
def test_every_combination_can_be_chosen(answer: str, expected: str):
    assert expected in _ask(_RUNNER, answer).stdout


def test_a_previous_localai_only_choice_stays_the_default():
    done = _ask(_RUNNER, sticky_runner="false", sticky_localai="true")
    assert "RUNNER=false LOCALAI=true" in done.stdout


def test_a_previous_choice_of_both_stays_the_default():
    done = _ask(_RUNNER, sticky_runner="true", sticky_localai="true")
    assert "RUNNER=true LOCALAI=true" in done.stdout


def test_with_localai_given_by_a_flag_only_the_runner_is_asked():
    done = _ask(_RUNNER, local_ai="true")
    assert "RUNNER=true LOCALAI=true" in done.stdout
    assert "3) Both" not in done.stderr


def test_without_a_runner_nothing_is_decided_and_the_reason_is_shown():
    done = _ask(_NO_RUNNER)
    assert done.returncode == 0, done.stderr
    assert "RUNNER= LOCALAI=" in done.stdout
    assert "switched off" in done.stderr


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [("Darwin", "arm64", 0), ("Darwin", "x86_64", 1), ("Linux", "x86_64", 1)],
)
def test_only_apple_silicon_is_asked(system: str, machine: str, expected: int):
    assert BASH is not None
    script = (
        f'source "{SH_LIB / "setup.sh"}"\n'
        f'uname() {{ case "$1" in -s) echo "{system}" ;; -m) echo "{machine}" ;; esac; }}\n'
        "_on_apple_silicon\n"
    )
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, check=False)
    assert done.returncode == expected
