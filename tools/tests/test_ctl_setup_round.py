"""The shell part of the question round (`setup --answers=FILE`, lib/sh/setup.sh).

The round and the size check run before anything is written: a host below the profile
stops `setup` with exit 3 and `py_cli setup` is never called (PLT-58-A5). After a
successful round the record reaches Python, the backup target and keys are set up and the
count is printed. Hermetic: `py_cli` and the steps around it are stubs that record calls.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

RECIPIENT = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"

_HARNESS = """
set -euo pipefail
CYAN="" NC="" YELLOW=""
DEFAULT_CONFIG_DIR="@CONFIG@"
source "@SH@/log.sh"; source "@SH@/prompt.sh"; source "@SH@/setup.sh"
CONFIG_SEEDED=false
usage() { :; }
is_tty() { return 1; }
_ensure_keycloak_certs() { echo "step keycloak-certs"; }
_macos_local_tls_steps() { :; }
_ensure_platform_pki() { echo "step pki"; }
_setup_pairings() { echo "step pairings $*"; }
_setup_module_offer() { :; }
_topology_mode() { echo single; }
py_cli() {
    echo "py_cli $*" >> "@CALLS@"
    case "$1" in
        setup-round) : ;;
        setup-round-values)
            echo "ROUND_APP_HOST=https://example.org" >&3
            ;;
        size-check) return "@SIZE_RC@" ;;
    esac
}
"""

_VALUES = (
    "ROUND_APP_HOST=https://example.org\n"
    "ROUND_SIZE_PROFILE=small\n"
    "ROUND_LOCAL_AI=true\n"
    "ROUND_BACKUP_DIR=/mnt/backup\n"
    f"ROUND_BACKUP_KEY=betrieb:{RECIPIENT}\n"
    "ROUND_APPROVE_PAIRINGS=\n"
    "ROUND_MAIL=false\n"
    "ROUND_TLS=internal\n"
    "ROUND_INPUTS=12\n"
)


def _run(tmp_path: Path, args: str, *, size_rc: int = 0, existing: bool = False):
    config = tmp_path / "papaia-config"
    config.mkdir()
    if existing:
        (config / ".env").write_text("PAPAIA_VERSION=1.10.0\n")
    answers = tmp_path / "answers.yaml"
    answers.write_text("format: papaia.setup-answers/1\n")
    harness = (
        _HARNESS.replace("@CONFIG@", config.as_posix())
        .replace("@SH@", SH_LIB.as_posix())
        .replace("@SIZE_RC@", str(size_rc))
        .replace("@CALLS@", (tmp_path / "calls").as_posix())
    )
    # setup-round-values prints the shell values; everything else only records.
    harness = harness.replace(
        '            echo "ROUND_APP_HOST=https://example.org" >&3\n',
        "".join(f"            echo '{line}'\n" for line in _VALUES.splitlines()),
    )
    harness += f'cmd_setup --answers="{answers.as_posix()}" {args}\n'
    assert BASH is not None
    done = subprocess.run(
        [BASH, "-c", harness], capture_output=True, text=True, timeout=30, check=False,
        env={"PATH": "/usr/bin:/bin", "TMPDIR": tmp_path.as_posix()},
    )
    calls = tmp_path / "calls"
    lines = calls.read_text().splitlines() if calls.exists() else []
    return done, lines


def test_a_host_below_the_profile_stops_before_anything_is_written(tmp_path):
    done, calls = _run(tmp_path, "-y", size_rc=3)

    assert done.returncode == 3, done.stderr
    calls = [line for line in calls if not line.startswith("py_cli defaults")]
    assert calls[0].startswith("py_cli setup-round ")
    assert "py_cli size-check --profile=small" in calls
    assert not any(c.startswith("py_cli setup --env") for c in calls)
    assert not list(tmp_path.glob("papaia-answers.*")), "the temporary record is removed"


def test_the_round_hands_its_record_to_setup_and_sets_up_the_backup(tmp_path):
    done, lines = _run(tmp_path, "-y")

    assert done.returncode == 0, done.stderr
    setup = next(line for line in lines if line.startswith("py_cli setup --env"))
    assert "--app-host=https://example.org" in setup
    assert "--reverse-proxy-provider=internal_nginx" in setup
    assert "--enable-local-ai=true" in setup
    assert "--backup-dir=/mnt/backup" in setup
    assert "--answers-record=" in setup
    round_call = next(line for line in lines if line.startswith("py_cli setup-round "))
    assert "--flags=-y" in round_call, "the switch is counted"
    assert "py_cli backup-target init --backup-dir=/mnt/backup" in lines
    assert f"py_cli backup-recipients add --name=betrieb --key={RECIPIENT}" in lines
    assert lines.index(setup) < lines.index("py_cli backup-target init --backup-dir=/mnt/backup")
    assert "Inputs of this installation: 12 of at most 15" in done.stdout + done.stderr
    # The request to delete the mail answer file comes after the backup, at the end.
    assert "py_cli setup-mail-file-notice" in lines
    assert lines.index("py_cli setup-mail-file-notice") > lines.index(
        f"py_cli backup-recipients add --name=betrieb --key={RECIPIENT}")


def test_answers_are_refused_for_an_existing_installation(tmp_path):
    done, lines = _run(tmp_path, "-y", existing=True)

    assert done.returncode == 2
    assert "fresh installation" in done.stderr
    assert not any(line.startswith("py_cli setup-round") for line in lines)


@pytest.mark.parametrize(
    "switch", ["--app-host=https://other.example.org", "--no-local-ai", "--backup-dir=/srv/b",
               "--reverse-proxy-provider=no_proxy", "--smtp-host=mail.example.org"],
)
def test_switches_the_round_decides_are_refused_with_an_answer_file(switch, tmp_path):
    done, lines = _run(tmp_path, f"-y {switch}")

    assert done.returncode == 2, done.stderr
    assert switch.split("=")[0] in done.stderr and "Nothing was changed" in done.stderr
    assert not any(line.startswith("py_cli setup-round") for line in lines)


def test_the_readme_counts_one_command_per_module_and_promises_no_edge_bundle():
    readme = (SH_LIB.parents[2] / "README.md").read_text(encoding="utf-8")
    start = readme.index("### Fresh installation")
    guide = readme[start:readme.index("### Question round")]
    assert "addon install <module> --path=" in guide
    assert "every chosen module" not in guide
    assert "installs nothing" in guide
    answer_file = readme[readme.index("format: papaia.setup-answers/1"):]
    answer_file = answer_file[:answer_file.index("```")]
    assert "edge.pem" not in answer_file
