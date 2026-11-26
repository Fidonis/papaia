"""The macOS offer to trust the edge CA after setup (`_macos_edge_tls_steps`, ADR 0035)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _run(
    config_dir: Path,
    *,
    system: str = "Darwin",
    edge_ca: bool = True,
    trusted: bool = False,
    tty: bool = False,
    non_interactive: int = 0,
    answer: str = "",
) -> subprocess.CompletedProcess:
    assert BASH is not None
    certs = config_dir / "certs"
    leaf = config_dir / "pki" / "edge" / "leaves" / "auth.itest.papaia.localhost"
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "tls.crt").write_text("leaf\n")
    certs.mkdir(exist_ok=True)
    if edge_ca:
        (certs / "edge-ca.crt").write_text("ca\n")
    script = (
        "set -euo pipefail\n"
        f'source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "prompt.sh"}"\n'
        f'source "{SH_LIB / "certs.sh"}"\n'
        f'CONFIG_DIR="{config_dir}"\n'
        f'uname() {{ echo "{system}"; }}\n'
        f"is_tty() {{ {'true' if tty else 'false'}; }}\n"
        "security() {\n"
        '    echo "security $*" >> "$CONFIG_DIR/calls"\n'
        f'    [ "$1" = "verify-cert" ] && return {0 if trusted else 1}\n'
        "    return 0\n"
        "}\n"
        f"_macos_edge_tls_steps {non_interactive}\n"
    )
    return subprocess.run(
        [BASH, "-c", script], input=answer + "\n", capture_output=True, text=True, check=False
    )


def _calls(config_dir: Path) -> str:
    calls = config_dir / "calls"
    return calls.read_text() if calls.exists() else ""


def test_does_nothing_off_macos(tmp_path):
    done = _run(tmp_path, system="Linux")
    assert done.returncode == 0, done.stderr
    assert _calls(tmp_path) == ""
    assert done.stderr == ""


def test_does_nothing_without_an_edge_ca(tmp_path):
    """A certificate bundle of row 3 or another proxy: no edge CA to trust."""
    done = _run(tmp_path, edge_ca=False)
    assert done.returncode == 0, done.stderr
    assert _calls(tmp_path) == ""


def test_trust_is_checked_under_the_tls_policy_with_a_leaf(tmp_path):
    done = _run(tmp_path, trusted=True)
    assert done.returncode == 0, done.stderr
    certs = tmp_path / "certs"
    leaf = tmp_path / "pki" / "edge" / "leaves" / "auth.itest.papaia.localhost" / "tls.crt"
    assert f"security verify-cert -c {leaf} -c {certs / 'edge-ca.crt'} -p ssl -L" in _calls(
        tmp_path
    )
    assert "add-trusted-cert" not in _calls(tmp_path)


def test_non_interactive_prints_the_trust_command_for_the_edge_ca(tmp_path):
    done = _run(tmp_path, non_interactive=1)
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert" not in _calls(tmp_path)
    assert "security add-trusted-cert -r trustRoot -p ssl -k" in done.stderr
    assert str(tmp_path / "certs" / "edge-ca.crt") in done.stderr


def test_interactive_yes_trusts_the_edge_ca_for_tls_only(tmp_path):
    done = _run(tmp_path, tty=True, answer="y")
    assert done.returncode == 0, done.stderr
    calls = _calls(tmp_path)
    assert "add-trusted-cert -r trustRoot -p ssl -k" in calls
    assert "login.keychain-db" in calls and "edge-ca.crt" in calls
    assert "Edge CA trusted" in done.stdout


def test_interactive_no_prints_the_command_instead(tmp_path):
    done = _run(tmp_path, tty=True, answer="n")
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert" not in _calls(tmp_path)
    assert "security add-trusted-cert" in done.stderr
