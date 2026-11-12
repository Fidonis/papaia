"""The macOS steps after the Keycloak certificates (`_macos_local_tls_steps`, #298)."""

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
    auth_host: str = "https://host.docker.internal:8110",
    trusted: bool = False,
    resolves: bool = True,
    tty: bool = False,
    non_interactive: int = 0,
    answer: str = "",
) -> subprocess.CompletedProcess:
    assert BASH is not None
    (config_dir / "certs").mkdir(parents=True, exist_ok=True)
    (config_dir / "certs" / "local-ca.crt").write_text("ca\n")
    (config_dir / ".env").write_text(f"PAPAIA_HOST=http://localhost\nAUTH_HOST={auth_host}\n")
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
        "dscacheutil() {\n"
        # A long answer, as a real one can be: a reader that quits early must not turn
        # the pipe's SIGPIPE into "does not resolve" under pipefail.
        f"    {'echo ip_address: 127.0.0.1; seq 1 20000' if resolves else 'true'}\n"
        "}\n"
        f"_macos_local_tls_steps {non_interactive}\n"
    )
    return subprocess.run(
        [BASH, "-c", script], input=answer + "\n", capture_output=True, text=True, check=False
    )


def _calls(config_dir: Path) -> str:
    calls = config_dir / "calls"
    return calls.read_text() if calls.exists() else ""


def test_does_nothing_off_macos(tmp_path):
    done = _run(tmp_path, system="Linux", resolves=False)
    assert done.returncode == 0, done.stderr
    assert _calls(tmp_path) == ""
    assert done.stderr == ""


def test_does_nothing_for_a_public_auth_host(tmp_path):
    done = _run(tmp_path, auth_host="https://auth.example.com", resolves=False)
    assert done.returncode == 0, done.stderr
    assert _calls(tmp_path) == ""


def test_silent_when_the_ca_is_trusted_and_the_host_resolves(tmp_path):
    done = _run(tmp_path, trusted=True)
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert" not in _calls(tmp_path)
    assert "Run:" not in done.stderr


def test_non_interactive_prints_the_trust_command(tmp_path):
    done = _run(tmp_path, non_interactive=1)
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert" not in _calls(tmp_path)
    assert "security add-trusted-cert -r trustRoot -p ssl -k" in done.stderr
    assert str(tmp_path / "certs" / "local-ca.crt") in done.stderr


def test_interactive_yes_trusts_the_ca_in_the_login_keychain(tmp_path):
    done = _run(tmp_path, tty=True, answer="y")
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert -r trustRoot -p ssl -k" in _calls(tmp_path)
    assert "login.keychain-db" in _calls(tmp_path)
    assert "Local CA trusted" in done.stdout


def test_interactive_no_prints_the_command_instead(tmp_path):
    done = _run(tmp_path, tty=True, answer="n")
    assert done.returncode == 0, done.stderr
    assert "add-trusted-cert" not in _calls(tmp_path)
    assert "security add-trusted-cert" in done.stderr


def test_trust_is_checked_under_the_tls_policy_with_keycloaks_certificate(tmp_path):
    # A trust limited to TLS does not show when the CA alone is checked under the default
    # (basic) policy, so the step would ask again on every run.
    done = _run(tmp_path, trusted=True)
    assert done.returncode == 0, done.stderr
    certs = tmp_path / "certs"
    assert (
        f"security verify-cert -c {certs / 'keycloak.crt'} -c {certs / 'local-ca.crt'} -p ssl -L"
        in _calls(tmp_path)
    )


def test_a_long_resolver_answer_counts_as_resolving(tmp_path):
    done = _run(tmp_path, trusted=True, resolves=True)
    assert done.returncode == 0, done.stderr
    assert "/etc/hosts" not in done.stderr


def test_reports_a_missing_hosts_entry(tmp_path):
    done = _run(tmp_path, trusted=True, resolves=False)
    assert done.returncode == 0, done.stderr
    assert 'echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts' in done.stderr


def test_no_hosts_hint_for_localhost(tmp_path):
    done = _run(tmp_path, auth_host="https://localhost:8110", trusted=True, resolves=False)
    assert done.returncode == 0, done.stderr
    assert "/etc/hosts" not in done.stderr
