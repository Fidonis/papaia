"""Local CA and Keycloak certificate generation in tools/lib/sh/certs.sh (#284, #289)."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SH_LIB = Path(__file__).resolve().parents[1] / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = [
    pytest.mark.skipif(BASH is None, reason="bash is not available"),
    pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not available"),
]


def _ensure(config_dir: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    assert BASH is not None
    script = (
        f'set -euo pipefail; source "{SH_LIB / "log.sh"}"; source "{SH_LIB / "certs.sh"}"; '
        f'CONFIG_DIR="{config_dir}"; _ensure_keycloak_certs'
    )
    return subprocess.run(
        [BASH, "-c", script], env=env, capture_output=True, text=True, check=False
    )


def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _days_left(cert: Path) -> int:
    for days in (826, 825, 824, 30):
        if subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-checkend", str(days * 86400)],
            capture_output=True,
            check=False,
        ).returncode == 0:
            return days
    return 0


def _sign_old_style(certs: Path, days: int, extensions: str) -> None:
    """Re-sign the Keycloak key the way an earlier release did, or close to its end."""
    ext = certs / "old.ext"
    ext.write_text(extensions, encoding="utf-8")
    csr = certs / "old.csr"
    openssl("req", "-new", "-key", str(certs / "keycloak.key"), "-out", str(csr),
            "-subj", "/CN=keycloak/O=papAIa")  # fmt: skip
    openssl("x509", "-req", "-in", str(csr), "-CA", str(certs / "local-ca.crt"),
            "-CAkey", str(certs / "local-ca.key"), "-CAcreateserial",
            "-out", str(certs / "keycloak.crt"), "-days", str(days),
            "-extfile", str(ext))  # fmt: skip
    for leftover in (ext, csr, certs / "local-ca.srl"):
        leftover.unlink(missing_ok=True)


def test_a_new_server_certificate_is_accepted_by_strict_tls_clients(tmp_path):
    done = _ensure(tmp_path)
    assert done.returncode == 0, done.stderr
    certs = tmp_path / "certs"
    crt = certs / "keycloak.crt"
    text = openssl("x509", "-in", str(crt), "-noout", "-text")
    assert "TLS Web Server Authentication" in text
    assert "Digital Signature, Key Encipherment" in text
    assert "CA:FALSE" in text
    assert "DNS:keycloak, DNS:localhost, DNS:host.docker.internal" in text
    assert _days_left(crt) == 824  # valid for 825 days, not 826
    assert openssl("verify", "-CAfile", str(certs / "local-ca.crt"), str(crt)).strip().endswith(
        "OK"
    )
    assert sorted(p.name for p in certs.iterdir()) == [
        "keycloak.crt",
        "keycloak.key",
        "local-ca.crt",
        "local-ca.key",
    ]


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="file modes are not POSIX on Windows")
def test_the_ca_key_is_readable_by_its_owner_only(tmp_path):
    assert _ensure(tmp_path).returncode == 0
    certs = tmp_path / "certs"
    assert _mode(certs / "local-ca.key") == 0o600
    assert _mode(certs / "local-ca.crt") == 0o644
    # Keycloak reads its own key inside the container as another user.
    assert _mode(certs / "keycloak.key") == 0o644


@pytest.mark.skipif(os.name == "nt", reason="file modes are not POSIX on Windows")
def test_a_world_readable_ca_key_from_an_earlier_setup_is_closed(tmp_path):
    assert _ensure(tmp_path).returncode == 0
    key = tmp_path / "certs" / "local-ca.key"
    key.chmod(0o644)
    before = _digest(key)
    done = _ensure(tmp_path)
    assert done.returncode == 0, done.stderr
    assert "already present" in done.stdout
    assert _mode(key) == 0o600
    assert _digest(key) == before


def test_a_new_ca_signs_for_keycloaks_names_only(tmp_path):
    assert _ensure(tmp_path).returncode == 0
    certs = tmp_path / "certs"
    text = openssl("x509", "-in", str(certs / "local-ca.crt"), "-noout", "-text")
    assert "X509v3 Name Constraints: critical" in text
    for name in ("DNS:keycloak", "DNS:localhost", "DNS:host.docker.internal"):
        assert name in text
    # A certificate the CA key issues for another domain fails verification.
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    openssl("genrsa", "-out", str(foreign / "f.key"), "2048")
    openssl("req", "-new", "-key", str(foreign / "f.key"), "-out", str(foreign / "f.csr"),
            "-subj", "/CN=www.example.com")  # fmt: skip
    (foreign / "f.ext").write_text("subjectAltName=DNS:www.example.com\n", encoding="utf-8")
    openssl("x509", "-req", "-in", str(foreign / "f.csr"), "-CA", str(certs / "local-ca.crt"),
            "-CAkey", str(certs / "local-ca.key"), "-CAcreateserial",
            "-out", str(foreign / "f.crt"), "-days", "30",
            "-extfile", str(foreign / "f.ext"))  # fmt: skip
    done = subprocess.run(
        ["openssl", "verify", "-CAfile", str(certs / "local-ca.crt"), str(foreign / "f.crt")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode != 0
    assert "permitted subtree violation" in done.stdout + done.stderr


@pytest.mark.parametrize(
    "days,extensions",
    [
        # What releases up to 1.7.0 issued: ten years, SAN only.
        (3650, "subjectAltName=DNS:keycloak,DNS:localhost,DNS:host.docker.internal\n"),
        # Current shape, but about to run out.
        (10, "subjectAltName=DNS:keycloak\nextendedKeyUsage=serverAuth\n"),
    ],
)
def test_an_outdated_server_certificate_is_renewed_under_the_same_ca(tmp_path, days, extensions):
    assert _ensure(tmp_path).returncode == 0
    certs = tmp_path / "certs"
    _sign_old_style(certs, days, extensions)
    names = ("local-ca.crt", "local-ca.key", "keycloak.key")
    kept = {name: _digest(certs / name) for name in names}

    done = _ensure(tmp_path)

    assert done.returncode == 0, done.stderr
    assert "Renewing the Keycloak TLS certificate" in done.stdout
    assert "papaia-ctl stop" in done.stderr
    assert {name: _digest(certs / name) for name in kept} == kept
    crt = certs / "keycloak.crt"
    assert "TLS Web Server Authentication" in openssl("x509", "-in", str(crt), "-noout", "-text")
    assert _days_left(crt) == 824


def test_a_current_certificate_is_left_alone(tmp_path):
    assert _ensure(tmp_path).returncode == 0
    crt = tmp_path / "certs" / "keycloak.crt"
    before = _digest(crt)
    done = _ensure(tmp_path)
    assert done.returncode == 0
    assert "already present" in done.stdout
    assert _digest(crt) == before


def test_a_failing_openssl_step_is_named_with_its_error(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    stub = fake / "openssl"
    stub.write_text('#!/bin/sh\necho "req: Unknown option -addext" >&2\nexit 1\n', encoding="utf-8")
    stub.chmod(0o755)
    env = {"PATH": f"{fake}:/usr/bin:/bin"}

    done = _ensure(tmp_path / "cfg", env)

    assert done.returncode == 2
    assert "Certificate generation failed: local CA key." in done.stderr
    assert "openssl: req: Unknown option -addext" in done.stderr
