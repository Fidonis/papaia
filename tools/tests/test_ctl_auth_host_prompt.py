"""The Keycloak prompt's pre-fill for an app host the defaults did not know yet.

`setup` asks for the Keycloak URL after the app host. For a new app host, or on a fresh
config dir, it pre-fills `_derive_auth_default`, and Enter stores that value. It must be
what `setup -y` derives for the same app host, or `sticky_auth_host` takes the stored
value for a choice and keeps it on later runs. Checked with the real `py_cli` and no
Docker: the derivation is pure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lib import resolve

TOOLS = Path(__file__).resolve().parents[1]
SETUP = TOOLS / "lib" / "sh" / "setup.sh"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

APP_HOSTS = [
    "https://chat.example.org",
    "http://chat.example.org",
    "http://192.168.50.20",
    "http://localhost",
    "http://127.0.0.1",
    "http://host.docker.internal",
    "http://myhost",
]


def _prefill(app_host: str, port: str | None, tmp_path: Path, provider: str = "") -> str:
    assert BASH is not None
    port_line = f"KEYCLOAK_EXT_PORT={port}\n" if port else ""
    port_line += f"reverse_proxy_provider={provider}\n" if provider else ""
    script = (
        "set -euo pipefail\n"
        'py_cli() { "$PYTHON_BIN" -m lib.cli --repo-root "$REPO_ROOT" '
        '--config-dir "$CONFIG_DIR" "$@"; }\n'
        f'source "{SETUP.as_posix()}"\n'
        f"{port_line}"
        '_derive_auth_default "$APP_HOST"\n'
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(TOOLS),
        "PYTHON_BIN": sys.executable,
        "REPO_ROOT": str(TOOLS.parent),
        "CONFIG_DIR": str(tmp_path),
        "APP_HOST": app_host,
    }
    done = subprocess.run(
        [BASH, "-c", script], env=env, capture_output=True, text=True, timeout=30, check=False
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


@needs_bash
@pytest.mark.parametrize("app_host", APP_HOSTS)
@pytest.mark.parametrize("provider", ["", "no_proxy"])
def test_the_prompt_pre_fills_what_setup_derives(
    app_host: str, provider: str, tmp_path: Path
) -> None:
    # A fresh installation behind the bundled proxy (the default provider) gets the
    # edge name; every other case the port derivation, as `setup -y` does. A LAN address
    # without a domain keeps the port pre-fill: `setup` refuses it afterwards and asks
    # for INGRESS_DOMAIN.
    try:
        edge = resolve.edge_url_default(
            "auth", app_host, "papaia", {}, provider=provider or None, allow_direct=False
        )
    except resolve.NoEdgeDomain:
        edge = None
    expected = edge or resolve.derive_auth_host_default(app_host, "18334")
    assert _prefill(app_host, "18334", tmp_path, provider) == expected


@needs_bash
def test_without_a_known_port_the_prompt_uses_the_default_port(tmp_path: Path) -> None:
    assert _prefill("http://192.168.50.20", None, tmp_path) == "https://192.168.50.20:8110"


@needs_bash
def test_a_local_app_host_behind_the_bundled_proxy_gets_the_edge_name(tmp_path: Path) -> None:
    assert _prefill("http://host.docker.internal", None, tmp_path) == (
        "https://auth.papaia.localhost"
    )
