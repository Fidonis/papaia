"""The CA bundle LiteLLM builds before it starts.

The startup command is taken from the compose file as compose hands it to `sh -c`, with its
two paths moved into a temporary directory and stand-ins for `python` and `litellm` on the
PATH. `certs/local-ca.crt` exists only with the bundled Keycloak: with an external OIDC
provider the command has to start LiteLLM on the public roots alone.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "ai" / "litellm" / "docker-compose.yml"
BUNDLE = "/tmp/ca-bundle.crt"
PUBLIC_ROOTS = "public roots\n"
LOCAL_CA = "local ca\n"


def _litellm() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["litellm"]


def _start(root: Path) -> subprocess.CompletedProcess[str]:
    """Run the startup command. The stand-in for `python` writes the public roots to the
    bundle, the one for `litellm` leaves a marker."""
    service = _litellm()
    assert service["entrypoint"] == ["/bin/sh", "-c"]
    script = service["command"][0].replace("$$", "$")
    script = script.replace(BUNDLE, f"{root.as_posix()}/ca-bundle.crt")
    script = script.replace("/certs/", f"{root.as_posix()}/certs/")

    bin_dir = root / "bin"
    bin_dir.mkdir()
    stand_ins = {
        "python": f"printf '{PUBLIC_ROOTS.strip()}\\n' > '{root.as_posix()}/ca-bundle.crt'",
        "litellm": f": > '{root.as_posix()}/started'",
    }
    for name, body in stand_ins.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8", newline="\n")
        path.chmod(0o755)

    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(
        ["sh", "-c", script], capture_output=True, text=True, timeout=30, check=False, env=env
    )


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    path = tmp_path / "certs"
    path.mkdir()
    return path


def test_starts_on_the_public_roots_without_a_local_ca(tmp_path: Path, certs: Path) -> None:
    result = _start(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "started").is_file()
    assert (tmp_path / "ca-bundle.crt").read_text() == PUBLIC_ROOTS


def test_appends_the_local_ca_to_the_public_roots(tmp_path: Path, certs: Path) -> None:
    (certs / "local-ca.crt").write_text(LOCAL_CA, encoding="utf-8", newline="\n")

    result = _start(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "started").is_file()
    assert (tmp_path / "ca-bundle.crt").read_text() == PUBLIC_ROOTS + LOCAL_CA


def test_does_not_start_when_the_local_ca_cannot_be_read(tmp_path: Path, certs: Path) -> None:
    # A directory stands in for an unreadable file, which root could still read.
    (certs / "local-ca.crt").mkdir()

    result = _start(tmp_path)

    assert result.returncode != 0
    assert not (tmp_path / "started").exists()


def test_python_is_pointed_at_the_bundle() -> None:
    assert _litellm()["environment"]["SSL_CERT_FILE"] == BUNDLE
