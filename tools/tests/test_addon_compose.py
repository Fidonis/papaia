"""`_addon_compose`: an addon whose `docker-compose.yml` is gone must not reach the core stack.

With the file missing, compose cannot build the project and `stop`/`down` fall back to
project-name-only mode, where the `COMPOSE_PROJECT_NAME` of the root `.env` beats `-p`: the call
then stops or removes the core stack instead of the addon. Docker is replaced by a function that
logs its arguments and the `COMPOSE_*` variables it sees, so what is checked is exactly which
`docker compose` command runs and that none runs when the request is refused.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
CONFIG_DIR="@CONFIG@"
REPO_ROOT="@REPO@"
info() { :; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
py_cli() { :; }
docker() {
    echo "docker $* | project=${COMPOSE_PROJECT_NAME:-} file=${COMPOSE_FILE:-}" \\
        "profiles=${COMPOSE_PROFILES:-}" >> "@LOG@"
}
_topology_mode() { echo single; }
source "@ADDON@"
# What a caller could have exported: the core stack's own settings.
export COMPOSE_PROJECT_NAME=papaia COMPOSE_FILE=/core/docker-compose.yml COMPOSE_PROFILES=rag
"""


def _run(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@REPO@", tmp_path.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
    )
    quoted = " ".join(f"'{a}'" for a in args)
    done = subprocess.run(
        [BASH, "-c", f"{harness}\n_addon_compose {quoted}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return done, log.read_text(encoding="utf-8").splitlines()


def _addon(tmp_path: Path, *, compose: bool) -> Path:
    path = tmp_path / "addons" / "n8n"
    path.mkdir(parents=True)
    if compose:
        (path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    return path


def test_with_the_compose_file_the_call_stays_pinned_to_the_addon_project(
    tmp_path: Path,
) -> None:
    addon = _addon(tmp_path, compose=True)

    done, calls = _run(tmp_path, "down", "n8n", addon.as_posix(), "-v")

    assert done.returncode == 0, done.stderr
    assert len(calls) == 1
    assert calls[0].startswith(
        f"docker compose -p n8n -f {addon.as_posix()}/docker-compose.yml"
        f" --env-file {tmp_path.as_posix()}/src/.env down -v |"
    )


@pytest.mark.parametrize("verb", ["stop", "down"])
def test_without_the_compose_file_the_addon_is_addressed_by_its_name_alone(
    tmp_path: Path, verb: str
) -> None:
    addon = _addon(tmp_path, compose=False)

    done, calls = _run(tmp_path, verb, "n8n", addon.as_posix())

    assert done.returncode == 0, done.stderr
    # No -f and no --env-file: the root .env, whose COMPOSE_PROJECT_NAME is the core
    # stack's, never reaches compose. The exported COMPOSE_* variables do not either.
    assert calls == [f"docker compose -p n8n {verb} | project= file= profiles="]
    assert "docker-compose.yml not found" in done.stderr


def test_the_extra_flags_of_a_teardown_are_kept(tmp_path: Path) -> None:
    addon = _addon(tmp_path, compose=False)

    done, calls = _run(tmp_path, "down", "n8n", addon.as_posix(), "-v")

    assert done.returncode == 0, done.stderr
    assert calls == ["docker compose -p n8n down -v | project= file= profiles="]


@pytest.mark.parametrize("verb", ["up", "config", "logs"])
def test_a_verb_that_needs_the_compose_file_is_refused_without_it(
    tmp_path: Path, verb: str
) -> None:
    addon = _addon(tmp_path, compose=False)

    done, calls = _run(tmp_path, verb, "n8n", addon.as_posix())

    assert done.returncode == 1
    assert calls == []
    assert f"Cannot run 'docker compose {verb}'" in done.stderr


@pytest.mark.parametrize("path", ["", "/", "."])
def test_no_project_name_can_be_made_of_an_unusable_path(tmp_path: Path, path: str) -> None:
    _addon(tmp_path, compose=False)

    done, calls = _run(tmp_path, "down", "n8n", path)

    assert done.returncode == 1
    assert calls == []
    assert "Cannot tell which containers belong to addon n8n" in done.stderr
