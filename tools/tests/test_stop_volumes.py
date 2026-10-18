"""`papaia-ctl stop --clean-up --volumes --profiles=...`: deleting the data of an optional module.

Docker is replaced by a function that logs its calls, so what is checked is exactly which
`docker compose` command runs and which requests are refused before any runs. `down --volumes`
removes the containers' anonymous volumes with them (a Redis or Postgres image declares one),
which is why it has to be the same call that removes the containers.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
CTL = TOOLS / "papaia-ctl"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@DEFAULT@"
REPO_ROOT="@REPO@"
COMPOSE_FILE="@REPO@/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
info() { :; }
success() { echo "OK $*"; }
usage() { echo USAGE; }
_addon_compose_all() { echo "addons $*" >> "@LOG@"; }
docker() {
    echo "docker COMPOSE_PROFILES=${COMPOSE_PROFILES:-} $*" >> "@LOG@"
    case " $* " in *" config "*) echo "service" ;; esac
}
source "@LIFECYCLE@"
"""


def _stop(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    harness = (
        _HARNESS.replace("@DEFAULT@", (tmp_path / "config").as_posix())
        .replace("@REPO@", tmp_path.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
    )
    quoted = " ".join(f"'{a}'" for a in args)
    done = subprocess.run(
        [BASH, "-c", f"{harness}\ncmd_stop {quoted}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines()
    return done, [c for c in calls if " config --services" not in c]


@pytest.mark.parametrize("profile", ["localai", "librechat-websearch", "rag", "smtp"])
def test_volumes_are_deleted_with_the_containers_of_exactly_the_named_profile(
    tmp_path: Path, profile: str
) -> None:
    done, calls = _stop(tmp_path, "--clean-up", "--volumes", f"--profiles={profile}")

    assert done.returncode == 0, done.stderr
    assert len(calls) == 1
    assert calls[0].startswith(f"docker COMPOSE_PROFILES={profile} compose -f ")
    assert calls[0].endswith(" down --volumes")


def test_without_volumes_the_data_is_kept(tmp_path: Path) -> None:
    done, calls = _stop(tmp_path, "--clean-up", "--profiles=rag")

    assert done.returncode == 0, done.stderr
    assert calls[0].startswith("docker COMPOSE_PROFILES=rag compose")
    assert calls[0].endswith(" down")
    assert "--volumes" not in calls[0]


def test_several_optional_profiles_may_be_named_together(tmp_path: Path) -> None:
    done, calls = _stop(tmp_path, "--clean-up", "--volumes", "--profiles=localai,rag")

    assert done.returncode == 0, done.stderr
    assert calls[0].startswith("docker COMPOSE_PROFILES=localai,rag compose")


@pytest.mark.parametrize(
    "args",
    [
        ("--volumes",),
        ("--volumes", "--profiles=rag"),
        ("--clean-up", "--volumes"),
        ("--clean-up", "--volumes", "--profiles="),
    ],
)
def test_volumes_without_clean_up_and_profiles_is_refused_before_docker_runs(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    done, calls = _stop(tmp_path, *args)

    assert done.returncode == 2
    assert "--volumes needs --clean-up and --profiles" in done.stderr
    assert calls == []


@pytest.mark.parametrize(
    "profiles",
    ["manager", "keycloak", "librechat", "litellm", "nginx", "oauth2-proxy", "rag,keycloak", "x"],
)
def test_only_the_optional_modules_may_have_their_volumes_deleted(
    tmp_path: Path, profiles: str
) -> None:
    done, calls = _stop(tmp_path, "--clean-up", "--volumes", f"--profiles={profiles}")

    assert done.returncode == 2
    assert "limited to the optional modules" in done.stderr
    assert calls == []


def test_the_profiles_are_resolved_before_anything_is_deleted(tmp_path: Path) -> None:
    done, _ = _stop(tmp_path, "--clean-up", "--volumes", "--profiles=rag")

    log = (tmp_path / "docker.log").read_text(encoding="utf-8").splitlines()
    assert " config --services" in log[0]
    assert done.returncode == 0


def test_the_header_and_the_dispatcher_know_the_flag() -> None:
    header = CTL.read_text(encoding="utf-8")
    assert "[--clean-up [--volumes]]" in header
    assert "--volumes) volumes=1" in LIFECYCLE.read_text(encoding="utf-8")
