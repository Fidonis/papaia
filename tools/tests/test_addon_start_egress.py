"""`papaia-ctl addon start <addon>` joins papaia-egress to the add-on's egress network.

The core override that attaches the proxy (`docker-compose.<addon>.egress.override.yml`)
can only be used once the add-on's network exists, that is after the add-on's first
start. Without this step the add-on's way out would stay closed until the next core
`start`. py_cli and docker are replaced by functions: docker logs its arguments and
answers `network inspect` for the networks that exist; py_cli answers
`override-external-nets` from a `<override>.nets` file next to each override.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
LIFECYCLE_SH = TOOLS / "lib" / "sh" / "lifecycle.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
source "@LIFECYCLE@"
source "@ADDON@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@REPO@"
COMPOSE_FILE="@REPO@/src/docker-compose.yml"
info() { :; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { :; }
usage() { :; }
_require_setup_done() { :; }
_topology_mode() { echo "@MODE@"; }
_stopped_containers_go_stale() { return 1; }
_pull_quietly() { return 1; }
_addon_path() { echo "@ADDON_PATH@"; }
py_cli() {
    case "$1" in
        override-external-nets)
            local file="${2#--file=}"
            [ -f "$file.nets" ] && cat "$file.nets"
            return 0
            ;;
    esac
}
docker() {
    printf '%s|' "$@" >> "@LOG@"; echo >> "@LOG@"
    if [ "$1" = network ] && [ "$2" = inspect ]; then
        case " @EXISTING@ " in *" $3 "*) return 0 ;; esac
        return 1
    fi
    if [ "$1" = compose ] && [ "$2" = -f ]; then
        return @CORE_RC@
    fi
    return 0
}
"""


def _override(config: Path, name: str, nets: list[str]) -> Path:
    path = config / "overrides" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("services: {}\n", encoding="utf-8")
    (path.parent / f"{name}.nets").write_text("".join(f"{n}\n" for n in nets), encoding="utf-8")
    return path


WIKI_EGRESS = "docker-compose.wiki.egress.override.yml"


def _run(
    tmp_path: Path,
    *,
    existing: str = "papaia-wiki-egress",
    mode: str = "single",
    core_rc: int = 0,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    addon = tmp_path / "addons" / "wiki"
    addon.mkdir(parents=True, exist_ok=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@REPO@", tmp_path.as_posix())
        .replace("@ADDON_PATH@", addon.as_posix())
        .replace("@MODE@", mode)
        .replace("@EXISTING@", existing)
        .replace("@CORE_RC@", str(core_rc))
        .replace("@LOG@", log.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE_SH.as_posix())
    )
    done = subprocess.run(
        [BASH, "-c", f"{harness}\ncmd_addon_start wiki"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return done, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def _core_calls(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("compose|-f|")]


def test_the_proxy_joins_the_egress_network_once_the_addon_runs(tmp_path: Path) -> None:
    config = tmp_path / "config"
    # The network of this override does not exist: left out, as `start` does.
    _override(config, "docker-compose.paperless.override.yml", ["papaia-paperless-net"])
    attachment = _override(config, WIKI_EGRESS, ["papaia-wiki-egress"])

    done, calls = _run(tmp_path)

    assert done.returncode == 0, done.stderr
    addon_up = next(i for i, c in enumerate(calls) if c.startswith("compose|-p|wiki|"))
    core = _core_calls(calls)
    assert core == [
        f"compose|-f|{tmp_path}/src/docker-compose.yml|-f|{attachment}|"
        f"--env-file|{tmp_path}/src/.env|up|-d|--no-deps|papaia-egress|"
    ]
    # After the add-on's own `up`, which creates the network.
    assert calls.index(core[0]) > addon_up


def test_every_usable_core_override_is_kept_when_the_proxy_is_recreated(tmp_path: Path) -> None:
    config = tmp_path / "config"
    other = _override(config, "docker-compose.docs.egress.override.yml", ["papaia-docs-egress"])
    attachment = _override(config, WIKI_EGRESS, ["papaia-wiki-egress"])

    done, calls = _run(tmp_path, existing="papaia-docs-egress papaia-wiki-egress")

    assert done.returncode == 0, done.stderr
    assert _core_calls(calls) == [
        f"compose|-f|{tmp_path}/src/docker-compose.yml|-f|{other}|-f|{attachment}|"
        f"--env-file|{tmp_path}/src/.env|up|-d|--no-deps|papaia-egress|"
    ]


def test_an_addon_without_an_egress_network_leaves_the_core_alone(tmp_path: Path) -> None:
    _override(tmp_path / "config", "docker-compose.wiki.override.yml", ["papaia-wiki-net"])

    done, calls = _run(tmp_path, existing="papaia-wiki-net")

    assert done.returncode == 0, done.stderr
    assert _core_calls(calls) == []


def test_a_missing_egress_network_is_reported_and_nothing_is_recreated(tmp_path: Path) -> None:
    _override(tmp_path / "config", WIKI_EGRESS, ["papaia-wiki-egress"])

    done, calls = _run(tmp_path, existing="")

    assert done.returncode == 0, done.stderr
    assert _core_calls(calls) == []
    assert "papaia-ctl start" in done.stderr


def test_a_failed_join_is_reported_without_failing_the_addon_start(tmp_path: Path) -> None:
    _override(tmp_path / "config", WIKI_EGRESS, ["papaia-wiki-egress"])

    done, calls = _run(tmp_path, core_rc=1)

    assert done.returncode == 0, done.stderr
    assert len(_core_calls(calls)) == 1
    assert "papaia-ctl start" in done.stderr


def test_a_distributed_installation_is_left_to_its_nodes(tmp_path: Path) -> None:
    _override(tmp_path / "config", WIKI_EGRESS, ["papaia-wiki-egress"])

    _, calls = _run(tmp_path, mode="distributed")

    assert _core_calls(calls) == []
