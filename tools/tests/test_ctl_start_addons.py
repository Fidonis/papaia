"""`start --addons` and the Keycloak clients of the add-ons.

`start` runs `addon-start` for every active add-on before the core's `docker compose up`,
when Keycloak may not be up yet (a cold start). The managed clients of the add-ons are
created by the `keycloak-role-sync` step after `up`, so `addon-start` is called with
`--no-keycloak` there and only fills in their secrets.

Hermetic: `py_cli`, `docker` and the add-on helpers are stubs that record their calls.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
BASH = shutil.which("bash")

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
_addon_path() { echo "/addons/$1"; }
_addon_compose_up() { echo "compose-up $1"; }
docker() { :; }
py_cli() {
    echo "py_cli $*"
    if [ "$1" = "active-addons" ]; then echo wiki; fi
}
cmd_start --addons
"""


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_start_leaves_the_addon_clients_to_its_keycloak_step(tmp_path):
    harness = _HARNESS.replace("@CONFIG@", tmp_path.as_posix())
    harness = harness.replace("@LIFECYCLE@", LIFECYCLE.as_posix())
    result = subprocess.run(
        [BASH, "-c", harness], capture_output=True, text=True, timeout=30, check=False
    )

    assert result.returncode == 0, result.stderr
    calls = result.stdout.splitlines()
    assert "py_cli addon-start --name=wiki --no-keycloak" in calls
    assert calls.index("py_cli addon-start --name=wiki --no-keycloak") < calls.index(
        "compose-up wiki"
    )
    # The step that creates the clients comes after the core's `up`.
    assert calls[-1] == "py_cli keycloak-role-sync"
