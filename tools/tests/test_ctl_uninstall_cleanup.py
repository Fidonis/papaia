"""`uninstall` deletes the configuration directory, including what containers wrote as root.

Nginx Proxy Manager writes `infra/nginx/nginx-data/` as root, so a plain `rm -rf` by a
non-root operator stopped there (Fidonis/papaia#300). The leftovers are now deleted by a
short-lived container, and when that fails the command names the path and how to remove it.

Hermetic: `docker` is a shell function. Its `run` stands in for a root container by making
the mounted directory writable and emptying it, so no daemon is needed. It refuses any mount
outside the test's own directory, and `HOME` points below it, so a broken guard fails a test
instead of emptying the user's files. A directory without write permission plays the
root-owned data, which does not work when the tests run as root.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from lib import node_shell

TOOLS = Path(__file__).resolve().parents[1]
SH = TOOLS / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = [
    pytest.mark.skipif(BASH is None, reason="bash is not available"),
    pytest.mark.skipif(os.name == "nt", reason="file modes are not meaningful here"),
    pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can delete anything"
    ),
]

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="/no/such/default"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/no-compose.yml"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo "USAGE"; }
is_tty() { return 1; }
_topology_mode() { echo single; }
docker() {
    echo "docker $*" >> "@LOG@"
    [ "${DOCKER_FAILS:-0}" -eq 1 ] && return 1
    local arg mount=""
    for arg in "$@"; do
        case "$arg" in *:/target) mount="${arg%:/target}" ;; esac
    done
    case "$mount" in "@ROOT@"/*) ;; *) return 1 ;; esac
    chmod -R u+w "$mount"
    find "$mount" -mindepth 1 -delete
}
source "@SH@/backup.sh"
source "@SH@/lifecycle.sh"
"""


def _run(tmp_path: Path, script: str, *, docker_fails: bool = False):
    assert BASH is not None
    log = tmp_path / "docker.log"
    harness = (
        _HARNESS.replace("@ROOT@", tmp_path.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@SH@", SH.as_posix())
    )
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": home.as_posix(), "DOCKER_FAILS": "1" if docker_fails else "0"}
    result = subprocess.run(
        [BASH, "-c", f"{harness}\n{script}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def _config(tmp_path: Path, *, root_owned: bool) -> Path:
    config = tmp_path / "config"
    data = config / "infra" / "nginx" / "nginx-data"
    data.mkdir(parents=True)
    (config / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    (data / "database.sqlite").write_text("x", encoding="utf-8")
    if root_owned:
        data.chmod(stat.S_IRUSR | stat.S_IXUSR)
    return config


@pytest.fixture(autouse=True)
def _writable_again(tmp_path: Path):
    yield
    for path in tmp_path.rglob("*"):
        if path.is_dir():
            path.chmod(stat.S_IRWXU)


def test_a_directory_the_operator_owns_is_deleted_without_a_container(tmp_path):
    config = _config(tmp_path, root_owned=False)

    result, calls = _run(tmp_path, f"_remove_config_dir '{config}'")

    assert result.returncode == 0, result.stderr
    assert not config.exists()
    assert calls == []


def test_root_owned_leftovers_are_deleted_through_a_container(tmp_path):
    config = _config(tmp_path, root_owned=True)

    result, calls = _run(tmp_path, f"_remove_config_dir '{config}'")

    assert result.returncode == 0, result.stderr
    assert not config.exists()
    [call] = calls
    physical = config.resolve().as_posix()
    assert call == (
        f"docker run --rm --network none -v {physical}:/target {node_shell.BACKUP_IMAGE} "
        "find /target -mindepth 1 -delete"
    )


def test_uninstall_completes_with_root_owned_leftovers(tmp_path):
    config = _config(tmp_path, root_owned=True)

    result, _ = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' -y")

    assert result.returncode == 0, result.stderr
    assert "OK: uninstall complete." in result.stdout
    assert not config.exists()


def test_a_failing_container_names_the_path_and_the_command(tmp_path):
    config = _config(tmp_path, root_owned=True)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' -y", docker_fails=True)

    assert result.returncode == 1
    assert "uninstall complete" not in result.stdout
    assert f"Remove what is left with: sudo rm -rf '{config}'" in result.stderr
    assert config.exists()
    assert len(calls) == 1


@pytest.mark.parametrize(
    "root", ["/", "//", "//tmp/.."], ids=["slash", "double-slash", "double-slash-dotdot"]
)
def test_the_root_directory_is_never_handed_to_a_container(tmp_path, root):
    result, calls = _run(tmp_path, f"rm() {{ return 0; }}; _remove_config_dir '{root}'")

    assert result.returncode == 1
    assert "is the root directory; refusing" in result.stderr
    assert "sudo rm" not in result.stderr
    assert calls == []


@pytest.mark.parametrize("home", ["config", "config/home"], ids=["equal", "below"])
def test_a_directory_with_the_home_directory_in_it_is_never_handed_to_a_container(
    tmp_path, home
):
    config = _config(tmp_path, root_owned=True)
    (tmp_path / home).mkdir(exist_ok=True)

    result, calls = _run(
        tmp_path, f"HOME='{tmp_path / home}'; rm() {{ return 0; }}; _remove_config_dir '{config}'"
    )

    assert result.returncode == 1
    assert "contains the home directory; refusing" in result.stderr
    assert "sudo rm" not in result.stderr
    assert calls == []
    assert (config / "infra" / "nginx" / "nginx-data" / "database.sqlite").exists()


@pytest.mark.parametrize(
    ("config_prefix", "home_prefix"), [("/", ""), ("", "/")], ids=["config", "home"]
)
def test_a_leading_double_slash_does_not_hide_the_home_directory(
    tmp_path, config_prefix, home_prefix
):
    # `pwd -P` keeps a leading `//`, which Docker mounts as `/`.
    config = _config(tmp_path, root_owned=True)

    result, calls = _run(
        tmp_path,
        f"HOME='{home_prefix}{config}'; rm() {{ return 0; }}; "
        f"_remove_config_dir '{config_prefix}{config}'",
    )

    assert result.returncode == 1
    assert "contains the home directory; refusing" in result.stderr
    assert calls == []


def test_a_directory_with_the_checkout_in_it_is_never_handed_to_a_container(tmp_path):
    config = _config(tmp_path, root_owned=True)
    (config / "checkout").mkdir()

    result, calls = _run(
        tmp_path,
        f"REPO_ROOT='{config / 'checkout'}'; rm() {{ return 0; }}; _remove_config_dir '{config}'",
    )

    assert result.returncode == 1
    assert "contains the papaia checkout; refusing" in result.stderr
    assert calls == []


def test_a_home_directory_next_to_the_config_dir_is_no_reason_to_refuse(tmp_path):
    config = _config(tmp_path, root_owned=True)
    (tmp_path / "config-home").mkdir()

    result, calls = _run(
        tmp_path, f"HOME='{tmp_path / 'config-home'}'; _remove_config_dir '{config}'"
    )

    assert result.returncode == 0, result.stderr
    assert not config.exists()
    assert len(calls) == 1
