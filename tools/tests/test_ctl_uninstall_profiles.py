"""`uninstall --clean-up` removes the volumes and networks of every profile, also switched-off ones.

A plain `docker compose down -v` only knows the services of the profiles enabled in the
env file. A profile that was switched off before (stop, then the profile disabled) is not in
the Compose model, so its named volumes stayed: on a test run `<project>_connections-db` and
`<project>_connections-keys` (the registry's keys) were left after the connection registry had
been switched off. The command now takes the core down with every declared profile and the
core overrides, then removes whatever still carries the project label of this installation,
and nothing without it.

Hermetic: `docker` and `py_cli` are shell functions. The `docker` stub records each call
together with the COMPOSE_PROFILES it saw, answers `config` and `ls` from fixed lists, and
ignores `--filter`, so the command must pick its own project's resources itself. Like a
real installation, its `config` fails with every profile on (the env files of profiles never
set up are missing), so the project name is read from the env file, not asked from `config`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
SH = TOOLS / "lib" / "sh"
BASH = shutil.which("bash")

pytestmark = [
    pytest.mark.skipif(BASH is None, reason="bash is not available"),
    pytest.mark.skipif(os.name == "nt", reason="bash harness"),
]

PROJECT = "papaia-itest"
DECLARED_PROFILES = ["connections", "keycloak", "me", "nginx"]

VOLUMES = [
    (PROJECT, f"{PROJECT}_connections-db"),
    (PROJECT, f"{PROJECT}_connections-keys"),
    ("papaia-other", "papaia-other_connections-keys"),
    (f"{PROJECT}-2", f"{PROJECT}-2_keycloak-db"),
    ("", f"{PROJECT}_handmade"),
]
NETWORKS = [
    (PROJECT, f"{PROJECT}_connections-net"),
    ("papaia-other", "papaia-other_default"),
    ("", "papaia-addon-net"),
]

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="/no/such/default"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/src/docker-compose.yml"
BACKUP_IMAGE="unused"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo "USAGE"; }
is_tty() { return 1; }
_topology_mode() { echo single; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    case "$1" in
        override-external-nets) echo "papaia-addon-net" ;;
    esac
    return 0
}
docker() {
    printf 'COMPOSE_PROFILES=%s docker %s\\n' "${COMPOSE_PROFILES-<unset>}" "$*" >> "@LOG@"
    case "$*" in
        "compose "*" config --profiles") printf '%s\\n' @PROFILES@ ;;
        "compose "*" config")
            # The env files of a profile that was never set up do not exist: Compose
            # cannot render the model with every profile on.
            if [ -n "${COMPOSE_PROFILES+set}" ]; then
                echo "env file @ROOT@/src/ai/jinaai/.env not found" >&2
                return 15
            fi
            printf 'name: papaia-itest\\nservices: {}\\n'
            ;;
        "compose "*) return 0 ;;
        "volume ls"*) printf '%b' "$STUB_VOLUMES" ;;
        "network ls"*) printf '%b' "$STUB_NETWORKS" ;;
        "network inspect"*) return 0 ;;
        "volume rm "*|"network rm "*)
            local target="${*: -1}"
            case " ${STUB_FAIL_RM:-} " in
                *" $target "*) echo "Error response from daemon: $target is in use" >&2; return 1 ;;
            esac
            echo "$target"
            ;;
        *) return 0 ;;
    esac
}
source "@SH@/backup.sh"
source "@SH@/lifecycle.sh"
"""


def _lines(pairs: list[tuple[str, str]]) -> str:
    return "".join(f"{label}\\t{name}\\n" for label, name in pairs)


def _setup(
    tmp_path: Path, project_line: str = f"COMPOSE_PROJECT_NAME={PROJECT}"
) -> tuple[Path, Path]:
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (src / ".env").write_text(
        f"# core\nCOMPOSE_PROJECT_NAME=papaia-old\n{project_line}\n"
        "COMPOSE_PROFILES=keycloak,nginx\n",
        encoding="utf-8",
    )
    config = tmp_path / "config"
    (config / "overrides").mkdir(parents=True)
    (config / ".env").write_text(f"COMPOSE_PROJECT_NAME={PROJECT}\n", encoding="utf-8")
    override = config / "overrides" / "docker-compose.paperless.override.yml"
    override.write_text("services: {}\n", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    return config, override


def _run(tmp_path: Path, script: str, *, fail_rm: str = ""):
    assert BASH is not None
    log = tmp_path / "docker.log"
    harness = (
        _HARNESS.replace("@ROOT@", tmp_path.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@SH@", SH.as_posix())
        .replace("@PROFILES@", " ".join(DECLARED_PROFILES))
    )
    env = {
        **os.environ,
        "HOME": (tmp_path / "home").as_posix(),
        "STUB_VOLUMES": _lines(VOLUMES),
        "STUB_NETWORKS": _lines(NETWORKS),
        "STUB_FAIL_RM": fail_rm,
    }
    env.pop("COMPOSE_PROFILES", None)
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


def _docker_calls(calls: list[str]) -> list[str]:
    return [c for c in calls if " docker " in f" {c}"]


def _removals(calls: list[str]) -> list[str]:
    return [c.split(" docker ", 1)[1] for c in calls if " rm " in c and " docker " in c]


def test_clean_up_takes_the_core_down_with_every_profile_and_the_overrides(tmp_path):
    config, override = _setup(tmp_path)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 0, result.stderr
    compose = tmp_path / "src" / "docker-compose.yml"
    env_file = tmp_path / "src" / ".env"
    downs = [c for c in calls if " compose " in c and " down" in c]
    assert downs == [
        f"COMPOSE_PROFILES={','.join(DECLARED_PROFILES)} docker compose -f {compose} "
        f"-f {override} --env-file {env_file} down -v --remove-orphans"
    ]


def test_clean_up_removes_every_volume_and_network_of_the_project_after_down(tmp_path):
    config, _ = _setup(tmp_path)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 0, result.stderr
    assert sorted(_removals(calls)) == sorted(
        [
            f"volume rm {PROJECT}_connections-db",
            f"volume rm {PROJECT}_connections-keys",
            f"network rm {PROJECT}_connections-net",
        ]
    )
    docker = _docker_calls(calls)
    down_at = next(i for i, c in enumerate(docker) if " down" in c)
    first_rm = next(i for i, c in enumerate(docker) if " rm " in c)
    assert down_at < first_rm
    for name in (
        f"{PROJECT}_connections-db",
        f"{PROJECT}_connections-keys",
        f"{PROJECT}_connections-net",
    ):
        assert name in result.stdout
    assert "OK: uninstall complete." in result.stdout
    assert not config.exists()


def test_the_listings_ask_for_the_project_label(tmp_path):
    config, _ = _setup(tmp_path)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 0, result.stderr
    label = f"label=com.docker.compose.project={PROJECT}"
    listings = [c for c in calls if " volume ls" in c or " network ls" in c]
    assert len(listings) == 2
    assert all(label in c for c in listings)


@pytest.mark.parametrize(
    "line, project",
    [
        (f"COMPOSE_PROJECT_NAME={PROJECT}", PROJECT),
        (f'  COMPOSE_PROJECT_NAME = "{PROJECT}"  ', PROJECT),
        (f"COMPOSE_PROJECT_NAME='{PROJECT}'\r", PROJECT),
        ("COMPOSE_PROJECT_NAME=", "papaia"),
    ],
)
def test_the_project_is_the_env_files_compose_project_name(tmp_path, line, project):
    # The last line wins, as in lib/common.py; an empty value means the default "papaia".
    # `config` is not asked: with every profile on it needs env files of profiles never
    # set up (the stub fails it then, as Compose does).
    config, _ = _setup(tmp_path, line)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 0, result.stderr
    listings = [c for c in calls if " volume ls" in c or " network ls" in c]
    assert listings
    assert all(f"label=com.docker.compose.project={project} " in c for c in listings)
    assert not any(" compose " in c and c.endswith(" config") for c in calls)


def test_resources_of_other_projects_and_unlabelled_ones_are_untouched(tmp_path):
    config, _ = _setup(tmp_path)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 0, result.stderr
    removed = " ".join(_removals(calls))
    for name in (
        "papaia-other_connections-keys",
        f"{PROJECT}-2_keycloak-db",
        f"{PROJECT}_handmade",
        "papaia-other_default",
        "papaia-addon-net",
    ):
        assert name not in removed
    assert not any("prune" in c for c in calls)


def test_a_resource_that_cannot_be_removed_fails_with_its_name_and_command(tmp_path):
    config, _ = _setup(tmp_path)

    result, calls = _run(
        tmp_path,
        f"cmd_uninstall --config-dir='{config}' --clean-up -y",
        fail_rm=f"{PROJECT}_connections-keys",
    )

    assert result.returncode == 1
    assert "uninstall complete" not in result.stdout
    assert f"{PROJECT}_connections-keys" in result.stderr
    assert f"docker volume rm {PROJECT}_connections-keys" in result.stderr
    # The others are still removed, and the configuration stays for a second run.
    assert f"volume rm {PROJECT}_connections-db" in _removals(calls)
    assert f"network rm {PROJECT}_connections-net" in _removals(calls)
    assert config.exists()


@pytest.mark.parametrize("name", ["Bad Name", "papaia;rm", "-papaia"])
def test_a_project_name_compose_would_not_accept_is_refused(tmp_path, name):
    config, _ = _setup(tmp_path, f"COMPOSE_PROJECT_NAME={name}")

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' --clean-up -y")

    assert result.returncode == 1
    assert _removals(calls) == []
    assert not any(" volume ls" in c or " network ls" in c for c in calls)
    assert config.exists()


def test_uninstall_without_clean_up_keeps_its_behaviour(tmp_path):
    config, _ = _setup(tmp_path)

    result, calls = _run(tmp_path, f"cmd_uninstall --config-dir='{config}' -y")

    assert result.returncode == 0, result.stderr
    compose = tmp_path / "src" / "docker-compose.yml"
    env_file = tmp_path / "src" / ".env"
    assert _docker_calls(calls) == [
        f"COMPOSE_PROFILES=<unset> docker compose -f {compose} --env-file {env_file} down"
    ]
    assert not config.exists()
