"""The identity service alone before the post-restore step, with the arguments of `start`.

A restore leaves the post-restore step pending; before any module starts, Keycloak and its
database come up alone (BE-17). In a scoped restore the rest of the stack keeps running, so
that step has to hand Compose the core project exactly as `start` does: the compose file,
the core overrides, the env file. Without the overrides Compose sees another definition of
a core network (with a subnet pool, the address block of the override is missing) and
recreates it under the services that still use it.

The shell tests run the real functions with `py_cli` and `docker` replaced by recording
stubs. The Compose test runs `docker compose config` (no daemon needed) on a real
installation set up with a subnet pool, once with the arguments of the Keycloak-alone step
and once with those of `start`.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest
from install_helpers import Installation, run_cli

from lib import subnet_pool
from tests.test_post_restore import (
    _HARNESS,
    ADDON_SH,
    BACKUP_SH,
    BASH,
    LIFECYCLE_SH,
    _bash,
    _marker,
    needs_bash,
)

APP_HOST = "--app-host=https://papaia.example.org"
POOL = "10.212.158.0/24"
BLOCK = 28


def _pending(config: Path) -> None:
    config.mkdir(parents=True, exist_ok=True)
    (config / "post-restore.pending").write_text("1790000000\n", encoding="utf-8")


def _overrides(config: Path) -> list[Path]:
    folder = config / "overrides"
    folder.mkdir(parents=True, exist_ok=True)
    files = [folder / subnet_pool.OVERRIDE, folder / "docker-compose.image-mirror.override.yml"]
    for path in files:
        path.write_text("networks: {}\n", encoding="utf-8")
    return sorted(files)


def _compose_calls(calls: list[str], verb: str) -> list[list[str]]:
    """The core compose calls of the log with `verb` (`up`, `config`), as argument lists."""
    found = []
    for line in calls:
        words = shlex.split(line)
        if words[:2] != ["docker", "compose"] or verb not in words:
            continue
        found.append(words)
    return found


def _files_and_env(words: list[str]) -> list[str]:
    """The `-f` files and the env file of one compose call, in order."""
    out = []
    for i, word in enumerate(words):
        if word in ("-f", "--env-file"):
            out += [word, words[i + 1]]
    return out


def _keycloak_up(calls: list[str]) -> list[str]:
    ups = [w for w in _compose_calls(calls, "up") if w[-1] == "keycloak"]
    assert len(ups) == 1, calls
    return ups[0]


# ─────────────────────────────────────────────────────────────────────────
# the arguments of every compose call of the step (recording docker stub)
# ─────────────────────────────────────────────────────────────────────────


@needs_bash
def test_every_compose_call_of_the_step_carries_the_core_overrides_and_env_file(tmp_path):
    _pending(tmp_path / "config")
    overrides = _overrides(tmp_path / "config")
    done, calls = _bash(tmp_path, "_post_restore_before_modules 0")
    assert done.returncode == 0, done.stderr
    expected = ["-f", (tmp_path / "root" / "src" / "docker-compose.yml").as_posix()]
    for path in overrides:
        expected += ["-f", path.as_posix()]
    expected += ["--env-file", (tmp_path / "root" / "src" / ".env").as_posix()]
    # config --services (is there a keycloak?), config --images (its images), up keycloak
    services = [w for w in _compose_calls(calls, "config") if "--services" in w]
    image_list = [w for w in _compose_calls(calls, "config") if "--images" in w]
    assert len(services) == 1 and len(image_list) == 1, calls
    for words in (services[0], image_list[0], _keycloak_up(calls)):
        assert _files_and_env(words) == expected, words
    assert _keycloak_up(calls)[-4:] == ["up", "-d", "--no-recreate", "keycloak"]


@needs_bash
@pytest.mark.parametrize("command", ["cmd_start", "cmd_start --addons", "cmd_start --no-addons"])
def test_keycloak_alone_gets_the_same_files_as_the_start_that_follows(tmp_path, command):
    _pending(tmp_path / "config")
    overrides = _overrides(tmp_path / "config")
    done, calls = _bash(tmp_path, command, real_start=True)
    assert done.returncode == 0, done.stderr
    stack_up = [w for w in _compose_calls(calls, "up") if w[-1] != "keycloak"]
    assert len(stack_up) == 1, calls
    alone = _files_and_env(_keycloak_up(calls))
    assert alone == _files_and_env(stack_up[0])
    assert all(path.as_posix() in alone for path in overrides)


@needs_bash
def test_a_scoped_restore_starts_keycloak_alone_with_the_core_overrides(tmp_path):
    overrides = _overrides(tmp_path / "config")
    done, calls = _bash(tmp_path, "cmd_restore -y --only=volume:papaia_v", real_start=True)
    assert done.returncode == 0, done.stderr
    alone = _files_and_env(_keycloak_up(calls))
    assert all(path.as_posix() in alone for path in overrides), alone
    assert alone[-2:] == ["--env-file", (tmp_path / "root" / "src" / ".env").as_posix()]
    assert not _marker(tmp_path).exists()


@needs_bash
def test_an_override_whose_add_on_network_is_missing_stays_out_of_the_step(tmp_path):
    """Keycloak starts before any add-on: an add-on network that does not exist yet would
    fail its `up`, so the override that declares it waits for the next start."""
    _pending(tmp_path / "config")
    folder = tmp_path / "config" / "overrides"
    folder.mkdir(parents=True)
    (folder / "docker-compose.flow.override.yml").write_text("networks: {}\n", encoding="utf-8")
    (folder / subnet_pool.OVERRIDE).write_text("networks: {}\n", encoding="utf-8")
    body = (
        'docker() { echo "docker $*" >> "' + (tmp_path / "calls.log").as_posix() + '";'
        ' case "$*" in "network inspect flow-net") return 1 ;;'
        ' *"config --services"*) echo keycloak ;; esac; }\n'
        "py_cli() { case \"$1\" in override-external-nets)"
        ' case "$2" in *flow*) echo flow-net ;; esac ;; esac; return 0; }\n'
        "_post_restore_before_modules 0"
    )
    done, calls = _bash(tmp_path, body)
    assert done.returncode == 0, done.stderr
    alone = _files_and_env(_keycloak_up(calls))
    assert (folder / subnet_pool.OVERRIDE).as_posix() in alone
    assert (folder / "docker-compose.flow.override.yml").as_posix() not in alone


# ─────────────────────────────────────────────────────────────────────────
# the network definitions Compose derives (docker compose config, no daemon)
# ─────────────────────────────────────────────────────────────────────────


def _compose_available() -> bool:
    try:
        done = subprocess.run(
            ["docker", "compose", "version", "--short"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def _recorded_ups(inst: Installation, tmp_path: Path, body: str) -> list[list[str]]:
    """The `docker compose ... up` calls the real shell functions make for `body`, on the
    installation `inst`; every other docker and py_cli call is answered by the stubs."""
    assert BASH is not None
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    (tmp_path / "backups").mkdir(exist_ok=True)
    harness = (
        _HARNESS.replace("@CONFIG@", inst.config.as_posix())
        .replace("@ROOT@", inst.repo.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@BACKUPS@", (tmp_path / "backups").as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE_SH.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@BACKUP@", BACKUP_SH.as_posix())
        .replace("@POST_RC@", "0")
        .replace("@ARTIFACT_RC@", "0")
        .replace("@MODE@", "single")
        .replace("@UP_RC@", "0")
        .replace("@RENDER_RC@", "0")
    )
    done = subprocess.run(
        [BASH, "-c", f"{harness}\n{body}"], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    return _compose_calls(log.read_text(encoding="utf-8").splitlines(), "up")


def _config(words: list[str]) -> dict:
    """`docker compose config` of the project one recorded `up` call describes."""
    args = words[: words.index("up")]
    done = subprocess.run(
        [*args, "config", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@needs_bash
@pytest.mark.skipif(not _compose_available(), reason="docker compose is not available")
def test_keycloak_alone_and_start_define_every_network_of_keycloak_alike(tmp_path):
    inst = Installation(tmp_path / "inst", [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}", f"--subnet-block={BLOCK}")
    run_cli(inst.repo, inst.config, "materialize-core")
    run_cli(inst.repo, inst.config, "render")
    assert (inst.config / "overrides" / subnet_pool.OVERRIDE).is_file()
    _pending(inst.config)

    ups = _recorded_ups(inst, tmp_path, "cmd_start --no-addons")
    alone = [w for w in ups if w[-1] == "keycloak"]
    stack = [w for w in ups if w[-1] != "keycloak"]
    assert len(alone) == 1 and len(stack) == 1, ups

    started = _config(stack[0])
    restored = _config(alone[0])
    networks = sorted(started["services"]["keycloak"]["networks"])
    assert networks, started["services"]["keycloak"]
    assert sorted(restored["services"]["keycloak"]["networks"]) == networks
    for name in networks:
        assert restored["networks"][name] == started["networks"][name], name
    # The pool reaches every internal network Keycloak joins: the comparison is not
    # one of two definitions without an address block.
    internal = [n for n in networks if not started["networks"][n].get("external")]
    assert internal
    for name in internal:
        assert started["networks"][name].get("ipam", {}).get("config"), name
