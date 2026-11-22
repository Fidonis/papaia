"""`papaia-ctl upgrade` end to end in bash against a git test clone of 1.8.0.

The clone carries the tags v1.8.0, v1.9.0 and v1.10.0; v1.10.0 ships a migration that
fails (the fault sits in the test artifact, not in the product). Docker-facing commands
(`backup`, `stop`, `setup`, `start`, `addon upgrade`, `addon stop`) are functions that
record their call; git, the add-on check, the migrations, the stage plan, the key check,
the state and the write lock are the real ones. The handoff to the target release's
papaia-ctl is replaced by a call into the same functions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from lib import age
from lib import upgrade_stages as us

TOOLS = Path(__file__).resolve().parents[1]
UPGRADE_SH = TOOLS / "lib" / "sh" / "upgrade.sh"
# The first phase of an installation that upgrades into this release: the upgrade.sh of
# releases/1.10.0, which has no stage state, no write lock and no key check.
PHASE1_1_10 = Path(__file__).resolve().parent / "fixtures" / "upgrade-1.10.0-phase1.sh"
BASH = shutil.which("bash")
GIT = shutil.which("git")

pytestmark = pytest.mark.skipif(BASH is None or GIT is None, reason="bash or git missing")

R0 = "2026-11-21_10-00-00"

_HARNESS = r"""
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
PYTHON_BIN="@PYTHON@"
ADDON_IMAGE_FLAGS=()
LAST_BACKUP_ID=""
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { :; }
is_tty() { return 1; }
confirm() { return 0; }
py_cli() {
    PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$REPO_ROOT" \
        --config-dir "$CONFIG_DIR" "$@"
}
_lock() { if [ -f "$CONFIG_DIR/state/write-lock.json" ]; then echo on; else echo off; fi; }
_require_setup_done() { :; }
_topology_mode() { echo single; }
_verify_images() { echo "verify-images" >> "@LOG@"; }
_addon_image_flags() { :; }
_addon_image_files_remove() { :; }
cmd_backup() { echo "backup lock=$(_lock)" >> "@LOG@"; LAST_BACKUP_ID="@R0@"; }
cmd_stop() { echo "stop lock=$(_lock) $*" >> "@LOG@"; }
cmd_setup() { echo "setup lock=$(_lock)" >> "@LOG@"; }
cmd_start() { echo "start lock=$(_lock) $*" >> "@LOG@"; }
cmd_addon_upgrade() { echo "addon-upgrade lock=$(_lock) $*" >> "@LOG@"; }
cmd_addon_stop() { echo "addon-stop $*" >> "@LOG@"; }
_cli_at() {
    _py_cli_at() {
        local root="$1"; shift
        # A crashing add-on check, when the test asks for one.
        if [ -n "${CRASH_ADDON_CHECK:-}" ] && [ "$1" = "addon-check" ]; then
            echo "Traceback (most recent call last): check crashed" >&2
            return 1
        fi
        PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$root" \
            --config-dir "$CONFIG_DIR" "$@"
    }
}
source "@PHASE1@"
_cli_at
# The handoff runs the target release's papaia-ctl; here it continues in this shell with
# this release's upgrade.sh.
exec() { shift 3; source "@UPGRADE@"; _cli_at; cmd_upgrade "$@"; exit $?; }
cmd_upgrade "$@"
"""

MATRIX_1_9 = {
    "schema": "papaia.compat-matrix/1",
    "components": ["papaia-data", "papaia-studio"],
    "suites": [
        {
            "suite": "1.9.0", "status": "released", "core": ">=1.9.0,<1.10.0",
            "addon_api": {"min": 1, "current": 6},
            "versions": {"papaia-data": ">=0.1.0,<0.2.0", "papaia-studio": ">=0.2.0,<0.3.0"},
        },
    ],
}


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    return subprocess.run(
        [GIT, "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()


def _release(repo: Path, version: str, files: dict[str, str]) -> None:
    (repo / "VERSION").write_text(version + "\n", encoding="utf-8")
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"release {version}")
    _git(repo, "tag", f"v{version}")


def _addon(tmp_path: Path, name: str, version: str) -> Path:
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    (path / "papaia-app.yaml").write_text(
        yaml.safe_dump({"name": name, "version": version}), encoding="utf-8"
    )
    return path


@pytest.fixture()
def clone(tmp_path: Path) -> dict:
    repo = tmp_path / "papaia"
    repo.mkdir()
    _git(repo, "init", "-q")
    _release(repo, "1.8.0", {"README.md": "core\n"})
    _release(repo, "1.9.0", {"compat/suite.yaml": yaml.safe_dump(MATRIX_1_9, sort_keys=False)})
    _git(repo, "rm", "-q", "compat/suite.yaml")
    _release(repo, "1.10.0", {
        "tools/migrations/1.10.0__forced-failure.sh": "#!/usr/bin/env bash\nexit 1\n",
    })
    _git(repo, "checkout", "-q", "--detach", "v1.8.0")

    secret, public = age.generate_identity()
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text(
        f"COMPOSE_PROJECT_NAME=papaia\nPAPAIA_BACKUP_RECIPIENTS=betrieb:{public}\n",
        encoding="utf-8",
    )
    data = _addon(tmp_path, "papaia-data", "0.1.0")
    studio = _addon(tmp_path, "papaia-studio", "0.2.0")
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({
            "platform_version": "1.8.0",
            "addons": [
                {"name": "papaia-studio", "path": str(studio), "active": True,
                 "state": "running"},
                {"name": "papaia-data", "path": str(data), "active": True, "state": "running"},
            ],
        }),
        encoding="utf-8",
    )
    identity = tmp_path / "operator.key"
    identity.write_text(secret + "\n", encoding="utf-8")
    identity.chmod(0o600)
    new_data = _addon(tmp_path / "new", "papaia-data", "0.1.1")
    new_studio = _addon(tmp_path / "new", "papaia-studio", "0.2.1")
    return {"repo": repo, "config": config, "identity": identity, "log": tmp_path / "calls.log",
            "harness": tmp_path / "harness.sh", "new_data": new_data, "new_studio": new_studio}


def _run(clone: dict, *args: str, stdin: str | None = None,
         phase1: Path = UPGRADE_SH, env: dict | None = None) -> subprocess.CompletedProcess:
    script = (
        _HARNESS.replace("@CONFIG@", str(clone["config"]))
        .replace("@ROOT@", str(clone["repo"]))
        .replace("@PYTHON@", sys.executable)
        .replace("@TOOLS@", str(TOOLS))
        .replace("@LOG@", str(clone["log"]))
        .replace("@R0@", R0)
        .replace("@UPGRADE@", str(UPGRADE_SH))
        .replace("@PHASE1@", str(phase1))
    )
    clone["harness"].write_text(script, encoding="utf-8")
    clone["log"].touch()
    return subprocess.run(
        [BASH, str(clone["harness"]), *args], capture_output=True, text=True, input=stdin,
        timeout=120, env={**os.environ, **(env or {})},
    )


def _calls(clone: dict) -> list[str]:
    return clone["log"].read_text(encoding="utf-8").splitlines()


def _head(clone: dict) -> str:
    return _git(clone["repo"], "rev-parse", "HEAD")


def _state(clone: dict) -> dict | None:
    return us.load_state(clone["config"])


# ── forced failure: the system stays at R0 ──────────────────────────────────


def test_a_forced_failure_leaves_the_installation_at_its_restore_point(clone: dict):
    before = _head(clone)
    result = _run(clone, "--version=1.10.0", "-y", "--insecure-images",
                  f"--identity={clone['identity']}")
    out = result.stdout + result.stderr
    assert result.returncode == 3, out
    calls = _calls(clone)
    # R0 first, the write lock from R0 on, then the stop; nothing ran before the restore point.
    assert calls.index("backup lock=off") < next(
        i for i, c in enumerate(calls) if c.startswith("stop lock=on")
    )
    assert not any(c.startswith(("setup", "start", "addon-upgrade")) for c in calls)
    state = _state(clone)
    assert state["restore_point"] == R0
    assert state["from"] == "1.8.0" and state["to"] == "1.10.0"
    assert state["stages"]["core"]["status"] == "failed"
    assert us.read_lock(clone["config"]).active
    # The way back names the tag of 1.8.0 and R0; the lock stays until it was taken.
    assert "1.10.0__forced-failure" in out
    assert f"git -C {clone['repo']} checkout v1.8.0" in out
    assert f"papaia-ctl restore --restore-point={R0}" in out
    assert "papaia-ctl upgrade --release-lock" in out
    assert _head(clone) != before
    deployed = yaml.safe_load((clone["config"] / "deployment.yaml").read_text())
    assert deployed["platform_version"] == "1.8.0"


def test_a_retry_after_a_failure_reuses_the_restore_point(clone: dict):
    _run(clone, "--version=1.10.0", "-y", "--insecure-images", f"--identity={clone['identity']}")
    _git(clone["repo"], "checkout", "-q", "--detach", "v1.8.0")
    clone["log"].write_text("")
    result = _run(clone, "--version=1.10.0", "-y", "--insecure-images",
                  f"--identity={clone['identity']}")
    assert result.returncode == 3
    assert not any(c.startswith("backup") for c in _calls(clone))
    assert f"Restore point {R0}" in result.stdout


def test_the_lock_is_released_after_the_way_back(clone: dict):
    _run(clone, "--version=1.10.0", "-y", "--insecure-images", f"--identity={clone['identity']}")
    refused = _run(clone, "--release-lock", "-y")
    assert refused.returncode == 2
    assert us.read_lock(clone["config"]).active
    # The restore of R0 brings the 1.8.0 bundle back.
    _git(clone["repo"], "checkout", "-q", "--detach", "v1.8.0")
    released = _run(clone, "--release-lock", "-y")
    assert released.returncode == 0, released.stderr
    assert not us.read_lock(clone["config"]).active


# ── stage 0: the operator key (RE-85) ───────────────────────────────────────


@pytest.mark.parametrize("key", ["missing", "wrong"])
def test_without_a_matching_key_nothing_is_changed(clone: dict, key: str):
    before = _head(clone)
    args = ["--version=1.9.0", "-y", "--insecure-images"]
    if key == "wrong":
        wrong = clone["identity"].parent / "wrong.key"
        wrong.write_text(age.generate_identity()[0] + "\n", encoding="utf-8")
        args.append(f"--identity={wrong}")
    result = _run(clone, *args)
    assert result.returncode == 2, result.stdout + result.stderr
    assert us.NO_KEY_MESSAGE in result.stderr
    assert _calls(clone) == ["verify-images"]
    assert _head(clone) == before
    assert _state(clone) is None
    assert not us.read_lock(clone["config"]).active


def test_the_key_can_come_from_standard_input(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images", "--identity=-",
                  f"--addon-path=papaia-data={clone['new_data']}",
                  f"--addon-path=papaia-studio={clone['new_studio']}",
                  stdin=clone["identity"].read_text())
    assert result.returncode == 0, result.stdout + result.stderr


# ── staged success ──────────────────────────────────────────────────────────


def test_a_staged_upgrade_runs_data_before_studio_under_the_write_lock(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images",
                  f"--identity={clone['identity']}",
                  f"--addon-path=papaia-studio={clone['new_studio']}",
                  f"--addon-path=papaia-data={clone['new_data']}")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    calls = _calls(clone)
    upgrades = [c for c in calls if c.startswith("addon-upgrade")]
    assert [c.split()[2] for c in upgrades] == ["papaia-data", "papaia-studio"]
    assert all("lock=on" in c for c in upgrades)
    assert any(c.startswith("start lock=on") for c in calls)
    assert all("--no-backup" in c for c in upgrades)
    state = _state(clone)
    assert state["finished"] is not None
    assert {s: v["status"] for s, v in state["stages"].items()} == {
        "preflight": "ok", "restore-point": "ok", "core": "ok", "me": "skipped",
        "data": "ok", "studio": "ok", "flow": "skipped", "assist": "skipped", "finish": "ok",
    }
    assert not us.read_lock(clone["config"]).active
    assert "Stage durations" in out


def test_a_core_only_run_keeps_the_lock_until_the_module_stages_ran(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images", "--stage=core",
                  f"--identity={clone['identity']}",
                  f"--addon-path=papaia-data={clone['new_data']}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert us.read_lock(clone["config"]).active
    assert not any(c.startswith("addon-upgrade") for c in _calls(clone))
    resumed = _run(clone, "--resume", "-y", "--stage=data", f"--identity={clone['identity']}")
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert any(c.startswith("addon-upgrade lock=on papaia-data") for c in _calls(clone))
    assert us.read_lock(clone["config"]).active
    rest = _run(clone, "--resume", "-y", f"--identity={clone['identity']}")
    assert rest.returncode == 0, rest.stdout + rest.stderr
    assert not us.read_lock(clone["config"]).active


def test_an_incompatible_module_stops_the_upgrade_before_any_change(clone: dict):
    deployed = yaml.safe_load((clone["config"] / "deployment.yaml").read_text())
    studio = Path(deployed["addons"][0]["path"])
    (studio / "papaia-app.yaml").write_text(
        yaml.safe_dump({"name": "papaia-studio", "version": "0.1.0"}), encoding="utf-8"
    )
    before = _head(clone)
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images",
                  f"--identity={clone['identity']}")
    assert result.returncode == 2
    assert "papaia-studio" in result.stderr and ">=0.2.0" in result.stderr
    assert _calls(clone) == []
    assert _head(clone) == before

    forced = _run(clone, "--version=1.9.0", "-y", "--insecure-images", "--force",
                  f"--identity={clone['identity']}")
    assert forced.returncode == 0, forced.stdout + forced.stderr
    entry = yaml.safe_load((clone["config"] / "deployment.yaml").read_text())["addons"][0]
    assert entry["active"] is False and entry["blocked"]["core"] == "1.9.0"
    calls = _calls(clone)
    stop = next(i for i, c in enumerate(calls) if c.startswith("stop lock=on"))
    assert stop < next(i for i, c in enumerate(calls) if c.startswith("start"))


def test_a_dry_run_names_every_stage_and_changes_nothing(clone: dict):
    before = _head(clone)
    result = _run(clone, "--version=1.10.0", "--dry-run", "--insecure-images",
                  f"--addon-path=papaia-data={clone['new_data']}")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    for line in ("stage 0 preflight", "stage 1 restore-point", "stage 2 core",
                 "stage 4 data: upgrade papaia-data", "stage 5 studio: keep papaia-studio",
                 "stage 8 finish", "1.10.0__forced-failure", "--identity"):
        assert line in out, line
    # The image check is read-only and part of the dry run.
    assert _calls(clone) == ["verify-images"]
    assert _head(clone) == before
    assert _state(clone) is None


def test_an_upgrade_without_a_restore_point_is_refused(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--no-backup",
                  f"--identity={clone['identity']}")
    assert result.returncode == 2
    assert "restore point" in result.stderr
    assert _calls(clone) == []


def test_every_write_of_the_upgrade_is_audited_under_one_correlation_id(clone: dict):
    _run(clone, "--version=1.9.0", "-y", "--insecure-images", f"--identity={clone['identity']}")
    path = clone["config"] / "audit" / "papaia-ctl.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows = [r for r in rows if r["operation"].startswith("upgrade.")]
    assert [r["operation"] for r in rows][0] == "upgrade.begin"
    assert rows[-1]["operation"] == "upgrade.finish"
    assert len({r["correlation_id"] for r in rows}) == 1
    assert all("AGE-SECRET-KEY" not in json.dumps(r) for r in rows)


# ── first upgrade into this release: phase 1 of a release without stages ─────


def test_the_first_upgrade_from_a_release_without_stages_completes(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images", phase1=PHASE1_1_10)
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    calls = _calls(clone)
    # The old first phase took the restore point and stopped the stack without a lock;
    # the second phase takes the run over with that restore point and locks from there on.
    assert calls.index("backup lock=off") < next(
        i for i, c in enumerate(calls) if c.startswith("stop lock=off")
    )
    assert any(c.startswith("setup lock=on") for c in calls)
    assert any(c.startswith("start lock=on") for c in calls)
    state = _state(clone)
    assert state["restore_point"] == R0
    assert state["from"] == "1.8.0" and state["to"] == "1.9.0"
    assert state["finished"] is not None
    assert {s: v["status"] for s, v in state["stages"].items()} == {
        "preflight": "ok", "restore-point": "ok", "core": "ok", "me": "skipped",
        "data": "kept", "studio": "kept", "flow": "skipped", "assist": "skipped",
        "finish": "ok",
    }
    assert not us.read_lock(clone["config"]).active
    assert "upgrade complete" in out
    assert "no key check" in out


def test_the_first_upgrade_keeps_the_lock_when_the_core_stage_fails(clone: dict):
    result = _run(clone, "--version=1.10.0", "-y", "--insecure-images", phase1=PHASE1_1_10)
    out = result.stdout + result.stderr
    assert result.returncode == 3, out
    state = _state(clone)
    assert state["restore_point"] == R0
    assert state["stages"]["core"]["status"] == "failed"
    assert us.read_lock(clone["config"]).active
    assert f"papaia-ctl restore --restore-point={R0}" in out


def test_the_first_upgrade_without_a_restore_point_stops_before_the_core_stage(clone: dict):
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images", "--no-backup",
                  phase1=PHASE1_1_10)
    out = result.stdout + result.stderr
    assert result.returncode == 3, out
    calls = _calls(clone)
    assert not any(c.startswith(("backup", "setup", "start")) for c in calls)
    assert "restore point" in result.stderr
    assert f"git -C {clone['repo']} checkout v1.8.0" in out
    assert "papaia-ctl start --addons" in out
    assert _state(clone) is None
    assert not us.read_lock(clone["config"]).active
    deployed = yaml.safe_load((clone["config"] / "deployment.yaml").read_text())
    assert deployed["platform_version"] == "1.8.0"


# ── stage 0: the add-on check must answer ──────────────────────────────────


def test_a_failing_add_on_check_stops_the_upgrade_before_any_change(clone: dict):
    before = _head(clone)
    result = _run(clone, "--version=1.9.0", "-y", "--insecure-images",
                  f"--identity={clone['identity']}", env={"CRASH_ADDON_CHECK": "1"})
    assert result.returncode == 2, result.stdout + result.stderr
    assert "add-on check" in result.stderr
    assert "check crashed" in result.stderr
    assert "Nothing has been changed" in result.stderr
    assert _calls(clone) == []
    assert _head(clone) == before
    assert _state(clone) is None
