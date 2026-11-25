"""`papaia-ctl upgrade` and `papaia-ctl rollback` end to end in bash: the way back without
the operator key (MN-12, RE-11, BE-11, BE-13, PLT-62-A3).

A git test clone carries v1.10.0 (the release the upgrade starts from), v1.10.1 (a good
target) and v1.11.0 (a target whose migration fails; the fault sits in the test artifact).
`backup` and `restore` run the real planning, sealing, key check and decryption with the
docker steps replaced by host `tar`: R0 is a real encrypted restore point. `stop`,
`setup`, `start` and `doctor` record their call. The handoff to the papaia-ctl of the
checkout is replaced by a call into the same functions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import hang_guard
import pytest
import yaml

from lib import age, backup, backup_crypt, rollback_key
from lib import upgrade_stages as us

TOOLS = Path(__file__).resolve().parents[1]
UPGRADE_SH = TOOLS / "lib" / "sh" / "upgrade.sh"
BASH = shutil.which("bash")
GIT = shutil.which("git")
TAR = shutil.which("tar")

pytestmark = pytest.mark.skipif(
    BASH is None or GIT is None or TAR is None, reason="bash, git or tar missing"
)

HOUR = 3600

_HARNESS = r"""
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
PYTHON_BIN="@PYTHON@"
ADDON_IMAGE_FLAGS=()
LAST_BACKUP_ID=""
RESTORE_TRIGGER="restore"
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
# The real plan, sealing and manifest; host tar in place of the docker sidecar.
cmd_backup() {
    local rk="" a
    for a in "$@"; do case "$a" in --rollback-key=*) rk="${a#*=}" ;; esac; done
    echo "backup lock=$(_lock) rollback-key=${rk:-none}" >> "@LOG@"
    local -a extra=()
    [ -n "$rk" ] && extra+=(--rollback-key="$rk")
    local plan snapshot="" kind archive source owner
    plan="$(py_cli backup-plan --backup-dir="@BACKUP@" ${extra[@]+"${extra[@]}"} | tr -d '\r')"
    while IFS=$'\t' read -r kind archive source owner; do
        case "$kind" in
            SNAPSHOT) snapshot="$archive" ;;
            configdir)
                tar czf - --exclude=./state -C "$source" . \
                    | py_cli backup-seal --snapshot="$snapshot" --archive="$archive"
                printf '%s\tok\n' "$archive" >> "$snapshot/results.tsv"
                ;;
        esac
    done <<< "$plan"
    LAST_BACKUP_ID="$(py_cli backup-finish --backup-dir="@BACKUP@" --snapshot="$snapshot" \
        | tr -d '\r' | awk -F'\t' '$1 == "ID" { print $2 }')"
}
# The real key check and decryption of R0 with the key on standard input; host tar unpacks.
cmd_restore() {
    echo "restore lock=$(_lock) trigger=$RESTORE_TRIGGER $*" >> "@LOG@"
    local point="" a
    for a in "$@"; do case "$a" in --restore-point=*) point="${a#*=}" ;; esac; done
    local ids snap="" kind archive rest
    ids="$(py_cli backup-identities --identity=-)"
    while IFS=$'\t' read -r kind archive rest; do
        case "$kind" in
            SNAPSHOT) snap="$archive" ;;
            configdir)
                printf '%s\n' "$ids" \
                    | py_cli restore-open --snapshot="$snap" --archive="$archive" --identity=- \
                    | tar xzf - -C "$CONFIG_DIR"
                echo "restored $archive" >> "@LOG@"
                ;;
        esac
    done < <(printf '%s\n' "$ids" | py_cli restore-resolve --restore-point="$point" \
        --identity=- | tr -d '\r')
}
cmd_stop() { echo "stop lock=$(_lock)" >> "@LOG@"; }
cmd_setup() { echo "setup lock=$(_lock)" >> "@LOG@"; }
cmd_start() { echo "start lock=$(_lock)" >> "@LOG@"; }
cmd_doctor() { echo "doctor" >> "@LOG@"; }
cmd_addon_upgrade() { echo "addon-upgrade $*" >> "@LOG@"; }
_cli_at() {
    _py_cli_at() {
        local root="$1"; shift
        PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$root" \
            --config-dir "$CONFIG_DIR" "$@"
    }
}
source "@UPGRADE@"
_cli_at
# The handoff runs the papaia-ctl of the checkout; here it continues in this shell.
exec() { shift 2; local cmd="$1"; shift; source "@UPGRADE@"; _cli_at; "cmd_$cmd" "$@"; exit $?; }
cmd="$1"; shift
"cmd_$cmd" "$@"
"""


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


@pytest.fixture()
def clone(tmp_path: Path) -> dict:
    repo = tmp_path / "papaia"
    repo.mkdir()
    _git(repo, "init", "-q")
    # The release the upgrade starts from knows `rollback` (phase 2 runs its papaia-ctl).
    _release(repo, "1.10.0", {
        "src/docker-compose.yml": "services:\n  stub:\n    image: stub\n",
        "tools/lib/sh/upgrade.sh": UPGRADE_SH.read_text(encoding="utf-8"),
    })
    _release(repo, "1.10.1", {"README.md": "good target\n"})
    _release(repo, "1.11.0", {
        "tools/migrations/1.11.0__forced-failure.sh": "#!/usr/bin/env bash\nexit 1\n",
    })
    _git(repo, "checkout", "-q", "--detach", "v1.10.0")

    secret, public = age.generate_identity()
    target = tmp_path / "backup"
    target.mkdir()
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text(
        "COMPOSE_PROJECT_NAME=papaia\n"
        f"PAPAIA_BACKUP_RECIPIENTS=betrieb:{public}\n"
        f"PAPAIA_BACKUP_DIR={target}\n",
        encoding="utf-8",
    )
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({"platform_version": "1.10.0", "addons": []}), encoding="utf-8"
    )
    # A canary of the configuration: the restore of R0 must bring it back.
    (config / "canary.txt").write_text("before the upgrade\n", encoding="utf-8")
    backup_crypt.init_target(config, target)
    identity = tmp_path / "operator.key"
    identity.write_text(secret + "\n", encoding="utf-8")
    identity.chmod(0o600)
    return {"repo": repo, "config": config, "backup": target, "identity": identity,
            "secret": secret, "log": tmp_path / "calls.log",
            "harness": tmp_path / "harness.sh"}


def _run(
    clone: dict, *args: str, stdin: str | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    script = (
        _HARNESS.replace("@CONFIG@", str(clone["config"]))
        .replace("@ROOT@", str(clone["repo"]))
        .replace("@PYTHON@", sys.executable)
        .replace("@TOOLS@", str(TOOLS))
        .replace("@LOG@", str(clone["log"]))
        .replace("@BACKUP@", str(clone["backup"]))
        .replace("@UPGRADE@", str(UPGRADE_SH))
    )
    clone["harness"].write_text(script, encoding="utf-8")
    clone["log"].touch()
    return subprocess.run(
        [BASH, str(clone["harness"]), *args], capture_output=True, text=True, input=stdin,
        timeout=hang_guard.seconds(), env=env,
    )


def _calls(clone: dict) -> list[str]:
    return clone["log"].read_text(encoding="utf-8").splitlines()


def _tag(clone: dict, version: str) -> str:
    return _git(clone["repo"], "rev-parse", f"v{version}^{{commit}}")


def _head(clone: dict) -> str:
    return _git(clone["repo"], "rev-parse", "HEAD")


def _keys(clone: dict) -> list[Path]:
    folder = clone["config"] / "state" / "rollback"
    return sorted(folder.iterdir()) if folder.is_dir() else []


def _audit(clone: dict) -> list[dict]:
    path = clone["config"] / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _no_secret_anywhere(clone: dict, *outputs: str) -> None:
    secret = clone["secret"].upper()
    texts = [*outputs, clone["log"].read_text(encoding="utf-8"),
             json.dumps(_audit(clone))]
    texts += [p.read_text(encoding="utf-8") for p in clone["config"].glob("*.log")]
    for text in texts:
        assert "AGE-SECRET-KEY" not in text.upper()
        assert secret not in text.upper()


def _upgrade_and_fail(clone: dict) -> subprocess.CompletedProcess:
    # Not a single operator key on this run.
    result = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images")
    assert result.returncode == 3, result.stdout + result.stderr
    return result


# ── MN-12: the way back without the operator key ────────────────────────────


def test_a_failed_upgrade_goes_back_with_one_command_and_without_the_operator_key(clone):
    failed = _upgrade_and_fail(clone)
    out = failed.stdout + failed.stderr
    assert "1.11.0__forced-failure" in out
    assert "papaia-ctl rollback -y" in out
    state = us.load_state(clone["config"])
    (key,) = _keys(clone)
    assert key.name == f"{state['id']}.key"
    assert "backup lock=off rollback-key=" + state["id"] in _calls(clone)
    # R0 is encrypted to the operator recipient and to the rollback key.
    entry = backup.load_index(clone["backup"])["backups"][0]
    assert entry["id"] == state["restore_point"]
    assert [r["name"] for r in entry["recipients"]] == [
        "betrieb", rollback_key.recipient_name(state["id"]),
    ]
    assert us.read_lock(clone["config"]).active
    (clone["config"] / "canary.txt").write_text("changed by the failed upgrade\n")

    clone["log"].write_text("")
    back = _run(clone, "rollback", "-y")
    out = back.stdout + back.stderr
    assert back.returncode == 0, out
    assert "no operator key is needed" in out
    assert _head(clone) == _tag(clone, "1.10.0")
    calls = _calls(clone)
    restore = next(c for c in calls if c.startswith("restore "))
    assert "lock=on trigger=rollback" in restore
    assert f"--restore-point={state['restore_point']}" in restore
    assert "--restart-clean" in restore and "--identity=-" in restore
    assert "restored configdir.tar.gz.age" in calls or any(c.startswith("restored ") for c in calls)
    assert calls[-1] == "doctor"
    assert (clone["config"] / "canary.txt").read_text() == "before the upgrade\n"
    assert not us.read_lock(clone["config"]).active
    assert us.load_state(clone["config"])["abandoned"] is not None
    assert _keys(clone) == []
    operations = [r["operation"] for r in _audit(clone)]
    assert "upgrade.rollback" in operations
    deleted = [r for r in _audit(clone) if r["event"] == "rollback_key_deleted"]
    assert deleted[-1]["detail"]["reason"] == "rolled back"
    _no_secret_anywhere(clone, failed.stdout, failed.stderr, back.stdout, back.stderr)


def test_a_second_rollback_has_nothing_to_do(clone: dict):
    _upgrade_and_fail(clone)
    assert _run(clone, "rollback", "-y").returncode == 0
    again = _run(clone, "rollback", "-y")
    assert again.returncode == 2
    assert "already rolled back" in again.stderr


def test_a_key_that_does_not_open_r0_changes_nothing(clone: dict):
    _upgrade_and_fail(clone)
    head = _head(clone)
    stranger = clone["identity"].parent / "stranger.key"
    stranger.write_text(age.generate_identity()[0] + "\n", encoding="utf-8")
    result = _run(clone, "rollback", "-y", f"--identity={stranger}")
    assert result.returncode == 2
    assert "nothing was changed" in result.stderr
    assert _head(clone) == head
    assert us.read_lock(clone["config"]).active
    assert not any(c.startswith("restore") for c in _calls(clone))


# ── the window ──────────────────────────────────────────────────────────────


def _finished_upgrade(clone: dict) -> dict:
    result = _run(clone, "upgrade", "--version=1.10.1", "-y", "--insecure-images")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "The rollback key of this upgrade stays until" in result.stdout
    state = us.load_state(clone["config"])
    assert state["finished"] is not None
    assert len(_keys(clone)) == 1
    return state


def _age_run(clone: dict, hours: int) -> None:
    state = us.load_state(clone["config"])
    state["finished"] -= hours * HOUR
    us._save(clone["config"], state)


def _doctor(clone: dict) -> dict:
    out = subprocess.run(
        [sys.executable, "-m", "lib.cli", "--repo-root", str(clone["repo"]), "--config-dir",
         str(clone["config"]), "doctor", "rollback_window", "--json"],
        capture_output=True, text=True, cwd=TOOLS, env={**os.environ, "PYTHONPATH": str(TOOLS)},
        timeout=hang_guard.seconds(),
    )
    (check,) = json.loads(out.stdout)["checks"]
    return check


def test_after_the_window_the_key_is_gone_and_rollback_needs_the_operator_key(clone: dict):
    _finished_upgrade(clone)
    assert _doctor(clone)["status"] == "pass"
    _age_run(clone, 73)
    # A key left past its window is reported before anything removes it.
    assert _doctor(clone)["status"] == "fail"

    head = _head(clone)
    refused = _run(clone, "rollback", "-y", "--accept-data-loss")
    assert refused.returncode == 2
    assert "--identity" in refused.stderr and "Nothing was changed" in refused.stderr
    assert _keys(clone) == []
    assert _head(clone) == head
    assert _doctor(clone)["status"] == "skip"

    back = _run(clone, "rollback", "-y", "--accept-data-loss",
                f"--identity={clone['identity']}")
    assert back.returncode == 0, back.stdout + back.stderr
    assert _head(clone) == _tag(clone, "1.10.0")
    _no_secret_anywhere(clone, back.stdout, back.stderr)


def test_the_key_from_standard_input_works_after_the_window(clone: dict):
    _finished_upgrade(clone)
    _age_run(clone, 80)
    back = _run(clone, "rollback", "-y", "--accept-data-loss", "--identity=-",
                stdin=clone["identity"].read_text())
    assert back.returncode == 0, back.stdout + back.stderr


def test_rolling_back_a_finished_upgrade_needs_the_data_loss_confirmed(clone: dict):
    _finished_upgrade(clone)
    head = _head(clone)
    refused = _run(clone, "rollback", "-y")
    assert refused.returncode == 2
    assert "--accept-data-loss" in refused.stderr
    assert _head(clone) == head
    assert len(_keys(clone)) == 1
    back = _run(clone, "rollback", "-y", "--accept-data-loss")
    assert back.returncode == 0, back.stdout + back.stderr
    assert _keys(clone) == []


def test_finalize_deletes_the_key(clone: dict):
    _finished_upgrade(clone)
    assert _run(clone, "upgrade", "--finalize").returncode == 2
    assert len(_keys(clone)) == 1
    done = _run(clone, "upgrade", "--finalize", "-y")
    assert done.returncode == 0, done.stderr
    assert _keys(clone) == []
    assert _doctor(clone)["status"] == "skip"
    refused = _run(clone, "rollback", "-y", "--accept-data-loss")
    assert refused.returncode == 2 and "--identity" in refused.stderr


def test_a_scheduled_backup_removes_a_key_past_its_window(clone: dict):
    _finished_upgrade(clone)
    _age_run(clone, 73)
    result = _run(clone, "backup")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _keys(clone) == []
    assert "time is over" in result.stderr


# ── RE-85: without a rollback key ────────────────────────────────────────────


def test_without_a_rollback_key_the_upgrade_needs_the_operator_key(clone: dict):
    head = _head(clone)
    refused = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images",
                   "--no-rollback-key")
    assert refused.returncode == 2
    assert us.NO_KEY_MESSAGE in refused.stderr
    assert _head(clone) == head
    assert us.load_state(clone["config"]) is None
    assert _keys(clone) == []

    failed = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images",
                  "--no-rollback-key", f"--identity={clone['identity']}")
    assert failed.returncode == 3
    assert _keys(clone) == []
    entry = backup.load_index(clone["backup"])["backups"][0]
    assert [r["name"] for r in entry["recipients"]] == ["betrieb"]
    refused = _run(clone, "rollback", "-y")
    assert refused.returncode == 2 and "--identity" in refused.stderr
    back = _run(clone, "rollback", "-y", f"--identity={clone['identity']}")
    assert back.returncode == 0, back.stdout + back.stderr
    assert _head(clone) == _tag(clone, "1.10.0")


def test_a_run_that_stops_before_r0_leaves_no_key(clone: dict):
    # The confirmation is refused (no terminal, no -y): stage 1 never begins.
    result = _run(clone, "upgrade", "--version=1.11.0", "--insecure-images")
    assert result.returncode == 2
    assert _keys(clone) == []
    assert us.load_state(clone["config"]) is None


def test_a_retry_of_a_run_without_a_rollback_key_needs_the_operator_key(clone: dict):
    failed = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images",
                  "--no-rollback-key", f"--identity={clone['identity']}")
    assert failed.returncode == 3, failed.stdout + failed.stderr
    state = us.load_state(clone["config"])
    assert state["finished"] is None and _keys(clone) == []
    head = _head(clone)
    clone["log"].write_text("")
    # The retry runs without --no-rollback-key and without --identity: the kept run has no
    # rollback key, so nothing in this call proves a way back to R0.
    retry = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images")
    assert retry.returncode == 2, retry.stdout + retry.stderr
    assert us.NO_KEY_MESSAGE in retry.stderr
    assert _head(clone) == head
    assert us.load_state(clone["config"]) == state
    assert not any(c.startswith(("stop", "backup", "setup", "start")) for c in _calls(clone))
    assert _keys(clone) == []

    again = _run(clone, "upgrade", "--version=1.11.0", "-y", "--insecure-images",
                 f"--identity={clone['identity']}")
    assert again.returncode == 3, again.stdout + again.stderr
    assert any(c.startswith("stop") for c in _calls(clone))


def test_the_second_phase_of_rollback_alone_is_refused_for_another_point(clone: dict):
    _upgrade_and_fail(clone)
    state = us.load_state(clone["config"])
    head = _head(clone)
    clone["log"].write_text("")
    key = rollback_key.identity(clone["config"], state["id"])
    wrong_point = _run(clone, "rollback", f"--resume-upgrade-id={state['id']}",
                       "--resume-restore-point=20200101T000000Z", stdin=key + "\n")
    assert wrong_point.returncode == 2, wrong_point.stdout + wrong_point.stderr
    wrong_id = _run(clone, "rollback", "--resume-upgrade-id=00000000-0000-4000-8000-000000000000",
                    f"--resume-restore-point={state['restore_point']}", stdin=key + "\n")
    assert wrong_id.returncode == 2, wrong_id.stdout + wrong_id.stderr
    assert "not the run to roll back" in wrong_id.stderr
    assert not any(c.startswith("restore") for c in _calls(clone))
    assert _head(clone) == head
    assert us.read_lock(clone["config"]).active


def test_the_second_phase_alone_keeps_the_data_loss_guard(clone: dict):
    state = _finished_upgrade(clone)
    clone["log"].write_text("")
    key = rollback_key.identity(clone["config"], state["id"])
    refused = _run(clone, "rollback", f"--resume-upgrade-id={state['id']}",
                   f"--resume-restore-point={state['restore_point']}", "-y", stdin=key + "\n")
    assert refused.returncode == 2, refused.stdout + refused.stderr
    assert "--accept-data-loss" in refused.stderr
    assert not any(c.startswith("restore") for c in _calls(clone))
    assert len(_keys(clone)) == 1



# ── a reader that stops early under pipefail ────────────────────────────────

# A git that, for the upgrade script of a release, keeps writing long after the line that
# `rollback` looks for: a reader that stops at the first match leaves it writing into a
# closed pipe, and it dies of SIGPIPE.
_LATE_GIT = """#!/usr/bin/env bash
"$STUB_REAL_GIT" "$@" || exit
for arg in "$@"; do
    case "$arg" in
        *:tools/lib/sh/upgrade.sh) yes "# still writing" | head -c 4194304; exit ;;
    esac
done
"""


def _late_git(clone: dict) -> dict[str, str]:
    fake = clone["harness"].parent / "late-git"
    fake.mkdir(exist_ok=True)
    stub = fake / "git"
    stub.write_text(_LATE_GIT, encoding="utf-8")
    stub.chmod(0o755)
    assert GIT is not None
    return {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "STUB_REAL_GIT": GIT}


def _retag(clone: dict, version: str, content: str | None) -> None:
    """Moves the tag v<version> to a commit whose upgrade script is `content` (None: gone)."""
    repo = clone["repo"]
    head = _head(clone)
    _git(repo, "checkout", "-q", "--detach", f"v{version}")
    if content is None:
        _git(repo, "rm", "-q", "tools/lib/sh/upgrade.sh")
    else:
        (repo / "tools/lib/sh/upgrade.sh").write_text(content, encoding="utf-8")
        _git(repo, "add", "tools/lib/sh/upgrade.sh")
    _git(repo, "commit", "-q", "-m", f"release {version}, changed")
    _git(repo, "tag", "-f", f"v{version}")
    _git(repo, "checkout", "-q", "--detach", head)


def test_the_late_git_is_killed_by_sigpipe_behind_an_early_reader(clone: dict):
    # The construction the next test relies on: under pipefail the old check fails.
    env = _late_git(clone)
    assert BASH is not None
    piped = subprocess.run(
        [BASH, "-c", f'set -o pipefail; git -C "{clone["repo"]}" show '
                     f'"{_tag(clone, "1.10.0")}:tools/lib/sh/upgrade.sh" '
                     "| grep -q '^cmd_rollback()'"],
        capture_output=True, env=env, check=False, timeout=hang_guard.seconds(),
    )
    assert piped.returncode == 141


def test_a_rollback_is_not_refused_when_the_reader_stops_early(clone: dict):
    _upgrade_and_fail(clone)
    clone["log"].write_text("")
    back = _run(clone, "rollback", "-y", env=_late_git(clone))
    out = back.stdout + back.stderr
    assert "has no 'rollback' command" not in out
    assert back.returncode == 0, out
    assert _head(clone) == _tag(clone, "1.10.0")
    assert _calls(clone)[-1] == "doctor"


def test_a_release_without_the_command_is_refused_as_before(clone: dict):
    _upgrade_and_fail(clone)
    _retag(clone, "1.10.0", "# an upgrade script without the rollback command\n")
    head = _head(clone)
    clone["log"].write_text("")
    refused = _run(clone, "rollback", "-y", env=_late_git(clone))
    assert refused.returncode == 2
    assert "Release 1.10.0 has no 'rollback' command. Go back step by step" in refused.stderr
    assert "papaia-ctl restore --restore-point=" in refused.stderr
    assert _head(clone) == head
    assert not any(c.startswith("restore") for c in _calls(clone))
    assert us.read_lock(clone["config"]).active


def test_an_unreadable_upgrade_script_of_the_release_has_its_own_error(clone: dict):
    _upgrade_and_fail(clone)
    _retag(clone, "1.10.0", None)
    head = _head(clone)
    clone["log"].write_text("")
    refused = _run(clone, "rollback", "-y")
    assert refused.returncode == 2
    assert "has no 'rollback' command" not in refused.stderr
    assert "Cannot read tools/lib/sh/upgrade.sh of release 1.10.0" in refused.stderr
    assert "papaia-ctl restore --restore-point=" in refused.stderr
    assert _head(clone) == head
    assert not any(c.startswith("restore") for c in _calls(clone))
    assert us.read_lock(clone["config"]).active
