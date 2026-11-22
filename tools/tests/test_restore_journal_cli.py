"""`papaia-ctl restore` end to end in bash: an encrypted restore point is opened with the
operator's key, and the erasure journal is applied before a module starts (RE-06, BE-16,
BE-17).

`docker` is a function that runs the same `tar` and `sh` on host directories, a named
volume is the directory volumes/<name>. An add-on's compose project is a function too: its
`run` executes a stub of the module's migration image, which applies the add-on's journal
at the backup target to its volume the way a module's `erasure-replay` does through the
kit. `py_cli` is the real one.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from lib import age, backup, backup_crypt, module_actions

TOOLS = Path(__file__).resolve().parents[1]
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")
TAR = shutil.which("tar")

pytestmark = pytest.mark.skipif(BASH is None or TAR is None, reason="bash or tar missing")

_HARNESS = r"""
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/src/docker-compose.yml"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo "usage"; }
is_tty() { return 1; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$REPO_ROOT" \
        --config-dir "$CONFIG_DIR" "$@"
}
# docker run with -i, -e, -v and either `tar ...` or `sh -c SCRIPT`; the container paths
# of the mounts are replaced by the host directories behind them.
docker() {
    echo "docker $*" >> "@LOG@"
    case "$1" in
        volume)
            case "$2" in
                ls) cat "@VOLUME_LIST@" ;;
                inspect) [ -d "@VOLUMES@/$3" ] ;;
                create) mkdir -p "@VOLUMES@/$3" ;;
            esac
            ;;
        ps)
            # A container of another compose project on the same engine holds a volume
            # when in-use.tsv names it: `<volume>\t<container>` per line.
            local v c
            if [ -f "@IN_USE@" ]; then
                while IFS=$'\t' read -r v c; do
                    case " $* " in *" volume=$v "*) echo "$c" ;; esac
                done < "@IN_USE@"
            fi
            ;;
        inspect|pause|unpause) ;;
        run)
            shift
            local -a cmd=() envs=() dsts=() srcs=()
            local image_seen=0 spec src dst
            while [ $# -gt 0 ]; do
                if [ "$image_seen" -eq 1 ]; then cmd+=("$1"); shift; continue; fi
                case "$1" in
                    --rm|-i) ;;
                    -e) envs+=("$2"); shift ;;
                    -v)
                        spec="${2%:ro}"; src="${spec%%:*}"; dst="${spec#*:}"
                        case "$src" in /*) : ;; *) src="@VOLUMES@/$src" ;; esac
                        srcs+=("$src"); dsts+=("$dst"); shift
                        ;;
                    *) image_seen=1 ;;
                esac
                shift
            done
            local i arg
            local -a out=()
            for arg in "${cmd[@]}"; do
                for i in "${!dsts[@]}"; do arg="${arg//${dsts[$i]}/${srcs[$i]}}"; done
                out+=("$arg")
            done
            if [ "${out[0]}" = tar ]; then
                "@TAR@" "${out[@]:1}"
            else
                ( for arg in ${envs[@]+"${envs[@]}"}; do export "$arg"; done
                  PATH="@TARDIR@:$PATH" "${out[@]}" )
            fi
            ;;
    esac
}
source "@ADDON@"
source "@BACKUP@"
# After the libraries: these replace their own definitions.
_require_setup_done() { :; }
_topology_mode() { echo single; }
_stopped_containers_go_stale() { return 1; }
_pull_quietly() { return 1; }
_verify_addon_images() { :; }
_addon_path() { echo "@ADDONS@/$1"; }
_post_restore_mark() { echo "$1" > "$CONFIG_DIR/post-restore.pending"; }
_post_restore_before_modules() {
    echo "post-restore core" >> "@LOG@"
    rm -f "$CONFIG_DIR/post-restore.pending"
    POST_RESTORE_STATUS="ok"
}
_post_restore() { echo "post-restore core now" >> "@LOG@"; }
_post_restore_hint() { :; }
# The add-on's compose project: `run` starts the module's migration image (the stub).
_addon_compose() {
    local verb="$1" name="$2"; shift 3
    echo "compose $verb $name $*" >> "@LOG@"
    if [ "$verb" = run ]; then
        local -a rest=()
        ( while [ $# -gt 0 ]; do
              case "$1" in
                  --rm|-T) ;;
                  -e) export "${2?}"; shift ;;
                  *) rest+=("$1") ;;
              esac
              shift
          done
          "@PYTHON@" "@STUB@" "${rest[@]}" )
    fi
}
"""

# The module's migration image: `erasure-replay` deletes every object of the add-on's
# journal at the target from its database volume; `post-restore` throws the delegation key
# away. It records what it was called with, and fails when told to.
_STUB = r"""
import json, os, sys
from pathlib import Path
service, action = sys.argv[1], sys.argv[2]
with open("@ACTIONS_LOG@", "a", encoding="utf-8") as log:
    log.write(json.dumps({"service": service, "action": action,
                          "trigger": os.environ.get("PAPAIA_ERASURE_TRIGGER"),
                          "correlation": os.environ.get("PAPAIA_CORRELATION_ID")}) + "\n")
if Path("@FAIL@").is_file() and Path("@FAIL@").read_text().strip() == action:
    sys.exit(7)
if action == "erasure-replay":
    journal = Path("@TARGET@") / "erasure-journal" / "flow.jsonl"
    for line in journal.read_text(encoding="utf-8").splitlines() if journal.is_file() else []:
        entry = json.loads(line)
        if entry["kind"] == "erase":
            (Path("@VOLUMES@") / "flow_flow-db" / entry["object_ref"]).unlink(missing_ok=True)
elif action == "post-restore":
    (Path("@VOLUMES@") / "flow_flow-delegation-key" / "key").write_text("new-key-after-restore")
"""

FLOW_MANIFEST = {
    "name": "flow",
    "actions": {
        "erasure-replay": {"service": "flow-migrate", "args": ["erasure-replay"]},
        "post-restore": {"service": "flow-migrate", "args": ["post-restore"]},
        "reset": {"service": "flow-maint", "args": ["--reset"], "destructive": True},
    },
}


def _stack(tmp_path: Path) -> dict:
    repo = tmp_path / "repo"
    (repo / "src" / "infra").mkdir(parents=True)
    (repo / "src" / "docker-compose.yml").write_text(
        "include:\n  - path: ./infra/docker-compose.yml\n", encoding="utf-8"
    )
    (repo / "src" / "infra" / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: stub\n    volumes: [keycloak-postgresql:/data]\n"
        "volumes:\n  keycloak-postgresql:\n  papaia-erasure:\n",
        encoding="utf-8",
    )
    addons = tmp_path / "addons"
    addon = addons / "flow"
    addon.mkdir(parents=True)
    (addon / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: stub\nvolumes:\n  flow-db:\n  flow-delegation-key:\n",
        encoding="utf-8",
    )
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump(FLOW_MANIFEST), encoding="utf-8")
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / "notes.txt").write_text("canary-config-5521\n", encoding="utf-8")
    (config / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "flow", "path": str(addon), "active": True}]}),
        encoding="utf-8",
    )
    volumes = tmp_path / "volumes"
    for name, files in {
        "papaia_keycloak-postgresql": {"data": "canary-db-7731"},
        "papaia_papaia-erasure": {"data": "local-journal-copy"},
        "flow_flow-db": {"run-1": "canary-flow-4410", "doc-7": "canary-deleted-8812"},
        "flow_flow-delegation-key": {"key": "delegation-key-at-backup"},
    }.items():
        (volumes / name).mkdir(parents=True)
        for file, content in files.items():
            (volumes / name / file).write_text(content, encoding="utf-8")
    volume_list = tmp_path / "volume-list.tsv"
    volume_list.write_text(
        "".join(
            f"{name.split('_', 1)[0]}\t{name}\n"
            for name in sorted(p.name for p in volumes.iterdir())
        ),
        encoding="utf-8",
    )
    target = tmp_path / "backup"
    target.mkdir()
    identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(config, "betrieb", recipient)
    backup_crypt.init_target(config, target)
    key_file = tmp_path / "keys" / "betrieb.age"
    key_file.parent.mkdir()
    key_file.write_text(f"# betrieb\n{identity}\n", encoding="utf-8")
    stub = tmp_path / "migrate_stub.py"
    stub.write_text(
        _STUB.replace("@ACTIONS_LOG@", (tmp_path / "actions.log").as_posix())
        .replace("@FAIL@", (tmp_path / "fail-action").as_posix())
        .replace("@TARGET@", target.as_posix())
        .replace("@VOLUMES@", volumes.as_posix()),
        encoding="utf-8",
    )
    return {"repo": repo, "config": config, "volumes": volumes, "list": volume_list,
            "target": target, "addons": addons, "identity": identity, "key": key_file,
            "stub": stub}


def _run(tmp_path: Path, stack: dict, body: str, *, stdin: str = "") -> tuple:
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", stack["config"].as_posix())
        .replace("@ROOT@", stack["repo"].as_posix())
        .replace("@TOOLS@", TOOLS.as_posix())
        .replace("@PYTHON@", sys.executable)
        .replace("@LOG@", log.as_posix())
        .replace("@VOLUME_LIST@", stack["list"].as_posix())
        .replace("@VOLUMES@", stack["volumes"].as_posix())
        .replace("@ADDONS@", stack["addons"].as_posix())
        .replace("@STUB@", stack["stub"].as_posix())
        .replace("@IN_USE@", (tmp_path / "in-use.tsv").as_posix())
        .replace("@TARDIR@", str(Path(TAR).parent))
        .replace("@TAR@", str(TAR))
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@BACKUP@", BACKUP_SH.as_posix())
    )
    env = {k: v for k, v in os.environ.items() if k != "PAPAIA_CORRELATION_ID"}
    done = subprocess.run(
        [str(BASH), "-c", f"{harness}\n{body}"], capture_output=True, text=True,
        input=stdin, check=False, timeout=120, env=env,
    )
    return done, log.read_text(encoding="utf-8").splitlines()


def _backup(tmp_path: Path, stack: dict) -> str:
    done, _calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 0, done.stderr + done.stdout
    return backup.load_index(stack["target"])["backups"][0]["id"]


def _after_backup(stack: dict) -> None:
    """What happens on the stack between the backup and the restore: a person deletes
    doc-7 (the module deletes it and writes the journal entry at the target), a new
    delegation key is made, and the database volume is lost."""
    flow_db = stack["volumes"] / "flow_flow-db"
    (flow_db / "doc-7").unlink()
    journal = stack["target"] / "erasure-journal"
    journal.mkdir(exist_ok=True)
    (journal / "flow.jsonl").write_text(
        json.dumps({"id": "0199a000-0000-7000-8000-0000000000e1", "module": "flow", "seq": 1,
                    "kind": "erase", "object_ref": "doc-7", "subject_ref": "ab" * 32,
                    "at": "2026-11-20T10:00:00Z", "reason": "person_request"}) + "\n",
        encoding="utf-8",
    )
    (stack["volumes"] / "flow_flow-delegation-key" / "key").write_text("delegation-key-later")
    for path in list(flow_db.iterdir()):
        path.unlink()
    (stack["volumes"] / "papaia_keycloak-postgresql" / "data").write_text("emptied")
    (stack["config"] / "notes.txt").write_text("changed\n", encoding="utf-8")


def _audit(config: Path) -> list[dict]:
    path = config / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _actions(tmp_path: Path) -> list[dict]:
    path = tmp_path / "actions.log"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _index(calls: list[str], needle: str) -> int:
    return next(i for i, c in enumerate(calls) if needle in c)


def _no_key_anywhere(tmp_path: Path, stack: dict, calls: list[str], done) -> None:
    secret = stack["identity"]
    assert secret not in "\n".join(calls)
    assert secret not in done.stdout and secret not in done.stderr
    for path in (stack["target"] / "backup.log", stack["config"] / "audit" / "papaia-ctl.jsonl"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8")
    assert not any(secret in p.read_text(errors="ignore")
                   for p in stack["config"].rglob("*") if p.is_file())


# ─────────────────────────────────────────────────────────────────────────
# the key
# ─────────────────────────────────────────────────────────────────────────


def test_an_encrypted_point_without_a_key_is_refused_before_anything_is_touched(tmp_path):
    stack = _stack(tmp_path)
    point = _backup(tmp_path, stack)
    _after_backup(stack)

    done, calls = _run(tmp_path, stack, f'cmd_restore -y --backup-dir="{stack["target"]}"')
    assert done.returncode == 2, done.stderr
    assert f"The key for restore point {point} is missing" in done.stderr
    assert "betrieb age1" in done.stderr and "--identity" in done.stderr
    assert not any(c.startswith("docker run") or c.startswith("compose ") for c in calls)
    assert (stack["config"] / "notes.txt").read_text() == "changed\n"
    assert not (stack["config"] / "post-restore.pending").exists()


def test_a_key_that_is_no_recipient_is_refused_before_anything_is_touched(tmp_path):
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    other, _recipient = age.generate_identity()

    done, calls = _run(tmp_path, stack,
                       f'cmd_restore -y --identity=- --backup-dir="{stack["target"]}"',
                       stdin=other + "\n")
    assert done.returncode == 2, done.stderr
    assert "is missing" in done.stderr and "not a recipient" in done.stderr
    assert not any(c.startswith("docker run") or c.startswith("compose ") for c in calls)
    assert other not in "\n".join(calls)


def test_a_changed_archive_is_refused_before_anything_is_touched(tmp_path):
    stack = _stack(tmp_path)
    point = _backup(tmp_path, stack)
    manifest = backup.read_manifest(stack["target"] / point)
    volume = next(a for a in manifest["artifacts"] if a["target"] == "flow_flow-db")
    archive = stack["target"] / point / volume["archive"]
    archive.write_bytes(archive.read_bytes() + b"x")

    done, calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --identity="{stack["key"]}" --backup-dir="{stack["target"]}"',
    )
    assert done.returncode == 3, done.stderr
    assert "checksum" in done.stderr
    assert not any(c.startswith("docker run") or c.startswith("compose ") for c in calls)


def test_the_key_on_standard_input_needs_y(tmp_path):
    # Standard input carries the key, so it cannot carry the answer to the confirmation.
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    _after_backup(stack)

    done, calls = _run(
        tmp_path, stack, f'cmd_restore --identity=- --backup-dir="{stack["target"]}"',
        stdin=stack["identity"] + "\n",
    )
    assert done.returncode == 2, done.stderr
    assert "--identity=- reads the key from standard input" in done.stderr
    assert "-y" in done.stderr
    assert not any("backup-identities" in c or "restore-resolve" in c for c in calls)
    assert not any(c.startswith("docker run") or c.startswith("compose ") for c in calls)
    assert (stack["config"] / "notes.txt").read_text() == "changed\n"


def test_restore_with_the_key_on_standard_input_brings_the_data_back(tmp_path):
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    _after_backup(stack)

    done, calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --no-restart --identity=- --backup-dir="{stack["target"]}"',
        stdin=stack["identity"] + "\n",
    )
    assert done.returncode == 0, done.stderr + done.stdout
    volumes = stack["volumes"]
    assert (volumes / "papaia_keycloak-postgresql" / "data").read_text() == "canary-db-7731"
    assert (volumes / "flow_flow-db" / "run-1").read_text() == "canary-flow-4410"
    assert (stack["config"] / "notes.txt").read_text() == "canary-config-5521\n"
    # Not in the backup, so not brought back: the key made after it stays.
    assert (volumes / "flow_flow-delegation-key" / "key").read_text() == "delegation-key-later"
    assert (volumes / "papaia_papaia-erasure" / "data").read_text() == "local-journal-copy"
    # Without a restart no module starts here; the journal is applied before it does.
    assert _actions(tmp_path) == []
    pending = module_actions.load(stack["config"])
    assert pending["modules"] == {"flow": ["erasure-replay", "post-restore"]}
    assert pending["trigger"] == "restore"
    _no_key_anywhere(tmp_path, stack, calls, done)


# ─────────────────────────────────────────────────────────────────────────
# the erasure journal and the module's post-restore before the module starts
# ─────────────────────────────────────────────────────────────────────────


def test_a_deleted_canary_stays_deleted_after_restore(tmp_path):
    stack = _stack(tmp_path)
    point = _backup(tmp_path, stack)
    _after_backup(stack)

    done, calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )
    assert done.returncode == 0, done.stderr + done.stdout
    flow_db = stack["volumes"] / "flow_flow-db"
    assert (flow_db / "run-1").read_text() == "canary-flow-4410"
    assert not (flow_db / "doc-7").exists(), "the deleted canary came back"

    # Database first (the restore), then the journal, then the holder's step, then the
    # module: nothing of the module runs before the deletions are applied again.
    replay = _index(calls, "compose run flow --rm")
    assert "flow-migrate erasure-replay" in calls[replay]
    holder = _index(calls, "flow-migrate post-restore")
    up = _index(calls, "compose up flow")
    assert _index(calls, "post-restore core") < replay < holder < up
    # Delegations are invalid: the holder made a new key, the old one is not in the backup.
    assert (stack["volumes"] / "flow_flow-delegation-key" / "key").read_text() == (
        "new-key-after-restore"
    )

    ran = _actions(tmp_path)
    assert [a["action"] for a in ran] == ["erasure-replay", "post-restore"]
    assert {a["trigger"] for a in ran} == {"restore"}
    rows = _audit(stack["config"])
    action_rows = [r for r in rows if r["event"] == "module_action_run"]
    assert [(r["detail"]["addon"], r["detail"]["action"], r["result"]) for r in action_rows] == [
        ("flow", "erasure-replay", "allowed"), ("flow", "post-restore", "allowed"),
    ]
    assert {r["correlation_id"] for r in action_rows} == {ran[0]["correlation"]}
    assert all(r["detail"]["restore_point"] == point for r in action_rows)
    assert module_actions.load(stack["config"]) is None
    log = (stack["target"] / "backup.log").read_text(encoding="utf-8")
    assert "module_actions=ok" in log
    _no_key_anywhere(tmp_path, stack, calls, done)


def test_the_restore_records_its_duration(tmp_path):
    stack = _stack(tmp_path)
    point = _backup(tmp_path, stack)

    done, _calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )
    assert done.returncode == 0, done.stderr
    log = (stack["target"] / "backup.log").read_text(encoding="utf-8")
    assert re.search(r"restore-scoped id=\S+ result=ok .*duration=\d+s", log)
    row = next(r for r in _audit(stack["config"]) if r["event"] == "restore_applied")
    assert row["detail"]["id"] == point and row["result"] == "allowed"
    assert isinstance(row["detail"]["duration_s"], int) and row["detail"]["duration_s"] >= 0
    assert row["detail"]["module_actions"] == "ok" and row["detail"]["encrypted"] is True
    assert "Restore took" in done.stdout


def test_a_failing_replay_keeps_the_module_down_and_the_step_pending(tmp_path):
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    _after_backup(stack)
    (tmp_path / "fail-action").write_text("erasure-replay")

    done, calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )
    assert done.returncode != 0
    assert "erasure-replay of add-on flow failed" in done.stderr
    assert not any(c.startswith("compose up flow") for c in calls)
    assert not any("flow-migrate post-restore" in c for c in calls)
    assert module_actions.load(stack["config"])["modules"] == {
        "flow": ["erasure-replay", "post-restore"]
    }
    failed = [r for r in _audit(stack["config"]) if r["event"] == "module_action_run"]
    assert [(r["detail"]["action"], r["result"], r["detail"]["exit_code"]) for r in failed] == [
        ("erasure-replay", "error", 7)
    ]
    assert "module_actions=pending" in (stack["target"] / "backup.log").read_text()

    # The next start of the add-on runs both before it comes up.
    (tmp_path / "fail-action").unlink()
    again, calls = _run(tmp_path, stack, f'_addon_compose_up flow "{stack["addons"]}/flow"')
    assert again.returncode == 0, again.stderr
    assert _index(calls, "flow-migrate erasure-replay") < _index(calls, "compose up flow")
    assert not (stack["volumes"] / "flow_flow-db" / "doc-7").exists()
    assert module_actions.load(stack["config"]) is None


def test_an_add_on_without_a_pending_step_starts_as_before(tmp_path):
    stack = _stack(tmp_path)
    done, calls = _run(tmp_path, stack, f'_addon_compose_up flow "{stack["addons"]}/flow"')
    assert done.returncode == 0, done.stderr
    assert [c for c in calls if c.startswith("compose ")] == ["compose up flow -d"]
    assert _actions(tmp_path) == []


def test_an_unreadable_pending_file_keeps_every_module_down(tmp_path):
    stack = _stack(tmp_path)
    (stack["config"] / module_actions.MARKER).write_text("{not json", encoding="utf-8")
    done, calls = _run(tmp_path, stack, f'_addon_compose_up flow "{stack["addons"]}/flow"')
    assert done.returncode == 3
    assert not any(c.startswith("compose up") for c in calls)
    assert module_actions.MARKER in done.stderr


def test_a_scoped_restore_with_a_damaged_pending_file_does_not_start_the_stack(tmp_path):
    # The steps of the add-ons outside the selection are unknown: replacing the file
    # would lose them, so the restore stops before anything starts.
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    _after_backup(stack)
    marker = stack["config"] / module_actions.MARKER
    marker.write_text("{not json", encoding="utf-8")

    done, calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )
    assert done.returncode == 3, done.stderr + done.stdout
    assert "whole restore" in done.stderr
    assert marker.read_text(encoding="utf-8") == "{not json"
    assert not any(c.startswith("compose up") or c.startswith("compose run") for c in calls)
    assert _actions(tmp_path) == []
    assert "module_actions=failed" in (stack["target"] / "backup.log").read_text()


def test_a_whole_restore_skips_a_volume_another_project_still_uses(tmp_path):
    # RS-2 next to RS on one engine: the original installation still runs its database.
    stack = _stack(tmp_path)
    _backup(tmp_path, stack)
    _after_backup(stack)
    (tmp_path / "in-use.tsv").write_text(
        "papaia_keycloak-postgresql\trs1-keycloak-db-1\n", encoding="utf-8"
    )

    done, calls = _run(
        tmp_path, stack,
        'cmd_start() { echo "start $*" >> "' + (tmp_path / "calls.log").as_posix() + '";'
        ' POST_RESTORE_STATUS=ok; }\n'
        '_addon_compose_all() { echo "compose-all $*" >> "'
        + (tmp_path / "calls.log").as_posix() + '"; }\n'
        f'cmd_restore -y --identity="{stack["key"]}" --backup-dir="{stack["target"]}"',
    )
    assert done.returncode == 0, done.stderr + done.stdout
    assert "skipped papaia_keycloak-postgresql: still in use by rs1-keycloak-db-1" in (
        done.stderr
    )
    volumes = stack["volumes"]
    # Not overwritten underneath the other project's process ...
    assert (volumes / "papaia_keycloak-postgresql" / "data").read_text() == "emptied"
    # ... while everything else came back.
    assert (volumes / "flow_flow-db" / "run-1").read_text() == "canary-flow-4410"
    assert (stack["config"] / "notes.txt").read_text() == "canary-config-5521\n"
    assert any(c.startswith("start ") for c in calls)
    log = (stack["target"] / "backup.log").read_text(encoding="utf-8")
    assert re.search(r"restore id=\S+ result=partial ", log)
    row = next(r for r in _audit(stack["config"]) if r["event"] == "restore_applied")
    assert row["detail"]["result"] == "partial"


def test_addon_run_does_not_offer_the_restore_actions(tmp_path):
    stack = _stack(tmp_path)
    done, calls = _run(tmp_path, stack, "cmd_addon_run flow erasure-replay")
    assert done.returncode == 2
    assert "only restore runs it" in done.stderr
    assert not any(c.startswith("compose ") for c in calls)
    listed, _calls = _run(tmp_path, stack, "cmd_addon_run flow --json")
    assert listed.returncode == 0, listed.stderr
    assert [a["name"] for a in json.loads(listed.stdout)] == ["reset"]
