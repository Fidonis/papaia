"""`papaia-ctl recover-snapshot` and the erasure journal mirror end to end in bash
(sicherheit §4.9 (3) and "Kopien außer Haus", betrieb BE-16, BE-16a Nr. 4 and 6, RE-65,
RE-84, RE-86).

The harness of tests/test_restore_journal_cli.py: `docker` runs `tar`/`sh` on host
directories, the add-on's compose project runs a stub of the module's migration image. Here
the stub keeps the module's applied seq next to its data the way a module keeps it in its
database, and reads the journal through the kit: a module whose applied seq is behind the
journal at the target is not ready (BE-16a Nr. 2), and its `erasure-replay` prints its
`erasure_replayed` row.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from papaia_kit.erasure import read_journal

from lib import module_actions
from tests.test_restore_journal_cli import _actions, _audit, _backup, _index, _run, _stack

STUB = r"""
import json, os, sys
from pathlib import Path
from papaia_kit.erasure import read_journal
service, action = sys.argv[1], sys.argv[2]
with open("@ACTIONS_LOG@", "a", encoding="utf-8") as log:
    log.write(json.dumps({"service": service, "action": action,
                          "trigger": os.environ.get("PAPAIA_ERASURE_TRIGGER"),
                          "correlation": os.environ.get("PAPAIA_CORRELATION_ID")}) + "\n")
db = Path("@VOLUMES@") / "flow_flow-db"
if action == "erasure-replay":
    applied_file = db / ".applied"
    applied = int(applied_file.read_text()) if applied_file.is_file() else 0
    kinds = {}
    for entry in read_journal("flow", [Path("@TARGET@") / "erasure-journal"]):
        if entry.seq <= applied:
            continue
        if entry.kind.value == "erase":
            (db / entry.object_ref).unlink(missing_ok=True)
        kinds[entry.kind.value] = kinds.get(entry.kind.value, 0) + 1
        applied = entry.seq
    applied_file.write_text(str(applied))
    print("migrate: replaying the erasure journal")
    print(json.dumps({"format": "papaia.audit/1", "event": "erasure_replayed",
                      "correlation_id": os.environ["PAPAIA_CORRELATION_ID"],
                      "object_ref": {"type": "erasure_journal", "id": "flow"},
                      "result": "allowed",
                      "detail": {"count": sum(kinds.values()), "by_kind": kinds,
                                 "trigger": os.environ["PAPAIA_ERASURE_TRIGGER"]}}))
elif action == "post-restore":
    (Path("@VOLUMES@") / "flow_flow-delegation-key" / "key").write_text("new-key-after-restore")
"""

ROLLBACK_ID = "6f1c2a7e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"


def _entry(seq: int, obj: str, *, kind: str = "erase") -> dict:
    return {"id": str(uuid.uuid4()), "module": "flow", "seq": seq, "kind": kind,
            "object_ref": obj, "subject_ref": "cd" * 32, "at": "2026-11-20T10:00:00.000Z",
            "reason": "person_request"}


def _journal(folder: Path, entries: list[dict]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "flow.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8"
    )


def _stack_with_stub(tmp_path: Path) -> dict:
    stack = _stack(tmp_path)
    stack["stub"].write_text(
        STUB.replace("@ACTIONS_LOG@", (tmp_path / "actions.log").as_posix())
        .replace("@TARGET@", stack["target"].as_posix())
        .replace("@VOLUMES@", stack["volumes"].as_posix()),
        encoding="utf-8",
    )
    with open(stack["config"] / ".env", "a", encoding="utf-8") as env:
        env.write(f"PAPAIA_BACKUP_DIR={stack['target']}\n")
    return stack


def _ready(stack: dict) -> bool:
    """The module's start check: not ready while the journal holds entries beyond its seq."""
    applied_file = stack["volumes"] / "flow_flow-db" / ".applied"
    applied = int(applied_file.read_text()) if applied_file.is_file() else 0
    journal = read_journal("flow", [stack["target"] / "erasure-journal"])
    return all(e.seq <= applied for e in journal)


def _rolled_back_vm(stack: dict) -> None:
    """The hypervisor brought back a VM snapshot: the module's data holds doc-7 and its
    applied seq is 0, while the journal at the backup target (not part of the VM) already
    deletes doc-7. The snapshot also holds a rollback key of an upgrade."""
    db = stack["volumes"] / "flow_flow-db"
    (db / "doc-7").write_text("canary-deleted-8812")
    (db / ".applied").write_text("0")
    _journal(stack["target"] / "erasure-journal", [_entry(1, "doc-7")])
    keys = stack["config"] / "state" / "rollback"
    keys.mkdir(parents=True)
    keys.chmod(0o700)
    (keys / f"{ROLLBACK_ID}.key").write_text("rollback-key-from-the-snapshot\n")
    (stack["target"] / "erasure-journal" / "epoch").write_text(json.dumps(
        {"format": "papaia.erasure-epoch/1", "generation": 4, "seq": {"flow": 1}}
    ))


# The stack's own start (lifecycle.sh): the pending core post-restore first, then every
# add-on through _addon_compose_up, which runs what is due before the add-on comes up.
START = r"""
cmd_start() {
    echo "start $*" >> "@LOG@"
    _post_restore_before_modules 0 || return $?
    _addon_compose_up flow "@ADDONS@/flow" || return $?
}
_addon_compose_all() { echo "compose-all $*" >> "@LOG@"; }
cmd_doctor() { echo "doctor $*" >> "@LOG@"; return "${DOCTOR_RC:-0}"; }
"""


def _start(tmp_path: Path, stack: dict) -> str:
    return (START.replace("@LOG@", (tmp_path / "calls.log").as_posix())
            .replace("@ADDONS@", stack["addons"].as_posix()))


def test_a_rolled_back_vm_keeps_the_module_not_ready_until_recover_snapshot(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _rolled_back_vm(stack)
    # The containers came back with their restart policy: the module is behind the journal.
    assert not _ready(stack)

    done, calls = _run(tmp_path, stack, _start(tmp_path, stack) + "cmd_recover_snapshot")

    assert done.returncode == 0, done.stderr + done.stdout
    db = stack["volumes"] / "flow_flow-db"
    assert not (db / "doc-7").exists(), "the deleted canary came back"
    assert (db / "run-1").read_text() == "canary-flow-4410"
    assert _ready(stack)
    # The add-on is stopped first, then the core's post-restore (realm-wide not-before),
    # then the journal, then the holder's step, then the module; doctor ends the run.
    stop = _index(calls, "compose-all stop")
    replay = _index(calls, "flow-migrate erasure-replay")
    assert stop < _index(calls, "post-restore core") < replay
    assert replay < _index(calls, "flow-migrate post-restore") < _index(calls, "compose up flow")
    assert _index(calls, "compose up flow") < _index(calls, "doctor ")
    ran = _actions(tmp_path)
    assert [a["action"] for a in ran] == ["erasure-replay", "post-restore"]
    assert {a["trigger"] for a in ran} == {"recover-snapshot"}
    assert (stack["volumes"] / "flow_flow-delegation-key" / "key").read_text() == (
        "new-key-after-restore"
    )
    # The rollback keys came from the VM snapshot: they are gone.
    assert list((stack["config"] / "state" / "rollback").iterdir()) == []
    assert module_actions.load(stack["config"]) is None
    assert not (stack["config"] / "post-restore.pending").exists()
    # One line per module: the deletions and revocations it applied again.
    assert "flow: 1 deletion(s), 0 revocation(s) applied again" in done.stdout
    rows = _audit(stack["config"])
    deleted = [r for r in rows if r["event"] == "rollback_key_deleted"]
    assert [r["detail"]["reason"] for r in deleted] == ["recover-snapshot"]
    record = next(r for r in rows if r["operation"] == "recover_snapshot")
    assert record["result"] == "allowed"
    assert record["detail"]["modules"] == {"flow": {"deletions": 1, "revocations": 0}}
    assert record["detail"]["rollback_keys_deleted"] == 1
    assert record["correlation_id"] == ran[0]["correlation"]
    action_rows = [r for r in rows if r["event"] == "module_action_run"]
    assert action_rows[0]["detail"]["count"] == 1
    # The generation the start gate reached is confirmed: doctor state_epoch passes.
    confirmed = json.loads((stack["config"] / "state" / "state-epoch.json").read_text())
    assert confirmed["generation"] == 4 and confirmed["by"] == "recover-snapshot"
    assert "rollback-key-from-the-snapshot" not in done.stdout + done.stderr


def test_a_failing_replay_keeps_the_module_down_and_recover_snapshot_fails(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _rolled_back_vm(stack)
    stack["stub"].write_text("import sys\nsys.exit(7)\n", encoding="utf-8")

    done, calls = _run(tmp_path, stack, _start(tmp_path, stack) + "cmd_recover_snapshot")

    assert done.returncode == 3, done.stderr + done.stdout
    assert "erasure-replay of add-on flow failed" in done.stderr
    assert not any(c.startswith("compose up flow") for c in calls)
    assert (stack["volumes"] / "flow_flow-db" / "doc-7").exists()
    assert not _ready(stack)
    assert module_actions.load(stack["config"])["trigger"] == "recover-snapshot"
    record = next(r for r in _audit(stack["config"]) if r["operation"] == "recover_snapshot")
    assert record["result"] == "error"
    assert not (stack["config"] / "state" / "state-epoch.json").exists()


def test_the_mirror_union_restores_a_journal_entry_missing_at_the_main_target(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _rolled_back_vm(stack)
    # The target was replaced by an older copy: seq 2 (doc-9) is in the mirror alone.
    (stack["volumes"] / "flow_flow-db" / "doc-9").write_text("canary-deleted-9931")
    first = json.loads(
        (stack["target"] / "erasure-journal" / "flow.jsonl").read_text().splitlines()[0]
    )
    mirror = tmp_path / "offsite" / "erasure-journal"
    _journal(mirror, [first, _entry(2, "doc-9")])
    with open(stack["config"] / ".env", "a", encoding="utf-8") as env:
        env.write(f"PAPAIA_ERASURE_MIRROR_DIR={mirror}\n")

    done, _calls = _run(tmp_path, stack, _start(tmp_path, stack) + "cmd_recover_snapshot")

    assert done.returncode == 0, done.stderr + done.stdout
    db = stack["volumes"] / "flow_flow-db"
    assert not (db / "doc-7").exists() and not (db / "doc-9").exists()
    at_target = read_journal("flow", [stack["target"] / "erasure-journal"])
    assert [(e.seq, e.object_ref) for e in at_target] == [(1, "doc-7"), (2, "doc-9")]
    assert "flow: 2 deletion(s), 0 revocation(s) applied again" in done.stdout
    assert "mirror: 1 entr(ies) the backup target lacked" in done.stdout


def test_a_restore_takes_the_union_of_target_and_mirror(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _backup(tmp_path, stack)
    # After the backup doc-9 was deleted; the target was then replaced by a copy from
    # before that deletion, the mirror still holds it.
    mirror = tmp_path / "offsite" / "erasure-journal"
    _journal(mirror, [_entry(1, "doc-7")])
    _journal(stack["target"] / "erasure-journal", [])
    with open(stack["config"] / ".env", "a", encoding="utf-8") as env:
        env.write(f"PAPAIA_ERASURE_MIRROR_DIR={mirror}\n")
    # The restore point brings the .env back; the mirror setting must be in it too.
    _backup(tmp_path, stack)

    done, _calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )

    assert done.returncode == 0, done.stderr + done.stdout
    assert not (stack["volumes"] / "flow_flow-db" / "doc-7").exists()
    assert "mirror: 1 entr(ies) the backup target lacked" in done.stdout


def test_a_restore_without_mirror_prints_the_handbook_sentence(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _backup(tmp_path, stack)
    _journal(stack["target"] / "erasure-journal", [])

    done, _calls = _run(
        tmp_path, stack,
        f'cmd_restore -y --only=addon:flow --identity="{stack["key"]}"'
        f' --backup-dir="{stack["target"]}"',
    )

    assert done.returncode == 0, done.stderr + done.stdout
    assert ("Wird von einer Kopie außer Haus wiederhergestellt, kehren Löschungen nach dem "
            "Tag dieser Kopie zurück.") in done.stderr


def test_an_unreachable_mirror_stops_recover_snapshot_before_anything_changes(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _rolled_back_vm(stack)
    with open(stack["config"] / ".env", "a", encoding="utf-8") as env:
        env.write(f"PAPAIA_ERASURE_MIRROR_DIR={tmp_path / 'unmounted'}\n")

    done, calls = _run(tmp_path, stack, _start(tmp_path, stack) + "cmd_recover_snapshot")

    assert done.returncode == 3
    assert "mirror" in done.stderr
    assert not any(c.startswith("compose") or c.startswith("start") for c in calls)
    assert len(list((stack["config"] / "state" / "rollback").iterdir())) == 1
    assert module_actions.load(stack["config"]) is None


def test_recover_snapshot_ends_with_the_exit_code_of_doctor(tmp_path):
    stack = _stack_with_stub(tmp_path)
    _rolled_back_vm(stack)
    done, _calls = _run(
        tmp_path, stack, _start(tmp_path, stack) + "DOCTOR_RC=1\ncmd_recover_snapshot"
    )
    assert done.returncode == 1
    assert "doctor still reports a failure" in done.stderr


def test_recover_snapshot_takes_no_operator_key_and_no_unknown_option(tmp_path):
    stack = _stack_with_stub(tmp_path)
    done, calls = _run(tmp_path, stack, "cmd_recover_snapshot --identity=-")
    assert done.returncode == 2
    assert "Unknown option for recover-snapshot" in done.stderr
    assert calls == []


def test_addon_run_cannot_start_the_replay_for_recover_snapshot(tmp_path):
    stack = _stack_with_stub(tmp_path)
    done, calls = _run(tmp_path, stack, "cmd_addon_run flow erasure-replay")
    assert done.returncode == 2
    assert not any(c.startswith("compose ") for c in calls)
