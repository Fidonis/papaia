"""The module actions a restore runs before an add-on starts (lib/module_actions.py)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
import yaml

from lib import compat, module_actions

CID = "0199a000-0000-7000-8000-00000000c0de"


def _addon(root: Path, name: str, actions: dict | None) -> Path:
    path = root / "addons" / name
    path.mkdir(parents=True)
    manifest: dict = {"name": name}
    if actions is not None:
        manifest["actions"] = actions
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return path


@pytest.fixture()
def stack(tmp_path: Path) -> dict:
    config = tmp_path / "config"
    config.mkdir()
    flow = _addon(tmp_path, "flow", {
        "post-restore": {"service": "flow-migrate", "args": ["post-restore"]},
        "erasure-replay": {"service": "flow-migrate", "args": ["erasure-replay", "--all"]},
        "reset": {"service": "flow-maint"},
    })
    studio = _addon(tmp_path, "studio", {
        "erasure-replay": {"service": "studio-migrate", "args": ["replay"]},
    })
    plain = _addon(tmp_path, "wiki", {"reset": {"service": "maint"}})
    gone = _addon(tmp_path, "old", {"erasure-replay": {"service": "m"}})
    (config / "deployment.yaml").write_text(yaml.safe_dump({"addons": [
        {"name": "flow", "path": str(flow), "active": True},
        {"name": "studio", "path": str(studio), "active": True},
        {"name": "wiki", "path": str(plain), "active": True},
        {"name": "old", "path": str(gone), "active": False},
    ]}), encoding="utf-8")
    return {"config": config, "root": tmp_path, "flow": flow}


def _mark(stack: dict, addons=None, trigger="restore") -> dict:
    return module_actions.mark(
        stack["config"], stack["root"], addons=addons, trigger=trigger,
        restore_point="2026-11-21_02-30-00", correlation_id=CID,
    )


def _rows(config: Path) -> list[dict]:
    path = config / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_a_restore_marks_every_active_add_on_that_declares_a_restore_action(stack):
    marked = _mark(stack)
    assert marked == {"flow": ["erasure-replay", "post-restore"], "studio": ["erasure-replay"]}
    doc = module_actions.load(stack["config"])
    assert doc["trigger"] == "restore" and doc["correlation_id"] == CID
    assert doc["restore_point"] == "2026-11-21_02-30-00"
    mode = stat.S_IMODE((stack["config"] / module_actions.MARKER).stat().st_mode)
    assert mode == 0o600


def test_a_scoped_restore_marks_only_the_add_ons_it_restored(stack):
    assert _mark(stack, addons=["studio"]) == {"studio": ["erasure-replay"]}


def test_nothing_to_run_leaves_no_pending_file(stack):
    assert _mark(stack, addons=["wiki"]) == {}
    assert not (stack["config"] / module_actions.MARKER).exists()


@pytest.mark.parametrize("trigger", ["lifecycle", "", "restore\n"])
def test_only_restore_and_rollback_trigger_the_actions(stack, trigger):
    with pytest.raises(module_actions.ModuleActionError):
        _mark(stack, trigger=trigger)


def test_a_rollback_is_named_as_the_trigger(stack):
    _mark(stack, trigger="rollback")
    trigger, cid, _steps = module_actions.pending(stack["config"], stack["root"], "flow")
    assert (trigger, cid) == ("rollback", CID)


def test_pending_names_the_service_and_fixed_arguments_in_order(stack):
    _mark(stack)
    _trigger, _cid, steps = module_actions.pending(stack["config"], stack["root"], "flow")
    assert steps == [
        ("erasure-replay", "flow-migrate", ["erasure-replay", "--all"]),
        ("post-restore", "flow-migrate", ["post-restore"]),
    ]
    assert module_actions.pending(stack["config"], stack["root"], "wiki")[2] == []


def test_without_a_pending_file_nothing_is_pending(stack):
    assert module_actions.pending(stack["config"], stack["root"], "flow") == ("", "", [])


def test_a_success_clears_the_step_and_the_last_one_the_file(stack):
    _mark(stack)
    module_actions.done(stack["config"], "flow", "erasure-replay", 0)
    module_actions.done(stack["config"], "studio", "erasure-replay", 0)
    assert module_actions.load(stack["config"])["modules"] == {"flow": ["post-restore"]}
    module_actions.done(stack["config"], "flow", "post-restore", 0)
    assert module_actions.load(stack["config"]) is None


def test_a_failure_keeps_the_step_and_every_run_is_one_audit_row(stack):
    _mark(stack)
    module_actions.done(stack["config"], "flow", "erasure-replay", 7)
    module_actions.done(stack["config"], "flow", "erasure-replay", 0)
    rows = _rows(stack["config"])
    assert [(r["event"], r["result"], r["detail"]["exit_code"]) for r in rows] == [
        ("module_action_run", "error", 7), ("module_action_run", "allowed", 0),
    ]
    assert {r["correlation_id"] for r in rows} == {CID}
    assert all(r["format"] == "papaia.audit/1" and r["operation"] == "restore" for r in rows)
    assert rows[0]["effect"] == "delete"
    assert rows[0]["detail"] == {
        "addon": "flow", "action": "erasure-replay", "trigger": "restore",
        "restore_point": "2026-11-21_02-30-00", "exit_code": 7,
        "confirmed_by": rows[0]["detail"]["confirmed_by"],
    }


def test_a_step_that_is_not_pending_is_refused(stack):
    _mark(stack)
    with pytest.raises(module_actions.ModuleActionError):
        module_actions.done(stack["config"], "wiki", "erasure-replay", 0)
    with pytest.raises(module_actions.ModuleActionError):
        module_actions.done(stack["config"], "flow", "reset", 0)


def test_an_action_the_add_on_no_longer_declares_keeps_it_down(stack):
    _mark(stack)
    (stack["flow"] / "papaia-app.yaml").write_text(yaml.safe_dump({"name": "flow"}))
    with pytest.raises(module_actions.ModuleActionError, match="no longer declares"):
        module_actions.pending(stack["config"], stack["root"], "flow")


@pytest.mark.parametrize("arg", ["a\tb", "a\nb", "x" * 600])
def test_arguments_that_do_not_fit_a_line_are_refused(stack, arg):
    _mark(stack)
    manifest = yaml.safe_load((stack["flow"] / "papaia-app.yaml").read_text())
    manifest["actions"]["erasure-replay"]["args"] = [arg]
    (stack["flow"] / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    with pytest.raises(module_actions.ModuleActionError):
        module_actions.pending(stack["config"], stack["root"], "flow")


@pytest.mark.parametrize("content", [
    "{not json",
    json.dumps({"format": "other/1"}),
    json.dumps({"format": module_actions.FORMAT, "trigger": "restore", "correlation_id": CID,
                "restore_point": "p", "modules": {"flow": ["erasure-replay"]}, "extra": 1}),
    json.dumps({"format": module_actions.FORMAT, "trigger": "restore", "correlation_id": CID,
                "restore_point": "p", "modules": {"flow": ["rm -rf"]}}),
    json.dumps({"format": module_actions.FORMAT, "trigger": "restore", "correlation_id": CID,
                "restore_point": "p", "modules": {"../x": ["erasure-replay"]}}),
])
def test_a_damaged_pending_file_is_refused(stack, content):
    (stack["config"] / module_actions.MARKER).write_text(content)
    with pytest.raises(module_actions.ModuleActionError):
        module_actions.load(stack["config"])


def test_a_scoped_restore_refuses_a_damaged_pending_file_and_keeps_it(stack):
    # What is due for the add-ons outside the selection is unknown; replacing the file
    # would drop their erasure replay without a trace.
    path = stack["config"] / module_actions.MARKER
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(module_actions.ModuleActionError, match="whole restore"):
        _mark(stack, addons=["studio"])
    assert path.read_text(encoding="utf-8") == "{not json"


def test_a_whole_restore_replaces_a_damaged_pending_file(stack):
    (stack["config"] / module_actions.MARKER).write_text("{not json", encoding="utf-8")
    assert _mark(stack) == {"flow": ["erasure-replay", "post-restore"],
                            "studio": ["erasure-replay"]}
    assert module_actions.load(stack["config"])["correlation_id"] == CID


def test_a_scoped_restore_keeps_the_steps_of_the_add_ons_outside_it(stack):
    _mark(stack)
    _mark(stack, addons=["studio"])
    assert module_actions.load(stack["config"])["modules"] == {
        "flow": ["erasure-replay", "post-restore"], "studio": ["erasure-replay"],
    }


def test_restore_actions_need_contract_generation_14():
    manifest = {"actions": {"erasure-replay": {"service": "m"}}}
    assert ("actions.erasure-replay", 14) in compat.manifest_generation_features(manifest)
    manifest = {"actions": {"post-restore": {"service": "m"}}}
    assert ("actions.post-restore", 14) in compat.manifest_generation_features(manifest)
    assert compat.manifest_generation_features({"actions": {"reset": {"service": "m"}}}) == []


def test_the_restore_record_is_one_audit_row(stack):
    module_actions.record_restore(
        stack["config"], restore_point="2026-11-21_02-30-00", operation="restore",
        result="ok", duration_s=42, post_restore="ok", module_actions_state="ok",
        artifacts="5/5", encrypted=True, correlation_id=CID,
    )
    (row,) = _rows(stack["config"])
    assert row["event"] == "restore_applied" and row["result"] == "allowed"
    assert row["detail"]["duration_s"] == 42 and row["detail"]["artifacts"] == "5/5"
    assert row["correlation_id"] == CID
