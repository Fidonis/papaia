"""Staged upgrade (lib/upgrade_stages.py): stage selection, the module plan against the
suite matrix, the upgrade state, the write lock and the stage-0 key check."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from lib import age
from lib import upgrade_stages as us

MATRIX = {
    "schema": "papaia.compat-matrix/1",
    "components": ["papaia-data", "papaia-studio", "papaia-flow"],
    "suites": [
        {
            "suite": "1.9.0", "status": "released", "core": ">=1.9.0,<1.10.0",
            "addon_api": {"min": 1, "current": 6},
            "versions": {"papaia-flow": ">=0.0.1,<0.1.0"},
        },
        {
            "suite": "1.10.0", "status": "candidate", "core": ">=1.10.0,<1.11.0",
            "addon_api": {"min": 1, "current": 13},
            "versions": {
                "papaia-data": ">=0.1.0,<0.2.0",
                "papaia-studio": ">=0.2.0,<0.3.0",
                "papaia-flow": ">=0.1.0,<0.2.0",
            },
        },
    ],
}


def _ok(name: str) -> dict:
    return {"name": name, "status": "OK", "axis": None, "reason": None}


def _config(tmp_path: Path, recipients: list[tuple[str, str]] | None = None,
            version: str = "1.8.0") -> Path:
    config = tmp_path / "papaia-config"
    config.mkdir()
    env = "COMPOSE_PROJECT_NAME=papaia\n"
    if recipients:
        env += "PAPAIA_BACKUP_RECIPIENTS=" + ",".join(f"{n}:{k}" for n, k in recipients) + "\n"
    (config / ".env").write_text(env, encoding="utf-8")
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({
            "platform_version": version,
            "addons": [
                {"name": "papaia-flow", "path": "/x/flow", "active": True, "state": "running"},
            ],
        }),
        encoding="utf-8",
    )
    return config


def _audit_rows(config: Path) -> list[dict]:
    path = config / "audit" / "papaia-ctl.jsonl"
    candidates = [path] if path.is_file() else list(config.rglob("*.jsonl"))
    rows: list[dict] = []
    for candidate in candidates:
        rows += [json.loads(line) for line in candidate.read_text().splitlines() if line]
    return [r for r in rows if str(r.get("operation", "")).startswith("upgrade.")]


# ── stage selection ──────────────────────────────────────────────────────────


def test_a_full_run_has_every_stage_in_the_default_order():
    assert us.select_stages(None, None, {}) == [
        "preflight", "restore-point", "core", "me", "data", "studio", "flow", "assist", "finish",
    ]
    assert us.STAGES.index("data") < us.STAGES.index("studio")


def test_a_module_stage_before_the_core_stage_is_refused():
    with pytest.raises(us.StageError, match="core"):
        us.select_stages("data", None, {})


def test_selected_stages_always_start_with_the_check_and_the_restore_point():
    assert us.select_stages("core", None, {}) == ["preflight", "restore-point", "core"]


def test_module_stages_run_in_any_order_after_the_core_stage():
    state = {"stages": {s: {"status": "ok" if s in us.CORE_STAGES else "pending"}
                        for s in us.STAGES}}
    assert us.select_stages("flow,data", state, {}) == ["flow", "data"]


def test_a_required_module_must_come_first():
    state = {"stages": {s: {"status": "ok" if s in us.CORE_STAGES else "pending"}
                        for s in us.STAGES}}
    requires = {"papaia-studio": ["papaia-data"]}
    with pytest.raises(us.StageError, match="papaia-data"):
        us.select_stages("studio,data", state, requires)
    assert us.select_stages("data,studio", state, requires) == ["data", "studio"]


def test_finish_waits_for_every_module_stage():
    state = {"stages": {s: {"status": "ok" if s in us.CORE_STAGES else "pending"}
                        for s in us.STAGES}}
    with pytest.raises(us.StageError, match="finish"):
        us.select_stages("finish", state, {})


def test_an_unknown_stage_is_refused():
    with pytest.raises(us.StageError, match="unknown stage"):
        us.select_stages("core,database", None, {})


# ── module plan ──────────────────────────────────────────────────────────────


def test_a_module_with_a_new_checkout_is_upgraded_in_its_stage(tmp_path: Path):
    steps, warnings = us.plan_modules(
        [_ok("papaia-data")], {"papaia-data": "0.1.0"}, MATRIX, "1.10.0",
        {"papaia-data": tmp_path}, force=False,
    )
    data = [s for s in steps if s["addon"] == "papaia-data"]
    assert data == [{"stage": "data", "addon": "papaia-data", "action": "upgrade",
                     "path": str(tmp_path), "reason": ""}]
    assert warnings == []


def test_a_module_one_suite_behind_stays_and_is_named(tmp_path: Path):
    steps, warnings = us.plan_modules(
        [_ok("papaia-flow")], {"papaia-flow": "0.0.5"}, MATRIX, "1.10.0", {}, force=False,
    )
    flow = next(s for s in steps if s["addon"] == "papaia-flow")
    assert flow["action"] == "keep"
    assert warnings == [
        "papaia-flow 0.0.5 is compatible with core 1.10.0; an update is recommended"
    ]


def test_an_incompatible_module_stops_the_upgrade_before_any_change():
    result = {"name": "papaia-studio", "status": "INCOMPATIBLE", "axis": "matrix",
              "reason": "'papaia-studio' 0.1.0 is not in the suite matrix for core 1.10.0: "
                        "allowed >=0.2.0,<0.3.0 (suite 1.10.0)"}
    with pytest.raises(us.StageError) as info:
        us.plan_modules([result], {"papaia-studio": "0.1.0"}, MATRIX, "1.10.0", {},
                        force=False)
    assert "papaia-studio" in str(info.value) and ">=0.2.0" in str(info.value)


def test_with_force_an_incompatible_module_is_blocked_not_upgraded():
    result = {"name": "papaia-studio", "status": "INCOMPATIBLE", "axis": "matrix",
              "reason": "not in the suite matrix"}
    steps, _ = us.plan_modules([result], {"papaia-studio": "0.1.0"}, MATRIX, "1.10.0", {},
                               force=True)
    studio = next(s for s in steps if s["addon"] == "papaia-studio")
    assert studio["action"] == "block"
    assert "not in the suite matrix" in studio["reason"]


def test_a_module_that_is_not_installed_is_reported_absent():
    steps, _ = us.plan_modules([], {}, MATRIX, "1.10.0", {}, force=False)
    assert {s["addon"]: s["action"] for s in steps}["papaia-assist"] == "absent"


def test_an_error_verdict_is_never_degraded_by_force():
    result = {"name": "papaia-data", "status": "ERROR", "axis": "manifest", "reason": "broken"}
    with pytest.raises(us.StageError, match="broken"):
        us.plan_modules([result], {"papaia-data": "0.1.0"}, MATRIX, "1.10.0", {}, force=True)


def test_addon_paths_are_checked_at_the_boundary(tmp_path: Path):
    assert us.parse_addon_paths([f"papaia-data={tmp_path}"], {"papaia-data"}) == {
        "papaia-data": tmp_path
    }
    for bad in ("papaia-data", "=x", f"Papaia-Data={tmp_path}", f"papaia-x={tmp_path}",
                "papaia-data=/does/not/exist", f"papaia-data={tmp_path},extra"):
        with pytest.raises(us.StageError):
            us.parse_addon_paths([bad], {"papaia-data", "papaia-x"} - {"papaia-x"})
    with pytest.raises(us.StageError, match="twice"):
        us.parse_addon_paths([f"papaia-data={tmp_path}"] * 2, {"papaia-data"})


# ── stage 0: the operator key ────────────────────────────────────────────────


def test_the_right_operator_key_opens_the_check_block(tmp_path: Path):
    secret, public = age.generate_identity()
    _, other = age.generate_identity()
    config = _config(tmp_path, [("betrieb", public), ("notfall", other)])
    assert us.check_identity(config, [secret]) == ["betrieb"]


def test_a_wrong_operator_key_is_refused_with_the_named_sentence(tmp_path: Path):
    _, public = age.generate_identity()
    wrong, _ = age.generate_identity()
    config = _config(tmp_path, [("betrieb", public)])
    with pytest.raises(us.StageError) as info:
        us.check_identity(config, [wrong])
    assert str(info.value).startswith(us.NO_KEY_MESSAGE)


def test_without_backup_recipients_there_is_no_way_back(tmp_path: Path):
    secret, _ = age.generate_identity()
    config = _config(tmp_path)
    with pytest.raises(us.StageError) as info:
        us.check_identity(config, [secret])
    assert str(info.value).startswith(us.NO_KEY_MESSAGE)


def test_no_key_at_all_is_refused(tmp_path: Path):
    _, public = age.generate_identity()
    config = _config(tmp_path, [("betrieb", public)])
    with pytest.raises(us.StageError):
        us.check_identity(config, [])


# ── state, write lock, audit ─────────────────────────────────────────────────


def _steps() -> list[dict]:
    return [{"stage": "data", "addon": "papaia-data", "action": "keep", "path": "",
             "reason": ""}]


def test_begin_sets_the_write_lock_and_records_the_restore_point(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PAPAIA_CORRELATION_ID", "0b9a4c0e-8d47-4b0a-9a51-1f2c3d4e5f60")
    config = _config(tmp_path)
    state = us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
                     steps=_steps())
    lock = us.read_lock(config)
    assert lock.active and lock.problem is None
    assert lock.doc["message"] == us.LOCK_MESSAGE
    assert lock.doc["upgrade_id"] == state["id"]
    mode = stat.S_IMODE(os.stat(config / "state" / us.LOCK_FILE).st_mode)
    assert mode == 0o644
    loaded = us.load_state(config)
    assert loaded["restore_point"] == "2026-11-21_10-00-00"
    assert loaded["stages"]["preflight"]["status"] == "ok"
    assert loaded["stages"]["restore-point"]["status"] == "ok"
    assert loaded["stages"]["core"]["status"] == "pending"
    rows = _audit_rows(config)
    assert [r["operation"] for r in rows] == ["upgrade.begin"]
    assert rows[0]["correlation_id"] == "0b9a4c0e-8d47-4b0a-9a51-1f2c3d4e5f60"
    assert rows[0]["detail"]["restore_point"] == "2026-11-21_10-00-00"


def test_a_retry_of_the_same_target_keeps_the_first_restore_point(tmp_path: Path):
    config = _config(tmp_path)
    first = us.begin(config, source="1.8.0", target="1.10.0",
                     restore_point="2026-11-21_10-00-00", steps=_steps())
    us.record(config, "core", "failed", 3)
    assert us.restore_point_for(config, "1.10.0") == "2026-11-21_10-00-00"
    again = us.begin(config, source="1.8.0", target="1.10.0",
                     restore_point="2026-11-21_10-00-00", steps=_steps())
    assert again["id"] == first["id"]


def test_another_target_is_refused_while_an_upgrade_is_unfinished(tmp_path: Path):
    config = _config(tmp_path)
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=_steps())
    with pytest.raises(us.StageError, match="1.10.0"):
        us.begin(config, source="1.8.0", target="1.9.0", restore_point="2026-11-21_11-00-00",
                 steps=_steps())
    with pytest.raises(us.StageError):
        us.restore_point_for(config, "1.9.0")


def test_a_failed_stage_keeps_the_lock(tmp_path: Path):
    config = _config(tmp_path)
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=_steps())
    us.record(config, "core", "failed", 12)
    assert us.read_lock(config).active
    assert us.load_state(config)["stages"]["core"] == {"status": "failed", "seconds": 12}
    assert [r["operation"] for r in _audit_rows(config)] == ["upgrade.begin", "upgrade.stage"]
    assert _audit_rows(config)[1]["result"] == "error"


def test_finish_lifts_the_lock_only_after_every_stage(tmp_path: Path):
    config = _config(tmp_path)
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=_steps())
    us.record(config, "core", "ok", 40)
    with pytest.raises(us.StageError, match="data"):
        us.finish(config)
    assert us.read_lock(config).active
    for stage in ("me", "data", "studio", "flow", "assist"):
        us.record(config, stage, "ok", 1)
    report = us.finish(config)
    assert not us.read_lock(config).active
    assert not (config / "state" / us.LOCK_FILE).exists()
    assert report["stages"]["core"]["seconds"] == 40
    assert us.load_state(config)["finished"] is not None
    assert _audit_rows(config)[-1]["operation"] == "upgrade.finish"


def test_the_lock_can_be_released_only_after_the_way_back(tmp_path: Path):
    config = _config(tmp_path, version="1.10.0")
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=_steps())
    us.record(config, "core", "failed", 3)
    with pytest.raises(us.StageError, match="1.8.0"):
        us.release_lock(config, bundle_version="1.8.0", checkout_version="1.10.0")
    us.release_lock(config, bundle_version="1.8.0", checkout_version="1.8.0")
    assert not us.read_lock(config).active
    assert us.load_state(config)["abandoned"] is not None
    assert _audit_rows(config)[-1]["operation"] == "upgrade.release-lock"


@pytest.mark.parametrize("content", [b"{", b"[]", b'{"schema":"x"}', b"\xff\xfe", b"x" * 9000])
def test_an_unreadable_lock_counts_as_active(tmp_path: Path, content: bytes):
    config = _config(tmp_path)
    (config / "state").mkdir()
    (config / "state" / us.LOCK_FILE).write_bytes(content)
    lock = us.read_lock(config)
    assert lock.active and lock.problem


def test_a_state_file_with_unknown_fields_is_refused(tmp_path: Path):
    config = _config(tmp_path)
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=_steps())
    path = config / "state" / us.STATE_FILE
    doc = json.loads(path.read_text())
    doc["surprise"] = 1
    path.write_text(json.dumps(doc))
    with pytest.raises(us.StageError, match="surprise"):
        us.load_state(config)


def test_blocking_a_module_stops_it_and_keeps_its_data_entry(tmp_path: Path):
    config = _config(tmp_path)
    us.begin(config, source="1.8.0", target="1.10.0", restore_point="2026-11-21_10-00-00",
             steps=[{"stage": "flow", "addon": "papaia-flow", "action": "block", "path": "",
                     "reason": "not in the suite matrix"}])
    assert us.block_addons(config) == ["papaia-flow"]
    entry = yaml.safe_load((config / "deployment.yaml").read_text())["addons"][0]
    assert entry["active"] is False
    assert entry["state"] == "stopped"
    assert entry["blocked"]["reason"] == "not in the suite matrix"
    assert entry["blocked"]["core"] == "1.10.0"
    assert entry["path"] == "/x/flow"
    assert _audit_rows(config)[-1]["operation"] == "upgrade.block-addon"


@pytest.mark.parametrize("content", ["", "  \n", "{}"])
def test_the_plan_refuses_an_add_on_check_without_a_result(tmp_path: Path, capsys,
                                                         content: str):
    from lib import cli

    config = tmp_path / "config"
    config.mkdir()
    (config / "deployment.yaml").write_text("platform_version: 1.8.0\naddons: []\n")
    check = tmp_path / "check.json"
    check.write_text(content)
    code = cli.main([
        "--repo-root", str(tmp_path), "--config-dir", str(config), "upgrade-stage", "plan",
        f"--check-file={check}", "--target=1.9.0", f"--target-core={tmp_path}",
    ])
    assert code == 2
    assert "add-on check gave no result" in capsys.readouterr().err
