"""The rollback key of an upgrade (BE-11, BE-13, RE-11, MN-12): made once per run, kept on
the host only (0600 in a 0700 folder), an extra recipient of R0, deleted with
`upgrade --finalize`, at the end of a run without the upgrade, or after its window, and
reported by `doctor rollback_window`.
"""

from __future__ import annotations

import io
import json
import os
import stat
import tarfile
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from lib import age, backup, backup_crypt, cli, doctor, rollback_key
from lib import upgrade_stages as us

HOUR = 3600


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


@pytest.fixture()
def config(tmp_path: Path) -> Path:
    _, operator = age.generate_identity()
    config_dir = tmp_path / "papaia-config"
    _write(config_dir / ".env",
           f"COMPOSE_PROJECT_NAME=papaia\nPAPAIA_BACKUP_RECIPIENTS=betrieb:{operator}\n")
    _write(config_dir / "deployment.yaml", yaml.safe_dump({"addons": []}))
    return config_dir


def _audit_rows(config_dir: Path) -> list[dict]:
    path = config_dir / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _begin(config_dir: Path, upgrade_id: str | None = None) -> dict:
    return us.begin(config_dir, source="1.10.0", target="1.11.0", restore_point="r0",
                    steps=[], upgrade_id=upgrade_id)


def _finish(config_dir: Path, at: int) -> dict:
    for stage in ("core", "me", "data", "studio", "flow", "assist"):
        us.record(config_dir, stage, "ok", 0)
    state = us.finish(config_dir)
    state["finished"] = at
    us._save(config_dir, state)
    return state


# ── the key itself ──────────────────────────────────────────────────────────


def test_a_new_key_is_private_to_the_host_and_opens_what_is_sealed_to_it(config: Path):
    upgrade_id, public = rollback_key.create(config)
    path = rollback_key.key_path(config, upgrade_id)
    assert path.parent == config / "state" / "rollback"
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    secret = rollback_key.identity(config, upgrade_id)
    assert age.recipient_of(secret) == public
    assert rollback_key.recipient(config, upgrade_id).key == public
    sealed = io.BytesIO()
    with age.Encryptor(sealed, [public]) as encryptor:
        encryptor.write(b"r0")
    opened = io.BytesIO()
    age.decrypt(io.BytesIO(sealed.getvalue()), opened, [secret])
    assert opened.getvalue() == b"r0"
    rows = _audit_rows(config)
    assert [r["event"] for r in rows] == ["rollback_key_created"]
    assert rows[0]["detail"]["upgrade_id"] == upgrade_id
    assert "AGE-SECRET-KEY" not in json.dumps(rows).upper()


def test_a_key_file_others_can_read_is_refused(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    rollback_key.key_path(config, upgrade_id).chmod(0o644)
    with pytest.raises(rollback_key.RollbackKeyError, match="readable by others"):
        rollback_key.identity(config, upgrade_id)


def test_a_key_is_named_by_its_upgrade_id_only(config: Path):
    for bad in ("../x", "", "0b0c64c1", None):
        with pytest.raises(rollback_key.RollbackKeyError):
            rollback_key.key_path(config, bad)


@pytest.mark.parametrize("value,hours", [("", 72), ("24", 24), ("168", 168), ("72", 72)])
def test_the_window_is_72_hours_and_can_be_set_from_24_to_168(config: Path, value, hours):
    if value:
        with open(config / ".env", "a", encoding="utf-8") as handle:
            handle.write(f"{rollback_key.WINDOW_VAR}={value}\n")
    assert rollback_key.window_hours(config) == hours


@pytest.mark.parametrize("value", ["23", "169", "0", "x", "72h", "-1"])
def test_a_window_outside_24_to_168_hours_is_refused(config: Path, value: str):
    with open(config / ".env", "a", encoding="utf-8") as handle:
        handle.write(f"{rollback_key.WINDOW_VAR}={value}\n")
    with pytest.raises(rollback_key.RollbackKeyError, match="24 to 168"):
        rollback_key.window_hours(config)


# ── the run and the window ─────────────────────────────────────────────────


def test_the_run_takes_the_id_of_its_rollback_key(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    state = _begin(config, upgrade_id)
    assert state["id"] == upgrade_id
    with pytest.raises(us.StageError):
        _begin(config, "not-a-uuid")


def test_the_key_stays_while_the_run_is_not_over_and_inside_its_window(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    assert rollback_key.sweep(config, us.load_state(config), now=time.time() + 500 * HOUR) == []
    finished = 1_800_000_000
    state = _finish(config, finished)
    assert rollback_key.sweep(config, state, now=finished + 71 * HOUR) == []
    assert rollback_key.exists(config, upgrade_id)
    assert us.rollback_plan(config, None, now=finished + 71 * HOUR)["key"] is True


def test_the_key_goes_after_72_hours(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    finished = 1_800_000_000
    state = _finish(config, finished)
    # Past its window the key is no way back, also before it was swept.
    assert us.rollback_plan(config, None, now=finished + 72 * HOUR)["key"] is False
    assert rollback_key.sweep(config, state, now=finished + 72 * HOUR) == [upgrade_id]
    assert not rollback_key.exists(config, upgrade_id)
    deleted = [r for r in _audit_rows(config) if r["event"] == "rollback_key_deleted"]
    assert deleted[-1]["detail"] == {"upgrade_id": upgrade_id, "reason": "expired",
                                     "confirmed_by": deleted[-1]["detail"]["confirmed_by"]}
    assert deleted[-1]["effect"] == "delete"


def test_a_shorter_window_ends_earlier(config: Path):
    with open(config / ".env", "a", encoding="utf-8") as handle:
        handle.write(f"{rollback_key.WINDOW_VAR}=24\n")
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    finished = 1_800_000_000
    state = _finish(config, finished)
    assert rollback_key.sweep(config, state, now=finished + 23 * HOUR) == []
    assert rollback_key.sweep(config, state, now=finished + 24 * HOUR) == [upgrade_id]


def test_a_key_of_a_run_that_never_began_goes_but_not_while_it_is_being_made(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    # The clock is the key's own age, not the host's: a slow run cannot cross the window.
    made = rollback_key.key_path(config, upgrade_id).stat().st_mtime
    later = made + rollback_key.ORPHAN_SECONDS + 1
    assert rollback_key.sweep(config, None, keep=upgrade_id, now=later) == []
    assert rollback_key.sweep(config, None, now=made + rollback_key.ORPHAN_SECONDS - 1) == []
    assert rollback_key.discard_unbegun(config, upgrade_id, None) is True
    other, _ = rollback_key.create(config)
    _begin(config, other)
    assert rollback_key.discard_unbegun(config, other, us.load_state(config)) is False
    assert rollback_key.exists(config, other)


def test_finalize_deletes_the_key_of_a_finished_upgrade_only(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    with pytest.raises(us.StageError, match="not finished"):
        us.finalize(config)
    assert rollback_key.exists(config, upgrade_id)
    _finish(config, int(time.time()))
    assert us.finalize(config) == [upgrade_id]
    assert not rollback_key.exists(config, upgrade_id)
    assert any(r["operation"] == "upgrade.finalize" for r in _audit_rows(config))


def test_a_new_run_deletes_the_key_of_the_finished_run_before_it(config: Path):
    old_id, _ = rollback_key.create(config)
    _begin(config, old_id)
    _finish(config, int(time.time()))
    assert rollback_key.exists(config, old_id)
    new_id, _ = rollback_key.create(config)
    us.begin(config, source="1.11.0", target="1.12.0", restore_point="r1", steps=[],
             upgrade_id=new_id)
    # R0 of the old run is superseded: its key does not outlive its window as an orphan.
    assert not rollback_key.exists(config, old_id)
    assert rollback_key.exists(config, new_id)
    deleted = [r for r in _audit_rows(config) if r["event"] == "rollback_key_deleted"]
    assert deleted[-1]["detail"]["upgrade_id"] == old_id
    assert deleted[-1]["detail"]["reason"] == "superseded"
    kinds = [k.kind for k in rollback_key.classify(config, us.load_state(config), 72)]
    assert kinds == ["running"]


def test_a_retry_keeps_the_key_of_its_own_run(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    _begin(config)
    assert rollback_key.exists(config, upgrade_id)


def test_finish_with_a_window_broken_during_the_run_still_reports_success(
        config: Path, tmp_path: Path, capsys):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    for stage in ("core", "me", "data", "studio", "flow", "assist"):
        us.record(config, stage, "ok", 0)
    with (config / ".env").open("a", encoding="utf-8") as handle:
        handle.write("PAPAIA_ROLLBACK_WINDOW_HOURS=9999\n")
    rc = cli.main(["--repo-root", str(tmp_path), "--config-dir", str(config),
                   "upgrade-stage", "finish"])
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert us.load_state(config)["finished"] is not None
    assert "Stage durations:" in out
    assert "ERROR" not in err
    assert "WARNING" in err and "PAPAIA_ROLLBACK_WINDOW_HOURS" in err
    assert rollback_key.exists(config, upgrade_id)


def test_the_end_of_a_run_without_the_upgrade_deletes_its_key(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    us.release_lock(config, bundle_version="1.10.0", checkout_version="1.10.0")
    assert not rollback_key.exists(config, upgrade_id)


def test_rollback_done_needs_the_release_the_run_started_from(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    with pytest.raises(us.StageError, match="not back at 1.10.0"):
        us.rollback_done(config, upgrade_id=upgrade_id, bundle_version="1.11.0",
                         checkout_version="1.10.0")
    assert rollback_key.exists(config, upgrade_id)
    assert us.read_lock(config).active
    state = us.rollback_done(config, upgrade_id=upgrade_id, bundle_version="1.10.0",
                             checkout_version="1.10.0")
    assert state["abandoned"] is not None
    assert not us.read_lock(config).active
    assert not rollback_key.exists(config, upgrade_id)
    with pytest.raises(us.StageError, match="already rolled back"):
        us.rollback_plan(config, None)


def test_rollback_goes_to_the_restore_point_of_the_run_only(config: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    plan = us.rollback_plan(config, "r0")
    assert (plan["from"], plan["to"], plan["restore_point"], plan["key"]) == \
        ("1.10.0", "1.11.0", "r0", True)
    with pytest.raises(us.StageError, match="papaia-ctl restore"):
        us.rollback_plan(config, "another-point")


# ── R0 is encrypted to the rollback key as well ─────────────────────────────


def _core(tmp_path: Path) -> Path:
    repo = tmp_path / "papaia"
    _write(repo / "src" / "docker-compose.yml", "services:\n  stub:\n    image: stub\n")
    return repo


def _plan(config: Path, repo: Path, target: Path, *extra: str) -> int:
    return cli.main(["--repo-root", str(repo), "--config-dir", str(config), "backup-plan",
                     f"--backup-dir={target}", *extra])


def test_backup_plan_adds_the_rollback_key_to_the_recipients_of_r0(tmp_path, config, capsys):
    target = tmp_path / "backup"
    target.mkdir()
    backup_crypt.init_target(config, target)
    upgrade_id, public = rollback_key.create(config)
    assert _plan(config, _core(tmp_path), target, f"--rollback-key={upgrade_id}") == 0
    snapshot = Path(capsys.readouterr().out.splitlines()[0].split("\t")[1])
    plan = backup.read_plan(snapshot)
    names = [r.name for r in plan.recipients]
    assert names == ["betrieb", rollback_key.recipient_name(upgrade_id)]
    assert plan.recipients[1].key == public


def test_an_ordinary_backup_is_not_encrypted_to_a_rollback_key(tmp_path, config, capsys):
    target = tmp_path / "backup"
    target.mkdir()
    backup_crypt.init_target(config, target)
    rollback_key.create(config)
    assert _plan(config, _core(tmp_path), target) == 0
    snapshot = Path(capsys.readouterr().out.splitlines()[0].split("\t")[1])
    assert [r.name for r in backup.read_plan(snapshot).recipients] == ["betrieb"]


def test_backup_plan_refuses_a_rollback_key_that_is_not_there(tmp_path, config, capsys):
    target = tmp_path / "backup"
    target.mkdir()
    backup_crypt.init_target(config, target)
    rc = _plan(config, _core(tmp_path), target,
               "--rollback-key=0b0c64c1-6f39-4f33-9d0f-0c3c8a7d1c11")
    assert rc == 3
    assert "no rollback key" in capsys.readouterr().err
    assert [p.name for p in target.iterdir()] == [backup_crypt.TARGET_FILE]


def test_the_rollback_key_never_goes_into_an_archive(tmp_path: Path):
    secret, public = age.generate_identity()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        data = f"{secret}\n".encode()
        info = tarfile.TarInfo("./state/rollback/x.key")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    stream.seek(0)
    with pytest.raises(backup_crypt.KeyMaterialError):
        backup_crypt.seal(stream, tmp_path / "a.tar.gz.age", [public])
    assert not (tmp_path / "a.tar.gz.age").exists()


# ── doctor rollback_window ──────────────────────────────────────────────────


def _doctor(config: Path, tmp_path: Path, at: float) -> doctor.CheckResult:
    ctx = doctor.Context(config, tmp_path, run=lambda *a, **k: None, probes=doctor.Probes(),
                         now=datetime.fromtimestamp(at, timezone.utc))
    return doctor.check_rollback_window(ctx)


def test_doctor_reports_the_time_left_and_fails_for_a_key_past_its_window(config, tmp_path):
    assert _doctor(config, tmp_path, time.time()).status == doctor.SKIP
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    running = _doctor(config, tmp_path, time.time())
    assert running.status == doctor.PASS and "in progress" in running.summary
    finished = 1_800_000_000
    _finish(config, finished)
    inside = _doctor(config, tmp_path, finished + 70 * HOUR)
    assert inside.status == doctor.PASS
    assert "2 h 00 min more" in inside.summary
    after = _doctor(config, tmp_path, finished + 73 * HOUR)
    assert after.status == doctor.FAIL
    assert "upgrade --finalize" in after.summary
    assert after.details["keys"][0]["state"] == "expired"


def test_doctor_fails_for_a_key_others_can_read(config: Path, tmp_path: Path):
    upgrade_id, _ = rollback_key.create(config)
    _begin(config, upgrade_id)
    rollback_key.key_path(config, upgrade_id).chmod(0o640)
    assert _doctor(config, tmp_path, time.time()).status == doctor.FAIL


def test_doctor_fails_for_a_malformed_window(config: Path, tmp_path: Path):
    with open(config / ".env", "a", encoding="utf-8") as handle:
        handle.write(f"{rollback_key.WINDOW_VAR}=500\n")
    assert _doctor(config, tmp_path, time.time()).status == doctor.FAIL
