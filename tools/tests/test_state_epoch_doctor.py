"""`doctor state_epoch` (betrieb BE-16a Nr. 3, sicherheit §4.9 (4)): `fail` while a module has
not applied the erasure journal, `warn` while the backup target cannot be read and until
`recover-snapshot` confirmed the generation the start gate reached after a rolled-back
state."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from lib import doctor, erasure_mirror, module_actions

CID = "0f8e2d4c-1b3a-4c5d-9e7f-123456789abc"


@pytest.fixture
def installation(tmp_path: Path) -> dict:
    config = tmp_path / "papaia-config"
    config.mkdir()
    backup = tmp_path / "backup"
    target = backup / "erasure-journal"
    target.mkdir(parents=True)
    (config / ".env").write_text(f"PAPAIA_BACKUP_DIR={backup}\n", encoding="utf-8")
    (config / "deployment.yaml").write_text(yaml.safe_dump({"addons": []}), encoding="utf-8")
    return {"config": config, "backup": backup, "target": target, "root": tmp_path}


def _epoch(target: Path, generation: int) -> None:
    (target / "epoch").write_text(json.dumps(
        {"format": "papaia.erasure-epoch/1", "generation": generation, "seq": {"flow": 3}}
    ))


def _check(inst: dict) -> doctor.CheckResult:
    ctx = doctor.Context(inst["config"], inst["root"], run=lambda *a, **k: None,
                         probes=doctor.Probes(), now=datetime.now(timezone.utc))
    return doctor.check_state_epoch(ctx)


def test_the_check_is_registered_after_the_start_gate():
    names = list(doctor.CHECK_NAMES)
    assert names.index("state_epoch") == names.index("startgate") + 1


def test_a_new_installation_with_generation_0_passes(installation):
    _epoch(installation["target"], 0)
    result = _check(installation)
    assert result.status == doctor.PASS, result.summary


def test_without_an_epoch_and_without_the_lifecycle_profile_it_is_skipped(installation):
    assert _check(installation).status == doctor.SKIP


def test_an_unreachable_backup_target_warns(installation):
    installation["target"].rmdir()
    result = _check(installation)
    assert result.status == doctor.WARN
    assert "not reachable" in result.summary


def test_a_damaged_epoch_fails(installation):
    (installation["target"] / "epoch").write_text("{not json")
    assert _check(installation).status == doctor.FAIL


def test_a_module_with_the_journal_still_due_fails_with_the_sentence(installation):
    _epoch(installation["target"], 0)
    (installation["config"] / module_actions.MARKER).write_text(json.dumps({
        "format": module_actions.FORMAT, "trigger": "recover-snapshot",
        "correlation_id": CID, "restore_point": "snapshot-1764000000",
        "modules": {"flow": ["erasure-replay", "post-restore"]},
    }))
    result = _check(installation)
    assert result.status == doctor.FAIL
    assert "flow" in result.summary
    assert "Datenstand älter als das Löschjournal" in result.summary
    assert "papaia-ctl recover-snapshot" in result.summary


def test_an_unreadable_pending_file_fails(installation):
    _epoch(installation["target"], 0)
    (installation["config"] / module_actions.MARKER).write_text("{")
    assert _check(installation).status == doctor.FAIL


def test_a_generation_the_start_gate_raised_warns_until_recover_snapshot(installation):
    # The VM came back from a snapshot; the start gate replayed and raised the generation.
    _epoch(installation["target"], 5)
    result = _check(installation)
    assert result.status == doctor.WARN
    assert "recover-snapshot" in result.summary
    erasure_mirror.confirm_generation(installation["config"], installation["target"],
                                      by="recover-snapshot")
    assert _check(installation).status == doctor.PASS
    # A later replay of the gate warns again.
    _epoch(installation["target"], 6)
    assert _check(installation).status == doctor.WARN


def test_an_unreachable_mirror_warns(installation, tmp_path):
    _epoch(installation["target"], 0)
    with open(installation["config"] / ".env", "a", encoding="utf-8") as env:
        env.write(f"PAPAIA_ERASURE_MIRROR_DIR={tmp_path / 'unmounted'}\n")
    result = _check(installation)
    assert result.status == doctor.WARN
    assert "mirror" in result.summary
