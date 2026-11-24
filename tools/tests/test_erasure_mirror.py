"""The mirror of the erasure journal and the offsite retention (sicherheit §4.9 "Kopien außer
Haus", betrieb BE-16, RE-86): settings, the union a restore and `recover-snapshot` read,
the copy to the mirror after every backup and the retention run of the mirror."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from papaia_kit.erasure import read_journal

from lib import erasure_mirror as em

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def _at(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _entry(seq: int, obj: str, *, module: str = "flow", at: datetime | None = None,
           entry_id: str | None = None, kind: str = "erase") -> dict:
    return {"id": entry_id or str(uuid.uuid4()), "module": module, "seq": seq, "kind": kind,
            "object_ref": obj, "subject_ref": "ab" * 32,
            "at": _at(at or NOW - timedelta(days=1)), "reason": "person_request"}


def _write(folder: Path, module: str, entries: list[dict]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{module}.jsonl").write_text(
        "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries), encoding="utf-8"
    )


def _seqs(folder: Path, module: str = "flow") -> list[tuple[int, str]]:
    return [(e.seq, e.object_ref) for e in read_journal(module, [folder])]


def _audit(config: Path) -> list[dict]:
    path = config / "audit" / "papaia-ctl.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def places(tmp_path: Path) -> dict:
    config = tmp_path / "papaia-config"
    config.mkdir()
    backup = tmp_path / "backup"
    target = backup / "erasure-journal"
    target.mkdir(parents=True)
    mirror = tmp_path / "offsite" / "erasure-journal"
    mirror.mkdir(parents=True)
    (config / ".env").write_text(f"PAPAIA_BACKUP_DIR={backup}\n", encoding="utf-8")
    return {"config": config, "backup": backup, "target": target, "mirror": mirror}


# ── settings ────────────────────────────────────────────────────────────────


def test_without_settings_there_is_no_mirror_and_the_offsite_retention_is_90_days(places):
    settings = em.load_settings(places["config"])
    assert settings.mirror is None
    assert settings.offsite_days == 90


def test_configure_stores_the_mirror_and_the_offsite_retention(places):
    settings = em.configure(places["config"], mirror=str(places["mirror"]), offsite="365")
    assert settings == em.Settings(mirror=places["mirror"], offsite_days=365)
    env = (places["config"] / ".env").read_text(encoding="utf-8")
    assert f"PAPAIA_ERASURE_MIRROR_DIR={places['mirror']}" in env
    assert "PAPAIA_OFFSITE_RETENTION_DAYS=365" in env
    assert em.load_settings(places["config"]) == settings
    row = _audit(places["config"])[-1]
    assert row["event"] == "config_changed" and row["operation"] == "erasure_mirror"
    assert row["detail"]["offsite_retention_days"] == 365 and row["detail"]["mirror"] is True
    # `none` takes the mirror away again; the retention stays.
    assert em.configure(places["config"], mirror="none", offsite=None).mirror is None
    assert em.load_settings(places["config"]).offsite_days == 365


@pytest.mark.parametrize("value", [
    "relative/path", "/srv/../etc", "/srv/mirror\nX=1", "https://offsite.example.org/journal",
    "/" + "a" * 1100,
])
def test_a_mirror_that_is_no_plain_absolute_path_is_refused(places, value):
    with pytest.raises(em.MirrorError):
        em.configure(places["config"], mirror=value, offsite=None)
    assert "PAPAIA_ERASURE_MIRROR_DIR" not in (places["config"] / ".env").read_text()


def test_the_mirror_must_be_a_second_place_not_the_backup_target(places):
    for inside in (places["backup"], places["target"], places["backup"] / "sub"):
        with pytest.raises(em.MirrorError, match="second place"):
            em.configure(places["config"], mirror=str(inside), offsite=None)


@pytest.mark.parametrize("value", ["-1", "3651", "ninety", "1.5", "", "90 "])
def test_an_offsite_retention_outside_0_to_3650_days_is_refused(places, value):
    with pytest.raises(em.MirrorError):
        em.configure(places["config"], mirror=None, offsite=value)


def test_a_damaged_setting_in_the_env_file_is_reported_not_guessed(places):
    (places["config"] / ".env").write_text(
        f"PAPAIA_BACKUP_DIR={places['backup']}\nPAPAIA_OFFSITE_RETENTION_DAYS=forever\n"
    )
    with pytest.raises(em.MirrorError, match="PAPAIA_OFFSITE_RETENTION_DAYS"):
        em.load_settings(places["config"])


# ── the union at restore and recover-snapshot ───────────────────────────────


def test_the_union_restores_an_entry_missing_at_the_target(places):
    # The target was replaced by an older copy (offsite) that ends before seq 2.
    first, second = _entry(1, "doc-7"), _entry(2, "doc-9")
    _write(places["target"], "flow", [first])
    _write(places["mirror"], "flow", [first, second])
    _write(places["mirror"], "identity", [_entry(1, "account", module="identity",
                                                  kind="account_disable")])

    added = em.union_into_target(places["config"], places["target"], places["mirror"])

    assert added == {"flow": 1, "identity": 1}
    assert _seqs(places["target"]) == [(1, "doc-7"), (2, "doc-9")]
    assert _seqs(places["target"], "identity") == [(1, "account")]
    # A second run finds nothing to add and writes nothing.
    before = (places["target"] / "flow.jsonl").read_bytes()
    assert em.union_into_target(places["config"], places["target"], places["mirror"]) == {}
    assert (places["target"] / "flow.jsonl").read_bytes() == before
    rows = [r for r in _audit(places["config"]) if r["operation"] == "erasure_mirror_union"]
    assert rows[0]["event"] == "erasure_journal_flushed"
    assert (rows[0]["detail"]["added"], rows[0]["detail"]["modules"]) == (2, 2)
    # Counts only: no object, no subject reference.
    assert "doc-9" not in json.dumps(rows) and "ab" * 32 not in json.dumps(rows)


def test_the_union_fills_a_gap_inside_the_target_journal(places):
    one, two, three = _entry(1, "doc-1"), _entry(2, "doc-2"), _entry(3, "doc-3")
    _write(places["target"], "flow", [one, three])
    _write(places["mirror"], "flow", [one, two])
    assert em.union_into_target(places["config"], places["target"], places["mirror"]) == {
        "flow": 1
    }
    assert _seqs(places["target"]) == [(1, "doc-1"), (2, "doc-2"), (3, "doc-3")]


def test_a_mirror_entry_under_a_seq_the_target_used_otherwise_is_renumbered(places):
    # The mirror kept a provisional seq while the target was away; the target gave seq 2
    # to another entry. The entry is not lost: it gets the next free seq and keeps the
    # first one as provisional_seq, so a replay rewinds behind it.
    one, at_target, mirror_only = _entry(1, "doc-1"), _entry(2, "doc-2"), _entry(2, "doc-x")
    _write(places["target"], "flow", [one, at_target])
    _write(places["mirror"], "flow", [one, mirror_only])
    assert em.union_into_target(places["config"], places["target"], places["mirror"]) == {
        "flow": 1
    }
    entries = read_journal("flow", [places["target"]])
    assert [(e.seq, e.object_ref, e.provisional_seq) for e in entries] == [
        (1, "doc-1", None), (2, "doc-2", None), (3, "doc-x", 2),
    ]


def test_one_entry_with_two_contents_stops_the_union(places):
    entry = _entry(1, "doc-1")
    _write(places["target"], "flow", [entry])
    _write(places["mirror"], "flow", [{**entry, "object_ref": "doc-other"}])
    with pytest.raises(em.MirrorError, match="flow"):
        em.union_into_target(places["config"], places["target"], places["mirror"])
    assert _seqs(places["target"]) == [(1, "doc-1")]


def test_a_missing_mirror_or_target_is_never_an_empty_journal(places, tmp_path):
    with pytest.raises(em.MirrorError, match="mirror"):
        em.union_into_target(places["config"], places["target"], tmp_path / "unmounted")
    with pytest.raises(em.MirrorError, match="target"):
        em.union_into_target(places["config"], tmp_path / "gone", places["mirror"])
    assert not (tmp_path / "unmounted").exists()


def test_entries_a_retention_run_retired_at_the_target_do_not_come_back(places):
    old = _entry(1, "doc-old", at=NOW - timedelta(days=400))
    new = _entry(2, "doc-new", at=NOW - timedelta(days=2))
    _write(places["target"], "flow", [new])
    (places["target"] / ".flow.retained").write_text(_at(NOW - timedelta(days=200)) + "\n")
    _write(places["mirror"], "flow", [old, new])
    assert em.union_into_target(places["config"], places["target"], places["mirror"],
                                now=NOW) == {}
    assert _seqs(places["target"]) == [(2, "doc-new")]


def test_a_planted_floor_marker_cannot_retire_fresh_deletions(places):
    fresh = _entry(1, "doc-fresh", at=NOW - timedelta(days=3))
    _write(places["target"], "flow", [])
    (places["target"] / ".flow.retained").write_text(_at(NOW) + "\n")
    _write(places["mirror"], "flow", [fresh])
    assert em.union_into_target(places["config"], places["target"], places["mirror"],
                                now=NOW) == {"flow": 1}


# ── the copy to the mirror after a backup ───────────────────────────────────


def test_the_backup_copies_what_the_mirror_lacks_by_appending(places):
    one, two = _entry(1, "doc-1"), _entry(2, "doc-2")
    _write(places["target"], "flow", [one, two])
    _write(places["mirror"], "flow", [one])
    before = (places["mirror"] / "flow.jsonl").read_bytes()

    assert em.sync_to_mirror(places["config"], places["target"], places["mirror"]) == {
        "flow": 1
    }
    after = (places["mirror"] / "flow.jsonl").read_bytes()
    assert after.startswith(before), "the mirror is appended to, not rewritten"
    assert _seqs(places["mirror"]) == [(1, "doc-1"), (2, "doc-2")]
    assert em.sync_to_mirror(places["config"], places["target"], places["mirror"]) == {}
    row = [r for r in _audit(places["config"]) if r["operation"] == "erasure_mirror_sync"][0]
    assert (row["detail"]["added"], row["detail"]["modules"]) == (1, 1)


def test_the_mirror_keeps_what_only_it_holds(places):
    # The target is an older copy: the mirror's later entry stays for the next restore.
    one, two = _entry(1, "doc-1"), _entry(2, "doc-2")
    _write(places["target"], "flow", [one])
    _write(places["mirror"], "flow", [one, two])
    assert em.sync_to_mirror(places["config"], places["target"], places["mirror"]) == {}
    assert _seqs(places["mirror"]) == [(1, "doc-1"), (2, "doc-2")]


def test_an_unreachable_mirror_is_reported_and_never_created(places, tmp_path):
    _write(places["target"], "flow", [_entry(1, "doc-1")])
    with pytest.raises(em.MirrorError, match="mirror"):
        em.sync_to_mirror(places["config"], places["target"], tmp_path / "unmounted")
    assert not (tmp_path / "unmounted").exists()


def test_the_copy_does_not_follow_a_symlink_in_the_mirror(places, tmp_path):
    _write(places["target"], "flow", [_entry(1, "doc-1")])
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched\n")
    os.symlink(outside, places["mirror"] / "flow.jsonl")
    with pytest.raises(em.MirrorError):
        em.sync_to_mirror(places["config"], places["target"], places["mirror"])
    assert outside.read_text() == "untouched\n"


# ── the retention run of the mirror ─────────────────────────────────────────


def test_the_mirror_keeps_entries_for_the_offsite_retention_plus_30_days(places):
    entries = [
        _entry(1, "doc-1", at=NOW - timedelta(days=200)),
        _entry(2, "doc-2", at=NOW - timedelta(days=121)),
        _entry(3, "doc-3", at=NOW - timedelta(days=119)),
        _entry(4, "doc-4", at=NOW - timedelta(days=1)),
    ]
    _write(places["mirror"], "flow", entries)
    oldest_point = NOW - timedelta(days=7)

    removed = em.retain_mirror(places["config"], places["mirror"], oldest_point=oldest_point,
                               offsite_days=90, now=NOW)

    # Older than 90 + 30 days goes; the restore point rule alone would remove more.
    assert removed == {"flow": 2}
    assert _seqs(places["mirror"]) == [(3, "doc-3"), (4, "doc-4")]
    row = [r for r in _audit(places["config"]) if r["event"] == "retention_run"][0]
    assert row["detail"]["removed"] == 2 and row["detail"]["offsite_retention_days"] == 90


def test_an_old_restore_point_keeps_the_mirror_longer_than_the_offsite_rule(places):
    _write(places["mirror"], "flow", [
        _entry(1, "doc-1", at=NOW - timedelta(days=300)),
        _entry(2, "doc-2", at=NOW - timedelta(days=1)),
    ])
    removed = em.retain_mirror(places["config"], places["mirror"],
                               oldest_point=NOW - timedelta(days=365), offsite_days=0, now=NOW)
    assert removed == {}
    assert len(_seqs(places["mirror"])) == 2


def test_the_newest_entry_always_stays_and_no_restore_point_removes_nothing(places):
    _write(places["mirror"], "flow", [_entry(1, "doc-1", at=NOW - timedelta(days=900))])
    assert em.retain_mirror(places["config"], places["mirror"], oldest_point=NOW,
                            offsite_days=0, now=NOW) == {}
    _write(places["mirror"], "flow", [_entry(1, "doc-1", at=NOW - timedelta(days=900)),
                                      _entry(2, "doc-2", at=NOW - timedelta(days=800))])
    assert em.retain_mirror(places["config"], places["mirror"], oldest_point=None,
                            offsite_days=0, now=NOW) == {}
    assert len(_seqs(places["mirror"])) == 2


# ── the generation recover-snapshot confirmed ───────────────────────────────


def test_the_confirmed_generation_follows_the_epoch_at_the_target(places):
    assert em.confirmed_generation(places["config"]) is None
    (places["target"] / "epoch").write_text(json.dumps(
        {"format": "papaia.erasure-epoch/1", "generation": 3, "seq": {"flow": 2}}
    ))
    assert em.confirm_generation(places["config"], places["target"], by="recover-snapshot") == 3
    assert em.confirmed_generation(places["config"]) == 3
    record = places["config"] / "state" / "state-epoch.json"
    assert oct(record.stat().st_mode & 0o777) == "0o600"
    # A target without epoch yet confirms nothing.
    (places["target"] / "epoch").unlink()
    assert em.confirm_generation(places["config"], places["target"], by="restore") is None
    assert em.confirmed_generation(places["config"]) == 3


def test_a_damaged_confirmation_counts_as_none(places):
    record = places["config"] / "state" / "state-epoch.json"
    record.parent.mkdir()
    record.write_text('{"generation": "3"}')
    assert em.confirmed_generation(places["config"]) is None
