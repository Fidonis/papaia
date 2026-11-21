"""Encrypted backups (BE-14, BE-15, RE-32, RE-33): recipients, the confirmed target, key
material that never goes into an archive, declared exclusions, retention by count and the
key check.

Keys are made at run time. The sealing is checked by decrypting what was written; the
docker half of `backup` is replaced by a function in test_backup_encrypted_cli.py.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from lib import age, backup, backup_crypt, cli, compat

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def _keys(count: int = 2) -> list[tuple[str, str]]:
    return [age.generate_identity() for _ in range(count)]


def _config(tmp_path: Path, recipients: str = "", addons: list[dict] | None = None) -> Path:
    config_dir = tmp_path / "papaia-config"
    env = "COMPOSE_PROJECT_NAME=papaia\n"
    if recipients:
        env += f"PAPAIA_BACKUP_RECIPIENTS={recipients}\n"
    _write(config_dir / ".env", env)
    _write(config_dir / "deployment.yaml", yaml.safe_dump({"addons": addons or []}))
    return config_dir


def _tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _open(path: Path, identity: str) -> dict[str, bytes]:
    plain = io.BytesIO()
    with open(path, "rb") as handle:
        age.decrypt(handle, plain, [identity])
    plain.seek(0)
    with tarfile.open(fileobj=plain, mode="r:gz") as tar:
        return {
            m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()
        }


# ---------------------------------------------------------------------------
# recipients
# ---------------------------------------------------------------------------


def test_recipients_are_named_public_keys():
    (_, first), (_, second) = _keys()
    parsed = backup_crypt.parse_recipients(f"betrieb:{first},notfall:{second}")
    assert [(r.name, r.key) for r in parsed] == [("betrieb", first), ("notfall", second)]
    assert backup_crypt.format_recipients(parsed) == f"betrieb:{first},notfall:{second}"
    assert backup_crypt.parse_recipients("") == []


@pytest.mark.parametrize(
    "raw",
    [
        "betrieb",  # no key
        "betrieb:age1notakey",
        "Betrieb Team:{key}",  # name with a space
        "betrieb:{key},betrieb:{other}",  # name twice
        "betrieb:{key},notfall:{key}",  # key twice
        "betrieb:{identity}",  # a private key is never a recipient
    ],
)
def test_malformed_recipients_are_refused(raw: str):
    (identity, key), (_, other) = _keys()
    with pytest.raises(backup.BackupError):
        backup_crypt.parse_recipients(raw.format(key=key, other=other, identity=identity))


def test_backup_refuses_without_a_recipient(tmp_path: Path):
    config_dir = _config(tmp_path)
    with pytest.raises(backup.BackupError, match="never written unencrypted"):
        backup_crypt.require_recipients(config_dir)


def test_add_and_remove_recipients_keep_the_rest_of_the_env_file(tmp_path: Path):
    (_, first), (_, second) = _keys()
    config_dir = _config(tmp_path)
    backup_crypt.add_recipient(config_dir, "betrieb", first)
    backup_crypt.add_recipient(config_dir, "notfall", second)
    text = (config_dir / ".env").read_text(encoding="utf-8")
    assert "COMPOSE_PROJECT_NAME=papaia" in text
    assert [r.name for r in backup_crypt.load_recipients(config_dir)] == ["betrieb", "notfall"]
    with pytest.raises(backup.BackupError):
        backup_crypt.add_recipient(config_dir, "betrieb", second)
    removed = backup_crypt.remove_recipient(config_dir, "betrieb")
    assert removed.key == first
    assert [r.name for r in backup_crypt.load_recipients(config_dir)] == ["notfall"]
    with pytest.raises(backup.BackupError):
        backup_crypt.remove_recipient(config_dir, "betrieb")
    rows = [json.loads(line) for line in (config_dir / "audit" / "papaia-ctl.jsonl")
            .read_text(encoding="utf-8").splitlines()]
    assert [r["event"] for r in rows] == ["backup_recipient_added"] * 2 + [
        "backup_recipient_removed"
    ]
    assert all(r["format"] == "papaia.audit/1" and r["correlation_id"] for r in rows)


def test_the_last_recipient_cannot_be_removed(tmp_path: Path):
    ((_, key),) = _keys(1)
    config_dir = _config(tmp_path, f"betrieb:{key}")
    with pytest.raises(backup.BackupError, match="last recipient"):
        backup_crypt.remove_recipient(config_dir, "betrieb")


# ---------------------------------------------------------------------------
# the confirmed target (RE-33)
# ---------------------------------------------------------------------------


def test_a_target_without_id_file_is_refused(tmp_path: Path):
    config_dir = _config(tmp_path)
    target = tmp_path / "backup"
    target.mkdir()
    with pytest.raises(backup.BackupError, match="no default"):
        backup_crypt.check_target(config_dir, target)


def test_a_missing_target_is_refused(tmp_path: Path):
    config_dir = _config(tmp_path)
    with pytest.raises(backup.BackupError, match="not mounted"):
        backup_crypt.check_target(config_dir, tmp_path / "gone")


def test_init_confirms_the_target_and_check_accepts_it(tmp_path: Path):
    config_dir = _config(tmp_path)
    target = tmp_path / "backup"
    target.mkdir()
    installation = backup_crypt.init_target(config_dir, target)
    assert backup_crypt.check_target(config_dir, target) == installation
    assert (config_dir / backup_crypt.INSTALLATION_ID_FILE).read_text().strip() == installation
    # A second init on the same target is a no-op.
    assert backup_crypt.init_target(config_dir, target) == installation


def test_a_target_of_another_installation_is_refused(tmp_path: Path):
    target = tmp_path / "backup"
    target.mkdir()
    other = _config(tmp_path / "other")
    backup_crypt.init_target(other, target)
    mine = _config(tmp_path / "mine")
    backup_crypt.init_target(mine, _mkdir(tmp_path / "mine-target"))
    with pytest.raises(backup.BackupError, match="another installation"):
        backup_crypt.check_target(mine, target)
    with pytest.raises(backup.BackupError, match="another installation"):
        backup_crypt.init_target(mine, target)


def _mkdir(path: Path) -> Path:
    path.mkdir(parents=True)
    return path


@pytest.mark.parametrize(
    "content",
    [
        "schema: papaia.backup-target/1\ninstallation_id: not-a-uuid\n",
        "schema: papaia.backup-target/2\ninstallation_id: 0b0c64c1-6f39-4f33-9d0f-0c3c8a7d1c11\n",
        "schema: papaia.backup-target/1\ninstallation_id: 0b0c64c1-6f39-4f33-9d0f-0c3c8a7d1c11\n"
        "extra: 1\n",
        "- a list\n",
    ],
)
def test_a_malformed_id_file_is_refused(tmp_path: Path, content: str):
    config_dir = _config(tmp_path)
    target = _mkdir(tmp_path / "backup")
    backup_crypt.init_target(config_dir, _mkdir(tmp_path / "first"))
    (target / backup_crypt.TARGET_FILE).write_text(content, encoding="utf-8")
    with pytest.raises(backup.BackupError):
        backup_crypt.check_target(config_dir, target)


def test_backup_plan_refuses_a_wrong_target_before_writing(tmp_path: Path, capsys):
    ((_, key),) = _keys(1)
    config_dir = _config(tmp_path / "mine", f"betrieb:{key}")
    target = _mkdir(tmp_path / "backup")
    backup_crypt.init_target(_config(tmp_path / "other"), target)
    backup_crypt.init_target(config_dir, _mkdir(tmp_path / "own"))
    rc = cli.main([
        "--repo-root", str(tmp_path / "repo"), "--config-dir", str(config_dir),
        "backup-plan", f"--backup-dir={target}",
    ])
    assert rc == 3
    assert "another installation" in capsys.readouterr().err
    assert [p.name for p in target.iterdir()] == [backup_crypt.TARGET_FILE]


def test_backup_plan_refuses_without_recipients(tmp_path: Path, capsys):
    config_dir = _config(tmp_path)
    target = _mkdir(tmp_path / "backup")
    backup_crypt.init_target(config_dir, target)
    rc = cli.main([
        "--repo-root", str(tmp_path / "repo"), "--config-dir", str(config_dir),
        "backup-plan", f"--backup-dir={target}",
    ])
    assert rc == 3
    assert "never written unencrypted" in capsys.readouterr().err
    assert [p.name for p in target.iterdir()] == [backup_crypt.TARGET_FILE]


# ---------------------------------------------------------------------------
# sealing and the key material scan
# ---------------------------------------------------------------------------


def test_seal_writes_an_age_file_both_recipients_can_open(tmp_path: Path):
    (first, first_r), (second, second_r) = _keys()
    stream = io.BytesIO(_tar_gz({"./db/canary.txt": b"canary-0815", "./b": b"x" * 200_000}))
    target = tmp_path / "volumes" / "a.tar.gz.age"
    digest = backup_crypt.seal(stream, target, [first_r, second_r])
    assert digest == hashlib.sha256(target.read_bytes()).hexdigest()
    assert b"canary-0815" not in target.read_bytes()
    for identity in (first, second):
        assert _open(target, identity)["./db/canary.txt"] == b"canary-0815"
    assert not list(target.parent.glob("*.part"))


@pytest.mark.parametrize(
    "files",
    [
        {"./state/rollback/u-1.key": b"anything"},
        {"./ai/litellm/test-hosted.env": b"TEST_HOSTED_API_KEY=x"},
        {"./notes.txt": b"# identity\nAGE-SECRET-KEY-1QQQQ\n"},
        # Lower case is the same bech32 identity; parse_identity accepts it.
        {"./notes.txt": b"age-secret-key-1qqqq\n"},
        {"./mixed.txt": b"Age-Secret-Key-1Qqqq\n"},
        # The marker split across the read boundary of the scan.
        {"./big.bin": b"z" * (backup_crypt.SCAN_BLOCK - 5) + b"AGE-SECRET-KEY-1X"},
    ],
)
def test_seal_refuses_key_material_and_leaves_nothing_behind(tmp_path: Path, files: dict):
    ((_, key),) = _keys(1)
    target = tmp_path / "papaia-config.tar.gz.age"
    with pytest.raises(backup_crypt.KeyMaterialError):
        backup_crypt.seal(io.BytesIO(_tar_gz(files)), target, [key])
    assert list(tmp_path.iterdir()) == []


def test_seal_refuses_a_stream_that_is_not_a_tar_archive(tmp_path: Path):
    ((_, key),) = _keys(1)
    with pytest.raises(backup.BackupError):
        backup_crypt.seal(io.BytesIO(b"not gzip"), tmp_path / "x.age", [key])
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# planning: exclusions (RE-05) and declared volumes
# ---------------------------------------------------------------------------


def _core(tmp_path: Path) -> Path:
    repo = tmp_path / "papaia"
    _write(
        repo / "src" / "docker-compose.yml", "include:\n  - path: ./infra/x/docker-compose.yml\n"
    )
    _write(
        repo / "src" / "infra" / "x" / "docker-compose.yml",
        """
        services:
          stub:
            image: stub
        volumes:
          keycloak-postgresql:
          papaia-lifecycle-key:
          papaia-erasure:
        """,
    )
    return repo


def _flow_addon(tmp_path: Path, manifest: str | None) -> Path:
    path = tmp_path / "addons" / "flow"
    _write(
        path / "docker-compose.yml",
        """
        services:
          app:
            image: stub
        volumes:
          flow-db:
          flow-delegation-key:
          flow-cache:
        """,
    )
    if manifest is not None:
        _write(path / "papaia-app.yaml", manifest)
    return path


def test_the_plan_never_holds_delegation_revocation_or_journal_volumes(tmp_path: Path):
    """No manifest declaration needed: the volumes of BE-14 are left out by name."""
    addon = _flow_addon(tmp_path, "name: flow\n")
    config_dir = _config(tmp_path, addons=[{"name": "flow", "path": str(addon), "active": True}])
    plan = backup.build_plan(config_dir, _core(tmp_path), tmp_path / "b", existing=[])
    sources = [a.source for a in plan.artifacts]
    assert "papaia_keycloak-postgresql" in sources
    assert "flow_flow-db" in sources
    for key in ("papaia-lifecycle-key", "papaia-erasure", "flow-delegation-key"):
        assert not any(source.endswith(key) for source in sources)
    assert {e["volume"] for e in plan.excluded} == {
        "papaia_papaia-lifecycle-key", "papaia_papaia-erasure", "flow_flow-delegation-key",
    }
    assert all(e["reason"] for e in plan.excluded)


def test_labelled_key_volumes_stay_out_as_well(tmp_path: Path):
    """A volume found through the compose label is checked like a declared one."""
    addon = _flow_addon(tmp_path, "name: flow\n")
    config_dir = _config(tmp_path, addons=[{"name": "flow", "path": str(addon), "active": True}])
    existing = [("flow", "flow_flow-delegation-key"), ("flow", "flow_flow-db"),
                ("papaia", "papaia_papaia-lifecycle-key")]
    plan = backup.build_plan(config_dir, _core(tmp_path), tmp_path / "b", existing=existing)
    sources = [a.source for a in plan.artifacts]
    assert "flow_flow-delegation-key" not in sources
    assert "papaia_papaia-lifecycle-key" not in sources


def test_a_manifest_excludes_a_volume_with_a_reason(tmp_path: Path):
    addon = _flow_addon(
        tmp_path,
        """
        name: flow
        volumes:
          - name: flow-db
            backup: include
          - name: flow-cache
            backup: exclude
            reason: rebuilt from the database at start
        """,
    )
    config_dir = _config(tmp_path, addons=[{"name": "flow", "path": str(addon), "active": True}])
    plan = backup.build_plan(config_dir, _core(tmp_path), tmp_path / "b", existing=[])
    sources = [a.source for a in plan.artifacts]
    assert "flow_flow-db" in sources and "flow_flow-cache" not in sources
    assert {"volume": "flow_flow-cache", "reason": "rebuilt from the database at start"} in (
        plan.excluded
    )


@pytest.mark.parametrize(
    "volumes",
    [
        "  - name: flow-db\n    backup: maybe\n",
        "  - name: flow-db\n    backup: exclude\n",  # an exclusion needs a reason
        "  - name: flow-db\n    backup: include\n    owner: me\n",  # unknown field
        "  - name: not-in-compose\n    backup: include\n",
        "  - name: flow-delegation-key\n    backup: include\n",  # BE-14 list wins: refused
        "  - name: flow-db\n    backup: include\n  - name: flow-db\n    backup: include\n",
        "  - flow-db\n",
    ],
)
def test_a_malformed_volume_declaration_stops_the_plan(tmp_path: Path, volumes: str):
    addon = _flow_addon(tmp_path, "name: flow\nvolumes:\n" + volumes)
    config_dir = _config(tmp_path, addons=[{"name": "flow", "path": str(addon), "active": True}])
    with pytest.raises(backup.BackupError):
        backup.build_plan(config_dir, _core(tmp_path), tmp_path / "b", existing=[])


def test_archives_are_named_as_age_files(tmp_path: Path):
    addon = _flow_addon(tmp_path, "name: flow\n")
    config_dir = _config(tmp_path, addons=[{"name": "flow", "path": str(addon), "active": True}])
    plan = backup.build_plan(config_dir, _core(tmp_path), tmp_path / "b", existing=[])
    assert all(a.archive.endswith(".tar.gz.age") for a in plan.artifacts)
    assert plan.artifacts[0].archive == "papaia-config.tar.gz.age"


def test_the_volume_declaration_is_contract_generation_13():
    assert compat.GENERATION_FEATURES["volumes"] == 13
    used = compat.manifest_generation_features(
        {"volumes": [{"name": "x", "backup": "include"}]}
    )
    assert ("volumes", 13) in used


# ---------------------------------------------------------------------------
# manifest and catalogue
# ---------------------------------------------------------------------------


def test_the_manifest_names_recipients_checksums_and_exclusions(tmp_path: Path):
    (_, first), (_, second) = _keys()
    recipients = backup_crypt.parse_recipients(f"betrieb:{first},notfall:{second}")
    plan = backup.BackupPlan(
        snapshot=tmp_path / "s", backup_id="s", core_project="papaia", config_dir=tmp_path
    )
    plan.artifacts.append(backup.Artifact("volume", "volumes/a.tar.gz.age", "a", "core"))
    plan.excluded.append({"volume": "papaia_papaia-erasure", "reason": "r"})
    plan.recipients = recipients
    _write(tmp_path / "s" / backup_crypt.CHECKSUMS_NAME, "volumes/a.tar.gz.age\t" + "a" * 64 + "\n")
    manifest = backup.write_manifest(
        tmp_path / "s", plan, {"volumes/a.tar.gz.age": "ok"}, papaia_version="1.10.0"
    )
    assert manifest["encryption"] == {
        "format": "age-encryption.org/v1",
        "recipients": [{"name": "betrieb", "key": first}, {"name": "notfall", "key": second}],
    }
    assert manifest["artifacts"][0]["sha256"] == "a" * 64
    assert manifest["excluded"] == [{"volume": "papaia_papaia-erasure", "reason": "r"}]


def test_the_plan_keeps_recipients_and_exclusions_across_the_round_trip(tmp_path: Path):
    ((_, key),) = _keys(1)
    plan = backup.BackupPlan(
        snapshot=tmp_path / "s", backup_id="s", core_project="papaia", config_dir=tmp_path
    )
    plan.recipients = backup_crypt.parse_recipients(f"betrieb:{key}")
    plan.excluded = [{"volume": "v", "reason": "r"}]
    backup.write_plan(plan)
    again = backup.read_plan(tmp_path / "s")
    assert again.recipients == plan.recipients
    assert again.excluded == plan.excluded


def _point(backup_dir: Path, backup_id: str, created: datetime, result: str = "ok") -> None:
    (backup_dir / backup_id).mkdir(parents=True)
    index = backup.load_index(backup_dir)
    index["backups"].append({
        "id": backup_id, "path": str(backup_dir / backup_id), "result": result,
        "created_at": created.isoformat().replace("+00:00", "Z"),
    })
    backup.save_index(backup_dir, index)


def test_retention_by_count_keeps_seven_of_nine_daily_points(tmp_path: Path):
    """PLT-63-A1: nine runs, seven points left, the two oldest removed."""
    start = datetime(2026, 11, 1, 2, 30, tzinfo=timezone.utc)
    for day in range(9):
        _point(tmp_path, f"p{day}", start + timedelta(days=day))
    removed = backup.prune_keep(tmp_path, 7)
    assert removed == ["p0", "p1"]
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_dir()) == [
        f"p{d}" for d in range(2, 9)
    ]


def test_retention_by_count_does_not_let_failed_runs_push_out_good_points(tmp_path: Path):
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    _point(tmp_path, "good-old", start)
    _point(tmp_path, "good-new", start + timedelta(days=1))
    for day in range(2, 6):
        _point(tmp_path, f"failed-{day}", start + timedelta(days=day), result="failed")
    removed = backup.prune_keep(tmp_path, 2)
    assert "good-old" not in removed and "good-new" not in removed
    assert removed == []
    with pytest.raises(backup.BackupError):
        backup.prune_keep(tmp_path, 0)


# ---------------------------------------------------------------------------
# restore and key check
# ---------------------------------------------------------------------------


def _encrypted_point(tmp_path: Path, recipients: str) -> tuple[Path, Path]:
    config_dir = _config(tmp_path, recipients)
    backup_dir = _mkdir(tmp_path / "backup")
    backup_crypt.init_target(config_dir, backup_dir)
    plan = backup.BackupPlan(
        snapshot=backup_dir / "p1", backup_id="p1", core_project="papaia", config_dir=config_dir
    )
    plan.recipients = backup_crypt.parse_recipients(recipients)
    plan.artifacts.append(backup.Artifact("volume", "volumes/a.tar.gz.age", "papaia_a", "core"))
    target = plan.snapshot / "volumes" / "a.tar.gz.age"
    backup_crypt.seal(io.BytesIO(_tar_gz({"./a": b"1"})), target,
                      [r.key for r in plan.recipients])
    manifest = backup.write_manifest(
        plan.snapshot, plan, {"volumes/a.tar.gz.age": "ok"}, papaia_version="1.10.0"
    )
    backup.record_backup(backup_dir, plan, manifest, "ok")
    return config_dir, backup_dir


def test_key_check_names_the_recipient_and_records_the_date(tmp_path: Path):
    (first, first_r), (second, second_r) = _keys()
    config_dir, backup_dir = _encrypted_point(tmp_path, f"betrieb:{first_r},notfall:{second_r}")
    point, names = backup_crypt.key_check(config_dir, backup_dir, [second])
    assert (point, names) == ("p1", ["notfall"])
    record = yaml.safe_load((config_dir / backup_crypt.KEY_CHECK_FILE).read_text())
    assert set(record["checked"]) == {second_r}
    stranger, _ = age.generate_identity()
    with pytest.raises(backup.BackupError, match="not a recipient"):
        backup_crypt.key_check(config_dir, backup_dir, [stranger])


def test_key_check_reads_the_identity_from_standard_input(tmp_path: Path, monkeypatch, capsys):
    (first, first_r), (_, second_r) = _keys()
    config_dir, backup_dir = _encrypted_point(tmp_path, f"betrieb:{first_r},notfall:{second_r}")
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(f"{first}\n".encode())))
    rc = cli.main([
        "--repo-root", str(tmp_path), "--config-dir", str(config_dir),
        "backup-key-check", f"--backup-dir={backup_dir}", "--identity=-",
    ])
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert "betrieb" in out.out
    assert first not in out.out + out.err
    rows = [json.loads(line) for line in (config_dir / "audit" / "papaia-ctl.jsonl")
            .read_text(encoding="utf-8").splitlines()]
    checked = [r for r in rows if r["event"] == "backup_key_checked"]
    assert len(checked) == 1
    row = checked[0]
    assert row["format"] == "papaia.audit/1" and row["correlation_id"]
    assert row["operation"] == "backup-key-check" and row["result"] == "allowed"
    # It updates the record of checked keys, so it is a write.
    assert row["effect"] == "write"
    assert row["detail"]["id"] == "p1" and row["detail"]["recipients"] == ["betrieb"]
    text = (config_dir / "audit" / "papaia-ctl.jsonl").read_text(encoding="utf-8")
    assert first not in text and "AGE-SECRET-KEY" not in text.upper()


def test_removing_a_recipient_names_the_newest_point_still_readable_with_it(
    tmp_path: Path, capsys
):
    (_, first_r), (_, second_r) = _keys()
    config_dir, backup_dir = _encrypted_point(tmp_path, f"betrieb:{first_r},notfall:{second_r}")
    created = backup.load_index(backup_dir)["backups"][0]["created_at"]
    rc = cli.main([
        "--repo-root", str(tmp_path), "--config-dir", str(config_dir),
        "backup-recipients", "remove", "--name=notfall", f"--backup-dir={backup_dir}",
    ])
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert "p1" in out.out
    assert f"taken {created}" in out.out


def test_restore_refuses_an_encrypted_point_without_its_key(tmp_path: Path, capsys):
    ((_, key),) = _keys(1)
    config_dir, backup_dir = _encrypted_point(tmp_path, f"betrieb:{key}")
    rc = cli.main([
        "--repo-root", str(tmp_path), "--config-dir", str(config_dir),
        "restore-resolve", f"--backup-dir={backup_dir}",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "p1" in err and key in err
