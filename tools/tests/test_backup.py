"""Tests for the backup/restore planner, catalogue and retention.

Everything here is filesystem- and YAML-level; the docker side lives in
tools/lib/sh/backup.sh and is exercised manually per the PR test plan.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from lib import backup, envtree

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def _core_repo(tmp_path: Path, *, project_volumes: dict[str, list[str]] | None = None) -> Path:
    """A minimal checkout whose root compose `include:`s two files, mirroring
    the real repo's structure so the include-walk is actually exercised."""
    repo = tmp_path / "papaia"
    _write(
        repo / "src" / "docker-compose.yml",
        """
        include:
          - path: ./infra/keycloak/docker-compose.yml
          - path: ./ai/librechat/docker-compose.yml
        """,
    )
    volumes = project_volumes or {
        "infra/keycloak": ["keycloak-postgresql"],
        "ai/librechat": ["librechat-images", "librechat-mongodb"],
    }
    for rel, keys in volumes.items():
        block = "\n".join(f"  {key}:" for key in keys)
        _write(
            repo / "src" / rel / "docker-compose.yml",
            f"services:\n  stub:\n    image: stub\nvolumes:\n{block}\n",
        )
    return repo


def _grouped_core_repo(tmp_path: Path) -> Path:
    """Like _core_repo, but the services actually mount their volumes and carry
    the module label -- which is what the grouping is read out of."""
    repo = tmp_path / "papaia-grouped"
    _write(
        repo / "src" / "docker-compose.yml",
        """
        include:
          - path: ./ai/librechat/docker-compose.yml
        """,
    )
    _write(
        repo / "src" / "ai" / "librechat" / "docker-compose.yml",
        """
        services:
          librechat-mongodb:
            image: stub
            profiles: [librechat]
            labels:
              de.fidonis.module: papaia-librechat
            volumes:
              - librechat-mongodb:/data/db
        volumes:
          librechat-mongodb:
        """,
    )
    return repo


def _config_dir(
    tmp_path: Path, *, project: str = "papaia", addons: list[dict] | None = None
) -> Path:
    config_dir = tmp_path / "papaia-config"
    _write(config_dir / ".env", f"COMPOSE_PROJECT_NAME={project}\n")
    _write(
        config_dir / "deployment.yaml",
        yaml.safe_dump({"addons": addons or []}, sort_keys=False),
    )
    return config_dir


def _addon(tmp_path: Path, name: str, compose: str) -> Path:
    addon_path = tmp_path / "papaia-addons" / name
    _write(addon_path / "docker-compose.yml", compose)
    return addon_path


def _entry(backup_id: str, created_at: str, *, result: str = "ok", path: str = "") -> dict:
    return {
        "id": backup_id,
        "path": path or f"/backups/{backup_id}",
        "created_at": created_at,
        "size_mb": 1.0,
        "result": result,
    }


# ---------------------------------------------------------------------------
# core volume resolution
# ---------------------------------------------------------------------------


def test_resolve_core_volumes_walks_include_list(tmp_path: Path):
    repo = _core_repo(tmp_path)
    assert backup.resolve_core_volumes(repo) == [
        "keycloak-postgresql",
        "librechat-images",
        "librechat-mongodb",
    ]


def test_resolve_core_volumes_deduplicates(tmp_path: Path):
    repo = _core_repo(
        tmp_path,
        project_volumes={
            "infra/keycloak": ["shared"],
            "ai/librechat": ["shared", "librechat-images"],
        },
    )
    assert backup.resolve_core_volumes(repo) == ["shared", "librechat-images"]


def test_resolve_core_volumes_without_compose_file(tmp_path: Path):
    # Synthetic contexts (minimal test repos) must degrade, not raise.
    assert backup.resolve_core_volumes(tmp_path / "nowhere") == []


# ---------------------------------------------------------------------------
# variable expansion and mount splitting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "env", "expected"),
    [
        ("${MEDIA_DIRECTORY:-./data/media}", {}, "./data/media"),
        ("${MEDIA_DIRECTORY:-./data/media}", {"MEDIA_DIRECTORY": ""}, "./data/media"),
        ("${MEDIA_DIRECTORY:-./data/media}", {"MEDIA_DIRECTORY": "/srv/m"}, "/srv/m"),
        ("${PAPAIA_CONFIG_DIR}/certs", {"PAPAIA_CONFIG_DIR": "/cfg"}, "/cfg/certs"),
        ("$HOME/data", {"HOME": "/root"}, "/root/data"),
        ("${UNSET}", {}, ""),
    ],
)
def test_expand(value, env, expected):
    assert backup.expand(value, env) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("./data/media:/usr/src/media", ("./data/media", "/usr/src/media", "")),
        ("/srv/x:/target:ro", ("/srv/x", "/target", "ro")),
        ("named-volume:/target", ("named-volume", "/target", "")),
        # A Windows source must not be split on its drive-letter colon.
        ("C:/data/media:/target", ("C:/data/media", "/target", "")),
    ],
)
def test_split_mount(entry, expected):
    assert backup._split_mount(entry) == expected


# ---------------------------------------------------------------------------
# add-on bind mounts
# ---------------------------------------------------------------------------


def test_addon_bind_dirs_selects_data_dirs_only(tmp_path: Path):
    config_dir = tmp_path / "papaia-config"
    (config_dir / "certs").mkdir(parents=True)
    addon_path = _addon(
        tmp_path,
        "paperless",
        """
        services:
          paperless:
            image: stub
            volumes:
              - ${PAPAIA_CONFIG_DIR}/certs:/certs:ro
              - paperless-data:/usr/src/paperless/data
              - ${MEDIA_DIRECTORY:-./data/media}:/usr/src/paperless/media
              - ${EXPORT_DIRECTORY:-./data/export}:/usr/src/paperless/export
              - /var/run/docker.sock:/var/run/docker.sock
        volumes:
          paperless-data:
        """,
    )
    (addon_path / "data" / "media").mkdir(parents=True)
    (addon_path / "data" / "export").mkdir(parents=True)

    env = {"PAPAIA_CONFIG_DIR": str(config_dir)}
    found = backup.addon_bind_dirs(addon_path, env, config_dir)

    assert found == [
        (addon_path / "data" / "media").resolve(),
        (addon_path / "data" / "export").resolve(),
    ]


def test_addon_bind_dirs_skips_missing_and_read_only(tmp_path: Path):
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir(parents=True)
    addon_path = _addon(
        tmp_path,
        "sample",
        """
        services:
          app:
            image: stub
            volumes:
              - ./never-created:/a
              - ./read-only:/b:ro
              - ./present:/c
        """,
    )
    (addon_path / "read-only").mkdir()
    (addon_path / "present").mkdir()

    found = backup.addon_bind_dirs(addon_path, {}, config_dir)

    assert found == [(addon_path / "present").resolve()]


def test_addon_bind_dirs_without_compose_file(tmp_path: Path):
    assert backup.addon_bind_dirs(tmp_path / "nope", {}, tmp_path) == []


# ---------------------------------------------------------------------------
# plan construction
# ---------------------------------------------------------------------------


def test_build_plan_prefixes_core_volumes_with_project_name(tmp_path: Path):
    repo = _core_repo(tmp_path)
    config_dir = _config_dir(tmp_path, project="papaia-demo")
    existing = [
        ("papaia-demo", "papaia-demo_keycloak-postgresql"),
        ("papaia-demo", "papaia-demo_librechat-images"),
        ("papaia-demo", "papaia-demo_librechat-mongodb"),
    ]

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=existing)

    assert plan.core_project == "papaia-demo"
    volumes = [a.source for a in plan.artifacts if a.kind == "volume"]
    assert volumes == [
        "papaia-demo_keycloak-postgresql",
        "papaia-demo_librechat-images",
        "papaia-demo_librechat-mongodb",
    ]


def test_build_plan_always_includes_the_config_dir(tmp_path: Path):
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), tmp_path / "backups"
    )
    config_artifacts = [a for a in plan.artifacts if a.kind == "configdir"]
    assert len(config_artifacts) == 1
    assert config_artifacts[0].archive == backup.CONFIG_ARCHIVE


def test_build_plan_skips_declared_volumes_that_do_not_exist(tmp_path: Path):
    repo = _core_repo(tmp_path)
    config_dir = _config_dir(tmp_path)
    # Only one of the three declared volumes was ever created (the others sit
    # behind a profile that is currently disabled).
    existing = [("papaia", "papaia_keycloak-postgresql")]

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=existing)

    assert [a.source for a in plan.artifacts if a.kind == "volume"] == [
        "papaia_keycloak-postgresql"
    ]
    assert plan.skipped == ["papaia_librechat-images", "papaia_librechat-mongodb"]


def test_build_plan_includes_labelled_volumes_that_are_no_longer_declared(tmp_path: Path):
    """A volume from a profile that has since been removed from the compose
    files still holds data and must be archived."""
    repo = _core_repo(tmp_path)
    config_dir = _config_dir(tmp_path)
    existing = [
        ("papaia", "papaia_keycloak-postgresql"),
        ("papaia", "papaia_librechat-images"),
        ("papaia", "papaia_librechat-mongodb"),
        ("papaia", "papaia_searxng_data"),
    ]

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=existing)

    assert "papaia_searxng_data" in [a.source for a in plan.artifacts if a.kind == "volume"]


def test_build_plan_falls_back_to_declared_names_without_docker(tmp_path: Path):
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), tmp_path / "backups", existing=[]
    )
    assert [a.source for a in plan.artifacts if a.kind == "volume"] == [
        "papaia_keycloak-postgresql",
        "papaia_librechat-images",
        "papaia_librechat-mongodb",
    ]


def test_build_plan_includes_addon_volumes_under_the_directory_basename(tmp_path: Path):
    """Add-on volumes are prefixed with the compose project, which is the
    add-on *directory* name -- not the manifest name."""
    repo = _core_repo(tmp_path)
    addon_path = _addon(
        tmp_path,
        "paperless-dir",
        """
        services:
          app:
            image: stub
        volumes:
          paperless-data:
          paperless-pgdata:
        """,
    )
    config_dir = _config_dir(
        tmp_path,
        addons=[{"name": "paperless", "path": str(addon_path), "active": True}],
    )

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=[])

    addon_volumes = [a.source for a in plan.artifacts if a.owner == "addon:paperless"]
    assert addon_volumes == ["paperless-dir_paperless-data", "paperless-dir_paperless-pgdata"]


def test_build_plan_ignores_connector_addons(tmp_path: Path):
    """paperless-connect points at an *external* Paperless instance: it owns no
    volumes and no data bind mounts, so it must contribute nothing."""
    repo = _core_repo(tmp_path)
    addon_path = _addon(
        tmp_path,
        "paperless-connect",
        """
        services:
          paperless-mcp:
            image: stub
            environment:
              PAPERLESS_MCP_PAPERLESS_URL: https://paperless.example.com
            volumes:
              - ${PAPAIA_CONFIG_DIR}/certs:/certs:ro
        networks:
          papaia-paperless-connect-net:
            driver: bridge
        """,
    )
    config_dir = _config_dir(
        tmp_path,
        addons=[{"name": "paperless-connect", "path": str(addon_path), "active": True}],
    )

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=[])

    assert [a for a in plan.artifacts if a.owner == "addon:paperless-connect"] == []
    assert plan.addons == ["paperless-connect"]


def test_build_plan_skips_inactive_addons(tmp_path: Path):
    repo = _core_repo(tmp_path)
    addon_path = _addon(
        tmp_path, "paperless", "services:\n  app:\n    image: stub\nvolumes:\n  data:\n"
    )
    config_dir = _config_dir(
        tmp_path, addons=[{"name": "paperless", "path": str(addon_path), "active": False}]
    )

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=[])

    assert plan.addons == []


def test_build_plan_archive_names_are_unique(tmp_path: Path):
    repo = _core_repo(tmp_path)
    addon_path = _addon(
        tmp_path,
        "paperless",
        """
        services:
          app:
            image: stub
            volumes:
              - ./data/media:/a
              - ./data/export:/b
        """,
    )
    (addon_path / "data" / "media").mkdir(parents=True)
    (addon_path / "data" / "export").mkdir(parents=True)
    config_dir = _config_dir(
        tmp_path, addons=[{"name": "paperless", "path": str(addon_path), "active": True}]
    )

    plan = backup.build_plan(config_dir, repo, tmp_path / "backups", existing=[])

    archives = [a.archive for a in plan.artifacts]
    assert len(archives) == len(set(archives))
    assert sorted(a.archive for a in plan.artifacts if a.kind == "binddir") == [
        "binds/paperless--data-export.tar.gz",
        "binds/paperless--data-media.tar.gz",
    ]


# ---------------------------------------------------------------------------
# plan / manifest round trips
# ---------------------------------------------------------------------------


def test_plan_round_trip(tmp_path: Path):
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), tmp_path / "backups", existing=[]
    )
    plan.snapshot.mkdir(parents=True)
    backup.write_plan(plan)

    restored = backup.read_plan(plan.snapshot)

    assert restored.backup_id == plan.backup_id
    assert restored.core_project == plan.core_project
    assert [a.archive for a in restored.artifacts] == [a.archive for a in plan.artifacts]


def test_read_plan_without_file_raises(tmp_path: Path):
    with pytest.raises(backup.BackupError):
        backup.read_plan(tmp_path)


def test_write_manifest_lists_successful_artifacts_only(tmp_path: Path):
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), tmp_path / "backups", existing=[]
    )
    plan.snapshot.mkdir(parents=True)
    results = {a.archive: "ok" for a in plan.artifacts}
    broken = plan.artifacts[-1].archive
    results[broken] = "failed"

    manifest = backup.write_manifest(plan.snapshot, plan, results, papaia_version="1.0.0")

    archives = [a["archive"] for a in manifest["artifacts"]]
    assert broken not in archives
    assert len(archives) == len(plan.artifacts) - 1
    assert backup.read_manifest(plan.snapshot)["id"] == plan.backup_id


def test_write_manifest_treats_unreported_artifacts_as_failed(tmp_path: Path):
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), tmp_path / "backups", existing=[]
    )
    plan.snapshot.mkdir(parents=True)

    manifest = backup.write_manifest(plan.snapshot, plan, {}, papaia_version="1.0.0")

    assert manifest["artifacts"] == []


def test_write_manifest_carries_the_grouping_fields(tmp_path: Path):
    """A partial restore selects on these, so they have to survive the plan ->
    manifest hop. `project` used to be computed and then dropped here."""
    plan = backup.build_plan(
        _config_dir(tmp_path), _grouped_core_repo(tmp_path), tmp_path / "backups", existing=[]
    )
    plan.snapshot.mkdir(parents=True)
    results = {a.archive: "ok" for a in plan.artifacts}

    manifest = backup.write_manifest(plan.snapshot, plan, results, papaia_version="1.0.0")

    assert manifest["version"] == backup.MANIFEST_VERSION
    mongodb = next(
        a for a in manifest["artifacts"] if a["target"] == "papaia_librechat-mongodb"
    )
    assert mongodb["module"] == "librechat"
    assert mongodb["profiles"] == ["librechat"]
    assert mongodb["services"] == ["librechat-mongodb"]
    assert mongodb["project"] == "papaia"
    # The config archive stays ungrouped: it is not selectable on its own.
    config = next(a for a in manifest["artifacts"] if a["kind"] == "configdir")
    assert config["module"] == ""


def test_build_plan_leaves_an_undeclared_volume_ungrouped(tmp_path: Path):
    """A volume that carries the project label but is no longer declared has no
    owner record. It keeps its data and stays reachable by name, but must not
    be invented into a module."""
    plan = backup.build_plan(
        _config_dir(tmp_path),
        _grouped_core_repo(tmp_path),
        tmp_path / "backups",
        existing=[("papaia", "papaia_leftover")],
    )
    leftover = next(a for a in plan.artifacts if a.source == "papaia_leftover")
    assert leftover.module == ""
    assert leftover.profiles == []


def test_build_plan_groups_addon_artifacts_under_the_addon_name(tmp_path: Path):
    addon_path = _addon(
        tmp_path,
        "paperless-dir",
        "services:\n  app:\n    image: stub\nvolumes:\n  paperless-data:\n",
    )
    config_dir = _config_dir(
        tmp_path,
        addons=[{"name": "paperless", "path": str(addon_path), "active": True}],
    )
    plan = backup.build_plan(
        config_dir,
        _grouped_core_repo(tmp_path),
        tmp_path / "backups",
        existing=[("paperless-dir", "paperless-dir_paperless-data")],
    )
    volume = next(a for a in plan.artifacts if a.owner == "addon:paperless")
    # Manifest name for the module, directory basename for the project -- the
    # two differ by design and a scoped restore needs both.
    assert volume.module == "paperless"
    assert volume.project == "paperless-dir"
    assert volume.profiles == []


def test_read_results_parses_tsv(tmp_path: Path):
    _write(tmp_path / backup.RESULTS_NAME, "volumes/a.tar.gz\tok\nvolumes/b.tar.gz\tfailed\n")
    assert backup.read_results(tmp_path) == {
        "volumes/a.tar.gz": "ok",
        "volumes/b.tar.gz": "failed",
    }


def test_read_manifest_without_file_raises(tmp_path: Path):
    with pytest.raises(backup.BackupError):
        backup.read_manifest(tmp_path)


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------


def test_record_backup_round_trip(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), backup_dir, existing=[]
    )
    plan.snapshot.mkdir(parents=True)
    (plan.snapshot / "payload.bin").write_bytes(b"x" * 3 * 1024 * 1024)
    manifest = backup.write_manifest(
        plan.snapshot,
        plan,
        {a.archive: "ok" for a in plan.artifacts},
        papaia_version="1.0.0",
    )

    entry = backup.record_backup(backup_dir, plan, manifest, "ok")

    assert entry["id"] == plan.backup_id
    assert entry["result"] == "ok"
    assert entry["size_mb"] == pytest.approx(3.0, abs=0.1)
    assert backup.load_index(backup_dir)["backups"] == [entry]


def test_record_backup_replaces_an_entry_with_the_same_id(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    plan = backup.build_plan(
        _config_dir(tmp_path), _core_repo(tmp_path), backup_dir, existing=[]
    )
    plan.snapshot.mkdir(parents=True)
    manifest = backup.write_manifest(plan.snapshot, plan, {}, papaia_version="1.0.0")

    backup.record_backup(backup_dir, plan, manifest, "failed")
    backup.record_backup(backup_dir, plan, manifest, "ok")

    backups = backup.load_index(backup_dir)["backups"]
    assert len(backups) == 1
    assert backups[0]["result"] == "ok"


def test_load_index_on_empty_directory(tmp_path: Path):
    assert backup.load_index(tmp_path) == {"version": 1, "backups": []}


def test_load_index_rejects_broken_yaml(tmp_path: Path):
    _write(tmp_path / backup.INDEX_NAME, "backups: [oops\n")
    with pytest.raises(backup.BackupError):
        backup.load_index(tmp_path)


# ---------------------------------------------------------------------------
# retention
# ---------------------------------------------------------------------------


def _seed_index(backup_dir: Path, entries: list[dict]) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        Path(entry["path"]).mkdir(parents=True, exist_ok=True)
    backup.save_index(backup_dir, {"version": 1, "backups": entries})


def test_prune_removes_old_snapshots_and_their_entries(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    old = _entry("old", (now - timedelta(days=30)).isoformat(), path=str(backup_dir / "old"))
    recent = _entry(
        "recent", (now - timedelta(days=2)).isoformat(), path=str(backup_dir / "recent")
    )
    _seed_index(backup_dir, [old, recent])

    removed = backup.prune(backup_dir, 14, now=now)

    assert removed == ["old"]
    assert not (backup_dir / "old").exists()
    assert (backup_dir / "recent").is_dir()
    assert [b["id"] for b in backup.load_index(backup_dir)["backups"]] == ["recent"]


def test_prune_leaves_unrecorded_directories_alone(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    old = _entry("old", (now - timedelta(days=30)).isoformat(), path=str(backup_dir / "old"))
    _seed_index(backup_dir, [old])
    stranger = backup_dir / "operator-notes"
    stranger.mkdir()

    backup.prune(backup_dir, 1, now=now)

    assert stranger.is_dir()


def test_prune_zero_days_removes_everything_recorded(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    entries = [
        _entry("a", (now - timedelta(hours=1)).isoformat(), path=str(backup_dir / "a")),
        _entry("b", (now - timedelta(days=3)).isoformat(), path=str(backup_dir / "b")),
    ]
    _seed_index(backup_dir, entries)

    removed = backup.prune(backup_dir, 0, now=now)

    assert sorted(removed) == ["a", "b"]
    assert backup.load_index(backup_dir)["backups"] == []


def test_prune_refuses_to_delete_outside_the_backup_dir(tmp_path: Path):
    """A `path` pointing elsewhere is dropped from the catalogue but must not
    take an unrelated directory with it."""
    backup_dir = tmp_path / "backups"
    outsider = tmp_path / "important"
    outsider.mkdir()
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    _seed_index(
        backup_dir,
        [_entry("escape", (now - timedelta(days=30)).isoformat(), path=str(outsider))],
    )

    backup.prune(backup_dir, 1, now=now)

    assert outsider.is_dir()


def test_prune_rejects_a_negative_retention(tmp_path: Path):
    with pytest.raises(backup.BackupError):
        backup.prune(tmp_path, -1)


# ---------------------------------------------------------------------------
# snapshot location
# ---------------------------------------------------------------------------


def test_snapshot_path_ignores_a_recorded_path_from_another_environment(tmp_path: Path):
    """A catalogue written under WSL records /mnt/c/...; read back from Windows
    that path does not resolve, but <backup_dir>/<id> always does."""
    backup_dir = tmp_path / "backups"
    (backup_dir / "2026-07-30_11-42-47").mkdir(parents=True)
    entry = {"id": "2026-07-30_11-42-47", "path": "/mnt/c/elsewhere/2026-07-30_11-42-47"}

    assert backup.snapshot_path(backup_dir, entry) == backup_dir / "2026-07-30_11-42-47"


def test_snapshot_path_falls_back_to_the_recorded_path(tmp_path: Path):
    moved = tmp_path / "moved-aside"
    moved.mkdir()
    entry = {"id": "2026-07-30_11-42-47", "path": str(moved)}

    assert backup.snapshot_path(tmp_path / "backups", entry) == moved


def test_prune_finds_snapshots_recorded_with_a_foreign_path(tmp_path: Path):
    backup_dir = tmp_path / "backups"
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    entry = _entry(
        "old", (now - timedelta(days=30)).isoformat(), path="/mnt/c/elsewhere/old"
    )
    backup_dir.mkdir(parents=True)
    (backup_dir / "old").mkdir()
    backup.save_index(backup_dir, {"version": 1, "backups": [entry]})

    assert backup.prune(backup_dir, 1, now=now) == ["old"]
    assert not (backup_dir / "old").exists()


# ---------------------------------------------------------------------------
# restore point selection
# ---------------------------------------------------------------------------


def test_resolve_restore_point_defaults_to_the_newest(tmp_path: Path):
    _seed_index(
        tmp_path,
        [
            _entry("older", "2026-07-01T10:00:00Z", path=str(tmp_path / "older")),
            _entry("newer", "2026-07-20T10:00:00Z", path=str(tmp_path / "newer")),
        ],
    )
    entry, warnings = backup.resolve_restore_point(tmp_path)
    assert entry["id"] == "newer"
    assert warnings == []


def test_resolve_restore_point_never_picks_a_failed_backup_implicitly(tmp_path: Path):
    _seed_index(
        tmp_path,
        [
            _entry("good", "2026-07-01T10:00:00Z", path=str(tmp_path / "good")),
            _entry(
                "broken", "2026-07-20T10:00:00Z", result="failed", path=str(tmp_path / "broken")
            ),
        ],
    )
    entry, _ = backup.resolve_restore_point(tmp_path)
    assert entry["id"] == "good"


def test_resolve_restore_point_warns_about_a_partial_backup(tmp_path: Path):
    _seed_index(
        tmp_path,
        [_entry("half", "2026-07-20T10:00:00Z", result="partial", path=str(tmp_path / "half"))],
    )
    entry, warnings = backup.resolve_restore_point(tmp_path)
    assert entry["id"] == "half"
    assert warnings and "partial" in warnings[0]


def test_resolve_restore_point_accepts_an_explicit_failed_id(tmp_path: Path):
    _seed_index(
        tmp_path,
        [_entry("broken", "2026-07-20T10:00:00Z", result="failed", path=str(tmp_path / "b"))],
    )
    entry, _ = backup.resolve_restore_point(tmp_path, "broken")
    assert entry["id"] == "broken"


def test_resolve_restore_point_rejects_an_unknown_id(tmp_path: Path):
    _seed_index(tmp_path, [_entry("known", "2026-07-20T10:00:00Z", path=str(tmp_path / "k"))])
    with pytest.raises(backup.BackupError, match="known"):
        backup.resolve_restore_point(tmp_path, "typo")


def test_resolve_restore_point_on_an_empty_catalogue(tmp_path: Path):
    with pytest.raises(backup.BackupError, match="No restore points"):
        backup.resolve_restore_point(tmp_path)


def test_resolve_restore_point_when_everything_failed(tmp_path: Path):
    _seed_index(
        tmp_path,
        [_entry("a", "2026-07-20T10:00:00Z", result="failed", path=str(tmp_path / "a"))],
    )
    with pytest.raises(backup.BackupError, match="--restore-point"):
        backup.resolve_restore_point(tmp_path)


# ---------------------------------------------------------------------------
# PAPAIA_BACKUP_DIR stamping
# ---------------------------------------------------------------------------


def test_stamp_backup_dir_derives_from_the_workspace():
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/srv/papaia", "PAPAIA_BACKUP_DIR": "/srv/papaia/backup"}}
    assert (
        envtree.stamp_backup_dir(tree)[""]["PAPAIA_BACKUP_DIR"] == "/srv/papaia/backup"
    )

    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/opt/workspace", "PAPAIA_BACKUP_DIR": ""}}
    assert (
        envtree.stamp_backup_dir(tree)[""]["PAPAIA_BACKUP_DIR"] == "/opt/workspace/backup"
    )


def test_stamp_backup_dir_replaces_the_shipped_placeholder():
    tree = {
        "": {
            "PAPAIA_WORKSPACE_DIR": "/opt/workspace",
            "PAPAIA_BACKUP_DIR": envtree._BACKUP_DIR_PLACEHOLDER,
        }
    }
    assert envtree.stamp_backup_dir(tree)[""]["PAPAIA_BACKUP_DIR"] == "/opt/workspace/backup"


def test_stamp_backup_dir_keeps_an_operator_value():
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/opt/workspace", "PAPAIA_BACKUP_DIR": "/mnt/nas/papaia"}}
    assert envtree.stamp_backup_dir(tree)[""]["PAPAIA_BACKUP_DIR"] == "/mnt/nas/papaia"


def test_stamp_backup_dir_override_beats_everything():
    tree = {"": {"PAPAIA_WORKSPACE_DIR": "/opt/workspace", "PAPAIA_BACKUP_DIR": "/mnt/nas/papaia"}}
    stamped = envtree.stamp_backup_dir(tree, override="/mnt/other")
    assert stamped[""]["PAPAIA_BACKUP_DIR"] == "/mnt/other"


def test_stamp_backup_dir_without_a_workspace_keeps_the_placeholder():
    tree = {"": {"PAPAIA_BACKUP_DIR": envtree._BACKUP_DIR_PLACEHOLDER}}
    assert (
        envtree.stamp_backup_dir(tree)[""]["PAPAIA_BACKUP_DIR"]
        == envtree._BACKUP_DIR_PLACEHOLDER
    )
