from __future__ import annotations

import json

import pytest

from lib import migrations


def _write(repo_root, *names):
    """Create migration scripts in a repo and return the parsed set."""
    directory = migrations.migrations_dir(repo_root)
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    return directory


# ── discovery ─────────────────────────────────────────────────────────────────


def test_discover_returns_semver_order_not_lexical(repo_root):
    _write(repo_root, "10.0.0__ten.sh", "1.2.0__two.sh", "9.0.0__nine.sh")
    assert [m.version for m in migrations.discover(repo_root)] == ["1.2.0", "9.0.0", "10.0.0"]


def test_discover_orders_same_version_by_slug(repo_root):
    _write(repo_root, "1.1.0__second.sh", "1.1.0__first.sh")
    assert [m.slug for m in migrations.discover(repo_root)] == ["first", "second"]


def test_discover_reads_both_kinds(repo_root):
    _write(repo_root, "1.1.0__shell.sh", "1.2.0__python.py")
    assert [(m.slug, m.kind) for m in migrations.discover(repo_root)] == [
        ("shell", "sh"),
        ("python", "py"),
    ]


def test_discover_ignores_the_readme_and_subdirectories(repo_root):
    directory = _write(repo_root, "1.1.0__real.sh")
    (directory / "README.md").write_text("docs\n", encoding="utf-8")
    (directory / "post").mkdir()
    (directory / "post" / "1.1.0__later.sh").write_text("exit 0\n", encoding="utf-8")
    assert [m.id for m in migrations.discover(repo_root)] == ["1.1.0__real"]


def test_discover_without_the_directory_is_empty(repo_root):
    assert migrations.discover(repo_root) == []


@pytest.mark.parametrize("name", ["1.1.0-no-separator.sh", "1.1__slug.sh", "next__slug.py"])
def test_discover_rejects_a_malformed_name(repo_root, name):
    # A migration that never runs because of a typo in its name is exactly the
    # silent failure this must not have.
    _write(repo_root, name)
    with pytest.raises(ValueError, match="Malformed migration file name"):
        migrations.discover(repo_root)


# ── selection ─────────────────────────────────────────────────────────────────


def test_pending_covers_every_release_in_a_jump(repo_root):
    _write(
        repo_root,
        "1.0.0__already-shipped.sh",
        "1.1.0__one.sh",
        "1.2.0__two.sh",
        "1.5.0__five.sh",
        "1.6.0__too-new.sh",
    )
    found = migrations.discover(repo_root)
    due = migrations.pending(found, "1.0.0", "1.5.0")
    assert [m.version for m in due] == ["1.1.0", "1.2.0", "1.5.0"]


def test_pending_skips_the_installed_version(repo_root):
    # A fresh install at 1.2.0 is seeded in 1.2.0's shape -- its own migrations
    # must not be replayed.
    _write(repo_root, "1.2.0__own.sh", "1.3.0__next.sh")
    found = migrations.discover(repo_root)
    assert [m.version for m in migrations.pending(found, "1.2.0", "1.3.0")] == ["1.3.0"]


def test_pending_skips_already_applied_ids(repo_root):
    _write(repo_root, "1.1.0__one.sh", "1.2.0__two.sh")
    found = migrations.discover(repo_root)
    due = migrations.pending(found, "1.0.0", "1.2.0", {"1.1.0__one"})
    assert [m.id for m in due] == ["1.2.0__two"]


def test_pending_is_empty_without_migrations(repo_root):
    _write(repo_root, "2.0.0__later.sh")
    found = migrations.discover(repo_root)
    assert migrations.pending(found, "1.0.0", "1.5.0") == []


# ── ledger ────────────────────────────────────────────────────────────────────


def test_record_then_read_back(repo_root, config_dir):
    _write(repo_root, "1.1.0__one.sh")
    migration = migrations.discover(repo_root)[0]
    migrations.record(config_dir, migration, duration_s=3)

    state = migrations.load_state(config_dir)
    assert migrations.applied_ids(state) == {"1.1.0__one"}
    entry = state["applied"][0]
    assert entry["version"] == "1.1.0"
    assert entry["duration_s"] == 3
    assert entry["applied_at"].endswith("Z")


def test_record_is_idempotent_for_the_same_migration(repo_root, config_dir):
    _write(repo_root, "1.1.0__one.sh")
    migration = migrations.discover(repo_root)[0]
    migrations.record(config_dir, migration)
    migrations.record(config_dir, migration)
    assert len(migrations.load_state(config_dir)["applied"]) == 1


def test_load_state_without_a_ledger_is_empty(config_dir):
    assert migrations.applied_ids(migrations.load_state(config_dir)) == set()


def test_load_state_rejects_a_corrupt_ledger(config_dir):
    # Resetting it silently would replay migrations that already ran.
    path = migrations.state_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        migrations.load_state(config_dir)


def test_load_state_rejects_an_unexpected_shape(config_dir):
    path = migrations.state_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"applied": "nope"}), encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected shape"):
        migrations.load_state(config_dir)
