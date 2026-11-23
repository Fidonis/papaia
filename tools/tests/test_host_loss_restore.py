"""Restore after the loss of the host (BE-18a, RE-88): every restore point carries an
unencrypted `RELEASE` file and `<target>/latest` names the newest good point, `restore
--from=<target>` runs on a fresh host without `setup`, stops with `git checkout <tag>` when
the checkout is another release, and ends with the erasure probe: every object journaled
for deletion since the point must be gone again, otherwise the probe fails.

The bash harness is the one of test_restore_journal_cli: `docker` runs `tar` on host
directories and the add-on's migration image is a stub that applies the journal at the
backup target, as a module's `erasure-replay` does.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from lib import backup, host_restore, images
from tests.test_restore_journal_cli import _actions, _audit, _no_key_anywhere, _run, _stack

REPO = Path(__file__).resolve().parents[2]

# The real gate of lib/sh/lifecycle.sh; the harness replaces it with a no-op.
_SETUP_GATE = """
_require_setup_done() {
    if [ ! -f "$CONFIG_DIR/.env" ] || [ ! -f "$CONFIG_DIR/deployment.yaml" ]; then
        error "No setup found at $CONFIG_DIR. Run 'papaia-ctl setup' first."
        exit 2
    fi
}
"""


def _start_stub(tmp_path: Path, stack: dict) -> str:
    """`start --addons` as far as the restore needs it: the pending post-restore step of
    the core, then the add-on, whose start runs its due module actions first. Compose
    creates the add-on's volumes that are not in the backup (the delegation key)."""
    log = (tmp_path / "calls.log").as_posix()
    key_volume = (stack["volumes"] / "flow_flow-delegation-key").as_posix()
    return (
        f'cmd_start() {{ echo "start $*" >> "{log}"; _require_setup_done;'
        f' mkdir -p "{key_volume}";'
        f' _post_restore_before_modules; _addon_compose_up flow "{stack["addons"]}/flow"; }}\n'
        f'_addon_compose_all() {{ echo "compose-all $*" >> "{log}"; }}\n'
    )


def _host_stack(tmp_path: Path, version: str = "1.9.0") -> dict:
    stack = _stack(tmp_path)
    (stack["repo"] / "VERSION").write_text(version + "\n", encoding="utf-8")
    (stack["repo"] / "compat").mkdir()
    shutil.copy(REPO / "compat" / "suite.yaml", stack["repo"] / "compat" / "suite.yaml")
    return stack


def _backup(tmp_path: Path, stack: dict) -> str:
    done, _calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 0, done.stderr + done.stdout
    return backup.load_index(stack["target"])["backups"][-1]["id"]


def _now() -> str:
    now = datetime.now(timezone.utc) + timedelta(seconds=1)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _journal(stack: dict, module: str, object_ref: str, *, seq: int = 1,
             at: str | None = None) -> None:
    folder = stack["target"] / "erasure-journal"
    folder.mkdir(exist_ok=True)
    with open(folder / f"{module}.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "id": f"0199a000-0000-4000-8000-{seq:012d}", "module": module, "seq": seq,
            "kind": "erase", "object_ref": object_ref, "subject_ref": "ab" * 32,
            "at": at or _now(), "reason": "person_request",
        }) + "\n")


def _lose_the_host(stack: dict) -> None:
    """After the last backup a person's record is deleted (the module deletes it and
    journals it at the target); then the host is gone with every volume, the local copy
    of the journal and the configuration directory. Target and key are left."""
    (stack["volumes"] / "flow_flow-db" / "doc-7").unlink()
    _journal(stack, "flow", "doc-7")
    shutil.rmtree(stack["volumes"])
    stack["volumes"].mkdir()
    shutil.rmtree(stack["config"])


def _restore(tmp_path: Path, stack: dict, flags: str = "", *, stdin: str = ""):
    return _run(
        tmp_path, stack,
        _SETUP_GATE + _start_stub(tmp_path, stack)
        + f'cmd_restore -y --from="{stack["target"]}" --identity="{stack["key"]}" {flags}',
        stdin=stdin,
    )


# ─────────────────────────────────────────────────────────────────────────
# RELEASE and latest
# ─────────────────────────────────────────────────────────────────────────


def test_every_point_carries_an_unencrypted_release_file_and_latest_names_it(tmp_path):
    stack = _host_stack(tmp_path)
    point = _backup(tmp_path, stack)

    release = (stack["target"] / point / "RELEASE").read_text(encoding="utf-8")
    assert "tag: v1.9.0" in release
    assert "suite: 1.9.0" in release
    assert f"id: {point}" in release
    assert "git checkout v1.9.0" in release
    # Plain text a file browser shows; no person and no key in it.
    assert "age-encryption" not in release and stack["identity"] not in release
    parsed = host_restore.read_release(stack["target"] / point / "RELEASE")
    assert parsed["tag"] == "v1.9.0" and parsed["suite"] == "1.9.0" and parsed["id"] == point

    latest = stack["target"] / "latest"
    assert (latest / "RELEASE").read_text(encoding="utf-8") == release
    assert (latest / "POINT").read_text(encoding="utf-8").strip() == point


def test_latest_follows_the_newest_good_point_of_the_whole_stack(tmp_path):
    target = tmp_path / "backup"
    target.mkdir()
    rows = [
        ("2026-11-20_10-00-00", "2026-11-20T10:00:00Z", "ok", None),
        ("2026-11-21_10-00-00", "2026-11-21T10:00:00Z", "ok", None),
        ("2026-11-22_10-00-00", "2026-11-22T10:00:00Z", "partial", None),
        ("2026-11-22_11-00-00", "2026-11-22T11:00:00Z", "failed", None),
        ("2026-11-22_12-00-00", "2026-11-22T12:00:00Z", "ok", ["addon:flow"]),
    ]
    entries = []
    for point, created, result, scope in rows:
        (target / point).mkdir()
        (target / point / "RELEASE").write_text(
            f"id: {point}\ntag: v1.9.0\nsuite: 1.9.0\n", encoding="utf-8"
        )
        entries.append({"id": point, "created_at": created, "result": result,
                        **({"scope": scope} if scope else {})})
    backup.save_index(target, {"version": 1, "backups": entries})

    assert host_restore.update_latest(target) == "2026-11-21_10-00-00"
    assert (target / "latest" / "POINT").read_text().strip() == "2026-11-21_10-00-00"
    entry, _warnings = backup.resolve_restore_point(target, "latest")
    assert entry["id"] == "2026-11-21_10-00-00"

    backup.delete_backups(target, ["2026-11-21_10-00-00"])
    assert host_restore.update_latest(target) == "2026-11-20_10-00-00"
    backup.delete_backups(target, ["2026-11-20_10-00-00"])
    assert host_restore.update_latest(target) is None
    assert not (target / "latest").exists()
    with pytest.raises(backup.BackupError, match="latest"):
        backup.resolve_restore_point(target, "latest")


@pytest.mark.parametrize("text", [
    "id: 2026-11-20_10-00-00\ntag: main\nsuite: 1.9.0\n",
    "id: 2026-11-20_10-00-00\ntag: v1.9.0\nsuite: 1.9.0\nowner: anna\n",
    "id: 2026-11-20_10-00-00\ntag: v1.9.0; rm -rf /\nsuite: 1.9.0\n",
    "id: ../../etc\ntag: v1.9.0\nsuite: 1.9.0\n",
    "tag: v1.9.0\nsuite: 1.9.0\n",
    "x" * 5000,
])
def test_a_release_file_that_is_not_one_is_refused(tmp_path, text):
    path = tmp_path / "RELEASE"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(backup.BackupError):
        host_restore.read_release(path)


# ─────────────────────────────────────────────────────────────────────────
# a fresh host
# ─────────────────────────────────────────────────────────────────────────


def test_a_fresh_host_with_another_checkout_stops_with_the_checkout_message(tmp_path):
    stack = _host_stack(tmp_path)
    _backup(tmp_path, stack)
    _lose_the_host(stack)
    (stack["repo"] / "VERSION").write_text("1.8.0\n", encoding="utf-8")

    done, calls = _restore(tmp_path, stack, "--restore-point=latest")
    assert done.returncode == 2, done.stderr + done.stdout
    assert "git checkout v1.9.0" in done.stderr
    assert "v1.8.0" in done.stderr
    assert not any(c.startswith("docker run") or c.startswith("compose ") for c in calls)
    assert not (stack["config"] / "deployment.yaml").exists()
    assert not any(stack["volumes"].iterdir())


def test_a_fresh_host_with_the_matching_tag_restores_and_the_probe_passes(tmp_path):
    stack = _host_stack(tmp_path)
    point = _backup(tmp_path, stack)
    _lose_the_host(stack)

    # No --restore-point: --from finds the latest point.
    done, calls = _restore(tmp_path, stack)
    assert done.returncode == 0, done.stderr + done.stdout
    assert f"Restore point {point}" in done.stderr
    assert (stack["config"] / "notes.txt").read_text() == "canary-config-5521\n"
    flow_db = stack["volumes"] / "flow_flow-db"
    assert (flow_db / "run-1").read_text() == "canary-flow-4410"
    assert not (flow_db / "doc-7").exists(), "the deletion after the point came back"
    # Nothing to stop on a fresh host; the module started after its journal was applied.
    assert not any(c.startswith("compose-all") for c in calls)
    assert [a["action"] for a in _actions(tmp_path)] == ["erasure-replay", "post-restore"]

    assert "erasure probe: flow pass (1 journaled since the point)" in done.stdout
    assert "erasure probe passed" in done.stdout
    rows = _audit(stack["config"])
    probe = [r for r in rows if r["event"] == "erasure_probe"]
    assert len(probe) == 1 and probe[0]["result"] == "allowed"
    assert probe[0]["detail"]["id"] == point
    assert probe[0]["detail"]["modules"] == {"flow": {"journaled": 1, "result": "pass",
                                                      "reason": "replayed"}}
    replay = next(r for r in rows if r["event"] == "module_action_run")
    assert probe[0]["correlation_id"] == replay["correlation_id"]
    assert "erasure_probe=pass" in (stack["target"] / "backup.log").read_text()
    _no_key_anywhere(tmp_path, stack, calls, done)


def test_without_setup_restore_names_from(tmp_path):
    stack = _host_stack(tmp_path)
    shutil.rmtree(stack["config"])
    done, calls = _run(tmp_path, stack, _SETUP_GATE + "cmd_restore -y")
    assert done.returncode == 2
    assert "--from=" in done.stderr
    assert not any(c.startswith("docker ") for c in calls)


def test_a_fresh_host_restores_the_whole_point_only(tmp_path):
    stack = _host_stack(tmp_path)
    _backup(tmp_path, stack)
    _lose_the_host(stack)
    done, calls = _restore(tmp_path, stack, "--only=addon:flow")
    assert done.returncode == 2
    assert "whole" in done.stderr
    assert not any(c.startswith("docker run") for c in calls)


def test_a_fresh_host_needs_a_confirmed_target(tmp_path):
    stack = _host_stack(tmp_path)
    _backup(tmp_path, stack)
    _lose_the_host(stack)
    (stack["target"] / ".papaia-target").unlink()
    done, calls = _restore(tmp_path, stack)
    assert done.returncode != 0
    assert ".papaia-target" in done.stderr
    assert not any(c.startswith("docker run") for c in calls)


def test_a_point_of_another_installation_is_refused(tmp_path):
    stack = _host_stack(tmp_path)
    point = _backup(tmp_path, stack)
    _lose_the_host(stack)
    release = stack["target"] / point / "RELEASE"
    text = release.read_text(encoding="utf-8")
    own = host_restore.read_release(release)["installation_id"]
    release.write_text(text.replace(own, "00000000-0000-4000-8000-000000000000"),
                       encoding="utf-8")
    done, calls = _restore(tmp_path, stack, f"--restore-point={point}")
    assert done.returncode != 0
    assert "another installation" in done.stderr
    assert not any(c.startswith("docker run") for c in calls)


# ─────────────────────────────────────────────────────────────────────────
# the erasure probe fails when a journaled object is not proven gone
# ─────────────────────────────────────────────────────────────────────────


def test_the_probe_fails_for_a_journaled_deletion_no_module_replays(tmp_path):
    stack = _host_stack(tmp_path)
    point = _backup(tmp_path, stack)
    _journal(stack, "studio", "row-9")
    _lose_the_host(stack)

    done, _calls = _restore(tmp_path, stack)
    assert done.returncode == 3, done.stderr + done.stdout
    assert "erasure probe failed" in done.stderr
    assert "studio fail (1 journaled since the point): not_installed" in done.stdout
    probe = next(r for r in _audit(stack["config"]) if r["event"] == "erasure_probe")
    assert probe["result"] == "error" and probe["error_code"] == "erasure_probe_failed"
    assert probe["detail"]["id"] == point
    assert probe["detail"]["modules"]["studio"]["result"] == "fail"
    assert "erasure_probe=fail" in (stack["target"] / "backup.log").read_text()


def test_the_probe_fails_for_a_journal_it_cannot_read(tmp_path):
    stack = _host_stack(tmp_path)
    _backup(tmp_path, stack)
    _lose_the_host(stack)
    # A journal no replay of this restore reads: only the probe looks at it.
    (stack["target"] / "erasure-journal" / "studio.jsonl").write_text("{not json\n")

    done, _calls = _restore(tmp_path, stack)
    assert done.returncode == 3, done.stderr + done.stdout
    assert "flow pass" in done.stdout
    assert "studio fail (0 journaled since the point): journal_unreadable" in done.stdout


def test_a_failed_replay_stops_the_restore_before_the_probe(tmp_path):
    stack = _host_stack(tmp_path)
    _backup(tmp_path, stack)
    _lose_the_host(stack)
    (tmp_path / "fail-action").write_text("erasure-replay")
    done, calls = _restore(tmp_path, stack)
    assert done.returncode != 0
    assert not any(c.startswith("compose up flow") for c in calls)
    assert not any("erasure-probe" in c for c in calls)


def _probe_setup(tmp_path: Path, *, declares: bool = True) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    addon = tmp_path / "addons" / "flow"
    addon.mkdir(parents=True)
    actions = {"erasure-replay": {"service": "m", "args": ["erasure-replay"]}} if declares else {}
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump({"name": "flow", **({"actions": actions} if actions else {})}),
        encoding="utf-8",
    )
    config = tmp_path / "config"
    config.mkdir()
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "flow", "path": str(addon), "active": True}]}),
        encoding="utf-8",
    )
    target = tmp_path / "backup"
    (target / "erasure-journal").mkdir(parents=True)
    return repo, config, target


CID = "0c8f3f3e-2b8a-4d5e-9a51-6f2b1c3d4e5f"


def _replay_row(config: Path, *, result: str = "allowed", point: str = "P1",
                cid: str = CID) -> None:
    images.append_audit(config, {
        "format": "papaia.audit/1", "correlation_id": cid, "event": "module_action_run",
        "result": result, "detail": {"addon": "flow", "action": "erasure-replay",
                                     "restore_point": point, "exit_code": 0},
    })


def _write(target: Path, module: str, lines: list[dict]) -> None:
    (target / "erasure-journal" / f"{module}.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )


def _line(module: str, seq: int, at: str) -> dict:
    return {"id": f"0199a000-0000-4000-8000-{seq:012d}", "module": module, "seq": seq,
            "kind": "erase", "object_ref": f"obj-{seq}", "subject_ref": "cd" * 32,
            "at": at, "reason": "person_request"}


CREATED = "2026-11-22T10:00:00Z"


def _probe(repo, config, target, **kw):
    return host_restore.erasure_probe(
        config, repo, target, restore_point="P1", created_at=CREATED,
        correlation_id=CID, **kw,
    )


def test_probe_counts_only_what_was_journaled_since_the_point(tmp_path):
    repo, config, target = _probe_setup(tmp_path)
    _write(target, "flow", [_line("flow", 1, "2026-11-21T09:00:00.000Z")])
    result = _probe(repo, config, target)
    assert result.passed
    assert [(m.module, m.journaled, m.result) for m in result.modules] == [("flow", 0, "pass")]


@pytest.mark.parametrize(("declares", "row", "reason"), [
    (True, None, "replay_missing"),
    (True, "error", "replay_failed"),
    (False, None, "no_replay_action"),
])
def test_probe_fails_without_a_successful_replay_of_this_restore(tmp_path, declares, row,
                                                                 reason):
    repo, config, target = _probe_setup(tmp_path, declares=declares)
    _write(target, "flow", [_line("flow", 1, "2026-11-22T10:00:05.000Z")])
    if row:
        _replay_row(config, result=row)
    # A successful replay of another restore is no evidence for this one.
    _replay_row(config, cid="11111111-2222-4333-8444-555555555555")
    _replay_row(config, point="P0")
    result = _probe(repo, config, target)
    assert not result.passed
    assert [(m.module, m.result, m.reason) for m in result.modules] == [("flow", "fail", reason)]


def test_probe_passes_with_the_replay_of_this_restore(tmp_path):
    repo, config, target = _probe_setup(tmp_path)
    _write(target, "flow", [_line("flow", 1, "2026-11-22T10:00:05.000Z"),
                            _line("flow", 2, "2026-11-22T11:00:00.000Z")])
    _replay_row(config)
    result = _probe(repo, config, target)
    assert result.passed
    assert [(m.module, m.journaled, m.reason) for m in result.modules] == [
        ("flow", 2, "replayed")
    ]


def test_probe_fails_for_a_line_of_another_module(tmp_path):
    repo, config, target = _probe_setup(tmp_path)
    _write(target, "flow", [_line("studio", 1, "2026-11-22T10:00:05.000Z")])
    _replay_row(config)
    result = _probe(repo, config, target)
    assert not result.passed
    assert result.modules[0].reason == "journal_unreadable"


def test_a_scoped_probe_looks_at_the_selected_add_ons_only(tmp_path):
    repo, config, target = _probe_setup(tmp_path)
    _write(target, "studio", [_line("studio", 1, "2026-11-22T10:00:05.000Z")])
    _write(target, "identity", [_line("identity", 1, "2026-11-22T10:00:05.000Z")])
    result = _probe(repo, config, target, addons=["flow"])
    assert result.passed
    assert [m.module for m in result.modules] == ["flow"]


def test_core_sources_are_reported_and_left_to_the_core(tmp_path):
    # identity, core-chat and model-gateway are replayed by the core itself, not by an
    # add-on's erasure-replay; the probe names them and does not fail on them.
    repo, config, target = _probe_setup(tmp_path)
    line = _line("identity", 1, "2026-11-22T10:00:05.000Z")
    line["kind"] = "account_delete"
    _write(target, "identity", [line])
    result = _probe(repo, config, target)
    assert result.passed
    core = next(m for m in result.modules if m.module == "identity")
    assert (core.result, core.reason, core.journaled) == ("core", "core_source", 1)
