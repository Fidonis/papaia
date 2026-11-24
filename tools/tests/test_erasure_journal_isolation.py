"""Isolation of the modules' erasure journals at the backup target (PLT-66, RE-06, BE-16).

Each add-on writes `$PAPAIA_BACKUP_DIR/erasure-journal/<module>.jsonl` and nothing else
there: the core creates that one file, and a generated override mounts it read-write into
the add-on's writer services under an empty folder of their own. The add-on's compose file
may not mount the backup target or anything in it, and `doctor erasure_journal` reports a
shared mount, a file another module could write and a line planted in another journal.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from papaia_kit.erasure import (
    EPOCH_FILE,
    ErasureJournal,
    ErasureKey,
    JournalCorruptError,
    Kind,
    read_journal,
)
from stack_helpers import FakeDocker, build_stack, healthy_addon, healthy_core, ps_line
from test_doctor import probes

from lib import compat, doctor, erasure_journal, gen_override
from lib.status import CommandResult

REPO = Path(__file__).resolve().parents[2]
CONTAINER_DIR = "/var/lib/papaia-backup/erasure-journal"
KEY = ErasureKey(b"k" * 32)
NOW = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _addon(root: Path, name: str, compose: dict | None = None) -> Path:
    """An add-on with a replay action, a personal-area entry and a database."""
    path = root / "addons" / name
    _write(
        path / "papaia-app.yaml",
        {
            "name": name,
            "actions": {
                "erasure-replay": {"service": f"{name}-replay"},
                "person-erase": {"service": f"{name}-api", "args": ["person-erase"]},
            },
            "exposes": [
                {"id": f"{name}.me", "kind": "me",
                 "address": {"service": f"{name}-api", "port": 8000, "path": "/api/me"}},
            ],
        },
    )
    _write(
        path / "docker-compose.yml",
        compose or {
            "services": {
                f"{name}-api": {"image": "x"},
                f"{name}-replay": {"image": "x"},
                f"{name}-db": {"image": "x"},
            }
        },
    )
    return path


@pytest.fixture
def setup(tmp_path: Path) -> dict[str, Path]:
    """A config dir with the lifecycle profile, a backup target whose journal folder was
    set up, and two active add-ons `alpha` and `beta`."""
    backup = tmp_path / "backup"
    folder = backup / "erasure-journal"
    folder.mkdir(parents=True, mode=0o700)
    (folder / EPOCH_FILE).write_text('{"format": "papaia.erasure-epoch/1"}\n', "utf-8")
    os.chmod(folder / EPOCH_FILE, 0o640)
    config = tmp_path / "papaia-config"
    (config / "overrides" / "addons").mkdir(parents=True)
    (config / ".env").write_text(
        f"COMPOSE_PROFILES=keycloak,lifecycle\nPAPAIA_BACKUP_DIR={backup}\n", "utf-8"
    )
    alpha, beta = _addon(tmp_path, "alpha"), _addon(tmp_path, "beta")
    _write(
        config / "deployment.yaml",
        {"addons": [{"name": "alpha", "path": str(alpha), "active": True},
                    {"name": "beta", "path": str(beta), "active": True}]},
    )
    return {"config": config, "repo": tmp_path / "repo", "folder": folder,
            "alpha": alpha, "beta": beta, "tmp": tmp_path}


def _override(config: Path, name: str) -> Path:
    return config / "overrides" / "addons" / f"docker-compose.{name}-erasure-journal.override.yml"


def _binds(service: dict) -> list[dict]:
    return [v for v in service.get("volumes") or [] if isinstance(v, dict)]


# ── the mount: own file only ─────────────────────────────────────────────────


def test_each_module_gets_its_own_journal_file_and_nothing_else(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])

    override = yaml.safe_load(_override(setup["config"], "alpha").read_text("utf-8"))
    services = override["services"]
    # The writer services: the replay action, the erase action and the personal area.
    assert sorted(services) == ["alpha-api", "alpha-replay"]
    for body in services.values():
        assert body["tmpfs"] == [f"{CONTAINER_DIR}:size=1m,mode=1777"]
        assert _binds(body) == [{
            "type": "bind",
            "source": str(setup["folder"] / "alpha.jsonl"),
            "target": f"{CONTAINER_DIR}/alpha.jsonl",
            "read_only": False,
            "bind": {"create_host_path": False},
        }]
    text = _override(setup["config"], "alpha").read_text("utf-8")
    assert "beta" not in text and EPOCH_FILE not in text
    assert str(setup["folder"]) + "\n" not in text  # never the folder itself


def test_the_core_creates_the_file_private_and_compose_never_does(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])

    for name in ("alpha", "beta"):
        st = os.lstat(setup["folder"] / f"{name}.jsonl")
        assert stat.S_ISREG(st.st_mode)
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_size == 0
    # A second run keeps what the module wrote.
    (setup["folder"] / "alpha.jsonl").write_text("x\n", "utf-8")
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    assert (setup["folder"] / "alpha.jsonl").read_text("utf-8") == "x\n"


def test_no_override_without_the_lifecycle_profile_and_none_for_an_inactive_addon(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    deployed = yaml.safe_load((setup["config"] / "deployment.yaml").read_text("utf-8"))
    deployed["addons"][1]["active"] = False
    _write(setup["config"] / "deployment.yaml", deployed)
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    assert _override(setup["config"], "alpha").is_file()
    assert not _override(setup["config"], "beta").exists()

    (setup["config"] / ".env").write_text("COMPOSE_PROFILES=keycloak\n", "utf-8")
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    assert not _override(setup["config"], "alpha").exists()


def test_a_missing_folder_is_not_created_and_the_mount_stays_fail_closed(setup):
    for path in setup["folder"].iterdir():
        path.unlink()
    setup["folder"].rmdir()

    erasure_journal.generate_overrides(setup["config"], setup["repo"])

    assert not setup["folder"].exists()
    # The mount is still there: Compose refuses to start the service without its file.
    override = yaml.safe_load(_override(setup["config"], "alpha").read_text("utf-8"))
    assert _binds(override["services"]["alpha-api"])[0]["bind"] == {"create_host_path": False}


def test_a_planted_link_in_place_of_a_journal_stops_the_render(setup):
    outside = setup["tmp"] / "elsewhere.jsonl"
    outside.write_text("", "utf-8")
    (setup["folder"] / "beta.jsonl").symlink_to(outside)

    with pytest.raises(erasure_journal.ErasureJournalError, match="beta.jsonl"):
        erasure_journal.generate_overrides(setup["config"], setup["repo"])


def test_a_journal_another_account_could_write_stops_the_render(setup):
    (setup["folder"] / "alpha.jsonl").write_text("", "utf-8")
    os.chmod(setup["folder"] / "alpha.jsonl", 0o666)

    with pytest.raises(erasure_journal.ErasureJournalError, match="alpha.jsonl"):
        erasure_journal.generate_overrides(setup["config"], setup["repo"])


@pytest.mark.parametrize("name", ["identity", "core-chat", "model-gateway", "Bad_Name"])
def test_an_addon_cannot_take_a_core_journal_or_an_invalid_name(setup, name):
    path = _addon(setup["tmp"], name)
    deployed = yaml.safe_load((setup["config"] / "deployment.yaml").read_text("utf-8"))
    deployed["addons"].append({"name": name, "path": str(path), "active": True})
    _write(setup["config"] / "deployment.yaml", deployed)

    with pytest.raises(erasure_journal.ErasureJournalError, match=name):
        erasure_journal.generate_overrides(setup["config"], setup["repo"])
    assert not (setup["folder"] / f"{name}.jsonl").exists()


def test_the_join_overrides_bring_the_journal_override_along(setup):
    gen_override.generate_addon_join_overrides(setup["config"], setup["repo"])
    assert _override(setup["config"], "alpha").is_file()


# ── what a module can reach through its mounts ──────────────────────────────


def _container_view(override: dict, service: str, root: Path) -> Path:
    """The journal folder as the container sees it: an empty folder of its own (the
    tmpfs) and, inside it, each bound file as the very same inode as on the host."""
    view = root / "view" / service
    view.mkdir(parents=True)
    body = override["services"][service]
    assert body["tmpfs"] == [f"{CONTAINER_DIR}:size=1m,mode=1777"]
    for bind in _binds(body):
        assert Path(bind["target"]).parent == Path(CONTAINER_DIR)
        os.link(bind["source"], view / Path(bind["target"]).name)
    return view


def _writer(module: str, target: Path, local: Path) -> ErasureJournal:
    local.mkdir(parents=True, exist_ok=True)
    return ErasureJournal(module, key=KEY, target_dir=target, local_dir=local,
                          audit=lambda row: None, writer=module, clock=lambda: NOW)


def test_module_a_writes_its_own_journal_but_never_b_or_epoch(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    override = yaml.safe_load(_override(setup["config"], "alpha").read_text("utf-8"))
    view = _container_view(override, "alpha-api", setup["tmp"])
    epoch_before = (setup["folder"] / EPOCH_FILE).read_bytes()

    entry = _writer("alpha", view, setup["tmp"] / "local-a").record(
        Kind.ERASE, object_ref="note:1", sub="anna", reason="user_request")
    assert entry.seq == 1
    assert json.loads((setup["folder"] / "alpha.jsonl").read_text("utf-8"))["module"] == "alpha"

    # Alpha posing as beta writes into its own empty folder, never into beta's journal.
    _writer("beta", view, setup["tmp"] / "local-b").record(
        Kind.ERASE, object_ref="doc:9", sub="anna", reason="user_request")
    assert (setup["folder"] / "beta.jsonl").read_bytes() == b""
    assert not (view / EPOCH_FILE).exists()
    (view / EPOCH_FILE).write_text("{}", "utf-8")
    assert (setup["folder"] / EPOCH_FILE).read_bytes() == epoch_before


def test_only_papaia_lifecycle_mounts_the_journal_folder_among_core_services():
    mounting = []
    for path in compat.compose_files(REPO / "src" / "docker-compose.yml"):
        document = yaml.safe_load(path.read_text("utf-8")) or {}
        for name, body in (document.get("services") or {}).items():
            for volume in body.get("volumes") or []:
                source = volume.get("source", "") if isinstance(volume, dict) else volume
                if "PAPAIA_BACKUP_DIR" in str(source) and "erasure-journal" in str(source):
                    mounting.append(name)
    assert mounting == ["papaia-lifecycle"]


# ── the add-on's own compose file ───────────────────────────────────────────


def _compat_manifest(path: Path) -> dict:
    """The add-on's manifest without its personal-area entry, whose full declaration
    the exposes schema checks elsewhere."""
    manifest = yaml.safe_load((path / "papaia-app.yaml").read_text("utf-8"))
    manifest.pop("exposes")
    return manifest


@pytest.mark.parametrize(
    "volume",
    [
        "${PAPAIA_BACKUP_DIR}/erasure-journal:/var/lib/papaia-backup/erasure-journal",
        "${PAPAIA_BACKUP_DIR}:/backup:ro",
        "/srv/backup/erasure-journal/beta.jsonl:/j/beta.jsonl",
        {"type": "bind", "source": "${PAPAIA_BACKUP_DIR:-/srv/backup}/erasure-journal/epoch",
         "target": "/j/epoch"},
    ],
)
def test_an_addon_that_mounts_the_backup_target_is_refused_even_with_force(setup, volume):
    _write(setup["alpha"] / "docker-compose.yml",
           {"services": {"alpha-api": {"image": "x", "volumes": [volume]}}})
    manifest = _compat_manifest(setup["alpha"])

    result = compat.evaluate_addon("alpha", manifest, compat.CoreTarget(None, None, None),
                                   addon_path=setup["alpha"])

    assert result.status == compat.STATUS_ERROR
    assert result.axis == "erasure_journal"
    assert "write refused" in result.reason
    assert compat.gate([result], mode=compat.MODE_WARN, force=True) != 0


def test_an_addon_volume_bound_to_the_target_through_driver_options_is_refused(setup):
    _write(setup["alpha"] / "docker-compose.yml", {
        "services": {"alpha-api": {"image": "x", "volumes": ["j:/j"]}},
        "volumes": {"j": {"driver": "local", "driver_opts": {
            "type": "none", "o": "bind", "device": "${PAPAIA_BACKUP_DIR}/erasure-journal"}}},
    })
    manifest = _compat_manifest(setup["alpha"])
    result = compat.evaluate_addon("alpha", manifest, compat.CoreTarget(None, None, None),
                                   addon_path=setup["alpha"])
    assert result.status == compat.STATUS_ERROR


def test_an_addon_with_volumes_of_its_own_passes(setup):
    _write(setup["alpha"] / "docker-compose.yml", {
        "services": {"alpha-api": {"image": "x", "volumes": ["data:/data", "./conf:/conf:ro"]}},
        "volumes": {"data": {}},
    })
    manifest = _compat_manifest(setup["alpha"])
    result = compat.evaluate_addon("alpha", manifest, compat.CoreTarget(None, None, None),
                                   addon_path=setup["alpha"])
    assert result.status != compat.STATUS_ERROR


# ── a line planted at the host ──────────────────────────────────────────────


def _line(module: str, seq: int) -> str:
    return json.dumps({
        "id": f"8f0c1a2e-0b1d-4c3e-9f4a-{seq:012x}", "module": module, "seq": seq,
        "object_ref": "doc:9", "subject_ref": "a" * 64, "kind": "erase",
        "at": "2026-11-24T08:00:00.000Z", "reason": "user_request",
    }) + "\n"


def test_an_erase_line_of_a_planted_in_b_is_not_replayed_and_reported(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    with (setup["folder"] / "beta.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(_line("alpha", 1))

    with pytest.raises(JournalCorruptError):
        read_journal("beta", [setup["folder"]])
    # The same line is a valid entry of alpha: only its place makes it foreign.
    own = setup["tmp"] / "alpha-only"
    own.mkdir()
    (own / "alpha.jsonl").write_text(_line("alpha", 1), "utf-8")
    assert [e.seq for e in read_journal("alpha", [own])] == [1]

    findings = erasure_journal.inspect_folder(setup["folder"])
    assert [(f.subject, f.status) for f in findings if f.status != "pass"] == [
        ("beta.jsonl", "fail")
    ]
    assert "another module" in next(f.text for f in findings if f.subject == "beta.jsonl")


def test_the_folder_check_reports_links_and_files_others_can_write(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    os.link(setup["folder"] / "alpha.jsonl", setup["tmp"] / "second-name")
    os.chmod(setup["folder"] / "beta.jsonl", 0o620)
    os.chmod(setup["folder"] / EPOCH_FILE, 0o666)

    failed = {f.subject for f in erasure_journal.inspect_folder(setup["folder"])
              if f.status == "fail"}
    assert failed == {"alpha.jsonl", "beta.jsonl", EPOCH_FILE}


def test_the_folder_check_reports_a_folder_others_can_write(setup):
    erasure_journal.generate_overrides(setup["config"], setup["repo"])
    os.chmod(setup["folder"], 0o770)

    failed = [(f.subject, f.text) for f in erasure_journal.inspect_folder(setup["folder"])
              if f.status == "fail"]
    assert failed == [("erasure-journal", "can be written by other accounts")]


# ── doctor erasure_journal ──────────────────────────────────────────────────


class MountDocker(FakeDocker):
    """FakeDocker that also answers `docker inspect` for the mounts of containers."""

    def __init__(self, ps: list[str], mounts: dict[str, list[dict]]):
        super().__init__(ps)
        self.mounts = mounts

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        if cmd[:2] == ["docker", "inspect"] and any("{{json .Mounts}}" in c for c in cmd):
            self.calls.append(cmd)
            names = cmd[4:]  # docker inspect --format <format> <container>...
            return CommandResult(
                0, "".join(f"/{n}\t{json.dumps(self.mounts.get(n, []))}\n" for n in names), "")
        return super().__call__(cmd, timeout)


def _bind(source: Path | str, target: str, rw: bool = True) -> dict:
    return {"Type": "bind", "Source": str(source), "Destination": target, "RW": rw}


def _doctor_stack(tmp_path: Path) -> dict[str, Path]:
    stack = build_stack(tmp_path)
    folder = tmp_path / "backup" / "erasure-journal"
    folder.mkdir(parents=True)
    with (stack["config"] / ".env").open("a", encoding="utf-8") as fh:
        fh.write(f"PAPAIA_BACKUP_DIR={tmp_path / 'backup'}\n")
    env = (stack["config"] / ".env").read_text("utf-8")
    (stack["config"] / ".env").write_text(
        env.replace("COMPOSE_PROFILES=keycloak,", "COMPOSE_PROFILES=keycloak,lifecycle,"),
        "utf-8")
    (folder / "paperless.jsonl").write_text("", "utf-8")
    os.chmod(folder / "paperless.jsonl", 0o600)
    stack["folder"] = folder
    return stack


def _check(stack, mounts: dict[str, list[dict]]) -> doctor.CheckResult:
    ps = [*healthy_core(), *healthy_addon(),
          ps_line("papaia-lifecycle-1", "running", "Up 1 hour (healthy)", "papaia-lifecycle",
                  "papaia-lifecycle", "lifecycle")]
    ctx = doctor.Context(stack["config"], stack["repo"], run=MountDocker(ps, mounts),
                         probes=probes(), now=NOW)
    return doctor.check_erasure_journal(ctx)


def test_doctor_passes_with_the_own_file_mounted_and_the_core_folder(tmp_path):
    stack = _doctor_stack(tmp_path)
    folder = stack["folder"]
    result = _check(stack, {
        "paperless-paperless-1": [_bind(folder / "paperless.jsonl",
                                        f"{CONTAINER_DIR}/paperless.jsonl")],
        "papaia-lifecycle-1": [_bind(folder, CONTAINER_DIR)],
    })
    assert result.status == doctor.PASS, result.summary


def test_doctor_fails_on_a_shared_read_write_mount_of_the_folder(tmp_path):
    stack = _doctor_stack(tmp_path)
    result = _check(stack, {
        "paperless-paperless-1": [_bind(stack["folder"], CONTAINER_DIR)],
    })
    assert result.status == doctor.FAIL
    assert "shared read-write mount" in result.summary
    assert "paperless-paperless-1" in result.summary


@pytest.mark.parametrize("source", ["backup", "backup/erasure-journal/epoch",
                                    "backup/erasure-journal/identity.jsonl"])
def test_doctor_fails_when_a_module_can_write_the_target_or_a_core_file(tmp_path, source):
    stack = _doctor_stack(tmp_path)
    result = _check(stack, {"paperless-paperless-db-1": [_bind(tmp_path / source, "/x")]})
    assert result.status == doctor.FAIL


def test_doctor_fails_when_another_core_service_writes_the_folder(tmp_path):
    stack = _doctor_stack(tmp_path)
    result = _check(stack, {"papaia-keycloak-1": [_bind(stack["folder"], "/j")]})
    assert result.status == doctor.FAIL


def test_doctor_warns_when_a_module_reads_every_journal(tmp_path):
    stack = _doctor_stack(tmp_path)
    result = _check(stack, {
        "paperless-paperless-1": [_bind(stack["folder"], "/j", rw=False)],
    })
    assert result.status == doctor.WARN


def test_doctor_skips_without_the_lifecycle_profile(tmp_path):
    stack = build_stack(tmp_path)
    assert _check(stack, {}).status == doctor.SKIP


def test_doctor_fails_when_the_folder_is_missing(tmp_path):
    stack = _doctor_stack(tmp_path)
    for path in stack["folder"].iterdir():
        path.unlink()
    stack["folder"].rmdir()
    assert _check(stack, {}).status == doctor.FAIL


def test_doctor_lists_the_check():
    assert "erasure_journal" in doctor.CHECK_NAMES
