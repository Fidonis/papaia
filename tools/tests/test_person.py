"""`papaia-ctl person export|erase|run`: information and erasure for a person whose account
is gone (security 1.14, OPS-08, OPS-03). A request is filed, confirmed by a second person
in the manager and then run: the core runs the reserved person actions of every module
(contract generation 15) as the operator and audits each call. The modules here are
simulated by a runner that answers as a module would; papaia-audit by its real request
routes over a store in a file (person_fake_docker.py)."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import age, compat, module_actions, person
from lib import person_request as pr
from lib import realm_sync as rs
from tests.person_fake_docker import FileRequestStore
from tests.test_audit_person_requests import CONFIRM, Caller
from tests.test_audit_read import DANA, EMIL
from tests.test_audit_read import signer as signer  # noqa: F401 - the shared fixture

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"
ANNA = "4c0a9e1d-2b7f-4f53-9d0e-6a1c2b3d4e5f"
BEN = "7d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6"
AUDIT_SCHEMA = json.loads(
    (REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text(encoding="utf-8")
)
SUBMISSION = Draft202012Validator(
    {**AUDIT_SCHEMA, "$ref": "#/$defs/submission", "required": [], "allOf": []}
)
TASKS_CATEGORIES = ("tasks", "assignments", "time_records")
SECRET_TEXT = "Arzttermin am Dienstag, bitte niemandem sagen"


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")


def _copy_tasks(tmp_path: Path, name: str) -> Path:
    """The tasks fixture installed under `name` (ids renamed so both copies are unique)."""
    path = tmp_path / "addons" / name
    shutil.copytree(FIXTURES / "person" / "addon-tasks", path)
    manifest_path = path / "papaia-app.yaml"
    text = manifest_path.read_text(encoding="utf-8")
    if name != "tasks":
        text = text.replace("tasks.api", f"{name}.api").replace("papaia-tasks", f"papaia-{name}")
        manifest = yaml.safe_load(text)
        manifest["name"] = name
        text = yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True)
    manifest_path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture()
def install(tmp_path: Path) -> dict:
    """An installation whose account of Anna is deleted: two modules that declare the
    person actions (tasks, planner), one with personal data and no action (notes), the
    chat, the identity service and the audit service as core profiles."""
    config = tmp_path / "config"
    backup = tmp_path / "backup"
    (backup / "erasure-journal").mkdir(parents=True)
    _write_env(config / ".env", {
        "COMPOSE_PROFILES": "librechat,keycloak,lifecycle,audit",
        "PAPAIA_BACKUP_DIR": str(backup),
    })
    key = os.urandom(32)
    key_file = config / "security" / "erasure-hmac"
    key_file.parent.mkdir(parents=True)
    key_file.write_text(key.hex() + "\n", encoding="ascii")
    key_file.chmod(0o600)
    entries = []
    for name in ("tasks", "planner"):
        path = _copy_tasks(tmp_path, name)
        entries.append({"name": name, "path": str(path), "active": True, "state": "running"})
    notes = tmp_path / "addons" / "notes"
    shutil.copytree(FIXTURES / "privacy" / "addon-notes", notes)
    entries.append({"name": "notes", "path": str(notes), "active": True, "state": "running"})
    (config / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries}), encoding="utf-8")
    return {"config": config, "backup": backup, "key": key, "tmp": tmp_path}


class Modules:
    """Answers the person actions as the modules do: the export of the person's data, the
    erasure with one journal entry per category written by the module's journal writer,
    the transfer of owned objects."""

    def __init__(self, install: dict) -> None:
        self.install = install
        self.steps: list[person.Step] = []
        self.fail: set[tuple[str, str]] = set()
        self.receipts: dict[str, dict] = {}
        self.journal_subject: str | None = None
        self.journal: bool = True

    def _journal(self, module: str, sub: str, category: str) -> dict:
        path = self.install["backup"] / "erasure-journal" / f"{module}.jsonl"
        seq = 1 + (len(path.read_text().splitlines()) if path.exists() else 0)
        line = {
            "id": str(uuid.uuid4()),
            "module": module,
            "seq": seq,
            "kind": "erase_subject",
            "object_ref": f"category:{category}",
            "subject_ref": hmac.new(
                self.install["key"], (self.journal_subject or sub).encode(), hashlib.sha256
            ).hexdigest(),
            "at": "2026-11-23T10:00:00.000Z",
            "reason": "person_erase",
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        return {"id": line["id"], "seq": seq}

    def __call__(self, step: person.Step) -> person.Outcome:
        self.steps.append(step)
        sub = step.env[person.ENV_SUB]
        if (step.addon, step.action) in self.fail:
            return person.Outcome(3, b"")
        if step.action == person.EXPORT:
            doc = {"contract": 2, "module": step.addon, "tasks": [{"text": SECRET_TEXT}]}
            return person.Outcome(0, json.dumps(doc).encode())
        if step.action == person.TRANSFER:
            return person.Outcome(0, json.dumps({"transferred": 2, "halted": 1}).encode())
        if step.addon in self.receipts:
            return person.Outcome(0, json.dumps(self.receipts[step.addon]).encode())
        journal = []
        if self.journal:
            journal = [self._journal(step.addon, sub, c) for c in ("tasks", "assignments")]
        receipt = {
            "categories": [
                {"id": "tasks", "state": "done", "deleted": 4},
                {"id": "assignments", "state": "done", "deleted": 1},
                {"id": "time_records", "state": "kept", "until": "2028-12-31",
                 "reason": "legal_obligation"},
            ],
            "journal": journal,
        }
        return person.Outcome(0, json.dumps(receipt).encode())


def _rows(config: Path) -> list[dict]:
    path = rs.audit_path(config)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _open_archive(path: Path, passphrase: str) -> zipfile.ZipFile:
    plain = io.BytesIO()
    with open(path, "rb") as fh:
        age.decrypt_with_passphrase(fh, plain, passphrase)
    return zipfile.ZipFile(io.BytesIO(plain.getvalue()))


# ─────────────────────────────────────────────────────────────────────────
# requests: filed by the host (Dana), confirmed by Emil in the manager
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def desk(install, signer) -> Caller:  # noqa: F811
    """papaia-audit with its request routes; the store is shared with the subprocess
    tests through a file."""
    caller = Caller(signer, FileRequestStore(install["tmp"] / "audit-requests.json"))
    caller.passphrases = {}
    install["now"] = caller.now
    return caller


def _gate(desk: Caller) -> pr.Gate:
    return lambda path, body: desk.host(path, body)


def _confirmed(install: dict, desk: Caller, operation: str, *, sub: str = ANNA,
               transfer_to: str | None = None) -> str:
    view = pr.create(_gate(desk), operation=operation, sub=sub, requested_by=DANA,
                     confirmed_by=EMIL, transfer_to=transfer_to)
    status, answer = desk.call("POST", f"/v1/person-requests/{view['id']}/confirm", EMIL,
                               roles=CONFIRM)
    assert status == 200, answer
    if operation == "export":
        desk.passphrases[view["id"]] = answer["passphrase"]
    return view["id"]


def _export(install: dict, desk: Caller, runner, **kw) -> tuple[person.Report, str]:
    request = _confirmed(install, desk, "export")
    report = person.run(install["config"], REPO, request=request, gate=_gate(desk),
                        runner=runner, **kw)
    return report, desk.passphrases[request]


def _erase(install: dict, desk: Caller, runner, *, sub: str = ANNA,
           transfer_to: str | None = None) -> person.Report:
    request = _confirmed(install, desk, "erase", sub=sub, transfer_to=transfer_to)
    return person.run(install["config"], REPO, request=request, gate=_gate(desk),
                      runner=runner)


# ─────────────────────────────────────────────────────────────────────────
# export
# ─────────────────────────────────────────────────────────────────────────


def test_export_of_a_deleted_account_contains_every_module_part(install, desk):
    modules = Modules(install)

    report, passphrase = _export(install, desk, modules)
    out = report.archive

    # Only the sub is needed: no account is looked up, so a deleted one works the same.
    assert [(s.addon, s.action) for s in modules.steps] == [
        ("planner", person.EXPORT), ("tasks", person.EXPORT)
    ]
    assert all(s.env[person.ENV_SUB] == ANNA for s in modules.steps)
    assert all(s.env[person.ENV_OPERATION] == "export" for s in modules.steps)
    # The request id ties the module calls to the request's events in papaia-audit.
    assert {s.env[person.ENV_CORRELATION] for s in modules.steps} == {
        out.name.removesuffix(pr.ARCHIVE_SUFFIX)
    }
    assert modules.steps[0].service == "tasks-admin"
    assert modules.steps[0].args == ("person-export",)
    assert report.ok

    archive = _open_archive(out, passphrase)
    names = set(archive.namelist())
    assert {"index.json", "LIESMICH.txt", "tasks.json", "planner.json"} <= names
    assert {"tasks.schema.json", "planner.schema.json"} <= names
    index = json.loads(archive.read("index.json"))
    by_module = {m["module"]: m for m in index["modules"]}
    assert by_module["tasks"]["status"] == "ok"
    assert by_module["planner"]["status"] == "ok"
    assert by_module["tasks"]["file"] == "tasks.json"
    assert by_module["tasks"]["bytes"] == len(archive.read("tasks.json"))
    assert json.loads(archive.read("tasks.json"))["tasks"][0]["text"] == SECRET_TEXT
    assert json.loads(archive.read("tasks.schema.json"))["title"] == "tasks-export/1"
    # Every row of the records of processing is named: included, or not with a reason.
    missing = {(m["module"], m["entry"]): m["reason"] for m in index["not_connected"]}
    assert ("notes", "notes.store") in missing
    assert "person-export" in missing[("notes", "notes.store")]
    assert {("core:chat", "librechat"), ("core:identity", "keycloak"),
            ("core:audit", "papaia-audit"), ("core:lifecycle", "papaia-lifecycle")} <= set(
        missing
    )
    assert all(reason for reason in missing.values())
    rows = {(r.module, r.entry): r for r in report.rows}
    assert rows[("tasks", "tasks.api")].included
    assert not rows[("notes", "notes.store")].included
    assert all(r.reason for r in report.rows if not r.included)


def test_export_archive_is_private_and_never_overwritten(install, desk):
    report, _ = _export(install, desk, Modules(install))
    out = report.archive
    assert out.parent == install["config"] / "state" / "person-export"
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert SECRET_TEXT.encode() not in out.read_bytes()
    before = out.read_bytes()
    request = out.name.removesuffix(pr.ARCHIVE_SUFFIX)
    # A request runs once.
    with pytest.raises(person.PersonError, match="done"):
        person.run(install["config"], REPO, request=request, gate=_gate(desk),
                   runner=Modules(install))
    assert out.read_bytes() == before
    assert not [p for p in out.parent.iterdir() if p.name.startswith(".")]


def test_the_archive_opens_only_with_the_passphrase_of_the_confirmation(install, desk):
    report, passphrase = _export(install, desk, Modules(install))
    with pytest.raises(age.NoIdentityError):
        _open_archive(report.archive, "not-the-passphrase")
    assert "tasks.json" in _open_archive(report.archive, passphrase).namelist()
    # The passphrase reached neither the host nor the audit outbox.
    assert passphrase not in rs.audit_path(install["config"]).read_text(encoding="utf-8")
    assert passphrase not in (install["tmp"] / "audit-requests.json").read_text()


def test_nothing_runs_without_the_confirmation_of_a_second_person(install, desk):
    view = pr.create(_gate(desk), operation="export", sub=ANNA, requested_by=DANA,
                     confirmed_by=EMIL)
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="open"):
        person.run(install["config"], REPO, request=view["id"], gate=_gate(desk),
                   runner=modules)
    # The requesting person cannot confirm it herself.
    status, problem = desk.call("POST", f"/v1/person-requests/{view['id']}/confirm", DANA,
                                roles=CONFIRM)
    assert status == 403 and problem["code"] == "AUDIT-PERSON-REQ-SELF"
    with pytest.raises(person.PersonError, match="open"):
        person.run(install["config"], REPO, request=view["id"], gate=_gate(desk),
                   runner=modules)
    assert modules.steps == []
    with pytest.raises(pr.RequestError, match="second person"):
        pr.create(_gate(desk), operation="erase", sub=ANNA, requested_by=DANA,
                  confirmed_by=DANA)


def test_the_request_records_the_run_as_done_or_partial(install, desk):
    modules = Modules(install)
    modules.fail.add(("planner", person.EXPORT))
    report, _ = _export(install, desk, modules)
    request = report.archive.name.removesuffix(pr.ARCHIVE_SUFFIX)
    assert pr.get(_gate(desk), request)["state"] == "partial"
    erased = _erase(install, desk, Modules(install))
    assert erased.state == "done"
    states = sorted(r.state for r in desk.store.requests.values())
    assert states == ["done", "partial"]


def test_export_audits_every_module_call_without_content(install, desk):
    _, passphrase = _export(install, desk, Modules(install))

    rows = _rows(install["config"])
    assert [r["operation"] for r in rows] == [
        "person.export", "person.export", "person.export_archive"
    ]
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == []
        assert row["object_ref"] == {"type": "person", "id": ANNA}
        assert row["sub"].startswith("host:")
        assert row["result"] == "allowed"
    assert len({r["correlation_id"] for r in rows}) == 1
    assert [r["effect"] for r in rows] == ["read", "read", "write"]
    assert {r["catalog_id"] for r in rows[:2]} == {"tasks.api", "planner.api"}
    text = rs.audit_path(install["config"]).read_text(encoding="utf-8")
    assert SECRET_TEXT not in text and passphrase not in text


def test_a_failed_module_is_named_in_the_archive_and_the_audit(install, desk):
    modules = Modules(install)
    modules.fail.add(("planner", person.EXPORT))

    report, passphrase = _export(install, desk, modules)

    assert not report.ok
    index = json.loads(_open_archive(report.archive, passphrase).read("index.json"))
    by_module = {m["module"]: m for m in index["modules"]}
    assert by_module["planner"]["status"] == "unavailable"
    assert by_module["planner"]["file"] is None
    assert by_module["tasks"]["status"] == "ok"
    failed = [r for r in _rows(install["config"]) if r["catalog_id"] == "planner.api"]
    assert [(r["result"], r["error_code"]) for r in failed] == [("error", "exit_3")]


@pytest.mark.parametrize("answer", [b"", b"[]", b"not json", b'{"a": 1, "a": 2}'])
def test_an_export_that_is_not_one_json_object_is_unavailable(install, desk, answer):
    modules = Modules(install)

    def runner(step):
        if step.addon == "planner":
            modules.steps.append(step)
            return person.Outcome(0, answer)
        return modules(step)

    report, passphrase = _export(install, desk, runner)
    assert not report.ok
    index = json.loads(_open_archive(report.archive, passphrase).read("index.json"))
    assert {m["module"]: m["status"] for m in index["modules"]}["planner"] == "unavailable"


def test_an_export_above_the_limit_is_truncated(install, desk, monkeypatch):
    monkeypatch.setattr(person, "MAX_EXPORT_BYTES", 64)
    report, passphrase = _export(install, desk, Modules(install))
    assert not report.ok
    archive = _open_archive(report.archive, passphrase)
    statuses = {m["module"]: m["status"] for m in json.loads(archive.read("index.json"))["modules"]}
    assert statuses == {"planner": "truncated", "tasks": "truncated"}
    assert "tasks.json" not in archive.namelist()


def test_a_request_not_run_within_a_day_of_its_confirmation_expires(install, desk):
    request = _confirmed(install, desk, "export")
    desk.now += 25 * 3600
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="expired"):
        person.run(install["config"], REPO, request=request, gate=_gate(desk),
                   runner=modules)
    assert modules.steps == []


# ─────────────────────────────────────────────────────────────────────────
# the archive folder: hand-over and 14 days
# ─────────────────────────────────────────────────────────────────────────


def test_the_archive_is_gone_after_14_days(install, desk):
    from datetime import datetime, timedelta, timezone

    written = datetime(2026, 11, 23, 9, 0, tzinfo=timezone.utc)
    report, _ = _export(install, desk, Modules(install), now=written)
    request = report.archive.name.removesuffix(pr.ARCHIVE_SUFFIX)
    assert pr.sweep(install["config"], now=written + timedelta(days=13, hours=23)) == []
    assert report.archive.exists()
    assert pr.sweep(install["config"], now=written + timedelta(days=14)) == [request]
    assert not report.archive.exists()
    assert list(report.archive.parent.iterdir()) == []
    gone = [r for r in _rows(install["config"]) if r["operation"] == "person.export_expired"]
    assert len(gone) == 1 and gone[0]["effect"] == "delete"
    assert gone[0]["object_ref"] == {"type": "person_request", "id": request}


def test_a_handed_over_archive_is_deleted_at_once(install, desk):
    report, _ = _export(install, desk, Modules(install))
    request = report.archive.name.removesuffix(pr.ARCHIVE_SUFFIX)
    assert pr.handover(install["config"], request) is True
    assert not report.archive.exists()
    assert pr.handover(install["config"], request) is False
    assert [r["operation"] for r in _rows(install["config"])][-1] == "person.export_handed_over"


# ─────────────────────────────────────────────────────────────────────────
# erase
# ─────────────────────────────────────────────────────────────────────────


def _journal_lines(install: dict, module: str) -> list[dict]:
    path = install["backup"] / "erasure-journal" / f"{module}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_erase_of_a_deleted_account_writes_journal_entries_in_every_module(install, desk):
    modules = Modules(install)
    report = _erase(install, desk, modules)

    assert [(s.addon, s.action) for s in modules.steps] == [
        ("planner", person.ERASE), ("tasks", person.ERASE)
    ]
    assert report.state == "done"
    ref = hmac.new(install["key"], ANNA.encode(), hashlib.sha256).hexdigest()
    for module in ("planner", "tasks"):
        lines = _journal_lines(install, module)
        assert len(lines) == 2 and all(line["subject_ref"] == ref for line in lines)
        assert ANNA not in json.dumps(lines)
    # Proof per module and category: counts and the journal entries, kept data with its date.
    proof = {(p["module"], p["category"]): p for p in report.proof}
    assert proof[("tasks", "tasks")]["deleted"] == 4
    assert proof[("tasks", "tasks")]["journal"] == "at_target"
    assert proof[("tasks", "time_records")]["state"] == "kept"
    assert proof[("tasks", "time_records")]["until"] == "2028-12-31"
    assert proof[("tasks", "time_records")]["reason"] == "legal_obligation"
    assert {p["module"] for p in report.proof} == {"tasks", "planner"}
    not_erased = {(r.module, r.entry) for r in report.rows if not r.included}
    assert ("notes", "notes.store") in not_erased
    assert ("core:audit", "papaia-audit") in not_erased

    rows = _rows(install["config"])
    assert [r["operation"] for r in rows] == ["person.erase", "person.erase"]
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == []
        assert row["effect"] == "delete" and row["result"] == "allowed"
        assert row["detail"]["count"] == 5
        assert row["detail"]["kind"] == "erase_subject"
    text = person.render(report)
    assert "tasks" in text and "time_records" in text and "2028-12-31" in text


def test_erase_with_transfer_hands_over_first_then_erases(install, desk):
    modules = Modules(install)
    report = _erase(install, desk, modules, transfer_to=BEN)

    assert [(s.addon, s.action) for s in modules.steps] == [
        ("planner", person.TRANSFER), ("tasks", person.TRANSFER),
        ("planner", person.ERASE), ("tasks", person.ERASE),
    ]
    transfer = [s for s in modules.steps if s.action == person.TRANSFER]
    assert all(s.env[person.ENV_NEW_OWNER] == BEN for s in transfer)
    assert all(person.ENV_NEW_OWNER not in s.env for s in modules.steps
               if s.action == person.ERASE)
    assert report.state == "done"
    assert {t["module"]: t["transferred"] for t in report.transfers} == {
        "planner": 2, "tasks": 2
    }
    rows = _rows(install["config"])
    assert [r["operation"] for r in rows][:2] == ["person.transfer_ownership"] * 2
    assert all(r["event"] == "ownership_transferred" for r in rows[:2])
    assert all(list(SUBMISSION.iter_errors(r)) == [] for r in rows)


def test_a_failed_transfer_stops_before_anything_is_erased(install, desk):
    modules = Modules(install)
    modules.fail.add(("tasks", person.TRANSFER))
    report = _erase(install, desk, modules, transfer_to=BEN)

    assert report.state == "partial"
    assert person.ERASE not in {s.action for s in modules.steps}
    assert not (install["backup"] / "erasure-journal" / "tasks.jsonl").exists()


def test_a_deletion_without_journal_entry_is_partial(install, desk):
    modules = Modules(install)
    modules.journal = False
    report = _erase(install, desk, modules)
    assert report.state == "partial"
    errors = {r["catalog_id"]: r["error_code"] for r in _rows(install["config"])}
    assert errors == {"tasks.api": "no_journal_entry", "planner.api": "no_journal_entry"}


def test_a_journal_entry_for_another_person_does_not_count(install, desk):
    modules = Modules(install)
    modules.journal_subject = BEN
    report = _erase(install, desk, modules)
    assert report.state == "partial"
    assert {r["error_code"] for r in _rows(install["config"])} == {"journal_mismatch"}


def test_an_entry_not_yet_at_the_backup_target_is_reported_pending(install, desk):
    modules = Modules(install)
    modules.receipts["tasks"] = {
        "categories": [
            {"id": "tasks", "state": "done", "deleted": 1},
            {"id": "assignments", "state": "done", "deleted": 0},
            {"id": "time_records", "state": "done", "deleted": 0},
        ],
        "journal": [{"id": str(uuid.uuid4()), "seq": 9}],
    }
    report = _erase(install, desk, modules)
    assert report.state == "done"
    proof = {(p["module"], p["category"]): p for p in report.proof}
    assert proof[("tasks", "tasks")]["journal"] == "pending"
    assert "pending" in person.render(report)


@pytest.mark.parametrize("receipt", [
    {"categories": [{"id": "tasks", "state": "done", "deleted": 0}], "journal": []},
    {"categories": [{"id": c, "state": "done", "deleted": 0} for c in TASKS_CATEGORIES]
     + [{"id": "unknown", "state": "done", "deleted": 0}], "journal": []},
    {"categories": [{"id": c, "state": "done", "deleted": 0} for c in TASKS_CATEGORIES],
     "journal": [], "extra": 1},
    {"categories": [{"id": c, "state": "done", "deleted": -1} for c in TASKS_CATEGORIES],
     "journal": []},
    {"categories": [{"id": c, "state": "kept", "until": "soon", "reason": "legal_obligation"}
                    for c in TASKS_CATEGORIES], "journal": []},
    {"categories": [{"id": c, "state": "kept", "until": "2027-01-01", "reason": "whim"}
                    for c in TASKS_CATEGORIES], "journal": []},
    {"categories": [{"id": c, "state": "done", "deleted": 0} for c in TASKS_CATEGORIES],
     "journal": [{"id": "not-a-uuid", "seq": 1}]},
])
def test_a_receipt_outside_the_contract_is_a_failed_module(install, desk, receipt):
    modules = Modules(install)
    modules.receipts["tasks"] = receipt
    report = _erase(install, desk, modules)
    assert report.state == "partial"
    errors = {r["catalog_id"]: r["error_code"] for r in _rows(install["config"])}
    assert errors["tasks.api"] == "invalid_receipt"
    assert errors["planner.api"] is None


def test_a_deletion_lock_is_reported(install, desk):
    modules = Modules(install)
    modules.receipts["tasks"] = {
        "categories": [{"id": c, "state": "kept", "until": "2027-06-30", "reason": "legal_hold"}
                       for c in TASKS_CATEGORIES],
        "journal": [],
    }
    report = _erase(install, desk, modules)
    assert report.state == "done"
    assert "legal_hold" in person.render(report)


def test_erase_needs_the_erasure_journal(install, desk):
    (install["config"] / "security" / "erasure-hmac").unlink()
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="erasure"):
        _erase(install, desk, modules)
    assert modules.steps == []


def test_erase_needs_the_journal_at_the_backup_target(install, desk):
    shutil.rmtree(install["backup"] / "erasure-journal")
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="backup target"):
        _erase(install, desk, modules)
    assert modules.steps == []


# ─────────────────────────────────────────────────────────────────────────
# input
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("sub", ["", "a" * 256, "anna\n", "../etc", " anna", "an na"])
def test_a_malformed_sub_is_refused_before_a_request_exists(install, desk, sub):
    with pytest.raises(pr.RequestError, match="400"):
        pr.create(_gate(desk), operation="erase", sub=sub, requested_by=DANA,
                  confirmed_by=EMIL)
    assert desk.store.requests == {}
    with pytest.raises(person.PersonError, match="sub"):
        person.check_sub(sub)


def test_transfer_to_the_person_herself_is_refused(install, desk):
    with pytest.raises(pr.RequestError, match="400"):
        pr.create(_gate(desk), operation="erase", sub=ANNA, requested_by=DANA,
                  confirmed_by=EMIL, transfer_to=ANNA)
    assert desk.store.requests == {}


# ─────────────────────────────────────────────────────────────────────────
# contract generation 15 and the docker runner
# ─────────────────────────────────────────────────────────────────────────


def test_the_person_actions_are_generation_15():
    manifest = yaml.safe_load(
        (FIXTURES / "person" / "addon-tasks" / "papaia-app.yaml").read_text(encoding="utf-8")
    )
    used = dict(compat.manifest_generation_features(manifest))
    assert used["actions.person-export"] == 15
    assert used["actions.person-erase"] == 15
    assert used["actions.transfer-ownership"] == 15
    assert compat.ADDON_API_GENERATIONS[15].startswith("reserved `actions` `person-export`")


def test_the_person_actions_are_no_maintenance_actions_and_no_restore_steps():
    for name in person.ACTIONS:
        assert module_actions.is_reserved(name)
    manifest = yaml.safe_load(
        (FIXTURES / "person" / "addon-tasks" / "papaia-app.yaml").read_text(encoding="utf-8")
    )
    assert module_actions.reserved_actions(manifest) == []


# ─────────────────────────────────────────────────────────────────────────
# the run in steps (papaia-ctl person: bash runs each step, py_cli checks it); `docker`
# is person_fake_docker.py, which answers as papaia-audit and papaia-lifecycle
# ─────────────────────────────────────────────────────────────────────────


def _fake_docker(install: dict, now: float) -> dict[str, str]:
    folder = install["tmp"] / "bin"
    folder.mkdir(exist_ok=True)
    docker = folder / "docker"
    docker.write_text(
        f"#!/bin/sh\nexec '{sys.executable}' '{Path(__file__).parent / 'person_fake_docker.py'}'"
        ' "$@"\n', encoding="utf-8",
    )
    docker.chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{folder}{os.pathsep}{os.environ.get('PATH', '')}",
        "PERSON_FAKE_AUDIT_STORE": str(install["tmp"] / "audit-requests.json"),
        "PERSON_FAKE_LIFECYCLE_KEYS": str(install["tmp"] / "lifecycle-keys"),
        "PERSON_FAKE_NOW": str(now),
        "TMPDIR": str(install["tmp"]),
    }


def _cli(install: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "lib.cli", "--repo-root", str(REPO),
         "--config-dir", str(install["config"]), *args],
        cwd=REPO / "tools", capture_output=True, text=True, check=False,
        env=_fake_docker(install, install.get("now", time.time())),
    )


def _work(install: dict) -> Path:
    work = install["tmp"] / "run"
    work.mkdir(mode=0o700)
    return work


def test_a_run_in_steps_names_each_step_and_takes_in_its_answer(install, desk):
    work = _work(install)
    modules = Modules(install)
    request = _confirmed(install, desk, "erase", transfer_to=BEN)
    begun = _cli(install, "person-begin", f"--work={work}", f"--request={request}")
    assert begun.returncode == 0, begun.stderr
    seen, code = [], []
    while True:
        done = _cli(install, "person-next", f"--work={work}", *code)
        assert done.returncode == 0, done.stderr
        if not done.stdout:
            break
        fields = done.stdout.rstrip("\n").split("\t")
        addon, rest = fields[0], fields[1:]
        env = dict(rest[i + 1].split("=", 1) for i in range(0, len(rest) - 2, 2))
        assert rest[-2] == "tasks-admin"
        action = rest[-1]
        seen.append((addon, action))
        outcome = modules(person.Step(addon, Path(), action, rest[-2], (action,), env))
        (work / person.STEP_OUT).write_bytes(outcome.stdout)
        code = [f"--exit-code={outcome.exit_code}"]
    assert seen == [("planner", person.TRANSFER), ("tasks", person.TRANSFER),
                    ("planner", person.ERASE), ("tasks", person.ERASE)]
    assert modules.steps[0].env[person.ENV_NEW_OWNER] == BEN
    assert modules.steps[-1].env[person.ENV_OPERATION] == "erase"
    finished = _cli(install, "person-finish", f"--work={work}")
    assert finished.returncode == 0, finished.stderr
    assert "erased        tasks/tasks: 4" in finished.stdout
    # One correlation id for the whole run, across the calls: the request id.
    assert {row["correlation_id"] for row in _rows(install["config"])} == {request}
    assert FileRequestStore(install["tmp"] / "audit-requests.json").requests[
        request].state == "done"


def test_a_run_folder_others_can_open_is_refused(install, desk):
    work = install["tmp"] / "open"
    work.mkdir(mode=0o755)
    work.chmod(0o755)
    request = _confirmed(install, desk, "export")
    done = _cli(install, "person-begin", f"--work={work}", f"--request={request}")
    assert done.returncode == 2
    assert "0700" in done.stderr
    assert desk.store.get_person_request(request).state == "confirmed"


def test_a_step_cannot_be_reported_twice_or_skipped(install, desk):
    work = _work(install)
    request = _confirmed(install, desk, "erase")
    assert _cli(install, "person-begin", f"--work={work}",
                f"--request={request}").returncode == 0
    with pytest.raises(person.PersonError, match="exit code"):
        person.advance(install["config"], REPO, work)
        person.advance(install["config"], REPO, work)
    with pytest.raises(person.PersonError, match="steps to take"):
        person.finish(install["config"], REPO, work, gate=_gate(desk))


def test_a_distributed_installation_is_refused(install, desk):
    (install["config"] / "deployment.yaml").write_text(
        yaml.safe_dump({"topology": {"mode": "distributed"}, "addons": []}), encoding="utf-8"
    )
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="single host"):
        _erase(install, desk, modules)
    assert modules.steps == []


def test_cli_refuses_a_malformed_request_id_with_exit_2(install):
    done = _cli(install, "person-begin", f"--work={_work(install)}", "--request=anna")
    assert done.returncode == 2
    assert "request id" in done.stderr


# The bash loop of `papaia-ctl person` with the real py_cli; `_addon_compose` stands in
# for `docker compose run` and answers as the module's export step.
_BASH = r"""
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
info() { echo "INFO: $*"; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo usage; }
_require_setup_done() { :; }
py_cli() {
    PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$REPO_ROOT" \
        --config-dir "$CONFIG_DIR" "$@"
}
_addon_path() { echo "@ADDONS@/$1"; }
_addon_compose() {
    echo "compose $*" >> "@LOG@"
    [ "$2" != "@FAIL@" ] || return 3
    printf '{"contract": 2, "module": "%s"}' "$2"
}
source "@LIFECYCLE@"
cmd_person "$@"
"""


def _bash(install: dict, *args: str, fail: str = "-") -> subprocess.CompletedProcess[str]:
    script = install["tmp"] / "harness.sh"
    log = install["tmp"] / "compose.log"
    text = _BASH
    for key, value in {
        "@CONFIG@": str(install["config"]), "@ROOT@": str(REPO), "@TOOLS@": str(REPO / "tools"),
        "@PYTHON@": sys.executable, "@ADDONS@": str(install["tmp"] / "addons"),
        "@LOG@": str(log), "@FAIL@": fail,
        "@LIFECYCLE@": str(REPO / "tools" / "lib" / "sh" / "lifecycle.sh"),
    }.items():
        text = text.replace(key, value)
    script.write_text(text, encoding="utf-8")
    return subprocess.run([shutil.which("bash") or "bash", str(script), *args],
                          capture_output=True, text=True, check=False,
                          env=_fake_docker(install, install.get("now", time.time())))


def _request_id(stdout: str) -> str:
    first = stdout.splitlines()[0]
    assert first.startswith("request ")
    return first.split()[1].rstrip(":")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
def test_papaia_ctl_person_export_files_a_request_and_runs_it_after_the_confirmation(
    install, desk
):
    filed = _bash(install, "export", f"--sub={ANNA}", f"--requested-by={DANA}",
                  f"--confirmed-by={EMIL}")
    assert filed.returncode == 0, filed.stderr
    request = _request_id(filed.stdout)
    assert "Nothing ran" in filed.stdout
    assert not (install["tmp"] / "compose.log").exists()
    early = _bash(install, "run", request)
    assert early.returncode == 2 and "open" in early.stderr
    assert not (install["tmp"] / "compose.log").exists()

    desk.store = FileRequestStore(install["tmp"] / "audit-requests.json")
    desk.api.store = desk.store
    status, answer = desk.call("POST", f"/v1/person-requests/{request}/confirm", EMIL,
                               roles=CONFIRM)
    assert status == 200, answer

    done = _bash(install, "run", request)
    assert done.returncode == 0, done.stderr
    log = (install["tmp"] / "compose.log").read_text().splitlines()
    assert len(log) == 2
    assert log[0].startswith(f"compose run planner {install['tmp'] / 'addons' / 'planner'} "
                             f"--rm -T -e PAPAIA_CORRELATION_ID={request}")
    assert f"-e {person.ENV_SUB}={ANNA}" in log[0]
    assert log[0].endswith("tasks-admin person-export")
    out = install["config"] / "state" / "person-export" / f"{request}{pr.ARCHIVE_SUFFIX}"
    assert f"Archive written to {out}" in done.stdout
    with _open_archive(out, answer["passphrase"]) as archive:
        assert json.loads(archive.read("tasks.json")) == {"contract": 2, "module": "tasks"}
    # The run folder is gone; the passphrase never reached the host's output.
    assert not list(install["tmp"].glob("papaia-person.*"))
    assert answer["passphrase"] not in done.stdout + done.stderr
    status_out = _bash(install, "status", request)
    assert "erledigt" in status_out.stdout and str(out) in status_out.stdout
    handed = _bash(install, "handover", request)
    assert handed.returncode == 0 and not out.exists()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
def test_papaia_ctl_person_run_names_a_failed_module_with_exit_1(install, desk):
    request = _confirmed(install, desk, "export")
    done = _bash(install, "run", request, fail="planner")
    assert done.returncode == 1, done.stderr
    assert "planner: unavailable" in done.stdout
    out = install["config"] / "state" / "person-export" / f"{request}{pr.ARCHIVE_SUFFIX}"
    with _open_archive(out, desk.passphrases[request]) as archive:
        index = json.loads(archive.read("index.json"))
    assert {m["module"]: m["status"] for m in index["modules"]}["planner"] == "unavailable"
    assert FileRequestStore(install["tmp"] / "audit-requests.json").requests[
        request].state == "partial"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
@pytest.mark.parametrize("args,message", [
    (("erase", f"--sub={ANNA}", f"--requested-by={DANA}", f"--confirmed-by={EMIL}"), "--now"),
    (("erase", f"--sub={ANNA}", "--now"), "--confirmed-by"),
    (("export", f"--sub={ANNA}", f"--requested-by={DANA}"), "--confirmed-by"),
    (("export", f"--sub={ANNA}", "--out=/tmp/a.age"), "Unknown option"),
    (("run",), "request id"),
])
def test_papaia_ctl_person_refuses_incomplete_requests(install, args, message):
    done = _bash(install, *args)
    assert done.returncode == 2
    assert message in done.stderr
    assert not (install["tmp"] / "compose.log").exists()
    assert not (install["tmp"] / "audit-requests.json").exists()


# ─────────────────────────────────────────────────────────────────────────
# person find (papaia-lifecycle's name index and tombstones)
# ─────────────────────────────────────────────────────────────────────────


def _lifecycle_state(install: dict, names: dict, tombstones: dict) -> None:
    from tests.test_lifecycle import lc

    keys = install["tmp"] / "lifecycle-keys"
    keys.mkdir(mode=0o700, exist_ok=True)
    state = lc._new_state()
    state["names"], state["tombstones"] = names, tombstones
    lc.Store(keys).save(state)


def test_person_find_hashes_the_input_and_finds_a_deleted_account_by_mail(install):
    from tests.test_lifecycle import lc

    mail = "anna.berger@example.org"
    ref = lc.name_ref(install["key"], mail)
    _lifecycle_state(install, {}, {ANNA: {"name": None, "mail": ref, "deleted": 1_795_000_000}})
    done = _bash(install, "find", "--email=Anna.Berger@Example.org ")
    assert done.returncode == 0, done.stderr
    assert ANNA in done.stdout and "deleted" in done.stdout
    rows = _rows(install["config"])
    assert [(r["operation"], r["detail"]) for r in rows] == [("person.find", {"count": 1})]
    assert "berger" not in json.dumps(rows).casefold()
    raw = (install["tmp"] / "lifecycle-keys" / lc.STATE_FILE).read_text().casefold()
    assert "berger" not in raw


def test_person_find_reports_nobody_and_needs_one_input(install):
    _lifecycle_state(install, {}, {})
    done = _bash(install, "find", "--name=nobody")
    assert done.returncode == 0 and "no person found" in done.stdout
    both = _cli(install, "person-find", "--name=a", "--email=a@b")
    assert both.returncode == 2 and "exactly one" in both.stderr
