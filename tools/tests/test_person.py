"""`papaia-ctl person export|erase`: information and erasure for a person whose account is
gone (security 1.14, OPS-08, OPS-03). The core runs the reserved person actions of every
module (contract generation 15) as the operator and audits each call; the modules here
are simulated by a runner that answers as a module would."""

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
import uuid
import zipfile
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import age, compat, module_actions, person
from lib import realm_sync as rs

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


def _open_archive(path: Path, identity: str) -> zipfile.ZipFile:
    plain = io.BytesIO()
    with open(path, "rb") as fh:
        age.decrypt(fh, plain, [identity])
    return zipfile.ZipFile(io.BytesIO(plain.getvalue()))


# ─────────────────────────────────────────────────────────────────────────
# export
# ─────────────────────────────────────────────────────────────────────────


def test_export_of_a_deleted_account_contains_every_module_part(install):
    identity, recipient = age.generate_identity()
    modules = Modules(install)
    out = install["tmp"] / "anna.zip.age"

    report = person.export(
        install["config"], REPO, sub=ANNA, out=out, recipients=[recipient], runner=modules
    )

    # Only the sub is needed: no account is looked up, so a deleted one works the same.
    assert [(s.addon, s.action) for s in modules.steps] == [
        ("planner", person.EXPORT), ("tasks", person.EXPORT)
    ]
    assert all(s.env[person.ENV_SUB] == ANNA for s in modules.steps)
    assert all(s.env[person.ENV_OPERATION] == "export" for s in modules.steps)
    assert len({s.env[person.ENV_CORRELATION] for s in modules.steps}) == 1
    assert modules.steps[0].service == "tasks-admin"
    assert modules.steps[0].args == ("person-export",)
    assert report.ok

    archive = _open_archive(out, identity)
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


def test_export_archive_is_private_and_never_overwritten(install):
    _, recipient = age.generate_identity()
    out = install["tmp"] / "anna.zip.age"
    person.export(install["config"], REPO, sub=ANNA, out=out, recipients=[recipient],
                  runner=Modules(install))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert SECRET_TEXT.encode() not in out.read_bytes()
    before = out.read_bytes()
    with pytest.raises(person.PersonError, match="exists"):
        person.export(install["config"], REPO, sub=ANNA, out=out, recipients=[recipient],
                      runner=Modules(install))
    assert out.read_bytes() == before
    assert not [p for p in out.parent.iterdir() if p.name.startswith(".anna")]


def test_export_audits_every_module_call_without_content(install):
    _, recipient = age.generate_identity()
    out = install["tmp"] / "anna.zip.age"
    person.export(install["config"], REPO, sub=ANNA, out=out, recipients=[recipient],
                  runner=Modules(install))

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
    assert SECRET_TEXT not in text and recipient not in text


def test_a_failed_module_is_named_in_the_archive_and_the_audit(install):
    identity, recipient = age.generate_identity()
    modules = Modules(install)
    modules.fail.add(("planner", person.EXPORT))
    out = install["tmp"] / "anna.zip.age"

    report = person.export(install["config"], REPO, sub=ANNA, out=out,
                           recipients=[recipient], runner=modules)

    assert not report.ok
    index = json.loads(_open_archive(out, identity).read("index.json"))
    by_module = {m["module"]: m for m in index["modules"]}
    assert by_module["planner"]["status"] == "unavailable"
    assert by_module["planner"]["file"] is None
    assert by_module["tasks"]["status"] == "ok"
    failed = [r for r in _rows(install["config"]) if r["catalog_id"] == "planner.api"]
    assert [(r["result"], r["error_code"]) for r in failed] == [("error", "exit_3")]


@pytest.mark.parametrize("answer", [b"", b"[]", b"not json", b'{"a": 1, "a": 2}'])
def test_an_export_that_is_not_one_json_object_is_unavailable(install, answer):
    identity, recipient = age.generate_identity()
    modules = Modules(install)

    def runner(step):
        if step.addon == "planner":
            modules.steps.append(step)
            return person.Outcome(0, answer)
        return modules(step)

    out = install["tmp"] / "anna.zip.age"
    report = person.export(install["config"], REPO, sub=ANNA, out=out,
                           recipients=[recipient], runner=runner)
    assert not report.ok
    index = json.loads(_open_archive(out, identity).read("index.json"))
    assert {m["module"]: m["status"] for m in index["modules"]}["planner"] == "unavailable"


def test_an_export_above_the_limit_is_truncated(install, monkeypatch):
    identity, recipient = age.generate_identity()
    monkeypatch.setattr(person, "MAX_EXPORT_BYTES", 64)
    out = install["tmp"] / "anna.zip.age"
    report = person.export(install["config"], REPO, sub=ANNA, out=out,
                           recipients=[recipient], runner=Modules(install))
    assert not report.ok
    archive = _open_archive(out, identity)
    statuses = {m["module"]: m["status"] for m in json.loads(archive.read("index.json"))["modules"]}
    assert statuses == {"planner": "truncated", "tasks": "truncated"}
    assert "tasks.json" not in archive.namelist()


@pytest.mark.parametrize("recipients", [[], ["age1notakey"], ["AGE-SECRET-KEY-1XYZ"]])
def test_export_needs_a_valid_recipient(install, recipients):
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="recipient"):
        person.export(install["config"], REPO, sub=ANNA, out=install["tmp"] / "a.age",
                      recipients=recipients, runner=modules)
    assert modules.steps == []


# ─────────────────────────────────────────────────────────────────────────
# erase
# ─────────────────────────────────────────────────────────────────────────


def _journal_lines(install: dict, module: str) -> list[dict]:
    path = install["backup"] / "erasure-journal" / f"{module}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_erase_of_a_deleted_account_writes_journal_entries_in_every_module(install):
    modules = Modules(install)
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)

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


def test_erase_with_transfer_hands_over_first_then_erases(install):
    modules = Modules(install)
    report = person.erase(install["config"], REPO, sub=ANNA, transfer_to=BEN, runner=modules)

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


def test_a_failed_transfer_stops_before_anything_is_erased(install):
    modules = Modules(install)
    modules.fail.add(("tasks", person.TRANSFER))
    report = person.erase(install["config"], REPO, sub=ANNA, transfer_to=BEN, runner=modules)

    assert report.state == "partial"
    assert person.ERASE not in {s.action for s in modules.steps}
    assert not (install["backup"] / "erasure-journal" / "tasks.jsonl").exists()


def test_a_deletion_without_journal_entry_is_partial(install):
    modules = Modules(install)
    modules.journal = False
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert report.state == "partial"
    errors = {r["catalog_id"]: r["error_code"] for r in _rows(install["config"])}
    assert errors == {"tasks.api": "no_journal_entry", "planner.api": "no_journal_entry"}


def test_a_journal_entry_for_another_person_does_not_count(install):
    modules = Modules(install)
    modules.journal_subject = BEN
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert report.state == "partial"
    assert {r["error_code"] for r in _rows(install["config"])} == {"journal_mismatch"}


def test_an_entry_not_yet_at_the_backup_target_is_reported_pending(install):
    modules = Modules(install)
    modules.receipts["tasks"] = {
        "categories": [
            {"id": "tasks", "state": "done", "deleted": 1},
            {"id": "assignments", "state": "done", "deleted": 0},
            {"id": "time_records", "state": "done", "deleted": 0},
        ],
        "journal": [{"id": str(uuid.uuid4()), "seq": 9}],
    }
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)
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
def test_a_receipt_outside_the_contract_is_a_failed_module(install, receipt):
    modules = Modules(install)
    modules.receipts["tasks"] = receipt
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert report.state == "partial"
    errors = {r["catalog_id"]: r["error_code"] for r in _rows(install["config"])}
    assert errors["tasks.api"] == "invalid_receipt"
    assert errors["planner.api"] is None


def test_a_deletion_lock_is_reported(install):
    modules = Modules(install)
    modules.receipts["tasks"] = {
        "categories": [{"id": c, "state": "kept", "until": "2027-06-30", "reason": "legal_hold"}
                       for c in TASKS_CATEGORIES],
        "journal": [],
    }
    report = person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert report.state == "done"
    assert "legal_hold" in person.render(report)


def test_erase_needs_the_erasure_journal(install):
    (install["config"] / "security" / "erasure-hmac").unlink()
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="erasure"):
        person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert modules.steps == []


def test_erase_needs_the_journal_at_the_backup_target(install):
    shutil.rmtree(install["backup"] / "erasure-journal")
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="backup target"):
        person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert modules.steps == []


# ─────────────────────────────────────────────────────────────────────────
# input
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("sub", ["", "a" * 256, "anna\n", "../etc", " anna", "an na"])
def test_a_malformed_sub_is_refused_before_any_module_runs(install, sub):
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="sub"):
        person.erase(install["config"], REPO, sub=sub, runner=modules)
    assert modules.steps == []


def test_transfer_to_the_person_herself_is_refused(install):
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="transfer"):
        person.erase(install["config"], REPO, sub=ANNA, transfer_to=ANNA, runner=modules)
    assert modules.steps == []


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
# the run in steps (papaia-ctl person: bash runs each step, py_cli checks it)
# ─────────────────────────────────────────────────────────────────────────

def _cli(install: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "lib.cli", "--repo-root", str(REPO),
         "--config-dir", str(install["config"]), *args],
        cwd=REPO / "tools", capture_output=True, text=True, check=False,
    )


def _work(install: dict) -> Path:
    work = install["tmp"] / "run"
    work.mkdir(mode=0o700)
    return work


def test_a_run_in_steps_names_each_step_and_takes_in_its_answer(install):
    work = _work(install)
    modules = Modules(install)
    begun = _cli(install, "person-begin", f"--work={work}", "--operation=erase",
                 f"--sub={ANNA}", f"--transfer-to={BEN}")
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
    # One correlation id for the whole run, across the calls.
    assert len({row["correlation_id"] for row in _rows(install["config"])}) == 1


def test_a_run_folder_others_can_open_is_refused(install):
    work = install["tmp"] / "open"
    work.mkdir(mode=0o755)
    work.chmod(0o755)
    done = _cli(install, "person-begin", f"--work={work}", "--operation=export",
                f"--sub={ANNA}", f"--out={install['tmp'] / 'a.age'}",
                f"--recipient={age.generate_identity()[1]}")
    assert done.returncode == 2
    assert "0700" in done.stderr


def test_a_step_cannot_be_reported_twice_or_skipped(install):
    work = _work(install)
    assert _cli(install, "person-begin", f"--work={work}", "--operation=erase",
                f"--sub={ANNA}").returncode == 0
    with pytest.raises(person.PersonError, match="exit code"):
        person.advance(install["config"], REPO, work)
        person.advance(install["config"], REPO, work)
    with pytest.raises(person.PersonError, match="steps to take"):
        person.finish(install["config"], REPO, work)


def test_a_distributed_installation_is_refused(install):
    (install["config"] / "deployment.yaml").write_text(
        yaml.safe_dump({"topology": {"mode": "distributed"}, "addons": []}), encoding="utf-8"
    )
    modules = Modules(install)
    with pytest.raises(person.PersonError, match="single host"):
        person.erase(install["config"], REPO, sub=ANNA, runner=modules)
    assert modules.steps == []


def test_cli_refuses_a_malformed_sub_with_exit_2(install):
    done = _cli(install, "person-begin", f"--work={_work(install)}", "--operation=erase",
                "--sub=anna\tx")
    assert done.returncode == 2
    assert "sub" in done.stderr


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
                          env={**os.environ, "TMPDIR": str(install["tmp"])})


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
def test_papaia_ctl_person_export_runs_each_step_in_the_add_on_project(install):
    identity, recipient = age.generate_identity()
    out = install["tmp"] / "anna.zip.age"
    done = _bash(install, "export", f"--sub={ANNA}", f"--out={out}", f"--recipient={recipient}")
    assert done.returncode == 0, done.stderr
    log = (install["tmp"] / "compose.log").read_text().splitlines()
    assert len(log) == 2
    assert log[0].startswith(f"compose run planner {install['tmp'] / 'addons' / 'planner'} "
                             "--rm -T -e PAPAIA_CORRELATION_ID=")
    assert f"-e {person.ENV_SUB}={ANNA}" in log[0]
    assert log[0].endswith("tasks-admin person-export")
    with _open_archive(out, identity) as archive:
        assert json.loads(archive.read("tasks.json")) == {"contract": 2, "module": "tasks"}
    # The run folder is gone.
    assert not list(install["tmp"].glob("papaia-person.*"))


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
def test_papaia_ctl_person_export_names_a_failed_module_with_exit_1(install):
    identity, recipient = age.generate_identity()
    out = install["tmp"] / "anna.zip.age"
    done = _bash(install, "export", f"--sub={ANNA}", f"--out={out}", f"--recipient={recipient}",
                 fail="planner")
    assert done.returncode == 1, done.stderr
    assert "planner: unavailable" in done.stdout
    with _open_archive(out, identity) as archive:
        index = json.loads(archive.read("index.json"))
    assert {m["module"]: m["status"] for m in index["modules"]}["planner"] == "unavailable"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash missing")
def test_papaia_ctl_person_erase_needs_now(install):
    done = _bash(install, "erase", f"--sub={ANNA}")
    assert done.returncode == 2
    assert "--now" in done.stderr
    assert not (install["tmp"] / "compose.log").exists()
