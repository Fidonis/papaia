"""`papaia-ctl report permissions` (tools/lib/access_report.py, security 1.16): the report
by person and by system from a seeded realm, its determinism and checksum, the
recertification state per row, the published schema, CSV output, and the release through
papaia-audit, which checks the role `papaia-auditor` and records every retrieval.

The realm is an in-memory double of the Admin REST API; papaia-audit is a function.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lib import access_report as ar
from lib import realm_sync as rs

REPO = Path(__file__).resolve().parents[2]
CTL = REPO / "tools" / "papaia-ctl"
BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not installed")
NOW = datetime(2026, 11, 22, 9, 0, tzinfo=timezone.utc)
BEN = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
DORA = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
CARLA = "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a"
GLASS = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b"
SVC = "4f5a6b7c-8d9e-4f0a-9b1c-3d4e5f6a7b8c"
FLOW_UUID = "5a6b7c8d-9e0f-4a1b-8c2d-4e5f6a7b8c9d"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
SCHEMA = REPO / "tools" / "schemas" / "access-report.schema.json"


class FakeRealm:
    """The Admin REST API calls the report makes, over seeded objects."""

    def __init__(self) -> None:
        self.users = [
            {"id": BEN, "username": "ben", "enabled": True, "credentials": [{"value": "x"}]},
            {"id": DORA, "username": "dora", "enabled": True},
            {"id": CARLA, "username": "carla", "enabled": False},
            {
                "id": GLASS,
                "username": "breakglass",
                "enabled": True,
            },
            {"id": SVC, "username": "service-account-svc-flow-x", "serviceAccountClientId": "svc"},
        ]
        self.roles = {
            BEN: (["user", "flow-author"], {"studio": ["studio-member"]}),
            DORA: (["user", "papaia-admin", "papaia-auditor"], {}),
            CARLA: (["user"], {}),
            GLASS: (["papaia-admin"], {"realm-management": ["realm-admin"]}),
        }
        self.groups = {BEN: ["/buendel/mitarbeit"], DORA: ["/buendel/verwaltung"]}
        self.offline = {(BEN, FLOW_UUID): 2}
        self.calls: list[tuple[str, str]] = []

    def call(self, method: str, path: str, body: object = None):
        assert method == "GET", (method, path)
        self.calls.append((method, path))
        if path == "":
            return {
                "realm": "papaia",
                "offlineSessionIdleTimeout": 90 * 86400,
                "offlineSessionMaxLifespanEnabled": True,
                "offlineSessionMaxLifespan": 180 * 86400,
                "smtpServer": {"password": "smtp-secret-value"},
            }
        if path.startswith("/users?"):
            query = dict(p.split("=") for p in path.partition("?")[2].split("&"))
            first, size = int(query["first"]), int(query["max"])
            return copy.deepcopy(self.users[first : first + size])
        if path == "/clients":
            return [
                {
                    "id": FLOW_UUID,
                    "clientId": "flow-engine",
                    "secret": "client-secret-value",
                    "attributes": {rs.MANAGED: "true", rs.KIND: "confidential"},
                },
                {
                    "id": "6b7c8d9e-0f1a-4b2c-9d3e-5f6a7b8c9d0e",
                    "clientId": "svc-flow-paperless",
                    "attributes": {rs.MANAGED: "true", rs.KIND: rs.SERVICE_ACCOUNT},
                },
            ]
        parts = path.strip("/").split("/")
        if parts[0] == "users" and parts[2:] == ["role-mappings"]:
            realm, clients = self.roles[parts[1]]
            return {
                "realmMappings": [{"name": r} for r in realm],
                "clientMappings": {
                    c: {"client": c, "mappings": [{"name": r} for r in names]}
                    for c, names in clients.items()
                },
            }
        if parts[0] == "users" and parts[2:] == ["role-mappings", "realm", "composite"]:
            realm, _ = self.roles[parts[1]]
            extra = ["flow-admin", "studio-admin"] if "papaia-admin" in realm else []
            return [{"name": r} for r in realm + extra + ["default-roles-papaia"]]
        if parts[0] == "users" and parts[2] == "groups":
            return [{"path": p, "name": p.rsplit("/", 1)[1]} for p in self.groups.get(parts[1], [])]
        if parts[0] == "users" and parts[2] == "offline-sessions":
            return [{"id": str(i)} for i in range(self.offline.get((parts[1], parts[3]), 0))]
        raise AssertionError(path)


SERVICE_ACCOUNTS = [
    {
        "id": "svc-flow-paperless",
        "module": "papaia-flow",
        "owner_sub": DORA,
        "deputy_sub": BEN,
        "audiences": ["paperless"],
        "roles": [],
        "effects": ["r", "w"],
        "rotation_days": 90,
        "key_rotated_at": "2026-11-01T00:00:00Z",
        "rotation_due": False,
        "last_used": None,
        "purpose": {"de": "Rechnungen ablegen"},
    }
]
PAIRINGS = [
    rs.Pairing("flow-engine", "paperless", ("r", "w"), True, "host:anna", "host:bert"),
    rs.Pairing("studio-api", "paperless", ("r",), True, "host:anna", "host:anna"),
    rs.Pairing("assist-engine", "qdrant", ("r",), False, "host:anna", None),
]
DELEGATIONS = {"idle_days": 90, "max_days": 180, "source": "default"}


def _snapshot(realm: FakeRealm | None = None) -> ar.Snapshot:
    return ar.collect(
        (realm or FakeRealm()).call,
        service_accounts=SERVICE_ACCOUNTS,
        pairings=PAIRINGS,
        delegations=DELEGATIONS,
        breakglass_ids=frozenset({GLASS}),
    )


def _rows(doc: dict) -> dict[str, dict]:
    return {row["key"]: row for row in doc["rows"]}


# ─────────────────────────────────────────────────────────────────────────
# by person
# ─────────────────────────────────────────────────────────────────────────


def test_the_person_report_lists_the_seeded_objects():
    doc = ar.build(_snapshot(), "person", [], NOW)
    rows = _rows(doc)

    assert sorted(rows) == sorted(f"person:{s}" for s in (BEN, DORA, CARLA, GLASS))
    ben = rows[f"person:{BEN}"]
    assert ben["username"] == "ben" and ben["enabled"] is True
    assert ben["realm_roles"] == ["flow-author", "user"]
    assert ben["module_roles"] == {"studio": ["studio-member"]}
    assert ben["groups"] == ["/buendel/mitarbeit"]
    assert ben["service_accounts"] == {"owner": [], "deputy": ["svc-flow-paperless"]}
    assert ben["delegations"] == {"flow-engine": 2}
    dora = rows[f"person:{DORA}"]
    assert dora["service_accounts"] == {"owner": ["svc-flow-paperless"], "deputy": []}
    assert dora["delegations"] == {}
    assert rows[f"person:{CARLA}"]["enabled"] is False
    # The service account's own user is listed under its account, not as a person.
    assert f"person:{SVC}" not in rows
    assert doc["sessions"] == {
        "offline": {"idle_days": 90, "max_age_days": 180},
        "delegations": DELEGATIONS,
    }


def test_holders_of_two_separated_platform_roles_are_marked():
    rows = _rows(ar.build(_snapshot(), "person", [], NOW))
    assert rows[f"person:{DORA}"]["separation_conflict"] == ["papaia-admin", "papaia-auditor"]
    assert rows[f"person:{BEN}"]["separation_conflict"] == []


def test_the_emergency_account_is_marked_and_its_rights_are_shown():
    glass = _rows(ar.build(_snapshot(), "person", [], NOW))[f"person:{GLASS}"]
    assert glass["breakglass"] is True
    assert glass["module_roles"] == {"realm-management": ["realm-admin"]}
    assert _rows(ar.build(_snapshot(), "person", [], NOW))[f"person:{BEN}"]["breakglass"] is False


def test_the_emergency_account_is_known_by_its_recorded_id_not_by_a_name_or_attribute():
    # Keycloak 26 drops user attributes its user profile does not declare, and anyone
    # with realm-admin can name an account "breakglass": the id recorded by
    # `papaia-ctl breakglass create` decides.
    realm = FakeRealm()
    realm.users[0]["attributes"] = {"papaia.breakglass": ["true"]}
    snapshot = ar.collect(
        realm.call,
        service_accounts=SERVICE_ACCOUNTS,
        pairings=PAIRINGS,
        delegations=DELEGATIONS,
        breakglass_ids=frozenset(),
    )
    rows = _rows(ar.build(snapshot, "person", [], NOW))
    assert rows[f"person:{BEN}"]["breakglass"] is False
    assert rows[f"person:{GLASS}"]["breakglass"] is False


def test_the_report_holds_no_secret_and_no_content():
    text = json.dumps(ar.build(_snapshot(), "person", [], NOW)) + json.dumps(
        ar.build(_snapshot(), "system", [], NOW)
    )
    for secret in ("client-secret-value", "smtp-secret-value", '"credentials"', "Rechnungen"):
        assert secret not in text


# ─────────────────────────────────────────────────────────────────────────
# by system
# ─────────────────────────────────────────────────────────────────────────


def test_the_system_report_lists_exchange_rights_and_service_accounts_per_entry():
    rows = _rows(ar.build(_snapshot(), "system", [], NOW))

    assert sorted(rows) == ["system:paperless"]  # the unconfirmed pairing grants nothing
    paperless = rows["system:paperless"]
    assert paperless["exchange_clients"] == [
        {
            "client": "flow-engine",
            "effects": ["r", "w"],
            "requested_by": "host:anna",
            "confirmed_by": "host:bert",
        },
        {
            "client": "studio-api",
            "effects": ["r"],
            "requested_by": "host:anna",
            "confirmed_by": "host:anna",
        },
    ]
    assert paperless["service_accounts"] == [
        {"id": "svc-flow-paperless", "module": "papaia-flow", "effects": ["r", "w"]}
    ]
    assert paperless["target_rights"] == "im Zielsystem geführt"


# ─────────────────────────────────────────────────────────────────────────
# determinism, recertification
# ─────────────────────────────────────────────────────────────────────────


def test_two_retrievals_are_equal_and_a_removed_role_changes_exactly_that_row():
    first = ar.build(_snapshot(), "person", [], NOW)
    second = ar.build(_snapshot(), "person", [], NOW + timedelta(minutes=5))
    assert first["checksum"] == second["checksum"]
    assert first["rows"] == second["rows"]

    realm = FakeRealm()
    realm.users.reverse()  # another order from the realm changes nothing
    realm.roles[BEN] = (["user"], {"studio": ["studio-member"]})
    third = ar.build(_snapshot(realm), "person", [], NOW)

    assert third["checksum"] != first["checksum"]
    changed = [
        key
        for key in _rows(first)
        if {k: v for k, v in _rows(first)[key].items()}
        != {k: v for k, v in _rows(third)[key].items()}
    ]
    assert changed == [f"person:{BEN}"]
    assert ar.checksum(first["sessions"], first["rows"]) == first["checksum"]


def _confirmation(key: str, digest: str, days_ago: int) -> dict:
    at = NOW - timedelta(days=days_ago)
    return {
        "key": key,
        "digest": digest,
        "confirmed_at": at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "confirmed_by": "P-ABCDEFGH",
    }


def test_each_row_carries_its_last_confirmation_and_old_ones_are_due():
    plain = _rows(ar.build(_snapshot(), "person", [], NOW))
    ben, dora = plain[f"person:{BEN}"], plain[f"person:{DORA}"]
    assert ben["last_confirmed_at"] is None and ben["confirmation_due"] is True

    confirmations = [
        _confirmation(f"person:{BEN}", ben["digest"], 10),
        _confirmation(f"person:{DORA}", dora["digest"], 181),
        _confirmation(f"person:{CARLA}", "sha256:" + "0" * 64, 1),
    ]
    rows = _rows(ar.build(_snapshot(), "person", confirmations, NOW))

    assert rows[f"person:{BEN}"]["last_confirmed_at"] == confirmations[0]["confirmed_at"]
    assert rows[f"person:{BEN}"]["confirmation_due"] is False
    # Older than the period (default 180 days).
    assert rows[f"person:{DORA}"]["confirmation_due"] is True
    # Confirmed for another content than the current one.
    assert rows[f"person:{CARLA}"]["confirmation_due"] is True
    # A shorter period marks Ben's row as well.
    short = _rows(ar.build(_snapshot(), "person", confirmations, NOW, period_days=7))
    assert short[f"person:{BEN}"]["confirmation_due"] is True


def test_the_confirmation_state_does_not_change_the_checksum():
    plain = ar.build(_snapshot(), "person", [], NOW)
    ben = _rows(plain)[f"person:{BEN}"]
    confirmed = ar.build(
        _snapshot(), "person", [_confirmation(f"person:{BEN}", ben["digest"], 1)], NOW
    )
    assert confirmed["checksum"] == plain["checksum"]


@pytest.mark.parametrize(("value", "days"), [(None, 180), ("30", 30), ("730", 730)])
def test_the_recertification_period_is_set_per_installation(value, days):
    env = {} if value is None else {ar.PERIOD_KEY: value}
    assert ar.period_days(env) == days


@pytest.mark.parametrize("value", ["29", "731", "abc", "-1", " 90"])
def test_a_period_out_of_range_is_refused(value):
    with pytest.raises(ar.ReportError):
        ar.period_days({ar.PERIOD_KEY: value})


# ─────────────────────────────────────────────────────────────────────────
# formats
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("by", ["person", "system"])
def test_the_json_report_follows_the_published_schema(by):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    doc = ar.build(_snapshot(), by, [], NOW)
    errors = list(Draft202012Validator(schema).iter_errors(doc))
    assert not errors, errors
    assert doc["format"] == "papaia.access-report/1" and doc["by"] == by


def test_the_csv_report_has_one_line_per_row_and_no_formula():
    realm = FakeRealm()
    realm.users[1]["username"] = "=cmd|calc"
    doc = ar.build(_snapshot(realm), "person", [], NOW)
    text = ar.render(doc, "csv")
    lines = list(csv.DictReader(io.StringIO(text)))
    assert len(lines) == 4
    ben = next(line for line in lines if line["key"] == f"person:{BEN}")
    assert ben["realm_roles"] == "flow-author user"
    assert ben["module_roles"] == "studio=studio-member"
    assert ben["delegations"] == "flow-engine=2"
    assert ben["confirmation_due"] == "true"
    dora = next(line for line in lines if line["key"] == f"person:{DORA}")
    assert dora["username"] == "'=cmd|calc"
    assert f"# checksum {doc['checksum']}" not in text  # metadata stays in the JSON form
    assert ar.render(doc, "json") == ar.render(doc, "json")


# ─────────────────────────────────────────────────────────────────────────
# release through papaia-audit
# ─────────────────────────────────────────────────────────────────────────


def test_the_report_is_printed_only_after_papaia_audit_released_it():
    seen = []

    def gate(path: str, token: str, body: dict) -> tuple[int, dict]:
        seen.append((path, token, body))
        return 200, {"confirmations": []}

    out = io.StringIO()
    code = ar.run(_snapshot(), "person", "json", TOKEN, gate, out, now=NOW)

    assert code == 0
    doc = json.loads(out.getvalue())
    ((path, token, body),) = seen
    assert path == "/v1/access-reports" and token == TOKEN
    assert body == {"by": "person", "rows": len(doc["rows"]), "checksum": doc["checksum"]}


@pytest.mark.parametrize(("status", "code"), [(403, 3), (401, 3), (503, 1), (400, 1)])
def test_a_refused_release_prints_nothing(status, code):
    out, err = io.StringIO(), io.StringIO()

    def gate(path, token, body):
        return status, {"message": "Nur mit der Rolle Audit-Prüfung.", "code": "X"}

    assert ar.run(_snapshot(), "person", "json", TOKEN, gate, out, now=NOW, err=err) == code
    assert out.getvalue() == "" and TOKEN not in err.getvalue()


def test_the_token_is_read_from_a_file_or_stdin_and_checked(tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    assert ar.read_token(str(path)) == TOKEN
    assert ar.read_token("-", stdin=io.StringIO(TOKEN)) == TOKEN
    for bad in ("", "not a token", "a.b", "x" * 9000):
        path.write_text(bad, encoding="utf-8")
        with pytest.raises(ar.ReportError) as raised:
            ar.read_token(str(path))
        assert bad[:20] not in str(raised.value) or not bad


def test_a_confirmation_goes_to_papaia_audit_with_the_row_digest():
    seen = []

    def gate(path, token, body):
        seen.append((path, body))
        return 201, {"key": body["key"], "digest": body["digest"], "confirmed_at": "x"}

    digest = "sha256:" + "a" * 64
    out = io.StringIO()
    assert ar.confirm(f"person:{BEN}", digest, TOKEN, gate, out) == 0
    assert seen == [
        ("/v1/access-reports/confirmations", {"key": f"person:{BEN}", "digest": digest})
    ]
    with pytest.raises(ar.ReportError):
        ar.confirm("person:not ok", digest, TOKEN, gate, out)
    with pytest.raises(ar.ReportError):
        ar.confirm(f"person:{BEN}", "abc", TOKEN, gate, out)


def test_the_gate_runs_inside_papaia_audit_with_the_token_on_stdin(monkeypatch, tmp_path):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"], captured["input"] = argv, kwargs["input"]
        answer = '{"status": 200, "body": {"confirmations": []}}'
        return subprocess.CompletedProcess(argv, 0, answer, "")

    monkeypatch.setattr(ar.audit, "find_container", lambda config_dir: "papaia-audit-1")
    monkeypatch.setattr(ar.subprocess, "run", fake_run)
    gate = ar.service_gate(tmp_path)
    status, body = gate("/v1/access-reports", TOKEN, {"by": "person"})

    assert (status, body) == (200, {"confirmations": []})
    assert TOKEN not in " ".join(captured["argv"])
    assert captured["argv"][-1] == "access" and captured["argv"][:3] == ["docker", "exec", "-i"]
    sent = json.loads(captured["input"])
    assert sent == {
        "method": "POST",
        "path": "/v1/access-reports",
        "authorization": f"Bearer {TOKEN}",
        "body": {"by": "person"},
    }


def _no_container(config_dir):
    raise ar.audit.AuditError("papaia-audit is not running")


def _no_answer(argv, **kwargs):
    return subprocess.CompletedProcess(argv, 1, "", "Error response from daemon")


@pytest.mark.parametrize("broken", ["container", "answer"])
def test_an_unavailable_papaia_audit_is_its_own_error(monkeypatch, tmp_path, broken):
    if broken == "container":
        monkeypatch.setattr(ar.audit, "find_container", _no_container)
    else:
        monkeypatch.setattr(ar.audit, "find_container", lambda config_dir: "papaia-audit-1")
        monkeypatch.setattr(ar.subprocess, "run", _no_answer)
    with pytest.raises(ar.AuditUnavailable):
        ar.service_gate(tmp_path)("/v1/access-reports", TOKEN, {"by": "person"})


def _cli_args(tmp_path, token_file):
    import argparse

    return argparse.Namespace(
        token_file=str(token_file), config_dir=str(tmp_path), repo_root=str(tmp_path),
        by="person", format="json", key="person:abc", digest="sha256:" + "0" * 64,
    )


@pytest.mark.parametrize("command", ["permissions", "confirm"])
def test_the_commands_exit_1_when_papaia_audit_is_unavailable(
    monkeypatch, tmp_path, capsys, command
):
    from lib import cli

    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    monkeypatch.setattr(ar.audit, "find_container", _no_container)
    monkeypatch.setattr(cli, "_report_inputs", lambda args: (None, {}, tmp_path))
    monkeypatch.setattr(ar, "collect", lambda call, **kwargs: ar.Snapshot())
    monkeypatch.setattr(cli.service_accounts, "describe", lambda call: [])
    monkeypatch.setattr(cli.realm_sync, "load_pairings", lambda path, register: [])
    monkeypatch.setattr(cli.delegation_lifetime, "report", lambda config_dir: {})
    run = cli.cmd_report_permissions if command == "permissions" else cli.cmd_report_confirm

    assert run(_cli_args(tmp_path, token_file)) == 1
    assert "papaia-audit" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["permissions", "confirm"])
def test_the_commands_exit_2_on_invalid_input(tmp_path, capsys, command):
    from lib import cli

    token_file = tmp_path / "token"
    token_file.write_text("not a token")
    run = cli.cmd_report_permissions if command == "permissions" else cli.cmd_report_confirm

    assert run(_cli_args(tmp_path, token_file)) == 2


# ─────────────────────────────────────────────────────────────────────────
# the shell command
# ─────────────────────────────────────────────────────────────────────────


@needs_bash
def test_the_command_is_dispatched_and_documented():
    text = CTL.read_text(encoding="utf-8")
    assert 'report)        cmd_report "$@" ;;' in text
    env = dict(os.environ, PATH=f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")
    help_text = subprocess.run(
        [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False, env=env
    ).stdout
    assert "papaia-ctl report permissions --by=person|system" in help_text
    assert "papaia-ctl report confirm --key=KEY --digest=SHA256" in help_text
    assert "papaia-ctl breakglass create|rotate|status" in help_text


@needs_bash
@pytest.mark.parametrize(
    "args",
    [
        ["permissions", "--by=team", "--token-file=-"],
        ["permissions", "--by=person", "--format=xml", "--token-file=-"],
        ["permissions", "--by=person"],
        ["permissions", "--by=person", f"--token={TOKEN}"],
        ["export"],
    ],
)
def test_the_command_refuses_bad_arguments_and_a_token_in_argv(tmp_path, args):
    env = dict(os.environ, PATH=f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")
    done = subprocess.run(
        [BASH, str(CTL), "report", *args, f"--config-dir={tmp_path}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert done.returncode == 2, done.stderr
    assert TOKEN not in done.stderr + done.stdout
