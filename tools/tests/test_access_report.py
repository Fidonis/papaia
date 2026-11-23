"""`papaia-ctl report permissions|confirm` and the inputs file of the permission report
(tools/lib/access_report.py, security 1.16).

papaia-audit builds the report (test_audit_report.py, test_audit_access.py); papaia-ctl
only calls `POST /v1/access-reports/build` inside the container and prints the answer
unchanged, without the master admin. The inputs file is written from a realm double of
the master admin's Admin API on realm sync.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lib import access_report as ar
from lib import realm_sync as rs

REPO = Path(__file__).resolve().parents[2]
CTL = REPO / "tools" / "papaia-ctl"
BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not installed")
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
INPUTS_SCHEMA = REPO / "tools" / "schemas" / "access-report-inputs.schema.json"
# The secret scan over the written inputs file needs gitleaks (CI installs the pinned one
# and sets PAPAIA_REQUIRE_GITLEAKS, so a missing binary fails there instead of skipping).
_GITLEAKS = shutil.which("gitleaks")
if _GITLEAKS is None and os.environ.get("PAPAIA_REQUIRE_GITLEAKS"):
    raise RuntimeError("PAPAIA_REQUIRE_GITLEAKS is set but gitleaks is not installed")
needs_gitleaks = pytest.mark.skipif(_GITLEAKS is None, reason="gitleaks not installed")
BEN = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
DORA = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
GLASS = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b"
FLOW_UUID = "5a6b7c8d-9e0f-4a1b-8c2d-4e5f6a7b8c9d"
CLIENT_SECRET = "client-secret-value-4711"
SMTP_SECRET = "smtp-secret-value-0815"
REPORT_JSON = '{\n  "by": "person",\n  "checksum": "sha256:' + "a" * 64 + '"\n}\n'


# ─────────────────────────────────────────────────────────────────────────
# report permissions: a call into papaia-audit, printed unchanged
# ─────────────────────────────────────────────────────────────────────────


def test_the_report_is_built_by_papaia_audit_and_printed_byte_for_byte():
    seen = []

    def gate(path: str, token: str, body: dict):
        seen.append((path, token, body))
        return 200, "text/csv; charset=utf-8", "key,sub\r\nperson:x,x\n"

    out = io.StringIO()
    assert ar.run("person", "csv", TOKEN, gate, out) == 0
    assert out.getvalue() == "key,sub\r\nperson:x,x\n"
    assert seen == [("/v1/access-reports/build", TOKEN, {"by": "person", "format": "csv"})]


@pytest.mark.parametrize(("status", "code"), [(403, 3), (401, 3), (503, 1), (400, 1), (404, 1)])
def test_a_refused_or_failed_build_prints_nothing(status, code):
    out, err = io.StringIO(), io.StringIO()

    def gate(path, token, body):
        problem = {"message": "Nur mit der Rolle Audit-Prüfung.", "code": "X", "hint": "H"}
        return status, "application/problem+json", json.dumps(problem)

    assert ar.run("person", "json", TOKEN, gate, out, err=err) == code
    assert out.getvalue() == "" and TOKEN not in err.getvalue()
    assert "Nur mit der Rolle Audit-Prüfung. H" in err.getvalue()


@pytest.mark.parametrize(("by", "fmt"), [("team", "json"), ("person", "xml")])
def test_unknown_kinds_and_formats_are_refused_before_the_call(by, fmt):
    def gate(path, token, body):
        raise AssertionError("no call expected")

    with pytest.raises(ar.ReportError):
        ar.run(by, fmt, TOKEN, gate, io.StringIO())


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
        answer = {"key": body["key"], "digest": body["digest"], "confirmed_at": "x"}
        return 201, "application/json", json.dumps(answer)

    digest = "sha256:" + "a" * 64
    out = io.StringIO()
    assert ar.confirm(f"person:{BEN}", digest, TOKEN, gate, out) == 0
    assert out.getvalue() == f"Confirmed person:{BEN} at x.\n"
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
        answer = {"status": 200, "content_type": "application/json", "text": REPORT_JSON}
        return subprocess.CompletedProcess(argv, 0, json.dumps(answer), "")

    monkeypatch.setattr(ar.audit, "find_container", lambda config_dir: "papaia-audit-1")
    monkeypatch.setattr(ar.subprocess, "run", fake_run)
    gate = ar.service_gate(tmp_path)

    assert gate(ar.BUILD_PATH, TOKEN, {"by": "person", "format": "json"}) == (
        200,
        "application/json",
        REPORT_JSON,
    )
    assert TOKEN not in " ".join(captured["argv"])
    assert captured["argv"][-1] == "access" and captured["argv"][:3] == ["docker", "exec", "-i"]
    assert json.loads(captured["input"]) == {
        "method": "POST",
        "path": "/v1/access-reports/build",
        "authorization": f"Bearer {TOKEN}",
        "body": {"by": "person", "format": "json"},
    }


def _no_container(config_dir):
    raise ar.audit.AuditError("papaia-audit is not running")


def _no_answer(argv, **kwargs):
    return subprocess.CompletedProcess(argv, 1, "", "Error response from daemon")


def _old_answer(argv, **kwargs):
    return subprocess.CompletedProcess(argv, 0, '{"status": 200, "body": {}}', "")


@pytest.mark.parametrize("broken", ["container", "answer", "old"])
def test_an_unavailable_papaia_audit_is_its_own_error(monkeypatch, tmp_path, broken):
    if broken == "container":
        monkeypatch.setattr(ar.audit, "find_container", _no_container)
    else:
        monkeypatch.setattr(ar.audit, "find_container", lambda config_dir: "papaia-audit-1")
        monkeypatch.setattr(ar.subprocess, "run", _no_answer if broken == "answer" else _old_answer)
    with pytest.raises(ar.AuditUnavailable):
        ar.service_gate(tmp_path)(ar.BUILD_PATH, TOKEN, {"by": "person", "format": "json"})


def _cli_args(tmp_path, token_file):
    import argparse

    return argparse.Namespace(
        token_file=str(token_file), config_dir=str(tmp_path), repo_root=str(tmp_path),
        by="person", format="json", key="person:abc", digest="sha256:" + "0" * 64,
    )


def test_the_command_never_signs_in_as_master_admin(monkeypatch, tmp_path, capsys):
    from lib import cli
    from lib import keycloak_role_sync as kcs

    def forbidden(*args, **kwargs):
        raise AssertionError("the master admin must not be used")

    monkeypatch.setattr(kcs, "_get_admin_token", forbidden)
    monkeypatch.setattr(rs, "MasterAdmin", forbidden)
    monkeypatch.setattr(cli.envtree, "load_config_dir_tree", forbidden)
    monkeypatch.setattr(ar.audit, "find_container", lambda config_dir: "papaia-audit-1")

    def fake_run(argv, **kwargs):
        answer = {"status": 200, "content_type": "application/json", "text": REPORT_JSON}
        return subprocess.CompletedProcess(argv, 0, json.dumps(answer), "")

    monkeypatch.setattr(ar.subprocess, "run", fake_run)
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)

    assert cli.cmd_report_permissions(_cli_args(tmp_path, token_file)) == 0
    assert capsys.readouterr().out == REPORT_JSON
    source = (REPO / "tools" / "lib" / "access_report.py").read_text(encoding="utf-8")
    command = (REPO / "tools" / "lib" / "cli.py").read_text(encoding="utf-8")
    body = command[command.index("def cmd_report_permissions") :]
    body = body[: body.index("\ndef ")]
    for word in ("KC_ADMIN_PASSWORD", "MasterAdmin", "_get_admin_token", "_connection"):
        assert word not in body
    assert "KC_ADMIN_PASSWORD" not in source


@pytest.mark.parametrize("command", ["permissions", "confirm"])
def test_the_commands_exit_1_when_papaia_audit_is_unavailable(
    monkeypatch, tmp_path, capsys, command
):
    from lib import cli

    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    monkeypatch.setattr(ar.audit, "find_container", _no_container)
    run = cli.cmd_report_permissions if command == "permissions" else cli.cmd_report_confirm

    assert run(_cli_args(tmp_path, token_file)) == 1
    assert "papaia-audit" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["permissions", "confirm"])
def test_the_commands_exit_2_on_invalid_input(tmp_path, command):
    from lib import cli

    token_file = tmp_path / "token"
    token_file.write_text("not a token")
    run = cli.cmd_report_permissions if command == "permissions" else cli.cmd_report_confirm

    assert run(_cli_args(tmp_path, token_file)) == 2


# ─────────────────────────────────────────────────────────────────────────
# the inputs file
# ─────────────────────────────────────────────────────────────────────────


class MasterRealm:
    """The master admin's reads the inputs file needs, with secrets where Keycloak has
    them: none of them may reach the file."""

    def __init__(self) -> None:
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
                "smtpServer": {"password": SMTP_SECRET},
            }
        if path == "/clients":
            return [
                {
                    "id": FLOW_UUID,
                    "clientId": "flow-engine",
                    "secret": CLIENT_SECRET,
                    "attributes": {rs.MANAGED: "true", rs.KIND: "confidential"},
                },
                {
                    "id": "6b7c8d9e-0f1a-4b2c-9d3e-5f6a7b8c9d0e",
                    "clientId": "svc-flow-paperless",
                    "secret": CLIENT_SECRET,
                    "optionalClientScopes": ["aud-paperless"],
                    "attributes": {
                        rs.MANAGED: "true",
                        rs.KIND: rs.SERVICE_ACCOUNT,
                        rs.OWNER: "papaia-flow",
                        "papaia.owner_sub": DORA,
                        "papaia.deputy_sub": BEN,
                        "papaia.effects": "w,r",
                        "jwks.string": '{"keys": [{"kty": "EC"}]}',
                    },
                },
                {"id": "7c8d9e0f-1a2b-4c3d-8e4f-6a7b8c9d0e1f", "clientId": "papaia-manager",
                 "secret": CLIENT_SECRET, "attributes": {}},
            ]
        raise AssertionError(path)


PAIRINGS = [
    rs.Pairing("flow-engine", "paperless", ("r", "w"), True, "host:anna", "host:bert"),
    rs.Pairing("assist-engine", "qdrant", ("r",), False, "host:anna", None),
    rs.Pairing("papaia-manager", "papaia-audit", ("r",), True, "platform", "platform"),
]
DELEGATIONS = {"idle_days": 90, "max_days": 180, "source": "default"}


def _inputs(now: float = 1_795_000_000.0) -> dict:
    return ar.build_inputs(
        MasterRealm().call,
        pairings=PAIRINGS,
        delegations=DELEGATIONS,
        breakglass_ids=frozenset({GLASS}),
        period=180,
        now=now,
    )


def test_the_inputs_file_follows_its_schema_and_names_what_the_report_needs():
    document = _inputs()
    schema = json.loads(INPUTS_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert not list(Draft202012Validator(schema).iter_errors(document))
    assert document["module_clients"] == [{"id": FLOW_UUID, "client_id": "flow-engine"}]
    assert document["service_accounts"] == [
        {"id": "svc-flow-paperless", "module": "papaia-flow", "owner_sub": DORA,
         "deputy_sub": BEN, "audiences": ["paperless"], "effects": ["r", "w"]}
    ]
    # Only confirmed pairings; the platform pairing of the realm sync is one of them.
    assert [(p["client"], p["audience"]) for p in document["pairings"]] == [
        ("papaia-manager", "papaia-audit"),
        ("flow-engine", "paperless"),
    ]
    assert document["sessions"] == {
        "offline": {"idle_days": 90, "max_age_days": 180},
        "delegations": DELEGATIONS,
    }
    assert document["breakglass_ids"] == [GLASS]
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", document["written_at"])


def test_papaia_audit_accepts_the_file_papaia_ctl_writes(tmp_path):
    sys.path.insert(0, str(REPO / "src" / "infra" / "audit"))
    from papaia_audit import report as rp

    path = ar.write_inputs(tmp_path, _inputs())
    inputs = rp.load_inputs(path)
    assert inputs.module_clients == ((FLOW_UUID, "flow-engine"),)
    assert inputs.recertification_days == 180


def test_the_inputs_file_holds_no_secret_and_is_written_for_papaia_audit(tmp_path):
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "local-ca.crt").write_text("-----BEGIN CERTIFICATE-----\nAA\n")
    (tmp_path / "certs" / "local-ca.key").write_text("never copied")
    path = ar.write_inputs(tmp_path, _inputs())

    assert path == tmp_path / "infra" / "audit" / "service" / "access-report-inputs.json"
    text = path.read_text(encoding="utf-8")
    for secret in (CLIENT_SECRET, SMTP_SECRET, '"secret"', "jwks", "password", "credential"):
        assert secret not in text
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    ca = path.with_name("keycloak-ca.crt")
    assert ca.read_text() == "-----BEGIN CERTIFICATE-----\nAA\n"
    assert not any("never copied" in p.read_text() for p in path.parent.iterdir())


@needs_gitleaks
def test_the_secret_scan_finds_nothing_in_the_inputs_file(tmp_path):
    out = tmp_path / "config"
    ar.write_inputs(out, _inputs())
    done = subprocess.run(
        [
            _GITLEAKS,
            "dir",
            "--no-banner",
            "--redact",
            "--exit-code",
            "1",
            "--config",
            str(REPO / ".gitleaks.toml"),
            str(out / "infra"),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_period_is_checked_before_it_is_written():
    assert ar.period_days({}) == 180
    assert ar.period_days({ar.PERIOD_KEY: "30"}) == 30
    for bad in ("29", "731", "abc", " 90"):
        with pytest.raises(ar.ReportError):
            ar.period_days({ar.PERIOD_KEY: bad})


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
