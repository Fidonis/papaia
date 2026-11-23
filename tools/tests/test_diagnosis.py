"""The nine injected faults of the troubleshooting guide (BE-29, EXK-PLT-68-A3).

Each fault is injected the way the host shows it to `doctor` (a stopped container, a
model that does not answer, a halt file, a realm deviation, a full disk, an expired
certificate, a mail server that does not answer). Expected for each: `doctor` exits
non-zero and names the cause in one German sentence with the section of the guide, in
the table and in `--json`. Docker, the disk, the certificates and the realm are fakes.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from stack_helpers import (
    NOW,
    FakeDocker,
    healthy_addon,
    healthy_core,
    ps_line,
    smtp_relay_container,
)
from test_doctor import QUEUE_TWO, enable_smtp, probes, set_env

from lib import diagnosis, doctor, smtp
from lib.doctor import FAIL, PASS
from lib.status import CommandResult

REPO = Path(__file__).resolve().parents[2]
VALIDATOR = Draft202012Validator(
    json.loads((REPO / "tools" / "schemas" / "doctor.schema.json").read_text("utf-8"))
)
GIB = 1024**3
MODEL = "qwen2.5-7b-instruct-q4"
SYNC_SECRET = "realm-sync-test-secret-value"


class GatewayDocker(FakeDocker):
    """FakeDocker plus LiteLLM: `docker exec <litellm> python -I -c <probe> [alias]` is
    answered with `answer` (a JSON line), as the probe prints it in the container."""

    def __init__(self, ps, *, answer: dict | None = None, **kwargs):
        super().__init__(ps, **kwargs)
        self.answer = answer
        self.probes: list[list[str]] = []

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        if cmd[:2] == ["docker", "exec"] and cmd[3:6] == ["python", "-I", "-c"]:
            self.calls.append(cmd)
            self.probes.append(cmd)
            if self.answer is None:
                return CommandResult(1, "", "Error response from daemon: not running")
            return CommandResult(0, json.dumps(self.answer) + "\n", "")
        return super().__call__(cmd, timeout)


def litellm(state: str = "running") -> list[str]:
    return [ps_line(
        "papaia-litellm-1", state,
        "Up 2 hours (healthy)" if state == "running" else "Exited (137) 1 minute ago",
        "litellm", "papaia-litellm", "llm-proxy",
    )]


def with_gateway(stack) -> None:
    """The model gateway as part of the synthetic installation."""
    src = stack["repo"] / "src"
    root = yaml.safe_load((src / "docker-compose.yml").read_text("utf-8"))
    root["include"].append({"path": "./ai/litellm/docker-compose.yml"})
    (src / "docker-compose.yml").write_text(yaml.safe_dump(root), encoding="utf-8")
    fragment = src / "ai" / "litellm" / "docker-compose.yml"
    fragment.parent.mkdir(parents=True)
    fragment.write_text(yaml.safe_dump({"services": {"litellm": {
        "image": "example/litellm:1", "profiles": ["litellm"],
        "labels": {"de.fidonis.module": "papaia-litellm", "de.fidonis.role": "llm-proxy"},
    }}}), encoding="utf-8")
    set_env(stack, COMPOSE_PROFILES="keycloak,oauth2-proxy,librechat-websearch,litellm",
            PAPAIA_DEFAULT_MODEL=MODEL)


def with_assist(stack, db_state: str = "running") -> list[str]:
    """An active add-on `assist` with its own database; its `docker ps` lines."""
    addon = stack["addon"].parent / "assist"
    addon.mkdir()
    (addon / "docker-compose.yml").write_text(yaml.safe_dump({"services": {
        "assist-db": {"image": "x"}, "assist-api": {"image": "x"},
    }}), encoding="utf-8")
    (addon / "papaia-app.yaml").write_text('name: assist\npapaia_compat: ">=1.0.0"\n',
                                           encoding="utf-8")
    deployment = stack["config"] / "deployment.yaml"
    doc = yaml.safe_load(deployment.read_text("utf-8"))
    doc["addons"].append({"name": "assist", "path": str(addon), "active": True})
    deployment.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return [
        ps_line("assist-assist-api-1", "running", "Up 1 hour", "assist-api",
                "papaia-assist", project="assist"),
        ps_line("assist-assist-db-1", db_state,
                "Up 1 hour (healthy)" if db_state == "running" else "Exited (0) 1 minute ago",
                "assist-db", "papaia-assist", project="assist"),
    ]


def run(stack, docker, **overrides) -> doctor.DoctorReport:
    return doctor.run_checks(stack["config"], stack["repo"], run=docker,
                             probes=probes(**overrides), now=NOW)


def check(report: doctor.DoctorReport, name: str) -> doctor.CheckResult:
    return next(c for c in report.checks if c.name == name)


def sentences(report: doctor.DoctorReport, name: str) -> list[tuple[str, str | None]]:
    return [(c.text, c.section) for c in report.causes_of(check(report, name))]


def assert_reported(report: doctor.DoctorReport, name: str, text: str, section: str) -> None:
    """Exit code, table line and JSON entry of one fault."""
    assert check(report, name).status == FAIL
    assert report.exit_code != 0
    assert (text, section) in sentences(report, name)
    assert f"    -> {text} (siehe Handbuch §{section})" in doctor.format_table(report)
    document = json.loads(doctor.to_json(report))
    assert not list(VALIDATOR.iter_errors(document))
    row = next(c for c in document["checks"] if c["name"] == name)
    assert {"text": text, "section": section,
            "reference": f"siehe Handbuch §{section}"} in row["causes"]


# ─── the nine faults ─────────────────────────────────────────────────────


def test_fault_1_model_gateway_stopped(stack):
    with_gateway(stack)
    docker = GatewayDocker(healthy_core() + healthy_addon() + litellm("exited"))
    report = run(stack, docker)

    text = "Das Modell-Gateway (LiteLLM) läuft nicht; Module können keine Modelle nutzen."
    assert_reported(report, "container_health", text, "S-1")
    assert_reported(report, "model_gateway", text, "S-1")
    assert check(report, "model_ready").status == "skip"
    assert docker.probes == [], "nothing is exec'd into a stopped container"


def test_fault_2_model_not_loaded(stack):
    with_gateway(stack)
    docker = GatewayDocker(healthy_core() + healthy_addon() + litellm(),
                           answer={"ready": 200, "model": 500, "seconds": 0.4})
    report = run(stack, docker)

    assert check(report, "model_gateway").status == PASS
    assert_reported(report, "model_ready",
                    f"Das Modell {MODEL} ist nicht geladen; Anfragen schlagen fehl.", "S-2")
    probe = docker.probes[-1]
    assert probe[-1] == doctor.MODEL_ALIAS, "one request through the alias"
    assert "max_tokens':1" in probe[6] and "LITELLM_MASTER_KEY" in probe[6]
    assert not any("sk-" in part for part in probe), "the key never leaves the container"


def test_fault_2_a_model_that_does_not_answer_in_30_s_is_not_loaded(stack):
    with_gateway(stack)
    docker = GatewayDocker(healthy_core() + healthy_addon() + litellm(),
                           answer={"ready": 200, "model": 0, "seconds": 30.0})
    report = run(stack, docker)

    assert check(report, "model_ready").summary == f"{MODEL} did not answer within 30 s"
    assert report.exit_code != 0


def test_fault_3_identity_service_stopped(stack):
    ps = healthy_core()
    ps[0] = ps_line("papaia-keycloak-1", "exited", "Exited (143) 1 minute ago", "keycloak",
                    "papaia-keycloak", "identity-provider")
    report = run(stack, FakeDocker(ps + healthy_addon()))

    assert_reported(
        report, "container_health",
        "Der Anmeldedienst (Keycloak) ist nicht erreichbar; niemand kann sich anmelden.", "S-3",
    )


def test_fault_4_database_of_assistant_stopped(stack):
    # `docker stop` ends PostgreSQL with exit code 0; the restart policy tells it apart
    # from a one-shot job that completed.
    ps = healthy_core() + healthy_addon() + with_assist(stack, db_state="exited")
    report = run(stack, FakeDocker(ps, policies={"assist-assist-db-1": "unless-stopped"}))

    assert_reported(report, "container_health", "Die Datenbank von Assistant läuft nicht.", "S-4")


def test_fault_5_emergency_halt_set(stack):
    state = stack["config"] / "state"
    state.mkdir()
    since = int((NOW - timedelta(minutes=5)).timestamp())
    (state / "halt.json").write_text(json.dumps(
        {"active": True, "since": since, "reason": "test", "by": "papaia-admin"}
    ), encoding="utf-8")
    report = run(stack, FakeDocker(healthy_core() + healthy_addon()))

    assert_reported(
        report, "halt",
        "Die Plattform ist per Not-Aus abgeschaltet (gesetzt von papaia-admin um "
        "27.09.2026 10:10 UTC).",
        "S-5",
    )
    assert "test" not in check(report, "halt").summary, "the reason is not shown"


def test_fault_6_scope_assignment_removed(stack):
    module = stack["config"] / "infra" / "keycloak"
    module.mkdir(parents=True)
    (module / ".env").write_text(f"KC_REALM_SYNC_CLIENT_SECRET={SYNC_SECRET}\n",
                                 encoding="utf-8")
    calls = []

    def realm_check(config_dir, repo_root):
        calls.append(config_dir)
        return 1, ("fail: client papaia-assist: optional scope aud-studio added\n"
                   "Realm check: fail (1 deviation(s)).\n")

    report = run(stack, FakeDocker(healthy_core() + healthy_addon()), realm_check=realm_check)

    assert calls == [stack["config"]]
    assert_reported(
        report, "realm",
        "Dem Client papaia-assist fehlt der Scope aud-studio; Zugriffe auf Studio werden "
        "abgelehnt.",
        "S-6",
    )
    assert SYNC_SECRET not in doctor.to_json(report)


def test_fault_7_data_disk_full(stack, tmp_path):
    target = tmp_path / "backup-volume"
    target.mkdir()
    set_env(stack, PAPAIA_BACKUP_DIR=str(target))

    def disk_usage(path):
        return (512 * 1024**2, 0) if path == target else (500 * GIB, 400 * GIB)

    report = run(stack, FakeDocker(healthy_core() + healthy_addon()), disk_usage=disk_usage)

    assert_reported(report, "disk_space",
                    f"Auf {target} ist kein Platz mehr; Schreiben ist gestoppt.", "S-7")


def test_fault_8_proxy_certificate_expired(stack):
    certs = stack["config"] / "certs"
    certs.mkdir()
    (certs / "edge.example.org.crt").write_text("-----BEGIN CERTIFICATE-----\n", "utf-8")
    report = run(stack, FakeDocker(healthy_core() + healthy_addon()),
                 cert_enddate=lambda path, run: NOW - timedelta(days=3))

    assert_reported(report, "certs",
                    "Das Zertifikat für edge.example.org ist seit 24.09.2026 abgelaufen.", "S-8")


def test_fault_9_mail_server_not_reachable(stack):
    enable_smtp(stack)
    docker = FakeDocker(healthy_core() + healthy_addon() + smtp_relay_container(),
                        tools={"postqueue": QUEUE_TWO})
    report = run(stack, docker, smtp_probe=lambda *a: smtp.ProbeResult(
        False, "connect", "[Errno 111] Connection refused"))

    assert_reported(report, "smtp",
                    "Der Mailserver smtp.example.org:587 antwortet nicht; 2 Nachrichten warten.",
                    "S-9")


# ─── around the faults ───────────────────────────────────────────────────


def test_a_healthy_gateway_passes_both_checks(stack):
    with_gateway(stack)
    docker = GatewayDocker(healthy_core() + healthy_addon() + litellm(),
                           answer={"ready": 200, "model": 200, "seconds": 1.2})
    report = run(stack, docker)

    assert check(report, "model_gateway").status == PASS
    assert check(report, "model_ready").status == PASS
    assert check(report, "model_ready").summary == f"{MODEL} answered in 1.2 s"


@pytest.mark.parametrize("answer", [
    None, {"ready": "200"}, {"ready": 200, "model": 200, "body": "x"}, {"ready": True},
    {"ready": 200, "model": 999}, {"model": 200},
])
def test_an_unreadable_gateway_answer_is_a_failure(stack, answer):
    with_gateway(stack)
    docker = GatewayDocker(healthy_core() + healthy_addon() + litellm(), answer=answer)
    report = run(stack, docker)

    assert check(report, "model_gateway").status == FAIL
    assert check(report, "model_gateway").summary == (
        "LiteLLM does not answer inside its container"
    )


def test_a_healthy_installation_has_no_cause(stack):
    report = run(stack, FakeDocker(healthy_core() + healthy_addon()))

    document = json.loads(doctor.to_json(report))
    assert report.exit_code == 0
    assert not any("causes" in c for c in document["checks"])
    assert "->" not in doctor.format_table(report)


def test_every_failing_check_gets_a_sentence():
    report = doctor.DoctorReport("2026-09-27T10:15:00Z", "1.3.0", [
        doctor.CheckResult("network", FAIL, "uplink missing"),
        doctor.CheckResult("cpu", PASS, "fine"),
    ])

    assert report.causes_of(report.checks[0]) == [diagnosis.general("network")]
    assert report.causes_of(report.checks[1]) == []
    assert not list(VALIDATOR.iter_errors(json.loads(doctor.to_json(report))))


def test_a_failure_no_fault_explains_points_at_the_diagnosis_section():
    cause = diagnosis.general("network")

    assert cause.section is None
    assert cause.line() == (
        "Die Prüfung „network“ meldet einen Fehler; die Zeile darüber nennt die Werte. "
        "(siehe Handbuch, Abschnitt Diagnose)"
    )


def test_a_realm_that_could_not_be_compared_is_a_warning(stack):
    module = stack["config"] / "infra" / "keycloak"
    module.mkdir(parents=True)
    (module / ".env").write_text(f"KC_REALM_SYNC_CLIENT_SECRET={SYNC_SECRET}\n",
                                 encoding="utf-8")
    report = run(stack, FakeDocker(healthy_core() + healthy_addon()),
                 realm_check=lambda c, r: (1, "Realm sync skipped: Keycloak did not answer\n"))

    assert check(report, "realm").status == "warn"


def test_the_realm_is_not_compared_while_keycloak_is_down(stack):
    module = stack["config"] / "infra" / "keycloak"
    module.mkdir(parents=True)
    (module / ".env").write_text(f"KC_REALM_SYNC_CLIENT_SECRET={SYNC_SECRET}\n",
                                 encoding="utf-8")
    ps = healthy_core()
    ps[0] = ps_line("papaia-keycloak-1", "exited", "Exited (143) 1 minute ago", "keycloak",
                    "papaia-keycloak", "identity-provider")

    def realm_check(config_dir, repo_root):
        raise AssertionError("must not run")

    report = run(stack, FakeDocker(ps + healthy_addon()), realm_check=realm_check)
    assert check(report, "realm").status == "skip"


def test_sentences_show_no_control_characters():
    cause = diagnosis._realm({"deviations": [
        "fail: client evil\x1b[31m: optional scope aud-flow added",
    ]})
    assert all(ch.isprintable() for c in cause for ch in c.text)


def test_module_names_follow_the_glossary():
    assert diagnosis.module_name("papaia-assist") == "Assistant"
    assert diagnosis.module_name("studio") == "Studio"
    assert diagnosis.module_name("papaia-other") == "other"
    assert diagnosis.scope_module("aud-flow") == "Flow"
    assert diagnosis.scope_module("papaia-person") == "das Modul"
