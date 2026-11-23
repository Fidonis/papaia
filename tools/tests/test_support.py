"""`papaia-ctl logs`, `support-bundle` and `metrics` (BE-27, EXK-PLT-68-A2, EXI-PLT-64-A3).

Docker is a fake that also answers `docker logs`. The bundle test plants the
installation's secrets, token and key patterns, mail addresses and a person identifier
in configuration and logs, then searches the written archive for each of them: zero hits.
"""

from __future__ import annotations

import io
import json
import re
import stat
import tarfile
from datetime import timedelta
from pathlib import Path

import pytest
from stack_helpers import NOW, FakeDocker, healthy_addon, healthy_core
from test_doctor import probes

from lib import cli, doctor, status, support
from lib.status import CommandResult

CID = "0f3c2a1e-6b7d-4e8f-9a0b-1c2d3e4f5a6b"
# Test values only: generated for this file, used nowhere else.
ADMIN_PASSWORD = "Kc-admin-Test-Value-7781"  # noqa: S105
SYNC_SECRET = "realm-sync-secret-test-4410"  # noqa: S105
# Token and key shapes are put together at run time, so that no scanner reads this file as
# holding one: a JWT shape whose parts are plain words, and a key block around filler.
JWT = ".".join(
    ["eyJ" + "hbGciOiJSUzI1NiJ9", "eyJ" + "zdWIiOiJhbm5hIiwiZXhwIjoxfQ", "testsignatureonly"]
)
AGE_KEY = "AGE-SECRET-KEY-1" + "Q" * 58
_BLOCK = "PRIVATE " + "KEY"
PEM = f"-----BEGIN {_BLOCK}-----\n" + "A" * 48 + f"\n-----END {_BLOCK}-----"
MAIL = "anna.beispiel@example.org"
SUB = "7d1b6c52-0a3e-4b4f-8a8e-2f0e7a1c9b31"


class LogDocker(FakeDocker):
    """FakeDocker that also answers `docker logs` and `docker ps --format names/images`."""

    def __init__(self, ps, logs: dict[str, str], **kwargs):
        super().__init__(ps, **kwargs)
        self.logs = logs

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        if cmd[:2] == ["docker", "logs"]:
            self.calls.append(cmd)
            return CommandResult(0, self.logs.get(cmd[-1], ""), "")
        if cmd[:3] == ["docker", "ps", "-a"] and "{{.Names}}\t{{.Image}}" in cmd:
            self.calls.append(cmd)
            return CommandResult(0, "papaia-keycloak-1\tquay.io/keycloak/keycloak@sha256:"
                                 + "a" * 64 + "\n", "")
        if cmd[:3] == ["docker", "version", "--format"]:
            return CommandResult(0, "27.0.3\n", "")
        return super().__call__(cmd, timeout)


LOGS = {
    "papaia-keycloak-1": (
        f"2026-09-27T10:00:02.000000001Z {{\"level\":\"info\",\"correlation_id\":\"{CID}\","
        "\"msg\":\"token issued\"}\n"
        "2026-09-27T10:00:00.5Z started\n"
    ),
    "papaia-keycloak-db-1": (
        f"2026-09-27T10:00:01Z checkpoint X-Papaia-Correlation-Id={CID}\n"
    ),
}


def make_docker(logs=None) -> LogDocker:
    return LogDocker(healthy_core() + healthy_addon(), logs if logs is not None else LOGS)


def report_of(stack, docker) -> status.StatusReport:
    return status.collect(stack["config"], stack["repo"], include_addons=True, run=docker,
                          now=NOW)


# ─── logs ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("target", ["papaia-keycloak", "keycloak"])
def test_logs_of_a_module_merge_every_container_in_time_order(stack, target):
    docker = make_docker()
    found = support.resolve(report_of(stack, docker), target)

    assert {s.service for s in found} == {"keycloak", "keycloak-db"}
    lines = support.format_entries(support.collect(docker, found, since="30m", lines=50))
    assert lines == [
        "2026-09-27T10:00:00.5Z keycloak    - started",
        f"2026-09-27T10:00:01Z keycloak-db {CID} checkpoint X-Papaia-Correlation-Id={CID}",
        f"2026-09-27T10:00:02.000000001Z keycloak    {CID} "
        f"{{\"level\":\"info\",\"correlation_id\":\"{CID}\",\"msg\":\"token issued\"}}",
    ]
    asked = [c for c in docker.calls if c[:2] == ["docker", "logs"]]
    assert all(c[2:7] == ["--timestamps", "--tail", "50", "--since", "30m"] for c in asked)


def test_logs_of_one_service_and_of_an_addon(stack):
    report = report_of(stack, make_docker())

    assert [s.container for s in support.resolve(report, "keycloak-db")] == [
        "papaia-keycloak-db-1"
    ]
    assert {s.service for s in support.resolve(report, "paperless")} == {
        "paperless", "paperless-db"
    }


def test_logs_name_the_known_targets_for_an_unknown_one(stack):
    with pytest.raises(support.SupportError, match="Known: .*keycloak"):
        support.resolve(report_of(stack, make_docker()), "nothing")


@pytest.mark.parametrize("raw", ["", "Keycloak", "../etc", "a" * 65, "-f", "x y"])
def test_logs_refuse_a_name_that_is_not_one(raw):
    with pytest.raises(support.SupportError):
        support.check_target(raw)


@pytest.mark.parametrize("raw", ["10x", "yesterday", "2026-09-27 10:00", "1;rm"])
def test_logs_refuse_a_since_docker_would_not_take(raw):
    with pytest.raises(support.SupportError):
        support.check_since(raw)


@pytest.mark.parametrize("raw", ["30m", "2h", "2026-09-27", "2026-09-27T10:15:00Z"])
def test_logs_take_a_duration_or_a_date(raw):
    assert support.check_since(raw) == raw


@pytest.mark.parametrize("raw", ["0", "10001", "x"])
def test_line_count_is_bounded(raw):
    with pytest.raises(support.SupportError):
        support.check_lines(raw)


def test_logs_command_prints_the_merged_lines(stack, monkeypatch, capsys):
    docker = make_docker()
    monkeypatch.setattr(status, "run_command", docker)
    code = cli.main(["--repo-root", str(stack["repo"]), "--config-dir", str(stack["config"]),
                     "logs", "--", "keycloak"])

    assert code == 0
    assert capsys.readouterr().out.splitlines()[0].endswith("keycloak    - started")


# ─── support bundle ──────────────────────────────────────────────────────


def plant(stack) -> None:
    """The installation's secrets in its configuration."""
    keycloak = stack["config"] / "infra" / "keycloak"
    keycloak.mkdir(parents=True, exist_ok=True)
    (keycloak / ".env").write_text(
        f"KC_ADMIN_PASSWORD={ADMIN_PASSWORD}\nKC_REALM_SYNC_CLIENT_SECRET={SYNC_SECRET}\n"
        "KC_HOSTNAME_URL=https://auth.example.org\n",
        encoding="utf-8",
    )


LEAKY_LOGS = {
    "papaia-keycloak-1": (
        f"2026-09-27T10:00:00Z login admin password={ADMIN_PASSWORD}\n"
        f"2026-09-27T10:00:01Z Authorization: Bearer {JWT}\n"
        f"2026-09-27T10:00:02Z {{\"sub\":\"{SUB}\",\"email\":\"{MAIL}\"}}\n"
        f"2026-09-27T10:00:03Z key {AGE_KEY}\n"
        f"2026-09-27T10:00:04Z {PEM}\n"
        f"2026-09-27T10:00:05Z sync with {SYNC_SECRET} ok\n"
    ),
    "paperless-paperless-1": f"2026-09-27T10:00:06Z token {JWT} for {MAIL}\n",
}
PLANTED = (ADMIN_PASSWORD, SYNC_SECRET, JWT, AGE_KEY, f"BEGIN {_BLOCK}", MAIL, SUB)


def read_archive(path: Path) -> dict[str, str]:
    with tarfile.open(path, "r:gz") as tar:
        return {
            m.name.split("/", 1)[1]: tar.extractfile(m).read().decode("utf-8")
            for m in tar.getmembers() if m.isfile()
        }


def make_bundle(stack, docker, **kwargs):
    report = doctor.run_checks(stack["config"], stack["repo"], run=docker, probes=probes(),
                               now=NOW)
    return support.bundle(stack["config"], stack["repo"], run=docker, now=NOW,
                          doctor_report=report, **kwargs)


def test_the_bundle_holds_status_versions_config_and_logs_without_secrets(stack):
    plant(stack)
    path, correlation_id = make_bundle(stack, make_docker(LEAKY_LOGS))

    assert path == stack["config"] / "support" / "papaia-support-20260927T101500Z.tar.gz"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    files = read_archive(path)
    assert {"doctor.json", "status.json", "versions.json", "bom.yaml", "config.txt",
            "logs/papaia/keycloak.log", "logs/paperless/paperless.log"} <= set(files)
    raw = path.read_bytes()
    everything = "\n".join(files.values())
    for planted in PLANTED:
        assert planted not in everything, planted
        assert planted.encode() not in raw
    assert re.search(r"^KC_ADMIN_PASSWORD=(\(set\)|\[redacted\])$", files["config.txt"], re.M)
    assert "KC_HOSTNAME_URL=https://auth.example.org" in files["config.txt"]
    assert "login admin password=[redacted]" in files["logs/papaia/keycloak.log"]
    json.loads(files["doctor.json"])
    versions = json.loads(files["versions.json"])
    assert versions["platform_version"] == "1.3.0"
    assert "sha256:" + "a" * 64 in versions["containers"]["papaia-keycloak-1"], (
        "an image digest is not a secret"
    )
    rows = (stack["config"] / "audit" / "outbox" / "papaia-ctl.jsonl").read_text().splitlines()
    row = json.loads(rows[-1])
    assert row["correlation_id"] == correlation_id
    assert row["writer"] == support.WRITER
    assert (row["result"], row["effect"], row["event"]) == ("allowed", "write", "operation")
    assert row["object_ref"] == {"type": "support_bundle", "id": path.name}


def test_a_secret_that_survives_the_masking_stops_the_bundle(stack, monkeypatch):
    plant(stack)
    monkeypatch.setattr(support, "mask", lambda text, secrets: text)

    with pytest.raises(support.LeakError, match="nothing was written") as caught:
        make_bundle(stack, make_docker(LEAKY_LOGS))

    assert ADMIN_PASSWORD not in str(caught.value), "the message names kinds, not values"
    assert not (stack["config"] / "support").exists()
    row = json.loads((stack["config"] / "audit" / "outbox" / "papaia-ctl.jsonl")
                     .read_text().splitlines()[-1])
    assert (row["result"], row["error_code"]) == ("error", "secret_found")


def test_the_bundle_never_replaces_a_file(stack, tmp_path):
    out = tmp_path / "case.tar.gz"
    out.write_bytes(b"keep")

    with pytest.raises(support.SupportError, match="exists already"):
        make_bundle(stack, make_docker(), out=str(out))
    assert out.read_bytes() == b"keep"


@pytest.mark.parametrize("out", ["case.zip", "/no/such/folder/case.tar.gz"])
def test_the_bundle_path_is_checked(stack, out):
    with pytest.raises(support.SupportError):
        support.check_out(out, stack["config"], NOW)


def test_the_bundle_takes_the_last_lines_of_every_container(stack):
    docker = make_docker()
    make_bundle(stack, docker, lines=1000)

    asked = [c for c in docker.calls if c[:2] == ["docker", "logs"]]
    containers = {c[-1] for c in asked}
    assert {"papaia-keycloak-1", "papaia-keycloak-db-1", "paperless-paperless-1"} <= containers
    assert all(c[2:5] == ["--timestamps", "--tail", "1000"] for c in asked)


def test_masking_keeps_ordinary_text():
    text = "2026-09-27T10:00:00Z GET /api/v1/things 200 in 12 ms (papaia-keycloak-1)"
    assert support.mask(text, ["unrelated-secret"]) == text


# ─── metrics ─────────────────────────────────────────────────────────────


def test_metrics_are_prometheus_text_without_a_person(stack):
    certs = stack["config"] / "certs"
    certs.mkdir()
    (certs / "edge.example.org.crt").write_text("x", encoding="utf-8")
    report = doctor.run_checks(
        stack["config"], stack["repo"], run=FakeDocker(healthy_core() + healthy_addon()),
        probes=probes(cert_enddate=lambda p, r: NOW + timedelta(days=40)), now=NOW,
    )
    text = support.metrics(report, stack["config"], NOW)

    assert 'papaia_certificate_days_left{file="certs/edge.example.org.crt"} 40' in text
    assert 'papaia_check_status{check="certs"} 0' in text
    assert "papaia_metrics_generated_timestamp_seconds " in text
    sample = re.compile(r'^[a-z_]+(\{[a-z_]+="[A-Za-z0-9._/:-]*"(,[a-z_]+="[A-Za-z0-9._/:-]*")*\})?'
                        r" -?\d+(\.\d+)?$")
    for line in text.splitlines():
        if line.startswith("#"):
            assert re.match(r"^# (HELP|TYPE) papaia_[a-z_]+ ", line)
        else:
            assert sample.match(line), line
    assert "@" not in text
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-", text), "no person identifier"


def test_metrics_carry_the_backup_age(stack, tmp_path):
    target = tmp_path / "backups"
    target.mkdir()
    (target / "backup.yaml").write_text(
        "version: 1\nbackups:\n- {id: a, created_at: '2026-09-27T08:15:00Z', result: ok}\n"
        "- {id: b, created_at: '2026-09-27T09:15:00Z', result: failed}\n",
        encoding="utf-8",
    )
    with (stack["config"] / ".env").open("a", encoding="utf-8") as env:
        env.write(f"PAPAIA_BACKUP_DIR={target}\n")
    report = doctor.DoctorReport("2026-09-27T10:15:00Z", "1.3.0", [])

    assert "papaia_backup_last_ok_age_seconds 7200.0" in support.metrics(
        report, stack["config"], NOW)


def test_metrics_file_is_replaced_whole(tmp_path):
    out = tmp_path / "papaia.prom"
    support.write_metrics(str(out), "a 1\n")
    assert out.read_text() == "a 1\n"
    with pytest.raises(support.SupportError):
        support.write_metrics(str(tmp_path / "papaia.txt"), "a 1\n")


def test_archive_members_are_private(stack):
    data = support.archive({"a.txt": "x"}, stamp=NOW)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.getmembers()[0]
    assert member.name == "papaia-support-20260927T101500Z/a.txt"
    assert member.mode == 0o600
