"""`papaia-ctl doctor`: preflight and diagnostics.

Nothing outside the process is touched. Docker is `FakeDocker`; the disk, the
network, the name resolver and the certificates are stubbed through `Probes`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from stack_helpers import (
    NOW,
    FakeDocker,
    healthy_addon,
    healthy_core,
)

from lib import cli, doctor, status
from lib.doctor import FAIL, PASS, SKIP, WARN, CertReadError, Probes
from lib.status import CommandResult

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "tools" / "schemas" / "doctor.schema.json").read_text("utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

GIB = 1024**3


# ─────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────


def probes(**overrides) -> Probes:
    values = {
        "disk_usage": lambda path: (500 * GIB, 400 * GIB),
        "connect": lambda host, port: False,
        "resolve": lambda host: doctor.RESOLVED,
        "cert_enddate": lambda path, run: NOW + timedelta(days=365),
    }
    values.update(overrides)
    return Probes(**values)


def healthy_docker(**kwargs) -> FakeDocker:
    return FakeDocker(healthy_core() + healthy_addon(), **kwargs)


def run_doctor(stack, docker=None, *, skip=None, **probe_overrides) -> doctor.DoctorReport:
    return doctor.run_checks(
        stack["config"],
        stack["repo"],
        skip=skip,
        run=docker or healthy_docker(),
        probes=probes(**probe_overrides),
        now=NOW,
    )


def result(report: doctor.DoctorReport, name: str) -> doctor.CheckResult:
    return next(c for c in report.checks if c.name == name)


def add_certs(stack, *names: str) -> None:
    certs = stack["config"] / "certs"
    certs.mkdir(exist_ok=True)
    for name in names:
        (certs / name).write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")


def set_env(stack, **values: str) -> None:
    env = stack["config"] / ".env"
    with env.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


# ─────────────────────────────────────────────────────────────────────────
# the report as a whole
# ─────────────────────────────────────────────────────────────────────────


def test_healthy_installation_passes_and_validates(stack):
    add_certs(stack, "local-ca.crt")
    report = run_doctor(stack)

    assert [c.status for c in report.checks] == [
        PASS,  # docker_version
        PASS,  # disk_space
        PASS,  # ports
        SKIP,  # dns: only local hostnames configured
        PASS,  # certs
        PASS,  # addon_compat
        PASS,  # container_health
    ]
    assert report.ok
    assert report.exit_code == 0
    assert not list(VALIDATOR.iter_errors(json.loads(doctor.to_json(report))))


def test_registry_names_are_unique_and_in_the_documented_order():
    assert doctor.CHECK_NAMES == (
        "docker_version",
        "disk_space",
        "ports",
        "dns",
        "certs",
        "addon_compat",
        "container_health",
    )


def test_any_fail_means_exit_2_warnings_and_skips_do_not(stack):
    failing = run_doctor(stack, docker=healthy_docker(engine=CommandResult(1, "", "no daemon")))
    assert failing.exit_code == 2
    assert not failing.ok

    warning_only = run_doctor(stack, disk_usage=lambda path: (500 * GIB, 5 * GIB))  # warn, not fail
    assert result(warning_only, "disk_space").status == WARN
    assert warning_only.exit_code == 0


def test_summary_counts_every_status(stack):
    report = run_doctor(stack, docker=healthy_docker(engine=CommandResult(1, "", "x")))

    counts = report.summary
    assert sum(counts.values()) == len(doctor.CHECKS)
    assert counts[FAIL] >= 1


def test_a_crashing_check_is_reported_not_raised(stack):
    def explode(path):
        raise RuntimeError("boom")

    report = run_doctor(stack, disk_usage=explode)

    crashed = result(report, "disk_space")
    assert crashed.status == FAIL
    assert crashed.summary == "check crashed: RuntimeError: boom"
    # the other checks still ran
    assert result(report, "docker_version").status == PASS
    assert report.exit_code == 2


# ─────────────────────────────────────────────────────────────────────────
# --skip
# ─────────────────────────────────────────────────────────────────────────


def test_skip_marks_checks_without_running_them(stack):
    docker = healthy_docker()
    report = run_doctor(stack, docker=docker, skip=["docker_version", "container_health"])

    assert result(report, "docker_version").status == SKIP
    assert result(report, "docker_version").summary == "skipped (--skip)"
    assert result(report, "container_health").status == SKIP
    assert not any(c[:2] == ["docker", "version"] for c in docker.calls)


def test_skip_rejects_unknown_names_and_lists_the_valid_ones(stack):
    with pytest.raises(doctor.DoctorError, match="nope.*Valid: docker_version"):
        run_doctor(stack, skip=["dns", "nope"])


def test_skip_accepts_comma_free_names_with_whitespace():
    assert doctor.parse_skip([" dns ", "certs"]) == ["dns", "certs"]
    assert doctor.parse_skip(None) == []


# ─────────────────────────────────────────────────────────────────────────
# docker_version
# ─────────────────────────────────────────────────────────────────────────


def test_docker_version_reports_engine_and_compose(stack):
    check = result(run_doctor(stack), "docker_version")

    assert check.status == PASS
    assert check.summary == "Docker Engine 27.0.3, Compose 2.29.1"
    assert check.details == {"engine": "27.0.3", "compose": "2.29.1", "min_compose": "2.20.0"}


def test_compose_older_than_the_minimum_fails(stack):
    docker = healthy_docker(compose=CommandResult(0, "2.19.1\n", ""))
    check = result(run_doctor(stack, docker=docker), "docker_version")

    assert check.status == FAIL
    assert "2.19.1" in check.summary and "2.20.0" in check.summary


@pytest.mark.parametrize("output", ["v2.29.1\n", "v2.29.1-desktop.1\n", "2.20.0\n"])
def test_compose_version_spellings_are_accepted(stack, output):
    docker = healthy_docker(compose=CommandResult(0, output, ""))

    assert result(run_doctor(stack, docker=docker), "docker_version").status == PASS


def test_unreadable_compose_version_is_a_warning(stack):
    docker = healthy_docker(compose=CommandResult(0, "dev\n", ""))

    assert result(run_doctor(stack, docker=docker), "docker_version").status == WARN


def test_missing_compose_plugin_fails(stack):
    docker = healthy_docker(compose=CommandResult(1, "", "unknown command"))
    check = result(run_doctor(stack, docker=docker), "docker_version")

    assert check.status == FAIL
    assert "Compose" in check.summary


def test_unreachable_daemon_and_missing_binary_fail_differently(stack):
    daemon = healthy_docker(engine=CommandResult(1, "", "Cannot connect to the Docker daemon"))
    missing = healthy_docker(engine=CommandResult(127, "", "docker: command not found"))

    assert "not reachable" in result(run_doctor(stack, docker=daemon), "docker_version").summary
    assert "not found" in result(run_doctor(stack, docker=missing), "docker_version").summary


# ─────────────────────────────────────────────────────────────────────────
# disk_space
# ─────────────────────────────────────────────────────────────────────────


def test_disk_space_measures_config_dir_and_backup_dir_in_bytes(stack, tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    set_env(stack, PAPAIA_BACKUP_DIR=str(backup_dir))
    seen: list[Path] = []

    def usage(path):
        seen.append(path)
        return (500 * GIB, 123 * GIB)

    check = result(run_doctor(stack, disk_usage=usage), "disk_space")

    assert check.status == PASS
    assert {Path(p["path"]) for p in check.details["paths"]} == {stack["config"], backup_dir}
    assert all(p["free_bytes"] == 123 * GIB for p in check.details["paths"])
    assert all(p["total_bytes"] == 500 * GIB for p in check.details["paths"])


@pytest.mark.parametrize(
    ("free_gib", "expected"),
    [(400, PASS), (10, PASS), (9, WARN), (2, WARN), (1, FAIL), (0, FAIL)],
)
def test_disk_space_thresholds(stack, free_gib, expected):
    check = result(
        run_doctor(stack, disk_usage=lambda p: (500 * GIB, free_gib * GIB)), "disk_space"
    )

    assert check.status == expected


def test_disk_space_reports_the_worst_path(stack, tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    set_env(stack, PAPAIA_BACKUP_DIR=str(backup_dir))

    def usage(path):
        return (500 * GIB, 1 * GIB if path == backup_dir else 300 * GIB)

    check = result(run_doctor(stack, disk_usage=usage), "disk_space")

    assert check.status == FAIL
    assert "backup_dir" in check.summary


def test_disk_space_uses_the_nearest_existing_parent_before_setup(tmp_path, stack):
    missing = tmp_path / "not" / "yet" / "there"
    measured: list[Path] = []

    def usage(path):
        measured.append(path)
        return (500 * GIB, 400 * GIB)

    doctor.run_checks(
        missing, stack["repo"], run=healthy_docker(), probes=probes(disk_usage=usage), now=NOW
    )

    assert tmp_path in measured


def test_docker_data_root_is_measured_when_the_host_can_see_it(stack, tmp_path):
    root = tmp_path / "docker-root"
    root.mkdir()
    docker = healthy_docker(root_dir=str(root))
    check = result(run_doctor(stack, docker=docker), "disk_space")

    assert "docker_root" in {p["label"] for p in check.details["paths"]}


def test_docker_data_root_inside_a_vm_is_skipped_with_a_note(stack):
    docker = healthy_docker(root_dir="/var/lib/docker-in-a-vm-that-is-not-here")
    check = result(run_doctor(stack, docker=docker), "disk_space")

    assert "docker_root" not in {p["label"] for p in check.details["paths"]}
    assert any("docker_root" in note for note in check.details["notes"])


# ─────────────────────────────────────────────────────────────────────────
# ports
# ─────────────────────────────────────────────────────────────────────────


def test_ports_are_taken_from_the_compose_files_and_the_env(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", HOST_IP="0.0.0.0")
    probed: list[tuple[str, int]] = []

    def connect(host, port):
        probed.append((host, port))
        return False

    check = result(run_doctor(stack, connect=connect), "ports")

    assert check.status == PASS
    assert probed == [("127.0.0.1", 8110)]
    assert check.details["ports"][0]["services"] == ["keycloak"]


def test_a_port_held_by_this_installation_is_fine(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110")
    check = result(run_doctor(stack, connect=lambda host, port: port == 8110), "ports")

    assert check.status == PASS
    assert check.details["ports"][0]["holder"] == "papaia-keycloak-1"
    assert "held" in check.summary


def test_a_port_held_by_something_else_fails(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="9999")  # not the port our container publishes
    check = result(run_doctor(stack, connect=lambda host, port: port == 9999), "ports")

    assert check.status == FAIL
    assert "9999" in check.summary and "keycloak" in check.summary


def test_a_busy_port_is_only_a_warning_when_docker_cannot_say_whose_it_is(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110")
    docker = healthy_docker(ps_result=CommandResult(1, "", "no daemon"))
    check = result(run_doctor(stack, docker=docker, connect=lambda host, port: True), "ports")

    assert check.status == WARN


def test_a_fixed_bind_address_in_the_compose_file_is_the_one_probed(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", HOST_IP="192.0.2.10")
    stack_repo_compose = stack["repo"] / "src" / "infra" / "keycloak" / "docker-compose.yml"
    stack_repo_compose.write_text(
        stack_repo_compose.read_text(encoding="utf-8").replace("${HOST_IP:-0.0.0.0}", "127.0.0.1"),
        encoding="utf-8",
    )
    probed: list[str] = []
    result(run_doctor(stack, connect=lambda host, port: probed.append(host) or False), "ports")

    assert probed == ["127.0.0.1"]


def test_unresolvable_port_variables_are_ignored(stack):
    # KEYCLOAK_EXT_PORT is not set anywhere: the entry cannot be resolved.
    (stack["config"] / ".env").write_text(
        "COMPOSE_PROJECT_NAME=papaia\nCOMPOSE_PROFILES=keycloak\n", encoding="utf-8"
    )
    check = result(run_doctor(stack), "ports")

    assert check.status == SKIP
    assert "no published ports" in check.summary


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("80:80", ("", 80)),
        ("0.0.0.0:8110:8443", ("0.0.0.0", 8110)),
        ("127.0.0.1:8181:81", ("127.0.0.1", 8181)),
        ("${HOST_IP:-0.0.0.0}:${P}:3080", ("0.0.0.0", 8000)),
        ("8000:8000/udp", ("", 8000)),
        ("8080", None),  # ephemeral host port
        ("8000-8002:8000-8002", None),  # range
        ("${UNSET}:3080", None),
    ],
)
def test_published_host_port_parsing(entry, expected):
    assert doctor._published_host_port(entry, {"P": "8000"}) == expected


# ─────────────────────────────────────────────────────────────────────────
# dns
# ─────────────────────────────────────────────────────────────────────────


def test_public_hostnames_are_looked_up(stack):
    set_env(
        stack, PAPAIA_HOST="https://papaia.example.org", AUTH_HOST="https://auth.example.org:8110"
    )
    asked: list[str] = []

    def resolve(host):
        asked.append(host)
        return doctor.RESOLVED

    check = result(run_doctor(stack, resolve=resolve), "dns")

    assert check.status == PASS
    assert asked == ["papaia.example.org", "auth.example.org"]


def test_a_name_that_does_not_resolve_is_a_warning(stack):
    set_env(stack, PAPAIA_HOST="https://gone.example.org")
    check = result(run_doctor(stack, resolve=lambda host: doctor.NOT_FOUND), "dns")

    assert check.status == WARN
    assert "gone.example.org" in check.summary


def test_an_unreachable_resolver_skips_instead_of_warning(stack):
    set_env(stack, PAPAIA_HOST="https://papaia.example.org")
    check = result(run_doctor(stack, resolve=lambda host: doctor.UNAVAILABLE), "dns")

    assert check.status == SKIP
    assert "offline" in check.summary


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://host.docker.internal",
        "http://127.0.0.1:8080",
        "http://192.168.1.10",
        "http://papaia",  # single label
        "http://[::1]:8000",
        "",
    ],
)
def test_local_names_are_not_looked_up(url):
    assert doctor._public_hostname(url) is None


def test_only_hostnames_of_active_profiles_are_checked(stack):
    set_env(stack, LITELLM_PUBLIC_URL="https://litellm.example.org")  # litellm is not active
    asked: list[str] = []
    run_doctor(stack, resolve=lambda host: asked.append(host) or doctor.RESOLVED)

    assert "litellm.example.org" not in asked


def test_the_external_oidc_issuer_is_checked_for_external_oidc(stack):
    set_env(stack, AUTH_PROVIDER="external_oidc", OIDC_ISSUER="https://idp.example.org/realms/x")
    asked: list[str] = []
    run_doctor(stack, resolve=lambda host: asked.append(host) or doctor.RESOLVED)

    assert asked == ["idp.example.org"]


# ─────────────────────────────────────────────────────────────────────────
# certs
# ─────────────────────────────────────────────────────────────────────────


def _cert_days(days_by_name: dict[str, int]):
    def enddate(path, run):
        return NOW + timedelta(days=days_by_name[path.name], hours=1)

    return enddate


def test_certs_report_days_until_expiry(stack):
    add_certs(stack, "local-ca.crt", "keycloak.crt")
    check = result(
        run_doctor(stack, cert_enddate=_cert_days({"local-ca.crt": 3000, "keycloak.crt": 200})),
        "certs",
    )

    assert check.status == PASS
    assert "certs/keycloak.crt expires in 200 day(s)" in check.summary
    days = {c["path"]: c["days_left"] for c in check.details["certificates"]}
    assert days == {"certs/keycloak.crt": 200, "certs/local-ca.crt": 3000}


@pytest.mark.parametrize(
    ("days", "expected"),
    [(365, PASS), (30, PASS), (29, WARN), (7, WARN), (6, FAIL), (0, FAIL), (-3, FAIL)],
)
def test_cert_thresholds(stack, days, expected):
    add_certs(stack, "keycloak.crt")
    check = result(run_doctor(stack, cert_enddate=_cert_days({"keycloak.crt": days})), "certs")

    assert check.status == expected


def test_an_expired_certificate_says_so(stack):
    add_certs(stack, "keycloak.crt")
    check = result(run_doctor(stack, cert_enddate=_cert_days({"keycloak.crt": -3})), "certs")

    assert "expired 3 day(s) ago" in check.summary


def test_lets_encrypt_certificates_on_disk_are_included(stack):
    live = stack["config"] / "infra" / "nginx" / "nginx-letsencrypt" / "live" / "npm-1"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    check = result(
        run_doctor(stack, cert_enddate=lambda path, run: NOW + timedelta(days=12)), "certs"
    )

    assert check.status == WARN
    assert check.details["certificates"][0]["path"].endswith("live/npm-1/fullchain.pem")


def test_no_certificates_means_skip(stack):
    assert result(run_doctor(stack), "certs").status == SKIP


def test_unreadable_certificates_skip_the_check_with_the_reason(stack):
    add_certs(stack, "keycloak.crt")

    def broken(path, run):
        raise CertReadError("openssl not found")

    check = result(run_doctor(stack, cert_enddate=broken), "certs")

    assert check.status == SKIP
    assert "openssl not found" in check.summary


def test_cert_enddate_parses_openssl_output():
    def run(cmd, timeout):
        assert cmd[:2] == ["openssl", "x509"]
        return CommandResult(0, "notAfter=Sep  7 10:15:00 2036 GMT\n", "")

    assert doctor._cert_enddate(Path("x.crt"), run) == datetime(
        2036, 9, 7, 10, 15, tzinfo=NOW.tzinfo
    )


def test_cert_enddate_reports_missing_openssl_and_bad_files():
    with pytest.raises(CertReadError, match="openssl not found"):
        doctor._cert_enddate(Path("x"), lambda cmd, t: CommandResult(127, "", "not found"))
    with pytest.raises(CertReadError, match="unable to load certificate"):
        doctor._cert_enddate(
            Path("x"), lambda cmd, t: CommandResult(1, "", "unable to load certificate\n")
        )
    with pytest.raises(CertReadError, match="unexpected date format"):
        doctor._cert_enddate(
            Path("x"), lambda cmd, t: CommandResult(0, "notAfter=tomorrow-ish\n", "")
        )


# ─────────────────────────────────────────────────────────────────────────
# addon_compat
# ─────────────────────────────────────────────────────────────────────────


def test_compatible_addons_pass(stack):
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == PASS
    assert check.details["addons"][0]["compat_status"] == "OK"


def test_incompatible_addon_fails_in_enforce_mode(stack):
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == FAIL
    assert "paperless: INCOMPATIBLE" in check.summary


def test_incompatible_addon_is_a_warning_in_warn_mode(stack, monkeypatch):
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    monkeypatch.setenv("PAPAIA_COMPAT_MODE", "warn")
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == WARN
    assert check.details["mode"] == "warn"


def test_addon_without_a_requirement_is_unknown_and_warns(stack):
    (stack["addon"] / "papaia-app.yaml").write_text("name: paperless\n", encoding="utf-8")

    assert result(run_doctor(stack), "addon_compat").status == WARN


def test_addon_with_a_missing_manifest_is_an_error_and_fails(stack):
    (stack["addon"] / "papaia-app.yaml").unlink()
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == FAIL
    assert "ERROR" in check.summary


def test_addon_compat_gives_the_verdict_addon_check_gives(stack, capsys):
    """Folded in, not duplicated: both go through evaluate_active_addons."""
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    code = cli.main(
        [
            "--repo-root",
            str(stack["repo"]),
            "--config-dir",
            str(stack["config"]),
            "addon-check",
            "--json",
        ]
    )
    verdict = json.loads(capsys.readouterr().out)[0]

    check = result(run_doctor(stack), "addon_compat")
    assert (code, verdict["status"]) == (2, "INCOMPATIBLE")
    assert check.details["addons"][0]["compat_status"] == verdict["status"]
    assert check.details["addons"][0]["reason"] == verdict["reason"]


def test_no_active_addons_passes(stack):
    deployment_file = stack["config"] / "deployment.yaml"
    deployment_file.write_text("addons: []\n", encoding="utf-8")

    assert result(run_doctor(stack), "addon_compat").status == PASS


# ─────────────────────────────────────────────────────────────────────────
# container_health
# ─────────────────────────────────────────────────────────────────────────


def test_unhealthy_and_stopped_modules_fail(stack):
    live = [
        line.replace("Up 2 hours (healthy)", "Up 2 hours (unhealthy)", 1) for line in healthy_core()
    ]
    check = result(run_doctor(stack, docker=FakeDocker(live + healthy_addon())), "container_health")

    assert check.status == FAIL
    assert "keycloak (unhealthy)" in check.summary


def test_a_never_started_module_is_only_a_warning(stack):
    live = [line for line in healthy_core() if "oauth2-proxy" not in line]
    check = result(run_doctor(stack, docker=FakeDocker(live + healthy_addon())), "container_health")

    assert check.status == WARN
    assert "auth (missing)" in check.summary


def test_docker_unreachable_is_a_warning_not_an_outage(stack):
    docker = healthy_docker(ps_result=CommandResult(1, "", "Cannot connect to the Docker daemon"))
    check = result(run_doctor(stack, docker=docker), "container_health")

    assert check.status == WARN
    assert "unknown" in check.summary


def test_container_health_reuses_one_status_reading(stack):
    docker = healthy_docker()
    run_doctor(stack, docker=docker)

    assert sum(1 for c in docker.calls if c[:3] == ["docker", "ps", "-a"]) == 1


# ─────────────────────────────────────────────────────────────────────────
# before setup, and read-only
# ─────────────────────────────────────────────────────────────────────────


def test_doctor_works_before_setup(tmp_path, stack):
    nowhere = tmp_path / "never-set-up"
    report = doctor.run_checks(
        nowhere, stack["repo"], run=healthy_docker(), probes=probes(), now=NOW
    )

    by_name = {c.name: c.status for c in report.checks}
    assert by_name["docker_version"] == PASS
    assert by_name["disk_space"] == PASS
    assert by_name["ports"] == SKIP
    assert by_name["dns"] == SKIP
    assert by_name["certs"] == SKIP
    assert by_name["addon_compat"] == SKIP
    assert by_name["container_health"] == SKIP
    assert report.exit_code == 0
    assert not nowhere.exists()


def _tree_state(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_doctor_writes_nothing(stack, tmp_path):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", PAPAIA_HOST="https://papaia.example.org")
    add_certs(stack, "local-ca.crt")
    before = _tree_state(tmp_path)
    docker = healthy_docker()
    run_doctor(stack, docker=docker)

    assert _tree_state(tmp_path) == before
    allowed = {
        ("docker", "ps"),
        ("docker", "inspect"),
        ("docker", "version"),
        ("docker", "compose"),
        ("docker", "info"),
    }
    assert {tuple(c[:2]) for c in docker.calls} <= allowed


# ─────────────────────────────────────────────────────────────────────────
# output and CLI
# ─────────────────────────────────────────────────────────────────────────


def test_table_lists_every_check_and_a_summary_line(stack):
    table = doctor.format_table(run_doctor(stack))

    for name in doctor.CHECK_NAMES:
        assert name in table
    assert table.splitlines()[-1].endswith("skip")
    assert "pass," in table.splitlines()[-1]


def test_json_carries_what_the_table_shows(stack):
    report = run_doctor(stack)
    document = json.loads(doctor.to_json(report))

    assert [c["name"] for c in document["checks"]] == list(doctor.CHECK_NAMES)
    assert document["summary"] == report.summary
    assert document["ok"] is True
    table = doctor.format_table(report)
    for check in document["checks"]:
        assert check["summary"] in table


def _run_cli(stack, monkeypatch, docker, *args):
    monkeypatch.setattr(status, "run_command", docker)
    monkeypatch.setattr(doctor, "Probes", lambda: probes())
    return cli.main(
        ["--repo-root", str(stack["repo"]), "--config-dir", str(stack["config"]), "doctor", *args]
    )


def test_cli_exit_code_and_json_for_a_healthy_installation(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, healthy_docker(), "--json")

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["ok"] is True


def test_cli_exits_2_when_a_check_fails(stack, monkeypatch, capsys):
    docker = healthy_docker(engine=CommandResult(1, "", "no daemon"))
    code = _run_cli(stack, monkeypatch, docker, "--json")

    document = json.loads(capsys.readouterr().out)
    assert code == 2
    assert document["ok"] is False
    assert document["summary"]["fail"] >= 1


def test_cli_skip_flag_accepts_repeated_and_comma_separated_values(stack, monkeypatch, capsys):
    code = _run_cli(
        stack, monkeypatch, healthy_docker(), "--json", "--skip=dns,certs", "--skip=ports"
    )

    statuses = {c["name"]: c["summary"] for c in json.loads(capsys.readouterr().out)["checks"]}
    assert code == 0
    assert [n for n, s in statuses.items() if s == "skipped (--skip)"] == ["ports", "dns", "certs"]


def test_cli_unknown_skip_name_exits_2_with_the_valid_names_on_stderr(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, healthy_docker(), "--skip=nope")

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "nope" in captured.err and "docker_version" in captured.err
