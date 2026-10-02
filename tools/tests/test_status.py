"""`papaia-ctl status`: declared state next to what Docker reports.

Docker is never touched: every test hands `collect()` a fake runner that
answers `docker ps -a` / `docker inspect` with canned text. The Compose trees
are built in tmp_path, because the shared `fixtures/repo` carries no
`de.fidonis.*` labels and is pinned by test_contract_surface.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from stack_helpers import (
    NOW,
    PROJECT,
    FakeDocker,
    healthy_addon,
    healthy_core,
    ps_line,
)

from lib import cli, status
from lib.status import CommandResult, Health

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "tools" / "schemas" / "status.schema.json").read_text("utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

# ─────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────


def collect(stack, docker, **kwargs):
    return status.collect(stack["config"], stack["repo"], run=docker, now=NOW, **kwargs)


def by_name(report: status.StatusReport) -> dict[str, status.Module]:
    return {m.name: m for m in report.modules}


def assert_schema_valid(report: status.StatusReport) -> None:
    errors = sorted(VALIDATOR.iter_errors(json.loads(status.to_json(report))), key=str)
    assert not errors, "\n".join(e.message for e in errors)


# ─────────────────────────────────────────────────────────────────────────
# health derivation
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("state", "text", "expected"),
    [
        ("running", "Up 2 hours (healthy)", Health.HEALTHY),
        ("running", "Up 2 hours", Health.HEALTHY),  # no healthcheck defined
        ("running", "Up 2 hours (unhealthy)", Health.UNHEALTHY),
        ("running", "Up 3 seconds (health: starting)", Health.STARTING),
        ("created", "Created", Health.STARTING),
        ("restarting", "Restarting (1) 4 seconds ago", Health.UNHEALTHY),
        ("exited", "Exited (0) 2 days ago", Health.COMPLETED),
        ("exited", "Exited (137) 2 days ago", Health.STOPPED),
        ("exited", "something unexpected", Health.STOPPED),
        ("paused", "Up 1 hour (Paused)", Health.STOPPED),
        ("dead", "Dead", Health.STOPPED),
        ("removing", "Removal In Progress", Health.STOPPED),
        ("mystery", "?", Health.UNKNOWN),
    ],
)
def test_derive_health(state, text, expected):
    assert status.derive_health(state, text) is expected


def test_worst_ignores_completed_one_shots_and_empty_is_unknown():
    assert status.worst([Health.COMPLETED, Health.HEALTHY]) is Health.HEALTHY
    assert status.worst([Health.COMPLETED, Health.COMPLETED]) is Health.COMPLETED
    assert status.worst([Health.HEALTHY, Health.UNHEALTHY, Health.STOPPED]) is Health.STOPPED
    assert status.worst([Health.STOPPED, Health.MISSING]) is Health.MISSING
    assert status.worst([]) is Health.UNKNOWN


def test_parse_ps_line_rejects_truncated_and_nameless_lines():
    assert status.parse_ps_line("only\ttwo") is None
    assert status.parse_ps_line(ps_line("", "running", "Up", "svc")) is None
    parsed = status.parse_ps_line(
        ps_line(
            "c1", "running", "Up", "svc", "papaia-x", "r", ports="0.0.0.0:80->80/tcp, :::80->80/tcp"
        )
    )
    assert parsed is not None
    project, module, container = parsed
    assert (project, module) == (PROJECT, "x")
    assert container.host_ports == [80]  # IPv4 and IPv6 binding collapse to one


def test_a_container_without_a_module_label_lands_in_other():
    parsed = status.parse_ps_line(ps_line("c1", "running", "Up", "svc"))
    assert parsed is not None
    assert parsed[1] == status.UNGROUPED_MODULE


# ─────────────────────────────────────────────────────────────────────────
# collect: the scenarios the report has to get right
# ─────────────────────────────────────────────────────────────────────────


def test_all_healthy(stack):
    report = collect(stack, FakeDocker(healthy_core() + healthy_addon()), include_addons=True)

    assert report.docker.reachable
    assert report.aggregate_core is Health.HEALTHY
    assert report.aggregate_addons is Health.HEALTHY
    assert all(m.status is Health.HEALTHY for m in report.modules)
    assert {m.name for m in report.core} == {"keycloak", "auth", "firecrawl", "searxng"}
    assert {m.name for m in report.addons} == {"paperless"}
    assert_schema_valid(report)


def test_module_is_a_label_not_a_profile(stack):
    """`oauth2-proxy` is the module `auth`; `librechat-websearch` spans two modules."""
    report = collect(stack, FakeDocker(healthy_core()))

    modules = by_name(report)
    assert modules["auth"].profiles == ("oauth2-proxy",)
    groups = {g.profile: g for g in report.groups}
    assert groups["librechat-websearch"].modules == ("firecrawl", "searxng")
    assert groups["librechat-websearch"].containers == 2
    assert groups["oauth2-proxy"].modules == ("auth",)


def test_one_addon_down(stack):
    docker = FakeDocker(
        healthy_core()
        + [
            healthy_addon()[0],
            ps_line(
                "paperless-paperless-db-1",
                "exited",
                "Exited (1) 3 minutes ago",
                "paperless-db",
                project="paperless",
            ),
        ]
    )
    report = collect(stack, docker, include_addons=True)

    assert report.aggregate_core is Health.HEALTHY
    assert report.aggregate_addons is Health.STOPPED
    paperless = by_name(report)["paperless"]
    assert paperless.status is Health.STOPPED
    assert paperless.summary == "1 of 2 containers stopped"
    assert_schema_valid(report)


def test_docker_unreachable_reports_nothing_instead_of_everything_missing(stack):
    docker = FakeDocker(ps_result=CommandResult(1, "", "Cannot connect to the Docker daemon\n"))
    report = collect(stack, docker, include_addons=True)

    assert report.docker.reachable is False
    assert report.docker.reason == "Cannot connect to the Docker daemon"
    assert report.modules == []
    assert report.groups == []
    assert report.aggregate_core is Health.UNKNOWN
    assert report.aggregate_addons is Health.UNKNOWN
    assert_schema_valid(report)
    assert "not reachable" in status.format_table(report)


def test_missing_docker_binary_is_unreachable_too(stack):
    docker = FakeDocker(ps_result=CommandResult(127, "", "docker: command not found"))
    report = collect(stack, docker)

    assert report.docker.reachable is False
    assert report.docker.reason == "docker: command not found"
    assert report.aggregate_addons is None  # not requested


def test_declared_but_never_started_profile_is_missing_not_absent(stack):
    live = [line for line in healthy_core() if "oauth2-proxy" not in line]
    report = collect(stack, FakeDocker(live))

    auth = by_name(report)["auth"]
    assert auth.status is Health.MISSING
    assert auth.declared
    [placeholder] = auth.containers
    assert (placeholder.name, placeholder.state, placeholder.status_text) == (
        "",
        "missing",
        "not deployed",
    )
    assert auth.summary == "not deployed"
    assert report.aggregate_core is Health.MISSING
    assert report.modules[0].name == "auth"  # worst first
    assert {g.profile: g.status for g in report.groups}["oauth2-proxy"] is Health.MISSING
    assert_schema_valid(report)


def test_empty_host_reports_every_declared_module_as_missing(stack):
    report = collect(stack, FakeDocker([]))

    assert report.docker.reachable
    assert {m.status for m in report.modules} == {Health.MISSING}
    assert len(report.modules) == 4


def test_completed_job_with_a_service_restart_policy_is_an_outage(stack):
    """`Exited (0)` of a service stopped on purpose must not read as a finished job."""
    _enable(stack, "localai")
    live = healthy_core() + [
        ps_line(
            "papaia-localai-model-init-1",
            "exited",
            "Exited (0) 1 hour ago",
            "localai-model-init",
            "papaia-localai",
            "model-init",
        ),
        ps_line(
            "papaia-localai-1",
            "exited",
            "Exited (0) 1 hour ago",
            "localai",
            "papaia-localai",
            "inference-engine",
        ),
    ]
    docker = FakeDocker(
        live,
        policies={"papaia-localai-model-init-1": "no", "papaia-localai-1": "unless-stopped"},
    )
    report = collect(stack, docker)

    localai = by_name(report)["localai"]
    states = {c.service: c.health for c in localai.containers}
    assert states == {"localai-model-init": Health.COMPLETED, "localai": Health.STOPPED}
    assert localai.status is Health.STOPPED
    inspect_calls = [c for c in docker.calls if c[:2] == ["docker", "inspect"]]
    assert len(inspect_calls) == 1  # one batched lookup, completed containers only


def test_completed_one_shot_does_not_drag_its_module_down(stack):
    _enable(stack, "localai")
    live = healthy_core() + [
        ps_line(
            "papaia-localai-model-init-1",
            "exited",
            "Exited (0) 1 hour ago",
            "localai-model-init",
            "papaia-localai",
            "model-init",
        ),
        ps_line(
            "papaia-localai-1",
            "running",
            "Up 1 hour (healthy)",
            "localai",
            "papaia-localai",
            "inference-engine",
        ),
    ]
    report = collect(stack, FakeDocker(live, policies={"papaia-localai-model-init-1": "no"}))

    assert by_name(report)["localai"].status is Health.HEALTHY


def test_no_inspect_call_when_nothing_has_completed(stack):
    docker = FakeDocker(healthy_core())
    collect(stack, docker)

    assert [c[:3] for c in docker.calls] == [["docker", "ps", "-a"]]


def test_other_compose_projects_are_ignored(stack):
    live = healthy_core() + [
        ps_line(
            "papaia-dev-keycloak-1",
            "exited",
            "Exited (1) 1 hour ago",
            "keycloak",
            "papaia-keycloak",
            project="papaia-dev",
        ),
        ps_line("unrelated-1", "running", "Up", "web", project=""),
    ]
    report = collect(stack, FakeDocker(live))

    assert by_name(report)["keycloak"].status is Health.HEALTHY
    assert report.aggregate_core is Health.HEALTHY


def test_undeclared_containers_are_shown_but_marked(stack):
    live = healthy_core() + [
        ps_line("papaia-extra-1", "running", "Up", "extra", "papaia-extra", "thing"),
        ps_line("papaia-stray-1", "running", "Up", "stray"),
    ]
    modules = by_name(collect(stack, FakeDocker(live)))

    assert modules["extra"].declared is False
    assert modules["other"].declared is False
    assert modules["keycloak"].declared is True


def test_compose_project_name_comes_from_the_core_env(stack):
    (stack["config"] / ".env").write_text(
        "COMPOSE_PROJECT_NAME=papaia-demo\nCOMPOSE_PROFILES=oauth2-proxy\n", encoding="utf-8"
    )
    live = [
        ps_line(
            "papaia-demo-oauth2-proxy-1",
            "running",
            "Up",
            "oauth2-proxy",
            "papaia-auth",
            project="papaia-demo",
        ),
        ps_line(
            "papaia-oauth2-proxy-1",
            "exited",
            "Exited (1) 1 hour ago",
            "oauth2-proxy",
            "papaia-auth",
        ),
    ]
    report = collect(stack, FakeDocker(live))

    assert report.compose_project == "papaia-demo"
    assert by_name(report)["auth"].status is Health.HEALTHY


def test_inactive_profiles_are_not_expected(stack):
    """Services of a profile that is not in COMPOSE_PROFILES are not declared."""
    modules = by_name(collect(stack, FakeDocker(healthy_core())))

    assert "localai" not in modules


# ─────────────────────────────────────────────────────────────────────────
# flags
# ─────────────────────────────────────────────────────────────────────────


def test_addons_are_only_reported_on_request(stack):
    docker = FakeDocker(healthy_core() + healthy_addon())
    report = collect(stack, docker)

    assert report.addons == []
    assert report.aggregate_addons is None
    assert json.loads(status.to_json(report))["aggregate"]["addons"] is None
    assert "ADD-ONS" not in status.format_table(report)


def test_only_active_addons_are_reported(stack):
    report = collect(stack, FakeDocker(healthy_core() + healthy_addon()), include_addons=True)

    assert [m.name for m in report.addons] == ["paperless"]  # "dormant" is inactive


def test_addon_without_a_module_label_is_named_after_the_addon(stack):
    """`de.fidonis.module` is not part of the add-on contract: running containers
    that carry none must still read as the add-on, not as a stray `other`."""
    report = collect(stack, FakeDocker(healthy_core() + healthy_addon()), include_addons=True)

    assert [m.name for m in report.addons] == ["paperless"]
    assert len(report.addons[0].containers) == 2
    assert "other" not in by_name(report)


def test_profiles_filter_narrows_core_modules_and_groups(stack):
    report = collect(stack, FakeDocker(healthy_core()), profiles=["keycloak"])

    assert [m.name for m in report.core] == ["keycloak"]
    assert [g.profile for g in report.groups] == ["keycloak"]
    assert report.aggregate_core is Health.HEALTHY


def test_profiles_filter_aggregates_only_the_selection(stack):
    live = [line for line in healthy_core() if "oauth2-proxy" not in line]
    report = collect(stack, FakeDocker(live), profiles=["keycloak"])

    assert report.aggregate_core is Health.HEALTHY  # the missing auth module is outside it


def test_unknown_or_inactive_profile_is_refused(stack):
    with pytest.raises(status.StatusError, match="localai, nope"):
        collect(stack, FakeDocker([]), profiles=["keycloak", "localai", "nope"])


def test_profile_validation_does_not_need_docker(stack):
    docker = FakeDocker([])
    with pytest.raises(status.StatusError):
        collect(stack, docker, profiles=["nope"])
    assert docker.calls == []


# ─────────────────────────────────────────────────────────────────────────
# output
# ─────────────────────────────────────────────────────────────────────────


def test_json_document_shape(stack):
    report = collect(stack, FakeDocker(healthy_core() + healthy_addon()), include_addons=True)
    document = json.loads(status.to_json(report))

    assert document["schema_version"] == 1
    assert document["generated_at"] == "2026-09-27T10:15:00Z"
    assert document["platform_version"] == "1.3.0"
    assert document["docker"] == {"reachable": True, "reason": None}
    keycloak = next(m for m in document["modules"] if m["name"] == "keycloak")
    assert keycloak["kind"] == "core"
    assert keycloak["compose_project"] == PROJECT
    container = next(c for c in keycloak["containers"] if c["service"] == "keycloak")
    assert container["host_ports"] == [8110]
    paperless = next(m for m in document["modules"] if m["name"] == "paperless")
    assert (paperless["kind"], paperless["compose_project"]) == ("addon", "paperless")


def test_schema_rejects_an_unknown_health_value(stack):
    report = collect(stack, FakeDocker(healthy_core()))
    document = json.loads(status.to_json(report))
    document["modules"][0]["status"] = "degraded"

    assert list(VALIDATOR.iter_errors(document))


def test_table_names_the_unhealthy_container(stack):
    live = [
        line.replace("Up 2 hours (healthy)", "Up 2 hours (unhealthy)", 1) for line in healthy_core()
    ]
    table = status.format_table(collect(stack, FakeDocker(live)))

    assert "CORE: unhealthy" in table
    assert "keycloak/keycloak (identity-provider): Up 2 hours (unhealthy)" in table


def test_host_ports_in_use_lists_only_running_containers(stack):
    live = healthy_core() + [
        ps_line(
            "papaia-stopped-1",
            "exited",
            "Exited (1) 1 hour ago",
            "stopped",
            "papaia-s",
            ports="0.0.0.0:9000->9000/tcp",
        ),
    ]
    report = collect(stack, FakeDocker(live))

    assert report.host_ports_in_use() == {8110: "papaia-keycloak-1"}


# ─────────────────────────────────────────────────────────────────────────
# read-only guarantee
# ─────────────────────────────────────────────────────────────────────────


def _tree_state(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_collect_writes_nothing(stack, tmp_path):
    before = _tree_state(tmp_path)
    docker = FakeDocker(healthy_core() + healthy_addon())
    collect(stack, docker, include_addons=True)

    assert _tree_state(tmp_path) == before
    assert all(c[0] == "docker" and c[1] in ("ps", "inspect") for c in docker.calls)


# ─────────────────────────────────────────────────────────────────────────
# CLI layer
# ─────────────────────────────────────────────────────────────────────────


def _run_cli(stack, monkeypatch, docker, *args):
    monkeypatch.setattr(status, "run_command", docker)
    return cli.main(
        ["--repo-root", str(stack["repo"]), "--config-dir", str(stack["config"]), "status", *args]
    )


def test_cli_json_is_the_only_thing_on_stdout(stack, monkeypatch, capsys):
    code = _run_cli(
        stack, monkeypatch, FakeDocker(healthy_core() + healthy_addon()), "--json", "--addons"
    )

    out = capsys.readouterr().out
    assert code == 0
    document = json.loads(out)  # raises if anything else was printed
    assert not list(VALIDATOR.iter_errors(document))
    assert document["aggregate"] == {"core": "healthy", "addons": "healthy"}


def test_cli_exits_zero_even_when_docker_is_unreachable(stack, monkeypatch, capsys):
    docker = FakeDocker(ps_result=CommandResult(127, "", "docker: command not found"))
    code = _run_cli(stack, monkeypatch, docker, "--json")

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["docker"]["reachable"] is False


def test_cli_table_output(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, FakeDocker(healthy_core()))

    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("papAIa 1.3.0")
    assert "MODULE" in out and "keycloak" in out


def test_cli_profiles_flag_accepts_repeated_and_comma_separated_values(stack, monkeypatch, capsys):
    _run_cli(
        stack,
        monkeypatch,
        FakeDocker(healthy_core()),
        "--json",
        "--profiles=keycloak",
        "--profiles=oauth2-proxy,librechat-websearch",
    )

    document = json.loads(capsys.readouterr().out)
    assert {g["profile"] for g in document["groups"]} == {
        "keycloak",
        "oauth2-proxy",
        "librechat-websearch",
    }


def test_cli_unknown_profile_exits_2_with_a_message_on_stderr(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, FakeDocker([]), "--json", "--profiles=nope")

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "nope" in captured.err


# ─────────────────────────────────────────────────────────────────────────
# the real Compose files
# ─────────────────────────────────────────────────────────────────────────


def test_every_shipped_core_service_resolves_to_a_module_and_a_profile():
    """Guards drift: a service added without its labels or profile would fall
    into the `other` bucket or stay invisible to `--profiles`."""
    root = REPO / "src" / "docker-compose.yml"
    every_profile = {
        p
        for path in status.compat.compose_files(root)
        for body in status._services(status._load_yaml(path)).values()
        for p in status._profiles_of(body)
    }
    expected = status.core_inventory(REPO, every_profile)

    assert expected, "no core service found"
    assert [e.service for e in expected if e.module == status.UNGROUPED_MODULE] == []
    assert [e.service for e in expected if not e.role] == []
    assert [e.service for e in expected if not e.profiles] == []
    assert len({e.service for e in expected}) == len(expected)


def _enable(stack, profile: str) -> None:
    env = stack["config"] / ".env"
    text = env.read_text(encoding="utf-8")
    env.write_text(
        text.replace("COMPOSE_PROFILES=", f"COMPOSE_PROFILES={profile},"), encoding="utf-8"
    )


def test_run_command_reports_a_missing_binary_without_raising():
    result = status.run_command(["definitely-not-a-real-binary-xyz"], 1.0)

    assert result.returncode == 127
    assert "command not found" in result.stderr


def test_run_command_captures_output():
    result = status.run_command([sys.executable, "-c", "print('hi')"], 10.0)

    assert (result.returncode, result.stdout.strip()) == (0, "hi")
