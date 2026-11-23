"""`papaia-ctl doctor`: the modules of the platform catalog (PLT-42, BE-26, RE-56, RE-61).

The probe container is replaced by running the probe script itself with this Python, so
the stub modules below are real HTTP servers on 127.0.0.1, addressed as `localhost`
(a single-label name like a compose service), and the probe's requests,
limits and parsing are exercised as they run in the container. Everything else Docker
answers comes from `FakeDocker`.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml
from stack_helpers import FakeDocker, healthy_addon, healthy_core, ps_line
from test_doctor import probes, result

from lib import doctor, module_health
from lib.doctor import FAIL, PASS, SKIP, WARN
from lib.status import CommandResult

RUNNER_IMAGE = "ghcr.io/example/papaia-manager:1.0.0@sha256:" + "a" * 64


# ─────────────────────────────────────────────────────────────────────────
# stub modules
# ─────────────────────────────────────────────────────────────────────────


class StubModule:
    """A module as the kit describes it: `/healthz` without sign-in, the gauge
    `revocations_age_seconds` under `/metrics`."""

    def __init__(self, *, health="ok", revocations_age=12.0, healthz_body=None,
                 healthz_code=200, metrics_code=200, metrics_text=None):
        self.health = health
        self.revocations_age = revocations_age
        self.healthz_body = healthz_body
        self.healthz_code = healthz_code
        self.metrics_code = metrics_code
        self.metrics_text = metrics_text
        self.requests: list[tuple[str, str | None]] = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - the stdlib's name
                stub.requests.append((self.path, self.headers.get("Authorization")))
                if self.path == "/healthz":
                    body = stub.healthz_body
                    if body is None:
                        body = json.dumps({"status": stub.health})
                    self._answer(stub.healthz_code, body)
                elif self.path == "/metrics":
                    text = stub.metrics_text
                    if text is None:
                        text = (
                            "# TYPE revocations_age_seconds gauge\n"
                            f"revocations_age_seconds {stub.revocations_age}\n"
                            "requests_total 7\n"
                        )
                    self._answer(stub.metrics_code, text)
                else:
                    self._answer(404, "")

            def _answer(self, code, body):
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self) -> str:
        return f"http://localhost:{self.port}/mcp"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stubs():
    made: list[StubModule] = []

    def make(**kwargs) -> StubModule:
        made.append(StubModule(**kwargs))
        return made[-1]

    yield make
    for stub in made:
        stub.close()


# ─────────────────────────────────────────────────────────────────────────
# installation
# ─────────────────────────────────────────────────────────────────────────


def write_runner_image(stack) -> None:
    compose = stack["repo"] / "src" / "manager" / "docker-compose.yml"
    compose.parent.mkdir(parents=True, exist_ok=True)
    compose.write_text(
        yaml.safe_dump({"services": {"papaia-manager": {"image": RUNNER_IMAGE}}}),
        encoding="utf-8",
    )


def add_addon(stack, name: str, *, attach=(), components=None, active=True) -> Path:
    path = stack["addon"].parent / name
    path.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "version": "0.2.0",
        "papaia_compat": ">=1.0.0",
        "networks": {"app_network": "${PAPAIA_PROJECT:-papaia}-" + name + "-net",
                     "attach": list(attach)},
    }
    if components is not None:
        manifest["components"] = components
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {name: {"image": "x"}}}), encoding="utf-8"
    )
    deployed_path = stack["config"] / "deployment.yaml"
    deployed = yaml.safe_load(deployed_path.read_text(encoding="utf-8"))
    deployed["addons"].append({"name": name, "path": str(path), "active": active})
    deployed_path.write_text(yaml.safe_dump(deployed), encoding="utf-8")
    return path


def write_catalog(stack, *entries: dict) -> None:
    folder = stack["config"] / "platform"
    folder.mkdir(exist_ok=True)
    (folder / "services.json").write_text(
        json.dumps({"format": "papaia.platform-services/1", "services": list(entries)}),
        encoding="utf-8",
    )


def entry(provider: str, address: str | None, *, state="running", version="0.2.0",
          entry_id=None) -> dict:
    item = {"id": entry_id or f"{provider}.tools", "provider": provider, "version": version,
            "kind": "mcp", "state": state, "trust": "platform",
            "title": {"de": "Werkzeuge", "en": "Tools"}}
    if address is not None:
        item["address"] = address
    return item


class Docker(FakeDocker):
    """FakeDocker plus what the module checks ask: `docker run` of the probe (run here
    with this Python), `docker network inspect` and `docker exec` of a selftest."""

    def __init__(self, *args, networks=None, run_failure=None, selftest=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.networks = networks or {}
        self.run_failure = run_failure
        self.selftest = selftest
        self.probe_runs: list[list[str]] = []

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        if cmd[:2] == ["docker", "run"]:
            self.calls.append(cmd)
            self.probe_runs.append(cmd)
            if self.run_failure is not None:
                return self.run_failure
            at = cmd.index("--entrypoint")
            assert cmd[at + 1] == "python3" and cmd[at + 2] == RUNNER_IMAGE
            done = subprocess.run(
                [sys.executable, *cmd[at + 3:]], capture_output=True, text=True, timeout=60,
                check=False,
            )
            return CommandResult(done.returncode, done.stdout, done.stderr)
        if cmd[:3] == ["docker", "network", "inspect"]:
            self.calls.append(cmd)
            members = self.networks.get(cmd[3])
            if members is None:
                return CommandResult(1, "", f"Error: No such network: {cmd[3]}")
            body = {f"id{n}": {"Name": name} for n, name in enumerate(members)}
            return CommandResult(0, json.dumps(body) + "\n", "")
        if cmd[:2] == ["docker", "exec"] and cmd[3:] == list(doctor.MSSQL_SELFTEST):
            self.calls.append(cmd)
            return self.selftest or CommandResult(1, "", "no selftest")
        return super().__call__(cmd, timeout)


def run(stack, docker, **kwargs) -> doctor.DoctorReport:
    return doctor.run_checks(
        stack["config"], stack["repo"], run=docker, probes=probes(), **kwargs
    )


def stub_stack(stack, stubs, **stub_kwargs):
    write_runner_image(stack)
    add_addon(stack, "stub")
    module = stubs(**stub_kwargs)
    write_catalog(stack, entry("stub", module.address))
    return module


def keycloak_neighbour_stack(stack, members):
    add_addon(stack, "lookup", attach=["keycloak"])
    return Docker(healthy_core() + healthy_addon(),
                  networks={"papaia-lookup-net": members})


# ─────────────────────────────────────────────────────────────────────────
# revocations_age (ticket test: stub module with a stale revocation list)
# ─────────────────────────────────────────────────────────────────────────


def test_stub_module_with_a_stale_revocation_list_is_fail(stack, stubs):
    module = stub_stack(stack, stubs, revocations_age=900)
    report = run(stack, Docker(healthy_core() + healthy_addon()))

    check = result(report, "revocations_age")
    assert check.status == FAIL
    assert "stub" in check.summary and "900 s" in check.summary
    assert check.details["modules"][0]["revocations_age_seconds"] == 900
    assert report.exit_code == 2
    # Read without a token, exactly the two documented paths.
    assert sorted(module.requests) == [("/healthz", None), ("/metrics", None)]


@pytest.mark.parametrize(
    ("age", "expected"),
    [(0, PASS), (60, PASS), (61, WARN), (300, WARN), (301, FAIL)],
)
def test_revocation_age_thresholds(stack, stubs, age, expected):
    stub_stack(stack, stubs, revocations_age=age)
    report = run(stack, Docker(healthy_core() + healthy_addon()))
    assert result(report, "revocations_age").status == expected


def test_the_oldest_labelled_series_counts(stack, stubs):
    stub_stack(stack, stubs, metrics_text=(
        'revocations_age_seconds{list="a"} 5\nrevocations_age_seconds{list="b"} 400.5\n'
    ))
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "revocations_age")
    assert check.status == FAIL
    assert check.details["modules"][0]["revocations_age_seconds"] == 400.5


def test_a_module_without_the_gauge_is_warn(stack, stubs):
    stub_stack(stack, stubs, metrics_text="requests_total 1\n")
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "revocations_age")
    assert check.status == WARN
    assert "does not report revocations_age_seconds" in check.summary


def test_metrics_behind_the_operations_token_is_skip(stack, stubs):
    stub_stack(stack, stubs, metrics_code=401, metrics_text="")
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "revocations_age")
    assert check.status == SKIP
    assert check.details["modules"][0]["text"].endswith("needs the operations token")


def test_revocations_age_is_skipped_without_a_catalog(stack):
    report = run(stack, Docker(healthy_core() + healthy_addon()))
    assert result(report, "revocations_age").status == SKIP


# ─────────────────────────────────────────────────────────────────────────
# modules: /healthz
# ─────────────────────────────────────────────────────────────────────────


def test_a_healthy_module_is_one_row_with_version_state_and_health(stack, stubs):
    module = stub_stack(stack, stubs)
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "modules")

    assert check.status == PASS
    row = next(r for r in check.details["modules"] if r["module"] == "stub")
    assert row["version"] == "0.2.0"
    assert row["state"] == "running"
    assert row["health"] == [{
        "origin": f"http://localhost:{module.port}", "network": "papaia-stub-net",
        "status": PASS, "text": f"http://localhost:{module.port} ok", "health": "ok",
        "http_status": 200,
    }]
    assert "stub 0.2.0 (running)" in check.summary


@pytest.mark.parametrize(
    ("kwargs", "expected", "text"),
    [
        ({"health": "degraded"}, WARN, "reports degraded"),
        ({"health": "down", "healthz_code": 503}, FAIL, "reports down"),
        ({"healthz_code": 404, "healthz_body": ""}, WARN, "serves no /healthz"),
        ({"healthz_code": 401, "healthz_body": ""}, WARN, "asks for sign-in"),
        ({"healthz_code": 500, "healthz_body": "boom"}, FAIL, "HTTP 500"),
        # The kit form carries the state only: a version or a reason is outside it.
        ({"healthz_body": '{"status": "ok", "version": "1.0"}'}, WARN, "outside the kit form"),
    ],
)
def test_healthz_answers(stack, stubs, kwargs, expected, text):
    stub_stack(stack, stubs, **kwargs)
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "modules")
    assert check.status == expected
    assert text in check.summary


def test_an_unreachable_module_names_module_network_and_missing_path(stack, stubs):
    module = stub_stack(stack, stubs)
    module.close()
    report = run(stack, Docker(healthy_core() + healthy_addon()))
    check = result(report, "modules")
    assert check.status == FAIL
    assert "stub:" in check.summary
    assert "papaia-stub-net" in check.summary and "network path is missing" in check.summary
    assert "ConnectionRefusedError" in check.summary
    assert report.exit_code == 2


def test_a_stopped_module_is_listed_and_not_probed(stack, stubs):
    write_runner_image(stack)
    add_addon(stack, "stub")
    module = stubs()
    write_catalog(stack, entry("stub", module.address, state="stopped"))
    docker = Docker(healthy_core() + healthy_addon())
    check = result(run(stack, docker), "modules")
    assert check.status == PASS
    assert "stub 0.2.0 (stopped)" in check.summary
    assert docker.probe_runs == [] and module.requests == []


def test_one_probe_per_network_and_one_request_pair_per_address(stack, stubs):
    write_runner_image(stack)
    add_addon(stack, "stub")
    module = stubs()
    core = stubs()
    write_catalog(
        stack,
        entry("stub", module.address, entry_id="stub.tools"),
        entry("stub", module.address.replace("/mcp", "/other"), entry_id="stub.more"),
        entry("core:rag", core.address, entry_id="qdrant.collections"),
    )
    docker = Docker(healthy_core() + healthy_addon())
    check = result(run(stack, docker), "modules")
    assert check.status == PASS
    assert [c[c.index("--network") + 1] for c in docker.probe_runs] == [
        "papaia-stub-net", "papaia-net"
    ]
    assert len(module.requests) == 2 and len(core.requests) == 2


def test_the_probe_container_is_locked_down(stack, stubs):
    stub_stack(stack, stubs)
    docker = Docker(healthy_core() + healthy_addon())
    run(stack, docker)
    argv = docker.probe_runs[0]
    for flag in (["--rm"], ["--pull", "never"], ["--read-only"], ["--cap-drop", "ALL"],
                 ["--security-opt", "no-new-privileges:true"], ["--user", "65534:65534"]):
        assert any(argv[i:i + len(flag)] == flag for i in range(len(argv)))
    for forbidden in ("-v", "--volume", "--mount", "-p", "--publish", "--privileged", "-e"):
        assert forbidden not in argv


def test_a_probe_that_cannot_start_is_warn(stack, stubs):
    stub_stack(stack, stubs)
    docker = Docker(healthy_core() + healthy_addon(),
                    run_failure=CommandResult(125, "", "Unable to find image locally"))
    report = run(stack, docker)
    check = result(report, "modules")
    assert check.status == WARN
    assert "did not run (Unable to find image locally)" in check.summary
    # The revocation age is unknown, not absent: warn with the probe failure.
    revocations = result(report, "revocations_age")
    assert revocations.status == WARN
    assert "stub:" in revocations.summary
    assert "did not run (Unable to find image locally)" in revocations.summary
    assert revocations.details["modules"][0]["revocations_age_seconds"] is None


def test_an_unreadable_probe_answer_is_warn(stack, stubs):
    stub_stack(stack, stubs)
    docker = Docker(healthy_core() + healthy_addon(),
                    run_failure=CommandResult(0, '[{"origin": "x"}]\n', ""))
    report = run(stack, docker)
    check = result(report, "modules")
    assert check.status == WARN
    assert "cannot be read" in check.summary
    revocations = result(report, "revocations_age")
    assert revocations.status == WARN
    assert "cannot be read" in revocations.summary


@pytest.mark.parametrize(
    "address",
    [
        "http://example.org:8080/mcp",
        "http://10.0.0.5:8080/mcp",
        "https://mcp.example.org/mcp",
    ],
)
def test_an_address_outside_the_compose_names_is_not_probed(stack, address):
    """The catalog comes from add-on manifests: an address whose host is not a single-label
    compose service or container name is never contacted from an internal network."""
    write_runner_image(stack)
    add_addon(stack, "stub")
    write_catalog(stack, entry("stub", address))
    docker = Docker(healthy_core() + healthy_addon())
    report = run(stack, docker)
    assert docker.probe_runs == []
    check = result(report, "modules")
    assert check.status == WARN
    assert "not probed" in check.summary and "not a compose service name" in check.summary
    revocations = result(report, "revocations_age")
    assert revocations.status == WARN
    assert "not a compose service name" in revocations.summary


def test_probe_argv_refuses_an_external_host(stack):
    write_runner_image(stack)
    with pytest.raises(module_health.ModuleHealthError, match="compose service name"):
        module_health.probe_argv(stack["repo"], "papaia-stub-net", ["http://example.org:80"])


@pytest.mark.parametrize(
    "document",
    [
        "not json",
        json.dumps({"format": "other/1", "services": []}),
        json.dumps({"format": "papaia.platform-services/1", "services": {}}),
        json.dumps({"format": "papaia.platform-services/1",
                    "services": [entry("stub", "ftp://host/x")]}),
        json.dumps({"format": "papaia.platform-services/1",
                    "services": [entry("stub", "http://user:pw@host/x")]}),
        json.dumps({"format": "papaia.platform-services/1",
                    "services": [entry("stub", "http://host/x", state="paused")]}),
        json.dumps({"format": "papaia.platform-services/1",
                    "services": [entry("bad provider", "http://host/x")]}),
    ],
)
def test_a_catalog_that_cannot_be_used_is_fail_and_nothing_is_probed(stack, document):
    write_runner_image(stack)
    (stack["config"] / "platform").mkdir()
    (stack["config"] / "platform" / "services.json").write_text(document, encoding="utf-8")
    docker = Docker(healthy_core() + healthy_addon())
    report = run(stack, docker)
    assert result(report, "modules").status == FAIL
    assert result(report, "revocations_age").status == FAIL
    assert docker.probe_runs == []


@pytest.mark.parametrize("case", ["core-rag", "rag-probe-flow"])
def test_the_catalog_as_render_writes_it_is_read(stack, case):
    """Reads the golden catalogs of test_catalog, which `catalog render` writes: every
    service is one entry and every internal address is probed."""
    golden = Path(__file__).parent / "golden" / "catalog" / f"{case}.services.json"
    folder = stack["config"] / "platform"
    folder.mkdir(exist_ok=True)
    (folder / "services.json").write_text(golden.read_text(encoding="utf-8"), encoding="utf-8")
    services = json.loads(golden.read_text(encoding="utf-8"))["services"]

    entries = module_health.load_entries(stack["config"])

    assert [e.id for e in entries] == [s["id"] for s in services]
    assert all(module_health.outside_the_stack(e.origin) is None
               for e in entries if e.origin is not None)


def test_parse_probe_refuses_answers_outside_the_form():
    origins = ["http://a:1"]
    good = [{"origin": "http://a:1", "healthz": {"code": 200, "error": None, "body": "{}"},
             "metrics": {"code": 200, "error": None, "values": ["3"]}}]
    assert module_health.parse_probe(json.dumps(good), origins)["http://a:1"].revocations == [3]
    for broken in (
        [],
        [dict(good[0], origin="http://b:1")],
        [dict(good[0], extra=1)],
        [dict(good[0], healthz={"code": 99, "error": None, "body": ""})],
        [dict(good[0], healthz={"code": True, "error": None, "body": ""})],
        [dict(good[0], healthz={"code": None, "error": "bad name!", "body": None})],
        [dict(good[0], metrics={"code": 200, "error": None, "values": ["-1"]})],
        [dict(good[0], metrics={"code": 200, "error": None, "values": ["nan"]})],
        [dict(good[0], metrics={"code": 200, "error": None, "values": ["1"] * 17})],
    ):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            module_health.parse_probe(json.dumps(broken), origins)


# ─────────────────────────────────────────────────────────────────────────
# modules: network path to the neighbours (PLT-42-A2)
# ─────────────────────────────────────────────────────────────────────────


def test_an_attached_neighbour_on_the_app_network_passes(stack):
    docker = keycloak_neighbour_stack(stack, ["lookup-lookup-1", "papaia-keycloak-1"])
    check = result(run(stack, docker), "modules")
    assert check.status == PASS
    row = next(r for r in check.details["modules"] if r["module"] == "lookup")
    assert row["neighbours"] == [{"neighbour": "keycloak", "network": "papaia-lookup-net",
                                  "status": PASS,
                                  "text": "keycloak reachable on papaia-lookup-net"}]
    assert row["state"] is None  # not in the catalog: the add-on exposes nothing


def test_a_neighbour_cut_off_from_the_app_network_names_module_neighbour_and_network(stack):
    docker = keycloak_neighbour_stack(stack, ["lookup-lookup-1"])
    report = run(stack, docker)
    check = result(report, "modules")
    assert check.status == FAIL
    assert check.summary == (
        "lookup: no network path to neighbour keycloak: papaia-keycloak-1 is not on network "
        "papaia-lookup-net"
    )
    assert report.exit_code == 2


def test_a_missing_app_network_is_fail(stack):
    add_addon(stack, "lookup", attach=["keycloak"])
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "modules")
    assert check.status == FAIL
    assert "network papaia-lookup-net does not exist" in check.summary


def test_a_stopped_neighbour_is_fail(stack):
    lines = [line.replace("\trunning\tUp 2 hours (healthy)\tpapaia\tkeycloak\t",
                          "\texited\tExited (1) 2 minutes ago\tpapaia\tkeycloak\t")
             for line in healthy_core()]
    add_addon(stack, "lookup", attach=["keycloak"])
    docker = Docker(lines + healthy_addon(), networks={"papaia-lookup-net": []})
    check = result(run(stack, docker), "modules")
    assert check.status == FAIL
    assert "neighbour keycloak is exited" in check.summary


def test_a_neighbour_on_another_node_is_warn(stack):
    add_addon(stack, "lookup", attach=["litellm"])
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "modules")
    assert check.status == WARN
    assert "neighbour litellm does not run on this host" in check.summary


# ─────────────────────────────────────────────────────────────────────────
# egress
# ─────────────────────────────────────────────────────────────────────────


EGRESS_LINE = ps_line("papaia-papaia-egress-1", "running", "Up 1 hour (healthy)",
                      "papaia-egress", "papaia-egress", "egress")


def enable_egress(stack) -> None:
    env = stack["config"] / ".env"
    text = env.read_text(encoding="utf-8").replace(
        "COMPOSE_PROFILES=keycloak,", "COMPOSE_PROFILES=egress,keycloak,"
    )
    env.write_text(text, encoding="utf-8")


def write_egress_config(stack, *sources: str) -> None:
    path = stack["config"] / "infra" / "egress" / "egress.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "format": "papaia.egress/1",
        "sources": [{"name": s, "alias": f"egress-{s}", "allow": [], "internal": []}
                    for s in sources],
        "protected": [], "upstream": None,
    }), encoding="utf-8")


def test_egress_off_is_warn(stack):
    check = result(run(stack, Docker(healthy_core() + healthy_addon())), "egress")
    assert check.status == WARN
    assert "egress profile is off" in check.summary


def test_egress_runs_with_its_configuration(stack):
    enable_egress(stack)
    write_egress_config(stack)
    check = result(run(stack, Docker(healthy_core() + healthy_addon() + [EGRESS_LINE])),
                   "egress")
    assert check.status == PASS
    assert check.summary == "papaia-egress runs with 0 source(s)"


def test_egress_stopped_is_fail(stack):
    enable_egress(stack)
    write_egress_config(stack)
    stopped = EGRESS_LINE.replace("\trunning\tUp 1 hour (healthy)\t", "\texited\tExited (1)\t")
    check = result(run(stack, Docker(healthy_core() + healthy_addon() + [stopped])), "egress")
    assert check.status == FAIL
    assert "nothing leaves the stack" in check.summary


def test_egress_without_its_configuration_is_fail(stack):
    enable_egress(stack)
    check = result(run(stack, Docker(healthy_core() + healthy_addon() + [EGRESS_LINE])),
                   "egress")
    assert check.status == FAIL
    assert "egress.json is missing" in check.summary


def test_an_addon_needing_the_exit_without_a_source_is_fail(stack):
    enable_egress(stack)
    write_egress_config(stack)
    path = add_addon(stack, "fetcher")
    manifest = yaml.safe_load((path / "papaia-app.yaml").read_text(encoding="utf-8"))
    manifest["networks"]["egress"] = {
        "network": "${PAPAIA_PROJECT:-papaia}-fetcher-egress",
        "allow": [{"host": "api.example.org", "ports": [443]}],
    }
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text(yaml.safe_dump({
        "services": {"fetcher": {"image": "x"}},
        "networks": {"egress": {"name": "${PAPAIA_PROJECT:-papaia}-fetcher-egress",
                                "internal": True}},
    }), encoding="utf-8")
    docker = Docker(healthy_core() + healthy_addon() + [EGRESS_LINE],
                    networks={"papaia-fetcher-net": []})
    check = result(run(stack, docker), "egress")
    assert check.status == FAIL
    assert "fetcher has no source in infra/egress/egress.json" in check.summary
    assert "fetcher has no attachment override" in check.summary


# ─────────────────────────────────────────────────────────────────────────
# source_protection: SQL Server version and encryption (RE-61)
# ─────────────────────────────────────────────────────────────────────────


MSSQL_LINE = ps_line("mssql-mcp-mssql-mcp-rbac-1", "running", "Up 1 hour (healthy)",
                     "mssql-mcp-rbac", "mssql-mcp", "mcp-server", project="mssql-mcp")
OK_REPORT = (
    "SQL Server 2022 16.0.4175.1, CU28, Linux; Encrypt=mandatory (TDS 7.4), certificate "
    "and host name yes checked"
)


def mssql_stack(stack) -> None:
    add_addon(stack, "mssql-mcp",
              components=[{"id": "mssql-mcp-rbac", "role": "primary", "version": "0.1.0"}])


def selftest(*lines: str, code: int = 0) -> CommandResult:
    return CommandResult(code, "\n".join(["[ok] DNS: db -> 10.0.0.5", *lines,
                                          "selftest: passed"]) + "\n", "")


def run_mssql(stack, **kwargs) -> doctor.CheckResult:
    docker = Docker(healthy_core() + healthy_addon() + [MSSQL_LINE],
                    networks={"papaia-mssql-mcp-net": []}, **kwargs)
    return result(run(stack, docker), "source_protection")


def test_source_protection_is_skipped_without_a_sql_source(stack):
    assert result(run(stack, Docker(healthy_core() + healthy_addon())),
                  "source_protection").status == SKIP


def test_source_protection_shows_version_and_encryption(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=selftest(
        "[ok] TLS + login [erp]: database ExampleErp",
        f"[ok] version + encryption [erp]: {OK_REPORT}",
    ))
    assert check.status == PASS
    assert check.summary == f"mssql-mcp: [erp] {OK_REPORT}"
    assert check.details["sources"][0]["database"] == "erp"


def test_source_protection_reports_the_server_warning(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=selftest(
        "[ok] version + encryption [erp]: SQL Server 2019 without TDS 8.0 (no strict)"
    ))
    assert check.status == WARN


def test_source_protection_fails_for_weak_encryption(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=selftest(
        f"[ok] version + encryption [erp]: {OK_REPORT}",
        "[FAIL] version + encryption [crm]: SQL Server 2022 on Windows requires "
        "MSSQL_ENCRYPT=strict",
        code=1,
    ))
    assert check.status == FAIL
    assert check.summary == (
        "mssql-mcp: [crm] SQL Server 2022 on Windows requires MSSQL_ENCRYPT=strict"
    )


def test_source_protection_shows_the_login_failure(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=selftest(
        "[FAIL] TLS + login [erp]: TLS certificate not trusted (MSSQL_TLS_CA_FILE)", code=1
    ))
    assert check.status == FAIL
    assert "TLS certificate not trusted" in check.summary


def test_source_protection_fails_when_the_server_does_not_run(stack):
    mssql_stack(stack)
    docker = Docker(healthy_core() + healthy_addon(), networks={"papaia-mssql-mcp-net": []})
    check = result(run(stack, docker), "source_protection")
    assert check.status == FAIL
    assert "version and encryption unknown" in check.summary


def test_source_protection_keeps_a_long_failure_line(stack):
    """The selftest joins every problem of one database into one line; a long line is
    still the verdict, shortened only for display."""
    mssql_stack(stack)
    problems = "; ".join(f"problem {n}: " + "x" * 60 for n in range(12))
    check = run_mssql(stack, selftest=selftest(
        "[ok] TLS + login [erp]: database ExampleErp",
        f"[FAIL] version + encryption [erp]: {problems}",
        code=1,
    ))
    assert len(problems) > 500
    assert check.status == FAIL
    assert "problem 0:" in check.summary
    text = check.details["sources"][0]["text"]
    assert len(text) <= doctor.MSSQL_DETAIL_SHOWN + len("[erp] ")
    assert text.endswith("...")


def test_source_protection_fails_for_an_unreadable_version_line(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=selftest(
        "[ok] TLS + login [erp]: database ExampleErp",
        "[ok] version + encryption [ERP!]: \x00",
    ))
    assert check.status == FAIL
    assert "cannot be read" in check.summary


def test_source_protection_fails_without_a_version_line(stack):
    mssql_stack(stack)
    check = run_mssql(stack, selftest=CommandResult(126, "", "OCI runtime exec failed"))
    assert check.status == FAIL
    assert "OCI runtime exec failed" in check.summary
