"""Operating a distributed installation: setup, start and stop in order, one status, and
the doctor checks only a distributed installation has."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from install_helpers import REPO, Installation, run_cli
from jsonschema import Draft202012Validator
from test_topology import FULL, dmz_split, write_topology

from lib import cli, cluster, deployment, executor, link, topology
from lib.executor import Result

STATUS_SCHEMA = Draft202012Validator(
    json.loads((REPO / "tools" / "schemas" / "status.schema.json").read_text("utf-8"))
)
DOCTOR_SCHEMA = Draft202012Validator(
    json.loads((REPO / "tools" / "schemas" / "doctor.schema.json").read_text("utf-8"))
)

NODE_FLAGS = [
    "--topology=distributed",
    "--node=internal=10.0.2.10",
    "--node=edge=10.0.1.10,ssh=papaia@10.0.1.10",
    "--preset=dmz-split",
]


class FakeNode:
    """A node's executor: records every command, answers from a table."""

    def __init__(self, name: str, log: list, answers: dict | None = None, fail: set | None = None):
        self.name = name
        self.node = topology.Node(name)
        self.log = log
        self.answers = answers or {}
        self.fail = fail or set()

    def run(self, command, *, stdin=None, capture=False, stdout=None, timeout=None):
        self.log.append((self.name, list(command)))
        if command[0] in self.fail or " ".join(command) in self.fail:
            return Result(5, "", "boom")
        answer = self.answers.get(command[0])
        if answer is not None:
            return Result(0, json.dumps(answer) + "\n", "")
        return Result(0, "", "")


@pytest.fixture
def distributed(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    run_cli(inst.repo, inst.config, "render")
    return inst


def fake_cluster(inst: Installation, monkeypatch, **per_node) -> tuple[cluster.Cluster, list]:
    log: list = []
    nodes = {name: FakeNode(name, log, **per_node.get(name, {})) for name in ("internal", "edge")}
    monkeypatch.setattr(executor, "for_node", lambda topo, name, **kw: nodes[name])
    monkeypatch.setattr(cluster, "push", lambda c, names: log.append(("push", list(names))))
    return cluster.load(inst.config, inst.repo), log


# ─────────────────────────────────────────────────────────────────────────
# setup
# ─────────────────────────────────────────────────────────────────────────


def test_a_new_installation_can_be_set_up_distributed(tmp_path: Path):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL, *NODE_FLAGS)
    topo = topology.load_config(inst.config)
    assert topo.distributed and topo.controller == "internal"
    assert topo.nodes["edge"].executor == "ssh" and topo.nodes["internal"].executor == "local"
    assert topo.node_of("keycloak") == "edge"
    assert topology.bundle_dir(inst.config, "edge").is_dir()


def test_a_topology_file_works_like_the_flags(tmp_path: Path):
    inst = Installation(tmp_path, FULL)
    path = tmp_path / "topology.yaml"
    path.write_text(json.dumps({"topology": dmz_split().to_dict()}), encoding="utf-8")
    inst.setup(*FULL, f"--topology-file={path}")
    assert topology.load_config(inst.config).to_dict() == dmz_split().to_dict()


def test_a_broken_placement_refuses_and_a_corrected_run_completes(tmp_path: Path, capsys):
    inst = Installation(tmp_path, FULL)
    argv = [
        "--repo-root",
        str(inst.repo),
        "--config-dir",
        str(inst.config),
        "setup",
        "--env=papaia",
        *FULL,
        *NODE_FLAGS[:3],
        "--place=manager=edge",
    ]
    assert cli.main(argv) == 2
    assert "'manager' must run on the controller" in capsys.readouterr().err
    assert "topology" not in deployment.load(inst.config)
    inst.setup(*FULL, *NODE_FLAGS)
    assert topology.load_config(inst.config).distributed


def test_distributed_setup_of_an_existing_installation_exits_2_and_changes_nothing(
    tmp_path: Path, capsys
):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    before = {p: p.read_bytes() for p in inst.config.rglob("*") if p.is_file()}
    argv = [
        "--repo-root",
        str(inst.repo),
        "--config-dir",
        str(inst.config),
        "setup",
        "--env=papaia",
        *NODE_FLAGS,
    ]
    assert cli.main(argv) == 2
    assert "is for new installations" in capsys.readouterr().err
    after = {p: p.read_bytes() for p in inst.config.rglob("*") if p.is_file()}
    assert after == before


def test_setup_does_not_change_the_topology_of_a_distributed_installation(tmp_path: Path, capsys):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL, *NODE_FLAGS)
    argv = [
        "--repo-root",
        str(inst.repo),
        "--config-dir",
        str(inst.config),
        "setup",
        "--env=papaia",
        *NODE_FLAGS[:3],
        "--preset=dmz-edge",
    ]
    assert cli.main(argv) == 2
    assert "does not change the topology" in capsys.readouterr().err
    # The same topology again is a plain re-render.
    inst.setup(*NODE_FLAGS)
    inst.setup()
    assert topology.load_config(inst.config).node_of("keycloak") == "edge"


def test_single_is_accepted_for_a_single_host(tmp_path: Path):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL, "--topology=single")
    inst.setup("--topology=single")
    assert "topology" not in deployment.load(inst.config)


@pytest.mark.parametrize(
    "flags, fragment",
    [
        (["--topology=distributed", "--node=a=10.0.0.1", "--node=b=10.0.0.2"], "--controller"),
        (["--topology=distributed", "--node=a"], "NAME=ADDRESS"),
        (["--node=a=10.0.0.1", "--node=a=10.0.0.2,ssh=x"], "named twice"),
        (["--node=a=1.1.1.1", "--node=b=2.2.2.2,colour=red"], "unknown node option"),
        (
            [
                "--node=a=1.1.1.1",
                "--node=b=2.2.2.2,ssh=x",
                "--node=c=3.3.3.3,ssh=y",
                "--preset=dmz-split",
            ],
            "one edge node",
        ),
        (["--node=a=1.1.1.1", "--node=b=2.2.2.2,ssh=x", "--place=nginx"], "SERVICE=NODE"),
    ],
)
def test_malformed_topology_flags_are_named(tmp_path: Path, capsys, flags, fragment):
    inst = Installation(tmp_path, FULL)
    argv = [
        "--repo-root",
        str(inst.repo),
        "--config-dir",
        str(inst.config),
        "setup",
        "--env=papaia",
        *FULL,
        *flags,
    ]
    assert cli.main(argv) == 2
    assert fragment in capsys.readouterr().err
    assert not (inst.config / ".env").exists()


def test_node_specs_parse_ssh_users_and_ports():
    topo = topology.from_flags(
        node_specs=["c=10.0.0.1", "e=10.0.0.2,ssh=admin@jump.example.org:2200,root=/opt/p"],
        places=["nginx=e"],
        preset=None,
        controller=None,
        link_port=8443,
    )
    edge = topo.nodes["e"]
    assert (edge.ssh_user, edge.ssh_host, edge.ssh_port, edge.root) == (
        "admin",
        "jump.example.org",
        2200,
        "/opt/p",
    )
    assert topo.link_port == 8443 and topo.placement == {"nginx": "e"}


BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_the_bash_entrypoint_passes_the_refusal_through_as_exit_2(tmp_path: Path):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    tools = Path(__file__).resolve().parents[1]
    shutil.copytree(
        tools,
        inst.repo / "tools",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("tests", "__pycache__"),
    )
    done = subprocess.run(
        [
            BASH,
            str(inst.repo / "tools" / "papaia-ctl"),
            "setup",
            f"--config-dir={inst.config}",
            "-y",
            *NODE_FLAGS,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 2, done.stderr
    assert "is for new installations" in done.stderr


# ─────────────────────────────────────────────────────────────────────────
# start / stop
# ─────────────────────────────────────────────────────────────────────────


def ups(log) -> list[tuple[str, list[str]]]:
    return [(node, cmd[1:]) for node, cmd in log if node != "push" and cmd[0] == "compose-up"]


def test_start_brings_identity_up_first_and_the_proxy_last(distributed, monkeypatch):
    found, log = fake_cluster(distributed, monkeypatch)
    assert cluster.start(found) == 0
    assert log[0] == ("push", ["internal", "edge"])
    steps = ups(log)
    assert steps[:2] == [("internal", ["link-gateway"]), ("edge", ["link-gateway"])]
    order = [service for _node, services in steps[2:] for service in services]
    assert order.index("keycloak") < order.index("litellm") < order.index("librechat")
    assert order[-1] == "nginx"
    assert ("edge", ["keycloak", "smtp"]) in steps
    hooks = [(n, c) for n, c in log if n != "push" and c[0] == "hook"]
    assert hooks == [("edge", ["hook", "npm-provision"]), ("edge", ["hook", "keycloak-role-sync"])]


def test_a_failing_node_stops_the_sequence_with_a_clear_message(distributed, monkeypatch, capsys):
    found, log = fake_cluster(distributed, monkeypatch, edge={"fail": {"compose-up litellm"}})
    assert cluster.start(found) == 3
    err = capsys.readouterr().err
    assert "start stopped at node 'edge' (litellm, exit 5)" in err
    started = [s for _n, services in ups(log) for s in services]
    assert "librechat" not in started and "nginx" not in started


def test_start_honours_node(distributed, monkeypatch):
    found, log = fake_cluster(distributed, monkeypatch)
    assert cluster.start(found, node="internal") == 0
    assert {n for n, _c in ups(log)} == {"internal"}
    # The hooks belong to services of the edge, which this start did not touch.
    assert not [c for n, c in log if n != "push" and c[0] == "hook"]


def test_an_unknown_node_is_refused(distributed, monkeypatch):
    found, _log = fake_cluster(distributed, monkeypatch)
    with pytest.raises(cluster.ClusterError, match="no node named 'dmz'"):
        cluster.start(found, node="dmz")


def test_stop_runs_the_start_order_backwards(distributed, monkeypatch):
    found, log = fake_cluster(distributed, monkeypatch)
    assert cluster.stop(found) == 0
    stops = [(n, c[1:]) for n, c in log if c[0] == "compose-stop"]
    order = [s for _n, services in stops for s in services]
    assert order[0] == "nginx"
    assert order.index("librechat") < order.index("litellm") < order.index("keycloak")
    assert stops[-2:] == [("internal", ["link-gateway"]), ("edge", ["link-gateway"])]


def test_stop_with_clean_up_removes(distributed, monkeypatch):
    found, log = fake_cluster(distributed, monkeypatch)
    cluster.stop(found, clean_up=True, profiles=["librechat"])
    assert [c for _n, c in log] == [["compose-down", "librechat"]]


def test_push_follows_the_release_the_node_reports(distributed, monkeypatch):
    """After a restore the controller's record can be stale; the node's own answer counts."""
    version = topology.envtree.resolve_platform_version(distributed.repo)
    calls: list = []
    monkeypatch.setattr(
        cluster.nodes,
        "node_version",
        lambda c, r, name: {"reachable": True, "papaia_version": "0.0.1"},
    )
    monkeypatch.setattr(
        cluster.nodes,
        "push_checkout",
        lambda c, r, name: calls.append(("checkout", name)) or Result(0),
    )
    monkeypatch.setattr(
        cluster.nodes, "push_bundle", lambda c, r, name: calls.append(("bundle", name)) or Result(0)
    )
    cluster.nodes.record_state(distributed.config, "edge", release=version)
    cluster.push(cluster.load(distributed.config, distributed.repo), ["internal", "edge"])
    assert calls == [("checkout", "edge"), ("bundle", "edge")]


def test_push_stops_at_a_node_that_does_not_answer(distributed, monkeypatch):
    monkeypatch.setattr(
        cluster.nodes, "node_version", lambda c, r, name: {"reachable": False, "reason": "x"}
    )
    with pytest.raises(cluster.ClusterError, match="does not answer"):
        cluster.push(cluster.load(distributed.config, distributed.repo), ["edge"])


# ─────────────────────────────────────────────────────────────────────────
# status
# ─────────────────────────────────────────────────────────────────────────


def node_status(*modules: tuple[str, str, list[str]], reachable: bool = True) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-10-30T12:00:00Z",
        "platform_version": "1.8.0",
        "compose_project": "papaia",
        "docker": {"reachable": reachable, "reason": None if reachable else "no socket"},
        "modules": [
            {
                "name": name,
                "kind": "core",
                "compose_project": "papaia",
                "profiles": profiles,
                "declared": True,
                "status": health,
                "containers": [
                    {
                        "name": f"papaia-{name}-1",
                        "service": name,
                        "role": "",
                        "state": "running",
                        "health": health,
                        "status_text": "Up",
                        "host_ports": [],
                    }
                ],
            }
            for name, health, profiles in modules
        ],
        "groups": [],
        "aggregate": {"core": "healthy", "addons": None},
    }


def test_status_merges_the_nodes_with_their_names(distributed, monkeypatch):
    found, _log = fake_cluster(
        distributed,
        monkeypatch,
        internal={"answers": {"status": node_status(("librechat", "healthy", ["librechat"]))}},
        edge={
            "answers": {
                "status": node_status(
                    ("keycloak", "unhealthy", ["keycloak"]), ("litellm", "healthy", ["litellm"])
                )
            }
        },
    )
    report = cluster.collect_status(found, now=datetime(2026, 10, 30, tzinfo=timezone.utc))
    assert not list(STATUS_SCHEMA.iter_errors(report))
    assert report["schema_version"] == 1
    assert [(m["name"], m["node"]) for m in report["modules"]][0] == ("keycloak", "edge")
    assert all(c["node"] == m["node"] for m in report["modules"] for c in m["containers"])
    assert report["aggregate"]["core"] == "unhealthy"
    assert {n["name"]: n["reachable"] for n in report["nodes"]} == {"internal": True, "edge": True}
    assert "NODE edge 10.0.1.10: unhealthy" in cluster.format_status(report)


def test_an_unreachable_node_is_reported_not_invented(distributed, monkeypatch):
    found, _log = fake_cluster(
        distributed,
        monkeypatch,
        internal={"answers": {"status": node_status(("librechat", "healthy", ["librechat"]))}},
        edge={"fail": {"status"}},
    )
    report = cluster.collect_status(found)
    assert not list(STATUS_SCHEMA.iter_errors(report))
    assert report["docker"]["reachable"] is False
    assert [m["node"] for m in report["modules"]] == ["internal"]
    edge = next(n for n in report["nodes"] if n["name"] == "edge")
    assert edge["reachable"] is False and edge["reason"] == "boom"


# ─────────────────────────────────────────────────────────────────────────
# doctor
# ─────────────────────────────────────────────────────────────────────────


def node_doctor(version: str, *, probes=(), time_offset: float = 0.0) -> dict:
    return {
        "node": "x",
        "papaia_version": version,
        "time": datetime.now(timezone.utc).timestamp() + time_offset,
        "doctor": {
            "checks": [{"name": "disk_space", "status": "pass", "summary": "ok", "details": {}}]
        },
        "links": list(probes),
    }


def ok_probe(peer: str) -> dict:
    later = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    return {
        "peer": peer,
        "address": "10.0.0.1",
        "port": 7443,
        "ok": True,
        "stage": "tls",
        "peer_not_after": later,
    }


def doctor_report(distributed, monkeypatch, internal: dict, edge: dict):
    found, _log = fake_cluster(
        distributed,
        monkeypatch,
        internal={"answers": {"doctor": internal}},
        edge={"answers": {"doctor": edge}},
    )
    monkeypatch.setattr(
        cluster.doctor,
        "run_checks",
        lambda *a, **k: cluster.doctor.DoctorReport("2026-10-30T12:00:00Z", "1.8.0", []),
    )
    return cluster.run_doctor(found)


def check(report, name):
    return next(c for c in report.checks if c.name == name)


def test_doctor_adds_nodes_and_links_in_distributed_mode(distributed, monkeypatch):
    version = topology.envtree.resolve_platform_version(distributed.repo)
    report = doctor_report(
        distributed,
        monkeypatch,
        node_doctor(version, probes=[ok_probe("edge")]),
        node_doctor(version, probes=[ok_probe("internal")]),
    )
    assert [c.name for c in report.checks] == ["nodes", "links"]
    assert check(report, "nodes").status == "pass"
    assert check(report, "links").status == "pass"
    assert not list(DOCTOR_SCHEMA.iter_errors(report.to_dict()))


def test_doctor_reports_version_skew_and_clock_deviation(distributed, monkeypatch):
    version = topology.envtree.resolve_platform_version(distributed.repo)
    report = doctor_report(
        distributed,
        monkeypatch,
        node_doctor(version),
        node_doctor("0.9.0", time_offset=120),
    )
    nodes = check(report, "nodes")
    assert nodes.status == "fail"
    assert "version skew" in nodes.summary
    assert "clock is +120s off" in nodes.summary or "clock is +1" in nodes.summary


def test_doctor_names_the_firewall_rule_of_an_unreachable_link(distributed, monkeypatch):
    version = topology.envtree.resolve_platform_version(distributed.repo)
    down = {
        "peer": "edge",
        "address": "10.0.1.10",
        "port": 7443,
        "ok": False,
        "stage": "connect",
        "reason": "timed out",
    }
    report = doctor_report(
        distributed, monkeypatch, node_doctor(version, probes=[down]), node_doctor(version)
    )
    links = check(report, "links")
    assert links.status == "fail"
    assert "firewall rule internal -> edge tcp/7443" in links.summary


def test_doctor_warns_30_days_before_a_link_certificate_expires(distributed, monkeypatch):
    version = topology.envtree.resolve_platform_version(distributed.repo)
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    probe = {**ok_probe("edge"), "peer_not_after": soon}
    report = doctor_report(
        distributed, monkeypatch, node_doctor(version, probes=[probe]), node_doctor(version)
    )
    assert check(report, "links").status == "warn"
    assert "expires" in check(report, "links").summary


def test_an_expiring_leaf_on_the_controller_is_named_with_the_fix(distributed, monkeypatch):
    version = topology.envtree.resolve_platform_version(distributed.repo)
    monkeypatch.setattr(
        link,
        "cert_not_after",
        lambda path: datetime.now(timezone.utc) + timedelta(days=5),
    )
    report = doctor_report(distributed, monkeypatch, node_doctor(version), node_doctor(version))
    assert "node renew-link" in check(report, "links").summary


def test_nodes_and_links_can_be_skipped_everywhere():
    assert cluster.doctor.parse_skip(["nodes", "links"]) == ["nodes", "links"]
