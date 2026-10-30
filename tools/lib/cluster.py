"""Operating a distributed installation from the controller: start, stop, status, doctor.

Every action reaches a node through its executor (lib/executor.py), which ends in the node's
`papaia-ctl node-shell`. The controller is a node like the others; its executor is local.

**Order.** `start` brings the services up in groups (`ServiceSpec.start_group`): Keycloak and
the mail relay first, then LiteLLM, then the application (LibreChat, web search, RAG, LocalAI,
papaia-manager), and the Nginx Proxy Manager last, so nothing is exposed half-started. Within
a group the nodes go one after another. The link gateways come first, since every service
that calls another node needs its own. `stop` runs the same order backwards. A node that
fails stops the sequence with the node, the services and the exit code. What already runs
keeps running, and re-running the command is safe.

**Hooks.** The provisioning steps that follow `start` on a single host run on the node of
their service: `npm-provision` where the proxy runs, `keycloak-role-sync` where Keycloak runs.
Their targets did not change: thanks to the link gateway, `librechat:3080` is a valid
upstream for the proxy on any node.

**Reports.** `status` asks every node and returns one report. It has the same shape as on
one host, with `node` added to every module and container, and `nodes` listing each node's
reachability and version. `doctor` runs the controller's own checks and adds two checks of
its own: `nodes` (each node's own doctor, version skew, clock deviation) and `links` (a TLS
handshake per link from the calling side, certificate expiry, unreachable peers named as the
firewall rule they need). Both additions appear in distributed mode only; `schema_version`
stays 1.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import doctor, envtree, executor, link, nodes, status, topology
from .topology import CATALOGUE, Topology

# A JWT carries `exp` and `nbf`; services accept a few seconds of skew at most.
CLOCK_WARN_SECONDS = 5.0
CLOCK_FAIL_SECONDS = 60.0
CERT_WARN_DAYS = 30


class ClusterError(Exception):
    """A distributed operation that cannot start (broken topology, unknown node)."""


@dataclass
class Cluster:
    config_dir: Path
    repo_root: Path
    topology: Topology
    profiles: list[str]

    @property
    def active(self) -> list[str]:
        return topology.active_services(self.profiles)

    def executor(self, name: str) -> executor.Executor:
        return executor.for_node(
            self.topology, name, config_dir=self.config_dir, repo_root=self.repo_root
        )

    def services_on(self, name: str) -> list[str]:
        return self.topology.services_on(name, self.active)


def load(config_dir: Path, repo_root: Path) -> Cluster:
    try:
        topo = topology.load_config(config_dir)
    except topology.TopologyError as exc:
        raise ClusterError(f"deployment.yaml: {exc}") from exc
    if not topo.distributed:
        raise ClusterError("this installation runs on one host")
    env = topology.validation_env(config_dir, repo_root)
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
    return Cluster(config_dir, repo_root, topo, profiles)


def _say(text: str) -> None:
    print(f"[papaia-ctl] {text}", flush=True)


def _nodes(cluster: Cluster, only: str | None) -> list[str]:
    if only is None:
        return list(cluster.topology.nodes)
    if only not in cluster.topology.nodes:
        raise ClusterError(f"no node named '{only}' (one of {', '.join(cluster.topology.nodes)})")
    return [only]


def _filter(services: list[str], profiles: list[str] | None) -> list[str]:
    if not profiles:
        return services
    wanted = set(profiles)
    return [s for s in services if wanted.intersection(CATALOGUE[s].profiles)]


def _groups(cluster: Cluster, names: list[str], profiles: list[str] | None, *, reverse: bool):
    """(group, node, services) in start order (or stop order with `reverse`)."""
    steps = []
    for group in sorted({spec.start_group for spec in CATALOGUE.values()}, reverse=reverse):
        for name in names:
            services = [
                s
                for s in _filter(cluster.services_on(name), profiles)
                if CATALOGUE[s].start_group == group
            ]
            if services:
                steps.append((group, name, services))
    return steps


# ─────────────────────────────────────────────────────────────────────────
# distribution
# ─────────────────────────────────────────────────────────────────────────


def push(cluster: Cluster, names: list[str]) -> None:
    """Hand each remote node its release (when it differs) and its bundle."""
    version = envtree.resolve_platform_version(cluster.repo_root)
    for name in names:
        if cluster.topology.nodes[name].is_local:
            continue
        if nodes.read_state(cluster.config_dir, name).get("release") != version:
            _say(f"node {name}: installing release {version}")
            result = nodes.push_checkout(cluster.config_dir, cluster.repo_root, name)
            if not result.ok:
                raise ClusterError(
                    f"node '{name}': the release could not be installed (exit"
                    f" {result.returncode}). Check the connection with"
                    f" 'papaia-ctl node check {name}'."
                )
            nodes.record_state(cluster.config_dir, name, release=version)
        _say(f"node {name}: installing its bundle")
        result = nodes.push_bundle(cluster.config_dir, cluster.repo_root, name)
        if not result.ok:
            raise ClusterError(
                f"node '{name}': its bundle could not be installed (exit {result.returncode})"
            )
        nodes.record_state(
            cluster.config_dir,
            name,
            bundle_pushed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


# ─────────────────────────────────────────────────────────────────────────
# start / stop
# ─────────────────────────────────────────────────────────────────────────


def _run(cluster: Cluster, name: str, command: list[str]) -> int:
    try:
        return cluster.executor(name).run(command).returncode
    except executor.ExecutorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 3


def start(cluster: Cluster, *, node: str | None = None, profiles: list[str] | None = None) -> int:
    names = _nodes(cluster, node)
    push(cluster, names)
    for name in names:
        _say(f"node {name}: link gateway")
        code = _run(cluster, name, ["compose-up", link.GATEWAY_SERVICE])
        if code != 0:
            return _stopped("start", name, [link.GATEWAY_SERVICE], code)
    for _group, name, services in _groups(cluster, names, profiles, reverse=False):
        _say(f"node {name}: starting {', '.join(services)}")
        code = _run(cluster, name, ["compose-up", *services])
        if code != 0:
            return _stopped("start", name, services, code)
    warnings = 0
    for hook, service in (("npm-provision", "nginx"), ("keycloak-role-sync", "keycloak")):
        owner = cluster.topology.node_of(service)
        if service not in cluster.active or owner not in names:
            continue
        _say(f"node {owner}: {hook}")
        if _run(cluster, owner, ["hook", hook]) != 0:
            warnings += 1
            print(
                f"WARNING: {hook} failed on node '{owner}'. Once the services are healthy,"
                f" retry with 'papaia-ctl start --node={owner}'.",
                file=sys.stderr,
                flush=True,
            )
    return 0


def stop(
    cluster: Cluster,
    *,
    node: str | None = None,
    profiles: list[str] | None = None,
    clean_up: bool = False,
) -> int:
    names = _nodes(cluster, node)
    verb = "compose-down" if clean_up else "compose-stop"
    for _group, name, services in _groups(cluster, names, profiles, reverse=True):
        _say(f"node {name}: {'removing' if clean_up else 'stopping'} {', '.join(services)}")
        code = _run(cluster, name, [verb, *services])
        if code != 0:
            return _stopped("stop", name, services, code)
    if not profiles:
        for name in names:
            _say(f"node {name}: link gateway")
            code = _run(cluster, name, [verb, link.GATEWAY_SERVICE])
            if code != 0:
                return _stopped("stop", name, [link.GATEWAY_SERVICE], code)
    return 0


def _stopped(action: str, node: str, services: list[str], code: int) -> int:
    print(
        f"ERROR: {action} stopped at node '{node}' ({', '.join(services)}, exit {code})."
        " Nodes and services before it are left as they are; fix the cause and run"
        f" 'papaia-ctl {action}' again.",
        file=sys.stderr,
        flush=True,
    )
    return 3


# ─────────────────────────────────────────────────────────────────────────
# status
# ─────────────────────────────────────────────────────────────────────────


def _node_json(
    cluster: Cluster, name: str, verb: str, timeout: float = 120
) -> tuple[dict | None, str]:
    try:
        result = cluster.executor(name).run([verb], capture=True, timeout=timeout)
    except executor.ExecutorError as exc:
        return None, str(exc)
    if not result.ok:
        lines = (result.stderr or result.stdout).strip().splitlines()
        return None, lines[-1] if lines else f"exit {result.returncode}"
    try:
        return json.loads(result.stdout), ""
    except ValueError:
        return None, "the node's answer is not JSON"


def _worst(values) -> str:
    return status.worst(status.Health(v) for v in values).value


def collect_status(
    cluster: Cluster,
    *,
    profiles: list[str] | None = None,
    include_addons: bool = False,
    now: datetime | None = None,
) -> dict:
    """One report for the whole installation, in the shape of `status --json`."""
    modules: list[dict] = []
    node_rows: list[dict] = []
    reachable_all = True
    for name, node in cluster.topology.nodes.items():
        report, reason = _node_json(cluster, name, "status")
        row = {
            "name": name,
            "address": node.address,
            "controller": name == cluster.topology.controller,
        }
        if report is None or not (report.get("docker") or {}).get("reachable"):
            reachable_all = False
            row.update(
                reachable=False,
                reason=reason or (report or {}).get("docker", {}).get("reason"),
                papaia_version=None,
            )
            node_rows.append(row)
            continue
        row.update(reachable=True, reason=None, papaia_version=report.get("platform_version"))
        node_rows.append(row)
        for module in report.get("modules") or []:
            if module.get("kind") == "addon" and not include_addons:
                continue
            module["node"] = name
            for container in module.get("containers") or []:
                container["node"] = name
            modules.append(module)

    if profiles:
        wanted = set(profiles)
        modules = [m for m in modules if wanted.intersection(m.get("profiles") or [])]
    modules.sort(key=lambda m: (status._SEVERITY[status.Health(m["status"])], m["name"], m["node"]))

    groups: dict[str, dict] = {}
    for module in modules:
        if module.get("kind") != "core":
            continue
        for profile in module.get("profiles") or []:
            group = groups.setdefault(
                profile, {"profile": profile, "modules": [], "containers": 0, "statuses": []}
            )
            if module["name"] not in group["modules"]:
                group["modules"].append(module["name"])
            group["containers"] += len(module.get("containers") or [])
            group["statuses"].append(module["status"])
    group_list = [
        {
            "profile": g["profile"],
            "modules": sorted(g["modules"]),
            "containers": g["containers"],
            "status": _worst(g["statuses"]),
        }
        for g in groups.values()
    ]
    group_list.sort(key=lambda g: (status._SEVERITY[status.Health(g["status"])], g["profile"]))

    core = [m["status"] for m in modules if m.get("kind") == "core"]
    addons = [m["status"] for m in modules if m.get("kind") == "addon"]
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "schema_version": status.SCHEMA_VERSION,
        "generated_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform_version": envtree.resolve_platform_version(cluster.repo_root),
        "compose_project": status.compose_project(cluster.config_dir),
        "docker": {
            "reachable": reachable_all,
            "reason": None if reachable_all else "not every node answered; see nodes",
        },
        "modules": modules,
        "groups": group_list,
        "aggregate": {
            "core": _worst(core) if core else (None if reachable_all else "unknown"),
            "addons": _worst(addons) if addons else None,
        },
        "nodes": node_rows,
    }


def format_status(report: dict) -> str:
    lines = [
        f"papAIa {report['platform_version']} - compose project '{report['compose_project']}'"
        f" on {len(report['nodes'])} nodes"
    ]
    for row in report["nodes"]:
        lines.append("")
        role = " (controller)" if row.get("controller") else ""
        if not row.get("reachable"):
            lines.append(
                f"NODE {row['name']} {row['address']}{role}: unreachable ({row.get('reason')})"
            )
            continue
        own = [m for m in report["modules"] if m["node"] == row["name"]]
        verdict = _worst(m["status"] for m in own) if own else "no modules"
        lines.append(f"NODE {row['name']} {row['address']}{role}: {verdict}")
        if own:
            rows = [
                (
                    m["name"],
                    m["status"],
                    ",".join(m.get("profiles") or []) or "-",
                    f"{len(m.get('containers') or [])} container(s)",
                )
                for m in own
            ]
            lines.extend(status._format_rows(("MODULE", "STATUS", "PROFILES", "DETAIL"), rows))
            for module in own:
                for container in module.get("containers") or []:
                    if container["health"] not in ("healthy", "completed"):
                        lines.append(
                            f"  {module['name']}/{container['service']}: {container['status_text']}"
                        )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────
# doctor
# ─────────────────────────────────────────────────────────────────────────


def _parse_cert_time(text: str | None) -> datetime | None:
    if not text:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_nodes(
    cluster: Cluster, answers: dict[str, dict | None], reasons: dict[str, str], now: datetime
) -> doctor.CheckResult:
    version = envtree.resolve_platform_version(cluster.repo_root)
    details: dict[str, Any] = {"controller_version": version, "nodes": []}
    statuses: list[str] = []
    problems: list[str] = []
    for name in cluster.topology.nodes:
        answer = answers.get(name)
        entry: dict[str, Any] = {"node": name}
        if answer is None:
            entry.update(reachable=False, reason=reasons.get(name))
            statuses.append(doctor.FAIL)
            problems.append(f"{name} unreachable")
            details["nodes"].append(entry)
            continue
        node_report = answer.get("doctor") or {}
        checks = node_report.get("checks") or []
        worst = doctor._worst(c["status"] for c in checks) if checks else doctor.SKIP
        offset = answer.get("clock_offset")
        entry.update(
            reachable=True,
            papaia_version=answer.get("papaia_version"),
            clock_offset=offset,
            status=worst,
            failing=[c["name"] for c in checks if c["status"] == doctor.FAIL],
            warning=[c["name"] for c in checks if c["status"] == doctor.WARN],
        )
        details["nodes"].append(entry)
        statuses.append(worst if worst != doctor.SKIP else doctor.PASS)
        if worst == doctor.FAIL:
            problems.append(f"{name}: {', '.join(entry['failing'])} failing")
        if answer.get("papaia_version") != version:
            statuses.append(doctor.FAIL)
            problems.append(
                f"{name} runs {answer.get('papaia_version')}, the controller {version}"
                " (version skew: run 'papaia-ctl upgrade')"
            )
        if isinstance(offset, (int, float)):
            if abs(offset) >= CLOCK_FAIL_SECONDS:
                statuses.append(doctor.FAIL)
                problems.append(f"{name}'s clock is {offset:+.0f}s off; tokens will be refused")
            elif abs(offset) >= CLOCK_WARN_SECONDS:
                statuses.append(doctor.WARN)
                problems.append(f"{name}'s clock is {offset:+.1f}s off")
    result = doctor._worst(statuses) if statuses else doctor.SKIP
    summary = (
        "; ".join(problems)
        if problems
        else (f"{len(cluster.topology.nodes)} nodes reachable, same version, clocks in step")
    )
    return doctor.CheckResult("nodes", result, summary, details)


def check_links(
    cluster: Cluster, answers: dict[str, dict | None], now: datetime
) -> doctor.CheckResult:
    statuses: list[str] = []
    problems: list[str] = []
    probes: list[dict] = []
    for name, answer in answers.items():
        if answer is None:
            continue
        for probe in answer.get("links") or []:
            probe = {"from": name, **probe}
            probes.append(probe)
            if probe.get("ok"):
                statuses.append(doctor.PASS)
                not_after = _parse_cert_time(probe.get("peer_not_after"))
                if not_after and not_after - now < timedelta(days=CERT_WARN_DAYS):
                    statuses.append(doctor.WARN)
                    problems.append(
                        f"the link certificate of {probe['peer']} expires {not_after:%Y-%m-%d}"
                    )
                continue
            statuses.append(doctor.FAIL)
            if probe.get("stage") == "connect":
                problems.append(
                    f"{name} cannot reach {probe['peer']} at {probe['address']}:{probe['port']}"
                    f" ({probe.get('reason')}) -- is the firewall rule {name} -> {probe['peer']}"
                    f" tcp/{probe['port']} open and the gateway running there?"
                )
            else:
                problems.append(
                    f"{name} -> {probe['peer']}: {probe.get('stage')}: {probe.get('reason')}"
                )
    certificates: list[dict] = []
    for name in cluster.topology.nodes:
        path = link.leaf_dir(cluster.config_dir, name) / "node.crt"
        not_after = link.cert_not_after(path) if path.is_file() else None
        if not_after is None:
            continue
        days = (not_after - now).days
        certificates.append(
            {"node": name, "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"), "days_left": days}
        )
        if days < 0:
            statuses.append(doctor.FAIL)
            problems.append(
                f"the link certificate of {name} expired; run 'papaia-ctl node renew-link {name}'"
            )
        elif days < CERT_WARN_DAYS:
            statuses.append(doctor.WARN)
            problems.append(
                f"the link certificate of {name} expires in {days} days;"
                f" run 'papaia-ctl node renew-link {name}'"
            )
    result = doctor._worst(statuses) if statuses else doctor.SKIP
    if not probes and not certificates:
        return doctor.CheckResult("links", doctor.SKIP, "no links between nodes to check", {})
    summary = (
        "; ".join(dict.fromkeys(problems))
        if problems
        else (f"{sum(1 for p in probes if p.get('ok'))} link(s) up, certificates valid")
    )
    return doctor.CheckResult(
        "links", result, summary, {"probes": probes, "certificates": certificates}
    )


def run_doctor(
    cluster: Cluster, *, skip: list[str] | None = None, now: datetime | None = None
) -> doctor.DoctorReport:
    """The controller's own node checked as on one host, plus `nodes` and `links`."""
    skipped = set(doctor.parse_skip(skip))
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    controller = cluster.topology.controller
    report = doctor.run_checks(
        topology.bundle_dir(cluster.config_dir, controller),
        cluster.repo_root,
        skip=[s for s in skipped if s in doctor.CHECK_NAMES],
        now=moment,
    )
    answers: dict[str, dict | None] = {}
    reasons: dict[str, str] = {}
    if not {"nodes", "links"} <= skipped:
        for name in cluster.topology.nodes:
            asked = datetime.now(timezone.utc).timestamp()
            answer, reason = _node_json(cluster, name, "doctor", timeout=300)
            answered = datetime.now(timezone.utc).timestamp()
            if answer is not None and isinstance(answer.get("time"), (int, float)):
                answer["clock_offset"] = round(answer["time"] - (asked + answered) / 2, 3)
            answers[name] = answer
            reasons[name] = reason
    for name, check in (("nodes", check_nodes), ("links", check_links)):
        if name in skipped:
            report.checks.append(doctor.CheckResult(name, doctor.SKIP, "skipped (--skip)"))
        elif name == "nodes":
            report.checks.append(check(cluster, answers, reasons, moment))
        else:
            report.checks.append(check(cluster, answers, moment))
    return report


# ─────────────────────────────────────────────────────────────────────────
# preflight (distributed setup)
# ─────────────────────────────────────────────────────────────────────────

MIN_COMPOSE = doctor.MIN_COMPOSE


def preflight(cluster: Cluster) -> int:
    """Before the first start: every node answers over its executor, has Docker and a
    recent Compose, and keeps time with the controller."""
    failed = 0
    for name in cluster.topology.nodes:
        data = nodes.node_version(cluster.config_dir, cluster.repo_root, name)
        if not data.get("reachable"):
            failed += 1
            print(f"  {name}: unreachable ({data.get('reason')})", flush=True)
            continue
        problems = []
        if not data.get("docker"):
            problems.append("Docker does not answer")
        compose = data.get("compose") or ""
        if not compose:
            problems.append("no docker compose plugin")
        else:
            try:
                from . import semver

                if semver.compare(compose.lstrip("v").split("-")[0], MIN_COMPOSE) < 0:
                    problems.append(f"Compose {compose} is older than {MIN_COMPOSE}")
            except ValueError:
                pass
        offset = data.get("clock_offset")
        if isinstance(offset, (int, float)) and abs(offset) >= CLOCK_WARN_SECONDS:
            problems.append(f"clock {offset:+.1f}s off")
        if problems:
            failed += 1
            print(f"  {name}: {'; '.join(problems)}", flush=True)
        else:
            print(
                f"  {name}: Docker {data.get('docker')}, Compose {compose}, clock in step",
                flush=True,
            )
    return 0 if failed == 0 else 3
