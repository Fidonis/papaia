"""Node command handlers for the papaia-ctl Python CLI (`papaia-ctl node ...`).

Bash owns the prompts (host key confirmation, the admin session); these handlers own the
topology edits, the keys, the archives and the calls through the executors. Parser wiring
is in `add_parsers`, called by cli.build_parser.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import common, envtree, executor, link, nodes, topology
from .topology import Node


def _fail(exc: Exception, code: int = 3) -> int:
    print(f"ERROR: {exc}", file=sys.stderr)
    return code


def _project(config_dir: Path, repo_root: Path) -> int:
    # Local import: cli imports this module.
    from . import cli

    return cli._project_bundles(config_dir, repo_root)


def cmd_node_register(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    node = Node(
        name=args.name,
        address=args.address,
        executor=topology.EXECUTOR_SSH,
        ssh_user=args.ssh_user or topology.DEFAULT_SSH_USER,
        ssh_port=args.ssh_port or topology.DEFAULT_SSH_PORT,
        ssh_host=args.ssh_host or "",
        root=args.root or topology.DEFAULT_NODE_ROOT,
        bind_ip=args.bind_ip or "",
        gpu=args.gpu or "",
    )
    try:
        _manifest, before = nodes.require_distributed(config_dir)
        topo = nodes.register(config_dir, node)
        findings = topology.validate_config(config_dir, repo_root, topo)
        if not findings.ok:
            # Put the topology back the way it was: a node that breaks it is not added.
            manifest, _ = nodes.load(config_dir)
            nodes.save(config_dir, manifest, before)
            for error in findings.errors:
                print(f"ERROR: topology: {error}", file=sys.stderr)
            return 2
        nodes.ensure_keypair(config_dir, node.name)
        link.issue_leaf(config_dir, topo.nodes[node.name])
    except (nodes.NodeError, link.LinkError) as exc:
        return _fail(exc, 2 if isinstance(exc, nodes.NodeError) else 3)
    if _project(config_dir, repo_root) != 0:
        return 3
    print(f"Node '{node.name}' registered ({node.ssh_user}@{node.ssh_target}:{node.ssh_port}).")
    return 0


def cmd_node_unregister(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        topo = nodes.unregister(config_dir, repo_root, args.name)
    except nodes.NodeError as exc:
        return _fail(exc, 2)
    if _project(config_dir, repo_root) != 0:
        return 3
    print(f"Node '{args.name}' removed. {len(topo.nodes)} node(s) left.")
    print(
        "The controller's key for it is deleted, so the node can no longer be reached. On the"
        " node, remove the user and its directory to finish."
    )
    return 0


def cmd_node_list(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
    except nodes.NodeError as exc:
        return _fail(exc, 2)
    env = topology.validation_env(config_dir, repo_root)
    active = topology.active_services([p for p in env.get("COMPOSE_PROFILES", "").split(",") if p])
    rows = []
    for node in topo.nodes.values():
        state = nodes.read_state(config_dir, node.name)
        row = {
            "name": node.name,
            "address": node.address,
            "executor": node.executor,
            "controller": node.name == topo.controller,
            "services": topo.services_on(node.name, active),
            "host_key_pinned": node.is_local or nodes.host_key_pinned(config_dir, node.name),
            "release": state.get("release"),
            "bundle_pushed_at": state.get("bundle_pushed_at"),
        }
        if args.check:
            row["check"] = nodes.node_version(config_dir, repo_root, node.name)
        rows.append(row)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(topology.format_table(topo, [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]))
    if args.check:
        print()
        for row in rows:
            print(_check_line(row["check"]))
    return 0


def _check_line(data: dict) -> str:
    if not data.get("reachable"):
        return f"  {data['node']}: unreachable ({data.get('reason', 'no answer')})"
    offset = data.get("clock_offset")
    clock = f", clock {offset:+.1f}s" if isinstance(offset, (int, float)) else ""
    docker = data.get("docker") or "?"
    compose = data.get("compose") or "?"
    return (
        f"  {data['node']}: papAIa {data.get('papaia_version')}, Docker {docker},"
        f" Compose {compose}{clock}"
    )


def cmd_node_pending(args: argparse.Namespace) -> int:
    """The remote nodes whose host key is not pinned yet: not enrolled, or not checked."""
    config_dir = Path(args.config_dir)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
    except nodes.NodeError as exc:
        return _fail(exc, 2)
    for node in topo.nodes.values():
        if not node.is_local and not nodes.host_key_pinned(config_dir, node.name):
            print(node.name)
    return 0


def cmd_node_check(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        data = nodes.node_version(config_dir, repo_root, args.name)
    except (nodes.NodeError, executor.ExecutorError) as exc:
        return _fail(exc)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(_check_line(data).strip())
    return 0 if data.get("reachable") else 3


def cmd_node_keyscan(args: argparse.Namespace) -> int:
    try:
        _manifest, topo = nodes.require_distributed(Path(args.config_dir))
        node = topo.nodes.get(args.name)
        if node is None:
            raise nodes.NodeError(f"no node named '{args.name}'")
        for kind, fingerprint, _key in nodes.host_key_fingerprints(nodes.scan_host_keys(node)):
            print(f"HOSTKEY\t{kind}\t{fingerprint}")
    except nodes.NodeError as exc:
        return _fail(exc)
    return 0


def cmd_node_pin(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
        node = topo.nodes.get(args.name)
        if node is None:
            raise nodes.NodeError(f"no node named '{args.name}'")
        kind = nodes.pin_host_key(config_dir, node, args.fingerprint)
    except nodes.NodeError as exc:
        return _fail(exc)
    print(f"Pinned the {kind} host key of '{args.name}' ({args.fingerprint}).")
    return 0


def cmd_node_join_bundle(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        data = nodes.join_archive(config_dir, repo_root, args.name)
    except nodes.NodeError as exc:
        return _fail(exc, 2)
    output = Path(args.output)
    # The archive carries the authorized_keys line: not a secret, but nobody else's business.
    common.atomic_write_private(output, "")
    output.write_bytes(data)
    print(f"Join archive for '{args.name}': {output}")
    return 0


def cmd_node_push(args: argparse.Namespace) -> int:
    """Hand a node its release and its bundle."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
        if not args.all and not args.name:
            raise nodes.NodeError("name a node, or pass --all")
        names = list(topo.nodes) if args.all else [args.name]
        for name in names:
            if name not in topo.nodes:
                raise nodes.NodeError(f"no node named '{name}'")
            if topo.nodes[name].is_local:
                continue
            version = envtree.resolve_platform_version(repo_root)
            if args.checkout or nodes.read_state(config_dir, name).get("release") != version:
                print(f"node {name}: installing release {version}", flush=True)
                result = nodes.push_checkout(config_dir, repo_root, name)
                if not result.ok:
                    raise nodes.NodeError(
                        f"node '{name}': checkout-put failed (exit {result.returncode})"
                    )
                nodes.record_state(config_dir, name, release=version)
            print(f"node {name}: installing its bundle", flush=True)
            result = nodes.push_bundle(config_dir, repo_root, name)
            if not result.ok:
                raise nodes.NodeError(
                    f"node '{name}': bundle-put failed (exit {result.returncode})"
                )
            nodes.record_state(config_dir, name, bundle_pushed_at=_now())
    except (nodes.NodeError, executor.ExecutorError) as exc:
        return _fail(exc)
    return 0


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_node_renew_link(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
        if args.name not in topo.nodes:
            raise nodes.NodeError(f"no node named '{args.name}'")
        # Same names as before; the render below reissues it once more only if they changed.
        names = link.leaf_dir(config_dir, args.name) / "names"
        serves = [
            n.removeprefix("DNS:")
            for n in (names.read_text(encoding="utf-8").split() if names.is_file() else [])
            if n.startswith("DNS:") and n != f"DNS:{args.name}"
        ]
        link.issue_leaf(config_dir, topo.nodes[args.name], serves=serves, force=True)
    except (nodes.NodeError, link.LinkError) as exc:
        return _fail(exc)
    if _project(config_dir, repo_root) != 0:
        return 3
    not_after = link.cert_not_after(link.leaf_dir(config_dir, args.name) / "node.crt")
    print(
        f"New link certificate for '{args.name}'"
        + (f", valid until {not_after:%Y-%m-%d}." if not_after else ".")
    )
    return 0


def cmd_node_exec(args: argparse.Namespace) -> int:
    """Run one node verb through the node's executor, output streaming."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        ex = nodes.executor(config_dir, repo_root, args.name)
        return ex.run(list(args.verb)).returncode
    except (nodes.NodeError, executor.ExecutorError) as exc:
        return _fail(exc)


def cmd_topology_firewall(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        _manifest, topo = nodes.require_distributed(config_dir)
        env = topology.validation_env(config_dir, repo_root)
        profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
        plan = link.plan(topo, profiles, env)
    except (nodes.NodeError, link.LinkError) as exc:
        return _fail(exc, 2)
    print(link.format_rules(link.firewall_rules(plan), args.format))
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("node-register")
    p.add_argument("--name", required=True)
    p.add_argument("--address", required=True)
    p.add_argument("--ssh-user", default=None)
    p.add_argument("--ssh-port", type=int, default=None)
    p.add_argument("--ssh-host", default=None)
    p.add_argument("--root", default=None)
    p.add_argument("--bind-ip", default=None)
    p.add_argument("--gpu", default=None, choices=list(topology.GPU_HINTS))
    p.set_defaults(func=cmd_node_register)

    p = sub.add_parser("node-unregister")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_node_unregister)

    p = sub.add_parser("node-list")
    p.add_argument("--json", action="store_true")
    p.add_argument("--check", action="store_true")
    p.set_defaults(func=cmd_node_list)

    p = sub.add_parser("node-check")
    p.add_argument("--name", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_node_check)

    p = sub.add_parser("node-pending")
    p.set_defaults(func=cmd_node_pending)

    p = sub.add_parser("node-keyscan")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_node_keyscan)

    p = sub.add_parser("node-pin")
    p.add_argument("--name", required=True)
    p.add_argument("--fingerprint", required=True)
    p.set_defaults(func=cmd_node_pin)

    p = sub.add_parser("node-join-bundle")
    p.add_argument("--name", required=True)
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_node_join_bundle)

    p = sub.add_parser("node-push")
    p.add_argument("--name", default=None)
    p.add_argument("--all", action="store_true")
    p.add_argument("--checkout", action="store_true")
    p.set_defaults(func=cmd_node_push)

    p = sub.add_parser("node-renew-link")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_node_renew_link)

    p = sub.add_parser("node-exec")
    p.add_argument("--name", required=True)
    p.add_argument("verb", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_node_exec)

    p = sub.add_parser("topology-firewall")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.set_defaults(func=cmd_topology_firewall)
