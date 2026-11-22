"""The direct route to the SQL source: network `papaia-sql-uplink` and its host rules.

Everything that leaves the stack goes through papaia-egress (docs/egress.md), with one
exception, row K-14 of the communication matrix (security/comm-matrix.yaml,
docs/network.md): `mcp-mssql` reads the operator's SQL Server directly. That route is
made explicit and narrow here:

  * A SQL source is a protected host (security/protected-hosts.yaml) whose
    `catalog_entry` is `mssql.<name>`. It needs `ports` and at least one IPv4 address or
    range; the proxy refuses it for every source anyway.
  * Only with a SQL source, `mcp-mssql` of the one active add-on that has that service
    joins the network `<project>-sql-uplink` (not internal, fixed range
    PAPAIA_SQL_UPLINK_SUBNET), through a generated override next to the networks it
    already has. No other service ever joins it.
  * The network is IPv4 only (`enable_ipv6: false`) and has a fixed bridge name, so the
    host rules can name the interface the traffic enters on.
  * Host rules for the chain DOCKER-USER (written to security/sql-uplink-rules.sh, loaded
    by the operator as root) let only the listed addresses and ports out of that range
    and that bridge, and keep every other container away from the listed addresses and
    the SQL ports.
    papaia-ctl never changes the host firewall itself; `doctor network` compares the
    loaded chain with the rendered one.
"""

from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path

import yaml

from . import common, deployment, egress

SERVICE = "mcp-mssql"
NETWORK = "papaia-sql-uplink"
CATALOG_PREFIX = "mssql."
SUBNET_KEY = "PAPAIA_SQL_UPLINK_SUBNET"
DEFAULT_SUBNET = "10.255.254.0/29"
RULES_FILE = "security/sql-uplink-rules.sh"
DOCKER_USER = "DOCKER-USER"
LABEL = {"de.fidonis.network": "sql-uplink"}
BRIDGE_OPTION = "com.docker.network.bridge.name"
# The uplink holds a gateway and one container; anything larger than a /24 would only
# widen the source the host rules let out.
_MIN_PREFIX, _MAX_PREFIX = 24, 29
# A target range wider than this is no single production system.
_MIN_TARGET_PREFIX = 16


class SqlUplinkError(ValueError):
    """A SQL source or uplink setting that cannot be used; nothing is rendered."""


def root_env(config_dir: Path) -> dict[str, str]:
    return common.parse_env_file(config_dir / ".env")


def project(env: dict[str, str]) -> str:
    return env.get("PAPAIA_PROJECT") or env.get("COMPOSE_PROJECT_NAME") or "papaia"


def network_name(env: dict[str, str]) -> str:
    """The Docker name of the uplink: scoped to the installation like the other networks."""
    return f"{project(env)}-sql-uplink"


def _digest(env: dict[str, str]) -> str:
    return hashlib.sha256(project(env).encode("utf-8")).hexdigest()[:8]


def chain(env: dict[str, str]) -> str:
    """The installation's own chain; two installations on one host do not share it.
    iptables allows 28 characters."""
    return f"PAPAIA-SQL-{_digest(env).upper()}"


def bridge(env: dict[str, str]) -> str:
    """The host interface of the uplink, fixed so that the host rules can match on it.
    Linux allows 15 characters."""
    return f"psql-{_digest(env)}"


def jump_rule(chain_name: str) -> str:
    return f"-A {DOCKER_USER} -j {chain_name}"


def subnet(env: dict[str, str]) -> ipaddress.IPv4Network:
    """The fixed range of the uplink: a private IPv4 range from /24 to /29."""
    raw = (env.get(SUBNET_KEY) or DEFAULT_SUBNET).strip()
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError:
        raise SqlUplinkError(f"{SUBNET_KEY}: not an address range: {raw!r}") from None
    if (
        not isinstance(net, ipaddress.IPv4Network)
        or not net.is_private
        or net.is_loopback
        or net.is_link_local
        or not _MIN_PREFIX <= net.prefixlen <= _MAX_PREFIX
    ):
        raise SqlUplinkError(
            f"{SUBNET_KEY}: {raw!r} must be a private IPv4 range from"
            f" /{_MIN_PREFIX} to /{_MAX_PREFIX}"
        )
    return net


def targets(config_dir: Path) -> list[dict]:
    """The SQL sources: {name, catalog_entry, networks, ports} for every protected host
    with a catalog entry `mssql.<name>`. Host names stay with the proxy (it refuses them
    by name and address); the host rules need the addresses."""
    found: list[dict] = []
    # Read only: the render seeds the file (lib/egress.py); doctor never writes.
    if not (config_dir / egress.PROTECTED_HOSTS_FILE).is_file():
        return found
    for entry in egress.load_protected_entries(config_dir):
        catalog = entry["catalog_entry"]
        if not catalog or not catalog.startswith(CATALOG_PREFIX):
            continue
        where = f"{egress.PROTECTED_HOSTS_FILE}: {entry['name']}"
        if not entry["ports"]:
            raise SqlUplinkError(f"{where}: a SQL source needs its ports (for example [1433])")
        networks = []
        for host in entry["hosts"]:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                continue  # a name: the proxy handles it, the host rules cannot
            if not isinstance(net, ipaddress.IPv4Network):
                raise SqlUplinkError(
                    f"{where}: {host} is IPv6; the uplink is IPv4 only, list the IPv4 address"
                )
            if net.prefixlen < _MIN_TARGET_PREFIX or net.is_loopback or net.is_multicast:
                raise SqlUplinkError(f"{where}: {host} is no address of a SQL Server")
            networks.append(net)
        if not networks:
            raise SqlUplinkError(
                f"{where}: list the IPv4 address of the SQL Server as well; the host rules"
                " cannot use a name"
            )
        found.append(
            {
                "name": entry["name"],
                "catalog_entry": catalog,
                "networks": networks,
                "ports": entry["ports"],
            }
        )
    return found


def expected_rules(config_dir: Path) -> list[str]:
    """The chain as `iptables -S <chain>` prints it, or [] without a SQL source."""
    found = targets(config_dir)
    if not found:
        return []
    env = root_env(config_dir)
    name, source, iface = chain(env), subnet(env), bridge(env)
    rules = [f"-N {name}"]
    for target in found:
        for net in target["networks"]:
            if net.overlaps(source):
                raise SqlUplinkError(
                    f"{SUBNET_KEY} {source} overlaps the SQL source {target['name']} ({net})"
                )
            # The order of `iptables -S`: source, destination, interface, protocol.
            rules += [
                f"-A {name} -s {source} -d {net} -i {iface} -p tcp -m tcp --dport {port}"
                " -j RETURN"
                for port in target["ports"]
            ]
    # The uplink range from any other interface is forged; anything else from the
    # uplink's bridge is not a listed route.
    rules.append(f"-A {name} -s {source} -j DROP")
    rules.append(f"-A {name} -i {iface} -j DROP")
    seen: list[str] = []
    for target in found:
        seen += [str(n) for n in target["networks"] if str(n) not in seen]
    rules += [f"-A {name} -d {net} -j DROP" for net in seen]
    ports = sorted({p for target in found for p in target["ports"]})
    rules += [f"-A {name} -p tcp -m tcp --dport {port} -j DROP" for port in ports]
    return rules


def render_rules(config_dir: Path) -> Path | None:
    """Write the script that loads the host rules, or remove it without a SQL source."""
    path = config_dir / RULES_FILE
    rules = expected_rules(config_dir)
    if not rules:
        path.unlink(missing_ok=True)
        return None
    env = root_env(config_dir)
    name = chain(env)
    body = "\n".join(rules[1:])
    script = f"""#!/bin/sh
# Host rules of the direct route to the SQL source (row K-14 of the communication
# matrix, docs/network.md) for the installation '{project(env)}'.
# Written by papaia-ctl on every setup and start; edits are overwritten.
# Load as root on the Docker host:   sudo sh {path}
# 'papaia-ctl doctor network' compares the loaded chain with this file.
#
# From {subnet(env)} on bridge {bridge(env)} (network {network_name(env)}, member
# {SERVICE} only) only the listed addresses and ports; every other container never to
# them, never to their ports.
# The rules live in the running kernel: load them again after every reboot of the host.
set -eu
iptables-restore --noflush <<'RULES'
*filter
:{name} - [0:0]
{body}
COMMIT
RULES
iptables -C {DOCKER_USER} -j {name} 2>/dev/null || iptables -I {DOCKER_USER} 1 -j {name}
"""
    common.atomic_write(path, script)
    path.chmod(0o644)
    return path


def _services(addon_path: Path) -> dict:
    compose = addon_path / "docker-compose.yml"
    if not compose.is_file():
        return {}
    try:
        doc = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}
    services = doc.get("services") if isinstance(doc, dict) else None
    return services if isinstance(services, dict) else {}


def sql_addon(config_dir: Path, repo_root: Path | None) -> tuple[str, Path] | None:
    """(name, path) of the one active add-on with a service `mcp-mssql`, or None."""
    base = repo_root if repo_root is not None else Path.cwd()
    found = []
    for addon in deployment.active_addons(deployment.load(config_dir)):
        if not addon.get("name") or not addon.get("path"):
            continue
        path = deployment.resolve_addon_path(addon, base)
        if SERVICE in _services(path):
            found.append((str(addon["name"]), path))
    if len(found) > 1:
        names = ", ".join(n for n, _ in found)
        raise SqlUplinkError(f"more than one active add-on has a service {SERVICE}: {names}")
    return found[0] if found else None


def override_path(config_dir: Path, name: str) -> Path:
    return config_dir / "overrides" / "addons" / f"docker-compose.{name}-sql-uplink.override.yml"


def generate_override(config_dir: Path, repo_root: Path | None) -> Path | None:
    """Write the override that puts `mcp-mssql` on the uplink, or remove it. Only with a
    SQL source and exactly one add-on with that service; every other add-on's file goes."""
    from . import gen_override  # the networks a service already has

    names = [
        str(a["name"])
        for a in (deployment.load(config_dir) or {}).get("addons") or []
        if isinstance(a.get("name"), str) and a["name"]
    ]
    try:
        chosen = sql_addon(config_dir, repo_root) if targets(config_dir) else None
    except (SqlUplinkError, egress.EgressError):
        for name in names:
            override_path(config_dir, name).unlink(missing_ok=True)
        raise
    for name in names:
        if chosen is None or name != chosen[0]:
            override_path(config_dir, name).unlink(missing_ok=True)
    if chosen is None:
        return None
    name, path = chosen
    env = root_env(config_dir)
    networks = [n for n in gen_override._service_networks(path, SERVICE) if n != NETWORK]
    override = {
        "services": {SERVICE: {"networks": [*networks, NETWORK]}},
        "networks": {
            NETWORK: {
                "name": network_name(env),
                "driver": "bridge",
                # The interface the host rules match on.
                "driver_opts": {BRIDGE_OPTION: bridge(env)},
                # The route out; the host rules are what keeps it narrow.
                "internal": False,
                # The host rules are IPv4 rules: an IPv6 range (also one the daemon adds by
                # default to new networks) would be a way out none of them covers.
                "enable_ipv6": False,
                "ipam": {"config": [{"subnet": str(subnet(env))}]},
                "labels": dict(LABEL),
            }
        },
    }
    out = override_path(config_dir, name)
    common.atomic_write(out, yaml.safe_dump(override, sort_keys=False, default_flow_style=False))
    return out


def compare(expected: list[str], chain_name: str, live_chain: str, docker_user: str) -> list[str]:
    """What differs between the rendered chain and `iptables -S` of the host: missing and
    unexpected rules, the order, and the jump, which must be DOCKER-USER's first rule."""
    live = [line.strip() for line in live_chain.splitlines() if line.strip()]
    problems = [f"missing: {line}" for line in expected if line not in live]
    problems += [f"unexpected: {line}" for line in live if line not in expected]
    if not problems and live != expected:
        problems.append(f"the rules of {chain_name} are in another order")
    jump = jump_rule(chain_name)
    user = [
        line.strip()
        for line in docker_user.splitlines()
        if line.strip().startswith(f"-A {DOCKER_USER} ")
    ]
    if jump not in user:
        problems.append(f"missing: {jump}")
    elif user[0] != jump:
        problems.append(f"the jump to {chain_name} is not the first rule of {DOCKER_USER}")
    elif user.count(jump) > 1:
        problems.append(f"the jump to {chain_name} is in {DOCKER_USER} more than once")
    return problems
