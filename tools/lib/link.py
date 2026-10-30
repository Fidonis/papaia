"""The link between the nodes of a distributed installation.

Every service keeps its address (`litellm:4000`, `keycloak:8443`, `librechat:3080`) on every
node. On a node where a service does not run, a link gateway carries the service's name as a
network alias on `papaia-net` and listens on its usual port. The gateway wraps the connection
in mutual TLS and hands it to the gateway of the node the service runs on, which unwraps it
and forwards it to the real container. The inner protocol is never touched: HTTP, WebSocket,
SSE and Keycloak's own TLS (with its certificate for the name `keycloak`) pass through as they
are.

    caller node                               target node
    librechat --> keycloak:8443  ==mTLS==>  :7443 --SNI keycloak--> keycloak:8443
                  (gateway alias)            (link port, client certificate required)

What this module decides, all of it from the topology and the static `EDGES` table:

* **which connections cross a node boundary** (`plan`): an edge whose caller and target share
  a node produces nothing;
* **the gateway configuration of each node** (HAProxy in TCP mode): one frontend per remote
  service on the caller side, one link port on the target side that requires a client
  certificate of the link CA, routes by SNI and only lets a client node reach the services
  the edge table allows it. A peer that is down means a refused connection, never a
  clear-text fallback: no backend has a server without `ssl verify required`;
* **the link CA** (`ensure_pki`): separate from the Keycloak CA. Its key stays in
  `$PAPAIA_CONFIG_DIR/link-ca/` on the controller; a node receives its own leaf certificate
  and key and the CA certificate, nothing else;
* **the firewall matrix** (`firewall_rules`): the connections the installation really uses.
  papaia never applies firewall rules itself.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import common
from .topology import Node, Topology, active_services

GATEWAY_PROFILE = "link-gateway"
GATEWAY_SERVICE = "link-gateway"
GATEWAY_FRAGMENT = "src/infra/link-gateway/docker-compose.yml"
GATEWAY_OVERRIDE = "docker-compose.link-gateway.override.yml"
# Where the official HAProxy image reads its configuration.
GATEWAY_CONFIG_PATH = "/usr/local/etc/haproxy"

CA_DIR = "link-ca"
LINK_DIR = "link"
LEAF_DAYS = 397
CA_DAYS = 3650
RENEW_WARN_DAYS = 30

# Long enough for a streamed answer that pauses between tokens; the services' own
# timeouts still apply inside the tunnel.
TUNNEL_TIMEOUT = "1h"
CONNECT_TIMEOUT = "5s"
CHECK_INTERVAL = "5s"


class LinkError(Exception):
    """A topology the link cannot serve (two remote services on one port), or a failure
    to create the link certificates."""


@dataclass(frozen=True)
class Edge:
    """One connection a service opens to another, by the address it uses."""

    caller: str  # catalogue service that opens the connection
    target: str  # catalogue service it reaches
    host: str  # the name the caller dials (a Compose service, or the public auth host)
    port: int
    purpose: str
    required: bool = True


# Every connection between catalogue services, by the address the caller uses. A
# connection inside one service (LibreChat to its MongoDB) is not listed: it never
# crosses a node.
EDGES: tuple[Edge, ...] = (
    Edge("librechat", "keycloak", "keycloak", 8443, "OIDC token exchange and keys"),
    Edge("librechat", "litellm", "litellm", 4000, "chat completions"),
    Edge("librechat", "rag", "qdrant-mcp", 8000, "MCP search tools", required=False),
    Edge("librechat", "rag", "qdrant-ingest", 8300, "MCP ingest tools", required=False),
    Edge("nginx", "keycloak", "keycloak", 8443, "public auth host and oauth2-proxy sign-in"),
    Edge("nginx", "librechat", "librechat", 3080, "public chat URL"),
    Edge("nginx", "litellm", "litellm", 4000, "public LiteLLM URL", required=False),
    Edge("nginx", "localai", "localai", 8080, "public LocalAI URL", required=False),
    Edge("nginx", "manager", "papaia-manager", 8000, "public manager URL", required=False),
    Edge("nginx", "rag", "qdrant", 6333, "public Qdrant URL", required=False),
    Edge("litellm", "keycloak", "keycloak", 8443, "admin UI sign-in", required=False),
    Edge("litellm", "localai", "localai", 8080, "local models", required=False),
    Edge("localai", "keycloak", "keycloak", 8443, "API sign-in", required=False),
    Edge("websearch", "litellm", "litellm", 4000, "reranking and extraction", required=False),
    Edge("rag", "litellm", "litellm", 4000, "embeddings"),
    Edge("rag", "keycloak", "keycloak", 8443, "MCP sign-in", required=False),
    Edge("keycloak", "smtp", "smtp-relay", 587, "password reset mail", required=False),
    Edge("manager", "keycloak", "keycloak", 8443, "Users & Roles"),
    Edge("manager", "litellm", "litellm", 4000, "Models & Usage", required=False),
)

# Services that discover the identity provider through its public URL from inside the
# container (LibreChat fetches the issuer's discovery document). Where the proxy runs on
# another node, the gateway carries the public auth host name as well and passes the TCP
# stream to the proxy's port 443 there: the real certificate, no split DNS.
PUBLIC_AUTH_CALLERS = ("librechat", "localai", "rag", "manager", "litellm")


@dataclass(frozen=True)
class Route:
    """One remote address a caller node reaches through its gateway."""

    host: str
    port: int
    target_node: str
    target_host: str  # the Compose service on the target node
    target_port: int
    target_service: str
    purposes: tuple[str, ...]
    required: bool

    @property
    def sni(self) -> str:
        return self.host


@dataclass
class NodeLink:
    node: str
    # Caller side: what this node reaches on other nodes.
    routes: list[Route] = field(default_factory=list)
    # Target side: SNI name -> (local host, port, client nodes allowed).
    inbound: dict[str, tuple[str, int, list[str]]] = field(default_factory=dict)

    @property
    def aliases(self) -> list[str]:
        return sorted({route.host for route in self.routes})

    @property
    def peers(self) -> list[str]:
        return sorted({route.target_node for route in self.routes})


@dataclass
class LinkPlan:
    topology: Topology
    nodes: dict[str, NodeLink]

    def for_node(self, name: str) -> NodeLink:
        return self.nodes[name]


def _auth_host(env: dict[str, str]) -> str | None:
    """The public auth host name, when the bundled Keycloak serves it by name."""
    if env.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        return None
    try:
        parts = urlsplit(env.get("AUTH_HOST", ""))
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or not host or port is not None or "." not in host:
        return None
    return host


def edges(topo: Topology, active: list[str], env: dict[str, str] | None = None) -> list[Edge]:
    """The edges that cross a node boundary in this topology."""
    found = [
        edge
        for edge in EDGES
        if edge.caller in active
        and edge.target in active
        and topo.node_of(edge.caller) != topo.node_of(edge.target)
    ]
    auth_host = _auth_host(env or {})
    if auth_host and "keycloak" in active and "nginx" in active:
        for caller in PUBLIC_AUTH_CALLERS:
            if caller in active and topo.node_of(caller) != topo.node_of("nginx"):
                found.append(
                    Edge(caller, "nginx", auth_host, 443, "OIDC discovery via the public auth host")
                )
    return found


def _target_host(edge: Edge) -> tuple[str, int]:
    """Where the target node's gateway forwards the edge to."""
    if edge.target == "nginx" and edge.port == 443:
        return "nginx-proxy-manager", 443
    return edge.host, edge.port


def plan(topo: Topology, active_profiles: list[str], env: dict[str, str]) -> LinkPlan:
    active = active_services(active_profiles)
    nodes = {name: NodeLink(name) for name in topo.nodes}
    routes: dict[tuple[str, str, int], dict] = {}
    for edge in edges(topo, active, env):
        caller_node = topo.node_of(edge.caller)
        target_node = topo.node_of(edge.target)
        key = (caller_node, edge.host, edge.port)
        entry = routes.setdefault(
            key,
            {"edge": edge, "target_node": target_node, "purposes": [], "required": False},
        )
        if entry["target_node"] != target_node:
            raise LinkError(f"'{edge.host}:{edge.port}' resolves to two nodes from '{caller_node}'")
        if edge.purpose not in entry["purposes"]:
            entry["purposes"].append(edge.purpose)
        entry["required"] = entry["required"] or edge.required
        local_host, local_port = _target_host(edge)
        sni_entry = nodes[target_node].inbound.setdefault(edge.host, (local_host, local_port, []))
        if caller_node not in sni_entry[2]:
            sni_entry[2].append(caller_node)

    for (caller_node, host, port), entry in sorted(routes.items()):
        edge = entry["edge"]
        local_host, local_port = _target_host(edge)
        nodes[caller_node].routes.append(
            Route(
                host=host,
                port=port,
                target_node=entry["target_node"],
                target_host=local_host,
                target_port=local_port,
                target_service=edge.target,
                purposes=tuple(entry["purposes"]),
                required=entry["required"],
            )
        )

    for link in nodes.values():
        by_port: dict[int, str] = {}
        for route in link.routes:
            other = by_port.setdefault(route.port, route.host)
            if other != route.host:
                raise LinkError(
                    f"node '{link.node}' reaches both '{other}' and '{route.host}' on port"
                    f" {route.port} on other nodes; the gateway can carry only one of them"
                    " per port. Place the two services on the same node."
                )
        if link.inbound and topo.link_port in {r.port for r in link.routes}:
            raise LinkError(
                f"node '{link.node}' reaches a service on port {topo.link_port}, which is"
                " also its link port; choose another link port"
            )
    return LinkPlan(topo, nodes)


# ─────────────────────────────────────────────────────────────────────────
# Gateway configuration
# ─────────────────────────────────────────────────────────────────────────


def _ident(text: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in text)


def link_bind_address(node: Node) -> str:
    """The address the link port is published on: the node's address when it is an IP
    literal, otherwise every address of the node."""
    try:
        ipaddress.ip_address(node.address)
    except ValueError:
        return "0.0.0.0"
    return node.address


def haproxy_config(plan_: LinkPlan, node: str) -> str:
    topo = plan_.topology
    link = plan_.for_node(node)
    conf = f"{GATEWAY_CONFIG_PATH}"
    lines = [
        f"# Link gateway of node '{node}'. Generated by papaia-ctl -- do not edit;",
        "# it is rewritten on every render.",
        "global",
        "    log stdout format raw local0 info",
        "    maxconn 4096",
        "    ssl-default-bind-options ssl-min-ver TLSv1.2",
        "    ssl-default-server-options ssl-min-ver TLSv1.2",
        "",
        "resolvers docker",
        "    nameserver dns 127.0.0.11:53",
        "    hold valid 10s",
        "",
        "defaults",
        "    mode tcp",
        "    log global",
        "    option tcplog",
        "    option clitcpka",
        "    option srvtcpka",
        f"    timeout connect {CONNECT_TIMEOUT}",
        f"    timeout client {TUNNEL_TIMEOUT}",
        f"    timeout server {TUNNEL_TIMEOUT}",
        f"    timeout tunnel {TUNNEL_TIMEOUT}",
        "    timeout client-fin 30s",
        "    timeout server-fin 30s",
    ]
    if link.routes:
        lines += ["", "# --- outgoing: services of other nodes, under their usual names ---"]
    for route in link.routes:
        peer = topo.nodes[route.target_node]
        name = f"{_ident(route.host)}_{route.port}"
        lines += [
            "",
            f"# {route.host}:{route.port} on '{route.target_node}': {', '.join(route.purposes)}",
            f"frontend out_{name}",
            f"    bind :{route.port}",
            f"    default_backend peer_{name}",
            f"backend peer_{name}",
            # verify required + the link CA: a peer without a certificate of this
            # installation is never talked to, and there is no server without TLS.
            # The peer's certificate is checked against the SNI name: only the node that
            # serves this service on the link has it in its certificate.
            f"    server {_ident(route.target_node)} {peer.address}:{topo.link_port}"
            f" ssl verify required ca-file {conf}/ca.crt crt {conf}/node.pem"
            f" sni str({route.sni}) check check-ssl check-sni {route.sni}"
            f" inter {CHECK_INTERVAL} fastinter 1s downinter 2s rise 1 fall 3",
        ]
    if link.inbound:
        lines += [
            "",
            "# --- incoming: the link port ---",
            "frontend link_in",
            f"    bind :{topo.link_port} ssl crt {conf}/node.pem ca-file {conf}/ca.crt"
            " verify required",
        ]
        clients = sorted({c for _h, (_lh, _lp, cs) in link.inbound.items() for c in cs})
        for client in clients:
            lines.append(f"    acl client_{_ident(client)} ssl_c_s_dn(CN) -m str {client}")
        for host, (_local_host, _local_port, allowed) in sorted(link.inbound.items()):
            acl = f"to_{_ident(host)}"
            lines.append(f"    acl {acl} ssl_fc_sni -m str {host}")
            for client in sorted(allowed):
                lines.append(f"    use_backend in_{_ident(host)} if {acl} client_{_ident(client)}")
        lines += [
            "    default_backend link_refused",
            "",
            "backend link_refused",
            "    tcp-request content reject",
        ]
        for host, (local_host, local_port, _allowed) in sorted(link.inbound.items()):
            lines += [
                "",
                f"backend in_{_ident(host)}",
                f"    server local {local_host}:{local_port} resolvers docker"
                " init-addr last,libc,none",
            ]
    return "\n".join(lines) + "\n"


def gateway_override(plan_: LinkPlan, node: Node, bundle_root: str) -> dict:
    """The node-specific part of the gateway's Compose service."""
    topo = plan_.topology
    link = plan_.for_node(node.name)
    service: dict = {
        "volumes": [f"{bundle_root.rstrip('/')}/{LINK_DIR}:{GATEWAY_CONFIG_PATH}:ro"],
    }
    if link.inbound:
        service["ports"] = [f"{link_bind_address(node)}:{topo.link_port}:{topo.link_port}"]
    network: dict = {}
    if link.aliases:
        network["aliases"] = link.aliases
    service["networks"] = {"papaia-net": network or None}
    return {"services": {GATEWAY_SERVICE: service}}


def edge_summary(plan_: LinkPlan, node: str) -> dict:
    """What the node's own tools need to know about its link: the peers it calls and the
    addresses it serves. Written into the bundle as `link/edges.json`."""
    topo = plan_.topology
    link = plan_.for_node(node)
    return {
        "node": node,
        "link_port": topo.link_port,
        "outgoing": [
            {
                "host": route.host,
                "port": route.port,
                "peer": route.target_node,
                "peer_address": topo.nodes[route.target_node].address,
                "purposes": list(route.purposes),
                "required": route.required,
            }
            for route in link.routes
        ],
        "incoming": [
            {"host": host, "forward": f"{lh}:{lp}", "clients": sorted(clients)}
            for host, (lh, lp, clients) in sorted(link.inbound.items())
        ],
    }


# ─────────────────────────────────────────────────────────────────────────
# Link PKI
# ─────────────────────────────────────────────────────────────────────────


def ca_dir(config_dir: Path) -> Path:
    return config_dir / CA_DIR


def leaf_dir(config_dir: Path, node: str) -> Path:
    """The node's link key and certificate on the controller. Outside the bundle
    directory, which is rewritten on every render."""
    return config_dir / "nodes" / node / LINK_DIR


def _openssl(args: list[str]) -> None:
    try:
        done = subprocess.run(
            ["openssl", *args], capture_output=True, text=True, timeout=60, check=False
        )
    except FileNotFoundError as exc:
        raise LinkError("openssl not found; it is needed for the link certificates") from exc
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()
        raise LinkError(f"openssl {args[0]} failed: {detail[-1] if detail else done.returncode}")


def _new_key(path: Path) -> None:
    tmp = path.with_suffix(".tmp")
    _openssl(
        ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(tmp)]
    )
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ensure_ca(config_dir: Path) -> tuple[Path, Path]:
    """The link CA's key and certificate, created on first use."""
    directory = ca_dir(config_dir)
    key, cert = directory / "ca.key", directory / "ca.crt"
    if key.is_file() and cert.is_file():
        return key, cert
    common.ensure_dir(directory)
    os.chmod(directory, 0o700)
    _new_key(key)
    _openssl(
        [
            "req",
            "-new",
            "-x509",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            str(CA_DAYS),
            "-subj",
            "/CN=papaia-link-ca/O=papAIa",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    return key, cert


def leaf_names(node: Node, serves: list[str] | tuple[str, ...] = ()) -> list[str]:
    """The subject alternative names of a node's link certificate: the node itself, and
    every name it serves on its link port. A gateway that sets SNI checks the peer's
    certificate against that name, so the edge node proves it may answer for `keycloak`,
    not only that it holds a certificate of this installation."""
    names = [f"DNS:{node.name}"]
    try:
        ipaddress.ip_address(node.address)
        names.append(f"IP:{node.address}")
    except ValueError:
        if node.address:
            names.append(f"DNS:{node.address}")
    names += [f"DNS:{host}" for host in sorted(set(serves)) if f"DNS:{host}" not in names]
    return names


def issue_leaf(
    config_dir: Path, node: Node, *, serves: list[str] | tuple[str, ...] = (), force: bool = False
) -> tuple[Path, Path]:
    """The node's link key and certificate, signed by the link CA. Kept unless `force`
    (`papaia-ctl node renew-link`) or its names changed: a new address, or services
    placed on the node or taken off it."""
    ca_key, ca_cert = ensure_ca(config_dir)
    directory = leaf_dir(config_dir, node.name)
    key, cert = directory / "node.key", directory / "node.crt"
    names = leaf_names(node, serves)
    stamp = directory / "names"
    current = stamp.read_text(encoding="utf-8").split() if stamp.is_file() else []
    if not force and key.is_file() and cert.is_file() and current == names:
        return key, cert
    common.ensure_dir(directory)
    os.chmod(directory, 0o700)
    _new_key(key)
    csr = directory / "node.csr"
    ext = directory / "node.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName={','.join(names)}\n",
        encoding="utf-8",
    )
    try:
        _openssl(
            [
                "req",
                "-new",
                "-key",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={node.name}/O=papAIa",
            ]
        )
        _openssl(
            [
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(cert),
                "-days",
                str(LEAF_DAYS),
                "-extfile",
                str(ext),
            ]
        )
    finally:
        csr.unlink(missing_ok=True)
        ext.unlink(missing_ok=True)
        (ca_dir(config_dir) / "ca.srl").unlink(missing_ok=True)
    common.atomic_write(stamp, "\n".join(names) + "\n")
    (directory / "address").unlink(missing_ok=True)
    return key, cert


def write_node_files(
    staging: Path, config_dir: Path, plan_: LinkPlan, node: Node, bundle_root: str
) -> None:
    """The node's link material and gateway configuration, into its bundle."""
    key, cert = issue_leaf(config_dir, node, serves=list(plan_.for_node(node.name).inbound))
    _ca_key, ca_cert = ensure_ca(config_dir)
    target = staging / LINK_DIR
    common.ensure_dir(target)
    common.atomic_write(target / "ca.crt", ca_cert.read_text(encoding="utf-8"))
    common.atomic_write(target / "node.crt", cert.read_text(encoding="utf-8"))
    common.atomic_write_private(target / "node.key", key.read_text(encoding="utf-8"))
    # HAProxy reads certificate and key from one file.
    common.atomic_write_private(
        target / "node.pem",
        cert.read_text(encoding="utf-8") + key.read_text(encoding="utf-8"),
    )
    common.atomic_write(target / "haproxy.cfg", haproxy_config(plan_, node.name))
    common.atomic_write(
        target / "edges.json", json.dumps(edge_summary(plan_, node.name), indent=2) + "\n"
    )
    common.atomic_write(
        staging / "overrides" / GATEWAY_OVERRIDE,
        yaml.safe_dump(gateway_override(plan_, node, bundle_root), sort_keys=False),
    )


def cert_not_after(path: Path) -> datetime | None:
    try:
        done = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = done.stdout.strip().partition("=")[2]
    try:
        return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────────────────────
# Firewall matrix
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    source: str
    destination: str
    destination_address: str
    port: int
    protocol: str
    purpose: str

    def to_dict(self) -> dict:
        return {
            "from": self.source,
            "to": self.destination,
            "to_address": self.destination_address,
            "port": self.port,
            "protocol": self.protocol,
            "purpose": self.purpose,
        }


def firewall_rules(plan_: LinkPlan) -> list[Rule]:
    """The connections between nodes this installation opens: SSH from the controller to
    every other node, and the link port wherever a node calls a service on another."""
    topo = plan_.topology
    rules: list[Rule] = []
    for node in topo.nodes.values():
        if node.name == topo.controller or node.is_local:
            continue
        rules.append(
            Rule(
                topo.controller,
                node.name,
                node.ssh_target,
                node.ssh_port,
                "tcp",
                "control channel (SSH, forced command)",
            )
        )
    pairs: dict[tuple[str, str], list[str]] = {}
    for link in plan_.nodes.values():
        for route in link.routes:
            pairs.setdefault((link.node, route.target_node), []).append(
                f"{route.host}:{route.port}"
            )
    for (source, destination), hosts in sorted(pairs.items()):
        rules.append(
            Rule(
                source,
                destination,
                topo.nodes[destination].address,
                topo.link_port,
                "tcp",
                "link: " + ", ".join(sorted(set(hosts))),
            )
        )
    return rules


def format_rules(rules: list[Rule], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([r.to_dict() for r in rules], indent=2)
    if fmt == "csv":
        lines = ["from,to,to_address,port,protocol,purpose"]
        lines += [
            ",".join(
                [
                    r.source,
                    r.destination,
                    r.destination_address,
                    str(r.port),
                    r.protocol,
                    '"' + r.purpose.replace('"', "'") + '"',
                ]
            )
            for r in rules
        ]
        return "\n".join(lines)
    header = ("FROM", "TO", "ADDRESS", "PORT", "PURPOSE")
    rows = [
        (r.source, r.destination, r.destination_address, f"{r.port}/{r.protocol}", r.purpose)
        for r in rules
    ]
    widths = [
        max(len(header[i]), *(len(row[i]) for row in rows)) if rows else len(header[i])
        for i in range(4)
    ]
    out = ["  ".join(header[i].ljust(widths[i]) for i in range(4)) + "  " + header[4]]
    out += ["  ".join(row[i].ljust(widths[i]) for i in range(4)) + "  " + row[4] for row in rows]
    if not rows:
        out.append("(no connections between nodes)")
    return "\n".join(out)
