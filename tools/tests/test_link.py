"""The link between nodes: which connections cross a node, the gateway configuration, the
link CA and the firewall matrix -- and, where an `haproxy` binary is at hand, the gateway
itself, with real mutual TLS between two gateway processes."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import pytest
from test_topology import ALL_PROFILES, two_nodes

from lib import link, topology
from lib.topology import Node, Topology

ENV = {
    "AUTH_PROVIDER": "internal_keycloak",
    "AUTH_HOST": "https://auth.example.org",
}


def split() -> Topology:
    return two_nodes(**topology.preset_placement("dmz-split", "edge"))


def edge_preset() -> Topology:
    return two_nodes(**topology.preset_placement("dmz-edge", "edge"))


# ─────────────────────────────────────────────────────────────────────────
# plan
# ─────────────────────────────────────────────────────────────────────────


def test_an_edge_inside_one_node_produces_nothing():
    plan = link.plan(two_nodes(), ALL_PROFILES, ENV)
    assert all(not n.routes and not n.inbound for n in plan.nodes.values())


def test_dmz_split_aliases_on_each_side():
    plan = link.plan(split(), ALL_PROFILES, ENV)
    assert plan.for_node("internal").aliases == ["auth.example.org", "keycloak", "litellm"]
    assert plan.for_node("edge").aliases == ["librechat", "localai", "papaia-manager", "qdrant"]


def test_dmz_edge_keeps_keycloak_internal():
    plan = link.plan(edge_preset(), ALL_PROFILES, ENV)
    assert "keycloak" in plan.for_node("edge").aliases
    assert "keycloak" not in plan.for_node("internal").aliases
    # The proxy reaches the public auth host on its own node; no alias for it anywhere.
    assert "auth.example.org" not in plan.for_node("edge").aliases


def test_the_public_auth_host_leads_to_the_proxy_port_443():
    plan = link.plan(split(), ALL_PROFILES, ENV)
    host, port, clients = plan.for_node("edge").inbound["auth.example.org"]
    assert (host, port, clients) == ("nginx-proxy-manager", 443, ["internal"])


def test_no_public_auth_alias_for_an_external_provider():
    env = {"AUTH_PROVIDER": "external_oidc", "AUTH_HOST": "https://auth.example.org"}
    plan = link.plan(split(), [p for p in ALL_PROFILES if p != "keycloak"], env)
    assert "auth.example.org" not in plan.for_node("internal").aliases


def test_a_target_only_admits_the_nodes_whose_services_call_it():
    three = Topology(
        mode="distributed",
        controller="internal",
        nodes={
            "internal": Node("internal", address="10.0.2.10", executor="local"),
            "edge": Node("edge", address="10.0.1.10"),
            "gpu": Node("gpu", address="10.0.3.10", gpu="nvidia"),
        },
        placement={"nginx": "edge", "keycloak": "edge", "smtp": "edge", "localai": "gpu"},
    )
    plan = link.plan(three, ALL_PROFILES, ENV)
    # LocalAI is called by LiteLLM (internal) and the proxy (edge), never by anything else.
    assert sorted(plan.for_node("gpu").inbound["localai"][2]) == ["edge", "internal"]
    # Keycloak on the edge is called from internal and from LocalAI's node.
    assert sorted(plan.for_node("edge").inbound["keycloak"][2]) == ["gpu", "internal"]
    # The proxy calls LibreChat; nobody on the GPU node does.
    assert plan.for_node("internal").inbound["librechat"][2] == ["edge"]


def test_two_remote_services_on_one_port_are_refused():
    original = link.EDGES
    try:
        link.EDGES = (*original, link.Edge("librechat", "keycloak", "keycloak-alt", 4000, "x"))
        with pytest.raises(link.LinkError, match="port 4000"):
            link.plan(split(), ALL_PROFILES, ENV)
    finally:
        link.EDGES = original


# ─────────────────────────────────────────────────────────────────────────
# gateway configuration
# ─────────────────────────────────────────────────────────────────────────


def test_every_outgoing_server_requires_tls_with_the_link_ca():
    plan = link.plan(split(), ALL_PROFILES, ENV)
    for node in ("edge", "internal"):
        config = link.haproxy_config(plan, node)
        servers = [line for line in config.splitlines() if line.strip().startswith("server ")]
        outgoing = [s for s in servers if ":7443" in s]
        assert outgoing, node
        for line in outgoing:
            assert " ssl verify required " in line
            assert "ca-file /usr/local/etc/haproxy/ca.crt" in line
            assert "crt /usr/local/etc/haproxy/node.pem" in line
            assert " sni str(" in line
        # The only servers without TLS are the local services behind the link port.
        for line in servers:
            if ":7443" not in line:
                assert "resolvers docker" in line


def test_the_link_port_requires_a_client_certificate_and_refuses_the_rest():
    config = link.haproxy_config(link.plan(split(), ALL_PROFILES, ENV), "edge")
    bind = next(line for line in config.splitlines() if "bind :7443" in line)
    assert "verify required" in bind and "ca-file" in bind
    assert "default_backend link_refused" in config
    assert "backend link_refused\n    tcp-request content reject" in config


def test_a_node_without_callers_has_no_link_port():
    plan = link.plan(split(), ALL_PROFILES, ENV)
    override = link.gateway_override(plan, split().nodes["edge"], "/srv/papaia-node/config")
    assert override["services"]["link-gateway"]["ports"] == ["10.0.1.10:7443:7443"]
    lonely = link.plan(two_nodes(), ALL_PROFILES, ENV)
    assert (
        "ports"
        not in link.gateway_override(lonely, two_nodes().nodes["edge"], "/x")["services"][
            "link-gateway"
        ]
    )


def test_the_link_port_binds_to_the_node_address_only():
    assert link.link_bind_address(Node("x", address="192.0.2.7")) == "192.0.2.7"
    assert link.link_bind_address(Node("x", address="edge.example.org")) == "0.0.0.0"


def test_long_answers_are_not_cut_by_the_gateway():
    config = link.haproxy_config(link.plan(split(), ALL_PROFILES, ENV), "internal")
    assert "timeout tunnel 1h" in config
    assert "option clitcpka" in config and "option srvtcpka" in config


def _write_material(tmp_path: Path, topo: Topology) -> Path:
    config = tmp_path / "config"
    for node in topo.nodes.values():
        link.issue_leaf(config, node)
    return config


@pytest.mark.skipif(shutil.which("haproxy") is None, reason="haproxy is not installed")
@pytest.mark.parametrize("topo", [split(), edge_preset()], ids=["dmz-split", "dmz-edge"])
def test_the_generated_configuration_is_valid_haproxy(tmp_path: Path, topo: Topology):
    config = _write_material(tmp_path, topo)
    plan = link.plan(topo, ALL_PROFILES, ENV)
    for node in topo.nodes.values():
        staging = tmp_path / node.name
        link.write_node_files(staging, config, plan, node, "/unused")
        text = (staging / "link" / "haproxy.cfg").read_text()
        text = text.replace(link.GATEWAY_CONFIG_PATH, str(staging / "link"))
        cfg = staging / "check.cfg"
        cfg.write_text(text)
        done = subprocess.run(["haproxy", "-c", "-f", str(cfg)], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr


# ─────────────────────────────────────────────────────────────────────────
# PKI
# ─────────────────────────────────────────────────────────────────────────


def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def test_the_ca_is_created_once_and_its_key_is_private(tmp_path: Path):
    key, cert = link.ensure_ca(tmp_path)
    assert (key.stat().st_mode & 0o777) == 0o600
    first = cert.read_text()
    link.ensure_ca(tmp_path)
    assert cert.read_text() == first
    assert "CA:TRUE" in openssl("x509", "-in", str(cert), "-noout", "-text")


def test_a_leaf_is_signed_by_the_link_ca_for_client_and_server(tmp_path: Path):
    node = Node("edge", address="10.0.1.10")
    key, cert = link.issue_leaf(tmp_path, node)
    _ca_key, ca = link.ensure_ca(tmp_path)
    assert openssl("verify", "-CAfile", str(ca), str(cert)).strip().endswith("OK")
    text = openssl("x509", "-in", str(cert), "-noout", "-text")
    assert "DNS:edge" in text and "IP Address:10.0.1.10" in text
    assert "TLS Web Server Authentication" in text and "TLS Web Client Authentication" in text
    assert (key.stat().st_mode & 0o777) == 0o600


def test_a_leaf_is_kept_until_renewed_or_its_names_change(tmp_path: Path):
    node = Node("edge", address="10.0.1.10")
    _key, cert = link.issue_leaf(tmp_path, node, serves=["keycloak"])
    first = cert.read_text()
    link.issue_leaf(tmp_path, node, serves=["keycloak"])
    assert cert.read_text() == first
    link.issue_leaf(tmp_path, node, serves=["keycloak"], force=True)
    renewed = cert.read_text()
    assert renewed != first
    link.issue_leaf(tmp_path, Node("edge", address="10.0.1.11"), serves=["keycloak"])
    moved = cert.read_text()
    assert moved != renewed
    link.issue_leaf(tmp_path, Node("edge", address="10.0.1.11"), serves=["keycloak", "litellm"])
    assert cert.read_text() != moved


def test_a_leaf_names_the_services_its_node_serves(tmp_path: Path):
    _key, cert = link.issue_leaf(
        tmp_path, Node("edge", address="10.0.1.10"), serves=["litellm", "keycloak"]
    )
    text = openssl("x509", "-in", str(cert), "-noout", "-ext", "subjectAltName")
    for name in ("DNS:edge", "IP Address:10.0.1.10", "DNS:keycloak", "DNS:litellm"):
        assert name in text


def test_the_ca_key_never_reaches_a_node(tmp_path: Path):
    topo = split()
    config = _write_material(tmp_path, topo)
    plan = link.plan(topo, ALL_PROFILES, ENV)
    ca_key = (config / "link-ca" / "ca.key").read_text()
    for node in topo.nodes.values():
        staging = tmp_path / f"bundle-{node.name}"
        link.write_node_files(staging, config, plan, node, "/x")
        for path in staging.rglob("*"):
            if path.is_file():
                assert ca_key not in path.read_text(), path


def test_expiry_is_readable(tmp_path: Path):
    _key, cert = link.issue_leaf(tmp_path, Node("edge", address="10.0.1.10"))
    not_after = link.cert_not_after(cert)
    assert not_after is not None
    assert 390 <= (not_after - __import__("datetime").datetime.now(not_after.tzinfo)).days <= 397


# ─────────────────────────────────────────────────────────────────────────
# firewall matrix
# ─────────────────────────────────────────────────────────────────────────


def test_the_firewall_matrix_of_the_example_topology():
    rules = link.firewall_rules(link.plan(split(), ALL_PROFILES, ENV))
    assert [(r.source, r.destination, r.port) for r in rules] == [
        ("internal", "edge", 22),
        ("edge", "internal", 7443),
        ("internal", "edge", 7443),
    ]


def test_the_firewall_matrix_lists_what_each_link_carries():
    rules = link.firewall_rules(link.plan(split(), ALL_PROFILES, ENV))
    inbound = next(r for r in rules if (r.source, r.destination) == ("edge", "internal"))
    assert inbound.purpose == "link: librechat:3080, localai:8080, papaia-manager:8000, qdrant:6333"


@pytest.mark.parametrize("fmt", ["table", "json", "csv"])
def test_the_firewall_matrix_renders(fmt):
    text = link.format_rules(link.firewall_rules(link.plan(split(), ALL_PROFILES, ENV)), fmt)
    assert "7443" in text and "edge" in text


# ─────────────────────────────────────────────────────────────────────────
# live: two gateway processes, mutual TLS between them
# ─────────────────────────────────────────────────────────────────────────


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo:
    """A TCP service that streams back what it receives, in chunks."""

    def __init__(self):
        self.port = free_port()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            try:
                while data := conn.recv(4096):
                    conn.sendall(data)
            except OSError:
                pass

    def close(self):
        self.server.close()


def wait_for(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"nothing listens on {port}")


@pytest.fixture
def gateways(tmp_path: Path):
    """LibreChat's node (internal) calls Keycloak on the edge: the two gateways as haproxy
    processes on this host, with local ports swapped in for the Docker network."""
    if shutil.which("haproxy") is None:
        pytest.skip("haproxy is not installed")
    topo = two_nodes(keycloak="edge")
    config = _write_material(tmp_path, topo)
    plan = link.plan(topo, ["keycloak", "librechat"], {})
    assert [r.host for r in plan.for_node("internal").routes] == ["keycloak"]
    echo = Echo()
    link_port, keycloak_port = free_port(), free_port()
    procs = {}
    for node in topo.nodes.values():
        staging = tmp_path / node.name
        link.write_node_files(staging, config, plan, node, "/unused")
        text = (staging / "link" / "haproxy.cfg").read_text()
        text = text.replace(link.GATEWAY_CONFIG_PATH, str(staging / "link"))
        text = text.replace("bind :7443", f"bind 127.0.0.1:{link_port}")
        text = text.replace("10.0.1.10:7443", f"127.0.0.1:{link_port}")
        text = text.replace("bind :8443", f"bind 127.0.0.1:{keycloak_port}")
        text = text.replace(
            "server local keycloak:8443 resolvers docker init-addr last,libc,none",
            f"server local 127.0.0.1:{echo.port}",
        )
        cfg = staging / "live.cfg"
        cfg.write_text(text)
        procs[node.name] = (
            cfg,
            subprocess.Popen(
                ["haproxy", "-db", "-f", str(cfg)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ),
        )
    wait_for(link_port)
    wait_for(keycloak_port)
    yield {
        "config": config,
        "link_port": link_port,
        "keycloak_port": keycloak_port,
        "procs": procs,
        "echo": echo,
    }
    for _cfg, proc in procs.values():
        proc.terminate()
        proc.wait(timeout=10)
    echo.close()


def roundtrip(port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        received = b""
        for chunk in (payload[i : i + 7] for i in range(0, len(payload), 7)):
            sock.sendall(chunk)
            time.sleep(0.002)
        sock.shutdown(socket.SHUT_WR)
        while data := sock.recv(4096):
            received += data
    return received


def until_linked(port: int, timeout: float = 15.0) -> None:
    """Wait for the caller's gateway to see its peer up: the first health check can run
    before the peer listens."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if roundtrip(port, b"ping") == b"ping":
                return
        except OSError:
            pass
        time.sleep(0.3)
    raise AssertionError("the link never came up")


def test_a_service_answers_across_the_link_under_its_usual_name(gateways):
    until_linked(gateways["keycloak_port"])
    payload = b"data: token 1\n\ndata: token 2\n\ndata: [DONE]\n\n" * 20
    assert roundtrip(gateways["keycloak_port"], payload) == payload


def test_the_link_port_refuses_a_client_without_a_certificate(gateways):
    context = ssl.create_default_context(cafile=str(gateways["config"] / "link-ca" / "ca.crt"))
    context.check_hostname = False
    with socket.create_connection(("127.0.0.1", gateways["link_port"]), timeout=5) as raw:
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            with context.wrap_socket(raw, server_hostname="edge") as tls:
                tls.sendall(b"x")
                assert tls.recv(10) == b""
                raise ConnectionError("closed without data")


def test_the_link_port_refuses_a_certificate_of_another_ca(gateways, tmp_path: Path):
    foreign = tmp_path / "foreign"
    key, cert = link.issue_leaf(foreign, Node("internal", address="10.0.2.10"))
    context = ssl.create_default_context(cafile=str(gateways["config"] / "link-ca" / "ca.crt"))
    context.check_hostname = False
    context.load_cert_chain(str(cert), str(key))
    with socket.create_connection(("127.0.0.1", gateways["link_port"]), timeout=5) as raw:
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            with context.wrap_socket(raw, server_hostname="keycloak") as tls:
                tls.sendall(b"x")
                if tls.recv(10) == b"":
                    raise ConnectionError("closed without data")


def test_a_client_node_only_reaches_the_services_the_edge_table_allows(gateways):
    """A valid certificate of the link CA for a node that calls nothing on the edge
    (here: a node named 'gpu') is accepted by TLS and then refused."""
    config = gateways["config"]
    key, cert = link.issue_leaf(config, Node("gpu", address="10.0.3.10"))
    context = ssl.create_default_context(cafile=str(config / "link-ca" / "ca.crt"))
    context.check_hostname = False
    context.load_cert_chain(str(cert), str(key))
    with socket.create_connection(("127.0.0.1", gateways["link_port"]), timeout=5) as raw:
        try:
            with context.wrap_socket(raw, server_hostname="keycloak") as tls:
                tls.sendall(b"hello")
                assert tls.recv(10) == b""
        except (ssl.SSLError, ConnectionError, OSError):
            pass
    # The same request from the allowed node goes through.
    key, cert = (
        link.leaf_dir(config, "internal") / "node.key",
        link.leaf_dir(config, "internal") / "node.crt",
    )
    context = ssl.create_default_context(cafile=str(config / "link-ca" / "ca.crt"))
    context.check_hostname = False
    context.load_cert_chain(str(cert), str(key))
    with socket.create_connection(("127.0.0.1", gateways["link_port"]), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="keycloak") as tls:
            tls.sendall(b"hello")
            assert tls.recv(10) == b"hello"


def test_a_peer_that_is_down_means_a_refused_connection_not_clear_text(gateways):
    until_linked(gateways["keycloak_port"])
    _cfg, edge = gateways["procs"]["edge"]
    edge.terminate()
    edge.wait(timeout=10)
    received = b""
    try:
        with socket.create_connection(("127.0.0.1", gateways["keycloak_port"]), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: keycloak\r\n\r\n")
            s.settimeout(5)
            received = s.recv(4096)
    except OSError:
        received = b""
    assert received == b""
    # Nothing answered in clear text on the link port either: nobody listens there now.
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", gateways["link_port"]), timeout=1).close()
