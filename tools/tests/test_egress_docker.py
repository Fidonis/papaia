"""papaia-egress with real containers: a service on the egress network of an add-on
reaches an allowed host only through the proxy; a protected host, an allowed name that
resolves into the stack, the host gateway and everything else are refused.

The proxy runs in the core's own image, built here from its Dockerfile and the inputs
compat/own-images.yaml declares (the pinned image is not pulled: the test is about the
proxy, the image path is test_own_images_registry.py). The setup is the one `papaia-ctl`
produces: the add-on's own compose file creates its
internal egress network, its manifest declares that network and the allow list, the
operator opens the test's "outside" range for that add-on, `lib.egress` renders the
proxy configuration and the attachment override, and the core compose file of the
service is started with that override. The "outside" is the proxy's own exit network
with three small HTTP servers on it (private addresses, hence the operator's opt-in).

Needs Docker; skipped without it. The Compose project and the address range can be set
with PAPAIA_EGRESS_TEST_PROJECT and PAPAIA_EGRESS_TEST_SUBNET (a /24) so the test does
not collide with other stacks on the same host.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import live_names
import pytest
import yaml

from lib import deployment, egress, gen_override, own_images

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "infra" / "egress" / "docker-compose.yml"
PROJECT = live_names.project("egress-test", "PAPAIA_EGRESS_TEST_PROJECT")
SUBNET = live_names.subnet("PAPAIA_EGRESS_TEST_SUBNET")
ADDON = "probe"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")

# One small HTTP server per "outside" host; it answers with its own name.
_SERVER = (
    "import http.server,os\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        body=os.environ['NAME'].encode()\n"
    "        self.send_response(200);self.send_header('Content-Length',str(len(body)))\n"
    "        self.end_headers();self.wfile.write(body)\n"
    "http.server.ThreadingHTTPServer(('',8080),H).serve_forever()\n"
)

# Runs in the client container on the add-on's egress network; prints one JSON object.
_CLIENT = r"""
import json, socket, sys
results = {}

def via_proxy(host):
    s = socket.create_connection(("papaia-egress", 3128), timeout=10)
    s.sendall(f"CONNECT {host}:8080 HTTP/1.1\r\nHost: {host}:8080\r\n"
              "X-Papaia-Correlation-Id: probe-1\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1])
    pairs = [line.split(":", 1) for line in lines[1:] if ":" in line]
    headers = {name.lower(): value.strip() for name, value in pairs}
    body = None
    if status == 200:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        body = data.split(b"\r\n\r\n", 1)[1].decode()
    s.close()
    return {"status": status, "error": headers.get("x-papaia-error"), "body": body}

def direct(target):
    try:
        socket.create_connection((target, 8080), timeout=5).close()
        return "reached"
    except OSError as exc:
        return type(exc).__name__

for host in json.loads(sys.argv[2]):
    results[host] = via_proxy(host)
results["direct_by_name"] = direct("allowed.example.test")
results["direct_by_address"] = direct(sys.argv[1])
print(json.dumps(results))
"""


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, env=env, timeout=300, check=check
    )


OUTSIDE = ("allowed.example.test", "protected.example.test", "other.example.test")


@pytest.fixture
def stack(tmp_path: Path):
    outside, inside = list(SUBNET.subnets(new_prefix=SUBNET.prefixlen + 1))
    gateway = str(outside.network_address + 1)
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(f"PAPAIA_PROJECT={PROJECT}\n", encoding="utf-8")
    image = f"{PROJECT}-egress:test"
    (own,) = [i for i in own_images.load(REPO) if egress.SERVICE in i.services]
    context = own_images.stage_context(REPO, own, tmp_path / "build")
    built = _run("docker", "buildx", "build", "--load", "--provenance=false", "-t", image,
                 "-f", str(context / own.dockerfile), str(context), check=False)
    assert built.returncode == 0, built.stderr

    def server(name: str, network: str, alias: str) -> dict:
        return {
            "image": image,
            "command": ["python3", "-c", _SERVER],
            "environment": {"NAME": name},
            "networks": {network: {"aliases": [alias]}},
        }

    # The add-on: its manifest, and its compose file with the internal egress network,
    # a client, and a service of its own that an allowed name points to.
    addon_dir = tmp_path / "addons" / ADDON
    addon_dir.mkdir(parents=True)
    manifest = {
        "name": ADDON,
        "version": "1.0.0",
        "networks": {
            "egress": {
                "network": "${PAPAIA_PROJECT:-papaia}-probe-egress",
                # The add-on asks for more than it gets: the protected host, a name inside
                # the stack and the gateway are refused although they are on the list.
                "allow": [
                    {"host": "allowed.example.test", "ports": [8080]},
                    {"host": "protected.example.test", "ports": [8080]},
                    {"host": "inside.example.test", "ports": [8080]},
                    {"host": gateway, "ports": [8080]},
                ],
            }
        },
    }
    (addon_dir / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    addon_compose = {
        "services": {
            "client": {"image": image, "command": ["sleep", "600"], "networks": ["egress"]},
            "inside": server("inside", "egress", "inside.example.test"),
        },
        "networks": {
            "egress": {
                "name": "${PAPAIA_PROJECT:-papaia}-probe-egress",
                "internal": True,
                "ipam": {"config": [{"subnet": str(inside)}]},
            }
        },
    }
    (addon_dir / "docker-compose.yml").write_text(yaml.safe_dump(addon_compose), encoding="utf-8")
    deployment.save(
        config_dir, {"addons": [{"name": ADDON, "path": str(addon_dir), "active": True}]}
    )
    security = config_dir / "security"
    security.mkdir()
    (config_dir / egress.PROTECTED_HOSTS_FILE).write_text(
        yaml.safe_dump([{"name": "erp", "hosts": ["protected.example.test"], "ports": [8080]}]),
        encoding="utf-8",
    )
    # The operator opens the whole test range (private addresses) for this add-on. That
    # covers the add-on's own egress network and the gateway as well: they stay refused
    # because the proxy knows it is attached to them, not because they are private.
    (config_dir / egress.INTERNAL_TARGETS_FILE).write_text(
        yaml.safe_dump([{"name": "outside", "ranges": [str(SUBNET)], "addons": [ADDON]}]),
        encoding="utf-8",
    )

    egress.render(config_dir)
    gen_override.generate_overrides(config_dir, tmp_path)
    override = egress.override_path(config_dir, ADDON)
    addon_network = f"{PROJECT}-probe-egress"

    targets = {
        "services": {
            **{name: server(name, egress.EGRESS_NETWORK, name) for name in OUTSIDE},
            egress.SERVICE: {"image": image},
        },
        "networks": {egress.EGRESS_NETWORK: {"ipam": {"config": [{"subnet": str(outside)}]}}},
    }
    targets_file = tmp_path / "targets.yml"
    targets_file.write_text(yaml.safe_dump(targets), encoding="utf-8")

    env = {
        **os.environ,
        "PAPAIA_CONFIG_DIR": str(config_dir),
        "PAPAIA_PROJECT": PROJECT,
        "UID": str(os.getuid()),
        "GID": str(os.getgid()),
    }
    addon = ["docker", "compose", "-p", PROJECT, "-f", str(addon_dir / "docker-compose.yml")]
    compose = [
        "docker", "compose", "-p", PROJECT,
        "-f", str(COMPOSE), "-f", str(override), "-f", str(targets_file),
        "--profile", egress.PROFILE,
    ]  # fmt: skip
    _run("docker", "network", "rm", addon_network, check=False)
    try:
        # As `papaia-ctl start` does it: the add-on first, it owns its egress network.
        up = _run(*addon, "up", "-d", "--wait", env=env, check=False)
        assert up.returncode == 0, up.stderr
        up = _run(*compose, "up", "-d", "--wait", env=env, check=False)
        assert up.returncode == 0, up.stderr
        yield {"compose": compose, "addon": addon, "env": env, "gateway": gateway}
    finally:
        _run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)
        _run(*addon, "down", "-v", "--remove-orphans", env=env, check=False)
        _run("docker", "network", "rm", addon_network, check=False)
        _run("docker", "image", "rm", image, check=False)


def test_an_addon_reaches_only_allowed_hosts_and_only_through_the_proxy(stack):
    compose, addon, env = stack["compose"], stack["addon"], stack["env"]
    gateway = stack["gateway"]
    target_id = _run(*compose, "ps", "-q", "allowed.example.test", env=env).stdout.strip()
    address = _run(
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", target_id,
    ).stdout.strip()  # fmt: skip
    hosts = json.dumps([*OUTSIDE, "inside.example.test", gateway])

    probe = _run(*addon, "exec", "-T", "client", "python3", "-c", _CLIENT, address, hosts, env=env)
    results = json.loads(probe.stdout)

    assert results["allowed.example.test"] == {
        "status": 200,
        "error": None,
        "body": "allowed.example.test",
    }
    assert results["protected.example.test"] == {
        "status": 403,
        "error": "protected_host",
        "body": None,
    }
    assert results["other.example.test"] == {"status": 403, "error": "not_allowed", "body": None}
    # An allowed name that resolves to a container inside the stack, and the host.
    assert results["inside.example.test"] == {
        "status": 403,
        "error": "blocked_address",
        "body": None,
    }
    assert results[gateway] == {"status": 403, "error": "blocked_address", "body": None}
    assert results["direct_by_name"] != "reached"
    assert results["direct_by_address"] != "reached"

    logs = _run(*compose, "logs", "--no-log-prefix", egress.SERVICE, env=env).stdout
    rows = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    outcomes = {(r["detail"]["host"], r["result"], r["error_code"]) for r in rows}
    assert ("allowed.example.test", "allowed", None) in outcomes
    assert ("protected.example.test", "denied", "protected_host") in outcomes
    assert ("other.example.test", "denied", "not_allowed") in outcomes
    assert ("inside.example.test", "denied", "blocked_address") in outcomes
    assert (gateway, "denied", "blocked_address") in outcomes
    assert {r["correlation_id"] for r in rows} == {"probe-1"}
