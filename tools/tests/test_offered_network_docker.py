"""Joining an offered network with real containers (addon_api 17, ADR 0027).

A consumer add-on joins the network a target add-on offers through an `exposes` entry
(`networks.join_addons[].network`). A probe service of the consumer, joined through the
override `gen_override.generate_addon_join_overrides` renders, reaches the relay of the
target on the offered network and nothing else: no service that sits only on the target's
app network, no core service on the core network. With the target stopped or removed the
consumer still starts, without the join.

The services are small HTTP stand-ins; the test is about the networks. The setup is the
one `papaia-ctl` produces: the target's compose project creates its networks, the
consumer's compose project is started with the override files `addon start` hands it
(`gen_override.usable_addon_override_files`).

Needs Docker; skipped without it. The Compose project prefix and the address range can be
set with PAPAIA_OFFERED_TEST_PROJECT and PAPAIA_OFFERED_TEST_SUBNET (a /24) so the test
does not collide with other stacks on the same host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import compat, deployment, envtree, gen_override

PROJECT = os.environ.get("PAPAIA_OFFERED_TEST_PROJECT", "papaia-offered-test")
SUBNET = ipaddress.ip_network(os.environ.get("PAPAIA_OFFERED_TEST_SUBNET", "10.250.81.0/24"))
# The pinned base image of the core's own images (src/infra/egress/Dockerfile).
IMAGE = (
    "python:3.12.16-slim-trixie@sha256:"
    "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
OFFER = "${PAPAIA_PROJECT:-papaia}-flow-modules"
# Services the probe must not reach: the target's API and database on its app network
# and the core services on the core network.
UNREACHABLE = ("api", "db", "keycloak", "papaia-audit")


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

# A stand-in for one service: answers every GET with its own name.
_SERVER = (
    "import http.server,os\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        body=os.environ['NAME'].encode()\n"
    "        self.send_response(200);self.send_header('Content-Length',str(len(body)))\n"
    "        self.end_headers();self.wfile.write(body)\n"
    "    def log_message(self,*a):pass\n"
    "http.server.ThreadingHTTPServer(('',int(os.environ['PORT'])),H).serve_forever()\n"
)

# Runs in the probe; prints one JSON object.
_PROBE = r"""
import json, socket, sys, time, urllib.request

def relay():
    deadline = time.time() + 30
    while True:
        try:
            with urllib.request.urlopen("http://relay:8080/", timeout=3) as r:
                return {"status": r.status, "body": r.read().decode()}
        except OSError as exc:
            if time.time() > deadline:
                return {"error": type(exc).__name__}
            time.sleep(1)

def connect(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "reached"
    except OSError as exc:
        return type(exc).__name__

results = {"relay": relay(), "names": {}, "addresses": {}}
for name in json.loads(sys.argv[1]):
    results["names"][name] = connect(name, 8080)
for address in json.loads(sys.argv[2]):
    results["addresses"][address] = connect(address, 8080)
print(json.dumps(results))
"""


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, env=env, timeout=300, check=check
    )


def _server(name: str, networks: list[str] | dict) -> dict:
    return {
        "image": IMAGE,
        "command": ["python3", "-I", "-c", _SERVER],
        "environment": {"NAME": name, "PORT": "8080"},
        "networks": networks,
    }


def _exposes() -> list[dict]:
    return [{
        "id": "flow.runs",
        "kind": "mcp",
        "title": {"de": "Abläufe", "en": "Runs"},
        "address": {"service": "relay", "port": 8080},
        "audience": "mcp-flow",
        "identity": ["service"],
        "operations": [{
            "name": "start_run", "version": 1, "title": {"de": "Start", "en": "Start"},
            "via": "tools", "effect": "read", "retry": "safe",
            "input_schema": {"type": "object"}, "output_schema": {"type": "object"},
            "data_class_max": "internal", "rights_check": "server",
        }],
    }]


def _write(path: Path, manifest: dict, compose: dict) -> Path:
    path.mkdir(parents=True)
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    return path


@pytest.fixture
def stack(tmp_path: Path, repo_root: Path):
    core_net, app_net, offer_net, own_net = SUBNET.subnets(new_prefix=SUBNET.prefixlen + 2)
    config_dir = tmp_path / "papaia-config"
    envtree.init(config_dir, repo_root, env_name="papaia")
    env_path = config_dir / ".env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8") + f"PAPAIA_PROJECT={PROJECT}\n", encoding="utf-8"
    )

    flow = _write(
        tmp_path / "addons" / "flow",
        {
            "name": "flow", "version": "1.0.0", "requires": {"addon_api": [7]},
            "networks": {"app_network": "${PAPAIA_PROJECT:-papaia}-flow-net"},
            "exposes": _exposes(),
        },
        {
            "services": {
                "api": _server("api", ["app"]),
                "db": _server("db", ["app"]),
                "relay": _server("relay", ["offer"]),
            },
            "networks": {
                "app": {"name": "${PAPAIA_PROJECT:-papaia}-flow-net",
                        "ipam": {"config": [{"subnet": str(app_net)}]}},
                "offer": {"name": OFFER, "internal": True,
                          "ipam": {"config": [{"subnet": str(offer_net)}]}},
            },
        },
    )
    consumer_manifest = {
        "name": "assist", "version": "1.0.0",
        "requires": {"addon_api": [17], "addons": [{"name": "flow", "optional": True}]},
        "networks": {
            "app_network": "${PAPAIA_PROJECT:-papaia}-assist-net",
            "join_addons": [{"addon": "flow", "services": ["gate"], "network": OFFER}],
        },
    }
    assist = _write(
        tmp_path / "addons" / "assist",
        consumer_manifest,
        {
            "services": {
                "gate": {"image": IMAGE, "command": ["sleep", "600"], "networks": ["own"]},
                "web": _server("web", ["own"]),
            },
            "networks": {"own": {"name": "${PAPAIA_PROJECT:-papaia}-assist-net",
                                 "ipam": {"config": [{"subnet": str(own_net)}]}}},
        },
    )
    deployed = deployment.load(config_dir)
    deployed["addons"] = [
        {"name": "flow", "path": str(flow), "active": True},
        {"name": "assist", "path": str(assist), "active": True},
    ]
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")
    # The consumer passes the check the core runs before install and start.
    result = compat.evaluate_addon(
        "assist", consumer_manifest, compat.CoreTarget(addon_api=(1, 17)), addon_path=assist
    )
    assert result.status == compat.STATUS_OK, result.reason

    core_file = tmp_path / "core.yml"
    core_file.write_text(yaml.safe_dump({
        "services": {name: _server(name, ["papaia-net"]) for name in ("keycloak", "papaia-audit")},
        "networks": {"papaia-net": {"name": f"{PROJECT}-core-net",
                                    "ipam": {"config": [{"subnet": str(core_net)}]}}},
    }), encoding="utf-8")

    env = {**os.environ, "PAPAIA_PROJECT": PROJECT}
    projects = {
        "flow": ["docker", "compose", "-p", f"{PROJECT}-flow",
                 "-f", str(flow / "docker-compose.yml")],
        "core": ["docker", "compose", "-p", f"{PROJECT}-core", "-f", str(core_file)],
    }

    def consumer() -> list[str]:
        files = ["-f", str(assist / "docker-compose.yml")]
        for path in gen_override.usable_addon_override_files(config_dir, "assist"):
            files += ["-f", str(path)]
        return ["docker", "compose", "-p", f"{PROJECT}-assist", *files]

    try:
        for name in ("flow", "core"):
            up = _run(*projects[name], "up", "-d", "--wait", env=env, check=False)
            assert up.returncode == 0, up.stderr
        gen_override.generate_addon_join_overrides(config_dir, repo_root)
        up = _run(*consumer(), "up", "-d", env=env, check=False)
        assert up.returncode == 0, up.stderr
        yield {"config": config_dir, "repo": repo_root, "env": env, "projects": projects,
               "consumer": consumer}
    finally:
        _run("docker", "compose", "-p", f"{PROJECT}-assist", "down", "-v", "--remove-orphans",
             env=env, check=False)
        for name in ("core", "flow"):
            _run(*projects[name], "down", "-v", "--remove-orphans", env=env, check=False)


def _addresses(compose: list[str], service: str, env: dict) -> list[str]:
    container = _run(*compose, "ps", "-q", service, env=env).stdout.strip()
    out = _run(
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container,
    ).stdout  # fmt: skip
    return out.split()


def test_the_consumer_reaches_the_relay_and_nothing_else(stack):
    env, projects = stack["env"], stack["projects"]
    addresses = sorted(
        {address for service in ("api", "db") for address in _addresses(projects["flow"],
                                                                         service, env)}
        | {address for service in ("keycloak", "papaia-audit")
           for address in _addresses(projects["core"], service, env)}
    )
    probe = _run(
        *stack["consumer"](), "exec", "-T", "gate", "python3", "-I", "-c", _PROBE,
        json.dumps(list(UNREACHABLE)), json.dumps(addresses), env=env,
    )  # fmt: skip
    results = json.loads(probe.stdout)

    assert results["relay"] == {"status": 200, "body": "relay"}
    for name in UNREACHABLE:
        assert results["names"][name] != "reached", name
    for address, outcome in results["addresses"].items():
        assert outcome != "reached", address

    # The offered network holds the relay and the probe, nothing else, and has no way out.
    inspected = json.loads(_run("docker", "network", "inspect", f"{PROJECT}-flow-modules").stdout)
    assert inspected[0]["Internal"] is True
    members = sorted(c["Name"] for c in inspected[0]["Containers"].values())
    assert len(members) == 2
    assert any("relay" in member for member in members)
    assert any("gate" in member for member in members)
    # The other service of the consumer stays off it, and nothing of the consumer is on
    # the target's app network.
    app = json.loads(_run("docker", "network", "inspect", f"{PROJECT}-flow-net").stdout)
    assert not any("assist" in c["Name"] for c in app[0]["Containers"].values())


def test_the_consumer_starts_without_its_target(stack):
    env, projects = stack["env"], stack["projects"]
    _run("docker", "compose", "-p", f"{PROJECT}-assist", "down", "-v", env=env, check=False)
    down = _run(*projects["flow"], "down", "-v", env=env, check=False)
    assert down.returncode == 0, down.stderr

    # Target still registered and active, its network gone: the join is left out.
    up = _run(*stack["consumer"](), "up", "-d", env=env, check=False)
    assert up.returncode == 0, up.stderr
    assert "offer-flow" not in " ".join(stack["consumer"]())

    # Target removed from the installation: no override names the network.
    deployed = deployment.load(stack["config"])
    deployed["addons"] = [a for a in deployed["addons"] if a["name"] != "flow"]
    (stack["config"] / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")
    gen_override.generate_addon_join_overrides(stack["config"], stack["repo"])
    up = _run(*stack["consumer"](), "up", "-d", env=env, check=False)
    assert up.returncode == 0, up.stderr
    files = deployment.addon_override_files(stack["config"], "assist")
    assert not any("flow-modules" in path.read_text(encoding="utf-8") for path in files)
