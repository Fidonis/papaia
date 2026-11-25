"""Isolated add-on networks with real containers (addon_api 16, ADR 0026).

A probe container that only joins the rendered isolated network of an add-on reaches the
LiteLLM health endpoint and nothing else: not the proxy, the identity provider, the audit
store or the mail relay (all on the core network and attached to the add-on's app
network), not a service of the add-on on its app network, and no address outside the
network. The isolated network itself holds the probe and LiteLLM, nothing more.

The core services are small HTTP stand-ins with the core's service names, so the override
`gen_override.generate_override` renders for the add-on applies to them unchanged; the
test is about the networks, not about the services behind them. The setup is the one
`papaia-ctl` produces: the add-on's own compose file creates its app network and the
internal isolated network, then the core compose file is started with the override.

Needs Docker; skipped without it. The Compose project and the address range can be set
with PAPAIA_ISOLATED_TEST_PROJECT and PAPAIA_ISOLATED_TEST_SUBNET (a /24) so the test
does not collide with other stacks on the same host.
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

from lib import compat, gen_override

PROJECT = live_names.project("isolated-test", "PAPAIA_ISOLATED_TEST_PROJECT")
SUBNET = live_names.subnet("PAPAIA_ISOLATED_TEST_SUBNET")
ADDON = "reader"
# The pinned base image of the core's own images (src/infra/egress/Dockerfile).
IMAGE = (
    "python:3.12.16-slim-trixie@sha256:"
    "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
# Core services the add-on attaches to its app network; none of them may be reachable
# from the isolated network.
APP_ATTACHED = ("nginx-proxy-manager", "keycloak", "papaia-audit", "smtp-relay")


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

# A stand-in for one core service: answers every GET with its own name.
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

# Runs in the probe on the isolated network; prints one JSON object.
_PROBE = r"""
import json, socket, sys, time, urllib.request

def health():
    deadline = time.time() + 30
    while True:
        try:
            with urllib.request.urlopen("http://litellm:4000/health/liveliness", timeout=3) as r:
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

results = {"litellm": health(), "names": {}, "addresses": {}}
for name in json.loads(sys.argv[1]):
    results["names"][name] = connect(name, 8080)
for address in json.loads(sys.argv[2]):
    results["addresses"][address] = connect(address, 8080)
for address in ("1.1.1.1", "8.8.8.8"):
    results["addresses"][address] = connect(address, 443)
print(json.dumps(results))
"""


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, env=env, timeout=300, check=check
    )


def _server(name: str, port: int, networks: list[str]) -> dict:
    return {
        "image": IMAGE,
        "command": ["python3", "-I", "-c", _SERVER],
        "environment": {"NAME": name, "PORT": str(port)},
        "networks": networks,
    }


@pytest.fixture
def stack(tmp_path: Path):
    core_net, app_net, isolated_net, _ = SUBNET.subnets(new_prefix=SUBNET.prefixlen + 2)
    config_dir = tmp_path / "papaia-config"
    (config_dir / "overrides").mkdir(parents=True)
    (config_dir / ".env").write_text(f"PAPAIA_PROJECT={PROJECT}\n", encoding="utf-8")

    addon_dir = tmp_path / "addons" / ADDON
    addon_dir.mkdir(parents=True)
    manifest = {
        "name": ADDON,
        "version": "1.0.0",
        "requires": {"addon_api": [16]},
        "networks": {
            "app_network": "${PAPAIA_PROJECT:-papaia}-reader-net",
            "attach": list(APP_ATTACHED),
            "isolated": [
                {"network": "${PAPAIA_PROJECT:-papaia}-reader-reader-net", "attach": ["litellm"]}
            ],
        },
    }
    (addon_dir / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    addon_compose = {
        "services": {
            "reader": {"image": IMAGE, "command": ["sleep", "600"], "networks": ["isolated"]},
            "app": _server("app", 8080, ["app"]),
        },
        "networks": {
            "app": {
                "name": "${PAPAIA_PROJECT:-papaia}-reader-net",
                "ipam": {"config": [{"subnet": str(app_net)}]},
            },
            "isolated": {
                "name": "${PAPAIA_PROJECT:-papaia}-reader-reader-net",
                "internal": True,
                "ipam": {"config": [{"subnet": str(isolated_net)}]},
            },
        },
    }
    (addon_dir / "docker-compose.yml").write_text(yaml.safe_dump(addon_compose), encoding="utf-8")

    # The add-on passes the check the core runs before install and start.
    result = compat.evaluate_addon(
        ADDON, manifest, compat.CoreTarget(addon_api=(1, 16)), addon_path=addon_dir
    )
    assert result.status == compat.STATUS_OK, result.reason
    override = gen_override.generate_override(manifest, config_dir, addon_dir)
    assert override is not None

    core = {
        "services": {
            "litellm": _server("litellm", 4000, ["papaia-net"]),
            **{name: _server(name, 8080, ["papaia-net"]) for name in APP_ATTACHED},
        },
        "networks": {
            "papaia-net": {
                "name": f"{PROJECT}-core-net",
                "ipam": {"config": [{"subnet": str(core_net)}]},
            }
        },
    }
    core_file = tmp_path / "core.yml"
    core_file.write_text(yaml.safe_dump(core), encoding="utf-8")

    env = {**os.environ, "PAPAIA_PROJECT": PROJECT}
    addon = ["docker", "compose", "-p", PROJECT, "-f", str(addon_dir / "docker-compose.yml")]
    compose = ["docker", "compose", "-p", PROJECT, "-f", str(core_file), "-f", str(override)]
    try:
        # As `papaia-ctl start` does it: the add-on first, it owns its networks.
        up = _run(*addon, "up", "-d", "--wait", env=env, check=False)
        assert up.returncode == 0, up.stderr
        up = _run(*compose, "up", "-d", "--wait", env=env, check=False)
        assert up.returncode == 0, up.stderr
        yield {"compose": compose, "addon": addon, "env": env, "isolated_net": isolated_net}
    finally:
        _run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)
        _run(*addon, "down", "-v", "--remove-orphans", env=env, check=False)


def _addresses(compose: list[str], service: str, env: dict) -> list[str]:
    container = _run(*compose, "ps", "-q", service, env=env).stdout.strip()
    out = _run(
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container,
    ).stdout  # fmt: skip
    return out.split()


def test_the_isolated_service_reaches_litellm_and_nothing_else(stack):
    compose, addon, env = stack["compose"], stack["addon"], stack["env"]
    names = [*APP_ATTACHED, "app"]
    addresses = sorted(
        {
            address
            for service in APP_ATTACHED
            for address in _addresses(compose, service, env)
        }
        | set(_addresses(addon, "app", env))
    )
    probe = _run(
        *addon, "exec", "-T", "reader", "python3", "-I", "-c", _PROBE,
        json.dumps(names), json.dumps(addresses), env=env,
    )  # fmt: skip
    results = json.loads(probe.stdout)

    assert results["litellm"] == {"status": 200, "body": "litellm"}
    for name in names:
        assert results["names"][name] != "reached", name
    for address, outcome in results["addresses"].items():
        assert outcome != "reached", address

    # The isolated network holds the probe and LiteLLM, nothing else, and has no way out.
    network = f"{PROJECT}-reader-reader-net"
    inspected = json.loads(_run("docker", "network", "inspect", network).stdout)[0]
    assert inspected["Internal"] is True
    members = sorted(c["Name"] for c in inspected["Containers"].values())
    assert len(members) == 2
    assert any("litellm" in member for member in members)
    assert any("reader" in member and "litellm" not in member for member in members)
    # The proxy stays on the app network only.
    proxy = _run(*compose, "ps", "-q", "nginx-proxy-manager", env=env).stdout.strip()
    joined = json.loads(
        _run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", proxy).stdout
    )
    assert network not in joined
    assert f"{PROJECT}-reader-net" in joined
