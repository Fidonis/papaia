"""The proxy side of the Paperless gate with real containers (PLT-22).

The bundled proxy is started from the core compose file, with the proxy secret and the
strip file `setup` writes, and `npm-provision` creates the Paperless route. Behind it a
stand-in for the Paperless add-on: Paperless on the loopback of its container only, and
in the same network namespace a gate that passes a request only with the proxy's secret
in `X-Papaia-Gate` and shows what Paperless would receive. The gate itself belongs to the
add-on; the stand-in only checks the contract the proxy has to meet.

Checked: a client cannot make the identity header take effect through the proxy, on the
Paperless route nor on a proxy host an operator created by hand; a forged gate header is
replaced; a container in the host network and one on a foreign Compose network do not get
through; a rotated secret takes effect after the reload `secrets rotate` runs.

Needs Docker; skipped without it. The Compose project, the address range (a /24) and the
first of three host ports (on 127.0.0.1) can be set with
PAPAIA_PAPERLESS_GATE_TEST_PROJECT, PAPAIA_PAPERLESS_GATE_TEST_SUBNET and
PAPAIA_PAPERLESS_GATE_TEST_PORT so the test does not collide with other stacks.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from lib import npm_provision, paperless_gate

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "infra" / "nginx" / "docker-compose.yml"
PROJECT = os.environ.get("PAPAIA_PAPERLESS_GATE_TEST_PROJECT", "papaia-paperless-gate-test")
SUBNET = ipaddress.ip_network(
    os.environ.get("PAPAIA_PAPERLESS_GATE_TEST_SUBNET", "10.250.78.0/24")
)
# The stand-in for Paperless and its gate; any small image with nginx and busybox wget.
STUB_IMAGE = (
    "nginx:1.31.2-alpine@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa"
)
PAPERLESS_HOST = "docs.gate-test.example"
OPERATOR_HOST = "manual.gate-test.example"


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

# Paperless stand-in: on the loopback of its container only, answers with the identity
# header it received. Port 8001 is the gate in the same network namespace.
_STUB = """
server {
    listen 127.0.0.1:8000;
    location / {
        default_type text/plain;
        return 200 "remote=[$http_x_papaia_remote_user] gate=[$http_x_papaia_gate]\\n";
    }
}
server {
    listen 8001;
    location / {
        if ($http_x_papaia_gate != "%s") { return 403; }
        proxy_set_header X-Papaia-Gate "";
        proxy_pass http://127.0.0.1:8000;
    }
}
"""
# A service the operator put behind the proxy by hand, reachable on every interface.
_ECHO = """
server {
    listen 8080;
    location / {
        default_type text/plain;
        return 200 "remote=[$http_x_papaia_remote_user] gate=[$http_x_papaia_gate]\\n";
    }
}
"""


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, env=env, timeout=600, check=check
    )


def _ports() -> list[int]:
    base = os.environ.get("PAPAIA_PAPERLESS_GATE_TEST_PORT")
    if base:
        return [int(base) + i for i in range(3)]
    found = []
    for _ in range(3):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            found.append(s.getsockname()[1])
    return found


def _get(port: int, host: str, headers: dict[str, str]) -> tuple[int, str]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/documents/", headers={"Host": host, **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _write_gate(path: Path, secret: str) -> None:
    path.write_text(_STUB % secret, encoding="utf-8")


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory):
    # One stack for the module: the proxy manager takes a while to start. The rotation
    # test changes the secret and runs last.
    tmp_path = tmp_path_factory.mktemp("paperless-gate")
    inner, foreign = list(SUBNET.subnets(new_prefix=SUBNET.prefixlen + 1))
    http_port, https_port, api_port = _ports()
    config_dir = tmp_path / "papaia-config"
    (config_dir / "infra" / "nginx" / "nginx-data").mkdir(parents=True)
    (config_dir / "infra" / "nginx" / "nginx-letsencrypt").mkdir(parents=True)
    paperless_gate.prepare(config_dir)

    gate_conf = tmp_path / "gate.conf"
    _write_gate(gate_conf, paperless_gate.read_proxy_secret(config_dir))
    echo_conf = tmp_path / "echo.conf"
    echo_conf.write_text(_ECHO, encoding="utf-8")
    password = secrets.token_urlsafe(24)
    extra = {
        "services": {
            "paperless": {
                "image": STUB_IMAGE,
                "volumes": [f"{gate_conf}:/etc/nginx/conf.d/default.conf:ro"],
                "networks": ["papaia-net"],
            },
            "operator-app": {
                "image": STUB_IMAGE,
                "volumes": [f"{echo_conf}:/etc/nginx/conf.d/default.conf:ro"],
                "networks": ["papaia-net"],
            },
        },
        "networks": {
            "papaia-net": {"ipam": {"config": [{"subnet": str(inner)}]}},
        },
    }
    extra_file = tmp_path / "stand-in.yml"
    extra_file.write_text(yaml.safe_dump(extra), encoding="utf-8")
    env = {
        **os.environ,
        "PAPAIA_CONFIG_DIR": str(config_dir),
        "HOST_IP": "127.0.0.1",
        "INGRESS_HTTP_EXT_PORT": str(http_port),
        "INGRESS_HTTPS_EXT_PORT": str(https_port),
        "NPM_API_LOCAL_PORT": str(api_port),
        "NPM_ADMIN_PASSWORD": password,
    }
    compose = [
        "docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), "-f", str(extra_file),
        "--profile", "nginx",
    ]  # fmt: skip
    try:
        up = _run(
            *compose, "up", "-d", "--wait", "nginx-proxy-manager", "paperless", "operator-app",
            env=env, check=False,
        )  # fmt: skip
        assert up.returncode == 0, up.stderr
        # Another Compose project's network, with nothing of the stack on it.
        _run("docker", "network", "create", "--subnet", str(foreign), f"{PROJECT}-foreign",
             check=False)  # fmt: skip
        tree = {
            "": {
                "REVERSE_PROXY_PROVIDER": "internal_nginx",
                "COMPOSE_PROFILES": "nginx",
                "COMPOSE_PROJECT_NAME": PROJECT,
            },
            "infra/nginx": {
                "NPM_ADMIN_EMAIL": "admin@papaia.local",
                "NPM_ADMIN_PASSWORD": password,
                "NPM_API_LOCAL_PORT": str(api_port),
            },
        }
        (config_dir / "addons" / "paperless").mkdir(parents=True)
        (config_dir / "addons" / "paperless" / ".env").write_text(
            f"PAPERLESS_PUBLIC_URL=http://{PAPERLESS_HOST}\n", encoding="utf-8"
        )
        (config_dir / "deployment.yaml").write_text(
            yaml.safe_dump({"addons": [{"name": "paperless", "path": "/x", "active": True}]}),
            encoding="utf-8",
        )
        assert npm_provision.provision_npm_hosts(tree, config_dir) is True
        # A host the operator added by hand, with the old reference block that sets the
        # header to empty at server level (ineffective in the proxy manager).
        base = f"http://127.0.0.1:{api_port}"
        token = npm_provision._get_token(base, "admin@papaia.local", password)
        npm_provision._post_proxy_host(
            base,
            token,
            npm_provision.proxy_host_body(
                OPERATOR_HOST, "operator-app", 8080, "http",
                advanced_config='proxy_set_header X-Papaia-Remote-User "";\n',
            ),
        )  # fmt: skip
        time.sleep(2)
        paperless_id = _run(*compose, "ps", "-q", "paperless", env=env).stdout.strip()
        address = _run(
            "docker", "inspect", "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", paperless_id,
        ).stdout.strip()  # fmt: skip
        yield {
            "compose": compose,
            "env": env,
            "http": http_port,
            "config_dir": config_dir,
            "gate_conf": gate_conf,
            "address": address,
        }
    finally:
        _run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)
        _run("docker", "network", "rm", f"{PROJECT}-foreign", check=False)


def _probe(network: str, url: str, header: str) -> str:
    """busybox wget from a throwaway container; returns its combined output."""
    result = _run(
        "docker", "run", "--rm", "--network", network, STUB_IMAGE,
        "wget", "-q", "-O", "-", "-T", "5", "--header", header, url,
        check=False,
    )  # fmt: skip
    return (result.stdout + result.stderr).strip()


def test_the_identity_header_has_no_effect_through_the_proxy(stack):
    status, body = _get(
        stack["http"],
        PAPERLESS_HOST,
        {"X-Papaia-Remote-User": "anna", "X-Papaia-Gate": "forged-" + "x" * 40},
    )

    # The gate let the request through, so the proxy replaced the forged gate header
    # with its own secret; Paperless received no identity header.
    assert (status, body) == (200, "remote=[] gate=[]\n")


def test_a_host_created_by_hand_does_not_forward_the_headers_either(stack):
    status, body = _get(
        stack["http"],
        OPERATOR_HOST,
        {"X-Papaia-Remote-User": "anna", "X-Papaia-Gate": "forged"},
    )

    assert (status, body) == (200, "remote=[] gate=[]\n")


def test_a_container_in_the_host_network_does_not_get_through(stack):
    address = stack["address"]

    direct = _probe("host", f"http://{address}:8000/api/documents/", "X-Papaia-Remote-User: anna")
    gate = _probe("host", f"http://{address}:8001/api/documents/", "X-Papaia-Remote-User: anna")

    assert "remote=" not in direct
    assert "refused" in direct.lower() or "timed out" in direct.lower(), direct
    assert "remote=" not in gate
    assert "403" in gate, gate


def test_a_container_on_a_foreign_network_does_not_get_through(stack):
    address = stack["address"]

    for port in (8000, 8001):
        out = _probe(
            f"{PROJECT}-foreign", f"http://{address}:{port}/api/documents/",
            "X-Papaia-Remote-User: anna",
        )  # fmt: skip
        assert "remote=" not in out, out
    by_name = _probe(
        f"{PROJECT}-foreign", "http://paperless:8001/api/documents/", "X-Papaia-Remote-User: anna"
    )
    assert "remote=" not in by_name, by_name


def test_a_rotated_secret_takes_effect_after_the_reload(stack):
    config_dir = stack["config_dir"]
    old = paperless_gate.read_proxy_secret(config_dir)

    paperless_gate.rotate(config_dir, "paperless-gate/proxy")
    assert paperless_gate.reload_proxy(PROJECT) is True
    time.sleep(1)

    # The gate still expects the old secret: the proxy no longer sends it.
    status, _ = _get(stack["http"], PAPERLESS_HOST, {"X-Papaia-Gate": old})
    assert status == 403
    _write_gate(stack["gate_conf"], paperless_gate.read_proxy_secret(config_dir))
    _run(*stack["compose"], "exec", "-T", "paperless", "nginx", "-s", "reload", env=stack["env"])
    time.sleep(1)
    status, body = _get(stack["http"], PAPERLESS_HOST, {"X-Papaia-Remote-User": "anna"})
    assert (status, body) == (200, "remote=[] gate=[]\n")
    rows = (config_dir / "audit" / "papaia-ctl.jsonl").read_text(encoding="utf-8")
    assert old not in rows
    assert [json.loads(r)["event"] for r in rows.splitlines()] == [
        "paperless_gate_secret_created",
        "paperless_gate_secret_rotated",
    ]
