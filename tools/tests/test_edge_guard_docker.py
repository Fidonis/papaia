"""The edge's refusal of writes from Studio app hosts, with real containers (STU-25-A7).

The bundled proxy is started from the core compose file; stand-ins for the manager and
for Me answer behind it, and `npm-provision` creates their proxy hosts and installs the
guard (lib/edge_guard.py). Without a second domain the app hosts are `apps.<domain>` and
its subdomains.

Checked: a write whose `Origin` is an app host is refused with 403 on the manager, on Me
and on a proxy host created by hand, and leaves one `papaia.audit/1` line; the same
write from the platform's own origin, a read from an app host and a preflight pass.

Needs Docker; skipped without it. The Compose project, the address range (a /24) and the
first of three host ports (on 127.0.0.1) can be set with PAPAIA_EDGE_GUARD_TEST_PROJECT,
PAPAIA_EDGE_GUARD_TEST_SUBNET and PAPAIA_EDGE_GUARD_TEST_PORT so the test does not
collide with other stacks.
"""

from __future__ import annotations

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

import live_names
import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import edge_guard, npm_provision, paperless_gate

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "infra" / "nginx" / "docker-compose.yml"
SCHEMA = json.loads(
    (REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json").read_text(
        encoding="utf-8"
    )
)
PROJECT = live_names.project("edge-guard-test", "PAPAIA_EDGE_GUARD_TEST_PROJECT")
SUBNET = live_names.subnet("PAPAIA_EDGE_GUARD_TEST_SUBNET")
STUB_IMAGE = (
    "nginx:1.31.2-alpine@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa"
)
DOMAIN = "edge-guard-test.example"
MANAGER_HOST = f"manager.{DOMAIN}"
ME_HOST = f"me.{DOMAIN}"
OPERATOR_HOST = f"manual.{DOMAIN}"
APP_ORIGIN = f"https://apps.{DOMAIN}"
PER_APP_ORIGIN = f"https://crm.apps.{DOMAIN}:8443"


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

# A stand-in for a platform service: answers every method with its name.
_ECHO = """
server {
    listen %d;
    location / {
        default_type text/plain;
        return 200 "%s method=[$request_method]\\n";
    }
}
"""


def _run(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, env=env, timeout=600, check=check
    )


def _ports() -> list[int]:
    base = os.environ.get("PAPAIA_EDGE_GUARD_TEST_PORT")
    if base:
        return [int(base) + i for i in range(3)]
    found = []
    for _ in range(3):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            found.append(s.getsockname()[1])
    return found


def _send(
    port: int, method: str, host: str, origin: str | None = None
) -> tuple[int, str, dict[str, str]]:
    headers = {"Host": host}
    if origin is not None:
        headers["Origin"] = origin
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/settings",
        data=b'{"x": 1}' if method in ("POST", "PUT", "PATCH", "DELETE") else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), dict(exc.headers)


def _audit_lines(config_dir: Path) -> list[dict]:
    path = edge_guard.host_path(config_dir, edge_guard.AUDIT_LOG)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _settled(config_dir: Path) -> list[dict]:
    """The audit lines once the count stops changing: the bind mount shows a line a
    moment after nginx wrote it."""
    lines = _audit_lines(config_dir)
    for _ in range(20):
        time.sleep(0.5)
        again = _audit_lines(config_dir)
        if len(again) == len(lines):
            return again
        lines = again
    return lines


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory):
    tmp_path = tmp_path_factory.mktemp("edge-guard")
    http_port, https_port, api_port = _ports()
    config_dir = tmp_path / "papaia-config"
    (config_dir / "infra" / "nginx" / "nginx-data").mkdir(parents=True)
    (config_dir / "infra" / "nginx" / "nginx-letsencrypt").mkdir(parents=True)
    paperless_gate.prepare(config_dir)

    services = {}
    for name, port in (("papaia-manager", 8000), ("me-web", 8000), ("operator-app", 8080)):
        conf = tmp_path / f"{name}.conf"
        conf.write_text(_ECHO % (port, name), encoding="utf-8")
        services[name] = {
            "image": STUB_IMAGE,
            "volumes": [f"{conf}:/etc/nginx/conf.d/default.conf:ro"],
            "networks": ["papaia-net"],
        }
    extra = {
        "services": services,
        "networks": {"papaia-net": {"ipam": {"config": [{"subnet": str(SUBNET)}]}}},
    }
    extra_file = tmp_path / "stand-in.yml"
    extra_file.write_text(yaml.safe_dump(extra), encoding="utf-8")
    password = secrets.token_urlsafe(24)
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
            *compose, "up", "-d", "--wait", "nginx-proxy-manager", *services,
            env=env, check=False,
        )  # fmt: skip
        assert up.returncode == 0, up.stderr
        tree = {
            "": {
                "REVERSE_PROXY_PROVIDER": "internal_nginx",
                "COMPOSE_PROFILES": "nginx,manager,me",
                "COMPOSE_PROJECT_NAME": PROJECT,
                "PAPAIA_HOST": f"http://{DOMAIN}",
                "MANAGER_PUBLIC_URL": f"http://{MANAGER_HOST}",
                "ME_PUBLIC_URL": f"http://{ME_HOST}",
            },
            "infra/nginx": {
                "NPM_ADMIN_EMAIL": "admin@papaia.local",
                "NPM_ADMIN_PASSWORD": password,
                "NPM_API_LOCAL_PORT": str(api_port),
            },
        }
        assert npm_provision.provision_npm_hosts(tree, config_dir) is True
        base = f"http://127.0.0.1:{api_port}"
        token = npm_provision._get_token(base, "admin@papaia.local", password)
        npm_provision._post_proxy_host(
            base, token, npm_provision.proxy_host_body(OPERATOR_HOST, "operator-app", 8080, "http")
        )
        time.sleep(2)
        yield {"http": http_port, "config_dir": config_dir, "tree": tree}
    finally:
        _run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)


@pytest.mark.parametrize("host", [MANAGER_HOST, ME_HOST, OPERATOR_HOST])
@pytest.mark.parametrize("origin", [APP_ORIGIN, PER_APP_ORIGIN])
def test_a_write_from_an_app_host_is_refused_and_audited(stack, host, origin):
    before = len(_settled(stack["config_dir"]))

    status, body, headers = _send(stack["http"], "POST", host, origin)

    assert status == 403
    assert "method=" not in body
    assert headers.get("X-Papaia-Error") == "app_origin_refused"
    correlation = headers.get("X-Papaia-Correlation-Id")
    assert correlation
    lines = _settled(stack["config_dir"])
    assert len(lines) == before + 1
    row = lines[-1]
    assert row["correlation_id"] == correlation
    assert row["object_ref"] == {"type": "host", "id": host}
    assert (row["event"], row["result"], row["error_code"]) == (
        "protected_host_denied",
        "denied",
        "app_origin_refused",
    )
    assert origin not in json.dumps(row)
    validator = Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/submission"})
    assert [e.message for e in validator.iter_errors({**row, "source_seq": 1})] == []


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_every_state_changing_method_is_refused(stack, method):
    status, _, _ = _send(stack["http"], method, MANAGER_HOST, APP_ORIGIN)

    assert status == 403


@pytest.mark.parametrize(
    ("method", "origin"),
    [
        ("POST", f"https://{MANAGER_HOST}"),
        ("POST", None),
        ("POST", "null"),
        ("GET", APP_ORIGIN),
        ("OPTIONS", APP_ORIGIN),
    ],
)
def test_platform_writes_reads_and_preflights_pass(stack, method, origin):
    before = len(_settled(stack["config_dir"]))

    status, body, headers = _send(stack["http"], method, MANAGER_HOST, origin)

    assert (status, body) == (200, f"papaia-manager method=[{method}]\n")
    assert "X-Papaia-Error" not in headers
    assert len(_settled(stack["config_dir"])) == before


def test_provisioning_again_changes_nothing(stack):
    project = stack["tree"][""]["COMPOSE_PROJECT_NAME"]

    assert edge_guard.install(project, edge_guard.app_host_bases(stack["tree"][""])) is False
