"""papaia-docker-gate, the manager's only way to the Docker socket: the compose service,
its network and the allow list of the gate itself.

The gate (`src/infra/docker-gate/docker_gate.py`) is one standard-library file in the
core's own image `ghcr.io/fidonis/papaia-docker-gate`, so it is imported here straight
from the checkout and run against a stand-in Docker daemon on a Unix socket. The stand-in
records every request that reaches it: a refused call must never get there.
"""

from __future__ import annotations

import http.client
import http.server
import io
import json
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import types
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import compat, own_images

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "docker-gate"
SERVICE = "papaia-docker-gate"
NETWORK = "papaia-docker-gate-net"
PROFILE = "manager"
SCHEMA = json.loads(
    (REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json")
    .read_text(encoding="utf-8")
)

OWN = "a" * 64  # a container of the named project `papaia`
FOREIGN = "b" * 64  # a container of another compose project on the same host
LOOSE = "c" * 64  # a container without a compose project


def _gate():
    """The gate module, loaded without leaving a bytecode cache in the source tree."""
    path = MODULE_DIR / "docker_gate.py"
    module = types.ModuleType("papaia_docker_gate")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def _service() -> dict:
    return _compose()["services"][SERVICE]


# ─────────────────────────────────────────────────────────────────────────
# compose service
# ─────────────────────────────────────────────────────────────────────────


def test_the_root_compose_includes_the_gate_with_the_manager_profile():
    services = compat.resolve_core_services(REPO)

    assert services[SERVICE] == [PROFILE]


def test_the_gate_has_no_port_and_only_its_internal_network():
    compose = _compose()
    service = _service()

    assert set(compose["services"]) == {SERVICE}
    assert "ports" not in service
    assert "expose" not in service
    assert service["networks"] == [NETWORK]
    assert set(compose["networks"]) == {NETWORK}
    assert compose["networks"][NETWORK]["internal"] is True


def test_only_the_manager_and_the_gate_are_on_the_gate_network():
    on_network = set()
    for path in sorted((REPO / "src").rglob("docker-compose*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            networks = body.get("networks") or []
            if NETWORK in (networks if isinstance(networks, list) else list(networks)):
                on_network.add(name)

    assert on_network == {SERVICE, "papaia-manager"}


def test_the_socket_is_mounted_read_only_and_nothing_else():
    mounts = _service()["volumes"]

    assert mounts == [{
        "type": "bind",
        "source": "/var/run/docker.sock",
        "target": "/var/run/docker.sock",
        "read_only": True,
        "bind": {"create_host_path": False},
    }]


def test_the_gate_runs_without_privileges_on_its_pinned_own_image():
    service = _service()

    version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    pinned = rf"ghcr\.io/fidonis/papaia-docker-gate:{re.escape(version)}@sha256:[0-9a-f]{{64}}"
    assert re.fullmatch(pinned, service["image"])
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert "privileged" not in service
    assert service["security_opt"] == ["no-new-privileges:true"]
    # Not root: the socket is reached through the group that owns it on the host.
    assert service["group_add"] == ["${DOCKER_GID:-999}"]
    assert "user" not in service
    # The named projects: the installation's own project, nothing else.
    assert service["environment"]["DOCKER_GATE_PROJECTS"] == "${COMPOSE_PROJECT_NAME}"


def test_the_gate_is_an_own_image_of_the_core():
    entry = next(i for i in own_images.load(REPO) if i.name == "ghcr.io/fidonis/papaia-docker-gate")

    assert entry.services == (SERVICE,)
    assert set(entry.inputs) == {
        "src/infra/docker-gate/Dockerfile",
        "src/infra/docker-gate/docker_gate.py",
        "src/infra/docker-gate/THIRD_PARTY_LICENSES.md",
    }
    assert own_images.check(REPO) == []


def test_no_add_on_may_attach_the_gate():
    assert SERVICE in compat.NEVER_ATTACHABLE


def test_the_healthcheck_looks_for_the_listener_of_the_gate_port():
    gate = _gate()
    test = " ".join(_service()["healthcheck"]["test"])

    assert f":{gate.PORT:04X} " in test


def test_every_compose_variable_of_the_gate_is_documented():
    text = (MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    documented = (REPO / "src" / ".env.example").read_text(encoding="utf-8")

    for var in set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)", code)):
        assert re.search(rf"^{var}=", documented, re.M), var


# ─────────────────────────────────────────────────────────────────────────
# configuration
# ─────────────────────────────────────────────────────────────────────────


def test_the_named_projects_are_validated():
    gate = _gate()

    assert gate.load_projects("papaia, papaia-stage") == frozenset({"papaia", "papaia-stage"})
    too_many = ",".join(f"p{i}" for i in range(gate.MAX_PROJECTS + 1))
    for value in ("", " , ", "Papaia", "papaia;rm", "-papaia", "a" * 64, too_many):
        with pytest.raises(gate.GateError):
            gate.load_projects(value)


# ─────────────────────────────────────────────────────────────────────────
# stand-in Docker daemon
# ─────────────────────────────────────────────────────────────────────────


def _container(cid: str, project: str | None, name: str) -> dict:
    labels = {"com.docker.compose.service": name}
    if project is not None:
        labels["com.docker.compose.project"] = project
    return {
        "Id": cid,
        "Names": [f"/{name}"],
        "Image": "example/image:1",
        "ImageID": "sha256:" + "d" * 64,
        "Command": "serve --password=not-for-the-manager",
        "Created": 1700000000,
        "State": "running",
        "Status": "Up 2 minutes",
        "Labels": labels,
        "Mounts": [{"Source": "/srv/secret", "Destination": "/data"}],
        "NetworkSettings": {"Networks": {}},
        "HostConfig": {"NetworkMode": "bridge"},
    }


CONTAINERS = {
    OWN: _container(OWN, "papaia", "papaia-librechat-1"),
    FOREIGN: _container(FOREIGN, "other", "other-db-1"),
    LOOSE: _container(LOOSE, None, "loose"),
}


class _Daemon(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list[tuple[str, str]]

    def log_message(self, *args) -> None:
        pass

    def address_string(self) -> str:  # Unix sockets have no peer address
        return "unix"

    def _reply(self, status: int, body: object | None, headers: dict | None = None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _lookup(self, ref: str) -> dict | None:
        for cid, body in CONTAINERS.items():
            if cid == ref or cid.startswith(ref) or body["Names"][0] == f"/{ref}":
                return body
        return None

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.server.seen.append((self.command, self.path))
        path = re.sub(r"^/v1\.\d+", "", self.path.split("?")[0])
        if path == "/_ping":
            data = b"OK"
            self.send_response(200)
            self.send_header("Api-Version", "1.47")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        if path == "/version":
            return self._reply(200, {"ApiVersion": "1.47", "Version": "27.0.0"})
        if path == "/containers/json":
            return self._reply(200, list(CONTAINERS.values()))
        match = re.fullmatch(r"/containers/([^/]+)/(json|start|stop)", path)
        if match:
            found = self._lookup(match.group(1))
            if found is None:
                return self._reply(404, {"message": "No such container"})
            if match.group(2) == "json":
                return self._reply(200, {
                    "Id": found["Id"],
                    "Name": found["Names"][0],
                    "Created": "2026-11-21T10:00:00Z",
                    "Image": found["ImageID"],
                    "RestartCount": 0,
                    "State": {"Status": "running", "Running": True,
                              "Health": {"Status": "healthy",
                                         "Log": [{"Output": "probe said: secret"}]}},
                    "Config": {"Image": found["Image"], "Labels": found["Labels"],
                               "Env": ["DB_PASSWORD=not-for-the-manager"]},
                    "HostConfig": {"Binds": ["/:/host"]},
                    "Mounts": found["Mounts"],
                })
            return self._reply(204, None)
        return self._reply(200, {"message": "the daemon would have done this"})

    do_GET = do_POST = do_HEAD = do_DELETE = do_PUT = _handle


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def stack():
    """A stand-in daemon on a Unix socket and the gate in front of it, named project
    `papaia`. Yields (request, seen, audit): `request(method, path, ...)` returns
    (status, headers, body); `seen` the requests that reached the daemon; `audit` the
    rows the gate wrote."""
    gate = _gate()
    # A short directory: a Unix socket path is limited to about 100 bytes.
    folder = tempfile.mkdtemp(prefix="dg", dir="/tmp")
    sock = f"{folder}/docker.sock"
    daemon = _UnixServer(sock, _Daemon)
    daemon.seen = []
    threading.Thread(target=daemon.serve_forever, args=(0.02,), daemon=True).start()
    out = io.StringIO()
    server = gate.make_server("127.0.0.1", 0, socket_path=sock,
                              projects=frozenset({"papaia"}), out=out)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    port = server.server_address[1]

    def request(method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, dict(response.getheaders()), data

    def audit():
        return [json.loads(line) for line in out.getvalue().splitlines() if line]

    try:
        yield gate, request, daemon.seen, audit
    finally:
        server.shutdown()
        server.server_close()
        daemon.shutdown()
        daemon.server_close()
        shutil.rmtree(folder, ignore_errors=True)


def _valid(row: dict) -> None:
    # The delivering writer numbers the rows of a source (docs/audit.md); the row itself
    # is the submission form otherwise.
    submitted = {**row, "source_seq": 1}
    validator = Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/submission"})
    assert [e.message for e in validator.iter_errors(submitted)] == []


# ─────────────────────────────────────────────────────────────────────────
# refused: exec, create, foreign projects, everything not on the list
# ─────────────────────────────────────────────────────────────────────────


def test_exec_is_refused_with_an_audit_row_and_never_reaches_the_socket(stack):
    _gate_module, request, seen, audit = stack

    body = json.dumps({"Cmd": ["sh"], "AttachStdout": True})
    status, headers, data = request(
        "POST", f"/v1.47/containers/{OWN}/exec", body=body,
        headers={"Content-Type": "application/json", "X-Papaia-Correlation-Id": "corr-exec-1"})

    assert status == 403
    assert json.loads(data)["error"] == "docker_gate.not_allowed"
    assert headers["X-Papaia-Correlation-Id"] == "corr-exec-1"
    assert seen == []
    (row,) = audit()
    assert row["result"] == "denied"
    assert row["operation"] == "docker_gate.container_exec"
    assert row["correlation_id"] == "corr-exec-1"
    assert row["error_code"] == "docker_gate.not_allowed"
    _valid(row)


def test_create_with_a_host_mount_is_refused_and_never_reaches_the_socket(stack):
    _gate_module, request, seen, audit = stack

    body = json.dumps({"Image": "alpine", "HostConfig": {"Binds": ["/:/host"],
                                                         "Privileged": True}})
    status, _headers, data = request("POST", "/containers/create?name=x", body=body,
                                     headers={"Content-Type": "application/json"})

    assert status == 403
    assert json.loads(data)["error"] == "docker_gate.not_allowed"
    assert seen == []
    (row,) = audit()
    assert row["operation"] == "docker_gate.container_create"
    assert row["result"] == "denied"
    _valid(row)


@pytest.mark.parametrize("ref", [FOREIGN, "other-db-1", LOOSE])
@pytest.mark.parametrize("action", ["start", "stop"])
def test_start_and_stop_of_a_foreign_project_are_refused(stack, ref, action):
    _gate_module, request, seen, audit = stack

    status, _headers, data = request("POST", f"/containers/{ref}/{action}")

    assert status == 403
    assert json.loads(data)["error"] == "docker_gate.foreign_project"
    # Only the lookup reached the daemon, never the action itself.
    assert all(method == "GET" for method, _path in seen)
    (row,) = audit()
    assert row["operation"] == f"docker_gate.container_{action}"
    assert row["effect"] == "write"
    assert row["result"] == "denied"
    _valid(row)


def test_an_unknown_container_is_refused_like_a_foreign_one(stack):
    _gate_module, request, seen, audit = stack

    status, _headers, data = request("POST", "/containers/nothere/start")

    assert status == 403
    assert json.loads(data)["error"] == "docker_gate.foreign_project"
    assert [m for m, _p in seen] == ["GET"]
    assert audit()[0]["result"] == "denied"


def test_inspect_of_a_foreign_container_is_refused(stack):
    _gate_module, request, _seen, audit = stack

    status, _headers, _data = request("GET", f"/containers/{FOREIGN}/json")

    assert status == 403
    assert audit()[0]["operation"] == "docker_gate.container_inspect"


@pytest.mark.parametrize("method,path", [
    ("POST", f"/containers/{OWN}/restart"),
    ("POST", f"/containers/{OWN}/kill"),
    ("POST", f"/containers/{OWN}/update"),
    ("POST", f"/containers/{OWN}/attach"),
    ("POST", f"/containers/{OWN}/rename?name=x"),
    ("DELETE", f"/containers/{OWN}"),
    ("PUT", f"/containers/{OWN}/archive?path=/"),
    ("GET", f"/containers/{OWN}/archive?path=/"),
    ("GET", f"/containers/{OWN}/logs"),
    ("GET", f"/containers/{OWN}/export"),
    ("POST", "/exec/abc/start"),
    ("POST", "/volumes/create"),
    ("POST", "/networks/create"),
    ("POST", "/images/create?fromImage=alpine"),
    ("POST", "/build"),
    ("POST", "/session"),
    ("GET", "/info"),
    ("GET", "/events"),
    ("POST", "/services/create"),
    ("GET", "/containers/../info"),
    ("GET", "/v9.99/containers/json"),
    ("GET", "/containers//json"),
    ("GET", "/containers/json/"),
])
def test_everything_not_on_the_allow_list_is_refused(stack, method, path):
    _gate_module, request, seen, audit = stack

    status, _headers, _data = request(method, path)

    assert status == 403
    assert seen == []
    (row,) = audit()
    assert row["result"] == "denied"
    _valid(row)


@pytest.mark.parametrize("method,path,body", [
    ("POST", f"/containers/{OWN}/start", b'{"x":1}'),
    ("POST", f"/containers/{OWN}/start?detachKeys=ctrl-p", None),
    ("POST", f"/containers/{OWN}/stop?t=abc", None),
    ("POST", f"/containers/{OWN}/stop?t=99999", None),
    ("POST", f"/containers/{OWN}/stop?signal=SIGKILL", None),
    ("POST", f"/containers/{OWN}/stop?t=1&t=2", None),
    ("GET", "/containers/json?size=1", None),
    ("GET", "/containers/json?all=maybe", None),
    ("GET", "/containers/json?filters=notjson", None),
    ("GET", "/containers/json?filters=" + "%5B%5D", None),
    ("POST", "/containers/" + "x" * 200 + "/start", None),
    ("POST", "/containers/bad%20name/start", None),
])
def test_invalid_input_on_an_allowed_call_is_rejected(stack, method, path, body):
    _gate_module, request, seen, audit = stack

    status, _headers, data = request(method, path, body=body)

    assert status == 400
    assert json.loads(data)["error"] == "docker_gate.invalid_request"
    assert seen == []
    (row,) = audit()
    assert row["result"] == "denied"
    _valid(row)


def test_a_chunked_body_is_rejected(stack):
    _gate_module, request, seen, _audit = stack

    status, _headers, _data = request("POST", f"/containers/{OWN}/start",
                                      headers={"Transfer-Encoding": "chunked"}, body=b"0\r\n\r\n")

    assert status == 400
    assert seen == []


def test_an_unusable_correlation_id_is_replaced(stack):
    _gate_module, request, _seen, audit = stack

    _status, headers, _data = request("POST", "/build",
                                      headers={"X-Papaia-Correlation-Id": "eyJ.bad value"})

    row = audit()[0]
    assert re.fullmatch(r"[0-9a-f-]{36}", row["correlation_id"])
    assert headers["X-Papaia-Correlation-Id"] == row["correlation_id"]


# ─────────────────────────────────────────────────────────────────────────
# allowed: status, start and stop of the named project
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("action", ["start", "stop"])
def test_start_and_stop_of_a_named_project_work_and_are_audited(stack, action):
    _gate_module, request, seen, audit = stack

    status, headers, _data = request(
        "POST", f"/v1.47/containers/papaia-librechat-1/{action}" + ("?t=10" if action == "stop"
                                                                    else ""),
        headers={"X-Papaia-Correlation-Id": "corr-1"})

    assert status == 204
    assert headers["X-Papaia-Correlation-Id"] == "corr-1"
    # The action names the full id the lookup returned, so the name cannot be moved to
    # another container between the check and the call.
    assert seen[-1] == ("POST", f"/v1.47/containers/{OWN}/{action}"
                        + ("?t=10" if action == "stop" else ""))
    (row,) = audit()
    assert row == {
        "format": "papaia.audit/1",
        "time": row["time"],
        "correlation_id": "corr-1",
        "writer": "papaia-docker-gate",
        "role": "server",
        "sub": "papaia-manager",
        "identity_kind": "service",
        "service_account": "papaia-manager",
        "azp": "papaia-manager",
        "catalog_id": "papaia-docker-gate",
        "operation": f"docker_gate.container_{action}",
        "effect": "write",
        "object_ref": {"type": "container", "id": OWN},
        "result": "allowed",
        "error_code": None,
        "client_ip": "127.0.0.1",
        "detail": None,
        "event": "operation",
    }
    _valid(row)


def test_the_status_lists_only_the_named_project_without_command_or_mounts(stack):
    _gate_module, request, seen, audit = stack

    status, _headers, data = request("GET", "/v1.47/containers/json?all=1")

    assert status == 200
    listed = json.loads(data)
    assert [c["Id"] for c in listed] == [OWN]
    assert set(listed[0]) == {"Id", "Names", "Image", "ImageID", "Created", "State", "Status",
                              "Labels"}
    assert b"not-for-the-manager" not in data and b"/srv/secret" not in data
    assert seen == [("GET", "/v1.47/containers/json?all=1")]
    # Reading is not a write; no audit row.
    assert audit() == []


def test_the_status_passes_a_valid_filter(stack):
    _gate_module, request, seen, _audit = stack

    status, _headers, _data = request(
        "GET", "/containers/json?filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D")

    assert status == 200
    assert seen[0][1].startswith("/containers/json?filters=")


def test_inspect_of_a_named_container_hides_environment_mounts_and_probe_output(stack):
    _gate_module, request, _seen, _audit = stack

    status, _headers, data = request("GET", f"/containers/{OWN}/json")

    assert status == 200
    found = json.loads(data)
    assert found["Id"] == OWN
    assert found["State"]["Health"] == {"Status": "healthy"}
    assert set(found["Config"]) == {"Image", "Labels"}
    assert "HostConfig" not in found and "Mounts" not in found
    assert b"not-for-the-manager" not in data and b"secret" not in data


def test_ping_and_version_work_for_client_negotiation(stack):
    _gate_module, request, _seen, audit = stack

    status, headers, data = request("GET", "/_ping")
    assert (status, data) == (200, b"OK")
    assert headers["Api-Version"] == "1.47"
    status, _headers, _data = request("HEAD", "/_ping")
    assert status == 200
    status, _headers, data = request("GET", "/v1.47/version")
    assert status == 200 and json.loads(data)["ApiVersion"] == "1.47"
    assert audit() == []


def test_a_daemon_that_does_not_answer_is_an_error_row(stack):
    gate, _request, _seen, _audit = stack
    out = io.StringIO()
    server = gate.make_server("127.0.0.1", 0, socket_path="/tmp/dg-missing.sock",
                              projects=frozenset({"papaia"}), out=out)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        conn.request("POST", f"/containers/{OWN}/start")
        response = conn.getresponse()
        response.read()
        conn.close()
    finally:
        server.shutdown()
        server.server_close()

    assert response.status == 502
    (row,) = [json.loads(line) for line in out.getvalue().splitlines()]
    assert row["result"] == "error"
    assert row["error_code"] == "docker_gate.upstream_failed"
    _valid(row)
