"""papaia-docker-gate: the manager's only way to the Docker socket.

Whoever can talk to the Docker socket is root on the host. The manager therefore gets no
socket: it talks HTTP to this gate on the internal network `papaia-docker-gate-net`, and
the gate alone holds the socket (mounted read-only). The gate speaks a small part of the
Docker Engine API and decides every request itself, before anything reaches the socket:

  allowed   GET|HEAD /_ping, GET /version              (client version negotiation)
            GET /containers/json                       status, only the named projects
            GET /containers/{id}/json                  status of one container
            POST /containers/{id}/start                containers of a named project
            POST /containers/{id}/stop[?t=seconds]

  refused   everything else with 403: `exec`, `create` (with or without host mounts),
            `kill`, `restart`, `update`, `logs`, archives, images, volumes, networks,
            builds, `info`, `events`, other API versions, ...

A container belongs to a named project when its label `com.docker.compose.project` is one
of DOCKER_GATE_PROJECTS (the installation's own compose project). For start and stop the
gate looks the container up first and then acts on the full id it found, so a name
cannot be moved to another container between the check and the call. An unknown
container is refused like a foreign one, so the answer does not tell which containers
exist elsewhere on the host.

Status answers are cut to a fixed set of fields: no environment, command line, mounts,
host configuration or health-check output leaves the gate, as those may hold secrets of
the services.

Every start and stop and every refusal is one JSON line on stdout in the shape of
`papaia.audit/1` (the submission form; the delivering writer numbers the rows), with the
correlation id of the request; ids and names only, never a body. Operational messages go
to stderr.

Standard library only; runs as an unprivileged user on a read-only file system.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass

PORT = 2375
DEFAULT_SOCKET = "/var/run/docker.sock"
PROJECT_LABEL = "com.docker.compose.project"
MAX_PROJECTS = 32
MAX_PATH = 512
MAX_QUERY = 2048
MAX_DRAIN = 64 * 1024
MAX_UPSTREAM_BYTES = 8 * 1024 * 1024
MAX_STOP_SECONDS = 600
MAX_CONCURRENT = 32
REQUEST_TIMEOUT_SECONDS = 15
UPSTREAM_TIMEOUT_SECONDS = 30
WRITER = "papaia-docker-gate"
# The one service on papaia-docker-gate-net besides the gate.
CALLER = "papaia-manager"

_PROJECT_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")
_CONTAINER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_FULL_ID_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_CORRELATION_RE = re.compile(r"\A[A-Za-z0-9-]{1,64}\Z")
_VERSION_RE = re.compile(r"\A/v1\.(?:2[4-9]|[3-9][0-9])(?=/)")
_BOOL = {"0", "1", "true", "false"}

# Fields of a status answer that may leave the gate.
LIST_FIELDS = ("Id", "Names", "Image", "ImageID", "Created", "State", "Status", "Labels")
INSPECT_FIELDS = ("Id", "Name", "Created", "Image", "RestartCount")
STATE_FIELDS = ("Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead", "ExitCode",
                "StartedAt", "FinishedAt")

NOT_ALLOWED = "docker_gate.not_allowed"
INVALID = "docker_gate.invalid_request"
FOREIGN = "docker_gate.foreign_project"
UPSTREAM = "docker_gate.upstream_failed"
BUSY = "docker_gate.busy"


class GateError(ValueError):
    """A setting the gate cannot start with; the message says why."""


class Refused(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def load_projects(value: str) -> frozenset[str]:
    """The named projects from DOCKER_GATE_PROJECTS: compose project names, comma
    separated, at least one."""
    names = [part.strip() for part in (value or "").split(",") if part.strip()]
    if not names:
        raise GateError("DOCKER_GATE_PROJECTS names no project")
    if len(names) > MAX_PROJECTS:
        raise GateError(f"DOCKER_GATE_PROJECTS names more than {MAX_PROJECTS} projects")
    for name in names:
        if not _PROJECT_RE.match(name):
            raise GateError(f"DOCKER_GATE_PROJECTS: {name!r} is not a compose project name")
    return frozenset(names)


# ─────────────────────────────────────────────────────────────────────────
# decisions
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Call:
    """An allowed call, its input checked."""

    operation: str  # container_list, container_inspect, container_start, ...
    effect: str
    prefix: str  # the API version prefix, as sent ("" or "/v1.47")
    container: str | None = None
    query: str = ""


def _query(raw: str, allowed: set[str]) -> dict[str, str]:
    if len(raw) > MAX_QUERY:
        raise Refused(400, INVALID)
    try:
        pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True, strict_parsing=bool(raw),
                                       max_num_fields=8)
    except ValueError as exc:
        raise Refused(400, INVALID) from exc
    found: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in found:
            raise Refused(400, INVALID)
        found[key] = value
    return found


def _filters(value: str) -> None:
    try:
        doc = json.loads(value)
    except ValueError as exc:
        raise Refused(400, INVALID) from exc
    if not isinstance(doc, dict) or len(doc) > 16:
        raise Refused(400, INVALID)
    for key, entry in doc.items():
        values = list(entry) if isinstance(entry, (list, dict)) else None
        if not isinstance(key, str) or values is None or len(values) > 16:
            raise Refused(400, INVALID)
        if not all(isinstance(v, str) and len(v) <= 256 for v in values):
            raise Refused(400, INVALID)


def denied_operation(path: str) -> str:
    """The name a refused request is audited under."""
    rest = _VERSION_RE.sub("", path, count=1)
    if re.fullmatch(r"/containers/[^/]+/exec", rest) or rest.startswith("/exec/"):
        return "container_exec"
    if rest == "/containers/create":
        return "container_create"
    match = re.fullmatch(r"/containers/([^/]+)/(start|stop|json)", rest)
    if match:
        return "container_inspect" if match.group(2) == "json" else f"container_{match.group(2)}"
    return "request"


def decide(method: str, target: str, headers) -> Call:
    """The allowed call a request asks for; raises Refused otherwise. Only the request
    line and the headers are looked at: no body is read for a decision."""
    if len(target) > MAX_PATH + MAX_QUERY + 1 or not target.startswith("/"):
        raise Refused(403, NOT_ALLOWED)
    path, _, raw_query = target.partition("?")
    version = _VERSION_RE.match(path)
    prefix = version.group(0) if version else ""
    rest = path[len(prefix):]
    if len(path) > MAX_PATH or "//" in path or "/." in path:
        raise Refused(403, NOT_ALLOWED)

    if rest == "/_ping" and method in ("GET", "HEAD"):
        call = Call("ping", "read", prefix)
        allowed: set[str] = set()
    elif rest == "/version" and method == "GET":
        call = Call("version", "read", prefix)
        allowed = set()
    elif rest == "/containers/json" and method == "GET":
        call = Call("container_list", "read", prefix)
        allowed = {"all", "filters"}
    else:
        match = re.fullmatch(r"/containers/([^/]+)/(json|start|stop)", rest)
        expected = {"json": "GET", "start": "POST", "stop": "POST"}
        if match is None or method != expected[match.group(2)]:
            raise Refused(403, NOT_ALLOWED)
        ref, action = match.groups()
        if not _CONTAINER_RE.match(ref):
            raise Refused(400, INVALID)
        operation = "container_inspect" if action == "json" else f"container_{action}"
        call = Call(operation, "read" if action == "json" else "write", prefix, ref)
        allowed = {"t"} if action == "stop" else set()

    if "Transfer-Encoding" in headers:
        raise Refused(400, INVALID)
    if (headers.get("Content-Length") or "0").strip() != "0":
        raise Refused(400, INVALID)
    query = _query(raw_query, allowed)
    if "all" in query and query["all"] not in _BOOL:
        raise Refused(400, INVALID)
    if "filters" in query:
        _filters(query["filters"])
    if "t" in query:
        if not re.fullmatch(r"[0-9]{1,3}", query["t"]) or int(query["t"]) > MAX_STOP_SECONDS:
            raise Refused(400, INVALID)
    return Call(call.operation, call.effect, call.prefix, call.container,
                urllib.parse.urlencode(query))


def project_of(container: dict) -> str | None:
    labels = (container.get("Config") or {}).get("Labels") if "Config" in container else (
        container.get("Labels"))
    value = (labels or {}).get(PROJECT_LABEL) if isinstance(labels, dict) else None
    return value if isinstance(value, str) else None


def list_view(containers: object, projects: frozenset[str]) -> list[dict]:
    if not isinstance(containers, list):
        raise Refused(502, UPSTREAM)
    return [{key: c[key] for key in LIST_FIELDS if key in c}
            for c in containers if isinstance(c, dict) and project_of(c) in projects]


def inspect_view(container: dict) -> dict:
    view = {key: container[key] for key in INSPECT_FIELDS if key in container}
    state = container.get("State")
    if isinstance(state, dict):
        view["State"] = {key: state[key] for key in STATE_FIELDS if key in state}
        health = state.get("Health")
        if isinstance(health, dict) and "Status" in health:
            view["State"]["Health"] = {"Status": health["Status"]}
    config = container.get("Config") or {}
    view["Config"] = {"Image": config.get("Image"), "Labels": config.get("Labels") or {}}
    return view


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def _uuid7() -> str:
    millis = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (millis & (2**48 - 1)) << 80 | 7 << 76 | (rand >> 62 & 0xFFF) << 64
    value |= 2 << 62 | rand & (2**62 - 1)
    return str(uuid.UUID(int=value))


def correlation_id(value: str | None) -> str:
    # A value shaped like a token is not kept (the token rule of papaia.audit/1).
    if value and _CORRELATION_RE.match(value) and not value.startswith("eyJ"):
        return value
    return _uuid7()


def _client_ip(address: str) -> str | None:
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


def audit_row(*, operation: str, effect: str | None, container: str | None, result: str,
              error_code: str | None, correlation: str, client: str) -> dict:
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1000):03d}Z"
    return {
        "format": "papaia.audit/1",
        "time": stamp,
        "correlation_id": correlation,
        "writer": WRITER,
        "role": "server",
        # There is no token: the caller is known by the network it comes from. Only
        # papaia-manager shares papaia-docker-gate-net with the gate, and no add-on may
        # attach the gate, so every request is the manager's.
        "sub": CALLER,
        "identity_kind": "service",
        "service_account": CALLER,
        "azp": CALLER,
        "catalog_id": WRITER,
        "operation": f"docker_gate.{operation}",
        "effect": effect,
        "object_ref": {"type": "container", "id": container} if container else None,
        "result": result,
        "error_code": error_code,
        "client_ip": _client_ip(client),
        "detail": None,
        "event": "operation",
    }


# ─────────────────────────────────────────────────────────────────────────
# the socket
# ─────────────────────────────────────────────────────────────────────────


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("docker", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


@dataclass
class Answer:
    status: int
    headers: dict[str, str]
    body: bytes


def upstream(socket_path: str, method: str, path: str, timeout: float) -> Answer:
    conn = _UnixConnection(socket_path, timeout)
    try:
        conn.request(method, path, headers={"Host": "docker", "Content-Length": "0"})
        response = conn.getresponse()
        body = response.read(MAX_UPSTREAM_BYTES + 1)
        if len(body) > MAX_UPSTREAM_BYTES:
            raise Refused(502, UPSTREAM)
        keep = {key: value for key, value in response.getheaders()
                if key.lower() in ("content-type", "api-version", "ostype")}
        return Answer(response.status, keep, body)
    except (OSError, http.client.HTTPException) as exc:
        raise Refused(502, UPSTREAM) from exc
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────
# server
# ─────────────────────────────────────────────────────────────────────────


def _log(message: str) -> None:
    print(f"papaia-docker-gate: {message}", file=sys.stderr, flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "papaia-docker-gate"
    sys_version = ""
    timeout = REQUEST_TIMEOUT_SECONDS

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # one line per decision in _finish instead; never the query

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    # -- one request -------------------------------------------------------

    def _handle(self) -> None:
        gate: Server = self.server  # type: ignore[assignment]
        correlation = correlation_id(self.headers.get("X-Papaia-Correlation-Id"))
        if not gate.slots.acquire(blocking=False):
            self._drain()
            self._send(503, {"error": BUSY}, correlation)
            return
        try:
            self._decide_and_run(gate, correlation)
        finally:
            gate.slots.release()

    def _decide_and_run(self, gate: Server, correlation: str) -> None:
        try:
            call = decide(self.command, self.path, self.headers)
        except Refused as refused:
            self._drain()
            ref = self._container_ref()
            self._audit(gate, denied_operation(self.path.partition("?")[0]),
                        "read" if self.command in ("GET", "HEAD") else "write", ref, "denied",
                        refused.code, correlation)
            self._send(refused.status, {"error": refused.code}, correlation)
            return
        try:
            self._run(gate, call, correlation)
        except Refused as refused:
            result = "denied" if refused.status < 500 else "error"
            self._audit(gate, call.operation, call.effect, call.container, result, refused.code,
                        correlation)
            self._send(refused.status, {"error": refused.code}, correlation)

    def _run(self, gate: Server, call: Call, correlation: str) -> None:
        suffix = f"?{call.query}" if call.query else ""
        if call.operation in ("ping", "version"):
            rest = "/_ping" if call.operation == "ping" else "/version"
            answer = upstream(gate.socket_path, self.command, call.prefix + rest,
                              UPSTREAM_TIMEOUT_SECONDS)
            self._send_raw(answer.status, answer.headers, answer.body, correlation)
            return
        if call.operation == "container_list":
            answer = upstream(gate.socket_path, "GET", f"{call.prefix}/containers/json{suffix}",
                              UPSTREAM_TIMEOUT_SECONDS)
            if answer.status != 200:
                raise Refused(502, UPSTREAM)
            self._send(200, list_view(self._json(answer), gate.projects), correlation)
            return

        found = self._lookup(gate, call)
        if call.operation == "container_inspect":
            self._send(200, inspect_view(found), correlation)
            return
        # Docker waits up to `t` seconds (default 10) before it kills the container.
        grace = int(urllib.parse.parse_qs(call.query).get("t", ["10"])[0])
        timeout = UPSTREAM_TIMEOUT_SECONDS + grace
        action = call.operation.removeprefix("container_")
        answer = upstream(gate.socket_path, "POST",
                          f"{call.prefix}/containers/{found['Id']}/{action}{suffix}", timeout)
        if answer.status not in (204, 304):
            self._audit(gate, call.operation, call.effect, found["Id"], "error", UPSTREAM,
                        correlation)
            self._send_raw(answer.status, answer.headers, answer.body, correlation)
            return
        self._audit(gate, call.operation, call.effect, found["Id"], "allowed", None, correlation)
        self._send_raw(answer.status, {}, b"", correlation)

    def _lookup(self, gate: Server, call: Call) -> dict:
        ref = urllib.parse.quote(call.container or "", safe="")
        answer = upstream(gate.socket_path, "GET", f"{call.prefix}/containers/{ref}/json",
                          UPSTREAM_TIMEOUT_SECONDS)
        if answer.status == 404:
            raise Refused(403, FOREIGN)
        if answer.status != 200:
            raise Refused(502, UPSTREAM)
        found = self._json(answer)
        if not isinstance(found, dict) or not _FULL_ID_RE.match(str(found.get("Id", ""))):
            raise Refused(502, UPSTREAM)
        if project_of(found) not in gate.projects:
            raise Refused(403, FOREIGN)
        return found

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _json(answer: Answer) -> object:
        try:
            return json.loads(answer.body)
        except ValueError as exc:
            raise Refused(502, UPSTREAM) from exc

    def _container_ref(self) -> str | None:
        match = re.match(r"\A(?:/v1\.[0-9]{2})?/containers/([^/?]+)/", self.path)
        if match and _CONTAINER_RE.match(match.group(1)) and match.group(1) != "create":
            return match.group(1)
        return None

    def _drain(self) -> None:
        """A refused request's body is not read for the decision; read a small one away
        so the client sees the answer, close the connection otherwise."""
        length = self.headers.get("Content-Length", "")
        if "Transfer-Encoding" in self.headers or not length.isdigit() or (
                int(length) > MAX_DRAIN):
            self.close_connection = True
            return
        if int(length):
            self.rfile.read(int(length))

    def _audit(self, gate: Server, operation: str, effect: str | None, container: str | None,
               result: str, error_code: str | None, correlation: str) -> None:
        row = audit_row(operation=operation, effect=effect, container=container, result=result,
                        error_code=error_code, correlation=correlation,
                        client=self.client_address[0])
        with gate.out_lock:
            print(json.dumps(row), file=gate.out, flush=True)
        _log(f"{operation} {result}{' ' + error_code if error_code else ''}")

    def _send(self, status: int, body: object, correlation: str) -> None:
        self._send_raw(status, {"Content-Type": "application/json"},
                       json.dumps(body).encode(), correlation)

    def _send_raw(self, status: int, headers: dict[str, str], body: bytes,
                  correlation: str) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("X-Papaia-Correlation-Id", correlation)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, *, socket_path: str, projects: frozenset[str], out):
        self.socket_path = socket_path
        self.projects = projects
        self.out = out
        self.out_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        super().__init__(address, Handler)


def make_server(host: str, port: int, *, socket_path: str, projects: frozenset[str],
                out=None) -> Server:
    if not projects:
        raise GateError("no named project")
    return Server((host, port), socket_path=socket_path, projects=projects,
                  out=out if out is not None else sys.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="papaia-docker-gate")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    args = parser.parse_args(argv)
    try:
        projects = load_projects(os.environ.get("DOCKER_GATE_PROJECTS", ""))
        server = make_server(args.listen, args.port, socket_path=args.socket, projects=projects)
    except (GateError, OSError) as exc:
        _log(f"cannot start: {exc}")
        return 2
    _log(f"listening on {args.listen}:{args.port} for projects {', '.join(sorted(projects))}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
