"""papaia-audit: ingest over mutual TLS, chain verification and signed chain heads.

    python -I -m papaia_audit schema
    python -I -m papaia_audit serve
    python -I -m papaia_audit verify [--source NAME] [--against FILE|-] [--json]
    python -I -m papaia_audit heads

`serve` accepts `POST /v1/ingest` on port 8443. The source of a request is the client
certificate: it must chain to the ingest CA and its fingerprint must be listed for that
source in sources.json (re-read when it changes); everything else is refused. Events are
stored through `audit.append` with the role `audit_ingest`, which may do nothing else.

`schema` runs once before the service, as the database owner: it creates the store
(schema.sql next to this file) in one transaction when it does not exist yet, and sets
the passwords of `audit_ingest` and `audit_read` from their secrets on every run, so a
replaced password takes effect. The service itself never holds the owner's password.

`verify` and `heads` read with the role `audit_read`. `heads` prints one line that signs
the last `seq` and hash of every source with the service's Ed25519 key; `verify
--against` checks the chains against such lines, which detects a rewrite by someone who
holds the database owner's rights, as long as the lines are kept outside the host.

Logs carry reason codes, sources and counts only, never an event.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import signal
import ssl
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from psycopg import sql

from papaia_audit import core

CONFIG_DIR = Path(os.environ.get("PAPAIA_AUDIT_CONFIG_DIR", "/etc/papaia-audit"))
SECRETS_DIR = Path(os.environ.get("PAPAIA_AUDIT_SECRETS_DIR", "/run/secrets"))
DB_HOST = os.environ.get("PAPAIA_AUDIT_DB_HOST", "papaia-audit-db")
DB_NAME = "audit"
PORT = 8443
HANDSHAKE_TIMEOUT_SECONDS = 10
REQUEST_TIMEOUT_SECONDS = 30
CONTENT_TYPE = "application/x-ndjson"
SCHEMA_SQL = Path(__file__).with_name("schema.sql")
SERVICE_ROLES = ("ingest", "read")


def log(message: str) -> None:
    print(f"papaia-audit: {message}", file=sys.stderr, flush=True)


def _password(role: str) -> str:
    return (SECRETS_DIR / f"audit_db_{role}_password").read_text(encoding="utf-8").strip()


def connect(role: str, **kwargs: Any) -> psycopg.Connection:
    password = _password(role)
    return psycopg.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=f"audit_{role}",
        password=password,
        connect_timeout=5,
        application_name=f"papaia-audit-{role}",
        **kwargs,
    )


class PgStore:
    def __init__(self, conn: psycopg.Connection) -> None:
        self.conn = conn

    def append(self, source: str, canonical: str) -> int:
        try:
            with self.conn.transaction():
                row = self.conn.execute(
                    "SELECT audit.append(%s, %s)", (source, canonical)
                ).fetchone()
        except psycopg.Error as error:
            if error.sqlstate == "PA001":
                raise core.Refused(core.GAP) from None
            log(f"store failed ({type(error).__name__})")
            raise core.Refused(core.STORAGE, 503) from None
        assert row is not None
        return int(row[0])


class Sources:
    """sources.json, re-read whenever its modification time or size changes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stamp: tuple[int, int] | None = None
        self._by_fingerprint: dict[str, str] = {}
        self._lock = threading.Lock()

    def source_of(self, certificate: bytes) -> str | None:
        with self._lock:
            try:
                stat = self.path.stat()
                stamp = (stat.st_mtime_ns, stat.st_size)
                if stamp != self._stamp:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    self._by_fingerprint = core.parse_sources(data)
                    self._stamp = stamp
            except (OSError, ValueError) as error:
                # Without a readable list no source is known; nothing is stored.
                log(f"sources.json not usable ({type(error).__name__}); refusing all sources")
                self._by_fingerprint, self._stamp = {}, None
            fingerprint = "sha256:" + hashlib.sha256(certificate).hexdigest()
            return self._by_fingerprint.get(fingerprint)


class IngestServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext, sources: Sources) -> None:
        super().__init__(("", PORT), IngestHandler)
        self.socket = context.wrap_socket(
            self.socket, server_side=True, do_handshake_on_connect=False
        )
        self.sources = sources
        self.check = core.SubmissionCheck()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A failed handshake (no or a foreign client certificate) or a dropped connection;
        # one line, no traceback.
        log(f"connection refused ({type(sys.exc_info()[1]).__name__})")


class IngestHandler(http.server.BaseHTTPRequestHandler):
    server: IngestServer
    server_version = "papaia-audit"
    sys_version = ""
    timeout = REQUEST_TIMEOUT_SECONDS

    def setup(self) -> None:
        # The handshake runs here, in the request's own thread, so a slow client cannot
        # hold up the accept loop.
        self.request.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        self.request.do_handshake()
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _reply(self, status: int, document: dict[str, Any]) -> None:
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, status: int, code: str, source: str = "-") -> None:
        log(f"refused source={source} error_code={code}")
        self._reply(status, {"error_code": code})

    def _source(self) -> str | None:
        certificate = self.request.getpeercert(binary_form=True)
        if not certificate:
            return None
        source = self.server.sources.source_of(certificate)
        subject = dict(item[0] for item in self.request.getpeercert().get("subject", ()))
        return source if source and subject.get("commonName") == source else None

    def do_POST(self) -> None:  # noqa: N802
        source = self._source()
        if source is None:
            return self._refuse(403, core.UNKNOWN_SOURCE)
        if self.path != "/v1/ingest":
            return self._refuse(404, core.INVALID_REQUEST, source)
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != CONTENT_TYPE:
            return self._refuse(415, core.INVALID_REQUEST, source)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._refuse(411, core.INVALID_REQUEST, source)
        if not 0 < length <= core.MAX_BODY_BYTES:
            return self._refuse(413, core.INVALID_REQUEST, source)
        body = self.rfile.read(length)
        try:
            lines = core.split_batch(body if len(body) == length else b"")
        except core.Refused as refused:
            return self._refuse(refused.status, refused.code, source)
        try:
            with connect("ingest", autocommit=True) as conn:
                result = core.ingest(PgStore(conn), self.server.check, source, lines)
        except psycopg.Error as error:
            log(f"database unreachable ({type(error).__name__})")
            return self._refuse(503, core.STORAGE, source)
        refused = result.refused
        if refused is not None and not result.acknowledged:
            return self._refuse(refused.status, refused.code, source)
        note = f" stopped error_code={refused.code}" if refused else ""
        log(f"stored source={source} lines={len(result.acknowledged)}{note}")
        self._reply(200, {"acknowledged": result.acknowledged})

    def _not_allowed(self) -> None:
        self._refuse(405, core.INVALID_REQUEST)

    do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_allowed  # noqa: N815


def serve() -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(CONFIG_DIR / "server.crt", CONFIG_DIR / "server.key")
    context.load_verify_locations(cafile=str(CONFIG_DIR / "ca.crt"))
    server = IngestServer(context, Sources(CONFIG_DIR / "sources.json"))
    # PID 1 in the container: without a handler SIGTERM would be ignored.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log(f"ingest listening on :{PORT}")
    server.serve_forever()
    return 0


# ─────────────────────────────────────────────────────────────────────────
# schema
# ─────────────────────────────────────────────────────────────────────────


def schema() -> int:
    passwords = {role: _password(role) for role in SERVICE_ROLES}
    if not all(passwords.values()):
        raise SystemExit("papaia-audit: a service role password is empty")
    with connect("owner") as conn, conn.transaction():
        # Two runs at once (a restart during the first start) must not both create it.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('papaia-audit schema'))")
        exists = conn.execute("SELECT to_regclass('audit.event') IS NOT NULL").fetchone()
        if not (exists and exists[0]):
            conn.execute(SCHEMA_SQL.read_text(encoding="utf-8"))
            log("store created")
        for role, password in passwords.items():
            # ALTER ROLE takes no parameters; the literal is quoted by the driver and the
            # statement is never logged.
            conn.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(f"audit_{role}"), sql.Literal(password)
                )
            )
    log("service role passwords set")
    return 0


# ─────────────────────────────────────────────────────────────────────────
# verify and heads
# ─────────────────────────────────────────────────────────────────────────


def _heads_key() -> Ed25519PrivateKey:
    key = load_pem_private_key((SECRETS_DIR / "audit_heads_key").read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("papaia-audit: the heads key is not an Ed25519 key")
    return key


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rows(conn: psycopg.Connection, source: str) -> Any:
    with conn.cursor(name=f"verify-{source}") as cursor:
        cursor.itersize = 2000
        cursor.execute(
            "SELECT seq, prev_hash, hash, source_seq, time, sub, event, correlation_id,"
            " catalog_id, result, body FROM audit.event WHERE source = %s ORDER BY seq",
            (source,),
        )
        for seq, prev, digest, source_seq, time, *rest, body in cursor:
            values = (source_seq, _time_text(time), *rest)
            columns = dict(zip(core.DERIVED_COLUMNS, values, strict=True))
            yield core.StoredRow(seq, bytes(prev), bytes(digest), columns, body)


def _read_heads(name: str) -> list[dict[str, Any]]:
    text = sys.stdin.read() if name == "-" else Path(name).read_text(encoding="utf-8")
    public = _heads_key().public_key()
    heads: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            document, signature = core.parse_heads_line(line)
            public.verify(signature, core.heads_payload(document))
        except (ValueError, InvalidSignature):
            raise SystemExit(
                f"papaia-audit: heads line {number} is not signed by this installation"
            ) from None
        heads.extend(document["heads"])
    return heads


def verify(source: str | None, against: str | None, as_json: bool) -> int:
    if source is not None and not core.SOURCE_RE.match(source):
        raise SystemExit("papaia-audit: --source must be a source name")
    heads = _read_heads(against) if against else []
    with connect("read") as conn:
        conn.read_only = True
        names = (
            [source]
            if source
            else [
                row[0] for row in conn.execute("SELECT DISTINCT source FROM audit.event ORDER BY 1")
            ]
        )
        names = sorted(set(names) | {h["source"] for h in heads if not source})
        reports = {}
        for name in names:
            wanted = [h["seq"] for h in heads if h["source"] == name]
            reports[name] = core.verify_chain(name, _rows(conn, name), wanted)
    core.check_heads(reports, heads)
    if as_json:
        print(json.dumps({"sources": [r.as_dict() for r in reports.values()]}))
    for report in reports.values():
        if as_json:
            continue
        if report.valid:
            print(f"{report.source}: valid ({report.count} events, head seq {report.head_seq})")
        else:
            print(f"{report.source}: broken at seq {report.broken_at} ({report.reason})")
    return 0 if all(r.valid for r in reports.values()) else 1


def heads() -> int:
    key = _heads_key()
    with connect("read") as conn:
        conn.read_only = True
        rows = conn.execute(
            "SELECT DISTINCT ON (source) source, seq, hash FROM audit.event"
            " ORDER BY source, seq DESC"
        ).fetchall()
    document = core.heads_document(
        [(source, seq, bytes(digest)) for source, seq, digest in rows],
        _time_text(datetime.now(timezone.utc)),
    )
    signature = key.sign(core.heads_payload(document))
    document["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    print(json.dumps(document, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="papaia-audit")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema")
    commands.add_parser("serve")
    p_verify = commands.add_parser("verify")
    p_verify.add_argument("--source")
    p_verify.add_argument("--against", help="file of signed heads, or - for stdin")
    p_verify.add_argument("--json", action="store_true")
    commands.add_parser("heads")
    args = parser.parse_args(argv)
    if args.command == "serve":
        return serve()
    try:
        if args.command == "schema":
            return schema()
        if args.command == "verify":
            return verify(args.source, args.against, args.json)
        return heads()
    except psycopg.Error as error:
        raise SystemExit(f"papaia-audit: database not reachable ({type(error).__name__})") from None


if __name__ == "__main__":
    sys.exit(main())
