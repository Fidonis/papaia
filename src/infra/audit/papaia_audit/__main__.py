"""papaia-audit: ingest and the read API over mutual TLS, chain verification and signed
chain heads.

    python -I -m papaia_audit schema
    python -I -m papaia_audit serve
    python -I -m papaia_audit verify [--source NAME] [--against FILE|-] [--json]
    python -I -m papaia_audit heads
    python -I -m papaia_audit retention
    python -I -m papaia_audit access < request.json
    python -I -m papaia_audit siem-status
    python -I -m papaia_audit siem-skip      (request as JSON on stdin)
    python -I -m papaia_audit idmap          (token and request as JSON on stdin)

`serve` accepts `POST /v1/ingest` on port 8443. The source of a request is the client
certificate: it must chain to the ingest CA and its fingerprint must be listed for that
source in sources.json (re-read when it changes); everything else is refused. Events are
stored through `audit.append` with the role `audit_ingest`, which may do nothing else.
The same listener serves the read API (read.py) to the reading clients, with a person's
bearer token checked against token-keys.json (re-read when it changes).

`schema` runs once before the service, as the database owner: it creates the store
(schema.sql next to this file) in one transaction when it does not exist yet, and sets
the passwords of the service roles (`audit_ingest`, `audit_read`, `audit_retention`,
`audit_hold`) from their secrets on every run, so a replaced password takes effect. The
service itself never holds the owner's password.

`serve` also runs the store's upkeep in one background thread: every full hour it signs
the chain heads into the heads folder at the backup target and verifies every chain;
daily at 03:30 UTC it runs retention (retention.py, role `audit_retention`); every few
seconds it sends new events to the SIEM target, if one is set (siem.py); every minute it
checks how far behind each target is and mails the operations address once a target
takes no events for more than 10 minutes (watch.py). Each duty fails
on its own (retention.Schedule): an unreachable SIEM target stops no heads, verification
or retention. Settings are
read from the environment at start; a malformed one stops the service. A changed setting
is recorded as a `config_changed` event.

`verify` and `heads` read with the role `audit_read`. `heads` prints one line that signs
the last `seq` and hash of every source with the service's Ed25519 key; `verify
--against` checks the chains against such lines, which detects a rewrite by someone who
holds the database owner's rights, as long as the lines are kept outside the host.

Logs carry reason codes, sources and counts only, never an event.
"""

from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import http.server
import json
import os
import signal
import ssl
import sys
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from psycopg import sql

from papaia_audit import access, core, idp, read, retention, siem, watch
from papaia_audit import report as permission_report

CONFIG_DIR = Path(os.environ.get("PAPAIA_AUDIT_CONFIG_DIR", "/etc/papaia-audit"))
SECRETS_DIR = Path(os.environ.get("PAPAIA_AUDIT_SECRETS_DIR", "/run/secrets"))
DB_HOST = os.environ.get("PAPAIA_AUDIT_DB_HOST", "papaia-audit-db")
DB_NAME = "audit"
PORT = 8443
HANDSHAKE_TIMEOUT_SECONDS = 10
REQUEST_TIMEOUT_SECONDS = 30
CONTENT_TYPE = "application/x-ndjson"
SCHEMA_SQL = Path(__file__).with_name("schema.sql")
SCHEMA_READ_SQL = Path(__file__).with_name("schema_read.sql")
SCHEMA_RETENTION_SQL = Path(__file__).with_name("schema_retention.sql")
SCHEMA_ACCESS_SQL = Path(__file__).with_name("schema_access.sql")
SCHEMA_SIEM_SQL = Path(__file__).with_name("schema_siem.sql")
SERVICE_ROLES = ("ingest", "read", "retention", "hold")
HEADS_DIR = Path(os.environ.get("PAPAIA_AUDIT_HEADS_DIR", "/var/lib/papaia-audit/heads"))
EXPORT_INTERVAL_SECONDS = 5
CONFIG_WRITER = "papaia-audit/config"


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


class TokenKeysFile:
    """token-keys.json, re-read whenever its modification time or size changes; None while
    it is missing or malformed, and then no token is accepted."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stamp: tuple[int, int] | None = None
        self._keys: read.TokenKeys | None = None
        self._lock = threading.Lock()

    def __call__(self) -> read.TokenKeys | None:
        with self._lock:
            try:
                stat = self.path.stat()
                stamp = (stat.st_mtime_ns, stat.st_size)
                if stamp != self._stamp:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    self._keys, self._stamp = read.TokenKeys.parse(data), stamp
            except (OSError, ValueError) as error:
                if self._stamp is not None or self._keys is not None:
                    log(f"token-keys.json not usable ({type(error).__name__}); refusing all tokens")
                self._keys, self._stamp = None, None
            return self._keys


def _query_row(row: tuple[Any, ...]) -> read.PersonQuery:
    query_id, requested_by, person_sub, start, end, reason, at, state, by, decided = row
    return read.PersonQuery(
        str(query_id), requested_by, person_sub, start, end, reason, at, state, by, decided
    )


_QUERY_COLUMNS = (
    "id, requested_by, person_sub, period_from, period_to, reason, requested_at, state,"
    " decided_by, decided_at"
)
_HOLD_COLUMNS = (
    "id, action, sub, reason, requested_by, requested_at, state, decided_by, decided_at"
)


def _hold_row(row: tuple[Any, ...]) -> access.HoldRequest:
    request_id, *rest = row
    return access.HoldRequest(str(request_id), *rest)


_SEARCH_COLUMNS = {
    "source": "source",
    "event": "event",
    "catalog_id": "catalog_id",
    "result": "result",
    "correlation_id": "correlation_id",
    "person_sub": "sub",
}


def _guarded(method: Any) -> Any:
    """A database error becomes read.StoreError (503); its text never leaves the service."""

    @functools.wraps(method)
    def call(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except psycopg.Error as error:
            log(f"read store failed ({type(error).__name__})")
            raise read.StoreError from None

    return call


class PgReadStore:
    """The read API's store: reads as audit_read, writes as audit_ingest (functions only);
    the deletion lock as audit_hold. A connection per call: requests are few, and no
    session outlives its request."""

    @_guarded
    def subjects(self) -> list[str]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT DISTINCT sub FROM audit.event WHERE sub IS NOT NULL"
            ).fetchall()
        return [row[0] for row in rows]

    @_guarded
    def search(self, search: read.Search, limit: int) -> list[read.Row]:
        where: list[sql.Composable] = []
        params: list[Any] = []
        for attribute, column in _SEARCH_COLUMNS.items():
            value = getattr(search, attribute)
            if value is not None:
                where.append(sql.SQL("{} = %s").format(sql.Identifier(column)))
                params.append(value)
        if search.start is not None:
            where.append(sql.SQL("time >= %s"))
            params.append(search.start)
        if search.end is not None:
            where.append(sql.SQL("time < %s"))
            params.append(search.end)
        if search.after is not None:
            where.append(sql.SQL("(time, source, seq) > (%s, %s, %s)"))
            params.extend(search.after)
        statement = sql.SQL(
            "SELECT source, seq, prev_hash, hash, time, body FROM audit.event{} "
            "ORDER BY time, source, seq LIMIT %s"
        ).format(sql.SQL(" WHERE ") + sql.SQL(" AND ").join(where) if where else sql.SQL(""))
        with connect("read") as conn:
            rows = conn.execute(statement, (*params, limit)).fetchall()
        return [
            read.Row(source, seq, bytes(prev), bytes(digest), moment, body)
            for source, seq, prev, digest, moment, body in rows
        ]

    @staticmethod
    def _append_on(conn: psycopg.Connection, build: Any) -> int:
        """Append the own event `build(next source_seq)` on `conn`, inside its open
        transaction, so it commits or rolls back together with the caller's change."""
        row = conn.execute("SELECT audit.next_source_seq(%s)", (read.OWN_SOURCE,)).fetchone()
        assert row is not None
        return PgStore(conn).append(read.OWN_SOURCE, build(int(row[0])))

    @_guarded
    def add_query(self, query: read.PersonQuery, build: Any) -> None:
        with connect("ingest") as conn, conn.transaction():
            conn.execute(
                "SELECT audit.person_query_add(%s, %s, %s, %s, %s, %s, %s)",
                (
                    query.id,
                    query.requested_by,
                    query.person_sub,
                    query.start,
                    query.end,
                    query.reason,
                    query.requested_at,
                ),
            )
            self._append_on(conn, build)

    @_guarded
    def get_query(self, query_id: str) -> read.PersonQuery | None:
        with connect("read") as conn:
            row = conn.execute(
                f"SELECT {_QUERY_COLUMNS} FROM audit.person_query WHERE id = %s", (query_id,)
            ).fetchone()
        return _query_row(row) if row else None

    @_guarded
    def open_queries(self, since: datetime) -> list[read.PersonQuery]:
        with connect("read") as conn:
            rows = conn.execute(
                f"SELECT {_QUERY_COLUMNS} FROM audit.person_query"
                " WHERE state = 'open' AND requested_at > %s ORDER BY requested_at LIMIT 500",
                (since,),
            ).fetchall()
        return [_query_row(row) for row in rows]

    @_guarded
    def decide_query(
        self, query_id: str, state: str, decided_by: str, at: datetime, build: Any
    ) -> bool:
        with connect("ingest") as conn, conn.transaction():
            row = conn.execute(
                "SELECT audit.person_query_decide(%s, %s, %s, %s)",
                (query_id, state, decided_by, at),
            ).fetchone()
            if not (row and row[0]):
                return False
            self._append_on(conn, build)
        return True

    def append_own(self, build: Any) -> int:
        try:
            with connect("ingest") as conn, conn.transaction():
                return self._append_on(conn, build)
        except psycopg.Error as error:
            log(f"own event not stored ({type(error).__name__})")
            raise core.Refused(core.STORAGE, 503) from None

    # -- permission report and deletion lock (access.py) -----------------

    @_guarded
    def confirmations_latest(self) -> list[access.Confirmation]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT DISTINCT ON (key) key, digest, confirmed_by, confirmed_at"
                " FROM audit.access_confirmation ORDER BY key, confirmed_at DESC"
            ).fetchall()
        return [access.Confirmation(*row) for row in rows]

    @_guarded
    def add_confirmation(self, confirmation: access.Confirmation, build: Any) -> None:
        with connect("ingest") as conn, conn.transaction():
            conn.execute(
                "SELECT audit.access_confirmation_add(%s, %s, %s, %s)",
                (
                    confirmation.key,
                    confirmation.digest,
                    confirmation.confirmed_by,
                    confirmation.confirmed_at,
                ),
            )
            self._append_on(conn, build)

    @_guarded
    def hold_active(self, sub: str) -> bool:
        with connect("read") as conn:
            row = conn.execute(
                "SELECT EXISTS (SELECT 1 FROM audit.legal_hold"
                " WHERE sub = %s AND lifted_at IS NULL)",
                (sub,),
            ).fetchone()
        return bool(row and row[0])

    @_guarded
    def active_holds(self) -> list[tuple[str, datetime]]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT sub, set_at FROM audit.legal_hold WHERE lifted_at IS NULL"
                " ORDER BY sub LIMIT 1000"
            ).fetchall()
        return [(row[0], row[1]) for row in rows]

    @staticmethod
    def _append_hold_on(conn: psycopg.Connection, build: Any) -> int:
        """Append an event of the deletion lock on `conn`, in its open transaction; the
        role audit_hold may append these events only (audit.append_hold)."""
        row = conn.execute("SELECT audit.next_source_seq(%s)", (read.OWN_SOURCE,)).fetchone()
        assert row is not None
        stored = conn.execute("SELECT audit.append_hold(%s)", (build(int(row[0])),)).fetchone()
        assert stored is not None
        return int(stored[0])

    @_guarded
    def add_hold_request(self, request: access.HoldRequest, build: Any) -> None:
        with connect("hold") as conn, conn.transaction():
            conn.execute(
                "SELECT audit.legal_hold_request_add(%s, %s, %s, %s, %s, %s)",
                (
                    request.id,
                    request.action,
                    request.sub,
                    request.reason,
                    request.requested_by,
                    request.requested_at,
                ),
            )
            self._append_hold_on(conn, build)

    @_guarded
    def get_hold_request(self, request_id: str) -> access.HoldRequest | None:
        with connect("read") as conn:
            row = conn.execute(
                f"SELECT {_HOLD_COLUMNS} FROM audit.legal_hold_request WHERE id = %s",
                (request_id,),
            ).fetchone()
        return _hold_row(row) if row else None

    @_guarded
    def open_hold_requests(self, since: datetime) -> list[access.HoldRequest]:
        with connect("read") as conn:
            rows = conn.execute(
                f"SELECT {_HOLD_COLUMNS} FROM audit.legal_hold_request"
                " WHERE state = 'open' AND requested_at > %s ORDER BY requested_at LIMIT 500",
                (since,),
            ).fetchall()
        return [_hold_row(row) for row in rows]

    @_guarded
    def decide_hold_request(
        self, request_id: str, state: str, by: str, at: datetime, build: Any
    ) -> bool:
        with connect("hold") as conn, conn.transaction():
            if state == "confirmed":
                # The database sets or lifts the lock and appends its event in one step.
                seq = conn.execute(
                    "SELECT audit.next_source_seq(%s)", (read.OWN_SOURCE,)
                ).fetchone()
                assert seq is not None
                row = conn.execute(
                    "SELECT audit.legal_hold_confirm(%s, %s, %s, %s)",
                    (request_id, by, at, build(int(seq[0]))),
                ).fetchone()
                return bool(row and row[0])
            row = conn.execute(
                "SELECT audit.legal_hold_request_reject(%s, %s, %s)", (request_id, by, at)
            ).fetchone()
            if not (row and row[0]):
                return False
            self._append_hold_on(conn, build)
        return True

    @_guarded
    def identity(self, sub: str) -> read.PersonIdentity | None:
        with connect("read") as conn:
            row = conn.execute(
                "SELECT sub, username, tid, oid FROM audit.person_identity WHERE sub = %s",
                (sub,),
            ).fetchone()
        return read.PersonIdentity(*row) if row else None

    @_guarded
    def sub_by_upstream(self, tid: str, oid: str) -> str | None:
        with connect("read") as conn:
            row = conn.execute(
                "SELECT sub FROM audit.person_identity WHERE tid = %s AND oid = %s", (tid, oid)
            ).fetchone()
        return row[0] if row else None

    @_guarded
    def put_identities(self, identities: list[read.PersonIdentity], build: Any) -> int:
        with connect("ingest") as conn, conn.transaction():
            for entry in identities:
                conn.execute(
                    "SELECT audit.identity_put(%s, %s, %s, %s)",
                    (entry.sub, entry.username, entry.tid, entry.oid),
                )
            self._append_on(conn, build)
        return len(identities)

    @_guarded
    def reads_about(self, sub: str, limit: int) -> list[tuple[datetime, read.PersonQuery]]:
        columns = ", ".join(f"q.{name.strip()}" for name in _QUERY_COLUMNS.split(","))
        with connect("read") as conn:
            rows = conn.execute(
                f"SELECT e.time, {columns} FROM audit.event e JOIN audit.person_query q"
                " ON q.id::text = e.body -> 'object_ref' ->> 'id'"
                " WHERE e.source = %s"
                " AND e.event IN ('audit_read', 'audit_exported', 'pseudonym_resolved')"
                " AND e.result = 'allowed' AND q.person_sub = %s"
                " ORDER BY e.time DESC LIMIT %s",
                (read.OWN_SOURCE, sub, limit),
            ).fetchall()
        return [(row[0], _query_row(row[1:])) for row in rows]


class IngestServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext, sources: Sources, api: read.ReadApi) -> None:
        super().__init__(("", PORT), IngestHandler)
        self.socket = context.wrap_socket(
            self.socket, server_side=True, do_handshake_on_connect=False
        )
        self.sources = sources
        self.check = core.SubmissionCheck()
        self.api = api

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

    def _read(self, source: str) -> None:
        path, _, query = self.path.partition("?")
        body = None
        if self.command == "POST":
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                length = -1
            limit = read.MAX_IDENTITY_BODY if path == read.IDENTITIES_PATH else read.MAX_JSON_BODY
            if content_type == "application/json" and 0 <= length <= limit:
                body = self.rfile.read(length)
        response = self.server.api.handle(
            read.Request(
                self.command,
                path,
                query,
                source,
                self.headers.get("Authorization"),
                self.headers.get("X-Papaia-Correlation-Id"),
                body,
            )
        )
        # Status, route and caller only: never a token, filter value, reason or row.
        log(
            f"read source={source} route={path if response.status != 404 else '-'}"
            f" status={response.status} correlation_id={response.correlation_id}"
        )
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("X-Papaia-Correlation-Id", response.correlation_id)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self) -> None:  # noqa: N802
        source = self._source()
        if source is None:
            return self._refuse(403, core.UNKNOWN_SOURCE)
        self._read(source)

    def do_POST(self) -> None:  # noqa: N802
        source = self._source()
        if source is None:
            return self._refuse(403, core.UNKNOWN_SOURCE)
        if self.path != "/v1/ingest":
            return self._read(source)
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

    do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_allowed  # noqa: N815


def report_source() -> tuple[permission_report.Inputs, permission_report.Call]:
    """The inputs file (re-read on every build) and the realm's Admin API as the report
    account (access.ReportSource)."""
    inputs = permission_report.load_inputs(CONFIG_DIR / permission_report.INPUTS_FILE)
    try:
        reader = idp.from_environment()
    except (OSError, ValueError, ssl.SSLError) as error:
        raise permission_report.SourceError(
            f"Keycloak connection not usable ({type(error).__name__})"
        ) from None
    return inputs, reader


def serve() -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(CONFIG_DIR / "server.crt", CONFIG_DIR / "server.key")
    context.load_verify_locations(cafile=str(CONFIG_DIR / "ca.crt"))
    settings = ServiceSettings(os.environ)
    check = core.SubmissionCheck()
    api = access.AccessApi(
        PgReadStore(),
        TokenKeysFile(CONFIG_DIR / "token-keys.json"),
        _pseudonym_key(),
        check,
        report_source=report_source,
    )
    server = IngestServer(context, Sources(CONFIG_DIR / "sources.json"), api)
    Upkeep(settings).start()
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
        queries = conn.execute("SELECT to_regclass('audit.person_query') IS NOT NULL").fetchone()
        if not (queries and queries[0]):
            conn.execute(SCHEMA_READ_SQL.read_text(encoding="utf-8"))
            log("person queries added to the store")
        upkeep = conn.execute("SELECT to_regclass('audit.anchor') IS NOT NULL").fetchone()
        if not (upkeep and upkeep[0]):
            # A new store, or one of a release without retention: added in place.
            conn.execute(SCHEMA_RETENTION_SQL.read_text(encoding="utf-8"))
            log("retention, deletion lock and export positions added")
        holds = conn.execute(
            "SELECT to_regclass('audit.legal_hold_request') IS NOT NULL"
        ).fetchone()
        if not (holds and holds[0]):
            conn.execute(SCHEMA_ACCESS_SQL.read_text(encoding="utf-8"))
            log("permission report confirmations and two-person deletion lock added")
        identities = conn.execute(
            "SELECT to_regclass('audit.person_identity') IS NOT NULL"
        ).fetchone()
        if not (identities and identities[0]):
            conn.execute(SCHEMA_SIEM_SQL.read_text(encoding="utf-8"))
            log("identity map, delivery state and skips added")
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


def _anchors(conn: psycopg.Connection) -> dict[str, tuple[int, bytes]]:
    rows = conn.execute("SELECT source, seq, hash FROM audit.anchor").fetchall()
    return {source: (seq, bytes(digest)) for source, seq, digest in rows}


def _attested(conn: psycopg.Connection, report: core.ChainReport | None) -> set[str]:
    """Anchor ids named by retention_run events of papaia-audit, up to where its own
    chain verified."""
    if report is None:
        return set()
    upto = report.head_seq if report.valid else (report.broken_at or 1) - 1
    rows = conn.execute(
        "SELECT body -> 'object_ref' ->> 'id' FROM audit.event WHERE source = %s"
        " AND event = 'retention_run' AND seq <= %s AND body -> 'object_ref' ->> 'type' = %s",
        (retention.OWN_SOURCE, upto, retention.ANCHOR_REF),
    ).fetchall()
    return {row[0] for row in rows if isinstance(row[0], str)}


def verify_all(
    conn: psycopg.Connection, source: str | None, heads: list[dict[str, Any]]
) -> dict[str, core.ChainReport]:
    anchors = _anchors(conn)
    names = (
        [source]
        if source
        else [row[0] for row in conn.execute("SELECT DISTINCT source FROM audit.event")]
    )
    found = set(names)
    if not source:
        found |= {h["source"] for h in heads} | set(anchors)
    reports = {}
    for name in sorted(found):
        wanted = [h["seq"] for h in heads if h["source"] == name]
        reports[name] = core.verify_chain(name, _rows(conn, name), wanted, anchors.get(name))
    own = reports.get(retention.OWN_SOURCE)
    if own is None:
        # Checking one source still needs the retention runs that attest its anchor.
        own = core.verify_chain(
            retention.OWN_SOURCE, _rows(conn, retention.OWN_SOURCE), (),
            anchors.get(retention.OWN_SOURCE),
        )
    core.check_anchors(reports, anchors, _attested(conn, own))
    core.check_heads(reports, heads)
    return reports


def verify(source: str | None, against: str | None, as_json: bool) -> int:
    if source is not None and not core.SOURCE_RE.match(source):
        raise SystemExit("papaia-audit: --source must be a source name")
    heads = _read_heads(against) if against else []
    if source:
        heads = [h for h in heads if h["source"] == source]
    with connect("read") as conn:
        conn.read_only = True
        reports = verify_all(conn, source, heads)
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


def signed_heads(key: Ed25519PrivateKey) -> dict[str, Any]:
    """The signed document of every source's last event (the anchor where none is left)."""
    with connect("read") as conn:
        conn.read_only = True
        rows = conn.execute(
            "SELECT DISTINCT ON (source) source, seq, hash FROM audit.event"
            " ORDER BY source, seq DESC"
        ).fetchall()
        last = {source: (seq, bytes(digest)) for source, seq, digest in rows}
        for source, anchor in _anchors(conn).items():
            last.setdefault(source, anchor)
    document = core.heads_document(
        [(source, seq, digest) for source, (seq, digest) in last.items()],
        _time_text(datetime.now(timezone.utc)),
    )
    signature = key.sign(core.heads_payload(document))
    document["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return document


def heads() -> int:
    print(json.dumps(signed_heads(_heads_key()), separators=(",", ":")))
    return 0


# ─────────────────────────────────────────────────────────────────────────
# retention, settings and SIEM export
# ─────────────────────────────────────────────────────────────────────────


class PgRetentionStore:
    """Facts through `audit_read`, removal through `audit_retention` (audit.prune)."""

    def sources(self) -> list[str]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT source FROM audit.event GROUP BY source"
                " UNION SELECT source FROM audit.anchor"
            ).fetchall()
        return [row[0] for row in rows]

    def facts(self, source: str, before: datetime) -> retention.Facts:
        with connect("read") as conn:
            row = conn.execute(
                """
                SELECT
                  coalesce((SELECT min(seq) FROM audit.event WHERE source = %(s)s
                            AND time >= %(t)s),
                           (SELECT coalesce(max(seq), 0) + 1 FROM audit.event
                            WHERE source = %(s)s)) - 1,
                  coalesce((SELECT seq FROM audit.anchor WHERE source = %(s)s), 0),
                  (SELECT min(e.seq) FROM audit.event e JOIN audit.legal_hold h
                     ON h.sub = e.sub AND h.lifted_at IS NULL WHERE e.source = %(s)s),
                  (SELECT min(coalesce(c.seq, 0)) FROM audit.export_target t
                     LEFT JOIN audit.export_cursor c ON c.target = t.target
                     AND c.source = %(s)s)
                """,
                {"s": source, "t": before},
            ).fetchone()
        assert row is not None
        return retention.Facts(int(row[0]), int(row[1]), row[2], row[3])

    def prune(self, source: str, upto: int, months: int,
              build: Any) -> retention.Pruned:
        with connect("retention") as conn, conn.transaction():
            try:
                row = conn.execute(
                    "SELECT removed, anchor_seq, anchor_hash FROM audit.prune(%s, %s, %s)",
                    (source, upto, months),
                ).fetchone()
            except psycopg.Error as error:
                if error.sqlstate == "PA002":
                    log(f"retention source={source} refused by the store")
                    raise retention.PruneRefused(source) from None
                raise
            assert row is not None
            result = retention.Pruned(
                int(row[0]), int(row[1] or 0), bytes(row[2]) if row[2] is not None else None
            )
            seq_row = conn.execute(
                "SELECT audit.next_seq(%s)", (retention.OWN_SOURCE,)
            ).fetchone()
            assert seq_row is not None
            conn.execute("SELECT audit.append_own(%s)", (build(result, int(seq_row[0])),))
        return result


class PgExportStore:
    """Events and read positions through `audit_read`; positions move through
    `audit_ingest` (audit.export_advance)."""

    def sources(self) -> list[str]:
        with connect("read") as conn:
            rows = conn.execute("SELECT DISTINCT source FROM audit.event ORDER BY 1").fetchall()
        return [row[0] for row in rows]

    def position(self, target: str, source: str) -> int:
        with connect("read") as conn:
            row = conn.execute(
                "SELECT seq FROM audit.export_cursor WHERE target = %s AND source = %s",
                (target, source),
            ).fetchone()
        return int(row[0]) if row else 0

    def rows_after(self, source: str, seq: int, limit: int) -> list[siem.Row]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT seq, prev_hash, hash, body FROM audit.event WHERE source = %s"
                " AND seq > %s ORDER BY seq LIMIT %s",
                (source, seq, limit),
            ).fetchall()
        return [siem.Row(source, s, bytes(p), bytes(h), b) for s, p, h, b in rows]

    def advance(self, target: str, source: str, seq: int) -> None:
        with connect("ingest", autocommit=True) as conn:
            conn.execute("SELECT audit.export_advance(%s, %s, %s)", (target, source, seq))

    def delivery(self, target: str, ok: bool) -> None:
        with connect("ingest", autocommit=True) as conn:
            conn.execute("SELECT audit.export_delivery(%s, %s)", (target, ok))

    def upstream(self, subs: set[str]) -> dict[str, tuple[str, str]]:
        with connect("read") as conn:
            rows = conn.execute(
                "SELECT sub, tid, oid FROM audit.person_identity"
                " WHERE sub = ANY(%s) AND tid IS NOT NULL",
                (sorted(subs),),
            ).fetchall()
        return {sub: (tid, oid) for sub, tid, oid in rows}


# Every source of a stored event by a skip scan over the primary key (source, seq): one
# index probe per source instead of reading every event.
_SOURCES = """
    WITH RECURSIVE s(source) AS (
        (SELECT e.source FROM audit.event e ORDER BY e.source LIMIT 1)
        UNION ALL
        SELECT (SELECT e.source FROM audit.event e WHERE e.source > s.source
                ORDER BY e.source LIMIT 1)
        FROM s WHERE s.source IS NOT NULL
    )
"""


def export_health() -> list[watch.TargetHealth]:
    """Backlog and delivery state of every SIEM target, active or not (audit_read).

    Per target and source one range scan of the primary key (source, seq) from the read
    position on, so the cost follows the backlog, not the size of the store; the sources
    by a skip scan over the same key."""
    with connect("read") as conn:
        rows = conn.execute(
            _SOURCES + """
            SELECT t.target, t.active, t.delivered_at, t.failing_since,
                   coalesce(sum(b.backlog), 0), min(b.oldest)
            FROM audit.export_target t
            LEFT JOIN s ON s.source IS NOT NULL
            LEFT JOIN audit.export_cursor c ON c.target = t.target AND c.source = s.source
            LEFT JOIN LATERAL (
                SELECT count(*) AS backlog, min(e.time) AS oldest FROM audit.event e
                WHERE e.source = s.source AND e.seq > coalesce(c.seq, 0)
            ) b ON true
            GROUP BY t.target, t.active, t.delivered_at, t.failing_since
            ORDER BY t.target
            """
        ).fetchall()
    return [
        watch.TargetHealth(target, active, int(backlog), oldest, failing, delivered)
        for target, active, delivered, failing, backlog, oldest in rows
    ]


class PgAlertState:
    """The outages already mailed (`audit.alert_state`): read as audit_read, changed as
    audit_retention through its two functions."""

    def raised(self) -> set[str]:
        with connect("read") as conn:
            return {row[0] for row in conn.execute("SELECT key FROM audit.alert_state")}

    def mark(self, key: str) -> None:
        with connect("retention", autocommit=True) as conn:
            conn.execute("SELECT audit.alert_mark(%s)", (key,))

    def clear(self, keys: set[str]) -> None:
        with connect("retention", autocommit=True) as conn:
            conn.execute("SELECT audit.alert_clear(%s)", (sorted(keys),))


def append_siem_event(build: Callable[[int], str]) -> None:
    """One own event of the SIEM writer (the warning mail), role audit_retention."""
    with connect("retention") as conn, conn.transaction():
        seq_row = conn.execute("SELECT audit.next_seq(%s)", (watch.OWN_SOURCE,)).fetchone()
        assert seq_row is not None
        conn.execute("SELECT audit.append_own(%s)", (build(int(seq_row[0])),))


class ServiceSettings:
    """The environment of the service, checked at start."""

    def __init__(self, env: Mapping[str, str]) -> None:
        try:
            self.months = retention.parse_months(env.get("PAPAIA_AUDIT_RETENTION_MONTHS"))
            self.target = siem.parse_target(env.get("PAPAIA_AUDIT_SIEM_TARGET"))
            self.pen = siem.parse_pen(env.get("PAPAIA_AUDIT_SIEM_PEN"))
            self.identity, self.basis = siem.parse_identity(
                env.get("PAPAIA_AUDIT_SIEM_IDENTITY"), env.get("PAPAIA_AUDIT_SIEM_BASIS")
            )
            siem.check_identity_target(self.identity, self.target)
            self.proxy = siem.parse_proxy(env.get("PAPAIA_AUDIT_SIEM_PROXY"))
            self.mail = watch.parse_mail(
                env.get("PAPAIA_AUDIT_MAIL_RELAY"),
                env.get("PAPAIA_AUDIT_ALERT_TO"),
                env.get("PAPAIA_AUDIT_ALERT_FROM"),
            )
        except ValueError as error:
            raise SystemExit(f"papaia-audit: {error}") from None

    def recorded(self) -> dict[str, str]:
        """What the store keeps as `audit.setting`; a change of it is an event."""
        return {
            "audit.retention_months": str(self.months),
            "audit.siem_target": self.target.name if self.target else "",
            "audit.siem_identity": self.identity,
            "audit.siem_basis": self.basis,
        }


def record_settings(settings: ServiceSettings, check: core.SubmissionCheck) -> None:
    """Activate the SIEM target's read positions and record changed settings, each with a
    `config_changed` event in the same transaction."""
    with connect("ingest", autocommit=True) as conn:
        conn.execute(
            "SELECT audit.export_targets_set(%s)",
            ([settings.target.name] if settings.target else [],),
        )
    with connect("read") as conn:
        stored = dict(conn.execute("SELECT key, value FROM audit.setting").fetchall())
    changed = retention.changed_settings(settings.recorded(), stored)
    if not changed:
        return
    correlation_id = "config-" + os.urandom(12).hex()
    with connect("retention") as conn, conn.transaction():
        for key in changed:
            seq_row = conn.execute(
                "SELECT audit.next_seq(%s)", (retention.OWN_SOURCE,)
            ).fetchone()
            assert seq_row is not None
            event = retention.own_event(
                check, event="config_changed", moment=datetime.now(timezone.utc),
                source_seq=int(seq_row[0]), correlation_id=correlation_id,
                writer=CONFIG_WRITER, effect="write",
                object_ref={"type": "setting", "id": key}, operation=None,
            )
            conn.execute("SELECT audit.append_own(%s)", (event,))
            conn.execute("SELECT audit.setting_put(%s, %s)", (key, settings.recorded()[key]))
    log(f"settings recorded changed={','.join(changed)}")


def _pseudonym_key() -> bytes:
    return (SECRETS_DIR / "audit_pseudonym_key").read_bytes().strip()


def _siem_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    extra = CONFIG_DIR / "siem-ca.crt"
    if extra.is_file():
        context.load_verify_locations(cafile=str(extra))
    return context


def make_exporter(settings: ServiceSettings) -> siem.Exporter | None:
    if settings.target is None:
        return None
    sender_type = siem.SyslogSender if settings.target.kind == "syslog" else siem.HttpsSender
    sender = sender_type(settings.target, _siem_context(), settings.proxy)
    return siem.Exporter(
        PgExportStore(), sender,
        siem.Settings(settings.target, settings.pen, settings.identity), _pseudonym_key(),
    )


def store_heads(document: dict[str, Any]) -> Path:
    """Append the signed heads to `<backup target>/audit-heads/YYYY-MM-DD.jsonl`."""
    path = HEADS_DIR / f"{document['signed_at'][:10]}.jsonl"
    line = (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    return path


def run_retention(settings: ServiceSettings, check: core.SubmissionCheck) -> retention.RunReport:
    report = retention.run(
        PgRetentionStore(), check, settings.months, lambda: datetime.now(timezone.utc)
    )
    for current in report.plans:
        held = f" held_back={current.held_back}" if current.held_back else ""
        log(f"retention source={current.source} removed="
            f"{report.removed.get(current.source, 0)}{held}")
    return report


def verify_chains() -> None:
    """Every chain, one log line per source (the hourly check of the service); the result
    is kept in audit.verify_state for `siem-status`."""
    with connect("read") as conn:
        conn.read_only = True
        reports = list(verify_all(conn, None, []).values())
    for report in reports:
        state = "valid" if report.valid else f"broken at seq {report.broken_at}"
        log(f"verify source={report.source} {state}")
    with connect("retention") as conn, conn.transaction():
        for report in reports:
            conn.execute(
                "SELECT audit.verify_record(%s, %s, %s)",
                (report.source, report.valid, None if report.valid else report.broken_at or 1),
            )


class Upkeep(threading.Thread):
    """The schedule of retention.Schedule with the service's duties, every few seconds."""

    def __init__(self, settings: ServiceSettings) -> None:
        super().__init__(name="upkeep", daemon=True)
        self.stop = threading.Event()
        check = core.SubmissionCheck()
        exporter = make_exporter(settings)
        mailer = watch.SmtpMailer(settings.mail) if settings.mail else None
        self.watch = watch.Watch(export_health, mailer, append_siem_event, check, log,
                                 disk=watch.volume_percent, state=PgAlertState())
        duties = retention.Duties(
            # Before anything is removed: a new SIEM target must hold events back.
            record=lambda: record_settings(settings, check),
            export=exporter.run_once if exporter else None,
            sign=lambda: signed_heads(_heads_key()),
            keep=store_heads,
            verify=verify_chains,
            send_heads=exporter.send_heads if exporter else None,
            retain=lambda: run_retention(settings, check),
            # Also without a target: the volume can fill, and an inactive target holds back.
            watch=self.watch.run,
        )
        target = settings.target.name if settings.target else ""
        self.schedule = retention.Schedule(duties, datetime.now(timezone.utc), log, target)

    def run(self) -> None:
        while not self.stop.wait(EXPORT_INTERVAL_SECONDS):
            self.schedule.tick(datetime.now(timezone.utc))


def retention_now() -> int:
    """`retention`: one run now, as the daily one would (operator command)."""
    settings = ServiceSettings(os.environ)
    check = core.SubmissionCheck()
    record_settings(settings, check)
    report = run_retention(settings, check)
    print(json.dumps({"months": settings.months, "removed": report.removed,
                      "held_back": {p.source: p.held_back for p in report.plans if p.held_back}}))
    return 0


def access_call() -> int:
    """`access`: one request of papaia-ctl to the read API through `docker exec`
    (access.host_request). Prints {"status", "content_type", "text"}: the answer's body as
    the route sends it, so papaia-ctl prints the same bytes. The API checks token and role."""
    request = access.host_request(sys.stdin.read(access.HOST_REQUEST_MAX + 1))
    if request is None:
        text = json.dumps({"code": "AUDIT-HOST-400"})
        print(json.dumps({"status": 400, "content_type": "application/json", "text": text}))
        return 0
    api = access.AccessApi(
        PgReadStore(),
        TokenKeysFile(CONFIG_DIR / "token-keys.json"),
        _pseudonym_key(),
        core.SubmissionCheck(),
        report_source=report_source,
    )
    response = api.handle(request)
    log(f"host request route={request.path} status={response.status}")
    print(
        json.dumps(
            {
                "status": response.status,
                "content_type": response.content_type,
                "text": response.body.decode("utf-8"),
            },
            ensure_ascii=False,
        )
    )
    return 0


def siem_status() -> int:
    """`siem-status`: backlog, lag and delivery state per target, the measurements and
    the last hourly verification of every chain with its age, as one JSON line (`doctor
    siem` reads it). It does not walk the chains itself: that takes longer than doctor
    waits on a large store; `verify` does it on demand."""
    now = datetime.now(timezone.utc)
    healths = export_health()
    with connect("read") as conn:
        conn.read_only = True
        # The oldest event of each source is its first by seq: one index probe per source.
        row = conn.execute(
            _SOURCES + """
            SELECT min((SELECT e.time FROM audit.event e WHERE e.source = s.source
                        ORDER BY e.seq LIMIT 1))
            FROM s WHERE s.source IS NOT NULL
            """
        ).fetchone()
        states = conn.execute(
            "SELECT source, valid, verified_at FROM audit.verify_state"
        ).fetchall()
    verified = {source: bool(valid) for source, valid, _ in states}
    verified_at = min((at for _, _, at in states), default=None)
    print(json.dumps(watch.report(healths, row[0] if row else None, verified, now,
                                  verified_at),
                     separators=(",", ":")))
    return 0


def siem_skip(stdin: str) -> int:
    """`siem-skip`: move read positions past undelivered events, with a reason; one
    `config_changed` event per moved position in the same transaction."""
    try:
        request = watch.parse_skip(json.loads(stdin))
    except (ValueError, json.JSONDecodeError) as error:
        print(f"papaia-audit: {error}", file=sys.stderr)
        return 2
    check = core.SubmissionCheck()
    correlation_id = "siem-skip-" + os.urandom(12).hex()
    now = datetime.now(timezone.utc)
    moved: list[dict[str, Any]] = []
    try:
        with connect("retention") as conn, conn.transaction():
            rows = conn.execute(
                "SELECT target, from_seq, released FROM audit.export_skip(%s, %s, %s, %s, %s)",
                (request.source, request.until, request.target, request.reason, correlation_id),
            ).fetchall()
            for target, from_seq, released in rows:
                seq_row = conn.execute(
                    "SELECT audit.next_seq(%s)", (watch.OWN_SOURCE,)
                ).fetchone()
                assert seq_row is not None
                conn.execute("SELECT audit.append_own(%s)", (watch.skip_event(
                    check, source=request.source, target=target, released=int(released),
                    moment=now, source_seq=int(seq_row[0]), correlation_id=correlation_id,
                ),))
                moved.append({"target": target, "from": int(from_seq), "until": request.until,
                              "released": int(released)})
    except psycopg.Error as error:
        if error.sqlstate == "PA003":
            print("papaia-audit: skip refused (no such source, seq or target)", file=sys.stderr)
            return 2
        raise
    log(f"siem skip source={request.source} until={request.until} positions={len(moved)}"
        f" correlation_id={correlation_id}")
    print(json.dumps({"source": request.source, "moved": moved,
                      "correlation_id": correlation_id}))
    return 0


def idmap(stdin: str) -> int:
    """`idmap`: the read API's `POST /v1/idmap` for `papaia-ctl audit idmap`, with the same
    checks (token of an auditor, ticket of that auditor for that person)."""
    try:
        document = json.loads(stdin)
        token, body = document["token"], document["request"]
        if set(document) != {"token", "request"} or not isinstance(token, str):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        print("papaia-audit: idmap takes a token and a request", file=sys.stderr)
        return 2
    api = read.ReadApi(
        PgReadStore(), TokenKeysFile(CONFIG_DIR / "token-keys.json"), _pseudonym_key(),
        core.SubmissionCheck(),
    )
    response = api.handle(read.Request(
        "POST", read.IDMAP_PATH, "", "papaia-ctl", f"Bearer {token}", None,
        json.dumps(body).encode("utf-8"),
    ))
    print(response.body.decode("utf-8"))
    return 0 if response.status == 200 else 1


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
    commands.add_parser("retention")
    commands.add_parser("access")
    commands.add_parser("siem-status")
    commands.add_parser("siem-skip")
    commands.add_parser("idmap")
    args = parser.parse_args(argv)
    if args.command == "serve":
        return serve()
    try:
        if args.command == "schema":
            return schema()
        if args.command == "verify":
            return verify(args.source, args.against, args.json)
        if args.command == "retention":
            return retention_now()
        if args.command == "access":
            return access_call()
        if args.command == "siem-status":
            return siem_status()
        if args.command == "siem-skip":
            return siem_skip(sys.stdin.read(64 * 1024))
        if args.command == "idmap":
            return idmap(sys.stdin.read(64 * 1024))
        return heads()
    except psycopg.Error as error:
        raise SystemExit(f"papaia-audit: database not reachable ({type(error).__name__})") from None


if __name__ == "__main__":
    sys.exit(main())
