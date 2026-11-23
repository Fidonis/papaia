"""papaia-audit without containers: what ingest stores and refuses, the hash chain per
source, verification and signed heads (src/infra/audit/papaia_audit/core.py), and the
certificates, passwords and wiring `papaia-ctl` provides (lib/audit.py).

The service logic is imported straight from the checkout. The store is an in-memory
double with the semantics of `audit.append` in src/infra/audit/db/10-audit.sql; the
end-to-end check with PostgreSQL and mutual TLS is in test_audit_docker.py.

The submission vectors are a copy of the platform kit's `papaia.audit/1` vectors
(fixtures/audit/audit.v1.json), so ingest accepts and refuses what every writer does.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import ssl
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from lib import audit, compat, gen_override, resolve, topology

REPO = Path(__file__).resolve().parents[2]
SERVICE_DIR = REPO / "src" / "infra" / "audit"
VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "audit" / "audit.v1.json").read_text(encoding="utf-8")
)


def _load_core() -> Any:
    path = SERVICE_DIR / "papaia_audit" / "core.py"
    spec = importlib.util.spec_from_file_location("papaia_audit_core", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


core = _load_core()
CHECK = core.SubmissionCheck()


class FakeStore:
    """`audit.append` in memory: one chain per source, repeats return their seq."""

    def __init__(self) -> None:
        self.rows: dict[str, list[core.StoredRow]] = {}

    def append(self, source: str, canonical: str) -> int:
        body = json.loads(canonical)
        rows = self.rows.setdefault(source, [])
        for row in rows:
            if row.body["source_seq"] == body["source_seq"]:
                return row.seq
        last_source_seq = rows[-1].body["source_seq"] if rows else 0
        if body["source_seq"] != last_source_seq + 1:
            raise core.Refused(core.GAP)
        prev = rows[-1].hash if rows else core.ZERO_HASH
        digest = hashlib.sha256(prev + canonical.encode("utf-8")).digest()
        rows.append(core.StoredRow(len(rows) + 1, prev, digest, core.derived_columns(body), body))
        return len(rows)


def _event(source_seq: int, **changes: Any) -> dict[str, Any]:
    event = {
        "format": "papaia.audit/1",
        "time": "2026-11-20T09:14:03.120Z",
        "source_seq": source_seq,
        "correlation_id": "c0a8-4e2f-91",
        "writer": "papaia-flow/flow-worker",
        "role": "caller",
        "sub": "4c0a9e1d-2b7f-4f53-9d0e-6a1c2b3d4e5f",
        "identity_kind": "person",
        "service_account": None,
        "azp": "flow-engine",
        "catalog_id": "paperless.documents",
        "operation": "add_note",
        "effect": "write",
        "result": "allowed",
        "event": "operation",
    }
    event.update(changes)
    return event


def _line(event: Any) -> bytes:
    return json.dumps(event, separators=(",", ":")).encode("utf-8")


def _ingest(store: FakeStore, *events: Any, source: str = "papaia-flow") -> Any:
    lines = [event if isinstance(event, bytes) else _line(event) for event in events]
    return core.ingest(store, CHECK, source, lines)


# ─────────────────────────────────────────────────────────────────────────
# ingest: valid and invalid rows
# ─────────────────────────────────────────────────────────────────────────


def test_valid_rows_are_stored_in_order_and_acknowledged_with_their_seq():
    store = FakeStore()
    result = _ingest(store, _event(1), _event(2), _event(3))

    assert result.refused is None
    assert result.acknowledged == [
        {"source_seq": 1, "seq": 1},
        {"source_seq": 2, "seq": 2},
        {"source_seq": 3, "seq": 3},
    ]
    assert [row.seq for row in store.rows["papaia-flow"]] == [1, 2, 3]


def test_a_repeated_delivery_is_acknowledged_with_the_seq_it_already_has():
    store = FakeStore()
    _ingest(store, _event(1), _event(2))

    result = _ingest(store, _event(2), _event(3))

    assert result.acknowledged == [{"source_seq": 2, "seq": 2}, {"source_seq": 3, "seq": 3}]
    assert len(store.rows["papaia-flow"]) == 3


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"payload": "x"}, core.INVALID),  # unknown field
        ({"source": "papaia-flow"}, core.INVALID),  # assigned by papaia-audit only
        ({"seq": 1}, core.INVALID),
        ({"prev_hash": "sha256:" + "0" * 64}, core.INVALID),
        ({"writer": "papaia-data"}, core.INVALID),  # another source's writer
        ({"correlation_id": "sk-" + "a" * 24}, core.INVALID),  # key-shaped
        ({"sub": "eyJhbGciOiJub25lIn0.e30."}, core.INVALID),  # token-shaped
        ({"time": "2026-02-30T09:14:03.120Z"}, core.INVALID),  # no such date
        ({"catalog_id": "x" * 300}, core.INVALID),  # over the string limit
        ({"format": "papaia.audit/2"}, core.UNSUPPORTED),
    ],
)
def test_an_invalid_first_row_is_refused_and_nothing_is_stored(changes, code):
    store = FakeStore()
    result = _ingest(store, _event(1, **changes))

    assert result.acknowledged == []
    assert result.refused.code == code
    assert store.rows.get("papaia-flow", []) == []


@pytest.mark.parametrize(
    "line",
    [
        b'{"source_seq": 1.0}',
        b'{"format":"papaia.audit/1","format":"papaia.audit/1"}',
        b"[1, 2]",
        b"\xff\xfe",
        b'{"a": NaN}',
        b"{" * 20000,
    ],
    ids=["fraction", "duplicate-key", "not-an-object", "not-utf8", "nan", "too-large"],
)
def test_lines_that_are_not_plain_json_objects_are_refused(line):
    result = _ingest(FakeStore(), line)
    assert result.refused.code == core.INVALID


def test_a_fraction_where_an_integer_belongs_is_refused_even_if_whole():
    line = _line(_event(1)).replace(b'"source_seq":1', b'"source_seq":1.0')
    assert _ingest(FakeStore(), line).refused.code == core.INVALID


def test_the_rows_before_a_refused_row_are_stored_and_the_rest_is_not():
    store = FakeStore()
    result = _ingest(store, _event(1), _event(2, payload="x"), _event(3))

    assert result.acknowledged == [{"source_seq": 1, "seq": 1}]
    assert result.refused.code == core.INVALID
    assert len(store.rows["papaia-flow"]) == 1


def test_a_gap_in_source_seq_is_refused_and_never_closed():
    store = FakeStore()
    _ingest(store, _event(1))

    result = _ingest(store, _event(3))

    assert result.refused.code == core.GAP
    assert len(store.rows["papaia-flow"]) == 1


def test_rows_of_a_request_must_rise_in_source_seq():
    result = _ingest(FakeStore(), _event(1), _event(1))
    assert result.acknowledged == [{"source_seq": 1, "seq": 1}]
    assert result.refused.code == core.INVALID


def test_each_source_has_its_own_chain():
    store = FakeStore()
    _ingest(store, _event(1), _event(2))
    result = _ingest(store, _event(1, writer="papaia-data"), source="papaia-data")

    assert result.acknowledged == [{"source_seq": 1, "seq": 1}]
    assert store.rows["papaia-data"][0].prev_hash == core.ZERO_HASH


@pytest.mark.parametrize(
    "body",
    [b"", b"\n", b"{}\n\n{}", b"\n".join([b"{}"] * 501), b"x" * (core.MAX_BODY_BYTES + 1)],
    ids=["empty", "only-newline", "blank-line", "501-lines", "too-large"],
)
def test_a_request_body_outside_the_batch_rules_is_refused(body):
    with pytest.raises(core.Refused) as refused:
        core.split_batch(body)
    assert refused.value.code == core.INVALID_REQUEST


def test_a_batch_may_end_with_a_newline():
    assert core.split_batch(b"{}\n{}\n") == [b"{}", b"{}"]


# ─────────────────────────────────────────────────────────────────────────
# the kit's vectors
# ─────────────────────────────────────────────────────────────────────────


def _vector_row(vector: dict[str, Any]) -> dict[str, Any]:
    if "row" in vector:
        return copy.deepcopy(vector["row"])
    base = next(v for v in VECTORS["valid"] if v["name"] == vector["base"])
    row = copy.deepcopy(base["row"])
    row.update(copy.deepcopy(vector.get("set", {})))
    for name in vector.get("unset", []):
        row.pop(name, None)
    return row


def _submissions(kind: str) -> list[dict[str, Any]]:
    return [v for v in VECTORS[kind] if v["stage"] == "submission"]


@pytest.mark.parametrize("vector", _submissions("valid"), ids=lambda v: v["name"])
def test_every_valid_submission_vector_is_stored(vector):
    row = _vector_row(vector)
    source = row["writer"].split("/", 1)[0]
    row["source_seq"] = 1

    result = _ingest(FakeStore(), row, source=source)

    assert result.refused is None
    assert result.acknowledged == [{"source_seq": 1, "seq": 1}]


@pytest.mark.parametrize("vector", _submissions("invalid"), ids=lambda v: v["name"])
def test_every_invalid_submission_vector_is_refused(vector):
    row = _vector_row(vector)
    writer = row.get("writer")
    source = writer.split("/", 1)[0] if isinstance(writer, str) else "papaia-flow"

    result = _ingest(FakeStore(), row, source=source)

    assert result.acknowledged == []
    assert result.refused.code in (core.INVALID, core.UNSUPPORTED)


# ─────────────────────────────────────────────────────────────────────────
# canonical JSON and the chain
# ─────────────────────────────────────────────────────────────────────────


def test_canonical_json_sorts_members_by_utf16_code_units_without_whitespace():
    value = {"\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\U0001f600": 5, "\u0080": 6}
    expected = '{"\\r":2,"1":4,"\u0080":6,"\u20ac":1,"\U0001f600":5,"\ufb33":3}'
    assert core.canonical_json(value) == expected.encode("utf-8")


def test_canonical_json_writes_large_integers_as_ecmascript_does():
    assert core.canonical_json([2**60, 10**21, 10**22]) == b"[1152921504606847000,1e+21,1e+22]"
    with pytest.raises(ValueError):
        core.canonical_json(2**53 + 1)
    with pytest.raises(ValueError):
        core.canonical_json(1.5)


def test_the_chain_links_each_event_to_the_hash_of_the_previous_one():
    store = FakeStore()
    _ingest(store, _event(1), _event(2))
    first, second = store.rows["papaia-flow"]

    canonical = core.canonical_json(_event(1))
    assert first.prev_hash == bytes(32)
    assert first.hash == hashlib.sha256(bytes(32) + canonical).digest()
    assert second.prev_hash == first.hash


# ─────────────────────────────────────────────────────────────────────────
# verification and signed heads
# ─────────────────────────────────────────────────────────────────────────


def _chain(n: int) -> list[core.StoredRow]:
    store = FakeStore()
    _ingest(store, *(_event(i) for i in range(1, n + 1)))
    return store.rows["papaia-flow"]


def test_an_untouched_chain_is_valid():
    report = core.verify_chain("papaia-flow", _chain(5))
    assert (report.valid, report.count, report.head_seq) == (True, 5, 5)


def test_a_tampered_row_is_detected_at_its_seq():
    rows = _chain(5)
    rows[2].body["result"] = "denied"
    rows[2].columns["result"] = "denied"

    report = core.verify_chain("papaia-flow", rows)

    assert (report.valid, report.broken_at, report.reason) == (False, 3, "event changed")


def test_a_changed_search_column_is_detected():
    rows = _chain(3)
    rows[1].columns["sub"] = "someone-else"

    report = core.verify_chain("papaia-flow", rows)

    assert (report.valid, report.broken_at) == (False, 2)
    assert report.reason == "search columns changed"


def test_a_removed_row_is_detected_as_a_gap():
    rows = _chain(4)
    del rows[1]

    report = core.verify_chain("papaia-flow", rows)

    assert (report.valid, report.broken_at, report.reason) == (False, 2, "missing events")


def test_a_rewritten_chain_passes_alone_but_not_against_a_signed_head():
    rows = _chain(4)
    signed = {"source": "papaia-flow", "seq": 3, "hash": core.hash_text(rows[2].hash)}
    # Someone with the owner's rights changes event 2 and recomputes the rest.
    rows[1].body["result"] = "denied"
    rows[1].columns["result"] = "denied"
    prev = rows[0].hash
    for row in rows[1:]:
        row.prev_hash = prev
        row.hash = core.chain_hash(prev, core.canonical_json(row.body))
        prev = row.hash

    report = core.verify_chain("papaia-flow", rows, wanted=[3])
    assert report.valid
    core.check_heads({"papaia-flow": report}, [signed])

    assert (report.valid, report.broken_at) == (False, 3)
    assert report.reason == "chain differs from a signed head"


def test_events_cut_after_a_signed_head_are_detected():
    rows = _chain(4)
    signed = {"source": "papaia-flow", "seq": 4, "hash": core.hash_text(rows[3].hash)}

    report = core.verify_chain("papaia-flow", rows[:2], wanted=[4])
    core.check_heads({"papaia-flow": report}, [signed])

    assert (report.valid, report.broken_at) == (False, 3)


def test_a_heads_line_round_trips_and_malformed_lines_are_rejected():
    document = core.heads_document([("papaia-flow", 4, b"\x01" * 32)], "2026-11-21T10:00:00.000Z")
    document["signature"] = "ed25519:" + base64.b64encode(b"\x02" * 64).decode()

    parsed, signature = core.parse_heads_line(json.dumps(document))

    assert parsed["heads"] == [{"source": "papaia-flow", "seq": 4, "hash": "sha256:" + "01" * 32}]
    assert signature == b"\x02" * 64
    assert b"signature" not in core.heads_payload(parsed)
    for broken in ({**document, "extra": 1}, {**document, "heads": [{"source": "X"}]}):
        with pytest.raises(ValueError):
            core.parse_heads_line(json.dumps(broken))


# ─────────────────────────────────────────────────────────────────────────
# sources.json
# ─────────────────────────────────────────────────────────────────────────


def test_sources_map_certificate_fingerprints_to_one_source_each():
    print_a, print_b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    data = {"format": core.SOURCES_FORMAT, "sources": {"papaia-flow": [print_a, print_b]}}
    assert core.parse_sources(data) == {print_a: "papaia-flow", print_b: "papaia-flow"}
    for broken in (
        {"format": core.SOURCES_FORMAT, "sources": {"papaia-flow": ["md5:1"]}},
        {"format": core.SOURCES_FORMAT, "sources": {"Flow": [print_a]}},
        {"format": core.SOURCES_FORMAT, "sources": {"a": [print_a], "b": [print_a]}},
        {"format": "other", "sources": {}},
    ):
        with pytest.raises(ValueError):
            core.parse_sources(broken)


# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl: certificates, passwords and keys
# ─────────────────────────────────────────────────────────────────────────


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def test_prepare_creates_the_ca_server_certificate_passwords_and_signing_key(tmp_path):
    audit.prepare(tmp_path)
    base = tmp_path / "infra" / "audit"

    assert _mode(base / "pki") == 0o700 and _mode(base / "secrets") == 0o700
    assert _mode(base / "pki" / "ca.key") == 0o600
    assert _mode(base / "service" / "server.key") == 0o600
    # Every secret file is read by its owner only: the database entrypoint as root, the
    # service and the schema step as the user that owns the config dir.
    assert all(_mode(path) == 0o600 for path in (base / "secrets").iterdir())
    passwords = {p.read_text() for p in (base / "secrets").glob("db-*-password")}
    assert len(passwords) == 5 and all(len(p) >= 40 for p in passwords)
    assert (
        "ED25519"
        in _openssl(
            "pkey", "-in", str(base / "secrets" / "heads-signing-key"), "-noout", "-text"
        ).upper()
    )
    text = _openssl("x509", "-in", str(base / "service" / "server.crt"), "-noout", "-text")
    assert "DNS:papaia-audit" in text and "TLS Web Server Authentication" in text
    _openssl(
        "verify", "-CAfile", str(base / "service" / "ca.crt"), str(base / "service" / "server.crt")
    )
    assert audit.load_sources(tmp_path) == {}
    assert not (base / "service" / "ca.key").exists()


def test_prepare_keeps_existing_material(tmp_path):
    audit.prepare(tmp_path)
    base = tmp_path / "infra" / "audit"
    files = [p for p in base.rglob("*") if p.is_file()]
    before = {p: p.read_bytes() for p in files}

    audit.prepare(tmp_path)

    assert {p: p.read_bytes() for p in files} == before


def test_a_source_certificate_is_a_client_certificate_listed_by_fingerprint(tmp_path):
    out = audit.issue_source_certificate(tmp_path, "papaia-flow")
    base = tmp_path / "infra" / "audit"

    text = _openssl(
        "x509", "-in", str(out / "client.crt"), "-noout", "-subject", "-ext", "extendedKeyUsage"
    )
    assert "CN=papaia-flow" in text.replace(" = ", "=")
    assert "TLS Web Client Authentication" in text
    _openssl("verify", "-CAfile", str(out / "ca.crt"), str(out / "client.crt"))
    assert _mode(out / "client.key") == 0o600
    der = ssl.PEM_cert_to_DER_cert((out / "client.crt").read_text())
    expected = "sha256:" + hashlib.sha256(der).hexdigest()
    assert audit.load_sources(tmp_path) == {"papaia-flow": [expected]}
    assert core.parse_sources(json.loads((base / "service" / "sources.json").read_text())) == {
        expected: "papaia-flow"
    }


def test_a_new_certificate_replaces_the_previous_one_of_the_source(tmp_path):
    first = audit.fingerprint(audit.issue_source_certificate(tmp_path, "mcp-qdrant") / "client.crt")
    second = audit.fingerprint(
        audit.issue_source_certificate(tmp_path, "mcp-qdrant") / "client.crt"
    )

    assert first != second
    assert audit.load_sources(tmp_path) == {"mcp-qdrant": [second]}


def test_no_certificate_is_issued_for_an_unknown_source(tmp_path):
    with pytest.raises(audit.AuditError):
        audit.issue_source_certificate(tmp_path, "papaia-unknown")
    assert not (tmp_path / "infra" / "audit" / "clients").exists()


def test_verify_and_heads_run_in_the_container_with_the_heads_file_on_stdin(tmp_path):
    heads = tmp_path / "heads.jsonl"
    heads.write_text('{"format":"papaia.audit-heads/1"}\n', encoding="utf-8")

    args, stdin = audit.service_command("verify", source="papaia-flow", against=heads)

    assert args == ["verify", "--source", "papaia-flow", "--against", "-"]
    assert stdin == heads.read_text(encoding="utf-8")
    assert audit.service_command("heads") == (["heads"], "")
    with pytest.raises(audit.AuditError):
        audit.service_command("verify", source="--json; rm")


# ─────────────────────────────────────────────────────────────────────────
# wiring: profile, networks, ports, attachment
# ─────────────────────────────────────────────────────────────────────────


def test_the_audit_profile_is_always_on_and_stays_on_the_controller():
    assert "audit" in resolve.ALWAYS_ON_PROFILES
    assert "audit" in topology.CONTROLLER_ONLY
    assert topology.CATALOGUE["audit"].profiles == ("audit",)


def test_the_compose_file_publishes_no_port_and_keeps_the_database_internal():
    doc = yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    services = doc["services"]

    assert set(services) == {"papaia-audit", "papaia-audit-schema", "papaia-audit-db"}
    assert all("ports" not in service for service in services.values())
    assert services["papaia-audit-db"]["networks"] == ["papaia-audit-net"]
    assert services["papaia-audit-schema"]["networks"] == ["papaia-audit-net"]
    assert set(services["papaia-audit"]["networks"]) == {
        "papaia-audit-net",
        "papaia-audit-ingest-net",
        "papaia-audit-idp-net",
    }
    assert all(net["internal"] is True for net in doc["networks"].values())
    assert all(service["profiles"] == ["audit"] for service in services.values())
    # The owner's password: the database and the one-shot schema step, never the service.
    assert services["papaia-audit-db"]["secrets"] == ["audit_db_owner_password"]
    assert "audit_db_owner_password" not in services["papaia-audit"]["secrets"]
    assert "audit_db_owner_password" in services["papaia-audit-schema"]["secrets"]
    assert services["papaia-audit-schema"]["restart"] == "no"
    assert services["papaia-audit"]["depends_on"]["papaia-audit-schema"] == {
        "condition": "service_completed_successfully"
    }
    assert "./infra/audit/docker-compose.yml" in (REPO / "src" / "docker-compose.yml").read_text()


def test_the_service_runs_from_the_own_image_and_nothing_of_the_checkout_is_mounted():
    doc = yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    services = doc["services"]
    version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    declared = yaml.safe_load((REPO / "compat" / "own-images.yaml").read_text(encoding="utf-8"))
    (entry,) = [i for i in declared["images"] if i["name"] == "ghcr.io/fidonis/papaia-audit"]

    assert set(entry["services"]) == {"papaia-audit", "papaia-audit-schema"}
    assert {
        "src/infra/audit/papaia_audit/core.py",
        "src/infra/audit/papaia_audit/schema.sql",
        "src/infra/audit/papaia_audit/audit.v1.schema.json",
        "src/infra/audit/requirements.txt",
    } <= set(entry["inputs"])
    for name in ("papaia-audit", "papaia-audit-schema"):
        service = services[name]
        assert "build" not in service
        assert service["image"].startswith(f"ghcr.io/fidonis/papaia-audit:{version}@sha256:")
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
    assert services["papaia-audit"]["image"] == services["papaia-audit-schema"]["image"]
    for service in services.values():
        for mount in service.get("volumes") or []:
            source = mount.get("source", "") if isinstance(mount, dict) else mount.split(":")[0]
            assert not str(source).startswith("."), source
    assert not (SERVICE_DIR / "db").exists()


def test_the_schema_file_holds_plain_sql_without_a_password():
    text = (SERVICE_DIR / "papaia_audit" / "schema.sql").read_text(encoding="utf-8")

    # Run through the driver, not psql: no meta commands, no file or shell access.
    assert not [line for line in text.splitlines() if line.lstrip().startswith("\\")]
    assert "PASSWORD" not in text.upper()
    assert "CREATE ROLE audit_ingest" in text and "CREATE ROLE audit_read" in text


def test_the_vendored_schema_is_the_revision_with_four_eyes_rows():
    schema = json.loads(
        (SERVICE_DIR / "papaia_audit" / "audit.v1.schema.json").read_text(encoding="utf-8")
    )
    names = {v["name"] for v in VECTORS["valid"]}

    assert schema["x-papaia-schema-version"] == "1.4.0"
    assert "four_eyes_changed" in schema["$defs"]["event"]["enum"]
    assert "delegation_lifetime_changed" in schema["$defs"]["event"]["enum"]
    assert {
        "operation_at_server_with_token_times",
        "delegation_lifetime_change",
        "delegation_lifetime_change_refused",
        "four_eyes_change",
        "four_eyes_change_refused_in_kritis",
        "self_approval_flagged",
    } <= names


def test_the_four_eyes_rows_of_the_kit_are_stored_and_a_bad_one_is_refused():
    valid = next(v for v in VECTORS["valid"] if v["name"] == "four_eyes_change_refused_in_kritis")
    row = _vector_row(valid)
    source = row["writer"].split("/", 1)[0]
    row["source_seq"] = 1

    stored = _ingest(FakeStore(), row, source=source)
    unchanged = _ingest(
        FakeStore(),
        {**row, "result": "allowed", "error_code": None,
         "detail": {"four_eyes_old": "on", "four_eyes_new": "on"}},
        source=source,
    )

    assert stored.refused is None
    assert unchanged.refused is not None and unchanged.refused.code == core.INVALID


def test_token_times_are_stored_only_in_the_server_row_of_an_operation():
    base = _vector_row(
        next(v for v in VECTORS["valid"] if v["name"] == "operation_at_server_with_token_times")
    )
    source = base["writer"].split("/", 1)[0]
    base["source_seq"] = 1

    stored = _ingest(FakeStore(), base, source=source)
    as_module = _ingest(FakeStore(), {**base, "role": "caller"}, source=source)
    negative = _ingest(FakeStore(), {**base, "token_remaining_s": -1}, source=source)

    assert stored.refused is None
    assert as_module.refused is not None and as_module.refused.code == core.INVALID
    assert negative.refused is not None and negative.refused.code == core.INVALID


@pytest.mark.parametrize("service", ["papaia-audit-db", "papaia-audit-schema"])
def test_no_add_on_may_attach_the_audit_database(tmp_path, service):
    manifest = {
        "name": "probe",
        "version": "1.0.0",
        "addon_api": 7,
        "networks": {"app_network": "papaia-probe-net", "attach": [service]},
    }

    result = compat.evaluate_addon("probe", manifest, compat.resolve_core_target(REPO))

    assert result.status == compat.STATUS_INCOMPATIBLE
    assert service in result.reason
    with pytest.raises(ValueError):
        gen_override.generate_override(manifest, tmp_path)
