"""papaia-audit retention, deletion lock, SIEM export and tamper evidence without containers
(src/infra/audit/papaia_audit/retention.py, siem.py, core.py) and their wiring
(lib/audit.py, the compose file, schema_retention.sql).

The store is an in-memory double with the semantics of `audit.append`, `audit.prune` and
the export positions of schema_retention.sql. The test clock only decides which business
timestamps (`time` of the events) count as old; nothing else reads it.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from lib import audit, egress, gen_override

REPO = Path(__file__).resolve().parents[2]
SERVICE_DIR = REPO / "src" / "infra" / "audit"
sys.path.insert(0, str(SERVICE_DIR))

from papaia_audit import core, retention, siem  # noqa: E402

CHECK = core.SubmissionCheck()
UTC = timezone.utc
NOW = datetime(2027, 11, 21, 3, 30, tzinfo=UTC)
ANNA = "4c0a9e1d-2b7f-4f53-9d0e-6a1c2b3d4e5f"
CEM = "9f1e2d3c-4b5a-4678-9abc-def012345678"


def _time(moment: datetime) -> str:
    return retention.time_text(moment)


def _event(source_seq: int, moment: datetime, sub: str = ANNA) -> dict[str, Any]:
    return {
        "format": "papaia.audit/1",
        "time": _time(moment),
        "source_seq": source_seq,
        "correlation_id": f"c-{source_seq}",
        "writer": "papaia-flow/flow-worker",
        "role": "caller",
        "sub": sub,
        "identity_kind": "person",
        "service_account": None,
        "azp": "flow-engine",
        "catalog_id": "paperless.documents",
        "operation": "add_note",
        "effect": "write",
        "result": "allowed",
        "event": "operation",
    }


class Store:
    """The store's functions in memory: append, prune with anchors, holds, positions."""

    def __init__(self, clock: Callable[[], datetime] = lambda: NOW) -> None:
        self.rows: dict[str, list[core.StoredRow]] = {}
        self.anchors: dict[str, tuple[int, int, bytes]] = {}  # source -> seq, source_seq, hash
        self.holds: set[str] = set()
        self.targets: dict[str, bool] = {}
        self.cursors: dict[tuple[str, str], int] = {}
        self.refuse: set[str] = set()  # sources whose prune the store refuses (PA002)
        self.deliveries: list[tuple[str, bool]] = []
        self.clock = clock

    # audit.append / next_seq / append_own
    def append(self, source: str, canonical: str) -> int:
        body = json.loads(canonical)
        rows = self.rows.setdefault(source, [])
        for row in rows:
            if row.body["source_seq"] == body["source_seq"]:
                return row.seq
        anchor = self.anchors.get(source)
        if anchor and body["source_seq"] <= anchor[1]:
            return anchor[0] - (anchor[1] - body["source_seq"])
        if rows:
            last_seq, last_ss, prev = rows[-1].seq, rows[-1].body["source_seq"], rows[-1].hash
        elif anchor:
            last_seq, last_ss, prev = anchor
        else:
            last_seq, last_ss, prev = 0, 0, core.ZERO_HASH
        if body["source_seq"] != last_ss + 1:
            raise core.Refused(core.GAP)
        digest = hashlib.sha256(prev + canonical.encode("utf-8")).digest()
        rows.append(core.StoredRow(last_seq + 1, prev, digest, core.derived_columns(body), body))
        return last_seq + 1

    def next_seq(self, source: str) -> int:
        rows = self.rows.get(source) or []
        if rows:
            return rows[-1].body["source_seq"] + 1
        return self.anchors[source][1] + 1 if source in self.anchors else 1

    # retention.Store
    def sources(self) -> list[str]:
        return sorted(set(self.rows) | set(self.anchors))

    def facts(self, source: str, before: datetime) -> retention.Facts:
        rows = self.rows.get(source) or []
        young = [r.seq for r in rows if r.body["time"] >= _time(before)]
        old_end = (min(young) if young else (rows[-1].seq + 1 if rows else 1)) - 1
        held = [r.seq for r in rows if r.body.get("sub") in self.holds]
        # Every target ever configured holds back, active or not, until it is skipped.
        delivered = min((self.cursors.get((t, source), 0) for t in self.targets), default=None)
        anchor = self.anchors.get(source, (0, 0, b""))[0]
        return retention.Facts(old_end, anchor, min(held) if held else None, delivered)

    def prune(self, source: str, upto: int, months: int, build: Any) -> retention.Pruned:
        rows = self.rows.get(source) or []
        anchor = self.anchors.get(source)
        removed = 0
        if upto > (anchor[0] if anchor else 0):
            if source in self.refuse:
                raise retention.PruneRefused(source)
            cut = [r for r in rows if r.seq <= upto]
            limit = _time(retention.cutoff(self.clock(), months))
            assert all(r.body["time"] < limit for r in cut), "prune refuses young events"
            assert not any(r.body.get("sub") in self.holds for r in cut), "prune refuses holds"
            for target in self.targets:
                assert self.cursors.get((target, source), 0) >= upto
            last = cut[-1]
            self.anchors[source] = (last.seq, last.body["source_seq"], last.hash)
            self.rows[source] = [r for r in rows if r.seq > upto]
            removed = len(cut)
        anchor = self.anchors.get(source)
        result = retention.Pruned(removed, anchor[0] if anchor else 0,
                                  anchor[2] if anchor else None)
        self.append(retention.OWN_SOURCE, build(result, self.next_seq(retention.OWN_SOURCE)))
        return result

    # siem.ExportStore
    def position(self, target: str, source: str) -> int:
        return self.cursors.get((target, source), 0)

    def rows_after(self, source: str, seq: int, limit: int) -> list[siem.Row]:
        rows = [r for r in self.rows.get(source) or [] if r.seq > seq][:limit]
        return [siem.Row(source, r.seq, r.prev_hash, r.hash, r.body) for r in rows]

    def advance(self, target: str, source: str, seq: int) -> None:
        self.cursors[(target, source)] = max(self.cursors.get((target, source), 0), seq)

    def delivery(self, target: str, ok: bool) -> None:
        self.deliveries.append((target, ok))

    def upstream(self, subs: set[str]) -> dict[str, tuple[str, str]]:
        return {}

    # verify as __main__.verify_all does it
    def verify(self) -> dict[str, core.ChainReport]:
        anchors = {s: (a[0], a[2]) for s, a in self.anchors.items()}
        reports = {
            s: core.verify_chain(s, self.rows.get(s) or [], (), anchors.get(s))
            for s in self.sources()
        }
        attested = {
            r.body["object_ref"]["id"]
            for r in self.rows.get(retention.OWN_SOURCE) or []
            if r.body["event"] == "retention_run"
            and r.body["object_ref"]["type"] == retention.ANCHOR_REF
        }
        core.check_anchors(reports, anchors, attested)
        return reports


def _fill(store: Store, times: Sequence[datetime], subs: Sequence[str] | None = None,
          source: str = "papaia-flow") -> None:
    for index, moment in enumerate(times, start=1):
        sub = subs[index - 1] if subs else ANNA
        event = {**_event(index, moment, sub), "writer": f"{source}/worker"}
        _, canonical = CHECK.check(json.dumps(event).encode(), source)
        store.append(source, canonical.decode())


def _run(store: Store, months: int = 12, now: datetime = NOW) -> retention.RunReport:
    return retention.run(store, CHECK, months, lambda: now)


# ─────────────────────────────────────────────────────────────────────────
# settings and boundaries
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text, months", [("", 12), (None, 12), ("6", 6), ("36", 36), (" 24 ", 24)])
def test_retention_is_12_months_by_default_and_6_to_36_when_set(text, months):
    assert retention.parse_months(text) == months


@pytest.mark.parametrize("text", ["5", "37", "0", "-12", "12x", "1e1", "١٢", "012"])
def test_retention_outside_6_to_36_months_is_refused(text):
    with pytest.raises(ValueError):
        retention.parse_months(text)


def test_the_cutoff_counts_calendar_months_and_clamps_to_the_month_end():
    assert retention.cutoff(NOW, 12) == datetime(2026, 11, 21, 3, 30, tzinfo=UTC)
    assert retention.cutoff(datetime(2027, 8, 31, tzinfo=UTC), 6) == datetime(
        2027, 2, 28, tzinfo=UTC
    )
    assert retention.cutoff(datetime(2028, 2, 29, tzinfo=UTC), 36) == datetime(
        2025, 2, 28, tzinfo=UTC
    )
    with pytest.raises(ValueError):
        retention.cutoff(NOW, 5)


def test_an_event_one_millisecond_older_than_the_limit_is_removed_one_at_it_is_kept():
    limit = retention.cutoff(NOW, 12)
    store = Store()
    _fill(store, [limit - timedelta(days=30), limit - timedelta(milliseconds=1), limit,
                  limit + timedelta(days=1)])

    report = _run(store)

    assert report.removed == {"papaia-flow": 2}
    assert [r.seq for r in store.rows["papaia-flow"]] == [3, 4]
    assert store.anchors["papaia-flow"][0] == 2


def test_the_configured_months_move_the_boundary():
    store = Store()
    _fill(store, [NOW - timedelta(days=200), NOW - timedelta(days=100)])

    assert _run(store, months=12).removed == {}
    assert _run(store, months=6).removed == {"papaia-flow": 1}


def test_a_chain_is_only_shortened_at_its_start():
    old = NOW - timedelta(days=500)
    store = Store()
    # A source with a wrong clock: a young event between old ones stops the run there.
    _fill(store, [old, NOW - timedelta(days=1), old])

    _run(store)

    assert [r.seq for r in store.rows["papaia-flow"]] == [2, 3]


# ─────────────────────────────────────────────────────────────────────────
# deletion lock and undelivered events
# ─────────────────────────────────────────────────────────────────────────


def test_a_deletion_lock_stops_the_run_before_the_oldest_locked_event():
    old = NOW - timedelta(days=500)
    store = Store()
    _fill(store, [old] * 5, subs=[ANNA, ANNA, CEM, ANNA, ANNA])
    store.holds.add(CEM)

    report = _run(store)

    assert report.removed == {"papaia-flow": 2}
    assert [r.seq for r in store.rows["papaia-flow"]] == [3, 4, 5]
    (own,) = [p for p in report.plans if p.source == "papaia-flow"]
    assert own.held_back == retention.LEGAL_HOLD
    run_event = store.rows[retention.OWN_SOURCE][-1].body
    assert run_event["operation"] == "retention.held_back.legal_hold"
    assert run_event["detail"] == {"count": 2}


def test_after_the_lock_is_lifted_the_next_run_removes_the_rest():
    old = NOW - timedelta(days=500)
    store = Store()
    _fill(store, [old] * 3, subs=[CEM, ANNA, ANNA])
    store.holds.add(CEM)
    assert _run(store).removed == {"papaia-flow": 0}

    store.holds.clear()

    assert _run(store, now=NOW + timedelta(days=1)).removed == {"papaia-flow": 3}
    assert store.rows["papaia-flow"] == []


def test_events_the_siem_target_has_not_taken_are_held_back():
    old = NOW - timedelta(days=500)
    store = Store()
    _fill(store, [old] * 4)
    store.targets["syslog-tls://siem.example.org:6514"] = True
    store.advance("syslog-tls://siem.example.org:6514", "papaia-flow", 1)

    report = _run(store)

    assert report.removed == {"papaia-flow": 1}
    assert next(p for p in report.plans if p.source == "papaia-flow").held_back == (
        retention.UNDELIVERED
    )


def test_a_target_no_longer_configured_still_holds_back_what_it_has_not_taken():
    # GV-06: nothing is lost without `audit siem skip`; removing or replacing the target in
    # the configuration does not release the events it has not taken.
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 3)
    store.targets["https://old.example.org:443/"] = False
    store.advance("https://old.example.org:443/", "papaia-flow", 1)

    report = _run(store)

    assert report.removed == {"papaia-flow": 1}
    assert next(p for p in report.plans if p.source == "papaia-flow").held_back == (
        retention.UNDELIVERED
    )
    # The store judges every target too, not only the active one.
    sql = (SERVICE_DIR / "papaia_audit" / "schema_retention.sql").read_text(encoding="utf-8")
    main = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    facts = main[main.index("    def facts(self, source: str, before: datetime)"):]
    facts = facts[: facts.index("    def prune(")]
    assert "t.active" not in sql and "active" not in facts


def test_a_refused_prune_of_one_source_does_not_stop_the_others():
    old = NOW - timedelta(days=500)
    store = Store()
    _fill(store, [old] * 2, source="papaia-data")
    _fill(store, [old] * 3, source="papaia-flow")
    store.refuse.add("papaia-data")

    report = _run(store)

    assert report.removed == {"papaia-data": 0, "papaia-flow": 3}
    assert [r.seq for r in store.rows["papaia-data"]] == [1, 2]
    (refused,) = [p for p in report.plans if p.source == "papaia-data"]
    assert refused.held_back == retention.REFUSED and not refused.removes
    events = {r.body["object_ref"]["id"]: r.body for r in store.rows[retention.OWN_SOURCE]}
    assert events["papaia-data"]["operation"] == "retention.held_back.store_refused"
    assert events["papaia-data"]["detail"] == {"count": 0}
    assert store.verify()["papaia-data"].valid


# ─────────────────────────────────────────────────────────────────────────
# the run is recorded, the chain stays verifiable
# ─────────────────────────────────────────────────────────────────────────


def test_each_run_writes_a_valid_retention_run_event_naming_the_anchor():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 3 + [NOW])

    _run(store)

    (event,) = [r.body for r in store.rows[retention.OWN_SOURCE]]
    seq, _, digest = store.anchors["papaia-flow"]
    assert event["event"] == "retention_run"
    assert event["writer"] == retention.WRITER
    assert event["object_ref"] == {"type": "audit_anchor",
                                   "id": f"papaia-flow:{seq}:{digest.hex()}"}
    assert event["effect"] == "delete" and event["result"] == "allowed"
    assert event["sub"] is None and event["service_account"] == "papaia-audit"
    # The own event passes the same submission check as every other event.
    CHECK.check(json.dumps(event).encode(), retention.OWN_SOURCE)


def test_a_source_without_old_events_gets_no_event():
    store = Store()
    _fill(store, [NOW])

    _run(store)

    assert retention.OWN_SOURCE not in store.rows


def test_the_chain_stays_valid_from_the_anchor_after_a_run():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 3 + [NOW - timedelta(days=1)] * 2)

    _run(store)
    _, canonical = CHECK.check(json.dumps(_event(6, NOW)).encode(), "papaia-flow")
    store.append("papaia-flow", canonical.decode())

    reports = store.verify()
    assert all(r.valid for r in reports.values()), reports
    assert reports["papaia-flow"].anchor_seq == 3
    assert [r.seq for r in store.rows["papaia-flow"]] == [4, 5, 6]


def test_a_chain_removed_entirely_continues_from_its_anchor():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 2)
    _run(store)
    assert store.rows["papaia-flow"] == []

    _, canonical = CHECK.check(json.dumps(_event(3, NOW)).encode(), "papaia-flow")
    seq = store.append("papaia-flow", canonical.decode())

    assert seq == 3
    assert store.rows["papaia-flow"][0].prev_hash == store.anchors["papaia-flow"][2]
    assert all(r.valid for r in store.verify().values())


def test_a_repeat_of_a_removed_event_is_acknowledged_with_its_seq():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 3)
    _run(store)

    _, canonical = CHECK.check(json.dumps(_event(2, NOW)).encode(), "papaia-flow")

    assert store.append("papaia-flow", canonical.decode()) == 2
    assert store.rows["papaia-flow"] == []


def test_an_anchor_moved_by_hand_breaks_the_chain():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 2 + [NOW - timedelta(days=1)] * 3)
    _run(store)
    # Someone with the owner's rights removes two more events and moves the anchor.
    rows = store.rows["papaia-flow"]
    store.anchors["papaia-flow"] = (rows[1].seq, rows[1].body["source_seq"], rows[1].hash)
    store.rows["papaia-flow"] = rows[2:]

    report = store.verify()["papaia-flow"]

    assert (report.valid, report.broken_at) == (False, 5)
    assert report.reason == "anchor not recorded by a retention run"


def test_a_signed_head_before_the_anchor_does_not_break_the_chain():
    store = Store()
    _fill(store, [NOW - timedelta(days=500)] * 3 + [NOW])
    early = {"source": "papaia-flow", "seq": 2, "hash": core.hash_text(
        store.rows["papaia-flow"][1].hash)}
    late = {"source": "papaia-flow", "seq": 4, "hash": core.hash_text(
        store.rows["papaia-flow"][3].hash)}
    _run(store)

    anchors = {s: (a[0], a[2]) for s, a in store.anchors.items()}
    report = core.verify_chain("papaia-flow", store.rows["papaia-flow"], [2, 4],
                               anchors["papaia-flow"])
    core.check_heads({"papaia-flow": report}, [early, late])

    assert report.valid
    # The anchor itself is a signed position too.
    at_anchor = {"source": "papaia-flow", "seq": 3, "hash": "sha256:" + "00" * 32}
    core.check_heads({"papaia-flow": report}, [at_anchor])
    assert not report.valid and report.reason == "chain differs from a signed head"


def test_settings_that_differ_from_the_recorded_ones_are_changes():
    current = {"audit.retention_months": "12", "audit.siem_target": ""}

    assert retention.changed_settings(current, {}) == sorted(current)
    assert retention.changed_settings(current, dict(current)) == []
    assert retention.changed_settings(current, {**current, "audit.retention_months": "24"}) == [
        "audit.retention_months"
    ]


def test_the_service_runs_heads_hourly_and_retention_daily_at_0330_utc():
    moment = datetime(2027, 3, 4, 3, 29, 59, tzinfo=UTC)
    assert retention.next_hour(moment) == datetime(2027, 3, 4, 4, 0, tzinfo=UTC)
    assert retention.next_run(moment) == datetime(2027, 3, 4, 3, 30, tzinfo=UTC)
    assert retention.next_run(moment + timedelta(seconds=1)) == datetime(
        2027, 3, 5, 3, 30, tzinfo=UTC
    )


# ─────────────────────────────────────────────────────────────────────────
# SIEM export
# ─────────────────────────────────────────────────────────────────────────

TARGET = siem.Target("syslog", "siem.example.org", 6514)
KEY = b"k" * 32


class Receiver:
    """A target that takes `budget` messages and then fails, like an outage."""

    def __init__(self, budget: int | None = None) -> None:
        self.messages: list[bytes] = []
        self.budget = budget

    def send(self, messages: Sequence[bytes]) -> None:
        if self.budget is not None and self.budget < len(messages):
            raise siem.ExportError("syslog target not reachable (ConnectionRefusedError)")
        if self.budget is not None:
            self.budget -= len(messages)
        self.messages.extend(messages)

    def close(self) -> None:
        return


def _seqs(messages: Sequence[bytes]) -> list[int]:
    return [json.loads(m.split(b"] ", 1)[1])["seq"] for m in messages]


def test_the_export_resumes_after_a_restart_from_the_stored_position(monkeypatch):
    monkeypatch.setattr(siem, "BATCH", 2)
    store = Store()
    _fill(store, [NOW] * 5)
    store.targets[TARGET.name] = True
    first = Receiver(budget=2)

    with pytest.raises(siem.ExportError):
        siem.Exporter(store, first, siem.Settings(TARGET), KEY).run_once()
    assert store.position(TARGET.name, "papaia-flow") == 2

    # A new exporter (the service restarted) continues where the target stopped taking.
    second = Receiver()
    sent = siem.Exporter(store, second, siem.Settings(TARGET), KEY).run_once()

    assert sent == 3
    assert _seqs(first.messages) + _seqs(second.messages) == [1, 2, 3, 4, 5]
    assert store.position(TARGET.name, "papaia-flow") == 5
    assert siem.Exporter(store, Receiver(), siem.Settings(TARGET), KEY).run_once() == 0


def test_a_syslog_message_follows_rfc_5424_with_octet_counting():
    store = Store()
    _fill(store, [NOW])
    receiver = Receiver()
    clock = datetime(2027, 1, 2, 3, 4, 5, 678000, tzinfo=UTC)

    siem.Exporter(store, receiver, siem.Settings(TARGET, pen=32473), KEY,
                  clock=lambda: clock).run_once()

    (frame,) = receiver.messages
    length, message = frame.split(b" ", 1)
    assert int(length) == len(message)
    head, body = message.decode().split("] ", 1)
    assert head == (
        '<110>1 2027-01-02T03:04:05.678Z papaia-audit papaia - operation '
        '[papaia@32473 source="papaia-flow" seq="1"'
    )
    document = json.loads(body)
    assert document["format"] == "papaia.audit/1"
    assert document["hash"] == core.hash_text(store.rows["papaia-flow"][0].hash)


def test_persons_leave_as_pseudonyms_unless_sub_is_set_with_a_basis():
    store = Store()
    _fill(store, [NOW])
    row = store.rows_after("papaia-flow", 0, 1)[0]
    row.body["client_ip"] = "192.0.2.7"
    row.body["object_ref"] = {"type": "user", "id": CEM}

    hidden = siem.present(row, "pseudonym", KEY)
    shown = siem.present(row, "sub", KEY)

    assert hidden["sub"] == siem.pseudonym(KEY, ANNA) and hidden["sub"].startswith("P-")
    assert hidden["object_ref"]["id"] == siem.pseudonym(KEY, CEM)
    assert hidden["client_ip"] is None
    assert ANNA not in json.dumps(hidden) and CEM not in json.dumps(hidden)
    assert shown["sub"] == ANNA
    assert siem.parse_identity("", "") == ("pseudonym", "")
    assert siem.parse_identity("sub", "BV-IT-2026-04") == ("sub", "BV-IT-2026-04")
    for identity, basis in (("sub", ""), ("sub", "a\nb"), ("upstream", "x")):
        with pytest.raises(ValueError):
            siem.parse_identity(identity, basis)


@pytest.mark.parametrize("text, expected", [
    ("", None),
    ("syslog-tls://SIEM.example.org", "syslog-tls://siem.example.org:6514"),
    ("syslog-tls://10.1.2.3:1514", "syslog-tls://10.1.2.3:1514"),
    ("https://siem.example.org/ingest", "https://siem.example.org:443/ingest"),
])
def test_siem_targets_are_parsed(text, expected):
    target = siem.parse_target(text)
    assert (target.name if target else None) == expected


@pytest.mark.parametrize("text", [
    "http://siem.example.org", "syslog://siem.example.org", "syslog-tls://u:p@siem.example.org",
    "https://siem.example.org/a?b=1", "syslog-tls://-bad", "syslog-tls://siem.example.org/x",
    "https://siem.example.org/../x", "tcp://siem.example.org:514",
])
def test_malformed_siem_targets_are_refused(text):
    with pytest.raises(ValueError):
        siem.parse_target(text)


@pytest.mark.parametrize("text", ["0", "-1", "x", "1234567890"])
def test_the_pen_is_a_positive_number(text):
    with pytest.raises(ValueError):
        siem.parse_pen(text)


def _tls_files(tmp_path: Path) -> tuple[Path, Path]:
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )
    return key, cert


def test_the_syslog_sender_delivers_over_tls_to_a_listening_target(tmp_path):
    key, cert = _tls_files(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    received = bytearray()

    def accept() -> None:
        conn, _ = listener.accept()
        with server_ctx.wrap_socket(conn, server_side=True) as tls:
            try:
                while chunk := tls.recv(65536):
                    received.extend(chunk)
            except ConnectionResetError:
                # The sender closes without a TLS close_notify.
                return

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    client_ctx = ssl.create_default_context(cafile=str(cert))
    sender = siem.SyslogSender(siem.Target("syslog", "localhost", port), client_ctx)
    frames = [siem.syslog_message({"n": i}, msgid="chain_head", pen=1, hostname="h", now=NOW)
              for i in range(3)]

    sender.send(frames)
    sender.close()
    thread.join(5)
    listener.close()

    assert bytes(received) == b"".join(frames)


def test_a_target_with_a_foreign_certificate_is_refused(tmp_path):
    key, cert = _tls_files(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def accept() -> None:
        conn, _ = listener.accept()
        try:
            server_ctx.wrap_socket(conn, server_side=True).close()
        except (ssl.SSLError, OSError):
            conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    sender = siem.SyslogSender(siem.Target("syslog", "localhost", port),
                               ssl.create_default_context())

    with pytest.raises(siem.ExportError):
        sender.send([b"1 x"])
    thread.join(5)
    listener.close()


class ClosingTarget:
    """A syslog TLS receiver that keeps what it read per connection and can drop the
    connection at any time, like papaia-egress after 300 s idle or a restarted receiver."""

    def __init__(self, tmp_path: Path) -> None:
        key, cert = _tls_files(tmp_path)
        self.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ctx.load_cert_chain(cert, key)
        self.client_ctx = ssl.create_default_context(cafile=str(cert))
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.connections: list[bytearray] = []
        self._open: list[ssl.SSLSocket] = []
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._read, args=(conn,), daemon=True).start()

    def _read(self, conn: socket.socket) -> None:
        received = bytearray()
        try:
            tls = self.server_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        with self._lock:
            self.connections.append(received)
            self._open.append(tls)
        try:
            while chunk := tls.recv(65536):
                received.extend(chunk)
        except OSError:
            return

    def wait_for(self, size: int) -> None:
        for _ in range(200):
            if sum(len(c) for c in self.connections) >= size:
                return
            threading.Event().wait(0.02)
        raise AssertionError("the receiver did not get the messages")

    def drop(self) -> None:
        """Close every open connection from the receiver's side, without close_notify."""
        with self._lock:
            for tls in self._open:
                try:
                    tls.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                tls.close()
            self._open.clear()
        threading.Event().wait(0.1)  # let the FIN reach the sender

    def stop(self) -> None:
        self.listener.close()
        self.drop()

    def seqs(self) -> list[list[int]]:
        return [_frames_seqs(bytes(c)) for c in self.connections]


def _frames_seqs(data: bytes) -> list[int]:
    seqs = []
    while data:
        length, rest = data.split(b" ", 1)
        frame, data = rest[: int(length)], rest[int(length):]
        seqs.append(json.loads(frame.split(b"] ", 1)[1])["seq"])
    return seqs


def _syslog_exporter(store: Store, receiver: ClosingTarget,
                     clock: Callable[[], float] | None = None) -> siem.Exporter:
    target = siem.Target("syslog", "localhost", receiver.port)
    store.targets[target.name] = True
    kwargs = {"clock": clock} if clock else {}
    sender = siem.SyslogSender(target, receiver.client_ctx, **kwargs)
    return siem.Exporter(store, sender, siem.Settings(target), KEY)


def test_a_connection_the_receiver_closed_between_batches_is_opened_again(tmp_path):
    store = Store()
    receiver = ClosingTarget(tmp_path)
    exporter = _syslog_exporter(store, receiver)
    name = exporter.settings.target.name
    _fill(store, [NOW] * 2)
    assert exporter.run_once() == 2
    receiver.wait_for(1)

    receiver.drop()
    for index in (3, 4):
        _, canonical = CHECK.check(json.dumps(_event(index, NOW)).encode(), "papaia-flow")
        store.append("papaia-flow", canonical.decode())
    sent = exporter.run_once()

    receiver.wait_for(sum(len(c) for c in receiver.connections) + 1)
    assert sent == 2
    # The second batch went over a new connection, not into the closed one.
    assert receiver.seqs() == [[1, 2], [3, 4]]
    assert store.position(name, "papaia-flow") == 4
    exporter.sender.close()
    receiver.stop()


def test_the_read_position_stays_when_the_closed_target_cannot_be_reached_again(tmp_path):
    store = Store()
    receiver = ClosingTarget(tmp_path)
    exporter = _syslog_exporter(store, receiver)
    name = exporter.settings.target.name
    _fill(store, [NOW] * 2)
    exporter.run_once()
    receiver.wait_for(1)

    receiver.stop()  # the receiver is gone: connection closed, nobody listens
    _, canonical = CHECK.check(json.dumps(_event(3, NOW)).encode(), "papaia-flow")
    store.append("papaia-flow", canonical.decode())

    with pytest.raises(siem.ExportError):
        exporter.run_once()
    assert store.position(name, "papaia-flow") == 2


def test_a_connection_idle_longer_than_the_egress_allows_is_opened_again(tmp_path):
    store = Store()
    receiver = ClosingTarget(tmp_path)
    moment = [1000.0]
    exporter = _syslog_exporter(store, receiver, clock=lambda: moment[0])
    _fill(store, [NOW])
    exporter.run_once()
    receiver.wait_for(1)
    egress_source = (REPO / "src" / "infra" / "egress" / "egress.py").read_text(encoding="utf-8")
    (egress_idle,) = re.findall(r"^IDLE_TIMEOUT_SECONDS = (\d+)$", egress_source, re.M)
    assert siem.IDLE_SECONDS < int(egress_idle)

    moment[0] += siem.IDLE_SECONDS + 1
    _, canonical = CHECK.check(json.dumps(_event(2, NOW)).encode(), "papaia-flow")
    store.append("papaia-flow", canonical.decode())
    exporter.run_once()

    receiver.wait_for(sum(len(c) for c in receiver.connections) + 1)
    assert receiver.seqs() == [[1], [2]]
    exporter.sender.close()
    receiver.stop()


# ─────────────────────────────────────────────────────────────────────────
# upkeep schedule of the service
# ─────────────────────────────────────────────────────────────────────────


class Duties:
    """The service's duties, recorded; `fail` names those that raise."""

    def __init__(self, *fail: str) -> None:
        self.fail = set(fail)
        self.calls: list[str] = []
        self.kept: list[dict[str, Any]] = []

    def _do(self, name: str) -> None:
        self.calls.append(name)
        if name in self.fail:
            if name in ("export", "send_heads"):
                raise siem.ExportError("syslog target not reachable (ConnectionRefusedError)")
            raise OSError("store not reachable")

    def build(self, with_target: bool = True) -> retention.Duties:
        def export() -> int:
            self._do("export")
            return 0

        def sign() -> dict[str, Any]:
            self._do("sign")
            return {"heads": [], "signed_at": "2027-11-21T04:00:00.000Z"}

        def keep(document: dict[str, Any]) -> None:
            self._do("keep")
            self.kept.append(document)

        return retention.Duties(
            record=lambda: self._do("record"),
            export=export if with_target else None,
            sign=sign,
            keep=keep,
            verify=lambda: self._do("verify"),
            send_heads=(lambda document: self._do("send_heads")) if with_target else None,
            retain=lambda: self._do("retain"),
        )


def _schedule(duties: Duties, start: datetime, **kwargs: Any) -> tuple[
        retention.Schedule, list[str]]:
    lines: list[str] = []
    schedule = retention.Schedule(duties.build(**kwargs), start, lines.append,
                                  target="syslog-tls://siem.example.org:6514")
    return schedule, lines


def test_an_unreachable_siem_target_does_not_stop_heads_verification_or_retention():
    duties = Duties("export", "send_heads")
    start = datetime(2027, 11, 21, 3, 29, 50, tzinfo=UTC)
    schedule, lines = _schedule(duties, start)

    schedule.tick(start + timedelta(seconds=5))
    schedule.tick(datetime(2027, 11, 21, 4, 0, 1, tzinfo=UTC))

    assert duties.kept, "the signed heads reach the backup target"
    assert duties.calls.count("verify") == 1
    assert duties.calls.count("retain") == 1
    assert duties.calls.count("export") == 2
    # Heads are kept and verified before they are sent; a failed send skips nothing.
    hour = duties.calls[duties.calls.index("sign"):]
    assert hour[:4] == ["sign", "keep", "verify", "send_heads"]
    assert any("not delivered" in line for line in lines)
    assert all("{" not in line for line in lines)


def test_failed_settings_hold_export_and_retention_back_but_not_heads():
    duties = Duties("record")
    start = datetime(2027, 11, 21, 3, 59, 0, tzinfo=UTC)
    schedule, _ = _schedule(duties, start)

    schedule.tick(datetime(2027, 11, 22, 4, 0, 1, tzinfo=UTC))

    # Without recorded settings a new target's read positions may not exist yet: no export
    # and no removal, but the heads and the verification run.
    assert "export" not in duties.calls and "retain" not in duties.calls
    assert ["sign", "keep", "verify", "send_heads"] == [
        c for c in duties.calls if c in ("sign", "keep", "verify", "send_heads")
    ]

    duties.fail.clear()
    schedule.tick(datetime(2027, 11, 22, 4, 0, 6, tzinfo=UTC))
    assert duties.calls.count("record") == 2
    assert "export" in duties.calls and "retain" in duties.calls


def test_a_failed_heads_duty_still_verifies_and_retention_waits_for_its_hour():
    duties = Duties("sign")
    start = datetime(2027, 11, 21, 2, 59, 58, tzinfo=UTC)
    schedule, _ = _schedule(duties, start, with_target=False)

    schedule.tick(datetime(2027, 11, 21, 3, 0, 1, tzinfo=UTC))
    schedule.tick(datetime(2027, 11, 21, 3, 0, 6, tzinfo=UTC))

    assert duties.calls == ["record", "sign", "verify"]
    assert duties.kept == []


# ─────────────────────────────────────────────────────────────────────────
# wiring
# ─────────────────────────────────────────────────────────────────────────


def _compose() -> dict[str, Any]:
    return yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def test_the_service_gets_the_retention_role_the_settings_and_the_heads_folder():
    services = _compose()["services"]
    service, schema = services["papaia-audit"], services["papaia-audit-schema"]

    assert "audit_db_retention_password" in service["secrets"]
    assert "audit_db_retention_password" in schema["secrets"]
    assert "audit_pseudonym_key" in service["secrets"]
    assert "audit_db_owner_password" not in service["secrets"]
    env = service["environment"]
    assert env["PAPAIA_AUDIT_RETENTION_MONTHS"] == "${PAPAIA_AUDIT_RETENTION_MONTHS:-12}"
    assert set(env) == {"PAPAIA_AUDIT_RETENTION_MONTHS", "PAPAIA_AUDIT_SIEM_TARGET",
                        "PAPAIA_AUDIT_SIEM_PEN", "PAPAIA_AUDIT_SIEM_IDENTITY",
                        "PAPAIA_AUDIT_SIEM_BASIS", "PAPAIA_AUDIT_KEYCLOAK_URL",
                        "PAPAIA_AUDIT_KEYCLOAK_CA", "PAPAIA_AUDIT_REPORT_ACCOUNT_DIR"}
    (heads,) = [m for m in service["volumes"] if m["target"] == "/var/lib/papaia-audit/heads"]
    assert heads["source"] == "${PAPAIA_BACKUP_DIR}/audit-heads"
    assert heads["bind"]["create_host_path"] is False
    # Still no way out of its internal networks without a SIEM target; the third one is
    # shared with Keycloak alone (permission report).
    assert set(service["networks"]) == {"papaia-audit-net", "papaia-audit-ingest-net",
                                        "papaia-audit-idp-net"}


def test_the_store_upgrade_gives_retention_only_prune_and_its_own_events():
    sql = (SERVICE_DIR / "papaia_audit" / "schema_retention.sql").read_text(encoding="utf-8")
    grants = [line for line in sql.splitlines() if line.startswith("GRANT")]

    assert "PASSWORD" not in sql.upper()
    assert [g for g in grants if "audit_retention" in g and "EXECUTE" in g] == [
        "GRANT EXECUTE ON FUNCTION audit.prune(text, bigint, integer) TO audit_retention;",
        "GRANT EXECUTE ON FUNCTION audit.next_seq(text) TO audit_retention;",
        "GRANT EXECUTE ON FUNCTION audit.append_own(text) TO audit_retention;",
        "GRANT EXECUTE ON FUNCTION audit.setting_put(text, text) TO audit_retention;",
    ]
    assert not [g for g in grants if "audit_retention" in g and "EXECUTE" not in g
                and "CONNECT" not in g and "USAGE" not in g]
    # Events are removed by audit.prune only; updates stay refused.
    assert "CREATE TRIGGER event_no_update BEFORE UPDATE ON audit.event" in sql
    assert "current_setting('papaia_audit.prune', true)" in sql
    assert "CHECK (set_confirmed_by <> set_by)" in sql
    main = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    assert "to_regclass('audit.anchor')" in main and "SCHEMA_RETENTION_SQL" in main


def test_no_service_role_may_set_or_lift_a_deletion_lock():
    # The two-person rule needs persons proven by their tokens (CORE-041); until that route
    # exists, no role of the stack, least of all the network-facing ingest, executes them.
    sql = (SERVICE_DIR / "papaia_audit" / "schema_retention.sql").read_text(encoding="utf-8")
    grants = [line for line in sql.splitlines() if line.startswith("GRANT")]

    assert not [g for g in grants if "legal_hold_set" in g or "legal_hold_lift" in g]
    assert "REVOKE ALL ON FUNCTION audit.legal_hold_set(uuid, text, text, text, text)" in sql
    assert "REVOKE ALL ON FUNCTION audit.legal_hold_lift(text, text, text)" in sql


def test_the_image_takes_the_new_modules():
    dockerfile = (SERVICE_DIR / "Dockerfile").read_text(encoding="utf-8")
    declared = yaml.safe_load((REPO / "compat" / "own-images.yaml").read_text(encoding="utf-8"))
    (entry,) = [i for i in declared["images"] if i["name"] == "ghcr.io/fidonis/papaia-audit"]
    for name in ("retention.py", "siem.py", "schema_retention.sql"):
        assert f"src/infra/audit/papaia_audit/{name}" in dockerfile
        assert f"src/infra/audit/papaia_audit/{name}" in entry["inputs"]


def test_prepare_creates_the_retention_password_and_the_pseudonym_key(tmp_path):
    audit.prepare(tmp_path)
    secrets_dir = tmp_path / "infra" / "audit" / "secrets"

    for name in ("db-retention-password", "pseudonym-key"):
        assert (secrets_dir / name).stat().st_mode & 0o777 == 0o600
    key = (secrets_dir / "pseudonym-key").read_bytes()
    audit.prepare(tmp_path)
    assert (secrets_dir / "pseudonym-key").read_bytes() == key


def _config(tmp_path: Path, **env: str) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    return config


def test_the_heads_folder_is_made_once_on_the_backup_target(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    config = _config(tmp_path, PAPAIA_BACKUP_DIR=str(backup))

    folder = audit.ensure_heads_folder(config)

    assert folder == backup / "audit-heads" and folder.stat().st_mode & 0o777 == 0o700
    folder.rmdir()
    # The target was set up before: a missing folder is an unmounted target.
    with pytest.raises(audit.AuditError, match="not mounted"):
        audit.ensure_heads_folder(config)


def test_the_heads_folder_needs_an_existing_backup_target(tmp_path):
    with pytest.raises(audit.AuditError, match="does not exist"):
        audit.ensure_heads_folder(_config(tmp_path, PAPAIA_BACKUP_DIR=str(tmp_path / "none")))
    (tmp_path / "rel").mkdir()
    with pytest.raises(audit.AuditError, match="absolute"):
        audit.ensure_heads_folder(_config(tmp_path / "rel", PAPAIA_BACKUP_DIR="backup"))


def test_a_siem_target_puts_papaia_audit_behind_papaia_egress_only(tmp_path):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET="syslog-tls://siem.example.org",
                     PAPAIA_PROJECT="papaia")

    source = audit.egress_source(config)
    path = audit.generate_siem_override(config)

    assert source is not None and source["allow"] == [
        {"host": "siem.example.org", "ports": [6514]}
    ]
    assert source["name"] == "papaia-audit" and source["alias"] == "egress-papaia-audit"
    assert path is not None
    override = yaml.safe_load(path.read_text(encoding="utf-8"))
    service = override["services"]["papaia-audit"]
    assert set(service["networks"]) == {"papaia-audit-net", "papaia-audit-ingest-net",
                                        "papaia-audit-idp-net", "papaia-papaia-audit-egress"}
    assert service["environment"] == {
        "PAPAIA_AUDIT_SIEM_PROXY": "http://egress-papaia-audit:3128"
    }
    assert override["networks"] == {
        "papaia-papaia-audit-egress": {"name": "papaia-papaia-audit-egress", "internal": True}
    }
    assert override["services"][egress.SERVICE]["networks"]["papaia-papaia-audit-egress"] == {
        "aliases": ["egress-papaia-audit"]
    }


def test_without_a_siem_target_there_is_no_way_out(tmp_path):
    config = _config(tmp_path)
    stale = audit.siem_override_path(config)
    stale.parent.mkdir(parents=True)
    stale.write_text("services: {}\n", encoding="utf-8")

    assert audit.egress_source(config) is None
    assert audit.generate_siem_override(config) is None
    assert not stale.exists()
    assert stale not in gen_override.generate_overrides(config, REPO)


@pytest.mark.parametrize("target", ["syslog-tls://papaia-audit-db", "syslog-tls://siem",
                                    "ftp://siem.example.org", "syslog-tls://host.docker.internal"])
def test_a_siem_target_inside_the_stack_or_of_another_kind_is_refused(tmp_path, target):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET=target)

    with pytest.raises(audit.AuditError):
        audit.egress_source(config)


def test_retention_runs_in_the_container_on_request():
    assert audit.service_command("retention") == (["retention"], "")
