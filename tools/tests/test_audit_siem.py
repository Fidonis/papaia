"""papaia-audit SIEM export, second part (src/infra/audit/papaia_audit/siem.py, watch.py and
schema_siem.sql): the identity `upstream_oid`, `client_ip` of sign-in events, the
delivery state of a target, the backlog and disk thresholds with the warning mail, and
`audit siem skip` with its reason; plus the wiring in lib/audit.py.

No container runs here: the store is an in-memory double and the clock is a parameter.
The database functions are checked live by the commands under "Not run" of the change
description; here only their text and grants.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from lib import audit

REPO = Path(__file__).resolve().parents[2]
SERVICE_DIR = REPO / "src" / "infra" / "audit"
sys.path.insert(0, str(SERVICE_DIR))

from papaia_audit import core, siem, watch  # noqa: E402

CHECK = core.SubmissionCheck()
UTC = timezone.utc
T0 = datetime(2026, 11, 22, 9, 0, tzinfo=UTC)
KEY = b"p" * 32
ANNA = "4c0a9e1d-2b7f-4f53-9d0e-6a1c2b3d4e5f"
TARGET = "syslog-tls://siem.example.org:6514"
REASON = "Ziel nach Umzug neu aufgebaut, Altereignisse liegen im Archiv 2026-11"


def _body(source_seq: int, moment: datetime, **changes: Any) -> dict[str, Any]:
    body = {
        "format": "papaia.audit/1",
        "time": siem_time(moment),
        "source_seq": source_seq,
        "correlation_id": f"c-{source_seq}",
        "writer": "papaia-flow/flow-worker",
        "role": "caller",
        "sub": ANNA,
        "identity_kind": "person",
        "service_account": None,
        "azp": "flow-engine",
        "catalog_id": "paperless.documents",
        "operation": "add_note",
        "effect": "write",
        "result": "allowed",
        "event": "operation",
        "client_ip": "192.0.2.7",
    }
    body.update(changes)
    return body


def siem_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _row(seq: int, body: dict[str, Any]) -> siem.Row:
    return siem.Row("papaia-flow", seq, core.ZERO_HASH, core.ZERO_HASH, body)


# ─────────────────────────────────────────────────────────────────────────
# persons in the SIEM
# ─────────────────────────────────────────────────────────────────────────


def test_upstream_oid_needs_a_basis_like_sub():
    assert siem.parse_identity("upstream_oid", "BV-IT-2026-04") == ("upstream_oid", "BV-IT-2026-04")
    for basis in ("", "  ", "a\nb"):
        with pytest.raises(ValueError, match="BASIS"):
            siem.parse_identity("upstream_oid", basis)


UPSTREAM = ("7a1d0c55-3e3b-4d5c-9a9e-0c5f1f0e2a11", "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a")


def _contract() -> Draft202012Validator:
    schema = json.loads(
        (SERVICE_DIR / "papaia_audit" / "audit.v1.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.mark.parametrize("identity", siem.IDENTITIES)
def test_every_identity_sends_documents_valid_against_the_contract(identity):
    contract = _contract()
    rows = [
        _row(1, _body(1, T0)),
        _row(2, _body(2, T0, event="login_failed", role=None, operation=None, catalog_id=None,
                      effect=None, object_ref={"type": "user", "id": ANNA})),
    ]

    for row in rows:
        document = siem.present(row, identity, KEY)
        errors = [e.message for e in contract.iter_errors(document)]
        assert errors == [], errors


def test_upstream_oid_carries_tid_and_oid_outside_the_document_in_the_syslog_header():
    store, sender = ExportStore([_row(1, _body(1, T0))]), Sender()
    store.known = {ANNA: UPSTREAM}

    _exporter(store, sender, "upstream_oid").run_once()

    frame = sender.batches[0][0].decode()
    header, _, message = frame.partition(" {")
    assert f'tid="{UPSTREAM[0]}" oid="{UPSTREAM[1]}"]' in header
    document = json.loads("{" + message)
    assert "tid" not in document and "oid" not in document
    assert document["sub"] == siem.pseudonym(KEY, ANNA) and ANNA not in frame
    assert list(_contract().iter_errors(document)) == []


def test_upstream_oid_without_a_mapping_sends_no_upstream_parameters():
    store, sender = ExportStore([_row(1, _body(1, T0, sub="someone-else"))]), Sender()

    _exporter(store, sender, "upstream_oid").run_once()

    assert "tid=" not in sender.batches[0][0].decode()


def test_the_other_identities_send_no_upstream_parameters():
    for identity in ("pseudonym", "sub"):
        store, sender = ExportStore([_row(1, _body(1, T0))]), Sender()
        store.known = {ANNA: UPSTREAM}
        _exporter(store, sender, identity).run_once()
        assert store.asked == [] and "tid=" not in sender.batches[0][0].decode()


def test_upstream_oid_needs_a_syslog_target():
    https = siem.parse_target("https://siem.example.org/in")
    syslog = siem.parse_target(TARGET)

    with pytest.raises(ValueError, match="syslog-tls"):
        siem.check_identity_target("upstream_oid", https)
    siem.check_identity_target("upstream_oid", syslog)
    siem.check_identity_target("sub", https)
    siem.check_identity_target("upstream_oid", None)


@pytest.mark.parametrize("identity", siem.IDENTITIES)
def test_client_ip_leaves_with_sign_in_events_only(identity):
    sign_in = _row(1, _body(1, T0, event="login_failed", role=None, operation=None,
                            catalog_id=None, effect=None))
    other = _row(2, _body(2, T0))

    assert siem.present(sign_in, identity, KEY)["client_ip"] == "192.0.2.7"
    expected = "192.0.2.7" if identity == "sub" else None
    assert siem.present(other, identity, KEY)["client_ip"] == expected


class ExportStore:
    """Read positions, the delivery state and the identity map in memory."""

    def __init__(self, rows: list[siem.Row]) -> None:
        self.rows = rows
        self.positions: dict[tuple[str, str], int] = {}
        self.deliveries: list[tuple[str, bool]] = []
        self.asked: list[set[str]] = []
        self.known: dict[str, tuple[str, str]] = {ANNA: ("tenant-1", "object-1")}

    def sources(self) -> list[str]:
        return sorted({r.source for r in self.rows})

    def position(self, target: str, source: str) -> int:
        return self.positions.get((target, source), 0)

    def rows_after(self, source: str, seq: int, limit: int) -> list[siem.Row]:
        return [r for r in self.rows if r.source == source and r.seq > seq][:limit]

    def advance(self, target: str, source: str, seq: int) -> None:
        self.positions[(target, source)] = max(self.position(target, source), seq)

    def delivery(self, target: str, ok: bool) -> None:
        self.deliveries.append((target, ok))

    def upstream(self, subs: set[str]) -> dict[str, tuple[str, str]]:
        self.asked.append(set(subs))
        return {sub: ids for sub, ids in self.known.items() if sub in subs}


class Sender:
    def __init__(self) -> None:
        self.up, self.batches = True, []

    def send(self, messages):
        if not self.up:
            raise siem.ExportError("syslog target not reachable (ConnectionRefusedError)")
        self.batches.append(list(messages))

    def close(self) -> None:
        return


def _exporter(store: ExportStore, sender: Sender, identity: str = "pseudonym") -> siem.Exporter:
    settings = siem.Settings(siem.parse_target(TARGET), identity=identity)
    return siem.Exporter(store, sender, settings, KEY, clock=lambda: T0)


def test_the_exporter_records_each_cycle_as_delivered_or_failing():
    store, sender = ExportStore([_row(1, _body(1, T0))]), Sender()
    exporter = _exporter(store, sender)

    sender.up = False
    with pytest.raises(siem.ExportError):
        exporter.run_once()
    sender.up = True
    assert exporter.run_once() == 1
    assert exporter.run_once() == 0

    assert store.deliveries == [(TARGET, False), (TARGET, True), (TARGET, True)]


def test_the_exporter_looks_up_the_upstream_ids_of_a_batch_once():
    store, sender = ExportStore([_row(1, _body(1, T0)), _row(2, _body(2, T0))]), Sender()

    _exporter(store, sender, "upstream_oid").run_once()

    assert store.asked == [{ANNA}]
    frame = sender.batches[0][0].decode()
    assert 'tid="tenant-1" oid="object-1"' in frame and ANNA not in frame


# ─────────────────────────────────────────────────────────────────────────
# thresholds
# ─────────────────────────────────────────────────────────────────────────


def _health(lag: int | None = None, failing: int | None = None, *, active: bool = True,
            backlog: int | None = None, now: datetime = T0) -> watch.TargetHealth:
    oldest = None if lag is None else now - timedelta(seconds=lag)
    return watch.TargetHealth(
        target=TARGET,
        active=active,
        backlog=backlog if backlog is not None else (0 if lag is None else 3),
        oldest_undelivered=oldest,
        failing_since=None if failing is None else now - timedelta(seconds=failing),
        delivered_at=None,
    )


@pytest.mark.parametrize(
    "lag, failing, expected",
    [
        (None, None, watch.OK),
        (60, None, watch.OK),
        (61, None, watch.WARN),
        (600, None, watch.WARN),
        (601, None, watch.FAIL),
        (None, 30, watch.OK),
        (None, 61, watch.WARN),
        (None, 601, watch.FAIL),
    ],
)
def test_backlog_over_60_s_warns_and_over_10_min_fails(lag, failing, expected):
    assert watch.assess(_health(lag, failing), T0).status == expected


def test_an_inactive_target_that_holds_events_back_warns_and_names_the_skip():
    held = watch.assess(_health(4000, active=False), T0)
    done = watch.assess(_health(active=False, backlog=0), T0)

    assert held.status == watch.WARN and "audit siem skip" in held.text
    assert done.status == watch.OK


@pytest.mark.parametrize("percent, expected", [(0, watch.OK), (79, watch.OK), (80, watch.WARN),
                                                (94, watch.WARN), (95, watch.FAIL),
                                                (100, watch.FAIL)])
def test_the_volume_warns_at_80_and_fails_at_95_percent(percent, expected):
    assert watch.disk_status(percent) == expected


def test_metrics_carry_no_person_and_name_the_target():
    healths = [_health(120), _health(active=False, backlog=0)]

    metrics = watch.metrics(healths, T0 - timedelta(days=40, hours=3), {"papaia-flow": True},
                            T0)

    assert metrics["papaia_audit_export_lag_seconds"] == {TARGET: 120}
    assert metrics["papaia_audit_export_backlog"] == {TARGET: 3}
    assert metrics["papaia_audit_oldest_event_age_days"] == 40
    assert metrics["papaia_audit_verify_ok"] == {"papaia-flow": 1}


# ─────────────────────────────────────────────────────────────────────────
# warning mail
# ─────────────────────────────────────────────────────────────────────────


class Mailer:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail = fail

    def send(self, subject: str, text: str) -> None:
        if self.fail:
            raise OSError("relay down")
        self.sent.append((subject, text))


class Events:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, build) -> None:
        self.rows.append(json.loads(build(len(self.rows) + 1)))


def _receiver_down() -> list[watch.TargetHealth]:
    """The receiver went down at T0 while events kept arriving."""
    return [watch.TargetHealth(TARGET, True, 12, T0, T0, T0 - timedelta(seconds=5))]


def test_a_receiver_down_for_11_minutes_gives_fail_and_one_mail():
    mailer, events, logs = Mailer(), Events(), []
    alarm = watch.Watch(_receiver_down, mailer, events.append, CHECK, logs.append)

    for minutes in (1, 5, 10):
        alarm.run(T0 + timedelta(minutes=minutes))
    assert mailer.sent == [] and events.rows == []

    alarm.run(T0 + timedelta(minutes=11))
    alarm.run(T0 + timedelta(minutes=12))

    assert len(mailer.sent) == 1
    subject, text = mailer.sent[0]
    assert subject == watch.ALERT_SUBJECT
    assert f"Das Ziel {TARGET} nimmt seit 11 Minuten keine Ereignisse an." in text
    assert "papaia-ctl doctor siem" in text
    (event,) = events.rows
    assert event["event"] == "operation" and event["effect"] == "send"
    assert event["operation"] == "siem.alert_mail" and event["result"] == "allowed"
    assert event["object_ref"] == {"type": "siem_target", "id": TARGET}
    assert event["writer"] == watch.WRITER
    assert not [line for line in logs if "@" in line]


def test_after_recovery_a_new_outage_mails_again():
    mailer, events = Mailer(), Events()
    state = {"healths": _receiver_down()}
    alarm = watch.Watch(lambda: state["healths"], mailer, events.append, CHECK, lambda _: None)

    alarm.run(T0 + timedelta(minutes=11))
    state["healths"] = [_health(now=T0 + timedelta(minutes=20))]
    alarm.run(T0 + timedelta(minutes=20))
    state["healths"] = [watch.TargetHealth(TARGET, True, 1, T0 + timedelta(minutes=20),
                                           T0 + timedelta(minutes=20), None)]
    alarm.run(T0 + timedelta(minutes=31))

    assert len(mailer.sent) == 2 and len(events.rows) == 2


def test_a_mail_the_relay_refuses_is_recorded_as_error_and_tried_again():
    mailer, events, logs = Mailer(fail=True), Events(), []
    alarm = watch.Watch(_receiver_down, mailer, events.append, CHECK, logs.append)

    alarm.run(T0 + timedelta(minutes=11))
    mailer.fail = False
    alarm.run(T0 + timedelta(minutes=12))

    assert [e["result"] for e in events.rows] == ["error", "allowed"]
    assert events.rows[0]["error_code"] == "mail_not_sent"
    assert len(mailer.sent) == 1
    assert any("not sent" in line for line in logs)


def test_without_an_operations_address_no_mail_and_no_event_but_a_log_line():
    events, logs = Events(), []
    alarm = watch.Watch(_receiver_down, None, events.append, CHECK, logs.append)

    alarm.run(T0 + timedelta(minutes=11))

    assert events.rows == []
    assert any("no mail settings" in line for line in logs)


class AlertState:
    """The mailed outages as the store keeps them across restarts."""

    def __init__(self) -> None:
        self.keys: set[str] = set()

    def raised(self) -> set[str]:
        return set(self.keys)

    def mark(self, key: str) -> None:
        self.keys.add(key)

    def clear(self, keys: set[str]) -> None:
        self.keys -= keys


def test_a_restart_during_an_outage_sends_no_second_mail():
    mailer, events, state = Mailer(), Events(), AlertState()

    watch.Watch(_receiver_down, mailer, events.append, CHECK, lambda _: None,
                state=state).run(T0 + timedelta(minutes=11))
    restarted = watch.Watch(_receiver_down, mailer, events.append, CHECK, lambda _: None,
                            state=state)
    restarted.run(T0 + timedelta(minutes=12))

    assert len(mailer.sent) == 1 and len(events.rows) == 1
    assert state.keys == {TARGET}


def test_a_recovered_target_is_cleared_in_the_kept_state():
    mailer, events, state = Mailer(), Events(), AlertState()
    healths = {"now": _receiver_down()}
    alarm = watch.Watch(lambda: healths["now"], mailer, events.append, CHECK, lambda _: None,
                        state=state)

    alarm.run(T0 + timedelta(minutes=11))
    healths["now"] = [_health(now=T0 + timedelta(minutes=20))]
    alarm.run(T0 + timedelta(minutes=20))

    assert state.keys == set()


def test_a_sent_mail_counts_even_when_its_event_cannot_be_stored():
    mailer, state, logs = Mailer(), AlertState(), []

    def broken(build) -> None:
        raise OSError("store down")

    alarm = watch.Watch(_receiver_down, mailer, broken, CHECK, logs.append, state=state)
    with pytest.raises(OSError):
        alarm.run(T0 + timedelta(minutes=11))
    assert state.keys == {TARGET}
    for minutes in (12, 13):
        # The kept state may be out of reach as well; the service remembers it too.
        state.keys.clear()
        alarm.run(T0 + timedelta(minutes=minutes))

    assert len(mailer.sent) == 1


def test_a_full_audit_volume_gives_one_mail_and_an_operation_event():
    mailer, events, logs = Mailer(), Events(), []
    level = {"percent": 94}
    alarm = watch.Watch(list, mailer, events.append, CHECK, logs.append,
                        disk=lambda: level["percent"])

    alarm.run(T0)
    assert mailer.sent == []
    level["percent"] = 96
    alarm.run(T0 + timedelta(minutes=1))
    alarm.run(T0 + timedelta(minutes=2))

    assert len(mailer.sent) == 1
    subject, text = mailer.sent[0]
    assert subject == watch.DISK_SUBJECT
    assert "papaia-audit-db" in text and "96 %" in text and "papaia-ctl doctor siem" in text
    (event,) = events.rows
    assert event["event"] == "operation" and event["effect"] == "send"
    assert event["operation"] == "store.disk_alert_mail" and event["result"] == "allowed"
    assert event["object_ref"] == {"type": "volume", "id": "papaia-audit-db"}
    assert list(_contract().iter_errors(dict(event, source="papaia-audit", seq=1,
                                             prev_hash="sha256:" + "0" * 64,
                                             hash="sha256:" + "0" * 64))) == []

    level["percent"] = 90
    alarm.run(T0 + timedelta(minutes=3))
    level["percent"] = 97
    alarm.run(T0 + timedelta(minutes=4))
    assert len(mailer.sent) == 2


def test_an_unreadable_volume_sends_no_mail():
    mailer, events = Mailer(), Events()

    watch.Watch(list, mailer, events.append, CHECK, lambda _: None,
                disk=lambda: None).run(T0)

    assert mailer.sent == [] and events.rows == []


class Statvfs:
    def __init__(self, blocks: int, free: int, avail: int) -> None:
        self.f_frsize, self.f_blocks, self.f_bfree, self.f_bavail = 4096, blocks, free, avail


class Stat:
    def __init__(self, dev: int) -> None:
        self.st_dev = dev


def test_the_volume_level_is_that_of_df_and_only_of_a_mounted_volume():
    devices = {"/var/lib/papaia-audit/db-volume": 7, "/var/lib/papaia-audit": 1}

    def stat(path: str) -> Stat:
        return Stat(devices[path])

    # 960 of 1000 blocks used, 30 free for root only: df shows 970/1000 used of usable.
    level = watch.volume_percent("/var/lib/papaia-audit/db-volume",
                                 statvfs=lambda _: Statvfs(1000, 40, 10), stat=stat)
    assert level == 99
    assert watch.volume_percent("/var/lib/papaia-audit/db-volume",
                                statvfs=lambda _: Statvfs(1000, 500, 500), stat=stat) == 50
    devices["/var/lib/papaia-audit/db-volume"] = 1
    assert watch.volume_percent("/var/lib/papaia-audit/db-volume",
                                statvfs=lambda _: Statvfs(1000, 500, 500), stat=stat) is None


def test_the_disk_alert_and_the_kept_state_are_in_the_schema():
    sql = _sql()
    own = sql[sql.index("CREATE OR REPLACE FUNCTION audit.append_own"):]
    own = own[: own.index("$$;")]

    assert "'store.disk_alert_mail'" in own
    assert "CREATE TABLE audit.alert_state" in sql
    assert "GRANT EXECUTE ON FUNCTION audit.alert_mark(text) TO audit_retention;" in sql
    assert "GRANT EXECUTE ON FUNCTION audit.alert_clear(text[]) TO audit_retention;" in sql


def test_the_service_mounts_the_database_volume_read_only_for_its_fill_level():
    compose = yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    mounts = compose["services"]["papaia-audit"]["volumes"]

    (mount,) = [m for m in mounts if m.get("source") == "papaia-audit-pgdata"]
    assert mount["type"] == "volume" and mount["read_only"] is True
    assert mount["target"] == watch.DB_VOLUME
    assert mount["volume"] == {"nocopy": True}


@pytest.mark.parametrize("relay, to, sender", [
    ("smtp-relay", "ops@example.org", "papaia@example.org"),
    ("smtp-relay:587", "ops@example.org, x@example.org", "papaia@example.org"),
    ("smtp-relay:587", "ops@example.org\nBcc: x@example.org", "papaia@example.org"),
    ("smtp-relay:587", "ops@example.org", ""),
])
def test_mail_settings_are_one_address_each_and_a_relay_with_port(relay, to, sender):
    with pytest.raises(ValueError):
        watch.parse_mail(relay, to, sender)


def test_no_mail_settings_mean_no_mailer():
    assert watch.parse_mail("", "", "") is None
    assert watch.parse_mail("smtp-relay:587", "ops@example.org", "papaia@example.org") == (
        watch.MailSettings("smtp-relay", 587, "ops@example.org", "papaia@example.org")
    )


# ─────────────────────────────────────────────────────────────────────────
# audit siem skip
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason", ["", "   ", "zu kurz", "x" * 1001, REASON[:30] + "\x07" + REASON]
)
def test_skip_without_a_reason_is_refused(reason):
    with pytest.raises(audit.AuditError, match="reason"):
        audit.siem_skip_command("papaia-flow", "120", reason)
    with pytest.raises(ValueError, match="reason"):
        watch.parse_skip({"source": "papaia-flow", "until": 120, "reason": reason, "target": None})


@pytest.mark.parametrize("source, until", [("Papaia Flow", "12"), ("papaia-flow", "0"),
                                           ("papaia-flow", "-3"), ("papaia-flow", "12a"),
                                           ("papaia-flow", "")])
def test_skip_needs_a_source_and_a_positive_seq(source, until):
    with pytest.raises(audit.AuditError):
        audit.siem_skip_command(source, until, REASON)


def test_the_skip_request_travels_on_stdin_and_is_checked_again_in_the_service():
    argv, stdin = audit.siem_skip_command("papaia-flow", "120", REASON, TARGET)

    assert argv == ["siem-skip"]
    request = json.loads(stdin)
    assert request == {"source": "papaia-flow", "until": 120, "reason": REASON, "target": TARGET}
    assert watch.parse_skip(request) == watch.Skip("papaia-flow", 120, REASON, TARGET)
    with pytest.raises(ValueError):
        watch.parse_skip({**request, "extra": 1})
    with pytest.raises(ValueError):
        watch.parse_skip({**request, "until": True})


def test_the_skip_event_names_source_target_and_count_never_the_reason():
    event = json.loads(watch.skip_event(CHECK, source="papaia-flow", target=TARGET, released=7,
                                        moment=T0, source_seq=4, correlation_id="skip-1"))

    assert event["event"] == "config_changed" and event["operation"] == "siem.skip"
    assert event["effect"] == "delete" and event["detail"] == {"count": 7}
    assert event["object_ref"] == {"type": "siem_position", "id": f"papaia-flow@{TARGET}"}
    assert REASON not in json.dumps(event)


def _sql() -> str:
    return (SERVICE_DIR / "papaia_audit" / "schema_siem.sql").read_text(encoding="utf-8")


def test_the_store_refuses_a_skip_without_a_reason_and_releases_inactive_targets_too():
    sql = _sql()
    skip = sql[sql.index("CREATE FUNCTION audit.export_skip"):]
    skip = skip[: skip.index("$$;")]

    assert "char_length(btrim(p_reason)) NOT BETWEEN 20 AND 1000" in skip
    # Every target, active or not, unless one is named.
    assert "FROM audit.export_target t" in skip and "t.active" not in skip
    assert "INSERT INTO audit.export_skip" in skip
    assert re.search(r"GRANT EXECUTE ON FUNCTION audit\.export_skip\([^)]*\) TO audit_retention;",
                     sql)
    assert "TO audit_ingest" not in re.findall(r"GRANT EXECUTE ON FUNCTION audit\.export_skip.*",
                                               sql)[0]


def test_skip_rows_cannot_be_changed_and_the_identity_map_only_through_its_function():
    sql = _sql()

    for table in ("export_skip",):
        assert f"BEFORE UPDATE OR DELETE ON audit.{table}" in sql
        assert f"BEFORE TRUNCATE ON audit.{table}" in sql
    assert (
        "GRANT EXECUTE ON FUNCTION audit.identity_put(text, text, text, text) TO audit_ingest;"
        in sql
    )
    assert "GRANT EXECUTE ON FUNCTION audit.export_delivery(text, boolean) TO audit_ingest;" in sql
    assert not re.search(r"GRANT (INSERT|UPDATE|DELETE)", sql)


def test_own_events_of_the_siem_writer_are_only_the_skip_and_the_warning_mail():
    sql = _sql()
    own = sql[sql.index("CREATE OR REPLACE FUNCTION audit.append_own"):]
    own = own[: own.index("$$;")]

    assert "'papaia-audit/siem'" in own
    assert "'siem.skip'" in own and "'siem.alert_mail'" in own


def test_the_schema_step_adds_the_siem_part_to_an_existing_store():
    main = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    dockerfile = (SERVICE_DIR / "Dockerfile").read_text(encoding="utf-8")
    declared = yaml.safe_load((REPO / "compat" / "own-images.yaml").read_text(encoding="utf-8"))
    (entry,) = [i for i in declared["images"] if i["name"] == "ghcr.io/fidonis/papaia-audit"]

    assert "to_regclass('audit.person_identity')" in main
    for name in ("watch.py", "schema_siem.sql"):
        assert f"src/infra/audit/papaia_audit/{name}" in dockerfile
        assert f"src/infra/audit/papaia_audit/{name}" in entry["inputs"]


def _function(name: str) -> str:
    main = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    text = main[main.index(f"def {name}("):]
    return text[: text.index("\n\n\n")]


def test_the_backlog_is_counted_by_range_on_the_primary_key():
    query = _function("export_health")

    # No correlated lookup per stored event: per target and source a range from the read position.
    assert "c.source = e.source" not in query
    assert "LATERAL" in query and "e.source = s.source AND e.seq >" in query
    # The sources by a skip scan over the primary key, not by reading every event.
    assert "_SOURCES + " in query
    main = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    assert re.search(r'_SOURCES = """\s+WITH RECURSIVE s\(source\)', main)


def test_the_siem_report_takes_the_hourly_verification_instead_of_verifying_again():
    status = _function("siem_status")
    hourly = _function("verify_chains")

    assert "verify_all" not in status and "audit.verify_state" in status
    assert "audit.verify_record" in hourly


def test_the_hourly_verification_is_kept_for_the_report():
    sql = _sql()

    assert "CREATE TABLE audit.verify_state" in sql
    assert ("GRANT EXECUTE ON FUNCTION audit.verify_record(text, boolean, bigint) TO "
            "audit_retention;") in sql
    assert "GRANT SELECT ON audit.person_identity, audit.export_skip, audit.alert_state," in sql


def test_the_report_carries_the_age_of_the_last_verification():
    shown = watch.report([], None, {"papaia-flow": True}, T0,
                         verified_at=T0 - timedelta(minutes=50))
    never = watch.report([], None, {}, T0, verified_at=None)

    assert shown["metrics"]["papaia_audit_verify_age_seconds"] == 3000
    assert never["metrics"]["papaia_audit_verify_age_seconds"] is None


# ─────────────────────────────────────────────────────────────────────────
# wiring
# ─────────────────────────────────────────────────────────────────────────


def _config(tmp_path: Path, **env: str) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    return config


def _with_relay(config: Path) -> None:
    relay = config / "infra" / "smtp-relay"
    relay.mkdir(parents=True)
    (relay / ".env").write_text(
        "SMTP_RELAY_UPSTREAM_HOST=mail.example.org\nSMTP_RELAY_FROM_ADDRESS=papaia@example.org\n",
        encoding="utf-8",
    )


def test_the_warning_mail_goes_through_the_relay_on_the_egress_network_only(tmp_path):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET="syslog-tls://siem.example.org",
                     PAPAIA_PROJECT="papaia", COMPOSE_PROFILES="audit,smtp",
                     PAPAIA_OPERATIONS_MAIL="ops@example.org")
    _with_relay(config)

    override = yaml.safe_load(audit.generate_siem_override(config).read_text(encoding="utf-8"))

    service = override["services"]["papaia-audit"]
    assert service["environment"]["PAPAIA_AUDIT_MAIL_RELAY"] == "smtp-relay:587"
    assert service["environment"]["PAPAIA_AUDIT_ALERT_TO"] == "ops@example.org"
    assert service["environment"]["PAPAIA_AUDIT_ALERT_FROM"] == "papaia@example.org"
    # The relay joins the audit egress network; it never joins papaia-audit-net.
    assert override["services"]["smtp-relay"]["networks"] == {
        "papaia-net": {}, "papaia-papaia-audit-egress": {}
    }


@pytest.mark.parametrize("env", [
    {"COMPOSE_PROFILES": "audit,smtp"},
    {"COMPOSE_PROFILES": "audit", "PAPAIA_OPERATIONS_MAIL": "ops@example.org"},
])
def test_without_address_or_relay_no_mail_is_wired(tmp_path, env):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET="syslog-tls://siem.example.org", **env)
    _with_relay(config)

    override = yaml.safe_load(audit.generate_siem_override(config).read_text(encoding="utf-8"))

    assert "smtp-relay" not in override["services"]
    assert "PAPAIA_AUDIT_ALERT_TO" not in override["services"]["papaia-audit"]["environment"]


def test_setup_refuses_upstream_oid_for_an_https_target(tmp_path):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET="https://siem.example.org/in",
                     PAPAIA_AUDIT_SIEM_IDENTITY="upstream_oid",
                     PAPAIA_AUDIT_SIEM_BASIS="BV-IT-2026-04", COMPOSE_PROFILES="audit")

    with pytest.raises(audit.AuditError, match="syslog-tls"):
        audit.generate_siem_override(config)


def test_a_malformed_operations_address_is_refused(tmp_path):
    config = _config(tmp_path, PAPAIA_AUDIT_SIEM_TARGET="syslog-tls://siem.example.org",
                     COMPOSE_PROFILES="audit,smtp",
                     PAPAIA_OPERATIONS_MAIL="ops@example.org,boss@example.org")
    _with_relay(config)

    with pytest.raises(audit.AuditError, match="PAPAIA_OPERATIONS_MAIL"):
        audit.generate_siem_override(config)


def test_the_new_service_commands_run_in_the_container():
    assert audit.service_command("siem-status") == (["siem-status"], "")
    with pytest.raises(audit.AuditError):
        audit.service_command("siem-skip")


TICKET = "6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"


def test_idmap_runs_in_the_container_with_the_token_on_stdin_never_in_argv():
    token = "header.payload.signature"
    argv, stdin = audit.idmap_command(TICKET, token, pseud="P-ABCDEFGH")

    assert argv == ["idmap"] and token not in " ".join(argv)
    assert json.loads(stdin) == {"token": token, "request": {"ticket": TICKET,
                                                             "pseud": "P-ABCDEFGH"}}
    _, back = audit.idmap_command(TICKET, token, tid="tenant-1", oid="object-1")
    assert json.loads(back)["request"] == {"ticket": TICKET, "tid": "tenant-1", "oid": "object-1"}


@pytest.mark.parametrize("kwargs", [
    {"pseud": "P-ABCDEFGH", "tid": "t", "oid": "o"},
    {},
    {"tid": "t"},
    {"pseud": "anna"},
])
def test_idmap_takes_one_direction(kwargs):
    with pytest.raises(audit.AuditError):
        audit.idmap_command(TICKET, "a.b.c", **kwargs)


@pytest.mark.parametrize("ticket, token", [("not-a-ticket", "a.b.c"), (TICKET, ""),
                                           (TICKET, "a b")])
def test_idmap_needs_a_ticket_and_a_token(ticket, token):
    with pytest.raises(audit.AuditError):
        audit.idmap_command(ticket, token, pseud="P-ABCDEFGH")


def test_the_upkeep_watches_the_targets_every_minute_once_the_settings_are_recorded():
    from papaia_audit import retention

    seen: list[datetime] = []
    state = {"recorded": False}

    def record() -> None:
        if not state["recorded"]:
            raise OSError("database not up yet")

    duties = retention.Duties(
        record=record, export=lambda: 0, sign=dict, keep=lambda heads: None,
        verify=lambda: None, send_heads=None, retain=lambda: None, watch=seen.append,
    )
    schedule = retention.Schedule(duties, T0, lambda line: None, TARGET)

    schedule.tick(T0)
    state["recorded"] = True
    for seconds in (5, 30, 64, 70, 130):
        schedule.tick(T0 + timedelta(seconds=seconds))

    assert seen == [T0 + timedelta(seconds=5), T0 + timedelta(seconds=70),
                    T0 + timedelta(seconds=130)]
