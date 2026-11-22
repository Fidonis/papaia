"""papaia-audit person routes of CORE-041 without containers
(src/infra/audit/papaia_audit/access.py): the gate of the permission report (role
`papaia-auditor`, one event per retrieval, also a refused one), the recertification of
report rows (role `papaia-admin`), and the deletion lock set and lifted by two persons
with `papaia-legal-hold`, each change in one transaction with its own event.

Tokens and the store double come from test_audit_read.py.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "infra" / "audit"))

from papaia_audit import access, read  # noqa: E402
from test_audit_read import (  # noqa: E402
    ANNA,
    BERT,
    CHECK,
    DANA,
    DORA,
    EMIL,
    NOW,
    PSEUDONYM_KEY,
    SERVICE_DIR,
    STORED,
    Api,
    FakeStore,
    _claims,
    _event,
    signer,  # noqa: F401  (fixture)
)

from lib import audit  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CHECKSUM = "sha256:" + "ab" * 32
DIGEST = "sha256:" + "cd" * 32
REASON = "Anordnung der Rechtsabteilung zum Verfahren 2026-031, Sicherung"
LEGAL = ("papaia-legal-hold",)
FRANZ = "6e5f4a3b-2c1d-4e0f-9a8b-7c6d5e4f3a2b"  # papaia-legal-hold


class AccessStore(FakeStore):
    """FakeStore plus confirmations, hold requests and holds; every change only
    together with its own event, like the database functions."""

    def __init__(self) -> None:
        super().__init__()
        self.confirmations: list[access.Confirmation] = []
        self.requests: dict[str, access.HoldRequest] = {}
        self.holds: dict[str, dict] = {}

    def confirmations_latest(self):
        latest: dict[str, access.Confirmation] = {}
        for item in self.confirmations:
            latest[item.key] = item
        return [latest[k] for k in sorted(latest)]

    def add_confirmation(self, confirmation, build) -> None:
        event = self._own_event(build)
        self.confirmations.append(confirmation)
        self.add("papaia-audit", event)

    def add_hold_request(self, request, build) -> None:
        event = self._own_event(build)
        self.requests[request.id] = request
        self.add("papaia-audit", event)

    def get_hold_request(self, request_id):
        found = self.requests.get(request_id)
        return None if found is None else access.HoldRequest(**vars(found))

    def open_hold_requests(self, since):
        return [r for r in self.requests.values() if r.state == "open" and r.requested_at > since]

    def active_holds(self):
        return sorted(
            (sub, hold["set_at"]) for sub, hold in self.holds.items() if hold["lifted"] is None
        )

    def hold_active(self, sub: str) -> bool:
        return sub in self.holds and self.holds[sub]["lifted"] is None

    def decide_hold_request(self, request_id, state, by, at, build) -> bool:
        request = self.requests[request_id]
        if request.state != "open":
            return False
        event = self._own_event(build)  # nothing below happens without it (rollback)
        if state == "confirmed":
            assert by != request.requested_by  # the database refuses it as well
            if request.action == "set":
                if self.hold_active(request.sub):
                    return False
                self.holds[request.sub] = {
                    "set_by": request.requested_by,
                    "confirmed_by": by,
                    "set_at": at,
                    "lifted": None,
                }
            else:
                if not self.hold_active(request.sub):
                    return False
                self.holds[request.sub]["lifted"] = (request.requested_by, by, at)
        request.state, request.decided_by, request.decided_at = state, by, at
        self.add("papaia-audit", event)
        return True


@pytest.fixture
def store() -> AccessStore:
    return AccessStore()


class AccessCaller(Api):
    def __init__(self, signer, store) -> None:  # noqa: F811
        super().__init__(signer, store)
        self.api = access.AccessApi(
            store, lambda: signer.keys, PSEUDONYM_KEY, CHECK, clock=lambda: self.now
        )


@pytest.fixture
def api(signer, store) -> Api:  # noqa: F811
    return AccessCaller(signer, store)


def _report(api: Api, sub: str = DANA, roles=("papaia-auditor",), by: str = "person", **kw):
    body = {"by": by, "rows": 3, "checksum": CHECKSUM}
    body.update(kw)
    return api.call("POST", "/v1/access-reports", sub, roles=roles, body=body, caller="papaia-ctl")


def _valid(event: dict) -> None:
    zero = "sha256:" + "0" * 64
    stored = dict(event, source="papaia-audit", seq=1, prev_hash=zero, hash=zero)
    errors = list(STORED.iter_errors(stored))
    assert not errors, errors


# ─────────────────────────────────────────────────────────────────────────
# permission report: the gate
# ─────────────────────────────────────────────────────────────────────────


def test_an_auditor_retrieves_the_report_and_each_retrieval_is_an_event(api):
    for _ in range(2):
        status, answer = _report(api)
        assert status == 200, answer
        assert answer == {"confirmations": []}

    events = api.store.own("inventory_exported")
    assert len(events) == 2
    for event in events:
        _valid(event)
        assert event["sub"] == DANA and event["result"] == "allowed"
        assert event["operation"] == "access_report.person"
        assert event["object_ref"] == {"type": "access_report", "id": CHECKSUM}
        assert event["detail"] == {"rows": 3} and event["effect"] == "read"
        assert event["writer"] == "papaia-audit/access"


@pytest.mark.parametrize(
    "roles", [(), ("papaia-admin",), ("papaia-operator", "papaia-admin"), ("papaia-legal-hold",)]
)
def test_without_the_auditor_role_the_report_is_refused_and_still_audited(api, roles):
    status, problem = _report(api, DORA, roles)

    assert status == 403 and problem["code"] == "AUDIT-REPORT-403"
    (event,) = api.store.own("inventory_exported")
    _valid(event)
    assert event["result"] == "denied" and event["sub"] == DORA
    assert event["error_code"] == "AUDIT-REPORT-403"


def test_the_report_gate_answers_only_the_reading_clients(api):
    status, _ = api.call(
        "POST",
        "/v1/access-reports",
        DANA,
        body={"by": "person", "rows": 1, "checksum": CHECKSUM},
        caller="papaia-flow",
    )
    assert status == 404 and api.store.own() == []


@pytest.mark.parametrize(
    "body",
    [
        {"by": "people", "rows": 1, "checksum": CHECKSUM},
        {"by": "person", "rows": -1, "checksum": CHECKSUM},
        {"by": "person", "rows": True, "checksum": CHECKSUM},
        {"by": "person", "rows": 100_001, "checksum": CHECKSUM},
        {"by": "person", "rows": 1, "checksum": "ab" * 32},
        {"by": "person", "rows": 1, "checksum": CHECKSUM, "extra": 1},
        {"by": "person", "rows": 1},
    ],
)
def test_the_report_gate_validates_its_body(api, body):
    status, problem = api.call("POST", "/v1/access-reports", DANA, body=body, caller="papaia-ctl")
    assert status == 400 and problem["class"] == "invalid_input"
    assert api.store.own() == []


def test_the_host_reaches_only_the_report_routes_with_the_token_on_stdin(api, signer):  # noqa: F811
    token = signer(_claims(DANA, ("papaia-auditor",)))
    body = {"by": "system", "rows": 0, "checksum": CHECKSUM}
    text = json.dumps(
        {"method": "POST", "path": "/v1/access-reports", "authorization": f"Bearer {token}",
         "body": body}
    )
    request = access.host_request(text)
    assert request is not None and request.caller == "papaia-ctl"
    response = api.api.handle(request)
    assert response.status == 200
    for bad in (
        text.replace("/v1/access-reports", "/v1/events"),
        text.replace('"POST"', '"GET"'),
        json.dumps({"method": "POST", "path": "/v1/access-reports", "body": body}),
        text[:-1] + ', "caller": "papaia-manager"}',
        "[]",
        "{",
        " " * (access.HOST_REQUEST_MAX + 1),
    ):
        assert access.host_request(bad) is None, bad


def test_without_its_event_the_report_is_not_released(api):
    api.store.fail_own = True
    status, _ = _report(api)
    assert status == 503


# ─────────────────────────────────────────────────────────────────────────
# recertification
# ─────────────────────────────────────────────────────────────────────────


def _confirm(api: Api, key: str, sub: str = DORA, roles=("papaia-admin",), digest=DIGEST):
    return api.call(
        "POST",
        "/v1/access-reports/confirmations",
        sub,
        roles=roles,
        body={"key": key, "digest": digest},
        caller="papaia-manager",
    )


def test_the_administration_confirms_a_row_and_the_report_carries_the_date(api):
    status, answer = _confirm(api, f"person:{BERT}")
    assert status == 201, answer
    assert answer["key"] == f"person:{BERT}" and answer["digest"] == DIGEST

    (event,) = api.store.own("approval_changed")
    _valid(event)
    assert event["sub"] == DORA and event["operation"] == "access_report.confirmed"
    assert event["object_ref"] == {"type": "person", "id": BERT}
    assert event["time"] == answer["confirmed_at"]

    status, report = _report(api)
    assert status == 200
    (row,) = report["confirmations"]
    assert row["key"] == f"person:{BERT}" and row["digest"] == DIGEST
    assert row["confirmed_at"] == answer["confirmed_at"]
    # Who confirmed is shown as pseudonym, never as sub.
    assert row["confirmed_by"] == read.pseudonym(PSEUDONYM_KEY, DORA)


def test_a_system_row_is_confirmed_with_its_catalog_entry(api):
    status, _ = _confirm(api, "system:paperless.documents")
    assert status == 201
    (event,) = api.store.own("approval_changed")
    assert event["object_ref"] == {"type": "catalog_entry", "id": "paperless.documents"}


def test_nobody_confirms_their_own_row(api):
    status, problem = _confirm(api, f"person:{DORA}")
    assert status == 403 and problem["code"] == "AUDIT-REPORT-SELF"
    (event,) = api.store.own("approval_changed")
    assert event["result"] == "denied" and api.store.confirmations == []


@pytest.mark.parametrize("roles", [(), ("papaia-auditor",), ("papaia-legal-hold",)])
def test_only_the_administration_confirms_rows(api, roles):
    status, problem = _confirm(api, f"person:{BERT}", DANA, roles)
    assert status == 403 and problem["code"] == "AUDIT-REPORT-ADMIN"
    assert api.store.confirmations == []


@pytest.mark.parametrize(
    "body",
    [
        {"key": "user:abc", "digest": DIGEST},
        {"key": "person:", "digest": DIGEST},
        {"key": "person:" + "a" * 300, "digest": DIGEST},
        {"key": f"person:{BERT}", "digest": "md5:00"},
        {"key": f"person:{BERT}"},
        {"key": f"person:{BERT}", "digest": DIGEST, "by": DORA},
        # '|' is valid in a subject but not in the id of the event's object_ref.
        {"key": "system:papaia|flow", "digest": DIGEST},
        {"key": "person:idp|bert", "digest": DIGEST},
    ],
)
def test_a_confirmation_is_validated(api, body):
    status, _ = api.call(
        "POST",
        "/v1/access-reports/confirmations",
        DORA,
        roles=("papaia-admin",),
        body=body,
        caller="papaia-manager",
    )
    assert status == 400 and api.store.confirmations == []


def test_a_confirmation_is_not_stored_without_its_event(api):
    api.store.fail_own = True
    status, _ = _confirm(api, f"person:{BERT}")
    assert status == 503 and api.store.confirmations == []


# ─────────────────────────────────────────────────────────────────────────
# deletion lock: two persons with papaia-legal-hold
# ─────────────────────────────────────────────────────────────────────────


def _hold(api: Api, action: str = "set", by: str = FRANZ, person: str = ANNA, **claims):
    return api.call(
        "POST",
        "/v1/legal-holds",
        by,
        roles=LEGAL,
        body={"action": action, "person": person, "reason": REASON},
        **claims,
    )


def _decide(api: Api, request_id: str, decision: str = "confirm", by: str = EMIL, **claims):
    return api.call(
        "POST", f"/v1/legal-holds/{request_id}/{decision}", by, roles=LEGAL, **claims
    )


def test_two_persons_set_a_lock_and_the_event_names_both(api):
    status, view = _hold(api)
    assert status == 201, view
    assert view["state"] == "open" and view["action"] == "set"
    assert api.store.holds == {}
    (requested,) = api.store.own("approval_changed")
    _valid(requested)
    assert requested["operation"] == "legal_hold.set.requested" and requested["sub"] == FRANZ

    status, view = _decide(api, view["id"])
    assert status == 200, view
    assert view["state"] == "confirmed"
    hold = api.store.holds[ANNA]
    assert (hold["set_by"], hold["confirmed_by"]) == (FRANZ, EMIL)
    (event,) = api.store.own("legal_hold_set")
    _valid(event)
    assert event["sub"] == EMIL and event["operation"] == "legal_hold.set"
    assert event["object_ref"] == {"type": "person", "id": ANNA}
    assert event["effect"] == "write" and event["writer"] == "papaia-audit/hold"


@pytest.mark.parametrize("four_eyes", ["on", "off"])
def test_one_person_alone_can_neither_set_nor_lift_a_lock(api, monkeypatch, four_eyes):
    monkeypatch.setenv("PAPAIA_APPROVALS_FOUR_EYES", four_eyes)
    _, view = _hold(api)
    status, problem = _decide(api, view["id"], by=FRANZ)
    assert status == 403 and problem["code"] == "AUDIT-HOLD-SELF"
    assert api.store.holds == {} and api.store.requests[view["id"]].state == "open"
    denied = [e for e in api.store.own("approval_changed") if e["result"] == "denied"]
    assert len(denied) == 1 and denied[0]["error_code"] == "AUDIT-HOLD-SELF"

    _decide(api, view["id"])
    _, lift = _hold(api, "lift", by=EMIL)
    status, problem = _decide(api, lift["id"], by=EMIL)
    assert status == 403 and api.store.holds[ANNA]["lifted"] is None


def test_two_persons_lift_a_lock(api):
    _, view = _hold(api)
    _decide(api, view["id"])
    _, lift = _hold(api, "lift", by=EMIL)
    status, view = _decide(api, lift["id"], by=FRANZ)
    assert status == 200, view
    assert api.store.holds[ANNA]["lifted"][:2] == (EMIL, FRANZ)
    (event,) = api.store.own("legal_hold_lifted")
    _valid(event)
    assert event["sub"] == FRANZ and event["operation"] == "legal_hold.lift"


def test_a_lift_without_a_lock_and_a_second_lock_are_refused(api):
    assert _hold(api, "lift")[0] == 409
    _, view = _hold(api)
    _decide(api, view["id"])
    assert _hold(api, "set", by=EMIL)[0] == 409


@pytest.mark.parametrize(
    "roles", [(), ("papaia-admin",), ("papaia-auditor",), ("papaia-admin", "papaia-auditor")]
)
def test_only_papaia_legal_hold_reaches_the_lock_routes(api, roles):
    for method, path, body in (
        ("GET", "/v1/legal-holds", None),
        ("POST", "/v1/legal-holds", {"action": "set", "person": ANNA, "reason": REASON}),
        ("POST", "/v1/legal-holds/00000000-0000-4000-8000-000000000000/confirm", None),
    ):
        status, problem = api.call(method, path, DANA, roles=roles, body=body)
        assert status == 403 and problem["code"] == "AUDIT-HOLD-403"
    assert api.store.requests == {}


def test_requesting_and_confirming_need_a_fresh_sign_in(api):
    stale = {"auth_time": int(NOW) - 600}
    status, problem = _hold(api, **stale)
    assert status == 401 and problem["code"] == "AUDIT-AUTH-FRESH"
    _, view = _hold(api)
    status, _ = _decide(api, view["id"], **stale)
    assert status == 401 and api.store.holds == {}


@pytest.mark.parametrize(
    "body",
    [
        {"action": "set", "person": ANNA, "reason": "zu kurz"},
        {"action": "freeze", "person": ANNA, "reason": REASON},
        {"action": "set", "person": "not a sub!", "reason": REASON},
        {"action": "set", "person": "idp|anna", "reason": REASON},
        {"action": "set", "person": ANNA, "reason": REASON, "set_by": EMIL},
        {"action": "set", "person": ANNA, "reason": REASON, "confirmed_by": EMIL},
        {"action": "set", "person": ANNA},
    ],
)
def test_a_lock_request_is_validated_and_takes_no_person_from_the_body(api, body):
    status, _ = api.call("POST", "/v1/legal-holds", FRANZ, roles=LEGAL, body=body)
    assert status == 400 and api.store.requests == {}


def test_a_rejected_request_sets_nothing_and_is_an_event(api):
    _, view = _hold(api)
    status, view = _decide(api, view["id"], "reject")
    assert status == 200 and view["state"] == "rejected"
    assert api.store.holds == {}
    ops = [e["operation"] for e in api.store.own("approval_changed")]
    assert ops == ["legal_hold.set.requested", "legal_hold.set.rejected"]
    assert _decide(api, view["id"])[0] == 409


def test_the_lock_list_shows_pseudonyms_and_reasons(api):
    _, view = _hold(api)
    status, listing = api.call("GET", "/v1/legal-holds", EMIL, roles=LEGAL)
    assert status == 200
    (open_request,) = listing["requests"]
    assert open_request["person"] == read.pseudonym(PSEUDONYM_KEY, ANNA)
    assert open_request["reason"] == REASON and open_request["own"] is False
    assert ANNA not in json.dumps(listing) and FRANZ not in json.dumps(listing)
    _decide(api, view["id"])
    _, listing = api.call("GET", "/v1/legal-holds", EMIL, roles=LEGAL)
    assert listing["requests"] == []
    assert [h["person"] for h in listing["holds"]] == [read.pseudonym(PSEUDONYM_KEY, ANNA)]


def test_open_lock_requests_expire_after_24_hours(api):
    _, view = _hold(api)
    api.now += timedelta(hours=24, seconds=1).total_seconds()
    status, _ = _decide(api, view["id"], auth_time=int(api.now) - 10)
    assert status == 404 and api.store.holds == {}


def test_a_lock_is_not_changed_without_its_event(api):
    _, view = _hold(api)
    api.store.fail_own = True
    status, _ = _decide(api, view["id"])
    assert status == 503 and api.store.holds == {}
    assert api.store.requests[view["id"]].state == "open"


def test_a_lock_request_for_a_pseudonym_resolves_it_from_the_log(api):
    api.store.add("papaia-flow", _event(1, BERT, "2026-11-02T08:00:00.000Z"))
    status, view = _hold(api, person=read.pseudonym(PSEUDONYM_KEY, BERT))
    assert status == 201
    assert api.store.requests[view["id"]].sub == BERT
    assert _hold(api, person="P-AAAAAAAA")[0] == 404


# ─────────────────────────────────────────────────────────────────────────
# database and wiring
# ─────────────────────────────────────────────────────────────────────────

ACCESS_SQL = (SERVICE_DIR / "papaia_audit" / "schema_access.sql").read_text(encoding="utf-8")
RETENTION_SQL = (SERVICE_DIR / "papaia_audit" / "schema_retention.sql").read_text(encoding="utf-8")


def _grants(text: str) -> list[tuple[str, str]]:
    found = re.findall(r"GRANT EXECUTE ON FUNCTION ([a-z_.]+)\([^)]*\)\s+TO ([a-z_]+);", text)
    return [(name, role) for name, role in found]


def test_the_lock_functions_are_reached_only_by_the_hold_role():
    grants = _grants(ACCESS_SQL) + _grants(RETENTION_SQL)
    for name, role in grants:
        if "legal_hold" in name:
            assert role == "audit_hold", (name, role)
    assert ("audit.legal_hold_confirm", "audit_hold") in grants
    assert ("audit.legal_hold_request_add", "audit_hold") in grants
    assert ("audit.append_hold", "audit_hold") in grants
    assert "CREATE ROLE audit_hold LOGIN" in ACCESS_SQL
    # The hold role appends only its own events, nothing else of the log.
    assert not re.search(r"GRANT EXECUTE ON FUNCTION audit\.append\(", ACCESS_SQL)
    assert "papaia-audit/hold" in ACCESS_SQL


def test_row_keys_are_valid_object_ref_ids_of_the_vendored_schema():
    schema = json.loads((SERVICE_DIR / "papaia_audit" / "audit.v1.schema.json").read_text())
    id_rule = schema["$defs"]["object_ref"]["properties"]["id"]["allOf"][1]
    id_re = re.compile(id_rule["pattern"])
    name = "[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}"
    # API, papaia-ctl and the CHECK of audit.access_confirmation accept the same names,
    # and every one of them is a valid object_ref id.
    assert access._KEY_RE.pattern == rf"^(person|system):({name})$"
    assert f"^(person|system):{name}$" in ACCESS_SQL
    from lib import access_report

    assert access_report._KEY_RE.pattern == rf"^(person|system):{name}$"
    for sample in ("a", "papaia-flow", "x.y_z:1@b+c-d", "a" * 255):
        assert id_re.match(sample)
    assert not access._KEY_RE.match("system:papaia|flow")


def test_the_confirmation_check_runs_in_the_database_too():
    body = ACCESS_SQL[ACCESS_SQL.index("FUNCTION audit.legal_hold_confirm") :]
    body = body[: body.index("$$;")]
    assert "requested_by = p_by" in body and "insufficient_privilege" in body
    assert "audit.legal_hold_set(" in body and "audit.legal_hold_lift(" in body
    assert "CHECK (state <> 'confirmed' OR decided_by <> requested_by)" in ACCESS_SQL


def test_the_database_writes_the_lock_event_itself_and_refuses_an_expired_request():
    body = ACCESS_SQL[ACCESS_SQL.index("FUNCTION audit.legal_hold_confirm") :]
    body = body[: body.index("$$;")]
    # The lock changes only together with its own event, checked against the request.
    assert "p_canonical text" in body and "audit.append('papaia-audit', p_canonical)" in body
    for check in ("'writer'", "'event'", "'result'", "'sub'", "'object_ref'"):
        assert check in body, check
    # The 24 h lifetime of a request holds in the database too, by the database clock.
    assert "clock_timestamp()" in body and "interval '24 hours'" in body
    # The hold role cannot append a lock event on its own.
    append = ACCESS_SQL[ACCESS_SQL.index("FUNCTION audit.append_hold") :]
    append = append[: append.index("$$;")]
    assert "legal_hold_set" not in append and "legal_hold_lifted" not in append
    assert "approval_changed" in append
    grants = _grants(ACCESS_SQL)
    assert ("audit.legal_hold_confirm", "audit_hold") in grants
    assert "legal_hold_confirm(uuid, text, timestamptz, text)" in ACCESS_SQL


def test_the_store_changes_a_lock_and_writes_its_event_in_one_transaction():
    text = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    store = text[text.index("class PgReadStore") : text.index("class IngestServer")]
    for function in ("legal_hold_request_add", "legal_hold_confirm"):
        start = store.index(f"audit.{function}")
        method = store[store.rindex("    def ", 0, start) : store.index("\n    @", start)]
        assert 'connect("hold")' in method and "autocommit" not in method
        assert "conn.transaction()" in method
    start = store.index("audit.legal_hold_request_add")
    method = store[store.rindex("    def ", 0, start) : store.index("\n    @", start)]
    assert "self._append_hold_on(conn, build)" in method
    # The confirmation hands its event to audit.legal_hold_confirm, which appends it.
    start = store.index("audit.legal_hold_confirm")
    method = store[store.rindex("    def ", 0, start) : store.index("\n    @", start)]
    assert "audit.next_source_seq" in method and "build(" in method
    start = store.index("audit.access_confirmation_add")
    method = store[store.rindex("    def ", 0, start) : store.index("\n    @", start)]
    assert 'connect("ingest")' in method and "self._append_on(conn, build)" in method


def test_the_schema_step_adds_the_access_tables_to_an_older_store():
    text = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    assert '"hold"' in text[text.index("SERVICE_ROLES") : text.index("SERVICE_ROLES") + 80]
    assert "audit.legal_hold_request" in text and "SCHEMA_ACCESS_SQL" in text
    docker = (SERVICE_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "papaia_audit/access.py" in docker and "papaia_audit/schema_access.sql" in docker


def test_compose_gives_the_hold_password_to_the_schema_step_and_the_service():
    compose = yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    for name in ("papaia-audit-schema", "papaia-audit"):
        assert "audit_db_hold_password" in services[name]["secrets"]
    assert compose["secrets"]["audit_db_hold_password"]["file"].endswith(
        "/infra/audit/secrets/db-hold-password"
    )


def test_prepare_creates_the_hold_password(tmp_path):
    audit.prepare(tmp_path)
    secret = tmp_path / "infra" / "audit" / "secrets" / "db-hold-password"
    assert secret.stat().st_mode & 0o777 == 0o600 and len(secret.read_text()) >= 40
    before = secret.read_text()
    audit.prepare(tmp_path)
    assert secret.read_text() == before


def test_the_events_use_names_of_the_vendored_schema_and_are_documented():
    # The vendored schema is the kit's; these routes add no event name to it.
    schema = json.loads((SERVICE_DIR / "papaia_audit" / "audit.v1.schema.json").read_text())
    assert set(access.EVENTS) <= set(schema["$defs"]["event"]["enum"])
    docs = REPO.joinpath("docs", "audit.md").read_text(encoding="utf-8")
    for route in ("/v1/access-reports", "/v1/access-reports/confirmations", "/v1/legal-holds"):
        assert f"`POST {route}" in docs or f"POST {route}" in docs, route
