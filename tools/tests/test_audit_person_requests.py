"""papaia-audit requests for information and erasure of a person without an account
(src/infra/audit/papaia_audit/person_requests.py; security 1.14 no. 2b), without
containers: filed by the host, confirmed by a second, named person in the manager after a
fresh sign-in, the passphrase answered once, then run by the host.

Tokens and the store double come from test_audit_read.py.
"""

from __future__ import annotations

import base64
import io
import json
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "infra" / "audit"))

from papaia_audit import person_requests as pr  # noqa: E402
from papaia_audit import read  # noqa: E402
from test_audit_read import (  # noqa: E402
    ANNA,
    BERT,
    CHECK,
    DANA,
    DORA,
    EMIL,
    PSEUDONYM_KEY,
    Api,
    FakeStore,
    signer,  # noqa: F401  (fixture)
)

from lib import age  # noqa: E402

CONFIRM = ("papaia-confirm",)
ADMIN = ("papaia-admin",)


class RequestStore(FakeStore):
    """FakeStore plus person requests; every change only together with its own event,
    like the database functions."""

    def __init__(self) -> None:
        super().__init__()
        self.requests: dict[str, pr.PersonRequest] = {}
        self.keys: dict[str, bytes] = {}

    def add_person_request(self, request, build) -> None:
        event = self._own_event(build)
        self.requests[request.id] = replace(request)
        self.add("papaia-audit", event)

    def get_person_request(self, request_id):
        found = self.requests.get(request_id)
        return None if found is None else replace(found)

    def person_requests_of(self, sub, since):
        found = [
            replace(r) for r in self.requests.values()
            if sub in (r.requested_by, r.confirmed_by) and r.requested_at > since
        ]
        return sorted(found, key=lambda r: r.requested_at, reverse=True)

    def decide_person_request(self, request_id, state, by, at, key, build) -> bool:
        item = self.requests[request_id]
        if item.state != "open" or at >= item.requested_at + pr.OPEN_LIFETIME:
            return False
        event = self._own_event(build)
        if state == "confirmed":
            # The database refuses both as well.
            assert by == item.confirmed_by and by != item.requested_by
            assert (key is not None) == (item.operation == "export")
            if key is not None:
                self.keys[request_id] = key
        item.state, item.decided_by, item.decided_at = state, by, at
        self.add("papaia-audit", event)
        return True

    def advance_person_request(self, request_id, from_state, to_state, at, build) -> bool:
        item = self.requests[request_id]
        if item.state != from_state:
            return False
        if from_state == "confirmed" and at >= item.decided_at + pr.RUN_LIFETIME:
            return False
        event = self._own_event(build)
        item.state, item.changed_at = to_state, at
        if to_state in ("done", "partial"):
            self.keys.pop(request_id, None)
        self.add("papaia-audit", event)
        return True

    def take_person_request_key(self, request_id, build):
        if self.requests[request_id].state != "running" or request_id not in self.keys:
            return None
        event = self._own_event(build)
        key = self.keys.pop(request_id)
        self.add("papaia-audit", event)
        return key


@pytest.fixture
def store() -> RequestStore:
    return RequestStore()


class Caller(Api):
    def __init__(self, signer, store) -> None:  # noqa: F811
        super().__init__(signer, store)
        self.api = pr.PersonRequestApi(
            store, lambda: signer.keys, PSEUDONYM_KEY, CHECK, clock=lambda: self.now
        )

    def host(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        request = pr.host_request(json.dumps({"path": path, "body": body or {}}))
        assert request is not None
        response = self.api.host(request)
        return response.status, json.loads(response.body)


@pytest.fixture
def api(signer, store) -> Caller:  # noqa: F811
    return Caller(signer, store)


def _create(api: Caller, operation: str = "export", *, requested_by: str = DANA,
            confirmed_by: str = EMIL, transfer_to: str | None = None) -> dict:
    status, view = api.host("/v1/person-requests", {
        "operation": operation, "person": ANNA, "requested_by": requested_by,
        "confirmed_by": confirmed_by, "transfer_to": transfer_to,
    })
    assert status == 201, view
    return view


def _confirm(api: Caller, request_id: str, sub: str = EMIL, roles=CONFIRM, **claims):
    return api.call("POST", f"/v1/person-requests/{request_id}/confirm", sub, roles=roles,
                    **claims)


# ── filing ───────────────────────────────────────────────────────────────────


def test_a_request_gets_an_id_and_runs_nothing(api, store):
    view = _create(api)
    assert view["state"] == "open"
    assert view["person"] == ANNA and view["requested_by"] == DANA
    created = store.own("person_request_created")
    assert len(created) == 1
    assert created[0]["sub"] == DANA
    assert created[0]["object_ref"] == {"type": "person_request", "id": view["id"]}
    assert created[0]["writer"] == "papaia-audit/person"
    assert not store.keys


def test_the_requesting_person_cannot_be_the_confirming_one(api):
    status, problem = api.host("/v1/person-requests", {
        "operation": "erase", "person": ANNA, "requested_by": DANA, "confirmed_by": DANA,
        "transfer_to": None,
    })
    assert status == 403 and problem["code"] == "AUDIT-PERSON-REQ-SELF"


@pytest.mark.parametrize("change", [
    {"operation": "delete"},
    {"person": "a b"},
    {"requested_by": ""},
    {"confirmed_by": 7},
    {"transfer_to": ANNA},
    {"extra": True},
])
def test_a_malformed_request_is_refused(api, store, change):
    body = {"operation": "erase", "person": ANNA, "requested_by": DANA,
            "confirmed_by": EMIL, "transfer_to": None, **change}
    status, problem = api.host("/v1/person-requests", body)
    assert status == 400 and problem["code"] == "AUDIT-READ-400"
    assert not store.requests


def test_a_transfer_belongs_to_an_erasure_only(api):
    status, _ = api.host("/v1/person-requests", {
        "operation": "export", "person": ANNA, "requested_by": DANA, "confirmed_by": EMIL,
        "transfer_to": BERT,
    })
    assert status == 400


def test_host_routes_are_not_reachable_over_the_network(api):
    for caller in ("papaia-manager", "papaia-ctl"):
        status, _ = api.call("POST", "/v1/person-requests", DANA, roles=CONFIRM,
                             caller=caller, body={})
        assert status == 404
    assert pr.host_request(json.dumps({"path": "/v1/events", "body": {}})) is None
    assert pr.host_request(json.dumps({"path": "/v1/person-requests", "body": {},
                                       "authorization": "Bearer x"})) is None


# ── confirmation ─────────────────────────────────────────────────────────────


def test_self_confirmation_is_refused_and_audited(api, store):
    view = _create(api, requested_by=DANA, confirmed_by=EMIL)
    status, problem = _confirm(api, view["id"], DANA)
    assert status == 403 and problem["code"] == "AUDIT-PERSON-REQ-SELF"
    denied = store.own("person_request_confirmed")
    assert [e["result"] for e in denied] == ["denied"]
    assert denied[0]["sub"] == DANA
    assert store.requests[view["id"]].state == "open"


def test_only_the_named_person_confirms(api, store):
    view = _create(api, confirmed_by=EMIL)
    # Neither requesting nor confirming: the request is not hers to see, admin or not.
    for sub, roles in ((DORA, ADMIN), (BERT, CONFIRM)):
        status, _ = _confirm(api, view["id"], sub, roles=roles)
        assert status == 404
    assert store.requests[view["id"]].state == "open"
    assert store.own("person_request_confirmed") == []


def test_confirmation_needs_the_role(api, store):
    view = _create(api)
    status, problem = _confirm(api, view["id"], EMIL, roles=("papaia-auditor",))
    assert status == 403 and problem["code"] == "AUDIT-PERSON-REQ-403"
    assert store.requests[view["id"]].state == "open"


def test_confirmation_needs_a_fresh_sign_in(api, store):
    view = _create(api)
    status, problem = _confirm(api, view["id"], auth_time=int(api.now) - 600)
    assert status == 401 and problem["code"] == "AUDIT-AUTH-FRESH"
    assert store.requests[view["id"]].state == "open"


def test_confirmation_by_the_named_person_shows_the_passphrase_once(api, store):
    view = _create(api)
    status, confirmed = _confirm(api, view["id"])
    assert status == 200, confirmed
    assert confirmed["state"] == "confirmed"
    passphrase = confirmed["passphrase"]
    assert len(passphrase) == pr.PASSPHRASE_GROUPS * (pr.PASSPHRASE_GROUP + 1) - 1
    events = store.own("person_request_confirmed")
    assert [e["result"] for e in events] == ["allowed"]
    assert events[0]["sub"] == EMIL
    # Both persons are in the audit under the request id.
    created = store.own("person_request_created")[0]
    assert created["object_ref"] == events[0]["object_ref"] and created["sub"] == DANA
    # The passphrase is stored nowhere, not even in an event.
    assert all(passphrase not in json.dumps(r.body) for r in store.rows)
    assert passphrase.encode() not in store.keys[view["id"]]
    # Listing and a second confirmation never show it again.
    status, listing = api.call("GET", "/v1/person-requests", EMIL, roles=CONFIRM)
    assert status == 200 and "passphrase" not in json.dumps(listing)
    status, again = _confirm(api, view["id"])
    assert status == 409 and "passphrase" not in again


def test_the_key_of_the_confirmation_opens_the_archive_only_with_the_passphrase(api, store):
    view = _create(api)
    _, confirmed = _confirm(api, view["id"])
    assert api.host(f"/v1/person-requests/{view['id']}/start")[0] == 200
    status, key = api.host(f"/v1/person-requests/{view['id']}/key")
    assert status == 200
    out = io.BytesIO()
    with age.Encryptor(out, scrypt=(base64.b64decode(key["salt"]), key["log_n"],
                                    base64.b64decode(key["key"]))) as enc:
        enc.write(b"archive")
    plain = io.BytesIO()
    age.decrypt_with_passphrase(io.BytesIO(out.getvalue()), plain, confirmed["passphrase"])
    assert plain.getvalue() == b"archive"
    with pytest.raises(age.NoIdentityError):
        age.decrypt_with_passphrase(io.BytesIO(out.getvalue()), io.BytesIO(), "wrong")
    # Taken once: the second call finds nothing.
    assert api.host(f"/v1/person-requests/{view['id']}/key")[0] == 409


def test_an_erasure_confirmation_has_no_passphrase(api, store):
    view = _create(api, "erase")
    status, confirmed = _confirm(api, view["id"])
    assert status == 200 and "passphrase" not in confirmed
    assert view["id"] not in store.keys


def test_the_named_person_or_the_requesting_one_may_reject(api, store):
    view = _create(api)
    status, rejected = api.call("POST", f"/v1/person-requests/{view['id']}/reject", DANA,
                                roles=CONFIRM)
    assert status == 200 and rejected["state"] == "rejected"
    assert [e["sub"] for e in store.own("person_request_rejected")] == [DANA]
    assert api.host(f"/v1/person-requests/{view['id']}/start")[0] == 409


def test_an_open_request_expires(api, store):
    view = _create(api)
    api.now += pr.OPEN_LIFETIME.total_seconds() + 1
    status, problem = _confirm(api, view["id"])
    assert status == 409
    assert api.host(f"/v1/person-requests/{view['id']}")[1]["state"] == "expired"


def test_the_list_shows_pseudonyms_and_what_the_caller_may_do(api):
    view = _create(api)
    status, listing = api.call("GET", "/v1/person-requests", EMIL, roles=CONFIRM)
    assert status == 200
    [item] = listing["requests"]
    assert item["id"] == view["id"] and item["can_confirm"] is True and item["own"] is False
    assert ANNA not in json.dumps(listing) and DANA not in json.dumps(listing)
    assert item["person"] == read.pseudonym(PSEUDONYM_KEY, ANNA)
    status, listing = api.call("GET", "/v1/person-requests", DANA, roles=CONFIRM)
    assert listing["requests"][0]["can_confirm"] is False
    status, listing = api.call("GET", "/v1/person-requests", DORA, roles=ADMIN)
    assert listing["requests"] == []
    status, _ = api.call("GET", "/v1/person-requests", EMIL, roles=CONFIRM,
                         caller="papaia-ctl")
    assert status == 404


# ── run ──────────────────────────────────────────────────────────────────────


def test_nothing_runs_before_the_confirmation(api):
    view = _create(api, "erase")
    status, problem = api.host(f"/v1/person-requests/{view['id']}/start")
    assert status == 409 and problem["code"] == "AUDIT-PERSON-REQ-409"


def test_a_run_moves_through_its_states_with_events(api, store):
    view = _create(api, "erase", transfer_to=BERT)
    _confirm(api, view["id"])
    status, started = api.host(f"/v1/person-requests/{view['id']}/start")
    assert status == 200 and started["state"] == "running"
    assert started["transfer_to"] == BERT
    assert api.host(f"/v1/person-requests/{view['id']}/start")[0] == 409
    status, done = api.host(f"/v1/person-requests/{view['id']}/finish", {"result": "partial"})
    assert status == 200 and done["state"] == "partial"
    operations = [e["operation"] for e in store.own("operation")]
    assert operations == ["person_request.erase.start", "person_request.erase.finish"]
    assert api.host(f"/v1/person-requests/{view['id']}/key")[0] == 409


def test_a_confirmation_not_run_within_a_day_expires(api, store):
    view = _create(api)
    _confirm(api, view["id"])
    api.now += timedelta(hours=25).total_seconds()
    assert api.host(f"/v1/person-requests/{view['id']}/start")[0] == 409
    assert api.host(f"/v1/person-requests/{view['id']}")[1]["state"] == "expired"


def test_a_finish_needs_a_known_result(api):
    view = _create(api, "erase")
    _confirm(api, view["id"])
    api.host(f"/v1/person-requests/{view['id']}/start")
    status, _ = api.host(f"/v1/person-requests/{view['id']}/finish", {"result": "ok"})
    assert status == 400


def test_an_unknown_request_is_not_found(api):
    status, _ = api.host("/v1/person-requests/1f0e2d3c-4b5a-4968-8776-a5b4c3d2e1f0")
    assert status == 404


def test_the_archive_key_is_an_age_scrypt_key():
    key = pr.archive_key("pass", b"s" * 16, 10)
    assert len(key) == 49 and key[16] == 10
    out = io.BytesIO()
    with age.Encryptor(out, scrypt=(key[:16], key[16], key[17:])) as enc:
        enc.write(b"x")
    plain = io.BytesIO()
    age.decrypt_with_passphrase(io.BytesIO(out.getvalue()), plain, "pass")
    assert plain.getvalue() == b"x"
