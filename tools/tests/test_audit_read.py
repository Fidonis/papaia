"""papaia-audit read API without containers (src/infra/audit/papaia_audit/read.py): who may
read, pseudonyms instead of persons, the person filter with a reason and a second person,
the events every request, decision and read with a ticket writes, and what the affected
person sees. The store is an in-memory double; tokens are real RS256 tokens signed with a
throwaway key made by `openssl` in a temporary directory.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import audit

REPO = Path(__file__).resolve().parents[2]
SERVICE_DIR = REPO / "src" / "infra" / "audit"
sys.path.insert(0, str(SERVICE_DIR))

from papaia_audit import core, read  # noqa: E402

ISSUER = "https://auth.example.test/realms/papaia"
KID = "realm-rs256"
NOW = datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc).timestamp()
PSEUDONYM_KEY = b"k" * 32
ANNA = "1f0e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
BERT = "2a1b0c9d-8e7f-4a6b-9c5d-4e3f2a1b0c9d"
DANA = "3b2c1d0e-9f8a-4b7c-8d6e-5f4a3b2c1d0e"  # papaia-auditor
EMIL = "4c3d2e1f-0a9b-4c8d-9e7f-6a5b4c3d2e1f"  # papaia-auditor
DORA = "5d4e3f2a-1b0c-4d9e-8f8a-7b6c5d4e3f2a"  # papaia-admin only
CHECK = core.SubmissionCheck()
STORED = Draft202012Validator(json.loads(core.SCHEMA_FILE.read_text(encoding="utf-8")))


# ─────────────────────────────────────────────────────────────────────────
# tokens
# ─────────────────────────────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    folder = tmp_path_factory.mktemp("realm-key")
    key = folder / "key.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(key),
        ],
        check=True,
        capture_output=True,
    )
    modulus = subprocess.run(
        ["openssl", "rsa", "-in", str(key), "-noout", "-modulus"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    n = bytes.fromhex(modulus.strip().split("=", 1)[1])
    jwks = {
        "format": read.TOKEN_KEYS_FORMAT,
        "issuer": ISSUER,
        "keys": [
            {
                "kid": KID,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": _b64(n),
                "e": _b64((65537).to_bytes(3, "big")),
            },
            # A realm also lists its encryption key; it never signs a token.
            {
                "kid": "realm-enc",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": _b64(n),
                "e": "AQAB",
            },
        ],
    }

    def sign(claims: dict[str, Any], header: dict[str, Any] | None = None) -> str:
        head = _b64(json.dumps(header or {"alg": "RS256", "typ": "JWT", "kid": KID}).encode())
        body = _b64(json.dumps(claims).encode())
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key)],
            input=f"{head}.{body}".encode(),
            check=True,
            capture_output=True,
        ).stdout
        return f"{head}.{body}.{_b64(signature)}"

    sign.keys = read.TokenKeys.parse(jwks)  # type: ignore[attr-defined]
    sign.jwks = jwks  # type: ignore[attr-defined]
    return sign


def _claims(sub: str, roles: tuple[str, ...] = (), **changes: Any) -> dict[str, Any]:
    claims = {
        "iss": ISSUER,
        "aud": "papaia-audit",
        "sub": sub,
        "typ": "Bearer",
        "azp": "papaia-manager",
        "sid": "a1b2c3",
        "iat": int(NOW) - 10,
        "exp": int(NOW) + 300,
        "auth_time": int(NOW) - 30,
        "roles": list(roles),
    }
    claims.update(changes)
    return claims


# ─────────────────────────────────────────────────────────────────────────
# store double
# ─────────────────────────────────────────────────────────────────────────


class FakeStore:
    def __init__(self) -> None:
        self.rows: list[read.Row] = []
        self.queries: dict[str, read.PersonQuery] = {}
        self.fail_own = False
        self.identities: dict[str, read.PersonIdentity] = {}

    # identity map (audit.person_identity)
    def identity(self, sub: str):
        return self.identities.get(sub)

    def sub_by_upstream(self, tid: str, oid: str):
        found = [i.sub for i in self.identities.values() if (i.tid, i.oid) == (tid, oid)]
        return found[0] if found else None

    def put_identities(self, identities, build) -> int:
        # One transaction: the entries are stored only together with their own event.
        event = self._own_event(build)
        for identity in identities:
            self.identities[identity.sub] = identity
        self.add("papaia-audit", event)
        return len(identities)

    def add(self, source: str, body: dict[str, Any]) -> None:
        chain = [r for r in self.rows if r.source == source]
        prev = chain[-1].hash if chain else core.ZERO_HASH
        _, canonical = CHECK.check(json.dumps(body).encode(), source)
        moment = datetime.strptime(body["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
        self.rows.append(
            read.Row(source, len(chain) + 1, prev, core.chain_hash(prev, canonical), moment, body)
        )

    def subjects(self):
        return {r.body["sub"] for r in self.rows if r.body.get("sub")}

    def search(self, search: read.Search, limit: int) -> list[read.Row]:
        def match(row: read.Row) -> bool:
            body = row.body
            return all(
                (
                    search.source in (None, row.source),
                    search.event in (None, body["event"]),
                    search.catalog_id in (None, body.get("catalog_id")),
                    search.result in (None, body["result"]),
                    search.correlation_id in (None, body["correlation_id"]),
                    search.person_sub in (None, body.get("sub")),
                    search.start is None or row.time >= search.start,
                    search.end is None or row.time < search.end,
                    search.after is None or (row.time, row.source, row.seq) > search.after,
                )
            )

        found = sorted((r for r in self.rows if match(r)), key=lambda r: (r.time, r.source, r.seq))
        return found[:limit]

    def add_query(self, query: read.PersonQuery, build) -> None:
        # One transaction: the request is stored only together with its own event.
        event = self._own_event(build)
        self.queries[query.id] = query
        self.add("papaia-audit", event)

    def get_query(self, query_id: str):
        query = self.queries.get(query_id)
        return None if query is None else read.PersonQuery(**vars(query))

    def open_queries(self, since: datetime):
        return [q for q in self.queries.values() if q.state == "open" and q.requested_at > since]

    def decide_query(self, query_id, state, decided_by, at, build) -> bool:
        # One transaction: the decision is stored only together with its own event.
        query = self.queries[query_id]
        if query.state != "open":
            return False
        event = self._own_event(build)
        query.state, query.decided_by, query.decided_at = state, decided_by, at
        self.add("papaia-audit", event)
        return True

    def _own_event(self, build) -> dict[str, Any]:
        if self.fail_own:
            raise core.Refused(core.STORAGE, 503)
        own = [r for r in self.rows if r.source == "papaia-audit"]
        return json.loads(build(len(own) + 1))

    def append_own(self, build) -> int:
        self.add("papaia-audit", self._own_event(build))
        return len(self.own())

    def reads_about(self, sub: str, limit: int):
        found = []
        for row in self.rows:
            ref = row.body.get("object_ref") or {}
            query = self.queries.get(ref.get("id", ""))
            if (
                row.source == "papaia-audit"
                and row.body["event"] in ("audit_read", "audit_exported", "pseudonym_resolved")
                and row.body["result"] == "allowed"
                and query
                and query.person_sub == sub
            ):
                found.append((row.time, query))
        return sorted(found, key=lambda item: item[0], reverse=True)[:limit]

    def own(self, event: str | None = None) -> list[dict[str, Any]]:
        return [
            r.body
            for r in self.rows
            if r.source == "papaia-audit" and event in (None, r.body["event"])
        ]


def _event(seq: int, sub: str | None, time: str, **changes: Any) -> dict[str, Any]:
    body = {
        "format": "papaia.audit/1",
        "time": time,
        "source_seq": seq,
        "correlation_id": f"c-{seq}",
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
        "client_ip": None,
    }
    body.update(changes)
    return body


class Api:
    def __init__(self, signer, store: FakeStore) -> None:
        self.signer, self.store, self.now = signer, store, NOW
        self.api = read.ReadApi(
            store, lambda: signer.keys, PSEUDONYM_KEY, CHECK, clock=lambda: self.now
        )

    def call(
        self,
        method: str,
        path: str,
        sub: str | None = DANA,
        *,
        roles=("papaia-auditor",),
        query: str = "",
        body: Any = None,
        caller: str = "papaia-manager",
        token: str | None = None,
        **claims: Any,
    ) -> tuple[int, Any]:
        if token is None and sub is not None:
            token = self.signer(
                _claims(sub, roles, iat=int(self.now) - 10, exp=int(self.now) + 300, **claims)
            )
        response = self.api.handle(
            read.Request(
                method,
                path,
                query,
                caller,
                f"Bearer {token}" if token else None,
                "corr-1",
                json.dumps(body).encode() if body is not None else None,
            )
        )
        if response.content_type == "application/x-ndjson":
            return response.status, [json.loads(x) for x in response.body.decode().splitlines()]
        return response.status, json.loads(response.body)


@pytest.fixture
def store() -> FakeStore:
    store = FakeStore()
    store.add(
        "papaia-flow",
        _event(
            1,
            ANNA,
            "2026-11-01T08:00:00.000Z",
            client_ip="192.0.2.10",
            event="login_failed",
            role=None,
            operation=None,
            catalog_id=None,
            effect=None,
        ),
    )
    store.add("papaia-flow", _event(2, BERT, "2026-11-02T08:00:00.000Z"))
    store.add("papaia-flow", _event(3, ANNA, "2026-11-03T08:00:00.000Z"))
    store.add("papaia-flow", _event(4, ANNA, "2026-12-30T08:00:00.000Z"))
    return store


@pytest.fixture
def api(signer, store) -> Api:
    return Api(signer, store)


REASON = "Hinweis auf unberechtigte Dokumentzugriffe, Meldung 2026-117"


def _request(api: Api, by: str = DANA, person: str = ANNA) -> str:
    status, view = api.call(
        "POST",
        "/v1/person-queries",
        by,
        body={"person": person, "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
    )
    assert status == 201, view
    return view["id"]


def _ticket(api: Api) -> str:
    query_id = _request(api)
    status, view = api.call("POST", f"/v1/person-queries/{query_id}/confirm", EMIL)
    assert status == 200 and view["state"] == "confirmed", view
    return query_id


# ─────────────────────────────────────────────────────────────────────────
# who may read
# ─────────────────────────────────────────────────────────────────────────

AUDITOR_ROUTES = [
    ("GET", "/v1/events", None),
    ("POST", "/v1/exports", {}),
    ("GET", "/v1/person-queries", None),
    (
        "POST",
        "/v1/person-queries",
        {"person": ANNA, "from": "2026-11-01", "to": "2026-11-02", "reason": REASON},
    ),
    ("POST", "/v1/person-queries/00000000-0000-4000-8000-000000000000/confirm", None),
]


@pytest.mark.parametrize(("method", "path", "body"), AUDITOR_ROUTES)
def test_without_the_auditor_role_every_route_answers_403(api, method, path, body):
    status, problem = api.call(method, path, DORA, roles=("papaia-admin",), body=body)

    assert status == 403
    assert problem["class"] == "forbidden_or_not_found" and problem["code"] == "AUDIT-READ-403"
    assert ANNA not in json.dumps(problem) and api.store.own() == []


@pytest.mark.parametrize(("method", "path", "body"), AUDITOR_ROUTES)
def test_without_a_valid_token_every_route_answers_401(api, method, path, body):
    assert api.call(method, path, None, body=body)[0] == 401


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "papaia-manager"},
        {"aud": ["papaia-audit", "papaia-flow"]},
        {"iss": "https://other.example.test/realms/papaia"},
        {"exp": int(NOW) - 1},
        {"nbf": int(NOW) + 600},
        {"typ": "ID"},
        {"sid": None},  # a service account's token has no session
    ],
)
def test_a_token_that_is_not_a_person_token_for_papaia_audit_is_refused(api, changes):
    token = api.signer(_claims(DANA, ("papaia-auditor",), **changes))
    assert api.call("GET", "/v1/events", token=token)[0] == 401


def test_a_token_with_a_malformed_subject_is_refused(api):
    assert api.call("GET", "/v1/events", "bad sub")[0] == 401


def test_a_forged_signature_or_an_unknown_key_is_refused(api):
    token = api.signer(_claims(DANA, ("papaia-auditor",)))
    head, body, signature = token.split(".")
    forged_body = _b64(json.dumps(_claims(DORA, ("papaia-auditor",))).encode())
    assert api.call("GET", "/v1/events", token=f"{head}.{forged_body}.{signature}")[0] == 401
    unknown = api.signer(_claims(DANA, ("papaia-auditor",)), {"alg": "RS256", "kid": "realm-enc"})
    assert api.call("GET", "/v1/events", token=unknown)[0] == 401
    none_alg = f"{_b64(json.dumps({'alg': 'none', 'kid': KID}).encode())}.{body}.{signature}"
    assert api.call("GET", "/v1/events", token=none_alg)[0] == 401
    assert api.call("GET", "/v1/events", token=f"{head}.{body}")[0] == 401


def test_only_the_reading_clients_reach_the_audit_routes(api):
    status, problem = api.call("GET", "/v1/events", caller="papaia-flow")
    assert status == 404 and problem["class"] == "forbidden_or_not_found"
    assert api.call("GET", "/v1/events", caller="papaia-ctl")[0] == 200
    assert api.call("GET", "/v1/me/reads", ANNA, roles=(), caller="papaia-manager")[0] == 404
    assert api.call("GET", "/v1/unknown")[0] == 404
    assert api.call("DELETE", "/v1/events")[0] == 404


def test_without_token_keys_the_api_is_unavailable_not_open(signer, store):
    api = read.ReadApi(store, lambda: None, PSEUDONYM_KEY, CHECK, clock=lambda: NOW)
    token = signer(_claims(DANA, ("papaia-auditor",)))
    response = api.handle(
        read.Request("GET", "/v1/events", "", "papaia-manager", f"Bearer {token}")
    )
    assert response.status == 503


# ─────────────────────────────────────────────────────────────────────────
# pseudonymous search
# ─────────────────────────────────────────────────────────────────────────


def test_events_show_pseudonyms_never_the_person(api):
    status, page = api.call("GET", "/v1/events")

    assert status == 200 and page["pseudonymous"] is True
    text = json.dumps(page)
    assert ANNA not in text and BERT not in text and "192.0.2.10" not in text
    subs = [event["sub"] for event in page["events"]]
    assert subs[0] == subs[2] == read.pseudonym(PSEUDONYM_KEY, ANNA) != subs[1]
    assert all(sub.startswith("P-") and len(sub) == 10 for sub in subs)
    for event in page["events"]:
        assert not list(STORED.iter_errors(event)), event
    assert api.store.own() == []  # a search without a person filter writes nothing


def test_the_pseudonym_is_stable_and_keyed():
    assert read.pseudonym(PSEUDONYM_KEY, ANNA) == read.pseudonym(PSEUDONYM_KEY, ANNA)
    assert read.pseudonym(PSEUDONYM_KEY, ANNA) != read.pseudonym(b"x" * 32, ANNA)


def test_search_filters_and_pages_by_time_source_and_seq(api):
    status, first = api.call("GET", "/v1/events", query="source=papaia-flow&limit=2")
    assert status == 200 and [e["seq"] for e in first["events"]] == [1, 2]
    status, second = api.call(
        "GET", "/v1/events", query=f"limit=2&page_token={first['next_page_token']}"
    )
    assert [e["seq"] for e in second["events"]] == [3, 4] and second["next_page_token"] is None
    status, page = api.call(
        "GET", "/v1/events", query="event=operation&from=2026-11-02&to=2026-11-03"
    )
    assert [e["seq"] for e in page["events"]] == [2]


@pytest.mark.parametrize(
    "query",
    [
        "sub=" + ANNA,
        "pseud=" + read.pseudonym(PSEUDONYM_KEY, ANNA),
        "ticket=00000000-0000-4000-8000-000000000000",
    ],
)
def test_a_person_filter_without_a_confirmed_ticket_is_refused(api, query):
    status, problem = api.call("GET", "/v1/events", query=query)

    assert status == 403 and problem["code"] == "AUDIT-PERSON-403"
    assert ANNA not in json.dumps(problem)


@pytest.mark.parametrize("query", ["group_by=sub", "count=sub", "per=person", "distinct=sub"])
def test_grouping_or_counting_by_person_is_not_offered(api, query):
    status, problem = api.call("GET", "/v1/events", query=query)
    assert status == 403 and problem["code"] == "AUDIT-READ-GROUP"
    assert problem["class"] == "forbidden_or_not_found"


@pytest.mark.parametrize(
    "query",
    [
        "unknown=1",
        "source=papaia-flow&source=papaia-data",
        "limit=501",
        "limit=0",
        "from=2026-13-01",
        "from=2026-11-02&to=2026-11-01",
        "result=maybe",
        "page_token=x",
        "source=Papaia",
        "correlation_id=" + "a" * 65,
    ],
)
def test_an_invalid_or_unknown_parameter_is_refused(api, query):
    status, problem = api.call("GET", "/v1/events", query=query)
    assert status == 400 and problem["class"] == "invalid_input"


def test_a_token_shaped_correlation_id_is_replaced(api):
    response = api.api.handle(
        read.Request("GET", "/v1/events", "", "papaia-manager", None, "sk-" + "a" * 30)
    )
    assert response.status == 401 and not response.correlation_id.startswith("sk-")


# ─────────────────────────────────────────────────────────────────────────
# person filter: reason, second person, ticket
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"person": ANNA, "from": "2026-11-01", "to": "2026-12-01", "reason": "zu kurz"},
        {"person": ANNA, "from": "2026-08-01", "to": "2026-11-03", "reason": REASON},
        {"person": ANNA, "from": "2026-11-02", "to": "2026-11-01", "reason": REASON},
        {"person": ANNA, "from": "2026-11-01", "to": "2026-12-01"},
        {"person": ANNA, "from": "2026-11-01", "to": "2026-12-01", "reason": REASON, "extra": 1},
        {"person": ["x"], "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
    ],
)
def test_a_request_needs_a_person_a_period_of_at_most_93_days_and_a_reason(api, body):
    status, problem = api.call("POST", "/v1/person-queries", body=body)
    assert status == 400 and problem["class"] == "invalid_input"
    assert api.store.queries == {} and api.store.own() == []


def test_a_request_for_an_unknown_pseudonym_is_not_found(api):
    # A pseudonym is what every auditor already sees in the log; its absence tells nothing
    # about a real person.
    status, _ = api.call(
        "POST",
        "/v1/person-queries",
        body={"person": "P-AAAAAAAA", "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
    )
    assert status == 404 and api.store.queries == {}


def test_the_requester_never_sees_the_pseudonym_of_the_person_before_confirmation(api):
    anna = read.pseudonym(PSEUDONYM_KEY, ANNA)
    status, view = api.call(
        "POST",
        "/v1/person-queries",
        DANA,
        body={"person": ANNA, "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
    )
    assert status == 201 and view["own"] is True and "person" not in view
    assert anna not in json.dumps(view) and ANNA not in json.dumps(view)

    status, listing = api.call("GET", "/v1/person-queries", DANA)
    assert status == 200 and [q["id"] for q in listing["queries"]] == [view["id"]]
    assert anna not in json.dumps(listing) and ANNA not in json.dumps(listing)

    # The second auditor sees the pseudonym, never the sub.
    (other,) = api.call("GET", "/v1/person-queries", EMIL)[1]["queries"]
    assert other["person"] == anna and ANNA not in json.dumps(other)

    # Rejecting it oneself shows nothing more.
    status, rejected = api.call("POST", f"/v1/person-queries/{view['id']}/reject", DANA)
    assert status == 200 and rejected["state"] == "rejected"
    assert anna not in json.dumps(rejected) and ANNA not in json.dumps(rejected)


def test_a_request_for_an_unknown_sub_answers_like_one_for_a_known_sub(api):
    unknown = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
    answers = []
    for person in (ANNA, unknown):
        status, view = api.call(
            "POST",
            "/v1/person-queries",
            DANA,
            body={"person": person, "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
        )
        answers.append((status, sorted(view), view["state"], view["own"]))
    assert answers[0] == answers[1] == (201, answers[0][1], "open", True)

    # Confirmed, the ticket for nobody reveals nobody.
    query_id = next(q.id for q in api.store.queries.values() if q.person_sub == unknown)
    assert api.call("POST", f"/v1/person-queries/{query_id}/confirm", EMIL)[0] == 200
    status, page = api.call("GET", "/v1/events", query=f"ticket={query_id}")
    assert status == 200 and page["events"] == []


def test_a_request_is_audited_and_shown_to_the_second_auditor_with_its_reason(api):
    query_id = _request(api, person=read.pseudonym(PSEUDONYM_KEY, ANNA))

    (event,) = api.store.own("audit_person_query_requested")
    assert event["sub"] == DANA and event["object_ref"] == {"type": "person_query", "id": query_id}
    assert REASON not in json.dumps(api.store.own())  # free text never enters the chain
    status, listing = api.call("GET", "/v1/person-queries", EMIL)
    (view,) = listing["queries"]
    assert status == 200 and view["reason"] == REASON and view["own"] is False
    assert view["person"] == read.pseudonym(PSEUDONYM_KEY, ANNA)
    assert ANNA not in json.dumps(listing) and DANA not in json.dumps(listing)


@pytest.mark.parametrize("four_eyes", ["off", "on"])
def test_self_confirmation_is_refused_whatever_the_four_eyes_setting(api, monkeypatch, four_eyes):
    monkeypatch.setenv("PAPAIA_APPROVALS_FOUR_EYES", four_eyes)
    query_id = _request(api)

    status, problem = api.call("POST", f"/v1/person-queries/{query_id}/confirm", DANA)

    assert status == 403 and problem["code"] == "AUDIT-PERSON-SELF"
    assert problem["message"].startswith("Sie können Ihren eigenen Antrag nicht bestätigen.")
    assert "Audit-Log → Offene Anträge" in problem["hint"]
    assert problem["correlation_id"] == "corr-1"
    (event,) = api.store.own("audit_person_query_rejected")
    assert event["result"] == "denied" and event["error_code"] == "AUDIT-PERSON-SELF"
    assert event["sub"] == DANA and event["object_ref"]["id"] == query_id
    assert api.store.queries[query_id].state == "open"
    status, _ = api.call("GET", "/v1/events", query=f"ticket={query_id}")
    assert status == 403


def test_the_read_module_knows_no_four_eyes_setting():
    text = (SERVICE_DIR / "papaia_audit" / "read.py").read_text(encoding="utf-8")
    assert "four_eyes" not in text and "FOUR_EYES" not in text


def test_confirmation_needs_a_fresh_sign_in(api):
    query_id = _request(api)
    status, problem = api.call(
        "POST", f"/v1/person-queries/{query_id}/confirm", EMIL, auth_time=int(NOW) - 301
    )
    assert status == 401 and problem["code"] == "AUDIT-AUTH-FRESH"
    assert api.store.queries[query_id].state == "open"


def test_two_auditors_reveal_the_person_and_each_read_is_an_event(api):
    query_id = _ticket(api)
    (confirmed,) = api.store.own("audit_person_query_confirmed")
    assert confirmed["sub"] == EMIL and confirmed["object_ref"]["id"] == query_id

    status, page = api.call("GET", "/v1/events", query=f"ticket={query_id}")

    assert status == 200 and page["pseudonymous"] is False
    assert [e["sub"] for e in page["events"]] == [ANNA, ANNA]  # the period ends 2026-12-01
    assert page["events"][0]["client_ip"] == "192.0.2.10"
    (event,) = api.store.own("audit_read")
    assert event["sub"] == DANA and event["detail"] == {"rows": 2}
    assert event["object_ref"] == {"type": "person_query", "id": query_id}
    stored = api.store.queries[query_id]
    assert (stored.requested_by, stored.decided_by, stored.reason) == (DANA, EMIL, REASON)


def test_a_ticket_holds_only_for_its_requester_person_and_period(api):
    query_id = _ticket(api)
    assert api.call("GET", "/v1/events", EMIL, query=f"ticket={query_id}")[0] == 403
    assert api.call("GET", "/v1/events", query=f"ticket={query_id}&sub={BERT}")[0] == 403
    assert api.call("GET", "/v1/events", query=f"ticket={query_id}&from=2026-10-01")[0] == 403
    assert api.call("GET", "/v1/events", query=f"ticket={query_id}&to=2026-12-31")[0] == 403
    pseud = read.pseudonym(PSEUDONYM_KEY, ANNA)
    assert api.call("GET", "/v1/events", query=f"ticket={query_id}&pseud={pseud}")[0] == 200


def test_the_ticket_expires_after_60_minutes(api):
    query_id = _ticket(api)
    api.now = NOW + 3600
    status, problem = api.call("GET", "/v1/events", query=f"ticket={query_id}")
    assert status == 403 and problem["code"] == "AUDIT-PERSON-EXPIRED"


def test_open_requests_expire_after_24_hours_and_decided_ones_stay_closed(api):
    query_id = _request(api)
    api.now = NOW + 86400
    assert api.call("GET", "/v1/person-queries", EMIL)[1]["queries"] == []
    assert (
        api.call("POST", f"/v1/person-queries/{query_id}/confirm", EMIL, auth_time=int(api.now))[0]
        == 404
    )

    api.now = NOW
    other = _request(api)
    assert api.call("POST", f"/v1/person-queries/{other}/reject", EMIL)[0] == 200
    assert api.store.own("audit_person_query_rejected")[0]["result"] == "allowed"
    status, problem = api.call("POST", f"/v1/person-queries/{other}/confirm", EMIL)
    assert status == 409 and problem["class"] == "conflict"


def test_without_its_audit_event_no_person_data_is_answered(api):
    query_id = _ticket(api)
    api.store.fail_own = True
    status, problem = api.call("GET", "/v1/events", query=f"ticket={query_id}")
    assert status == 503 and ANNA not in json.dumps(problem)


def test_a_request_is_not_stored_without_its_audit_event(api):
    api.store.fail_own = True
    status, problem = api.call(
        "POST",
        "/v1/person-queries",
        body={"person": ANNA, "from": "2026-11-01", "to": "2026-12-01", "reason": REASON},
    )
    assert status == 503 and problem["class"] == "upstream_unavailable"
    assert api.store.queries == {} and api.store.own() == []


@pytest.mark.parametrize("action", ["confirm", "reject"])
def test_a_decision_is_not_stored_without_its_audit_event(api, action):
    query_id = _request(api)
    api.store.fail_own = True

    status, _ = api.call("POST", f"/v1/person-queries/{query_id}/{action}", EMIL)

    assert status == 503
    stored = api.store.queries[query_id]
    assert (stored.state, stored.decided_by, stored.decided_at) == ("open", None, None)
    assert api.store.own("audit_person_query_confirmed") == []
    api.store.fail_own = False
    assert api.call("GET", "/v1/events", query=f"ticket={query_id}")[0] == 403


def test_the_store_writes_each_change_and_its_event_in_one_transaction():
    text = (SERVICE_DIR / "papaia_audit" / "__main__.py").read_text(encoding="utf-8")
    store = text[text.index("class PgReadStore") : text.index("class IngestServer")]
    for function in ("person_query_add", "person_query_decide"):
        start = store.index(f"audit.{function}")
        method = store[store.rindex("    def ", 0, start) : store.index("\n    @", start)]
        assert 'connect("ingest")' in method and "autocommit" not in method
        assert "conn.transaction()" in method and "self._append_on(conn, build)" in method


def test_an_unreachable_store_answers_503_without_detail(api, monkeypatch):
    def fail(*_args):
        raise read.StoreError

    monkeypatch.setattr(api.store, "search", fail)
    status, problem = api.call("GET", "/v1/events")
    assert status == 503 and problem["class"] == "upstream_unavailable"
    assert problem["retryable"] is True


def test_the_affected_person_sees_each_read_but_not_who_read(api):
    query_id = _ticket(api)
    api.call("GET", "/v1/events", query=f"ticket={query_id}")

    status, mine = api.call("GET", "/v1/me/reads", ANNA, roles=(), caller="papaia-me")

    assert status == 200
    assert mine == {
        "reads": [
            {
                "time": "2026-11-21T10:00:00.000Z",
                "role": "papaia-auditor",
                "from": "2026-11-01T00:00:00.000Z",
                "to": "2026-12-01T00:00:00.000Z",
                "confirmed": True,
            }
        ]
    }
    text = json.dumps(mine)
    assert DANA not in text and EMIL not in text and REASON not in text
    assert api.call("GET", "/v1/me/reads", BERT, roles=(), caller="papaia-me")[1] == {"reads": []}


LIFECYCLE = "papaia-lifecycle"


def _ref(kind: str, ref_id: str) -> dict[str, str]:
    return {"type": kind, "id": ref_id}


def _person_refs(store: FakeStore) -> None:
    # A lifecycle change on Anna's account (object_ref names her sub), a realm sync on a
    # user by name, and Bert naming his own sub under a type that is no person type.
    store.add(
        "papaia-lifecycle",
        _event(
            1, DANA, "2026-11-04T08:00:00.000Z", writer=LIFECYCLE, object_ref=_ref("user", ANNA)
        ),
    )
    store.add(
        "papaia-ctl",
        _event(
            1,
            DANA,
            "2026-11-05T08:00:00.000Z",
            writer="papaia-ctl",
            object_ref=_ref("user", "anna"),
        ),
    )
    store.add(
        "papaia-flow",
        _event(5, BERT, "2026-11-06T08:00:00.000Z", object_ref={"type": "workflow", "id": BERT}),
    )
    store.add(
        "papaia-flow",
        _event(6, BERT, "2026-11-07T08:00:00.000Z", object_ref={"type": "workflow", "id": "wf-7"}),
    )


def test_object_refs_naming_a_person_are_pseudonymous_in_search_and_export(api):
    _person_refs(api.store)

    status, page = api.call("GET", "/v1/events")
    assert status == 200
    status, lines = api.call("POST", "/v1/exports", body={})
    assert status == 200 and lines == page["events"]

    text = json.dumps(page) + json.dumps(lines)
    assert ANNA not in text and BERT not in text and '"anna"' not in text
    refs = {e["source"]: e["object_ref"] for e in page["events"] if e.get("object_ref")}
    assert refs["papaia-lifecycle"] == {"type": "user", "id": read.pseudonym(PSEUDONYM_KEY, ANNA)}
    assert refs["papaia-ctl"] == {"type": "user", "id": read.pseudonym(PSEUDONYM_KEY, "anna")}
    flow = [e.get("object_ref") for e in page["events"] if e["source"] == "papaia-flow"]
    assert {"type": "workflow", "id": read.pseudonym(PSEUDONYM_KEY, BERT)} in flow
    assert {"type": "workflow", "id": "wf-7"} in flow  # objects that are no person stay clear
    for event in page["events"]:
        assert not list(STORED.iter_errors(event)), event


def test_a_ticket_reveals_only_its_person_not_a_third_one(api):
    api.store.add(
        "papaia-lifecycle",
        _event(
            1, ANNA, "2026-11-04T08:00:00.000Z", writer=LIFECYCLE, object_ref=_ref("user", BERT)
        ),
    )
    api.store.add(
        "papaia-lifecycle",
        _event(
            2, ANNA, "2026-11-05T08:00:00.000Z", writer=LIFECYCLE, object_ref=_ref("user", ANNA)
        ),
    )
    query_id = _ticket(api)

    status, page = api.call("GET", "/v1/events", query=f"ticket={query_id}")

    assert status == 200 and BERT not in json.dumps(page)
    refs = [e["object_ref"] for e in page["events"] if e.get("object_ref")]
    assert refs == [
        {"type": "user", "id": read.pseudonym(PSEUDONYM_KEY, BERT)},
        {"type": "user", "id": ANNA},
    ]


# ─────────────────────────────────────────────────────────────────────────
# export
# ─────────────────────────────────────────────────────────────────────────


def test_an_export_is_papaia_audit_1_lines_pseudonymous_and_audited(api):
    status, lines = api.call("POST", "/v1/exports", body={"source": "papaia-flow"})

    assert status == 200 and [line["seq"] for line in lines] == [1, 2, 3, 4]
    for line in lines:
        assert not list(STORED.iter_errors(line)), line
        assert line["format"] == "papaia.audit/1" and line["sub"].startswith("P-")
    (event,) = api.store.own("audit_exported")
    assert event["detail"] == {"rows": 4} and event["object_ref"] is None
    _, page = api.call("GET", "/v1/events", query="source=papaia-flow")
    assert page["events"] == lines  # the file holds what the view shows


def test_an_export_by_person_needs_a_ticket_and_is_shown_to_the_person(api):
    assert api.call("POST", "/v1/exports", body={"sub": ANNA})[0] == 403
    assert api.call("POST", "/v1/exports", body={"limit": "5"})[0] == 400
    query_id = _ticket(api)
    status, lines = api.call("POST", "/v1/exports", body={"ticket": query_id})
    assert status == 200 and {line["sub"] for line in lines} == {ANNA}
    reads = api.call("GET", "/v1/me/reads", ANNA, roles=(), caller="papaia-me")[1]["reads"]
    assert len(reads) == 1


# ─────────────────────────────────────────────────────────────────────────
# the service's own chain, keys and wiring
# ─────────────────────────────────────────────────────────────────────────


def test_own_events_form_a_valid_chain_of_papaia_audit(api):
    query_id = _ticket(api)
    api.call("GET", "/v1/events", query=f"ticket={query_id}")
    rows = [r for r in api.store.rows if r.source == "papaia-audit"]
    stored = [
        core.StoredRow(r.seq, r.prev_hash, r.hash, core.derived_columns(r.body), r.body)
        for r in rows
    ]

    report = core.verify_chain("papaia-audit", stored)

    assert report.valid and report.count == 3
    assert [r.body["writer"] for r in rows] == ["papaia-audit/read"] * 3
    assert [r.body["source_seq"] for r in rows] == [1, 2, 3]


def test_token_keys_keep_rsa_signing_keys_only_and_refuse_malformed_files(signer):
    assert set(signer.keys.keys) == {KID}
    for broken in (
        {**signer.jwks, "format": "x"},
        {**signer.jwks, "extra": 1},
        {**signer.jwks, "issuer": "ftp://x"},
        {**signer.jwks, "keys": [{"kid": "k", "kty": "RSA", "n": "AQAB", "e": "AQAB"}]},
        [],
    ):
        with pytest.raises(ValueError):
            read.TokenKeys.parse(broken)


def test_rsa_verification_compares_the_whole_block():
    assert read.rsa_sha256_verify(3233, 17, b"m", b"\x00\x01") is False
    assert read.rsa_sha256_verify(3233, 17, b"m", (4000).to_bytes(2, "big")) is False


def test_prepare_creates_the_pseudonym_key_and_token_keys_are_written_checked(tmp_path, signer):
    audit.prepare(tmp_path)
    key = tmp_path / "infra" / "audit" / "secrets" / audit.PSEUDONYM_KEY
    assert key.stat().st_mode & 0o777 == 0o600 and len(key.read_bytes()) >= 32
    before = key.read_bytes()
    audit.prepare(tmp_path)
    assert key.read_bytes() == before

    discovery = {"issuer": ISSUER, "jwks_uri": "https://keycloak:8443/x"}
    path = audit.write_token_keys(tmp_path, discovery, {"keys": signer.jwks["keys"]})
    assert path == tmp_path / "infra" / "audit" / "service" / "token-keys.json"
    written = json.loads(path.read_text(encoding="utf-8"))
    assert read.TokenKeys.parse(written).keys == signer.keys.keys
    with pytest.raises(audit.AuditError):
        audit.write_token_keys(tmp_path, {"issuer": 5}, {"keys": []})
    with pytest.raises(audit.AuditError):
        audit.write_token_keys(
            tmp_path, discovery, {"keys": [{"kid": "x", "kty": "RSA", "n": "AQAB", "e": "AQAB"}]}
        )


def test_the_service_holds_the_pseudonym_key_and_the_image_carries_the_read_api():
    doc = yaml.safe_load((SERVICE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    services = doc["services"]
    assert "audit_pseudonym_key" in services["papaia-audit"]["secrets"]
    assert "audit_pseudonym_key" not in services["papaia-audit-schema"]["secrets"]
    assert "audit_pseudonym_key" not in services["papaia-audit-db"]["secrets"]
    assert doc["secrets"]["audit_pseudonym_key"]["file"].endswith("/secrets/pseudonym-key")
    assert "ports" not in services["papaia-audit"]
    declared = yaml.safe_load((REPO / "compat" / "own-images.yaml").read_text(encoding="utf-8"))
    (entry,) = [i for i in declared["images"] if i["name"] == "ghcr.io/fidonis/papaia-audit"]
    dockerfile = (SERVICE_DIR / "Dockerfile").read_text(encoding="utf-8")
    for name in ("read.py", "schema_read.sql"):
        assert f"src/infra/audit/papaia_audit/{name}" in entry["inputs"]
        assert f"src/infra/audit/papaia_audit/{name}" in dockerfile


def test_the_person_query_table_is_written_only_through_functions_with_two_persons():
    text = (SERVICE_DIR / "papaia_audit" / "schema_read.sql").read_text(encoding="utf-8")
    assert "CHECK (state <> 'confirmed' OR decided_by <> requested_by)" in text
    assert "GRANT SELECT ON audit.person_query TO audit_read;" in text
    assert "GRANT INSERT" not in text and "GRANT UPDATE" not in text
    assert "password" not in text.lower()
    assert "SECURITY DEFINER" in text and "REVOKE ALL ON FUNCTION" in text


# ─────────────────────────────────────────────────────────────────────────
# identity map (audit idmap): one person, both directions, only with a ticket
# ─────────────────────────────────────────────────────────────────────────

TENANT = "7a1d0c55-3e3b-4d5c-9a9e-0c5f1f0e2a11"
OBJECT = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"


def _mapped(api: Api) -> None:
    api.store.identities[ANNA] = read.PersonIdentity(ANNA, "anna.berger", TENANT, OBJECT)
    api.store.identities[BERT] = read.PersonIdentity(BERT, "bert.kurz", TENANT, "other-object")


def test_idmap_round_trip_from_pseudonym_to_upstream_id_and_back(api):
    _mapped(api)
    query_id = _ticket(api)
    pseud = read.pseudonym(PSEUDONYM_KEY, ANNA)

    status, person = api.call("POST", "/v1/idmap", body={"ticket": query_id, "pseud": pseud})
    assert status == 200, person
    assert person == {"pseud": pseud, "sub": ANNA, "username": "anna.berger", "tid": TENANT,
                      "oid": OBJECT}

    status, back = api.call("POST", "/v1/idmap",
                            body={"ticket": query_id, "tid": person["tid"], "oid": person["oid"]})
    assert status == 200, back
    assert back == {"pseud": pseud}

    resolved = api.store.own("pseudonym_resolved")
    assert [e["operation"] for e in resolved] == [
        "idmap.pseudonym_to_identity",
        "idmap.upstream_to_pseudonym",
    ]
    for event in resolved:
        assert event["sub"] == DANA and event["effect"] == "read"
        assert event["object_ref"] == {"type": "person_query", "id": query_id}
        assert ANNA not in json.dumps(event) and OBJECT not in json.dumps(event)
    # The affected person sees both resolutions under "Aktivität".
    status, page = api.call("GET", "/v1/me/reads", ANNA, roles=(), caller="papaia-me")
    assert status == 200 and len(page["reads"]) == 2


def test_idmap_without_a_confirmed_ticket_is_refused_and_resolves_nothing(api):
    _mapped(api)
    pseud = read.pseudonym(PSEUDONYM_KEY, ANNA)
    open_query = _request(api)

    for body in ({"pseud": pseud}, {"ticket": open_query, "pseud": pseud},
                 {"ticket": "00000000-0000-4000-8000-000000000000", "pseud": pseud}):
        status, problem = api.call("POST", "/v1/idmap", body=body)
        assert status in (400, 403), problem
        assert ANNA not in json.dumps(problem)
    assert api.store.own("pseudonym_resolved") == []


def test_idmap_holds_only_for_the_requester_and_the_person_of_the_ticket(api):
    _mapped(api)
    query_id = _ticket(api)

    other = read.pseudonym(PSEUDONYM_KEY, BERT)
    assert api.call("POST", "/v1/idmap", body={"ticket": query_id, "pseud": other})[0] == 403
    # The upstream id of another person: refused like an unknown one, nothing revealed.
    for oid in ("other-object", "never-seen"):
        status, problem = api.call("POST", "/v1/idmap",
                                   body={"ticket": query_id, "tid": TENANT, "oid": oid})
        assert status == 403 and problem["code"] == "AUDIT-PERSON-403"
    pseud = read.pseudonym(PSEUDONYM_KEY, ANNA)
    assert api.call("POST", "/v1/idmap", EMIL, body={"ticket": query_id, "pseud": pseud})[0] == 403
    api.now += 3601
    status, problem = api.call("POST", "/v1/idmap", body={"ticket": query_id, "pseud": pseud})
    assert status == 403 and problem["code"] == "AUDIT-PERSON-EXPIRED"


@pytest.mark.parametrize("body", [
    {"ticket": "00000000-0000-4000-8000-000000000000"},
    {"ticket": "00000000-0000-4000-8000-000000000000", "pseud": "P-AAAAAAAA", "tid": "t",
     "oid": "o"},
    {"ticket": "00000000-0000-4000-8000-000000000000", "tid": "t"},
    {"ticket": "00000000-0000-4000-8000-000000000000", "pseud": "anna"},
    {"ticket": "00000000-0000-4000-8000-000000000000", "pseud": "P-AAAAAAAA", "all": True},
    {"ticket": "00000000-0000-4000-8000-000000000000", "tid": "t\n", "oid": "o"},
])
def test_idmap_takes_exactly_one_direction_and_no_unknown_field(api, body):
    status, problem = api.call("POST", "/v1/idmap", body=body)
    assert status == 400, problem


def test_idmap_needs_the_auditor_role_and_a_reading_client(api):
    body = {"ticket": "00000000-0000-4000-8000-000000000000", "pseud": "P-AAAAAAAA"}
    assert api.call("POST", "/v1/idmap", DORA, roles=("papaia-admin",), body=body)[0] == 403
    assert api.call("POST", "/v1/idmap", body=body, caller="papaia-me")[0] == 404
    assert api.call("GET", "/v1/idmap")[0] == 404


def test_idmap_of_a_person_without_a_mapping_answers_the_sub_only(api):
    query_id = _ticket(api)
    pseud = read.pseudonym(PSEUDONYM_KEY, ANNA)

    status, person = api.call("POST", "/v1/idmap", body={"ticket": query_id, "pseud": pseud})

    assert status == 200
    assert person == {"pseud": pseud, "sub": ANNA, "username": None, "tid": None, "oid": None}


def _identities(api: Api, document: Any, caller: str = "papaia-lifecycle") -> tuple[int, Any]:
    return api.call("POST", "/v1/identities", None, body=document, caller=caller)


def test_the_identity_map_is_fed_by_papaia_lifecycle_only(api):
    entry = {"sub": ANNA, "username": "anna.berger", "tid": TENANT, "oid": OBJECT}

    status, answer = _identities(api, {"identities": [entry]})
    assert status == 200 and answer == {"stored": 1}
    assert api.store.identities[ANNA] == read.PersonIdentity(ANNA, "anna.berger", TENANT, OBJECT)
    (event,) = api.store.own("operation")
    assert event["operation"] == "identity_map.put" and event["effect"] == "write"
    assert event["sub"] == "papaia-lifecycle" and event["detail"] == {"count": 1}
    assert ANNA not in json.dumps(event) and OBJECT not in json.dumps(event)
    for caller in ("papaia-manager", "papaia-ctl", "papaia-flow"):
        assert _identities(api, {"identities": [entry]}, caller)[0] == 404


@pytest.mark.parametrize("entry", [
    {"sub": ANNA, "username": "anna", "tid": TENANT},
    {"sub": ANNA, "username": "anna", "tid": TENANT, "oid": None},
    {"sub": ANNA, "username": "anna", "tid": TENANT, "oid": OBJECT, "email": "a@example.org"},
    {"sub": "eyJhbGciOiJub25lIn0.e30.", "username": None, "tid": None, "oid": None},
    {"sub": ANNA, "username": "anna\nberger", "tid": None, "oid": None},
    {"sub": ANNA, "username": "a" * 256, "tid": None, "oid": None},
])
def test_identity_entries_are_checked_field_by_field(api, entry):
    assert _identities(api, {"identities": [entry]})[0] == 400
    assert api.store.identities == {} and api.store.own("operation") == []


def test_an_identity_batch_holds_at_most_500_entries_and_nothing_else(api):
    entry = {"sub": ANNA, "username": None, "tid": None, "oid": None}
    assert _identities(api, {"identities": [entry] * 501})[0] == 400
    assert _identities(api, {"identities": [entry], "more": 1})[0] == 400
    assert _identities(api, [entry])[0] == 400
