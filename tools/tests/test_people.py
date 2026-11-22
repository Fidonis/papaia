"""papaia-people: the exact-match people lookup for the assistant (`GET /v1/people/lookup`)
and the bounded group member lookup for Studio (`GET /v1/people/group-members`).

The service (`src/infra/people/people.py`) is one standard-library file in the core's own
image `ghcr.io/fidonis/papaia-people`, so it is imported here straight from the checkout,
like papaia-lifecycle. Tokens are signed with a throwaway RSA key (openssl); Keycloak's
user search is replaced by an in-memory stand-in that answers exact searches like
Keycloak 26.7.0 (MN-16).
"""

from __future__ import annotations

import base64
import http.client
import io
import json
import stat
import subprocess
import sys
import threading
import types
import urllib.parse
from pathlib import Path

import pytest
import yaml

from lib import render_core, topology

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "people"
ISSUER = "https://auth.example.test/realms/papaia"
ANNA = "0b9c7b1e-1c1f-4e55-9a51-2f7c0c3d4e5f"
BEN = "5d0f6a2b-8e1c-4a7d-b3f2-9c8e7d6a5b4c"
CEM = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
DORA = "3c2b1a09-8f7e-4d6c-9b5a-4f3e2d1c0b9a"
EMIL = "7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918"
NOW = 1_790_000_000


def _service_module():
    path = MODULE_DIR / "people.py"
    module = types.ModuleType("papaia_people_service")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


pp = _service_module()


# ─────────────────────────────────────────────────────────────────────────
# tokens
# ─────────────────────────────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Signer:
    """A throwaway RSA key of the realm; signs like Keycloak (RS256)."""

    def __init__(self, folder: Path, kid: str = "realm-key-1") -> None:
        self.kid = kid
        self.path = folder / f"{kid}.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(self.path)],
            check=True, capture_output=True,
        )
        out = subprocess.run(
            ["openssl", "rsa", "-in", str(self.path), "-noout", "-modulus"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.n = int(out.strip().split("=", 1)[1], 16)

    def jwk(self) -> dict:
        n = self.n.to_bytes((self.n.bit_length() + 7) // 8, "big")
        return {"kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig", "n": _b64(n),
                "e": "AQAB"}

    def token(self, header: dict | None = None, **claims) -> str:
        head = {"alg": "RS256", "typ": "JWT", "kid": self.kid, **(header or {})}
        body = {
            "iss": ISSUER,
            "aud": "papaia-people",
            "azp": "assist-gate",
            "sub": ANNA,
            "sid": "4f1c9a7e-2b3d-4c5e-8f6a-7b8c9d0e1f2a",
            "typ": "Bearer",
            "iat": NOW - 10,
            "auth_time": NOW - 600,
            "exp": NOW + 290,
        }
        for key, value in claims.items():
            if value is None:
                body.pop(key, None)
            else:
                body[key] = value
        signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(body).encode())}"
        sig = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.path)],
            input=signing_input.encode(), check=True, capture_output=True,
        ).stdout
        return f"{signing_input}.{_b64(sig)}"


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    return Signer(tmp_path_factory.mktemp("realm-key"))


@pytest.fixture(scope="module")
def stranger(tmp_path_factory):
    """A key the realm does not publish, with the realm key's kid."""
    return Signer(tmp_path_factory.mktemp("other-key"))


# ─────────────────────────────────────────────────────────────────────────
# Keycloak's user search
# ─────────────────────────────────────────────────────────────────────────


def _person(uid, first, last, email, roles, enabled=True, username=None):
    return {
        "id": uid,
        "username": username or email.split("@")[0],
        "firstName": first,
        "lastName": last,
        "email": email,
        "enabled": enabled,
        "_roles": set(roles),
    }


class FakeUsers:
    """`GET /users` with `exact=true`, `GET /groups/{id}/members` and
    `GET /users/{id}/role-mappings/realm/composite` as Keycloak answers them; every
    request is recorded. `members` maps a group id to the ids of its direct members."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail = False
        self.members: dict[str, list[str]] = {}
        self.users = [
            _person(ANNA, "Anna", "Albers", "anna.albers@example.test", {"assist-member"}),
            _person(BEN, "Ben", "Berger", "ben.berger@example.test", {"assist-admin"}),
            _person(CEM, "Cem", "van Dijk", "cem.vandijk@example.test", {"assist-member"}),
            _person(DORA, "Dora", "Dietz", "dora.dietz@example.test", {"flow-member"}),
            _person(EMIL, "Emil", "Ebner", "emil.ebner@example.test", {"assist-member"},
                    enabled=False),
        ]

    def get(self, path: str, params: dict):
        self.calls.append((path, dict(params)))
        if self.fail:
            raise pp.DirectoryError("HTTP 503")
        if path == "/users":
            assert params["exact"] == "true" and params["briefRepresentation"] == "true"
            found = []
            for user in self.users:
                if all(
                    str(user.get(field) or "").lower() == str(params[field]).lower()
                    for field in ("email", "firstName", "lastName")
                    if field in params
                ):
                    found.append({k: v for k, v in user.items() if not k.startswith("_")})
            return found[: int(params["max"])]
        if path.startswith("/groups/") and path.endswith("/members"):
            assert params["briefRepresentation"] == "true"
            gid = path.split("/")[2]
            first, size = int(params["first"]), int(params["max"])
            ids = self.members.get(gid, [])[first : first + size]
            by_id = {u["id"]: u for u in self.users}
            return [{k: v for k, v in by_id[i].items() if not k.startswith("_")} for i in ids]
        if path.startswith("/users/") and path.endswith("/role-mappings/realm/composite"):
            uid = path.split("/")[2]
            user = next(u for u in self.users if u["id"] == uid)
            return [{"name": n} for n in sorted(user["_roles"] | {"default-roles-papaia"})]
        raise AssertionError(f"unexpected read {path}")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


SALES, SOUTH, BUNDLE, OUTSIDE = "g-sales", "g-south", "g-bundle", "g-outside"


def _group(gid: str, path: str, technical: bool = False) -> dict:
    name = path.rsplit("/", 1)[1]
    return {"id": gid, "path": path, "display_name": {"de": name, "en": name},
            "technical": technical}


def _write_groups(path: Path, groups: list[dict]) -> None:
    doc = {"format": "papaia.platform-groups/1", "generated_at": "2026-11-22T10:00:00Z",
           "groups": groups}
    path.write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def stack(signer, tmp_path):
    users = FakeUsers()
    clock = Clock()
    out = io.StringIO()
    groups_file = tmp_path / "platform" / "groups.json"
    groups_file.parent.mkdir()
    _write_groups(
        groups_file,
        [
            _group(SALES, "/sales"),
            _group(SOUTH, "/sales/south"),
            _group(BUNDLE, "/studio-authors", technical=True),
        ],
    )
    verifier = pp.TokenVerifier(
        pp.Keys(lambda: {"keys": [signer.jwk()]}, clock=clock), ISSUER, wall=lambda: NOW
    )
    lookup = pp.Lookup(
        verifier,
        pp.Directory(users),
        groups=pp.GroupList(groups_file),
        per_client=300,
        clock=clock,
        wall=lambda: NOW,
        out=out,
    )
    return types.SimpleNamespace(
        users=users, clock=clock, out=out, lookup=lookup, signer=signer, groups_file=groups_file
    )


def _ask(stack, query, token=None, correlation=None, **claims):
    if isinstance(query, dict):
        query = urllib.parse.urlencode(query)
    token = token if token is not None else stack.signer.token(**claims)
    return stack.lookup.handle(f"Bearer {token}", query, correlation)


def _rows(stack) -> list[dict]:
    return [json.loads(line) for line in stack.out.getvalue().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# exact match and role filter
# ─────────────────────────────────────────────────────────────────────────


def test_a_full_display_name_finds_the_person_with_the_role(stack):
    status, body, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"})
    assert status == 200
    assert body == {"people": [{"sub": ANNA, "display_name": "Anna Albers"}]}


def test_a_full_mail_address_finds_the_person_case_insensitively(stack):
    status, body, _ = _ask(stack, {"q": "Ben.Berger@Example.test", "role": "assist-admin"})
    assert (status, body) == (200, {"people": [{"sub": BEN, "display_name": "Ben Berger"}]})


def test_a_name_with_several_words_is_tried_at_every_split(stack):
    status, body, _ = _ask(stack, {"q": "Cem van Dijk", "role": "assist-member"})
    assert body == {"people": [{"sub": CEM, "display_name": "Cem van Dijk"}]}
    searches = [p for path, p in stack.users.calls if path == "/users"]
    assert [(p["firstName"], p["lastName"]) for p in searches] == [
        ("Cem", "van Dijk"),
        ("Cem van", "Dijk"),
    ]
    assert all(p["exact"] == "true" for p in searches)


def test_the_answer_carries_only_sub_and_display_name(stack):
    _, body, _ = _ask(stack, {"q": "anna.albers@example.test", "role": "assist-member"})
    (person,) = body["people"]
    assert set(person) == {"sub", "display_name"}


@pytest.mark.parametrize(
    "q, role",
    [
        ("Dora Dietz", "assist-member"),  # no assistant role
        ("Ben Berger", "assist-member"),  # holds the other role only
        ("Emil Ebner", "assist-member"),  # deactivated account
        ("Anna Alb", "assist-member"),  # prefix of the last name
        ("Ann Albers", "assist-member"),  # prefix of the first name
        ("anna.albers@example.tes", "assist-member"),  # prefix of the domain
    ],
)
def test_no_hit_without_the_role_an_active_account_or_an_exact_match(stack, q, role):
    status, body, _ = _ask(stack, {"q": q, "role": role})
    assert (status, body) == (200, {"people": []})


def test_a_role_outside_the_assistant_roles_is_refused(stack):
    status, body, _ = _ask(stack, {"q": "Dora Dietz", "role": "flow-member"})
    assert (status, body["error"]) == (403, "role_not_allowed")
    assert not [c for c in stack.users.calls if c[0] == "/users"]


# ─────────────────────────────────────────────────────────────────────────
# partial queries
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "query, code",
    [
        ({"q": "Anna", "role": "assist-member"}, "invalid_query"),  # one word
        ({"q": "An Al*", "role": "assist-member"}, "invalid_query"),
        ({"q": "*", "role": "assist-member"}, "invalid_query"),
        ({"q": "%", "role": "assist-member"}, "invalid_query"),
        ({"q": "Anna %", "role": "assist-member"}, "invalid_query"),
        ({"q": "Anna A", "role": "assist-member"}, "invalid_query"),  # initial only
        ({"q": "", "role": "assist-member"}, "invalid_query"),
        ({"q": "   ", "role": "assist-member"}, "invalid_query"),
        ({"q": "anna.albers@", "role": "assist-member"}, "invalid_query"),
        ({"q": "@example.test", "role": "assist-member"}, "invalid_query"),
        ({"q": "anna*@example.test", "role": "assist-member"}, "invalid_query"),
        ({"q": "Anna  Albers", "role": "assist-member"}, "invalid_query"),
        ({"q": "Anna Albers", "role": "Assist-Member!"}, "invalid_role"),
        ({"q": "Anna Albers"}, "missing_parameter"),
        ({"role": "assist-member"}, "missing_parameter"),
        ({"q": "Anna Albers", "role": "assist-member", "max": "50"}, "unknown_parameter"),
        ("q=Anna+Albers&q=Ben+Berger&role=assist-member", "duplicate_parameter"),
        ("q=Anna+Albers&role", "malformed_query"),
        ("q=" + "a" * 700 + "&role=assist-member", "malformed_query"),
    ],
)
def test_a_partial_wild_or_malformed_query_is_refused(stack, query, code):
    status, body, _ = _ask(stack, query)
    assert (status, body) == (400, {"error": code})
    assert not [c for c in stack.users.calls if c[0] == "/users"]


def test_a_decomposed_name_is_refused():
    assert pp.classify("Ünal Özdemir") == "name"
    assert pp.classify("Ünal Özdemir") is None


# ─────────────────────────────────────────────────────────────────────────
# caller
# ─────────────────────────────────────────────────────────────────────────


def test_another_client_is_refused(stack):
    for azp in ("papaia-studio-gateway", "flow-engine", "librechat"):
        status, body, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, azp=azp)
        assert (status, body) == (403, {"error": "client_not_paired"})
    assert stack.users.calls == []
    rows = _rows(stack)
    assert [r["result"] for r in rows] == ["denied"] * 3
    assert [r["azp"] for r in rows] == ["papaia-studio-gateway", "flow-engine", "librechat"]


def test_a_service_identity_is_refused(stack):
    status, body, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, sid=None)
    assert (status, body) == (403, {"error": "person_token_required"})
    (row,) = _rows(stack)
    assert row["identity_kind"] == "service"
    assert row["error_code"] == "person_token_required"


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "assist-api"},
        {"aud": ["papaia-people", "assist-api"]},
        {"aud": None},
        {"iss": "https://elsewhere.example.test/realms/papaia"},
        {"exp": NOW - 31},
        {"iat": NOW + 120},
        {"typ": "Refresh"},
        {"sub": "not a subject"},
        {"azp": None},
    ],
)
def test_a_token_for_another_audience_issuer_or_time_is_refused(stack, claims):
    status, body, headers = _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, **claims)
    assert (status, body) == (401, {"error": "invalid_token"})
    assert headers["WWW-Authenticate"].startswith("Bearer")
    assert _rows(stack) == []


def test_a_token_within_the_clock_tolerance_is_accepted(stack):
    status, _, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, exp=NOW - 20)
    assert status == 200
    (row,) = _rows(stack)
    assert row["token_remaining_s"] == 0


def test_a_forged_or_unsigned_token_is_refused(stack, stranger):
    forged = stranger.token()
    head, body, _ = stack.signer.token().split(".")
    unsigned = f"{_b64(json.dumps({'alg': 'none', 'kid': 'realm-key-1'}).encode())}.{body}."
    hs256 = f"{_b64(json.dumps({'alg': 'HS256', 'kid': 'realm-key-1'}).encode())}.{body}.abc"
    for token in (forged, unsigned, hs256, f"{head}.{body}", "x" * 20, ""):
        status, payload, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, token)
        assert (status, payload) == (401, {"error": "invalid_token"})
    status, payload, _ = stack.lookup.handle(None, "q=Anna+Albers&role=assist-member", None)
    assert (status, payload) == (401, {"error": "invalid_token"})
    status, payload, _ = stack.lookup.handle(
        f"Basic {stack.signer.token()}", "q=Anna+Albers&role=assist-member", None
    )
    assert (status, payload) == (401, {"error": "invalid_token"})


def test_an_unknown_key_id_reads_the_keys_again_at_most_every_thirty_seconds(signer):
    fetches = []
    clock = Clock()

    def fetch():
        fetches.append(clock.now)
        return {"keys": [signer.jwk()]}

    keys = pp.Keys(fetch, clock=clock)
    assert keys.key("realm-key-1") is not None
    assert keys.key("rotated") is None
    assert keys.key("rotated") is None
    clock.now += 31
    assert keys.key("rotated") is None
    assert fetches == [1000.0, 1031.0]


# ─────────────────────────────────────────────────────────────────────────
# rate limits
# ─────────────────────────────────────────────────────────────────────────


def test_the_thirty_first_request_of_a_person_in_ten_minutes_is_rate_limited(stack):
    query = {"q": "Anna Albers", "role": "assist-member"}
    for _ in range(30):
        assert _ask(stack, query)[0] == 200
    status, body, headers = _ask(stack, query)
    assert (status, body) == (429, {"error": "rate_limited"})
    assert int(headers["Retry-After"]) > 0
    row = _rows(stack)[-1]
    assert (row["result"], row["error_code"]) == ("denied", "rate_limited")
    # Another person of the same client is not limited by Anna's requests.
    assert _ask(stack, query, sub=BEN)[0] == 200
    stack.clock.now += 601
    assert _ask(stack, query)[0] == 200


def test_invalid_queries_count_towards_the_limit(stack):
    for _ in range(30):
        assert _ask(stack, {"q": "Anna", "role": "assist-member"})[0] == 400
    assert _ask(stack, {"q": "Anna Albers", "role": "assist-member"})[0] == 429


def test_the_client_is_limited_across_persons(signer):
    clock, out = Clock(), io.StringIO()
    verifier = pp.TokenVerifier(
        pp.Keys(lambda: {"keys": [signer.jwk()]}, clock=clock), ISSUER, wall=lambda: NOW
    )
    lookup = pp.Lookup(
        verifier, pp.Directory(FakeUsers()), per_client=5, clock=clock, wall=lambda: NOW, out=out
    )
    query = "q=Anna+Albers&role=assist-member"
    subs = [ANNA, BEN, CEM, DORA, EMIL]
    for sub in subs:
        assert lookup.handle(f"Bearer {signer.token(sub=sub)}", query, None)[0] == 200
    status, body, _ = lookup.handle(f"Bearer {signer.token(sub=ANNA)}", query, None)
    assert (status, body) == (429, {"error": "rate_limited"})


def test_the_client_limit_must_be_positive():
    with pytest.raises(ValueError):
        pp.Lookup(None, None, per_client=0)


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def test_every_request_writes_one_audit_row_without_the_search_text(stack):
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, correlation="req-0001")
    _ask(stack, {"q": "Dora Dietz", "role": "assist-member"})
    _ask(stack, {"q": "Anna", "role": "assist-member"})
    rows = _rows(stack)
    assert len(rows) == 3
    first = rows[0]
    assert first == {
        "format": "papaia.audit/1",
        "time": first["time"],
        "correlation_id": "req-0001",
        "writer": "papaia-people",
        "role": "server",
        "sub": ANNA,
        "identity_kind": "person",
        "service_account": None,
        "azp": "assist-gate",
        "aud": "papaia-people",
        "catalog_id": "people.lookup",
        "operation": "people_lookup",
        "effect": "read",
        "object_ref": {"type": "role", "id": "assist-member"},
        "data_class": None,
        "result": "allowed",
        "error_code": None,
        "detail": {"count": 1},
        "event": "operation",
        "token_iat": NOW - 10,
        "token_auth_time": NOW - 600,
        "token_remaining_s": 290,
    }
    assert rows[1]["detail"] == {"count": 0}
    assert (rows[2]["result"], rows[2]["error_code"], rows[2]["detail"]) == (
        "denied",
        "invalid_query",
        None,
    )
    text = stack.out.getvalue()
    for secret in ("Anna Albers", "Albers", "Dora", "Dietz", "anna.albers"):
        assert secret not in text
    assert stack.signer.token().split(".")[2] not in text


def test_an_invalid_correlation_id_is_replaced(stack):
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, correlation="Bearer x.y.z")
    (row,) = _rows(stack)
    assert row["correlation_id"] != "Bearer x.y.z"
    assert pp._CORRELATION_RE.fullmatch(row["correlation_id"])


def test_a_directory_failure_is_an_error_row_and_502(stack):
    stack.users.fail = True
    status, body, _ = _ask(stack, {"q": "Anna Albers", "role": "assist-member"})
    assert (status, body) == (502, {"error": "directory_unavailable"})
    (row,) = _rows(stack)
    assert (row["result"], row["error_code"]) == ("error", "directory_unavailable")


def test_every_audit_row_is_a_valid_submission_of_the_audit_schema(stack):
    """The rows match `#/$defs/submission` of the audit store's schema once the writer
    that delivers them adds its gapless `source_seq`, as for the other core services."""
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        {**schema, "$ref": "#/$defs/submission", "required": [], "properties": {}},
        format_checker=jsonschema.FormatChecker(),
    )
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, correlation="req-0001")
    _ask(stack, {"q": "Anna", "role": "assist-member"})
    _ask(stack, {"q": "Anna Albers", "role": "realm-admin"})
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, azp="flow-engine")
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"}, sid=None)
    stack.users.fail = True
    _ask(stack, {"q": "Anna Albers", "role": "assist-member"})
    rows = _rows(stack)
    assert len(rows) == 6
    for seq, row in enumerate(rows, start=1):
        errors = [e.message for e in validator.iter_errors({**row, "source_seq": seq})]
        assert errors == [], (row["result"], row["error_code"], errors)


def test_a_role_not_offered_never_reaches_the_audit_row(stack):
    _ask(stack, {"q": "Anna Albers", "role": "realm-admin"})
    (row,) = _rows(stack)
    assert row["object_ref"] is None


# ─────────────────────────────────────────────────────────────────────────
# group members for Studio (GET /v1/people/group-members)
# ─────────────────────────────────────────────────────────────────────────

STUDIO = "papaia-studio-gateway"


def _members(stack, gid: str, count: int, roles=("studio-member",), enabled=True, start=0):
    """`count` accounts as direct members of `gid`; returns their ids."""
    ids = []
    for i in range(start, start + count):
        uid = f"00000000-0000-4000-8000-{i:012d}"
        stack.users.users.append(
            _person(uid, "Member", f"No{i}", f"member{i}@example.test", roles, enabled=enabled)
        )
        stack.users.members.setdefault(gid, []).append(uid)
        ids.append(uid)
    return ids


def _group_ask(stack, query, token=None, correlation=None, **claims):
    if isinstance(query, dict):
        query = urllib.parse.urlencode(query)
    claims.setdefault("azp", STUDIO)
    token = token if token is not None else stack.signer.token(**claims)
    return stack.lookup.handle_group(f"Bearer {token}", query, correlation)


def test_a_group_of_fifty_active_members_with_the_role_answers_their_subs(stack):
    ids = _members(stack, SALES, 50)
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert status == 200
    assert body == {"members": sorted(ids)}


def test_a_group_of_fifty_one_answers_too_many_without_a_list(stack):
    _members(stack, SALES, 51)
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert (status, body) == (200, {"too_many": True})
    (row,) = _rows(stack)
    assert (row["result"], row["error_code"], row["detail"]) == ("allowed", "too_many", None)


def test_inactive_accounts_and_members_without_the_role_are_not_returned(stack):
    active = _members(stack, SALES, 2)
    _members(stack, SALES, 1, enabled=False, start=10)
    _members(stack, SALES, 1, roles=("flow-member",), start=20)
    stack.users.members[SALES].append(ANNA)  # assistant role only
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert (status, body) == (200, {"members": sorted(active)})


def test_inactive_members_and_members_without_the_role_do_not_count_towards_the_limit(stack):
    active = _members(stack, SALES, 50)
    _members(stack, SALES, 5, enabled=False, start=100)
    _members(stack, SALES, 5, roles=("assist-member",), start=200)
    assert _group_ask(stack, {"group": SALES})[1] == {"members": sorted(active)}


def test_a_service_account_in_the_group_is_never_a_member(stack):
    stack.users.users.append(
        _person("11111111-2222-4333-8444-555555555555", "", "", "svc@example.test",
                {"studio-member"}, username="service-account-robot")
    )
    stack.users.members[SALES] = ["11111111-2222-4333-8444-555555555555"]
    assert _group_ask(stack, {"group": SALES})[1] == {"members": []}


def test_members_of_subgroups_count_like_the_groups_claim_and_once_only(stack):
    direct = _members(stack, SALES, 2)
    below = _members(stack, SOUTH, 2, start=10)
    stack.users.members[SOUTH].append(direct[0])
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert body == {"members": sorted(direct + below)}
    # The subgroup alone holds only its own members.
    assert _group_ask(stack, {"group": SOUTH})[1] == {"members": sorted([direct[0], *below])}


def test_the_role_parameter_selects_a_studio_role(stack):
    authors = _members(stack, SALES, 2, roles=("studio-author",))
    _members(stack, SALES, 2, start=10)
    status, body, _ = _group_ask(stack, {"group": SALES, "role": "studio-author"})
    assert body == {"members": sorted(authors)}


def test_a_role_outside_the_studio_roles_is_refused(stack):
    for role in ("assist-member", "realm-admin"):
        status, body, _ = _group_ask(stack, {"group": SALES, "role": role})
        assert (status, body) == (403, {"error": "role_not_allowed"})
    assert stack.users.calls == []


@pytest.mark.parametrize("gid", [BUNDLE, OUTSIDE, "g-sale"])
def test_a_group_that_is_not_a_share_target_is_refused(stack, gid):
    stack.users.members[gid] = [ANNA]
    status, body, _ = _group_ask(stack, {"group": gid})
    assert (status, body) == (403, {"error": "group_not_offered"})
    assert stack.users.calls == []


@pytest.mark.parametrize(
    "query, code",
    [
        ({"group": "*"}, "invalid_group"),
        ({"group": "%"}, "invalid_group"),
        ({"group": "g-*"}, "invalid_group"),
        ({"group": ""}, "invalid_group"),
        ({"group": " "}, "invalid_group"),
        ({"group": "/sales"}, "invalid_group"),
        ({"group": "sales south"}, "invalid_group"),
        ({"group": "-sales"}, "invalid_group"),
        ({"group": "g" * 65}, "invalid_group"),
        ({"group": SALES, "role": ""}, "invalid_role"),
        ({"group": SALES, "role": "Studio*"}, "invalid_role"),
        ({}, "missing_parameter"),
        ({"role": "studio-member"}, "missing_parameter"),
        ({"group": SALES, "max": "100"}, "unknown_parameter"),
        ({"group": SALES, "q": "Anna Albers"}, "unknown_parameter"),
        (f"group={SALES}&group={SOUTH}", "duplicate_parameter"),
        ("group", "malformed_query"),
        ("group=" + "a" * 700, "malformed_query"),
    ],
)
def test_a_wild_empty_partial_or_malformed_group_query_is_refused(stack, query, code):
    status, body, _ = _group_ask(stack, query)
    assert (status, body) == (400, {"error": code})
    assert stack.users.calls == []


def test_only_the_studio_gateway_reaches_the_group_route(stack):
    _members(stack, SALES, 1)
    for azp in ("assist-gate", "flow-engine", "papaia-studio-me"):
        status, body, _ = _group_ask(stack, {"group": SALES}, azp=azp)
        assert (status, body) == (403, {"error": "client_not_paired"})
    assert stack.users.calls == []
    assert [r["azp"] for r in _rows(stack)] == ["assist-gate", "flow-engine", "papaia-studio-me"]


def test_the_group_route_needs_a_person_token(stack):
    status, body, _ = _group_ask(stack, {"group": SALES}, sid=None)
    assert (status, body) == (403, {"error": "person_token_required"})


def test_the_group_route_refuses_a_token_for_another_audience(stack):
    status, body, _ = _group_ask(stack, {"group": SALES}, aud="papaia-studio")
    assert (status, body) == (401, {"error": "invalid_token"})
    assert _rows(stack) == []


def test_the_group_route_is_rate_limited_per_person(stack):
    _members(stack, SALES, 1)
    for _ in range(30):
        assert _group_ask(stack, {"group": SALES})[0] == 200
    status, body, headers = _group_ask(stack, {"group": SALES})
    assert (status, body) == (429, {"error": "rate_limited"})
    assert int(headers["Retry-After"]) > 0
    row = _rows(stack)[-1]
    assert (row["result"], row["error_code"], row["azp"]) == ("denied", "rate_limited", STUDIO)
    assert _group_ask(stack, {"group": SALES}, sub=BEN)[0] == 200


def test_the_group_route_is_rate_limited_per_client(signer, tmp_path):
    groups_file = tmp_path / "groups.json"
    _write_groups(groups_file, [_group(SALES, "/sales")])
    clock, out = Clock(), io.StringIO()
    verifier = pp.TokenVerifier(
        pp.Keys(lambda: {"keys": [signer.jwk()]}, clock=clock), ISSUER, wall=lambda: NOW
    )
    lookup = pp.Lookup(
        verifier, pp.Directory(FakeUsers()), groups=pp.GroupList(groups_file), per_client=3,
        clock=clock, wall=lambda: NOW, out=out,
    )
    query = f"group={SALES}"
    for sub in (ANNA, BEN, CEM):
        assert lookup.handle_group(f"Bearer {signer.token(sub=sub, azp=STUDIO)}", query, None)[
            0
        ] == 200
    status, body, _ = lookup.handle_group(
        f"Bearer {signer.token(sub=DORA, azp=STUDIO)}", query, None
    )
    assert (status, body) == (429, {"error": "rate_limited"})
    # The assistant's gate keeps its own client budget.
    assert lookup.handle(
        f"Bearer {signer.token(sub=DORA)}", "q=Anna+Albers&role=assist-member", None
    )[0] == 200
    rows = [json.loads(line) for line in out.getvalue().splitlines()]
    assert (rows[3]["result"], rows[3]["error_code"]) == ("denied", "rate_limited")


def test_the_group_audit_row_names_the_group_and_the_count_never_the_members(stack):
    ids = _members(stack, SALES, 3)
    _group_ask(stack, {"group": SALES}, correlation="share-0001")
    (row,) = _rows(stack)
    assert row["correlation_id"] == "share-0001"
    assert (row["operation"], row["catalog_id"], row["effect"]) == (
        "people_lookup",
        "people.group_members",
        "read",
    )
    assert row["object_ref"] == {"type": "group", "id": SALES}
    assert (row["sub"], row["azp"], row["aud"]) == (ANNA, STUDIO, "papaia-people")
    assert (row["result"], row["error_code"], row["detail"]) == ("allowed", None, {"count": 3})
    text = stack.out.getvalue()
    for uid in ids:
        assert uid not in text
    assert "member0@" not in text and "No0" not in text


def test_every_group_audit_row_is_a_valid_submission_of_the_audit_schema(stack):
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        {**schema, "$ref": "#/$defs/submission", "required": [], "properties": {}},
        format_checker=jsonschema.FormatChecker(),
    )
    _members(stack, SALES, 51)
    _group_ask(stack, {"group": SALES})
    _group_ask(stack, {"group": SOUTH})
    _group_ask(stack, {"group": "*"})
    _group_ask(stack, {"group": OUTSIDE})
    _group_ask(stack, {"group": SALES}, azp="assist-gate")
    stack.users.fail = True
    _group_ask(stack, {"group": SALES})
    rows = _rows(stack)
    assert len(rows) == 6
    for seq, row in enumerate(rows, start=1):
        errors = [e.message for e in validator.iter_errors({**row, "source_seq": seq})]
        assert errors == [], (row["result"], row["error_code"], errors)


def test_a_directory_failure_on_the_group_route_is_502(stack):
    stack.users.fail = True
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert (status, body) == (502, {"error": "directory_unavailable"})
    (row,) = _rows(stack)
    assert (row["result"], row["error_code"]) == ("error", "directory_unavailable")


@pytest.mark.parametrize(
    "content",
    [
        None,
        "not json",
        json.dumps({"format": "papaia.platform-groups/2", "groups": []}),
        json.dumps({"format": "papaia.platform-groups/1", "groups": [{"id": "*", "path": "/x",
                    "technical": False}]}),
        json.dumps({"format": "papaia.platform-groups/1", "groups": [{"id": "g-sales",
                    "path": "/sales", "technical": "no"}]}),
    ],
)
def test_without_a_readable_group_list_no_group_is_offered(stack, content):
    if content is None:
        stack.groups_file.unlink()
    else:
        stack.groups_file.write_text(content, encoding="utf-8")
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert (status, body) == (503, {"error": "group_list_unavailable"})
    assert stack.users.calls == []
    (row,) = _rows(stack)
    assert row["result"] == "error"


def test_a_new_group_list_is_read_once_it_is_replaced(stack):
    assert _group_ask(stack, {"group": OUTSIDE})[0] == 403
    replacement = stack.groups_file.with_name("groups.json.new")
    _write_groups(replacement, [_group(OUTSIDE, "/outside")])
    replacement.replace(stack.groups_file)
    assert _group_ask(stack, {"group": OUTSIDE})[1] == {"members": []}
    assert _group_ask(stack, {"group": SALES})[0] == 403


def test_a_group_larger_than_the_scan_bound_answers_too_many(stack, monkeypatch):
    monkeypatch.setattr(pp, "MAX_SCANNED", 20)
    _members(stack, SALES, 30, roles=("flow-member",))
    _members(stack, SALES, 2, start=100)
    status, body, _ = _group_ask(stack, {"group": SALES})
    assert (status, body) == (200, {"too_many": True})
    role_reads = [c for c in stack.users.calls if c[0].endswith("/composite")]
    assert len(role_reads) <= 20


def test_the_member_scan_stops_once_the_limit_is_passed(stack):
    _members(stack, SALES, 120)
    assert _group_ask(stack, {"group": SALES})[1] == {"too_many": True}
    role_reads = [c for c in stack.users.calls if c[0].endswith("/composite")]
    assert len(role_reads) == 51


# ─────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def server(stack):
    httpd = pp.make_server(stack.lookup, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def _http(port, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read() or b"null"), dict(resp.getheaders())
    finally:
        conn.close()


def test_the_route_answers_over_http(server, stack):
    token = stack.signer.token()
    status, body, headers = _http(
        server,
        "GET",
        "/v1/people/lookup?q=Anna+Albers&role=assist-member",
        {"Authorization": f"Bearer {token}", "X-Papaia-Correlation-Id": "abc-1"},
    )
    assert (status, body) == (200, {"people": [{"sub": ANNA, "display_name": "Anna Albers"}]})
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert _rows(stack)[0]["correlation_id"] == "abc-1"


def test_the_group_route_answers_over_http(server, stack):
    ids = _members(stack, SALES, 2)
    token = stack.signer.token(azp=STUDIO)
    status, body, headers = _http(
        server,
        "GET",
        f"/v1/people/group-members?group={SALES}&role=studio-member",
        {"Authorization": f"Bearer {token}"},
    )
    assert (status, body) == (200, {"members": sorted(ids)})
    assert headers["Cache-Control"] == "no-store"
    assert _http(server, "POST", f"/v1/people/group-members?group={SALES}",
                 {"Authorization": f"Bearer {token}"})[0] == 405
    assert _http(server, "GET", "/v1/people/group-members/", {})[0] == 404


def test_other_routes_and_methods_are_refused(server, stack):
    token = stack.signer.token()
    auth = {"Authorization": f"Bearer {token}"}
    assert _http(server, "GET", "/v1/people/search?q=Anna", auth)[0] == 404
    assert _http(server, "GET", "/v1/people/lookup/", auth)[0] == 404
    assert _http(server, "POST", "/v1/people/lookup?q=Anna+Albers&role=assist-member", auth)[
        0
    ] == 405
    assert _http(server, "GET", "/v1/people/lookup?q=Anna+Albers&role=assist-member")[0] == 401
    assert _http(server, "GET", "/healthz")[:2] == (200, {"status": "ok"})


# ─────────────────────────────────────────────────────────────────────────
# the Admin API account
# ─────────────────────────────────────────────────────────────────────────


def test_the_account_signs_in_with_an_es256_assertion(tmp_path):
    folder = tmp_path / "account"
    folder.mkdir(mode=0o700)
    key = folder / "private-key.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(key)],
        check=True, capture_output=True,
    )
    key.chmod(0o600)
    assertion = pp.AccountKey(folder).assertion("https://auth.example.test/realms/papaia")
    head, body, sig = assertion.split(".")
    header = json.loads(base64.urlsafe_b64decode(head + "=="))
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert header["alg"] == "ES256"
    assert claims["iss"] == claims["sub"] == "svc-papaia-people"
    assert claims["exp"] - claims["iat"] == 60
    assert len(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))) == 64


def test_a_key_others_can_read_is_refused(tmp_path):
    folder = tmp_path / "account"
    folder.mkdir()
    key = folder / "private-key.pem"
    key.write_text("x")
    key.chmod(0o644)
    with pytest.raises(pp.PeopleError):
        pp.AccountKey(folder)


@pytest.mark.parametrize(
    "url", ["http://keycloak:8080", "https://keycloak:8443/admin", "ftp://keycloak"]
)
def test_the_keycloak_url_must_be_https_or_loopback(url):
    with pytest.raises(pp.PeopleError):
        pp.keycloak_url(url)
    assert pp.keycloak_url("https://keycloak:8443") == "https://keycloak:8443"
    assert pp.keycloak_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_the_rsa_check_refuses_a_changed_message(signer):
    token = signer.token()
    head, body, sig = token.split(".")
    raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    assert pp.rsa_verify(signer.n, 65537, f"{head}.{body}".encode(), raw)
    assert not pp.rsa_verify(signer.n, 65537, f"{head}.{body}x".encode(), raw)
    assert not pp.rsa_verify(signer.n, 65537, f"{head}.{body}".encode(), raw[:-1])


# ─────────────────────────────────────────────────────────────────────────
# compose, catalogue, render
# ─────────────────────────────────────────────────────────────────────────


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def test_the_root_compose_includes_the_people_file():
    root = yaml.safe_load((REPO / "src" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"path": "./infra/people/docker-compose.yml"} in root["include"]


def test_the_service_runs_unprivileged_on_the_stack_network_without_a_port():
    doc = _compose()
    service = doc["services"]["papaia-people"]
    assert service["profiles"] == ["people"]
    assert service["networks"] == ["papaia-net"]
    assert "networks" not in doc and "volumes" not in doc
    assert "ports" not in service
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["image"].startswith("ghcr.io/fidonis/papaia-people:")
    mounts = {m["target"]: m for m in service["volumes"]}
    account = mounts["/run/papaia-people/account"]
    assert account["read_only"] is True
    assert account["source"].endswith("/security/service-accounts/svc-papaia-people")
    platform = mounts["/run/papaia-people/platform"]
    assert platform["source"] == "${PAPAIA_CONFIG_DIR}/platform"
    assert "--groups-file=/run/papaia-people/platform/groups.json" in service["command"]
    assert all(m["read_only"] for m in mounts.values())


def test_the_catalogue_places_the_service_next_to_keycloak():
    spec = topology.CATALOGUE["people"]
    assert spec.profiles == ("people",)
    assert ("people", "keycloak") in topology.COLOCATED


def test_render_creates_the_account_key_only_with_the_profile(tmp_path):
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=keycloak,egress\n")
    render_core.ensure_people_key(tmp_path)
    folder = tmp_path / "security" / "service-accounts" / "svc-papaia-people"
    assert not folder.exists()
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=keycloak,egress,people\n")
    render_core.ensure_people_key(tmp_path)
    key = folder / "private-key.pem"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    before = key.read_bytes()
    render_core.ensure_people_key(tmp_path)
    assert key.read_bytes() == before
