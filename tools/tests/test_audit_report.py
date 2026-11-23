"""The permission report built inside papaia-audit (src/infra/audit/papaia_audit/report.py
and idp.py, security 1.16): the content by person and by system from a seeded realm and
the inputs file, its determinism and checksum (the same as papaia-ctl built on the host
before), the recertification state per row, the published schema, CSV output, the checks
of the inputs file, and the Admin API client of the report account (GET only, the
report's paths only, private_key_jwt with ES256).

The realm is an in-memory double of the Admin REST API that answers only what
`view-users` may read: the client list and the realm settings are refused.
"""

from __future__ import annotations

import base64
import copy
import csv
import io
import json
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "infra" / "audit"))

from papaia_audit import idp  # noqa: E402
from papaia_audit import report as rp  # noqa: E402

from lib import service_account_keys as sak  # noqa: E402

NOW = datetime(2026, 11, 22, 9, 0, tzinfo=timezone.utc)
BEN = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
DORA = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
CARLA = "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a"
GLASS = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b"
SVC = "4f5a6b7c-8d9e-4f0a-9b1c-3d4e5f6a7b8c"
FLOW_UUID = "5a6b7c8d-9e0f-4a1b-8c2d-4e5f6a7b8c9d"
REPORT_SCHEMA = REPO / "tools" / "schemas" / "access-report.schema.json"
INPUTS_SCHEMA = REPO / "tools" / "schemas" / "access-report-inputs.schema.json"
# What papaia-ctl's host-side builder (lib/access_report.py of release 1.10.0 before the
# move) gave for the same realm, pairings and service accounts: the move keeps the
# format, the row digests and the checksum.
BEFORE = {
    "person": "sha256:1e7d9235de50c1ea20e2e755bfc8ed56124856c76b621a6bb171d48716562cda",
    "system": "sha256:1e51ffe4e71ee6edb53253ab96a42c6a8b07d43a7120c39d9cd971ab0863e738",
}
BEFORE_BEN = "sha256:db72b115fbe2099bb31a3839780e57ba8eacdb14a95a9cf0c506b6dda442ae24"
DELEGATIONS = {"idle_days": 90, "max_days": 180, "source": "default"}


class FakeRealm:
    """The Admin REST API reads of the report over seeded objects; GET only, and only
    what `view-users` allows (measured against Keycloak 26.7.0, docs/adr/0025)."""

    def __init__(self) -> None:
        self.users = [
            {"id": BEN, "username": "ben", "enabled": True, "credentials": [{"value": "x"}]},
            {"id": DORA, "username": "dora", "enabled": True},
            {"id": CARLA, "username": "carla", "enabled": False},
            {"id": GLASS, "username": "breakglass", "enabled": True},
            {"id": SVC, "username": "service-account-svc-flow-x", "serviceAccountClientId": "svc"},
        ]
        self.roles = {
            BEN: (["user", "flow-author"], {"studio": ["studio-member"]}),
            DORA: (["user", "papaia-admin", "papaia-auditor"], {}),
            CARLA: (["user"], {}),
            GLASS: (["papaia-admin"], {"realm-management": ["realm-admin"]}),
        }
        self.groups = {BEN: ["/buendel/mitarbeit"], DORA: ["/buendel/verwaltung"]}
        self.offline = {(BEN, FLOW_UUID): 2}
        self.calls: list[str] = []

    def call(self, path: str):
        self.calls.append(path)
        if path == "" or path.startswith("/clients"):
            raise rp.SourceError("Keycloak answered HTTP 403")  # no view-realm, view-clients
        if path.startswith("/users?"):
            query = dict(urllib.parse.parse_qsl(path.partition("?")[2]))
            first, size = int(query["first"]), int(query["max"])
            return copy.deepcopy(self.users[first : first + size])
        parts = path.strip("/").split("/")
        if parts[2:] == ["role-mappings"]:
            realm, clients = self.roles[parts[1]]
            return {
                "realmMappings": [{"name": r} for r in realm],
                "clientMappings": {
                    c: {"client": c, "mappings": [{"name": r} for r in names]}
                    for c, names in clients.items()
                },
            }
        if parts[2:] == ["role-mappings", "realm", "composite"]:
            realm, _ = self.roles[parts[1]]
            extra = ["flow-admin", "studio-admin"] if "papaia-admin" in realm else []
            return [{"name": r} for r in realm + extra + ["default-roles-papaia"]]
        if parts[2] == "groups":
            return [{"path": p, "name": p.rsplit("/", 1)[1]} for p in self.groups.get(parts[1], [])]
        if parts[2] == "offline-sessions":
            return [{"id": str(i)} for i in range(self.offline.get((parts[1], parts[3]), 0))]
        raise AssertionError(path)


def inputs_document(**changes) -> dict:
    """An inputs file as papaia-ctl writes it (lib/access_report.build_inputs)."""
    document = {
        "format": rp.INPUTS_FORMAT,
        "written_at": "2026-11-22T08:30:00Z",
        "module_clients": [{"id": FLOW_UUID, "client_id": "flow-engine"}],
        "service_accounts": [
            {
                "id": "svc-flow-paperless",
                "module": "papaia-flow",
                "owner_sub": DORA,
                "deputy_sub": BEN,
                "audiences": ["paperless"],
                "effects": ["r", "w"],
            }
        ],
        "pairings": [
            {"client": "flow-engine", "audience": "paperless", "effects": ["r", "w"],
             "requested_by": "host:anna", "confirmed_by": "host:bert"},
            {"client": "studio-api", "audience": "paperless", "effects": ["r"],
             "requested_by": "host:anna", "confirmed_by": "host:anna"},
        ],
        "breakglass_ids": [GLASS],
        "sessions": {
            "offline": {"idle_days": 90, "max_age_days": 180},
            "delegations": DELEGATIONS,
        },
        "recertification_days": 180,
    }
    document.update(changes)
    return document


def _snapshot(realm: FakeRealm | None = None, **changes) -> rp.Snapshot:
    return rp.collect((realm or FakeRealm()).call, rp.parse_inputs(inputs_document(**changes)))


def _rows(doc: dict) -> dict[str, dict]:
    return {row["key"]: row for row in doc["rows"]}


# ─────────────────────────────────────────────────────────────────────────
# content
# ─────────────────────────────────────────────────────────────────────────


def test_the_person_report_lists_the_seeded_objects():
    doc = rp.build(_snapshot(), "person", [], NOW)
    rows = _rows(doc)

    assert sorted(rows) == sorted(f"person:{s}" for s in (BEN, DORA, CARLA, GLASS))
    ben = rows[f"person:{BEN}"]
    assert ben["username"] == "ben" and ben["enabled"] is True
    assert ben["realm_roles"] == ["flow-author", "user"]
    assert ben["module_roles"] == {"studio": ["studio-member"]}
    assert ben["groups"] == ["/buendel/mitarbeit"]
    assert ben["service_accounts"] == {"owner": [], "deputy": ["svc-flow-paperless"]}
    assert ben["delegations"] == {"flow-engine": 2}
    assert rows[f"person:{DORA}"]["service_accounts"] == {
        "owner": ["svc-flow-paperless"],
        "deputy": [],
    }
    assert rows[f"person:{CARLA}"]["enabled"] is False
    assert f"person:{SVC}" not in rows
    assert doc["sessions"] == {
        "offline": {"idle_days": 90, "max_age_days": 180},
        "delegations": DELEGATIONS,
    }
    assert doc["inputs_written_at"] == "2026-11-22T08:30:00Z"


def test_the_report_reads_only_what_view_users_allows():
    realm = FakeRealm()
    rp.build(rp.collect(realm.call, rp.parse_inputs(inputs_document())), "person", [], NOW)
    assert realm.calls and all(path.startswith("/users") for path in realm.calls)
    assert "briefRepresentation=true" in realm.calls[0]
    # Every path is one the report account's client lets through.
    assert all(idp._PATH_RE.match(path) for path in realm.calls)


def test_separation_conflicts_and_the_emergency_account_are_marked():
    rows = _rows(rp.build(_snapshot(), "person", [], NOW))
    assert rows[f"person:{DORA}"]["separation_conflict"] == ["papaia-admin", "papaia-auditor"]
    assert rows[f"person:{BEN}"]["separation_conflict"] == []
    assert rows[f"person:{GLASS}"]["breakglass"] is True
    assert rows[f"person:{BEN}"]["breakglass"] is False
    other = _rows(rp.build(_snapshot(breakglass_ids=[]), "person", [], NOW))
    assert other[f"person:{GLASS}"]["breakglass"] is False


def test_the_report_holds_no_secret_and_no_content():
    text = json.dumps(rp.build(_snapshot(), "person", [], NOW)) + json.dumps(
        rp.build(_snapshot(), "system", [], NOW)
    )
    assert '"credentials"' not in text


def test_the_system_report_lists_exchange_rights_and_service_accounts_per_entry():
    pairings = inputs_document()["pairings"] + [
        {"client": "papaia-manager", "audience": "papaia-audit", "effects": ["r"],
         "requested_by": "platform", "confirmed_by": "platform"}
    ]
    rows = _rows(rp.build(_snapshot(pairings=pairings), "system", [], NOW))

    assert sorted(rows) == ["system:papaia-audit", "system:paperless"]
    assert rows["system:paperless"]["exchange_clients"][0] == {
        "client": "flow-engine",
        "effects": ["r", "w"],
        "requested_by": "host:anna",
        "confirmed_by": "host:bert",
    }
    assert rows["system:paperless"]["service_accounts"] == [
        {"id": "svc-flow-paperless", "module": "papaia-flow", "effects": ["r", "w"]}
    ]
    # The platform pairing of the realm sync is listed like any other exchange right.
    assert rows["system:papaia-audit"]["exchange_clients"] == [
        {"client": "papaia-manager", "effects": ["r"], "requested_by": "platform",
         "confirmed_by": "platform"}
    ]
    assert rows["system:paperless"]["target_rights"] == "im Zielsystem geführt"


# ─────────────────────────────────────────────────────────────────────────
# determinism, checksum, recertification
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("by", ["person", "system"])
def test_the_checksum_is_the_one_papaia_ctl_built_before_the_move(by):
    doc = rp.build(_snapshot(), by, [], NOW)
    assert doc["checksum"] == BEFORE[by]
    if by == "person":
        assert _rows(doc)[f"person:{BEN}"]["digest"] == BEFORE_BEN


def test_two_builds_are_equal_and_a_removed_role_changes_exactly_that_row():
    first = rp.build(_snapshot(), "person", [], NOW)
    second = rp.build(_snapshot(), "person", [], NOW + timedelta(minutes=5))
    assert first["checksum"] == second["checksum"] and first["rows"] == second["rows"]

    realm = FakeRealm()
    realm.users.reverse()  # another order from the realm changes nothing
    realm.roles[BEN] = (["user"], {"studio": ["studio-member"]})
    third = rp.build(_snapshot(realm), "person", [], NOW)

    assert third["checksum"] != first["checksum"]
    before, after = _rows(first), _rows(third)
    assert [key for key in before if before[key] != after[key]] == [f"person:{BEN}"]


def _confirmation(key: str, digest: str, days_ago: int) -> dict:
    at = NOW - timedelta(days=days_ago)
    return {
        "key": key,
        "digest": digest,
        "confirmed_at": at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "confirmed_by": "P-ABCDEFGH",
    }


def test_each_row_carries_its_last_confirmation_and_old_ones_are_due():
    plain = _rows(rp.build(_snapshot(), "person", [], NOW))
    ben, dora = plain[f"person:{BEN}"], plain[f"person:{DORA}"]
    assert ben["last_confirmed_at"] is None and ben["confirmation_due"] is True

    confirmations = [
        _confirmation(f"person:{BEN}", ben["digest"], 10),
        _confirmation(f"person:{DORA}", dora["digest"], 181),
        _confirmation(f"person:{CARLA}", "sha256:" + "0" * 64, 1),
    ]
    doc = rp.build(_snapshot(), "person", confirmations, NOW)
    rows = _rows(doc)
    assert rows[f"person:{BEN}"]["last_confirmed_at"] == confirmations[0]["confirmed_at"]
    assert rows[f"person:{BEN}"]["confirmation_due"] is False
    assert rows[f"person:{DORA}"]["confirmation_due"] is True  # older than 180 days
    assert rows[f"person:{CARLA}"]["confirmation_due"] is True  # another content
    short = _rows(rp.build(_snapshot(), "person", confirmations, NOW, period_days=7))
    assert short[f"person:{BEN}"]["confirmation_due"] is True
    # The confirmation state changes no checksum.
    assert doc["checksum"] == BEFORE["person"]


# ─────────────────────────────────────────────────────────────────────────
# formats
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("by", ["person", "system"])
def test_the_json_report_follows_the_published_schema(by):
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    doc = rp.build(_snapshot(), by, [], NOW)
    errors = list(Draft202012Validator(schema).iter_errors(doc))
    assert not errors, errors
    assert doc["format"] == "papaia.access-report/1" and doc["by"] == by


def test_the_csv_report_has_one_line_per_row_and_no_formula():
    realm = FakeRealm()
    realm.users[1]["username"] = "=cmd|calc"
    doc = rp.build(_snapshot(realm), "person", [], NOW)
    lines = list(csv.DictReader(io.StringIO(rp.render(doc, "csv"))))
    assert len(lines) == 4
    ben = next(line for line in lines if line["key"] == f"person:{BEN}")
    assert ben["realm_roles"] == "flow-author user"
    assert ben["module_roles"] == "studio=studio-member"
    assert ben["delegations"] == "flow-engine=2"
    dora = next(line for line in lines if line["key"] == f"person:{DORA}")
    assert dora["username"] == "'=cmd|calc"
    assert rp.render(doc, "json") == rp.render(doc, "json")


# ─────────────────────────────────────────────────────────────────────────
# the inputs file
# ─────────────────────────────────────────────────────────────────────────


def test_the_inputs_fixture_follows_the_published_schema():
    schema = json.loads(INPUTS_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert not list(Draft202012Validator(schema).iter_errors(inputs_document()))


@pytest.mark.parametrize(
    "changes",
    [
        {"format": "papaia.access-report-inputs/2"},
        {"written_at": "yesterday"},
        {"extra": 1},
        {"module_clients": [{"id": "a b", "client_id": "flow-engine"}]},
        {"module_clients": [{"id": FLOW_UUID, "client_id": "flow-engine", "secret": "x"}]},
        {"service_accounts": [{"id": "robot"}]},
        {"pairings": [{"client": "a", "audience": "b", "effects": ["z"],
                       "requested_by": None, "confirmed_by": None}]},
        {"pairings": [{"client": "a", "audience": "b", "effects": ["r"],
                       "requested_by": "anna", "confirmed_by": None}]},
        {"breakglass_ids": ["../x"]},
        {"sessions": {"offline": {"idle_days": -1, "max_age_days": None}, "delegations": {}}},
        {"recertification_days": 10},
        {"recertification_days": True},
    ],
)
def test_an_unusable_inputs_file_is_refused(changes):
    document = inputs_document(**changes)
    with pytest.raises(rp.InputsInvalid):
        rp.parse_inputs(document)
    schema = json.loads(INPUTS_SCHEMA.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(document))


def test_a_missing_or_broken_inputs_file_is_its_own_error(tmp_path):
    with pytest.raises(rp.InputsMissing):
        rp.load_inputs(tmp_path / rp.INPUTS_FILE)
    path = tmp_path / rp.INPUTS_FILE
    path.write_text("{", encoding="utf-8")
    with pytest.raises(rp.InputsInvalid):
        rp.load_inputs(path)
    path.write_text(json.dumps(inputs_document()), encoding="utf-8")
    assert rp.load_inputs(path).recertification_days == 180


# ─────────────────────────────────────────────────────────────────────────
# the Admin API client of the report account
# ─────────────────────────────────────────────────────────────────────────


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.fixture
def account(tmp_path) -> Path:
    keys = sak.KeyStore(tmp_path / "service-accounts")
    keys.generate(idp.CLIENT_ID)
    return tmp_path / "service-accounts" / idp.CLIENT_ID


def test_the_assertion_is_es256_with_the_key_id_the_realm_sync_registers(account):
    jwk = sak.KeyStore(account.parent).public_jwk(idp.CLIENT_ID)
    token = idp.AccountKey(account).assertion("https://auth.example.test/realms/papaia", now=100)
    head, body, signature = token.split(".")
    header, claims = json.loads(_b64d(head)), json.loads(_b64d(body))
    assert header == {"alg": "ES256", "kid": jwk["kid"], "typ": "JWT"}
    assert claims["iss"] == claims["sub"] == "svc-papaia-audit-report"
    assert claims["aud"] == "https://auth.example.test/realms/papaia"
    assert claims["exp"] - claims["iat"] == 60
    raw = _b64d(signature)
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    public.verify(
        encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
        f"{head}.{body}".encode(),
        ec.ECDSA(hashes.SHA256()),
    )


def test_a_key_readable_by_others_is_refused(account):
    (account / idp.KEY_FILE).chmod(0o644)
    with pytest.raises(rp.SourceError, match="owner only"):
        idp.AccountKey(account).assertion("aud")


class _Answer:
    def __init__(self, body: object) -> None:
        self.raw = json.dumps(body).encode()

    def read(self, limit: int) -> bytes:
        return self.raw[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def test_the_client_signs_in_with_the_assertion_and_sends_get_only(account, monkeypatch):
    sent = []

    def urlopen(request, timeout, context):
        sent.append(request)
        url = request.full_url
        if url.endswith("/.well-known/openid-configuration"):
            return _Answer({"issuer": "https://auth.example.test/realms/papaia"})
        if url.endswith("/protocol/openid-connect/token"):
            return _Answer({"access_token": "header.payload.sig", "expires_in": 300})
        return _Answer([])

    monkeypatch.setattr(idp.urllib.request, "urlopen", urlopen)
    reader = idp.AdminReader("https://keycloak:8443", None, idp.AccountKey(account))
    assert reader(f"/users/{BEN}/groups") == []
    assert reader(f"/users/{BEN}/role-mappings") == []

    token_request = sent[1]
    form = dict(urllib.parse.parse_qsl(token_request.data.decode()))
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == "svc-papaia-audit-report"
    assert form["client_assertion_type"].endswith("jwt-bearer") and "client_secret" not in form
    admin = [r for r in sent if "/admin/realms/papaia/" in r.full_url]
    assert len(admin) == 2 and all(r.get_method() == "GET" and r.data is None for r in admin)
    assert admin[0].get_header("Authorization") == "Bearer header.payload.sig"
    assert len(sent) == 4  # one sign-in for both reads


@pytest.mark.parametrize(
    "path",
    ["", "/clients", f"/users/{BEN}", f"/users/{BEN}/credentials", "/users?search=a",
     f"/users/{BEN}/role-mappings/realm", "/roles", f"/users/{BEN}/../clients"],
)
def test_the_client_refuses_every_path_outside_the_report(account, monkeypatch, path):
    def urlopen(request, timeout, context):
        raise AssertionError(f"no request expected: {request.full_url}")

    monkeypatch.setattr(idp.urllib.request, "urlopen", urlopen)
    reader = idp.AdminReader("https://keycloak:8443", None, idp.AccountKey(account))
    with pytest.raises(rp.SourceError, match="outside the report"):
        reader(path)


def test_keycloak_errors_become_a_source_error_without_detail(account, monkeypatch):
    def urlopen(request, timeout, context):
        raise idp.urllib.error.URLError("connection refused")

    monkeypatch.setattr(idp.urllib.request, "urlopen", urlopen)
    reader = idp.AdminReader("https://keycloak:8443", None, idp.AccountKey(account))
    with pytest.raises(rp.SourceError, match="not reachable"):
        reader(f"/users/{BEN}/groups")


def test_the_report_module_uses_the_standard_library_only():
    text = (REPO / "src" / "infra" / "audit" / "papaia_audit" / "report.py").read_text()
    imports = {
        line.split()[1].split(".")[0]
        for line in text.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imports <= set(sys.stdlib_module_names) | {"__future__"}, imports
