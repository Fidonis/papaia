"""The emergency account (tools/lib/breakglass.py, security 1.15) and its sign-in alert in
papaia-lifecycle (src/infra/lifecycle/lifecycle.py): created sealed with a second factor
required, the password shown once on the terminal and never in an output, a log or an
audit row; rotation; the status that flags a use until the next rotation; every sign-in of
the account one `breakglass_login` row and an alert of the lifecycle service.

The realm double drops every user attribute, as Keycloak 26 does for attributes its user
profile does not declare: the account is known by the id papaia-ctl records, never by an
attribute.
"""

from __future__ import annotations

import io
import json
import os
import stat
import urllib.parse
from pathlib import Path

import pytest
from test_lifecycle import PERSON, _ms, _rows, lc, stack  # noqa: F401  (fixture)

from lib import breakglass as bg
from lib import lifecycle_account as la
from lib import realm_sync as rs
from lib import service_account_keys as sak

GLASS = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b"
ADMIN_ROLE = {"id": "r-admin", "name": "papaia-admin"}
REALM_ADMIN = {"id": "r-realm-admin", "name": "realm-admin"}
RM_CLIENT = "c0ffee00-0000-4000-8000-000000000001"


class FakeAdmin:
    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.passwords: dict[str, str] = {}
        self.realm_roles: dict[str, list[str]] = {}
        self.client_roles: dict[str, list[str]] = {}
        self.credentials: dict[str, list[str]] = {}
        self.logins: list[dict] = []
        self.calls: list[tuple[str, str, object]] = []
        self.fail_client_roles = False

    def call(self, method: str, path: str, body: object = None):
        self.calls.append((method, path, body))
        base, _, query = path.partition("?")
        q = urllib.parse.parse_qs(query)
        if (method, base) == ("GET", "/users"):
            name = q["username"][0]
            return [dict(u) for u in self.users.values() if u["username"] == name]
        if (method, base) == ("POST", "/users"):
            assert isinstance(body, dict)
            # Undeclared attributes are dropped (Keycloak 26 user profile).
            user = {k: v for k, v in body.items() if k not in ("credentials", "attributes")}
            user["id"] = GLASS
            self.users[GLASS] = user
            (cred,) = body["credentials"]
            assert cred["type"] == "password" and cred["temporary"] is False
            self.passwords[GLASS] = cred["value"]
            return None
        if (method, base) == ("GET", "/roles/papaia-admin"):
            return ADMIN_ROLE
        if (method, base) == ("GET", "/clients"):
            assert q["clientId"] == ["realm-management"]
            return [{"id": RM_CLIENT, "clientId": "realm-management"}]
        if (method, base) == ("GET", f"/clients/{RM_CLIENT}/roles/realm-admin"):
            return REALM_ADMIN
        if (method, base) == ("GET", "/events"):
            assert q["type"] == ["LOGIN"] and q["user"] == [GLASS]
            return self.logins[:1]
        parts = base.strip("/").split("/")
        uid = parts[1]
        if parts[2:] == ["role-mappings", "realm"] and method == "POST":
            self.realm_roles.setdefault(uid, []).extend(r["name"] for r in body)
            return None
        if parts[2:] == ["role-mappings", "clients", RM_CLIENT] and method == "POST":
            if self.fail_client_roles:
                raise rs.RealmSyncError("HTTP 500")
            self.client_roles.setdefault(uid, []).extend(r["name"] for r in body)
            return None
        if parts[2:] == ["reset-password"] and method == "PUT":
            assert body["temporary"] is False
            self.passwords[uid] = body["value"]
            return None
        if parts[2:] == ["credentials"] and method == "GET":
            return [{"type": t, "secretData": "never-shown"} for t in self.credentials.get(uid, [])]
        if len(parts) == 2 and method == "PUT":
            self.users[uid].update(body)
            return None
        if len(parts) == 2 and method == "DELETE":
            del self.users[uid]
            self.passwords.pop(uid, None)
            return None
        if len(parts) == 2 and method == "GET":
            return dict(self.users[uid])
        raise AssertionError((method, path))


class Audit:
    def __init__(self) -> None:
        self.rows: list[tuple[rs.Change, str]] = []

    def write(self, change, result, error_code=None, **kwargs) -> None:
        self.rows.append((change, result))


@pytest.fixture
def realm() -> FakeAdmin:
    return FakeAdmin()


@pytest.fixture
def config(tmp_path) -> Path:
    return tmp_path / "config"


@pytest.fixture
def keys(config) -> sak.KeyStore:
    store = rs.keystore(config)
    store.write(la.CLIENT_ID, la.GROUP_FILE, b"group\n")  # the lifecycle profile is on
    return store


@pytest.fixture
def records(config):
    return bg.record_store(config)


def _create(realm, keys, records, tty=None, audit=None, address="betrieb@example.test"):
    tty = tty or io.StringIO()
    audit = audit or Audit()
    bg.create(
        realm.call, audit, tty, keys, records=records, address=address, now=1_800_000_000.0
    )
    return tty, audit


def _rotate(realm, keys, records, now, tty=None, audit=None):
    tty = tty or io.StringIO()
    audit = audit or Audit()
    bg.rotate(realm.call, audit, tty, keys, records=records, now=now)
    return tty, audit


def test_the_account_is_created_sealed_with_a_second_factor_and_no_data_rights(
    realm, keys, records
):
    tty, audit = _create(realm, keys, records)

    user = realm.users[GLASS]
    assert user["username"] == "breakglass" and user["enabled"] is True
    assert user["requiredActions"] == ["CONFIGURE_TOTP"]
    assert bg.recorded_ids(records) == frozenset({GLASS})
    assert user["email"] == "betrieb@example.test" and user["emailVerified"] is True
    assert realm.realm_roles[GLASS] == ["papaia-admin"]
    assert realm.client_roles[GLASS] == ["realm-admin"]
    # Administration only: no role of a target system (no data rights).
    assert not any(r.startswith(("qdrant", "paperless")) for r in realm.realm_roles[GLASS])
    ((change, result),) = audit.rows
    assert change.event == "breakglass_change" and change.operation == "created"
    assert result == "allowed"


def test_the_password_is_shown_once_on_the_terminal_only(realm, keys, records, capsys):
    tty, audit = _create(realm, keys, records)

    password = realm.passwords[GLASS]
    assert len(password) >= 24
    assert tty.getvalue().count(password) == 1
    captured = capsys.readouterr()
    assert password not in captured.out + captured.err
    assert password not in repr(audit.rows)
    assert all(password not in json.dumps(body) for m, p, body in realm.calls if m != "POST")
    assert password not in (keys.read(la.CLIENT_ID, bg.IDS_FILE) or b"").decode()
    assert password not in (records.read(bg.USERNAME, bg.RECORD_FILE) or b"").decode()


def test_a_second_create_is_refused_and_rotate_shows_a_new_password(realm, keys, records):
    _create(realm, keys, records)
    first = realm.passwords[GLASS]
    with pytest.raises(bg.BreakglassError):
        _create(realm, keys, records)
    assert realm.passwords[GLASS] == first

    tty, audit = _rotate(realm, keys, records, 1_800_000_100.0)
    assert realm.passwords[GLASS] != first
    assert tty.getvalue().count(realm.passwords[GLASS]) == 1
    assert audit.rows[0][0].operation == "rotated"
    assert json.loads(records.read(bg.USERNAME, bg.RECORD_FILE)) == {
        "id": GLASS,
        "rotated_at": 1_800_000_100,
    }
    # No partial user representation is written: only the password is reset.
    assert not any(m == "PUT" and p == f"/users/{GLASS}" for m, p, _ in realm.calls)


def test_the_record_is_private_to_the_operator(realm, keys, records, config):
    _create(realm, keys, records)
    folder = config / "security" / bg.RECORD_DIR
    assert stat.S_IMODE(os.lstat(folder).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(folder / bg.RECORD_FILE).st_mode) == 0o600


def test_an_account_named_breakglass_that_was_not_recorded_is_never_used(realm, keys, records):
    # Someone with realm-admin added an account of that name; papaia-ctl did not create it.
    realm.users[GLASS] = {"id": GLASS, "username": "breakglass", "enabled": True}
    realm.passwords[GLASS] = "theirs"
    for action in (
        lambda: _create(realm, keys, records),
        lambda: _rotate(realm, keys, records, 1_800_000_100.0),
        lambda: bg.status(realm.call, keys, records=records),
    ):
        with pytest.raises(bg.BreakglassError, match="not the emergency account"):
            action()
    assert realm.passwords[GLASS] == "theirs" and GLASS in realm.users
    assert keys.read(la.CLIENT_ID, bg.IDS_FILE) is None


def test_a_record_of_another_id_does_not_match(realm, keys, records):
    _create(realm, keys, records)
    records.write(bg.USERNAME, bg.RECORD_FILE, b'{"id": "other-id", "rotated_at": 1}')
    with pytest.raises(bg.BreakglassError, match="not the emergency account"):
        bg.status(realm.call, keys, records=records)


def test_a_malformed_record_is_refused(realm, keys, records):
    _create(realm, keys, records)
    for bad in (b"not json", b'{"id": "../x", "rotated_at": 1}', b'{"id": "a", "rotated_at": -1}',
                b'{"id": "a"}', b"[]"):
        records.write(bg.USERNAME, bg.RECORD_FILE, bad)
        with pytest.raises(bg.BreakglassError, match="record"):
            bg.recorded_ids(records)


def test_a_create_that_cannot_be_completed_removes_the_new_account(realm, keys, records, capsys):
    realm.fail_client_roles = True
    tty, audit = io.StringIO(), Audit()
    with pytest.raises(rs.RealmSyncError):
        _create(realm, keys, records, tty=tty, audit=audit)

    # The account nobody holds a password of is gone, nothing is recorded, nothing shown.
    assert realm.users == {}
    assert any(m == "DELETE" and p == f"/users/{GLASS}" for m, p, _ in realm.calls)
    assert tty.getvalue() == ""
    assert records.read(bg.USERNAME, bg.RECORD_FILE) is None
    ((change, result),) = audit.rows
    assert change.operation == "created" and result == "error"
    # A new attempt works.
    realm.fail_client_roles = False
    _create(realm, keys, records)
    assert bg.recorded_ids(records) == frozenset({GLASS})


def test_an_address_is_validated(realm, keys, records):
    for bad in ("", "no-at-sign", "a@b", "x" * 300 + "@example.test", "a b@example.test"):
        with pytest.raises(bg.BreakglassError):
            _create(realm, keys, records, address=bad)
    assert realm.users == {}


def test_the_lifecycle_service_learns_the_account_id(realm, keys, records):
    _create(realm, keys, records)
    assert keys.read(la.CLIENT_ID, bg.IDS_FILE) == f"{GLASS}\n".encode()


def test_the_status_flags_a_use_until_the_next_rotation(realm, keys, records):
    _create(realm, keys, records)
    realm.credentials[GLASS] = ["password", "otp"]
    status = bg.status(realm.call, keys, records=records)
    assert status == {
        "present": True,
        "enabled": True,
        "monitored": True,
        "second_factor": True,
        "second_factor_pending": True,
        "rotated_at": "2027-01-15T08:00:00Z",
        "last_login": None,
        "rotation_due": False,
    }
    realm.logins = [{"time": 1_800_000_500_000, "type": "LOGIN", "userId": GLASS}]
    status = bg.status(realm.call, keys, records=records)
    assert status["last_login"] == "2027-01-15T08:08:20Z" and status["rotation_due"] is True
    assert "never-shown" not in json.dumps(status)
    _rotate(realm, keys, records, 1_800_000_600.0)
    assert bg.status(realm.call, keys, records=records)["rotation_due"] is False


def test_without_the_account_the_status_says_so(realm, keys, records):
    assert bg.status(realm.call, keys, records=records) == {"present": False, "monitored": True}


def test_without_the_lifecycle_profile_every_command_warns_that_sign_ins_go_unseen(
    realm, records, config, capsys
):
    keys = rs.keystore(config)  # no folder of svc-papaia-lifecycle: the profile is off
    _create(realm, keys, records)
    assert "WARNING" in capsys.readouterr().err
    _rotate(realm, keys, records, 1_800_000_100.0)
    assert "WARNING" in capsys.readouterr().err
    status = bg.status(realm.call, keys, records=records)
    assert status["monitored"] is False
    err = capsys.readouterr().err
    assert "WARNING" in err and "lifecycle" in err
    assert keys.read(la.CLIENT_ID, bg.IDS_FILE) is None


def test_with_the_lifecycle_profile_nothing_is_warned(realm, keys, records, capsys):
    _create(realm, keys, records)
    _rotate(realm, keys, records, 1_800_000_100.0)
    bg.status(realm.call, keys, records=records)
    assert "WARNING" not in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────
# papaia-lifecycle: the sign-in alert
# ─────────────────────────────────────────────────────────────────────────


def test_the_realm_stores_sign_in_events_for_the_alert():
    assert "LOGIN" in la.USER_EVENT_TYPES and "LOGIN" in lc.USER_EVENT_TYPES
    assert set(la.USER_EVENT_TYPES) == set(lc.USER_EVENT_TYPES)


def test_a_sign_in_of_the_emergency_account_is_one_audit_row_and_an_alert(stack, capsys):  # noqa: F811
    kc = stack.keycloak
    kc.add_user(PERSON)
    kc.breakglass_ids = lambda: frozenset({GLASS})
    stack.service.start()
    kc.user_event("LOGIN", GLASS, _ms(stack, 10), client="security-admin-console")
    kc.user_event("LOGIN", PERSON, _ms(stack, 20), client="flow-web")
    stack.service.step()

    rows = [r for r in _rows(stack.out) if r["event"] == "breakglass_login"]
    (row,) = rows
    assert row["object_ref"] == {"type": "user", "id": GLASS}
    assert row["operation"] == "lifecycle.breakglass_login" and row["result"] == "allowed"
    assert "ALERT" in capsys.readouterr().err
    # A sign-in of anyone else writes nothing and changes nothing.
    assert not any(m != "GET" for m, _ in kc.calls)
    stack.service.step()
    assert len([r for r in _rows(stack.out) if r["event"] == "breakglass_login"]) == 1


def test_the_service_reads_the_account_ids_from_its_folder(tmp_path):
    folder = tmp_path / "account"
    folder.mkdir(mode=0o700)
    client = lc.AccountClient("https://keycloak:8443", None, folder)
    assert client.breakglass_ids() == frozenset()
    path = folder / lc.BREAKGLASS_FILE
    path.write_text(f"{GLASS}\n", encoding="ascii")
    path.chmod(0o600)
    assert client.breakglass_ids() == frozenset({GLASS})
    path.write_text("../etc\n", encoding="ascii")
    with pytest.raises(lc.LifecycleError):
        client.breakglass_ids()


def test_the_lifecycle_file_name_matches(tmp_path):
    assert bg.IDS_FILE == lc.BREAKGLASS_FILE
    assert Path(bg.__file__).name == "breakglass.py"
