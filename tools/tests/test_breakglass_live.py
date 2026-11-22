"""`papaia-ctl breakglass` against a throwaway Keycloak of the pinned version: the account
is created, shown by `status`, rotated, and marked in the permission report, with the user
profile Keycloak 26 gives a new realm (no attribute of papaia declared).

Start one with tests/fixtures/keycloak/docker-compose.yml and point the tests at it:

    export PAPAIA_TEST_KEYCLOAK_URL=http://127.0.0.1:58340
    export PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD=<the bootstrap admin password>

Without both variables the tests are skipped. They replace the realm `papaia` of that
Keycloak, so never point them at an installation.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from lib import access_report as ar
from lib import breakglass as bg
from lib import lifecycle_account as la
from lib import realm_sync as rs
from tests.test_realm_sync_live import PASSWORD, URL, _admin

pytestmark = pytest.mark.skipif(
    not (URL and PASSWORD),
    reason="no throwaway Keycloak (PAPAIA_TEST_KEYCLOAK_URL, PAPAIA_TEST_KEYCLOAK_ADMIN_PASSWORD)",
)


def _call(method: str, path: str, body=None):
    return _admin(method, f"/papaia{path}", body)


class _Audit:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def write(self, change, result, error_code=None, **kwargs) -> None:
        self.rows.append((change.operation, result))


@pytest.fixture(scope="module")
def realm(tmp_path_factory):
    try:
        _admin("DELETE", "/papaia")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    _admin("POST", "", {"realm": "papaia", "enabled": True})
    _call("POST", "/roles", {"name": bg.REALM_ROLE})
    config = tmp_path_factory.mktemp("config")
    keys = rs.keystore(config)
    keys.write(la.CLIENT_ID, la.GROUP_FILE, b"group\n")  # the lifecycle profile is on
    return {"keys": keys, "records": bg.record_store(config)}


def test_create_status_rotate_and_the_report_mark_on_the_pinned_keycloak(realm):
    keys, records = realm["keys"], realm["records"]
    audit, tty = _Audit(), io.StringIO()
    uid = bg.create(_call, audit, tty, keys, records=records, address="betrieb@example.test")
    assert audit.rows == [("created", "allowed")]

    user = _call("GET", f"/users/{uid}")
    assert user["username"] == bg.USERNAME and user["enabled"] is True
    assert user["requiredActions"] == ["CONFIGURE_TOTP"]
    assert user["email"] == "betrieb@example.test"
    assert {r["name"] for r in _call("GET", f"/users/{uid}/role-mappings/realm")} >= {
        bg.REALM_ROLE
    }
    management = _call("GET", "/clients?clientId=realm-management")[0]
    assert [r["name"] for r in _call(
        "GET", f"/users/{uid}/role-mappings/clients/{management['id']}"
    )] == [bg.MANAGEMENT_ROLE]
    assert keys.read(la.CLIENT_ID, bg.IDS_FILE) == f"{uid}\n".encode()

    status = bg.status(_call, keys, records=records)
    assert status["present"] is True and status["monitored"] is True
    assert status["second_factor"] is False and status["second_factor_pending"] is True
    assert status["rotation_due"] is False and status["rotated_at"]

    first = tty.getvalue()
    bg.rotate(_call, audit, tty, keys, records=records)
    assert audit.rows[-1] == ("rotated", "allowed")
    assert tty.getvalue() != first
    # The rotation left the account as it was: still enabled, still asking for a factor.
    after = _call("GET", f"/users/{uid}")
    assert after["enabled"] is True and after["requiredActions"] == ["CONFIGURE_TOTP"]
    assert after["email"] == "betrieb@example.test"

    with pytest.raises(bg.BreakglassError, match="exists"):
        bg.create(_call, _Audit(), io.StringIO(), keys, records=records,
                  address="betrieb@example.test")

    snapshot = ar.collect(
        _call,
        service_accounts=[],
        pairings=[],
        delegations={},
        breakglass_ids=bg.recorded_ids(records),
    )
    marked = {p["username"]: p["breakglass"] for p in snapshot.persons}
    assert marked[bg.USERNAME] is True
    assert json.dumps(status).count(uid) == 0  # the status names no id


def test_an_unrecorded_account_of_that_name_is_refused_and_left_alone(realm, tmp_path):
    other = bg.record_store(tmp_path / "other-config")
    with pytest.raises(bg.BreakglassError, match="not the emergency account"):
        bg.status(_call, realm["keys"], records=other)
    with pytest.raises(bg.BreakglassError, match="not the emergency account"):
        bg.rotate(_call, _Audit(), io.StringIO(), realm["keys"], records=other)
    (user,) = _call("GET", f"/users?username={bg.USERNAME}&exact=true")
    assert user["enabled"] is True
