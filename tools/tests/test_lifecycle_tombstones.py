"""papaia-lifecycle: name index, tombstones, name lock and `find` (security 1.14 no. 2b,
RE-101): `papaia-ctl person find` finds deactivated and deleted accounts by user name or
mail; the tombstone list holds HMAC values only, never a clear name; a new account with
the name of a deleted one is disabled. Keycloak is the in-memory admin API of
`test_lifecycle.py`.
"""

from __future__ import annotations

import json

import pytest

from tests.test_lifecycle import OTHER, PERSON, THIRD, _rows, lc
from tests.test_lifecycle import stack as stack  # noqa: F401 - the shared fixture

NAME = "Anna.Berger"
MAIL = "Anna.Berger@example.org"


def _person(stack, uid: str = PERSON, *, name: str = NAME, mail: str = MAIL,
            enabled: bool = True) -> None:
    stack.keycloak.add_user(uid, enabled=enabled)
    stack.keycloak.users[uid].update({"username": name.lower(), "email": mail})


def _ref(stack, value: str) -> str:
    return lc.name_ref(stack.erasure_key, value)


def _state(stack) -> dict:
    with stack.store.locked():
        return stack.store.load()


def _deleted(stack, uid: str = PERSON) -> None:
    stack.keycloak.users.pop(uid)
    stack.keycloak.event("DELETE", uid, int(stack.clock.now * 1000) + 100)
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()


def test_the_round_indexes_name_and_mail_as_hmac_only(stack):
    _person(stack)
    stack.service.start()
    stack.service.step()
    item = _state(stack)["names"][PERSON]
    assert item["name"] == _ref(stack, NAME) and item["mail"] == _ref(stack, MAIL)
    assert item["enabled"] is True
    raw = (stack.key_dir / lc.STATE_FILE).read_text(encoding="utf-8").casefold()
    assert "anna" not in raw and "example.org" not in raw


def test_a_deleted_account_becomes_a_tombstone_without_a_clear_name(stack):
    _person(stack)
    stack.service.start()
    stack.service.step()
    _deleted(stack)
    state = _state(stack)
    assert PERSON not in state["names"]
    tomb = state["tombstones"][PERSON]
    assert tomb["name"] == _ref(stack, NAME) and tomb["mail"] == _ref(stack, MAIL)
    raw = (stack.key_dir / lc.STATE_FILE).read_text(encoding="utf-8").casefold()
    assert "anna" not in raw and "berger" not in raw and "example.org" not in raw


def test_a_deletion_missed_while_stopped_becomes_a_tombstone_on_the_next_round(stack):
    _person(stack)
    stack.service.start()
    stack.service.step()
    stack.keycloak.users.pop(PERSON)
    stack.clock.now += lc.RECONCILE_SECONDS + 1
    stack.service.step()
    assert PERSON in _state(stack)["tombstones"]


def test_find_finds_a_deleted_account_by_its_mail(stack):
    _person(stack)
    stack.service.start()
    stack.service.step()
    _deleted(stack)
    found = lc.find(stack.store, None, _ref(stack, "  anna.BERGER@example.org "))
    assert found == [{"sub": PERSON, "status": "deleted", "last_login": None,
                      "deleted": found[0]["deleted"]}]
    assert found[0]["deleted"] is not None


def test_find_finds_a_disabled_account_by_name_with_its_last_sign_in(stack):
    _person(stack)
    _person(stack, OTHER, name="ben", mail="ben@example.org")
    stack.service.start()
    stack.service.step()
    stack.keycloak.user_event("LOGIN", PERSON, int(stack.clock.now * 1000) + 100)
    stack.keycloak.users[PERSON]["enabled"] = False
    stack.keycloak.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 200)
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    [found] = lc.find(stack.store, _ref(stack, NAME), None)
    assert found["sub"] == PERSON and found["status"] == "disabled"
    assert found["last_login"] is not None and found["deleted"] is None
    assert lc.find(stack.store, _ref(stack, "nobody"), None) == []


@pytest.mark.parametrize("name,mail", [(None, None), ("not-a-ref", None), (None, "Anna")])
def test_find_takes_hmac_values_only(stack, name, mail):
    with pytest.raises(lc.LifecycleError):
        lc.find(stack.store, name, mail)


def test_the_find_command_prints_subs_and_states_only(stack, capsys):
    _person(stack)
    stack.service.start()
    stack.service.step()
    _deleted(stack)
    capsys.readouterr()
    code = lc.main(["find", f"--key-dir={stack.key_dir}",
                    f"--name-ref={_ref(stack, NAME)}"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [p["sub"] for p in out["persons"]] == [PERSON]
    assert set(out["persons"][0]) == {"sub", "status", "last_login", "deleted"}


def test_a_new_account_with_the_name_of_a_deleted_one_is_disabled_once(stack, capsys):
    _person(stack)
    stack.service.start()
    stack.service.step()
    _deleted(stack)
    _person(stack, THIRD)  # same user name and mail
    stack.clock.now += lc.RECONCILE_SECONDS + 1
    stack.service.step()
    assert stack.keycloak.users[THIRD]["enabled"] is False
    assert ("PUT", f"/users/{THIRD}") in stack.keycloak.calls
    locked = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.account_name_locked"]
    assert len(locked) == 1 and locked[0]["object_ref"] == {"type": "user", "id": THIRD}
    assert "ALERT" in capsys.readouterr().err
    # An administrator who checked the person enables the account again: it stays on.
    stack.keycloak.users[THIRD]["enabled"] = True
    stack.clock.now += lc.RECONCILE_SECONDS + 1
    stack.service.step()
    assert stack.keycloak.users[THIRD]["enabled"] is True


def test_an_account_with_another_name_is_not_locked(stack):
    _person(stack)
    stack.service.start()
    stack.service.step()
    _deleted(stack)
    _person(stack, THIRD, name="carla", mail="carla@example.org")
    stack.clock.now += lc.RECONCILE_SECONDS + 1
    stack.service.step()
    assert stack.keycloak.users[THIRD]["enabled"] is True


def test_a_state_without_names_is_taken_over(stack):
    stack.service.start()
    with stack.store.locked():
        state = stack.store.load()
        del state["names"], state["tombstones"]
        (stack.key_dir / lc.STATE_FILE).write_bytes(lc.canonical(state))
    assert _state(stack)["names"] == {} and _state(stack)["tombstones"] == {}


@pytest.mark.parametrize("names,tombstones", [
    ({PERSON: {"name": "Anna", "mail": None, "enabled": True, "login": None,
               "locked": False}}, {}),
    ({}, {PERSON: {"name": "a" * 64, "mail": None}}),
])
def test_a_malformed_index_is_refused(stack, names, tombstones):
    state = lc._new_state()
    state["names"], state["tombstones"] = names, tombstones
    with pytest.raises(lc.LifecycleError):
        lc._check_state(state)
