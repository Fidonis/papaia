"""papaia-lifecycle: reconciliation independent of events (security 1.12 no. 2).

Missed events (service stopped, events expired, a deactivation without a Keycloak
event) must not leave delegations alive. At start and every hour the service reads
the deactivated accounts and removes what they still hold; an account that comes back
loses the consents from before its deactivation; after a gap longer than the event
retention every consent at a holder client goes. Keycloak is the in-memory admin API
of `test_lifecycle.py`.
"""

from __future__ import annotations

import io
import json

import pytest

from lib import doctor
from lib import lifecycle_account as la
from lib import realm_sync as rs
from tests.test_lifecycle import OTHER, PERSON, _published, _rows, lc
from tests.test_lifecycle import stack as stack  # noqa: F401 - the shared fixture

HOUR = 3600
DAY = 24 * HOUR


def _restart(stack, out: io.StringIO | None = None):
    """A new process on the same volumes, as after `docker compose up` again."""
    stack.out = out or io.StringIO()
    stack.service = lc.Lifecycle(
        stack.keycloak,
        lc.Store(stack.key_dir),
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=stack.out,
        clock=stack.clock,
    )
    stack.service.start()
    return stack.service


def _ran_once(stack) -> None:
    stack.service.start()
    stack.service.step()


def _ms(stack) -> int:
    return int(stack.clock.now * 1000)


def _health(stack) -> tuple[int, dict]:
    return lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)


# ─────────────────────────────────────────────────────────────────────────
# deactivated while the service was stopped
# ─────────────────────────────────────────────────────────────────────────


def test_a_deactivation_missed_while_stopped_is_revoked_at_start(stack):
    """Stopped, person deactivated (no event reaches the service), started: the offline
    session ends at once (well within 300 s), reactivation revives nothing."""
    kc = stack.keycloak
    kc.add_user(PERSON, consents=("flow-engine", "assist-gate"))
    kc.add_user(OTHER)
    _ran_once(stack)
    assert kc.consents[PERSON] == ["flow-engine", "assist-gate"]

    # Stopped for ten minutes; the account is deactivated without an event the service
    # sees (expired, or from a directory behind Keycloak).
    stack.clock.now += 600
    kc.users[PERSON]["enabled"] = False
    started = stack.clock.now
    _restart(stack).step()

    assert stack.clock.now - started <= 300
    assert ("POST", f"/users/{PERSON}/logout") in kc.calls
    assert kc.consents[PERSON] == []
    assert kc.consents[OTHER] == ["flow-engine"]
    entries = _published(stack.state_dir)["entries"]
    assert entries == [{"sub": PERSON, "since": int(started), "reason": "account_disabled"}]
    rows = [r for r in _rows(stack.out) if (r["object_ref"] or {}).get("id") == PERSON]
    assert [r["operation"] for r in rows] == [
        "lifecycle.logout",
        "lifecycle.consent_delete",
        "lifecycle.consent_delete",
    ]
    assert len({r["correlation_id"] for r in rows}) == 1

    # Reactivated: nothing comes back, and a new grant after the reactivation stays.
    kc.users[PERSON]["enabled"] = True
    stack.clock.now += 30
    kc.grant(PERSON, "flow-engine", _ms(stack))
    kc.event("UPDATE", PERSON, _ms(stack) + 5)
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    assert kc.consents[PERSON] == ["flow-engine"]
    stack.clock.now += HOUR + 1
    stack.service.step()
    assert kc.consents[PERSON] == ["flow-engine"]
    code, report = _health(stack)
    assert code == 0, report
    assert report["disabled_with_consent"] == 0


def _stopped_while(stack, change) -> float:
    """The service ran, was stopped for ten minutes while `change(t_ms)` happened in
    Keycloak (with its admin events), and is started again; returns the start time."""
    _ran_once(stack)
    stack.clock.now += 300
    change(_ms(stack))
    stack.clock.now += 300
    started = stack.clock.now
    _restart(stack).step()
    return started


def test_deactivated_and_reactivated_while_stopped_ends_the_old_delegations(stack):
    """sicherheit §1.12 no. 2: stopped, account deactivated and activated again (both
    events kept by Keycloak), started: the delegations from before are gone after the
    first round. The account reads active, so only the late read of its update events
    tells; every consent at a holder client from before the last of them goes."""
    kc = stack.keycloak
    kc.add_user(PERSON, consents=("flow-engine", "librechat"))
    kc.grant(PERSON, "assist-gate", _ms(stack) - 50_000)
    kc.add_user(OTHER, consents=("flow-engine",))

    def toggle(t_ms: int) -> None:
        kc.users[PERSON]["enabled"] = False
        kc.event("UPDATE", PERSON, t_ms)
        kc.users[PERSON]["enabled"] = True
        kc.event("UPDATE", PERSON, t_ms + 60_000)
        # Granted anew after the reactivation (Keycloak keeps one consent per client).
        kc.consents[PERSON].remove("assist-gate")
        kc.grant(PERSON, "assist-gate", t_ms + 120_000)

    started = _stopped_while(stack, toggle)
    assert stack.clock.now - started <= 300
    assert sorted(kc.consents[PERSON]) == ["assist-gate", "librechat"]
    assert kc.created[(PERSON, "assist-gate")] > 0  # the new grant
    assert kc.consents[OTHER] == ["flow-engine"]
    deleted = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.consent_delete"]
    assert [r["detail"]["client"] for r in deleted] == ["flow-engine"]
    assert all(r["result"] == "allowed" and r["event"] == "delegation_revoked" for r in deleted)
    assert len({r["correlation_id"] for r in deleted}) == 1
    assert _health(stack)[0] == 0


def test_an_update_read_late_after_a_read_outage_ends_the_old_delegations(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, consents=("flow-engine",))
    _ran_once(stack)
    kc.events_error = lc.HttpError(503)
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    kc.users[PERSON]["enabled"] = False
    kc.event("UPDATE", PERSON, _ms(stack))
    kc.users[PERSON]["enabled"] = True
    kc.event("UPDATE", PERSON, _ms(stack) + 1000)
    stack.clock.now += 300
    kc.events_error = None
    stack.service.step()
    assert kc.consents[PERSON] == []


def test_an_update_read_in_time_of_an_active_account_removes_nothing(stack):
    """Read within the usual poll delay: an update of an active account the service never
    saw deactivated is an ordinary change (name, mail) and leaves the delegations."""
    kc = stack.keycloak
    kc.add_user(PERSON, consents=("flow-engine", "assist-gate"))
    _ran_once(stack)
    kc.event("UPDATE", PERSON, _ms(stack))
    stack.clock.now += lc.LATE_EVENT_SECONDS
    stack.service.step(force_poll=True)
    assert kc.consents[PERSON] == ["flow-engine", "assist-gate"]


def test_the_reconciliation_runs_every_hour(stack):
    kc = stack.keycloak
    kc.add_user(PERSON)
    _ran_once(stack)
    kc.users[PERSON]["enabled"] = False  # no event
    stack.clock.now += HOUR - 5
    stack.service.step()
    assert ("POST", f"/users/{PERSON}/logout") not in kc.calls
    stack.clock.now += 10
    stack.service.step()
    assert ("POST", f"/users/{PERSON}/logout") in kc.calls
    assert kc.consents[PERSON] == []


def test_a_deactivated_account_is_revoked_once_not_every_hour(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    _ran_once(stack)
    assert kc.calls.count(("POST", f"/users/{PERSON}/logout")) == 1
    for _ in range(3):
        stack.clock.now += HOUR + 1
        stack.service.step()
    assert kc.calls.count(("POST", f"/users/{PERSON}/logout")) == 1


def test_a_consent_a_deactivated_account_still_holds_is_removed_on_the_next_round(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    kc.fail_consent_delete_for.add(PERSON)
    _ran_once(stack)
    assert kc.consents[PERSON] == ["flow-engine"]
    code, report = _health(stack)
    assert code == 1 and report["status"] == "fail"
    assert report["disabled_with_consent"] == 1

    kc.fail_consent_delete_for.clear()
    stack.clock.now += HOUR + 1
    stack.service.step()
    assert kc.consents[PERSON] == []
    code, report = _health(stack)
    assert code == 0 and report["disabled_with_consent"] == 0


# ─────────────────────────────────────────────────────────────────────────
# activation
# ─────────────────────────────────────────────────────────────────────────


def test_activation_removes_the_consents_from_before_the_deactivation(stack):
    """The account was seen deactivated; whatever consent survived that (here: the
    removal failed) goes on the activation event, a consent granted after it stays."""
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False, consents=())
    kc.grant(PERSON, "assist-gate", _ms(stack) - 50_000)
    kc.fail_consent_delete_for.add(PERSON)
    _ran_once(stack)
    assert kc.consents[PERSON] == ["assist-gate"]
    kc.fail_consent_delete_for.clear()

    stack.clock.now += 20
    kc.users[PERSON]["enabled"] = True
    kc.event("UPDATE", PERSON, _ms(stack))
    stack.clock.now += 5
    kc.grant(PERSON, "flow-engine", _ms(stack))
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()

    assert kc.consents[PERSON] == ["flow-engine"]
    deleted = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.consent_delete"]
    assert [r["detail"]["client"] for r in deleted][-1] == "assist-gate"
    assert deleted[-1]["result"] == "allowed"


def test_an_update_of_an_account_never_seen_deactivated_removes_nothing(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, consents=())
    kc.grant(PERSON, "flow-engine", _ms(stack) - 10_000)
    _ran_once(stack)
    kc.event("UPDATE", PERSON, _ms(stack) + 1)
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    assert kc.consents[PERSON] == ["flow-engine"]


def test_an_account_back_in_the_group_is_reconciled(stack, capsys):
    """An account the service could not read (outside the group) is looked at again by
    the reconciliation once the realm sync has put it back."""
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    kc.forbidden.add(PERSON)
    stack.service.start()
    kc.event("UPDATE", PERSON, _ms(stack) + 10)
    stack.service.step()
    assert _health(stack)[1]["skipped_revocations"] == 1
    assert kc.consents[PERSON] == ["flow-engine"]

    kc.forbidden.clear()
    stack.clock.now += HOUR + 1
    stack.service.step()
    assert kc.consents[PERSON] == []
    assert _health(stack)[1]["skipped_revocations"] == 0


# ─────────────────────────────────────────────────────────────────────────
# event gap
# ─────────────────────────────────────────────────────────────────────────


def test_a_gap_longer_than_the_event_retention_removes_every_holder_consent(stack):
    """Deactivated and activated again while the service was stopped for longer than
    Keycloak keeps events: nothing tells the two apart from an active account, so every
    consent at a holder client goes (`lifecycle_gap_revoke`)."""
    kc = stack.keycloak
    kc.add_user(PERSON, consents=("flow-engine", "assist-gate", "librechat"))
    kc.add_user(OTHER, consents=("flow-engine",))
    _ran_once(stack)

    stack.clock.now += lc.EVENT_RETENTION_SECONDS + DAY
    _restart(stack).step()

    assert kc.consents[PERSON] == ["librechat"]
    assert kc.consents[OTHER] == []
    assert ("POST", f"/users/{PERSON}/logout") not in kc.calls
    rows = _rows(stack.out)
    gap = [r for r in rows if r["operation"] == "lifecycle.gap_revoke"]
    assert len(gap) == 1
    assert gap[0]["format"] == "papaia.audit/1"
    assert gap[0]["result"] == "allowed"
    assert gap[0]["event"] == "delegation_revoked"
    assert gap[0]["detail"] == {"count": 3, "persons": 2, "reason": "lifecycle_gap_revoke"}
    deletes = [r for r in rows if r["operation"] == "lifecycle.consent_delete"]
    assert len(deletes) == 3
    assert {r["correlation_id"] for r in deletes} == {gap[0]["correlation_id"]}
    code, report = _health(stack)
    assert code == 0, report
    assert report["gap_revoke_age_seconds"] == 0

    # Done once: neither the next round nor a restart repeats it.
    kc.grant(OTHER, "flow-engine", _ms(stack))
    stack.clock.now += HOUR + 1
    stack.service.step()
    _restart(stack).step()
    assert kc.consents[OTHER] == ["flow-engine"]
    assert not [r for r in _rows(stack.out) if r["operation"] == "lifecycle.gap_revoke"]


def test_a_stop_shorter_than_the_retention_is_no_gap(stack):
    kc = stack.keycloak
    kc.add_user(PERSON)
    _ran_once(stack)
    stack.clock.now += lc.EVENT_RETENTION_SECONDS - HOUR
    _restart(stack).step()
    assert kc.consents[PERSON] == ["flow-engine"]
    assert not [r for r in _rows(stack.out) if r["operation"] == "lifecycle.gap_revoke"]
    assert _health(stack)[1]["gap_revoke_age_seconds"] is None


def test_a_first_start_is_no_gap(stack):
    stack.keycloak.add_user(PERSON)
    _ran_once(stack)
    assert stack.keycloak.consents[PERSON] == ["flow-engine"]


def test_reading_keycloak_failing_for_longer_than_the_retention_is_a_gap(stack):
    kc = stack.keycloak
    kc.add_user(PERSON)
    _ran_once(stack)
    kc.events_error = lc.HttpError(503)
    kc.users_error = lc.HttpError(503)
    stack.clock.now += lc.EVENT_RETENTION_SECONDS + HOUR
    stack.service.step()
    kc.events_error = kc.users_error = None
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    assert kc.consents[PERSON] == []
    assert [r for r in _rows(stack.out) if r["operation"] == "lifecycle.gap_revoke"]


def test_a_gap_revoke_that_fails_is_kept_until_it_succeeds(stack):
    """A successful poll in between must not make the service forget the gap."""
    kc = stack.keycloak
    kc.add_user(PERSON)
    _ran_once(stack)
    stack.clock.now += lc.EVENT_RETENTION_SECONDS + DAY
    kc.fail_consent_delete_for.add(PERSON)
    _restart(stack).step()
    assert kc.consents[PERSON] == ["flow-engine"]
    for _ in range(3):
        stack.clock.now += lc.POLL_SECONDS
        stack.service.step()
    kc.fail_consent_delete_for.clear()
    stack.clock.now += lc.RECONCILE_RETRY_SECONDS + 1
    stack.service.step()
    assert kc.consents[PERSON] == []
    assert len([r for r in _rows(stack.out) if r["operation"] == "lifecycle.gap_revoke"]) == 1


# ─────────────────────────────────────────────────────────────────────────
# health and state
# ─────────────────────────────────────────────────────────────────────────


def test_health_fails_when_the_last_reconciliation_is_older_than_two_hours(stack):
    kc = stack.keycloak
    _ran_once(stack)
    kc.users_error = lc.HttpError(503)
    stack.clock.now += 2 * HOUR - 60
    stack.service.step()
    code, report = _health(stack)
    assert code == 0, report
    assert report["last_reconcile_age_seconds"] == 2 * HOUR - 60
    stack.clock.now += 120
    stack.service.step()
    code, report = _health(stack)
    assert code == 1 and report["status"] == "fail"
    assert report["last_reconcile_age_seconds"] > lc.RECONCILE_FAIL_SECONDS


def test_health_fails_two_hours_after_the_first_start_while_events_keep_coming(stack):
    """No round succeeds (no id of the persons group, as after an upgrade before the
    realm sync), yet events are read every 10 s: health still fails after 2 h, counted
    from the first start, not from the newest event."""
    kc = stack.keycloak
    kc.add_user(PERSON, consents=())
    kc.group_id = None
    _ran_once(stack)
    first = stack.clock.now
    for _ in range(6):
        stack.clock.now += HOUR
        kc.event("UPDATE", PERSON, _ms(stack))
        stack.service.step(force_poll=True)
        code, report = _health(stack)
        assert report["last_reconcile_age_seconds"] is None
        if stack.clock.now - first > lc.RECONCILE_FAIL_SECONDS:
            assert code == 1 and report["status"] == "fail", report
        else:
            assert code == 0, report
    assert stack.store.load()["last_reconcile"] == 0
    # A restart does not move the first start.
    _restart(stack).step()
    assert _health(stack)[1]["status"] == "fail"


def test_the_first_start_is_recorded_once(stack):
    stack.service.start()
    first = stack.store.load()["started_at"]
    assert first == int(stack.clock.now)
    stack.clock.now += DAY
    _restart(stack)
    assert stack.store.load()["started_at"] == first


def test_a_failed_reconciliation_is_tried_again_within_minutes(stack):
    kc = stack.keycloak
    kc.add_user(PERSON)
    kc.users_error = lc.HttpError(503)
    _ran_once(stack)
    kc.users_error = None
    kc.users[PERSON]["enabled"] = False
    stack.clock.now += lc.RECONCILE_RETRY_SECONDS + 1
    stack.service.step()
    assert kc.consents[PERSON] == []


def test_listed_accounts_with_a_malformed_id_are_left_alone(stack):
    kc = stack.keycloak
    kc.extra_listed = [
        {"id": "../clients", "enabled": False},
        {"id": "a" * 80, "enabled": False},
        "not an object",
        {"enabled": False},
    ]
    _ran_once(stack)
    assert not any(".." in path or "a" * 80 in path for _, path in kc.calls)
    assert _health(stack)[0] == 0


def test_a_state_of_the_previous_version_is_taken_over(stack):
    stack.service.start()
    path = stack.key_dir / lc.STATE_FILE
    doc = json.loads(path.read_text())
    for key in ("disabled", "last_reconcile", "disabled_with_consent", "gap_pending",
                "gap_revoke_at", "started_at"):
        doc.pop(key)
    path.write_text(json.dumps(doc))
    state = lc.Store(stack.key_dir).load()
    assert state["disabled"] == {} and state["last_reconcile"] == 0
    assert state["gap_pending"] is False and state["gap_revoke_at"] is None
    assert state["started_at"] is None
    # The next start of the new version records it.
    _restart(stack)
    assert stack.store.load()["started_at"] == int(stack.clock.now)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("disabled", {"../x": 1}),
        ("disabled", {PERSON: -1}),
        ("gap_pending", "yes"),
        ("gap_revoke_at", "now"),
        ("disabled_with_consent", True),
        ("started_at", "yesterday"),
        ("started_at", -5),
    ],
)
def test_a_malformed_reconciliation_state_is_refused(stack, key, value):
    stack.service.start()
    path = stack.key_dir / lc.STATE_FILE
    doc = json.loads(path.read_text())
    doc[key] = value
    path.write_text(json.dumps(doc))
    with pytest.raises(lc.LifecycleError):
        lc.Store(stack.key_dir).load()


def test_the_constants_agree_with_the_realm_sync_and_doctor():
    """Holder clients and event retention are defined where the realm is kept; the
    service runs alone in its container and carries its own copy."""
    assert lc.HOLDER_CLIENTS == rs.HOLDER_CLIENTS
    assert lc.EVENT_RETENTION_SECONDS == la.ADMIN_EVENTS_EXPIRATION
    assert doctor.LIFECYCLE_RECONCILE_FAIL_SECONDS == lc.RECONCILE_FAIL_SECONDS
    assert doctor.LIFECYCLE_GAP_WARN_SECONDS == lc.EVENT_RETENTION_SECONDS
    health = list(doctor.LIFECYCLE_HEALTH_COMMAND)
    compose = lc_compose_health()
    assert health == compose


def lc_compose_health() -> list[str]:
    import yaml

    from tests.test_lifecycle import MODULE_DIR

    doc = yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    return doc["services"]["papaia-lifecycle"]["healthcheck"]["test"][1:]


# ─────────────────────────────────────────────────────────────────────────
# where the accounts come from
# ─────────────────────────────────────────────────────────────────────────


def test_the_round_reads_the_members_of_the_persons_group(stack):
    """Keycloak refuses the user search to the account (its group permission grants
    view-members only): the round lists the group's members and filters by state."""
    kc = stack.keycloak
    kc.add_user(PERSON)
    kc.add_user(OTHER)
    kc.users[PERSON]["enabled"] = False
    _ran_once(stack)
    assert kc.consents[PERSON] == []
    assert kc.consents[OTHER] == ["flow-engine"]
    listed = [path for _, path in kc.calls if path.startswith("/groups/")]
    assert listed and all(
        path.startswith(f"/groups/{kc.group_id}/members?") and "briefRepresentation=true" in path
        for path in listed
    )
    assert not [path for _, path in kc.calls if path.startswith("/users?")]


def test_the_members_are_read_page_by_page(stack):
    kc = stack.keycloak
    for n in range(lc.USER_PAGE + 5):
        kc.add_user(f"{n:08d}-0000-4000-8000-000000000000", consents=())
    last = f"{lc.USER_PAGE + 4:08d}-0000-4000-8000-000000000000"
    kc.users[last]["enabled"] = False
    _ran_once(stack)
    assert ("POST", f"/users/{last}/logout") in kc.calls


def test_without_the_id_of_the_persons_group_the_round_fails(stack, capsys):
    """Not set up by the realm sync yet: no round counts as done, health fails 2 h after
    the first start, the event path keeps working."""
    kc = stack.keycloak
    kc.add_user(PERSON)
    kc.group_id = None
    _ran_once(stack)
    assert "persons group" in capsys.readouterr().err
    assert stack.store.load()["last_reconcile"] == 0
    stack.clock.now += lc.RECONCILE_FAIL_SECONDS + 60
    stack.service.step()
    code, report = _health(stack)
    assert code == 1 and report["status"] == "fail"


def _account_folder(tmp_path, group_text: str | None, mode: int = 0o600):
    folder = tmp_path / "account"
    folder.mkdir(mode=0o700, parents=True)
    if group_text is not None:
        path = folder / lc.GROUP_FILE
        path.write_text(group_text)
        path.chmod(mode)
    return lc.AccountClient("https://keycloak:8443", None, folder)


def test_the_client_reads_the_group_id_the_realm_sync_wrote(tmp_path):
    api = _account_folder(tmp_path, "6f1c2b9e-0d4a-4c1e-9a77-3b5e8d2f4a10\n")
    assert api.persons_group() == "6f1c2b9e-0d4a-4c1e-9a77-3b5e8d2f4a10"


@pytest.mark.parametrize(
    "text", ["", "../users", "6f1c2b9e/members", "x" * 80, "6f1c2b9e-0d4a\n4c1e"]
)
def test_a_malformed_group_id_is_refused(tmp_path, text):
    api = _account_folder(tmp_path, text)
    with pytest.raises(lc.LifecycleError):
        api.persons_group()


def test_a_missing_or_open_group_file_is_refused(tmp_path):
    with pytest.raises(lc.LifecycleError, match="realm sync"):
        _account_folder(tmp_path, None).persons_group()
    with pytest.raises(lc.LifecycleError):
        open_file = _account_folder(tmp_path / "b", "6f1c2b9e-0d4a-4c1e-9a77-3b5e8d2f4a10", 0o644)
        open_file.persons_group()


def test_the_realm_sync_writes_the_group_id_next_to_the_key(tmp_path):
    from lib import service_account_keys as sak

    keys = sak.KeyStore(tmp_path / "service-accounts")
    keys.generate(la.CLIENT_ID)
    gid = "6f1c2b9e-0d4a-4c1e-9a77-3b5e8d2f4a10"
    dry = la._Align(None, keys, False, None)
    dry.persons_group_file(gid)
    assert [c.action for c in dry.act.changes] == ["id of papaia-persons written for the service"]
    assert not (keys.folder(la.CLIENT_ID) / la.GROUP_FILE).exists()

    run = la._Align(None, keys, True, None)
    run.persons_group_file(gid)
    path = keys.folder(la.CLIENT_ID) / la.GROUP_FILE
    assert path.read_text() == gid + "\n"
    assert path.stat().st_mode & 0o777 == 0o600
    assert la.GROUP_FILE == lc.GROUP_FILE

    again = la._Align(None, keys, True, None)
    again.persons_group_file(gid)
    assert again.act.changes == []
    other = la._Align(None, keys, True, None)
    other.persons_group_file("0a1b2c3d-0000-4000-8000-000000000000")
    assert other.act.changes and path.read_text().startswith("0a1b2c3d")
