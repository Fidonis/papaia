"""papaia-lifecycle: the core start gate (sicherheit §4.9 (2a), RE-99, RE-102...RE-107).

Identity provider, chat and model gateway have no start check of their own. So after
every start the edge serves the maintenance page for every public host until
papaia-lifecycle has compared the `epoch` at the backup target with its own state and,
if its state is older (a restored VM or volume snapshot), has replayed the journal.

The edge asks a check service without secrets for every request; the service reads the
lease `startgate.json`, which papaia-lifecycle alone writes and renews every 30 s for 90 s.
Keycloak is the in-memory admin API of `test_lifecycle.py`; papaia-replay and the
module endpoints are fakes that record their jobs.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import shutil
import threading
from pathlib import Path

import pytest
import yaml
from papaia_kit.authz import RevocationList

from tests.test_lifecycle import (
    MODULE_DIR,
    OTHER,
    PERSON,
    FakeKeycloak,
    _published,
    _rows,
    lc,
)
from tests.test_lifecycle import stack as stack  # noqa: F401 - the shared fixture

ADMIN = "2a1b0c9d-8e7f-4a6b-9c5d-4e3f2a1b0c9d"
SECOND_ADMIN = "8f7e6d5c-4b3a-4291-8f7e-6d5c4b3a2910"


class FakeReplay:
    """papaia-replay as papaia-lifecycle sees it: one job per call, counts only."""

    def __init__(self) -> None:
        self.jobs: list[dict] = []
        self.fail = False

    def run(self, kind: str, correlation: str, *, sub=None, key_id=None) -> dict:
        if self.fail:
            raise lc.LifecycleError("papaia-replay is not reachable")
        self.jobs.append({"kind": kind, "sub": sub, "key_id": key_id, "cid": correlation})
        return {"deleted": 1}


class FakeModules:
    """`POST /internal/lifecycle` of the modules: the applied seq they report."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.applied: dict[str, int] = {}
        self.failing: set[str] = set()

    def run(self, module: str, action: str, correlation: str) -> dict:
        if module in self.failing:
            raise lc.LifecycleError(f"{module} did not answer")
        self.calls.append((module, action))
        if action == "erasure-replay":
            return {"action": action, "module": module, "applied_seq": self.applied[module]}
        return {"action": action, "module": module, "counts": {}}


class FakeMailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, subject: str, text: str) -> None:
        self.sent.append((subject, text))


def _gate(stack, **kwargs):
    stack.replay = kwargs.pop("replay", FakeReplay())
    stack.modules = kwargs.pop("modules", FakeModules())
    stack.mailer = kwargs.pop("mailer", FakeMailer())
    stack.gate = lc.StartGate(
        stack.service,
        state_dir=stack.state_dir,
        key_dir=stack.key_dir,
        target_dir=stack.target,
        local_dir=stack.local,
        replay=stack.replay,
        modules=stack.modules,
        mailer=stack.mailer,
        clock=stack.clock,
    )
    stack.service.gate = stack.gate
    return stack.gate


def _lease(stack) -> dict | None:
    return lc.read_gate(stack.state_dir)


def _open_for(stack, key: str) -> bool:
    return lc.gate_allows(_lease(stack), key, int(stack.clock.now))


def _running(stack, *people: str, consents=("flow-engine",)) -> None:
    """A stack in use: people in the realm, the gate started and open."""
    for uid in people:
        stack.keycloak.add_user(uid, consents=consents)
    _gate(stack)
    stack.service.start()
    stack.service.step()


def _epoch(stack) -> dict:
    return lc.read_epoch(stack.target)


def _snapshot(stack, tmp: Path) -> Path:
    """A VM snapshot of what the host holds: the service's own volume (state, local copy
    of the journal) and the security state volume (the lease). The backup target is
    outside the VM and keeps going."""
    copy = tmp / "snapshot"
    shutil.copytree(stack.key_dir, copy / "key", symlinks=True)
    shutil.copytree(stack.state_dir, copy / "state", symlinks=True)
    return copy


def _roll_back(stack, copy: Path, keycloak: FakeKeycloak) -> None:
    """The VM comes back from the snapshot: both volumes and Keycloak's database as they
    were; the process starts anew (`docker compose up`)."""
    shutil.rmtree(stack.key_dir)
    shutil.rmtree(stack.state_dir)
    shutil.copytree(copy / "key", stack.key_dir, symlinks=True)
    shutil.copytree(copy / "state", stack.state_dir, symlinks=True)
    stack.keycloak = keycloak
    stack.out = io.StringIO()
    stack.journal = lc.ErasureJournal(
        "identity",
        key=stack.erasure_key,
        target_dir=stack.target,
        local_dir=stack.local,
        clock=stack.clock,
    )
    stack.store = lc.Store(stack.key_dir)
    stack.service = lc.Lifecycle(
        keycloak,
        stack.store,
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=stack.out,
        clock=stack.clock,
        journal=stack.journal,
    )


def _keycloak_copy(kc: FakeKeycloak) -> FakeKeycloak:
    copy = FakeKeycloak()
    copy.users = {uid: dict(u) for uid, u in kc.users.items()}
    copy.consents = {uid: list(c) for uid, c in kc.consents.items()}
    copy.created = dict(kc.created)
    return copy


def _ops(out: io.StringIO, operation: str) -> list[dict]:
    return [r for r in _rows(out) if r["operation"] == f"lifecycle.{operation}"]


# ─────────────────────────────────────────────────────────────────────────
# closed at every start
# ─────────────────────────────────────────────────────────────────────────


def test_the_service_writes_closed_before_anything_else_at_every_start(stack):
    """The first write of every start is `closed`, before Keycloak is asked."""
    stack.keycloak.users_error = lc.HttpError(503)
    gate = _gate(stack)
    gate.begin()

    lease = _lease(stack)
    assert lease["state"] == "closed"
    assert lease["expires_at"] - lease["issued_at"] == lc.GATE_LEASE_SECONDS
    assert stack.keycloak.calls == []
    for key in ("core", "identity", "core-chat", "model-gateway", "papaia-flow"):
        assert not _open_for(stack, key)
    assert _open_for(stack, "admin")  # the administration host stays open


def test_a_fresh_installation_records_the_epoch_and_opens(stack):
    _running(stack, PERSON)

    assert _epoch(stack) == {"generation": 0, "seq": {}}
    for key in ("core", "identity", "core-chat", "model-gateway", "papaia-flow"):
        assert _open_for(stack, key)
    assert stack.replay.jobs == []
    assert ("POST", f"/users/{PERSON}/logout") not in stack.keycloak.calls


def test_the_lease_is_renewed_every_30_seconds_and_lasts_90(stack):
    _running(stack, PERSON)
    first = _lease(stack)["issued_at"]
    stack.clock.now += lc.GATE_RENEW_SECONDS
    stack.service.step()
    lease = _lease(stack)
    assert lease["issued_at"] == first + lc.GATE_RENEW_SECONDS
    assert lease["expires_at"] == lease["issued_at"] + lc.GATE_LEASE_SECONDS


# ─────────────────────────────────────────────────────────────────────────
# snapshot with a lower seq
# ─────────────────────────────────────────────────────────────────────────


def _deactivated_after_the_snapshot(stack, tmp_path):
    """Snapshot S taken while PERSON is active; then PERSON is deactivated (one entry in
    the journal `identity` at the target) and the gate records it in `epoch`. The VM is
    then rolled back to S."""
    _running(stack, PERSON, OTHER, consents=("flow-engine", "assist-gate"))
    copy = _snapshot(stack, tmp_path)
    kc_at_snapshot = _keycloak_copy(stack.keycloak)
    stack.clock.now += lc.POLL_SECONDS
    stack.keycloak.users[PERSON]["enabled"] = False
    stack.keycloak.event("UPDATE", PERSON, int(stack.clock.now * 1000))
    stack.service.step()
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert _epoch(stack)["seq"]["identity"] == 1
    stack.clock.now += 3600
    _roll_back(stack, copy, kc_at_snapshot)
    return kc_at_snapshot


def test_a_snapshot_with_a_lower_seq_keeps_the_edge_closed_after_compose_up(stack, tmp_path):
    """`docker compose up` of the rolled back VM: the lease in the snapshot said `open`,
    but it expired long ago, so the edge serves the maintenance page also before
    papaia-lifecycle runs at all."""
    _deactivated_after_the_snapshot(stack, tmp_path)

    lease = _lease(stack)
    assert lease["state"] == "open"  # as the snapshot holds it
    for key in ("core", "identity", "core-chat", "model-gateway"):
        assert not _open_for(stack, key)
    assert lc.gate_code(lease, int(stack.clock.now)) == "CHECK"


def test_the_replay_disables_again_logs_everyone_out_and_then_opens(stack, tmp_path):
    kc = _deactivated_after_the_snapshot(stack, tmp_path)
    assert kc.users[PERSON]["enabled"] is True  # the snapshot brought the account back
    gate = _gate(stack)
    started = int(stack.clock.now)
    stack.service.start()

    # Disabled again, with every consent; every account logged out, the holder
    # consents of every account removed.
    assert kc.users[PERSON]["enabled"] is False
    assert kc.consents[PERSON] == []
    assert kc.consents[OTHER] == []
    for uid in (PERSON, OTHER):
        assert ("POST", f"/users/{uid}/logout") in kc.calls
    # The revocation list: the person, and every token from before the run.
    published = _published(stack.state_dir)
    assert published["global_since"] == started
    assert {e["sub"] for e in published["entries"]} == {PERSON}
    # Chat sessions of every account are deleted through papaia-replay.
    assert [j["kind"] for j in stack.replay.jobs] == ["chat_sessions_reset"]
    # Generation raised at the target, the edge open again.
    assert _epoch(stack)["generation"] == 1
    assert _epoch(stack)["seq"]["identity"] == 1
    for key in ("core", "identity", "core-chat", "model-gateway"):
        assert _open_for(stack, key)
    behind = [r for r in _rows(stack.out) if r["event"] == "state_epoch_behind"]
    assert len(behind) == 1
    replayed = _ops(stack.out, "startgate_replay")
    assert replayed and all(r["correlation_id"] == behind[0]["correlation_id"] for r in replayed)
    assert gate.status()["status"] == "open"


def test_sessions_from_before_the_snapshot_are_refused_after_open(stack, tmp_path):
    """global_since (RE-102): a token issued before the run is refused for everyone, also
    for accounts the journal does not name; one issued afterwards is accepted."""
    _deactivated_after_the_snapshot(stack, tmp_path)
    old_token_iat = int(stack.clock.now) - 60
    _gate(stack)
    stack.service.start()
    stack.clock.now += 1

    revocations = RevocationList.from_dict(_published(stack.state_dir))
    assert revocations.revoked(OTHER, old_token_iat)
    assert not revocations.revoked(OTHER, int(stack.clock.now))


def test_a_replay_runs_once_not_on_every_check(stack, tmp_path):
    kc = _deactivated_after_the_snapshot(stack, tmp_path)
    _gate(stack)
    stack.service.start()
    logouts = kc.calls.count(("POST", f"/users/{OTHER}/logout"))
    for _ in range(3):
        stack.clock.now += lc.GATE_CHECK_SECONDS
        stack.service.step()
    assert kc.calls.count(("POST", f"/users/{OTHER}/logout")) == logouts
    assert _epoch(stack)["generation"] == 1


def test_the_backlog_found_at_start_survives_a_failed_replay(stack, tmp_path):
    """Keycloak is not reachable at start: the journal is copied into the local copy by
    the next flush, but the entries still due are kept and replayed later."""
    kc = _deactivated_after_the_snapshot(stack, tmp_path)
    kc.users_error = lc.HttpError(503)
    gate = _gate(stack)
    stack.service.start()
    assert not _open_for(stack, "core")
    assert gate.status()["status"] == "replay_failed"
    assert gate.status()["failed"] == ["identity"]
    assert lc.gate_code(_lease(stack), int(stack.clock.now)) == "BLOCKED"

    kc.users_error = None
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert kc.users[PERSON]["enabled"] is False
    assert _open_for(stack, "core")


def test_an_unreadable_gate_file_keeps_the_edge_closed(stack):
    _running(stack, PERSON)
    now = int(stack.clock.now)
    path = stack.state_dir / lc.GATE_FILE
    lease = json.loads(path.read_bytes())
    broken = [
        b"",
        b"not json",
        b"[]",
        json.dumps({**lease, "state": "opened"}).encode(),
        json.dumps({**lease, "extra": 1}).encode(),
        json.dumps({**lease, "expires_at": lease["issued_at"] + 3600}).encode(),
        json.dumps({**lease, "generation": 1.0}).encode(),
        json.dumps({**lease, "hosts": "core"}).encode(),
        b'{"state": "open", "state": "open"}',
        b"[" * 100_000,
        b" " * (lc.MAX_GATE_BYTES + 1),
    ]
    for data in broken:
        path.write_bytes(data)
        assert lc.read_gate(stack.state_dir) is None, data[:40]
        assert not lc.gate_allows(lc.read_gate(stack.state_dir), "core", now)
    path.unlink()
    os.symlink(stack.key_dir / lc.STATE_FILE, path)
    assert lc.read_gate(stack.state_dir) is None
    path.unlink()
    assert lc.read_gate(stack.state_dir) is None
    assert lc.gate_allows(None, "admin", now)


def test_a_module_behind_the_journal_is_replayed_and_a_failed_one_stays_closed(stack, tmp_path):
    """Module journals at the target: the modules apply them through
    `POST /internal/lifecycle`; a module that fails keeps its host closed, the core
    opens."""
    _running(stack, PERSON)
    for module, seq in (("papaia-flow", 2), ("papaia-studio", 3)):
        _module_journal(stack.target, module, seq)
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert _epoch(stack)["seq"] == {"papaia-flow": 2, "papaia-studio": 3}
    copy = _snapshot(stack, tmp_path)
    _module_journal(stack.target, "papaia-flow", 4)
    _module_journal(stack.target, "papaia-studio", 5)
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    _roll_back(stack, copy, _keycloak_copy(stack.keycloak))

    modules = FakeModules()
    modules.applied = {"papaia-flow": 4}
    modules.failing = {"papaia-studio"}
    gate = _gate(stack, modules=modules)
    stack.service.start()

    assert modules.calls == [("papaia-flow", "erasure-replay"), ("papaia-flow", "post-restore")]
    assert _open_for(stack, "core") and _open_for(stack, "papaia-flow")
    assert not _open_for(stack, "papaia-studio")
    assert gate.status()["status"] == "replay_failed"
    assert gate.status()["failed"] == ["papaia-studio"]
    # The module is tried again on the next check, the core steps are not repeated.
    modules.failing.clear()
    modules.applied["papaia-studio"] = 5
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert _open_for(stack, "papaia-studio")
    assert gate.status()["status"] == "open"


def _module_journal(target: Path, module: str, upto: int) -> None:
    lines = [
        json.dumps(
            {
                "id": f"00000000-0000-4000-8000-{module[-4:].encode().hex()}{seq:04d}",
                "module": module,
                "seq": seq,
                "kind": "erase",
                "object_ref": f"row:{seq}",
                "subject_ref": "0" * 64,
                "at": "2027-01-15T08:00:00.000Z",
                "reason": "user_request",
            }
        )
        for seq in range(1, upto + 1)
    ]
    (target / f"{module}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_chat_and_gateway_entries_are_replayed_through_papaia_replay(stack, tmp_path):
    """Entries `core-chat` and `model-gateway` beyond the applied seq: the person is
    erased by `sub` (resolved from subject_ref over the realm's accounts), a revoked key
    deleted again; papaia-replay never sees the HMAC key."""
    _running(stack, PERSON, OTHER)
    copy = _snapshot(stack, tmp_path)
    chat = lc.ErasureJournal(
        "core-chat",
        key=stack.erasure_key,
        target_dir=stack.target,
        local_dir=stack.target.parent / "chat-local",
        clock=stack.clock,
    )
    chat.record("erase_subject", object_ref="person", sub=OTHER, reason="art17")
    gateway = lc.ErasureJournal(
        "model-gateway",
        key=stack.erasure_key,
        target_dir=stack.target,
        local_dir=stack.target.parent / "gw-local",
        clock=stack.clock,
    )
    gateway.record("key_revoke", object_ref="key:k-7f3a", sub=OTHER, reason="rotated")
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    _roll_back(stack, copy, _keycloak_copy(stack.keycloak))
    _gate(stack)
    stack.service.start()

    jobs = [(j["kind"], j["sub"], j["key_id"]) for j in stack.replay.jobs]
    assert ("erase_subject", OTHER, None) in jobs
    assert ("key_revoke", None, "k-7f3a") in jobs
    assert ("chat_sessions_reset", None, None) in jobs
    assert _open_for(stack, "core-chat") and _open_for(stack, "model-gateway")


def test_without_papaia_replay_the_core_stays_closed(stack, tmp_path):
    _deactivated_after_the_snapshot(stack, tmp_path)
    replay = FakeReplay()
    replay.fail = True
    gate = _gate(stack, replay=replay)
    stack.service.start()
    assert not _open_for(stack, "core")
    assert gate.status()["failed"] == ["core-chat"]
    assert stack.mailer.sent and "CORE-STARTGATE-REPLAY-FAILED" in stack.mailer.sent[0][1]


# ─────────────────────────────────────────────────────────────────────────
# lease and recheck while running
# ─────────────────────────────────────────────────────────────────────────


def test_an_expired_lease_closes_the_edge(stack):
    """papaia-lifecycle stopped (no renewal): the edge closes once the lease ran out,
    90 s after the last renewal at the latest."""
    _running(stack, PERSON)
    issued = _lease(stack)["issued_at"]
    stack.clock.now = issued + lc.GATE_LEASE_SECONDS - 1
    assert _open_for(stack, "core")
    stack.clock.now = issued + lc.GATE_LEASE_SECONDS
    assert not _open_for(stack, "core")


def test_an_epoch_that_moves_ahead_while_running_closes_within_60_seconds(stack):
    _running(stack, PERSON)
    epoch = _epoch(stack)
    lc.write_epoch(stack.target, epoch["generation"] + 1, epoch["seq"])
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step(force_poll=False)
    behind = [r for r in _rows(stack.out) if r["event"] == "state_epoch_behind"]
    assert behind
    # Replayed at once (nothing in the journal but the generation), then open again.
    assert _open_for(stack, "core")
    assert _epoch(stack)["generation"] == epoch["generation"] + 2


def test_an_unreachable_target_keeps_the_edge_closed(stack):
    _running(stack, PERSON)
    shutil.move(stack.target, stack.target.parent / "unmounted")
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert not _open_for(stack, "core")
    assert lc.gate_code(_lease(stack), int(stack.clock.now)) == "BLOCKED"
    rows = [r for r in _rows(stack.out) if r["event"] == "state_epoch_unverified"]
    assert len(rows) == 1
    assert stack.gate.status()["status"] == "unverified"
    # One mail per closing, not one per check.
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert len(stack.mailer.sent) == 1
    assert "CORE-STARTGATE-UNVERIFIED" in stack.mailer.sent[0][1]


# ─────────────────────────────────────────────────────────────────────────
# credential_reset and the override
# ─────────────────────────────────────────────────────────────────────────


def test_a_replayed_credential_reset_deactivates_the_account(stack, tmp_path):
    _running(stack, PERSON, OTHER)
    copy = _snapshot(stack, tmp_path)
    kc = _keycloak_copy(stack.keycloak)
    stack.clock.now += lc.POLL_SECONDS
    stack.keycloak.admin_event(
        "ACTION", "USER", f"users/{PERSON}/reset-password", int(stack.clock.now * 1000)
    )
    stack.service.step()
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    _roll_back(stack, copy, kc)
    gate = _gate(stack)
    stack.service.start()

    assert kc.users[PERSON]["enabled"] is False
    assert kc.users[OTHER]["enabled"] is True
    report = gate.status()
    assert report["credential_replay"] == [PERSON]
    assert _open_for(stack, "core")
    rows = [
        r for r in _ops(stack.out, "startgate_replay") if r["detail"]["kind"] == "credential_reset"
    ]
    assert rows and rows[0]["detail"]["reason"] == "credential_replay"


def _unverified(stack) -> None:
    shutil.move(stack.target, stack.target.parent / "unmounted")
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()


def test_an_override_by_one_person_is_refused_with_four_eyes_on(stack):
    _running(stack, PERSON)
    _unverified(stack)
    with pytest.raises(lc.OverrideDenied):
        stack.gate.request_override("journal disk replaced", ADMIN, ADMIN, single_person=False)
    stack.clock.now += 1
    stack.service.step()
    assert not _open_for(stack, "core")


def test_an_override_by_two_persons_opens_and_is_audited(stack):
    _running(stack, PERSON)
    _unverified(stack)
    stack.gate.request_override("journal disk replaced", ADMIN, SECOND_ADMIN, single_person=False)
    stack.clock.now += 1
    stack.service.step()

    assert _open_for(stack, "core")
    (row,) = _ops(stack.out, "startgate_override")
    assert row["detail"] == {
        "requested_by": ADMIN,
        "confirmed_by": SECOND_ADMIN,
        "reason": "journal disk replaced",
        "single_person": False,
    }
    assert stack.gate.status()["status"] == "override"
    assert any("CORE-STARTGATE-OVERRIDE" in text for _, text in stack.mailer.sent)
    # The check goes on every 60 s; the target is back without backlog: normal open.
    shutil.move(stack.target.parent / "unmounted", stack.target)
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert stack.gate.status()["status"] == "open"


def test_an_override_needs_a_closed_gate_and_valid_input(stack):
    _running(stack, PERSON)
    with pytest.raises(lc.OverrideDenied):
        stack.gate.request_override("nothing to open", ADMIN, SECOND_ADMIN, single_person=False)
    _unverified(stack)
    for reason, req, conf in (
        ("", ADMIN, SECOND_ADMIN),
        ("x" * 501, ADMIN, SECOND_ADMIN),
        ("line\nbreak", ADMIN, SECOND_ADMIN),
        ("ok", "../admin", SECOND_ADMIN),
        ("ok", ADMIN, "a" * 65),
    ):
        with pytest.raises(lc.LifecycleError):
            stack.gate.request_override(reason, req, conf, single_person=False)


def test_an_override_by_a_replayed_account_raises_revoked_actor(stack):
    """The override was confirmed by an account that a journal entry, known only after
    the override, deactivates: audit, mail, doctor fail (RE-107)."""
    _running(stack, PERSON, ADMIN, SECOND_ADMIN)
    _unverified(stack)
    stack.gate.request_override("journal disk replaced", ADMIN, SECOND_ADMIN, single_person=False)
    stack.clock.now += 1
    stack.service.step()
    assert stack.gate.status()["status"] == "override"
    # Meanwhile the target came back; it holds a deactivation of SECOND_ADMIN written
    # by another installation state (not in this service's local copy).
    shutil.move(stack.target.parent / "unmounted", stack.target)
    other = lc.ErasureJournal(
        "identity",
        key=stack.erasure_key,
        target_dir=stack.target,
        local_dir=stack.target.parent / "elsewhere",
        clock=stack.clock,
    )
    other.record(
        "account_disable", object_ref="account", sub=SECOND_ADMIN, reason="account_disabled"
    )
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()

    (row,) = _ops(stack.out, "startgate_override_revoked_actor")
    assert row["object_ref"] == {"type": "user", "id": SECOND_ADMIN}
    assert stack.gate.status()["revoked_actors"] == [SECOND_ADMIN]
    assert any("CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR" in text for _, text in stack.mailer.sent)
    # The backlog closed the gate and was replayed.
    assert stack.keycloak.users[SECOND_ADMIN]["enabled"] is False


def test_an_override_is_refused_after_a_failed_replay(stack, tmp_path):
    """The override opens only a gate held closed by an unreachable target (sicherheit
    §4.9 (2a) (v)). After a failed replay the backlog is still due: the next comparison
    would replay it again, so the gate is never opened for it, also not by a request
    that reached the state file."""
    _deactivated_after_the_snapshot(stack, tmp_path)
    replay = FakeReplay()
    replay.fail = True
    gate = _gate(stack, replay=replay)
    stack.service.start()
    assert gate.status()["status"] == "replay_failed"
    with pytest.raises(lc.OverrideDenied):
        gate.request_override("chat is down", ADMIN, SECOND_ADMIN, single_person=False)
    # A request written into the state file anyway (an older papaia-ctl) is denied.
    with gate.store.locked():
        st = gate.store.load()
        st["request"] = {
            "reason": "chat is down",
            "requested_by": ADMIN,
            "confirmed_by": SECOND_ADMIN,
            "single_person": False,
            "correlation_id": "0190f0c8-0000-7000-8000-000000000001",
        }
        gate.store.save(st)
    stack.clock.now += 1
    stack.service.step()
    (row,) = _ops(stack.out, "startgate_override")
    assert (row["result"], row["error_code"]) == ("denied", "not_closed")
    # Across the next comparison: still closed, still the failed replay.
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.service.step()
    assert gate.status()["status"] == "replay_failed"
    assert not _open_for(stack, "core")


def test_a_request_written_during_a_check_is_not_lost(stack, monkeypatch):
    """`papaia-ctl startgate open` writes its request from another process while the
    service compares; the state the comparison saves keeps that request."""
    _running(stack, PERSON)
    _unverified(stack)
    real = lc.read_epoch

    def epoch_while_a_request_arrives(target):
        lc.request_override(
            lc.GateStore(stack.key_dir), "journal disk replaced", ADMIN, SECOND_ADMIN,
            single_person=False,
        )  # fmt: skip
        return real(target)

    monkeypatch.setattr(lc, "read_epoch", epoch_while_a_request_arrives)
    stack.clock.now += lc.GATE_CHECK_SECONDS
    stack.gate.check()
    monkeypatch.setattr(lc, "read_epoch", real)
    assert stack.gate.store.load()["request"] is not None
    stack.clock.now += 1
    stack.service.step()
    assert stack.gate.status()["status"] == "override"
    assert _open_for(stack, "core")


def _revoked_actor(stack) -> None:
    test_an_override_by_a_replayed_account_raises_revoked_actor(stack)
    assert stack.gate.status()["revoked_actors"] == [SECOND_ADMIN]


def test_an_acknowledgement_clears_the_revoked_actor(stack):
    """`doctor startgate` fails until an administrator acknowledged the review of the
    override (`papaia-ctl startgate acknowledge`): audited, then the list is empty."""
    _revoked_actor(stack)
    with pytest.raises(lc.OverrideDenied):
        stack.gate.request_acknowledge("reviewed", SECOND_ADMIN)
    for reason, by in (("", ADMIN), ("x\ny", ADMIN), ("ok", "../admin")):
        with pytest.raises(lc.LifecycleError):
            stack.gate.request_acknowledge(reason, by)
    stack.gate.request_acknowledge("reviewed with the operations address", ADMIN)
    stack.clock.now += 1
    stack.service.step()
    assert stack.gate.status()["revoked_actors"] == []
    (row,) = _ops(stack.out, "startgate_override_acknowledged")
    assert row["result"] == "allowed"
    assert row["detail"] == {
        "by": ADMIN,
        "reason": "reviewed with the operations address",
        "actors": [SECOND_ADMIN],
    }
    # Nothing left to acknowledge.
    with pytest.raises(lc.OverrideDenied):
        stack.gate.request_acknowledge("again", ADMIN)


def test_a_new_override_starts_a_new_watch(stack):
    """A new override replaces the earlier one: its persons are watched, the earlier
    alarm stays until it is acknowledged."""
    _revoked_actor(stack)
    _unverified(stack)
    stack.gate.request_override("disk replaced again", ADMIN, PERSON, single_person=False)
    stack.clock.now += 1
    stack.service.step()
    report = stack.gate.status()
    assert report["override"]["confirmed_by"] == PERSON
    assert report["revoked_actors"] == [SECOND_ADMIN]


def test_the_acknowledge_command_reads_its_request_from_stdin_only(stack, monkeypatch):
    _revoked_actor(stack)
    key_dir = f"--key-dir={stack.key_dir}"

    def run(text: str) -> int:
        monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(text.encode())))
        return lc.main(["startgate-acknowledge", key_dir])

    assert run("not json") == 2
    assert run(json.dumps({"reason": "x"})) == 2
    assert run(json.dumps({"reason": "x", "by": SECOND_ADMIN})) == 3
    assert stack.gate.store.load()["acknowledge"] is None


# ─────────────────────────────────────────────────────────────────────────
# the administration path while the gate is closed
# ─────────────────────────────────────────────────────────────────────────

SIGN_IN = "/realms/papaia/protocol/openid-connect/auth"


def _check(stack, key: str, uri: str | None, now: int) -> int:
    headers = {"X-Papaia-Gate-Service": key}
    if uri is not None:
        headers["X-Papaia-Gate-Uri"] = uri
    return lc.gate_check_response(stack.state_dir, "GET", "/check", headers, now)[0]


@pytest.mark.parametrize(
    "uri",
    [
        f"{SIGN_IN}?client_id=oauth2-proxy&response_type=code&scope=openid&state=a1"
        "&redirect_uri=https%3A%2F%2Fnpm.example.org%2Foauth2%2Fcallback",
        "/realms/papaia/login-actions/authenticate?session_code=x1&execution=e-1"
        "&client_id=oauth2-proxy&tab_id=t1",
        "/realms/papaia/login-actions/required-action?execution=CONFIGURE_TOTP"
        "&client_id=oauth2-proxy&tab_id=t1",
        "/realms/papaia/login-actions/restart?client_id=oauth2-proxy&tab_id=t1",
        "/resources/1x2y3/login/keycloak.v2/css/styles.css",
    ],
)
def test_the_admin_sign_in_route_is_open_while_the_lease_is_closed(stack, uri):
    """The confirming person of an override signs in again over the administration path
    (the proxy admin host, which signs in at the identity provider): those sign-in
    requests pass the closed gate, nothing else on the identity provider's host does."""
    _running(stack, PERSON)
    _unverified(stack)
    now = int(stack.clock.now)
    assert not _open_for(stack, "identity")
    assert _check(stack, "identity", uri, now) == 204
    # The same request on any other host, or without the URI, stays closed.
    assert _check(stack, "core", uri, now) == 401
    assert _check(stack, "core-chat", uri, now) == 401
    assert _check(stack, "identity", None, now) == 401
    # Also without any lease (papaia-lifecycle stopped).
    (stack.state_dir / lc.GATE_FILE).unlink()
    assert _check(stack, "identity", uri, now) == 204


@pytest.mark.parametrize(
    "uri",
    [
        f"{SIGN_IN}?client_id=librechat&response_type=code",
        f"{SIGN_IN}?client_id=oauth2-proxy&client_id=librechat",
        f"{SIGN_IN}?response_type=code",
        "/realms/master/protocol/openid-connect/auth?client_id=oauth2-proxy",
        "/realms/papaia/protocol/openid-connect/token?client_id=oauth2-proxy",
        "/realms/papaia/account/?client_id=oauth2-proxy",
        "/realms/papaia/login-actions/reset-credentials?client_id=oauth2-proxy",
        "/admin/papaia/console/",
        "/resources/../admin/master/console/",
        "/resources/a/%2e%2e/b",
        "/realms/papaia/login-actions/%2e%2e/x?client_id=oauth2-proxy",
        "//realms/papaia/protocol/openid-connect/auth?client_id=oauth2-proxy",
        f"{SIGN_IN}/?client_id=oauth2-proxy",
        "/resources/" + "a" * 5000,
        "",
    ],
)
def test_nothing_else_passes_the_closed_gate_on_the_identity_host(stack, uri):
    _running(stack, PERSON)
    _unverified(stack)
    assert _check(stack, "identity", uri, int(stack.clock.now)) == 401


# ─────────────────────────────────────────────────────────────────────────
# the check service and the health report
# ─────────────────────────────────────────────────────────────────────────


def test_the_check_service_answers_per_host_key(stack):
    _running(stack, PERSON)
    now = int(stack.clock.now)
    ok = lc.gate_check_response(
        stack.state_dir, "GET", "/check", {"X-Papaia-Gate-Service": "core"}, now
    )
    assert ok[0] == 204
    later = now + lc.GATE_LEASE_SECONDS
    closed = lc.gate_check_response(
        stack.state_dir, "GET", "/check", {"X-Papaia-Gate-Service": "core"}, later
    )
    assert closed[0] == 401
    admin = lc.gate_check_response(
        stack.state_dir, "GET", "/check", {"X-Papaia-Gate-Service": "admin"}, later
    )
    assert admin[0] == 204
    for headers in ({}, {"X-Papaia-Gate-Service": "Core!"}, {"X-Papaia-Gate-Service": "x" * 41}):
        assert lc.gate_check_response(stack.state_dir, "GET", "/check", headers, now)[0] == 401
    assert lc.gate_check_response(stack.state_dir, "POST", "/check", {}, now)[0] == 405
    assert lc.gate_check_response(stack.state_dir, "GET", "/other", {}, now)[0] == 404


def test_the_maintenance_page_names_the_situation_and_the_correlation_id(stack):
    _running(stack, PERSON)
    _unverified(stack)
    now = int(stack.clock.now)
    status, headers, body = lc.gate_check_response(
        stack.state_dir,
        "GET",
        "/maintenance",
        {"X-Papaia-Gate-Contact": "IT-Service%20%3Cb%3E%20Tel.%201234"},
        now,
    )
    text = body.decode("utf-8")
    assert status == 503
    assert headers["Retry-After"] == "60"
    assert headers["Cache-Control"] == "no-store"
    assert "gesperrt, bis ihr Datenstand geprüft ist" in text
    assert "Fragen Sie IT-Service &lt;b&gt; Tel. 1234." in text
    assert f"Kennung: {_lease(stack)['correlation_id']}" in text
    # Without a lease (fresh start): the short check text.
    (stack.state_dir / lc.GATE_FILE).unlink()
    text = lc.gate_check_response(stack.state_dir, "GET", "/maintenance", {}, now)[2].decode()
    assert "prüft nach einem Neustart ihren Datenstand" in text


def test_the_check_service_serves_http(stack):
    _running(stack, PERSON)
    server = lc.gate_check_server(stack.state_dir, "127.0.0.1", 0, clock=stack.clock)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.request("GET", "/check", headers={"X-Papaia-Gate-Service": "identity"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 204
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_the_health_report_carries_the_gate(stack, tmp_path):
    _deactivated_after_the_snapshot(stack, tmp_path)
    stack.keycloak.users_error = lc.HttpError(503)
    _gate(stack)
    stack.service.start()
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    gate = report["startgate"]
    assert gate["status"] == "replay_failed"
    assert gate["failed"] == ["identity"]
    assert gate["lease"] == "closed"
    assert isinstance(gate["correlation_id"], str)


# ─────────────────────────────────────────────────────────────────────────
# epoch file and compose
# ─────────────────────────────────────────────────────────────────────────


def test_the_epoch_file_is_read_strictly(tmp_path):
    lc.write_epoch(tmp_path, 3, {"identity": 2, "papaia-flow": 7})
    assert lc.read_epoch(tmp_path) == {"generation": 3, "seq": {"identity": 2, "papaia-flow": 7}}
    path = tmp_path / lc.EPOCH_FILE
    for data in (
        b"{}",
        b'{"format":"papaia.erasure-epoch/1","generation":1,"seq":{},"x":1}',
        b'{"format":"papaia.erasure-epoch/1","generation":-1,"seq":{}}',
        b'{"format":"papaia.erasure-epoch/1","generation":1,"seq":{"Bad":1}}',
        b'{"format":"papaia.erasure-epoch/1","generation":1,"seq":{"a":true}}',
        b'{"format":"papaia.erasure-epoch/1","generation":NaN,"seq":{}}',
    ):
        path.write_bytes(data)
        with pytest.raises(lc.EpochError) as exc:
            lc.read_epoch(tmp_path)
        assert exc.value.state == "corrupt"
    with pytest.raises(lc.EpochError) as exc:
        lc.read_epoch(tmp_path / "missing")
    assert exc.value.state == "unreachable"
    path.unlink()
    assert lc.read_epoch(tmp_path) is None


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def test_no_add_on_may_attach_the_check_service():
    from lib import compat

    assert "papaia-startgate-check" in compat.NEVER_ATTACHABLE


def test_the_check_service_holds_no_secret_and_reads_the_lease_only():
    services = _compose()["services"]
    check = services["papaia-startgate-check"]
    assert check["image"] == services["papaia-lifecycle"]["image"]
    assert check["profiles"] == ["lifecycle"]
    assert check["read_only"] is True and check["cap_drop"] == ["ALL"]
    assert "environment" not in check and "ports" not in check
    assert check["networks"] == ["papaia-net"]
    (mount,) = check["volumes"]
    assert mount["source"] == "papaia-security-state" and mount["read_only"] is True
    assert "gate-check" in check["command"]
    # Only papaia-lifecycle writes the security state.
    writers = [
        name
        for name, svc in services.items()
        for m in svc.get("volumes") or []
        if isinstance(m, dict)
        and m.get("source") == "papaia-security-state"
        and not m.get("read_only")
        and name != "papaia-lifecycle-init"
    ]
    assert writers == ["papaia-lifecycle"]


def test_the_override_command_reads_its_request_from_stdin_only(stack, monkeypatch, capsys):
    gate = _gate(stack)
    gate.begin()
    key_dir = f"--key-dir={stack.key_dir}"

    def run(text: str) -> int:
        monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(text.encode())))
        return lc.main(["startgate-override", key_dir])

    assert run("not json") == 2
    assert run(json.dumps({"reason": "x", "requested_by": PERSON})) == 2
    request = {"reason": "disk replaced", "requested_by": PERSON, "confirmed_by": OTHER}
    # The gate is checking, not held closed: nothing to override.
    assert run(json.dumps({**request, "single_person": False})) == 3
    assert gate.store.load()["request"] is None
