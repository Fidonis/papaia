"""papaia-lifecycle: revocation on deactivation and the signed revocation list.

The service (`src/infra/lifecycle/lifecycle.py`) runs in a stock Python image, so it is
imported here straight from the checkout, like papaia-egress. Keycloak is replaced by an
in-memory admin API; `test_lifecycle_live.py` runs the same code against a throwaway
Keycloak of the pinned version.
"""

from __future__ import annotations

import copy
import http.client
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

from lib import backup, render_core, topology
from lib import lifecycle_account as la
from tests.realm_fake import FakeRealm

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "lifecycle"
PERSON = "0b9c7b1e-1c1f-4e55-9a51-2f7c0c3d4e5f"
OTHER = "5d0f6a2b-8e1c-4a7d-b3f2-9c8e7d6a5b4c"


def _service_module():
    path = MODULE_DIR / "lifecycle.py"
    module = types.ModuleType("papaia_lifecycle_service")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


lc = _service_module()


# ─────────────────────────────────────────────────────────────────────────
# compose service
# ─────────────────────────────────────────────────────────────────────────


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def test_the_root_compose_includes_the_lifecycle_file():
    root = yaml.safe_load((REPO / "src" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"path": "./infra/lifecycle/docker-compose.yml"} in root["include"]


def test_the_service_is_on_its_own_internal_network_only():
    doc = _compose()
    service = doc["services"]["papaia-lifecycle"]
    assert service["networks"] == ["papaia-lifecycle-net"]
    assert doc["networks"]["papaia-lifecycle-net"]["internal"] is True
    assert "ports" not in service
    assert service["profiles"] == ["lifecycle"]
    keycloak = yaml.safe_load(
        (REPO / "src" / "infra" / "keycloak" / "docker-compose.yml").read_text(encoding="utf-8")
    )["services"]["keycloak"]
    assert "papaia-lifecycle-net" in keycloak["networks"]


def test_the_service_is_hardened_and_pinned():
    doc = _compose()
    for name in ("papaia-lifecycle", "papaia-lifecycle-init"):
        service = doc["services"][name]
        assert "@sha256:" in service["image"]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
    service = doc["services"]["papaia-lifecycle"]
    assert "cap_add" not in service
    assert service["user"] == "${UID:-1000}:${GID:-1000}"
    init = doc["services"]["papaia-lifecycle-init"]
    assert init["cap_add"] == ["CHOWN"]
    assert init["network_mode"] == "none"
    assert service["depends_on"]["papaia-lifecycle-init"]["condition"] == (
        "service_completed_successfully"
    )


def _docker_daemon() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


@pytest.mark.skipif(not _docker_daemon(), reason="no Docker daemon")
def test_init_completes_again_on_volumes_it_already_handed_over(tmp_path):
    """The init service runs before every start of papaia-lifecycle. After its first run
    the folders belong to the unprivileged user, so a second run must not need a
    capability the first one used (CAP_FOWNER for chmod), or every later `up` fails."""
    doc = _compose()
    init = copy.deepcopy(doc["services"]["papaia-lifecycle-init"])
    init.pop("profiles")
    after = {
        "image": init["image"],
        "user": "${UID:-1000}:${GID:-1000}",
        "command": [
            "stat",
            "-c",
            "%u %a",
            "/var/lib/papaia-lifecycle",
            "/var/lib/papaia-security-state",
        ],
        "volumes": copy.deepcopy(init["volumes"]),
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "depends_on": {"papaia-lifecycle-init": {"condition": "service_completed_successfully"}},
    }
    project = {
        "services": {"papaia-lifecycle-init": init, "after": after},
        "volumes": copy.deepcopy(doc["volumes"]),
    }
    path = tmp_path / "docker-compose.yml"
    path.write_text(yaml.safe_dump(project), encoding="utf-8")
    name = os.environ.get("PAPAIA_TEST_COMPOSE_PROJECT") or f"papaia-test-lifecycle-{os.getpid()}"
    env = dict(os.environ, UID="1000", GID="1000")
    base = ["docker", "compose", "-p", name, "-f", str(path)]
    try:
        for attempt in (1, 2, 3):
            done = subprocess.run(
                [*base, "up", "--no-color", "after"],
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            assert done.returncode == 0, f"run {attempt}: {done.stdout}\n{done.stderr}"
            logs = subprocess.run(
                [*base, "logs", "--no-log-prefix", "after"],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            ).stdout.split()
            assert logs[-4:] == ["1000", "700", "1000", "755"], f"run {attempt}: {logs}"
    finally:
        subprocess.run([*base, "down", "-v"], env=env, capture_output=True, timeout=120)


def test_the_volumes_are_the_signing_key_and_the_security_state():
    doc = _compose()
    assert set(doc["volumes"]) == {"papaia-lifecycle-key", "papaia-security-state"}
    mounts = doc["services"]["papaia-lifecycle"]["volumes"]
    named = {m["source"]: m for m in mounts if m["type"] == "volume"}
    assert set(named) == {"papaia-lifecycle-key", "papaia-security-state"}
    binds = {m["target"]: m for m in mounts if m["type"] == "bind"}
    assert all(m["read_only"] for m in binds.values())
    account = binds["/run/papaia-lifecycle/account"]
    assert account["source"].endswith("/security/service-accounts/svc-papaia-lifecycle")
    assert account["bind"]["create_host_path"] is False


def test_the_signing_key_volume_is_left_out_of_backups():
    assert "papaia-lifecycle-key" in backup.EXCLUDED_CORE_VOLUMES
    assert "papaia-lifecycle-key" not in backup.resolve_core_volumes(REPO)
    assert "papaia-security-state" in backup.resolve_core_volumes(REPO)


def test_the_catalogue_places_the_service_next_to_keycloak():
    spec = topology.CATALOGUE["lifecycle"]
    assert spec.profiles == ("lifecycle",)
    assert ("lifecycle", "keycloak") in topology.COLOCATED


def test_render_creates_the_account_key_only_with_the_profile(tmp_path):
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=keycloak,egress\n")
    render_core.ensure_lifecycle_key(tmp_path)
    folder = tmp_path / "security" / "service-accounts" / "svc-papaia-lifecycle"
    assert not folder.exists()
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=keycloak,egress,lifecycle\n")
    render_core.ensure_lifecycle_key(tmp_path)
    key = folder / "private-key.pem"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    before = key.read_bytes()
    render_core.ensure_lifecycle_key(tmp_path)
    assert key.read_bytes() == before


# ─────────────────────────────────────────────────────────────────────────
# in-memory Keycloak
# ─────────────────────────────────────────────────────────────────────────


class FakeKeycloak:
    """The admin endpoints papaia-lifecycle uses, with a log of every call."""

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.consents: dict[str, list[str]] = {}
        self.events: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.forbidden: set[str] = set()
        self.fail_logout = False
        self.fail_logout_for: set[str] = set()
        self.events_error: Exception | None = None

    def add_user(self, uid: str, *, enabled: bool = True, consents=("flow-engine",)) -> None:
        self.users[uid] = {"id": uid, "username": f"u-{uid[:4]}", "enabled": enabled}
        self.consents[uid] = list(consents)

    def event(self, op: str, uid: str, ms: int, eid: str | None = None, path=None) -> None:
        self.events.append(
            {
                "id": eid or f"e{len(self.events):04d}",
                "time": ms,
                "operationType": op,
                "resourceType": "USER",
                "resourcePath": path or f"users/{uid}",
            }
        )

    def call(self, method: str, path: str, body=None):
        self.calls.append((method, path))
        base, _, query = path.partition("?")
        parts = base.strip("/").split("/")
        if parts == ["admin-events"]:
            if self.events_error is not None:
                raise self.events_error
            q = dict(p.split("=", 1) for p in query.split("&") if p and "=" in p)
            since = int(q.get("dateFrom", "0"))
            first, size = int(q.get("first", "0")), int(q.get("max", "100"))
            rows = sorted((e for e in self.events if e["time"] >= since), key=lambda e: e["time"])
            return rows[first : first + size]
        uid = parts[1]
        if uid in self.forbidden:
            raise lc.HttpError(403)
        if uid not in self.users:
            raise lc.HttpError(404)
        if len(parts) == 2 and method == "GET":
            return dict(self.users[uid])
        if parts[2:] == ["logout"]:
            if self.fail_logout or uid in self.fail_logout_for:
                raise lc.HttpError(500)
            return None
        if parts[2:] == ["consents"]:
            return [{"clientId": c, "grantedClientScopes": []} for c in self.consents[uid]]
        if parts[2] == "consents" and method == "DELETE":
            self.consents[uid].remove(parts[3])
            return None
        raise AssertionError(f"unexpected call {method} {path}")


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def stack(tmp_path):
    key_dir, state_dir = tmp_path / "key", tmp_path / "state"
    key_dir.mkdir(mode=0o700)
    state_dir.mkdir()
    keycloak, clock, out = FakeKeycloak(), Clock(), io.StringIO()
    store = lc.Store(key_dir)
    publisher = lc.Publisher(state_dir, lc.Signer(key_dir))
    service = lc.Lifecycle(keycloak, store, publisher, out=out, clock=clock)
    return types.SimpleNamespace(
        keycloak=keycloak,
        clock=clock,
        out=out,
        store=store,
        service=service,
        state_dir=state_dir,
        key_dir=key_dir,
    )


def _rows(out: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def _published(state_dir: Path) -> dict:
    return json.loads((state_dir / lc.LIST_FILE).read_bytes())


# ─────────────────────────────────────────────────────────────────────────
# revocation
# ─────────────────────────────────────────────────────────────────────────


def test_deactivation_logs_out_removes_every_consent_and_lists_the_person(stack):
    """RE-05a: logout alone leaves offline sessions alive; every consent goes too."""
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False, consents=("flow-engine", "assist-gate"))
    kc.add_user(OTHER)
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 500)
    kc.event("UPDATE", OTHER, int(stack.clock.now * 1000) + 600)
    stack.clock.now += 1
    stack.service.step()

    assert ("POST", f"/users/{PERSON}/logout") in kc.calls
    assert kc.consents[PERSON] == []
    assert kc.consents[OTHER] == ["flow-engine"]
    assert not any(c[1].startswith(f"/users/{OTHER}/") for c in kc.calls)
    doc = _published(stack.state_dir)
    assert set(doc) == {"seq", "issued_at", "entries"}
    assert doc["entries"] == [{"sub": PERSON, "since": 1_800_000_001, "reason": "account_disabled"}]


def test_every_write_is_one_audit_row_with_one_correlation_id(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False, consents=("flow-engine", "assist-gate"))
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    rows = [r for r in _rows(stack.out) if r["object_ref"]["id"] == PERSON]
    assert [r["operation"] for r in rows] == [
        "lifecycle.logout",
        "lifecycle.consent_delete",
        "lifecycle.consent_delete",
    ]
    assert len({r["correlation_id"] for r in rows}) == 1
    assert {r["detail"]["client"] for r in rows[1:]} == {"flow-engine", "assist-gate"}
    for row in _rows(stack.out):
        assert row["format"] == "papaia.audit/1"
        assert row["writer"] == "papaia-lifecycle"
        assert row["service_account"] == "svc-papaia-lifecycle"
        assert row["result"] == "allowed"
    assert [r["event"] for r in rows] == ["operation", "delegation_revoked", "delegation_revoked"]
    issued = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.revocation_list"]
    assert len(issued) == 2  # the first list at start, the list with the person


def test_a_deleted_account_is_listed_without_calls(stack):
    kc = stack.keycloak
    stack.service.start()
    kc.event("DELETE", PERSON, int(stack.clock.now * 1000) + 10)
    before = len(kc.calls)
    stack.service.step()
    assert all(c[1].startswith("/admin-events") for c in kc.calls[before:])
    assert _published(stack.state_dir)["entries"][0]["reason"] == "account_deleted"


def test_an_update_of_an_active_account_changes_nothing(stack):
    kc = stack.keycloak
    kc.add_user(PERSON)
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    assert ("POST", f"/users/{PERSON}/logout") not in kc.calls
    assert _published(stack.state_dir)["entries"] == []


def test_an_event_is_handled_once(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    stack.clock.now += 20
    stack.service.step()
    assert kc.calls.count(("POST", f"/users/{PERSON}/logout")) == 1


def test_a_failed_revocation_keeps_the_entry_and_is_retried(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    kc.fail_logout = True
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    assert _published(stack.state_dir)["entries"][0]["sub"] == PERSON
    errors = [r for r in _rows(stack.out) if r["result"] == "error"]
    assert errors and errors[0]["error_code"] == "http_500"
    kc.fail_logout = False
    stack.clock.now += 20
    stack.service.step()
    assert kc.consents[PERSON] == []


def test_an_account_outside_the_persons_group_is_skipped_with_a_note(stack, capsys):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    kc.forbidden.add(PERSON)
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    assert "outside the group" in capsys.readouterr().err
    assert _published(stack.state_dir)["entries"] == []
    # The gap is visible: one audit row and a count in health.
    skipped = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.revoke"]
    assert len(skipped) == 1
    assert skipped[0]["result"] == "denied"
    assert skipped[0]["error_code"] == "http_403"
    assert skipped[0]["object_ref"] == {"type": "user", "id": PERSON}
    _, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert report["skipped_revocations"] == 1
    # The same event is not counted twice.
    stack.clock.now += 20
    stack.service.step()
    assert len([r for r in _rows(stack.out) if r["operation"] == "lifecycle.revoke"]) == 1


def test_a_revocation_that_keeps_failing_does_not_hold_up_later_ones(stack):
    """After a few attempts a failing event is parked: later deactivations go ahead, the
    parked one is tried again on every poll and health warns while it is parked."""
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False)
    kc.add_user(OTHER, enabled=False)
    kc.fail_logout_for.add(PERSON)
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    kc.event("UPDATE", OTHER, int(stack.clock.now * 1000) + 20)
    for _ in range(lc.MAX_EVENT_ATTEMPTS):
        stack.clock.now += lc.POLL_SECONDS
        stack.service.step()
    assert ("POST", f"/users/{OTHER}/logout") in kc.calls
    assert kc.consents[OTHER] == []
    subs = {e["sub"] for e in _published(stack.state_dir)["entries"]}
    assert subs == {PERSON, OTHER}
    parked = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.revocation_parked"]
    assert len(parked) == 1 and parked[0]["object_ref"]["id"] == PERSON
    assert parked[0]["result"] == "error"
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert code == 1 and report["status"] == "warn"
    assert report["parked_revocations"] == 1
    # Keycloak recovers: the parked event is handled on the next poll and leaves the park.
    kc.fail_logout_for.clear()
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    assert kc.consents[PERSON] == []
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert code == 0 and report["parked_revocations"] == 0


def test_a_broken_answer_of_keycloak_does_not_stop_the_service(stack):
    stack.service.start()
    stack.keycloak.events_error = http.client.IncompleteRead(b"")
    stack.service.step()
    stack.keycloak.events_error = http.client.RemoteDisconnected("closed")
    stack.clock.now += lc.POLL_SECONDS
    stack.service.step()
    assert _published(stack.state_dir)["seq"] >= 1


def test_a_restart_does_not_hide_a_poll_that_keeps_failing(stack):
    stack.service.start()
    stack.service.step()
    stack.keycloak.events_error = lc.HttpError(503)
    stack.clock.now += 400
    again = lc.Lifecycle(
        stack.keycloak,
        lc.Store(stack.key_dir),
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=io.StringIO(),
        clock=stack.clock,
    )
    again.start()
    again.step()
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert code == 1 and report["status"] == "fail"
    assert report["last_poll_age_seconds"] >= 400


@pytest.mark.parametrize(
    "path",
    ["users/../clients", "users/a/b", "users/", "clients/x", "users/" + "a" * 80, "users/ä"],
)
def test_malformed_events_are_ignored(stack, path):
    kc = stack.keycloak
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10, path=path)
    before = len(kc.calls)
    stack.service.step()
    assert all(c[1].startswith("/admin-events") for c in kc.calls[before:])


def test_a_malformed_consent_client_is_not_put_into_a_path(stack):
    kc = stack.keycloak
    kc.add_user(PERSON, enabled=False, consents=("../../clients", "flow-engine"))
    stack.service.start()
    kc.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    assert not any("clients" in path.split("consents", 1)[-1] for _, path in kc.calls)
    assert kc.consents[PERSON] == ["../../clients"]


# ─────────────────────────────────────────────────────────────────────────
# signed revocation list
# ─────────────────────────────────────────────────────────────────────────


def test_the_list_is_signed_with_ed25519_and_verifies(stack):
    stack.service.start()
    data = (stack.state_dir / lc.LIST_FILE).read_bytes()
    sig = (stack.state_dir / lc.SIG_FILE).read_bytes()
    pub = (stack.state_dir / lc.PUB_FILE).read_bytes()
    assert len(sig) == 64
    assert b"PRIVATE" not in pub
    assert lc.verify(data, sig, pub)
    assert not lc.verify(data.replace(b'"entries"', b'"entries" '), sig, pub)


def test_the_list_files_are_readable_by_modules_and_the_key_is_not(stack):
    stack.service.start()
    for name in (lc.LIST_FILE, lc.SIG_FILE, lc.PUB_FILE):
        assert stat.S_IMODE((stack.state_dir / name).stat().st_mode) == 0o644
    key = stack.key_dir / lc.KEY_FILE
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert not any(p.name == lc.KEY_FILE for p in stack.state_dir.iterdir())


def test_the_list_is_reissued_every_15_seconds_with_a_new_seq(stack):
    stack.service.start()
    first = _published(stack.state_dir)
    stack.clock.now += 5
    stack.service.step()
    assert _published(stack.state_dir) == first
    stack.clock.now += 11
    stack.service.step()
    second = _published(stack.state_dir)
    assert second["seq"] == first["seq"] + 1
    assert second["issued_at"] == first["issued_at"] + 16
    # Reissue without change is not a write of new content: no further audit row.
    issued = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.revocation_list"]
    assert len(issued) == 1


def test_the_list_matches_the_kit_format(stack):
    stack.keycloak.add_user(PERSON, enabled=False)
    stack.service.start()
    stack.keycloak.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    doc = _published(stack.state_dir)
    assert isinstance(doc["seq"], int) and doc["seq"] >= 1
    assert isinstance(doc["issued_at"], int)
    for entry in doc["entries"]:
        assert set(entry) == {"sub", "since", "reason"}
        assert isinstance(entry["since"], int)


def test_global_since_is_set_once_and_never_moves_back(stack):
    stack.service.start()
    assert stack.service.set_global_since(1_800_000_100)
    stack.service.reissue()
    assert _published(stack.state_dir)["global_since"] == 1_800_000_100
    assert not stack.service.set_global_since(1_700_000_000)
    stack.service.reissue()
    assert _published(stack.state_dir)["global_since"] == 1_800_000_100
    rows = [r for r in _rows(stack.out) if r["operation"] == "lifecycle.global_since"]
    assert len(rows) == 1


def test_global_since_far_in_the_future_is_refused(stack):
    """global_since never moves back: a typo would refuse every token until the state
    file is edited by hand."""
    stack.service.start()
    with pytest.raises(lc.LifecycleError, match="future"):
        stack.service.set_global_since(int(stack.clock.now) + lc.GLOBAL_SINCE_SKEW_SECONDS + 1)
    assert stack.service.set_global_since(int(stack.clock.now) + lc.GLOBAL_SINCE_SKEW_SECONDS)
    assert lc.Store(stack.key_dir).load()["global_since"] == (
        int(stack.clock.now) + lc.GLOBAL_SINCE_SKEW_SECONDS
    )


def test_global_since_from_a_second_process_is_audited_by_the_running_service(stack):
    """`docker compose exec ... global-since` is a second process: its output is not the
    container log. The running service publishes the change and writes both rows."""
    stack.service.start()
    cli_out = io.StringIO()
    cli = lc.Lifecycle(
        None,
        lc.Store(stack.key_dir),
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=cli_out,
        clock=stack.clock,
    )
    assert cli.set_global_since(1_800_000_050)
    assert cli_out.getvalue() == ""
    stack.service.step()
    assert _published(stack.state_dir)["global_since"] == 1_800_000_050
    rows = _rows(stack.out)
    since = [r for r in rows if r["operation"] == "lifecycle.global_since"]
    assert len(since) == 1 and since[0]["detail"] == {"global_since": 1_800_000_050}
    issued = [r for r in rows if r["operation"] == "lifecycle.revocation_list"]
    assert len(issued) == 2  # the first list at start, the list with global_since
    # A restart of the service does not write the row again.
    again = lc.Lifecycle(
        stack.keycloak,
        lc.Store(stack.key_dir),
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=io.StringIO(),
        clock=stack.clock,
    )
    again.start()
    assert "lifecycle.global_since" not in again.out.getvalue()


def test_the_global_since_command_waits_for_the_running_service(stack, capsys, monkeypatch):
    stack.service.start()
    monkeypatch.setattr(lc, "GLOBAL_SINCE_WAIT_SECONDS", 0)
    code = lc.main(
        [
            "global-since",
            f"--key-dir={stack.key_dir}",
            f"--state-dir={stack.state_dir}",
            f"--at={int(lc.time.time())}",
        ]
    )
    assert code == 0
    assert "not yet published" in capsys.readouterr().out
    code = lc.main(
        [
            "global-since",
            f"--key-dir={stack.key_dir}",
            f"--state-dir={stack.state_dir}",
            f"--at={int(lc.time.time()) + 10 * lc.GLOBAL_SINCE_SKEW_SECONDS}",
        ]
    )
    assert code == 1


def test_the_state_survives_a_restart(stack):
    stack.keycloak.add_user(PERSON, enabled=False)
    stack.service.start()
    stack.keycloak.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    seq = _published(stack.state_dir)["seq"]
    again = lc.Lifecycle(
        stack.keycloak,
        lc.Store(stack.key_dir),
        lc.Publisher(stack.state_dir, lc.Signer(stack.key_dir)),
        out=io.StringIO(),
        clock=stack.clock,
    )
    again.start()
    doc = _published(stack.state_dir)
    assert doc["seq"] == seq + 1
    assert doc["entries"][0]["sub"] == PERSON
    assert stack.keycloak.calls.count(("POST", f"/users/{PERSON}/logout")) == 1


def test_a_state_file_with_unknown_fields_is_refused(stack):
    stack.service.start()
    path = stack.key_dir / lc.STATE_FILE
    doc = json.loads(path.read_text())
    doc["extra"] = 1
    path.write_text(json.dumps(doc))
    with pytest.raises(lc.LifecycleError):
        lc.Store(stack.key_dir).load()


def test_old_entries_are_dropped_after_the_retention(stack):
    stack.keycloak.add_user(PERSON, enabled=False)
    stack.service.start()
    stack.keycloak.event("UPDATE", PERSON, int(stack.clock.now * 1000) + 10)
    stack.service.step()
    stack.clock.now += lc.ENTRY_RETENTION_SECONDS + 60
    stack.service.step()
    assert _published(stack.state_dir)["entries"] == []


# ─────────────────────────────────────────────────────────────────────────
# health
# ─────────────────────────────────────────────────────────────────────────


def test_health_reports_the_age_of_the_list(stack):
    stack.service.start()
    stack.service.step()
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now + 7)
    assert code == 0
    assert report["status"] == "ok"
    assert report["revocations_age_seconds"] == 7


def test_health_fails_for_an_old_list(stack):
    stack.service.start()
    stack.service.step()
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now + 61)
    assert code == 1 and report["status"] == "warn"
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now + 301)
    assert code == 1 and report["status"] == "fail"


def test_health_fails_for_a_list_that_does_not_verify(stack):
    stack.service.start()
    path = stack.state_dir / lc.LIST_FILE
    path.write_bytes(path.read_bytes().replace(b'"entries":[]', b'"entries":[ ]'))
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert code == 1 and report["status"] == "fail"


def test_health_fails_without_a_recent_poll(stack):
    stack.service.start()
    stack.clock.now += 400
    stack.service.reissue()  # the list stays fresh while Keycloak is not read
    code, report = lc.health(stack.state_dir, stack.key_dir, now=stack.clock.now)
    assert code == 1
    assert report["last_poll_age_seconds"] >= 400


# ─────────────────────────────────────────────────────────────────────────
# boundaries
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    ["http://keycloak:8080", "ftp://keycloak", "https://", "https://kc/x?y", "http://10.0.0.1"],
)
def test_keycloak_url_is_https_or_loopback(url):
    with pytest.raises(lc.LifecycleError):
        lc.keycloak_url(url)


@pytest.mark.parametrize("url", ["https://keycloak:8443", "http://127.0.0.1:58540"])
def test_keycloak_url_accepted(url):
    assert lc.keycloak_url(url) == url


def test_the_client_assertion_is_es256_with_the_account_key(tmp_path):
    folder = tmp_path / "account"
    folder.mkdir(mode=0o700)
    pem = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        capture_output=True,
        check=True,
    ).stdout
    fd = os.open(folder / "private-key.pem", os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, pem)
    os.close(fd)
    account = lc.AccountKey(folder)
    token = account.assertion("https://auth.example.org/realms/papaia", now=1_800_000_000)
    header, claims, signature = token.split(".")
    decode = lc.b64decode
    assert json.loads(decode(header)) == {"alg": "ES256", "kid": account.kid, "typ": "JWT"}
    body = json.loads(decode(claims))
    assert body["iss"] == body["sub"] == "svc-papaia-lifecycle"
    assert body["exp"] - body["iat"] <= 60
    assert len(decode(signature)) == 64


def test_main_rejects_unknown_arguments():
    with pytest.raises(SystemExit):
        lc.main(["run", "--unknown"])


# ─────────────────────────────────────────────────────────────────────────
# realm switches of the account
# ─────────────────────────────────────────────────────────────────────────


def _switches(fake: FakeRealm, *, apply: bool = True) -> list:
    run = la._Align(fake.call, None, apply, None)
    run.realm_switches()
    return run.act.changes


def test_admin_events_are_stored_for_seven_days_only():
    """Admin events carry actor, address and resource path: Keycloak keeps them 7 days
    (sicherheit §1.12 events row, EXI-P08); papaia-audit is the record that lasts."""
    fake = FakeRealm()
    _switches(fake)
    assert fake.events_config["adminEventsEnabled"] is True
    assert fake.events_config["adminEventsDetailsEnabled"] is False
    assert fake.realm["attributes"]["adminEventsExpiration"] == str(7 * 24 * 3600)
    assert la.ADMIN_EVENTS_EXPIRATION == 7 * 24 * 3600
    assert _switches(fake, apply=False) == []


def test_a_retention_the_operator_set_is_kept():
    fake = FakeRealm()
    fake.realm["attributes"] = {"adminEventsExpiration": "86400", "other": "x"}
    _switches(fake)
    assert fake.realm["attributes"] == {"adminEventsExpiration": "86400", "other": "x"}


def test_unlimited_admin_events_get_the_retention():
    fake = FakeRealm()
    fake.events_config["adminEventsEnabled"] = True
    fake.realm["attributes"] = {"other": "x"}
    changes = _switches(fake)
    assert [c.action for c in changes if "retention" in c.action]
    assert fake.realm["attributes"] == {
        "adminEventsExpiration": str(la.ADMIN_EVENTS_EXPIRATION),
        "other": "x",
    }


@pytest.mark.parametrize("value", ["", "0", "-5", "x"])
def test_no_or_an_unlimited_retention_is_replaced(value):
    fake = FakeRealm()
    fake.realm["attributes"] = {"adminEventsExpiration": value}
    _switches(fake)
    assert fake.realm["attributes"]["adminEventsExpiration"] == str(la.ADMIN_EVENTS_EXPIRATION)
