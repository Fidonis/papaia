"""`papaia-ctl post-restore`: no delegation from a restore point stays usable (RE-05a, BE-17).

After `restore` (and so after `addon rollback --restore-data`, which restores through it),
the realm's "not before" moves past every token issued before, and the consents of the two
holders of delegations, `flow-engine` and `assist-gate`, are removed for every person whose
grant predates the restore. A second run changes nothing, and a grant made after the restore
survives it. Every write is one `papaia.audit/1` row with the run's correlation id.

The Admin API is an in-memory stand-in that also checks refresh tokens the way Keycloak
does: refused when issued before the realm's "not before" or when the offline session of
that client is gone.
"""

from __future__ import annotations

import copy
import io
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

from lib import post_restore as pr
from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import _flow, _pairings, _paperless, _plan, _run, _studio

TOOLS = Path(__file__).resolve().parents[1]
CTL = TOOLS / "papaia-ctl"
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
LIFECYCLE_SH = TOOLS / "lib" / "sh" / "lifecycle.sh"
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")

BACKUP_TIME = 1_790_000_000  # when the restore point was taken
RESTORE_TIME = BACKUP_TIME + 86_400  # when it was restored
ANNA, BEN, CARL = (
    "6f1c2a9e-0000-4000-8000-00000000a001",
    "6f1c2a9e-0000-4000-8000-00000000b002",
    "6f1c2a9e-0000-4000-8000-00000000c003",
)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Keycloak:
    """Users, consents, offline sessions and refresh tokens of the `papaia` realm."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.realm = {"realm": "papaia", "notBefore": 0}
        self.clients = {
            "flow-engine": "c0000000-0000-4000-8000-0000000000f1",
            "assist-gate": "c0000000-0000-4000-8000-0000000000a2",
            "librechat": "c0000000-0000-4000-8000-0000000000c3",
        }
        # uid -> client -> consent dates (ms) or None for a grant without a consent
        self.consents: dict[str, dict[str, dict | None]] = {}
        # uid -> client -> offline session starts (ms)
        self.sessions: dict[str, dict[str, list[int]]] = {}
        self.writes: list[tuple[str, str]] = []
        self.reads: list[str] = []
        self.fail: dict[tuple[str, str], int] = {}
        self._tokens = 0

    # state --------------------------------------------------------------
    def grant(self, uid: str, client: str, *, consent: bool = True) -> tuple[str, str, int]:
        """A person grants `client` a delegation now: consent and offline session."""
        ms = int(self.clock() * 1000)
        self.consents.setdefault(uid, {})[client] = (
            {"createdDate": ms, "lastUpdatedDate": ms} if consent else None
        )
        self.sessions.setdefault(uid, {}).setdefault(client, []).append(ms)
        return (uid, client, int(self.clock()))

    def add_user(self, uid: str) -> None:
        self.consents.setdefault(uid, {})
        self.sessions.setdefault(uid, {})

    def refresh(self, token: tuple[str, str, int]) -> int:
        uid, client, iat = token
        if iat < self.realm["notBefore"]:
            return 400
        if not self.sessions.get(uid, {}).get(client):
            return 400
        return 200

    def snapshot(self) -> dict:
        return copy.deepcopy(
            {"realm": self.realm, "consents": self.consents, "sessions": self.sessions}
        )

    def restore(self, snap: dict) -> None:
        snap = copy.deepcopy(snap)
        self.realm, self.consents, self.sessions = snap["realm"], snap["consents"], snap["sessions"]

    # Admin API ----------------------------------------------------------
    def call(self, method: str, path: str, body=None):
        key = (method, urllib.parse.urlsplit(path).path)
        if key in self.fail:
            raise urllib.error.HTTPError(path, self.fail[key], "refused", {}, io.BytesIO(b""))
        if method == "GET":
            self.reads.append(path)
        else:
            self.writes.append((method, path))
        parts = urllib.parse.urlsplit(path)
        route, query = parts.path, urllib.parse.parse_qs(parts.query)
        if route == "":
            if method == "GET":
                return copy.deepcopy(self.realm)
            assert set(body) == {"notBefore"}, body
            self.realm.update(body)
            return None
        if route == "/clients" and method == "GET":
            wanted = query["clientId"][0]
            return [{"id": u, "clientId": c} for c, u in self.clients.items() if c == wanted]
        if route == "/users" and method == "GET":
            assert query["briefRepresentation"] == ["true"]
            first, size = int(query["first"][0]), int(query["max"][0])
            users = sorted(self.consents)[first : first + size]
            return [{"id": u, "username": f"user-{u[-4:]}"} for u in users]
        m = re.fullmatch(r"/users/([^/]+)/consents", route)
        if m and method == "GET":
            return self._consents(urllib.parse.unquote(m.group(1)))
        m = re.fullmatch(r"/users/([^/]+)/consents/([^/]+)", route)
        if m and method == "DELETE":
            uid, client = (urllib.parse.unquote(g) for g in m.groups())
            if client not in self.consents.get(uid, {}):
                raise urllib.error.HTTPError(path, 404, "not found", {}, io.BytesIO(b""))
            del self.consents[uid][client]
            self.sessions.get(uid, {}).pop(client, None)
            return None
        m = re.fullmatch(r"/users/([^/]+)/offline-sessions/([^/]+)", route)
        if m and method == "GET":
            uid, uuid = (urllib.parse.unquote(g) for g in m.groups())
            client = next(c for c, u in self.clients.items() if u == uuid)
            return [
                {"id": f"s{i}", "start": start, "clients": {uuid: client}}
                for i, start in enumerate(self.sessions.get(uid, {}).get(client, []))
            ]
        raise AssertionError(f"unexpected call {method} {path}")

    def _consents(self, uid: str) -> list[dict]:
        rows = []
        for client, dates in self.consents.get(uid, {}).items():
            row = {"clientId": client, "grantedClientScopes": []}
            if dates:
                row.update(dates)
            if self.sessions.get(uid, {}).get(client):
                row["additionalGrants"] = [{"client": self.clients[client], "key": "Offline Token"}]
            rows.append(row)
        return rows


@pytest.fixture
def clock() -> Clock:
    return Clock(BACKUP_TIME - 3600)


@pytest.fixture
def kc(clock: Clock) -> Keycloak:
    return Keycloak(clock)


def _restore(kc: Keycloak, clock: Clock, snap: dict) -> int:
    """Put the restore point back; returns the `--since` a restore passes."""
    clock.now = RESTORE_TIME
    kc.restore(snap)
    since = int(clock())
    clock.now += 40  # the stack starts again
    return since


def _audit(tmp_path: Path, correlation: str = "0199a000-0000-7000-8000-000000000001"):
    return rs.AuditLog(tmp_path / "outbox.jsonl", correlation, writer="papaia-ctl/post-restore")


def _rows(tmp_path: Path) -> list[dict]:
    path = tmp_path / "outbox.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# the post-restore step
# ─────────────────────────────────────────────────────────────────────────


def test_after_a_simulated_restore_an_old_refresh_token_is_refused_and_a_second_run_is_a_no_op(
    kc, clock, tmp_path
):
    kc.add_user(CARL)
    anna_flow = kc.grant(ANNA, "flow-engine")
    ben_assist = kc.grant(BEN, "assist-gate", consent=False)
    clock.now = BACKUP_TIME
    snap = kc.snapshot()
    # After the backup: Anna and Ben revoke; the restore point brings both grants back.
    kc.consents[ANNA].clear()
    kc.sessions[ANNA].clear()
    kc.consents[BEN].clear()
    kc.sessions[BEN].clear()
    since = _restore(kc, clock, snap)
    assert kc.refresh(anna_flow) == 200, "the restored grant would be usable"
    assert kc.refresh(ben_assist) == 200

    with _audit(tmp_path) as audit:
        changes = pr.run(kc.call, since, audit=audit, now=clock)

    assert kc.refresh(anna_flow) == 400
    assert kc.refresh(ben_assist) == 400
    assert kc.realm["notBefore"] > since
    assert kc.consents[ANNA] == {} and kc.consents[BEN] == {}
    assert [c.operation for c in changes] == ["not_before", "consent_delete", "consent_delete"]

    kc.writes.clear()
    with _audit(tmp_path) as audit:
        assert pr.run(kc.call, since, audit=audit, now=clock) == []
    assert kc.writes == []


def test_the_realm_not_before_is_past_every_token_of_the_second_it_is_set(kc, clock):
    clock.now = RESTORE_TIME + 0.4
    late = kc.grant(ANNA, "librechat")
    pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert kc.refresh(late) == 400, "a token issued in the same second must not survive"
    assert kc.realm["notBefore"] == RESTORE_TIME + 1


def test_not_before_is_never_moved_back(kc, clock):
    kc.realm["notBefore"] = RESTORE_TIME + 500
    clock.now = RESTORE_TIME + 600
    assert pr.run(kc.call, RESTORE_TIME, audit=None, now=clock) == []
    assert kc.realm["notBefore"] == RESTORE_TIME + 500
    assert kc.writes == []


def test_consents_of_other_clients_are_kept(kc, clock):
    kc.grant(ANNA, "librechat")
    kc.grant(ANNA, "flow-engine")
    clock.now = RESTORE_TIME
    pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert set(kc.consents[ANNA]) == {"librechat"}
    assert ("DELETE", f"/users/{ANNA}/consents/librechat") not in kc.writes


def test_a_grant_made_after_the_restore_survives_a_second_run(kc, clock, tmp_path):
    kc.grant(ANNA, "flow-engine")
    clock.now = BACKUP_TIME
    snap = kc.snapshot()
    since = _restore(kc, clock, snap)
    pr.run(kc.call, since, audit=None, now=clock)

    clock.now += 120
    regrant = kc.grant(ANNA, "flow-engine")
    regrant_offline = kc.grant(BEN, "assist-gate", consent=False)
    kc.writes.clear()
    assert pr.run(kc.call, since, audit=None, now=clock) == []
    assert kc.writes == []
    assert kc.refresh(regrant) == 200
    assert kc.refresh(regrant_offline) == 200


def test_a_grant_without_a_consent_is_judged_by_its_offline_session(kc, clock):
    kc.grant(BEN, "assist-gate", consent=False)
    clock.now = RESTORE_TIME
    pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert "assist-gate" not in kc.consents[BEN]
    uuid = kc.clients["assist-gate"]
    assert f"/users/{BEN}/offline-sessions/{uuid}" in kc.reads


def test_a_recent_consent_with_an_old_offline_session_is_removed(kc, clock):
    kc.grant(ANNA, "flow-engine", consent=False)
    clock.now = RESTORE_TIME + 10
    kc.consents[ANNA]["flow-engine"] = {
        "createdDate": int(clock() * 1000),
        "lastUpdatedDate": int(clock() * 1000),
    }
    pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert "flow-engine" not in kc.consents[ANNA]


def test_every_person_is_reached_across_pages(kc, clock):
    uids = [f"6f1c2a9e-0000-4000-8000-{n:012d}" for n in range(pr.PAGE + 3)]
    for uid in uids:
        kc.grant(uid, "flow-engine")
    clock.now = RESTORE_TIME
    changes = pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert len([c for c in changes if c.operation == "consent_delete"]) == len(uids)
    assert all(kc.consents[uid] == {} for uid in uids)


def test_a_holder_client_the_realm_does_not_have_is_left_out(kc, clock):
    del kc.clients["assist-gate"]
    kc.grant(ANNA, "flow-engine")
    clock.now = RESTORE_TIME
    changes = pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert [c.name for c in changes if c.kind == "consent"] == [f"{ANNA}/flow-engine"]


def test_one_audit_row_per_write_with_one_correlation_id_and_no_secret(kc, clock, tmp_path):
    kc.grant(ANNA, "flow-engine")
    kc.grant(BEN, "assist-gate")
    clock.now = RESTORE_TIME
    with _audit(tmp_path) as audit:
        changes = pr.run(kc.call, RESTORE_TIME, audit=audit, now=clock)
    rows = _rows(tmp_path)
    assert len(rows) == len(changes) == 3
    assert {r["format"] for r in rows} == {"papaia.audit/1"}
    assert len({r["correlation_id"] for r in rows}) == 1
    assert [r["source_seq"] for r in rows] == [1, 2, 3]
    assert {r["result"] for r in rows} == {"allowed"}
    assert {r["writer"] for r in rows} == {"papaia-ctl/post-restore"}
    first, *consents = rows
    assert first["operation"] == "post_restore.not_before"
    assert first["object_ref"] == {"type": "realm", "id": "papaia"}
    assert first["event"] == "sessions_revoked"
    assert {r["operation"] for r in consents} == {"post_restore.consent_delete"}
    assert {r["effect"] for r in consents} == {"delete"}
    assert {r["event"] for r in consents} == {"delegation_revoked"}
    assert {r["object_ref"]["id"] for r in consents} == {
        f"{ANNA}/flow-engine",
        f"{BEN}/assist-gate",
    }
    text = (tmp_path / "outbox.jsonl").read_text()
    assert "token" not in text.lower().replace("sessions_revoked", "")


def test_a_refused_removal_is_audited_as_an_error_and_stops_the_run(kc, clock, tmp_path):
    kc.grant(ANNA, "flow-engine")
    kc.fail[("DELETE", f"/users/{ANNA}/consents/flow-engine")] = 403
    clock.now = RESTORE_TIME
    with pytest.raises(urllib.error.HTTPError), _audit(tmp_path) as audit:
        pr.run(kc.call, RESTORE_TIME, audit=audit, now=clock)
    rows = _rows(tmp_path)
    assert [(r["operation"], r["result"], r["error_code"]) for r in rows] == [
        ("post_restore.not_before", "allowed", None),
        ("post_restore.consent_delete", "error", "http_403"),
    ]
    # A second run after the cause is fixed finishes the job.
    del kc.fail[("DELETE", f"/users/{ANNA}/consents/flow-engine")]
    changes = pr.run(kc.call, RESTORE_TIME, audit=None, now=clock)
    assert [c.operation for c in changes] == ["consent_delete"]


@pytest.mark.parametrize(
    "users",
    [
        [{"id": "../../clients"}],
        [{"id": ""}],
        [{"username": "no-id"}],
        ["not-an-object"],
        {"id": ANNA},
    ],
)
def test_a_malformed_account_list_stops_the_run_before_any_consent_is_touched(kc, clock, users):
    kc.grant(ANNA, "flow-engine")
    clock.now = RESTORE_TIME
    real = kc.call

    def call(method, path, body=None):
        if path.startswith("/users?"):
            return users
        return real(method, path, body)

    with pytest.raises(pr.PostRestoreError):
        pr.run(call, RESTORE_TIME, audit=None, now=clock)
    assert not any(method == "DELETE" for method, _ in kc.writes)


@pytest.mark.parametrize(
    "consent",
    [
        {"clientId": "flow-engine", "createdDate": "yesterday"},
        {"clientId": "flow-engine", "createdDate": -1},
        {"clientId": "flow-engine", "createdDate": True},
    ],
)
def test_a_malformed_consent_date_counts_as_old(kc, clock, consent):
    """Fail closed: a grant whose age cannot be read is removed."""
    kc.grant(ANNA, "flow-engine")
    clock.now = RESTORE_TIME
    real = kc.call

    def call(method, path, body=None):
        if method == "GET" and path == f"/users/{ANNA}/consents":
            return [consent]
        return real(method, path, body)

    pr.run(call, RESTORE_TIME, audit=None, now=clock)
    assert ("DELETE", f"/users/{ANNA}/consents/flow-engine") in kc.writes


@pytest.mark.parametrize("raw", ["", "abc", "-5", "0", "1e9", " 17", "1790000000\n", "9" * 11])
def test_since_must_be_a_plain_positive_unix_time(raw):
    with pytest.raises(pr.PostRestoreError):
        pr.parse_since(raw, now=RESTORE_TIME)


def test_since_may_not_lie_in_the_future():
    with pytest.raises(pr.PostRestoreError):
        pr.parse_since(str(RESTORE_TIME + pr.MAX_SKEW + 1), now=RESTORE_TIME)
    assert pr.parse_since(str(RESTORE_TIME + pr.MAX_SKEW), now=RESTORE_TIME) == (
        RESTORE_TIME + pr.MAX_SKEW
    )


def test_without_since_the_step_starts_now():
    assert pr.parse_since(None, now=RESTORE_TIME + 0.7) == RESTORE_TIME


# ─────────────────────────────────────────────────────────────────────────
# entry point
# ─────────────────────────────────────────────────────────────────────────


def test_with_an_external_identity_provider_there_is_nothing_to_do(tmp_path, capsys):
    tree = {"": {"AUTH_PROVIDER": "external_oidc"}}
    assert pr.main(tree, tmp_path, None) == 0
    out = capsys.readouterr().out
    assert "external identity provider" in out
    assert not (tmp_path / "audit").exists()


def test_a_bad_since_is_refused_with_exit_2_before_keycloak_is_asked(tmp_path, capsys):
    assert pr.main({"": {}}, tmp_path, "yesterday") == 2
    assert "Nothing was changed" in capsys.readouterr().err


def test_without_the_admin_password_the_step_fails(tmp_path, capsys):
    tree = {"": {}, "infra/keycloak": {}}
    assert pr.main(tree, tmp_path, None) == 1
    assert "KC_ADMIN_PASSWORD" in capsys.readouterr().err


def test_the_cli_offers_post_restore_with_since():
    from lib import cli

    args = cli.build_parser().parse_args(
        ["--repo-root", "/r", "--config-dir", "/c", "post-restore", "--since", "1790000000"]
    )
    assert args.func is cli.cmd_post_restore
    assert args.since == "1790000000"


# ─────────────────────────────────────────────────────────────────────────
# a later realm sync never puts "not before" back
# ─────────────────────────────────────────────────────────────────────────


def test_a_realm_sync_after_the_restore_leaves_not_before_alone():
    assert "notBefore" not in rh.Settings().realm()
    realm = FakeRealm()
    realm.realm["notBefore"] = RESTORE_TIME + 1
    plan = _plan([_flow(), _studio(), _paperless()], _pairings())
    plan.hardening = rh.load({}, None)
    _run(realm, plan)
    _run(realm, plan)
    assert realm.realm["notBefore"] == RESTORE_TIME + 1


# ─────────────────────────────────────────────────────────────────────────
# restore runs the step (bash, with py_cli and the stack replaced)
# ─────────────────────────────────────────────────────────────────────────

_HARNESS = """
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/src/docker-compose.yml"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
usage() { echo "usage"; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    case "$1" in
        backup-dir) echo "@BACKUPS@" ;;
        restore-resolve)
            printf 'SNAPSHOT\\t@BACKUPS@/p1\\n'
            printf 'ID\\tp1\\n'
            printf 'volume\\tv.tar.gz\\tpapaia_v\\tcore\\n'
            ;;
        post-restore) return @POST_RC@ ;;
        render) return @RENDER_RC@ ;;
        active-addons) echo flow ;;
        *) return 0 ;;
    esac
}
docker() {
    echo "docker $*" >> "@LOG@"
    case "$*" in
        *"config --services"*) echo keycloak ;;
        *"config --images"*) echo "quay.io/keycloak/keycloak@sha256:0" ;;
        *" up "*) return @UP_RC@ ;;
    esac
}
source "@LIFECYCLE@"
source "@ADDON@"
source "@BACKUP@"
# After the libraries: these replace their own definitions.
_require_setup_done() { :; }
_topology_mode() { echo @MODE@; }
_restore_teardown() { echo "teardown" >> "@LOG@"; }
_restore_teardown_scoped() { echo "teardown-scoped" >> "@LOG@"; }
_restore_artifact() { echo "artifact $3" >> "@LOG@"; return @ARTIFACT_RC@; }
_containers_using_volume() { :; }
_localai_native_install() { :; }
_localai_native_start() { :; }
_stopped_containers_go_stale() { return 1; }
_pull_quietly() { return 1; }
_addon_image_flags() { :; }
_addon_image_files_remove() { :; }
_addon_path() { echo "@ROOT@/addons/$1"; }
_addon_compose_up() { echo "addon-up $1" >> "@LOG@"; }
"""

# The restart as the real one behaves around the step: `fail` returns before the step is
# reached (an image refusal), `exit` leaves the script there (an explicit exit or a `set -e`
# stop), `late` fails after it (a service that does not come up). `MODULES` marks the first
# module start.
_RESTART_STUBS = """
_stub_start() {
    echo "$1" >> "@LOG@"
    case "@START@" in
        fail) return 2 ;;
        exit) exit 2 ;;
    esac
    _post_restore_before_modules 0 || return $?
    echo "MODULES" >> "@LOG@"
    [ "@START@" = late ] && return 1
    return 0
}
cmd_start() { _stub_start "cmd_start $*"; }
_restore_restart_scoped() { _stub_start "restart-scoped"; }
"""


def _bash(
    tmp_path: Path,
    body: str,
    *,
    post_rc=0,
    artifact_rc=0,
    mode="single",
    start="ok",
    up_rc=0,
    render_rc=0,
    real_start=False,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert BASH is not None
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    (tmp_path / "backups").mkdir(exist_ok=True)
    (tmp_path / "config").mkdir(exist_ok=True)
    harness = _HARNESS if real_start else _HARNESS + _RESTART_STUBS
    harness = (
        harness.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@ROOT@", (tmp_path / "root").as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@BACKUPS@", (tmp_path / "backups").as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE_SH.as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@BACKUP@", BACKUP_SH.as_posix())
        .replace("@POST_RC@", str(post_rc))
        .replace("@ARTIFACT_RC@", str(artifact_rc))
        .replace("@MODE@", mode)
        .replace("@START@", start)
        .replace("@UP_RC@", str(up_rc))
        .replace("@RENDER_RC@", str(render_rc))
    )
    done = subprocess.run(
        [BASH, "-c", f"{harness}\n{body}"], capture_output=True, text=True, timeout=60, check=False
    )
    return done, log.read_text(encoding="utf-8").splitlines()


needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")


def _since(calls: list[str]) -> int:
    line = next(c for c in calls if c.startswith("py_cli post-restore"))
    return int(re.search(r"--since=(\d+)", line).group(1))


def _index(calls: list[str], prefix: str) -> int:
    return next(i for i, c in enumerate(calls) if c.startswith(prefix))


def _marker(tmp_path: Path) -> Path:
    return tmp_path / "config" / "post-restore.pending"


def _restore_log(tmp_path: Path) -> str:
    return (tmp_path / "backups" / "backup.log").read_text(encoding="utf-8")


@needs_bash
def test_restore_runs_post_restore_before_the_first_module_with_the_time_it_began(tmp_path):
    import time

    before = int(time.time())
    done, calls = _bash(tmp_path, "cmd_restore -y")
    assert done.returncode == 0, done.stderr
    assert _index(calls, "teardown") < _index(calls, "py_cli post-restore")
    assert _index(calls, "cmd_start") < _index(calls, "py_cli post-restore")
    assert _index(calls, "py_cli post-restore") < _index(calls, "MODULES")
    assert before <= _since(calls) <= int(time.time())
    assert "post_restore=ok" in _restore_log(tmp_path)
    assert not _marker(tmp_path).exists()


@needs_bash
@pytest.mark.parametrize("flags", ["--only=volume:papaia_v", "--no-restart"])
def test_a_scoped_restore_or_one_without_restart_runs_it_too(tmp_path, flags):
    done, calls = _bash(tmp_path, f"cmd_restore -y {flags}")
    assert done.returncode == 0, done.stderr
    assert any(c.startswith("py_cli post-restore --since=") for c in calls)


@needs_bash
def test_a_scoped_restore_runs_it_before_the_modules_it_restarts(tmp_path):
    done, calls = _bash(tmp_path, "cmd_restore -y --only=volume:papaia_v")
    assert done.returncode == 0, done.stderr
    assert _index(calls, "py_cli post-restore") < _index(calls, "MODULES")
    assert not _marker(tmp_path).exists()


@needs_bash
def test_restore_scoped_runs_it_as_well(tmp_path):
    done, calls = _bash(tmp_path, "cmd_restore_scoped -y --only=volume:papaia_v")
    assert done.returncode == 0, done.stderr
    assert any(c.startswith("py_cli post-restore --since=") for c in calls)


@needs_bash
def test_without_restart_the_step_runs_now_and_again_at_the_next_start(tmp_path):
    """Keycloak may serve the realm from its cache over the overwritten database."""
    done, calls = _bash(tmp_path, "cmd_restore -y --no-restart")
    assert done.returncode == 0, done.stderr
    assert _marker(tmp_path).read_text().strip() == str(_since(calls))
    assert "next start" in done.stderr


@needs_bash
def test_a_failed_post_restore_fails_the_restore_and_names_the_way_to_finish_it(tmp_path):
    done, calls = _bash(tmp_path, "cmd_restore -y", post_rc=1)
    assert done.returncode == 3
    since = _since(calls)
    assert f"papaia-ctl post-restore --since={since}" in done.stderr
    assert "restore complete" not in done.stdout
    assert "post_restore=failed" in _restore_log(tmp_path)
    assert "MODULES" not in calls
    assert _marker(tmp_path).read_text().strip() == str(since)


@needs_bash
@pytest.mark.parametrize("scope", ["", "--only=volume:papaia_v"])
@pytest.mark.parametrize("start", ["fail", "exit"])
def test_a_restart_that_fails_before_the_step_leaves_it_pending_and_names_it(
    tmp_path, scope, start
):
    """Fail closed: the restored delegations must not come back with the next start."""
    import time

    before = int(time.time())
    done, calls = _bash(tmp_path, f"cmd_restore -y {scope}", start=start)
    assert done.returncode != 0
    assert not any(c.startswith("py_cli post-restore") for c in calls)
    since = int(re.search(r"post-restore --since=(\d+)", done.stderr).group(1))
    assert before <= since <= int(time.time())
    assert f"--config-dir={tmp_path / 'config'}" in done.stderr
    log = _restore_log(tmp_path)
    assert "post_restore=pending" in log
    assert log.count(" id=p1 ") == 1
    assert "restore complete" not in done.stdout
    # The next `start` runs the step before any module (see the cmd_start tests below).
    assert _marker(tmp_path).read_text().strip() == str(since)


@needs_bash
@pytest.mark.parametrize("scope", ["", "--only=volume:papaia_v"])
def test_a_restart_that_fails_after_the_step_still_fails_the_restore(tmp_path, scope):
    done, calls = _bash(tmp_path, f"cmd_restore -y {scope}", start="late")
    assert done.returncode != 0
    assert "post-restore ran, but the stack did not" in done.stderr
    assert "post_restore=ok" in _restore_log(tmp_path)
    assert "restore complete" not in done.stdout
    assert not _marker(tmp_path).exists()


@needs_bash
def test_a_failing_step_inside_the_real_start_still_stops_it(tmp_path):
    """`set -e` keeps applying inside the restart: a failed render starts nothing."""
    done, calls = _bash(tmp_path, "cmd_restore -y", real_start=True, render_rc=1)
    assert done.returncode != 0
    assert not any(c.startswith("docker") and " up " in c for c in calls)
    assert "addon-up flow" not in calls
    assert "post_restore=pending" in _restore_log(tmp_path)
    assert "papaia-ctl post-restore --since=" in done.stderr


@needs_bash
def test_a_restore_through_the_real_start_runs_the_step_before_the_first_module(tmp_path):
    done, calls = _bash(tmp_path, "cmd_restore -y", real_start=True)
    assert done.returncode == 0, done.stderr
    step = _index(calls, "py_cli post-restore --since=")
    assert step < _index(calls, "addon-up flow")
    assert "post_restore=ok" in _restore_log(tmp_path)
    assert not _marker(tmp_path).exists()


@needs_bash
def test_a_restore_that_restored_nothing_does_not_run_it(tmp_path):
    done, calls = _bash(tmp_path, "cmd_restore -y", artifact_rc=1)
    assert done.returncode == 3
    assert not any(c.startswith("py_cli post-restore") for c in calls)
    assert not _marker(tmp_path).exists()
    assert "result=failed" in _restore_log(tmp_path)
    assert "post_restore=skipped" in _restore_log(tmp_path)


# ─────────────────────────────────────────────────────────────────────────
# a pending step: Keycloak alone, the step, then the modules (BE-17)
# ─────────────────────────────────────────────────────────────────────────


@needs_bash
def test_nothing_pending_means_nothing_extra(tmp_path):
    done, calls = _bash(tmp_path, "_post_restore_before_modules 0")
    assert done.returncode == 0, done.stderr
    assert calls == []


@needs_bash
def test_a_pending_step_brings_up_keycloak_alone_checks_its_images_and_runs(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "_post_restore_before_modules 0")
    assert done.returncode == 0, done.stderr
    verify = _index(calls, "py_cli image-verify")
    up = next(i for i, c in enumerate(calls) if c.startswith("docker") and " up " in c)
    assert calls[up].endswith("up -d --no-recreate keycloak")
    assert "COMPOSE_PROFILES" not in calls[up]
    assert verify < up < _index(calls, "py_cli post-restore --since=1790000000")
    assert not _marker(tmp_path).exists()


@needs_bash
@pytest.mark.parametrize("content", ["", "yesterday", "0", "1790000000; rm -rf /"])
def test_an_unreadable_marker_runs_the_step_from_now(tmp_path, content):
    """Fail closed: a later `since` revokes more, never less."""
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text(content)
    done, calls = _bash(tmp_path, "_post_restore_before_modules 0")
    assert done.returncode == 0, done.stderr
    assert "py_cli post-restore" in calls


@needs_bash
@pytest.mark.parametrize(("post_rc", "up_rc"), [(1, 0), (0, 1)])
def test_a_failed_step_or_keycloak_start_keeps_it_pending(tmp_path, post_rc, up_rc):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "_post_restore_before_modules 0", post_rc=post_rc, up_rc=up_rc)
    assert done.returncode != 0
    assert _marker(tmp_path).exists()
    assert "papaia-ctl post-restore --since=1790000000" in done.stderr
    if up_rc:
        assert not any(c.startswith("py_cli post-restore") for c in calls)


@needs_bash
def test_start_runs_a_pending_step_before_the_first_module(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "cmd_start --addons", real_start=True)
    assert done.returncode == 0, done.stderr
    step = _index(calls, "py_cli post-restore --since=1790000000")
    stack_up = next(
        i for i, c in enumerate(calls) if c.startswith("docker") and c.endswith(" up -d")
    )
    assert _index(calls, "py_cli image-verify") < step
    assert step < _index(calls, "addon-up flow")
    assert step < stack_up
    assert not _marker(tmp_path).exists()


@needs_bash
def test_start_starts_no_module_when_the_pending_step_fails(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "cmd_start --addons", real_start=True, post_rc=1)
    assert done.returncode == 3
    assert "addon-up flow" not in calls
    assert not any(c.startswith("docker") and c.endswith(" up -d") for c in calls)
    assert _marker(tmp_path).exists()


@needs_bash
def test_start_without_a_pending_step_is_unchanged(tmp_path):
    done, calls = _bash(tmp_path, "cmd_start --addons", real_start=True)
    assert done.returncode == 0, done.stderr
    assert not any(c.startswith("py_cli post-restore") for c in calls)
    assert not any(c.endswith("keycloak") and " up " in c for c in calls)


@needs_bash
def test_addon_start_is_refused_while_the_step_is_pending(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "cmd_addon_start flow", real_start=True)
    assert done.returncode == 2
    assert "addon-up flow" not in calls
    assert "post-restore" in done.stderr


@needs_bash
def test_post_restore_command_clears_the_pending_step(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "cmd_post_restore --since=1790000000")
    assert done.returncode == 0, done.stderr
    assert not _marker(tmp_path).exists()


@needs_bash
def test_post_restore_command_with_an_earlier_since_keeps_the_pending_step(tmp_path):
    _marker(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    _marker(tmp_path).write_text("1790000000\n")
    done, calls = _bash(tmp_path, "cmd_post_restore --since=1789999999")
    assert done.returncode == 0, done.stderr
    assert _marker(tmp_path).exists()


@needs_bash
def test_post_restore_command_passes_since_and_joins_the_stack_network(tmp_path):
    done, calls = _bash(tmp_path, "cmd_post_restore --since=1790000000")
    assert done.returncode == 0, done.stderr
    assert "py_cli join-stack-network" in calls
    assert "py_cli post-restore --since=1790000000" in calls


@needs_bash
def test_post_restore_command_without_since_lets_python_take_the_time(tmp_path):
    done, calls = _bash(tmp_path, "cmd_post_restore")
    assert done.returncode == 0, done.stderr
    assert "py_cli post-restore" in calls


@needs_bash
@pytest.mark.parametrize("arg", ["--since=abc", "--since=-1", "--since=", "--force", "extra"])
def test_post_restore_command_refuses_bad_arguments(tmp_path, arg):
    done, calls = _bash(tmp_path, f"cmd_post_restore {arg}")
    assert done.returncode == 2
    assert not any(c.startswith("py_cli post-restore") for c in calls)


@needs_bash
def test_post_restore_is_refused_in_a_distributed_installation(tmp_path):
    done, calls = _bash(tmp_path, "cmd_post_restore", mode="distributed")
    assert done.returncode == 2
    assert not any(c.startswith("py_cli post-restore") for c in calls)


def test_papaia_ctl_dispatches_and_documents_post_restore():
    text = CTL.read_text(encoding="utf-8")
    assert re.search(r"^    post-restore\)\s+cmd_post_restore", text, re.M)
    assert re.search(r"^#   papaia-ctl post-restore\s+\[--since=EPOCH\]", text, re.M)
