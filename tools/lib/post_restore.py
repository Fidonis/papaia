"""`papaia-ctl post-restore`: no delegation from a restore point stays usable.

A restore point brings back the Keycloak database as it was when it was taken: the offline
sessions behind the delegations persons had granted then, including the ones they revoked
since. `restore` therefore runs this step once the stack is up again (and so does `addon
rollback --restore-data`, which restores through `restore`):

1. The realm's "not before" moves past every token issued until now (`PUT
   /admin/realms/papaia` with `notBefore`). Keycloak refuses every older access, ID and
   refresh token, offline ones included ("Stale token"), for every client. It is set one
   second past the current time, because Keycloak accepts a token whose `iat` equals it.
   It never moves back: a value already past `since` is left alone, and the realm sync
   never writes it.
2. For every person, the consents of the two holders of delegations, `flow-engine` and
   `assist-gate`, are removed when they predate `since` (`GET /users/{id}/consents`, then
   `DELETE /users/{id}/consents/{client}`); that also ends the client's offline sessions
   of the person, which a logout alone does not (Keycloak spike T7). A consent's age is
   its `createdDate`/`lastUpdatedDate`; a grant without a consent (an offline token only)
   is judged by the start of its offline sessions. A grant whose age cannot be read
   counts as old. Consents of other clients stay.

`since` is the time the restore began. A second run with the same `since` finds nothing to
do and writes nothing; a delegation granted after the restore survives it. Without
`--since` the step starts at the current second.

The step runs with the master admin, as the realm sync does for accounts: no new client,
role or scope. Every write is one `papaia.audit/1` row in the core's audit outbox with
one correlation id per run; a refused write is a row with `result: error` and stops the
run. No token or secret is read into the output.

Not here: the holders' own step (new sealing key, emptied `delegations` table, halted
triggers and runs), which belongs to each module.
"""

from __future__ import annotations

import re
import sys
import time
import urllib.error
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path

from . import keycloak_role_sync as kcs
from . import realm_sync as rs

HOLDERS = ("flow-engine", "assist-gate")
WRITER = "papaia-ctl/post-restore"
PAGE = 100
# Ten thousand pages: a realm larger than that is not what this step was measured for,
# and stopping is safer than looping on an Admin API that keeps answering full pages.
MAX_USERS = PAGE * 10_000
# `since` may lie a little ahead (clock skew between the host and the caller), not more.
MAX_SKEW = 300
OFFLINE_GRANT = "Offline Token"

_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_SINCE_RE = re.compile(r"[1-9][0-9]{0,9}")


class PostRestoreError(Exception):
    """An input or an answer of Keycloak the step cannot act on safely."""


def parse_since(raw: str | None, *, now: float) -> int:
    """The Unix time (seconds) the restore began; the current second without one."""
    if raw is None:
        return int(now)
    if not isinstance(raw, str) or not _SINCE_RE.fullmatch(raw):
        raise PostRestoreError("--since must be a Unix time in seconds")
    value = int(raw)
    if value > now + MAX_SKEW:
        raise PostRestoreError(f"--since lies more than {MAX_SKEW} s in the future")
    return value


def _valid_ms(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _account_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise PostRestoreError(f"{label}: Keycloak answered with a malformed id")
    return value


def _holders(call: Callable) -> dict[str, str]:
    """clientId -> internal id of the holders the realm has."""
    found: dict[str, str] = {}
    for client in HOLDERS:
        rows = call("GET", f"/clients?clientId={urllib.parse.quote(client, safe='')}")
        if not isinstance(rows, list):
            raise PostRestoreError(f"client {client}: Keycloak answered with no list")
        match = [r for r in rows if isinstance(r, dict) and r.get("clientId") == client]
        if not match:
            print(f"  note: client {client} does not exist; it holds no delegation", flush=True)
            continue
        found[client] = _account_id(match[0].get("id"), f"client {client}")
    return found


def _users(call: Callable) -> Iterator[str]:
    """Every account of the realm, page by page; each page is checked before it is used.
    Keycloak leaves service-account users out of this list, and they hold no delegation."""
    first = 0
    while True:
        batch = call("GET", f"/users?briefRepresentation=true&first={first}&max={PAGE}")
        if not isinstance(batch, list):
            raise PostRestoreError("the account list is not a list")
        ids = [
            _account_id(u.get("id") if isinstance(u, dict) else None, "account list") for u in batch
        ]
        yield from ids
        if len(batch) < PAGE:
            return
        first += PAGE
        if first >= MAX_USERS:
            raise PostRestoreError(f"more than {MAX_USERS} accounts; stopped")


def _old(call: Callable, uid: str, entry: dict, uuid: str, since_ms: int) -> bool:
    """Whether the grant `entry` of one holder predates the restore."""
    dates = [entry[k] for k in ("createdDate", "lastUpdatedDate") if k in entry]
    if dates and (not all(_valid_ms(d) for d in dates) or max(dates) < since_ms):
        return True
    grants = entry.get("additionalGrants") or []
    offline = isinstance(grants, list) and any(
        isinstance(g, dict) and g.get("key") == OFFLINE_GRANT for g in grants
    )
    if not offline:
        # A dated consent made after the restore; an entry with neither a date nor an
        # offline token cannot be placed in time and is removed.
        return not dates
    sessions = call("GET", f"/users/{uid}/offline-sessions/{uuid}")
    if not isinstance(sessions, list):
        raise PostRestoreError(f"offline sessions of {uid}: Keycloak answered with no list")
    for session in sessions:
        start = session.get("start") if isinstance(session, dict) else None
        if not _valid_ms(start) or start < since_ms:
            return True
    return False


def run(
    call: Callable,
    since: int,
    *,
    audit: rs.AuditLog | None,
    now: Callable[[], float] = time.time,
) -> list[rs.Change]:
    """The step against the `papaia` realm's Admin API `call` (the master admin). Returns
    the writes made; an empty list is a run that found nothing to do."""
    act = rs._Actions(call, True, audit, master=True)
    realm = call("GET", "")
    current = realm.get("notBefore", 0) if isinstance(realm, dict) else None
    if not _valid_ms(current):
        raise PostRestoreError("the realm's notBefore is not a number")
    if current <= since:
        stamp = max(int(now()), since) + 1
        act.do(
            rs.Change(
                "realm",
                kcs._REALM,
                f"not before set to {stamp}",
                "not_before",
                event="sessions_revoked",
            ),
            "PUT",
            "",
            {"notBefore": stamp},
        )

    holders = _holders(call)
    since_ms = since * 1000
    for uid in _users(call) if holders else ():
        entries = call("GET", f"/users/{uid}/consents")
        if not isinstance(entries, list):
            raise PostRestoreError(f"consents of {uid}: Keycloak answered with no list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise PostRestoreError(f"consents of {uid}: malformed entry")
            client = entry.get("clientId")
            if client not in holders or not _old(call, uid, entry, holders[client], since_ms):
                continue
            act.do(
                rs.Change(
                    "consent",
                    f"{uid}/{client}",
                    "consent removed",
                    "consent_delete",
                    event="delegation_revoked",
                    effect="delete",
                ),
                "DELETE",
                f"/users/{uid}/consents/{urllib.parse.quote(client, safe='')}",
            )
    return act.changes


def main(tree: dict, config_dir: Path, since_raw: str | None) -> int:
    """`papaia-ctl post-restore [--since=EPOCH]`. 0: done or nothing to do, 1: Keycloak
    refused or could not be reached (run it again), 2: refused input, nothing changed."""
    root = tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        print(
            "Post-restore skipped: an external identity provider holds the sessions "
            "(AUTH_PROVIDER is not internal_keycloak); revoke the delegations there.",
            flush=True,
        )
        return 0
    try:
        since = parse_since(since_raw, now=time.time())
    except PostRestoreError as exc:
        print(f"Post-restore refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    keycloak = tree.get(kcs._KEYCLOAK_NODE, {})
    admin_password = kcs._compose_value(keycloak.get("KC_ADMIN_PASSWORD", ""))
    if not admin_password or kcs._unset(admin_password):
        print(
            f"Post-restore failed: KC_ADMIN_PASSWORD is not set in {kcs._KEYCLOAK_NODE}/.env.",
            file=sys.stderr,
            flush=True,
        )
        return 1
    base_url, ctx = kcs._admin_connection(root, config_dir)
    try:
        audit = rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        print(f"Post-restore refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    try:
        with audit:
            kcs._wait_for_keycloak(base_url, ctx)
            changes = run(rs.MasterAdmin(base_url, ctx, admin_password).call, since, audit=audit)
    except (PostRestoreError, rs.RealmSyncError) as exc:
        print(f"Post-restore stopped: {exc}", file=sys.stderr, flush=True)
        return 1
    except TimeoutError as exc:
        print(f"Post-restore failed: {exc}", file=sys.stderr, flush=True)
        return 1
    except urllib.error.HTTPError as exc:
        path = urllib.parse.urlsplit(exc.url or "").path
        print(f"Post-restore failed: HTTP {exc.code} on {path}", file=sys.stderr, flush=True)
        return 1
    except OSError as exc:
        print(f"Post-restore failed: {exc}", file=sys.stderr, flush=True)
        return 1
    if not changes:
        print("Post-restore complete: nothing to do (already done for this restore).", flush=True)
        return 0
    removed = sum(1 for c in changes if c.operation == "consent_delete")
    moved = any(c.operation == "not_before" for c in changes)
    print(
        f"Post-restore complete: realm not before {'set' if moved else 'already set'}, "
        f"{removed} consent(s) of {' and '.join(HOLDERS)} removed. Delegations from the "
        "restore point are invalid; persons grant them again.",
        flush=True,
    )
    return 0
