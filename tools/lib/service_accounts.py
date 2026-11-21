"""`papaia-ctl service-account list|rotate`: the declared service accounts.

The realm sync creates each account a module declares (`service_accounts[]`) and keeps it
to its declaration. This module shows them with their owner, rotation and last use, and
replaces an account's key pair:

    rotate: new key pair -> Keycloak accepts the new key (and, during an optional grace
    period of at most 60 s, the old one) -> the new key file replaces the old one -> only
    the new key is registered -> the run checks with Keycloak that the new key signs in
    and that the old key is refused, at the latest 60 s after the rotation began.

Owner, deputy, purpose, effects and rotation interval come from the declaration and are
recorded as attributes of the account's client; the time of the last rotation as well.
The last use is the newest CLIENT_LOGIN event Keycloak stored for the account.
"""

from __future__ import annotations

import calendar
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import keycloak_role_sync as kcs
from . import realm_sync as rs
from . import service_account_keys as sak

WRITER = "papaia-ctl/service-account"
MAX_GRACE_SECONDS = 60
# The old key must be refused at the latest this long after the rotation began.
MAX_REFUSAL_SECONDS = 60
POLL_SECONDS = 2.0


class RotationError(Exception):
    """The rotation was refused, or its result could not be confirmed."""


class _Clock:
    def time(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _account_client(call, account_id: str) -> dict:
    """The client of a declared (managed) service account, or RotationError."""
    try:
        sak.account_name(account_id)
    except ValueError:
        raise RotationError(f"{account_id!r} is not a declared service account") from None
    found = call("GET", f"/clients?clientId={urllib.parse.quote(account_id)}") or []
    attributes = (found[0].get("attributes") or {}) if found else {}
    if attributes.get(rs.MANAGED) != "true" or attributes.get(rs.KIND) != rs.SERVICE_ACCOUNT:
        raise RotationError(f"{account_id} is not a declared service account")
    return {k: v for k, v in found[0].items() if k != "secret"}


def _register(call, audit, client: dict, keys: list[dict], action: str) -> None:
    attributes = dict(client.get("attributes") or {})
    attributes["jwks.string"] = json.dumps({"keys": keys}, sort_keys=True)
    attributes[rs.ROTATED_AT] = rs._now_iso()
    change = rs.Change(
        rs.SERVICE_ACCOUNT, client["clientId"], action, "rotate_key", "service_account_rotated"
    )
    rs._Actions(call, True, audit).do(
        change, "PUT", f"/clients/{client['id']}", {"attributes": attributes}
    )
    client["attributes"] = attributes


def rotate_key(
    call,
    keys: sak.KeyStore,
    account_id: str,
    *,
    audit: rs.AuditLog | None,
    grace: int,
    try_sign_in,
    clock=None,
) -> float:
    """Replace the key pair of `account_id`; returns the seconds from the start of the
    rotation until Keycloak refused the old key. `try_sign_in(client_id, key_path, jwk)`
    tells whether Keycloak accepts a sign-in with that key."""
    if isinstance(grace, bool) or not isinstance(grace, int) or not 0 <= grace <= MAX_GRACE_SECONDS:
        raise RotationError(f"the grace period must be 0 to {MAX_GRACE_SECONDS} seconds")
    clock = clock or _Clock()
    client = _account_client(call, account_id)
    old = keys.public_jwk(account_id)
    new = keys.generate(account_id, sak.NEXT_FILE)
    started = clock.time()
    if grace and old:
        _register(
            call, audit, client, [new, old], f"new key {new['kid']} added, old key kept {grace} s"
        )
    else:
        _register(call, audit, client, [new], f"key replaced by {new['kid']}")
    if old:
        keys.move(account_id, sak.KEY_FILE, sak.OLD_FILE)
    keys.move(account_id, sak.NEXT_FILE, sak.KEY_FILE)
    try:
        if grace and old:
            clock.sleep(grace)
            _register(call, audit, client, [new], f"old key {old['kid']} removed")
        if not try_sign_in(account_id, keys.key_path(account_id), new):
            raise RotationError(f"{account_id}: Keycloak does not accept the new key")
        if old is None:
            return clock.time() - started
        old_path = keys.folder(account_id) / sak.OLD_FILE
        while True:
            elapsed = clock.time() - started
            if not try_sign_in(account_id, old_path, old):
                return elapsed
            if elapsed >= MAX_REFUSAL_SECONDS:
                raise RotationError(
                    f"{account_id}: the old key is still accepted {elapsed:.0f} s after the "
                    "rotation; check the account in the admin console"
                )
            clock.sleep(POLL_SECONDS)
    finally:
        keys.discard(account_id, sak.OLD_FILE)


def _sign_in_check(base_url: str, ctx):
    """A `try_sign_in` against Keycloak's token endpoint: a client_credentials grant
    with a client assertion signed by the key. The token is not kept."""
    token_url = f"{base_url}/realms/{kcs._REALM}/protocol/openid-connect/token"

    def try_sign_in(client_id: str, key_path: Path, jwk: dict) -> bool:
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": sak.client_assertion(key_path, jwk, client_id, token_url),
            }
        ).encode()
        req = urllib.request.Request(token_url, data=form, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                resp.read()
            return True
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401):
                return False
            raise

    return try_sign_in


def describe(call, *, now: float | None = None) -> list[dict]:
    """The declared service accounts with owner, rotation and last use (master admin's
    `call`: reading events needs view-events)."""
    now = time.time() if now is None else now
    rows = []
    for client in sorted(call("GET", "/clients") or [], key=lambda c: c["clientId"]):
        attributes = client.get("attributes") or {}
        if attributes.get(rs.MANAGED) != "true" or attributes.get(rs.KIND) != rs.SERVICE_ACCOUNT:
            continue
        client_id = client["clientId"]
        scope = call("GET", f"/clients/{client['id']}/scope-mappings") or {}
        query = urllib.parse.urlencode({"client": client_id, "type": rs.LOGIN_EVENT, "max": 1})
        events = call("GET", f"/events?{query}") or []
        days = int(attributes.get("papaia.rotation_days") or rs.ROTATION_DAYS)
        rotated = attributes.get(rs.ROTATED_AT)
        try:
            rotated_epoch = calendar.timegm(time.strptime(rotated, "%Y-%m-%dT%H:%M:%SZ"))
        except (TypeError, ValueError):
            rotated_epoch = None
        try:
            purpose = json.loads(attributes.get("papaia.purpose") or "{}")
        except ValueError:
            purpose = {}
        rows.append(
            {
                "id": client_id,
                "module": attributes.get(rs.OWNER),
                "purpose": purpose,
                "owner_sub": attributes.get("papaia.owner_sub"),
                "deputy_sub": attributes.get("papaia.deputy_sub"),
                "audiences": sorted(
                    s.removeprefix("aud-")
                    for s in client.get("optionalClientScopes") or []
                    if s.startswith("aud-")
                ),
                "roles": sorted(r["name"] for r in scope.get("realmMappings") or []),
                "effects": [e for e in (attributes.get("papaia.effects") or "").split(",") if e],
                "rotation_days": days,
                "key_rotated_at": rotated,
                "rotation_due": rotated_epoch is None or now - rotated_epoch > days * 86400,
                "last_used": rs._now_iso(events[0]["time"] / 1000) if events else None,
            }
        )
    return rows


def _connection(tree: dict, config_dir: Path):
    root = tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        raise RotationError("service accounts need the bundled Keycloak (AUTH_PROVIDER)")
    keycloak = tree.get(kcs._KEYCLOAK_NODE, {})
    admin_password = kcs._compose_value(keycloak.get("KC_ADMIN_PASSWORD", ""))
    base_url, ctx = kcs._admin_connection(root, config_dir)
    return base_url, ctx, admin_password, keycloak


def list_accounts(tree: dict, config_dir: Path, *, as_json: bool = False) -> int:
    """`papaia-ctl service-account list [--json]`; read-only."""
    try:
        base_url, ctx, admin_password, _ = _connection(tree, config_dir)
        kcs._wait_for_keycloak(base_url, ctx)
        rows = describe(rs.MasterAdmin(base_url, ctx, admin_password).call)
    except (RotationError, TimeoutError, urllib.error.URLError, OSError) as exc:
        print(f"Service accounts cannot be listed: {exc}", file=sys.stderr, flush=True)
        return 1
    if as_json:
        print(json.dumps(rows, indent=2, sort_keys=True), flush=True)
        return 0
    if not rows:
        print("No declared service accounts.", flush=True)
        return 0
    for row in rows:
        due = " (rotation due)" if row["rotation_due"] else ""
        print(
            f"{row['id']}  module {row['module']}  owner {row['owner_sub']}  "
            f"deputy {row['deputy_sub']}\n"
            f"    audiences {', '.join(row['audiences']) or '-'}  roles "
            f"{', '.join(row['roles']) or '-'}  effects {', '.join(row['effects'])}\n"
            f"    key rotated {row['key_rotated_at'] or 'never'}, every "
            f"{row['rotation_days']} days{due}  last use {row['last_used'] or 'never'}",
            flush=True,
        )
    return 0


def rotate(tree: dict, config_dir: Path, account_id: str, *, grace: int = 30) -> int:
    """`papaia-ctl service-account rotate <id> [--grace=SECONDS]`. 0: rotated and the old
    key refused within 60 s, 1: Keycloak not reachable or the result not confirmed,
    2: refused (not a declared account, bad grace period); nothing was changed then."""
    try:
        base_url, ctx, admin_password, keycloak = _connection(tree, config_dir)
    except RotationError as exc:
        print(f"Rotation refused: {exc}", file=sys.stderr, flush=True)
        return 2
    secret = kcs._compose_value(keycloak.get(rs.SYNC_SECRET_KEY, ""))
    if kcs._unset(secret) or secret.startswith("GENERATE_"):
        print(f"Rotation refused: {rs.SYNC_SECRET_KEY} is not set.", file=sys.stderr, flush=True)
        return 2
    keys = rs.keystore(config_dir)
    try:
        audit = rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        print(f"Rotation refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    try:
        with audit:
            kcs._wait_for_keycloak(base_url, ctx)
            api = rs.AdminApi(
                base_url, ctx, rs.sync_token(base_url, ctx, admin_password, secret, audit)
            )
            try:
                _account_client(api.call, account_id)
                if isinstance(grace, bool) or not 0 <= grace <= MAX_GRACE_SECONDS:
                    raise RotationError(
                        f"the grace period must be 0 to {MAX_GRACE_SECONDS} seconds"
                    )
            except RotationError as exc:
                print(f"Rotation refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
                return 2
            refused_after = rotate_key(
                api.call,
                keys,
                account_id,
                audit=audit,
                grace=grace,
                try_sign_in=_sign_in_check(base_url, ctx),
            )
    except (RotationError, rs.RealmSyncError, sak.KeyFileError) as exc:
        print(f"Rotation failed: {exc}", file=sys.stderr, flush=True)
        return 1
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        print(f"Rotation failed: {exc}", file=sys.stderr, flush=True)
        return 1
    print(
        f"{account_id}: new key in {keys.key_path(account_id)}; the old key was refused "
        f"{refused_after:.0f} s after the rotation began.",
        flush=True,
    )
    return 0
