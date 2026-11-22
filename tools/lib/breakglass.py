"""`papaia-ctl breakglass create|rotate|status`: the emergency account of the `papaia`
realm (security 1.15, OPS-20).

`create` adds the local account `breakglass` once:

- sealed: a password of 32 random characters, shown once on the terminal (`/dev/tty`)
  and nowhere else (no output stream, no log, no audit row, no file), and the required
  action `CONFIGURE_TOTP`, so the first sign-in sets up the second factor and every later
  one asks for it;
- rights to administer Keycloak (`realm-management` `realm-admin`) and the platform
  (`papaia-admin`), no role of a target system: no data rights. A realm administrator can
  give any account any role, so data rights are detected (permission report, which marks
  the account), not prevented;
- the operator address as its e-mail (`--address`).

The account is known by its id, which papaia-ctl records with the time of the last
rotation in `security/breakglass/account.json` of the configuration directory (0600),
never by a user attribute: Keycloak 26 drops attributes its user profile does not
declare, and anyone with `realm-admin` could set one. An account named `breakglass` whose
id is not the recorded one is refused by every command and never changed. A `create` that
fails after Keycloak added the account removes it again (nobody has seen its password).

The account is local, so it works while an upstream identity provider is down. Its id is
written next to the key of `svc-papaia-lifecycle`; papaia-lifecycle then turns every
sign-in of the account (Keycloak user event `LOGIN`) into the audit row
`breakglass_login` and an alert in its log. Without the `lifecycle` profile no sign-in is
seen: every command then warns, and `status` reports `monitored: false`. `status` shows
the last sign-in and flags `rotation_due` from a sign-in until the next `rotate`, which
sets a new password, shows it once and records the rotation. `create` and `rotate` are
each one `papaia.audit/1` row `breakglass_change`, without the password.
"""

from __future__ import annotations

import json
import re
import secrets
import string
import sys
import time
import urllib.parse
from pathlib import Path
from typing import TextIO

from . import realm_sync as rs
from . import service_account_keys as sak

USERNAME = "breakglass"
REQUIRED_ACTIONS = ["CONFIGURE_TOTP"]
REALM_ROLE = "papaia-admin"
MANAGEMENT_CLIENT = "realm-management"
MANAGEMENT_ROLE = "realm-admin"
# Next to the key of svc-papaia-lifecycle (same name in src/infra/lifecycle/lifecycle.py).
LIFECYCLE_ACCOUNT = "svc-papaia-lifecycle"
IDS_FILE = "breakglass-ids"
# The record of papaia-ctl: security/<RECORD_DIR>/<RECORD_FILE> of the config dir.
RECORD_DIR = "breakglass"
RECORD_FILE = "account.json"
_MAX_RECORD = 512
WRITER = "papaia-ctl/breakglass"
EVENT = "breakglass_change"
PASSWORD_LENGTH = 32
_ALPHABET = string.ascii_letters + string.digits
_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
UNMONITORED = (
    "WARNING: the 'lifecycle' profile is not active, so a sign-in of the emergency account "
    "writes no audit row and raises no alert. Activate it, then run "
    "'papaia-ctl breakglass status' once."
)


class BreakglassError(Exception):
    """The emergency account could not be created or changed; nothing secret in it."""


class _RecordStore(sak.KeyStore):
    """The folder `security/breakglass` (0700, no symbolic link) and its files (0600, of
    the user running papaia-ctl), checked like the key files of the service accounts."""

    def folder(self, account_id: str) -> Path:
        if account_id != USERNAME:
            raise ValueError(f"{account_id!r} is not the emergency account")
        return self.root


def record_store(config_dir) -> sak.KeyStore:
    """Where papaia-ctl records the emergency account of `config_dir`."""
    return _RecordStore(Path(config_dir) / "security" / RECORD_DIR)


def _load(records: sak.KeyStore) -> dict | None:
    """The record ({"id", "rotated_at"}), None when there is none."""
    try:
        raw = records.read(USERNAME, RECORD_FILE)
    except (OSError, sak.KeyFileError) as exc:
        raise BreakglassError(
            f"the record of the emergency account cannot be read: {exc}"
        ) from None
    if raw is None:
        return None
    try:
        record = json.loads(raw.decode("utf-8")) if len(raw) <= _MAX_RECORD else None
    except (UnicodeDecodeError, ValueError):
        record = None
    if (
        not isinstance(record, dict)
        or set(record) != {"id", "rotated_at"}
        or not isinstance(record["id"], str)
        or not _ID_RE.match(record["id"])
        or type(record["rotated_at"]) is not int
        or record["rotated_at"] < 0
    ):
        raise BreakglassError(
            f"the record of the emergency account ({RECORD_DIR}/{RECORD_FILE}) is malformed"
        )
    return record


def _store(records: sak.KeyStore, uid: str, rotated_at: float) -> None:
    data = json.dumps({"id": uid, "rotated_at": int(rotated_at)}, sort_keys=True) + "\n"
    try:
        records.write(USERNAME, RECORD_FILE, data.encode("ascii"))
    except (OSError, sak.KeyFileError) as exc:
        raise BreakglassError(
            f"the record of the emergency account cannot be written: {exc}"
        ) from None


def recorded_ids(records: sak.KeyStore) -> frozenset[str]:
    """The id of the emergency account papaia-ctl created, for the permission report."""
    record = _load(records)
    return frozenset() if record is None else frozenset({record["id"]})


def _password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(PASSWORD_LENGTH))


def _show(tty: TextIO, password: str, action: str) -> None:
    tty.write(
        f"\nEmergency account '{USERNAME}' {action}. Password (shown once, not stored):\n\n"
        f"    {password}\n\n"
        "Keep it in two parts with two persons, as the operating manual says.\n"
    )
    tty.flush()


def _by_name(call) -> list[dict]:
    query = urllib.parse.urlencode({"username": USERNAME, "exact": "true"})
    return [u for u in call("GET", f"/users?{query}") or [] if u.get("username") == USERNAME]


def _find(call, records: sak.KeyStore) -> tuple[dict, dict] | None:
    """The account and its record; None when there is no account of that name. An account
    of that name whose id is not the recorded one is refused."""
    record = _load(records)
    found = _by_name(call)
    if not found:
        return None
    user = found[0]
    if record is None or str(user.get("id", "")) != record["id"]:
        raise BreakglassError(
            f"an account '{USERNAME}' exists that is not the emergency account recorded by "
            "this installation; rename or remove it in Keycloak first"
        )
    return user, record


def _ids_file(keys: sak.KeyStore, user_id: str) -> bool:
    """Tell papaia-lifecycle the account's id, while its profile (its folder) exists.
    False, with a warning, when the profile is off and no sign-in would be seen."""
    try:
        if keys.read(LIFECYCLE_ACCOUNT, "persons-group") is None:
            print(UNMONITORED, file=sys.stderr, flush=True)
            return False
        data = f"{user_id}\n".encode("ascii")
        if keys.read(LIFECYCLE_ACCOUNT, IDS_FILE) != data:
            keys.write(LIFECYCLE_ACCOUNT, IDS_FILE, data)
    except (OSError, sak.KeyFileError) as exc:
        raise BreakglassError(
            f"the id file for papaia-lifecycle cannot be written: {exc}"
        ) from None
    return True


def _discard(call) -> None:
    """Remove the account a failed `create` left behind. Before the create no account of
    that name existed, so the one found now is the new one, whose password nobody saw."""
    try:
        for user in _by_name(call):
            uid = str(user.get("id", ""))
            if _ID_RE.match(uid):
                call("DELETE", f"/users/{uid}")
    except Exception as exc:  # noqa: BLE001 - the original failure is raised by the caller
        print(
            f"WARNING: the half-created account '{USERNAME}' could not be removed "
            f"({type(exc).__name__}); remove it in Keycloak before the next create.",
            file=sys.stderr,
            flush=True,
        )


def _change(action: str, operation: str) -> rs.Change:
    return rs.Change("user", USERNAME, action, operation, EVENT)


def create(
    call, audit, tty: TextIO, keys: sak.KeyStore, *, records: sak.KeyStore, address: str,
    now=None,
) -> str:
    """Create the account; BreakglassError when it exists. Returns its id."""
    if not isinstance(address, str) or len(address) > 254 or not _ADDRESS_RE.match(address):
        raise BreakglassError("--address must be the operator's e-mail address")
    if _find(call, records) is not None:
        raise BreakglassError(
            "the emergency account exists; use 'papaia-ctl breakglass rotate' for a new password"
        )
    now = time.time() if now is None else now
    password = _password()
    change = _change("emergency account created (second factor at first sign-in)", "created")
    posted = False
    try:
        call(
            "POST",
            "/users",
            {
                "username": USERNAME,
                "enabled": True,
                "email": address,
                "emailVerified": True,
                "firstName": "Notfall",
                "lastName": "Konto",
                "requiredActions": list(REQUIRED_ACTIONS),
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        # Only an account this POST added is removed again on a failure below.
        posted = True
        found = _by_name(call)
        if len(found) != 1 or not _ID_RE.match(str(found[0].get("id", ""))):
            raise BreakglassError("the emergency account was not created")
        uid = str(found[0]["id"])
        call("POST", f"/users/{uid}/role-mappings/realm", [call("GET", f"/roles/{REALM_ROLE}")])
        query = urllib.parse.urlencode({"clientId": MANAGEMENT_CLIENT})
        (management,) = call("GET", f"/clients?{query}")
        role = call("GET", f"/clients/{management['id']}/roles/{MANAGEMENT_ROLE}")
        call("POST", f"/users/{uid}/role-mappings/clients/{management['id']}", [role])
        _store(records, uid, now)
    except Exception:
        if posted:
            _discard(call)
        audit.write(change, "error", "keycloak", master=True)
        raise
    audit.write(change, "allowed", master=True)
    _show(tty, password, "created")
    _ids_file(keys, uid)
    return uid


def rotate(
    call, audit, tty: TextIO, keys: sak.KeyStore, *, records: sak.KeyStore, now=None
) -> None:
    """A new password, shown once; the time of the rotation is recorded by papaia-ctl.
    Only the password is reset: the account itself is not written."""
    found = _find(call, records)
    if found is None:
        raise BreakglassError("there is no emergency account; run 'papaia-ctl breakglass create'")
    uid = found[0]["id"]
    now = time.time() if now is None else now
    password = _password()
    change = _change("emergency account password rotated", "rotated")
    try:
        call("PUT", f"/users/{uid}/reset-password",
             {"type": "password", "value": password, "temporary": False})
    except Exception:
        audit.write(change, "error", "keycloak", master=True)
        raise
    audit.write(change, "allowed", master=True)
    # The new password is in force: show it even if the rotation time cannot be recorded.
    _show(tty, password, "rotated")
    _ids_file(keys, uid)
    try:
        _store(records, uid, now)
    except BreakglassError as exc:
        raise BreakglassError(
            f"the new password is set and was shown, but {exc}; run 'rotate' again"
        ) from None


def status(call, keys: sak.KeyStore, *, records: sak.KeyStore) -> dict:
    """Whether the account exists and is monitored, its second factor, last rotation and
    last sign-in; `rotation_due` from a sign-in after the last rotation until the next one."""
    found = _find(call, records)
    if found is None:
        try:
            monitored = keys.read(LIFECYCLE_ACCOUNT, "persons-group") is not None
        except (OSError, sak.KeyFileError):
            monitored = False
        if not monitored:
            print(UNMONITORED, file=sys.stderr, flush=True)
        return {"present": False, "monitored": monitored}
    user, record = found
    uid = user["id"]
    monitored = _ids_file(keys, uid)
    types = {c.get("type") for c in call("GET", f"/users/{uid}/credentials") or []}
    query = urllib.parse.urlencode({"user": uid, "type": "LOGIN", "max": 1})
    logins = call("GET", f"/events?{query}") or []
    last_login = logins[0]["time"] / 1000 if logins else None
    rotated = record["rotated_at"]
    return {
        "present": True,
        "enabled": user.get("enabled") is True,
        "monitored": monitored,
        "second_factor": "otp" in types or "webauthn" in types,
        "second_factor_pending": "CONFIGURE_TOTP" in (user.get("requiredActions") or []),
        "rotated_at": rs._now_iso(rotated) if rotated else None,
        "last_login": rs._now_iso(last_login) if last_login else None,
        "rotation_due": last_login is not None and last_login > rotated,
    }


def open_tty() -> TextIO:
    """The terminal for the password; BreakglassError without one (nothing created)."""
    try:
        return open("/dev/tty", "w", encoding="utf-8")  # noqa: SIM115 - closed by the caller
    except OSError:
        raise BreakglassError(
            "no terminal: the password is shown on the terminal only; run the command "
            "interactively"
        ) from None


def main(action: str, tree: dict, config_dir, *, address: str | None = None) -> int:
    """The shell command; 0 done, 1 Keycloak not reachable, 2 refused."""
    from . import keycloak_role_sync as kcs
    from . import service_accounts

    try:
        base_url, ctx, admin_password, _ = service_accounts._connection(tree, config_dir)
    except service_accounts.RotationError as exc:
        print(f"Refused: {exc}", file=sys.stderr, flush=True)
        return 2
    keys, records = rs.keystore(config_dir), record_store(config_dir)
    try:
        kcs._wait_for_keycloak(base_url, ctx)
        call = rs.MasterAdmin(base_url, ctx, admin_password).call
        if action == "status":
            print(json.dumps(status(call, keys, records=records), indent=2, sort_keys=True),
                  flush=True)
            return 0
        tty = open_tty()
        with tty, rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(),
                              writer=WRITER) as audit:
            if action == "create":
                create(call, audit, tty, keys, records=records, address=address or "")
            else:
                rotate(call, audit, tty, keys, records=records)
    except BreakglassError as exc:
        print(f"Refused: {exc}", file=sys.stderr, flush=True)
        return 2
    except (TimeoutError, OSError, rs.RealmSyncError) as exc:
        print(f"Keycloak not reachable: {type(exc).__name__}", file=sys.stderr, flush=True)
        return 1
    if action != "status":
        print("Done. 'papaia-ctl breakglass status' shows the account.", flush=True)
    return 0
