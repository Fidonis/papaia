"""`papaia-ctl delegations lifetime`: how long a delegation (an offline session of Flow or
the assistant) lives in this installation.

Two settings, `delegations.idle_days` (days without use) and `delegations.max_days` (days
since the grant, however often it is used):

- profile `standard`: default 90 / 180 days; each may be set from 1 to 365 days;
- profile `kritis`: default 7 / 30 days, which are also the upper bound;
- in both, idle days are never more than the maximum age.

The administration sets them on the host; they are kept in

    $PAPAIA_CONFIG_DIR/settings/delegations.json
        = {"format": "papaia.delegation-lifetime/1", "idle_days": N, "max_days": M}

and nowhere else. Without the file the profile's defaults apply. The rendered realm and
`realm sync` write the values in effect as Offline Session Idle / Max of the realm (the
maximum always switched on, realm_hardening), the platform catalog publishes them as
`delegations {idle_days, max_days}` so holders and the personal area compute expiry dates
from them, and the permission report shows them (`report`).

The bound of the profile holds on every path: a value above it is refused by the command,
and a stored value above it (for example one set before the profile changed to `kritis`)
stops the render, the realm sync and the catalog until a value within the bound is set.
The command takes such a value (the stored values are the old ones of its audit row), and
shows the stored values marked as out of bound (`within_bound: false`, exit status 1). A
settings file that is not the documented document is never taken for anything: the
command neither shows nor replaces it.

Every change is one `papaia.audit/1` row `delegation_lifetime_changed` with the values
before and after; a refused change is a row with `result: denied`, `PK-INPUT-001` and no
values, since the value asked for may lie outside what the row can hold. The row of an
allowed change is written before the file; when the file cannot be written, a second row
with the same correlation id says so (`result: error`, `io`).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import common
from .keycloak_role_sync import _compose_value

# realm_sync is imported where it is used: it imports realm_hardening, which imports this.

PROFILE_KEY = "PAPAIA_SECURITY_PROFILE"
SETTINGS_DIR = "settings"
SETTINGS_FILE = "delegations.json"
FORMAT = "papaia.delegation-lifetime/1"
WRITER = "papaia-ctl/delegations"
EVENT = "delegation_lifetime_changed"
INPUT_REFUSED = "PK-INPUT-001"
# (idle, max) in days per security profile.
DEFAULTS = {"standard": (90, 180), "kritis": (7, 30)}
UPPER = {"standard": (365, 365), "kritis": (7, 30)}
_FIELDS = ("format", "idle_days", "max_days")
MAX_FILE_BYTES = 4096
# More digits than any accepted value has: refused before int() reads them.
_MAX_DIGITS = 3


class LifetimeError(ValueError):
    """A value, a profile or a stored setting that cannot be used; nothing was changed."""


class SettingError(LifetimeError):
    """The settings file or the security profile cannot be read as documented; nothing is
    shown or changed from it."""


@dataclass(frozen=True)
class Lifetime:
    idle_days: int
    max_days: int
    # "default": the profile's default; "setting": set by the administration.
    source: str = "default"


def settings_path(config_dir: Path) -> Path:
    return config_dir / SETTINGS_DIR / SETTINGS_FILE


def profile_of(env: dict) -> str:
    profile = _compose_value(str(env.get(PROFILE_KEY) or "")).strip() or "standard"
    if profile not in DEFAULTS:
        raise SettingError(f"{PROFILE_KEY}={profile!r}: must be standard or kritis")
    return profile


def _root_env(config_dir: Path) -> dict:
    return common.parse_env_file(config_dir / ".env")


def check(profile: str, idle_days: object, max_days: object) -> None:
    """LifetimeError unless both are whole numbers of days within the profile's bound and
    the idle days are not more than the maximum age."""
    if profile not in UPPER:
        raise LifetimeError(f"{PROFILE_KEY}={profile!r}: must be standard or kritis")
    idle_limit, max_limit = UPPER[profile]
    for name, value, limit in (
        ("idle_days", idle_days, idle_limit),
        ("max_days", max_days, max_limit),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise LifetimeError(f"delegations.{name}: must be a whole number of days")
        if not 1 <= value <= limit:
            raise LifetimeError(
                f"delegations.{name}: must be 1 to {limit} days in security profile {profile}"
            )
    assert isinstance(idle_days, int) and isinstance(max_days, int)
    if idle_days > max_days:
        raise LifetimeError("delegations.idle_days: greater than delegations.max_days")


def stored(config_dir: Path) -> tuple[int, int] | None:
    """The values the administration set, or None when nothing was set. SettingError for
    a file that is not exactly the documented document within the widest bound (a broken
    setting is never taken for the default). The bound of the profile is not checked here
    (`resolve`)."""
    path = settings_path(config_dir)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SettingError(f"{path}: cannot be read ({exc.strerror})") from None
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    where = str(path)
    if len(data) > MAX_FILE_BYTES:
        raise SettingError(f"{where}: larger than expected")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SettingError(f"{where}: not JSON") from None
    if not isinstance(doc, dict) or set(doc) != set(_FIELDS) or doc["format"] != FORMAT:
        raise SettingError(f"{where}: not a {FORMAT} document")
    idle, age = doc["idle_days"], doc["max_days"]
    try:
        check("standard", idle, age)
    except LifetimeError as exc:
        raise SettingError(f"{where}: {exc}") from None
    return idle, age


def resolve(profile: str, values: tuple[int, int] | None) -> Lifetime:
    """The lifetime in effect: the stored values within the profile's bound, or the
    profile's default."""
    if profile not in DEFAULTS:
        raise LifetimeError(f"{PROFILE_KEY}={profile!r}: must be standard or kritis")
    if values is None:
        return Lifetime(*DEFAULTS[profile], "default")
    check(profile, *values)
    return Lifetime(values[0], values[1], "setting")


def effective(config_dir: Path, env: dict | None = None) -> Lifetime:
    """The lifetime in effect for the installation at `config_dir`; `env` is its root
    .env (read from the directory when not given)."""
    env = _root_env(config_dir) if env is None else env
    return resolve(profile_of(env), stored(config_dir))


def _current(profile: str, values: tuple[int, int] | None) -> tuple[Lifetime, bool]:
    """The stored values (or the profile's default) and whether they lie within the
    profile's bound; never raises for a well-formed value above the bound."""
    try:
        return resolve(profile, values), True
    except LifetimeError:
        assert values is not None  # the defaults always lie within the bound
        return Lifetime(values[0], values[1], "setting"), False


def report(config_dir: Path, env: dict | None = None) -> dict:
    """The values for the permission report (security 1.16): the ones in effect, or the
    stored ones with `within_bound: false` when they lie above the profile's bound (then
    none are in effect and render, catalog and realm sync stop). SettingError for a
    settings file or a profile that cannot be read."""
    env = _root_env(config_dir) if env is None else env
    profile = profile_of(env)
    lifetime, within = _current(profile, stored(config_dir))
    idle_limit, max_limit = UPPER[profile]
    return {
        "security_profile": profile,
        "idle_days": lifetime.idle_days,
        "max_days": lifetime.max_days,
        "source": lifetime.source,
        "within_bound": within,
        "upper_bound": {"idle_days": idle_limit, "max_days": max_limit},
    }


def catalog_block(config_dir: Path, env: dict) -> dict:
    """The catalog's `delegations` block: both values, always."""
    lifetime = effective(config_dir, env)
    return {"idle_days": lifetime.idle_days, "max_days": lifetime.max_days}


# ─────────────────────────────────────────────────────────────────────────
# the change
# ─────────────────────────────────────────────────────────────────────────


def parse_days(name: str, raw: str | None) -> int | None:
    """A command-line value: None when not given, else a whole number of days."""
    if raw is None:
        return None
    text = raw.strip()
    if not text.isascii() or not text.isdigit() or len(text) > _MAX_DIGITS:
        raise LifetimeError(f"--{name}: must be a whole number of days from 1 to 365")
    return int(text)


def _write(config_dir: Path, idle: int, age: int) -> None:
    folder = config_dir / SETTINGS_DIR
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    doc = {"format": FORMAT, "idle_days": idle, "max_days": age}
    data = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".delegations.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, folder / SETTINGS_FILE)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _change():
    from . import realm_sync as rs

    return rs.Change("setting", "delegations", "set_lifetime", "set_lifetime", event=EVENT)


def change(
    config_dir: Path, idle_raw: str | None, max_raw: str | None
) -> tuple[bool, Lifetime, Lifetime]:
    """Set the lifetime; a value left out keeps the stored one (or the default). Returns
    (changed, old, new). LifetimeError for a refused value (audited, nothing changed). A
    stored value above the profile's bound is replaced by new values within it; a settings
    file that cannot be read raises SettingError before anything is audited, as no change
    was asked for that could be judged."""
    from . import realm_sync as rs

    env = _root_env(config_dir)
    profile = profile_of(env)
    old, within = _current(profile, stored(config_dir))
    with rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER) as audit:
        try:
            idle = parse_days("idle-days", idle_raw)
            age = parse_days("max-days", max_raw)
            idle = old.idle_days if idle is None else idle
            age = old.max_days if age is None else age
            check(profile, idle, age)
        except LifetimeError:
            audit.write(_change(), "denied", INPUT_REFUSED, host=True)
            raise
        new = Lifetime(idle, age, "setting")
        if within and (idle, age) == (old.idle_days, old.max_days):
            return False, old, old
        # The row first: a change that took effect is never missing from the audit.
        audit.write(
            _change(),
            "allowed",
            host=True,
            detail={
                "idle_days_old": old.idle_days,
                "idle_days_new": idle,
                "max_days_old": old.max_days,
                "max_days_new": age,
            },
        )
        try:
            _write(config_dir, idle, age)
        except OSError:
            audit.write(_change(), "error", "io", host=True)
            raise
    return True, old, new


def _show(config_dir: Path, as_json: bool) -> int:
    values = report(config_dir)
    bound = values["upper_bound"]
    if as_json:
        print(json.dumps(values, sort_keys=True), flush=True)
    else:
        print(
            f"Delegation lifetime: {values['idle_days']} days without use, at most "
            f"{values['max_days']} days in all ({values['source']}; security profile "
            f"{values['security_profile']}, upper bound {bound['idle_days']} / "
            f"{bound['max_days']} days).",
            flush=True,
        )
    if values["within_bound"]:
        return 0
    print(
        f"Delegation lifetime: the stored values are above the upper bound of security "
        f"profile {values['security_profile']} and are not used; render, catalog and realm "
        f"sync stop until values within {bound['idle_days']} / {bound['max_days']} days are "
        "set with --idle-days=N --max-days=N.",
        file=sys.stderr,
    )
    return 1


def main(
    config_dir: Path,
    idle_raw: str | None,
    max_raw: str | None,
    *,
    show: bool = False,
    as_json: bool = False,
) -> int:
    """0: shown, set or unchanged; 1: the stored setting, the audit log or the file
    cannot be used, or the stored values shown lie above the profile's bound; 2: refused
    input, nothing changed."""
    from . import realm_sync as rs

    try:
        if show:
            if idle_raw is not None or max_raw is not None:
                raise LifetimeError("show the values or set them, not both")
            return _show(config_dir, as_json)
        if idle_raw is None and max_raw is None:
            raise LifetimeError("give --idle-days=N, --max-days=N or both")
        changed, old, new = change(config_dir, idle_raw, max_raw)
    except SettingError as exc:
        print(
            f"Delegation lifetime: the stored setting cannot be used: {exc}. Nothing was "
            "changed.",
            file=sys.stderr,
            flush=True,
        )
        return 1
    except LifetimeError as exc:
        print(f"Delegation lifetime refused: {exc}. Nothing was changed.", file=sys.stderr)
        return 2
    except (rs.RealmSyncError, OSError) as exc:
        print(f"Delegation lifetime failed: {exc}.", file=sys.stderr, flush=True)
        return 1
    if not changed:
        print(
            f"Delegation lifetime unchanged: {new.idle_days} days without use, at most "
            f"{new.max_days} days in all."
        )
        return 0
    print(
        f"Delegation lifetime set: {new.idle_days} days without use (was {old.idle_days}), "
        f"at most {new.max_days} days in all (was {old.max_days}). The realm takes it with "
        "the next realm sync; a shorter value applies to existing delegations at their next "
        "renewal."
    )
    return 0
