"""Installation settings: contact point, brand and the four-eyes rule (`papaia-ctl settings`).

The settings are kept in the operator overlay next to the configuration and published in
the platform catalog (`platform/services.json`), which every module reads:

| Key                   | Overlay file                         | Catalog field              |
|-----------------------|--------------------------------------|----------------------------|
| `branding.name`       | `overlay/platform/branding.yaml`     | `branding.name`            |
| `branding.suffix`     | `overlay/platform/branding.yaml`     | `branding.suffix`          |
| `branding.logo`       | `overlay/platform/brand-logo`        | `branding.logo_sha256`     |
| `contact.name`, `.mail`, `.phone` | `overlay/platform/branding.yaml` | `branding.contact` |
| `approvals.four_eyes` | `overlay/platform/approvals.yaml`    | `approvals.four_eyes`      |

`approvals.four_eyes` is the only four-eyes setting of the platform (E-18): `on` means an
approval needs a second person, `off` lets the submitter approve with the audit flag
`selbstfreigabe`. The default is `off`; in security profile `kritis` it is always `on`,
and switching it off is refused. The setting decides approvals of the modules only; it
never applies to the resolution of pseudonyms, the deletion lock or write pairings of
data class `vertraulich`, which always need a second person.

Every value is checked before anything is written. A change is written atomically,
leaves one `papaia.audit/1` row and renders the catalog at once; setting a value that is
already in effect is no change and writes nothing. A change of `approvals.four_eyes` is
the event `four_eyes_changed` with the old and the new value, a refused change in profile
`kritis` is stored with result `denied`; there, setting `on` rewrites a stored `off` (left
from before the profile changed). An unknown security profile stops every command, since
the rule depends on it. Read, change and write run under a lock (`LOCK_FILE`). The rows
name the setting, never its value (besides the four-eyes values). papaia-ctl acts as the
host account (`sub` `host:<account>`); whoever may run it on the host may change the
settings.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import catalog, common, exposes, schema_check
from . import realm_sync as rs

WRITER = "papaia-ctl/settings"
APPROVALS_OVERLAY = catalog.APPROVALS_OVERLAY
# Held around read, change and write of the overlay, so that two writers at once (the
# manager and a shell) cannot lose a change.
LOCK_FILE = "overlay/platform/.settings.lock"

BRANDING_KEYS = ("branding.name", "branding.suffix")
CONTACT_KEYS = ("contact.name", "contact.mail", "contact.phone")
LOGO_KEY = "branding.logo"
FOUR_EYES_KEY = "approvals.four_eyes"
KEYS = (*BRANDING_KEYS, LOGO_KEY, *CONTACT_KEYS, FOUR_EYES_KEY)
UNSET_KEYS = (*BRANDING_KEYS, LOGO_KEY, "contact", "contact.mail", "contact.phone")

# Limits of the Branding definition of platform-services.v1.
LENGTHS = {"branding.name": 60, "branding.suffix": 60, "contact.name": 120}
MAIL_MAX = 254
MAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
PHONE_RE = re.compile(r"\+?[0-9 ()/-]{3,40}")
# A refused change of the four-eyes rule (the value asked for is not allowed here).
REFUSED_CODE = "PK-INPUT-001"


class SettingsError(Exception):
    """The request is invalid; nothing was changed (exit 2)."""


class RefusedError(SettingsError):
    """The request is well formed but not allowed here; it was audited (exit 1)."""


@dataclass(frozen=True)
class Outcome:
    changed: bool
    # True/False: the catalog was (not) rewritten; None: the installation has no catalog.
    catalog_written: bool | None = None


# ─────────────────────────────────────────────────────────────────────────
# reading
# ─────────────────────────────────────────────────────────────────────────


def _profile(config_dir: Path) -> str:
    """The security profile; SettingsError for an unknown one (nothing is shown or changed
    from a profile that cannot be read)."""
    try:
        return catalog.profile_name(common.parse_env_file(config_dir / ".env"))
    except catalog.CatalogError as exc:
        raise SettingsError(f"{exc}; fix the root .env first") from None


def show(config_dir: Path) -> dict:
    """The settings in effect, as the catalog publishes them."""
    try:
        branding = catalog.current_branding(config_dir)
        stored = catalog.stored_four_eyes(config_dir)
    except catalog.CatalogError as exc:
        raise SettingsError(str(exc)) from None
    profile = _profile(config_dir)
    contact = branding.pop("contact", None)
    return {
        "security_profile": profile,
        "branding": branding,
        "contact": contact,
        "approvals": {
            "four_eyes": catalog.four_eyes_in_effect(profile, stored),
            "fixed": profile == catalog.FOUR_EYES_FIXED_PROFILE,
        },
    }


def format_table(shown: dict) -> str:
    branding, contact = shown["branding"], shown["contact"] or {}
    four_eyes = shown["approvals"]["four_eyes"]
    if shown["approvals"]["fixed"]:
        four_eyes += f" (fixed by security profile {shown['security_profile']})"
    rows = [
        ("security_profile", shown["security_profile"]),
        ("branding.name", branding["name"]),
        ("branding.suffix", branding.get("suffix", "not set")),
        ("branding.logo", f"sha256:{branding['logo_sha256']}" if "logo_sha256" in branding
         else "not set"),
        ("contact", "not set" if not contact else contact["name"]),
        ("contact.mail", contact.get("mail", "not set")),
        ("contact.phone", contact.get("phone", "not set")),
        (FOUR_EYES_KEY, four_eyes),
    ]
    width = max(len(key) for key, _ in rows)
    return "\n".join(f"{key.ljust(width)}  {value}" for key, value in rows)


# ─────────────────────────────────────────────────────────────────────────
# checks
# ─────────────────────────────────────────────────────────────────────────


def _text(key: str, value: str) -> str:
    limit = LENGTHS[key]
    if not 1 <= len(value) <= limit:
        raise SettingsError(f"{key} must be 1 to {limit} characters long")
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise SettingsError(f"{key} must not contain a control character")
    if value != value.strip():
        raise SettingsError(f"{key} must not start or end with a space")
    return value


def _check(key: str, value: str) -> str:
    if type(value) is not str:
        raise SettingsError(f"{key}: the value must be a text")
    if key in LENGTHS:
        return _text(key, value)
    if key == "contact.mail":
        if len(value) > MAIL_MAX or not MAIL_RE.fullmatch(value):
            raise SettingsError("contact.mail must be a mail address such as it@example.org")
        return value
    if key == "contact.phone":
        if not PHONE_RE.fullmatch(value):
            raise SettingsError(
                "contact.phone must be a phone number of 3 to 40 digits, spaces and ()/-, "
                "optionally starting with +"
            )
        return value
    if key == FOUR_EYES_KEY:
        if value not in catalog.FOUR_EYES_VALUES:
            raise SettingsError(f"{FOUR_EYES_KEY} must be on or off")
        return value
    raise SettingsError(f"unknown setting {key!r}; known: {', '.join(KEYS)}")


def _read_logo(raw: str) -> bytes:
    path = Path(raw)
    try:
        if not path.is_file():
            raise OSError
        with path.open("rb") as fh:
            data = fh.read(catalog.MAX_BYTES + 1)
    except OSError:
        raise SettingsError(f"{LOGO_KEY}: {raw} is not a readable file") from None
    problem = catalog.logo_problem(data)
    if problem is not None:
        raise SettingsError(f"{LOGO_KEY}: {problem}")
    return data


def _check_branding(overlay: dict) -> None:
    """The whole overlay against the kit schema, as the catalog render checks it."""
    try:
        schema_check.validate(
            {"name": catalog.DEFAULT_BRAND_NAME, **overlay},
            exposes.load_schema(exposes.SERVICES_SCHEMA),
            "#/$defs/Branding",
        )
    except schema_check.SchemaError as exc:
        raise SettingsError(f"branding: {exc}") from None


# ─────────────────────────────────────────────────────────────────────────
# writing
# ─────────────────────────────────────────────────────────────────────────


@contextlib.contextmanager
def _locked(config_dir: Path):
    path = config_dir / LOCK_FILE
    common.ensure_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write(path: Path, data: bytes) -> None:
    common.ensure_dir(path.parent)
    catalog._write(path, data)


def _remove(path: Path) -> None:
    path.unlink(missing_ok=True)


def _audit_log(config_dir: Path) -> rs.AuditLog:
    try:
        return rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        raise SettingsError(f"the audit outbox cannot be written: {exc}") from None


def _apply(config_dir: Path, change: rs.Change, write, detail: dict | None = None) -> None:
    """Write one change with its audit row; the outbox is opened (and checked) first."""
    with _audit_log(config_dir) as audit:
        try:
            write()
        except OSError:
            audit.write(change, "error", "io", host=True, detail=detail)
            raise
        audit.write(change, "allowed", host=True, detail=detail)


def _render(config_dir: Path, repo_root: Path) -> bool | None:
    """Render the catalog after a change; None when the installation has none yet."""
    written = catalog.render(config_dir, repo_root)
    if catalog.skip_reason(config_dir, repo_root) is not None:
        return None
    return written


def _branding_yaml(overlay: dict) -> bytes:
    return yaml.safe_dump(overlay, allow_unicode=True, sort_keys=False).encode("utf-8")


def _store_branding(config_dir: Path, key: str, overlay: dict, effect: str) -> None:
    path = config_dir / catalog.BRANDING_OVERLAY
    action = "removed" if effect == "delete" else "written"
    change = rs.Change(
        "setting", key, f"{key} {action}",
        "branding_delete" if effect == "delete" else "branding_write", effect=effect,
    )
    if overlay:
        _apply(config_dir, change, lambda: _write(path, _branding_yaml(overlay)))
    else:
        _apply(config_dir, change, lambda: _remove(path))


def _overlay(config_dir: Path) -> dict:
    try:
        return dict(catalog.branding_overlay(config_dir))
    except catalog.CatalogError as exc:
        raise SettingsError(f"{exc}; fix or remove the file first") from None


def _set_four_eyes(config_dir: Path, value: str) -> bool:
    try:
        stored = catalog.stored_four_eyes(config_dir)
    except catalog.CatalogError as exc:
        raise SettingsError(f"{exc}; fix or remove the file first") from None
    profile = _profile(config_dir)
    old = catalog.four_eyes_in_effect(profile, stored)
    detail = {"four_eyes_old": old, "four_eyes_new": value}
    change = rs.Change(
        "setting", FOUR_EYES_KEY, f"four eyes {value}", "four_eyes_set",
        event="four_eyes_changed",
    )
    if profile == catalog.FOUR_EYES_FIXED_PROFILE and value != "on":
        with _audit_log(config_dir) as audit:
            audit.write(change, "denied", REFUSED_CODE, host=True, detail=detail)
        raise RefusedError(
            f"{FOUR_EYES_KEY} stays on: security profile {profile} does not allow switching "
            "the four-eyes rule off"
        )
    if value == old:
        if stored is None or stored == value:
            return False
        # Only in kritis: `on` is in effect, but the file still says off (written before
        # the profile changed). Rewriting it is the remedy doctor names; the row carries
        # the stored value as the old one.
        detail = {"four_eyes_old": stored, "four_eyes_new": value}
    path = config_dir / APPROVALS_OVERLAY
    data = f'four_eyes: "{value}"\n'.encode("ascii")
    _apply(config_dir, change, lambda: _write(path, data), detail)
    return True


def set_value(config_dir: Path, repo_root: Path, key: str, value: str) -> Outcome:
    """Set one setting. Raises SettingsError for an invalid key or value and RefusedError
    for a change the security profile does not allow; catalog.CatalogError when the
    setting was stored but the catalog could not be rendered."""
    with _locked(config_dir):
        return _set_locked(config_dir, repo_root, key, value)


def _set_locked(config_dir: Path, repo_root: Path, key: str, value: str) -> Outcome:
    if key == LOGO_KEY:
        data = _read_logo(value)
        path = config_dir / catalog.LOGO_OVERLAY
        if path.is_file() and path.read_bytes() == data:
            return Outcome(False)
        change = rs.Change("setting", key, f"{key} written", "branding_write")
        _apply(config_dir, change, lambda: _write(path, data))
        return Outcome(True, _render(config_dir, repo_root))
    value = _check(key, value)
    if key == FOUR_EYES_KEY:
        if not _set_four_eyes(config_dir, value):
            return Outcome(False)
        return Outcome(True, _render(config_dir, repo_root))
    overlay = _overlay(config_dir)
    if key in BRANDING_KEYS:
        field = key.split(".", 1)[1]
        if overlay.get(field) == value:
            return Outcome(False)
        overlay[field] = value
    else:
        field = key.split(".", 1)[1]
        contact = dict(overlay.get("contact") or {})
        if field != "name" and "name" not in contact:
            raise SettingsError(f"set contact.name first; {key} belongs to a named contact")
        if contact.get(field) == value:
            return Outcome(False)
        contact[field] = value
        overlay["contact"] = contact
    _check_branding(overlay)
    _store_branding(config_dir, key, overlay, "write")
    return Outcome(True, _render(config_dir, repo_root))


def unset(config_dir: Path, repo_root: Path, key: str) -> Outcome:
    """Remove one setting: the product name, no suffix, no logo, no contact point."""
    with _locked(config_dir):
        return _unset_locked(config_dir, repo_root, key)


def _unset_locked(config_dir: Path, repo_root: Path, key: str) -> Outcome:
    if key == FOUR_EYES_KEY:
        raise SettingsError(f"{FOUR_EYES_KEY} cannot be unset; set it to on or off")
    if key == "contact.name":
        raise SettingsError("contact.name cannot be unset alone; unset contact instead")
    if key not in UNSET_KEYS:
        raise SettingsError(f"unknown setting {key!r}; can be unset: {', '.join(UNSET_KEYS)}")
    if key == LOGO_KEY:
        path = config_dir / catalog.LOGO_OVERLAY
        if not (path.exists() or path.is_symlink()):
            return Outcome(False)
        change = rs.Change("setting", key, f"{key} removed", "branding_delete", effect="delete")
        _apply(config_dir, change, lambda: _remove(path))
        return Outcome(True, _render(config_dir, repo_root))
    overlay = _overlay(config_dir)
    if key == "contact":
        if "contact" not in overlay:
            return Outcome(False)
        del overlay["contact"]
    elif key in BRANDING_KEYS:
        field = key.split(".", 1)[1]
        if field not in overlay:
            return Outcome(False)
        del overlay[field]
    else:
        field = key.split(".", 1)[1]
        contact = dict(overlay.get("contact") or {})
        if field not in contact:
            return Outcome(False)
        del contact[field]
        overlay["contact"] = contact
    _check_branding(overlay)
    _store_branding(config_dir, key, overlay, "delete")
    return Outcome(True, _render(config_dir, repo_root))
