"""Exchange-right pairings at installation and their approval (security 1.4).

A pairing is (module client, audience, effects); `$PAPAIA_CONFIG_DIR/security/pairings.yaml`
holds the confirmed ones and those waiting for approval, and the realm sync assigns only
the confirmed ones. This module is the only writer of that file:

- `setup` shows every pairing of the signed bill of materials of the checkout (section
  `pairings`) with the sha256 of the list. Confirming exactly that list (interactively, or
  with `--approve-pairings=<sha256>`; `-y` never confirms) confirms the read pairings, and
  records every write pairing (effect `w` or `d`) as waiting for approval, requested by
  the host account that confirmed. Pairings already in the file are left as they are.
- `papaia-ctl pairing approve` confirms a read pairing, or records a new write pairing as
  waiting; a waiting write pairing is confirmed only by another host account than the one
  that requested it. The same person is refused, whatever the four-eyes setting says.
- `papaia-ctl pairing revoke` removes a pairing.

The acting person is the host account that runs papaia-ctl (`host:<login>`; under `sudo`,
the login that called it): on the host, running papaia-ctl is the `papaia-admin` role of
the installation. Every change and every refused attempt is one `papaia.audit/1` row,
event `exchange_right_changed`, in the core's audit outbox; a change takes effect with the
next realm sync (`start` runs it).
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pwd
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import images
from . import realm_sync as rs

WRITER = "papaia-ctl/pairing"
EVENT = "exchange_right_changed"
LIST_FORMAT = "papaia.pairing-list/1"
LOCK_FILE = ".pairings.lock"

_DIGEST_RE = re.compile(r"\A(?:sha256:)?([0-9a-f]{64})\Z")
_REGISTER_NAME_RE = re.compile(r"\A[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
_LOGIN_RE = re.compile(r"\A[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}\Z")
UNKNOWN = "unknown"


class PairingError(Exception):
    """A pairing decision that is refused; nothing was changed."""


@dataclass
class ConfirmResult:
    digest: str
    confirmed: list[rs.Pairing] = field(default_factory=list)
    waiting: list[rs.Pairing] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# the list of the bill of materials
# ─────────────────────────────────────────────────────────────────────────


def _effects_text(effects: tuple[str, ...]) -> str:
    return "".join(e for e in rs.EFFECTS if e in effects)


def _sorted_effects(effects) -> tuple[str, ...]:
    return tuple(e for e in rs.EFFECTS if e in effects)


def describe(pairing: rs.Pairing) -> str:
    return f"{pairing.client} -> {pairing.audience} ({_effects_text(pairing.effects)})"


def bom_pairings(doc: dict, register: rs.Register) -> list[rs.Pairing]:
    """The pairings of a verified bill of materials, checked against the naming register
    like a line of pairings.yaml, sorted by client and audience."""
    rows = [
        {"client": p["client"], "audience": p["audience"], "effects": list(p["effects"]),
         "state": "pending"}
        for p in doc.get("pairings", [])
    ]
    try:
        parsed = rs.parse_pairings({"format": rs.PAIRINGS_FORMAT, "pairings": rows}, register)
    except rs.RealmSyncError as exc:
        raise PairingError(
            str(exc).replace("pairings.yaml: pairing", "bill of materials: pairing")
        ) from None
    return sorted(
        (rs.Pairing(p.client, p.audience, _sorted_effects(p.effects), False) for p in parsed),
        key=lambda p: (p.client, p.audience),
    )


def list_digest(pairings: list[rs.Pairing]) -> str:
    """`sha256:<hex>` over the canonical list: one line `<client> <audience> <effects>`
    per pairing, sorted, after a format line. The order of the file does not count; every
    effect does."""
    lines = sorted(f"{p.client} {p.audience} {_effects_text(p.effects)}\n" for p in pairings)
    text = LIST_FORMAT + "\n" + "".join(lines)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _approved_digest(value: object) -> str:
    match = _DIGEST_RE.match(value) if isinstance(value, str) else None
    if not match:
        raise PairingError(
            "--approve-pairings: expected the sha256 of the list as setup shows it "
            "(sha256:<64 hex digits>)"
        )
    return "sha256:" + match.group(1)


# ─────────────────────────────────────────────────────────────────────────
# the acting person
# ─────────────────────────────────────────────────────────────────────────


def acting_person() -> str:
    """`host:<login>` of the person running papaia-ctl. `SUDO_USER` is believed only when
    papaia-ctl runs as root (sudo sets it; any other caller could set it to anything)."""
    uid = os.geteuid()
    if uid == 0:
        name = os.environ.get("SUDO_USER", "").strip() or "root"
    else:
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            name = ""
    return f"host:{name}" if _LOGIN_RE.match(name) else UNKNOWN


def _named(person: str) -> str:
    if not isinstance(person, str) or not rs._PAIRING_PERSON_RE.match(person):
        raise PairingError(
            "the acting host account cannot be named, so no second person can be told apart; "
            "run papaia-ctl from a named login"
        )
    return person


# ─────────────────────────────────────────────────────────────────────────
# pairings.yaml
# ─────────────────────────────────────────────────────────────────────────


@contextlib.contextmanager
def _locked(config_dir: Path):
    folder = rs.pairings_path(config_dir).parent
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(folder / LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _load(config_dir: Path, register: rs.Register) -> list[rs.Pairing]:
    try:
        return rs.load_pairings(rs.pairings_path(config_dir), register)
    except rs.RealmSyncError as exc:
        raise PairingError(str(exc)) from None


def _row(pairing: rs.Pairing) -> dict:
    row: dict = {
        "client": pairing.client,
        "audience": pairing.audience,
        "effects": list(_sorted_effects(pairing.effects)),
        "state": "confirmed" if pairing.confirmed else "pending",
    }
    if pairing.requested_by:
        row["requested_by"] = pairing.requested_by
    if pairing.confirmed_by:
        row["confirmed_by"] = pairing.confirmed_by
    return row


def _store(config_dir: Path, register: rs.Register, pairings: list[rs.Pairing]) -> None:
    """Check the new list as the realm sync will read it, then replace the file
    atomically (0600, written next to it)."""
    doc = {"format": rs.PAIRINGS_FORMAT, "pairings": [_row(p) for p in pairings]}
    try:
        rs.parse_pairings(doc, register)
    except rs.RealmSyncError as exc:
        raise PairingError(str(exc)) from None
    path = rs.pairings_path(config_dir)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def _audit(config_dir: Path, person: str) -> rs.AuditLog:
    return rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(),
                       host_account=person, writer=WRITER)


def _change(pairing_id: str, operation: str, kind: str = "pairing") -> rs.Change:
    return rs.Change(kind, pairing_id, operation, operation, event=EVENT)


def _pid(client: str, audience: str) -> str:
    return f"{client}/{audience}"


# ─────────────────────────────────────────────────────────────────────────
# decisions
# ─────────────────────────────────────────────────────────────────────────


def confirm_installation(
    config_dir: Path,
    register: rs.Register,
    entries: list[rs.Pairing],
    approved: str,
    *,
    person: str,
) -> ConfirmResult:
    """Confirm the list of the bill of materials the operator approved by its digest:
    read pairings are confirmed, write pairings wait for a second person. A pairing the
    file already holds is not touched."""
    approved = _approved_digest(approved)
    digest = list_digest(entries)
    result = ConfirmResult(digest)
    if approved != digest:
        with _audit(config_dir, person) as audit:
            audit.write(_change("bill-of-materials", "confirm", "pairing-list"), "denied",
                        "list_digest_mismatch", host=True, detail={"statement_hash": digest})
        raise PairingError(
            f"the list of pairings ({digest}) differs from the approved one ({approved}); "
            "nothing was confirmed"
        )
    person = _named(person)
    with _locked(config_dir):
        current = _load(config_dir, register)
        known = {(p.client, p.audience) for p in current}
        added: list[rs.Pairing] = []
        for entry in entries:
            if (entry.client, entry.audience) in known:
                continue
            if entry.writes:
                pairing = rs.Pairing(entry.client, entry.audience, entry.effects, False,
                                     requested_by=person)
                result.waiting.append(pairing)
            else:
                pairing = rs.Pairing(entry.client, entry.audience, entry.effects, True,
                                     confirmed_by=person)
                result.confirmed.append(pairing)
            added.append(pairing)
        if not added:
            return result
        with _audit(config_dir, person) as audit:
            _store(config_dir, register, [*current, *added])
            for pairing in added:
                audit.write(
                    _change(_pid(pairing.client, pairing.audience),
                            "confirm" if pairing.confirmed else "request"),
                    "allowed", host=True, detail={"statement_hash": digest},
                )
    return result


def _check_effects(effects: list[str] | None) -> tuple[str, ...] | None:
    if effects is None:
        return None
    if (
        not isinstance(effects, list)
        or not effects
        or len(set(effects)) != len(effects)
        or not all(e in rs.EFFECTS for e in effects)
    ):
        raise PairingError(f"effects must be distinct letters out of {''.join(rs.EFFECTS)}")
    return _sorted_effects(effects)


def _names(client: object, audience: object) -> None:
    for label, value in (("client", client), ("audience", audience)):
        if not isinstance(value, str) or not _REGISTER_NAME_RE.match(value):
            raise PairingError(f"{label}: not a name of the naming register")


def approve(
    config_dir: Path,
    register: rs.Register,
    client: str,
    audience: str,
    effects: list[str] | None,
    *,
    person: str,
) -> str:
    """Approve one pairing; returns "confirmed" or "waiting" (a write pairing that now
    needs a second person). `effects` is needed for a pairing the file does not hold yet
    and must match a recorded one."""
    _names(client, audience)
    wanted = _check_effects(effects)
    pid = _pid(client, audience)
    with _locked(config_dir):
        current = _load(config_dir, register)
        index = next((i for i, p in enumerate(current)
                      if (p.client, p.audience) == (client, audience)), None)
        if index is None:
            if wanted is None:
                raise PairingError(f"{client} -> {audience} is not recorded; name its --effects")
            existing = rs.Pairing(client, audience, wanted, False)
        else:
            existing = current[index]
            if wanted is not None and wanted != _sorted_effects(existing.effects):
                raise PairingError(
                    f"{describe(existing)} is recorded with other effects; revoke it first"
                )
        if existing.confirmed:
            return "confirmed"
        if not existing.writes:
            updated = rs.Pairing(client, audience, existing.effects, True,
                                 existing.requested_by, _named(person))
            operation, outcome = "approve", "confirmed"
        elif existing.requested_by is None:
            updated = rs.Pairing(client, audience, existing.effects, False,
                                 requested_by=_named(person))
            operation, outcome = "request", "waiting"
        elif person == existing.requested_by or not rs._PAIRING_PERSON_RE.match(person):
            with _audit(config_dir, person) as audit:
                audit.write(_change(pid, "approve"), "denied", "same_person", host=True)
            raise PairingError(
                f"{describe(existing)} writes or deletes and was requested by "
                f"{existing.requested_by}: a second person must approve it"
            )
        else:
            updated = rs.Pairing(client, audience, existing.effects, True,
                                 existing.requested_by, person)
            operation, outcome = "approve", "confirmed"
        pairings = list(current)
        if index is None:
            pairings.append(updated)
        else:
            pairings[index] = updated
        with _audit(config_dir, person) as audit:
            _store(config_dir, register, pairings)
            audit.write(_change(pid, operation), "allowed", host=True)
    return outcome


def revoke(
    config_dir: Path, register: rs.Register, client: str, audience: str, *, person: str
) -> None:
    """Remove one pairing, whatever its state; the realm sync removes its scope."""
    _names(client, audience)
    with _locked(config_dir):
        current = _load(config_dir, register)
        remaining = [p for p in current if (p.client, p.audience) != (client, audience)]
        if len(remaining) == len(current):
            raise PairingError(f"{client} -> {audience} is not recorded")
        with _audit(config_dir, person) as audit:
            _store(config_dir, register, remaining)
            audit.write(_change(_pid(client, audience), "revoke"), "allowed", host=True)


# ─────────────────────────────────────────────────────────────────────────
# commands
# ─────────────────────────────────────────────────────────────────────────


def _trusted_bom(repo_root: Path) -> dict | None:
    """The verified bill of materials of this checkout; None when the checkout has none.
    A file that is there but does not verify is an error, never "no pairings"."""
    try:
        path = images.bom_path(repo_root, images.core_version(repo_root))
    except images.ImageError:
        return None
    if not path.is_file():
        return None
    try:
        return images.load_trusted_bom(repo_root)
    except images.ImageError as exc:
        raise PairingError(str(exc)) from None


def _state(pairing: rs.Pairing, recorded: dict[tuple[str, str], rs.Pairing]) -> str:
    found = recorded.get((pairing.client, pairing.audience))
    if found is None:
        return "not recorded"
    return "confirmed" if found.confirmed else "waiting for approval"


def cmd_list(args: argparse.Namespace) -> int:
    register = rs.load_register()
    try:
        doc = _trusted_bom(Path(args.repo_root))
        entries = bom_pairings(doc, register) if doc else []
        recorded = {(p.client, p.audience): p for p in _load(Path(args.config_dir), register)}
    except PairingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    digest = list_digest(entries) if entries else None
    rows = [
        {"client": p.client, "audience": p.audience, "effects": _effects_text(p.effects),
         "kind": "write" if p.writes else "read", "state": _state(p, recorded)}
        for p in entries
    ]
    pending = any(row["state"] == "not recorded" for row in rows)
    if args.digest:
        if pending:
            print(digest)
        return 0
    if args.json:
        print(json.dumps({"bom": doc is not None, "suite": doc["suite"] if doc else None,
                          "pairings": rows, "digest": digest, "pending_decision": pending}))
        return 0
    if doc is None:
        print("No signed bill of materials in this checkout; no pairings to confirm.")
        return 0
    if not rows:
        print(f"The bill of materials of suite {doc['suite']} names no pairings.")
        return 0
    print(f"Pairings of the signed bill of materials (suite {doc['suite']}):")
    for row in rows:
        print(f"  {row['kind']:<5}  {row['client']} -> {row['audience']} ({row['effects']})"
              f"  [{row['state']}]")
    print(f"sha256 of the list: {digest}")
    print("Confirming this list confirms the read pairings; each write pairing then waits "
          "for a second person ('papaia-ctl pairing approve').")
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    register = rs.load_register()
    config_dir = Path(args.config_dir)
    try:
        doc = _trusted_bom(Path(args.repo_root))
        if doc is None:
            raise PairingError("no signed bill of materials in this checkout")
        entries = bom_pairings(doc, register)
        result = confirm_installation(config_dir, register, entries, args.approve_pairings,
                                      person=acting_person())
    except PairingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not result.confirmed and not result.waiting:
        print("Every pairing of the bill of materials is recorded already; nothing changed.")
        return 0
    for pairing in result.confirmed:
        print(f"confirmed: {describe(pairing)}")
    for pairing in result.waiting:
        print(f"waiting for approval: {describe(pairing)} "
              "(a second person: 'papaia-ctl pairing approve')")
    print("The realm sync assigns the confirmed pairings ('papaia-ctl start' runs it).")
    return 0


def _effects_arg(value: str | None) -> list[str] | None:
    if value is None:
        return None
    if len(value) > len(rs.EFFECTS):
        raise PairingError(f"effects must be distinct letters out of {''.join(rs.EFFECTS)}")
    return list(value)


def cmd_approve(args: argparse.Namespace) -> int:
    register = rs.load_register()
    try:
        outcome = approve(Path(args.config_dir), register, args.client, args.audience,
                          _effects_arg(args.effects), person=acting_person())
    except PairingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if outcome == "waiting":
        print(f"{args.client} -> {args.audience} writes or deletes: it waits for a second "
              "person, who runs 'papaia-ctl pairing approve' with the same names.")
    else:
        print(f"confirmed: {args.client} -> {args.audience}; the next realm sync assigns it.")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    register = rs.load_register()
    try:
        revoke(Path(args.config_dir), register, args.client, args.audience,
               person=acting_person())
    except PairingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"revoked: {args.client} -> {args.audience}; the next realm sync removes it.")
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("pairing-list")
    p.add_argument("--json", action="store_true")
    p.add_argument("--digest", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("pairing-confirm")
    p.add_argument("--approve-pairings", required=True)
    p.set_defaults(func=cmd_confirm)

    for name, func in (("pairing-approve", cmd_approve), ("pairing-revoke", cmd_revoke)):
        p = sub.add_parser(name)
        p.add_argument("--client", required=True)
        p.add_argument("--audience", required=True)
        if name == "pairing-approve":
            p.add_argument("--effects", default=None)
        p.set_defaults(func=func)
