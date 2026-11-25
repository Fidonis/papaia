"""The operator's opt-in of an add-on outside the suite for the chat (ADR 0029 points 4-6).

A tool server outside the suite (`trust: addon`) reaches the chat only through the core
chat relay `papaia-chat-relay`, and only after the operator allowed that add-on:

- `papaia-ctl addon chat allow <addon>` accepts only an installed, active add-on whose
  catalog entry is one tool server (`kind: mcp`) for persons with an address, a
  registered audience and at least one operation `via: tools`. It refuses a module of the
  suite (it reaches the chat directly), an unknown name, an add-on that puts `librechat`
  on one of its networks and an audience that exchanges tokens itself. The approval names
  the audience that was shown (`--approve=<audience>`), so what was shown is what is
  allowed.
- The opt-in is a pairing of `papaia-chat-relay` with the add-on's audience in
  `security/pairings.yaml`, with the effects of the declared tools (`read`, `check` as
  `r`; `write`, `send` as `w`; `delete` as `d`). A write opt-in, and every opt-in while
  `approvals.four_eyes` is on, waits for a second host account, who runs the same
  command; the same account is refused. `papaia-ctl pairing approve` and `pairing revoke`
  refuse the relay, so this is the only path.
- `addon chat revoke` removes the pairing in any state, `addon uninstall` removes it with
  the add-on. Either way the relay's list is written at once, so the relay refuses the
  add-on from that moment; the next realm sync removes the scope from the relay's client.
- Only a confirmed opt-in of a running add-on whose declared effects still match is
  served: it is on the relay's list (`chat-relay/servers.json`, `papaia.chat-relay-servers/1`)
  and gets a chat entry named after its audience that points to the relay, never to the
  add-on. No audience mapper of the add-on's audience goes on `librechat`; the catalog
  entry keeps `trust: addon`.

Every decision (`chat_relay.allow`, `chat_relay.approve`, `chat_relay.revoke`, a refused
attempt too) and every write of the list (`chat_relay.list_write`) is one
`papaia.audit/1` row of `papaia-ctl/chat-relay` in the core's outbox, with the host
account, the add-on, its catalog entry and the data class cap; never a token.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import stat
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import catalog, chat_relay, common, deployment
from . import pairing_approval as pa
from . import realm_sync as rs
from .chat_servers import ChatServer

WRITER = "papaia-ctl/chat-relay"
EVENT = "exchange_right_changed"
RELAY = chat_relay.RELAY
RELAY_ORIGIN = f"http://{RELAY}:8080"
LIST_REF = f"{chat_relay.LIST_DIR.as_posix()}/{chat_relay.SERVERS_FILE}"
# The data class scale of the platform, lowest first (kit platform-services `DataClass`).
DATA_CLASSES = (
    "public",
    "internal",
    "partner_contact",
    "personal",
    "employee",
    "confidential",
    "special",
    "professional_secret",
)
# Effect of a declared operation -> effect letter of the pairing (ADR 0029 point 4).
EFFECT_LETTERS = {"read": "r", "check": "r", "write": "w", "send": "w", "delete": "d"}
# The relay's own limits of its list (src/infra/chat-relay/relay.py).
MAX_TOOLS = 100
MAX_ADDRESS = 512
_NAME_RE = re.compile(r"\A[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
_NAME_MAX = 64

ALLOWED = "allowed"
WAITING = "waiting for approval"
NOT_SERVED = "allowed, not served"


class OptInError(Exception):
    """A refused opt-in decision; `code` is the audit row's error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Candidate:
    """The one tool server of an add-on the relay may serve, as the catalog lists it."""

    addon: str
    catalog_id: str
    audience: str
    address: str
    title: str
    description: str
    state: str
    data_class_max: str | None
    tools: tuple[dict, ...]
    effects: tuple[str, ...]
    network: str


# ─────────────────────────────────────────────────────────────────────────
# what an add-on offers
# ─────────────────────────────────────────────────────────────────────────


def _check_name(addon: object) -> str:
    if not isinstance(addon, str) or len(addon) > _NAME_MAX or not _NAME_RE.match(addon):
        raise OptInError("invalid_name", "the add-on name is not a name of an add-on")
    return addon


def _person(person: str) -> str:
    try:
        return pa._named(person)
    except pa.PairingError as exc:
        raise OptInError("unnamed_person", str(exc)) from None


def _context(config_dir: Path, repo_root: Path) -> tuple[dict, dict | None]:
    deployed = deployment.load(config_dir) or {}
    try:
        doc = catalog.build(config_dir, repo_root, deployed=deployed)
    except catalog.CatalogError as exc:
        raise OptInError("catalog", f"platform catalog: {exc}") from None
    return deployed, doc


def _plain(text: object) -> bool:
    return isinstance(text, str) and 0 < len(text) and not any(
        ord(c) < 32 and c not in "\n\t" for c in text
    )


def _address_ok(value: object) -> bool:
    if not isinstance(value, str) or len(value) > MAX_ADDRESS:
        return False
    parts = urllib.parse.urlsplit(value)
    return (
        parts.scheme in ("http", "https")
        and bool(parts.hostname)
        and not (parts.username or parts.password or parts.query or parts.fragment)
    )


def _cap(classes) -> str | None:
    known = [c for c in classes if c in DATA_CLASSES]
    return max(known, key=DATA_CLASSES.index) if known else None


def _not_eligible(addon: str, why: str) -> OptInError:
    return OptInError("not_eligible", f"add-on '{addon}' {why}; the chat relay cannot serve it")


def _assess(
    doc: dict | None, deployed: dict, repo_root: Path, register: rs.Register, addon: str
) -> Candidate:
    """The tool server of `addon` an opt-in may name, or OptInError with the reason."""
    active = {
        a["name"]: a for a in deployment.active_addons(deployed) if isinstance(a.get("name"), str)
    }
    if addon not in active:
        raise OptInError(
            "unknown_addon", f"add-on '{addon}' is not installed (papaia-ctl addon list)"
        )
    entries = [e for e in (doc or {}).get("services") or [] if e.get("provider") == addon]
    if any(e.get("trust") == "platform" for e in entries):
        raise OptInError(
            "suite_module",
            f"add-on '{addon}' is a module of the suite: its tool server reaches the chat "
            "directly and needs no opt-in",
        )
    servers = [
        e for e in entries
        if e.get("kind") == "mcp"
        and "person" in (e.get("identity") or ())
        and e.get("address")
        and e.get("audience")
    ]
    if not servers:
        raise _not_eligible(
            addon, "declares no tool server (kind: mcp) for persons with an address and an audience"
        )
    if len(servers) > 1:
        raise _not_eligible(addon, "declares more than one tool server for persons")
    entry = servers[0]
    manifest, _ = deployment.load_addon_manifest(
        deployment.resolve_addon_path(active[addon], repo_root)
    )
    if chat_relay.attaches_chat(manifest):
        raise OptInError(
            "attaches_chat",
            f"add-on '{addon}' puts librechat on one of its networks, a direct path to the "
            "chat; drop that attachment before it can be allowed",
        )
    networks = (manifest or {}).get("networks")
    app_network = networks.get("app_network") if isinstance(networks, dict) else None
    if not isinstance(app_network, str) or not app_network:
        raise _not_eligible(addon, "declares no app network (networks.app_network) to join")
    audience = entry["audience"]
    if audience not in register.audiences:
        raise _not_eligible(addon, f"serves the audience '{audience}', which is not registered")
    if audience in register.exchange_clients() or audience in (RELAY, chat_relay.CHAT_CLIENT):
        raise OptInError(
            "exchange_client",
            f"the audience '{audience}' of add-on '{addon}' exchanges tokens itself; the "
            "relay's token could be exchanged onwards",
        )
    if not _address_ok(entry["address"]):
        raise _not_eligible(addon, "has an address the relay does not accept")
    tools = [op for op in entry.get("operations") or [] if op.get("via") == "tools"]
    if not tools:
        raise _not_eligible(addon, "declares no operation via tools")
    if len(tools) > MAX_TOOLS:
        raise _not_eligible(addon, f"declares more than {MAX_TOOLS} tools")
    rows: list[dict] = []
    for op in tools:
        schema = op.get("input_schema")
        title = (op.get("title") or {}).get("en")
        tool = f"declares the tool '{op.get('name')}'"
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise _not_eligible(addon, f"{tool} without an object input_schema")
        if not _plain(title) or op.get("effect") not in EFFECT_LETTERS:
            raise _not_eligible(addon, f"{tool} with a title or effect the relay refuses")
        rows.append({
            "name": op["name"],
            "title": title,
            "description": title,
            "input_schema": schema,
            "effect": op["effect"],
            "data_class_max": op.get("data_class_max"),
        })
    letters = {EFFECT_LETTERS[op["effect"]] for op in tools}
    title = entry["title"]["en"]
    description = (entry.get("description") or entry["title"])["en"]
    if not _plain(title) or not _plain(description):
        raise _not_eligible(addon, "has a title or description the chat cannot show")
    return Candidate(
        addon=addon,
        catalog_id=entry["id"],
        audience=audience,
        address=entry["address"],
        title=title,
        description=description,
        state=entry.get("state") or catalog.STOPPED,
        data_class_max=_cap(op.get("data_class_max") for op in tools),
        tools=tuple(rows),
        effects=tuple(e for e in rs.EFFECTS if e in letters),
        network=app_network,
    )


def describe(config_dir: Path, repo_root: Path, addon: str) -> Candidate:
    """What `addon chat allow` would allow (shown before it asks)."""
    _check_name(addon)
    deployed, doc = _context(config_dir, repo_root)
    return _assess(doc, deployed, repo_root, rs.load_register(), addon)


def _by_audience(
    config_dir: Path, repo_root: Path, register: rs.Register
) -> dict[str, Candidate | OptInError]:
    """Per audience served by an active add-on: its candidate, or why it is none."""
    deployed, doc = _context(config_dir, repo_root)
    found: dict[str, Candidate | OptInError] = {}
    for addon in deployment.active_addons(deployed):
        name = addon.get("name")
        if not isinstance(name, str):
            continue
        try:
            candidate = _assess(doc, deployed, repo_root, register, name)
        except OptInError as exc:
            for entry in (doc or {}).get("services") or []:
                if entry.get("provider") == name and entry.get("audience"):
                    found.setdefault(entry["audience"], exc)
            continue
        found[candidate.audience] = candidate
    return found


# ─────────────────────────────────────────────────────────────────────────
# the pairings of the relay
# ─────────────────────────────────────────────────────────────────────────


def _load(config_dir: Path, register: rs.Register) -> list[rs.Pairing]:
    try:
        return rs.load_pairings(rs.pairings_path(config_dir), register)
    except rs.RealmSyncError as exc:
        raise OptInError("pairings", str(exc)) from None


def _relay_pairings(config_dir: Path, register: rs.Register) -> list[rs.Pairing]:
    return [p for p in _load(config_dir, register) if p.client == RELAY]


def _store(config_dir: Path, register: rs.Register, pairings: list[rs.Pairing]) -> None:
    try:
        pa._store(config_dir, register, pairings)
    except pa.PairingError as exc:
        raise OptInError("pairings", str(exc)) from None


def _served(
    pairing: rs.Pairing, offered: dict[str, Candidate | OptInError]
) -> tuple[Candidate | None, str | None]:
    """The candidate a confirmed opt-in serves, or None and why not."""
    found = offered.get(pairing.audience)
    if found is None:
        return None, "no installed add-on serves this audience"
    if isinstance(found, OptInError):
        return None, str(found)
    if found.state != catalog.RUNNING:
        return None, f"add-on '{found.addon}' is stopped"
    if set(found.effects) != set(pairing.effects):
        return None, (
            f"the opt-in covers the effects {''.join(pairing.effects)}, the add-on now "
            f"declares {''.join(found.effects)}; revoke and allow it again"
        )
    return found, None


def allowed(config_dir: Path, repo_root: Path) -> list[Candidate]:
    """The tool servers the relay serves: confirmed opt-ins of running add-ons whose
    declared effects still match, sorted by audience. Empty without any opt-in (the
    catalog is then not read)."""
    register = rs.load_register()
    confirmed = [p for p in _relay_pairings(config_dir, register) if p.confirmed]
    if not confirmed:
        return []
    offered = _by_audience(config_dir, repo_root, register)
    served = []
    for pairing in confirmed:
        candidate, _ = _served(pairing, offered)
        if candidate is not None:
            served.append(candidate)
    return sorted(served, key=lambda c: c.audience)


def chat_entries(candidates: list[Candidate]) -> list[ChatServer]:
    """The chat entries of the served tool servers: named after the audience, pointing to
    the relay, the description ending with the data class cap (ADR 0029 point 6)."""
    return [
        ChatServer(
            provider=c.addon,
            catalog_id=c.catalog_id,
            audience=c.audience,
            url=f"{RELAY_ORIGIN}/servers/{c.audience}/mcp",
            title=c.title,
            description=f"{c.description} Data class up to: {c.data_class_max or 'not declared'}.",
        )
        for c in candidates
    ]


def listing(config_dir: Path, repo_root: Path) -> list[dict]:
    """Every opt-in of the relay with its state, sorted by audience."""
    register = rs.load_register()
    pairings = _relay_pairings(config_dir, register)
    if not pairings:
        return []
    offered = _by_audience(config_dir, repo_root, register)
    rows = []
    for pairing in sorted(pairings, key=lambda p: p.audience):
        found = offered.get(pairing.audience)
        candidate = found if isinstance(found, Candidate) else None
        if pairing.confirmed:
            served, reason = _served(pairing, offered)
            state = ALLOWED if served is not None else NOT_SERVED
        else:
            state, reason = WAITING, None
        rows.append({
            "addon": candidate.addon if candidate else None,
            "audience": pairing.audience,
            "catalog_id": candidate.catalog_id if candidate else None,
            "effects": "".join(pairing.effects),
            "state": state,
            "reason": reason,
            "requested_by": pairing.requested_by,
            "confirmed_by": pairing.confirmed_by,
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def _audit(config_dir: Path, person: str | None) -> rs.AuditLog:
    return rs.AuditLog(
        rs.audit_path(config_dir), rs.new_correlation_id(), host_account=person, writer=WRITER
    )


def _row(
    audit: rs.AuditLog,
    operation: str,
    object_ref: dict,
    result: str,
    *,
    error_code: str | None = None,
    effect: str = "write",
    catalog_id: str | None = None,
    data_class: str | None = None,
) -> None:
    audit.append({
        "role": "caller",
        "sub": audit.host_account,
        "identity_kind": None,
        "service_account": None,
        "azp": None,
        "aud": None,
        "origin_azp": None,
        "origin_source": None,
        "origin_asserted_by": None,
        "context": None,
        "catalog_id": catalog_id,
        "operation": f"chat_relay.{operation}",
        "effect": effect,
        "object_ref": object_ref,
        "data_class": data_class,
        "result": result,
        "error_code": error_code,
        "client_ip": None,
        "detail": None,
        "event": EVENT,
    })


def _decision(
    audit: rs.AuditLog,
    operation: str,
    addon: str,
    result: str,
    candidate: Candidate | None = None,
    *,
    error_code: str | None = None,
    effect: str = "write",
) -> None:
    _row(
        audit,
        operation,
        {"type": "addon", "id": addon},
        result,
        error_code=error_code,
        effect=effect,
        catalog_id=candidate.catalog_id if candidate else None,
        data_class=candidate.data_class_max if candidate else None,
    )


def _deny(
    config_dir: Path,
    person: str,
    operation: str,
    addon: str,
    exc: OptInError,
    candidate: Candidate | None = None,
    effect: str = "write",
) -> OptInError:
    with _audit(config_dir, person) as audit:
        _decision(audit, operation, addon, "denied", candidate, error_code=exc.code, effect=effect)
    return exc


# ─────────────────────────────────────────────────────────────────────────
# the relay's list
# ─────────────────────────────────────────────────────────────────────────


def _list_document(candidates: list[Candidate]) -> bytes:
    doc = {
        "format": chat_relay.SERVERS_FORMAT,
        "servers": [
            {
                "audience": c.audience,
                "scope": rs.exchange_scope(c.audience),
                "addon": c.addon,
                "catalog_id": c.catalog_id,
                "address": c.address,
                "data_class_max": c.data_class_max,
                "tools": list(c.tools),
            }
            for c in candidates
        ],
    }
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _write_list(path: Path, data: bytes) -> None:
    """Replace the list atomically (0600: the relay runs as the owner of the
    configuration directory); a symbolic link in its place is refused."""
    folder = path.parent
    folder.mkdir(mode=0o755, parents=True, exist_ok=True)
    st = os.lstat(folder)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{folder} is not a folder")
    tmp = folder / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def _current(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError:
        return b""  # a symbolic link or unreadable file: replaced or removed below
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def render_list(
    config_dir: Path, repo_root: Path, *, audit: rs.AuditLog | None = None
) -> bool:
    """Write `chat-relay/servers.json` from the served opt-ins, or remove it when there is
    none; True when the file changed. Every change is one audit row (in `audit` when the
    caller holds one)."""
    path = chat_relay.servers_path(config_dir)
    candidates = allowed(config_dir, repo_root)
    data = _list_document(candidates) if candidates else None
    current = _current(path)
    if data == current or (data is None and current is None and not path.is_symlink()):
        return False
    effect = "write" if data is not None else "delete"
    with contextlib.ExitStack() as stack:
        try:
            log = audit or stack.enter_context(_audit(config_dir, None))
        except rs.RealmSyncError as exc:
            raise OptInError("audit_unavailable", f"the audit outbox: {exc}") from None
        ref = {"type": "file", "id": LIST_REF}
        try:
            if data is None:
                path.unlink(missing_ok=True)
            else:
                _write_list(path, data)
        except OSError:
            _row(log, "list_write", ref, "error", error_code="io", effect=effect)
            raise
        _row(log, "list_write", ref, "allowed", effect=effect)
    return True


# ─────────────────────────────────────────────────────────────────────────
# the relay's way to the add-ons
# ─────────────────────────────────────────────────────────────────────────

OVERRIDE_PREFIX = "docker-compose.chat-relay-"
OVERRIDE_SUFFIX = ".override.yml"


def override_name(addon: str) -> str:
    return f"{OVERRIDE_PREFIX}{addon}{OVERRIDE_SUFFIX}"


def _override(network: str, addon: str) -> bytes:
    head = (
        f"# Generated by papaia-ctl: the chat relay joins the app network of {addon}, which\n"
        "# the operator allowed in the chat (papaia-ctl addon chat allow); do not edit.\n"
    )
    doc = {
        "services": {RELAY: {"networks": [network]}},
        "networks": {network: {"external": True}},
    }
    return (head + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)).encode()


def generate_overrides(config_dir: Path, repo_root: Path) -> list[Path]:
    """One override per served add-on that puts the relay on the add-on's app network
    (`overrides/docker-compose.chat-relay-<addon>.override.yml`, mode 0644), so the relay
    reaches the address of the list; an override whose add-on is no longer served is
    removed. `start` leaves out an override whose network does not exist yet, so one
    stopped add-on never keeps the relay from the others. Every write and removal is one
    audit row; returns the overrides that exist afterwards."""
    from . import gen_override  # it reaches the render path, which imports this module

    folder = config_dir / "overrides"
    wanted = {
        override_name(c.addon): _override(
            gen_override.resolve_app_network(c.network, config_dir), c.addon
        )
        for c in allowed(config_dir, repo_root)
    }
    present = (
        {p.name for p in folder.glob(f"{OVERRIDE_PREFIX}*{OVERRIDE_SUFFIX}")}
        if folder.is_dir() else set()
    )
    changes: list[tuple[str, bytes | None]] = []
    for name in sorted(present | set(wanted)):
        target = wanted.get(name)
        if _current(folder / name) != target:
            changes.append((name, target))
    if changes:
        with _audit(config_dir, None) as audit:
            for name, target in changes:
                path = folder / name
                ref = {"type": "file", "id": f"overrides/{name}"}
                effect = "write" if target is not None else "delete"
                try:
                    if target is None:
                        path.unlink(missing_ok=True)
                    else:
                        folder.mkdir(parents=True, exist_ok=True)
                        tmp = folder / f".{name}.{os.getpid()}.tmp"
                        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                                     0o644)
                        with os.fdopen(fd, "wb") as fh:
                            os.fchmod(fh.fileno(), 0o644)
                            fh.write(target)
                            fh.flush()
                            os.fsync(fh.fileno())
                        os.replace(tmp, path)
                except OSError:
                    _row(audit, "override_write", ref, "error", error_code="io", effect=effect)
                    raise
                _row(audit, "override_write", ref, "allowed", effect=effect)
    return [folder / name for name in sorted(wanted)]


# ─────────────────────────────────────────────────────────────────────────
# decisions
# ─────────────────────────────────────────────────────────────────────────


def _four_eyes(config_dir: Path) -> bool:
    env = common.parse_env_file(config_dir / ".env")
    try:
        profile = catalog.profile_name(env)
        return catalog.four_eyes_in_effect(profile, catalog.stored_four_eyes(config_dir)) == "on"
    except catalog.CatalogError as exc:
        raise OptInError("four_eyes_unknown", f"the four-eyes rule cannot be read: {exc}") from None


def allow(
    config_dir: Path, repo_root: Path, addon: str, *, person: str, approve: str
) -> str:
    """Allow `addon` in the chat, or approve a waiting opt-in as the second host account.
    Returns "allowed", "waiting" (a second host account must approve) or "unchanged".
    `approve` is the audience the operator saw and confirmed."""
    _check_name(addon)
    person = _person(person)
    register = rs.load_register()
    try:
        deployed, doc = _context(config_dir, repo_root)
        candidate = _assess(doc, deployed, repo_root, register, addon)
    except OptInError as exc:
        raise _deny(config_dir, person, "allow", addon, exc) from None
    if approve != candidate.audience:
        raise _deny(config_dir, person, "allow", addon, OptInError(
            "approval_mismatch",
            f"the approval names '{approve}', but add-on '{addon}' serves "
            f"'{candidate.audience}'; nothing was allowed",
        ), candidate) from None
    four_eyes = _four_eyes(config_dir)
    writes = any(e in rs.WRITE_EFFECTS for e in candidate.effects)
    with pa._locked(config_dir):
        current = _load(config_dir, register)
        index = next(
            (i for i, p in enumerate(current)
             if (p.client, p.audience) == (RELAY, candidate.audience)),
            None,
        )
        existing = current[index] if index is not None else None
        if existing is not None and set(existing.effects) != set(candidate.effects):
            raise _deny(config_dir, person, "allow", addon, OptInError(
                "effects_changed",
                f"the opt-in of '{addon}' is recorded with the effects "
                f"{''.join(existing.effects)}, the add-on now declares "
                f"{''.join(candidate.effects)}; revoke it and allow it again",
            ), candidate) from None
        if existing is not None and existing.confirmed:
            return "unchanged"
        if existing is None or existing.requested_by is None:
            if writes or four_eyes:
                updated = rs.Pairing(RELAY, candidate.audience, candidate.effects, False,
                                     requested_by=person)
                outcome = "waiting"
            else:
                updated = rs.Pairing(RELAY, candidate.audience, candidate.effects, True,
                                     requested_by=person, confirmed_by=person)
                outcome = "allowed"
            operation = "allow"
        elif person == existing.requested_by:
            raise _deny(config_dir, person, "approve", addon, OptInError(
                "same_person",
                f"the opt-in of '{addon}' was requested by {existing.requested_by}: a second "
                "host account must approve it",
            ), candidate) from None
        else:
            updated = rs.Pairing(RELAY, candidate.audience, candidate.effects, True,
                                 existing.requested_by, person)
            operation, outcome = "approve", "allowed"
        pairings = list(current)
        if index is None:
            pairings.append(updated)
        else:
            pairings[index] = updated
        with _audit(config_dir, person) as audit:
            _store(config_dir, register, pairings)
            _decision(audit, operation, addon, "allowed", candidate)
            render_list(config_dir, repo_root, audit=audit)
    return outcome


def _listed_audiences(config_dir: Path, addon: str) -> dict[str, dict]:
    """{audience: row} of the relay's current list for `addon`; nothing for a missing or
    unreadable list (the pairings decide, the list only adds what it names)."""
    data = _current(chat_relay.servers_path(config_dir))
    try:
        doc = json.loads(data) if data else {}
    except ValueError:
        return {}
    rows = doc.get("servers") if isinstance(doc, dict) else None
    return {
        row["audience"]: row
        for row in rows or []
        if isinstance(row, dict)
        and row.get("addon") == addon
        and isinstance(row.get("audience"), str)
    }


def revoke(config_dir: Path, repo_root: Path, addon: str, *, person: str) -> list[str]:
    """Remove the opt-in of `addon` in any state and write the relay's list at once.
    Returns the audiences whose opt-in was removed."""
    _check_name(addon)
    person = _person(person)
    register = rs.load_register()
    try:
        deployed, doc = _context(config_dir, repo_root)
    except OptInError:
        deployed, doc = {}, None  # a broken catalog must not keep an opt-in alive
    audiences = {
        e["audience"] for e in (doc or {}).get("services") or []
        if e.get("provider") == addon and e.get("audience")
    }
    listed = _listed_audiences(config_dir, addon)
    audiences |= set(listed)
    candidate = None
    with contextlib.suppress(OptInError):
        candidate = _assess(doc, deployed, repo_root, register, addon)
    with pa._locked(config_dir):
        current = _load(config_dir, register)
        removed = [p for p in current if p.client == RELAY and p.audience in audiences]
        if not removed:
            raise _deny(config_dir, person, "revoke", addon, OptInError(
                "not_allowed", f"add-on '{addon}' is not allowed in the chat; nothing to revoke"
            ), candidate, effect="delete") from None
        remaining = [p for p in current if p not in removed]
        with _audit(config_dir, person) as audit:
            _store(config_dir, register, remaining)
            _decision(audit, "revoke", addon, "allowed", candidate, effect="delete")
            render_list(config_dir, repo_root, audit=audit)
    return sorted(p.audience for p in removed)


def forget(config_dir: Path, addon: str, audiences: set[str]) -> list[str]:
    """Remove the opt-in of an add-on that is being uninstalled (`audiences`: those its
    manifest declares), so it never applies to another add-on with the same audience
    later. The list follows with the render of the uninstall."""
    register = rs.load_register()
    with pa._locked(config_dir):
        current = _load(config_dir, register)
        removed = [p for p in current if p.client == RELAY and p.audience in audiences]
        if not removed:
            return []
        with _audit(config_dir, None) as audit:
            _store(config_dir, register, [p for p in current if p not in removed])
            _decision(audit, "revoke", addon, "allowed", effect="delete")
    return sorted(p.audience for p in removed)


# ─────────────────────────────────────────────────────────────────────────
# commands
# ─────────────────────────────────────────────────────────────────────────


def _rerender(config_dir: Path, repo_root: Path) -> None:
    """The chat's configuration with the new entry set; the relay's list is already
    written. A failure here leaves the decision in place and is named."""
    from . import render_core  # it imports this module

    try:
        render_core.render(config_dir, repo_root)
        generate_overrides(config_dir, repo_root)
    except (render_core.RenderError, OptInError, rs.RealmSyncError, OSError) as exc:
        print(f"WARNING: the chat configuration was not rendered: {exc}; "
              "'papaia-ctl start' renders it.", file=sys.stderr)


def cmd_show(args: argparse.Namespace) -> int:
    try:
        shown = describe(Path(args.config_dir), Path(args.repo_root), args.name)
        four_eyes = _four_eyes(Path(args.config_dir))
    except OptInError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.audience_only:
        print(shown.audience)
        return 0
    print(f"Add-on:       {shown.addon} (catalog entry {shown.catalog_id}, trust: addon)")
    print(f"Audience:     {shown.audience} (the relay's token carries this audience only)")
    print(f"Data class:   up to {shown.data_class_max or 'not declared'}")
    print("Tools:")
    for tool in shown.tools:
        print(f"  {tool['name']:<32} {tool['effect']:<7} {tool['data_class_max'] or '-'}")
    writes = any(e in rs.WRITE_EFFECTS for e in shown.effects)
    if writes or four_eyes:
        why = "it writes or deletes" if writes else "four eyes are in effect"
        print(f"A second host account must approve this opt-in ({why}).")
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        outcome = allow(config_dir, repo_root, args.name, person=pa.acting_person(),
                        approve=args.approve)
    except (OptInError, rs.RealmSyncError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if outcome == "waiting":
        print(f"waiting for approval: {args.name} in the chat. A second host account runs "
              f"'papaia-ctl addon chat allow {args.name}'.")
        return 0
    if outcome == "unchanged":
        print(f"{args.name} is allowed in the chat already; nothing changed.")
        return 0
    _rerender(config_dir, repo_root)
    print(f"allowed: {args.name} in the chat, through the chat relay. 'papaia-ctl start' "
          "grants the relay the add-on's scope and lets LibreChat read the new entry.")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        revoke(config_dir, repo_root, args.name, person=pa.acting_person())
    except (OptInError, rs.RealmSyncError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _rerender(config_dir, repo_root)
    print(f"revoked: {args.name} in the chat. The relay refuses it from now on; "
          "'papaia-ctl start' removes the entry from LibreChat and the scope from the relay.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    try:
        rows = listing(Path(args.config_dir), Path(args.repo_root))
    except OptInError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"addons": rows}))
        return 0
    if not rows:
        print("No add-on outside the suite is allowed in the chat.")
        return 0
    for row in rows:
        line = f"{row['addon'] or '-':<24} {row['audience']:<24} {row['effects']:<4} {row['state']}"
        if row["reason"]:
            line += f" ({row['reason']})"
        print(line)
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("addon-chat-show")
    p.add_argument("--name", required=True)
    p.add_argument("--audience-only", action="store_true")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("addon-chat-allow")
    p.add_argument("--name", required=True)
    p.add_argument("--approve", required=True)
    p.set_defaults(func=cmd_allow)

    p = sub.add_parser("addon-chat-revoke")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("addon-chat-list")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)
