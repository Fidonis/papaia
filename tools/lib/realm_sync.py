"""`papaia-ctl realm sync`: clients, roles and exchange scopes of the realm from declarations.

The core is the only writer of realm-wide objects. This module derives them from three
sources and reconciles the live `papaia` realm with them, idempotently:

- the naming register (`names_register.json`, a snapshot of the platform kit's register:
  every client, audience, role and service account with its owning repository);
- the `exposes:` sections of the installed modules (active add-ons): the roles they
  declare, the audiences they serve, `delegation` and `service_accounts`;
- `$PAPAIA_CONFIG_DIR/security/pairings.yaml`: which client may exchange tokens for which
  audience. Only confirmed pairings count; a pairing waiting for approval assigns nothing.

What it manages:

- every register client of an installed module, and the resource-server client of every
  registered audience a module declares: attribute `papaia.managed=true` (a fixed value,
  so client policies can name it; no wildcard), `papaia.owner=<module>`,
  `fullScopeAllowed: false`, no implicit flow, no password grant, token exchange only
  where the register grants it;
- one client scope `aud-<audience>` per audience of a confirmed pairing, with exactly one
  audience mapper and no role scope mapping (also when an existing scope is adopted); a
  managed client's optional scopes are exactly its confirmed pairings (at most 12), never
  a default scope; an `aud-*` scope is removed from the realm's default scopes and from
  every unmanaged client that can obtain a token;
- `offline_access` only at `flow-engine` and `assist-gate`, and only when Flow or the
  assistant declare `delegation` with purposes of their own; it is removed from every other
  client and from the realm's default scopes;
- the scopes every managed client shares (Keycloak's default scopes and `offline_access`)
  map no role, except `offline_access` its own role, which is no composite, and carry no
  mapper that adds a role or an audience (Keycloak's audience resolve mapper of `roles`
  stays: no client role reaches a managed client's token scope);
- the declared module roles and the platform roles `papaia-admin`, `papaia-auditor`,
  `papaia-confirm`; each declared `<module>-admin` role joins `papaia-admin`, which never
  includes `papaia-auditor` or `papaia-operator` (separation of duties);
- the token scope of each sign-in client: its module's roles, the roles of every
  `visible_for_roles` that exist and `papaia-confirm`. `papaia-admin` never enters it, nor
  any role whose composite reaches beyond that set or into client roles: an admin's token
  of a module client carries that module's admin role and nothing of `realm-management`;
- no client-level mapper on a managed client that adds an audience or a role;
- a client role of a managed client includes no role but other roles of that client:
  Keycloak puts a client's own roles, with their composites, into its token scope
  whatever `fullScopeAllowed` says.

Every input is checked before the first write: a rejected declaration changes nothing. A
second run reports 0 changes; `--check` compares without writing and reports every
deviation. Every write is one `papaia.audit/1` row in the core's audit outbox.

Credentials. Every `realm sync` and every `--check` reads the master admin password from
the Keycloak `.env` and signs in with it, to check (and with `realm sync` create or
realign) the sync account; the `keycloak_role_sync` step before it on every start uses
the master admin as well. The reconcile itself, every change derived from declarations
and pairings, runs with a token of the service account `svc-papaia-realm-sync` of the
`papaia` realm, not with a master token: that is what the dedicated account limits, and
its rows carry an identity of their own. It does not keep the master password off the
start path. The account holds `manage-clients` and `manage-realm` of the `papaia` realm's
`realm-management`, nothing in the master realm. `manage-realm` is needed to create roles,
composites and role scope mappings, and it lets the account grow into `realm-admin` of the
`papaia` realm (for example through a partial import), so its secret is a second
persistent secret of that reach. Every run checks with the master admin that the account
holds exactly these rights, in its role mappings and its token scope, that its user is in
no group and that Keycloak's `service_account` scope maps no role; `--check` reports a
deviation, `realm sync` removes an extra mapping or membership. Before any write, the
composites of the target rights (and of the realm's default roles) are expanded; one
that reaches further fails `--check` and stops `realm sync` without a write. No client
secret is read, printed or written by this module, except the sync account's own secret,
which lives in the Keycloak `.env`.

Clients of the realm template (LibreChat, LiteLLM, oauth2-proxy, LocalAI, the manager, the
RAG resource servers) stay with `keycloak_role_sync` until their modules declare themselves.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import pwd
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import common, deployment
from . import keycloak_role_sync as kcs

REGISTER_PATH = Path(__file__).with_name("names_register.json")
REGISTER_FORMAT = "papaia.names-register-snapshot/1"
PAIRINGS_FORMAT = "papaia.pairings/1"

SYNC_CLIENT = "svc-papaia-realm-sync"
SYNC_SECRET_KEY = "KC_REALM_SYNC_CLIENT_SECRET"
# Measured against Keycloak 26.7.0: manage-clients creates clients and client scopes and
# changes the realm's default scopes; creating realm roles, adding composites and mapping
# realm roles into a client's scope are refused (403) without manage-realm. manage-realm
# is not a narrow right: it allows a partial import, so the account can grant itself
# realm-admin of the papaia realm (not of the master realm). The master admin is used on
# every run anyway (account check); the account keeps the reconcile on a papaia-realm
# token and gives its writes an identity of their own. Whether that is worth a second
# secret of this reach is open for the maintainer (see docs/architecture.md).
SYNC_RIGHTS = ("manage-clients", "manage-realm")

MANAGED = "papaia.managed"
OWNER = "papaia.owner"
TOKEN_EXCHANGE = "standard.token.exchange.enabled"
MAX_EXCHANGE_SCOPES = 12
PLATFORM_ROLES = ("papaia-admin", "papaia-auditor", "papaia-confirm")
ADMIN_ROLE = "papaia-admin"
# Separation of duties (security 1.3): never part of the papaia-admin composite.
NOT_IN_ADMIN = ("papaia-auditor", "papaia-operator")
# The one platform role a module reads from its own token (second person for approvals).
# papaia-admin is never in a module client's scope: it is a composite of every module's
# admin role and of the manager's realm-management roles; an admin gets the module's own
# admin role through it.
MODULE_PLATFORM_ROLES = ("papaia-confirm",)
OFFLINE = "offline_access"
# Keycloak's own default scopes; every client that issues tokens keeps exactly these.
DEFAULT_SCOPES = frozenset({"basic", "acr", "profile", "email", "roles", "web-origins"})
EFFECTS = ("r", "w", "d", "x")
CHAIN_HOLDER = "papaia-data"

# Delegation (offline sessions) is held at exactly one client per purpose family.
HOLDERS = {"flow": ("papaia-flow", "flow-engine"), "assist": ("papaia-assist", "assist-gate")}
HOLDER_CLIENTS = frozenset(client for _, client in HOLDERS.values())
PURPOSES = frozenset({"flow.run", "assist.event", "assist.room-check", "assist.tools"})
MAX_IDLE_DAYS, MAX_AGE_DAYS = 30, 180

# How each client signs in (security 1.2); the register gives name, owner and exchange
# right. A registered audience is a bearer-only resource server unless it signs persons
# in itself; the chain holder signs nobody in; the Flow CLI is the only public client.
_SIGN_IN_AUDIENCES = frozenset({"assist-api", "papaia-studio-builder-mcp"})
_NO_SIGN_IN = frozenset({CHAIN_HOLDER})
_PUBLIC = frozenset({"flow-cli"})

_FLAGS = {
    "bearer": {"bearerOnly": True, "publicClient": False, "standardFlowEnabled": False},
    "confidential": {"bearerOnly": False, "publicClient": False, "standardFlowEnabled": True},
    "exchange-only": {"bearerOnly": False, "publicClient": False, "standardFlowEnabled": False},
    "public": {"bearerOnly": False, "publicClient": True, "standardFlowEnabled": True},
}
_COMMON_FLAGS = {
    "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": False,
    "fullScopeAllowed": False,
}

_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Z][A-Z0-9_]{0,63})\}$")
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@|+-]{0,254}$")
_MAX_PAIRINGS = 1000
_MAX_FILE_BYTES = 1 << 20
_HOST_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Seconds a run waits for another papaia-ctl run that holds the audit counter.
LOCK_TIMEOUT = 120.0

_ROLE_KEYS = frozenset({"name", "title", "description"})
_DELEGATION_KEYS = frozenset({"purposes", "max_idle_days", "max_age_days"})
_ACCOUNT_KEYS = frozenset(
    {
        "id",
        "purpose",
        "owner_sub",
        "deputy_sub",
        "roles",
        "audiences",
        "effects",
        "realm_management_roles",
        "credential",
    }
)


class RealmSyncError(Exception):
    """A declaration or the pairings file is not acceptable; nothing was changed."""


# ─────────────────────────────────────────────────────────────────────────
# naming register
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Name:
    name: str
    kind: str
    owner: str
    token_exchange: bool = False
    test_profile_only: bool = False


class Register:
    def __init__(self, data: dict) -> None:
        if data.get("format") != REGISTER_FORMAT:
            raise RealmSyncError(f"naming register: format is not {REGISTER_FORMAT}")
        entries = [Name(**e) for e in data["entries"]]
        self._by_kind: dict[str, dict[str, Name]] = {}
        for entry in entries:
            self._by_kind.setdefault(entry.kind, {})[entry.name] = entry
        self.clients = self._by_kind.get("client", {})
        self.roles = self._by_kind.get("role", {})
        self.service_accounts = self._by_kind.get("service-account", {})
        self.audiences = set(self._by_kind.get("audience", {}))
        self.owners = {e.owner for e in entries}
        self._removed = {r["name"]: r for r in data["removed"]}

    def successor(self, name: str, kind: str | None = None) -> str | None:
        removed = self._removed.get(name)
        if removed is None or (kind and "kinds" in removed and kind not in removed["kinds"]):
            return None
        return removed["successor"]

    def product_clients(self) -> dict[str, Name]:
        return {n: e for n, e in self.clients.items() if not e.test_profile_only}

    def exchange_clients(self) -> set[str]:
        return {n for n, e in self.clients.items() if e.token_exchange}

    def check(self, name: object, kind: str, label: str) -> str:
        """`name` as a registered name of `kind`, or RealmSyncError naming the successor."""
        limit = 60 if kind == "audience" else 64
        if not isinstance(name, str) or not name or len(name) > limit:
            raise RealmSyncError(f"{label}: {kind} must be a name of at most {limit} characters")
        successor = self.successor(name, kind)
        if successor:
            raise RealmSyncError(f"{label}: {name!r} was removed; use {successor!r}")
        if name not in self._by_kind.get(kind, {}):
            raise RealmSyncError(f"{label}: {name!r} is not a registered {kind.replace('-', ' ')}")
        return name


def load_register(path: Path = REGISTER_PATH) -> Register:
    return Register(json.loads(path.read_text(encoding="utf-8")))


def exchange_scope(audience: str) -> str:
    """The exchange scope of one audience; the only place the `aud-` prefix is added."""
    return f"aud-{audience}"


def _owner_value(owner: str) -> str:
    return owner.removeprefix("papaia-")


# ─────────────────────────────────────────────────────────────────────────
# pairings
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Pairing:
    client: str
    audience: str
    effects: tuple[str, ...]
    confirmed: bool


def pairings_path(config_dir: Path) -> Path:
    return config_dir / "security" / "pairings.yaml"


def _exact_keys(value: object, keys: frozenset[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise RealmSyncError(f"{label}: must be a mapping")
    unknown = sorted(str(k) for k in set(value) - keys)
    if unknown:
        raise RealmSyncError(f"{label}: unknown field {', '.join(unknown)}")
    missing = sorted(keys - set(value))
    if missing:
        raise RealmSyncError(f"{label}: missing field {', '.join(missing)}")
    return value


def parse_pairings(doc: object, register: Register) -> list[Pairing]:
    doc = _exact_keys(doc, frozenset({"format", "pairings"}), "pairings.yaml")
    if doc["format"] != PAIRINGS_FORMAT:
        raise RealmSyncError(f"pairings.yaml: format must be {PAIRINGS_FORMAT}")
    rows = doc["pairings"]
    if not isinstance(rows, list) or len(rows) > _MAX_PAIRINGS:
        raise RealmSyncError(f"pairings.yaml: pairings must be a list of at most {_MAX_PAIRINGS}")
    exchange_clients = register.exchange_clients()
    pairings: list[Pairing] = []
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        label = f"pairings.yaml: pairing {index + 1}"
        row = _exact_keys(row, frozenset({"client", "audience", "effects", "state"}), label)
        client = register.check(row["client"], "client", label)
        entry = register.clients[client]
        if entry.test_profile_only:
            raise RealmSyncError(f"{label}: {client!r} exists only in the test profile")
        if not entry.token_exchange:
            raise RealmSyncError(f"{label}: {client!r} has no token exchange")
        audience = register.check(row["audience"], "audience", label)
        if audience in exchange_clients and audience != CHAIN_HOLDER:
            raise RealmSyncError(f"{label}: {audience!r} exchanges tokens and is never an audience")
        effects = row["effects"]
        if (
            not isinstance(effects, list)
            or not effects
            or len(set(effects)) != len(effects)
            or not all(e in EFFECTS for e in effects)
        ):
            raise RealmSyncError(f"{label}: effects must be distinct letters out of {EFFECTS}")
        if row["state"] not in ("confirmed", "pending"):
            raise RealmSyncError(f"{label}: state must be confirmed or pending")
        if (client, audience) in seen:
            raise RealmSyncError(f"{label}: {client} -> {audience} is listed twice")
        seen.add((client, audience))
        pairings.append(Pairing(client, audience, tuple(effects), row["state"] == "confirmed"))
    for client in sorted({p.client for p in pairings}):
        count = sum(1 for p in pairings if p.client == client and p.confirmed)
        if count > MAX_EXCHANGE_SCOPES:
            raise RealmSyncError(
                f"pairings.yaml: {client} has {count} confirmed pairings; "
                f"at most {MAX_EXCHANGE_SCOPES} exchange scopes per client"
            )
    return pairings


def _trusted(st: os.stat_result, label: object) -> None:
    """pairings.yaml grants exchange rights; only the user running papaia-ctl (or root)
    may be able to change it, never group or others."""
    if st.st_uid not in (os.geteuid(), 0):
        raise RealmSyncError(
            f"{label} is owned by uid {st.st_uid}, not by the user running papaia-ctl; "
            "it grants exchange rights"
        )
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RealmSyncError(
            f"{label} is writable by group or others; it grants exchange rights (chmod go-w)"
        )


def load_pairings(path: Path, register: Register) -> list[Pairing]:
    """The pairings in `path`; no file pairs nothing. The file and its directory must
    belong to the user running papaia-ctl and not be writable by anyone else; a
    symbolic link is refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RealmSyncError(f"{path} cannot be opened safely: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RealmSyncError(f"{path} is not a regular file")
        _trusted(st, path)
        _trusted(os.stat(path.parent), path.parent)
        if st.st_size > _MAX_FILE_BYTES:
            raise RealmSyncError(f"{path} is larger than {_MAX_FILE_BYTES} bytes")
        raw = fh.read(_MAX_FILE_BYTES + 1)
    try:
        doc = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise RealmSyncError(f"{path} is not valid YAML: {exc}") from None
    return parse_pairings(doc, register)


# ─────────────────────────────────────────────────────────────────────────
# module declarations
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Module:
    name: str
    exposes: object
    install_input: dict[str, str] = field(default_factory=dict)


def load_modules(config_dir: Path, repo_root: Path) -> list[Module]:
    """The active add-ons that declare `exposes:`, with their install input (the
    add-on's `.env` in the configuration directory).

    The module identity decides which clients a module owns, whether it may hold a
    delegation and which roles join papaia-admin. It is the deployment entry's name, and
    the manifest must carry the same `name`: an add-on installed as `foo` cannot claim to
    be `papaia-flow`."""
    modules = []
    for addon in deployment.active_addons(deployment.load(config_dir) or {}):
        name = addon.get("name")
        if not isinstance(name, str) or len(name) > 64 or not _NAME_RE.match(name):
            raise RealmSyncError(f"add-on {name!r}: not a module name")
        manifest, reason = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if manifest is None:
            raise RealmSyncError(f"add-on {name}: {reason}")
        if "exposes" not in manifest:
            continue
        declared = manifest.get("name")
        if not isinstance(declared, str) or not declared:
            raise RealmSyncError(f"add-on {name}: the manifest declares exposes but no name")
        if len(declared) > 64 or not _NAME_RE.match(declared):
            raise RealmSyncError(
                f"add-on {name}: the manifest names {declared!r}, not a module name"
            )
        if declared != name:
            raise RealmSyncError(
                f"add-on {name}: the manifest names the module {declared!r}, "
                f"but it is installed as {name!r}"
            )
        env = common.parse_env_file(config_dir / "addons" / str(name) / ".env")
        install_input = {k: kcs._compose_value(v) for k, v in env.items()}
        modules.append(Module(declared, manifest["exposes"], install_input))
    return modules


@dataclass
class ClientSpec:
    client_id: str
    owner: str
    kind: str
    token_exchange: bool
    optional_scopes: set[str] = field(default_factory=set)
    default_scopes: set[str] = field(default_factory=set)
    role_scope: set[str] = field(default_factory=set)

    def representation(self) -> dict:
        attributes = {
            MANAGED: "true",
            OWNER: _owner_value(self.owner),
            TOKEN_EXCHANGE: "true" if self.token_exchange else "false",
        }
        if self.kind in ("confidential", "public"):
            attributes["pkce.code.challenge.method"] = "S256"
        if self.kind == "public":
            attributes["oauth2.device.authorization.grant.enabled"] = "true"
        return {
            "clientId": self.client_id,
            "protocol": "openid-connect",
            **_FLAGS[self.kind],
            **_COMMON_FLAGS,
            "attributes": attributes,
        }


@dataclass
class Plan:
    clients: dict[str, ClientSpec]
    roles: dict[str, str]
    admin_members: set[str]
    exchange_scopes: dict[str, str]
    notes: list[str]


def _resolve_person(value: object, module: Module, label: str) -> str:
    if not isinstance(value, str):
        raise RealmSyncError(f"{label}: must be a string")
    match = _PLACEHOLDER_RE.match(value)
    if match:
        key = match.group(1)
        resolved = module.install_input.get(key, "")
        if not resolved or kcs._unset(resolved) or resolved.startswith("GENERATE_"):
            raise RealmSyncError(
                f"{label}: placeholder ${{{key}}} is not resolved from the install input "
                f"of {module.name}"
            )
        value = resolved
    if not _SUBJECT_RE.match(value):
        raise RealmSyncError(f"{label}: not a person identifier")
    return value


def _check_accounts(accounts: object, module: Module, register: Register, label: str) -> None:
    """Service accounts are created by their own step; here they are only checked, so a
    declaration that could never be created stops the sync before any change."""
    if not isinstance(accounts, list):
        raise RealmSyncError(f"{label}: service_accounts must be a list")
    for account in accounts:
        if not isinstance(account, dict):
            raise RealmSyncError(f"{label}: a service account must be a mapping")
        unknown = sorted(str(k) for k in set(account) - _ACCOUNT_KEYS)
        if unknown:
            raise RealmSyncError(f"{label}: service account: unknown field {', '.join(unknown)}")
        sa_label = f"{label}: service account {account.get('id')}"
        name = register.check(account.get("id"), "service-account", sa_label)
        if register.service_accounts[name].owner != module.name:
            raise RealmSyncError(f"{sa_label}: belongs to {register.service_accounts[name].owner}")
        owner = _resolve_person(account.get("owner_sub"), module, f"{sa_label}: owner_sub")
        deputy = _resolve_person(account.get("deputy_sub"), module, f"{sa_label}: deputy_sub")
        if owner == deputy:
            raise RealmSyncError(f"{sa_label}: owner_sub and deputy_sub are the same person")


def _check_delegation(delegation: object, module: Module, label: str) -> str:
    """The holder client of a valid `delegation`, or RealmSyncError."""
    if not isinstance(delegation, dict):
        raise RealmSyncError(f"{label}: delegation must be a mapping")
    unknown = sorted(str(k) for k in set(delegation) - _DELEGATION_KEYS)
    if unknown:
        raise RealmSyncError(f"{label}: delegation: unknown field {', '.join(unknown)}")
    purposes = delegation.get("purposes")
    if not isinstance(purposes, list) or not purposes:
        raise RealmSyncError(f"{label}: delegation needs at least one purpose")
    holders = {m: c for m, c in HOLDERS.values()}
    if module.name not in holders:
        raise RealmSyncError(
            f"{label}: delegation is held only by {', '.join(sorted(holders))}, "
            f"not by {module.name}"
        )
    for purpose in purposes:
        if not isinstance(purpose, str) or purpose not in PURPOSES:
            raise RealmSyncError(f"{label}: delegation: unknown purpose {purpose!r}")
        holder = HOLDERS[purpose.split(".", 1)[0]][0]
        if holder != module.name:
            raise RealmSyncError(
                f"{label}: delegation purpose {purpose} belongs to {holder}, not {module.name}"
            )
    idle = delegation.get("max_idle_days", MAX_IDLE_DAYS)
    age = delegation.get("max_age_days", MAX_AGE_DAYS)
    for key, value, limit in (
        ("max_idle_days", idle, MAX_IDLE_DAYS),
        ("max_age_days", age, MAX_AGE_DAYS),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= limit:
            raise RealmSyncError(f"{label}: delegation: {key} must be 1 to {limit}")
    if age < idle:
        raise RealmSyncError(f"{label}: delegation: max_age_days is below max_idle_days")
    return holders[module.name]


def _list(mapping: dict, key: str, label: str) -> list:
    value = mapping.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise RealmSyncError(f"{label}: {key} must be a list")
    return value


def build_plan(register: Register, modules: list[Module], pairings: list[Pairing]) -> Plan:
    """The target state of the managed objects; RealmSyncError for anything not
    acceptable. Nothing is read from or written to Keycloak here."""
    clients: dict[str, ClientSpec] = {}
    own_roles: dict[str, set[str]] = {}
    visible: set[str] = set()
    holders: set[str] = set()
    audiences: set[str] = set()
    notes: list[str] = []
    product_clients = register.product_clients()

    def manage(client_id: str, owner: str) -> None:
        if client_id in clients:
            if clients[client_id].owner != owner:
                raise RealmSyncError(
                    f"client {client_id} is claimed by {clients[client_id].owner} and {owner}"
                )
            return
        entry = product_clients[client_id]
        if client_id in _PUBLIC:
            kind = "public"
        elif client_id in _NO_SIGN_IN:
            kind = "exchange-only"
        elif (
            client_id in register.audiences
            and not entry.token_exchange
            and client_id not in _SIGN_IN_AUDIENCES
        ):
            kind = "bearer"
        else:
            kind = "confidential"
        clients[client_id] = ClientSpec(client_id, owner, kind, entry.token_exchange)

    names = [m.name for m in modules]
    for module in modules:
        label = f"module {module.name}"
        if not isinstance(module.name, str) or not _NAME_RE.match(module.name):
            raise RealmSyncError(f"{label}: not a module name")
        if names.count(module.name) > 1:
            raise RealmSyncError(f"{label}: installed twice")
        if not isinstance(module.exposes, list):
            raise RealmSyncError(f"{label}: exposes must be a list")
        roles = own_roles.setdefault(module.name, set())
        for entry in module.exposes:
            if not isinstance(entry, dict):
                raise RealmSyncError(f"{label}: an exposes entry must be a mapping")
            entry_label = f"{label}, entry {entry.get('id')}"
            if "audience" in entry:
                audience = entry["audience"]
                if isinstance(audience, str) and audience in register.audiences:
                    audiences.add(audience)
                    if audience in product_clients:
                        manage(audience, module.name)
                elif isinstance(audience, str) and register.successor(audience, "audience"):
                    register.check(audience, "audience", entry_label)
                else:
                    notes.append(f"{entry_label}: audience {audience!r} is not registered")
            for role in _list(entry, "roles", entry_label):
                if not isinstance(role, dict):
                    raise RealmSyncError(f"{entry_label}: a role must be a mapping")
                unknown = sorted(str(k) for k in set(role) - _ROLE_KEYS)
                if unknown:
                    raise RealmSyncError(f"{entry_label}: role: unknown field {', '.join(unknown)}")
                name = register.check(role.get("name"), "role", entry_label)
                if register.roles[name].owner != module.name:
                    raise RealmSyncError(
                        f"{entry_label}: role {name} belongs to {register.roles[name].owner}"
                    )
                roles.add(name)
            for surface in _list(entry, "ui", entry_label):
                if not isinstance(surface, dict):
                    raise RealmSyncError(f"{entry_label}: a ui surface must be a mapping")
                for role in _list(surface, "visible_for_roles", entry_label):
                    visible.add(register.check(role, "role", f"{entry_label}: visible_for_roles"))
            if "delegation" in entry:
                holders.add(_check_delegation(entry["delegation"], module, entry_label))
            if "service_accounts" in entry:
                _check_accounts(entry["service_accounts"], module, register, entry_label)
        if module.name in register.owners:
            for client_id, entry in product_clients.items():
                if entry.owner == module.name:
                    manage(client_id, module.name)

    exchange_scopes: dict[str, str] = {}
    for pairing in pairings:
        text = f"{pairing.client} -> {pairing.audience} ({''.join(pairing.effects)})"
        if not pairing.confirmed:
            notes.append(f"pairing waiting for approval, not assigned: {text}")
        elif pairing.client not in clients or pairing.audience not in audiences:
            notes.append(f"pairing inactive until both sides are installed: {text}")
        else:
            scope = exchange_scope(pairing.audience)
            exchange_scopes[scope] = pairing.audience
            clients[pairing.client].optional_scopes.add(scope)

    for holder in holders:
        clients[holder].optional_scopes.add(OFFLINE)

    roles = {name: "papaia" for name in PLATFORM_ROLES}
    for module_name, declared in own_roles.items():
        roles.update({name: module_name for name in declared})
    if ADMIN_ROLE in visible:
        visible.discard(ADMIN_ROLE)
        notes.append(f"visible_for_roles: {ADMIN_ROLE} is never in a module's token scope")
    for role in sorted(visible - set(roles)):
        notes.append(
            f"visible_for_roles: role {role} of {register.roles[role].owner} is not declared by "
            "an installed module; it enters the token scope once it exists"
        )
    for spec in clients.values():
        if spec.kind != "bearer":
            spec.default_scopes = set(DEFAULT_SCOPES)
            spec.role_scope = (
                own_roles.get(spec.owner, set()) | visible | set(MODULE_PLATFORM_ROLES)
            )
    admin_members = {
        name for declared in own_roles.values() for name in declared if name.endswith("-admin")
    }
    return Plan(clients, roles, admin_members, exchange_scopes, notes)


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Change:
    kind: str
    name: str
    action: str
    operation: str
    event: str = "config_changed"
    effect: str = "write"


def new_correlation_id() -> str:
    """A UUIDv7 (RFC 9562): 48 bits of Unix time in milliseconds, version, variant and
    74 random bits, as V-07 asks for a correlation id a writer creates itself."""
    millis = time.time_ns() // 1_000_000 & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (
        millis << 80 | 0x7 << 76 | (rand >> 68 & 0xFFF) << 64 | 0b10 << 62 | rand & ((1 << 62) - 1)
    )
    return str(uuid.UUID(int=value))


def _host_account() -> str:
    """The host account that runs papaia-ctl, as the subject of the audit rows."""
    uid = os.geteuid()
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = ""
    return f"host:{name if _HOST_ACCOUNT_RE.match(name) else f'uid-{uid}'}"


def seq_path(outbox: Path) -> Path:
    """The counter of `source_seq` next to the outbox; it outlives a drained outbox."""
    return outbox.with_name(f"{outbox.stem}.seq")


class AuditLog:
    """`papaia.audit/1` rows of the realm sync, appended to the core's audit outbox (one
    JSON line each, the submission form: `source`, `seq` and `prev_hash` are assigned by
    papaia-audit) with one correlation id per run.

    `source_seq` is gapless per source. Its counter lives in a file of its own, so it
    does not restart when the outbox has been delivered and emptied. The counter file is
    locked (flock) from construction to `close()`: a second papaia-ctl run waits, and
    two runs never append at the same time or reuse a number."""

    def __init__(self, path: Path, correlation_id: str, *, host_account: str | None = None) -> None:
        self.path = path
        self.correlation_id = correlation_id
        self.host_account = host_account or _host_account()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._fd: int | None = os.open(
            seq_path(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            os.fchmod(self._fd, 0o600)
            self._lock()
            self._seq = max(self._stored_seq(), self._outbox_seq())
            # Pre-flight: an outbox that cannot be appended to stops the run before the
            # first change, so no change is made that could not be audited.
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600))
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)  # releases the lock
            self._fd = None

    def _lock(self) -> None:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RealmSyncError(
                        f"another papaia-ctl run holds {seq_path(self.path)}; "
                        "run again when it has finished"
                    ) from None
                time.sleep(0.1)

    def _stored_seq(self) -> int:
        raw = os.pread(self._fd, 32, 0).decode("ascii", "replace").strip()
        if not raw:
            return 0
        if not raw.isdigit():
            raise RealmSyncError(f"{seq_path(self.path)} is not a sequence counter")
        return int(raw)

    def _outbox_seq(self) -> int:
        """The last `source_seq` still in the outbox: covers a run that stopped between
        appending a row and storing the counter."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return 0
        with os.fdopen(fd, "rb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - 65536))
            lines = [line for line in fh.read().splitlines() if line.strip()]
        if not lines:
            return 0
        try:
            return int(json.loads(lines[-1])["source_seq"])
        except (ValueError, KeyError, TypeError):
            raise RealmSyncError(f"{self.path}: the last line is not an audit row") from None

    def next_seq(self) -> int:
        return self._seq + 1

    def write(
        self, change: Change, result: str, error_code: str | None = None, *, master: bool = False
    ) -> None:
        """One row. `master`: the write was made with the master admin (creating or
        realigning the sync account), not with the sync account."""
        if self._fd is None:
            raise RealmSyncError("the audit log is closed")
        now = time.time()
        stamp = (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1000):03d}Z"
        )
        row = {
            "format": "papaia.audit/1",
            "time": stamp,
            "source_seq": self._seq + 1,
            "correlation_id": self.correlation_id,
            "writer": "papaia-ctl/realm-sync",
            "role": "caller",
            "sub": self.host_account,
            "identity_kind": None if master else "service",
            "service_account": None if master else SYNC_CLIENT,
            "azp": "admin-cli" if master else SYNC_CLIENT,
            "aud": None,
            "origin_azp": None,
            "origin_source": None,
            "origin_asserted_by": None,
            "context": None,
            "catalog_id": None,
            "operation": f"realm_sync.{change.operation}",
            "effect": change.effect,
            "object_ref": {"type": change.kind.replace("-", "_"), "id": change.name},
            "data_class": None,
            "result": result,
            "error_code": error_code,
            "client_ip": None,
            "detail": None,
            "event": change.event,
        }
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._seq += 1
        os.ftruncate(self._fd, 0)
        os.pwrite(self._fd, f"{self._seq}\n".encode("ascii"), 0)
        os.fsync(self._fd)


def audit_path(config_dir: Path) -> Path:
    return config_dir / "audit" / "outbox" / "papaia-ctl.jsonl"


class _Actions:
    """Deviations found; with `apply` each is corrected and leaves one audit row:
    `result: error` with `http_<status>` when Keycloak refuses it, or `transport` when the
    call fails on the way (Keycloak may have applied it). The outbox is checked before the
    first write (AuditLog); if a row still cannot be written after Keycloak applied the
    change, the run stops and reports a failed sync."""

    def __init__(self, call, apply: bool, audit: AuditLog | None, *, master: bool = False):
        self.call, self.apply, self.audit, self.master = call, apply, audit, master
        self.changes: list[Change] = []
        self.skipped: list[Change] = []

    def do(self, change: Change, method: str, path: str, body: object = None) -> None:
        self.changes.append(change)
        prefix = "  " if self.apply else "fail: "
        print(f"{prefix}{change.kind} {change.name}: {change.action}", flush=True)
        if not self.apply:
            return
        try:
            self.call(method, path, body)
        except urllib.error.HTTPError as exc:
            self._audit(change, "error", f"http_{exc.code}")
            raise
        except Exception:
            self._audit(change, "error", "transport")
            raise
        self._audit(change, "allowed")

    def _audit(self, change: Change, result: str, error_code: str | None = None) -> None:
        if self.audit:
            self.audit.write(change, result, error_code, master=self.master)

    def report(self, change: Change) -> None:
        """A deviation the sync does not correct: `--check` reports it, a sync stops."""
        self.changes.append(change)
        print(f"fail: {change.kind} {change.name}: {change.action}", flush=True)
        if self.apply:
            raise RealmSyncError(f"{change.kind} {change.name}: {change.action}")

    def skip(self, change: Change, reason: str) -> None:
        """A correction that cannot be addressed (an object Keycloak does not know): no
        call is made; `--check` keeps reporting it and the sync ends incomplete."""
        self.skipped.append(change)
        print(f"  note: {change.kind} {change.name}: {change.action} skipped, {reason}", flush=True)

    def by_id(self, change: Change, method: str, base: str, ref: str | None, what: str) -> None:
        """`do` on `base/<ref>`, where `ref` is the id of `what` and may not resolve."""
        if ref is None and self.apply:
            self.skip(change, f"{what} does not exist")
            return
        self.do(change, method, f"{base}/{ref}")


# ─────────────────────────────────────────────────────────────────────────
# Admin API and the sync account
# ─────────────────────────────────────────────────────────────────────────


class AdminApi:
    """The `papaia` realm's Admin REST API with one bearer token."""

    def __init__(self, base_url: str, ctx, token: str) -> None:
        self.base_url, self.ctx, self.token = base_url, ctx, token

    def call(self, method: str, path: str, body: object = None):
        req = urllib.request.Request(
            f"{self.base_url}/admin/realms/{kcs._REALM}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15, context=self.ctx) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None


def _client_credentials(base_url: str, ctx, secret: str) -> str:
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": SYNC_CLIENT, "client_secret": secret}
    ).encode()
    req = urllib.request.Request(
        f"{base_url}/realms/{kcs._REALM}/protocol/openid-connect/token", data=form, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        return json.loads(resp.read())["access_token"]


def _names(roles: list[dict]) -> str:
    return ", ".join(sorted(r["name"] for r in roles))


def align_sync_account(
    call,
    secret: str | None,
    *,
    apply: bool,
    audit: AuditLog | None = None,
    reset_secret: bool = False,
    skipped: list[Change] | None = None,
) -> list[Change]:
    """Compare the sync account with its target through the master admin's `call`: a
    confidential client with a service account, no full scope and no client scopes but
    Keycloak's own `service_account`, which maps no role; its user is in no group and
    holds exactly SYNC_RIGHTS of realm-management (and the realm's default roles), and
    exactly SYNC_RIGHTS are in its token scope. With `apply`, create the account or
    correct each deviation (`reset_secret` also writes `secret`); corrections that name a
    client scope Keycloak does not list are skipped and appended to `skipped`.

    First, before any write: the composites of these target roles must reach no
    realm-management role beyond SYNC_RIGHTS. That is a realm-wide role definition the
    sync does not change; `--check` reports it, `realm sync` stops without a write."""
    act = _Actions(call, apply, audit, master=True)
    rm = call("GET", "/clients?clientId=realm-management")[0]["id"]
    default_roles = f"default-roles-{kcs._REALM}"
    target = [call("GET", f"/roles/{urllib.parse.quote(default_roles)}")]
    target += [call("GET", f"/clients/{rm}/roles/{r}") for r in SYNC_RIGHTS]
    beyond = sorted(name for container, name in _reached(call, target) if container == rm)
    beyond = [name for name in beyond if name not in SYNC_RIGHTS]
    if beyond:
        act.report(
            Change(
                "client",
                SYNC_CLIENT,
                "a composite of its rights reaches realm-management roles beyond them: "
                + ", ".join(beyond),
                "check_sync_rights",
            )
        )
    rep = ClientSpec(SYNC_CLIENT, "papaia", "exchange-only", False).representation()
    rep.update(serviceAccountsEnabled=True, clientAuthenticatorType="client-secret")
    found = call("GET", f"/clients?clientId={SYNC_CLIENT}")
    if not found:
        body = dict(rep, secret=secret, defaultClientScopes=[], optionalClientScopes=[])
        act.do(
            Change("client", SYNC_CLIENT, "created", "create_sync_account"),
            "POST",
            "/clients",
            body,
        )
        if not apply:
            return act.changes
        found = call("GET", f"/clients?clientId={SYNC_CLIENT}")
    current = {k: v for k, v in found[0].items() if k != "secret"}
    uid = current["id"]

    drift = sorted(
        k for k, v in rep.items() if k not in ("attributes", "clientId") and current.get(k) != v
    )
    attributes = dict(current.get("attributes") or {})
    drift += sorted(k for k, v in rep["attributes"].items() if attributes.get(k) != v)
    if drift or reset_secret:
        attributes.update(rep["attributes"])
        body = {k: v for k, v in rep.items() if k != "clientId"}
        body["attributes"] = attributes
        what = [f"settings corrected ({', '.join(drift)})"] if drift else []
        if reset_secret:
            body["secret"] = secret
            what.append("secret realigned with the .env")
        act.do(
            Change("client", SYNC_CLIENT, "; ".join(what), "align_sync_account"),
            "PUT",
            f"/clients/{uid}",
            body,
        )
        if not apply and "serviceAccountsEnabled" in drift:
            return act.changes
    scope_ids = {s["name"]: s["id"] for s in call("GET", "/client-scopes") or []}
    for kind in ("default", "optional"):
        have = set(current.get(f"{kind}ClientScopes") or [])
        # Keycloak gives every service-account client its `service_account` scope (client
        # id and address claims, no roles) and puts it back when it is removed.
        for name in sorted(have - {"service_account"}):
            act.by_id(
                Change(
                    "client",
                    SYNC_CLIENT,
                    f"{kind} scope {name} removed",
                    "align_sync_account",
                    effect="delete",
                ),
                "DELETE",
                f"/clients/{uid}/{kind}-client-scopes",
                scope_ids.get(name),
                f"client scope {name}",
            )

    if "service_account" in scope_ids:
        # Its role mappings feed the account's token scope like its own scope mappings.
        base = f"/client-scopes/{scope_ids['service_account']}/scope-mappings"
        _strip_mappings(act, "client-scope", "service_account", "its scope mappings", base)

    user = call("GET", f"/clients/{uid}/service-account-user")["id"]
    # A group would give the account roles beside its own role mappings.
    for group in call("GET", f"/users/{user}/groups") or []:
        act.do(
            Change(
                "client",
                SYNC_CLIENT,
                f"left group {group.get('path') or group.get('name')}",
                "revoke_sync_rights",
                effect="delete",
            ),
            "DELETE",
            f"/users/{user}/groups/{group['id']}",
        )
    for label, base, allowed_realm in (
        ("rights", f"/users/{user}/role-mappings", {default_roles}),
        ("token scope", f"/clients/{uid}/scope-mappings", set()),
    ):
        mappings = call("GET", base) or {}
        extra = [r for r in mappings.get("realmMappings") or [] if r["name"] not in allowed_realm]
        if extra:
            act.do(
                Change(
                    "client",
                    SYNC_CLIENT,
                    f"realm roles out of its {label}: {_names(extra)}",
                    "revoke_sync_rights",
                    effect="delete",
                ),
                "DELETE",
                f"{base}/realm",
                extra,
            )
        held: set[str] = set()
        for client_id, entry in sorted((mappings.get("clientMappings") or {}).items()):
            roles = entry.get("mappings") or []
            keep = set(SYNC_RIGHTS) if entry.get("id") == rm else set()
            held |= {r["name"] for r in roles} & keep
            extra = [r for r in roles if r["name"] not in keep]
            if extra:
                act.do(
                    Change(
                        "client",
                        SYNC_CLIENT,
                        f"{client_id} roles out of its {label}: {_names(extra)}",
                        "revoke_sync_rights",
                        effect="delete",
                    ),
                    "DELETE",
                    f"{base}/clients/{entry['id']}",
                    extra,
                )
        missing = [r for r in SYNC_RIGHTS if r not in held]
        if missing:
            reps = [call("GET", f"/clients/{rm}/roles/{r}") for r in missing] if apply else []
            act.do(
                Change(
                    "client",
                    SYNC_CLIENT,
                    f"realm-management roles added to its {label}: {', '.join(missing)}",
                    "grant_sync_rights",
                ),
                "POST",
                f"{base}/clients/{rm}",
                reps,
            )
    if skipped is not None:
        skipped.extend(act.skipped)
    return act.changes


def _strip_mappings(act: _Actions, kind: str, name: str, label: str, base: str) -> None:
    """Remove every role scope mapping under `base`: one change per role container."""
    mappings = act.call("GET", base) or {}
    realm_roles = mappings.get("realmMappings") or []
    if realm_roles:
        act.do(
            Change(
                kind,
                name,
                f"realm roles out of {label}: {_names(realm_roles)}",
                "remove_scope_role",
                effect="delete",
            ),
            "DELETE",
            f"{base}/realm",
            realm_roles,
        )
    for client_id, entry in sorted((mappings.get("clientMappings") or {}).items()):
        roles = entry.get("mappings") or []
        if roles:
            act.do(
                Change(
                    kind,
                    name,
                    f"{client_id} roles out of {label}: {_names(roles)}",
                    "remove_scope_role",
                    effect="delete",
                ),
                "DELETE",
                f"{base}/clients/{entry['id']}",
                roles,
            )


def _reached(call, roles: list[dict]) -> set[tuple[str, str]]:
    """The client roles (container id, name) that `roles` bring in through their
    composites, transitively; the roles themselves are not included."""
    reached: set[tuple[str, str]] = set()
    seen: set[str] = set()
    todo = [r for r in roles if r.get("composite")]
    while todo:
        role = todo.pop()
        if role["id"] in seen:
            continue
        seen.add(role["id"])
        for inner in call("GET", f"/roles-by-id/{role['id']}/composites") or []:
            if inner.get("clientRole"):
                reached.add((inner.get("containerId"), inner["name"]))
            if inner.get("composite"):
                todo.append(inner)
    return reached


def sync_account_token(
    base_url: str,
    ctx,
    admin_password: str,
    secret: str,
    audit: AuditLog | None = None,
    *,
    apply: bool = True,
) -> tuple[str | None, list[Change], list[Change]]:
    """Check the sync account with the master admin on every run, then sign in with it.
    With `apply`, the account is created or realigned (also its secret, when its own
    sign-in is refused). Without `apply` (`--check`) nothing is written: the token is
    None when the account cannot sign in. Returns the token, the deviations found and
    the corrections skipped because a client scope they name does not resolve."""
    master = AdminApi(base_url, ctx, kcs._get_admin_token(base_url, ctx, admin_password)).call
    skipped: list[Change] = []
    changes = align_sync_account(master, secret, apply=apply, audit=audit, skipped=skipped)
    try:
        return _client_credentials(base_url, ctx, secret), changes, skipped
    except urllib.error.HTTPError as exc:
        if exc.code not in (400, 401):
            raise
    if not apply:
        refused = Change(
            "client", SYNC_CLIENT, "sign-in refused with the secret of the .env", "sign_in"
        )
        print(f"fail: client {SYNC_CLIENT}: {refused.action}", flush=True)
        return None, [*changes, refused], skipped
    changes += align_sync_account(
        master, secret, apply=True, audit=audit, reset_secret=True, skipped=skipped
    )
    return _client_credentials(base_url, ctx, secret), changes, skipped


def sync_token(
    base_url: str, ctx, admin_password: str, secret: str, audit: AuditLog | None = None
) -> str:
    """An access token of the sync account, which is created or realigned first."""
    token, _, _ = sync_account_token(base_url, ctx, admin_password, secret, audit, apply=True)
    if token is None:
        raise RealmSyncError(f"{SYNC_CLIENT} cannot sign in")
    return token


# ─────────────────────────────────────────────────────────────────────────
# reconcile
# ─────────────────────────────────────────────────────────────────────────

_SCOPE_ATTRIBUTES = {
    MANAGED: "true",
    "include.in.token.scope": "true",
    "display.on.consent.screen": "false",
}
_AUDIENCE_MAPPERS = frozenset({"oidc-audience-mapper", "oidc-audience-resolve-mapper"})


def _exchange_event(scope_name: str) -> str:
    return (
        "exchange_right_changed"
        if scope_name.startswith("aud-") or scope_name == OFFLINE
        else "config_changed"
    )


def _audience_mapper(audience: str) -> dict:
    return {
        "name": "audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.client.audience": audience,
            "access.token.claim": "true",
            "id.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


def _mapper_matches(mapper: dict, audience: str) -> bool:
    wanted = _audience_mapper(audience)
    config = mapper.get("config") or {}
    return mapper.get("protocolMapper") == wanted["protocolMapper"] and all(
        config.get(k) == v for k, v in wanted["config"].items()
    )


def _adds_audience(mapper: dict) -> bool:
    """A client-level mapper that puts an audience into the token: the audience mappers
    and any mapper writing the `aud` claim. Audiences come only from `aud-*` scopes."""
    config = mapper.get("config") or {}
    return mapper.get("protocolMapper") in _AUDIENCE_MAPPERS or config.get("claim.name") == "aud"


def _own_resolve_mapper(scope_name: str, mapper: dict) -> bool:
    """Keycloak's audience resolve mapper of the `roles` scope: it adds the clients whose
    client roles are in the token, and no client role reaches a managed client's token
    scope (role scope, scope mappings and its own roles are checked)."""
    return scope_name == "roles" and mapper.get("protocolMapper") == "oidc-audience-resolve-mapper"


# Mappers that put a role into the token whatever the token scope says.
_ROLE_MAPPERS = frozenset({"oidc-hardcoded-role-mapper", "oidc-role-name-mapper"})
# Keycloak's own role mappers (those of the `roles` scope) only show the roles already in
# the token scope; they may write `roles`, `realm_access` or `resource_access`.
_SCOPED_ROLE_MAPPERS = frozenset(
    {"oidc-usermodel-realm-role-mapper", "oidc-usermodel-client-role-mapper"}
)
_ROLE_CLAIMS = ("realm_access", "resource_access", "roles")


def _adds_role(mapper: dict) -> bool:
    """A mapper that can put a role into the token beyond the token scope: a hardcoded
    role, a renamed role, a script, or any other mapper writing a role claim."""
    kind = mapper.get("protocolMapper") or ""
    if kind in _ROLE_MAPPERS or kind.startswith("script-"):
        return True
    if kind in _SCOPED_ROLE_MAPPERS:
        return False
    claim = str((mapper.get("config") or {}).get("claim.name") or "")
    return any(claim == c or claim.startswith(f"{c}.") for c in _ROLE_CLAIMS)


def _is_managed(role: dict | None) -> bool:
    value = ((role or {}).get("attributes") or {}).get(MANAGED)
    return value == "true" or value == ["true"]


class _Reconciler(_Actions):
    def __init__(self, call, plan: Plan, apply: bool, audit: AuditLog | None) -> None:
        super().__init__(call, apply, audit)
        self.plan = plan
        self.role_info: dict[str, dict] = {}
        self.client_names: dict[str, str] = {}
        self._expanded: dict[str, tuple[set[str], set[str]]] = {}
        self._noted: set[str] = set()

    def _note(self, text: str) -> None:
        if text not in self._noted:
            self._noted.add(text)
            print(f"  note: {text}", flush=True)

    def _scopes(self) -> dict[str, dict]:
        return {s["name"]: s for s in self.call("GET", "/client-scopes") or []}

    def _clients(self) -> dict[str, dict]:
        # GET /clients carries the secrets of confidential clients; they are dropped here.
        clients = self.call("GET", "/clients") or []
        return {c["clientId"]: {k: v for k, v in c.items() if k != "secret"} for c in clients}

    def _roles(self) -> dict[str, dict]:
        return {r["name"]: r for r in self.call("GET", "/roles?briefRepresentation=false") or []}

    def run(self) -> list[Change]:
        self.roles()
        self.exchange_scopes()
        self.realm_defaults()
        self.shared_scopes()
        scopes = self._scopes()
        clients = self._clients()
        self.client_names = {c["id"]: client_id for client_id, c in clients.items()}
        for client_id in sorted(self.plan.clients):
            self.client(self.plan.clients[client_id], clients.get(client_id), scopes)
        self.exchange_elsewhere(clients, scopes)
        for client_id, client in sorted(clients.items()):
            managed = (client.get("attributes") or {}).get(MANAGED) == "true"
            if managed and client_id not in self.plan.clients and client_id != SYNC_CLIENT:
                print(
                    f"WARNING: managed client {client_id} has no declaration any more; it is "
                    "left in place. Remove it in the admin console once its module is gone.",
                    file=sys.stderr,
                    flush=True,
                )
        return self.changes

    # roles ----------------------------------------------------------------
    def roles(self) -> None:
        self.role_info = self._roles()
        existing = set(self.role_info)
        changed = False
        for name in sorted(self.plan.roles):
            if name in existing:
                continue
            owner = self.plan.roles[name]
            rep = {
                "name": name,
                "description": f"{_owner_value(owner)} role",
                "attributes": {MANAGED: ["true"], OWNER: [_owner_value(owner)]},
            }
            self.do(Change("role", name, "created", "create_role"), "POST", "/roles", rep)
            changed = True
        members: dict[str, dict] = {}
        admin = urllib.parse.quote(ADMIN_ROLE)
        if ADMIN_ROLE in existing:
            members = {
                r["name"]: r for r in self.call("GET", f"/roles/{admin}/composites/realm") or []
            }
        for name in sorted(self.plan.admin_members - set(members)):
            rep = self.call("GET", f"/roles/{urllib.parse.quote(name)}") if self.apply else None
            self.do(
                Change("role", ADMIN_ROLE, f"{name} added to the composite", "add_composite"),
                "POST",
                f"/roles/{admin}/composites",
                [rep],
            )
            changed = True
        for name in sorted(members):
            stale_admin = (
                name.endswith("-admin")
                and name not in self.plan.admin_members
                and _is_managed(self.role_info.get(name))
            )
            if name in NOT_IN_ADMIN or stale_admin:
                self.do(
                    Change(
                        "role",
                        ADMIN_ROLE,
                        f"{name} removed from the composite",
                        "remove_composite",
                        effect="delete",
                    ),
                    "DELETE",
                    f"/roles/{admin}/composites",
                    [members[name]],
                )
                changed = True
        if changed and self.apply:
            self.role_info = self._roles()

    def _expand(self, name: str, visiting: frozenset[str] = frozenset()) -> tuple[set, set]:
        """The realm roles and the client roles (`client:role`) a role brings into a
        token through its composite, transitively."""
        if name in self._expanded:
            return self._expanded[name]
        realm: set[str] = set()
        client: set[str] = set()
        if (self.role_info.get(name) or {}).get("composite") and name not in visiting:
            path = f"/roles/{urllib.parse.quote(name)}/composites"
            for role in self.call("GET", path) or []:
                if role.get("clientRole"):
                    owner = self.client_names.get(role.get("containerId"), "client")
                    client.add(f"{owner}:{role['name']}")
                    continue
                realm.add(role["name"])
                inner_realm, inner_client = self._expand(role["name"], visiting | {name})
                realm |= inner_realm
                client |= inner_client
        self._expanded[name] = (realm, client)
        return realm, client

    def _token_scope(self, spec: ClientSpec) -> set[str]:
        """The roles of the client's token scope: the planned ones that exist (or are
        created by this run), without papaia-admin and without any role whose composite
        reaches beyond the set or into client roles."""
        known = set(self.role_info) | set(self.plan.roles)
        wanted = {r for r in spec.role_scope if r in known and r != ADMIN_ROLE}
        while True:
            dropped = set()
            for role in sorted(wanted):
                realm, client = self._expand(role)
                outside = sorted((realm - wanted) | client)
                if outside:
                    dropped.add(role)
                    self._note(
                        f"role {role} is not mapped into the token scope of {spec.client_id}: "
                        f"its composite reaches {', '.join(outside)}"
                    )
            if not dropped:
                return wanted
            wanted -= dropped

    # exchange scopes ------------------------------------------------------
    def exchange_scopes(self) -> None:
        scopes = self._scopes()
        for name, audience in sorted(self.plan.exchange_scopes.items()):
            scope = scopes.get(name)
            if scope is None:
                rep = {
                    "name": name,
                    "protocol": "openid-connect",
                    "attributes": dict(_SCOPE_ATTRIBUTES),
                    "protocolMappers": [_audience_mapper(audience)],
                }
                self.do(
                    Change(
                        "client-scope", name, "created", "create_scope", "exchange_right_changed"
                    ),
                    "POST",
                    "/client-scopes",
                    rep,
                )
                continue
            self.scope_settings(name, scope)
            # An exchange scope carries an audience and no role (also when adopted).
            self.scope_roles(name, scope["id"], set(), "exchange_right_changed")
            mappers = scope.get("protocolMappers") or []
            if len(mappers) == 1 and _mapper_matches(mappers[0], audience):
                continue
            base = f"/client-scopes/{scope['id']}/protocol-mappers/models"
            for mapper in mappers:
                self.do(
                    Change(
                        "client-scope",
                        name,
                        f"mapper {mapper.get('name')} removed",
                        "remove_mapper",
                        "exchange_right_changed",
                        "delete",
                    ),
                    "DELETE",
                    f"{base}/{mapper['id']}",
                )
            self.do(
                Change(
                    "client-scope",
                    name,
                    f"audience mapper set to {audience}",
                    "set_mapper",
                    "exchange_right_changed",
                ),
                "POST",
                base,
                _audience_mapper(audience),
            )
        for name, scope in sorted(scopes.items()):
            managed = (scope.get("attributes") or {}).get(MANAGED) == "true"
            if managed and name.startswith("aud-") and name not in self.plan.exchange_scopes:
                self.do(
                    Change(
                        "client-scope",
                        name,
                        "removed, no confirmed pairing",
                        "delete_scope",
                        "exchange_right_changed",
                        "delete",
                    ),
                    "DELETE",
                    f"/client-scopes/{scope['id']}",
                )

    def scope_settings(self, name: str, scope: dict) -> None:
        """Protocol and attributes of an exchange scope. A scope that a module's own
        setup created is adopted: it gets `papaia.managed=true`, so revoking its last
        confirmed pairing removes it."""
        attributes = dict(scope.get("attributes") or {})
        drift = ["protocol"] if scope.get("protocol") != "openid-connect" else []
        drift += sorted(k for k, v in _SCOPE_ATTRIBUTES.items() if attributes.get(k) != v)
        if not drift:
            return
        action = (
            "adopted as managed"
            if attributes.get(MANAGED) != "true"
            else f"settings corrected ({', '.join(drift)})"
        )
        attributes.update(_SCOPE_ATTRIBUTES)
        self.do(
            Change("client-scope", name, action, "update_scope", "exchange_right_changed"),
            "PUT",
            f"/client-scopes/{scope['id']}",
            {
                "id": scope["id"],
                "name": name,
                "protocol": "openid-connect",
                "attributes": attributes,
            },
        )

    def scope_roles(self, name: str, scope_id: str, keep: set[str], event: str) -> None:
        """Remove every role scope mapping of a client scope but the realm roles in
        `keep`: Keycloak adds a scope's mapped roles to every token issued with it, also
        to an exchanged one and with `fullScopeAllowed: false`. One row per role."""
        base = f"/client-scopes/{scope_id}/scope-mappings"
        mappings = self.call("GET", base) or {}
        for role in sorted(mappings.get("realmMappings") or [], key=lambda r: r["name"]):
            if role["name"] in keep:
                continue
            self.do(
                Change(
                    "client-scope",
                    name,
                    f"realm role {role['name']} out of its scope mappings",
                    "remove_scope_role",
                    event,
                    "delete",
                ),
                "DELETE",
                f"{base}/realm",
                [role],
            )
        for client_id, entry in sorted((mappings.get("clientMappings") or {}).items()):
            for role in sorted(entry.get("mappings") or [], key=lambda r: r["name"]):
                self.do(
                    Change(
                        "client-scope",
                        name,
                        f"{client_id} role {role['name']} out of its scope mappings",
                        "remove_scope_role",
                        event,
                        "delete",
                    ),
                    "DELETE",
                    f"{base}/clients/{entry['id']}",
                    [role],
                )

    def shared_scopes(self) -> None:
        """Keycloak's default scopes and `offline_access` are shared by every managed
        client. They map no role, except `offline_access`, which maps only its own role,
        and that role is no composite; they carry no role-adding mapper and no mapper
        that adds an audience (but Keycloak's audience resolve mapper of `roles`).
        Everything else is removed: it would put a role or a fixed audience into every
        managed client's token, also an exchanged one."""
        scopes = self._scopes()
        for name in sorted(DEFAULT_SCOPES | {OFFLINE}):
            scope = scopes.get(name)
            if scope is None:
                continue
            event = _exchange_event(name)
            keep = {OFFLINE} if name == OFFLINE else set()
            self.scope_roles(name, scope["id"], keep, event)
            for mapper in scope.get("protocolMappers") or []:
                if _adds_audience(mapper) and not _own_resolve_mapper(name, mapper):
                    why, mapper_event = "adds an audience", "exchange_right_changed"
                elif _adds_role(mapper):
                    why, mapper_event = "adds roles", event
                else:
                    continue
                self.do(
                    Change(
                        "client-scope",
                        name,
                        f"mapper {mapper.get('name')} removed ({why})",
                        "remove_mapper",
                        mapper_event,
                        "delete",
                    ),
                    "DELETE",
                    f"/client-scopes/{scope['id']}/protocol-mappers/models/{mapper['id']}",
                )
        if (self.role_info.get(OFFLINE) or {}).get("composite"):
            path = f"/roles/{OFFLINE}/composites"
            for role in self.call("GET", path) or []:
                owner = self.client_names.get(role.get("containerId")) or self._client_name(
                    role.get("containerId")
                )
                label = f"{owner}:{role['name']}" if role.get("clientRole") else role["name"]
                self.do(
                    Change(
                        "role",
                        OFFLINE,
                        f"{label} removed from the composite",
                        "remove_composite",
                        "exchange_right_changed",
                        "delete",
                    ),
                    "DELETE",
                    path,
                    [role],
                )

    def _client_name(self, uid: str | None) -> str:
        if uid and not self.client_names:
            self.client_names = {c["id"]: cid for cid, c in self._clients().items()}
        return self.client_names.get(uid or "", "client")

    def realm_defaults(self) -> None:
        """Neither `offline_access` nor an exchange scope is a default or optional scope
        of new clients: both are assigned per client only."""
        for kind in ("default", "optional"):
            for scope in self.call("GET", f"/default-{kind}-client-scopes") or []:
                name = scope["name"]
                if name == OFFLINE or name.startswith("aud-"):
                    self.do(
                        Change(
                            "realm",
                            kcs._REALM,
                            f"{name} removed from the {kind} scopes of new clients",
                            "remove_default_scope",
                            "exchange_right_changed",
                            "delete",
                        ),
                        "DELETE",
                        f"/default-{kind}-client-scopes/{scope['id']}",
                    )

    # clients --------------------------------------------------------------
    def client(self, spec: ClientSpec, current: dict | None, scopes: dict[str, dict]) -> None:
        rep = spec.representation()
        if current is None:
            rep["defaultClientScopes"] = sorted(spec.default_scopes)
            rep["optionalClientScopes"] = sorted(spec.optional_scopes)
            event = "exchange_right_changed" if spec.optional_scopes else "config_changed"
            self.do(
                Change("client", spec.client_id, "created", "create_client", event),
                "POST",
                "/clients",
                rep,
            )
            if not self.apply or not spec.role_scope:
                return
            current = self._clients()[spec.client_id]
            self.role_scope(spec, current["id"])
            return

        uid = current["id"]
        drift = sorted(
            k for k, v in rep.items() if k not in ("attributes", "clientId") and current.get(k) != v
        )
        attributes = dict(current.get("attributes") or {})
        drift += sorted(k for k, v in rep["attributes"].items() if attributes.get(k) != v)
        if drift:
            attributes.update(rep["attributes"])
            body = {k: v for k, v in rep.items() if k != "clientId"}
            body["attributes"] = attributes
            self.do(
                Change(
                    "client",
                    spec.client_id,
                    f"settings corrected ({', '.join(drift)})",
                    "update_client",
                ),
                "PUT",
                f"/clients/{uid}",
                body,
            )
        for mapper in current.get("protocolMappers") or []:
            if _adds_audience(mapper):
                why, event = "fixed audience", "exchange_right_changed"
            elif _adds_role(mapper):
                why, event = "adds roles", "config_changed"
            else:
                continue
            self.do(
                Change(
                    "client",
                    spec.client_id,
                    f"mapper {mapper.get('name')} removed ({why})",
                    "remove_client_mapper",
                    event,
                    "delete",
                ),
                "DELETE",
                f"/clients/{uid}/protocol-mappers/models/{mapper['id']}",
            )
        for kind, wanted in (("default", spec.default_scopes), ("optional", spec.optional_scopes)):
            have = set(current.get(f"{kind}ClientScopes") or [])
            base = f"/clients/{uid}/{kind}-client-scopes"
            for name in sorted(have - wanted):
                self.by_id(
                    Change(
                        "client",
                        spec.client_id,
                        f"{kind} scope {name} removed",
                        "remove_scope",
                        _exchange_event(name),
                        "delete",
                    ),
                    "DELETE",
                    base,
                    (scopes.get(name) or {}).get("id"),
                    f"client scope {name}",
                )
            for name in sorted(wanted - have):
                self.by_id(
                    Change(
                        "client",
                        spec.client_id,
                        f"{kind} scope {name} added",
                        "add_scope",
                        _exchange_event(name),
                    ),
                    "PUT",
                    base,
                    (scopes.get(name) or {}).get("id"),
                    f"client scope {name}",
                )
        self.role_scope(spec, uid)
        self.client_roles(spec, uid)

    def client_roles(self, spec: ClientSpec, uid: str) -> None:
        """Keycloak puts a client's own client roles into its token scope, with their
        composites, whatever `fullScopeAllowed` says. Module roles are realm roles, so a
        client role of a managed client includes nothing but other roles of that client:
        every other composite is removed, one row each."""
        roles = self.call("GET", f"/clients/{uid}/roles") or []
        for role in sorted(roles, key=lambda r: r["name"]):
            if not role.get("composite"):
                continue
            path = f"/roles-by-id/{role['id']}/composites"
            inner = self.call("GET", path) or []
            for other in sorted(inner, key=lambda r: (r.get("containerId") or "", r["name"])):
                if other.get("clientRole") and other.get("containerId") == uid:
                    continue
                label = (
                    f"{self._client_name(other.get('containerId'))}:{other['name']}"
                    if other.get("clientRole")
                    else other["name"]
                )
                self.do(
                    Change(
                        "client",
                        spec.client_id,
                        f"role {role['name']} no longer includes {label}",
                        "remove_client_role_composite",
                        effect="delete",
                    ),
                    "DELETE",
                    path,
                    [other],
                )

    def role_scope(self, spec: ClientSpec, uid: str) -> None:
        mappings = self.call("GET", f"/clients/{uid}/scope-mappings") or {}
        path = f"/clients/{uid}/scope-mappings/realm"
        wanted = self._token_scope(spec)
        have = {r["name"]: r for r in mappings.get("realmMappings") or []}
        missing = sorted(wanted - set(have))
        extra = sorted(set(have) - wanted)
        if missing:
            reps = (
                [self.call("GET", f"/roles/{urllib.parse.quote(n)}") for n in missing]
                if self.apply
                else []
            )
            self.do(
                Change(
                    "client",
                    spec.client_id,
                    f"roles in token scope: {', '.join(missing)}",
                    "add_role_scope",
                ),
                "POST",
                path,
                reps,
            )
        if extra:
            self.do(
                Change(
                    "client",
                    spec.client_id,
                    f"roles out of token scope: {', '.join(extra)}",
                    "remove_role_scope",
                    effect="delete",
                ),
                "DELETE",
                path,
                [have[n] for n in extra],
            )
        # Module roles are realm roles; no client role belongs in a module client's scope.
        for client_id, entry in sorted((mappings.get("clientMappings") or {}).items()):
            roles = entry.get("mappings") or []
            if roles:
                self.do(
                    Change(
                        "client",
                        spec.client_id,
                        f"{client_id} roles out of token scope: {_names(roles)}",
                        "remove_client_role_scope",
                        effect="delete",
                    ),
                    "DELETE",
                    f"/clients/{uid}/scope-mappings/clients/{entry['id']}",
                    roles,
                )

    def exchange_elsewhere(self, clients: dict[str, dict], scopes: dict[str, dict]) -> None:
        """No client but an installed holder whose module declares delegation has
        offline_access, and no client but a managed one with a confirmed pairing has an
        `aud-*` scope (managed clients get exactly their planned scopes in `client`;
        pairings name only register clients, which are managed once installed). A holder
        or register client without an installed module is treated like any other client.
        Bearer-only clients never obtain a token, so a scope there has no effect;
        Keycloak's own `realm-management` is one of them and cannot be changed from
        inside the realm."""
        for client_id, client in sorted(clients.items()):
            if client_id in self.plan.clients or client.get("bearerOnly"):
                continue
            for kind in ("default", "optional"):
                for name in sorted(client.get(f"{kind}ClientScopes") or []):
                    if name != OFFLINE and not name.startswith("aud-"):
                        continue
                    self.by_id(
                        Change(
                            "client",
                            client_id,
                            f"{kind} scope {name} removed",
                            "remove_scope",
                            "exchange_right_changed",
                            "delete",
                        ),
                        "DELETE",
                        f"/clients/{client['id']}/{kind}-client-scopes",
                        (scopes.get(name) or {}).get("id"),
                        f"client scope {name}",
                    )


def reconcile(call, plan: Plan, *, apply: bool, audit: AuditLog | None = None) -> list[Change]:
    """Compare the realm behind `call` with `plan`; with `apply`, correct every deviation.
    Returns the deviations found (= the changes made when applying)."""
    return _Reconciler(call, plan, apply, audit).run()


# ─────────────────────────────────────────────────────────────────────────
# entry point
# ─────────────────────────────────────────────────────────────────────────


def sync(tree: dict, config_dir: Path, repo_root: Path, *, check: bool = False) -> int:
    """`papaia-ctl realm sync [--check]`. 0: in line (or corrected), 1: deviations found
    by --check or Keycloak not reachable, 2: a declaration was refused (nothing changed)."""
    root = tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        print("Realm sync skipped: AUTH_PROVIDER is not internal_keycloak.", flush=True)
        return 0
    try:
        register = load_register()
        plan = build_plan(
            register,
            load_modules(config_dir, repo_root),
            load_pairings(pairings_path(config_dir), register),
        )
    except RealmSyncError as exc:
        print(f"Realm sync refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    for note in plan.notes:
        print(f"  {note}", flush=True)

    keycloak = tree.get(kcs._KEYCLOAK_NODE, {})
    admin_password = kcs._compose_value(keycloak.get("KC_ADMIN_PASSWORD", ""))
    secret = kcs._compose_value(keycloak.get(SYNC_SECRET_KEY, ""))
    if kcs._unset(secret) or secret.startswith("GENERATE_"):
        print(
            f"Realm sync skipped: {SYNC_SECRET_KEY} is not set in {kcs._KEYCLOAK_NODE}/.env. "
            "Run 'papaia-ctl setup' first.",
            file=sys.stderr,
            flush=True,
        )
        return 1
    base_url, ctx = kcs._admin_connection(root, config_dir)
    try:
        audit = None if check else AuditLog(audit_path(config_dir), new_correlation_id())
    except (RealmSyncError, OSError) as exc:
        print(f"Realm sync refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    try:
        with audit or contextlib.nullcontext():
            kcs._wait_for_keycloak(base_url, ctx)
            token, changes, skipped = sync_account_token(
                base_url, ctx, admin_password, secret, audit, apply=not check
            )
            if token is None:
                print(
                    f"Realm check: fail ({len(changes)} deviation(s)); the sync account cannot "
                    "sign in, so the rest of the realm was not compared.",
                    flush=True,
                )
                return 1
            api = AdminApi(base_url, ctx, token)
            reconciler = _Reconciler(api.call, plan, not check, audit)
            changes += reconciler.run()
            skipped += reconciler.skipped
    except RealmSyncError as exc:
        print(f"Realm sync stopped: {exc}", file=sys.stderr, flush=True)
        return 1
    except TimeoutError as exc:
        print(f"Realm sync skipped: {exc}", file=sys.stderr, flush=True)
        return 1
    except urllib.error.HTTPError as exc:
        path = urllib.parse.urlsplit(exc.url or "").path
        print(f"Realm sync failed: HTTP {exc.code} on {path}", file=sys.stderr, flush=True)
        return 1
    except OSError as exc:
        print(f"Realm sync failed: {exc}", file=sys.stderr, flush=True)
        return 1
    if check:
        print(
            f"Realm check: {'fail' if changes else 'ok'} ({len(changes)} deviation(s)).", flush=True
        )
        return 1 if changes else 0
    if skipped:
        print(
            f"Realm sync incomplete: {len(changes)} change(s), {len(skipped)} "
            "skipped because an object they name does not exist (see the notes above).",
            flush=True,
        )
        return 1
    print(f"Realm sync complete: {len(changes)} change(s).", flush=True)
    return 0
