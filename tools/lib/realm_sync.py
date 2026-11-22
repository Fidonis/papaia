"""`papaia-ctl realm sync`: clients, roles and exchange scopes of the realm from declarations.

The core is the only writer of realm-wide objects. This module derives them from three
sources and reconciles the live `papaia` realm with them, idempotently:

- the naming register (`names_register.json`, a snapshot of the platform kit's register:
  every client, audience, role and service account with its owning repository);
- the `exposes:` sections of the installed modules (active add-ons): the roles they
  declare, the audiences they serve, `delegation` and `service_accounts`;
- `$PAPAIA_CONFIG_DIR/security/pairings.yaml`: which client may exchange tokens for which
  audience. Only confirmed pairings count; a pairing waiting for approval assigns nothing,
  and a confirmed write pairing (effect `w` or `d`) names two different host accounts
  (`requested_by`, `confirmed_by`; `pairing_approval` writes the file).

The core serves audiences of its own under its profiles: `papaia-people` (the people
lookup, profile `people`, lib/people_account.py) is a bearer-only resource server for
persons only, and only `assist-gate` may exchange for it, with effect x (security 1.4).

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
- no client-level mapper on a managed client that adds an audience or a role, and no
  `oidc-claims-param-token-mapper` (it takes claims from the request) on a managed client
  or a shared scope;
- no exchange client but the chain holder is an audience: no scope `aud-<client>` and no
  audience mapper naming it, anywhere in the realm (`flow-engine` included);
- Data's two clients: the chain holder `papaia-data` signs nobody in and carries the
  attribute `papaia.chain-holder=true`; `papaia-data-ui`, the sign-in client of Data's own
  interface, authenticates with `private_key_jwt` (Keycloak's `client-jwt`; the module
  registers its own public key through `client_keys`; undeclared, the sync leaves a
  registered key in place). No other client carries
  the attribute, whatever its value: the sync removes it (`--check` reports it);
- the client policies the identity provider enforces: per pair of `aud-*` scopes of one
  client a policy `papaia-one-aud-<x>-<y>` that rejects a sign-in or an exchange asking
  for both (`reject-request`); Data's `data-chain` for the client named by
  `papaia.chain-holder=true` (the subject token's `azp` is one of Data's
  `upstream_origins`, first delivery only Studio, and its `aud` is exactly
  `papaia-data`), `data-self` for every other Data client
  (only an own session token of `papaia-data-ui` that carries no `aud-*` scope yet: one
  hop) and, with `aud-papaia-studio`, `data-handover`; per person-only audience (Data, the
  knowledge map, module APIs for Me, any audience declared `identity: [person]`) no
  `client_credentials` and no exchange without `sid`. Other policies and profiles of
  the realm are left as they are;
- Flow's console `flow-console`: `private_key_jwt` (Keycloak holds the public key Flow
  declares in `client_keys`; the sync writes no private key material), the shared person scope
  `papaia-person` as its only default scope, `aud-flow` as an optional sign-in scope
  while Flow serves `flow`, and pairings only for the task sources `papaia-data` and
  `papaia-studio`; no client with token exchange keeps an `aud-*` default scope;
- a client role of a managed client includes no role but other roles of that client:
  Keycloak puts a client's own roles, with their composites, into its token scope
  whatever `fullScopeAllowed` says;
- the name list of the Paperless gate, `$PAPAIA_CONFIG_DIR/security/paperless-gate/
  users.json`: the user names of the active persons (no service account) that hold a
  role of the module serving `mcp-paperless`, directly, through a group or through a
  composite. It is rewritten when the realm changes, so an account that is deleted,
  deactivated or loses the role is gone after the next run, and removed when no module
  serves `mcp-paperless` any more. Keycloak's accounts are read with the master admin
  (the sync account holds no `view-users`); the list is the only thing that reads them.
- the public keys of module clients (`client_keys[]` of a manifest, lib/client_keys.py):
  for each client the module owns and declares, `client-jwt` and exactly the public JWK
  set of the file the module wrote to its add-on configuration folder; a changed file is
  applied on the next run or by `papaia-ctl realm keys apply <module>`;
- one client per declared service account (`svc-<module>-<purpose>`): client_credentials
  with `private_key_jwt` only, the key pair in the configuration directory, only the
  declared audiences (`aud-*` optional scopes) and roles, owner, deputy and rotation
  recorded; undeclared service accounts are removed. The service-account users' roles
  and groups and the realm's event settings (last use = CLIENT_LOGIN events) are
  changed with the master admin, which the sync account cannot.

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

Realm hardening (`realm_hardening`): the realm settings of the security profile, no password
grant and no implicit flow at any client, PKCE S256 at public clients, redirect URIs only
of the configured hosts, and the client policy `papaia-hardening` for managed clients,
which is written last, once every managed client carries PKCE S256.
"""

from __future__ import annotations

import contextlib
import fcntl
import itertools
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

from . import client_keys as ck
from . import common, delegation_lifetime, deployment, uninstall_journal
from . import keycloak_role_sync as kcs
from . import realm_hardening as rh
from . import service_account_keys as sak

REGISTER_PATH = Path(__file__).with_name("names_register.json")
REGISTER_FORMAT = "papaia.names-register-snapshot/1"
PAIRINGS_FORMAT = "papaia.pairings/1"

SYNC_CLIENT = "svc-papaia-realm-sync"
# Core accounts the realm sync keeps outside the module declarations: its own, the one
# of papaia-lifecycle (lib/lifecycle_account.py) and the one of papaia-people
# (lib/people_account.py). Keycloak's `admin-permissions` client (admin permissions
# switched on for papaia-lifecycle) carries a service account Keycloak needs for its
# authorization settings.
CORE_ACCOUNTS = frozenset(
    {SYNC_CLIENT, "svc-papaia-lifecycle", "svc-papaia-people", "admin-permissions"}
)
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
# Effects that make a pairing a write pairing (security 1.4: a second person confirms it).
WRITE_EFFECTS = frozenset({"w", "d"})
CHAIN_HOLDER = "papaia-data"
# The client attribute that names the chain holder positively in `data-chain`; set on
# CHAIN_HOLDER alone (security 1.5 no. 2).
CHAIN_HOLDER_MARK = "papaia.chain-holder"
# Data's own interface: signs persons in, exchanges only its own session token, in one hop.
DATA_UI = "papaia-data-ui"
# The clients whose tokens the chain holder may exchange further. First delivery: only
# Studio (Studio -> Data -> connection); the assistant and Flow are no origins, and any
# extension comes with its own acceptance. A Data client is never an origin.
CHAIN_ORIGINS = ("papaia-studio-gateway",)
_MAX_ORIGINS = 8
IDENTITIES = ("person", "service")
# Audiences that admit persons only, whatever a manifest says: Data and the knowledge map;
# every module API for Me (`kind: me`) as well.
PERSON_ONLY_AUDIENCES = frozenset({CHAIN_HOLDER, "mcp-knowledge-map"})
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
# The `scope` claim of a token that carries no `aud-*` scope: a session token, not one that
# was exchanged already (jwt-claim-enforcer matches the whole value).
NO_EXCHANGE_SCOPE = "^(?!(.* )?aud-).*$"
# Takes claims from the caller's request; never on a client or scope a managed client uses.
CLAIMS_PARAM_MAPPER = "oidc-claims-param-token-mapper"

# Client policies and profiles the sync owns (identified by name).
PAIR_POLICY_PREFIX = "papaia-one-aud-"
PERSON_POLICY_PREFIX = "papaia-person-"
CHAIN_POLICIES = ("data-chain", "data-self", "data-handover")
REJECT_PROFILE = "papaia-reject"
PERSON_PROFILE = "papaia-person-subject"
MANAGED_PROFILES = frozenset({REJECT_PROFILE, PERSON_PROFILE, *CHAIN_POLICIES})

# The Paperless gate passes the identity header only for names on this list (security
# 4.5 (f)); the realm sync writes it, the gate mounts its directory read-only.
PAPERLESS_AUDIENCE = "mcp-paperless"
PAPERLESS_USERS_FORMAT = "papaia.paperless-users/1"
PAPERLESS_USERS_REF = "security/paperless-gate/users.json"
USER_PAGE = 100
# A name the gate compares with a header value: no space, comma, control character or
# other separator, at most 255 characters (Keycloak's own limit).
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$")

# Flow's console (security 1.2, 1.4 "Aufgabenquellen"): it signs persons in with a signed
# assertion (private_key_jwt, RFC 7523; the key pair is Flow's, Keycloak holds the public
# key Flow registers), its only default scope is the shared person scope, `aud-flow` is
# an optional scope it asks for at sign-in, and it exchanges its own tokens only for the
# task sources Data and Studio. It is never an audience (an exchange client).
# Clients that authenticate with a signed JWT (RFC 7523, `private_key_jwt`): Data's own
# interface and Flow's console.
PRIVATE_KEY_JWT = frozenset({DATA_UI, "flow-console"})
PERSON_SCOPE = "papaia-person"
PERSON_SCOPE_CLIENTS = frozenset({"flow-console"})
SIGN_IN_AUDIENCES = {"flow-console": ("flow",)}
EXCHANGE_LIMITS = {"flow-console": ("papaia-data", "papaia-studio")}
# Audiences only named clients may exchange for, with fixed effects (security 1.4): the
# people lookup of the core is reached by the assistant's gate alone, effect x.
AUDIENCE_LIMITS = {"papaia-people": (("assist-gate",), ("x",))}

# Delegation (offline sessions) is held at exactly one client per purpose family.
HOLDERS = {"flow": ("papaia-flow", "flow-engine"), "assist": ("papaia-assist", "assist-gate")}
HOLDER_CLIENTS = frozenset(client for _, client in HOLDERS.values())
PURPOSES = frozenset({"flow.run", "assist.event", "assist.room-check", "assist.tools"})
# Bounds of a manifest's `delegation.max_idle_days` / `max_age_days` (exposes.v1 1.2.0):
# what a module is built for. The lifetime in effect is the installation setting
# (delegation_lifetime), never these values.
MAX_IDLE_DAYS, MAX_AGE_DAYS = 365, 365

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
    # A declared service account: client_credentials with private_key_jwt, nothing else.
    "service-account": {"bearerOnly": False, "publicClient": False, "standardFlowEnabled": False},
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
_ACCOUNT_REQUIRED = _ACCOUNT_KEYS - {"roles", "realm_management_roles"}

# Declared service accounts (security 1.9): one client per account, kind attribute below.
KIND = "papaia.kind"
SERVICE_ACCOUNT = "service-account"
ACCOUNT_EFFECTS = ("read", "write", "send", "delete", "check")
MAX_ACCOUNT_AUDIENCES = 12
MAX_ACCOUNT_ROLES = 20
# Days between key rotations the core asks for; `service-account list` marks an account
# whose key is older as due.
ROTATION_DAYS = 90
ROTATED_AT = "papaia.key_rotated_at"
# A service account gets `sub` (basic) and its realm roles (roles); Keycloak adds its own
# `service_account` scope to every service-account client and puts it back when removed.
ACCOUNT_DEFAULT_SCOPES = frozenset({"basic", "roles", "service_account"})
# Last use of an account is Keycloak's CLIENT_LOGIN event (a client_credentials grant).
# Kept 180 days, two rotation intervals, when the realm stores no events yet.
# The audit event of a client key change. The kit's papaia.audit/1 schema (1.1.0) has no
# `client_key_rotated` yet, and papaia-audit refuses an unknown event, so the rows carry
# `config_changed` with the operations `set_client_key` and `rotate_client_key`.
KEY_EVENT = "config_changed"
LOGIN_EVENT = "CLIENT_LOGIN"
EVENTS_EXPIRATION = 180 * 24 * 3600
_ACCOUNT_ID_RE = re.compile(r"^svc-[a-z][a-z0-9]*-[a-z0-9]+(-[a-z0-9]+)*$")
# Plain text as the kit's exposes schema defines it: no control, zero-width or
# direction-changing characters, no markup, no links.
_PLAIN_TEXT_RE = re.compile(
    "[^\\x00-\\x1f\\x7f<>\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\ufeff]*"
)
_LINK_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|[Ww]{3}\.|javascript:|\]\(", re.IGNORECASE)
_ACCOUNT_FLAGS = {"serviceAccountsEnabled": True, "clientAuthenticatorType": "client-jwt"}
_ACCOUNT_ATTRIBUTES = {
    KIND: SERVICE_ACCOUNT,
    "use.jwks.string": "true",
    "use.jwks.url": "false",
    "token.endpoint.auth.signing.alg": sak.ALGORITHM,
}


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
    # The host accounts (`host:<login>`) that asked for the pairing and that confirmed it
    # (security 1.4). A write pairing is confirmed only by a second person.
    requested_by: str | None = None
    confirmed_by: str | None = None

    @property
    def writes(self) -> bool:
        """Effect `w` or `d`: such a pairing needs a second person (security 1.4)."""
        return any(e in WRITE_EFFECTS for e in self.effects)


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


_PAIRING_KEYS = frozenset({"client", "audience", "effects", "state"})
_PAIRING_PERSONS = ("requested_by", "confirmed_by")
# `host:<login>`: the host account that acted (pairing_approval.acting_person).
_PAIRING_PERSON_RE = re.compile(r"^host:[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}$")


def _pairing_person(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _PAIRING_PERSON_RE.match(value):
        raise RealmSyncError(f"{label}: must be host:<login>")
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
        if not isinstance(row, dict):
            raise RealmSyncError(f"{label}: must be a mapping")
        # requested_by and confirmed_by are optional; every other field is required.
        _exact_keys({k: v for k, v in row.items() if k not in _PAIRING_PERSONS},
                    _PAIRING_KEYS, label)
        persons = {k: _pairing_person(row.get(k), f"{label}: {k}") for k in _PAIRING_PERSONS}
        client = register.check(row["client"], "client", label)
        entry = register.clients[client]
        if entry.test_profile_only:
            raise RealmSyncError(f"{label}: {client!r} exists only in the test profile")
        if not entry.token_exchange:
            raise RealmSyncError(f"{label}: {client!r} has no token exchange")
        audience = register.check(row["audience"], "audience", label)
        if audience in exchange_clients and audience != CHAIN_HOLDER:
            raise RealmSyncError(f"{label}: {audience!r} exchanges tokens and is never an audience")
        limits = EXCHANGE_LIMITS.get(client)
        if limits is not None and audience not in limits:
            raise RealmSyncError(f"{label}: {client} exchanges only for {', '.join(limits)}")
        effects = row["effects"]
        if audience in AUDIENCE_LIMITS:
            allowed, fixed = AUDIENCE_LIMITS[audience]
            if client not in allowed:
                raise RealmSyncError(
                    f"{label}: only {', '.join(allowed)} exchanges for {audience}"
                )
            if effects != list(fixed):
                raise RealmSyncError(
                    f"{label}: {audience} is paired with effect {''.join(fixed)} only"
                )
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
        pairing = Pairing(
            client, audience, tuple(effects), row["state"] == "confirmed",
            persons["requested_by"], persons["confirmed_by"],
        )
        if pairing.confirmed and pairing.writes and (
            pairing.requested_by is None
            or pairing.confirmed_by is None
            or pairing.requested_by == pairing.confirmed_by
        ):
            raise RealmSyncError(
                f"{label}: {client} -> {audience} writes or deletes and is confirmed without "
                "a second person (requested_by and confirmed_by must name two host accounts; "
                "papaia-ctl pairing approve)"
            )
        pairings.append(pairing)
    for client in sorted({p.client for p in pairings}):
        count = sum(1 for p in pairings if p.client == client and p.confirmed)
        if count > MAX_EXCHANGE_SCOPES:
            raise RealmSyncError(
                f"pairings.yaml: {client} has {count} confirmed pairings; "
                f"at most {MAX_EXCHANGE_SCOPES} exchange scopes per client"
            )
    return pairings


def _trusted(st: os.stat_result, label: object, grants: str = "exchange rights") -> None:
    """pairings.yaml grants exchange rights, the Paperless name list grants the identity
    header; only the user running papaia-ctl (or root) may be able to change them, never
    group or others."""
    if st.st_uid not in (os.geteuid(), 0):
        raise RealmSyncError(
            f"{label} is owned by uid {st.st_uid}, not by the user running papaia-ctl; "
            f"it grants {grants}"
        )
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RealmSyncError(
            f"{label} is writable by group or others; it grants {grants} (chmod go-w)"
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
    # `client_keys:` of the manifest as declared (None: not declared) and the add-on's
    # configuration folder its `jwks_file` paths are relative to.
    client_keys: object = None
    folder: Path | None = None


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
        if "exposes" not in manifest and "client_keys" not in manifest:
            continue
        declared = manifest.get("name")
        if not isinstance(declared, str) or not declared:
            raise RealmSyncError(
                f"add-on {name}: the manifest declares exposes or client_keys but no name"
            )
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
        modules.append(
            Module(
                declared,
                manifest.get("exposes", []),
                install_input,
                client_keys=manifest.get("client_keys"),
                folder=config_dir / "addons" / str(name),
            )
        )
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
    # Recorded facts of a service account (owner, deputy, purpose, effects, rotation).
    record: dict[str, str] = field(default_factory=dict)
    # Keycloak's client authenticator, where the sync fixes it ("client-jwt" for
    # private_key_jwt); None leaves the one Keycloak gives the client.
    authenticator: str | None = None
    # Declared in client_keys[]: the key file (for messages), the public keys Keycloak
    # must hold (empty when the file is missing) and whether the file is missing.
    key_file: str | None = None
    jwks: list[dict] = field(default_factory=list)
    key_missing: bool = False

    @property
    def service_account(self) -> bool:
        return self.kind == SERVICE_ACCOUNT

    def representation(self) -> dict:
        # PKCE S256 on every managed client, also on those without a sign-in flow: the
        # client policy refuses any update of a managed client without it.
        attributes = {
            MANAGED: "true",
            OWNER: _owner_value(self.owner),
            TOKEN_EXCHANGE: "true" if self.token_exchange else "false",
            rh.PKCE: "S256",
        }
        if self.kind == "public":
            attributes["oauth2.device.authorization.grant.enabled"] = "true"
        if self.service_account:
            attributes.update(_ACCOUNT_ATTRIBUTES, **self.record)
        if self.client_id == CHAIN_HOLDER:
            attributes[CHAIN_HOLDER_MARK] = "true"
        if self.key_file is not None:
            attributes.update({"use.jwks.string": "true", "use.jwks.url": "false"})
        rep = {
            "clientId": self.client_id,
            "protocol": "openid-connect",
            **_FLAGS[self.kind],
            **_COMMON_FLAGS,
            **(_ACCOUNT_FLAGS if self.service_account else {}),
            "attributes": attributes,
        }
        authenticator = self.authenticator or (
            "client-jwt" if self.client_id in PRIVATE_KEY_JWT else None
        )
        if authenticator:
            rep["clientAuthenticatorType"] = authenticator
        return rep


@dataclass
class Plan:
    clients: dict[str, ClientSpec]
    roles: dict[str, str]
    admin_members: set[str]
    exchange_scopes: dict[str, str]
    notes: list[str]
    # Roles whose holders are on the Paperless name list; None: no module serves
    # mcp-paperless, so there is no list.
    paperless_roles: frozenset[str] | None = None
    # realm-level client policies and profiles the sync owns, by name
    policies: dict[str, dict] = field(default_factory=dict)
    profiles: dict[str, dict] = field(default_factory=dict)
    # exchange clients that are never an audience: no scope aud-<name>, no mapper to them
    never_audiences: set[str] = field(default_factory=set)
    # Registered service accounts named outside svc-<module>-<purpose> (flow-directory,
    # flow-control): a module's own setup creates them and they cannot be declared in
    # service_accounts[] yet, so the sync names them and leaves them alone.
    legacy_accounts: frozenset[str] = frozenset()
    # Realm settings, client hardening and client policy (realm_hardening); `sync` sets
    # it from the security profile and the configured hosts.
    hardening: rh.Hardening = field(default_factory=rh.Hardening)
    # the shared person scope is the default scope of a planned client
    person_scope: bool = False
    # `papaia.owner` values of modules `addon uninstall` removed and nobody installed again
    # (lib/uninstall_journal.py): their managed clients are deleted, not left in place.
    uninstalled: frozenset[str] = frozenset()


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


@dataclass(frozen=True)
class Account:
    """One declared service account, checked."""

    id: str
    module: str
    purpose: dict[str, str]
    owner_sub: str
    deputy_sub: str
    roles: tuple[str, ...]
    audiences: tuple[str, ...]
    effects: tuple[str, ...]


def _names_list(value: object, limit: int, label: str) -> list:
    if not isinstance(value, list) or len(value) > limit or len(set(map(str, value))) != len(value):
        raise RealmSyncError(f"{label} must be a list of at most {limit} distinct names")
    return value


def _purpose(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value or set(value) - {"de", "en"}:
        raise RealmSyncError(f"{label}: purpose must be a mapping with de and/or en")
    for text in value.values():
        if (
            not isinstance(text, str)
            or not 1 <= len(text) <= 80
            or not _PLAIN_TEXT_RE.fullmatch(text)
            or _LINK_RE.search(text)
        ):
            raise RealmSyncError(f"{label}: purpose must be plain text of 1 to 80 characters")
    return dict(value)


def _parse_accounts(
    accounts: object, module: Module, register: Register, label: str
) -> list[Account]:
    """The service accounts of one exposes entry (security 1.9, kit exposes schema). A
    declaration that could never be created stops the sync before any change."""
    if not isinstance(accounts, list) or len(accounts) > 50:
        raise RealmSyncError(f"{label}: service_accounts must be a list of at most 50")
    parsed = []
    exchange_clients = register.exchange_clients()
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
        if not _ACCOUNT_ID_RE.match(name):
            raise RealmSyncError(f"{sa_label}: a declared account is named svc-<module>-<purpose>")
        owner = _resolve_person(account.get("owner_sub"), module, f"{sa_label}: owner_sub")
        deputy = _resolve_person(account.get("deputy_sub"), module, f"{sa_label}: deputy_sub")
        if owner == deputy:
            raise RealmSyncError(f"{sa_label}: owner_sub and deputy_sub are the same person")
        missing = sorted(_ACCOUNT_REQUIRED - set(account))
        if missing:
            raise RealmSyncError(f"{sa_label}: missing field {', '.join(missing)}")
        if account["credential"] != "private_key_jwt":
            raise RealmSyncError(f"{sa_label}: credential must be private_key_jwt")
        if _names_list(
            account.get("realm_management_roles", []), 20, f"{sa_label}: realm_management_roles"
        ):
            raise RealmSyncError(
                f"{sa_label}: realm-management roles for a module's service account need a "
                "confirmation at installation, which the core does not offer yet; "
                "declare realm_management_roles: []"
            )
        effects = account["effects"]
        if (
            not isinstance(effects, list)
            or not effects
            or len(set(map(str, effects))) != len(effects)
            or not all(e in ACCOUNT_EFFECTS for e in effects)
        ):
            raise RealmSyncError(
                f"{sa_label}: effects must be distinct values out of {', '.join(ACCOUNT_EFFECTS)}"
            )
        roles = []
        for role in _names_list(account.get("roles", []), MAX_ACCOUNT_ROLES, f"{sa_label}: roles"):
            role = register.check(role, "role", f"{sa_label}: roles")
            if register.roles[role].owner == "papaia" or role.endswith("-admin"):
                raise RealmSyncError(
                    f"{sa_label}: {role} is a platform or admin role; a service account never "
                    "holds one"
                )
            roles.append(role)
        audiences = []
        for audience in _names_list(
            account["audiences"], MAX_ACCOUNT_AUDIENCES, f"{sa_label}: audiences"
        ):
            audience = register.check(audience, "audience", f"{sa_label}: audiences")
            if audience in exchange_clients:
                raise RealmSyncError(
                    f"{sa_label}: audience {audience} exchanges tokens; a service account "
                    "never reaches it"
                )
            audiences.append(audience)
        parsed.append(
            Account(
                name,
                module.name,
                _purpose(account["purpose"], sa_label),
                owner,
                deputy,
                tuple(roles),
                tuple(audiences),
                tuple(effects),
            )
        )
    return parsed


def _account_spec(account: Account, audiences: list[str]) -> ClientSpec:
    return ClientSpec(
        account.id,
        account.module,
        SERVICE_ACCOUNT,
        False,
        optional_scopes={exchange_scope(a) for a in audiences},
        default_scopes=set(ACCOUNT_DEFAULT_SCOPES),
        role_scope=set(account.roles),
        record={
            "papaia.owner_sub": account.owner_sub,
            "papaia.deputy_sub": account.deputy_sub,
            "papaia.purpose": json.dumps(account.purpose, sort_keys=True, ensure_ascii=False),
            "papaia.effects": ",".join(account.effects),
            "papaia.rotation_days": str(ROTATION_DAYS),
        },
    )


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


def _check_identity(entry: dict, label: str) -> tuple[str, ...] | None:
    """The declared identity kinds of an exposes entry, or None if it declares none."""
    if "identity" not in entry:
        return None
    value = entry["identity"]
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) and v in IDENTITIES for v in value)
        or len(set(value)) != len(value)
    ):
        raise RealmSyncError(f"{label}: identity must be distinct values out of {IDENTITIES}")
    return tuple(value)


def _check_origins(value: object, register: Register, chain_owner: str, label: str) -> tuple:
    """`upstream_origins` of the chain holder: registered clients of the first delivery,
    never a Data client."""
    label = f"{label}: upstream_origins"
    if not isinstance(value, list):
        raise RealmSyncError(f"{label} must be a list of client ids")
    if not value or len(value) > _MAX_ORIGINS:
        raise RealmSyncError(f"{label} needs at least one and at most {_MAX_ORIGINS} origins")
    origins: list[str] = []
    for origin in value:
        name = register.check(origin, "client", label)
        if name in origins:
            raise RealmSyncError(f"{label}: {name} is listed twice")
        if register.clients[name].owner == chain_owner:
            raise RealmSyncError(f"{label}: {name} is a Data client; Data is never its own origin")
        if name not in CHAIN_ORIGINS:
            raise RealmSyncError(
                f"{label}: {name} is not a chain origin in this release "
                f"(only {', '.join(CHAIN_ORIGINS)})"
            )
        origins.append(name)
    return tuple(origins)


def _grant(*grants: str) -> dict:
    return {"condition": "grant-type", "configuration": {"grant_types": list(grants)}}


def _scope_condition(scope: str, kind: str) -> dict:
    return {"condition": "client-scopes", "configuration": {"type": kind, "scopes": [scope]}}


def _attribute_condition(key: str, value: str, *, negative: bool = False) -> dict:
    """Clients with the attribute `key=value` (an exact value; Keycloak has no wildcard
    here); with `negative`, every client without it."""
    configuration: dict = {"attributes": json.dumps([{"key": key, "value": value}])}
    if negative:
        configuration["is-negative-logic"] = True
    return {"condition": "client-attributes", "configuration": configuration}


def _owner_condition(owner: str) -> dict:
    """Clients with `papaia.owner=<owner>`."""
    return _attribute_condition(OWNER, _owner_value(owner))


def _claim(name: str, pattern: str) -> dict:
    """The subject token's claim `name` must match `pattern`; an empty pattern only asks
    for the claim to be present."""
    return {
        "executor": "jwt-claim-enforcer",
        "configuration": {"claim-name": name, "allowed-value": pattern},
    }


def _policy(name: str, purpose: str, conditions: list[dict], profile: str) -> dict:
    return {
        "name": name,
        "description": f"papaia.managed=true; {purpose}",
        "enabled": True,
        "conditions": conditions,
        "profiles": [profile],
    }


def _client_policies(
    clients: dict[str, ClientSpec],
    exchange_scopes: dict[str, str],
    person_audiences: set[str],
    origins: tuple[str, ...],
) -> tuple[dict[str, dict], dict[str, dict]]:
    """The client policies and profiles the identity provider enforces (security 1.4,
    1.5, 1.9). A `client-scopes` condition may only name a scope that exists, so every
    policy here names planned exchange scopes only."""
    policies: dict[str, dict] = {}

    # Exactly one audience: a request that asks for two aud-* scopes of a client is
    # rejected, one policy per pair (k*(k-1)/2 per client, at most 66). No grant-type
    # condition: the rule holds for a sign-in (authorization request, code, refresh) as
    # for a token exchange, so Flow's console cannot sign in with aud-flow and a task
    # source at once (Keycloak 26.7.0 evaluates `client-scopes` on each of them).
    for spec in clients.values():
        audiences = sorted(exchange_scopes[s] for s in spec.optional_scopes if s in exchange_scopes)
        for x, y in itertools.combinations(audiences, 2):
            name = f"{PAIR_POLICY_PREFIX}{x}-{y}"
            policies[name] = _policy(
                name,
                f"rejects a sign-in or token exchange for both {x} and {y}",
                [
                    _scope_condition(exchange_scope(x), "Optional"),
                    _scope_condition(exchange_scope(y), "Optional"),
                ],
                REJECT_PROFILE,
            )

    # Person-only audiences: no client_credentials, and an exchange only with a subject
    # token that carries `sid` (service tokens carry none). "Any" also catches the scope
    # as a default scope.
    for audience in sorted(person_audiences):
        scope = exchange_scope(audience)
        if scope not in exchange_scopes:
            continue
        name = f"{PERSON_POLICY_PREFIX}{audience}-client-credentials"
        policies[name] = _policy(
            name,
            f"{audience} admits persons only: no client_credentials",
            [_grant("client_credentials"), _scope_condition(scope, "Any")],
            REJECT_PROFILE,
        )
        name = f"{PERSON_POLICY_PREFIX}{audience}-exchange"
        policies[name] = _policy(
            name,
            f"{audience} admits persons only: an exchange needs a subject token with sid",
            [_grant(TOKEN_EXCHANGE_GRANT), _scope_condition(scope, "Any")],
            PERSON_PROFILE,
        )

    profiles: dict[str, dict] = {}
    if CHAIN_HOLDER in clients:
        owner = clients[CHAIN_HOLDER].owner
        origin = origins[0] if len(origins) == 1 else f"({'|'.join(origins)})"
        # The holder is named positively by its own attribute: the owner attribute is
        # shared by both Data clients, and a scope condition would open a gap as soon as
        # the scope is assigned again.
        policies["data-chain"] = _policy(
            "data-chain",
            "Data re-exchanges only tokens of its upstream origins issued for papaia-data alone",
            [_grant(TOKEN_EXCHANGE_GRANT), _attribute_condition(CHAIN_HOLDER_MARK, "true")],
            "data-chain",
        )
        profiles["data-chain"] = [_claim("azp", f"^{origin}$"), _claim("aud", f"^{CHAIN_HOLDER}$")]
        # Every other Data client (papaia-data-ui) exchanges only its own session token, in
        # one hop: a token it got from an exchange carries an aud-* scope. Without the
        # holder's attribute both Data clients fall under this policy, which fails closed.
        policies["data-self"] = _policy(
            "data-self",
            "Data's own interface exchanges only its own session token, in one hop",
            [
                _grant(TOKEN_EXCHANGE_GRANT),
                _owner_condition(owner),
                _attribute_condition(CHAIN_HOLDER_MARK, "true", negative=True),
            ],
            "data-self",
        )
        profiles["data-self"] = [_claim("azp", f"^{DATA_UI}$"), _claim("scope", NO_EXCHANGE_SCOPE)]
        handover = exchange_scope("papaia-studio")
        if handover in exchange_scopes:
            policies["data-handover"] = _policy(
                "data-handover",
                "the handover to Studio only with the session token of Data's own interface",
                [
                    _grant(TOKEN_EXCHANGE_GRANT),
                    _owner_condition(owner),
                    _scope_condition(handover, "Optional"),
                ],
                "data-handover",
            )
            profiles["data-handover"] = [_claim("azp", f"^{DATA_UI}$")]

    executors = {
        REJECT_PROFILE: [{"executor": "reject-request", "configuration": {}}],
        PERSON_PROFILE: [_claim("sid", "")],
        **profiles,
    }
    used = {p for policy in policies.values() for p in policy["profiles"]}
    return policies, {
        name: {
            "name": name,
            "description": "papaia.managed=true; profile of the realm sync",
            "executors": executors[name],
        }
        for name in sorted(used)
    }


def _managed_policy(name: str) -> bool:
    return name.startswith((PAIR_POLICY_PREFIX, PERSON_POLICY_PREFIX)) or name in CHAIN_POLICIES


def _list(mapping: dict, key: str, label: str) -> list:
    value = mapping.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise RealmSyncError(f"{label}: {key} must be a list")
    return value


def build_plan(
    register: Register,
    modules: list[Module],
    pairings: list[Pairing],
    *,
    core_audiences: frozenset[str] = frozenset(),
) -> Plan:
    """The target state of the managed objects; RealmSyncError for anything not
    acceptable. Nothing is read from or written to Keycloak here. `core_audiences` are
    the audiences the core serves itself under its active profiles (persons only)."""
    clients: dict[str, ClientSpec] = {}
    own_roles: dict[str, set[str]] = {}
    visible: set[str] = set()
    holders: set[str] = set()
    audiences: set[str] = set()
    paperless_modules: set[str] = set()
    # The identity kinds each installed audience accepts (exposes `identity`).
    identities: dict[str, set[str]] = {}
    accounts: list[Account] = []
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

    chain_owner = register.clients[CHAIN_HOLDER].owner
    person_audiences: set[str] = set()
    origins: tuple[str, ...] | None = None

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
            identity = _check_identity(entry, entry_label)
            for key in ("downstream", "upstream_origins"):
                if key in entry and module.name != chain_owner:
                    raise RealmSyncError(
                        f"{entry_label}: only the chain holder {CHAIN_HOLDER} declares {key}"
                    )
            if "upstream_origins" in entry:
                found = _check_origins(
                    entry["upstream_origins"], register, chain_owner, entry_label
                )
                if origins is not None and found != origins:
                    raise RealmSyncError(f"{entry_label}: upstream_origins differ between entries")
                origins = found
            if "audience" in entry:
                audience = entry["audience"]
                if isinstance(audience, str) and audience in register.audiences:
                    audiences.add(audience)
                    if audience == PAPERLESS_AUDIENCE:
                        paperless_modules.add(module.name)
                    identities.setdefault(audience, set()).update(identity or ())
                    if audience in product_clients:
                        manage(audience, module.name)
                    person_only = audience in PERSON_ONLY_AUDIENCES or entry.get("kind") == "me"
                    if person_only and identity and "service" in identity:
                        raise RealmSyncError(
                            f"{entry_label}: {audience} admits persons only; "
                            "identity must not list service"
                        )
                    if person_only or identity == ("person",):
                        person_audiences.add(audience)
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
                accounts += _parse_accounts(
                    entry["service_accounts"], module, register, entry_label
                )
        if module.name in register.owners:
            for client_id, entry in product_clients.items():
                if entry.owner == module.name:
                    manage(client_id, module.name)

    for audience in sorted(core_audiences):
        register.check(audience, "audience", "core audience")
        if register.clients.get(audience) is None or register.clients[audience].owner != "papaia":
            raise RealmSyncError(f"core audience {audience}: not a client of the core")
        audiences.add(audience)
        identities.setdefault(audience, set()).add("person")
        person_audiences.add(audience)
        manage(audience, "papaia")

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

    # Sign-in scopes come from the declaration, not from a pairing: an optional `aud-*`
    # scope the client asks for at sign-in, while both sides are installed.
    for client_id, sign_in in SIGN_IN_AUDIENCES.items():
        for audience in sign_in:
            if client_id in clients and audience in audiences:
                scope = exchange_scope(audience)
                exchange_scopes[scope] = audience
                clients[client_id].optional_scopes.add(scope)

    for holder in holders:
        clients[holder].optional_scopes.add(OFFLINE)

    _plan_client_keys(register, modules, clients, notes)

    # Service accounts: one client each, with the scopes of its installed audiences only.
    # It obtains an audience with client_credentials and scope=aud-<a>; no exchange.
    for account in accounts:
        if account.id in clients:
            raise RealmSyncError(f"service account {account.id} is declared twice")
        active = []
        for audience in account.audiences:
            if audience not in audiences:
                notes.append(
                    f"service account {account.id}: audience {audience} is not installed; "
                    "its scope is assigned once it is"
                )
            elif "service" not in identities.get(audience, set()):
                raise RealmSyncError(
                    f"service account {account.id}: audience {audience} accepts persons only"
                )
            else:
                active.append(audience)
                exchange_scopes[exchange_scope(audience)] = audience
        clients[account.id] = _account_spec(account, active)

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
    for account in accounts:
        for role in sorted(set(account.roles) - set(roles)):
            notes.append(
                f"service account {account.id}: role {role} of {register.roles[role].owner} is "
                "not declared by an installed module; it is mapped once it exists"
            )
    for spec in clients.values():
        if spec.client_id in PRIVATE_KEY_JWT:
            spec.authenticator = "client-jwt"
        if spec.kind not in ("bearer", SERVICE_ACCOUNT):
            spec.default_scopes = (
                {PERSON_SCOPE} if spec.client_id in PERSON_SCOPE_CLIENTS else set(DEFAULT_SCOPES)
            )
            spec.role_scope = (
                own_roles.get(spec.owner, set()) | visible | set(MODULE_PLATFORM_ROLES)
            )
        # No client with token exchange holds an aud-* default scope (security 1.2):
        # Keycloak would put that audience into every token of the client.
        if spec.token_exchange and {s for s in spec.default_scopes if s.startswith("aud-")}:
            raise RealmSyncError(f"client {spec.client_id}: an aud-* scope as a default scope")
    admin_members = {
        name for declared in own_roles.values() for name in declared if name.endswith("-admin")
    }
    legacy = frozenset(n for n in register.service_accounts if not _ACCOUNT_ID_RE.match(n))
    paperless_roles = None
    if paperless_modules:
        paperless_roles = frozenset().union(*(own_roles[m] for m in paperless_modules))
        if not paperless_roles:
            notes.append(
                f"module {', '.join(sorted(paperless_modules))} serves {PAPERLESS_AUDIENCE} but "
                "declares no role: the Paperless name list stays empty, the gate admits no name"
            )
    policies, profiles = _client_policies(
        clients, exchange_scopes, person_audiences, origins or CHAIN_ORIGINS
    )
    never = register.exchange_clients() - {CHAIN_HOLDER}
    return Plan(
        clients,
        roles,
        admin_members,
        exchange_scopes,
        notes,
        paperless_roles=paperless_roles,
        policies=policies,
        profiles=profiles,
        never_audiences=never,
        legacy_accounts=legacy,
        person_scope=any(PERSON_SCOPE in s.default_scopes for s in clients.values()),
    )


def _plan_client_keys(
    register: Register, modules: list[Module], clients: dict[str, ClientSpec], notes: list[str]
) -> None:
    """`client_keys[]`: only clients the module owns and the sync manages, which
    authenticate (not public, not bearer-only, not a service account); the key file is
    read and checked here, before any write."""
    for module in modules:
        if module.client_keys is None:
            continue
        label = f"module {module.name}"
        try:
            declarations = ck.parse_declarations(module.client_keys, label)
        except ck.ClientKeyError as exc:
            raise RealmSyncError(str(exc)) from None
        for decl in declarations:
            entry = register.clients.get(decl.client)
            if entry is None or entry.test_profile_only:
                raise RealmSyncError(
                    f"{label}: client_keys: {decl.client!r} is not a registered client"
                )
            if entry.owner != module.name:
                raise RealmSyncError(
                    f"{label}: client_keys: {decl.client} belongs to {entry.owner}"
                )
            spec = clients.get(decl.client)
            if spec is None:
                raise RealmSyncError(
                    f"{label}: client_keys: {decl.client} is not a client the sync manages"
                )
            if spec.kind == "public":
                raise RealmSyncError(
                    f"{label}: client_keys: {decl.client} is a public client without credentials"
                )
            if spec.kind == "bearer":
                raise RealmSyncError(
                    f"{label}: client_keys: {decl.client} is bearer-only and never signs in"
                )
            keys = None
            if module.folder is not None:
                try:
                    keys = ck.read_jwks(module.folder, decl.jwks_file, f"{label}, {decl.client}")
                except ck.ClientKeyError as exc:
                    raise RealmSyncError(str(exc)) from None
            spec.authenticator = "client-jwt"
            spec.key_file = decl.jwks_file
            spec.jwks = keys or []
            spec.key_missing = keys is None
            if keys is None:
                notes.append(
                    f"{label}: no key file {decl.jwks_file} for {decl.client}; it cannot sign "
                    "in until the module writes its public keys there"
                )


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


def _now_iso(now: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


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

    def __init__(
        self,
        path: Path,
        correlation_id: str,
        *,
        host_account: str | None = None,
        writer: str = "papaia-ctl/realm-sync",
    ) -> None:
        self.path = path
        self.correlation_id = correlation_id
        self.host_account = host_account or _host_account()
        self.writer = writer
        # realm-sync -> realm_sync.<operation>, service-account -> service_account.<...>
        self.operation_prefix = writer.rsplit("/", 1)[-1].replace("-", "_")
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
        self,
        change: Change,
        result: str,
        error_code: str | None = None,
        *,
        master: bool = False,
        host: bool = False,
        detail: dict | None = None,
    ) -> None:
        """One row. `master`: the write was made with the master admin (creating or
        realigning the sync account), not with the sync account. `host`: the host account
        acted alone, without any identity of the realm and with no token (the platform halt,
        or a file write in the configuration directory). `detail`: counters, hashes or values
        the event's schema allows (papaia.audit/1 `detail`), never content."""
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
            "writer": self.writer,
            "role": "caller",
            "sub": self.host_account,
            "identity_kind": None if master or host else "service",
            "service_account": None if master or host else SYNC_CLIENT,
            "azp": None if host else "admin-cli" if master else SYNC_CLIENT,
            "aud": None,
            "origin_azp": None,
            "origin_source": None,
            "origin_asserted_by": None,
            "context": None,
            "catalog_id": None,
            "operation": f"{self.operation_prefix}.{change.operation}",
            "effect": change.effect,
            "object_ref": {"type": change.kind.replace("-", "_"), "id": change.name},
            "data_class": None,
            "result": result,
            "error_code": error_code,
            "client_ip": None,
            "detail": dict(detail) if detail else None,
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

_IN_TOKENS = {
    "access.token.claim": "true",
    "id.token.claim": "true",
    "introspection.token.claim": "true",
    "userinfo.token.claim": "true",
}
# The shared person claims (security 1.2 "Gemeinsame Claims") of the scope `papaia-person`,
# as (name, mapper, config); Keycloak sets `sid`, `iat` and `exp` itself. `sub` and
# `auth_time` are the mappers of Keycloak's `basic` scope, which a client with only this
# default scope does not have. `roles` shows only the realm roles of the token scope.
# A group id claim (`group_ids`) has no mapper in Keycloak 26.7.0 and is not set here.
PERSON_MAPPERS = (
    ("sub", "oidc-sub-mapper", {"access.token.claim": "true", "introspection.token.claim": "true"}),
    (
        "auth_time",
        "oidc-usersessionmodel-note-mapper",
        {
            **_IN_TOKENS,
            "user.session.note": "AUTH_TIME",
            "claim.name": "auth_time",
            "jsonType.label": "long",
        },
    ),
    (
        "person_id",
        "oidc-usermodel-property-mapper",
        {
            **_IN_TOKENS,
            "user.attribute": "id",
            "claim.name": "person_id",
            "jsonType.label": "String",
        },
    ),
    (
        "roles",
        "oidc-usermodel-realm-role-mapper",
        {**_IN_TOKENS, "claim.name": "roles", "multivalued": "true", "jsonType.label": "String"},
    ),
    (
        "groups",
        "oidc-group-membership-mapper",
        {**_IN_TOKENS, "claim.name": "groups", "full.path": "true"},
    ),
    (
        "email",
        "oidc-usermodel-attribute-mapper",
        {
            **_IN_TOKENS,
            "user.attribute": "email",
            "claim.name": "email",
            "jsonType.label": "String",
        },
    ),
    (
        "email verified",
        "oidc-usermodel-property-mapper",
        {
            **_IN_TOKENS,
            "user.attribute": "emailVerified",
            "claim.name": "email_verified",
            "jsonType.label": "boolean",
        },
    ),
)


def _person_mappers() -> list[dict]:
    return [
        {"name": name, "protocol": "openid-connect", "protocolMapper": kind, "config": dict(config)}
        for name, kind, config in PERSON_MAPPERS
    ]


def _same_mapper(mapper: dict, wanted: dict) -> bool:
    """Exactly the wanted mapper: name, type and the whole configuration."""
    return (
        all(mapper.get(k) == wanted[k] for k in ("name", "protocolMapper"))
        and (mapper.get("config") or {}) == wanted["config"]
    )


def _exchange_event(scope_name: str) -> str:
    return (
        "exchange_right_changed"
        if scope_name.startswith("aud-") or scope_name == OFFLINE
        else "config_changed"
    )


def _scope_removed(kind: str, name: str, exchange: bool) -> str:
    """The action of removing a scope from a client; an `aud-*` default scope of an
    exchange client is named as what it is (security 1.2, ISB-G2.3)."""
    if kind == "default" and exchange and name.startswith("aud-"):
        return f"default scope {name} removed (an exchange client holds no aud-* default scope)"
    return f"{kind} scope {name} removed"


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
    def __init__(
        self,
        call,
        plan: Plan,
        apply: bool,
        audit: AuditLog | None,
        *,
        keys: sak.KeyStore | None = None,
        master=None,
    ) -> None:
        super().__init__(call, apply, audit)
        self.plan = plan
        self.keys = keys
        # The master admin: only it may change a service-account user's role mappings
        # and groups and the realm's event settings (the sync account gets HTTP 403).
        self.master = _Actions(master, apply, audit, master=True) if master else None
        self.role_info: dict[str, dict] = {}
        self.client_names: dict[str, str] = {}
        self._expanded: dict[str, tuple[set[str], set[str]]] = {}
        self._noted: set[str] = set()
        self._accounts = [s for s in plan.clients.values() if s.service_account]
        if self._accounts and (keys is None or master is None):
            raise RealmSyncError("service accounts need the key folder and the master admin")

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
        self.realm_settings()
        self.roles()
        self.exchange_scopes()
        self.realm_defaults()
        self.shared_scopes()
        self.person_scope()
        scopes = self._scopes()
        clients = self._clients()
        self.client_names = {c["id"]: client_id for client_id, c in clients.items()}
        for client_id in sorted(self.plan.clients):
            self.client(self.plan.clients[client_id], clients.get(client_id), scopes)
        self.exchange_elsewhere(clients, scopes)
        self.undeclared_accounts(clients)
        self.never_audience()
        self.chain_holder_mark()
        # Policies before stale scopes: a policy may only name a scope that exists.
        self.client_policies()
        self.stale_exchange_scopes()
        # Fresh: an update names all attributes, and `client` may just have changed some.
        self.harden_clients(self._clients() if self.apply else clients)
        # Last: the policy refuses an update of a managed client without PKCE S256, which
        # the steps above give every managed client first.
        self.client_policy()
        for client_id, client in sorted(clients.items()):
            attributes = client.get("attributes") or {}
            managed = attributes.get(MANAGED) == "true"
            if (
                managed
                and client_id not in self.plan.clients
                and client_id != SYNC_CLIENT
                and attributes.get(KIND) != SERVICE_ACCOUNT
            ):
                if attributes.get(OWNER) in self.plan.uninstalled:
                    self.do(
                        Change(
                            "client",
                            client_id,
                            "removed, its module was uninstalled",
                            "delete_client",
                            effect="delete",
                        ),
                        "DELETE",
                        f"/clients/{client['id']}",
                    )
                    continue
                print(
                    f"WARNING: managed client {client_id} has no declaration any more; it is "
                    "left in place. Remove it in the admin console once its module is gone.",
                    file=sys.stderr,
                    flush=True,
                )
        if self.master:
            self.account_users()
            self.login_events()
            self.changes += self.master.changes
            self.skipped += self.master.skipped
        return self.changes

    # realm hardening -------------------------------------------------------
    def realm_settings(self) -> None:
        live = self.call("GET", "") or {}
        settings = self.plan.hardening.settings
        want = settings.realm()
        drift = sorted(k for k, v in want.items() if live.get(k) != v)
        if drift:
            self.do(
                Change(
                    "realm", kcs._REALM, f"settings corrected ({', '.join(drift)})", "update_realm"
                ),
                "PUT",
                "",
                {k: want[k] for k in drift},
            )
        shown = {**live, **want} if self.apply else live
        print(f"  {rh.describe(shown, settings.profile)}", flush=True)

    def harden_clients(self, clients: dict[str, dict]) -> None:
        """No password grant and no implicit flow at any client, PKCE S256 at public
        ones, redirect URIs and web origins only of the configured hosts. Managed
        clients have their switches from `client`; here only their URIs are checked."""
        for client_id, client in sorted(clients.items()):
            if client_id == SYNC_CLIENT:
                continue
            body, drift = rh.harden_client(
                client, self.plan.hardening, uris_only=client_id in self.plan.clients
            )
            if body:
                self.do(
                    Change("client", client_id, f"hardened ({', '.join(drift)})", "harden_client"),
                    "PUT",
                    f"/clients/{client['id']}",
                    body,
                )

    def client_policy(self) -> None:
        """The profile and the policy `papaia-hardening`; the realm's other client
        profiles and policies are kept as they are."""
        for kind, one, want in (
            ("profiles", "profile", rh.client_profile()),
            ("policies", "policy", rh.client_policy()),
        ):
            path = f"/client-policies/{kind}"
            have = (self.call("GET", path) or {}).get(kind) or []
            current = next((p for p in have if p.get("name") == want["name"]), None)
            if rh.same(current, want):
                continue
            others = [p for p in have if p.get("name") != want["name"]]
            self.do(
                Change(
                    "realm",
                    kcs._REALM,
                    f"client {one} {want['name']} set",
                    f"set_client_{one}",
                ),
                "PUT",
                path,
                {kind: [*others, want]},
            )

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

    def stale_exchange_scopes(self) -> None:
        """A managed `aud-*` scope without a confirmed pairing is removed; this runs after
        the client policies, which no longer name it by then."""
        for name, scope in sorted(self._scopes().items()):
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

    def person_scope(self) -> None:
        """The shared person scope, while a planned client has it as its default scope:
        exactly the mappers of PERSON_MAPPERS, no role mapping. Any other mapper is
        removed (one that adds an audience or takes claims from the request with event
        `exchange_right_changed`); a changed one is removed and added again."""
        if not self.plan.person_scope:
            return
        wanted = _person_mappers()
        scope = self._scopes().get(PERSON_SCOPE)
        if scope is None:
            rep = {
                "name": PERSON_SCOPE,
                "protocol": "openid-connect",
                "attributes": dict(_SCOPE_ATTRIBUTES),
                "protocolMappers": wanted,
            }
            self.do(
                Change("client-scope", PERSON_SCOPE, "created", "create_scope"),
                "POST",
                "/client-scopes",
                rep,
            )
            return
        self.scope_settings(PERSON_SCOPE, scope, "config_changed")
        self.scope_roles(PERSON_SCOPE, scope["id"], set(), "config_changed")
        base = f"/client-scopes/{scope['id']}/protocol-mappers/models"
        kept: set[str] = set()
        for mapper in scope.get("protocolMappers") or []:
            target = _named(wanted, mapper.get("name") or "")
            if target is not None and target["name"] not in kept and _same_mapper(mapper, target):
                kept.add(target["name"])
                continue
            event = "exchange_right_changed"
            if mapper.get("protocolMapper") == CLAIMS_PARAM_MAPPER:
                why = "takes claims from the request"
            elif _adds_audience(mapper):
                why = "adds an audience"
            else:
                why, event = "not one of the shared person claims", "config_changed"
                if target is not None:
                    why = "differs from the shared person claims"
            self.do(
                Change(
                    "client-scope",
                    PERSON_SCOPE,
                    f"mapper {mapper.get('name')} removed ({why})",
                    "remove_mapper",
                    event,
                    "delete",
                ),
                "DELETE",
                f"{base}/{mapper['id']}",
            )
        for mapper in wanted:
            if mapper["name"] in kept:
                continue
            self.do(
                Change("client-scope", PERSON_SCOPE, f"mapper {mapper['name']} set", "set_mapper"),
                "POST",
                base,
                mapper,
            )

    def scope_settings(self, name: str, scope: dict, event: str = "exchange_right_changed") -> None:
        """Protocol and attributes of a managed scope. A scope that a module's own
        setup created is adopted: it gets `papaia.managed=true`, so revoking the last
        confirmed pairing of an exchange scope removes it."""
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
            Change("client-scope", name, action, "update_scope", event),
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
                if mapper.get("protocolMapper") == CLAIMS_PARAM_MAPPER:
                    why, mapper_event = "takes claims from the request", "exchange_right_changed"
                elif _adds_audience(mapper) and not _own_resolve_mapper(name, mapper):
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
            if not self.apply:
                return
            current = self._clients()[spec.client_id]
            if spec.role_scope:
                self.role_scope(spec, current["id"])
            if spec.service_account:
                # Created without a key: the key is registered as a change of its own.
                self.credential(spec, current)
            if spec.key_file is not None:
                self.client_key(spec, current)
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
            if mapper.get("protocolMapper") == CLAIMS_PARAM_MAPPER:
                why, event = "takes claims from the request", "exchange_right_changed"
            elif _adds_audience(mapper):
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
                        _scope_removed(kind, name, spec.token_exchange),
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
        if spec.service_account:
            self.credential(spec, dict(current, attributes=attributes))
        if spec.key_file is not None:
            # The settings drift above already covers the authenticator and attributes.
            settled = {k: v for k, v in rep.items() if k not in ("attributes", "clientId")}
            self.client_key(spec, dict(current, **settled, attributes=attributes))

    # client keys ----------------------------------------------------------
    def client_key(self, spec: ClientSpec, current: dict) -> None:
        """Keycloak holds exactly the public keys of the client's declared key file, with
        `client-jwt`. A missing file fails `--check`; the sync removes registered keys,
        since none of them comes from a file any more (the client cannot sign in)."""
        if spec.key_missing:
            missing = Change(
                "client", spec.client_id, f"no key file {spec.key_file}", "set_client_key",
                KEY_EVENT,
            )
            if self.apply:
                self._note(f"client {spec.client_id}: no key file {spec.key_file}")
            else:
                self.report(missing)
        attributes = dict(current.get("attributes") or {})
        try:
            registered = json.loads(attributes.get("jwks.string") or "{}").get("keys") or []
        except (ValueError, AttributeError):
            registered = None
        rep = spec.representation()
        stale = current.get("clientAuthenticatorType") != "client-jwt" or any(
            attributes.get(k) != v for k, v in rep["attributes"].items()
        )
        if registered == spec.jwks and not stale:
            return
        if registered == spec.jwks:
            action, operation = "key settings corrected", "set_client_key"
        elif spec.key_missing:
            action, operation = "registered keys removed, no key file", "rotate_client_key"
        elif not registered:
            action, operation = f"public key registered from {spec.key_file}", "set_client_key"
        else:
            action = f"registered keys replaced by the keys of {spec.key_file}"
            operation = "rotate_client_key"
        attributes["jwks.string"] = (
            json.dumps({"keys": spec.jwks}, sort_keys=True) if spec.jwks else ""
        )
        body = {k: v for k, v in rep.items() if k != "clientId"}
        body["attributes"] = dict(attributes, **body["attributes"])
        self.do(
            Change("client", spec.client_id, action, operation, KEY_EVENT),
            "PUT",
            f"/clients/{current['id']}",
            body,
        )

    # service accounts -----------------------------------------------------
    def credential(self, spec: ClientSpec, current: dict) -> None:
        """Keycloak holds exactly the public key of the account's key file. A missing key
        file gets a new key pair (the module must then read the new file); any other
        registered key (a stranger's, or the old one of an interrupted rotation) goes."""
        account = spec.client_id
        jwk = self.keys.public_jwk(account)
        attributes = dict(current.get("attributes") or {})
        try:
            registered = json.loads(attributes.get("jwks.string") or "{}").get("keys")
        except (ValueError, AttributeError):
            registered = None
        if jwk is not None and registered == [jwk]:
            return
        if jwk is None:
            action = "new key pair, no key file in the configuration directory"
        elif not registered:
            action = "public key registered"
        else:
            action = "registered keys set to the key file's public key"
        change = Change(
            SERVICE_ACCOUNT, account, action, "set_key", "service_account_rotated", "write"
        )
        if self.apply and jwk is None:
            jwk = self.keys.generate(account)
        attributes["jwks.string"] = json.dumps({"keys": [jwk]}, sort_keys=True) if jwk else ""
        attributes[ROTATED_AT] = _now_iso()
        body = {k: v for k, v in spec.representation().items() if k != "clientId"}
        body["attributes"] = dict(attributes, **body["attributes"])
        self.do(change, "PUT", f"/clients/{current['id']}", body)

    def undeclared_accounts(self, clients: dict[str, dict]) -> None:
        """Clients with an active service account are exactly the declared ones (and the
        sync account). A managed account without declaration is deleted with its key
        folder; another client loses its service account. `--check` reports both first.
        A registered legacy account of a module's own setup is named, not changed."""
        for client_id, client in sorted(clients.items()):
            if client_id in self.plan.clients or client_id in CORE_ACCOUNTS:
                continue
            attributes = client.get("attributes") or {}
            if attributes.get(MANAGED) == "true" and attributes.get(KIND) == SERVICE_ACCOUNT:
                self.do(
                    Change(
                        SERVICE_ACCOUNT,
                        client_id,
                        "removed, no installed module declares it",
                        "delete_service_account",
                        effect="delete",
                    ),
                    "DELETE",
                    f"/clients/{client['id']}",
                )
                if self.apply and self.keys:
                    with contextlib.suppress(ValueError):
                        self.keys.remove(client_id)
            elif not client.get("serviceAccountsEnabled") or client.get("bearerOnly"):
                continue
            elif client_id in self.plan.legacy_accounts:
                self._note(
                    f"service account {client_id} is created by its module's own setup, not "
                    "declared in service_accounts[]; it is left as it is"
                )
            else:
                self.do(
                    Change(
                        "client",
                        client_id,
                        "service account turned off, it is not declared",
                        "remove_service_account",
                        effect="delete",
                    ),
                    "PUT",
                    f"/clients/{client['id']}",
                    {"serviceAccountsEnabled": False},
                )

    def account_users(self) -> None:
        """A service-account user holds exactly the roles of its account's token scope
        (and the realm's default roles), no client role and no group: Keycloak gives a
        client_credentials token the user's roles within the client's scope."""
        act = self.master
        clients = self._clients() if self.apply else None
        for spec in self._accounts:
            current = (clients or {}).get(spec.client_id) or self._existing(spec.client_id)
            if current is None or not current.get("serviceAccountsEnabled"):
                continue
            user = act.call("GET", f"/clients/{current['id']}/service-account-user")["id"]
            for group in act.call("GET", f"/users/{user}/groups") or []:
                act.do(
                    Change(
                        SERVICE_ACCOUNT,
                        spec.client_id,
                        f"left group {group.get('path') or group.get('name')}",
                        "revoke_service_account_role",
                        effect="delete",
                    ),
                    "DELETE",
                    f"/users/{user}/groups/{group['id']}",
                )
            base = f"/users/{user}/role-mappings"
            mappings = act.call("GET", base) or {}
            wanted = self._token_scope(spec)
            have = {r["name"]: r for r in mappings.get("realmMappings") or []}
            allowed = wanted | {f"default-roles-{kcs._REALM}"}
            extra = [have[n] for n in sorted(set(have) - allowed)]
            if extra:
                act.do(
                    Change(
                        SERVICE_ACCOUNT,
                        spec.client_id,
                        f"realm roles out of its rights: {_names(extra)}",
                        "revoke_service_account_role",
                        effect="delete",
                    ),
                    "DELETE",
                    f"{base}/realm",
                    extra,
                )
            missing = sorted(wanted - set(have))
            if missing:
                reps = (
                    [act.call("GET", f"/roles/{urllib.parse.quote(n)}") for n in missing]
                    if self.apply
                    else []
                )
                act.do(
                    Change(
                        SERVICE_ACCOUNT,
                        spec.client_id,
                        f"realm roles granted: {', '.join(missing)}",
                        "grant_service_account_role",
                    ),
                    "POST",
                    f"{base}/realm",
                    reps,
                )
            for client_id, entry in sorted((mappings.get("clientMappings") or {}).items()):
                roles = entry.get("mappings") or []
                if roles:
                    act.do(
                        Change(
                            SERVICE_ACCOUNT,
                            spec.client_id,
                            f"{client_id} roles out of its rights: {_names(roles)}",
                            "revoke_service_account_role",
                            effect="delete",
                        ),
                        "DELETE",
                        f"{base}/clients/{entry['id']}",
                        roles,
                    )

    def _existing(self, client_id: str) -> dict | None:
        found = self.call("GET", f"/clients?clientId={urllib.parse.quote(client_id)}") or []
        return {k: v for k, v in found[0].items() if k != "secret"} if found else None

    def login_events(self) -> None:
        """Last use of a service account is its last CLIENT_LOGIN event: the realm stores
        that event type while any account is declared. Event types an operator chose are
        kept; with every type stored (an empty list) nothing changes."""
        if not self._accounts:
            return
        config = self.master.call("GET", "/events/config") or {}
        types = list(config.get("enabledEventTypes") or [])
        enabled = bool(config.get("eventsEnabled"))
        if enabled and (not types or LOGIN_EVENT in types):
            return
        body = dict(config)
        body["eventsEnabled"] = True
        body["enabledEventTypes"] = sorted(set(types if enabled else []) | {LOGIN_EVENT})
        if not config.get("eventsExpiration"):
            body["eventsExpiration"] = EVENTS_EXPIRATION
        self.master.do(
            Change(
                "realm",
                kcs._REALM,
                f"sign-ins of service accounts recorded ({LOGIN_EVENT} events)",
                "record_service_account_use",
            ),
            "PUT",
            "/events/config",
            body,
        )

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
        Bearer-only clients never obtain a token, so a scope there has no effect, unless
        the client has token exchange switched on: no client with token exchange keeps an
        `aud-*` scope. Keycloak's own `realm-management` is bearer-only without exchange
        and cannot be changed from inside the realm."""
        for client_id, client in sorted(clients.items()):
            attributes = client.get("attributes") or {}
            exchange = attributes.get(TOKEN_EXCHANGE) == "true"
            if client_id in self.plan.clients or (client.get("bearerOnly") and not exchange):
                continue
            if attributes.get(MANAGED) == "true" and attributes.get(KIND) == SERVICE_ACCOUNT:
                continue  # an undeclared account is removed as a whole
            for kind in ("default", "optional"):
                for name in sorted(client.get(f"{kind}ClientScopes") or []):
                    if name != OFFLINE and not name.startswith("aud-"):
                        continue
                    self.by_id(
                        Change(
                            "client",
                            client_id,
                            _scope_removed(kind, name, exchange),
                            "remove_scope",
                            "exchange_right_changed",
                            "delete",
                        ),
                        "DELETE",
                        f"/clients/{client['id']}/{kind}-client-scopes",
                        (scopes.get(name) or {}).get("id"),
                        f"client scope {name}",
                    )

    def never_audience(self) -> None:
        """No client that exchanges tokens is an audience, the chain holder aside: no
        scope `aud-<client>` and no audience mapper naming it, on any client scope or any
        client. Managed clients, Keycloak's shared scopes and the exchange scopes are
        already checked above (they carry no foreign audience at all)."""
        never = self.plan.never_audiences
        checked = DEFAULT_SCOPES | {OFFLINE} | set(self.plan.exchange_scopes)
        if self.plan.person_scope:
            checked |= {PERSON_SCOPE}
        for name, scope in sorted(self._scopes().items()):
            if name in {exchange_scope(n) for n in never}:
                self.do(
                    Change(
                        "client-scope",
                        name,
                        f"removed, {name.removeprefix('aud-')} exchanges tokens and is never "
                        "an audience",
                        "delete_scope",
                        "exchange_right_changed",
                        "delete",
                    ),
                    "DELETE",
                    f"/client-scopes/{scope['id']}",
                )
            elif name not in checked:
                base = f"/client-scopes/{scope['id']}/protocol-mappers/models"
                self._never_audience_mappers("client-scope", name, scope, base)
        for client_id, client in sorted(self._clients().items()):
            if client_id not in self.plan.clients:
                base = f"/clients/{client['id']}/protocol-mappers/models"
                self._never_audience_mappers("client", client_id, client, base)

    def chain_holder_mark(self) -> None:
        """`papaia.chain-holder` names the client `data-chain` applies to; no client but
        the installed chain holder carries it, with any value (the holder's own value is
        set in `client`). An empty value is how Keycloak removes an attribute."""
        holder = CHAIN_HOLDER if CHAIN_HOLDER in self.plan.clients else None
        for client_id, client in sorted(self._clients().items()):
            if client_id == holder or CHAIN_HOLDER_MARK not in (client.get("attributes") or {}):
                continue
            self.do(
                Change(
                    "client",
                    client_id,
                    f"attribute {CHAIN_HOLDER_MARK} removed (only {CHAIN_HOLDER} holds the chain)",
                    "remove_client_attribute",
                    "exchange_right_changed",
                    "delete",
                ),
                "PUT",
                f"/clients/{client['id']}",
                {"attributes": {CHAIN_HOLDER_MARK: ""}},
            )

    def _never_audience_mappers(self, kind: str, name: str, holder: dict, base: str) -> None:
        for mapper in holder.get("protocolMappers") or []:
            audience = _mapper_audience(mapper)
            if audience not in self.plan.never_audiences:
                continue
            self.do(
                Change(
                    kind,
                    name,
                    f"mapper {mapper.get('name')} removed ({audience} is never an audience)",
                    "remove_mapper",
                    "exchange_right_changed",
                    "delete",
                ),
                "DELETE",
                f"{base}/{mapper['id']}",
            )

    # client policies -------------------------------------------------------
    def client_policies(self) -> None:
        """The realm's client profiles and policies the sync owns are exactly the planned
        ones; every other profile or policy is left as it is. Keycloak replaces the whole
        list on each write, so each change is one write of the full list (and one audit
        row): profiles the planned policies need first, then stale policies out and
        planned ones in, stale profiles last (a policy names its profiles)."""
        profiles = (self.call("GET", "/client-policies/profiles") or {}).get("profiles") or []
        policies = (self.call("GET", "/client-policies/policies") or {}).get("policies") or []
        profiles = self._align("profiles", profiles, self.plan.profiles, lambda n: False)
        policies = self._align("policies", policies, self.plan.policies, _managed_policy)
        self._align("profiles", profiles, self.plan.profiles, MANAGED_PROFILES.__contains__)

    def _align(self, kind: str, items: list[dict], wanted: dict[str, dict], stale) -> list[dict]:
        """Remove each item named `stale(name)` that is not wanted, then add or correct
        each wanted one; one PUT of the whole list per change. Returns the new list."""
        noun, keys = _POLICY_KINDS[kind]
        label = f"client-{noun}"

        def write(change: Change, new: list[dict]) -> list[dict]:
            self.do(change, "PUT", f"/client-policies/{kind}", {kind: new})
            return new

        for item in list(items):
            name = item.get("name") or ""
            if stale(name) and name not in wanted:
                change = Change(
                    label,
                    name,
                    "removed, no longer planned",
                    f"delete_{noun}",
                    "exchange_right_changed",
                    "delete",
                )
                items = write(change, [i for i in items if i.get("name") != name])
        for name, want in sorted(wanted.items()):
            have = _named(items, name)
            if have is not None and all(have.get(k) == want.get(k) for k in keys):
                continue
            if have is None:
                change = Change(label, name, "created", f"create_{noun}", "exchange_right_changed")
                items = write(change, [*items, want])
            else:
                change = Change(
                    label, name, "settings corrected", f"update_{noun}", "exchange_right_changed"
                )
                items = write(change, [want if i.get("name") == name else i for i in items])
        return items


# What the sync compares of a realm client policy or profile; Keycloak 26.7.0 returns
# them exactly as written.
_POLICY_KINDS = {
    "policies": ("policy", ("name", "description", "enabled", "conditions", "profiles")),
    "profiles": ("profile", ("name", "description", "executors")),
}


def _named(items: list[dict], name: str) -> dict | None:
    return next((i for i in items if i.get("name") == name), None)


def _mapper_audience(mapper: dict) -> str | None:
    config = mapper.get("config") or {}
    return config.get("included.client.audience") or config.get("included.custom.audience")


# ─────────────────────────────────────────────────────────────────────────
# the name list of the Paperless gate
# ─────────────────────────────────────────────────────────────────────────


def paperless_users_path(config_dir: Path) -> Path:
    return config_dir / PAPERLESS_USERS_REF


def paperless_users(call, roles: frozenset[str]) -> list[str]:
    """The user names of the active persons holding one of `roles` as an effective realm
    role (direct, through a group or a composite), sorted. `call` must be allowed to read
    accounts (the master admin). Service accounts are never listed: Keycloak leaves them
    out of the user list, and one that shows up anyway is skipped. A name that could not
    be compared with a header value safely is left out and noted by account id."""
    if not roles:
        return []
    names: set[str] = set()
    first = 0
    while True:
        page = call("GET", f"/users?briefRepresentation=true&first={first}&max={USER_PAGE}") or []
        for user in page:
            uid = user.get("id")
            if (
                user.get("enabled") is not True
                or user.get("serviceAccountClientLink")
                or not isinstance(uid, str)
                or not uid
            ):
                continue
            held = call(
                "GET", f"/users/{urllib.parse.quote(uid, safe='')}/role-mappings/realm/composite"
            )
            if not roles & {r.get("name") for r in held or []}:
                continue
            name = user.get("username")
            if not isinstance(name, str) or not _HEADER_NAME_RE.match(name):
                print(
                    f"  note: account {uid}: its user name cannot be compared with a header "
                    "value safely; it is not on the Paperless name list",
                    flush=True,
                )
                continue
            names.add(name)
        if len(page) < USER_PAGE:
            return sorted(names)
        first += USER_PAGE


def _gate_directory(config_dir: Path, *, create: bool) -> int | None:
    """A descriptor of the list's directory, created (0755) with `create`; None when it
    does not exist. A symbolic link, or a directory someone else could change, is
    refused."""
    directory = paperless_users_path(config_dir).parent
    if create:
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        try:
            os.mkdir(directory, 0o755)
            os.chmod(directory, 0o755)  # the gate runs under its own uid and must read it
        except FileExistsError:
            pass
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RealmSyncError(
            f"{directory} cannot be opened safely (a symbolic link is refused): {exc.strerror}"
        ) from None
    try:
        _trusted(os.fstat(fd), directory, "the Paperless identity header")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_list(dfd: int | None, name: str) -> bytes | None:
    """The current list; None when there is none, b"" when it is no regular file."""
    if dfd is None:
        return None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError:
        return b""  # a symbolic link or worse: replaced, never followed
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return b""
        return fh.read()


def _replace_list(dfd: int, name: str, content: bytes) -> None:
    """Write `content` beside the list and rename it into place: the gate reads either
    the old or the new list, never a part. A bind mount of the single file would keep
    the old inode, so the gate mounts the directory."""
    tmp = f".{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o644)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dfd)
        raise
    os.fsync(dfd)


def sync_paperless_users(
    call, plan: Plan, config_dir: Path, *, apply: bool, audit: AuditLog | None = None
) -> list[Change]:
    """Compare the Paperless name list with the realm behind `call` (the master admin);
    with `apply`, rewrite it (or remove it when no module serves mcp-paperless). One
    audit row per write or removal, never with a name. Returns the deviation, if any."""
    name = paperless_users_path(config_dir).name
    if plan.paperless_roles is None:
        target = None
    else:
        users = paperless_users(call, plan.paperless_roles)
        doc = {"format": PAPERLESS_USERS_FORMAT, "users": users}
        target = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    dfd = _gate_directory(config_dir, create=apply and target is not None)
    try:
        current = _read_list(dfd, name)
        if current == target:
            return []
        if target is None:
            change = Change(
                "file",
                PAPERLESS_USERS_REF,
                f"Paperless name list removed (no module serves {PAPERLESS_AUDIENCE})",
                "paperless_users.delete",
                effect="delete",
            )
        else:
            change = Change(
                "file",
                PAPERLESS_USERS_REF,
                f"Paperless name list written ({len(users)} name(s))",
                "paperless_users.write",
            )
        print(
            f"{'  ' if apply else 'fail: '}{change.kind} {change.name}: {change.action}", flush=True
        )
        if not apply:
            return [change]
        assert dfd is not None  # created above, or the list to remove exists
        try:
            if target is None:
                os.unlink(name, dir_fd=dfd)
            else:
                _replace_list(dfd, name, target)
        except OSError:
            if audit:
                audit.write(change, "error", "io", master=True)
            raise
        if audit:
            audit.write(change, "allowed", master=True)
        return [change]
    finally:
        if dfd is not None:
            os.close(dfd)


def sync_platform_groups(
    call, config_dir: Path, *, apply: bool, audit: AuditLog | None = None
) -> list[Change]:
    """Compare `platform/groups.json` with the groups of the realm behind `call` (the
    master admin); with `apply`, rewrite it. Only id, path, display name and the
    technical mark are written, never a member (catalog.groups_from_realm). One audit
    row per write. Returns the deviation, if any."""
    from . import catalog  # it imports the render path

    try:
        groups = catalog.groups_from_realm(call)
    except catalog.CatalogError as exc:
        raise RealmSyncError(str(exc)) from None
    if catalog.current_groups(config_dir) == groups:
        return []
    change = Change(
        "file",
        f"{catalog.CATALOG_DIR}/{catalog.GROUPS_FILE}",
        f"group list written ({len(groups)} group(s))",
        "platform_groups.write",
    )
    print(f"{'  ' if apply else 'fail: '}{change.kind} {change.name}: {change.action}", flush=True)
    if not apply:
        return [change]
    try:
        catalog.write_groups(config_dir, groups)
    except (OSError, catalog.CatalogError) as exc:
        if audit:
            audit.write(change, "error", "io", host=True)
        if isinstance(exc, catalog.CatalogError):
            raise RealmSyncError(str(exc)) from None
        raise
    # The master admin only read the groups; the write is a file on the host, so the row
    # names the host like the one for services.json (catalog.render).
    if audit:
        audit.write(change, "allowed", host=True)
    return [change]


def sync_template_users(
    call, hardening: rh.Hardening, *, apply: bool, audit: AuditLog | None = None
) -> list[Change]:
    """Take the known password away from the accounts the 1.9.0 realm template created
    (`admin`/`admin`, `testuser`/`testuser`) while they still have it (rh.known_password):
    `admin` gets KC_REALM_ADMIN_PASSWORD as a temporary password (changed at the next
    sign-in), every other one, and `admin` without that value, is disabled. `call` must
    be allowed to manage accounts (the master admin). One audit row per write, never with
    the password. Returns the deviations found (= the changes made when applying)."""
    actions = _Actions(call, apply, audit, master=True)
    for name in sorted(rh.TEMPLATE_USERS):
        query = urllib.parse.urlencode({"username": name, "exact": "true"})
        for user in call("GET", f"/users?{query}") or []:
            uid = user.get("id")
            if not isinstance(uid, str) or not uid:
                continue
            base = f"/users/{urllib.parse.quote(uid, safe='')}"
            if not rh.known_password(user, call("GET", f"{base}/credentials") or []):
                continue
            if name == rh.REALM_ADMIN and hardening.realm_admin_password:
                change = Change(
                    "user",
                    name,
                    f"the realm template's password replaced by {rh.REALM_ADMIN_PASSWORD_KEY}, "
                    "to be changed at the next sign-in",
                    "reset_template_password",
                )
                body = {
                    "type": "password",
                    "value": hardening.realm_admin_password,
                    "temporary": True,
                }
                actions.do(change, "PUT", f"{base}/reset-password", body)
            else:
                change = Change(
                    "user",
                    name,
                    "disabled, it still has the realm template's password",
                    "disable_template_user",
                )
                actions.do(change, "PUT", base, {"enabled": False})
    return actions.changes


def reconcile(
    call,
    plan: Plan,
    *,
    apply: bool,
    audit: AuditLog | None = None,
    keys: sak.KeyStore | None = None,
    master=None,
) -> list[Change]:
    """Compare the realm behind `call` with `plan`; with `apply`, correct every deviation.
    Returns the deviations found (= the changes made when applying). Declared service
    accounts need `keys` (their key folder) and `master` (the master admin's call)."""
    return _Reconciler(call, plan, apply, audit, keys=keys, master=master).run()


def keystore(config_dir: Path) -> sak.KeyStore:
    """The key pairs of the service accounts in the configuration directory."""
    return sak.KeyStore(config_dir / "security" / "service-accounts")


class MasterAdmin:
    """The master admin's Admin API call, signing in again when the token may be near
    its end (master tokens of admin-cli live 60 s by default)."""

    REFRESH_AFTER = 30.0

    def __init__(self, base_url: str, ctx, password: str) -> None:
        self.base_url, self.ctx, self.password = base_url, ctx, password
        self._api: AdminApi | None = None
        self._since = 0.0

    def call(self, method: str, path: str, body: object = None):
        if self._api is None or time.monotonic() - self._since > self.REFRESH_AFTER:
            token = kcs._get_admin_token(self.base_url, self.ctx, self.password)
            self._api, self._since = AdminApi(self.base_url, self.ctx, token), time.monotonic()
        return self._api.call(method, path, body)


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
    keycloak = tree.get(kcs._KEYCLOAK_NODE, {})
    try:
        register = load_register()
        from . import people_account  # it imports this module

        plan = build_plan(
            register,
            load_modules(config_dir, repo_root),
            load_pairings(pairings_path(config_dir), register),
            core_audiences=people_account.core_audiences(tree),
        )
        plan.hardening = rh.load(
            {**root, **keycloak},
            tree.get("ai/librechat", {}),
            lifetime=delegation_lifetime.stored(config_dir),
        )
        removed = _uninstalled(config_dir, plan)
    except (RealmSyncError, rh.HardeningError, delegation_lifetime.LifetimeError) as exc:
        print(f"Realm sync refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    for note in plan.notes + plan.hardening.notes:
        print(f"  {note}", flush=True)

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
            # The name list first: a reconcile that stops must not keep a removed account
            # on it. Accounts are read with the master admin (no view-users for the
            # sync account); a fresh token, the first may have run out meanwhile.
            master = AdminApi(base_url, ctx, kcs._get_admin_token(base_url, ctx, admin_password))
            # Before the name list: a disabled template account is not on it.
            changes += sync_template_users(
                master.call, plan.hardening, apply=not check, audit=audit
            )
            changes += sync_paperless_users(
                master.call, plan, config_dir, apply=not check, audit=audit
            )
            # The group list next to the catalog (RE-14): read with the master admin,
            # who may list groups; no right is added for it.
            changes += sync_platform_groups(
                master.call, config_dir, apply=not check, audit=audit
            )
            api = AdminApi(base_url, ctx, token)
            reconciler = _Reconciler(
                api.call,
                plan,
                not check,
                audit,
                keys=keystore(config_dir),
                master=MasterAdmin(base_url, ctx, admin_password).call,
            )
            changes += reconciler.run()
            skipped += reconciler.skipped
            from . import lifecycle_account  # it imports this module

            changes += lifecycle_account.align(
                MasterAdmin(base_url, ctx, admin_password).call,
                keystore(config_dir),
                enabled=lifecycle_account.enabled(tree),
                apply=not check,
                audit=audit,
            )
            changes += people_account.align(
                MasterAdmin(base_url, ctx, admin_password).call,
                keystore(config_dir),
                enabled=people_account.enabled(tree),
                apply=not check,
                audit=audit,
            )
    except (RealmSyncError, sak.KeyFileError) as exc:
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
    if removed:
        try:
            uninstall_journal.done(config_dir, uninstall_journal.REALM, removed)
        except (uninstall_journal.JournalError, OSError) as exc:
            print(f"WARNING: {exc}", file=sys.stderr, flush=True)
    print(f"Realm sync complete: {len(changes)} change(s).", flush=True)
    return 0


def apply_keys(tree: dict, config_dir: Path, repo_root: Path, module: str) -> int:
    """`papaia-ctl realm keys apply <module>`: register the current key files of the
    module's declared `client_keys` without a full sync. Every declaration is checked
    as for `realm sync` first. 0: applied (or nothing to do), 1: Keycloak not reachable
    or a client not created yet, 2: refused (nothing changed)."""
    root = tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        print("Client keys skipped: AUTH_PROVIDER is not internal_keycloak.", flush=True)
        return 0
    if not isinstance(module, str) or len(module) > 64 or not _NAME_RE.match(module):
        print(f"Client keys refused: {module!r} is not a module name.", file=sys.stderr)
        return 2
    keycloak = tree.get(kcs._KEYCLOAK_NODE, {})
    try:
        register = load_register()
        plan = build_plan(
            register,
            load_modules(config_dir, repo_root),
            load_pairings(pairings_path(config_dir), register),
        )
    except RealmSyncError as exc:
        print(f"Client keys refused: {exc}. Nothing was changed.", file=sys.stderr, flush=True)
        return 2
    specs = [
        s for _, s in sorted(plan.clients.items()) if s.key_file is not None and s.owner == module
    ]
    if not specs:
        print(
            f"Client keys refused: {module} is not installed or declares no client_keys.",
            file=sys.stderr,
            flush=True,
        )
        return 2
    admin_password = kcs._compose_value(keycloak.get("KC_ADMIN_PASSWORD", ""))
    secret = kcs._compose_value(keycloak.get(SYNC_SECRET_KEY, ""))
    if kcs._unset(secret) or secret.startswith("GENERATE_"):
        print(
            f"Client keys skipped: {SYNC_SECRET_KEY} is not set. Run 'papaia-ctl setup' first.",
            file=sys.stderr,
            flush=True,
        )
        return 1
    base_url, ctx = kcs._admin_connection(root, config_dir)
    try:
        with AuditLog(audit_path(config_dir), new_correlation_id()) as audit:
            kcs._wait_for_keycloak(base_url, ctx)
            token, _, _ = sync_account_token(
                base_url, ctx, admin_password, secret, audit, apply=True
            )
            if token is None:
                print("Client keys failed: the sync account cannot sign in.", file=sys.stderr)
                return 1
            reconciler = _Reconciler(
                AdminApi(base_url, ctx, token).call,
                plan,
                True,
                audit,
                keys=keystore(config_dir),
                master=MasterAdmin(base_url, ctx, admin_password).call,
            )
            clients = reconciler._clients()
            for spec in specs:
                current = clients.get(spec.client_id)
                if current is None:
                    print(
                        f"Client keys incomplete: {spec.client_id} does not exist yet; "
                        "run 'papaia-ctl realm sync'.",
                        file=sys.stderr,
                        flush=True,
                    )
                    return 1
                reconciler.client_key(spec, current)
    except (RealmSyncError, sak.KeyFileError, TimeoutError, OSError) as exc:
        print(f"Client keys failed: {exc}", file=sys.stderr, flush=True)
        return 1
    except urllib.error.HTTPError as exc:
        path = urllib.parse.urlsplit(exc.url or "").path
        print(f"Client keys failed: HTTP {exc.code} on {path}", file=sys.stderr, flush=True)
        return 1
    print(
        f"Client keys of {module} applied: {len(reconciler.changes)} change(s).", flush=True
    )
    return 0


def _uninstalled(config_dir: Path, plan: Plan) -> set[str]:
    """Set `plan.uninstalled` from the uninstall journal and return the recorded module
    names it covers. A module installed again keeps its clients."""
    try:
        recorded = uninstall_journal.pending(config_dir, uninstall_journal.REALM)
    except uninstall_journal.JournalError as exc:
        raise RealmSyncError(str(exc)) from None
    owners = {spec.owner for spec in plan.clients.values()}
    names = {name for name in recorded if name not in owners}
    plan.uninstalled = frozenset(_owner_value(name) for name in names)
    return names
