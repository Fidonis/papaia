"""Sign-in addresses of add-on clients: the manifest key `client_addresses[]` (addon_api 18).

An add-on names, for a confidential client it owns in the names register, the paths of
its sign-in addresses on one of its own interfaces (`integration.nginx`):

    client_addresses:
      - client: flow-console
        host_key: console
        redirects: [/auth/callback]
        post_logout: [/]
        backchannel_logout: /auth/backchannel-logout
        web_origin: true

The core gives the interface its host name (lib/ingress.py), so the manifest never names
a host; `papaia-ctl realm sync` sets exactly these addresses on that host and removes the
ones the manifest no longer declares (lib/realm_sync.py, lib/realm_hardening.py). The add-on
holds no realm token for it. ADR 0028.

This module checks the declaration: the shape, the host key and the paths here, the
client against the names register in `check_owner`. A path is absolute and exact: it
starts with `/`, has no wildcard, query, fragment, `..`, `.` or empty segment, and only the
characters of an unreserved path (no percent-encoding). At most 8 entries, at most 8
redirects and 8 post-logout redirects per client.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass

KEY = "client_addresses"
MAX_ENTRIES = 8
MAX_PATHS = 8
MAX_PATH_LENGTH = 255
FIELDS = frozenset(
    {"client", "host_key", "redirects", "post_logout", "backchannel_logout", "web_origin"}
)
REQUIRED = frozenset({"client", "host_key", "redirects"})
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


class ClientAddressError(ValueError):
    """A declaration that is refused; the message names the entry and the reason."""


@dataclass(frozen=True)
class Declaration:
    client: str
    host_key: str
    redirects: tuple[str, ...]
    post_logout: tuple[str, ...]
    backchannel_logout: str | None
    web_origin: bool
    index: int

    @property
    def label(self) -> str:
        return f"{KEY}[{self.index}] ({self.client})"


def path_problem(path: object) -> str | None:
    """Why `path` is not an absolute, exact path on the add-on's host, or None."""
    if not isinstance(path, str) or not path.startswith("/"):
        return "must be an absolute path starting with '/' (the core adds the host)"
    if len(path) > MAX_PATH_LENGTH:
        return f"is longer than {MAX_PATH_LENGTH} characters"
    if "*" in path:
        return "has a wildcard; only exact paths are allowed"
    if "?" in path:
        return "has a query; only exact paths are allowed"
    if "#" in path:
        return "has a fragment; only exact paths are allowed"
    if "//" in path:
        return "has '//'"
    segments = path[1:].split("/")
    if segments[-1] == "":
        segments.pop()
    for segment in segments:
        if segment in ("..", "."):
            return "has a '..' or '.' segment"
        if not _SEGMENT_RE.match(segment):
            return "has characters outside A-Z a-z 0-9 . _ ~ - (no percent-encoding)"
    return None


def _paths(value: object, where: str, field: str, *, required: bool) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list):
        raise ClientAddressError(f"{where}: {field} must be a list of paths")
    if required and not value:
        raise ClientAddressError(f"{where}: {field} needs at least one path")
    if len(value) > MAX_PATHS:
        raise ClientAddressError(f"{where}: {field} may name at most {MAX_PATHS} paths")
    for path in value:
        problem = path_problem(path)
        if problem:
            raise ClientAddressError(f"{where}: {field} {path!r} {problem}")
    if len(set(value)) != len(value):
        raise ClientAddressError(f"{where}: {field} names a path twice")
    return tuple(value)


def parse(value: object, host_keys: frozenset[str]) -> list[Declaration]:
    """The declarations of `client_addresses`, in manifest order. `host_keys` are the host
    keys of the add-on's `integration.nginx` list. ClientAddressError names the entry."""
    if not isinstance(value, list):
        raise ClientAddressError(f"{KEY} must be a list")
    if len(value) > MAX_ENTRIES:
        raise ClientAddressError(f"{KEY} may have at most {MAX_ENTRIES} entries")
    found: list[Declaration] = []
    for index, entry in enumerate(value):
        where = f"{KEY}[{index}]"
        if not isinstance(entry, dict):
            raise ClientAddressError(f"{where} must be a mapping")
        client = entry.get("client")
        if isinstance(client, str) and client:
            where = f"{where} ({client[:64]})"
        unknown = sorted(str(k) for k in set(entry) - FIELDS)
        if unknown:
            raise ClientAddressError(f"{where}: unknown field {', '.join(unknown)}")
        missing = sorted(REQUIRED - set(entry))
        if missing:
            raise ClientAddressError(f"{where}: missing field {', '.join(missing)}")
        if not isinstance(client, str) or not client or len(client) > 64:
            raise ClientAddressError(f"{where}: client must be a client name")
        host_key = entry["host_key"]
        if not isinstance(host_key, str) or host_key not in host_keys:
            known = ", ".join(sorted(host_keys)) or "none"
            raise ClientAddressError(
                f"{where}: host_key {host_key!r} is not one of the add-on's"
                f" integration.nginx entries ({known})"
            )
        redirects = _paths(entry["redirects"], where, "redirects", required=True)
        post_logout = _paths(entry.get("post_logout"), where, "post_logout", required=False)
        backchannel = entry.get("backchannel_logout")
        if backchannel is not None:
            problem = path_problem(backchannel)
            if problem:
                raise ClientAddressError(f"{where}: backchannel_logout {backchannel!r} {problem}")
        web_origin = entry.get("web_origin", False)
        if not isinstance(web_origin, bool):
            raise ClientAddressError(f"{where}: web_origin must be true or false")
        if any(d.client == client for d in found):
            raise ClientAddressError(f"{where}: {client} is declared twice")
        found.append(
            Declaration(client, host_key, redirects, post_logout, backchannel, web_origin, index)
        )
    return found


def host_keys_of(manifest: dict) -> frozenset[str]:
    """The host keys of the list form of `integration.nginx` (empty without it)."""
    integration = manifest.get("integration")
    nginx = integration.get("nginx") if isinstance(integration, dict) else None
    if not isinstance(nginx, list):
        return frozenset()
    return frozenset(
        e["host_key"] for e in nginx if isinstance(e, dict) and isinstance(e.get("host_key"), str)
    )


@functools.lru_cache(maxsize=1)
def _register():
    from . import realm_sync  # it imports compat, which imports this module

    return realm_sync.load_register()


def check_owner(declarations: list[Declaration], owner: str, register=None) -> None:
    """Every client is a registered confidential sign-in client of `owner`: not a client
    of the core, of another module, a public, bearer-only or exchange-only client."""
    from . import realm_hardening as rh
    from . import realm_sync as rs

    register = register or _register()
    for decl in declarations:
        entry = register.clients.get(decl.client)
        if entry is None or entry.test_profile_only:
            raise ClientAddressError(f"{decl.label}: {decl.client!r} is not a registered client")
        if entry.owner in rs.CORE_OWNERS or decl.client in rh.CORE_CLIENTS:
            raise ClientAddressError(
                f"{decl.label}: {decl.client} is a client of the core; its addresses come from"
                " the core's own settings"
            )
        if entry.owner != owner:
            raise ClientAddressError(
                f"{decl.label}: {decl.client} belongs to {entry.owner}, not {owner}"
            )
        kind = rs.client_kind(register, decl.client)
        if kind == "public":
            raise ClientAddressError(
                f"{decl.label}: {decl.client} is a public client; only confidential clients"
                " get sign-in addresses"
            )
        if kind == "bearer":
            raise ClientAddressError(
                f"{decl.label}: {decl.client} is bearer-only and never signs in"
            )
        if kind != "confidential":
            raise ClientAddressError(f"{decl.label}: {decl.client} signs nobody in")


def check_manifest(manifest: dict, name: str) -> list[Declaration]:
    """The declarations of a manifest, checked against its interfaces and the names
    register ([] without the key). ClientAddressError names the entry."""
    if manifest.get(KEY) is None:
        return []
    declarations = parse(manifest[KEY], host_keys_of(manifest))
    owner = manifest.get("name") or name
    check_owner(declarations, owner if isinstance(owner, str) else name)
    return declarations


def addresses(decl: Declaration, base: str) -> tuple:
    """(redirects, web origins, post-logout redirects, back-channel URL) of `decl` on the
    host `base` (scheme, host and port, no path)."""
    return (
        tuple(base + p for p in decl.redirects),
        (base,) if decl.web_origin else (),
        tuple(base + p for p in decl.post_logout),
        base + decl.backchannel_logout if decl.backchannel_logout else None,
    )
