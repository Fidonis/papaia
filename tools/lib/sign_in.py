"""One sign-in, one sign-out and one entry page for every module (PLT-29, PLT-71).

Interface spec 2.3 and 2.6, security spec 1.7 (row "Abmeldung"):

- Sign-in. Every module signs persons in at the same identity provider with the login
  theme `papaia`, which the core builds from the kit's theme (`kit_snapshot.py` copies the
  kit's files, `src/infra/keycloak/themes/papaia/login/`). The realm sync gives each
  module's sign-in client below the theme when it has none (an operator's choice stays).
- Sign-out. Signing out in one module ends the single sign-on session at the identity
  provider. The provider then calls the back-channel logout address (OpenID Connect
  Back-Channel Logout 1.0) of every sign-in client that holds a session of it, and the
  module ends its own sessions of that `sid` at once. The core sets that address at each
  sign-in client from the table below, with the session id required and the front
  channel off (it needs the browser and third-party cookies; no module serves one). A
  module without an address learns of the sign-out at its next token refresh, which
  fails: access tokens live 240 s (realm_hardening), below the deadline of 300 s. After
  the sign-out the provider sends the browser to the module's own `/_kit/signed-out`, a
  page of the kit, which every post-logout redirect `<public URL>/*` admits.
- Entry page. The main address of the installation (the domain without a module host
  name) leads to the overview of Mein Bereich, the same page for every person. The bundled
  proxy answers it with a redirect; `papaia-ctl proxy list` names the redirect for an
  external proxy. Without Mein Bereich there is no entry page: each module lands on its
  own `/` after the sign-in. When another interface already serves the main address
  (e.g. Chat at the bare domain), there is none either, with a note; the proxy never
  takes over a host at the domain that does not forward to Mein Bereich.

The provider calls the add-ons' addresses from inside its container by their public
host names. Where they do not reach the proxy from there (the local `.localhost` names, a
host without hairpin NAT), the call fails and the module falls back to the token refresh.

The back-channel paths are the modules' own routes; a module states its path in its
own documentation, and the exposes contract has no field for it yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from . import common, ingress

# Sessions of every module end at the latest this many seconds after the sign-out
# (PLT-29-A1: a page loaded 301 s later leads to the sign-in).
DEADLINE = 300
ME_PROFILE = "me"
ME_URL_KEY = "ME_PUBLIC_URL"
ME_SERVICE, ME_PORT = "me-web", 8000
ENTRY_HOST_KEY = "entry"


@dataclass(frozen=True)
class SignInClient:
    """The client a module signs persons in with, and where it hears of a sign-out.

    `module` is the add-on's name (or `me` for the core profile), `host_key` the key of
    its interface in `integration.nginx`, `internal` the address on the stack network of
    a core profile, `path` the module's back-channel route (None: it has none)."""

    client_id: str
    module: str
    host_key: str | None
    internal: str | None
    path: str | None


SIGN_IN_CLIENTS: tuple[SignInClient, ...] = (
    SignInClient("papaia-me", ME_PROFILE, None, f"http://{ME_SERVICE}:{ME_PORT}",
                 "/auth/backchannel-logout"),
    SignInClient("flow-console", "papaia-flow", "flow", None, "/auth/backchannel-logout"),
    SignInClient("papaia-studio-gateway", "papaia-studio", "studio", None,
                 "/gw/v1/auth/backchannel-logout"),
    SignInClient("assist-api", "papaia-assist", "assistant", None, "/signin/backchannel-logout"),
    # Data's interface ends its session when the refresh fails (no back-channel route).
    SignInClient("papaia-data-ui", "papaia-data", "data", None, None),
)  # fmt: skip

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


def client_ids() -> frozenset[str]:
    return frozenset(c.client_id for c in SIGN_IN_CLIENTS)


def backchannel_targets(tree: dict, found: list[ingress.Route]) -> dict[str, str]:
    """The back-channel logout address of each installed module's sign-in client:
    Mein Bereich on the stack network while its profile is on, an add-on on the public
    address of its interface (`found`, lib/ingress.py). A module that is not installed,
    has no route or no back-channel route gets none."""
    active = common.cluster_profiles(tree.get("", {}))
    targets: dict[str, str] = {}
    for client in SIGN_IN_CLIENTS:
        if client.path is None:
            continue
        if client.internal is not None:
            if client.module in active:
                targets[client.client_id] = client.internal + client.path
            continue
        route = next(
            (r for r in found if r.module == client.module and r.host_key == client.host_key),
            None,
        )
        if route is not None:
            targets[client.client_id] = route.public_url.rstrip("/") + client.path
    return targets


def owned_addresses() -> dict[str, str]:
    """The back-channel addresses the core sets on the stack network, by client: the
    realm sync clears one of them again when its profile is off (an add-on's client
    goes with the add-on)."""
    return {c.client_id: c.internal + c.path for c in SIGN_IN_CLIENTS if c.internal and c.path}


# What reading the add-on routes can raise on unreadable add-on data: a scheme value or a
# claimed host name (IngressError, a ValueError), a file that cannot be read (OSError),
# text that is not UTF-8 (a ValueError), YAML that does not parse, or a deployment file
# or manifest of the wrong shape.
ROUTE_ERRORS: tuple[type[BaseException], ...] = (
    OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError,
)  # fmt: skip


def installation_targets(tree: dict, config_dir, repo_root) -> tuple[dict[str, str], list[str]]:
    """`backchannel_targets` for the installation, with a note instead of the add-ons'
    addresses when their interfaces cannot be listed (the realm sync goes on), and a
    note when the add-ons' addresses are local names the identity provider cannot reach.
    """
    try:
        found = ingress.routes(tree, config_dir, repo_root)
    except ROUTE_ERRORS as exc:
        return backchannel_targets(tree, []), [f"sign-out: add-on addresses not set ({exc})"]
    targets = backchannel_targets(tree, found)
    return targets, _local_notes(targets)


def _local_notes(targets: dict[str, str]) -> list[str]:
    """The identity provider calls a back-channel address from inside its container.
    A `.localhost` name resolves to that container's own loopback there, so the call
    of a local add-on fails and the module learns of the sign-out at its next token
    refresh (240 s)."""
    local = sorted(
        client_id
        for client_id, url in targets.items()
        if (urlsplit(url).hostname or "").endswith("." + ingress.LOCAL_SUFFIX)
    )
    if not local:
        return []
    return [
        f"sign-out: {', '.join(local)} use .localhost names the identity provider cannot"
        " call; these modules end their sessions at the next token refresh (240 s)"
    ]


# ─────────────────────────────────────────────────────────────────────────
# entry page
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Entry:
    """The main address of the installation and the entry page it leads to."""

    hostname: str
    public_url: str
    target: str

    def route(self, network: str) -> ingress.Route:
        """The main address as a route of the core (target: Mein Bereich's service; the
        proxy answers every request with the redirect before forwarding any)."""
        return ingress.Route(
            "core", ENTRY_HOST_KEY, (self.hostname,), self.public_url, ME_SERVICE, ME_PORT,
            "http", network,
        )  # fmt: skip


def main_hostname(tree: dict) -> str | None:
    """The host name of the main address (the host scheme's domain), or None: no proxy,
    no domain, or a scheme value that cannot be read."""
    try:
        scheme = ingress.host_scheme(tree.get("", {}))
    except ingress.IngressError:
        return None
    if scheme.provider == "no_proxy":
        return None
    return scheme.domain


def entry(tree: dict, found: list[ingress.Route] | None = None) -> Entry | None:
    """`entry_and_note` without the note."""
    return entry_and_note(tree, found)[0]


def entry_and_note(
    tree: dict, found: list[ingress.Route] | None = None
) -> tuple[Entry | None, str | None]:
    """The entry page of the installation, or None: no proxy, no domain, Mein Bereich off
    or not served by host name, or the main address already served by another interface
    of `found` (default: the core's, ingress.core_routes); only the last comes with a
    note. The target is built from the parsed host name and port of `ME_PUBLIC_URL`
    alone, so nothing else of the value reaches the proxy configuration."""
    root = tree.get("", {})
    if ME_PROFILE not in common.cluster_profiles(root):
        return None, None
    domain = main_hostname(tree)
    if domain is None:
        return None, None
    scheme = ingress.host_scheme(root)
    url = (root.get(ME_URL_KEY) or "").strip()
    if not ingress.is_proxied_url(url, ingress.edge_ports(root)):
        return None, None
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not _HOST_RE.match(hostname):
        return None, None
    if hostname == domain:
        return None, None
    if found is None:
        found = ingress.core_routes(tree)
    owner = next((r for r in found if domain in r.hostnames), None)
    if owner is not None:
        return None, (
            f"entry page: the main address {domain} is served by"
            f" {owner.module}:{owner.host_key}; no redirect to Mein Bereich is set"
        )
    port = f":{parts.port}" if parts.port is not None else ""
    target = f"{parts.scheme}://{hostname}{port}/"
    return Entry(domain, scheme.url_of(domain), target), None


def redirect_config(target: str) -> str:
    """The proxy's server-level redirect to `target` (an origin with a trailing slash)."""
    parts = urlsplit(target)
    if (
        parts.scheme not in ("http", "https")
        or not _HOST_RE.match(parts.hostname or "")
        or parts.path != "/"
        or parts.query
        or parts.fragment
        or parts.username is not None
        or target != f"{parts.scheme}://{parts.netloc}/"
    ):
        raise ValueError(f"entry page {target!r}: not an origin of the installation")
    return f"return 302 {target};\n"
