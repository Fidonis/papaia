"""Add-on ingress (contract generation 12) and the host scheme of an installation.

An add-on declares its web interfaces in `integration.nginx` as a list of
`{host_key, service, port, websocket, max_body}` (lib/compat.py checks the shape). The
core gives each one a host name of the installation's scheme; the manifest never names a
host. What follows from the list:

- `internal_nginx`: the bundled proxy gets one proxy host per interface
  (lib/npm_provision.py), and the proxy joins the add-on's network (lib/gen_override.py);
  no proxy host is created by hand.
- `external_proxy`: `papaia-ctl proxy list` (and the end of `setup`) prints
  "host name -> internal target" for every interface of the core and the add-ons.
- `no_proxy`: no host names; the interfaces are reached on documented ports.

Host scheme (oberflaeche §2.5, betrieb §1.7.2):

- a server domain (`PAPAIA_HOST` is a fully qualified name, or `INGRESS_DOMAIN`):
  `<label>.<domain>`;
- a local installation (`host.docker.internal`, `localhost`, a loopback address):
  `<label>.<env>.papaia.localhost` with the edge port, `<env>` taken from the Compose
  project (`papaia-itest` -> `itest`; the default project `papaia` has none). Browsers
  resolve names below `localhost` without an `/etc/hosts` entry (RFC 6761 §6.3);
- a LAN address or a bare host name: no host names until `INGRESS_DOMAIN` names a domain.

The label is the host key; the operator renames it with `INGRESS_HOST_<KEY>` in the
root `.env` (one DNS label, nothing else). The host key `apps` is the app host: it lives
on a second domain, a site of its own, so cookies of the platform domain never reach it
(`INGRESS_APP_DOMAIN`; locally `<env>.papaia-apps.localhost`), and serves its
subdomains too.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import common, compat, deployment, gen_override

APP_HOST_KEY = "apps"
LOCAL_SUFFIX = "papaia.localhost"
LOCAL_APP_SUFFIX = "papaia-apps.localhost"
DOMAIN_KEY = "INGRESS_DOMAIN"
APP_DOMAIN_KEY = "INGRESS_APP_DOMAIN"
RENAME_PREFIX = "INGRESS_HOST_"
HTTPS_PORT_KEY = "INGRESS_HTTPS_EXT_PORT"
HTTP_PORT_KEY = "INGRESS_HTTP_EXT_PORT"
PROXY_SERVICE = "nginx-proxy-manager"

_LOCAL_HOSTS = {"localhost", "host.docker.internal"}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_DNS_LABEL}(?:\.{_DNS_LABEL})+$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")

# The core's web interfaces the bundled proxy serves, as
# (compose profile, .env node, URL key, label, service, port, scheme, verify TLS, websocket).
# Only those whose profile is active and whose URL is served by host name count.
CORE_PROXY_HOSTS: list[tuple[str, str, str, str, str, int, str, bool, bool]] = [
    ("keycloak", "", "AUTH_HOST", "auth", "keycloak", 8443, "https", False, False),
    ("librechat", "ai/librechat", "DOMAIN_SERVER", "chat", "librechat", 3080, "http", True, True),
    ("litellm", "", "LITELLM_PUBLIC_URL", "litellm", "litellm", 4000, "http", True, False),
    ("localai", "", "LOCALAI_PUBLIC_URL", "localai", "localai", 8080, "http", True, False),
    ("manager", "", "MANAGER_PUBLIC_URL", "manager", "papaia-manager", 8000, "http", True, False),
    ("rag", "", "QDRANT_PUBLIC_URL", "qdrant", "qdrant", 6333, "http", True, False),
]

# On a node of a distributed installation the proxy's node does not have LibreChat's
# .env; the node bundle carries the URL in the root .env under this key instead.
_ROOT_FALLBACK = {("ai/librechat", "DOMAIN_SERVER"): "LIBRECHAT_PUBLIC_URL"}


class IngressError(ValueError):
    """An ingress declaration or a host-scheme value that cannot be served."""


@dataclass(frozen=True)
class HostScheme:
    """Where the interfaces of one installation live. `domain` is None without a proxy."""

    provider: str
    domain: str | None
    app_domain: str | None
    port: int | None  # in the URL; None for the scheme's default port
    scheme: str = "https"

    def hostname(self, label: str) -> str:
        if self.domain is None:
            raise IngressError(f"{self.provider}: interfaces have no host names")
        return f"{label}.{self.domain}"

    def url(self, label: str) -> str:
        return self.url_of(self.hostname(label))

    def url_of(self, hostname: str) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port in (None, default) else f":{self.port}"
        return f"{self.scheme}://{hostname}{port}"


@dataclass(frozen=True)
class Route:
    """One web interface behind the proxy: its host names and its internal target."""

    module: str
    host_key: str
    hostnames: tuple[str, ...]
    public_url: str
    service: str
    port: int
    scheme: str
    network: str
    websocket: bool = False
    max_body: str | None = None
    verify_tls: bool = True

    @property
    def target(self) -> str:
        return f"{self.scheme}://{self.service}:{self.port}"

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "host_key": self.host_key,
            "hostnames": list(self.hostnames),
            "public_url": self.public_url,
            "target": self.target,
            "network": self.network,
            "websocket": self.websocket,
            "max_body": self.max_body,
        }


def is_local_host(hostname: str) -> bool:
    """A host on this machine only (`localhost`, `host.docker.internal`, a loopback
    address): its interfaces move to `.localhost` names, which every browser resolves to
    its own loopback. A LAN address or a bare host name is not: other machines reach it,
    and `.localhost` would point them at themselves."""
    return hostname in _LOCAL_HOSTS or hostname.startswith("127.") or hostname == "::1"


def env_label(project: str) -> str:
    """The `<env>` part of local names: `papaia-itest` -> `itest`, `papaia` -> ``."""
    project = (project or "papaia").strip()
    if project == "papaia":
        return ""
    label = project.removeprefix("papaia-")
    if not _DOMAIN_RE.match(f"{label}.x"):
        raise IngressError(f"COMPOSE_PROJECT_NAME={project!r}: no usable DNS label")
    return label


def local_domains(project: str) -> tuple[str, str]:
    env = env_label(project)
    prefix = f"{env}." if env else ""
    return f"{prefix}{LOCAL_SUFFIX}", f"{prefix}{LOCAL_APP_SUFFIX}"


def edge_port(root: dict[str, str], key: str = HTTPS_PORT_KEY, default: int = 443) -> int:
    raw = (root.get(key) or "").strip()
    if not raw:
        return default
    if not _PORT_RE.match(raw) or not 1 <= int(raw) <= 65535:
        raise IngressError(f"{key}={raw!r}: must be a port from 1 to 65535")
    return int(raw)


def local_scheme(project: str, root: dict[str, str]) -> HostScheme:
    """The local edge scheme: `.localhost` names with the edge's HTTPS port."""
    domain, app_domain = local_domains(project)
    return HostScheme("internal_nginx", domain, app_domain, edge_port(root))


def _domain(root: dict[str, str], key: str) -> str | None:
    raw = (root.get(key) or "").strip().lower()
    if not raw:
        return None
    if not _DOMAIN_RE.match(raw):
        raise IngressError(f"{key}={raw!r}: must be a domain such as example.org")
    return raw


def host_scheme(root: dict[str, str]) -> HostScheme:
    """The host scheme of the installation described by the root `.env`."""
    provider = root.get("REVERSE_PROXY_PROVIDER") or "internal_nginx"
    if provider == "no_proxy":
        return HostScheme(provider, None, None, None)
    app_host = urlsplit(root.get("PAPAIA_HOST") or "")
    hostname = (app_host.hostname or "").lower()
    domain = _domain(root, DOMAIN_KEY)
    app_domain = _domain(root, APP_DOMAIN_KEY)
    if domain is None and (not hostname or is_local_host(hostname)):
        local, local_apps = local_domains(root.get("COMPOSE_PROJECT_NAME", ""))
        scheme = HostScheme(provider, local, app_domain or local_apps, edge_port(root))
    elif domain is None and (_IPV4_RE.match(hostname) or not _DOMAIN_RE.match(hostname)):
        # A LAN address or a bare host name: no domain to name the interfaces under.
        return HostScheme(provider, None, app_domain, None)
    else:
        domain = domain or hostname
        # The interfaces follow the scheme of PAPAIA_HOST, on the edge's port for it.
        url_scheme = app_host.scheme if app_host.scheme in ("http", "https") else "https"
        port = None
        if provider == "internal_nginx":
            port = edge_port(root) if url_scheme == "https" else edge_port(root, HTTP_PORT_KEY, 80)
        scheme = HostScheme(provider, domain, app_domain, port, url_scheme)
    if scheme.app_domain is not None:
        a, d = scheme.app_domain, scheme.domain or ""
        if a == d or a.endswith(f".{d}") or d.endswith(f".{a}"):
            raise IngressError(
                f"{APP_DOMAIN_KEY}={a!r}: the app host needs a site of its own, not one"
                f" inside or above {d!r}"
            )
    return scheme


def _label(host_key: str, root: dict[str, str]) -> str:
    key = RENAME_PREFIX + host_key.upper().replace("-", "_")
    raw = root.get(key)
    if raw is None or raw.strip() == "":
        return host_key
    value = raw.strip()
    if not _LABEL_RE.match(value):
        raise IngressError(f"{key}={value!r}: must be one DNS label such as portal")
    return value


def addon_routes(manifest: dict, root: dict[str, str]) -> list[Route]:
    """The routes of one add-on's `integration.nginx` list (empty without the list
    form or without a proxy). IngressError for an entry that cannot be served."""
    name = manifest.get("name") or "?"
    nginx = (manifest.get("integration") or {}).get("nginx")
    if not isinstance(nginx, list):
        return []
    try:
        compat._validate_ingress_entries(nginx)
    except ValueError as exc:
        raise IngressError(f"add-on '{name}': {exc}") from exc
    scheme = host_scheme(root)
    if scheme.domain is None:
        if scheme.provider == "no_proxy":
            return []
        raise IngressError(
            f"add-on '{name}': PAPAIA_HOST names no domain for the host names of its"
            f" interfaces; set {DOMAIN_KEY} in the root .env"
        )
    raw_network = (manifest.get("networks") or {}).get("app_network")
    if not isinstance(raw_network, str) or not raw_network:
        raise IngressError(
            f"add-on '{name}': integration.nginx needs networks.app_network, the network"
            " the proxy joins to reach the interfaces"
        )
    network = gen_override._expand_env_refs(raw_network, root)
    routes = []
    for entry in nginx:
        host_key = entry["host_key"]
        if host_key == APP_HOST_KEY:
            if scheme.app_domain is None:
                raise IngressError(
                    f"add-on '{name}': the app host needs a second domain; set"
                    f" {APP_DOMAIN_KEY} in the root .env"
                )
            hostnames = (scheme.app_domain, f"*.{scheme.app_domain}")
            public_url = scheme.url_of(scheme.app_domain)
        else:
            hostname = scheme.hostname(_label(host_key, root))
            hostnames = (hostname,)
            public_url = scheme.url_of(hostname)
        routes.append(
            Route(
                module=name,
                host_key=host_key,
                hostnames=hostnames,
                public_url=public_url,
                service=entry["service"],
                port=entry["port"],
                scheme="http",
                network=network,
                websocket=bool(entry.get("websocket", False)),
                max_body=entry.get("max_body"),
            )
        )
    return routes


def public_url_of(tree: dict, node: str, key: str) -> str:
    root = tree.get("", {})
    if not node:
        return root.get(key, "")
    fallback = _ROOT_FALLBACK.get((node, key))
    if fallback and root.get(fallback):
        return root[fallback]
    return tree.get(node, {}).get(key, "")


def edge_ports(root: dict[str, str]) -> tuple[int, int]:
    return edge_port(root), edge_port(root, HTTP_PORT_KEY, 80)


def is_proxied_url(url: str, edge: tuple[int, ...] = ()) -> bool:
    """True for a URL the proxy serves by host name: a subdomain URL without a port, or
    with one of the edge's own ports. Another port means direct port access; the bare
    local names (`localhost`, `host.docker.internal`, an IP) are no host names."""
    if not url:
        return False
    try:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        port = parts.port
    except ValueError:
        return False
    if not hostname or not parts.scheme:
        return False
    if hostname in ("localhost", "host.docker.internal", "127.0.0.1"):
        return False
    if port is not None and port not in edge:
        return False
    return "." in hostname


def core_routes(tree: dict) -> list[Route]:
    """The core's interfaces the proxy serves: active profile, URL served by host name."""
    root = tree.get("", {})
    active = common.cluster_profiles(root)
    network = root.get("DOCKER_NETWORK") or "papaia-net"
    edge = edge_ports(root)
    routes = []
    for profile, node, key, label, service, port, scheme, verify, ws in CORE_PROXY_HOSTS:
        url = public_url_of(tree, node, key)
        if profile not in active or not is_proxied_url(url, edge):
            continue
        hostname = (urlsplit(url).hostname or "").lower()
        routes.append(
            Route(
                module="core",
                host_key=label,
                hostnames=(hostname,),
                public_url=url.rstrip("/"),
                service=service,
                port=port,
                scheme=scheme,
                network=network,
                websocket=ws,
                verify_tls=verify,
            )
        )
    return routes


def routes(tree: dict, config_dir: Path, repo_root: Path) -> list[Route]:
    """Every interface of the installation, core first, then the active add-ons in
    deployment order. IngressError when two of them claim the same host name."""
    root = tree.get("", {})
    found = core_routes(tree)
    if (root.get("REVERSE_PROXY_PROVIDER") or "internal_nginx") == "no_proxy":
        return found
    for addon in deployment.active_addons(deployment.load(config_dir)):
        manifest, reason = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if manifest is None:
            raise IngressError(f"add-on '{addon.get('name')}': {reason}")
        found.extend(addon_routes(manifest, root))
    owners: dict[str, str] = {}
    for route in found:
        for hostname in route.hostnames:
            owner = f"{route.module}:{route.host_key}"
            if hostname in owners:
                raise IngressError(
                    f"host name {hostname} is claimed by {owners[hostname]} and {owner};"
                    f" rename one with {RENAME_PREFIX}<KEY> in the root .env"
                )
            owners[hostname] = owner
    return found


def _matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        base = pattern[2:]
        head, _, rest = hostname.partition(".")
        return bool(head) and rest == base
    return hostname == pattern


def is_installation_url(url: str, found: list[Route]) -> bool:
    """Whether `url` is an absolute http(s) address on a host of the installation,
    with the host's own port. Everything else (another host, a relative or
    scheme-relative value, a user name, `module:target:id`) is not."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not url.lower().startswith(f"{parts.scheme}://"):
        return False
    if parts.username is not None or parts.password is not None:
        return False
    hostname = (parts.hostname or "").lower()
    for route in found:
        own = urlsplit(route.public_url)
        if parts.scheme != own.scheme or port != own.port:
            continue
        if any(_matches(hostname, pattern) for pattern in route.hostnames):
            return True
    return False


def format_table(provider: str, found: list[Route]) -> str:
    """The list of forwards for an operator: host name -> internal target."""
    if provider == "no_proxy":
        return (
            "REVERSE_PROXY_PROVIDER=no_proxy: no proxy serves the interfaces; they are\n"
            "reached on their documented ports.\n"
        )
    header = ("HOST NAME", "TARGET", "NETWORK", "MODULE", "OPTIONS")
    rows = []
    for route in found:
        options = []
        if route.websocket:
            options.append("websocket")
        if route.max_body:
            options.append(f"max_body={route.max_body}")
        if route.scheme == "https" and not route.verify_tls:
            options.append("tls-no-verify")
        for hostname in route.hostnames:
            rows.append(
                (hostname, route.target, route.network, route.module, ",".join(options) or "-")
            )
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    lines = [
        "  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip()
        for row in [header, *rows]
    ]
    return "\n".join(lines) + "\n"


def to_json(provider: str, found: list[Route]) -> str:
    return json.dumps(
        {"provider": provider, "routes": [r.as_dict() for r in found]}, indent=2, sort_keys=True
    )
