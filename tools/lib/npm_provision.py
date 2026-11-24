"""Automatic NPM proxy-host provisioning for the bundled Nginx Proxy Manager.

Called by `papaia-ctl start` (via `py_cli npm-provision`) when
REVERSE_PROXY_PROVIDER=internal_nginx.  Only creates hosts that don't already
exist; subsequent runs are fully idempotent.

Uses only Python stdlib — no third-party dependencies.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import catalog, common, deployment, ingress, paperless_gate, startgate, uninstall_journal
from .envtree import EnvTree

# Env-tree node holding the bundled proxy's own configuration. The NPM admin
# credentials and the local API port binding are only consumed by the nginx
# compose module, so they live in src/infra/nginx/.env rather than the root .env.
_NGINX_NODE = "infra/nginx"

# NPM groups all reverse-proxy resources under /api/nginx/ — /api/proxy-hosts
# (without the segment) answers 404.
_PROXY_HOSTS_PATH = "/api/nginx/proxy-hosts"

# The writer of the audit rows for proxy hosts this module deletes.
WRITER = "papaia-ctl/npm-provision"


def _is_subdomain_url(url: str, edge: tuple[int, ...] = ()) -> bool:
    """Return True only for URLs the proxy serves by host name.

    Port-based URLs (e.g. https://papaia.example.com:8200) indicate direct port
    access -- no NPM proxy host is created for them -- unless the port is one of the
    edge's own (`edge`), as in the local scheme `https://auth.itest.papaia.localhost:57143`.
    localhost / host.docker.internal addresses are also skipped since they are not
    reachable from inside the Docker network via the domain name NPM would proxy.
    """
    return ingress.is_proxied_url(url, edge)


_public_url = ingress.public_url_of


def _wait_for_npm(base_url: str, timeout: int = 60) -> None:
    """Poll the NPM API root until it responds HTTP 200 or the timeout expires."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/", timeout=3):
                return
        except Exception as exc:
            last_exc = exc
            time.sleep(2)
    raise TimeoutError(
        f"NPM API at {base_url} did not become ready within {timeout}s"
        + (f": {last_exc}" if last_exc else "")
    )


def _get_token(base_url: str, email: str, password: str) -> str:
    """Authenticate to the NPM API and return a Bearer token."""
    payload = json.dumps({"identity": email, "secret": password}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/tokens",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    return data["token"]


def _existing_domains(base_url: str, token: str) -> set[str]:
    """Return the set of all domain names already registered as proxy hosts."""
    result: set[str] = set()
    for host in _list_proxy_hosts(base_url, token):
        result.update(host.get("domain_names", []))
    return result


def proxy_host_body(
    domain: str | list[str],
    forward_host: str,
    forward_port: int,
    forward_scheme: str,
    *,
    ssl_verify: bool = True,
    allow_websocket: bool = False,
    advanced_config: str | None = None,
) -> dict:
    """The NPM API body of one proxy host. Without `advanced_config` the host clears the
    identity and gate headers itself, like every host through `server_proxy.conf`."""
    if advanced_config is None:
        advanced_config = paperless_gate.strip_config() + (
            "" if ssl_verify else "proxy_ssl_verify off;\n"
        )
    return {
        "domain_names": [domain] if isinstance(domain, str) else list(domain),
        "forward_host": forward_host,
        "forward_port": forward_port,
        "forward_scheme": forward_scheme,
        "caching_enabled": False,
        "allow_websocket_upgrade": allow_websocket,
        "block_exploits": True,
        "access_list_id": 0,
        "certificate_id": 0,
        "ssl_forced": False,
        "http2_support": False,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "locations": [],
        "advanced_config": advanced_config,
    }


# The admin console and admin REST API of the identity provider are never served by the
# public edge (BE-06): the papaia-ctl steps reach them on the stack network
# (lib/keycloak_admin_path.py), papaia-manager with the signed-in account's own token.
IDP_SERVICE = "keycloak"
IDP_ADMIN_BLOCK = "location ~ ^/admin(/|$) {\n    return 403;\n}\n"
# The fields of the identity provider's host that setup owns and corrects: where it
# forwards to and the advanced config with the admin block. A certificate, forced SSL,
# HSTS or a location the operator added in the NPM UI stays as it is.
IDP_OWNED_FIELDS = (
    "forward_scheme",
    "forward_host",
    "forward_port",
    "allow_websocket_upgrade",
    "advanced_config",
)


def core_host_body(
    domain: str, service: str, port: int, scheme: str, ssl_verify: bool, websocket: bool
) -> dict:
    """The NPM API body of a core interface; the identity provider's host refuses its
    admin paths."""
    advanced = None
    if service == IDP_SERVICE:
        advanced = (
            paperless_gate.strip_config()
            + ("" if ssl_verify else "proxy_ssl_verify off;\n")
            + IDP_ADMIN_BLOCK
        )
    return proxy_host_body(
        domain,
        service,
        port,
        scheme,
        ssl_verify=ssl_verify,
        allow_websocket=websocket,
        advanced_config=advanced,
    )


def route_body(route: ingress.Route) -> dict:
    """The NPM API body of an add-on interface (lib/ingress.py): its host names to its
    service, the identity and gate headers cleared, the upload limit of `max_body`."""
    advanced = paperless_gate.strip_config()
    if route.scheme == "https" and not route.verify_tls:
        advanced += "proxy_ssl_verify off;\n"
    if route.max_body:
        advanced += f"client_max_body_size {route.max_body};\n"
    return proxy_host_body(
        list(route.hostnames),
        route.service,
        route.port,
        route.scheme,
        allow_websocket=route.websocket,
        advanced_config=advanced,
    )


def _correct_host(
    base_url: str,
    token: str,
    route: ingress.Route,
    body: dict,
    hosts: list[dict] | None = None,
    owned: tuple[str, ...] | None = None,
) -> bool:
    """Create the proxy host of `route`, or correct one that differs from `body`. With
    `owned`, an existing host is compared and corrected in those fields only, and the
    others keep what they have. True when something was written."""
    if hosts is None:
        hosts = _list_proxy_hosts(base_url, token)
    current = next(
        (h for h in hosts if set(route.hostnames) & set(h.get("domain_names") or [])), None
    )
    if current is None:
        _post_proxy_host(base_url, token, body)
        print(f"  created proxy host: {route.hostnames[0]} -> {route.target}", flush=True)
        return True
    if owned is not None:
        body = {key: body[key] for key in owned}
    if any(current.get(key) != value for key, value in body.items()):
        _put_proxy_host(base_url, token, current.get("id"), body)
        print(f"  updated proxy host: {route.hostnames[0]} -> {route.target}", flush=True)
    else:
        return False
    return True


def _ingress_hosts(base_url: str, token: str, found: list[ingress.Route]) -> int:
    """Create or correct the proxy host of every add-on interface; the count of hosts
    created or corrected. A host that already matches is left as it is."""
    hosts = _list_proxy_hosts(base_url, token)
    return sum(
        1 for route in found if _correct_host(base_url, token, route, route_body(route), hosts)
    )


def _delete_proxy_host(base_url: str, token: str, host_id: int) -> None:
    if isinstance(host_id, bool) or not isinstance(host_id, int):
        raise ValueError("proxy host id must be an integer")
    _send(base_url, token, f"{_PROXY_HOSTS_PATH}/{host_id}", "DELETE")


def uninstalled_hostnames(
    manifest: dict, name: str, root: dict[str, str], bundle: dict[str, str]
) -> list[str]:
    """The proxy host names an add-on's interfaces had, for the uninstall journal: its
    `integration.nginx` routes (`root` = the root .env) and, for Paperless, the host of
    its public URL (in its bundle .env) when the proxy serves it under a host name."""
    try:
        hostnames = [h for r in ingress.addon_routes(manifest, root) for h in r.hostnames]
    except ingress.IngressError:
        hostnames = []
    if name == paperless_gate.ADDON:
        url = bundle.get(paperless_gate.PUBLIC_URL_KEY, "")
        if url and _is_subdomain_url(url, ingress.edge_ports(root)):
            hostnames.append(urlsplit(url).hostname or "")
    return sorted({h.lower() for h in hostnames if h})


def _uninstalled_hosts(
    base_url: str, token: str, config_dir: Path, served: set[str]
) -> bool:
    """Delete the proxy hosts `addon uninstall` recorded (lib/uninstall_journal.py) that
    no installed interface serves; each deletion is one `papaia.audit/1` row. Clears the
    journal's part once every recorded host is gone. False when that failed."""
    from . import realm_sync as rs  # it imports the render path

    try:
        recorded = uninstall_journal.pending(config_dir, uninstall_journal.PROXY)
    except uninstall_journal.JournalError as exc:
        print(f"Proxy hosts of uninstalled add-ons kept: {exc}", file=sys.stderr, flush=True)
        return False
    if not recorded:
        return True
    names = {h for entry in recorded.values() for h in entry["proxy_hosts"]} - served
    try:
        with rs.AuditLog(
            rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER
        ) as audit:
            for host in _list_proxy_hosts(base_url, token):
                domains = set(host.get("domain_names") or [])
                if not domains & names or domains & served:
                    continue
                change = rs.Change(
                    "proxy-host",
                    sorted(domains & names)[0],
                    "removed, its add-on was uninstalled",
                    "delete_proxy_host",
                    effect="delete",
                )
                try:
                    _delete_proxy_host(base_url, token, host.get("id"))
                except (urllib.error.URLError, OSError, ValueError):
                    audit.write(change, "error", "transport", host=True)
                    raise
                audit.write(change, "allowed", host=True)
                print(f"  removed proxy host: {', '.join(sorted(domains))}", flush=True)
        uninstall_journal.done(config_dir, uninstall_journal.PROXY, set(recorded))
    except (rs.RealmSyncError, uninstall_journal.JournalError, urllib.error.URLError,
            OSError, ValueError) as exc:
        print(f"Proxy hosts of uninstalled add-ons kept: {exc}", file=sys.stderr, flush=True)
        return False
    return True


def _send(base_url: str, token: str, path: str, method: str, body: dict | None = None):
    """One NPM API call; the parsed answer for a GET, None otherwise."""
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read()) if method == "GET" else None


def _list_proxy_hosts(base_url: str, token: str) -> list[dict]:
    hosts = _send(base_url, token, _PROXY_HOSTS_PATH, "GET")
    return [h for h in hosts if isinstance(h, dict)] if isinstance(hosts, list) else []


def _post_proxy_host(base_url: str, token: str, body: dict) -> None:
    _send(base_url, token, _PROXY_HOSTS_PATH, "POST", body)


def _put_proxy_host(base_url: str, token: str, host_id: int, body: dict) -> None:
    if isinstance(host_id, bool) or not isinstance(host_id, int):
        raise ValueError("proxy host id must be an integer")
    _send(base_url, token, f"{_PROXY_HOSTS_PATH}/{host_id}", "PUT", body)


def _create_proxy_host(
    base_url: str,
    token: str,
    domain: str,
    forward_host: str,
    forward_port: int,
    forward_scheme: str,
    ssl_verify: bool,
    allow_websocket: bool,
) -> None:
    """Create a single proxy host entry via the NPM REST API."""
    _post_proxy_host(
        base_url,
        token,
        proxy_host_body(
            domain,
            forward_host,
            forward_port,
            forward_scheme,
            ssl_verify=ssl_verify,
            allow_websocket=allow_websocket,
        ),
    )


def _paperless_route(base_url: str, token: str, config_dir: Path) -> bool:
    """Create or correct the proxy host of the Paperless add-on: to the gate, with the
    proxy's gate secret from the included file. Only while the add-on is active and its
    public URL is a host name the proxy serves. False when the secret is missing or
    unusable: a route without it would only ever be refused by the gate."""
    active = deployment.active_addons(deployment.load(config_dir))
    if not any(entry.get("name") == paperless_gate.ADDON for entry in active):
        return True
    env = common.parse_env_file(config_dir / "addons" / paperless_gate.ADDON / ".env")
    url = env.get(paperless_gate.PUBLIC_URL_KEY, "")
    edge = ingress.edge_ports(common.parse_env_file(config_dir / ".env"))
    if not _is_subdomain_url(url, edge):
        return True
    try:
        secret = paperless_gate.read_proxy_secret(config_dir)
    except paperless_gate.GateError as exc:
        print(f"Paperless proxy host skipped: {exc}", file=sys.stderr, flush=True)
        return False
    if secret is None:
        print(
            "Paperless proxy host skipped: the proxy has no gate secret; run"
            " 'papaia-ctl setup' or 'papaia-ctl secrets rotate paperless-gate/proxy'",
            file=sys.stderr,
            flush=True,
        )
        return False
    domain = urlsplit(url).hostname or ""
    wanted = {
        "forward_scheme": "http",
        "forward_host": paperless_gate.GATE_SERVICE,
        "forward_port": paperless_gate.GATE_PORT,
        "advanced_config": paperless_gate.route_advanced_config(),
    }
    for host in _list_proxy_hosts(base_url, token):
        if domain not in (host.get("domain_names") or []):
            continue
        if all(host.get(key) == value for key, value in wanted.items()):
            return True
        _put_proxy_host(base_url, token, host.get("id"), wanted)
        print(f"  updated proxy host: {domain} -> the Paperless gate", flush=True)
        return True
    _post_proxy_host(
        base_url,
        token,
        proxy_host_body(
            domain,
            paperless_gate.GATE_SERVICE,
            paperless_gate.GATE_PORT,
            "http",
            advanced_config=paperless_gate.route_advanced_config(),
        ),
    )
    print(f"  created proxy host: {domain} -> the Paperless gate", flush=True)
    return True


# The NPM admin API on the stack's network, for a papaia-ctl that runs in a container.
NPM_API_IN_STACK = "http://nginx-proxy-manager:81"


def _api_base_url(nginx: dict[str, str]) -> str:
    """Where this process reaches the NPM admin API.

    On the host that is the port published on localhost (`NPM_API_LOCAL_PORT`). In a
    container (papaia-manager and its runners run `start`, and with it this step, in
    their own) `localhost` is the container itself; there it is the service on the
    stack's network, which `start` has joined."""
    if common.in_container():
        return NPM_API_IN_STACK
    return f"http://localhost:{nginx.get('NPM_API_LOCAL_PORT', '8181')}"


def provision_npm_hosts(
    tree: EnvTree, config_dir: Path | None = None, repo_root: Path | None = None
) -> bool:
    """Create NPM proxy hosts for all active services, skipping existing ones.

    No-op when REVERSE_PROXY_PROVIDER is not 'internal_nginx'.
    Idempotent: already-existing domain names are silently skipped.
    With `config_dir`, also puts the header strip into the proxy's `server_proxy.conf`
    and creates or corrects the Paperless route (lib/paperless_gate.py); with
    `repo_root` as well, creates or corrects the host of every add-on interface
    declared in `integration.nginx` (lib/ingress.py).
    Returns False if the NPM API was not reachable, an add-on interface cannot be served
    or the Paperless route could not be set up; True otherwise.
    """
    root = tree.get("", {})
    if root.get("REVERSE_PROXY_PROVIDER") != "internal_nginx":
        return True

    nginx = tree.get(_NGINX_NODE, {})
    base_url = _api_base_url(nginx)
    email = nginx.get("NPM_ADMIN_EMAIL", "admin@papaia.local")
    password = nginx.get("NPM_ADMIN_PASSWORD", "")
    if not password or password.startswith("GENERATE_"):
        raise RuntimeError(
            f"NPM_ADMIN_PASSWORD is not set in {_NGINX_NODE}/.env. "
            "Run 'papaia-ctl setup' first."
        )

    # Cluster-wide: the proxy serves the services of every node, not only its own.
    active_profiles = common.cluster_profiles(root)

    print("Waiting for NPM API to become ready...", flush=True)
    try:
        _wait_for_npm(base_url)
    except TimeoutError as exc:
        print(f"NPM provisioning skipped: {exc}", file=sys.stderr, flush=True)
        return False

    token = _get_token(base_url, email, password)
    existing = _existing_domains(base_url, token)

    created = 0
    skipped_existing = 0
    skipped_port_based = 0

    edge = ingress.edge_ports(root)
    served: set[str] = set()  # host names an installed interface serves
    for spec in ingress.CORE_PROXY_HOSTS:
        profile, node, key, label, fwd_host, fwd_port, fwd_scheme, ssl_verify, ws = spec
        if profile not in active_profiles:
            continue
        url = _public_url(tree, node, key)
        served.add(urlsplit(url).hostname or "")
        if not _is_subdomain_url(url, edge):
            skipped_port_based += 1
            continue
        domain = urlsplit(url).hostname or ""
        if fwd_host == IDP_SERVICE:
            # Created or corrected, so an earlier host without the admin block gets it.
            body = core_host_body(domain, fwd_host, fwd_port, fwd_scheme, ssl_verify, ws)
            route = ingress.Route(
                "core", label, (domain,), url, fwd_host, fwd_port, fwd_scheme, "",
            )
            if _correct_host(base_url, token, route, body, owned=IDP_OWNED_FIELDS):
                existing.add(domain)
                created += 1
            else:
                skipped_existing += 1
            continue
        if domain in existing:
            skipped_existing += 1
            continue
        _create_proxy_host(
            base_url,
            token,
            domain,
            fwd_host,
            fwd_port,
            fwd_scheme,
            ssl_verify,
            ws,
        )
        existing.add(domain)
        print(f"  created proxy host: {domain} -> {fwd_scheme}://{fwd_host}:{fwd_port}", flush=True)
        created += 1

    ok = True
    found: list = []
    if config_dir is not None and repo_root is not None:
        try:
            found = ingress.routes(tree, Path(config_dir), Path(repo_root))
        except ingress.IngressError as exc:
            print(f"Add-on proxy hosts skipped: {exc}", file=sys.stderr, flush=True)
            ok = False
        else:
            # The Paperless route goes to its gate with the proxy's secret (below).
            addon = [r for r in found if r.module not in ("core", paperless_gate.ADDON)]
            created += _ingress_hosts(base_url, token, addon)
            served |= {h for r in found for h in r.hostnames}
            ok = _uninstalled_hosts(base_url, token, Path(config_dir), served) and ok
    if config_dir is not None:
        try:
            block = _startgate_block(tree, Path(config_dir), found)
        except startgate.StartgateError as exc:
            # Without the block the edge would forward while the gate is closed.
            print(f"ERROR: the start gate cannot be set up at the edge: {exc}", file=sys.stderr)
            return False
        ok = _gate_steps(base_url, token, Path(config_dir), root, block) and ok

    if created:
        print(f"NPM provisioning complete: {created} host(s) created.", flush=True)
    else:
        print(
            f"NPM provisioning: no new hosts (skipped {skipped_existing} existing,"
            f" {skipped_port_based} port-based).",
            flush=True,
        )
    return ok


# The gate key of a core service's public host (sicherheit §4.9 (2a)): the journals of
# the core, `admin` for the proxy's own administration (never closed), `core` otherwise.
_GATE_KEYS = {
    "keycloak": "identity",
    "librechat": "core-chat",
    "litellm": "model-gateway",
    "nginx-proxy-manager-auth": startgate.GATE_ADMIN_KEY,
}


def gate_host_keys(tree: EnvTree | dict, routes: list) -> dict[str, str]:
    """Every public host name the proxy serves, mapped to its start gate key: the core's
    hosts by service, an add-on's by its module name. Hosts not named get `core`."""
    root = tree.get("", {})
    active = common.cluster_profiles(root)
    edge = ingress.edge_ports(root)
    keys: dict[str, str] = {}
    for profile, node, key, _label, service, *_ in ingress.CORE_PROXY_HOSTS:
        url = ingress.public_url_of(tree, node, key)
        if profile not in active or not ingress.is_proxied_url(url, edge):
            continue
        host = (urlsplit(url).hostname or "").lower()
        if host:
            keys[host] = _GATE_KEYS.get(service, "core")
    for route in routes:
        name = route.module if startgate.is_gate_key(route.module) else "core"
        for host in route.hostnames:
            keys.setdefault(host.lower(), name)
    return keys


def _startgate_block(tree, config_dir: Path, routes: list) -> str:
    """The edge's start gate block while papaia-lifecycle runs, else nothing: without
    the lifecycle profile nobody writes the lease and the edge would stay closed."""
    if "lifecycle" not in common.cluster_profiles(tree.get("", {})):
        return ""
    contact = catalog.current_branding(config_dir).get("contact") or {}
    text = " ".join(
        str(contact[k]) for k in ("name", "phone") if isinstance(contact.get(k), str)
    )
    return startgate.edge_block(gate_host_keys(tree, routes), contact=text or None)


def _gate_steps(
    base_url: str, token: str, config_dir: Path, root: dict[str, str], gate_block: str = ""
) -> bool:
    project = root.get("COMPOSE_PROJECT_NAME") or "papaia"
    changed = paperless_gate.install_strip_file(project, gate_block)
    if changed is None:
        print(
            "WARNING: could not write server_proxy.conf in the proxy container; proxy"
            " hosts created by hand do not clear X-Papaia-Remote-User and X-Papaia-Gate."
            " Run 'papaia-ctl npm-provision' again once the proxy runs.",
            file=sys.stderr,
            flush=True,
        )
    ok = _paperless_route(base_url, token, config_dir)
    if changed and not paperless_gate.reload_proxy(project):
        print(
            "WARNING: the proxy did not reload; server_proxy.conf takes effect at its next start.",
            file=sys.stderr,
            flush=True,
        )
    return ok
