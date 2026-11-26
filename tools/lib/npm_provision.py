"""Automatic NPM proxy-host provisioning for the bundled Nginx Proxy Manager.

Called by `papaia-ctl start` (via `py_cli npm-provision`) when
REVERSE_PROXY_PROVIDER=internal_nginx.  Only creates hosts that don't already
exist; subsequent runs are fully idempotent.

Uses only Python stdlib — no third-party dependencies.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import (
    catalog,
    common,
    deployment,
    edge_guard,
    edge_pki,
    ingress,
    module_tls,
    paperless_gate,
    sign_in,
    startgate,
    uninstall_journal,
)
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
    certificate_id: int = 0,
) -> dict:
    """The NPM API body of one proxy host. Without `advanced_config` the host clears the
    identity and gate headers itself, like every host through `server_proxy.conf`.
    `certificate_id` is the uploaded edge leaf of the host (ADR 0035), 0 for none."""
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
        "certificate_id": certificate_id,
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
    domain: str,
    service: str,
    port: int,
    scheme: str,
    ssl_verify: bool,
    websocket: bool,
    *,
    certificate_id: int = 0,
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
        certificate_id=certificate_id,
    )


# The fields of the main address's host that setup owns (lib/sign_in.py): the redirect to
# the entry page. A certificate or HSTS the operator set stays.
ENTRY_OWNED_FIELDS = ("forward_scheme", "forward_host", "forward_port", "advanced_config")


def entry_host_body(entry: sign_in.Entry, root: dict[str, str], certificate_id: int = 0) -> dict:
    """The NPM API body of the main address: every request is redirected to the entry
    page before anything is forwarded; the identity and gate headers are cleared. Its
    upstream is Mein Bereich's service with the scheme the security profile asks for
    (https with the platform CA under `kritis`, lib/module_tls.py)."""
    scheme, _, tls = ingress.core_upstream(root, "me", sign_in.ME_SERVICE, "http", False)
    advanced = paperless_gate.strip_config()
    if tls:
        advanced += module_tls.proxy_config(sign_in.ME_SERVICE)
    return proxy_host_body(
        entry.hostname,
        sign_in.ME_SERVICE,
        sign_in.ME_PORT,
        scheme,
        advanced_config=advanced + sign_in.redirect_config(entry.target),
        certificate_id=certificate_id,
    )


def _is_entry_host(host: dict) -> bool:
    """Whether setup created `host` as the main address's host: it forwards to Mein
    Bereich's service and redirects (entry_host_body). An operator's host or another
    interface's host at the domain is neither."""
    return host.get("forward_host") == sign_in.ME_SERVICE and "return 302 " in (
        host.get("advanced_config") or ""
    )


def _entry_host(
    base_url: str,
    token: str,
    root: dict[str, str],
    tree,
    edge,
    found: list[ingress.Route],
    certs: _EdgeCertificates | None = None,
) -> str | None:
    """Create or correct the host of the main address; its host name, or None when the
    installation has no entry page. A host at the domain that does not forward to Mein
    Bereich (another interface's, an operator's) stays as it is, with a note. Without an
    entry page, a host setup created there is removed."""
    hosts = _list_proxy_hosts(base_url, token)
    domain = sign_in.main_hostname(tree)
    current = next(
        (h for h in hosts if domain is not None and domain in (h.get("domain_names") or [])),
        None,
    )
    main, note = sign_in.entry_and_note(tree, found)
    if main is None or not _is_subdomain_url(main.public_url, edge):
        if note:
            print(f"  {note}", file=sys.stderr, flush=True)
        if current is not None and _is_entry_host(current):
            _delete_proxy_host(base_url, token, current.get("id"))
            print(f"  removed proxy host: {domain} (no entry page)", flush=True)
        return None
    if current is not None and current.get("forward_host") != sign_in.ME_SERVICE:
        print(
            f"  entry page: the main address {domain} has a proxy host setup did not"
            f" create (-> {current.get('forward_host')}); left as it is",
            file=sys.stderr,
            flush=True,
        )
        return None
    route = main.route(root.get("DOCKER_NETWORK") or "papaia-net")
    _correct_host(
        base_url, token, route, entry_host_body(main, root), hosts, owned=ENTRY_OWNED_FIELDS,
        certs=certs,
    )  # fmt: skip
    return main.hostname


# The fields of a module service's host (module_tls.CORE_ROUTES) that setup owns and
# corrects, so a change of the security profile reaches a host created before it.
MODULE_OWNED_FIELDS = IDP_OWNED_FIELDS


def _core_spec(label: str) -> tuple:
    return next(spec for spec in ingress.CORE_PROXY_HOSTS if spec[3] == label)


def core_route(root: dict[str, str], label: str, url: str) -> ingress.Route:
    """The route of the core interface `label` served at `url`, with the upstream the
    security profile asks for."""
    _, _, _, _, service, port, scheme, verify, ws = _core_spec(label)
    scheme, verify, tls = ingress.core_upstream(root, label, service, scheme, verify)
    hostname = urlsplit(url).hostname or ""
    return ingress.Route(
        "core", label, (hostname,), url, service, port, scheme, "", websocket=ws,
        verify_tls=verify, platform_tls=tls,
    )  # fmt: skip


def core_route_body(root: dict[str, str], label: str) -> dict:
    """The NPM API body of the module service `label` of the core (module_tls.CORE_ROUTES)
    at its public URL in the root `.env`."""
    _, node, key, *_ = _core_spec(label)
    return route_body(core_route(root, label, ingress.public_url_of({"": root}, node, key)))


def route_body(route: ingress.Route, certificate_id: int = 0) -> dict:
    """The NPM API body of an add-on interface (lib/ingress.py): its host names to its
    service, the identity and gate headers cleared, the upload limit of `max_body`."""
    advanced = paperless_gate.strip_config()
    if route.platform_tls:
        advanced += module_tls.proxy_config(route.service)
    elif route.scheme == "https" and not route.verify_tls:
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
        certificate_id=certificate_id,
    )


def _correct_host(
    base_url: str,
    token: str,
    route: ingress.Route,
    body: dict,
    hosts: list[dict] | None = None,
    owned: tuple[str, ...] | None = None,
    certs: _EdgeCertificates | None = None,
) -> bool:
    """Create the proxy host of `route`, or correct one that differs from `body`. With
    `owned`, an existing host is compared and corrected in those fields only, and the
    others keep what they have. With `certs`, the host gets the uploaded edge leaf of its
    names, unless it carries a certificate the operator set (ADR 0035). True when
    something was written."""
    if hosts is None:
        hosts = _list_proxy_hosts(base_url, token)
    current = next(
        (h for h in hosts if set(route.hostnames) & set(h.get("domain_names") or [])), None
    )
    certificate = certs.id_for(route.hostnames) if certs is not None else None
    if current is None:
        if certificate is not None:
            body = {**body, "certificate_id": certificate}
        _post_proxy_host(base_url, token, body)
        print(f"  created proxy host: {route.hostnames[0]} -> {route.target}", flush=True)
        return True
    if owned is not None:
        body = {key: body[key] for key in owned}
    if certificate is None:
        # No leaf applies (none issued, a refused name, a failed upload): whatever
        # certificate the host has stays, an operator's included.
        if "certificate_id" in body:
            body["certificate_id"] = current.get("certificate_id", body["certificate_id"])
    elif certs is not None:
        # The leaf replaces no certificate or an earlier upload; an operator's stays.
        if certs.replaces(current, certificate):
            body["certificate_id"] = certificate
        elif "certificate_id" in body:
            body["certificate_id"] = current.get("certificate_id")
    if any(current.get(key) != value for key, value in body.items()):
        _put_proxy_host(base_url, token, current.get("id"), body)
        print(f"  updated proxy host: {route.hostnames[0]} -> {route.target}", flush=True)
    else:
        return False
    return True


def _ingress_hosts(
    base_url: str,
    token: str,
    found: list[ingress.Route],
    certs: _EdgeCertificates | None = None,
) -> int:
    """Create or correct the proxy host of every add-on interface; the count of hosts
    created or corrected. A host that already matches is left as it is."""
    hosts = _list_proxy_hosts(base_url, token)
    return sum(
        1
        for route in found
        if _correct_host(base_url, token, route, route_body(route), hosts, certs=certs)
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


def _send(
    base_url: str, token: str, path: str, method: str, body: dict | None = None,
    answer: bool = False,
):  # fmt: skip
    """One NPM API call; the parsed answer for a GET (or with `answer`), None otherwise."""
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if method != "GET" and not answer:
            return None
        raw = resp.read()
        return json.loads(raw) if raw.strip() else None


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
    certificate_id: int = 0,
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
            certificate_id=certificate_id,
        ),
    )


def _paperless_route(
    base_url: str, token: str, config_dir: Path, certs: _EdgeCertificates | None = None
) -> bool:
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
    certificate = certs.id_for((domain,)) if certs is not None else None
    for host in _list_proxy_hosts(base_url, token):
        if domain not in (host.get("domain_names") or []):
            continue
        if certificate is not None and certs is not None and certs.replaces(host, certificate):
            wanted["certificate_id"] = certificate
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
            certificate_id=certificate or 0,
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


# ─────────────────────────────────────────────────────────────────────────
# edge certificates (ADR 0035)
# ─────────────────────────────────────────────────────────────────────────

_CERTIFICATES_PATH = "/api/nginx/certificates"
# The certificates papaia-ctl uploaded, by the first name of their leaf: the proxy's id
# and the leaf's fingerprint. Ids listed under `retired` were replaced and are deleted once
# no host uses them.
UPLOADS_FILE = "npm-certificates.json"
UPLOADS_FORMAT = "papaia.edge-uploads/1"
NICE_NAME_PREFIX = "papaia edge "


def edge_hosts(tree, config_dir: Path, repo_root: Path) -> list[tuple[str, ...]]:
    """The names of every proxy host `npm-provision` creates and owns: the core's
    interfaces, the add-ons' interfaces, the Paperless route and the main address, one
    tuple per host. Empty without the bundled proxy. IngressError when the interfaces
    cannot be read."""
    root = tree.get("", {})
    if root.get("REVERSE_PROXY_PROVIDER") != "internal_nginx":
        return []
    edge = ingress.edge_ports(root)
    found = ingress.routes(tree, Path(config_dir), Path(repo_root))
    hosts: list[tuple[str, ...]] = [tuple(h.lower() for h in r.hostnames) for r in found]
    main, _ = sign_in.entry_and_note(tree, found)
    if main is not None and _is_subdomain_url(main.public_url, edge):
        hosts.append((main.hostname.lower(),))
    active = deployment.active_addons(deployment.load(Path(config_dir)))
    if any(entry.get("name") == paperless_gate.ADDON for entry in active):
        env = common.parse_env_file(
            Path(config_dir) / "addons" / paperless_gate.ADDON / ".env"
        )
        url = env.get(paperless_gate.PUBLIC_URL_KEY, "")
        if _is_subdomain_url(url, edge):
            hosts.append(((urlsplit(url).hostname or "").lower(),))
    unique: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for names in hosts:
        if names and not seen & set(names):
            unique.append(names)
            seen |= set(names)
    return unique


def _list_certificates(base_url: str, token: str) -> list[dict]:
    found = _send(base_url, token, _CERTIFICATES_PATH, "GET")
    return [c for c in found if isinstance(c, dict)] if isinstance(found, list) else []


def _create_certificate(base_url: str, token: str, nice_name: str) -> int:
    """A custom certificate entry without files; its id."""
    made = _send(
        base_url, token, _CERTIFICATES_PATH, "POST",
        {"provider": "other", "nice_name": nice_name}, answer=True,
    )  # fmt: skip
    cert_id = made.get("id") if isinstance(made, dict) else None
    if isinstance(cert_id, bool) or not isinstance(cert_id, int):
        raise ValueError("the proxy did not return the id of the new certificate")
    return cert_id


def _upload_certificate(base_url: str, token: str, cert_id: int, certificate: str,
                        key: str) -> None:  # fmt: skip
    """The certificate and its key into the custom certificate `cert_id` (multipart, as
    the proxy's upload takes them)."""
    if isinstance(cert_id, bool) or not isinstance(cert_id, int):
        raise ValueError("certificate id must be an integer")
    boundary = "papaia-" + secrets.token_hex(16)
    parts = []
    for name, filename, content in (
        ("certificate", "tls.crt", certificate),
        ("certificate_key", "tls.key", key),
    ):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\";"
            f" filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            f"{content}\r\n"
        )
    data = ("".join(parts) + f"--{boundary}--\r\n").encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{_CERTIFICATES_PATH}/{cert_id}/upload",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def _delete_certificate(base_url: str, token: str, cert_id: int) -> None:
    if isinstance(cert_id, bool) or not isinstance(cert_id, int):
        raise ValueError("certificate id must be an integer")
    _send(base_url, token, f"{_CERTIFICATES_PATH}/{cert_id}", "DELETE")


class _EdgeCertificates:
    """The edge leaves of one installation as custom certificates of the proxy.

    `upload` brings every leaf into the proxy that is not there with its current
    fingerprint; `id_for` names the certificate of a host's names; `replaces` says whether
    a host's certificate may be set (none, or one papaia-ctl uploaded: an operator's
    stays); `clean_up` deletes the uploads of replaced or removed leaves once no host uses
    them. Each upload and deletion is one `papaia.audit/1` row; a run that changes nothing
    writes no row and no file."""

    def __init__(self, config_dir: Path, base_url: str, token: str):
        self.config_dir = config_dir
        self.base_url = base_url
        self.token = token
        self.leaves = edge_pki.leaves(config_dir)
        self.path = edge_pki.private_dir(config_dir) / UPLOADS_FILE
        self.state = self._load()
        self.domains = edge_pki.ca_domains(config_dir) or ()
        self.ids: dict[tuple[str, ...], int] = {}

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"format": UPLOADS_FORMAT, "uploads": {}, "retired": []}
        uploads = data.get("uploads") if isinstance(data, dict) else None
        retired = data.get("retired") if isinstance(data, dict) else None
        good = {
            label: entry
            for label, entry in (uploads.items() if isinstance(uploads, dict) else [])
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), int)
            and not isinstance(entry.get("id"), bool)
            and isinstance(entry.get("sha256"), str)
        }
        ids = [i for i in (retired if isinstance(retired, list) else [])
               if isinstance(i, int) and not isinstance(i, bool)]  # fmt: skip
        return {"format": UPLOADS_FORMAT, "uploads": good, "retired": ids}

    def _save(self) -> None:
        common.atomic_write_private(self.path, json.dumps(self.state, indent=2) + "\n")

    @property
    def ours(self) -> set[int]:
        return {e["id"] for e in self.state["uploads"].values()} | set(self.state["retired"])

    def id_for(self, names) -> int | None:
        return self.ids.get(tuple(n.lower() for n in names))

    def replaces(self, host: dict, certificate: int) -> bool:
        have = host.get("certificate_id") or 0
        return have != certificate and (have == 0 or have in self.ours)

    def _ours_by_name(self, cert: dict) -> bool:
        """Whether a certificate of the proxy carries the name papaia-ctl gives an upload:
        a custom one named after a leaf of this installation's edge domains."""
        name = cert.get("nice_name")
        if cert.get("provider") != "other" or not isinstance(name, str):
            return False
        if not name.startswith(NICE_NAME_PREFIX):
            return False
        try:
            edge_pki.check_name(name[len(NICE_NAME_PREFIX):], self.domains)
        except edge_pki.EdgePkiError:
            return False
        return True

    def _adopt(self, listed: list[dict]) -> None:
        """Uploads of papaia-ctl the state file does not know (it was lost or reset) are
        taken as replaced: hosts get the current leaf, and they are deleted once unused."""
        found = [
            c["id"] for c in listed
            if isinstance(c.get("id"), int) and not isinstance(c.get("id"), bool)
            and c["id"] not in self.ours and self._ours_by_name(c)
        ]  # fmt: skip
        if found:
            self.state["retired"].extend(sorted(found))
            self._save()

    def _upload_leaf(self, audit, change, leaf: edge_pki.Leaf) -> int:
        """Creates the custom certificate entry of `leaf` and uploads its files: one row,
        `error` with `file` (the leaf cannot be read; nothing is sent) or `transport` (the
        proxy refused or did not answer), else `allowed`. An entry left without files is
        deleted again, with a row of its own."""
        from . import realm_sync as rs

        try:
            certificate = leaf.cert.read_text(encoding="utf-8")
            key = leaf.key.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            audit.write(change, "error", "file", host=True)
            raise
        try:
            cert_id = _create_certificate(
                self.base_url, self.token, NICE_NAME_PREFIX + leaf.label
            )
        except (urllib.error.URLError, OSError, ValueError):
            audit.write(change, "error", "transport", host=True)
            raise
        try:
            _upload_certificate(self.base_url, self.token, cert_id, certificate, key)
        except (urllib.error.URLError, OSError, ValueError):
            audit.write(change, "error", "transport", host=True)
            undo = rs.Change(
                "certificate", leaf.label, "deleted from the proxy after a failed upload",
                "delete_certificate", effect="delete",
            )  # fmt: skip
            try:
                _delete_certificate(self.base_url, self.token, cert_id)
            except (urllib.error.URLError, OSError, ValueError):
                audit.write(undo, "error", "transport", host=True)
            else:
                audit.write(undo, "allowed", host=True)
            raise
        audit.write(change, "allowed", host=True)
        return cert_id

    def upload(self) -> None:
        if not self.leaves and not self.state["uploads"] and not self.state["retired"]:
            return
        listed = _list_certificates(self.base_url, self.token)
        present = {c.get("id") for c in listed}
        self._adopt(listed)
        from . import realm_sync as rs

        audit: rs.AuditLog | None = None
        try:
            for leaf in self.leaves:
                entry = self.state["uploads"].get(leaf.label)
                fingerprint = leaf.fingerprint()
                if entry and entry["sha256"] == fingerprint and entry["id"] in present:
                    self.ids[leaf.names] = entry["id"]
                    continue
                if audit is None:
                    audit = rs.AuditLog(
                        rs.audit_path(self.config_dir), rs.new_correlation_id(), writer=WRITER
                    )
                change = rs.Change(
                    "certificate", leaf.label, "uploaded to the proxy", "upload_certificate"
                )
                cert_id = self._upload_leaf(audit, change, leaf)
                if entry:
                    # Replaced; a host that still names it gets the new one below.
                    self.state["retired"].append(entry["id"])
                self.state["uploads"][leaf.label] = {"id": cert_id, "sha256": fingerprint}
                self._save()
                self.ids[leaf.names] = cert_id
                print(f"  uploaded edge certificate: {leaf.label}", flush=True)
        finally:
            if audit is not None:
                audit.close()

    def clean_up(self) -> None:
        current = {leaf.label for leaf in self.leaves}
        gone = {
            label: entry["id"]
            for label, entry in self.state["uploads"].items()
            if label not in current
        }
        if not gone and not self.state["retired"]:
            return
        in_use = {h.get("certificate_id") for h in _list_proxy_hosts(self.base_url, self.token)}
        present = {c.get("id") for c in _list_certificates(self.base_url, self.token)}
        from . import realm_sync as rs

        doomed = [(label, cert_id) for label, cert_id in gone.items()]
        doomed += [(None, cert_id) for cert_id in self.state["retired"]]
        audit: rs.AuditLog | None = None
        changed = False
        try:
            for label, cert_id in doomed:
                if cert_id in in_use:
                    continue  # a host still serves it; deleted at a later run
                if cert_id in present:
                    if audit is None:
                        audit = rs.AuditLog(
                            rs.audit_path(self.config_dir), rs.new_correlation_id(),
                            writer=WRITER,
                        )  # fmt: skip
                    name = label or f"certificate {cert_id}"
                    change = rs.Change(
                        "certificate", name, "deleted from the proxy", "delete_certificate",
                        effect="delete",
                    )  # fmt: skip
                    try:
                        _delete_certificate(self.base_url, self.token, cert_id)
                    except (urllib.error.URLError, OSError, ValueError):
                        audit.write(change, "error", "transport", host=True)
                        raise
                    audit.write(change, "allowed", host=True)
                    print(f"  deleted edge certificate: {name}", flush=True)
                if label is None:
                    self.state["retired"].remove(cert_id)
                else:
                    del self.state["uploads"][label]
                changed = True
        finally:
            if changed:
                self._save()
            if audit is not None:
                audit.close()


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

    ok = True
    # The edge leaves first (ADR 0035): every host below is created or corrected with its
    # uploaded certificate. Without leaves (a certificate bundle of row 3, another proxy
    # provider) nothing is uploaded and the hosts keep what they have.
    certs: _EdgeCertificates | None = None
    if config_dir is not None:
        certs = _EdgeCertificates(Path(config_dir), base_url, token)
        try:
            certs.upload()
        except (edge_pki.EdgePkiError, urllib.error.URLError, OSError, ValueError,
                KeyError, TypeError) as exc:  # fmt: skip
            print(f"Edge certificates not uploaded: {exc}", file=sys.stderr, flush=True)
            certs, ok = None, False

    # Every interface first: the main address must not take a host name one of them
    # serves (lib/sign_in.py).
    edge = ingress.edge_ports(root)
    found: list[ingress.Route] | None = None
    routes_error: ingress.IngressError | None = None
    if config_dir is not None and repo_root is not None:
        try:
            found = ingress.routes(tree, Path(config_dir), Path(repo_root))
        except ingress.IngressError as exc:
            routes_error = exc
    main = _entry_host(
        base_url, token, root, tree, edge,
        found if found is not None else ingress.core_routes(tree), certs,
    )  # fmt: skip
    existing = _existing_domains(base_url, token)

    created = 0
    skipped_existing = 0
    skipped_port_based = 0

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
        if module_tls.CORE_ROUTES.get(label) == fwd_host:
            # Created or corrected, so the upstream follows the security profile.
            route = core_route(root, label, url)
            if _correct_host(base_url, token, route, route_body(route),
                             owned=MODULE_OWNED_FIELDS, certs=certs):  # fmt: skip
                existing.add(domain)
                created += 1
            else:
                skipped_existing += 1
            continue
        route = ingress.Route("core", label, (domain,), url, fwd_host, fwd_port, fwd_scheme, "")
        if fwd_host == IDP_SERVICE:
            # Created or corrected, so an earlier host without the admin block gets it.
            body = core_host_body(domain, fwd_host, fwd_port, fwd_scheme, ssl_verify, ws)
            if _correct_host(base_url, token, route, body, owned=IDP_OWNED_FIELDS, certs=certs):
                existing.add(domain)
                created += 1
            else:
                skipped_existing += 1
            continue
        if domain in existing:
            # Kept as it is; only a missing certificate is set (an operator's stays).
            if certs is not None and _correct_host(
                base_url, token, route, {}, owned=(), certs=certs
            ):
                created += 1
            else:
                skipped_existing += 1
            continue
        certificate = certs.id_for((domain,)) if certs is not None else None
        _create_proxy_host(
            base_url,
            token,
            domain,
            fwd_host,
            fwd_port,
            fwd_scheme,
            ssl_verify,
            ws,
            **({"certificate_id": certificate} if certificate is not None else {}),
        )
        existing.add(domain)
        print(f"  created proxy host: {domain} -> {fwd_scheme}://{fwd_host}:{fwd_port}", flush=True)
        created += 1

    if main is not None:
        served.add(main)

    if config_dir is not None and repo_root is not None:
        if found is None:
            print(f"Add-on proxy hosts skipped: {routes_error}", file=sys.stderr, flush=True)
            ok = False
        else:
            # The Paperless route goes to its gate with the proxy's secret (below).
            addon = [r for r in found if r.module not in ("core", paperless_gate.ADDON)]
            created += _ingress_hosts(base_url, token, addon, certs)
            served |= {h for r in found for h in r.hostnames}
            ok = _uninstalled_hosts(base_url, token, Path(config_dir), served) and ok
    if config_dir is not None:
        try:
            block = _startgate_block(tree, Path(config_dir), found or [])
        except startgate.StartgateError as exc:
            # Without the block the edge would forward while the gate is closed.
            print(f"ERROR: the start gate cannot be set up at the edge: {exc}", file=sys.stderr)
            return False
        ok = _gate_steps(base_url, token, Path(config_dir), root, block, certs) and ok
    if certs is not None:
        try:
            certs.clean_up()
        except (edge_pki.EdgePkiError, urllib.error.URLError, OSError, ValueError,
                KeyError, TypeError) as exc:  # fmt: skip
            print(f"Edge certificates not cleaned up: {exc}", file=sys.stderr, flush=True)
            ok = False

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
    base_url: str,
    token: str,
    config_dir: Path,
    root: dict[str, str],
    gate_block: str = "",
    certs: _EdgeCertificates | None = None,
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
    ok = _paperless_route(base_url, token, config_dir, certs)
    guarded = _app_origin_guard(project, root)
    if guarded is None:
        ok = False
    if (changed or guarded) and not paperless_gate.reload_proxy(project):
        print(
            "WARNING: the proxy did not reload; server_proxy.conf takes effect at its next start.",
            file=sys.stderr,
            flush=True,
        )
    return ok


def _app_origin_guard(project: str, root: dict[str, str]) -> bool | None:
    """The edge's refusal of writes from Studio app hosts (lib/edge_guard.py): whether it
    changed, None when it is not in place."""
    try:
        bases = edge_guard.app_host_bases(root)
    except ingress.IngressError as exc:
        print(
            f"ERROR: the edge cannot refuse writes from the app hosts: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return None
    guarded = edge_guard.install(project, bases)
    if guarded is None:
        print(
            "ERROR: could not put the refusal of writes from the app hosts into the proxy"
            " (http_top.conf, server_proxy.conf); the previous configuration stays. Run"
            " 'papaia-ctl npm-provision' again once the proxy runs.",
            file=sys.stderr,
            flush=True,
        )
    return guarded
