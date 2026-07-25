"""Automatic NPM proxy-host provisioning for the bundled Nginx Proxy Manager.

Called by `papaia-ctl start` (via `py_cli npm-provision`) when
REVERSE_PROXY_PROVIDER=internal_nginx.  Only creates hosts that don't already
exist; subsequent runs are fully idempotent.

Uses only Python stdlib — no third-party dependencies.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .envtree import EnvTree


# Ordered list of (compose-profile, url-node, url-key, forward-host, forward-port,
# forward-scheme, ssl-verify, allow-websocket) tuples.  Only entries whose profile
# is in COMPOSE_PROFILES and whose URL passes _is_subdomain_url() are provisioned.
_PROXY_HOST_SPECS: list[tuple[str, str, str, str, int, str, bool, bool]] = [
    ("keycloak",  "",             "AUTH_HOST",          "keycloak",       8443, "https", False, False),
    ("librechat", "ai/librechat", "DOMAIN_SERVER",      "librechat",      3080, "http",  True,  True),
    ("litellm",   "",             "LITELLM_PUBLIC_URL", "litellm",        4000, "http",  True,  False),
    ("localai",   "",             "LOCALAI_PUBLIC_URL", "localai",        8080, "http",  True,  False),
    ("manager",   "",             "MANAGER_PUBLIC_URL", "papaia-manager", 8000, "http",  True,  False),
]


def _is_subdomain_url(url: str) -> bool:
    """Return True only for clean subdomain URLs with no explicit port.

    Port-based URLs (e.g. https://papaia.example.com:8200) indicate direct port
    access — no NPM proxy host should be created for them.  localhost /
    host.docker.internal addresses are also skipped since they are not reachable
    from inside the Docker network via the domain name NPM would proxy.
    """
    if not url:
        return False
    try:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        if not hostname or not parts.scheme:
            return False
        if hostname in ("localhost", "host.docker.internal", "127.0.0.1"):
            return False
        if parts.port is not None:
            return False
        return "." in hostname
    except Exception:
        return False


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
    req = urllib.request.Request(
        f"{base_url}/api/proxy-hosts?expand=domain_names",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        hosts = json.loads(resp.read())
    result: set[str] = set()
    for host in hosts:
        result.update(host.get("domain_names", []))
    return result


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
    payload: dict = {
        "domain_names": [domain],
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
        "advanced_config": "" if ssl_verify else "proxy_ssl_verify off;\n",
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base_url}/api/proxy-hosts",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10):
        pass


def provision_npm_hosts(tree: EnvTree) -> None:
    """Create NPM proxy hosts for all active services, skipping existing ones.

    No-op when REVERSE_PROXY_PROVIDER is not 'internal_nginx'.
    Idempotent: already-existing domain names are silently skipped.
    """
    root = tree.get("", {})
    if root.get("REVERSE_PROXY_PROVIDER") != "internal_nginx":
        return

    npm_api_port = root.get("NPM_API_LOCAL_PORT", "8181")
    base_url = f"http://localhost:{npm_api_port}"
    email = root.get("NPM_ADMIN_EMAIL", "admin@papaia.local")
    password = root.get("NPM_ADMIN_PASSWORD", "")
    if not password or password.startswith("GENERATE_"):
        raise RuntimeError(
            "NPM_ADMIN_PASSWORD is not set. Run 'papaia-ctl setup' first."
        )

    active_profiles = set(root.get("COMPOSE_PROFILES", "").split(","))

    print("Waiting for NPM API to become ready...", flush=True)
    _wait_for_npm(base_url)

    token = _get_token(base_url, email, password)
    existing = _existing_domains(base_url, token)

    created = 0
    skipped_existing = 0
    skipped_port_based = 0

    for profile, node, key, fwd_host, fwd_port, fwd_scheme, ssl_verify, ws in _PROXY_HOST_SPECS:
        if profile not in active_profiles:
            continue
        url = tree.get(node, {}).get(key, "") if node else root.get(key, "")
        if not _is_subdomain_url(url):
            skipped_port_based += 1
            continue
        domain = urlsplit(url).hostname or ""
        if domain in existing:
            skipped_existing += 1
            continue
        _create_proxy_host(base_url, token, domain, fwd_host, fwd_port, fwd_scheme, ssl_verify, ws)
        existing.add(domain)
        print(f"  created proxy host: {domain} -> {fwd_scheme}://{fwd_host}:{fwd_port}", flush=True)
        created += 1

    if created:
        print(f"NPM provisioning complete: {created} host(s) created.", flush=True)
    else:
        print(
            f"NPM provisioning: no new hosts (skipped {skipped_existing} existing,"
            f" {skipped_port_based} port-based).",
            flush=True,
        )
