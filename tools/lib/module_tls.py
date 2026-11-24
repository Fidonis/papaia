"""TLS to the module services under the `kritis` security profile (ADR 0022, PLT-23).

Under `kritis` every way the core points at a module service goes over TLS with a
certificate of the platform PKI (docs/pki.md), checked against the platform CA:

- the proxy forwards the interfaces of Flow and the assistant (`integration.nginx`) and
  Mein Bereich (`me-web`) with https; it checks the certificate and the service name and
  presents its own client certificate (src/infra/nginx/pki.yaml);
- the catalog (`platform/services.json`) gives the addresses of Flow, the assistant and
  the connection registry as https, so Me and every other module call them with TLS;
- `me-web` listens with its server certificate (src/infra/me/pki.yaml) and checks the
  modules it calls against the platform CA (the override below); the identity provider,
  which does not trust that CA, calls Me's back-channel logout through the proxy
  (lib/sign_in.py).

A module service that has no server certificate of the platform PKI for the name it is
reached under is refused when the configuration is rendered; it is never forwarded in
plain text. Under `standard` nothing here applies. Other add-ons keep what they had:
whether they listen with TLS under `kritis` is not known to the core.
"""

from __future__ import annotations

from . import security_profile

# The module services this applies to: add-ons by name, core profiles by profile.
ADDONS = frozenset({"papaia-flow", "papaia-assist"})
CORE_PROFILES = frozenset({"me", "connections"})
# Core interfaces of the proxy (label of ingress.CORE_PROXY_HOSTS -> service) that are
# module services.
CORE_ROUTES = {"me": "me-web"}

# Where the proxy and me-web find their directory of the platform PKI.
TLS_DIR = "/run/papaia/tls"
EDGE_TLS_DIR = TLS_DIR
EDGE_SERVICE = "nginx-proxy-manager"
ME_SERVICE = "me-web"
ME_PORT = 8000
OVERRIDE = "docker-compose.module-tls.override.yml"


class ModuleTlsError(ValueError):
    """A module service that would be reached in plain text under `kritis`."""


def required(root: dict) -> bool:
    """Whether the installation whose root `.env` is `root` reaches the module services
    with TLS. ProfileError for a value that is no profile."""
    return security_profile.load(root).module_tls


def covers_provider(provider: str) -> bool:
    """Whether a catalog provider (`<add-on>` or `core:<profile>`) is a module service."""
    if provider.startswith("core:"):
        return provider.removeprefix("core:") in CORE_PROFILES
    return provider in ADDONS


def server_names(block: object, module: str, source: str, *, addon: bool) -> dict:
    """Service -> DNS names of its server certificate, from one `pki:` block."""
    from . import pki  # pki imports the realm sync, which imports the render path

    try:
        requests = pki.parse_request(block, module, source, addon=addon)
    except pki.PkiError as exc:
        raise ModuleTlsError(str(exc)) from None
    return {r.name: r.dns for r in requests if r.dns}


def tls_host(names: dict, service: str, candidates: tuple[str, ...], where: str) -> str:
    """The first of `candidates` (names `service` is reached under) that its server
    certificate covers. ModuleTlsError when there is none: the upstream would be plain."""
    dns = names.get(service, ())
    for host in candidates:
        if host in dns:
            return host
    raise ModuleTlsError(
        f"{where}: the kritis security profile reaches {service} over TLS only, but the"
        f" `pki:` request has no server certificate for {' or '.join(candidates)};"
        " the plain upstream is refused"
    )


def proxy_config(service: str) -> str:
    """The proxy lines of one TLS upstream: the platform CA, the service's name, its own
    client certificate. Nothing here turns a check off."""
    return (
        "proxy_ssl_verify on;\n"
        f"proxy_ssl_trusted_certificate {EDGE_TLS_DIR}/ca.crt;\n"
        "proxy_ssl_verify_depth 2;\n"
        f"proxy_ssl_name {service};\n"
        "proxy_ssl_server_name on;\n"
        "proxy_ssl_protocols TLSv1.3;\n"
        f"proxy_ssl_certificate {EDGE_TLS_DIR}/client.crt;\n"
        f"proxy_ssl_certificate_key {EDGE_TLS_DIR}/client.key;\n"
    )


def _mount(service: str) -> str:
    return f"${{PAPAIA_PKI_DIR}}/core/{service}:{TLS_DIR}:ro"


def override(profiles: set[str]) -> dict | None:
    """The compose override of the core services under `kritis` for the active
    `profiles`; None when no such service runs."""
    services: dict = {}
    if "nginx" in profiles:
        services[EDGE_SERVICE] = {"volumes": [_mount(EDGE_SERVICE)]}
    if "me" in profiles:
        probe = (
            "import ssl, urllib.request; urllib.request.urlopen("
            f"'https://{ME_SERVICE}:{ME_PORT}/readyz', timeout=3, "
            f"context=ssl.create_default_context(cafile='{TLS_DIR}/ca.crt'))"
        )
        services[ME_SERVICE] = {
            # The image's server reads these; the area checks the modules it calls
            # against the platform CA.
            "environment": {
                "UVICORN_SSL_CERTFILE": f"{TLS_DIR}/tls.crt",
                "UVICORN_SSL_KEYFILE": f"{TLS_DIR}/tls.key",
                "ME_MODULE_CA_FILE": f"{TLS_DIR}/ca.crt",
            },
            "volumes": [_mount(ME_SERVICE)],
            "healthcheck": {"test": ["CMD", "python", "-c", probe]},
        }
    return {"services": services} if services else None
