"""The edge refuses platform writes from Studio app hosts (security §4.1 (3), E-20).

Studio apps are served from the app host (host key `apps`, lib/ingress.py): on a second
domain when `INGRESS_APP_DOMAIN` names one, otherwise on `apps.<domain>` and its
subdomains. Without a second domain the apps share the site of the platform, and
`SameSite` no longer keeps a browser from sending the platform's cookies with a request
an app makes. The compensating control at the edge:

- Every proxy host of the bundled proxy refuses a request whose method is not GET, HEAD
  or OPTIONS when its `Origin` is an app host (the app domain, `apps.<domain>`, or a host
  below one of them; any scheme and port). The answer is `403` with
  `X-Papaia-Error: app_origin_refused` and `X-Papaia-Correlation-Id`.
- Each refusal is one line in the shape of `papaia.audit/1` (the submission form; the
  delivering writer numbers the rows, as for papaia-egress) in the proxy's
  `/data/logs/papaia-audit.log`, on the host
  `$PAPAIA_CONFIG_DIR/infra/nginx/nginx-data/logs/papaia-audit.log`: event
  `protected_host_denied`, operation `edge.write`, the refused host as `object_ref`,
  the proxy's request id as correlation id, the time in UTC (the proxy's container runs
  in UTC; `doctor edge_app_origin` warns when lines lack it). No person, no origin
  value, no path, no query and no body are written: the edge knows no identity, and the
  line names the host that was protected only.

Both modes get the guard: with a second domain an app origin is cross-site anyway, and
the rule costs nothing. `Origin: null` (a sandboxed frame) is not refused here: browsers
also send it after redirects across sites, and the sign-in flows of the platform post
across sites. Studio's own gateway refuses it, and the app frame's CSP allows no request
at all (`connect-src 'none'`, `form-action 'none'`).

`npm-provision` writes the guard as managed blocks into two files of the proxy manager's
custom directory, through the proxy container like the header strip
(lib/paperless_gate.py): the maps and the log format into `http_top.conf` (http level),
the refusal into `server_proxy.conf`, which the proxy manager includes in every proxy
host, also in hosts created by hand. The proxy's configuration is tested
(`nginx -t`) before the reload; a configuration it refuses is rolled back.

`doctor edge_app_origin` checks that the guard is in place and that no platform cookie
carries a `Domain` attribute covering an app host (only host-only cookies).
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import ingress, paperless_gate, startgate, status

WRITER = "papaia-edge"
ERROR_CODE = "app_origin_refused"
SINGLE_SITE_LABEL = "apps"

# In the proxy container, and where the host sees them (the proxy's data directory).
AUDIT_LOG = "/data/logs/papaia-audit.log"
HTTP_TARGET = "/data/nginx/custom/http_top.conf"
SERVER_TARGET = "/data/nginx/custom/server_proxy.conf"
DATA_DIR = Path("infra") / "nginx" / "nginx-data"


def host_path(config_dir: Path, target: str) -> Path:
    """Where the host sees a file of the proxy's data directory."""
    return Path(config_dir) / DATA_DIR / target.removeprefix("/data/")


_HTTP_BEGIN = "# >>> papaia: Studio app hosts at the edge (managed by papaia-ctl, do not edit)"
_SERVER_BEGIN = (
    "# >>> papaia: refuse writes from Studio app hosts (managed by papaia-ctl, do not edit)"
)
_END = "# <<< papaia"

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_TIMEOUT = 60


def app_host_bases(root: dict[str, str]) -> list[str]:
    """The domains whose hosts are app hosts: `apps.<domain>` of the platform domain and
    the second domain, when there is one. Empty without host names (no proxy, a LAN
    address). IngressError for a host scheme that cannot be served."""
    scheme = ingress.host_scheme(root)
    bases = set()
    if scheme.domain is not None:
        bases.add(f"{SINGLE_SITE_LABEL}.{scheme.domain}")
    if scheme.app_domain is not None:
        bases.add(scheme.app_domain)
    return sorted(bases)


def origin_regex(bases: list[str]) -> str | None:
    """The `Origin` values of the app hosts, as a regular expression (nginx `~*`): an
    origin on one of `bases` or a host below it, http or https, with or without a port.
    None without app hosts. ValueError for a base that is not a domain."""
    if not bases:
        return None
    for base in bases:
        if not _DOMAIN_RE.fullmatch(base):
            raise ValueError(f"{base!r} is not a domain")
    names = "|".join(re.escape(b).replace(r"\-", "-") for b in bases)
    return rf"^https?://([a-z0-9-]+\.)*({names})(:[0-9]{{1,5}})?$"


def http_block(bases: list[str]) -> str:
    """The managed block of `http_top.conf`: which requests are refused, and the audit
    line. Valid on its own, so the proxy starts with it whatever `server_proxy.conf`
    holds."""
    regex = origin_regex(bases)
    origin_rule = f'    "~*{regex}" 1;\n' if regex else ""
    row = (
        '{"format":"papaia.audit/1",'
        '"time":"$papaia_audit_second.${papaia_audit_milli}Z",'
        '"correlation_id":"$request_id",'
        f'"writer":"{WRITER}",'
        '"role":"server","sub":null,"identity_kind":null,"azp":null,"catalog_id":null,'
        '"operation":"edge.write","effect":"write",'
        '"object_ref":{"type":"host","id":"$papaia_audit_host"},'
        f'"result":"denied","error_code":"{ERROR_CODE}","event":"protected_host_denied"}}'
    )
    return (
        f"{_HTTP_BEGIN}\n"
        "map $request_method $papaia_unsafe_method {\n"
        "    GET 0;\n"
        "    HEAD 0;\n"
        "    OPTIONS 0;\n"
        "    default 1;\n"
        "}\n"
        "map $http_origin $papaia_app_origin {\n"
        "    default 0;\n"
        f"{origin_rule}"
        "}\n"
        'map "$papaia_unsafe_method:$papaia_app_origin" $papaia_app_write {\n'
        '    "1:1" 1;\n'
        '    default "";\n'
        "}\n"
        "map $papaia_app_write $papaia_app_write_error {\n"
        f"    1 {ERROR_CODE};\n"
        '    default "";\n'
        "}\n"
        "map $papaia_app_write $papaia_app_write_correlation {\n"
        "    1 $request_id;\n"
        '    default "";\n'
        "}\n"
        "map $host $papaia_audit_host {\n"
        '    "~^[a-z0-9][a-z0-9.-]{0,252}$" $host;\n'
        "    default unknown;\n"
        "}\n"
        # UTC only: the proxy's container runs in UTC; with another zone (a TZ set for
        # it) the time stays empty, delivery refuses the line instead of storing a wrong
        # time, and `doctor edge_app_origin` warns.
        "map $time_iso8601 $papaia_audit_second {\n"
        '    "~^(?<papaia_t_second>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})'
        '(\\+00:00|Z)$" $papaia_t_second;\n'
        '    default "";\n'
        "}\n"
        "map $msec $papaia_audit_milli {\n"
        '    "~\\.(?<papaia_t_milli>[0-9]{3})$" $papaia_t_milli;\n'
        "    default 000;\n"
        "}\n"
        f"log_format papaia_audit escape=json '{row}';\n"
        f"{_END}\n"
    )


def server_block() -> str:
    """The managed block of `server_proxy.conf`, included in every proxy host."""
    return (
        f"{_SERVER_BEGIN}\n"
        f"access_log {AUDIT_LOG} papaia_audit if=$papaia_app_write;\n"
        "add_header X-Papaia-Error $papaia_app_write_error always;\n"
        "add_header X-Papaia-Correlation-Id $papaia_app_write_correlation always;\n"
        "if ($papaia_app_write) {\n"
        "    return 403;\n"
        "}\n"
        f"{_END}\n"
    )


def _split_block(text: str, begin: str) -> tuple[str, str]:
    """(the managed block starting `text`, the rest); ('', text) without one."""
    if not text.startswith(begin):
        return "", text
    end = text.find(_END + "\n")
    if end < 0:
        return text, ""
    cut = end + len(_END) + 1
    return text[:cut], text[cut:]


def merge_http(current: str, block: str) -> str:
    """`http_top.conf` with the managed block on top and the operator's lines kept."""
    _, rest = _split_block(current, _HTTP_BEGIN)
    return block + rest


def _remove_block(text: str, begin: str) -> str:
    """`text` without the managed block `begin`, wherever it stands."""
    start = text.find(begin)
    if start < 0:
        return text
    end = text.find(_END + "\n", start)
    if end < 0:
        return text[:start]
    return text[:start] + text[end + len(_END) + 1 :]


def merge_server(current: str, block: str) -> str:
    """`server_proxy.conf` with the header strip (when there) first, the core start gate
    (when there) after it, then the guard, and the operator's lines kept below. The
    order is the one the header strip writes (paperless_gate.merge_strip keeps what
    follows the start gate), so neither step rewrites the other's result."""
    strip, rest = _split_block(current, paperless_gate.STRIP_BEGIN)
    rest = _remove_block(rest, _SERVER_BEGIN)
    gate = ""
    if rest.startswith(startgate.BLOCK_BEGIN):
        end = rest.find(startgate.BLOCK_END + "\n")
        if end >= 0:
            cut = end + len(startgate.BLOCK_END) + 1
            gate, rest = rest[:cut], rest[cut:]
    return strip + gate + block + rest


def _proxy_container(project: str) -> str | None:
    return paperless_gate._proxy_container(project)


# The docker calls go through the probe runner of status and doctor (no shell on the
# host, literal subcommands); the script inside the proxy container takes the path and
# the content as arguments, never as part of its text.
_READ_SCRIPT = 'cat "$1" 2>/dev/null || true'
_WRITE_SCRIPT = (
    'mkdir -p "$(dirname "$1")" && printf "%s" "$2" > "$1.papaia" && mv "$1.papaia" "$1"'
)


def _read(container: str, target: str) -> str | None:
    done = status.run_command(
        ["docker", "exec", container, "sh", "-c", _READ_SCRIPT, "sh", target], _TIMEOUT
    )
    return done.stdout if done.returncode == 0 else None


def _write(container: str, target: str, text: str) -> bool:
    done = status.run_command(
        ["docker", "exec", container, "sh", "-c", _WRITE_SCRIPT, "sh", target, text], _TIMEOUT
    )
    return done.returncode == 0


def _config_test(container: str) -> bool:
    done = status.run_command(["docker", "exec", container, "nginx", "-t"], _TIMEOUT)
    return done.returncode == 0


def install(project: str, bases: list[str]) -> bool | None:
    """Put the guard into the running proxy of Compose project `project`. Returns whether
    a file changed (the proxy then needs a reload), None when the proxy does not run, a
    file cannot be read or written, or the proxy refuses the configuration (the previous
    files are then put back)."""
    container = _proxy_container(project)
    if container is None:
        return None
    current = {target: _read(container, target) for target in (HTTP_TARGET, SERVER_TARGET)}
    if any(text is None for text in current.values()):
        return None
    wanted = {
        HTTP_TARGET: merge_http(current[HTTP_TARGET] or "", http_block(bases)),
        SERVER_TARGET: merge_server(current[SERVER_TARGET] or "", server_block()),
    }
    if wanted == current:
        return False
    written: list[str] = []
    # The http level first: the server block uses its maps and log format.
    for target in (HTTP_TARGET, SERVER_TARGET):
        if wanted[target] == current[target]:
            continue
        if not _write(container, target, wanted[target]):
            _restore(container, current, written)
            return None
        written.append(target)
    if not _config_test(container):
        _restore(container, current, written)
        return None
    return True


def _restore(container: str, current: dict[str, str | None], written: list[str]) -> None:
    for target in reversed(written):
        _write(container, target, current[target] or "")


def guard_in_place(config_dir: Path, bases: list[str]) -> list[str]:
    """What is missing from the proxy's custom files as the host sees them; empty when
    both managed blocks are there and current."""
    missing = []
    for target, block in ((HTTP_TARGET, http_block(bases)), (SERVER_TARGET, server_block())):
        path = host_path(config_dir, target)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            missing.append(f"{target} is missing or unreadable")
            continue
        if block not in text:
            missing.append(f"{target} lacks the current managed block")
    return missing


def refusals(config_dir: Path) -> int | None:
    """How many refusals the audit log of the edge holds; None without the file."""
    path = host_path(config_dir, AUDIT_LOG)
    try:
        with path.open("rb") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


_UTC_TIME = re.compile(
    rb'"time":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"'
)


def lines_without_time(config_dir: Path) -> int:
    """Audit lines of the edge without a UTC time: the proxy then runs in another time
    zone (a `TZ` set for it), and delivery refuses those lines."""
    path = host_path(config_dir, AUDIT_LOG)
    try:
        with path.open("rb") as handle:
            return sum(1 for line in handle if line.strip() and not _UTC_TIME.search(line))
    except OSError:
        return 0


def covering_cookie(header: str, bases: list[str]) -> tuple[str, str] | None:
    """(cookie name, domain) when a `Set-Cookie` header carries a `Domain` attribute
    (the last one counts, a leading dot is ignored) that covers an app host; None for a
    host-only cookie or a domain that covers none. The value is never returned."""
    parts = header.split(";")
    name = parts[0].split("=", 1)[0].strip()
    domain = None
    for attribute in parts[1:]:
        key, _, value = attribute.partition("=")
        if key.strip().lower() == "domain":
            domain = value.strip().lstrip(".").lower() or None
    if domain is None:
        return None
    for base in bases:
        if base == domain or base.endswith(f".{domain}"):
            return name, domain
    return None


# ── platform cookies, read the way an anonymous browser gets them ────────────

PROBE_TIMEOUT_SECONDS = 5.0
PROBE_MAX_HOPS = 5
PROBE_MAX_URLS = 64
_MAX_URL = 2048
# One answer: (status, Set-Cookie headers, Location header or None).
Answer = tuple[int, list[str], "str | None"]


def http_get(address: str, url: str, ca_file: Path | None) -> Answer:
    """One anonymous GET of `url`, connected to `address` (the edge) with the URL's host
    as `Host` and TLS server name. No cookie, no credential; the body is not read. TLS is
    verified against the system's trust and the installation's CA (`ca_file`). OSError
    (ssl.SSLError included) when the host cannot be reached."""
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    sock = socket.create_connection((address, port), timeout=PROBE_TIMEOUT_SECONDS)
    try:
        if https:
            context = ssl.create_default_context()
            if ca_file is not None and ca_file.is_file():
                context.load_verify_locations(cafile=str(ca_file))
            sock = context.wrap_socket(sock, server_hostname=hostname)
        connection = http.client.HTTPConnection(hostname, port, timeout=PROBE_TIMEOUT_SECONDS)
        connection.sock = sock
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        connection.request(
            "GET",
            target,
            headers={"Host": parts.netloc, "Accept": "text/html"},
        )
        response = connection.getresponse()
        cookies = response.headers.get_all("Set-Cookie") or []
        return response.status, list(cookies), response.getheader("Location")
    except http.client.HTTPException as exc:
        raise OSError(f"no HTTP answer: {type(exc).__name__}") from exc
    finally:
        sock.close()


def platform_urls(tree: dict, config_dir: Path, repo_root: Path) -> list[ingress.Route]:
    """The interfaces of the platform: every route but the app host's."""
    return [r for r in ingress.routes(tree, config_dir, repo_root) if r.host_key != "apps"]


def start_urls(tree: dict, found: list[ingress.Route]) -> list[str]:
    """Where an anonymous browser starts: each interface's address, and the account page
    of the realm (the identity provider's sign-in sets its cookies there)."""
    urls = [f"{r.public_url}/" for r in found]
    issuer = (tree.get("", {}).get("OIDC_ISSUER") or "").rstrip("/")
    account = f"{issuer}/account/"
    if issuer and ingress.is_installation_url(account, found):
        urls.append(account)
    return list(dict.fromkeys(urls))[:PROBE_MAX_URLS]


def read_cookies(
    start: str,
    found: list[ingress.Route],
    bases: list[str],
    get: Callable[[str], Answer],
) -> tuple[list[str], str | None]:
    """Follow `start` through its redirects on the installation's hosts (at most
    PROBE_MAX_HOPS) and name every cookie whose `Domain` covers an app host, as
    `<name> (Domain=<domain>, set by <host>)`. The second value says why a host could not
    be read, None when every hop answered."""
    findings: list[str] = []
    url = start
    for _ in range(PROBE_MAX_HOPS + 1):
        host = urlsplit(url).hostname or url
        try:
            _status, cookies, location = get(url)
        except OSError as exc:
            return findings, f"{host}: {type(exc).__name__}"
        for header in cookies:
            hit = covering_cookie(header, bases)
            if hit is not None:
                findings.append(f"{hit[0]} (Domain={hit[1]}, set by {host})")
        if not location:
            return findings, None
        url = urljoin(url, location.strip())
        if len(url) > _MAX_URL or not ingress.is_installation_url(url, found):
            return findings, None
    return findings, None
