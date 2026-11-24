"""The proxy side of the Paperless gate.

Paperless takes the person from the request header `X-Papaia-Remote-User`. The Paperless
add-on puts a gate in front of it (in Paperless' network namespace) that passes a request
only when `X-Papaia-Gate` carries the secret issued to that caller. Each caller has its
own secret, revocable on its own: the bundled proxy has the one managed here, the
Paperless MCP server has another one that the add-on manages.

The core's part:

- `setup` generates the proxy's secret and stores it as a file outside every `.env`:
  `$PAPAIA_CONFIG_DIR/secrets/paperless-gate/proxy/secret` (the raw value, for the gate)
  and `nginx.conf` beside it (the header directive the proxy includes). Directory 0700,
  files 0600. The proxy mounts the directory read-only; no other core service sees it.
- Every proxy host clears both headers from the client request (`strip_config`, written
  by `npm-provision` to the proxy manager's `server_proxy.conf`, which it includes in
  every proxy host), so neither header can be sent through the proxy, also not on a host
  created by hand. The hosts `npm-provision` creates carry the same line themselves.
- Only the Paperless route sets the gate header, from the included file
  (`route_advanced_config`); the value never sits in the proxy manager's database.
- `papaia-ctl secrets rotate paperless-gate/proxy` replaces the secret and reloads the
  proxy; the gate reads the new value when the add-on is started again.
- The chat service is kept off the Paperless network; it reaches the MCP server over a
  front network (`front_network`, used by lib/gen_override.py).

The header directive uses `more_set_input_headers` / `more_clear_input_headers` (the
headers-more module of the proxy manager's OpenResty): a `proxy_set_header` in a proxy
host's advanced configuration sits at server level and is ignored, because the proxy
manager's own `location /` sets headers of its own.
"""

from __future__ import annotations

import os
import re
import secrets as _secrets
import shutil
import stat
import subprocess
from pathlib import Path

from . import common, images

REMOTE_USER_HEADER = "X-Papaia-Remote-User"
GATE_HEADER = "X-Papaia-Gate"

# The add-on whose service takes the person from the header, and the services of it the
# chat service may reach (over the front network, never over the Paperless network).
ADDON = "paperless"
FRONT_SERVICES: dict[str, tuple[str, ...]] = {ADDON: ("paperless-mcp",)}
FRONT_NETWORK_TEMPLATE = "${PAPAIA_PROJECT:-papaia}-%s-front"
FRONT_NETWORK_KEY = "%s-front"
# The core services that stay on the Paperless network: the proxy, nothing else.
PROXY_SERVICES = ("nginx-proxy-manager",)

# Where the proxy finds the gate: it shares Paperless' network namespace, so it is
# reached under the Paperless service name. Part of the contract with the add-on.
GATE_SERVICE = "paperless"
GATE_PORT = 8001
PUBLIC_URL_KEY = "PAPERLESS_PUBLIC_URL"

PROXY_SECRET_DIR = "secrets/paperless-gate/proxy"
SECRET_FILE = "secret"
NGINX_INCLUDE = "nginx.conf"
PROXY_MOUNT = "/run/papaia/paperless-gate"
ROTATE_TARGETS = ("paperless-gate/proxy",)

# Included by the proxy manager in every proxy host (`server_proxy.conf` of its custom
# directory); lives in its data directory, on the proxy's node, and is written by
# `npm-provision` through the proxy container.
STRIP_FILE = "infra/nginx/nginx-data/nginx/custom/server_proxy.conf"
_STRIP_BEGIN = "# >>> papaia: clear the gate headers (managed by papaia-ctl, do not edit)"
_STRIP_END = "# <<< papaia"
STRIP_BEGIN = _STRIP_BEGIN

# Header-safe and safe inside a double-quoted nginx string: no quote, backslash, `$`,
# whitespace or control character. The same rule the MCP server applies to its own.
_SECRET_RE = re.compile(r"\A[A-Za-z0-9._~+/=-]{32,512}\Z")
_MAX_FILE = 4096

PROXY_SERVICE = "nginx-proxy-manager"


class GateError(Exception):
    """The proxy's gate secret cannot be used; the message says what to do."""


def secret_dir(config_dir: Path) -> Path:
    return Path(config_dir) / PROXY_SECRET_DIR


def _include_text(secret: str) -> str:
    return f'more_set_input_headers "{GATE_HEADER}: {secret}";\n'


def read_proxy_secret(config_dir: Path) -> str | None:
    """The stored secret, or None when there is none. Raises GateError for a file that
    is a symbolic link, too large or not a valid secret: it is never passed on."""
    path = secret_dir(config_dir) / SECRET_FILE
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise GateError(f"{path} is a symbolic link; remove it and run 'papaia-ctl setup'")
    if not stat.S_ISREG(info.st_mode):
        raise GateError(f"{path} is not a file; remove it and run 'papaia-ctl setup'")
    if info.st_size > _MAX_FILE:
        raise GateError(
            f"{path} is larger than {_MAX_FILE} bytes; "
            "run 'papaia-ctl secrets rotate paperless-gate/proxy'"
        )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(_MAX_FILE + 1)
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        value = ""
    if not _SECRET_RE.match(value):
        raise GateError(
            f"{path} does not hold a valid gate secret (32 to 512 characters of"
            " A-Z a-z 0-9 . _ ~ + / = -); run 'papaia-ctl secrets rotate paperless-gate/proxy'"
        )
    return value


def _new_secret() -> str:
    # 32 random bytes, URL-safe base64 without padding: 43 characters.
    return _secrets.token_urlsafe(32)


def _private_dir(directory: Path) -> None:
    if directory.is_symlink():
        raise GateError(f"{directory} is a symbolic link; remove it and run 'papaia-ctl setup'")
    common.ensure_dir(directory)
    os.chmod(directory, 0o700)


def _write(config_dir: Path, secret: str) -> None:
    directory = secret_dir(config_dir)
    _private_dir(directory)
    for name in (SECRET_FILE, NGINX_INCLUDE):
        # atomic_write_private replaces a symlink at the path, it never follows one.
        if (directory / name).is_symlink():
            (directory / name).unlink()
    common.atomic_write_private(directory / SECRET_FILE, secret)
    common.atomic_write_private(directory / NGINX_INCLUDE, _include_text(secret))


def _audit(config_dir: Path, operation: str, event: str, correlation: str | None) -> None:
    """One `papaia.audit/1` row per write; the value is never part of it."""
    row = images._row(operation, event, {"target": ROTATE_TARGETS[0]}, correlation)
    row["effect"] = "write"
    images.append_audit(config_dir, row)


def ensure_proxy_secret(config_dir: Path, *, correlation: str | None = None) -> bool:
    """Generate the proxy's secret unless one is stored (sticky), and keep the include
    beside it in step. Returns whether a new secret was generated."""
    config_dir = Path(config_dir)
    correlation = images.correlation_id(correlation)  # checked before anything is written
    secret = read_proxy_secret(config_dir)
    include = secret_dir(config_dir) / NGINX_INCLUDE
    if secret is not None:
        try:
            current = include.read_text(encoding="utf-8") if not include.is_symlink() else ""
        except OSError:
            current = ""
        if current != _include_text(secret):
            _write(config_dir, secret)
        return False
    _write(config_dir, _new_secret())
    _audit(config_dir, "setup", "paperless_gate_secret_created", correlation)
    return True


def rotate(config_dir: Path, target: str, *, correlation: str | None = None) -> None:
    """Replace the secret of `target` (only `paperless-gate/proxy`)."""
    if target not in ROTATE_TARGETS:
        raise GateError(
            f"unknown secret '{target}'; this command rotates: {', '.join(ROTATE_TARGETS)}"
        )
    config_dir = Path(config_dir)
    correlation = images.correlation_id(correlation)  # checked before anything is written
    try:
        old = read_proxy_secret(config_dir)
    except GateError:
        old = None  # a broken file is exactly what rotation repairs
    new = _new_secret()
    while new == old:
        new = _new_secret()
    _write(config_dir, new)
    _audit(config_dir, "secrets-rotate", "paperless_gate_secret_rotated", correlation)


def strip_config() -> str:
    return (
        f"{_STRIP_BEGIN}\n"
        f'more_clear_input_headers "{REMOTE_USER_HEADER}" "{GATE_HEADER}";\n'
        f"{_STRIP_END}\n"
    )


def merge_strip(current: str, extra: str = "") -> str:
    """The proxy manager's `server_proxy.conf` with the managed block at the top, the
    managed block `extra` after it (the core start gate, lib/startgate.py; left out when
    empty) and whatever the operator wrote below kept as it is."""
    from . import startgate

    rest = current
    if current.startswith(_STRIP_BEGIN):
        end = current.find(_STRIP_END + "\n")
        rest = current[end + len(_STRIP_END) + 1 :] if end >= 0 else ""
    return strip_config() + extra + startgate.strip_block(rest)


def _proxy_container(project: str) -> str | None:
    """The id of the running proxy of Compose project `project`, or None."""
    if shutil.which("docker") is None:
        return None
    try:
        found = subprocess.run(
            [
                "docker", "ps", "-q",
                "--filter", f"label=com.docker.compose.project={project}",
                "--filter", f"label=com.docker.compose.service={PROXY_SERVICE}",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return None
    ids = found.stdout.split()
    return ids[0] if found.returncode == 0 and len(ids) == 1 else None


def install_strip_file(project: str, extra: str = "") -> bool | None:
    """Put the managed block into `server_proxy.conf` of the running proxy. Written
    through the proxy container: the proxy manager owns its data directory (as root),
    and it rewrites the files of its custom directory when it starts, so the directory
    can be neither read-only nor written by papaia-ctl on the host. Returns whether the
    file changed, None when the proxy does not run or the file cannot be written.
    `extra`: the start gate's block (merge_strip)."""
    container = _proxy_container(project)
    if container is None:
        return None
    target = f"/data/{STRIP_FILE.split('nginx-data/', 1)[1]}"
    try:
        read = subprocess.run(
            ["docker", "exec", container, "sh", "-c", f'cat "{target}" 2>/dev/null || true'],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
        if read.returncode != 0:
            return None
        wanted = merge_strip(read.stdout, extra)
        if wanted == read.stdout:
            return False
        write = subprocess.run(
            [
                "docker", "exec", "-i", container, "sh", "-c",
                f'mkdir -p "$(dirname "{target}")" && cat > "{target}.papaia"'
                f' && mv "{target}.papaia" "{target}"',
            ],
            input=wanted, capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return None
    return True if write.returncode == 0 else None


def route_advanced_config() -> str:
    """The advanced configuration of the Paperless proxy host. It brings its own
    `location /`, so the gate header is set where the request is proxied; the proxy
    manager then leaves out its default location."""
    return (
        "location / {\n"
        f'  more_clear_input_headers "{REMOTE_USER_HEADER}";\n'
        f"  include {PROXY_MOUNT}/{NGINX_INCLUDE};\n"
        # Document uploads, and the status updates Paperless sends over a websocket.
        "  client_max_body_size 100m;\n"
        "  proxy_http_version 1.1;\n"
        "  proxy_set_header Upgrade $http_upgrade;\n"
        "  proxy_set_header Connection $http_connection;\n"
        "  include conf.d/include/proxy.conf;\n"
        "}\n"
    )


def prepare(config_dir: Path) -> None:
    """What `setup` does: the secret, before the proxy starts (it mounts the directory)."""
    ensure_proxy_secret(config_dir)


def reload_proxy(project: str) -> bool:
    """Reload nginx in the running proxy of Compose project `project`, so a changed
    include or strip file takes effect. False when the proxy does not run or Docker is
    not reachable; the next start of the proxy reads the files anyway."""
    container = _proxy_container(project)
    if container is None:
        return False
    try:
        done = subprocess.run(
            ["docker", "exec", container, "nginx", "-s", "reload"],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def front_network(addon: str) -> tuple[str, str]:
    """(compose key in the add-on's project, network name template) of the front
    network of a header-identity add-on."""
    return FRONT_NETWORK_KEY % addon, FRONT_NETWORK_TEMPLATE % addon
