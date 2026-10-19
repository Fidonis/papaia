"""Outbound mail: the optional `smtp` profile and its one internal relay.

A single service, `smtp-relay`, holds the credentials of the real mail server (the
"upstream") and forwards to it. Everything else sends to `smtp-relay:587` without a
login and without TLS inside papaia-net; Keycloak is configured that way by the realm
bake and by `keycloak_role_sync`.

This module is the one place that knows how the relay is configured, so a different
relay image changes this file and `src/infra/smtp-relay/docker-compose.yml` and
nothing else:

  - the module env keys, their validation, and the keys derived from them,
  - the upstream password, which is kept in a file and not in an env file: an env
    file is written unquoted and Compose reads `$` and ` #` in it, and an env value
    shows up in `docker inspect`,
  - the Keycloak `smtpServer` block,
  - the probe `doctor` uses and the parser of the queue listing it reads.

Nothing here prompts; setup resolves values in bash and passes them in. Pure functions
wherever feasible, the same split the other lib modules keep.
"""

from __future__ import annotations

import re
import smtplib
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from . import common

PROFILE = "smtp"
SERVICE = "smtp-relay"

# What every consumer of the relay is told: plain SMTP on this name and port, inside
# papaia-net or an add-on network that attaches the service. Fixed because the realm
# block, the add-on contract and the docs all name them.
RELAY_HOST = "smtp-relay"
RELAY_PORT = 587

MODULE_DIR = "infra/smtp-relay"
PASSWORD_FILE = "upstream-password"

SECURITY_MODES = ("starttls", "tls", "none")
DEFAULT_PORTS = {"starttls": 587, "tls": 465, "none": 25}

KEY_HOST = "SMTP_RELAY_UPSTREAM_HOST"
KEY_PORT = "SMTP_RELAY_UPSTREAM_PORT"
KEY_SECURITY = "SMTP_RELAY_UPSTREAM_SECURITY"
KEY_USER = "SMTP_RELAY_UPSTREAM_USER"
KEY_FROM = "SMTP_RELAY_FROM_ADDRESS"
KEY_FROM_NAME = "SMTP_RELAY_FROM_NAME"
KEY_SENDER_DOMAINS = "SMTP_RELAY_SENDER_DOMAINS"
KEY_TLS_LEVEL = "SMTP_RELAY_TLS_LEVEL"
KEY_TLS_WRAPPER = "SMTP_RELAY_TLS_WRAPPER"
KEY_PASSWORD_REV = "SMTP_RELAY_PASSWORD_REV"

DEFAULT_FROM_NAME = "papAIa"

# Listing of the Postfix queue; read by `doctor`. Image specific, hence kept here.
QUEUE_COMMAND = ("postqueue", "-p")

PROBE_TIMEOUT_SECONDS = 8.0

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ADDRESS_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)$"
)
# The module env is written as KEY=value without quotes, and Compose reads it back:
# these characters would change meaning on the way (`$` interpolation, ` #` comment,
# quoting, escapes).
_ENV_UNSAFE = set("#$\"'\\`")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

MAX_PASSWORD_LENGTH = 512


class SmtpConfigError(ValueError):
    """A value setup cannot accept; the message says what to change."""


# ─────────────────────────────────────────────────────────────────────────
# validation
# ─────────────────────────────────────────────────────────────────────────


def validate_host(value: str) -> str:
    host = value.strip()
    if not host or not _HOST_RE.match(host):
        raise SmtpConfigError(
            f"'{value}' is not a valid mail server host name (letters, digits, dots and"
            " hyphens; no scheme, no port)."
        )
    return host


def validate_port(value: str | int) -> int:
    try:
        port = int(str(value).strip())
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise SmtpConfigError(f"'{value}' is not a valid port (1-65535).")
    return port


def validate_security(value: str) -> str:
    mode = value.strip().lower()
    if mode not in SECURITY_MODES:
        raise SmtpConfigError(
            f"'{value}' is not a valid connection security ({', '.join(SECURITY_MODES)})."
        )
    return mode


def _env_safe(label: str, value: str) -> str:
    text = value.strip()
    if _CONTROL.search(text) or any(ch in _ENV_UNSAFE for ch in text):
        raise SmtpConfigError(
            f"{label} may not contain control characters or any of # $ \" ' \\ ` (they would"
            " change meaning in the .env file)."
        )
    return text


def validate_user(value: str) -> str:
    user = _env_safe("The mail server login", value)
    if len(user) > 256 or ":" in user:
        raise SmtpConfigError("The mail server login may not contain ':' or exceed 256 characters.")
    return user


def validate_address(value: str) -> str:
    address = _env_safe("The sender address", value)
    if not _ADDRESS_RE.match(address):
        raise SmtpConfigError(
            f"'{value}' is not a valid sender address (expected name@example.org)."
        )
    return address


def validate_display_name(value: str) -> str:
    name = _env_safe("The sender name", value)
    if not name or len(name) > 80:
        raise SmtpConfigError("The sender name must have 1-80 characters.")
    return name


def validate_password(value: str) -> str:
    """The upstream password, as the user typed it.

    Any printable character is fine, including `$ # " ' \\` and inner spaces or
    colons. Leading and trailing whitespace is refused: Postfix reads the credentials
    from a table whose values are stripped, so such a password would silently differ
    from the one the server expects."""
    if not value or len(value) > MAX_PASSWORD_LENGTH:
        raise SmtpConfigError(
            f"The mail server password must have 1-{MAX_PASSWORD_LENGTH} characters."
        )
    if any(ch in value for ch in "\r\n\x00"):
        raise SmtpConfigError("The mail server password may not contain line breaks.")
    if value != value.strip():
        raise SmtpConfigError(
            "The mail server password may not start or end with a space: the relay"
            " could not send it unchanged."
        )
    return value


def derived_keys(security: str, from_address: str) -> dict[str, str]:
    """The module env keys that follow from the chosen security and sender."""
    return {
        KEY_SENDER_DOMAINS: from_address.rsplit("@", 1)[1].lower(),
        KEY_TLS_LEVEL: "none" if security == "none" else "verify",
        KEY_TLS_WRAPPER: "yes" if security == "tls" else "no",
    }


# ─────────────────────────────────────────────────────────────────────────
# the stored configuration
# ─────────────────────────────────────────────────────────────────────────


def password_path(config_dir: Path) -> Path:
    return config_dir / MODULE_DIR / PASSWORD_FILE


def read_password(config_dir: Path) -> str:
    """The stored upstream password, or "" when there is none or the file is missing."""
    try:
        return password_path(config_dir).read_text(encoding="utf-8")
    except OSError:
        return ""


def write_password(config_dir: Path, password: str) -> bool:
    """Store the upstream password (empty: the upstream needs no login). The file has
    to exist whenever the relay is configured, because it is mounted. Returns whether
    the password differs from the one stored before; a file that did not exist holds
    the empty password."""
    path = password_path(config_dir)
    changed = read_password(config_dir) != password
    if changed or not path.is_file():
        common.atomic_write_private(path, password)
    return changed


def _profiles(root_env: dict[str, str]) -> set[str]:
    return {p.strip() for p in root_env.get("COMPOSE_PROFILES", "").split(",") if p.strip()}


@dataclass(frozen=True)
class Settings:
    """The relay configuration as setup stored it."""

    profile_on: bool
    host: str = ""
    port: int | None = None
    security: str = "starttls"
    user: str = ""
    from_address: str = ""
    from_name: str = DEFAULT_FROM_NAME

    @property
    def configured(self) -> bool:
        return bool(self.host and self.from_address)

    @property
    def active(self) -> bool:
        """The relay runs and knows where to deliver: Keycloak gets a mail server."""
        return self.profile_on and self.configured

    @classmethod
    def from_env(cls, root_env: dict[str, str], module_env: dict[str, str]) -> Settings:
        raw_port = module_env.get(KEY_PORT, "").strip()
        security = module_env.get(KEY_SECURITY, "").strip().lower()
        return cls(
            profile_on=PROFILE in _profiles(root_env),
            host=module_env.get(KEY_HOST, "").strip(),
            port=int(raw_port) if raw_port.isdigit() else None,
            security=security if security in SECURITY_MODES else "starttls",
            user=module_env.get(KEY_USER, "").strip(),
            from_address=module_env.get(KEY_FROM, "").strip(),
            from_name=module_env.get(KEY_FROM_NAME, "").strip() or DEFAULT_FROM_NAME,
        )

    @classmethod
    def load(cls, config_dir: Path) -> Settings:
        return cls.from_env(
            common.parse_env_file(config_dir / ".env"),
            common.parse_env_file(config_dir / MODULE_DIR / ".env"),
        )


def realm_smtp_server(settings: Settings) -> dict[str, str]:
    """The `smtpServer` block of the Keycloak realm.

    Points at the relay, so it carries no credentials and no TLS settings. Keycloak
    stores every value of this map as a string."""
    return {
        "host": RELAY_HOST,
        "port": str(RELAY_PORT),
        "from": settings.from_address,
        "fromDisplayName": settings.from_name,
        "auth": "false",
        "ssl": "false",
        "starttls": "false",
    }


# ─────────────────────────────────────────────────────────────────────────
# probes (used by `doctor`)
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a handshake with the upstream. `stage` is where it stopped:
    resolve, connect, tls, starttls or auth; `ok` only after all of them."""

    ok: bool
    stage: str
    reason: str = ""
    login: str = "not tested"  # "ok" | "not tested" | "not needed"


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text[:200]


def probe_upstream(
    host: str,
    port: int,
    security: str,
    user: str,
    password: str,
    check_login: bool = True,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> ProbeResult:
    """Connect to the upstream the way the relay does: greeting, EHLO, STARTTLS or
    implicit TLS, and a login. No mail is sent, so a `doctor` run never delivers
    anything. A login is only attempted over an encrypted connection."""
    smtp: smtplib.SMTP | None = None
    stage = "connect"
    try:
        context = ssl.create_default_context()
        if security == "tls":
            stage = "tls"
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
        stage = "connect"
        smtp.ehlo()
        if security == "starttls":
            stage = "starttls"
            smtp.starttls(context=context)
            smtp.ehlo()
        login = "not needed"
        if user and security != "none":
            if not check_login:
                login = "not tested"
            else:
                stage = "auth"
                smtp.login(user, password)
                login = "ok"
        return ProbeResult(True, "ok", login=login)
    except socket.gaierror as exc:
        return ProbeResult(False, "resolve", f"cannot resolve {host}: {_short(exc)}")
    except ssl.SSLError as exc:
        return ProbeResult(False, stage, f"TLS handshake failed: {_short(exc)}")
    except smtplib.SMTPNotSupportedError as exc:
        return ProbeResult(False, stage, f"server does not offer it: {_short(exc)}")
    except smtplib.SMTPAuthenticationError as exc:
        return ProbeResult(False, "auth", f"login refused: {_short(exc)}")
    except (smtplib.SMTPException, OSError) as exc:
        return ProbeResult(False, stage, _short(exc))
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except OSError:
                pass


_QUEUE_COUNT_RE = re.compile(r"--\s*\d+\s*Kbytes in (\d+) Requests?", re.IGNORECASE)


def parse_queue_count(text: str) -> int | None:
    """Messages in the queue from `postqueue -p`, or None if the output is unknown."""
    if "Mail queue is empty" in text:
        return 0
    match = _QUEUE_COUNT_RE.search(text)
    return int(match.group(1)) if match else None
