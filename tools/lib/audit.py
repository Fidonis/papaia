"""papaia-audit: the keys, certificates and passwords of the audit store (docs/audit.md).

Everything lives under `$PAPAIA_CONFIG_DIR/infra/audit/`:

    pki/ca.key, pki/ca.crt        the ingest CA; the key never leaves papaia-ctl
    service/server.crt, .key      the certificate papaia-audit serves on :8443
    service/ca.crt                the CA it checks client certificates against
    service/sources.json          source -> fingerprints of its client certificates
    service/token-keys.json       the realm's issuer and signing keys, for the read API
    secrets/                      database passwords, the key that signs chain heads and
                                  the key of the pseudonyms (read API and SIEM export)
    clients/<source>/             client.crt, client.key and ca.crt of one source

The signed chain heads go to `$PAPAIA_BACKUP_DIR/audit-heads/` (`ensure_heads_folder`).
With a SIEM target over the network (`PAPAIA_AUDIT_SIEM_TARGET`), papaia-audit leaves the
stack through papaia-egress only: `egress_source` allows that one host and port, and
`generate_siem_override` puts the service on its own internal egress network. With an
operations address (`PAPAIA_OPERATIONS_MAIL`) and the mail relay, the relay joins that
network too, for the warning mails when the target takes no events for 10 minutes or
the volume of the store is 95 % full. `upstream_oid` is refused for a JSON lines target:
its `tid` and `oid` travel in the syslog header only.

`prepare` creates what is missing and never replaces what exists, so it runs before
every start. `issue_source_certificate` gives a source (one of SOURCES) a new client
certificate and lists only that one for the source: the previous one stops working.
`ensure_source_certificates`, also before every start, issues one for each source of an
enabled core profile (PROFILE_SOURCES) whose folder holds no usable certificate, and never
replaces a usable one. Run as root, both hand the files of the client folder of such a
source to the user its services run as (SOURCE_READERS); the folder stays root's.
`write_token_keys` stores the realm's signing keys that `papaia-ctl audit token-keys`
fetched; the read API accepts no token without them.

Keys and certificates are made with the `openssl` command, like the local CA of Keycloak.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.request
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import common, smtp, status

SERVICE = "papaia-audit"
PROFILE = "audit"
SOURCES_FORMAT = "papaia.audit-sources/1"
CERT_DAYS = 825
CA_DAYS = 3650
EXEC_TIMEOUT_SECONDS = 600.0

# The audit sources (governance GV-01); a client certificate is issued for these only.
SOURCES = (
    "papaia-studio",
    "papaia-data",
    "papaia-flow",
    "papaia-assist",
    "papaia-me",
    "papaia-connections",
    "papaia-manager",
    "papaia-lifecycle",
    "papaia-egress",
    "papaia-audit",
    "mcp-paperless",
    "mcp-qdrant",
    "mcp-mssql",
    "papaia-ctl",
)

# Secret file -> mode. Each is read by its owner only: the owner's password by the
# database entrypoint (root) and by papaia-audit-schema, the role passwords and the
# signing key by the service; both run as the user that owns the config dir.
SECRET_FILES = {
    "db-owner-password": 0o600,
    "db-ingest-password": 0o600,
    "db-read-password": 0o600,
    "db-retention-password": 0o600,
    "db-hold-password": 0o600,
}
HEADS_KEY = "heads-signing-key"
# Never replaced: a new key gives every person a new pseudonym.
PSEUDONYM_KEY = "pseudonym-key"
TOKEN_KEYS_FORMAT = "papaia.audit-token-keys/1"
_TOKEN_KEY_FIELDS = ("kid", "kty", "alg", "use", "n", "e")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]{1,1024}$")
HEADS_FOLDER = "audit-heads"
# The backup target the heads folder was set up on; its folder must exist from then on.
HEADS_TARGET_FILE = Path("infra") / "audit" / "heads-target"
SIEM_KEY = "PAPAIA_AUDIT_SIEM_TARGET"
IDENTITY_KEY = "PAPAIA_AUDIT_SIEM_IDENTITY"
OPERATIONS_MAIL_KEY = "PAPAIA_OPERATIONS_MAIL"
_MAIL_RE = re.compile(r"^[^@\s,;<>\"'\x00-\x1f\x7f]{1,64}@[A-Za-z0-9.-]{1,253}$")
SKIP_REASON_MIN, SKIP_REASON_MAX = 20, 1000
_TICKET_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PSEUD_RE = re.compile(r"^P-[A-Z2-7]{8}$")
_UPSTREAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
SIEM_SCHEMES = {"syslog-tls": 6514, "https": 443}


class AuditError(Exception):
    """The audit material could not be prepared or used; the message says why."""


def audit_dir(config_dir: Path) -> Path:
    return config_dir / "infra" / "audit"


def _openssl(*args: str, check: bool = True) -> str | None:
    """The output of `openssl <args>`. A failure raises, or with `check=False` gives None
    (a test of a certificate that answers "no")."""
    if shutil.which("openssl") is None:
        raise AuditError("openssl not found; it is needed for the audit certificates.")
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["openssl", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        if not check:
            return None
        lines = [line for line in result.stderr.splitlines() if line.strip()]
        raise AuditError(f"openssl {args[0]} failed: {lines[-1] if lines else 'no message'}")
    return result.stdout


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _issue(ca_dir: Path, out_dir: Path, name: str, usage: str) -> tuple[Path, Path]:
    """A P-256 key and a certificate for `name` signed by the ingest CA, written
    atomically into `out_dir` as <stem>.key / <stem>.crt."""
    stem = "server" if usage == "serverAuth" else "client"
    extensions = [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature",
        f"extendedKeyUsage={usage}",
        "subjectKeyIdentifier=hash",
        "authorityKeyIdentifier=keyid",
    ]
    if usage == "serverAuth":
        extensions.append(f"subjectAltName=DNS:{name}")
    with tempfile.TemporaryDirectory(dir=out_dir) as tmp:
        work = Path(tmp)
        (work / "ext").write_text("\n".join(extensions) + "\n", encoding="utf-8")
        _openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(work / "key"),
            "-out",
            str(work / "csr"),
            "-subj",
            f"/CN={name}",
        )
        _openssl(
            "x509",
            "-req",
            "-in",
            str(work / "csr"),
            "-CA",
            str(ca_dir / "ca.crt"),
            "-CAkey",
            str(ca_dir / "ca.key"),
            "-set_serial",
            str(secrets.randbits(120)),
            "-days",
            str(CERT_DAYS),
            "-extfile",
            str(work / "ext"),
            "-out",
            str(work / "crt"),
        )
        os.chmod(work / "key", 0o600)
        os.chmod(work / "crt", 0o644)
        os.replace(work / "key", out_dir / f"{stem}.key")
        os.replace(work / "crt", out_dir / f"{stem}.crt")
    return out_dir / f"{stem}.crt", out_dir / f"{stem}.key"


def fingerprint(certificate: Path) -> str:
    """`sha256:` and the SHA-256 of the certificate's DER form, as papaia-audit sees it."""
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    return "sha256:" + hashlib.sha256(der).hexdigest()


def load_sources(config_dir: Path) -> dict[str, list[str]]:
    path = audit_dir(config_dir) / "service" / "sources.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != SOURCES_FORMAT or not isinstance(data.get("sources"), dict):
        raise AuditError(f"{path} is not a {SOURCES_FORMAT} file.")
    return {str(name): list(prints) for name, prints in data["sources"].items()}


def _write_sources(config_dir: Path, sources: dict[str, list[str]]) -> None:
    document = {"format": SOURCES_FORMAT, "sources": dict(sorted(sources.items()))}
    path = audit_dir(config_dir) / "service" / "sources.json"
    common.atomic_write(path, json.dumps(document, indent=2) + "\n")
    os.chmod(path, 0o644)


def prepare(config_dir: Path) -> None:
    """Create the CA, the server certificate, the passwords, the signing key and an empty
    source list where they are missing. Existing material is kept as it is."""
    base = audit_dir(config_dir)
    pki = _private_dir(base / "pki")
    service = base / "service"
    service.mkdir(parents=True, exist_ok=True)
    secrets_dir = _private_dir(base / "secrets")

    if not (pki / "ca.key").is_file() or not (pki / "ca.crt").is_file():
        _openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(pki / "ca.key"),
            "-out",
            str(pki / "ca.crt"),
            "-days",
            str(CA_DAYS),
            "-subj",
            "/CN=papaia-audit ingest CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        os.chmod(pki / "ca.key", 0o600)
        # A new CA invalidates every certificate of the old one.
        for stale in (service / "server.crt", service / "server.key"):
            stale.unlink(missing_ok=True)
        _write_sources(config_dir, {})
    shutil.copyfile(pki / "ca.crt", service / "ca.crt")
    os.chmod(service / "ca.crt", 0o644)
    if not (service / "server.crt").is_file() or not (service / "server.key").is_file():
        _issue(pki, service, SERVICE, "serverAuth")
    if not (service / "sources.json").is_file():
        _write_sources(config_dir, {})

    for name, mode in SECRET_FILES.items():
        path = secrets_dir / name
        if not path.is_file():
            common.atomic_write_private(path, secrets.token_urlsafe(32))
        os.chmod(path, mode)
    if not (secrets_dir / HEADS_KEY).is_file():
        _openssl("genpkey", "-algorithm", "ed25519", "-out", str(secrets_dir / HEADS_KEY))
    os.chmod(secrets_dir / HEADS_KEY, 0o600)
    if not (secrets_dir / PSEUDONYM_KEY).is_file():
        common.atomic_write_private(secrets_dir / PSEUDONYM_KEY, secrets.token_urlsafe(48))
    os.chmod(secrets_dir / PSEUDONYM_KEY, 0o600)


def write_token_keys(config_dir: Path, discovery: object, jwks: object) -> Path:
    """Write service/token-keys.json from the realm's discovery document and key set:
    the issuer and its RSA signing keys (RS256, at least 2048 bits), nothing else.
    papaia-audit re-reads the file when it changes."""
    issuer = discovery.get("issuer") if isinstance(discovery, dict) else None
    if not isinstance(issuer, str) or not issuer.startswith(("https://", "http://")):
        raise AuditError("the realm's discovery document names no issuer.")
    entries = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(entries, list):
        raise AuditError("the realm's key set holds no keys.")
    keys = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA":
            continue
        if entry.get("use", "sig") != "sig" or entry.get("alg", "RS256") != "RS256":
            continue
        key = {name: entry[name] for name in _TOKEN_KEY_FIELDS if name in entry}
        if not all(
            isinstance(key.get(name), str) and _B64URL_RE.match(key[name])
            for name in ("kid", "n", "e")
        ):
            raise AuditError("the realm's key set holds a malformed key.")
        padded = key["n"] + "=" * (-len(key["n"]) % 4)
        if int.from_bytes(base64.urlsafe_b64decode(padded), "big").bit_length() < 2048:
            raise AuditError("the realm's signing key is shorter than 2048 bits.")
        keys.append(key)
    if not keys:
        raise AuditError("the realm has no RS256 signing key.")
    path = audit_dir(config_dir) / "service" / "token-keys.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"format": TOKEN_KEYS_FORMAT, "issuer": issuer, "keys": keys}
    common.atomic_write(path, json.dumps(document, indent=2) + "\n")
    os.chmod(path, 0o644)
    return path


def fetch_token_keys(base_url: str, ctx: ssl.SSLContext) -> tuple[object, object]:
    """The realm's discovery document and key set, from where `papaia-ctl` reaches Keycloak
    (the key set by its fixed path there, not by the `jwks_uri` the document names)."""
    realm = f"{base_url}/realms/papaia"
    documents = []
    for url in (
        f"{realm}/.well-known/openid-configuration",
        f"{realm}/protocol/openid-connect/certs",
    ):
        try:
            with urllib.request.urlopen(url, timeout=10, context=ctx) as response:  # noqa: S310
                documents.append(json.loads(response.read(256 * 1024)))
        except (OSError, ValueError) as exc:
            raise AuditError(f"Keycloak did not answer at {base_url}: {exc}") from None
    return documents[0], documents[1]
def ensure_heads_folder(config_dir: Path) -> Path:
    """`$PAPAIA_BACKUP_DIR/audit-heads`, where papaia-audit appends the signed chain heads
    every hour (K-15). The backup target itself is never created, and the folder only
    once per target (recorded in infra/audit/heads-target): a missing folder after that
    is an unmounted target, and its empty mount point must not take the heads instead."""
    backup = common.parse_env_file(config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if not backup or not Path(backup).is_absolute():
        raise AuditError("PAPAIA_BACKUP_DIR must be set to an absolute path (the signed "
                         "chain heads are kept there).")
    backup_dir = Path(backup)
    folder = backup_dir / HEADS_FOLDER
    marker = config_dir / HEADS_TARGET_FILE
    recorded = marker.read_text(encoding="utf-8").strip() if marker.is_file() else None
    if not folder.is_dir():
        if recorded == str(backup_dir):
            raise AuditError(f"{folder} is missing: the backup target is not mounted. Mount "
                             "it and run again; only for a new, empty target create the "
                             "folder (mode 0700).")
        if not backup_dir.is_dir():
            raise AuditError(f"the backup target PAPAIA_BACKUP_DIR={backup_dir} does not "
                             "exist: create or mount it (the signed chain heads are kept "
                             "there).")
        folder.mkdir(mode=0o700)
    if recorded != str(backup_dir):
        marker.parent.mkdir(parents=True, exist_ok=True)
        common.atomic_write_private(marker, f"{backup_dir}\n")
    return folder


# ─────────────────────────────────────────────────────────────────────────
# SIEM target behind papaia-egress
# ─────────────────────────────────────────────────────────────────────────


def siem_target(env: dict[str, str]) -> tuple[str, int] | None:
    """Host and port of `PAPAIA_AUDIT_SIEM_TARGET`, or None when no target is set."""
    raw = env.get(SIEM_KEY, "").strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port or SIEM_SCHEMES.get(parts.scheme)
        host = egress_host(parts.hostname or "")
    except ValueError as exc:
        raise AuditError(f"{SIEM_KEY}: {exc}") from None
    if parts.scheme not in SIEM_SCHEMES or port is None or parts.username or parts.query:
        raise AuditError(f"{SIEM_KEY} must be syslog-tls://host[:port] or "
                         "https://host[:port]/path")
    return host, port


def egress_host(value: str) -> str:
    from . import egress

    return egress.allowed_host(value)


def siem_network(env: dict[str, str]) -> str:
    project = env.get("PAPAIA_PROJECT") or env.get("COMPOSE_PROJECT_NAME") or "papaia"
    return f"{project}-{SERVICE}-egress"


def egress_source(config_dir: Path) -> dict | None:
    """The source of papaia-audit at papaia-egress while a SIEM target is set."""
    from . import egress

    found = siem_target(common.parse_env_file(config_dir / ".env"))
    if found is None:
        return None
    host, port = found
    return {
        "name": SERVICE,
        "alias": egress.alias(SERVICE),
        "allow": [{"host": host, "ports": [port]}],
        "internal": egress.load_internal_targets(config_dir).get(SERVICE, []),
    }


def siem_override_path(config_dir: Path) -> Path:
    return config_dir / "overrides" / f"docker-compose.{SERVICE}.siem.override.yml"


def generate_siem_override(config_dir: Path) -> Path | None:
    """Put papaia-audit on its own internal egress network, with papaia-egress as its only
    way out, while a SIEM target is set; remove the override otherwise."""
    from . import egress

    out = siem_override_path(config_dir)
    env = common.parse_env_file(config_dir / ".env")
    if siem_target(env) is None:
        out.unlink(missing_ok=True)
        return None
    identity = env.get(IDENTITY_KEY, "").strip()
    if identity == "upstream_oid" and urlsplit(env.get(SIEM_KEY, "").strip()).scheme != (
        "syslog-tls"
    ):
        raise AuditError(f"{IDENTITY_KEY}=upstream_oid needs a syslog-tls:// target: tid and "
                         "oid travel in the syslog header, never in the papaia.audit/1 document")
    net = siem_network(env)
    mail = operations_mail(env)
    relay = smtp.Settings.load(config_dir)
    override: dict = {
        "services": {
            SERVICE: {
                "environment": {
                    "PAPAIA_AUDIT_SIEM_PROXY": f"http://{egress.alias(SERVICE)}:{egress.PORT}",
                },
                "networks": {
                    "papaia-audit-net": {},
                    "papaia-audit-ingest-net": {},
                    "papaia-audit-idp-net": {},
                    net: {},
                },
            },
            egress.SERVICE: {
                "networks": {
                    egress.EGRESS_NETWORK: {},
                    net: {"aliases": [egress.alias(SERVICE)]},
                }
            },
        },
        "networks": {net: {"name": net, "internal": True}},
    }
    if mail and relay.active:
        # The relay joins the audit egress network, never papaia-audit-net.
        override["services"][SERVICE]["environment"].update({
            "PAPAIA_AUDIT_MAIL_RELAY": f"{smtp.RELAY_HOST}:{smtp.RELAY_PORT}",
            "PAPAIA_AUDIT_ALERT_TO": mail,
            "PAPAIA_AUDIT_ALERT_FROM": relay.from_address,
        })
        override["services"][smtp.SERVICE] = {"networks": {"papaia-net": {}, net: {}}}
    out.parent.mkdir(parents=True, exist_ok=True)
    common.atomic_write(out, yaml.safe_dump(override, sort_keys=False, default_flow_style=False))
    return out


def operations_mail(env: dict[str, str]) -> str:
    """`PAPAIA_OPERATIONS_MAIL`: one address for the warning mails, or empty."""
    value = env.get(OPERATIONS_MAIL_KEY, "").strip()
    if value and not _MAIL_RE.fullmatch(value):
        raise AuditError(f"{OPERATIONS_MAIL_KEY} must be one mail address")
    return value


def issue_source_certificate(config_dir: Path, source: str) -> Path:
    """A new client certificate for `source`; it replaces the source's previous one."""
    if source not in SOURCES:
        raise AuditError(f"'{source}' is not an audit source. Known: {', '.join(SOURCES)}.")
    prepare(config_dir)
    base = audit_dir(config_dir)
    out_dir = _client_dir(base / "clients" / source, source)
    certificate, _ = _issue(base / "pki", out_dir, source, "clientAuth")
    _replace_file(out_dir / "ca.crt", (base / "pki" / "ca.crt").read_bytes(), 0o644)
    _hand_over(out_dir, source)
    sources = load_sources(config_dir)
    sources[source] = [fingerprint(certificate)]
    _write_sources(config_dir, sources)
    return out_dir


# ─────────────────────────────────────────────────────────────────────────
# the source certificates `start` issues
# ─────────────────────────────────────────────────────────────────────────

# Core profiles whose services deliver audit rows as a source from a mounted client folder
# (`infra/audit/clients/<source>`). `start` issues the certificates of the sources of every
# enabled profile here when they are missing or unusable (ensure_source_certificates); a
# test over the core's compose files keeps this table complete. Never an add-on source.
PROFILE_SOURCES: dict[str, tuple[str, ...]] = {
    "me": ("papaia-me",),
    "connections": ("papaia-connections",),
}
# The numeric user the services of each of these sources run as (the image's `USER`, or the
# compose file's `user:`), with every capability dropped: the only account besides root
# that can read the 0600 key. Run as root, papaia-ctl hands the three files to it and
# keeps the folder itself (root, 0711): that user opens the files by name but can never
# add, replace or remove an entry that a later run as root would then act on. A test
# holds the table to the compose files.
SOURCE_READERS: dict[str, int] = {
    "papaia-me": 10001,
    "papaia-connections": 10001,
}
_CLIENT_FILES = ("client.key", "client.crt", "ca.crt")
CERT_WRITER = "papaia-ctl/audit-cert"
_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
_CLIENT_MOUNT_RE = re.compile(r"(?:^|/)infra/audit/clients/([^/:]+)/?$")
_CLIENT_AUTH = "TLS Web Client Authentication"


@dataclass(frozen=True)
class ClientMount:
    """A service of a core compose file that mounts the client folder of `source`."""

    file: str
    service: str
    profiles: frozenset[str]
    source: str


@dataclass(frozen=True)
class Issued:
    """One certificate `start` issued (or, with the reason `wrong_owner`, handed to the user
    of its services without replacing it): the source, why, and the fingerprint."""

    source: str
    reason: str
    fingerprint: str


@dataclass(frozen=True)
class SourceCertificates:
    """What ensure_source_certificates did, and what the operator must still do."""

    issued: list[Issued]
    warnings: list[str]


_HANDED_MODE = 0o711


def _uid_of(path: Path) -> int:
    """The owner of `path` itself; a symbolic link is never followed."""
    return os.lstat(path).st_uid


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _single_file(path: Path) -> bool:
    """`path` itself is a regular file with no other name: not a symbolic link, not a
    device or pipe, and not a hard link to a file elsewhere."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def _folder_exists(folder: Path, source: str) -> bool:
    """Whether the client folder of `source` exists. Anything at its place that is not a
    folder (a symbolic link included) is refused, never followed."""
    try:
        info = os.lstat(folder)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise AuditError(
            f"audit source {source}: {folder} is not a folder (a link or a file); remove it."
        )
    return True


def _claim(folder: Path) -> None:
    """Run as root: a client folder that root does not own, or that others may write to,
    goes to root with mode 0700 before anything in it is read or written, so no other
    account can change its entries meanwhile. The parent `clients/` is root's or the
    operator's, so the folder cannot be swapped for a link after the check."""
    info = os.lstat(folder)
    if _uid_of(folder) != 0 or info.st_mode & 0o022:
        os.chown(folder, 0, -1, follow_symlinks=False)
        os.chmod(folder, 0o700)


def _client_dir(folder: Path, source: str) -> Path:
    """The client folder of `source`, created when missing and private (0700) while it is
    written; run as root it is root's first (_claim)."""
    if not _folder_exists(folder, source):
        folder.mkdir(mode=0o700, parents=True)
    if _is_root():
        _claim(folder)
    os.chmod(folder, 0o700)
    return folder


def _replace_file(path: Path, content: bytes, mode: int) -> None:
    """Write `path` as a new file (a temp file of a random name in the same folder, then
    os.replace): whatever was at that name, a link included, is replaced, never written
    through."""
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            os.fchmod(handle.fileno(), mode)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def _hand_over(folder: Path, source: str) -> None:
    """Run as root: the three files to the user the source's services run as, the folder
    root's with mode 0711. The file modes stay (key 0600); the group is left alone; a
    link is never followed, and a name that is not a single regular file is refused.
    Nothing for a source no core service reads from a client folder, and nothing when not
    run as root."""
    uid = SOURCE_READERS.get(source)
    if uid is None or not _is_root():
        return
    _claim(folder)
    for name in _CLIENT_FILES:
        if not _single_file(folder / name):
            raise AuditError(f"audit source {source}: {folder / name} is not a regular file.")
        os.chown(folder / name, uid, -1, follow_symlinks=False)
    os.chmod(folder, _HANDED_MODE)


def _held_by(folder: Path, uid: int) -> bool:
    """Handed over: the folder root's with mode 0711, the files `uid`'s."""
    if _uid_of(folder) != 0 or stat.S_IMODE(os.lstat(folder).st_mode) != _HANDED_MODE:
        return False
    return all(_uid_of(folder / name) == uid for name in _CLIENT_FILES)


def _handed_over(folder: Path, uid: int) -> bool:
    """Seen by another account: the folder root's and its key `uid`'s (the folder can be
    passed through, not listed)."""
    try:
        return _uid_of(folder) == 0 and _uid_of(folder / "client.key") == uid
    except OSError:
        return False


def core_compose_files(repo_root: Path) -> list[Path]:
    """Every compose file of the core: `src/**/docker-compose*.yml`."""
    src = repo_root / "src"
    return sorted(
        path
        for pattern in ("docker-compose*.yml", "docker-compose*.yaml")
        for path in src.rglob(pattern)
        if path.is_file()
    )


def _compose_services(path: Path) -> dict[str, dict]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AuditError(f"cannot read the compose file {path}: {exc}") from None
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict):
        return {}
    return {str(name): body for name, body in services.items() if isinstance(body, dict)}


def _profiles_of(body: dict) -> frozenset[str]:
    raw = body.get("profiles")
    return frozenset(str(p) for p in raw) if isinstance(raw, list) else frozenset()


def declared_profiles(files: Sequence[Path]) -> set[str]:
    """The profiles the services of these compose files name."""
    found: set[str] = set()
    for path in files:
        for body in _compose_services(path).values():
            found |= _profiles_of(body)
    return found


def client_mounts(files: Sequence[Path]) -> list[ClientMount]:
    """Every service of these compose files that mounts `infra/audit/clients/<source>`,
    in the short (`source:target[:mode]`) or the long (`source:`) form."""
    found = []
    for path in files:
        for service, body in _compose_services(path).items():
            volumes = body.get("volumes")
            for volume in volumes if isinstance(volumes, list) else []:
                if isinstance(volume, str):
                    host = volume.split(":", 1)[0]
                elif isinstance(volume, dict):
                    host = str(volume.get("source") or "")
                else:
                    continue
                match = _CLIENT_MOUNT_RE.search(host)
                if match:
                    found.append(ClientMount(str(path), service, _profiles_of(body),
                                             match.group(1)))  # fmt: skip
    return found


def unmapped_client_mounts(files: Sequence[Path]) -> list[str]:
    """Mounted client folders `start` would leave empty: a service without a profile, or
    one whose profiles PROFILE_SOURCES does not map to the source it mounts."""
    findings = []
    for mount in client_mounts(files):
        if not mount.profiles or not any(
            mount.source in PROFILE_SOURCES.get(profile, ()) for profile in mount.profiles
        ):
            profiles = ", ".join(sorted(mount.profiles)) or "no profile"
            findings.append(
                f"{mount.file}: service '{mount.service}' ({profiles}) mounts the client "
                f"folder of '{mount.source}', which PROFILE_SOURCES does not issue for it"
            )
    return findings


def _der(path: Path) -> bytes | None:
    try:
        return ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _certificate_problem(base: Path, source: str, listed: Sequence[str]) -> str | None:
    """Why the client folder of `source` is unusable, or None when it is usable."""
    folder = base / "clients" / source
    crt, key, ca = folder / "client.crt", folder / "client.key", folder / "ca.crt"
    for path in (crt, key, ca):
        if not os.path.lexists(path):
            return "missing"
        if not _single_file(path):
            # A link, a hard link or a special file is never read; a new file replaces it.
            return "not_regular"
    current = base / "pki" / "ca.crt"
    if _der(ca) is None or _der(ca) != _der(current):
        return "foreign_ca"
    if _der(crt) is None:
        return "not_signed"
    if _openssl("x509", "-in", str(crt), "-noout", "-checkend", "0", check=False) is None:
        return "expired"
    text = _openssl("x509", "-in", str(crt), "-noout", "-subject", "-nameopt", "RFC2253",
                    "-text", check=False) or ""  # fmt: skip
    subject = text.splitlines()[0] if text else ""
    if subject.removeprefix("subject=").strip() != f"CN={source}" or _CLIENT_AUTH not in text:
        return "wrong_identity"
    verified = _openssl("verify", "-CAfile", str(current), "-purpose", "sslclient", str(crt),
                        check=False)  # fmt: skip
    if verified is None or not verified.rstrip().endswith(": OK"):
        return "not_signed"
    public = _openssl("x509", "-in", str(crt), "-noout", "-pubkey", check=False)
    private = _openssl("pkey", "-in", str(key), "-pubout", check=False)
    if public is None or private is None or public.strip() != private.strip():
        return "key_mismatch"
    if fingerprint(crt) not in listed:
        return "not_listed"
    return None


def _wanted_sources(profiles: Sequence[str], known_profiles: Collection[str]) -> list[str]:
    """The sources of the enabled profiles, in the order of PROFILE_SOURCES. A malformed or
    unknown profile and a table entry for an unknown source are refused."""
    known = set(known_profiles)
    enabled = set()
    for profile in profiles:
        if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
            raise AuditError(f"'{profile}' is not a profile name.")
        if profile not in known:
            raise AuditError(f"'{profile}' is not a profile of the core.")
        enabled.add(profile)
    wanted: list[str] = []
    for profile, sources in PROFILE_SOURCES.items():
        if profile not in enabled:
            continue
        for source in sources:
            if source not in SOURCES:
                raise AuditError(f"'{source}' (profile '{profile}') is not an audit source.")
            if source not in wanted:
                wanted.append(source)
    return wanted


def ensure_source_certificates(
    config_dir: Path, profiles: Sequence[str], *, known_profiles: Collection[str]
) -> SourceCertificates:
    """Issue the client certificate of each source of an enabled core profile
    (PROFILE_SOURCES) whose folder holds no usable one: a file missing, `ca.crt` not the
    current ingest CA, the certificate not signed by it, expired, not for `clientAuth` with
    the source as common name, its key not matching, or its fingerprint not listed for the
    source. A usable certificate is never replaced; rotation stays `audit cert`.

    The services read the files as their own user (SOURCE_READERS). Run as root, the
    folder is root's before anything in it is read; a link, a hard link or a special file
    in it is never followed but unusable (`not_regular`) and replaced by a new file; the
    files of a new certificate are handed to that user, and a usable certificate the
    services cannot own is handed over without being replaced (`wrong_owner`). Run as
    another account, a folder already handed over is left alone (it cannot be looked
    into), a folder of a third account is refused before anything is written, and on Linux
    a folder the services cannot read gives a warning on every run. A client folder that
    is not a folder (a link) is refused in either case.

    Each issue or hand-over writes one `papaia.audit/1` row (source, reason, fingerprint)
    to the outbox of papaia-ctl; the outbox is opened at the first one, so a run with
    nothing to do writes nothing. Runs after `prepare`: without the ingest CA it refuses."""
    wanted = _wanted_sources(profiles, known_profiles)
    if not wanted:
        return SourceCertificates([], [])
    base = audit_dir(config_dir)
    if not (base / "pki" / "ca.crt").is_file() or not (base / "pki" / "ca.key").is_file():
        raise AuditError("the ingest CA is missing; 'papaia-ctl start' creates it first.")
    listed = load_sources(config_dir)
    root = _is_root()
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    due: list[tuple[str, str]] = []
    for source in wanted:
        folder = base / "clients" / source
        reader = SOURCE_READERS[source]
        exists = _folder_exists(folder, source)
        if root and exists:
            _claim(folder)
        elif not root and euid is not None and exists:
            owner = _uid_of(folder)
            if owner != euid and _handed_over(folder, reader):
                # Handed over by a start as root; this account cannot look into it.
                continue
            if owner != euid:
                raise AuditError(
                    f"audit source {source}: the folder {folder} belongs to uid {owner}, "
                    f"not to uid {euid} that runs papaia-ctl. Remove it if it is empty "
                    "(Docker creates a missing folder as root), or run 'papaia-ctl start' "
                    "as root."
                )
        reason = _certificate_problem(base, source, listed.get(source, []))
        if reason is None and root and not _held_by(folder, reader):
            reason = "wrong_owner"
        if reason:
            due.append((source, reason))
    if not due:
        return SourceCertificates([], _reader_warnings(base, wanted))

    from . import realm_sync

    issued: list[Issued] = []
    try:
        log = realm_sync.AuditLog(
            realm_sync.audit_path(config_dir), realm_sync.new_correlation_id(), writer=CERT_WRITER
        )
    except (realm_sync.RealmSyncError, OSError) as exc:
        raise AuditError(f"the audit outbox cannot be written: {exc}") from None
    with log:
        for source, reason in due:
            if reason == "wrong_owner":
                folder = base / "clients" / source
                print_ = fingerprint(folder / "client.crt")
                change = realm_sync.Change("audit_source_certificate", f"{source}/{print_}",
                                           "handed_over", "hand_over")  # fmt: skip
                try:
                    _hand_over(folder, source)
                except OSError as exc:
                    log.write(change, "error", "file", host=True)
                    raise AuditError(f"audit source {source} ({reason}): {exc}") from None
                log.write(change, "allowed", host=True)
                issued.append(Issued(source, reason, print_))
                continue
            try:
                out_dir = issue_source_certificate(config_dir, source)
            except (AuditError, OSError) as exc:
                code = "openssl" if isinstance(exc, AuditError) else "file"
                change = realm_sync.Change("audit_source_certificate", source, "issued",
                                           f"issue_{reason}")  # fmt: skip
                log.write(change, "error", code, host=True)
                raise AuditError(f"audit source {source} ({reason}): {exc}") from None
            new_print = fingerprint(out_dir / "client.crt")
            change = realm_sync.Change("audit_source_certificate", f"{source}/{new_print}",
                                       "issued", f"issue_{reason}")  # fmt: skip
            log.write(change, "allowed", host=True)
            issued.append(Issued(source, reason, new_print))
    return SourceCertificates(issued, _reader_warnings(base, wanted))


def _reader_warnings(base: Path, sources: Sequence[str]) -> list[str]:
    """On Linux, run as neither root nor the services' user: a client folder the services
    cannot read. Docker Desktop's file sharing does not enforce the owner, so elsewhere
    nothing is said."""
    if _is_root() or not hasattr(os, "geteuid") or platform.system() != "Linux":
        return []
    warnings = []
    for source in sources:
        folder, reader = base / "clients" / source, SOURCE_READERS[source]
        if folder.is_dir() and _uid_of(folder) == os.geteuid() != reader:
            warnings.append(
                f"audit source {source}: the folder {folder} belongs to uid {os.geteuid()}, "
                f"its services run as uid {reader} and cannot read it; run 'papaia-ctl "
                "start' as root to hand it over"
            )
    return warnings


# ─────────────────────────────────────────────────────────────────────────
# verify and heads, run inside the papaia-audit container
# ─────────────────────────────────────────────────────────────────────────

_SOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def find_container(config_dir: Path) -> str:
    project = status.compose_project(config_dir)
    result = status.run_command(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={SERVICE}",
            "--filter",
            "status=running",
            "--format",
            "{{.Names}}",
        ],
        status.DOCKER_TIMEOUT_SECONDS,
    )
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not names:
        raise AuditError(
            "papaia-audit is not running. Start the stack with 'papaia-ctl start' and run "
            "the command again."
        )
    return names[0]


def service_command(
    command: str, *, source: str | None = None, against: Path | None = None, as_json: bool = False
) -> tuple[list[str], str]:
    """Arguments for `python -m papaia_audit` in the container, and its stdin."""
    if command not in ("verify", "heads", "retention", "siem-status"):
        raise AuditError(f"unknown audit command '{command}'")
    args = [command]
    stdin = ""
    if source is not None:
        if not _SOURCE_RE.match(source):
            raise AuditError(f"'{source}' is not a source name.")
        args += ["--source", source]
    if against is not None:
        try:
            stdin = against.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"cannot read {against}: {exc.strerror or exc}") from None
        args += ["--against", "-"]
    if as_json:
        args.append("--json")
    return args, stdin


def siem_skip_command(source: str, until: str, reason: str,
                      target: str | None = None) -> tuple[list[str], str]:
    """`siem-skip` and its request on stdin; the service checks everything again."""
    text = (reason or "").strip()
    if not SKIP_REASON_MIN <= len(text) <= SKIP_REASON_MAX or any(
        (ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in text
    ):
        raise AuditError(
            "audit siem skip needs --reason, 20 to 1000 characters: why these events may be "
            "missing in the SIEM."
        )
    if not _SOURCE_RE.fullmatch(source or ""):
        raise AuditError(f"'{source}' is not a source name.")
    if not until.isascii() or not until.isdigit() or len(until) > 18 or int(until) < 1:
        raise AuditError("audit siem skip needs --until=<seq>, a seq of 1 or more.")
    if target is not None and not target.strip():
        raise AuditError("audit siem skip --target needs a target as 'doctor siem' shows it.")
    request = {"source": source, "until": int(until), "reason": text, "target": target}
    return ["siem-skip"], json.dumps(request)


def idmap_command(ticket: str, token: str, *, pseud: str | None = None,
                  tid: str | None = None, oid: str | None = None) -> tuple[list[str], str]:
    """`idmap` and its token and request on stdin: the token never shows in a process
    list. Exactly one direction: a pseudonym, or the provider's tid and oid."""
    if not _TICKET_RE.fullmatch(ticket or ""):
        raise AuditError("audit idmap needs --ticket=<id> of a confirmed person filter.")
    if not _TOKEN_RE.fullmatch(token or ""):
        raise AuditError(
            "audit idmap needs the token of a person with the role papaia-auditor in "
            "PAPAIA_AUDIT_TOKEN."
        )
    request: dict[str, str] = {"ticket": ticket}
    if pseud is not None and tid is None and oid is None:
        if not _PSEUD_RE.fullmatch(pseud):
            raise AuditError(f"'{pseud}' is not a pseudonym (P- and 8 characters).")
        request["pseud"] = pseud
    elif pseud is None and tid is not None and oid is not None:
        if not (_UPSTREAM_RE.fullmatch(tid) and _UPSTREAM_RE.fullmatch(oid)):
            raise AuditError("--tid and --oid must be ids of the upstream provider.")
        request.update(tid=tid, oid=oid)
    else:
        raise AuditError("audit idmap takes either --pseud or both --tid and --oid.")
    return ["idmap"], json.dumps({"token": token, "request": request})


def run_in_service(config_dir: Path, args: Sequence[str], stdin: str) -> int:
    """Runs `python -I -m papaia_audit <args>` in the running container; output passes
    through. Returns its exit status."""
    container = find_container(config_dir)
    argv = ["docker", "exec", "-i", container, "python3", "-I", "-m", "papaia_audit", *args]
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, input=stdin, text=True, timeout=EXEC_TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditError(f"docker exec failed: {exc}") from None
    return result.returncode
