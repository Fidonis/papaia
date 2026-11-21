"""papaia-audit: the keys, certificates and passwords of the audit store (docs/audit.md).

Everything lives under `$PAPAIA_CONFIG_DIR/infra/audit/`:

    pki/ca.key, pki/ca.crt        the ingest CA; the key never leaves papaia-ctl
    service/server.crt, .key      the certificate papaia-audit serves on :8443
    service/ca.crt                the CA it checks client certificates against
    service/sources.json          source -> fingerprints of its client certificates
    secrets/                      database passwords and the key that signs chain heads
    clients/<source>/             client.crt, client.key and ca.crt of one source

`prepare` creates what is missing and never replaces what exists, so it runs before
every start. `issue_source_certificate` gives a source (one of SOURCES) a new client
certificate and lists only that one for the source: the previous one stops working.

Keys and certificates are made with the `openssl` command, like the local CA of Keycloak.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import common, status

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
}
HEADS_KEY = "heads-signing-key"


class AuditError(Exception):
    """The audit material could not be prepared or used; the message says why."""


def audit_dir(config_dir: Path) -> Path:
    return config_dir / "infra" / "audit"


def _openssl(*args: str) -> None:
    if shutil.which("openssl") is None:
        raise AuditError("openssl not found; it is needed for the audit certificates.")
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["openssl", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        lines = [line for line in result.stderr.splitlines() if line.strip()]
        raise AuditError(f"openssl {args[0]} failed: {lines[-1] if lines else 'no message'}")


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


def issue_source_certificate(config_dir: Path, source: str) -> Path:
    """A new client certificate for `source`; it replaces the source's previous one."""
    if source not in SOURCES:
        raise AuditError(f"'{source}' is not an audit source. Known: {', '.join(SOURCES)}.")
    prepare(config_dir)
    base = audit_dir(config_dir)
    out_dir = _private_dir(base / "clients" / source)
    certificate, _ = _issue(base / "pki", out_dir, source, "clientAuth")
    shutil.copyfile(base / "pki" / "ca.crt", out_dir / "ca.crt")
    os.chmod(out_dir / "ca.crt", 0o644)
    sources = load_sources(config_dir)
    sources[source] = [fingerprint(certificate)]
    _write_sources(config_dir, sources)
    return out_dir


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
    if command not in ("verify", "heads"):
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
