"""The platform PKI: one CA per installation for TLS between its services (ADR 0019).

Contract `papaia.platform-pki/1` (docs/pki.md). Modules ask for certificates in the `pki:`
block of their manifest (contract generation 11); a core module asks in a `pki.yaml` next
to its compose file. papaia-ctl issues them with the host's openssl into

    <config>/pki/ca/ca.key, ca.crt, retired.json      the CA; only papaia-ctl reads it
    <config>/pki/ca-bundle.crt, inventory.json
    <config>/pki/<module>/<service>/{ca.crt, tls.crt, tls.key, client.crt, client.key,
                                     generation, request.json}

and keeps the one trust bundle of the installation, `<config>/certs/trust/ca-bundle.pem`:
the platform CA plus the company roots the operator imported (`setup --ca-bundle`). A
service that needs it mounts it read-only; no core compose file does so yet.

Every run is idempotent: it issues what is missing, renews a leaf once two thirds of its
lifetime have passed or its request or CA changed, and removes what is no longer asked
for. Each of these writes is one `papaia.audit/1` row; a run with nothing to do writes
nothing.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import common, deployment, realm_sync, security_profile

FORMAT = "papaia.platform-pki/1"
LEAF_DAYS = 90
# A leaf is renewed when a third of its lifetime is left.
RENEW_LEFT_DAYS = 30
CA_DAYS = 3650
# A CA is replaced a year before it ends, so no leaf outlives its issuer.
CA_RENEW_LEFT_DAYS = 365
CORE_MODULE = "core"
CORE_REQUEST_FILE = "pki.yaml"
# The edge CA's own directory (lib/edge_pki.py, ADR 0035); the platform PKI leaves it alone.
EDGE_DIR = "edge"
# Names an add-on cannot use: they are directories of the layout or the core's.
RESERVED_MODULES = frozenset({"ca", EDGE_DIR, CORE_MODULE})
MAX_SERVICES = 64
MAX_DNS = 32
# Profiles a core request's client certificate may additionally depend on.
MAX_PROFILES = 8
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_UID = 2**31 - 1
# How long a run waits for another one (`certs renew` from a timer, `start`, `addon start`).
LOCK_WAIT_SECONDS = 120.0

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_LABEL_RE = re.compile(rf"^{_LABEL}$")
_DNS_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----"
)
_TIME = "%Y-%m-%dT%H:%M:%SZ"


class PkiError(Exception):
    """A request, a bundle or a step of the PKI that cannot be used. The message says why."""


@dataclass(frozen=True)
class ServiceRequest:
    module: str
    name: str
    # The numeric user of the service; None: the user that runs papaia-ctl.
    uid: int | None
    dns: tuple[str, ...] = ()
    client: bool = False

    @property
    def label(self) -> str:
        return f"{self.module}/{self.name}"


@dataclass
class Result:
    issued: list[str] = field(default_factory=list)
    renewed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    # Services whose bundle changed (a CA left or joined it), certificates unchanged.
    bundle_updated: list[str] = field(default_factory=list)
    ca: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> list[str]:
        return [*self.issued, *self.renewed, *self.removed]


def pki_dir(config_dir: Path) -> Path:
    return config_dir / "pki"


def trust_bundle_path(config_dir: Path) -> Path:
    """The one place of the trust anchors (BE-04). Not mounted by a core service yet."""
    return config_dir / "certs" / "trust" / "ca-bundle.pem"


def lock_path(config_dir: Path) -> Path:
    """The file every writing run holds an exclusive lock on."""
    return pki_dir(config_dir) / ".lock"


@contextlib.contextmanager
def _locked(config_dir: Path):
    """One writing run at a time per installation; PkiError after LOCK_WAIT_SECONDS."""
    path = lock_path(config_dir)
    common.ensure_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise PkiError(
                        f"another papaia-ctl run holds {path}; try again once it has ended"
                    ) from None
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _company_path(config_dir: Path) -> Path:
    return config_dir / "certs" / "trust" / "company.pem"


# ─────────────────────────────────────────────────────────────────────────
# requests
# ─────────────────────────────────────────────────────────────────────────


def _unknown(where: str, entry: dict, allowed: set[str]) -> None:
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise PkiError(f"{where} has unknown keys: {', '.join(map(str, unknown))}")


def _client_wanted(value: object, where: str, addon: bool, profiles: set[str] | None) -> bool:
    """`client` of one service: true or false; in a core request also
    `{with_profiles: [...]}`, a client certificate only while every named profile is on as
    well (None: the profiles are not known, as when only server names are read)."""
    if isinstance(value, bool):
        return value
    if addon or not isinstance(value, dict):
        raise PkiError(f"{where}.client must be true or false")
    _unknown(f"{where}.client", value, {"with_profiles"})
    names = value.get("with_profiles")
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= MAX_PROFILES
        or not all(isinstance(n, str) and _LABEL_RE.match(n) for n in names)
    ):
        raise PkiError(
            f"{where}.client.with_profiles must list 1 to {MAX_PROFILES} profile names"
        )
    return profiles is not None and set(names) <= profiles


def parse_request(
    block: object,
    module: str,
    source: str,
    *,
    addon: bool = False,
    profiles: set[str] | None = None,
) -> list[ServiceRequest]:
    """The service requests of one `pki:` block; `source` names the file in messages.
    `profiles` are the active profiles a core request's `client.with_profiles` is held to."""
    if not _LABEL_RE.match(module) or (addon and module in RESERVED_MODULES):
        raise PkiError(f"{source}: '{module}' cannot name a module directory of the PKI")
    if block is None:
        return []
    if not isinstance(block, dict):
        raise PkiError(f"{source}: `pki` must be a mapping with a `services` list")
    _unknown(f"{source}: pki", block, {"services"})
    services = block.get("services") or []
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise PkiError(f"{source}: `pki.services` must be a list of at most {MAX_SERVICES}")
    found: list[ServiceRequest] = []
    for index, entry in enumerate(services):
        where = f"{source}: pki.services[{index}]"
        if not isinstance(entry, dict):
            raise PkiError(f"{where} must be a mapping")
        _unknown(where, entry, {"name", "uid", "server", "client"})
        name = entry.get("name")
        if not isinstance(name, str) or not _LABEL_RE.match(name):
            raise PkiError(f"{where}.name must be a DNS label (a-z, 0-9, -), not {name!r}")
        if any(r.name == name for r in found):
            raise PkiError(f"{where}.name '{name}' is requested twice")
        uid = entry.get("uid")
        if uid is not None and (
            isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= MAX_UID
        ):
            raise PkiError(f"{where}.uid must be the numeric user of the service, not {uid!r}")
        client = _client_wanted(entry.get("client", False), where, addon, profiles)
        dns: list[str] = []
        server = entry.get("server")
        if server is not None:
            if not isinstance(server, dict):
                raise PkiError(f"{where}.server must be a mapping with a `dns` list")
            _unknown(f"{where}.server", server, {"dns"})
            names = server.get("dns")
            if not isinstance(names, list) or not names or len(names) > MAX_DNS:
                raise PkiError(
                    f"{where}.server.dns must list at least one, at most {MAX_DNS} names"
                )
            for value in names:
                if not isinstance(value, str) or not _DNS_RE.match(value):
                    raise PkiError(f"{where}.server.dns: {value!r} is not a DNS name")
                if value not in dns:
                    dns.append(value)
        if not dns and not client:
            raise PkiError(f"{where} needs a server, a client certificate or both")
        found.append(ServiceRequest(module, name, uid, tuple(dns), client))
    return found


def core_requests(repo_root: Path, profiles: set[str]) -> list[ServiceRequest]:
    """Requests of core modules: `src/**/pki.yaml` with the `pki:` block, an optional
    `profile` it belongs to (always on without one) and an optional `module` name. A
    service's client certificate may depend on further profiles (`client.with_profiles`)."""
    found: list[ServiceRequest] = []
    for path in sorted((repo_root / "src").rglob(CORE_REQUEST_FILE)):
        source = path.relative_to(repo_root).as_posix()
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PkiError(f"{source} is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise PkiError(f"{source} must be a mapping")
        _unknown(source, doc, {"profile", "module", "pki"})
        profile = doc.get("profile")
        if profile is not None and profile not in profiles:
            continue
        found += parse_request(
            doc.get("pki"), str(doc.get("module") or CORE_MODULE), source, profiles=profiles
        )
    return found


def addon_refusal(name: str, manifest: dict, root_env: dict) -> str | None:
    """Why an add-on cannot be installed or started under this installation's security
    profile, or None. A malformed `pki:` block is refused under every profile."""
    try:
        profile = security_profile.load(root_env)
        parse_request(manifest.get("pki"), name, f"{name}/papaia-app.yaml", addon=True)
    except (security_profile.ProfileError, PkiError) as exc:
        return str(exc)
    if profile.addon_pki_required and not manifest.get("pki"):
        return (
            f"add-on '{name}' declares no `pki:` request; the kritis security profile "
            "requires every add-on to request certificates of the platform PKI (docs/pki.md)"
        )
    return None


def collect(config_dir: Path, repo_root: Path) -> list[ServiceRequest]:
    """Everything requested by the core modules that are on and by the active add-ons."""
    root = common.parse_env_file(config_dir / ".env")
    requests = core_requests(repo_root, common.cluster_profiles(root))
    for entry in deployment.active_addons(deployment.load(config_dir)):
        name = str(entry.get("name") or "")
        path = deployment.resolve_addon_path(entry, repo_root)
        manifest, reason = deployment.load_addon_manifest(path)
        if manifest is None:
            raise PkiError(f"add-on '{name}': {reason}")
        refusal = addon_refusal(name, manifest, root)
        if refusal:
            raise PkiError(refusal)
        requests += parse_request(manifest.get("pki"), name, f"{name}/papaia-app.yaml", addon=True)
    return requests


# ─────────────────────────────────────────────────────────────────────────
# openssl
# ─────────────────────────────────────────────────────────────────────────


def _openssl(args: list[str], stdin: str | None = None) -> str:
    try:
        done = subprocess.run(
            ["openssl", *args], input=stdin, capture_output=True, text=True, timeout=60,
            check=False,
        )  # fmt: skip
    except FileNotFoundError as exc:
        raise PkiError("openssl not found; it is needed for the platform PKI") from exc
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()
        raise PkiError(f"openssl {args[0]} failed: {detail[-1] if detail else done.returncode}")
    return done.stdout


def _new_key(path: Path) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    _openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-out", str(tmp)])  # fmt: skip
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _not_after(pem: str) -> datetime:
    line = _openssl(["x509", "-noout", "-enddate"], stdin=pem).strip()
    value = " ".join(line.partition("=")[2].split())
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _fingerprint(pem: str) -> str:
    out = _openssl(["x509", "-noout", "-fingerprint", "-sha256"], stdin=pem)
    return out.strip().partition("=")[2].replace(":", "").lower()


def _subject(pem: str) -> str:
    return _openssl(["x509", "-noout", "-subject"], stdin=pem).strip().partition("=")[2].strip()


def _serial() -> str:
    # Random and positive: 159 bits, as RFC 5280 asks for at most 20 octets.
    return "0x" + format(secrets.randbits(159) | 1 << 158, "x")


def _sign(ca: Path, csr: Path, ext: str, out: Path, days: int) -> None:
    extfile = out.with_name(out.name + ".ext")
    extfile.write_text(ext, encoding="utf-8")
    try:
        _openssl(["x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.crt"),
                  "-CAkey", str(ca / "ca.key"), "-set_serial", _serial(), "-days", str(days),
                  "-sha256", "-extfile", str(extfile), "-out", str(out)])  # fmt: skip
    finally:
        extfile.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────
# the CA
# ─────────────────────────────────────────────────────────────────────────


def _create_ca(ca: Path) -> None:
    """A new CA key and certificate. Both are made as temporaries next to the live files
    and moved into place only once both exist, the key first; a failure leaves the old
    pair as it was."""
    common.ensure_dir(ca)
    os.chmod(ca, 0o700)
    key, cert = ca / "ca.key.new", ca / "ca.crt.new"
    try:
        _new_key(key)
        _openssl(["req", "-new", "-x509", "-key", str(key), "-out", str(cert),
                  "-days", str(CA_DAYS), "-sha256", "-subj", "/CN=papaia-platform-ca/O=papAIa",
                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign"])  # fmt: skip
        os.replace(key, ca / "ca.key")
        os.replace(cert, ca / "ca.crt")
    finally:
        for leftover in (key, cert, key.with_name(key.name + ".tmp")):
            leftover.unlink(missing_ok=True)


def _ca_pair_matches(ca: Path) -> bool:
    """Whether ca.key is the key of ca.crt (a rotation cut off between the two moves, or a
    file replaced by hand, leaves a pair that cannot sign)."""
    try:
        key = _openssl(["pkey", "-pubout", "-in", str(ca / "ca.key")])
        cert = _openssl(["x509", "-noout", "-pubkey", "-in", str(ca / "ca.crt")])
    except PkiError:
        return False
    return key.strip() == cert.strip()


def _retire(ca: Path, pem: str, now: datetime) -> None:
    """Keeps `pem` in the bundles until the last leaf it signed has ended."""
    drop = (now + timedelta(days=LEAF_DAYS)).strftime(_TIME)
    retired = [*_retired(ca), {"pem": pem, "drop_after": drop}]
    common.atomic_write(ca / "retired.json", json.dumps(retired, indent=2) + "\n")


def _retired(ca: Path) -> list[dict]:
    path = ca / "retired.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [e for e in data if isinstance(e, dict) and "pem" in e and "drop_after" in e]


def _bundle_pems(ca: Path, now: datetime) -> list[tuple[str, str]]:
    """(pem, role) of the CAs the services trust: the active one, then the retired ones
    whose last leaf may still be in use."""
    pems = [((ca / "ca.crt").read_text(encoding="utf-8"), "active")]
    for entry in _retired(ca):
        if datetime.strptime(entry["drop_after"], _TIME).replace(tzinfo=timezone.utc) > now:
            pems.append((entry["pem"], "retired"))
    return pems


# ─────────────────────────────────────────────────────────────────────────
# issuing
# ─────────────────────────────────────────────────────────────────────────


class _Audit:
    """Opens the audit outbox at the first write, so a run without a change leaves no
    trace; the outbox is checked (AuditLog's pre-flight) before that write is made."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.log: realm_sync.AuditLog | None = None

    def before(self) -> None:
        if self.log is None:
            self.log = realm_sync.AuditLog(
                realm_sync.audit_path(self.config_dir),
                realm_sync.new_correlation_id(),
                writer="papaia-ctl/pki",
            )

    def row(self, kind: str, name: str, action: str, operation: str) -> None:
        self.before()
        assert self.log is not None
        change = realm_sync.Change(kind, name, action, operation)
        self.log.write(change, "success", host=True)

    def close(self) -> None:
        if self.log is not None:
            self.log.close()


def _leaf_due(directory: Path, request: ServiceRequest, now: datetime) -> bool:
    for kind, wanted in (("tls", bool(request.dns)), ("client", request.client)):
        cert = directory / f"{kind}.crt"
        if not wanted:
            continue
        if not cert.is_file() or not (directory / f"{kind}.key").is_file():
            return True
        try:
            left = _not_after(cert.read_text(encoding="utf-8")) - now
        except (PkiError, ValueError):
            return True
        if left < timedelta(days=RENEW_LEFT_DAYS):
            return True
    return False


def _stamp(request: ServiceRequest, issuer: str) -> dict:
    return {
        "format": FORMAT,
        "module": request.module,
        "name": request.name,
        "uid": request.uid,
        "dns": list(request.dns),
        "client": request.client,
        "issuer": issuer,
    }


def _owner(path: Path, uid: int | None) -> None:
    if uid is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(path, uid, -1)


def _issue_leaf(ca: Path, directory: Path, request: ServiceRequest, kind: str) -> None:
    """One key and certificate (`tls` for the server, `client`) into `directory`."""
    key, cert = directory / f"{kind}.key", directory / f"{kind}.crt"
    new_key, csr, new_cert = (directory / f".{kind}.{s}" for s in ("key", "csr", "crt"))
    common_ext = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
    if kind == "tls":
        san = ",".join(f"DNS:{name}" for name in request.dns)
        ext = f"{common_ext}extendedKeyUsage=serverAuth\nsubjectAltName={san}\n"
    else:
        ext = f"{common_ext}extendedKeyUsage=clientAuth\n"
    try:
        _new_key(new_key)
        _openssl(["req", "-new", "-key", str(new_key), "-out", str(csr),
                  "-subj", f"/CN={request.name}/O=papAIa"])  # fmt: skip
        _sign(ca, csr, ext, new_cert, LEAF_DAYS)
        for path in (new_key, new_cert):
            _owner(path, request.uid)
        os.chmod(new_cert, 0o644)
        # The key first: a reader never pairs a new certificate with the old key.
        os.replace(new_key, key)
        os.replace(new_cert, cert)
    finally:
        for path in (new_key, csr, new_cert):
            path.unlink(missing_ok=True)


def _write_service(ca: Path, root: Path, request: ServiceRequest, bundle: str, issuer: str,
                   *, certificates: bool) -> None:  # fmt: skip
    directory = root / request.module / request.name
    common.ensure_dir(directory)
    os.chmod(directory, 0o700)
    _owner(directory, request.uid)
    if certificates:
        for kind, wanted in (("tls", bool(request.dns)), ("client", request.client)):
            if wanted:
                _issue_leaf(ca, directory, request, kind)
            else:
                (directory / f"{kind}.key").unlink(missing_ok=True)
                (directory / f"{kind}.crt").unlink(missing_ok=True)
    common.atomic_write(directory / "ca.crt", bundle)
    common.atomic_write(
        directory / "request.json", json.dumps(_stamp(request, issuer), indent=2) + "\n"
    )
    generation = directory / "generation"
    current = generation.read_text(encoding="ascii").strip() if generation.is_file() else "0"
    # Last: a reader that sees a new generation sees the complete set.
    common.atomic_write(generation, f"{int(current) + 1 if current.isdigit() else 1}\n")
    for name in ("ca.crt", "request.json", "generation"):
        _owner(directory / name, request.uid)


def issue(
    config_dir: Path,
    requests: list[ServiceRequest],
    *,
    now: datetime | None = None,
    force: bool = False,
    rotate_ca: bool = False,
) -> Result:
    """Brings the files of the PKI in line with `requests`. `force` renews every leaf,
    `rotate_ca` replaces the CA (the old one stays trusted until its last leaf ended)."""
    with _locked(config_dir):
        return _issue(config_dir, requests, now or datetime.now(timezone.utc), force, rotate_ca)


def _issue(
    config_dir: Path, requests: list[ServiceRequest], now: datetime, force: bool, rotate_ca: bool
) -> Result:
    root, result, audit = pki_dir(config_dir), Result(), _Audit(config_dir)
    ca = root / "ca"
    try:
        common.ensure_dir(root)
        if not (ca / "ca.key").is_file() or not (ca / "ca.crt").is_file():
            audit.before()
            _create_ca(ca)
            audit.row("ca", "papaia-platform-ca", "created", "ca_create")
            result.ca = "created"
        elif not _ca_pair_matches(ca):
            current = (ca / "ca.crt").read_text(encoding="utf-8")
            audit.before()
            _create_ca(ca)
            _retire(ca, current, now)
            audit.row("ca", "papaia-platform-ca", "recreated", "ca_repair")
            result.ca = "recreated"
            result.warnings.append(
                "the CA key did not match the CA certificate; a new CA was created and "
                "every certificate issued again"
            )
        else:
            current = (ca / "ca.crt").read_text(encoding="utf-8")
            if rotate_ca or _not_after(current) - now < timedelta(days=CA_RENEW_LEFT_DAYS):
                audit.before()
                _create_ca(ca)
                _retire(ca, current, now)
                audit.row("ca", "papaia-platform-ca", "replaced", "ca_rotate")
                result.ca = "rotated"
        pems = _bundle_pems(ca, now)
        bundle = "".join(pem if pem.endswith("\n") else pem + "\n" for pem, _ in pems)
        issuer = hashlib.sha256(pems[0][0].encode("utf-8")).hexdigest()
        if not (root / "ca-bundle.crt").is_file() or (root / "ca-bundle.crt").read_text(
            encoding="utf-8"
        ) != bundle:
            common.atomic_write(root / "ca-bundle.crt", bundle)

        wanted = {(r.module, r.name) for r in requests}
        for request in requests:
            directory = root / request.module / request.name
            stamp_path = directory / "request.json"
            stamp = (
                json.loads(stamp_path.read_text(encoding="utf-8")) if stamp_path.is_file() else None
            )
            if stamp is None:
                action = "issued"
            elif force or stamp != _stamp(request, issuer) or _leaf_due(directory, request, now):
                action = "renewed"
            elif (directory / "ca.crt").read_text(encoding="utf-8") != bundle:
                _write_service(ca, root, request, bundle, issuer, certificates=False)
                result.bundle_updated.append(request.label)
                continue
            else:
                continue
            audit.before()
            _write_service(ca, root, request, bundle, issuer, certificates=True)
            operation = "issue" if action == "issued" else "renew"
            audit.row("certificate", request.label, action, operation)
            (result.issued if action == "issued" else result.renewed).append(request.label)
            if (
                request.uid is not None
                and platform.system() == "Linux"
                and hasattr(os, "geteuid")
                and os.geteuid() not in (0, request.uid)
            ):
                result.warnings.append(
                    f"{request.label}: the files belong to uid {os.geteuid()}, the service "
                    f"runs as uid {request.uid}; run 'papaia-ctl certs renew' as root"
                )

        for module_dir in sorted(
            p for p in root.iterdir() if p.is_dir() and p.name not in ("ca", EDGE_DIR)
        ):
            for directory in sorted(p for p in module_dir.iterdir() if p.is_dir()):
                if (module_dir.name, directory.name) in wanted:
                    continue
                if not (directory / "request.json").is_file():
                    continue  # not written by the PKI: left alone
                audit.before()
                shutil.rmtree(directory)
                label = f"{module_dir.name}/{directory.name}"
                audit.row("certificate", label, "removed", "remove")
                result.removed.append(label)
            if not any(module_dir.iterdir()):
                module_dir.rmdir()

        _write_inventory(root, requests, pems)
        _write_trust_bundle(config_dir, bundle)
    finally:
        audit.close()
    return result


def _iso(value: datetime) -> str:
    return value.strftime(_TIME)


def _write_inventory(root: Path, requests: list[ServiceRequest], pems: list) -> None:
    services = []
    for request in sorted(requests, key=lambda r: r.label):
        directory = root / request.module / request.name
        entry: dict = {
            "module": request.module,
            "name": request.name,
            "dns": list(request.dns),
            "client": request.client,
            "generation": int((directory / "generation").read_text(encoding="ascii")),
        }
        for kind, key in (("tls", "server_not_after"), ("client", "client_not_after")):
            cert = directory / f"{kind}.crt"
            if cert.is_file():
                entry[key] = _iso(_not_after(cert.read_text(encoding="utf-8")))
        services.append(entry)
    inventory = {
        "format": FORMAT,
        "ca": [
            {
                "subject": _subject(pem),
                "sha256": _fingerprint(pem),
                "not_after": _iso(_not_after(pem)),
                "role": role,
            }
            for pem, role in pems
        ],
        "services": services,
    }
    text = json.dumps(inventory, indent=2) + "\n"
    path = root / "inventory.json"
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        common.atomic_write(path, text)


def read_inventory(config_dir: Path) -> dict | None:
    path = pki_dir(config_dir) / "inventory.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def status(config_dir: Path, now: datetime | None = None) -> dict:
    """Every certificate of the inventory with its end and days left."""
    now = now or datetime.now(timezone.utc)
    inventory = read_inventory(config_dir) or {"ca": [], "services": []}
    rows = [(f"ca {ca['subject']} ({ca['role']})", ca["not_after"]) for ca in inventory["ca"]]
    for service in inventory["services"]:
        label = f"{service['module']}/{service['name']}"
        for key, file in (("server_not_after", "tls.crt"), ("client_not_after", "client.crt")):
            if key in service:
                rows.append((f"{label}/{file}", service[key]))
    certificates = []
    for label, end in rows:
        days = (datetime.strptime(end, _TIME).replace(tzinfo=timezone.utc) - now).days
        certificates.append({"certificate": label, "not_after": end, "days_left": days})
    return {"format": FORMAT, "certificates": certificates}


def doctor_files(config_dir: Path) -> list[Path]:
    """The certificates `doctor certs` checks besides the Keycloak ones: the platform CA,
    every service certificate and the trust bundle."""
    root = pki_dir(config_dir)
    files = sorted((root / "ca").glob("ca.crt"))
    files += sorted(root.glob("*/*/tls.crt")) + sorted(root.glob("*/*/client.crt"))
    trust = trust_bundle_path(config_dir)
    return files + ([trust] if trust.is_file() else [])


# ─────────────────────────────────────────────────────────────────────────
# company CA bundle
# ─────────────────────────────────────────────────────────────────────────


def check_bundle(path: Path) -> list[str]:
    """The certificates of a company CA bundle as PEM blocks, each checked: readable, a CA
    certificate, not expired. PkiError with the reason otherwise."""
    try:
        if path.stat().st_size > MAX_BUNDLE_BYTES:
            raise PkiError(f"{path}: larger than {MAX_BUNDLE_BYTES // 1024} KiB")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = getattr(exc, "strerror", None) or "not a text file"
        raise PkiError(f"{path}: cannot be read ({reason})") from None
    if "PRIVATE KEY" in text:
        raise PkiError(f"{path}: contains a private key; only certificates belong in it")
    blocks = [
        "\n".join(line.strip() for line in m.group(0).splitlines() if line.strip())
        for m in _PEM_RE.finditer(text)
    ]
    if not blocks:
        raise PkiError(f"{path}: no certificate in PEM form (-----BEGIN CERTIFICATE-----)")
    for number, pem in enumerate(blocks, 1):
        try:
            _openssl(["x509", "-noout"], stdin=pem + "\n")
        except PkiError:
            raise PkiError(f"{path}: certificate {number} is not readable") from None
        name = _subject(pem + "\n")
        if not _is_ca(pem + "\n"):
            raise PkiError(f"{path}: certificate {number} ({name}) is not a CA certificate")
        if _not_after(pem + "\n") <= datetime.now(timezone.utc):
            raise PkiError(f"{path}: certificate {number} ({name}) has expired")
    return [pem + "\n" for pem in blocks]


def _is_ca(pem: str) -> bool:
    """Whether the Basic Constraints extension itself says CA:TRUE; a subject or another
    extension that contains the text does not count."""
    try:
        out = _openssl(["x509", "-noout", "-ext", "basicConstraints"], stdin=pem)
    except PkiError as exc:  # the certificate was readable: this openssl lacks `-ext`
        raise PkiError(
            f"{exc}; checking a CA bundle needs OpenSSL 1.1.1 or later (`x509 -ext`)"
        ) from None
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("X509v3 Basic Constraints"):
        return False
    return any(part.strip() == "CA:TRUE" for line in lines[1:] for part in line.split(","))


def _write_trust_bundle(config_dir: Path, platform_bundle: str) -> None:
    company = _company_path(config_dir)
    text = platform_bundle + (company.read_text(encoding="utf-8") if company.is_file() else "")
    path = trust_bundle_path(config_dir)
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        common.atomic_write(path, text)
        os.chmod(path, 0o644)


def import_bundle(config_dir: Path, path: Path) -> int:
    """Checks the company bundle at `path`, keeps it and rebuilds the trust bundle.
    Returns the number of certificates."""
    pems = check_bundle(path)
    with _locked(config_dir):
        return _import_bundle(config_dir, pems)


def _import_bundle(config_dir: Path, pems: list[str]) -> int:
    audit = _Audit(config_dir)
    try:
        audit.before()
        common.atomic_write(_company_path(config_dir), "".join(pems))
        platform_bundle = pki_dir(config_dir) / "ca-bundle.crt"
        _write_trust_bundle(
            config_dir,
            platform_bundle.read_text(encoding="utf-8") if platform_bundle.is_file() else "",
        )
        audit.row("trust_bundle", f"{len(pems)} certificate(s)", "imported", "trust_import")
    finally:
        audit.close()
    return len(pems)
