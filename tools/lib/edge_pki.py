"""The edge CA: certificates for the host names the bundled proxy serves (ADR 0035).

With `tls: internal` (row 3 of the question round, or a setup without the round) and the
bundled Nginx Proxy Manager, papaia-ctl issues one leaf per proxy host it creates, from a
CA of the installation's own. Contract `papaia.edge-pki/1`:

    <config>/certs/edge-ca.crt                   the CA's certificate, for distribution
    <config>/pki/edge/ca.key, ca.json            its key and domains; papaia-ctl only
    <config>/pki/edge/leaves/<first name>/{tls.crt, tls.key, request.json}

`certs/` is mounted read-only into many services, so it holds only the public
certificate. The key and the leaves live in `pki/edge/` (0700), which no compose file
mounts, as the platform CA's key lives in `pki/ca/`; a leaf key reaches only the proxy,
through its API (lib/npm_provision.py).

The CA is separate from the platform CA (ADR 0019, internal mTLS) and from the Keycloak
CA. Operators distribute its root certificate to browsers and hosts, so it is limited by
critical name constraints to the installation's base domain and app domain: it cannot
sign a certificate any client would accept for another name. Its leaves carry only
`serverAuth` and exactly the names of their one proxy host.

Every run is idempotent: it issues what is missing, renews a leaf with 30 days or less
left or whose names or CA changed, and removes the leaf of a host no longer served. Each
of these writes is one `papaia.audit/1` row; a run with nothing to do writes nothing.
`npm-provision` uploads the leaves to the proxy (lib/npm_provision.py).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import common, ingress, realm_sync

FORMAT = "papaia.edge-pki/1"
WRITER = "papaia-ctl/edge-pki"
CA_NAME = "papaia-edge-ca"
LEAF_DAYS = 90
# A leaf is renewed when it has this many days or fewer left.
RENEW_LEFT_DAYS = 30
CA_DAYS = 3650
# A CA is replaced a year before it ends, so no leaf outlives its issuer.
CA_RENEW_LEFT_DAYS = 365
LOCK_WAIT_SECONDS = 120.0
MAX_HOSTS = 256
MAX_NAMES = 8
INTERNAL_TLS = "internal"

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_DNS_RE = re.compile(rf"^(?=.{{1,253}}$)(\*\.)?{_LABEL}(\.{_LABEL})+$")
# X.509 (RFC 5280, ub-common-name) allows 64 characters in a commonName.
_CN_MAX = 64
_TIME = "%Y-%m-%dT%H:%M:%SZ"


class EdgePkiError(Exception):
    """A name, a file or a step of the edge CA that cannot be used. The message says why."""


@dataclass(frozen=True)
class Host:
    """One proxy host: the names it serves, the first one names it."""

    names: tuple[str, ...]

    @property
    def label(self) -> str:
        return self.names[0] if self.names else ""


@dataclass(frozen=True)
class Leaf:
    names: tuple[str, ...]
    cert: Path
    key: Path

    @property
    def label(self) -> str:
        return self.names[0]

    def fingerprint(self) -> str:
        return hashlib.sha256(self.cert.read_bytes()).hexdigest()


@dataclass
class Result:
    issued: list[str] = field(default_factory=list)
    renewed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    # Names of a proxy host outside the CA's domains: no leaf, the host keeps what it has.
    refused: list[str] = field(default_factory=list)
    ca: str | None = None

    @property
    def changed(self) -> bool:
        return bool(self.ca or self.issued or self.renewed or self.removed)


def private_dir(config_dir: Path) -> Path:
    """The edge CA's own directory: key, domains, lock and leaves; read by papaia-ctl only."""
    return config_dir / "pki" / "edge"


def ca_paths(config_dir: Path) -> tuple[Path, Path]:
    return config_dir / "certs" / "edge-ca.crt", private_dir(config_dir) / "ca.key"


def leaves_dir(config_dir: Path) -> Path:
    return private_dir(config_dir) / "leaves"


def _domains_path(config_dir: Path) -> Path:
    return private_dir(config_dir) / "ca.json"


def lock_path(config_dir: Path) -> Path:
    return private_dir(config_dir) / ".lock"


def _private(path: Path) -> None:
    """`path` as a directory only its owner can enter."""
    common.ensure_dir(path)
    os.chmod(path, 0o700)


# ─────────────────────────────────────────────────────────────────────────
# when, and for which domains
# ─────────────────────────────────────────────────────────────────────────


def _recorded_tls(config_dir: Path) -> str:
    """Row 3 of the recorded question round; `internal` without a record (a setup with
    switches has no bundle)."""
    from . import setup_answers

    path = config_dir / setup_answers.RECORD_FILE
    if not path.is_file():
        return INTERNAL_TLS
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        raise EdgePkiError(f"{path} cannot be read: {exc}") from None
    answers = doc.get("answers") if isinstance(doc, dict) else None
    tls = answers.get("tls") if isinstance(answers, dict) else None
    return tls.strip() if isinstance(tls, str) and tls.strip() else INTERNAL_TLS


def enabled(config_dir: Path, root: dict[str, str]) -> bool:
    """Whether the edge CA serves this installation: the bundled proxy, `tls: internal`
    and a domain for the host names."""
    if root.get("REVERSE_PROXY_PROVIDER") != "internal_nginx":
        return False
    if _recorded_tls(config_dir).lower() != INTERNAL_TLS:
        return False
    try:
        return ingress.host_scheme(root).domain is not None
    except ingress.IngressError:
        return False


def domains(root: dict[str, str]) -> tuple[str, ...]:
    """The base domain and the app domain of the installation, the subtrees the CA is
    constrained to; an app domain inside the base domain is not named twice. Locally the
    two registrable domains below `localhost` that setup derived."""
    scheme = ingress.host_scheme(root)
    if scheme.domain is None:
        return ()
    found = [scheme.domain]
    app = scheme.app_domain
    if app and app != scheme.domain and not app.endswith(f".{scheme.domain}"):
        found.append(app)
    return tuple(found)


def check_name(name: str, allowed: tuple[str, ...]) -> str:
    """`name` lower-cased when it is a DNS name (a leading `*.` allowed) in one of the
    `allowed` domains or below it; EdgePkiError otherwise."""
    value = name.strip().lower() if isinstance(name, str) else ""
    if not _DNS_RE.match(value):
        raise EdgePkiError(f"{name!r} is not a DNS name the edge CA can sign")
    bare = value[2:] if value.startswith("*.") else value
    for domain in allowed:
        if bare == domain or bare.endswith(f".{domain}"):
            return value
    raise EdgePkiError(
        f"{name} is outside the domains of the edge CA ({', '.join(allowed) or 'none'})"
    )


# ─────────────────────────────────────────────────────────────────────────
# openssl
# ─────────────────────────────────────────────────────────────────────────


def _openssl(args: list[str], stdin: str | None = None) -> str:
    from . import pki

    try:
        return pki._openssl(args, stdin)
    except pki.PkiError as exc:
        raise EdgePkiError(str(exc).replace("platform PKI", "edge CA")) from None


def _new_key(path: Path) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    _openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-out", str(tmp)])  # fmt: skip
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _not_after(pem: str) -> datetime:
    line = _openssl(["x509", "-noout", "-enddate"], stdin=pem).strip()
    value = " ".join(line.partition("=")[2].split())
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _serial() -> str:
    return "0x" + format(secrets.randbits(159) | 1 << 158, "x")


# ─────────────────────────────────────────────────────────────────────────
# the CA
# ─────────────────────────────────────────────────────────────────────────


def _constraints(allowed: tuple[str, ...]) -> str:
    permitted = ",".join(f"permitted;DNS:{d}" for d in allowed)
    # DNS subtrees do not limit addresses; no address is ever a name of the edge.
    return (
        f"nameConstraints=critical,{permitted},"
        "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"
    )


def _ca_subject(allowed: tuple[str, ...]) -> str:
    """`papaia-edge-ca <base domain>`; a base domain too long for a commonName is named by
    a hash of the domains instead, so the subject stays unique per installation."""
    name = f"{CA_NAME} {allowed[0]}"
    if len(name) > _CN_MAX:
        name = f"{CA_NAME} {hashlib.sha256(','.join(allowed).encode()).hexdigest()[:16]}"
    return f"/CN={name}/O=papAIa"


def _leaf_subject(names: tuple[str, ...]) -> str:
    """The first name as commonName when it fits; the subjectAltName carries every name,
    and clients match only that, so a longer first name leaves the commonName out."""
    return f"/CN={names[0]}/O=papAIa" if len(names[0]) <= _CN_MAX else "/O=papAIa"


def _create_ca(config_dir: Path, allowed: tuple[str, ...]) -> None:
    """A new CA key and certificate, made as temporaries and moved into place key first;
    a failure leaves the old pair as it was."""
    crt, key = ca_paths(config_dir)
    common.ensure_dir(crt.parent)
    _private(key.parent)
    new_key, new_crt = key.with_name(key.name + ".new"), crt.with_name(crt.name + ".new")
    try:
        _new_key(new_key)
        _openssl(["req", "-new", "-x509", "-key", str(new_key), "-out", str(new_crt),
                  "-days", str(CA_DAYS), "-sha256",
                  "-subj", _ca_subject(allowed),
                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                  "-addext", _constraints(allowed)])  # fmt: skip
        os.chmod(new_crt, 0o644)
        os.replace(new_key, key)
        os.replace(new_crt, crt)
    finally:
        for leftover in (new_key, new_crt, new_key.with_name(new_key.name + ".tmp")):
            leftover.unlink(missing_ok=True)
    common.atomic_write(
        _domains_path(config_dir),
        json.dumps({"format": FORMAT, "domains": list(allowed)}, indent=2) + "\n",
    )


def ca_domains(config_dir: Path) -> tuple[str, ...] | None:
    try:
        data = json.loads(_domains_path(config_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    found = data.get("domains") if isinstance(data, dict) else None
    if not isinstance(found, list) or not all(isinstance(d, str) for d in found):
        return None
    return tuple(found)


def _ca_pair_matches(config_dir: Path) -> bool:
    crt, key = ca_paths(config_dir)
    try:
        public = _openssl(["pkey", "-pubout", "-in", str(key)])
        cert = _openssl(["x509", "-noout", "-pubkey", "-in", str(crt)])
    except EdgePkiError:
        return False
    return public.strip() == cert.strip()


def _ca_state(config_dir: Path, allowed: tuple[str, ...], now: datetime) -> str | None:
    """What has to happen to the CA: `created`, `replaced` (other domains, a key that does
    not match, or its end near) or None."""
    crt, key = ca_paths(config_dir)
    if not crt.is_file() or not key.is_file():
        return "created"
    if ca_domains(config_dir) != allowed or not _ca_pair_matches(config_dir):
        return "replaced"
    try:
        left = _not_after(crt.read_text(encoding="utf-8")) - now
    except (EdgePkiError, ValueError):
        return "replaced"
    return "replaced" if left < timedelta(days=CA_RENEW_LEFT_DAYS) else None


# ─────────────────────────────────────────────────────────────────────────
# leaves
# ─────────────────────────────────────────────────────────────────────────


def _directory(config_dir: Path, label: str) -> Path:
    # A wildcard as first name never names a directory: `*` is not a file-name character
    # papaia-ctl writes.
    return leaves_dir(config_dir) / label.replace("*", "_wildcard")


def _stamp(names: tuple[str, ...], issuer: str) -> dict:
    return {"format": FORMAT, "names": list(names), "issuer": issuer}


def _read_stamp(directory: Path) -> dict | None:
    try:
        data = json.loads((directory / "request.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("format") == FORMAT else None


def _due(directory: Path, now: datetime) -> bool:
    cert, key = directory / "tls.crt", directory / "tls.key"
    if not cert.is_file() or not key.is_file():
        return True
    try:
        left = _not_after(cert.read_text(encoding="utf-8")) - now
    except (EdgePkiError, ValueError):
        return True
    return left <= timedelta(days=RENEW_LEFT_DAYS)


def _issue_leaf(config_dir: Path, directory: Path, names: tuple[str, ...], issuer: str) -> None:
    """Key, certificate and stamp of one proxy host into `directory`; the key first, so a
    reader never pairs a new certificate with the old key."""
    crt, ca_key = ca_paths(config_dir)
    _private(directory.parent)
    _private(directory)
    new_key, csr, new_crt = (directory / f".tls.{s}" for s in ("key", "csr", "crt"))
    ext = directory / ".tls.ext"
    san = ",".join(f"DNS:{name}" for name in names)
    try:
        _new_key(new_key)
        _openssl(["req", "-new", "-key", str(new_key), "-out", str(csr),
                  "-subj", _leaf_subject(names)])  # fmt: skip
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={san}\n",
            encoding="utf-8",
        )
        _openssl(["x509", "-req", "-in", str(csr), "-CA", str(crt), "-CAkey", str(ca_key),
                  "-set_serial", _serial(), "-days", str(LEAF_DAYS), "-sha256",
                  "-extfile", str(ext), "-out", str(new_crt)])  # fmt: skip
        os.chmod(new_crt, 0o644)
        os.replace(new_key, directory / "tls.key")
        os.replace(new_crt, directory / "tls.crt")
    finally:
        for path in (new_key, csr, new_crt, ext, new_key.with_name(new_key.name + ".tmp")):
            path.unlink(missing_ok=True)
    common.atomic_write(
        directory / "request.json", json.dumps(_stamp(names, issuer), indent=2) + "\n"
    )


def leaves(config_dir: Path) -> list[Leaf]:
    """The leaves on disk, by their first name."""
    root = leaves_dir(config_dir)
    found = []
    if not root.is_dir():
        return found
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        stamp = _read_stamp(directory)
        names = stamp.get("names") if stamp else None
        if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
            continue
        if (directory / "tls.crt").is_file() and (directory / "tls.key").is_file():
            found.append(Leaf(tuple(names), directory / "tls.crt", directory / "tls.key"))
    return found


def leaf_for(config_dir: Path, names: tuple[str, ...] | list[str]) -> Leaf | None:
    """The leaf issued for exactly these names, or None."""
    wanted = tuple(n.lower() for n in names)
    return next((leaf for leaf in leaves(config_dir) if leaf.names == wanted), None)


# ─────────────────────────────────────────────────────────────────────────
# a run
# ─────────────────────────────────────────────────────────────────────────


@contextlib.contextmanager
def _locked(config_dir: Path):
    path = lock_path(config_dir)
    common.ensure_dir(path.parent.parent)
    _private(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise EdgePkiError(
                        f"another papaia-ctl run holds {path}; try again once it has ended"
                    ) from None
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class _Audit:
    """Opens the audit outbox at the first write, so a run without a change leaves no
    trace; the outbox is checked before that write is made."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.log: realm_sync.AuditLog | None = None

    def before(self) -> None:
        if self.log is None:
            self.log = realm_sync.AuditLog(
                realm_sync.audit_path(self.config_dir),
                realm_sync.new_correlation_id(),
                writer=WRITER,
            )

    def step(self, kind: str, name: str, action: str, operation: str, write) -> None:
        """`write()` and its row: `allowed`, or `error` (with `openssl` or `file` as the
        code) when it failed, which then stops the run (papaia.audit/1 knows no other
        result)."""
        self.before()
        assert self.log is not None
        effect = "delete" if operation == "remove" else "write"
        change = realm_sync.Change(kind, name, action, operation, effect=effect)
        try:
            write()
        except EdgePkiError:
            self.log.write(change, "error", "openssl", host=True)
            raise
        except OSError:
            self.log.write(change, "error", "file", host=True)
            raise
        self.log.write(change, "allowed", host=True)

    def close(self) -> None:
        if self.log is not None:
            self.log.close()


def _wanted(hosts: list[Host], allowed: tuple[str, ...], result: Result) -> dict[str, tuple]:
    """label -> names of every host whose names the CA can sign; the others go to
    `result.refused`. A name already served by an earlier host is not issued twice."""
    wanted: dict[str, tuple[str, ...]] = {}
    seen: set[str] = set()
    if len(hosts) > MAX_HOSTS:
        raise EdgePkiError(f"more than {MAX_HOSTS} proxy hosts")
    for host in hosts:
        try:
            if not host.names or len(host.names) > MAX_NAMES:
                raise EdgePkiError(f"a proxy host needs 1 to {MAX_NAMES} names")
            names = tuple(check_name(name, allowed) for name in host.names)
        except EdgePkiError:
            result.refused.append(", ".join(str(n) for n in host.names))
            continue
        if seen & set(names):
            continue
        seen |= set(names)
        wanted[names[0]] = names
    return wanted


def issue(
    config_dir: Path,
    hosts: list[Host],
    allowed: tuple[str, ...],
    *,
    now: datetime | None = None,
    force: bool = False,
) -> Result:
    """Brings the edge CA and its leaves in line with `hosts`; `force` renews every leaf."""
    if not allowed:
        raise EdgePkiError("the installation names no domain for the edge CA")
    checked = [check_name(d, (d,)) for d in allowed]
    if any(d.startswith("*.") for d in checked):
        raise EdgePkiError("a domain of the edge CA cannot be a wildcard")
    # A domain inside another is covered by it and not named twice.
    allowed = tuple(
        dict.fromkeys(d for d in checked if not any(d.endswith(f".{o}") for o in checked))
    )
    with _locked(config_dir):
        return _issue(config_dir, hosts, allowed, now or datetime.now(timezone.utc), force)


def _issue(
    config_dir: Path, hosts: list[Host], allowed: tuple[str, ...], now: datetime, force: bool
) -> Result:
    result, audit = Result(), _Audit(config_dir)
    root = leaves_dir(config_dir)
    _private(root)
    try:
        wanted = _wanted(hosts, allowed, result)
        state = _ca_state(config_dir, allowed, now)
        if state is not None:
            operation = "ca_create" if state == "created" else "ca_replace"
            audit.step("ca", CA_NAME, state, operation, lambda: _create_ca(config_dir, allowed))
            result.ca = state
        crt, key = ca_paths(config_dir)
        os.chmod(key, 0o600)
        issuer = hashlib.sha256(crt.read_bytes()).hexdigest()

        for label, names in wanted.items():
            directory = _directory(config_dir, label)
            stamp = _read_stamp(directory)
            if stamp is None:
                action, operation = "issued", "issue"
            elif force or stamp != _stamp(names, issuer) or _due(directory, now):
                action, operation = "renewed", "renew"
            else:
                continue
            audit.step(
                "certificate", label, action, operation,
                lambda d=directory, n=names: _issue_leaf(config_dir, d, n, issuer),
            )  # fmt: skip
            (result.issued if action == "issued" else result.renewed).append(label)

        keep = {_directory(config_dir, label) for label in wanted}
        for directory in sorted(p for p in root.iterdir() if p.is_dir()):
            stamp = _read_stamp(directory)
            if directory in keep or stamp is None:
                continue  # not written by the edge CA: left alone
            names = stamp.get("names") or [directory.name]
            audit.step("certificate", str(names[0]), "removed", "remove",
                       lambda d=directory: shutil.rmtree(d))  # fmt: skip
            result.removed.append(str(names[0]))
    finally:
        audit.close()
    return result


# ─────────────────────────────────────────────────────────────────────────
# status and doctor
# ─────────────────────────────────────────────────────────────────────────


def status(config_dir: Path, now: datetime | None = None) -> list[dict]:
    """The edge CA and every leaf with its end and days left (empty without a CA)."""
    now = now or datetime.now(timezone.utc)
    crt, _ = ca_paths(config_dir)
    rows: list[tuple[str, Path]] = []
    if crt.is_file():
        rows.append((f"edge ca {CA_NAME} ({', '.join(ca_domains(config_dir) or ())})", crt))
    rows += [(f"edge/{leaf.label}/tls.crt", leaf.cert) for leaf in leaves(config_dir)]
    found = []
    for label, path in rows:
        try:
            end = _not_after(path.read_text(encoding="utf-8"))
        except (EdgePkiError, OSError, ValueError):
            continue
        found.append(
            {"certificate": label, "not_after": end.strftime(_TIME), "days_left": (end - now).days}
        )
    return found


def doctor_files(config_dir: Path) -> list[Path]:
    """The leaves `doctor certs` checks; the CA is `certs/edge-ca.crt`, which it reads with
    the other certificates of `certs/`. The platform PKI's own list reaches only
    `pki/<module>/<service>/`, so no leaf is listed twice."""
    return [leaf.cert for leaf in leaves(config_dir)]
