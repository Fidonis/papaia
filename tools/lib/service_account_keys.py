"""Key pairs of the declared service accounts (`private_key_jwt`, ES256 on P-256).

A service account signs in with a client assertion (RFC 7523) signed by its private
key; Keycloak holds only the public key, as a JWK set in the client's `jwks.string`.
The private key lives only in the configuration directory:

    $PAPAIA_CONFIG_DIR/security/service-accounts/<id>/private-key.pem   (0600, folder 0700)

and is never printed, logged or sent anywhere. Keys are made and used with the
`openssl` command line, which `setup` already requires; the private key is written by
this module, never through a path openssl chooses.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path

KEY_FILE = "private-key.pem"
NEXT_FILE = "private-key.next.pem"
OLD_FILE = "private-key.old.pem"
ALGORITHM = "ES256"
# DER prefix of a SubjectPublicKeyInfo of an uncompressed P-256 point: SEQUENCE {
# SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 0x04 || x || y }.
P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
ASSERTION_SECONDS = 60
_ACCOUNT_RE = re.compile(r"^svc-[a-z][a-z0-9]*-[a-z0-9]+(-[a-z0-9]+)*$")
_MAX_KEY_BYTES = 16384


class KeyFileError(Exception):
    """A key file or its folder is missing, unsafe or unreadable."""


def account_name(value: object) -> str:
    """`value` if it is a service account name (svc-<module>-<purpose>), else ValueError;
    checked before any path is built from it."""
    if not isinstance(value, str) or not _ACCOUNT_RE.fullmatch(value):
        raise ValueError(f"{value!r} is not a service account name (svc-<module>-<purpose>)")
    return value


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint (SHA-256) of an EC public key: the key id."""
    members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("ascii")
    return _b64(hashlib.sha256(canonical).digest())


def _openssl(args: list[str], data: bytes) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args], input=data, capture_output=True, timeout=30, check=False
        )
    except FileNotFoundError:
        raise KeyFileError("openssl not found; it is needed for service account keys") from None
    if result.returncode != 0:
        raise KeyFileError(f"openssl {args[0]} failed")
    return result.stdout


def public_jwk(private_pem: bytes) -> dict:
    """The public JWK (with `kid`, `use` and `alg`) of a P-256 private key."""
    der = _openssl(["pkey", "-pubout", "-outform", "DER"], private_pem)
    prefix = bytes.fromhex(P256_SPKI_PREFIX)
    if len(der) != len(prefix) + 64 or not der.startswith(prefix):
        raise KeyFileError("the key is not a P-256 key")
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64(der[-64:-32]), "y": _b64(der[-32:])}
    return dict(jwk, kid=thumbprint(jwk), use="sig", alg=ALGORITHM)


def _raw_signature(der: bytes) -> bytes:
    """An ECDSA signature in DER (SEQUENCE of two INTEGERs) as JOSE wants it: r || s."""
    if len(der) < 8 or der[0] != 0x30 or der[1] & 0x80:
        raise KeyFileError("unexpected signature from openssl")
    pos, parts = 2, []
    for _ in range(2):
        if der[pos] != 0x02:
            raise KeyFileError("unexpected signature from openssl")
        length = der[pos + 1]
        value = der[pos + 2 : pos + 2 + length].lstrip(b"\0")
        if len(value) > 32:
            raise KeyFileError("unexpected signature from openssl")
        parts.append(value.rjust(32, b"\0"))
        pos += 2 + length
    return parts[0] + parts[1]


def client_assertion(
    key_path: Path, jwk: dict, client_id: str, audience: str, *, now: float | None = None
) -> str:
    """A signed client assertion (RFC 7523) for `client_id` at the token endpoint
    `audience`, valid for at most 60 seconds and usable once (`jti`)."""
    issued = int(time.time() if now is None else now)
    header = {"alg": ALGORITHM, "kid": jwk["kid"], "typ": "JWT"}
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": str(uuid.uuid4()),
        "iat": issued,
        "exp": issued + ASSERTION_SECONDS,
    }
    signing_input = ".".join(
        _b64(json.dumps(part, separators=(",", ":"), sort_keys=True).encode())
        for part in (header, claims)
    )
    der = _openssl(["dgst", "-sha256", "-sign", str(key_path)], signing_input.encode("ascii"))
    return f"{signing_input}.{_b64(_raw_signature(der))}"


class KeyStore:
    """The key pairs under `root` (`security/service-accounts` of the config dir), one
    folder per account. Folders are 0700 and must not be symbolic links; key files are
    0600 and belong to the user running papaia-ctl."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def folder(self, account_id: str) -> Path:
        return self.root / account_name(account_id)

    def key_path(self, account_id: str) -> Path:
        return self.folder(account_id) / KEY_FILE

    def _safe_dir(self, path: Path, *, create: bool) -> None:
        if create:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise KeyFileError(f"{path} does not exist") from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise KeyFileError(f"{path} is not a folder (a symbolic link is refused)")
        if st.st_uid not in (os.geteuid(), 0):
            raise KeyFileError(f"{path} does not belong to the user running papaia-ctl")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(path, 0o700)

    def _prepare(self, account_id: str) -> Path:
        folder = self.folder(account_id)
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._safe_dir(self.root, create=True)
        self._safe_dir(folder, create=True)
        return folder

    def _read(self, path: Path) -> bytes | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise KeyFileError(f"{path} cannot be opened safely: {exc.strerror}") from None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise KeyFileError(f"{path} is not a regular file")
            if st.st_uid not in (os.geteuid(), 0):
                raise KeyFileError(f"{path} does not belong to the user running papaia-ctl")
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise KeyFileError(f"{path} is readable by group or others; it must be 0600")
            return fh.read(_MAX_KEY_BYTES)

    def public_jwk(self, account_id: str, file: str = KEY_FILE) -> dict | None:
        """The public JWK of an account's key, None when there is no key file."""
        folder = self.folder(account_id)
        try:
            st = os.lstat(folder)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise KeyFileError(f"{folder} is not a folder (a symbolic link is refused)")
        pem = self._read(folder / file)
        return None if pem is None else public_jwk(pem)

    def generate(self, account_id: str, file: str = KEY_FILE) -> dict:
        """A new key pair in `file` of the account's folder (replacing it); returns the
        public JWK. The private key goes from openssl's output straight into a new 0600
        file, which then replaces the old one in one step."""
        pem = _openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], b"")
        jwk = public_jwk(pem)
        self.write(account_id, file, pem)
        return jwk

    def write(self, account_id: str, file: str, data: bytes) -> None:
        """`data` as `file` (0600) of the account's folder, replacing it in one step."""
        folder = self._prepare(account_id)
        staging = folder / f".{file}.{os.getpid()}.tmp"
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(staging, folder / file)
        except BaseException:
            staging.unlink(missing_ok=True)
            raise

    def read(self, account_id: str, file: str) -> bytes | None:
        """`file` of the account's folder (checked like a key file), None when missing."""
        folder = self.folder(account_id)
        try:
            st = os.lstat(folder)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise KeyFileError(f"{folder} is not a folder (a symbolic link is refused)")
        return self._read(folder / file)

    def move(self, account_id: str, source: str, target: str) -> None:
        folder = self.folder(account_id)
        self._safe_dir(folder, create=False)
        os.replace(folder / source, folder / target)

    def discard(self, account_id: str, file: str) -> None:
        (self.folder(account_id) / file).unlink(missing_ok=True)

    def remove(self, account_id: str) -> None:
        """Delete an account's folder with its keys (the account is gone)."""
        folder = self.folder(account_id)
        try:
            st = os.lstat(folder)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise KeyFileError(f"{folder} is not a folder (a symbolic link is refused)")
        shutil.rmtree(folder)
