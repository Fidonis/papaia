"""Public keys of module clients: the manifest key `client_keys[]`.

A module may declare, for clients it owns, a file in its add-on configuration folder
(`$PAPAIA_CONFIG_DIR/addons/<module>/`) that holds the public JWK set of the client:

    client_keys:
      - client: flow-engine
        jwks_file: keys/flow-engine.jwks.json

The module writes the file (only public keys; the private key stays in its own volume),
`papaia-ctl realm sync` registers it at the client with `private_key_jwt`. No module needs
a realm admin token or an account with write access to the Admin API for that.

This module checks the declaration and the file; the realm sync checks ownership. Only
EC P-256 (ES256) and RSA keys of at least 3072 bits (RS*/PS*) with `use: sig` pass, at
most two keys (old and new during a rotation), no private member, no unknown member.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_DECLARATIONS = 8
MAX_KEYS = 2
MAX_FILE_BYTES = 65536
RSA_MIN_BITS = 3072
RSA_MAX_BITS = 8192
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
_COMMON = frozenset({"kty", "kid", "use", "alg"})
_MEMBERS = {"EC": _COMMON | {"crv", "x", "y"}, "RSA": _COMMON | {"n", "e"}}
_ALGS = {
    "EC": frozenset({"ES256"}),
    "RSA": frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}),
}
_DECLARATION_KEYS = frozenset({"client", "jwks_file"})
_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}(\.[A-Za-z0-9_-]{1,16}){0,3}"
_FILE_RE = re.compile(rf"^{_SEGMENT}(/{_SEGMENT}){{0,3}}$")
_KID_RE = re.compile(r"^[A-Za-z0-9._:+/=-]{1,128}$")
_B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# NIST P-256 (FIPS 186-4 D.1.2.3): y^2 = x^3 - 3x + b over GF(p)
_P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


class ClientKeyError(ValueError):
    """A declaration or a key file that is refused; the message names the reason."""


@dataclass(frozen=True)
class Declaration:
    client: str
    jwks_file: str


def parse_declarations(value: object, label: str) -> list[Declaration]:
    if not isinstance(value, list):
        raise ClientKeyError(f"{label}: client_keys must be a list")
    if len(value) > MAX_DECLARATIONS:
        raise ClientKeyError(f"{label}: client_keys: at most {MAX_DECLARATIONS} entries")
    found: list[Declaration] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ClientKeyError(f"{label}: a client_keys entry must be a mapping")
        unknown = sorted(str(k) for k in set(entry) - _DECLARATION_KEYS)
        if unknown:
            raise ClientKeyError(f"{label}: client_keys: unknown field {', '.join(unknown)}")
        missing = sorted(_DECLARATION_KEYS - set(entry))
        if missing:
            raise ClientKeyError(f"{label}: client_keys: missing field {', '.join(missing)}")
        client, path = entry["client"], entry["jwks_file"]
        if not isinstance(client, str) or not client or len(client) > 64:
            raise ClientKeyError(f"{label}: client_keys: client must be a client name")
        if not isinstance(path, str) or not _FILE_RE.match(path):
            raise ClientKeyError(
                f"{label}: client_keys {client}: jwks_file must be a relative path inside the "
                "add-on configuration folder (no '..', no leading dot, at most 4 levels)"
            )
        if any(d.client == client for d in found):
            raise ClientKeyError(f"{label}: client_keys: {client} is declared twice")
        found.append(Declaration(client, path))
    return found


def _b64_int(jwk: dict, member: str, label: str) -> bytes:
    value = jwk.get(member)
    if not isinstance(value, str) or len(value) > 2048 or not _B64_RE.match(value):
        raise ClientKeyError(f"{label}: {member} is not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise ClientKeyError(f"{label}: {member} is not base64url") from None


def _check_key(jwk: object, label: str) -> dict:
    if not isinstance(jwk, dict):
        raise ClientKeyError(f"{label}: a key must be a JSON object")
    for member in PRIVATE_MEMBERS:
        if member in jwk:
            raise ClientKeyError(
                f"{label}: private key member {member}; the file may hold public keys only"
            )
    kty = jwk.get("kty")
    if kty not in _MEMBERS:
        raise ClientKeyError(f"{label}: kty must be EC or RSA")
    unknown = sorted(str(k) for k in set(jwk) - _MEMBERS[kty])
    if unknown:
        raise ClientKeyError(f"{label}: unknown member {', '.join(unknown)}")
    if jwk.get("use") != "sig":
        raise ClientKeyError(f"{label}: use must be sig")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not _KID_RE.match(kid):
        raise ClientKeyError(f"{label}: kid must be 1 to 128 characters of [A-Za-z0-9._:+/=-]")
    alg = jwk.get("alg")
    if alg is not None and alg not in _ALGS[kty]:
        raise ClientKeyError(f"{label}: alg {alg} is not allowed for {kty} keys")
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise ClientKeyError(f"{label}: EC keys must use P-256")
        x, y = (_b64_int(jwk, m, label) for m in ("x", "y"))
        if len(x) != 32 or len(y) != 32:
            raise ClientKeyError(f"{label}: x and y must be 32 bytes each")
        xi, yi = int.from_bytes(x, "big"), int.from_bytes(y, "big")
        if (
            xi >= _P256_P
            or yi >= _P256_P
            or (yi * yi - (xi * xi * xi - 3 * xi + _P256_B)) % _P256_P
        ):
            raise ClientKeyError(f"{label}: not a point on P-256")
    else:
        n = int.from_bytes(_b64_int(jwk, "n", label), "big")
        e = int.from_bytes(_b64_int(jwk, "e", label), "big")
        if not RSA_MIN_BITS <= n.bit_length() <= RSA_MAX_BITS:
            raise ClientKeyError(
                f"{label}: RSA keys need at least {RSA_MIN_BITS} bits (at most {RSA_MAX_BITS})"
            )
        if e < 65537 or e % 2 == 0 or e.bit_length() > 256:
            raise ClientKeyError(f"{label}: RSA exponent e must be odd and at least 65537")
    return dict(jwk)


def check_jwks(doc: object, label: str) -> list[dict]:
    """The keys of a public JWK set, or ClientKeyError."""
    if not isinstance(doc, dict):
        raise ClientKeyError(f"{label}: not a JWK set (a JSON object with keys)")
    unknown = sorted(str(k) for k in set(doc) - {"keys"})
    if unknown:
        raise ClientKeyError(f"{label}: unknown field {', '.join(unknown)}")
    keys = doc.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ClientKeyError(f"{label}: the JWK set needs at least one key")
    if len(keys) > MAX_KEYS:
        raise ClientKeyError(f"{label}: at most {MAX_KEYS} keys (the new and the old one)")
    checked = [_check_key(k, f"{label}, key {i + 1}") for i, k in enumerate(keys)]
    kids = [k["kid"] for k in checked]
    for kid in kids:
        if kids.count(kid) > 1:
            raise ClientKeyError(f"{label}: kid {kid} is used twice")
    return checked


def _unsafe(st: os.stat_result, what: str) -> None:
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ClientKeyError(f"{what} is writable by group or others (chmod go-w)")


def read_jwks(folder: Path, relative: str, label: str) -> list[dict] | None:
    """The checked keys of `folder/relative`; None when the folder or the file is missing.
    No path component may be a symbolic link; the file and its folders must not be
    writable by group or others (the file grants a client's sign-in)."""
    parts = relative.split("/")
    path = folder / relative
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fds: list[int] = []
    try:
        try:
            fds.append(os.open(folder, flags | os.O_DIRECTORY))
            _unsafe(os.fstat(fds[-1]), str(folder))
            for part in parts[:-1]:
                fds.append(os.open(part, flags | os.O_DIRECTORY, dir_fd=fds[-1]))
                _unsafe(os.fstat(fds[-1]), f"{folder}/{part}")
            fd = os.open(parts[-1], flags, dir_fd=fds[-1])
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ClientKeyError(
                f"{label}: {path} cannot be opened safely: {exc.strerror}"
            ) from None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ClientKeyError(f"{label}: {path} is not a regular file")
            _unsafe(st, str(path))
            if st.st_size > MAX_FILE_BYTES:
                raise ClientKeyError(f"{label}: {path} is larger than {MAX_FILE_BYTES} bytes")
            raw = fh.read(MAX_FILE_BYTES + 1)
    finally:
        for fd_ in fds:
            os.close(fd_)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ClientKeyError(f"{label}: {path} is not a JWK set (not valid JSON)") from None
    return check_jwks(doc, f"{label}: {path}")
