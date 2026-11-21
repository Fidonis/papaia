"""The age v1 file format with X25519 recipients (https://age-encryption.org/v1).

Backups are encrypted to one or more public keys of the operator; the private keys never
reach the host. Files written here are age files: the `age` command opens them, and a
file the `age` command wrote to an X25519 recipient opens here.

The primitives (X25519, ChaCha20-Poly1305) come from the OpenSSL library the Python
interpreter is already linked against for `hashlib`; HKDF-SHA256 and HMAC are the
standard library. Nothing has to be installed on the host and no helper image is pulled.
Python 3.10 and later require OpenSSL 1.1.1 or newer, which provides both primitives.

Only X25519 stanzas are produced. On reading, stanzas of other types are skipped, as the
format asks. An scrypt (passphrase) file is only opened as a whole, for a
passphrase-protected identity file (`decrypt_with_passphrase`).
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass
from typing import BinaryIO

VERSION_LINE = b"age-encryption.org/v1"
RECIPIENT_HRP = "age"
IDENTITY_HRP = "age-secret-key-"
CHUNK = 64 * 1024
TAG = 16
_X25519_INFO = b"age-encryption.org/v1/X25519"
_MAX_HEADER = 64 * 1024
_MAX_STANZAS = 64
_MAX_KEY_TEXT = 128


class AgeError(ValueError):
    """A key, a header or a payload that is not a valid age file for the given key."""


class NoIdentityError(AgeError):
    """None of the given identities is a recipient of the file."""


# ── OpenSSL ──────────────────────────────────────────────────────────────────

_NID_X25519 = 1034
_CTRL_AEAD_GET_TAG = 0x10
_CTRL_AEAD_SET_TAG = 0x11
_P = ctypes.c_void_p
_SIZE_P = ctypes.POINTER(ctypes.c_size_t)
_INT_P = ctypes.POINTER(ctypes.c_int)

_SIGNATURES = {
    "EVP_PKEY_new_raw_private_key": (_P, [ctypes.c_int, _P, ctypes.c_char_p, ctypes.c_size_t]),
    "EVP_PKEY_new_raw_public_key": (_P, [ctypes.c_int, _P, ctypes.c_char_p, ctypes.c_size_t]),
    "EVP_PKEY_get_raw_public_key": (ctypes.c_int, [_P, ctypes.c_char_p, _SIZE_P]),
    "EVP_PKEY_free": (None, [_P]),
    "EVP_PKEY_CTX_new": (_P, [_P, _P]),
    "EVP_PKEY_CTX_free": (None, [_P]),
    "EVP_PKEY_derive_init": (ctypes.c_int, [_P]),
    "EVP_PKEY_derive_set_peer": (ctypes.c_int, [_P, _P]),
    "EVP_PKEY_derive": (ctypes.c_int, [_P, ctypes.c_char_p, _SIZE_P]),
    "EVP_chacha20_poly1305": (_P, []),
    "EVP_CIPHER_CTX_new": (_P, []),
    "EVP_CIPHER_CTX_free": (None, [_P]),
    "EVP_CIPHER_CTX_ctrl": (ctypes.c_int, [_P, ctypes.c_int, ctypes.c_int, _P]),
    "EVP_EncryptInit_ex": (ctypes.c_int, [_P, _P, _P, ctypes.c_char_p, ctypes.c_char_p]),
    "EVP_EncryptUpdate": (
        ctypes.c_int, [_P, ctypes.c_char_p, _INT_P, ctypes.c_char_p, ctypes.c_int]
    ),
    "EVP_EncryptFinal_ex": (ctypes.c_int, [_P, ctypes.c_char_p, _INT_P]),
    "EVP_DecryptInit_ex": (ctypes.c_int, [_P, _P, _P, ctypes.c_char_p, ctypes.c_char_p]),
    "EVP_DecryptUpdate": (
        ctypes.c_int, [_P, ctypes.c_char_p, _INT_P, ctypes.c_char_p, ctypes.c_int]
    ),
    "EVP_DecryptFinal_ex": (ctypes.c_int, [_P, ctypes.c_char_p, _INT_P]),
}

_LIB = None


def _candidates() -> list[str]:
    """Libraries to look the symbols up in, the interpreter's own OpenSSL first.

    A handle of the `_hashlib` extension resolves the symbols of the libcrypto it is
    linked against (dlsym searches a library's dependencies). The system library is the
    fallback for an interpreter that links OpenSSL statically; on macOS it is never
    loaded by its unversioned name, which aborts the process."""
    found: list[str] = []
    for module in ("_hashlib", "_ssl"):
        try:
            found.append(__import__(module).__file__)
        except (ImportError, AttributeError):
            continue
    if sys.platform != "darwin":
        name = ctypes.util.find_library("crypto")
        if name:
            found.append(name)
    return found


def _lib():
    global _LIB
    if _LIB is not None:
        return _LIB
    for path in _candidates():
        try:
            lib = ctypes.CDLL(path)
            for name, (restype, argtypes) in _SIGNATURES.items():
                func = getattr(lib, name)
                func.restype = restype
                func.argtypes = argtypes
        except (OSError, AttributeError):
            continue
        _LIB = lib
        return lib
    raise AgeError(
        "this Python has no OpenSSL with X25519 and ChaCha20-Poly1305 (OpenSSL 1.1.1 or newer)"
    )


def _raw_key(raw: bytes, private: bool):
    lib = _lib()
    make = lib.EVP_PKEY_new_raw_private_key if private else lib.EVP_PKEY_new_raw_public_key
    key = make(_NID_X25519, None, raw, len(raw))
    if not key:
        raise AgeError("not an X25519 key")
    return key


def x25519_public(private: bytes) -> bytes:
    lib = _lib()
    key = _raw_key(private, True)
    try:
        out = ctypes.create_string_buffer(32)
        size = ctypes.c_size_t(32)
        if lib.EVP_PKEY_get_raw_public_key(key, out, ctypes.byref(size)) != 1:
            raise AgeError("X25519 public key could not be derived")
        return out.raw[: size.value]
    finally:
        lib.EVP_PKEY_free(key)


def x25519(private: bytes, public: bytes) -> bytes:
    """The shared secret; refuses the all-zero result of a low-order point."""
    if len(private) != 32 or len(public) != 32:
        raise AgeError("X25519 keys are 32 bytes")
    lib = _lib()
    own = _raw_key(private, True)
    peer = _raw_key(public, False)
    ctx = lib.EVP_PKEY_CTX_new(own, None)
    try:
        out = ctypes.create_string_buffer(32)
        size = ctypes.c_size_t(32)
        if (
            not ctx
            or lib.EVP_PKEY_derive_init(ctx) != 1
            or lib.EVP_PKEY_derive_set_peer(ctx, peer) != 1
            or lib.EVP_PKEY_derive(ctx, out, ctypes.byref(size)) != 1
        ):
            raise AgeError("X25519 key agreement failed")
        secret = out.raw[: size.value]
    finally:
        if ctx:
            lib.EVP_PKEY_CTX_free(ctx)
        lib.EVP_PKEY_free(peer)
        lib.EVP_PKEY_free(own)
    if secret == bytes(32):
        raise AgeError("X25519 key agreement gave the all-zero value")
    return secret


class _Aead:
    """ChaCha20-Poly1305 (RFC 8439) without associated data, one context reused."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise AgeError("ChaCha20-Poly1305 keys are 32 bytes")
        self._lib = _lib()
        self._key = key
        self._ctx = self._lib.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise AgeError("no cipher context")

    def close(self) -> None:
        if self._ctx:
            self._lib.EVP_CIPHER_CTX_free(self._ctx)
            self._ctx = None

    def __del__(self) -> None:
        self.close()

    def seal(self, nonce: bytes, data: bytes) -> bytes:
        lib, ctx = self._lib, self._ctx
        out = ctypes.create_string_buffer(len(data) + TAG)
        size = ctypes.c_int(0)
        tail = ctypes.c_int(0)
        tag = ctypes.create_string_buffer(TAG)
        if (
            lib.EVP_EncryptInit_ex(ctx, lib.EVP_chacha20_poly1305(), None, self._key, nonce) != 1
            or lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(size), data, len(data)) != 1
            or lib.EVP_EncryptFinal_ex(ctx, out, ctypes.byref(tail)) != 1
            or lib.EVP_CIPHER_CTX_ctrl(ctx, _CTRL_AEAD_GET_TAG, TAG, ctypes.cast(tag, _P)) != 1
        ):
            raise AgeError("encryption failed")
        return out.raw[: size.value] + tag.raw

    def open(self, nonce: bytes, sealed: bytes) -> bytes:
        if len(sealed) < TAG:
            raise AgeError("ciphertext shorter than its tag")
        lib, ctx = self._lib, self._ctx
        body, tag = sealed[:-TAG], sealed[-TAG:]
        out = ctypes.create_string_buffer(len(body) + TAG)
        size = ctypes.c_int(0)
        tail = ctypes.c_int(0)
        tag_buf = ctypes.create_string_buffer(tag, TAG)
        if (
            lib.EVP_DecryptInit_ex(ctx, lib.EVP_chacha20_poly1305(), None, self._key, nonce) != 1
            or lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(size), body, len(body)) != 1
            or lib.EVP_CIPHER_CTX_ctrl(ctx, _CTRL_AEAD_SET_TAG, TAG, ctypes.cast(tag_buf, _P))
            != 1
            or lib.EVP_DecryptFinal_ex(ctx, out, ctypes.byref(tail)) != 1
        ):
            raise AgeError("decryption failed: wrong key or changed data")
        return out.raw[: size.value]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# ── Bech32 (BIP-173; age lifts the 90-character limit) ──────────────────────

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for i, gen in enumerate(_GENERATOR):
            if top >> i & 1:
                check ^= gen
    return check


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert(data, from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc, bits, out, top = 0, 0, [], (1 << to_bits) - 1
    for value in data:
        acc = acc << from_bits | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append(acc >> bits & top)
    if pad and bits:
        out.append(acc << (to_bits - bits) & top)
    elif not pad and (bits >= from_bits or acc << (to_bits - bits) & top):
        raise AgeError("bech32 padding is not zero")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    values = _convert(data, 8, 5, True)
    checksum = _polymod(_hrp_expand(hrp) + values + [0] * 6) ^ 1
    values += [checksum >> 5 * (5 - i) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[v] for v in values)


def bech32_decode(text: str) -> tuple[str, bytes]:
    if not isinstance(text, str) or len(text) > _MAX_KEY_TEXT or not text.isascii():
        raise AgeError("not a bech32 string")
    if text.lower() != text and text.upper() != text:
        raise AgeError("bech32 must not mix upper and lower case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise AgeError("not a bech32 string")
    hrp, rest = text[:pos], text[pos + 1 :]
    if any(c not in _CHARSET for c in rest) or any(not 33 <= ord(c) <= 126 for c in hrp):
        raise AgeError("bech32 string has characters outside its alphabet")
    values = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise AgeError("bech32 checksum does not match")
    return hrp, bytes(_convert(values[:-6], 5, 8, False))


# ── keys ─────────────────────────────────────────────────────────────────────


def parse_recipient(text: str) -> bytes:
    """The 32-byte X25519 public key of an `age1...` recipient."""
    hrp, data = bech32_decode(text.strip() if isinstance(text, str) else text)
    if hrp != RECIPIENT_HRP or len(data) != 32 or text.strip() != text.strip().lower():
        raise AgeError("not an age X25519 recipient (age1...)")
    return data


def parse_identity(text: str) -> bytes:
    """The 32-byte X25519 private key of an `AGE-SECRET-KEY-1...` identity."""
    hrp, data = bech32_decode(text.strip() if isinstance(text, str) else text)
    if hrp != IDENTITY_HRP or len(data) != 32:
        raise AgeError("not an age X25519 identity (AGE-SECRET-KEY-1...)")
    return data


def recipient_of(identity: str) -> str:
    return bech32_encode(RECIPIENT_HRP, x25519_public(parse_identity(identity)))


def generate_identity() -> tuple[str, str]:
    """A new key pair as (identity, recipient). The identity is shown once, never stored."""
    private = os.urandom(32)
    identity = bech32_encode(IDENTITY_HRP, private).upper()
    return identity, bech32_encode(RECIPIENT_HRP, x25519_public(private))


def parse_identity_file(text: str) -> list[str]:
    """The identities of an identity file: one per line, `#` comments and blank lines."""
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parse_identity(line)
        found.append(line)
        if len(found) > _MAX_STANZAS:
            raise AgeError("too many identities")
    if not found:
        raise AgeError("no identity (AGE-SECRET-KEY-1...) in the identity file")
    return found


# ── header ───────────────────────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


_B64_RE = re.compile(r"\A[A-Za-z0-9+/]*\Z")


def _unb64(text: str) -> bytes:
    if not _B64_RE.match(text) or len(text) % 4 == 1:
        raise AgeError("invalid base64 in the header")
    data = base64.b64decode(text + "=" * (-len(text) % 4))
    if _b64(data) != text:
        raise AgeError("non-canonical base64 in the header")
    return data


def _stanza(file_key: bytes, recipient: bytes) -> bytes:
    ephemeral = os.urandom(32)
    share = x25519_public(ephemeral)
    secret = x25519(ephemeral, recipient)
    wrap_key = hkdf_sha256(secret, share + recipient, _X25519_INFO, 32)
    aead = _Aead(wrap_key)
    try:
        body = aead.seal(bytes(12), file_key)
    finally:
        aead.close()
    return f"-> X25519 {_b64(share)}\n{_b64(body)}\n".encode("ascii")


def _header(file_key: bytes, recipients: list[bytes]) -> bytes:
    head = VERSION_LINE + b"\n" + b"".join(_stanza(file_key, r) for r in recipients) + b"---"
    mac = hmac.new(hkdf_sha256(file_key, b"", b"header", 32), head, hashlib.sha256).digest()
    return head + b" " + _b64(mac).encode("ascii") + b"\n"


@dataclass(frozen=True)
class Header:
    file_key: bytes
    recipients: int  # X25519 stanzas in the header


def _read_line(stream: BinaryIO, budget: list[int]) -> bytes:
    line = stream.readline(budget[0] + 1)
    budget[0] -= len(line)
    if budget[0] < 0 or not line.endswith(b"\n"):
        raise AgeError("not an age file (header too long or cut off)")
    return line[:-1]


_SCRYPT_LABEL = b"age-encryption.org/v1/scrypt"
# Work factor 2^20 needs 1 GiB; a file asking for more is refused rather than obeyed.
_SCRYPT_MAX_LOG_N = 20


def _scrypt_file_key(stanzas: list[tuple[list[str], bytes]], passphrase: str) -> bytes:
    if len(stanzas) != 1:
        raise AgeError("a passphrase-encrypted file has exactly one stanza")
    args, body = stanzas[0]
    if len(args) != 3 or not args[2].isdigit() or len(body) != 32:
        raise AgeError("malformed scrypt stanza")
    salt, log_n = _unb64(args[1]), int(args[2])
    if len(salt) != 16 or not 1 <= log_n <= _SCRYPT_MAX_LOG_N or args[2] != str(log_n):
        raise AgeError("scrypt stanza outside the accepted work factor")
    wrap_key = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=_SCRYPT_LABEL + salt, n=1 << log_n, r=8, p=1,
        maxmem=(128 * 8 * (1 << log_n)) + (64 << 20), dklen=32,
    )
    aead = _Aead(wrap_key)
    try:
        return aead.open(bytes(12), body)
    except AgeError:
        raise NoIdentityError("wrong passphrase") from None
    finally:
        aead.close()


def open_header(
    stream: BinaryIO, identities: list[str], *, passphrase: str | None = None
) -> Header:
    """Read and authenticate the header; the stream is left at the payload nonce."""
    privates = [(parse_identity(i), None) for i in identities]
    privates = [(p, x25519_public(p)) for p, _ in privates]
    budget = [_MAX_HEADER]
    if _read_line(stream, budget) != VERSION_LINE:
        raise AgeError("not an age v1 file")
    head = VERSION_LINE + b"\n"
    stanzas: list[tuple[list[str], bytes]] = []
    while True:
        line = _read_line(stream, budget)
        if line.startswith(b"--- "):
            mac_text = line[4:].decode("ascii", "replace")
            head += b"---"
            break
        if not line.startswith(b"-> ") or len(stanzas) >= _MAX_STANZAS:
            raise AgeError("malformed age header")
        args = line[3:].decode("ascii", "replace").split(" ")
        head += line + b"\n"
        body = b""
        while True:
            part = _read_line(stream, budget)
            head += part + b"\n"
            body += _unb64(part.decode("ascii", "replace"))
            if len(part) < 64:
                break
        stanzas.append((args, body))
    x25519_stanzas = [(a, b) for a, b in stanzas if a and a[0] == "X25519"]
    file_key = None
    if passphrase is not None:
        if not any(a and a[0] == "scrypt" for a, _ in stanzas):
            raise NoIdentityError("the file is not encrypted with a passphrase")
        file_key = _scrypt_file_key(stanzas, passphrase)
        x25519_stanzas = []
    elif any(a and a[0] == "scrypt" for a, _ in stanzas):
        raise NoIdentityError("the file is encrypted with a passphrase, not to a key")
    for args, body in x25519_stanzas:
        if len(args) != 2 or len(body) != 32:
            raise AgeError("malformed X25519 stanza")
        share = _unb64(args[1])
        if len(share) != 32:
            raise AgeError("malformed X25519 stanza")
        for private, public in privates:
            wrap_key = hkdf_sha256(x25519(private, share), share + public, _X25519_INFO, 32)
            aead = _Aead(wrap_key)
            try:
                file_key = aead.open(bytes(12), body)
            except AgeError:
                continue
            finally:
                aead.close()
            break
        if file_key is not None:
            break
    if file_key is None:
        raise NoIdentityError("none of the given keys is a recipient of this file")
    mac = hmac.new(hkdf_sha256(file_key, b"", b"header", 32), head, hashlib.sha256).digest()
    if not hmac.compare_digest(_unb64(mac_text), mac):
        raise AgeError("the age header was changed (MAC does not match)")
    return Header(file_key=file_key, recipients=len(x25519_stanzas))


# ── payload ──────────────────────────────────────────────────────────────────


def _nonce(counter: int, last: bool) -> bytes:
    if counter >= 1 << 88:
        raise AgeError("payload too long")
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


class Encryptor:
    """A write-only stream: plaintext in, an age file out to `out`.

    `close()` writes the last chunk; without it the file is incomplete and does not open."""

    def __init__(self, out: BinaryIO, recipients: list[str]) -> None:
        if not recipients:
            raise AgeError("at least one recipient is needed")
        keys = [parse_recipient(r) for r in recipients]
        file_key = os.urandom(16)
        nonce = os.urandom(16)
        self._out = out
        self._out.write(_header(file_key, keys) + nonce)
        self._aead = _Aead(hkdf_sha256(file_key, nonce, b"payload", 32))
        self._buffer = bytearray()
        self._counter = 0
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise AgeError("write to a closed encryptor")
        self._buffer += data
        # Keep at least one byte back: only close() knows which chunk is the last.
        while len(self._buffer) > CHUNK:
            self._out.write(self._aead.seal(_nonce(self._counter, False),
                                            bytes(self._buffer[:CHUNK])))
            del self._buffer[:CHUNK]
            self._counter += 1
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        self._out.write(self._aead.seal(_nonce(self._counter, True), bytes(self._buffer)))
        self._buffer.clear()
        self._aead.close()
        self._closed = True

    def __enter__(self) -> Encryptor:
        return self

    def __exit__(self, exc_type, *_exc: object) -> None:
        if exc_type is None:
            self.close()
        else:
            self._aead.close()
            self._closed = True


def decrypt_with_passphrase(stream: BinaryIO, out: BinaryIO, passphrase: str) -> int:
    """Decrypt a passphrase-encrypted age file, such as a protected identity file."""
    return _decrypt_payload(stream, out, open_header(stream, [], passphrase=passphrase))


def decrypt(stream: BinaryIO, out: BinaryIO, identities: list[str]) -> int:
    """Decrypt an age file to `out`; returns the plaintext length. Refuses a changed,
    cut-off or extended file before the end, so a caller must discard `out` on error."""
    return _decrypt_payload(stream, out, open_header(stream, identities))


def _decrypt_payload(stream: BinaryIO, out: BinaryIO, header: Header) -> int:
    nonce = stream.read(16)
    if len(nonce) != 16:
        raise AgeError("age payload nonce is missing")
    aead = _Aead(hkdf_sha256(header.file_key, nonce, b"payload", 32))
    total, counter = 0, 0
    try:
        current = stream.read(CHUNK + TAG)
        while True:
            following = stream.read(CHUNK + TAG) if len(current) == CHUNK + TAG else b""
            last = not following
            if len(current) < TAG or (last and len(current) == TAG and counter > 0):
                raise AgeError("age payload is cut off")
            plain = aead.open(_nonce(counter, last), current)
            out.write(plain)
            total += len(plain)
            if last:
                return total
            counter += 1
            current = following
    finally:
        aead.close()
