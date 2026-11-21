"""The age v1 file format (lib/age.py): X25519 recipients, header MAC and the STREAM payload.

Known answers come from the public test vectors of the primitives (RFC 7748, RFC 5869,
BIP-173). Files are checked against the `age` command where it is installed, in both
directions; every key of these tests is made at run time.
"""

from __future__ import annotations

import io
import shutil
import subprocess
from pathlib import Path

import pytest

from lib import age


def test_x25519_matches_rfc7748():
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    point = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert age.x25519(scalar, point).hex() == (
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    )


def test_hkdf_matches_rfc5869_case_1():
    okm = age.hkdf_sha256(
        b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_bech32_accepts_bip173_vectors():
    assert age.bech32_decode("A12UEL5L") == ("a", b"")
    assert age.bech32_decode("a12uel5l") == ("a", b"")
    with pytest.raises(age.AgeError):
        age.bech32_decode("a12uel5m")  # wrong checksum
    with pytest.raises(age.AgeError):
        age.bech32_decode("A12uEL5L")  # mixed case


def test_a_new_identity_names_its_recipient():
    identity, recipient = age.generate_identity()
    assert identity.startswith("AGE-SECRET-KEY-1") and identity == identity.upper()
    assert recipient.startswith("age1") and recipient == recipient.lower()
    assert age.recipient_of(identity) == recipient
    assert age.parse_recipient(recipient) != age.parse_identity(identity)


@pytest.mark.parametrize("bad", ["", "age1", "age1qqqq", "AGE-SECRET-KEY-1QQ", "x" * 300])
def test_parse_recipient_refuses_malformed_keys(bad: str):
    with pytest.raises(age.AgeError):
        age.parse_recipient(bad)


def _seal(data: bytes, recipients: list[str]) -> bytes:
    out = io.BytesIO()
    with age.Encryptor(out, recipients) as enc:
        # Odd write sizes cross the chunk boundary at every possible offset class.
        for start in range(0, len(data), 7001):
            enc.write(data[start : start + 7001])
    return out.getvalue()


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 3 * 65536, 3 * 65536 + 5])
def test_round_trip(size: int):
    identity, recipient = age.generate_identity()
    data = bytes((i * 31 + 7) % 251 for i in range(size))
    sealed = _seal(data, [recipient])
    assert sealed.startswith(b"age-encryption.org/v1\n-> X25519 ")
    out = io.BytesIO()
    age.decrypt(io.BytesIO(sealed), out, [identity])
    assert out.getvalue() == data


def test_every_recipient_can_open_the_file_and_no_other_key_can():
    first, first_r = age.generate_identity()
    second, second_r = age.generate_identity()
    stranger, _ = age.generate_identity()
    sealed = _seal(b"canary-7d1e", [first_r, second_r])
    for identity in (first, second):
        out = io.BytesIO()
        age.decrypt(io.BytesIO(sealed), out, [identity])
        assert out.getvalue() == b"canary-7d1e"
    with pytest.raises(age.NoIdentityError):
        age.decrypt(io.BytesIO(sealed), io.BytesIO(), [stranger])


def test_the_plaintext_is_not_in_the_file():
    _identity, recipient = age.generate_identity()
    sealed = _seal(b"canary-plain-4411" * 100, [recipient])
    assert b"canary-plain" not in sealed


def test_a_changed_payload_byte_is_refused():
    identity, recipient = age.generate_identity()
    sealed = bytearray(_seal(b"x" * 100_000, [recipient]))
    sealed[-20] ^= 0x01
    with pytest.raises(age.AgeError):
        age.decrypt(io.BytesIO(bytes(sealed)), io.BytesIO(), [identity])


def test_a_changed_header_is_refused():
    identity, recipient = age.generate_identity()
    _other, other_r = age.generate_identity()
    sealed = _seal(b"payload", [recipient, other_r])
    # Drop the second stanza: the file key still unwraps, the header MAC no longer fits.
    lines = sealed.split(b"\n")
    cut = b"\n".join(lines[:3] + lines[5:])
    with pytest.raises(age.AgeError):
        age.decrypt(io.BytesIO(cut), io.BytesIO(), [identity])


def test_a_truncated_file_is_refused():
    identity, recipient = age.generate_identity()
    sealed = _seal(b"y" * (2 * 65536 + 10), [recipient])
    truncated = sealed[: len(sealed) - (10 + 16)]  # the whole last chunk is gone
    with pytest.raises(age.AgeError):
        age.decrypt(io.BytesIO(truncated), io.BytesIO(), [identity])


def test_open_header_checks_the_key_without_reading_the_payload():
    identity, recipient = age.generate_identity()
    sealed = _seal(b"z" * 10, [recipient])
    header = age.open_header(io.BytesIO(sealed), [identity])
    assert header.recipients == 1
    stranger, _ = age.generate_identity()
    with pytest.raises(age.NoIdentityError):
        age.open_header(io.BytesIO(sealed), [stranger])


def test_an_encryptor_needs_a_recipient():
    with pytest.raises(age.AgeError):
        age.Encryptor(io.BytesIO(), [])


def test_identity_file_text_is_parsed_with_comments():
    identity, recipient = age.generate_identity()
    text = f"# created: today\n# public key: {recipient}\n{identity}\n"
    assert age.parse_identity_file(text) == [identity]
    with pytest.raises(age.AgeError):
        age.parse_identity_file("# nothing here\n")


AGE = shutil.which("age")


@pytest.mark.skipif(AGE is None, reason="the age command is not installed")
def test_a_file_sealed_here_opens_with_the_age_command(tmp_path: Path):
    identity, recipient = age.generate_identity()
    key = tmp_path / "id.txt"
    key.write_text(identity + "\n", encoding="utf-8")
    key.chmod(0o600)
    data = bytes(range(256)) * 700
    sealed = tmp_path / "f.age"
    sealed.write_bytes(_seal(data, [recipient]))
    done = subprocess.run(
        [AGE, "-d", "-i", str(key), str(sealed)], capture_output=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == data


@pytest.mark.skipif(AGE is None, reason="the age command is not installed")
def test_a_file_sealed_by_the_age_command_opens_here(tmp_path: Path):
    identity, recipient = age.generate_identity()
    data = b"from the reference tool\n" * 5000
    done = subprocess.run(
        [AGE, "-r", recipient], input=data, capture_output=True, check=False
    )
    assert done.returncode == 0, done.stderr
    out = io.BytesIO()
    age.decrypt(io.BytesIO(done.stdout), out, [identity])
    assert out.getvalue() == data
