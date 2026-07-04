from __future__ import annotations

import base64

import pytest

from lib import common


def test_marks_generated_secret():
    # The GENERATE_ marker in .env.example is what selects a key for generation,
    # not its name -- so CREDS_IV (no SECRET/KEY/... substring) qualifies, while
    # literals shipped without the marker do not.
    assert common.marks_generated_secret("GENERATE_CREDS_IV")
    assert common.marks_generated_secret("GENERATE_NEW_SECRET")
    assert not common.marks_generated_secret("")
    assert not common.marks_generated_secret("keycloak")
    assert not common.marks_generated_secret("sk-not-used")


def test_is_placeholder():
    assert common.is_placeholder("")
    assert common.is_placeholder("GENERATE_FOO")
    assert not common.is_placeholder("already-set-value")


def test_generate_secret_default_is_24_byte_hex():
    value = common.generate_secret("SOME_RANDOM_SECRET")
    assert len(value) == 48
    int(value, 16)  # raises if not valid hex


def test_generate_secret_cookie_secret_is_32_byte_base64():
    # oauth2-proxy decodes --cookie-secret as URL-safe base64 (RFC 4648 §5):
    # a standard-alphabet value containing '+' or '/' fails to decode there
    # and gets treated as raw bytes of the wrong length instead.
    value = common.generate_secret("OAUTH2_PROXY_COOKIE_SECRET")
    decoded = base64.urlsafe_b64decode(value)
    assert len(decoded) == 32


def test_generate_secret_creds_key_and_iv_exact_lengths():
    creds_key = common.generate_secret("CREDS_KEY")
    creds_iv = common.generate_secret("CREDS_IV")
    assert len(bytes.fromhex(creds_key)) == 32
    assert len(bytes.fromhex(creds_iv)) == 16


def test_env_file_round_trip_preserves_comments(tmp_path):
    template = tmp_path / "template.env"
    template.write_text("# a comment\nFOO=bar\n\nBAZ=qux\n", encoding="utf-8")

    out = tmp_path / "out.env"
    common.write_env_file(out, {"FOO": "bar", "BAZ": "changed"}, template_path=template)
    content = out.read_text(encoding="utf-8")
    assert "# a comment" in content
    assert "FOO=bar" in content
    assert "BAZ=changed" in content

    # A second write with identical values produces byte-identical output.
    before = out.read_text(encoding="utf-8")
    common.write_env_file(out, {"FOO": "bar", "BAZ": "changed"}, template_path=template)
    after = out.read_text(encoding="utf-8")
    assert before == after


def test_write_env_file_appends_keys_missing_from_template(tmp_path):
    template = tmp_path / "template.env"
    template.write_text("FOO=bar\n", encoding="utf-8")
    out = tmp_path / "out.env"
    common.write_env_file(out, {"FOO": "bar", "NEW_KEY": "value"}, template_path=template)
    content = out.read_text(encoding="utf-8")
    assert "NEW_KEY=value" in content


def test_atomic_write_replaces_stray_directory(tmp_path):
    # Reproduces Docker's bind-mount auto-vivification: a container with
    # `restart: unless-stopped` recreates its host bind-mount source as an
    # empty directory if the source file is missing at (re)start time.
    target = tmp_path / ".env"
    target.mkdir()
    (target / "leftover").write_text("stray", encoding="utf-8")

    common.atomic_write(target, "FOO=bar\n")

    assert target.is_file()
    assert target.read_text(encoding="utf-8") == "FOO=bar\n"


def test_ensure_dir_creates_nested_path(tmp_path):
    target = tmp_path / "a" / "b" / "c"
    common.ensure_dir(target)
    assert target.is_dir()
    common.ensure_dir(target)  # already exists -- idempotent, no error
    assert target.is_dir()


class _FlakyPath:
    """Mimics the WSL2 DrvFs race: the first mkdir() spuriously raises
    FileExistsError while is_dir() still (also spuriously) reports False,
    then both settle to the true state on the next attempt."""

    def __init__(self):
        self.mkdir_calls = 0
        self.is_dir_calls = 0

    def mkdir(self, parents=True, exist_ok=True):
        self.mkdir_calls += 1
        if self.mkdir_calls == 1:
            raise FileExistsError(17, "File exists")

    def is_dir(self):
        self.is_dir_calls += 1
        return self.is_dir_calls > 1


class _AlwaysConflictingPath:
    """A genuine conflict (e.g. a file occupies the target path) -- mkdir
    always raises and is_dir() never becomes true."""

    def mkdir(self, parents=True, exist_ok=True):
        raise FileExistsError(17, "File exists")

    def is_dir(self):
        return False


def test_ensure_dir_retries_through_transient_race(monkeypatch):
    monkeypatch.setattr(common.time, "sleep", lambda _: None)
    fake = _FlakyPath()
    common.ensure_dir(fake)
    assert fake.mkdir_calls == 2


def test_ensure_dir_reraises_on_genuine_conflict(monkeypatch):
    monkeypatch.setattr(common.time, "sleep", lambda _: None)
    with pytest.raises(FileExistsError):
        common.ensure_dir(_AlwaysConflictingPath())
