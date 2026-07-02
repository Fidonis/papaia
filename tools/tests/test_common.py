from __future__ import annotations

import base64

from lib import common


def test_is_secret_key_matches_known_secrets():
    for key in [
        "OAUTH2_PROXY_CLIENT_SECRET",
        "OAUTH2_PROXY_COOKIE_SECRET",
        "KC_LIBRECHAT_CLIENT_SECRET",
        "CREDS_KEY",
        "JWT_SECRET",
        "MEILI_MASTER_KEY",
        "LITELLM_API_KEY",
        "KC_DB_PASSWORD",
    ]:
        assert common.is_secret_key(key), key


def test_is_secret_key_no_false_positives():
    for key in ["OPENID_CLIENT_ID", "GENERIC_CLIENT_ID", "PAPAIA_HOST", "COMPOSE_PROFILES"]:
        assert not common.is_secret_key(key), key


def test_is_placeholder():
    assert common.is_placeholder("")
    assert common.is_placeholder("GENERATE_FOO")
    assert not common.is_placeholder("already-set-value")


def test_generate_secret_default_is_24_byte_hex():
    value = common.generate_secret("SOME_RANDOM_SECRET")
    assert len(value) == 48
    int(value, 16)  # raises if not valid hex


def test_generate_secret_cookie_secret_is_32_byte_base64():
    value = common.generate_secret("OAUTH2_PROXY_COOKIE_SECRET")
    decoded = base64.b64decode(value)
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
