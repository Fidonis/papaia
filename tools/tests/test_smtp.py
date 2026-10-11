"""The mail relay's configuration: validation, derived keys, the password file, the
Keycloak block, the queue parser and the probe `doctor` uses."""

from __future__ import annotations

import os
import smtplib
import socket
import threading

import pytest

from lib import smtp

# ─────────────────────────────────────────────────────────────────────────
# validation
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("host", ["smtp.example.org", "mail", "10.0.0.5", "a-b.c-d.example"])
def test_a_host_name_or_an_ipv4_address_is_accepted(host):
    assert smtp.validate_host(host) == host


@pytest.mark.parametrize(
    "host", ["", "  ", "smtp.example.org:587", "https://smtp.example.org", "-bad", "bad-", "a b"]
)
def test_a_host_with_a_scheme_a_port_or_a_space_is_refused(host):
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_host(host)


@pytest.mark.parametrize("value,port", [("587", 587), (" 25 ", 25), (465, 465), ("65535", 65535)])
def test_a_port_in_range_is_accepted(value, port):
    assert smtp.validate_port(value) == port


@pytest.mark.parametrize("value", ["", "0", "65536", "-1", "smtp", "58 7"])
def test_a_port_out_of_range_is_refused(value):
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_port(value)


def test_the_security_mode_is_one_of_three():
    assert smtp.validate_security(" TLS ") == "tls"
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_security("ssl")


@pytest.mark.parametrize(
    "address", ["noreply@example.org", "a.b+tag@mail.example.co.uk", "x_y@sub.example.de"]
)
def test_a_sender_address_is_accepted(address):
    assert smtp.validate_address(address) == address


@pytest.mark.parametrize(
    "address", ["", "noreply", "noreply@", "@example.org", "no reply@example.org", "a@b", "a@b..c"]
)
def test_a_malformed_sender_address_is_refused(address):
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_address(address)


@pytest.mark.parametrize("value", ["a$b", "a#b", 'a"b', "a'b", "a\\b", "a`b", "a\nb"])
def test_values_written_to_the_env_file_may_not_carry_characters_that_change_meaning(value):
    # Written unquoted to a .env file and read back by Compose: these would not survive.
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_display_name(value)
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_user(value)


def test_a_login_may_not_contain_a_colon():
    # SASL PLAIN is built as user:password and split at the first colon.
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_user("mail:er")
    assert smtp.validate_user("mailer@example.org") == "mailer@example.org"


def test_a_sender_name_with_spaces_and_accents_is_fine():
    assert smtp.validate_display_name("Café Mail 24") == "Café Mail 24"
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_display_name("x" * 81)


@pytest.mark.parametrize("password", ["p@ss$w0rd#\"'\\x", "with space inside", "co:lon:s", "ü€漢"])
def test_a_password_keeps_every_character_the_user_typed(password):
    assert smtp.validate_password(password) == password


@pytest.mark.parametrize("password", ["", " lead", "trail ", "a\nb", "a\rb", "a\x00b", "x" * 513])
def test_a_password_the_relay_could_not_send_unchanged_is_refused(password):
    with pytest.raises(smtp.SmtpConfigError):
        smtp.validate_password(password)


# ─────────────────────────────────────────────────────────────────────────
# derived keys
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "security,level,wrapper",
    [("starttls", "verify", "no"), ("tls", "verify", "yes"), ("none", "none", "no")],
)
def test_the_tls_keys_follow_the_security_mode(security, level, wrapper):
    keys = smtp.derived_keys(security, "noreply@example.org")

    assert keys[smtp.KEY_TLS_LEVEL] == level
    assert keys[smtp.KEY_TLS_WRAPPER] == wrapper


def test_the_sender_domain_is_the_lower_cased_domain_of_the_address():
    assert smtp.derived_keys("starttls", "NoReply@Example.ORG")[smtp.KEY_SENDER_DOMAINS] == (
        "example.org"
    )


# ─────────────────────────────────────────────────────────────────────────
# the password file
# ─────────────────────────────────────────────────────────────────────────


def test_the_password_is_stored_byte_for_byte(tmp_path):
    password = "p@ss$w0rd#\"'\\x with space"

    smtp.write_password(tmp_path, password)

    assert smtp.password_path(tmp_path).read_bytes() == password.encode("utf-8")
    assert smtp.read_password(tmp_path) == password


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_the_password_file_is_private(tmp_path):
    smtp.write_password(tmp_path, "secret")

    assert smtp.password_path(tmp_path).stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_rewriting_the_password_keeps_the_file_private(tmp_path):
    smtp.write_password(tmp_path, "one")
    smtp.password_path(tmp_path).chmod(0o644)

    smtp.write_password(tmp_path, "two")

    assert smtp.password_path(tmp_path).stat().st_mode & 0o777 == 0o600


def test_write_password_reports_whether_it_changed(tmp_path):
    assert smtp.write_password(tmp_path, "") is False, "a missing file holds the empty password"
    assert smtp.password_path(tmp_path).is_file(), "the relay mounts the file, so it must exist"
    assert smtp.write_password(tmp_path, "secret") is True
    assert smtp.write_password(tmp_path, "secret") is False
    assert smtp.write_password(tmp_path, "other") is True
    assert smtp.write_password(tmp_path, "") is True
    assert smtp.read_password(tmp_path) == ""


def test_a_missing_password_reads_as_empty(tmp_path):
    assert smtp.read_password(tmp_path) == ""


# ─────────────────────────────────────────────────────────────────────────
# settings and the Keycloak block
# ─────────────────────────────────────────────────────────────────────────

MODULE_ENV = {
    smtp.KEY_HOST: "smtp.example.org",
    smtp.KEY_PORT: "465",
    smtp.KEY_SECURITY: "tls",
    smtp.KEY_USER: "mailer",
    smtp.KEY_FROM: "noreply@example.org",
    smtp.KEY_FROM_NAME: "Example Mail",
}


def test_settings_are_read_from_the_module_env_and_the_profile_list():
    settings = smtp.Settings.from_env({"COMPOSE_PROFILES": "keycloak, smtp"}, MODULE_ENV)

    assert settings.profile_on and settings.configured and settings.active
    assert (settings.host, settings.port, settings.security) == ("smtp.example.org", 465, "tls")
    assert (settings.user, settings.from_address, settings.from_name) == (
        "mailer",
        "noreply@example.org",
        "Example Mail",
    )


def test_a_relay_that_is_on_but_unconfigured_is_not_active():
    settings = smtp.Settings.from_env({"COMPOSE_PROFILES": "smtp"}, {smtp.KEY_PORT: "587"})

    assert settings.profile_on and not settings.configured and not settings.active


def test_a_configured_relay_with_the_profile_off_is_not_active():
    settings = smtp.Settings.from_env({"COMPOSE_PROFILES": "keycloak"}, MODULE_ENV)

    assert settings.configured and not settings.active


def test_unknown_values_fall_back_to_defaults():
    settings = smtp.Settings.from_env(
        {}, {smtp.KEY_SECURITY: "ssl", smtp.KEY_PORT: "abc", smtp.KEY_FROM_NAME: ""}
    )

    assert settings.security == "starttls"
    assert settings.port is None
    assert settings.from_name == smtp.DEFAULT_FROM_NAME


def test_load_reads_the_config_dir(tmp_path):
    (tmp_path / "infra" / "smtp-relay").mkdir(parents=True)
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=smtp\n", encoding="utf-8")
    (tmp_path / "infra" / "smtp-relay" / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in MODULE_ENV.items()), encoding="utf-8"
    )

    assert smtp.Settings.load(tmp_path).active
    assert not smtp.Settings.load(tmp_path / "missing").profile_on


def test_the_realm_block_points_at_the_relay_and_carries_no_credentials():
    settings = smtp.Settings.from_env({"COMPOSE_PROFILES": "smtp"}, MODULE_ENV)

    assert smtp.realm_smtp_server(settings) == {
        "host": "smtp-relay",
        "port": "587",
        "from": "noreply@example.org",
        "fromDisplayName": "Example Mail",
        "auth": "false",
        "ssl": "false",
        "starttls": "false",
    }


# ─────────────────────────────────────────────────────────────────────────
# the queue listing
# ─────────────────────────────────────────────────────────────────────────


def test_an_empty_queue_is_zero():
    assert smtp.parse_queue_count("Mail queue is empty\n") == 0


def test_the_request_count_of_a_listing_is_the_queue_size():
    listing = (
        "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n"
        "082E0140BBF*    349 Sun Oct 11 12:42:51  noreply@example.org\n"
        "                                         a@example.com\n"
        "\n"
        "-- 1 Kbytes in 2 Requests.\n"
    )
    assert smtp.parse_queue_count(listing) == 2
    assert smtp.parse_queue_count("-- 0 Kbytes in 1 Request.\n") == 1


@pytest.mark.parametrize("text", ["", "postqueue: fatal: Queue report unavailable", "garbage"])
def test_an_unknown_listing_is_none(text):
    assert smtp.parse_queue_count(text) is None


# ─────────────────────────────────────────────────────────────────────────
# the probe
# ─────────────────────────────────────────────────────────────────────────


class _MiniServer:
    """A one-connection SMTP server on a local socket: greets, answers EHLO with the
    given extension lines, QUIT with 221, and remembers every command it was sent."""

    def __init__(self, extensions=()):
        self.commands: list[str] = []
        self._extensions = list(extensions)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _ = self._sock.accept()
        with conn, conn.makefile("rwb") as stream:
            stream.write(b"220 test ESMTP\r\n")
            stream.flush()
            for raw in stream:
                line = raw.decode("ascii", "replace").strip()
                self.commands.append(line)
                verb = line.split(" ", 1)[0].upper()
                if verb == "EHLO":
                    lines = ["test", *self._extensions]
                    for index, text in enumerate(lines):
                        sep = " " if index == len(lines) - 1 else "-"
                        stream.write(f"250{sep}{text}\r\n".encode())
                elif verb == "QUIT":
                    stream.write(b"221 bye\r\n")
                    stream.flush()
                    return
                else:
                    stream.write(b"502 not implemented\r\n")
                stream.flush()

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def mini_server():
    servers: list[_MiniServer] = []

    def make(*extensions: str) -> _MiniServer:
        server = _MiniServer(extensions)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def test_a_plain_server_is_reachable_and_no_login_is_attempted(mini_server):
    server = mini_server("AUTH PLAIN LOGIN")

    result = smtp.probe_upstream("127.0.0.1", server.port, "none", "mailer", "pw", True, 5)

    assert result.ok and result.stage == "ok"
    assert result.login == "not needed", "a login is never sent over an unencrypted connection"
    assert not any(command.upper().startswith("AUTH") for command in server.commands)
    assert any(command.upper().startswith("EHLO") for command in server.commands)


def test_a_server_without_starttls_is_reported_at_that_stage(mini_server):
    server = mini_server("SIZE 1000")

    result = smtp.probe_upstream("127.0.0.1", server.port, "starttls", "", "", True, 5)

    assert not result.ok
    assert result.stage == "starttls"
    assert "does not offer" in result.reason


def test_a_closed_port_is_reported_as_a_connect_failure():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    result = smtp.probe_upstream("127.0.0.1", port, "none", "", "", True, 2)

    assert not result.ok
    assert result.stage == "connect"


class _FakeSMTP:
    """Stands in for smtplib.SMTP / SMTP_SSL: no network, scripted outcomes."""

    login_error: Exception | None = None
    starttls_error: Exception | None = None
    connect_error: Exception | None = None
    instances: list[_FakeSMTP] = []

    def __init__(self, host, port, timeout=None, context=None):
        if type(self).connect_error is not None:
            raise type(self).connect_error
        self.events: list[str] = []
        self.context = context
        type(self).instances.append(self)

    def ehlo(self):
        self.events.append("ehlo")

    def starttls(self, context=None):
        if type(self).starttls_error is not None:
            raise type(self).starttls_error
        self.events.append("starttls")

    def login(self, user, password):
        if type(self).login_error is not None:
            raise type(self).login_error
        self.events.append(f"login:{user}:{password}")

    def close(self):
        self.events.append("close")


@pytest.fixture
def fake_smtp(monkeypatch):
    class Fake(_FakeSMTP):
        login_error = None
        starttls_error = None
        connect_error = None
        instances: list = []

    monkeypatch.setattr(smtplib, "SMTP", Fake)
    monkeypatch.setattr(smtplib, "SMTP_SSL", Fake)
    return Fake


def test_starttls_then_a_login_is_reachable(fake_smtp):
    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "mailer", "pw")

    assert (result.ok, result.stage, result.login) == (True, "ok", "ok")
    assert fake_smtp.instances[0].events == ["ehlo", "starttls", "ehlo", "login:mailer:pw", "close"]


def test_implicit_tls_logs_in_without_starttls(fake_smtp):
    result = smtp.probe_upstream("smtp.example.org", 465, "tls", "mailer", "pw")

    assert result.ok and result.login == "ok"
    assert "starttls" not in fake_smtp.instances[0].events


def test_the_login_can_be_left_out(fake_smtp):
    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "mailer", "pw", False)

    assert result.ok and result.login == "not tested"
    assert not any(e.startswith("login") for e in fake_smtp.instances[0].events)


def test_a_server_that_needs_no_login_is_reachable_without_one(fake_smtp):
    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "", "")

    assert result.ok and result.login == "not needed"


def test_a_refused_login_is_reported_at_the_auth_stage_without_the_password(fake_smtp):
    fake_smtp.login_error = smtplib.SMTPAuthenticationError(535, b"5.7.8 credentials invalid")

    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "mailer", "hunter2")

    assert not result.ok and result.stage == "auth"
    assert "login refused" in result.reason and "535" in result.reason
    assert "hunter2" not in result.reason


def test_a_tls_error_is_reported_with_its_stage(fake_smtp):
    import ssl

    fake_smtp.starttls_error = ssl.SSLCertVerificationError("certificate verify failed")

    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "mailer", "pw")

    assert not result.ok and result.stage == "starttls"
    assert "TLS handshake failed" in result.reason


def test_a_name_that_does_not_resolve_is_reported_as_such(fake_smtp):
    fake_smtp.connect_error = socket.gaierror(-2, "Name or service not known")

    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "", "")

    assert not result.ok and result.stage == "resolve"
    assert "smtp.example.org" in result.reason


def test_a_timeout_is_a_connect_failure(fake_smtp):
    fake_smtp.connect_error = TimeoutError("timed out")

    result = smtp.probe_upstream("smtp.example.org", 587, "starttls", "", "")

    assert not result.ok and result.stage == "connect"
    assert "timed out" in result.reason
