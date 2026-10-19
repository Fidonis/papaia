"""Consistency of the mail relay module, read from the real checkout.

The module's names cross the compose file, its .env.example, `lib/smtp.py` and the
add-on contract. Most of what the compose file says is the result of running the
image (see the comments there), so the facts that keep it working are pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from lib import common, compat, smtp

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "smtp-relay"

# Variables docker compose takes from the root .env, not from the module's own.
PLATFORM_VARS = {"PAPAIA_CONFIG_DIR"}


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def _service() -> dict:
    return _compose()["services"]["smtp-relay"]


def _code() -> str:
    """The compose file without comments, whose own header explains the `${VAR}` syntax."""
    return "\n".join(
        re.sub(r"\s#.*$", "", line)
        for line in (MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def _seconds(value: str) -> int:
    return int(value.rstrip("s"))


def test_the_root_compose_includes_the_module_under_the_smtp_profile():
    services = compat.resolve_core_services(REPO)

    assert services["smtp-relay"] == ["smtp"]


def test_the_module_is_one_service_in_the_papaia_network_with_its_labels():
    compose = _compose()
    service = _service()

    assert set(compose["services"]) == {"smtp-relay"}
    assert service["profiles"] == ["smtp"]
    assert service["networks"] == ["papaia-net"]
    assert service["labels"]["de.fidonis.module"] == "papaia-smtp-relay"
    assert service["labels"]["de.fidonis.role"] == "mail-relay"
    assert smtp.SERVICE == "smtp-relay"


def test_no_port_is_published_or_exposed():
    service = _service()

    assert "ports" not in service
    assert "expose" not in service


def test_nothing_depends_on_anything_so_the_profile_stays_independent_of_keycloak():
    assert "depends_on" not in _service()


def test_the_image_is_pinned_to_an_exact_tag_and_listed_with_its_license():
    image = _service()["image"]
    repository, _, tag = image.rpartition(":")

    assert tag and tag != "latest"
    assert re.fullmatch(r"\d+\.\d+\.\d+-alpine", tag), "the Alpine variant, pinned to a release"
    assert f"`{repository}`" in (REPO / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")


def test_the_upstream_password_is_a_read_only_file_that_is_never_created_by_docker():
    mounts = [v for v in _service()["volumes"] if isinstance(v, dict)]
    (password,) = [m for m in mounts if m["target"] == "/run/secrets/upstream-password"]

    assert password["type"] == "bind"
    assert password["read_only"] is True
    assert password["bind"]["create_host_path"] is False
    relative = f"{smtp.MODULE_DIR}/{smtp.PASSWORD_FILE}"
    assert password["source"] == "${PAPAIA_CONFIG_DIR}/" + relative


def test_the_password_is_never_an_environment_value():
    environment = _service()["environment"]

    assert environment["RELAYHOST_PASSWORD_FILE"] == "/run/secrets/upstream-password"
    assert "RELAYHOST_PASSWORD" not in environment
    assert [k for k in environment if "PASSWORD" in k and k != "RELAYHOST_PASSWORD_FILE"] == [
        "SMTP_RELAY_PASSWORD_REV"
    ]


def test_a_changed_password_recreates_the_container():
    # The file is read once at start, and Compose only recreates on a changed config hash.
    environment = _service()["environment"]

    assert "${SMTP_RELAY_PASSWORD_REV" in environment["SMTP_RELAY_PASSWORD_REV"]


def test_the_generated_configuration_lives_on_tmpfs_so_a_new_password_wins():
    # On a volume that survives a recreated container the image appends the new password
    # next to the old one, Postfix keeps the first, and mail queues as "SASL authentication
    # failed". A tmpfs starts clean on every start.
    tmpfs = [entry.split(":")[0] for entry in _service()["tmpfs"]]

    assert "/etc/postfix" in tmpfs
    assert "/etc/opendkim/keys" in tmpfs


def test_the_queue_survives_a_recreated_container():
    volumes = [v for v in _service()["volumes"] if isinstance(v, str)]

    assert "smtp-relay-queue:/var/spool/postfix" in volumes
    assert "smtp-relay-queue" in _compose()["volumes"]


def test_the_healthcheck_asks_for_a_listener_and_never_touches_the_upstream():
    check = _service()["healthcheck"]
    command = " ".join(check["test"])

    # Port 587 is 0x024B, LISTEN is state 0A.
    assert "024B" in command and "/proc/net/tcp" in command
    assert "SMTP_RELAY" not in command and "nc " not in command and "postfix status" not in command
    assert _seconds(check["start_period"]) >= 60, "slow hosts need time to start Postfix"
    assert _seconds(check["timeout"]) <= _seconds(check["interval"])
    assert check["retries"] >= 3
    assert "start_interval" not in check, "needs a newer Compose than the documented minimum"


def test_the_relay_is_hardened_as_far_as_the_image_allows():
    service = _service()

    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["cap_drop"] == ["ALL"]
    assert sorted(service["cap_add"]) == sorted(
        ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL", "NET_BIND_SERVICE"]
    )
    # The image changes the mode of its own scripts at start, so the root file system
    # has to stay writable.
    assert not service.get("read_only")


def test_without_configuration_the_relay_cannot_deliver_anywhere():
    environment = _service()["environment"]

    assert ".invalid" in environment["RELAYHOST"], "no host: never deliver directly"
    assert ".invalid" in environment["ALLOWED_SENDER_DOMAINS"]


def test_clients_are_limited_to_the_private_ranges_by_default():
    mynetworks = _service()["environment"]["POSTFIX_mynetworks"]

    assert "127.0.0.0/8" in mynetworks and "172.16.0.0/12" in mynetworks
    assert "0.0.0.0/0" not in mynetworks


def test_every_variable_has_a_default_and_is_documented():
    used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", _code()))
    documented = set(common.parse_env_file(MODULE_DIR / ".env.example"))
    for line in (MODULE_DIR / ".env.example").read_text(encoding="utf-8").splitlines():
        match = re.match(r"#\s*([A-Z][A-Z0-9_]*)=", line)
        if match:
            documented.add(match.group(1))

    assert used - PLATFORM_VARS <= documented
    for name in used - PLATFORM_VARS:
        assert re.search(rf"\$\{{{name}:-", _code()), f"{name} needs a default"
    assert "PAPAIA_CONFIG_DIR" in common.parse_env_file(REPO / "src" / ".env.example")


def test_the_example_env_matches_the_keys_and_defaults_of_the_helper():
    example = common.parse_env_file(MODULE_DIR / ".env.example")

    assert set(example) == {
        smtp.KEY_HOST,
        smtp.KEY_PORT,
        smtp.KEY_SECURITY,
        smtp.KEY_USER,
        smtp.KEY_FROM,
        smtp.KEY_FROM_NAME,
        smtp.KEY_SENDER_DOMAINS,
        smtp.KEY_TLS_LEVEL,
        smtp.KEY_TLS_WRAPPER,
        smtp.KEY_PASSWORD_REV,
    }
    assert example[smtp.KEY_HOST] == "", "empty means not configured"
    assert example[smtp.KEY_FROM] == ""
    assert example[smtp.KEY_SECURITY] == "starttls"
    assert example[smtp.KEY_PORT] == str(smtp.DEFAULT_PORTS["starttls"])
    derived = smtp.derived_keys("starttls", "noreply@example.org")
    assert example[smtp.KEY_TLS_LEVEL] == derived[smtp.KEY_TLS_LEVEL]
    assert example[smtp.KEY_TLS_WRAPPER] == derived[smtp.KEY_TLS_WRAPPER]


def test_the_example_env_holds_no_secret_and_no_unconfigured_marker():
    text = (MODULE_DIR / ".env.example").read_text(encoding="utf-8")

    assert "GENERATE_" not in text and "CHANGE_ME" not in text
    assert "PASSWORD=" not in re.sub(r"SMTP_RELAY_PASSWORD_REV=", "", text)


def test_the_consumer_contract_is_what_the_realm_block_and_the_docs_name():
    assert (smtp.RELAY_HOST, smtp.RELAY_PORT) == ("smtp-relay", 587)
    block = smtp.realm_smtp_server(smtp.Settings(profile_on=True, host="h", from_address="a@b.c"))
    assert (block["host"], block["port"]) == ("smtp-relay", "587")
