"""The `smtp` choice in `papaia-ctl setup`: the toggle, the stored relay settings, the
password file, the sticky re-run, and the CLI path from flags to the stored environment
and the rendered Keycloak realm."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from lib import cli, common, defaults, envtree, reporting, resolve, smtp

REAL_REPO = Path(__file__).resolve().parents[2]
PASSWORD = "p@ss$w0rd#\"'\\x with space"


@pytest.fixture(autouse=True)
def _module(repo_root):
    """The real module's .env.example in the synthetic checkout, so the test follows the
    keys the module ships. Other tests of the fixture repo are unaffected."""
    target = repo_root / "src" / "infra" / "smtp-relay"
    target.mkdir(parents=True)
    shutil.copy(REAL_REPO / "src/infra/smtp-relay/.env.example", target / ".env.example")


@pytest.fixture(autouse=True)
def _no_password_in_the_environment(monkeypatch):
    monkeypatch.delenv("PAPAIA_SMTP_PASSWORD", raising=False)


def _args(config_dir, **kwargs) -> resolve.SetupArgs:
    kwargs.setdefault("non_interactive", True)
    return resolve.SetupArgs(config_dir=config_dir, **kwargs)


def _tree(repo_root, profiles="keycloak,librechat") -> dict:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    tree[""]["COMPOSE_PROFILES"] = profiles
    return tree


def _on(config_dir, **kwargs) -> resolve.SetupArgs:
    values = {
        "enable_smtp": True,
        "smtp_host": "smtp.example.org",
        "smtp_from": "noreply@example.org",
        "smtp_user": "mailer",
        "smtp_password": PASSWORD,
    }
    values.update(kwargs)
    return _args(config_dir, **values)


def _profiles(tree) -> list[str]:
    return [p for p in tree[""]["COMPOSE_PROFILES"].split(",") if p]


# ─────────────────────────────────────────────────────────────────────────
# resolve_smtp
# ─────────────────────────────────────────────────────────────────────────


def test_enabling_stores_the_settings_the_derived_keys_and_the_profile_once(repo_root, config_dir):
    tree = _tree(repo_root)

    tree = resolve.resolve_smtp(tree, _on(config_dir))
    tree = resolve.resolve_smtp(tree, _on(config_dir))

    module = tree[smtp.MODULE_DIR]
    assert module[smtp.KEY_HOST] == "smtp.example.org"
    assert module[smtp.KEY_PORT] == "587"
    assert module[smtp.KEY_SECURITY] == "starttls"
    assert module[smtp.KEY_USER] == "mailer"
    assert module[smtp.KEY_FROM] == "noreply@example.org"
    assert module[smtp.KEY_FROM_NAME] == "papAIa"
    assert module[smtp.KEY_SENDER_DOMAINS] == "example.org"
    assert module[smtp.KEY_TLS_LEVEL] == "verify"
    assert _profiles(tree) == ["keycloak", "librechat", "smtp"]


def test_the_password_goes_to_the_file_and_into_no_env_value(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))

    assert smtp.read_password(config_dir) == PASSWORD
    assert not any(PASSWORD in str(value) for values in tree.values() for value in values.values())


def test_without_a_flag_or_a_value_nothing_changes(repo_root, config_dir):
    tree = _tree(repo_root, "keycloak,smtp")
    before = {k: dict(v) for k, v in tree.items()}

    resolve.resolve_smtp(tree, _args(config_dir))

    assert tree == before
    assert not smtp.password_path(config_dir).exists()


def test_disabling_removes_only_the_profile_and_keeps_the_settings(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))

    tree = resolve.resolve_smtp(tree, _args(config_dir, enable_smtp=False))

    assert _profiles(tree) == ["keycloak", "librechat"]
    assert tree[smtp.MODULE_DIR][smtp.KEY_HOST] == "smtp.example.org"
    assert smtp.read_password(config_dir) == PASSWORD, "a later opt-in finds it ready"


def test_enabling_again_reuses_what_was_stored(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))
    tree = resolve.resolve_smtp(tree, _args(config_dir, enable_smtp=False))

    tree = resolve.resolve_smtp(tree, _args(config_dir, enable_smtp=True))

    assert "smtp" in _profiles(tree)
    assert tree[smtp.MODULE_DIR][smtp.KEY_USER] == "mailer"
    assert smtp.read_password(config_dir) == PASSWORD


def test_a_changed_password_raises_the_revision_and_an_unchanged_one_does_not(
    repo_root, config_dir
):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))
    first = tree[smtp.MODULE_DIR][smtp.KEY_PASSWORD_REV]

    tree = resolve.resolve_smtp(tree, _on(config_dir))  # the same password again
    assert tree[smtp.MODULE_DIR][smtp.KEY_PASSWORD_REV] == first

    tree = resolve.resolve_smtp(tree, _on(config_dir, smtp_password="another"))
    assert int(tree[smtp.MODULE_DIR][smtp.KEY_PASSWORD_REV]) == int(first) + 1


def test_changing_only_the_server_keeps_the_stored_password(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))
    revision = tree[smtp.MODULE_DIR][smtp.KEY_PASSWORD_REV]

    tree = resolve.resolve_smtp(
        tree, _args(config_dir, smtp_host="smtp2.example.org", smtp_password=None)
    )

    assert tree[smtp.MODULE_DIR][smtp.KEY_HOST] == "smtp2.example.org"
    assert smtp.read_password(config_dir) == PASSWORD
    assert tree[smtp.MODULE_DIR][smtp.KEY_PASSWORD_REV] == revision


def test_a_new_security_mode_without_a_port_takes_that_modes_default_port(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))
    assert tree[smtp.MODULE_DIR][smtp.KEY_PORT] == "587"

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_security="tls"))
    assert tree[smtp.MODULE_DIR][smtp.KEY_PORT] == "465"
    assert tree[smtp.MODULE_DIR][smtp.KEY_TLS_WRAPPER] == "yes"

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_security="tls", smtp_port="2465"))
    assert tree[smtp.MODULE_DIR][smtp.KEY_PORT] == "2465"


def test_a_stored_port_is_kept_while_the_mode_stays(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir, smtp_port="2525"))

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_from="other@example.org"))

    assert tree[smtp.MODULE_DIR][smtp.KEY_PORT] == "2525"
    assert tree[smtp.MODULE_DIR][smtp.KEY_FROM] == "other@example.org"


def test_no_login_drops_the_user_and_the_stored_password(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_no_auth=True))

    assert tree[smtp.MODULE_DIR][smtp.KEY_USER] == ""
    assert smtp.read_password(config_dir) == ""
    assert smtp.password_path(config_dir).is_file(), "the relay mounts the file"


def test_an_emptied_user_drops_the_stored_password_too(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_user=""))

    assert tree[smtp.MODULE_DIR][smtp.KEY_USER] == ""
    assert smtp.read_password(config_dir) == ""


def test_a_server_without_encryption_takes_no_login(repo_root, config_dir):
    tree = resolve.resolve_smtp(
        _tree(repo_root),
        _args(
            config_dir,
            enable_smtp=True,
            smtp_host="mailpit",
            smtp_port="1025",
            smtp_security="none",
            smtp_from="noreply@example.org",
            smtp_no_auth=True,
        ),
    )

    module = tree[smtp.MODULE_DIR]
    assert (module[smtp.KEY_SECURITY], module[smtp.KEY_PORT], module[smtp.KEY_USER]) == (
        "none",
        "1025",
        "",
    )
    assert module[smtp.KEY_TLS_LEVEL] == "none"


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"smtp_host": None}, "--smtp-host is required"),
        ({"smtp_from": None}, "--smtp-from is required"),
        ({"smtp_host": "smtp.example.org:587"}, "host name"),
        ({"smtp_port": "99999"}, "port"),
        ({"smtp_security": "ssl"}, "connection security"),
        ({"smtp_from": "not-an-address"}, "sender address"),
        ({"smtp_from_name": "Mail $1"}, "sender name"),
        ({"smtp_user": "a:b"}, "login"),
        ({"smtp_password": " leading"}, "may not start or end"),
        ({"smtp_password": None}, "needs its password"),
        ({"smtp_user": "", "smtp_password": "x"}, "needs a login"),
        ({"smtp_security": "none"}, "unencrypted"),
        ({"smtp_no_auth": True}, "cannot be combined"),
    ],
)
def test_an_unusable_value_is_refused_and_nothing_is_written(
    repo_root, config_dir, overrides, message
):
    tree = _tree(repo_root)
    before = {k: dict(v) for k, v in tree.items()}

    with pytest.raises(resolve.SetupError, match=message):
        resolve.resolve_smtp(tree, _on(config_dir, **overrides))

    assert tree == before
    assert not smtp.password_path(config_dir).exists()


def test_an_option_without_the_relay_is_refused(repo_root, config_dir):
    with pytest.raises(resolve.SetupError, match="--smtp"):
        resolve.resolve_smtp(_tree(repo_root), _args(config_dir, smtp_host="smtp.example.org"))


def test_an_option_is_accepted_once_the_relay_is_on(repo_root, config_dir):
    tree = resolve.resolve_smtp(_tree(repo_root), _on(config_dir))

    tree = resolve.resolve_smtp(tree, _args(config_dir, smtp_from_name="Example Mail"))

    assert tree[smtp.MODULE_DIR][smtp.KEY_FROM_NAME] == "Example Mail"


# ─────────────────────────────────────────────────────────────────────────
# defaults for the wizard
# ─────────────────────────────────────────────────────────────────────────


def _setup(repo_root, config_dir, *flags: str) -> int:
    return cli.main(
        [
            "--repo-root",
            str(repo_root),
            "--config-dir",
            str(config_dir),
            "setup",
            "--app-host=https://papaia.example.com",
            *flags,
        ]
    )


FLAGS = (
    "--enable-smtp=true",
    "--smtp-host=smtp.example.org",
    "--smtp-from=noreply@example.org",
    "--smtp-user=mailer",
)


def test_defaults_are_empty_before_the_config_dir_exists(repo_root, config_dir):
    got = defaults.compute_defaults(config_dir, repo_root)

    for key in ("SMTP_STICKY", "SMTP_HOST_STICKY", "SMTP_FROM_STICKY", "SMTP_SECURITY_STICKY"):
        assert got[key] == ""
    assert got["SMTP_PASSWORD_STORED"] == "false"


def test_defaults_do_not_offer_the_shipped_example_as_a_choice(repo_root, config_dir):
    assert _setup(repo_root, config_dir) == 0

    got = defaults.compute_defaults(config_dir, repo_root)
    assert got["SMTP_STICKY"] == "false"
    assert got["SMTP_HOST_STICKY"] == "", "the shipped port and mode are defaults, not choices"
    assert got["SMTP_PORT_STICKY"] == ""


def test_defaults_report_the_stored_choice_but_never_the_password(
    repo_root, config_dir, monkeypatch
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0

    got = defaults.compute_defaults(config_dir, repo_root)

    assert got["SMTP_STICKY"] == "true"
    assert got["SMTP_HOST_STICKY"] == "smtp.example.org"
    assert got["SMTP_PORT_STICKY"] == "587"
    assert got["SMTP_SECURITY_STICKY"] == "starttls"
    assert got["SMTP_USER_STICKY"] == "mailer"
    assert got["SMTP_FROM_STICKY"] == "noreply@example.org"
    assert got["SMTP_FROM_NAME_STICKY"] == "papAIa"
    assert got["SMTP_PASSWORD_STORED"] == "true"
    assert PASSWORD not in "".join(got.values())


# ─────────────────────────────────────────────────────────────────────────
# the CLI
# ─────────────────────────────────────────────────────────────────────────


def _module_env(config_dir) -> dict[str, str]:
    return common.parse_env_file(config_dir / smtp.MODULE_DIR / ".env")


def _realm(config_dir) -> dict:
    path = config_dir / "infra/keycloak/realm-import/papaia-realm.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_setup_flags_and_the_environment_reach_the_stored_configuration(
    repo_root, config_dir, monkeypatch, capsys
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)

    assert _setup(repo_root, config_dir, *FLAGS, "--smtp-from-name=Example Mail") == 0

    stored = common.parse_env_file(config_dir / ".env")
    assert "smtp" in stored["COMPOSE_PROFILES"].split(",")
    module = _module_env(config_dir)
    assert module[smtp.KEY_HOST] == "smtp.example.org"
    assert module[smtp.KEY_FROM_NAME] == "Example Mail"
    assert smtp.read_password(config_dir) == PASSWORD
    assert "PAPAIA_SMTP_PASSWORD" not in os.environ, "taken out so nothing inherits it"
    out = capsys.readouterr()
    assert "Mail relay enabled" in out.out
    assert "papaia-ctl doctor" in out.out


def test_the_password_appears_nowhere_but_in_its_file(repo_root, config_dir, monkeypatch, capsys):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0

    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err
    password_file = smtp.password_path(config_dir)
    for base in (config_dir, repo_root):
        for path in base.rglob("*"):
            if path.is_file() and path != password_file:
                assert PASSWORD not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_a_second_run_keeps_the_choice_the_credentials_and_the_revision(
    repo_root, config_dir, monkeypatch, capsys
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0
    revision = _module_env(config_dir)[smtp.KEY_PASSWORD_REV]
    capsys.readouterr()

    assert _setup(repo_root, config_dir) == 0  # no flags, no password

    assert "smtp" in common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"]
    assert _module_env(config_dir)[smtp.KEY_PASSWORD_REV] == revision
    assert smtp.read_password(config_dir) == PASSWORD
    assert "Mail relay enabled" not in capsys.readouterr().out, "no reminder for a re-run"


def test_confirming_an_enabled_relay_prints_no_reminder_but_a_new_opt_in_does(
    repo_root, config_dir, monkeypatch, capsys
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0
    capsys.readouterr()

    assert _setup(repo_root, config_dir, "--enable-smtp=true") == 0
    assert "Mail relay enabled" not in capsys.readouterr().out

    assert _setup(repo_root, config_dir, "--enable-smtp=false") == 0
    assert _setup(repo_root, config_dir, "--enable-smtp=true") == 0
    assert "Mail relay enabled" in capsys.readouterr().out


def test_turning_it_off_keeps_the_settings_and_the_password(repo_root, config_dir, monkeypatch):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0

    assert _setup(repo_root, config_dir, "--enable-smtp=false") == 0

    assert "smtp" not in common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"]
    assert _module_env(config_dir)[smtp.KEY_HOST] == "smtp.example.org"
    assert smtp.read_password(config_dir) == PASSWORD


def test_setup_refuses_with_exit_code_3_and_changes_nothing(repo_root, config_dir, capsys):
    code = _setup(repo_root, config_dir, "--enable-smtp=true", "--smtp-from=noreply@example.org")

    assert code == 3
    assert "--smtp-host is required" in capsys.readouterr().err
    assert not smtp.password_path(config_dir).exists()
    assert "smtp" not in common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"]


def test_a_login_without_a_password_is_refused_with_a_hint(repo_root, config_dir, capsys):
    assert _setup(repo_root, config_dir, *FLAGS) == 3

    assert "PAPAIA_SMTP_PASSWORD" in capsys.readouterr().err


def test_the_unsafe_combination_is_refused_before_anything_is_stored(
    repo_root, config_dir, monkeypatch, capsys
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)

    code = _setup(repo_root, config_dir, *FLAGS, "--smtp-security=none", "--smtp-port=1025")

    assert code == 3
    assert "unencrypted" in capsys.readouterr().err
    assert not smtp.password_path(config_dir).exists()


def test_the_relay_hint_names_the_next_steps_and_never_prints_a_secret(repo_root, config_dir):
    tree = {
        "": {"AUTH_PROVIDER": "internal_keycloak", "COMPOSE_PROFILES": "keycloak,smtp"},
        smtp.MODULE_DIR: {smtp.KEY_FROM: "noreply@example.org", smtp.KEY_USER: "mailer"},
    }
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        reporting.print_smtp_next_steps(tree)
    text = buffer.getvalue()

    assert "noreply@example.org" in text
    assert "papaia-ctl doctor" in text
    assert "mailer" not in text, "the login is not echoed"
    assert "retries for a day" in text


def test_the_setup_json_contract_is_untouched(repo_root, config_dir):
    assert _setup(repo_root, config_dir) == 0

    summary = json.loads((config_dir / "deployed.lock").read_text(encoding="utf-8"))
    assert "smtp" not in json.dumps(summary)


# ─────────────────────────────────────────────────────────────────────────
# the rendered realm
# ─────────────────────────────────────────────────────────────────────────


def test_a_setup_without_the_relay_renders_a_realm_without_a_mail_server(repo_root, config_dir):
    assert _setup(repo_root, config_dir) == 0

    realm = _realm(config_dir)
    assert "smtpServer" not in realm
    assert "resetPasswordAllowed" not in realm


def test_setup_renders_the_relay_block_into_the_realm(repo_root, config_dir, monkeypatch):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS, "--smtp-from-name=Café Mail") == 0

    realm = _realm(config_dir)
    assert realm["smtpServer"] == {
        "host": "smtp-relay",
        "port": "587",
        "from": "noreply@example.org",
        "fromDisplayName": "Café Mail",
        "auth": "false",
        "ssl": "false",
        "starttls": "false",
    }
    assert realm["resetPasswordAllowed"] is True


def test_turning_the_relay_off_removes_the_block_from_the_next_render(
    repo_root, config_dir, monkeypatch
):
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", PASSWORD)
    assert _setup(repo_root, config_dir, *FLAGS) == 0
    assert "smtpServer" in _realm(config_dir)

    assert _setup(repo_root, config_dir, "--enable-smtp=false") == 0

    assert "smtpServer" not in _realm(config_dir)
