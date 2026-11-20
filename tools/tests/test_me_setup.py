"""The `me` choice in `papaia-ctl setup`: the toggle, the public URL of the personal area,
the wizard defaults, the proxy host and the CLI path from flags to the stored environment."""

from __future__ import annotations

import pytest

from lib import cli, common, defaults, envtree, npm_provision, reporting, resolve


def _args(repo_root, **kwargs) -> resolve.SetupArgs:
    kwargs.setdefault("non_interactive", True)
    return resolve.SetupArgs(config_dir=repo_root, **kwargs)


def _tree(repo_root, host="https://papaia.example.com") -> dict:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = host
    return tree


@pytest.mark.parametrize(
    "app_host,url",
    [
        ("http://host.docker.internal", "http://host.docker.internal:8130"),
        ("https://papaia.example.com", "https://papaia.example.com:8130"),
    ],
)
def test_the_url_default_appends_the_published_port_to_the_app_host(app_host, url):
    assert resolve.derive_me_url_default(app_host, "8130") == url


def test_the_url_is_derived_and_stored_while_the_profile_is_off(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat"
    tree[""]["ME_EXT_PORT"] = "18130"

    tree = resolve.resolve_me_hosts(tree, _args(repo_root))

    assert tree[""]["ME_PUBLIC_URL"] == "https://papaia.example.com:18130"
    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat"


def test_the_flag_wins_over_a_stored_value_and_a_stored_value_is_kept(repo_root):
    tree = _tree(repo_root)
    tree[""]["ME_PUBLIC_URL"] = "https://me.example.com"

    kept = resolve.resolve_me_hosts(tree, _args(repo_root, fresh_init=False))
    assert kept[""]["ME_PUBLIC_URL"] == "https://me.example.com"

    flagged = resolve.resolve_me_hosts(
        tree, _args(repo_root, fresh_init=False, me_host="https://mine.example.com")
    )
    assert flagged[""]["ME_PUBLIC_URL"] == "https://mine.example.com"


def test_a_prompt_gets_the_default_and_its_answer_wins(repo_root):
    asked = []

    def prompt(question, default):
        asked.append((question, default))
        return "https://me.example.com"

    tree = resolve.resolve_me_hosts(
        _tree(repo_root), _args(repo_root, non_interactive=False, prompt=prompt)
    )

    assert asked == [
        ("Public URL of the personal area (ME_PUBLIC_URL)", "https://papaia.example.com:8130")
    ]
    assert tree[""]["ME_PUBLIC_URL"] == "https://me.example.com"


@pytest.mark.parametrize(
    "before,flag,after",
    [
        ("keycloak,librechat", True, "keycloak,librechat,me"),
        ("keycloak,me,librechat", True, "keycloak,librechat,me"),
        ("keycloak,me,librechat", False, "keycloak,librechat"),
        ("keycloak,me", None, "keycloak,me"),
    ],
)
def test_the_toggle_adds_or_removes_only_the_profile(repo_root, before, flag, after):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = before

    tree = resolve.resolve_me(tree, _args(repo_root, enable_me=flag))

    assert tree[""]["COMPOSE_PROFILES"] == after


def test_defaults_report_the_stored_choice_for_the_wizard(repo_root, config_dir):
    assert defaults.compute_defaults(config_dir, repo_root)["ME_STICKY"] == ""
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,me"
    tree[""]["ME_PUBLIC_URL"] = "https://me.example.com"
    envtree.persist_tree(tree, config_dir, repo_root)

    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["ME_STICKY"] == "true"
    assert out["ME_HOST_STICKY"] == "https://me.example.com"
    assert out["ME_EXT_PORT"] == "8130"


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


def test_setup_flags_reach_the_stored_environment_and_print_the_next_steps(
    repo_root, config_dir, capsys
):
    code = _setup(repo_root, config_dir, "--enable-me=true", "--me-host=https://me.example.com")

    assert code == 0
    stored = common.parse_env_file(config_dir / ".env")
    assert "me" in stored["COMPOSE_PROFILES"].split(",")
    assert stored["ME_PUBLIC_URL"] == "https://me.example.com"
    out = capsys.readouterr().out
    assert "Personal area enabled" in out
    assert "personal-settings/registry.yaml" in out

    capsys.readouterr()
    assert _setup(repo_root, config_dir) == 0
    assert "me" in common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"].split(",")
    assert "Personal area enabled" not in capsys.readouterr().out, "the hint is for the switch-on"


def test_setup_without_the_flag_leaves_the_profile_off(repo_root, config_dir):
    assert _setup(repo_root, config_dir) == 0
    stored = common.parse_env_file(config_dir / ".env")
    assert "me" not in stored["COMPOSE_PROFILES"].split(",")
    assert stored["ME_PUBLIC_URL"] == "https://papaia.example.com:8130"


def test_the_external_oidc_checklist_names_the_client_only_with_the_profile(repo_root, capsys):
    tree = _tree(repo_root)
    tree[""]["ME_PUBLIC_URL"] = "https://me.example.com"
    tree[""]["COMPOSE_PROFILES"] = "librechat"
    reporting.print_external_oidc_checklist(repo_root, tree)
    assert "papaia-me" not in capsys.readouterr().out

    tree[""]["COMPOSE_PROFILES"] = "librechat,me"
    reporting.print_external_oidc_checklist(repo_root, tree)
    out = capsys.readouterr().out
    assert "papaia-me" in out
    assert "token exchange" in out
    assert "https://me.example.com" in out


def test_the_proxy_host_of_the_area_follows_its_profile():
    specs = {spec[0]: spec for spec in npm_provision._PROXY_HOST_SPECS}
    assert specs["me"][1:6] == ("", "ME_PUBLIC_URL", "me-web", 8000, "http")


def test_the_link_for_other_modules_is_set_only_while_the_area_runs(repo_root, config_dir):
    _setup(repo_root, config_dir, "--enable-me=true", "--me-host=https://me.example.com")
    assert common.parse_env_file(config_dir / ".env")["PERSONAL_SETTINGS_URL"] == (
        "https://me.example.com"
    )
    _setup(repo_root, config_dir, "--enable-me=false")
    stored = common.parse_env_file(config_dir / ".env")
    assert stored["PERSONAL_SETTINGS_URL"] == ""
    assert stored["ME_PUBLIC_URL"] == "https://me.example.com", "the URL itself stays"


def test_the_manager_receives_the_link_to_the_area():
    from pathlib import Path

    import yaml

    compose = Path(__file__).resolve().parents[2] / "src" / "manager" / "docker-compose.yml"
    env = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]["papaia-manager"][
        "environment"
    ]
    assert env["MANAGER_PERSONAL_SETTINGS_URL"] == "${PERSONAL_SETTINGS_URL:-}"


def test_the_area_follows_the_platform_profile_and_trusts_the_module_ca_folder():
    """Module calls (contract "Transport"): no plain http under kritis, and the public CA
    files of the modules lie next to the registry, mounted read-only."""
    from pathlib import Path

    import yaml

    compose = Path(__file__).resolve().parents[2] / "src" / "infra" / "me" / "docker-compose.yml"
    service = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]["me-web"]
    env = service["environment"]
    assert env["PAPAIA_SECURITY_PROFILE"] == "${PAPAIA_SECURITY_PROFILE:-standard}"
    assert env["ME_MODULE_CA_DIR"] == "/registry/module-ca"
    assert env["SSL_CERT_FILE"] == "/certs/local-ca.crt"
    assert "${PAPAIA_CONFIG_DIR}/personal-settings:/registry:ro" in service["volumes"]
