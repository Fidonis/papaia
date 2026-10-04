"""The `rag` choice in `papaia-ctl setup`: the toggle, the two URLs, the add-on
guard, and the CLI path from flags to the stored environment."""

from __future__ import annotations

import json

import pytest
import yaml

from lib import cli, defaults, envtree, reporting, resolve


def _args(repo_root, **kwargs) -> resolve.SetupArgs:
    kwargs.setdefault("non_interactive", True)
    return resolve.SetupArgs(config_dir=repo_root, **kwargs)


def _tree(repo_root, host="https://papaia.example.com") -> dict:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = host
    return tree


@pytest.mark.parametrize(
    "app_host,qdrant,ingest",
    [
        ("http://host.docker.internal", "http://host.docker.internal:6333", "http://host.docker.internal:8300"),
        ("http://192.168.1.50", "http://192.168.1.50:6333", "http://192.168.1.50:8300"),
        ("https://papaia.example.com", "https://papaia.example.com:6333", "https://papaia.example.com:8300"),
    ],
)
def test_url_defaults_append_the_published_port_to_the_app_host(app_host, qdrant, ingest):
    assert resolve.derive_qdrant_url_default(app_host, "6333") == qdrant
    assert resolve.derive_qdrant_ingest_url_default(app_host, "8300") == ingest


def test_hosts_are_derived_from_the_app_host_and_the_stored_ports(repo_root):
    tree = _tree(repo_root)
    tree[""]["QDRANT_INGEST_EXT_PORT"] = "18300"

    tree = resolve.resolve_rag_hosts(tree, _args(repo_root))

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://papaia.example.com:6333"
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"] == "https://papaia.example.com:18300"


def test_hosts_are_stored_while_the_profile_is_off(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat"

    tree = resolve.resolve_rag_hosts(tree, _args(repo_root, enable_rag=False))

    assert tree[""]["QDRANT_PUBLIC_URL"]
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"]
    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat"


def test_flags_win_over_a_stored_value(repo_root):
    tree = _tree(repo_root)
    tree[""]["QDRANT_PUBLIC_URL"] = "https://old-qdrant.example.com"
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "https://old-ingest.example.com"
    args = _args(
        repo_root,
        fresh_init=False,
        qdrant_host="https://qdrant.example.com",
        qdrant_ingest_host="https://ingest.example.com",
    )

    tree = resolve.resolve_rag_hosts(tree, args)

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://qdrant.example.com"
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"] == "https://ingest.example.com"


def test_a_stored_value_is_reused_when_the_config_dir_is_not_new(repo_root):
    tree = _tree(repo_root)
    tree[""]["QDRANT_PUBLIC_URL"] = "https://qdrant.example.com"
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "https://ingest.example.com"

    tree = resolve.resolve_rag_hosts(tree, _args(repo_root, fresh_init=False))

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://qdrant.example.com"
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"] == "https://ingest.example.com"


def test_a_fresh_config_dir_ignores_what_the_seed_carries(repo_root):
    tree = _tree(repo_root)
    tree[""]["QDRANT_PUBLIC_URL"] = "https://seeded.example.com"

    tree = resolve.resolve_rag_hosts(tree, _args(repo_root, fresh_init=True))

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://papaia.example.com:6333"


def test_the_value_env_example_ships_is_not_kept_as_a_choice(repo_root):
    """`start` appends keys a newer release added, with the example's value. Kept as
    sticky, it would pin host.docker.internal on a host that has a real name."""
    tree = _tree(repo_root)
    tree[""]["QDRANT_PUBLIC_URL"] = "http://host.docker.internal:6333"
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "http://host.docker.internal:8300"

    tree = resolve.resolve_rag_hosts(tree, _args(repo_root, fresh_init=False))

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://papaia.example.com:6333"
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"] == "https://papaia.example.com:8300"


def test_a_prompt_gets_the_default_and_its_answer_wins(repo_root):
    asked: list[tuple[str, str]] = []

    def prompt(label: str, default: str) -> str:
        asked.append((label, default))
        return "https://typed.example.com"

    tree = resolve.resolve_rag_hosts(
        _tree(repo_root), _args(repo_root, non_interactive=False, prompt=prompt)
    )

    assert [default for _, default in asked] == [
        "https://papaia.example.com:6333",
        "https://papaia.example.com:8300",
    ]
    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://typed.example.com"


def test_hosts_resolve_for_an_install_that_already_uses_an_external_idp(repo_root):
    """resolve_hostnames returns early for a configured external OIDC provider, so the
    URLs must not depend on it."""
    tree = _tree(repo_root)
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    args = _args(repo_root, fresh_init=False)

    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_rag_hosts(tree, args)

    assert tree[""]["QDRANT_PUBLIC_URL"] == "https://papaia.example.com:6333"
    assert tree[""]["QDRANT_INGEST_PUBLIC_URL"] == "https://papaia.example.com:8300"


def test_enabling_adds_the_profile_once_and_keeps_the_others(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,manager"

    tree = resolve.resolve_rag(tree, _args(repo_root, enable_rag=True))
    tree = resolve.resolve_rag(tree, _args(repo_root, enable_rag=True))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat,manager,rag"


def test_disabling_removes_only_the_profile(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,rag,librechat"

    tree = resolve.resolve_rag(tree, _args(repo_root, enable_rag=False))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat"


@pytest.mark.parametrize("profiles", ["keycloak,librechat", "keycloak,rag,librechat"])
def test_no_flag_leaves_the_profiles_alone(repo_root, profiles):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = profiles

    tree = resolve.resolve_rag(tree, _args(repo_root, enable_rag=None))

    assert tree[""]["COMPOSE_PROFILES"] == profiles


def _deploy(config_dir, *addons: tuple[str, bool]) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "addons": [
            {"name": name, "path": f"addons/{name}", "version": "1.1.0", "active": active}
            for name, active in addons
        ]
    }
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")


@pytest.mark.parametrize("addon", ["qdrant", "qdrant-connect", "qdrant-ingest"])
def test_enabling_is_refused_while_a_conflicting_addon_is_active(tmp_path, repo_root, addon):
    _deploy(tmp_path / "config", ("paperless", True), (addon, True))
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat"
    args = resolve.SetupArgs(
        config_dir=tmp_path / "config", non_interactive=True, enable_rag=True
    )

    with pytest.raises(resolve.SetupError) as excinfo:
        resolve.resolve_rag(tree, args)

    message = str(excinfo.value)
    assert addon in message
    assert f"papaia-ctl addon stop {addon} --clean-up" in message
    assert f"papaia-ctl addon remove {addon}" in message
    assert "6333" in message and "8300" in message
    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat", "nothing changed on refusal"


def test_every_active_conflicting_addon_is_named(tmp_path, repo_root):
    _deploy(tmp_path / "config", ("qdrant", True), ("qdrant-ingest", True))
    args = resolve.SetupArgs(
        config_dir=tmp_path / "config", non_interactive=True, enable_rag=True
    )

    with pytest.raises(resolve.SetupError, match="qdrant, qdrant-ingest"):
        resolve.resolve_rag(_tree(repo_root), args)


def test_an_inactive_or_unrelated_addon_does_not_block(tmp_path, repo_root):
    # `addon remove` deactivates but keeps the entry; paperless has nothing in common.
    _deploy(tmp_path / "config", ("qdrant-ingest", False), ("paperless", True))
    args = resolve.SetupArgs(
        config_dir=tmp_path / "config", non_interactive=True, enable_rag=True
    )

    tree = resolve.resolve_rag(_tree(repo_root), args)

    assert "rag" in tree[""]["COMPOSE_PROFILES"].split(",")


@pytest.mark.parametrize("flag", [False, None])
def test_the_guard_only_applies_to_switching_the_profile_on(tmp_path, repo_root, flag):
    _deploy(tmp_path / "config", ("qdrant", True))
    args = resolve.SetupArgs(config_dir=tmp_path / "config", non_interactive=True, enable_rag=flag)

    resolve.resolve_rag(_tree(repo_root), args)  # must not raise


def test_a_missing_deployment_manifest_does_not_block(tmp_path, repo_root):
    args = resolve.SetupArgs(
        config_dir=tmp_path / "no-config-yet", non_interactive=True, enable_rag=True
    )

    tree = resolve.resolve_rag(_tree(repo_root), args)

    assert "rag" in tree[""]["COMPOSE_PROFILES"].split(",")


def test_defaults_report_the_stored_choice_for_the_wizard(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,rag"
    tree[""]["QDRANT_PUBLIC_URL"] = "https://qdrant.example.com"
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "https://ingest.example.com"
    tree[""]["QDRANT_EXT_PORT"] = "16333"
    envtree.persist_tree(tree, config_dir, repo_root)

    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["RAG_STICKY"] == "true"
    assert out["QDRANT_HOST_STICKY"] == "https://qdrant.example.com"
    assert out["QDRANT_INGEST_HOST_STICKY"] == "https://ingest.example.com"
    assert out["QDRANT_EXT_PORT"] == "16333"
    assert out["QDRANT_INGEST_EXT_PORT"] == "8300"


def test_defaults_are_empty_before_the_config_dir_exists(repo_root, config_dir):
    out = defaults.compute_defaults(config_dir, repo_root)

    assert out["RAG_STICKY"] == ""
    assert out["QDRANT_HOST_STICKY"] == ""
    assert out["QDRANT_INGEST_HOST_STICKY"] == ""


def test_defaults_do_not_offer_the_example_value_as_a_stored_choice(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree[""]["QDRANT_PUBLIC_URL"] = "http://host.docker.internal:6333"
    envtree.persist_tree(tree, config_dir, repo_root)

    assert defaults.compute_defaults(config_dir, repo_root)["QDRANT_HOST_STICKY"] == ""


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


def _stored(config_dir) -> dict[str, str]:
    from lib import common

    return common.parse_env_file(config_dir / ".env")


def test_setup_flags_reach_the_stored_environment(repo_root, config_dir, capsys):
    code = _setup(
        repo_root,
        config_dir,
        "--enable-rag=true",
        "--qdrant-host=https://qdrant.example.com",
        "--qdrant-ingest-host=https://ingest.example.com",
    )

    assert code == 0
    stored = _stored(config_dir)
    assert "rag" in stored["COMPOSE_PROFILES"].split(",")
    assert stored["QDRANT_PUBLIC_URL"] == "https://qdrant.example.com"
    assert stored["QDRANT_INGEST_PUBLIC_URL"] == "https://ingest.example.com"
    out = capsys.readouterr().out
    assert "RAG system enabled" in out
    assert "qdrant-ingest-operator" in out
    assert "https://ingest.example.com/ui" in out


def test_setup_without_a_rag_flag_derives_the_urls_and_leaves_the_profile_off(
    repo_root, config_dir, capsys
):
    assert _setup(repo_root, config_dir) == 0

    stored = _stored(config_dir)
    assert "rag" not in stored["COMPOSE_PROFILES"].split(",")
    assert stored["QDRANT_PUBLIC_URL"] == "https://papaia.example.com:6333"
    assert stored["QDRANT_INGEST_PUBLIC_URL"] == "https://papaia.example.com:8300"
    assert "RAG system enabled" not in capsys.readouterr().out


def test_a_second_run_keeps_the_choice_and_the_urls(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir, "--enable-rag=true", "--qdrant-host=https://q.example.com")
    capsys.readouterr()

    assert _setup(repo_root, config_dir) == 0

    stored = _stored(config_dir)
    assert "rag" in stored["COMPOSE_PROFILES"].split(",")
    assert stored["QDRANT_PUBLIC_URL"] == "https://q.example.com"
    assert "RAG system enabled" not in capsys.readouterr().out, "the hint is for the switch-on"


def test_confirming_an_already_enabled_rag_system_prints_no_reminder(
    repo_root, config_dir, capsys
):
    _setup(repo_root, config_dir, "--enable-rag=true")
    capsys.readouterr()

    assert _setup(repo_root, config_dir, "--enable-rag=true") == 0

    assert "RAG system enabled" not in capsys.readouterr().out


def test_switching_it_on_again_after_an_opt_out_prints_the_reminder_again(
    repo_root, config_dir, capsys
):
    _setup(repo_root, config_dir, "--enable-rag=true")
    _setup(repo_root, config_dir, "--enable-rag=false")
    capsys.readouterr()

    assert _setup(repo_root, config_dir, "--enable-rag=true") == 0

    assert "RAG system enabled" in capsys.readouterr().out


def test_turning_it_off_again_keeps_the_urls(repo_root, config_dir):
    _setup(repo_root, config_dir, "--enable-rag=true", "--qdrant-host=https://q.example.com")

    assert _setup(repo_root, config_dir, "--enable-rag=false") == 0

    stored = _stored(config_dir)
    assert "rag" not in stored["COMPOSE_PROFILES"].split(",")
    assert stored["QDRANT_PUBLIC_URL"] == "https://q.example.com"


def test_setup_refuses_with_exit_code_3_and_changes_nothing(repo_root, config_dir, capsys):
    _setup(repo_root, config_dir)
    before = (config_dir / ".env").read_bytes()
    _deploy(config_dir, ("qdrant-ingest", True))
    capsys.readouterr()

    assert _setup(repo_root, config_dir, "--enable-rag=true") == 3

    assert "qdrant-ingest" in capsys.readouterr().err
    assert (config_dir / ".env").read_bytes() == before


def test_the_rag_hint_names_the_secret_file_but_never_the_secret(tmp_path, capsys):
    tree = _external_oidc_tree("librechat,rag")
    tree["ai/rag"]["QDRANT_JWT_SECRET"] = "must-not-appear-in-output"

    reporting.print_rag_next_steps(tmp_path, tree)

    out = capsys.readouterr().out
    assert "QDRANT_JWT_SECRET" in out
    assert str(tmp_path / "ai" / "rag" / ".env") in out
    assert "must-not-appear-in-output" not in out


def _external_oidc_tree(profiles: str) -> dict:
    return {
        "": {
            "PAPAIA_HOST": "https://papaia.example.com",
            "OIDC_ISSUER": "https://idp.example.com/realms/x",
            "COMPOSE_PROFILES": profiles,
            "QDRANT_INGEST_PUBLIC_URL": "https://ingest.example.com",
        },
        "ai/rag": {"QI_UI_CLIENT_SECRET": "REPLACE_WITH_VALID_SECRET"},
    }


def test_the_external_oidc_checklist_lists_the_rag_client_only_with_the_profile(
    tmp_path, capsys
):
    reporting.print_external_oidc_checklist(tmp_path, _external_oidc_tree("librechat,rag"))
    with_rag = capsys.readouterr().out
    reporting.print_external_oidc_checklist(tmp_path, _external_oidc_tree("librechat"))
    without = capsys.readouterr().out

    assert "qdrant-ingest-ui" in with_rag
    assert "https://ingest.example.com/ui/auth/callback" in with_rag
    assert "mcp-qdrant-ingest" in with_rag
    assert "qdrant-ingest-operator" in with_rag
    assert "ai/rag/.env" in with_rag, "its client secret still has to be filled in"
    assert "qdrant" not in without


def test_the_setup_json_contract_is_untouched(repo_root, config_dir):
    """The manager imports lib.*, so the setup path must keep writing a parseable
    deployment manifest."""
    _setup(repo_root, config_dir, "--enable-rag=true")

    manifest = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    assert "rag" in manifest["core"]["profiles"]
    json.dumps(manifest)
