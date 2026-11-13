from __future__ import annotations

from lib import envtree, reporting


def test_external_oidc_checklist_lists_clients_and_placeholders(repo_root, config_dir, capsys):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    tree[""]["OAUTH2_PROXY_CLIENT_SECRET"] = "REPLACE_WITH_VALID_SECRET"

    reporting.print_external_oidc_checklist(config_dir, tree)

    out = capsys.readouterr().out
    # All three OIDC clients with their redirect URIs
    assert "https://idp.customer.com/realms/foo" in out
    assert "librechat" in out and "/oauth/openid/callback" in out
    assert "oauth2-proxy" in out and "https://papaia.example.com/oauth2/callback" in out
    # The placeholder section names the env file and the key
    assert "REPLACE_WITH_VALID_SECRET" in out
    assert "OAUTH2_PROXY_CLIENT_SECRET" in out


def test_external_oidc_checklist_omits_placeholder_section_when_none(repo_root, config_dir, capsys):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["OIDC_ISSUER"] = "https://idp.customer.com/realms/foo"
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"

    reporting.print_external_oidc_checklist(config_dir, tree)

    out = capsys.readouterr().out
    assert "Replace REPLACE_WITH_VALID_SECRET" not in out
    assert "Apply and start the stack" in out


def test_keycloak_checklist_lists_imports_mappers_and_secret_hints(tmp_path, capsys):
    addon_path = tmp_path / "addon"
    addon_path.mkdir()
    config_dir = tmp_path / "config"
    bundle_dir = config_dir / "addons" / "paperless"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / ".env").write_text(
        "KC_PAPERLESS_CLIENT_SECRET=REPLACE_WITH_KC_PAPERLESS_CLIENT_SECRET\n"
        "PAPERLESS_DBPASS=already-set\n",
        encoding="utf-8",
    )
    manifest = {
        "integration": {
            "keycloak": {
                "clients": ["integration/keycloak/clients/paperless.json"],
                "client_mappers": {
                    "litellm": ["integration/keycloak/mappers/audience.json"]
                },
            }
        },
        "env_replace_secrets": {
            "KC_PAPERLESS_CLIENT_SECRET": {"hint": "Clients → paperless → Credentials"}
        },
    }

    reporting.print_keycloak_checklist("paperless", manifest, addon_path, config_dir)

    out = capsys.readouterr().out
    assert "Import these OIDC clients" in out
    assert "paperless.json" in out
    assert "litellm" in out and "audience.json" in out
    assert "KC_PAPERLESS_CLIENT_SECRET" in out
    assert "Clients → paperless → Credentials" in out
    # Keys that already hold a real value get no secret-entry step line
    assert "PAPERLESS_DBPASS" not in out


def test_keycloak_checklist_numbers_the_install_notes_after_its_own_steps(tmp_path, capsys):
    addon_path = tmp_path / "addon"
    manifest = {
        "integration": {"keycloak": {"clients": ["clients/wiki.json"]}},
        "install_notes": ["Set MW_SERVER in the add-on .env.", "Allow the callback."],
    }
    reporting.print_keycloak_checklist("wiki", manifest, addon_path, tmp_path)
    out = capsys.readouterr().out
    assert "2. Set MW_SERVER in the add-on .env." in out
    assert "3. Allow the callback." in out


def test_keycloak_checklist_prints_install_notes_on_their_own(tmp_path, capsys):
    manifest = {"install_notes": ["Set MW_SERVER."]}
    reporting.print_keycloak_checklist("wiki", manifest, tmp_path, tmp_path)
    assert "1. Set MW_SERVER." in capsys.readouterr().out


def test_keycloak_checklist_takes_a_single_install_note_as_one_step(tmp_path, capsys):
    manifest = {"install_notes": "Set MW_SERVER."}
    reporting.print_keycloak_checklist("wiki", manifest, tmp_path, tmp_path)
    out = capsys.readouterr().out
    assert "1. Set MW_SERVER." in out
    assert "2." not in out


def test_keycloak_checklist_indents_a_multi_line_install_note(tmp_path, capsys):
    manifest = {"install_notes": ["Set these in the add-on .env:\nMW_SERVER\nMW_SITENAME\n"]}
    reporting.print_keycloak_checklist("wiki", manifest, tmp_path, tmp_path)
    assert "1. Set these in the add-on .env:\n   MW_SERVER\n   MW_SITENAME\n" in (
        capsys.readouterr().out
    )


def test_keycloak_checklist_silent_when_nothing_to_do(tmp_path, capsys):
    reporting.print_keycloak_checklist("paperless", {}, tmp_path, tmp_path)
    assert capsys.readouterr().out == ""


def test_keycloak_checklist_leaves_managed_clients_to_start(tmp_path, capsys):
    addon_path = tmp_path / "addon"
    addon_path.mkdir()
    config_dir = tmp_path / "config"
    (config_dir / "addons" / "wiki").mkdir(parents=True)
    (config_dir / "addons" / "wiki" / ".env").write_text("KC_WIKI_SECRET=s\n", encoding="utf-8")
    manifest = {
        "integration": {
            "keycloak": {
                "clients": ["kc/wiki.json", "kc/manual.json"],
                "client_secrets": {"kc/wiki.json": {"secret_env": "KC_WIKI_SECRET"}},
            }
        }
    }

    reporting.print_keycloak_checklist("wiki", manifest, addon_path, config_dir)

    out = capsys.readouterr().out
    created, manual = out.split("Import these OIDC clients")
    assert "created by 'papaia-ctl start'" in created and "wiki.json" in created
    assert "manual.json" in manual and "wiki.json" not in manual


def test_keycloak_checklist_does_not_ask_to_enter_a_managed_secret(tmp_path, capsys):
    # The placeholder of a manual import, as an add-on for an older core still ships it:
    # `addon start` generates the value, so only the unmanaged key is listed.
    addon_path = tmp_path / "addon"
    addon_path.mkdir()
    config_dir = tmp_path / "config"
    (config_dir / "addons" / "wiki").mkdir(parents=True)
    (config_dir / "addons" / "wiki" / ".env").write_text(
        "KC_WIKI_SECRET=REPLACE_WITH_WIKI_SECRET\nKC_OTHER_SECRET=REPLACE_WITH_OTHER\n",
        encoding="utf-8",
    )
    manifest = {
        "integration": {
            "keycloak": {
                "clients": ["kc/wiki.json", "kc/other.json"],
                "client_secrets": {"kc/wiki.json": {"secret_env": "KC_WIKI_SECRET"}},
            }
        }
    }

    reporting.print_keycloak_checklist("wiki", manifest, addon_path, config_dir)

    out = capsys.readouterr().out
    assert "their secrets are generated" in out
    _, steps = out.split("manual steps required")
    assert "KC_OTHER_SECRET" in steps
    assert "KC_WIKI_SECRET" not in steps


def test_keycloak_checklist_without_manual_steps_for_a_managed_placeholder(tmp_path, capsys):
    addon_path = tmp_path / "addon"
    addon_path.mkdir()
    config_dir = tmp_path / "config"
    (config_dir / "addons" / "wiki").mkdir(parents=True)
    (config_dir / "addons" / "wiki" / ".env").write_text(
        "KC_WIKI_SECRET=REPLACE_WITH_WIKI_SECRET\n", encoding="utf-8"
    )
    manifest = {
        "integration": {
            "keycloak": {
                "clients": ["kc/wiki.json"],
                "client_secrets": {"kc/wiki.json": {"secret_env": "KC_WIKI_SECRET"}},
            }
        }
    }

    reporting.print_keycloak_checklist("wiki", manifest, addon_path, config_dir)

    assert "manual steps required" not in capsys.readouterr().out
