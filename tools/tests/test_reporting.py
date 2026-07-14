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


def test_keycloak_checklist_silent_when_nothing_to_do(tmp_path, capsys):
    reporting.print_keycloak_checklist("paperless", {}, tmp_path, tmp_path)
    assert capsys.readouterr().out == ""
