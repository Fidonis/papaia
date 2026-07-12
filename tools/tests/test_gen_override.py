from __future__ import annotations

from pathlib import Path

import yaml

from lib import bootstrap, common, gen_override

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_generate_overrides_empty_on_lean_core(repo_root, config_dir):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    written = gen_override.generate_overrides(config_dir)
    assert written == []
    # overrides/ contains only the addons/ subdirectory — no override files
    assert list((config_dir / "overrides").glob("*.yml")) == []


def test_generate_override_synthetic_fixture():
    manifest = yaml.safe_load(
        (FIXTURES_DIR / "addon-paperless" / "papaia-app.yaml").read_text(encoding="utf-8")
    )

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        config_dir = Path(tmp)
        (config_dir / "overrides").mkdir()
        out_path = gen_override.generate_override(manifest, config_dir)

        assert out_path is not None
        assert out_path.name == "docker-compose.paperless.override.yml"
        override = yaml.safe_load(out_path.read_text(encoding="utf-8"))
        assert override["services"]["nginx-proxy-manager"]["networks"] == ["papaia-paperless-net"]
        assert override["services"]["librechat"]["networks"] == ["papaia-paperless-net"]
        assert override["networks"]["papaia-paperless-net"]["external"] is True


def test_generate_override_returns_none_without_networks():
    out_path = gen_override.generate_override({"name": "foo"}, Path("/tmp/unused"))
    assert out_path is None


def test_generate_ssl_cert_override_creates_file_for_external_oidc(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_ssl_cert_override(config_dir, "external_oidc")

    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    assert out_path.is_file()
    override = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    services = override["services"]
    assert services["litellm"]["environment"]["SSL_CERT_FILE"] == ""
    assert services["oauth2-proxy"]["environment"]["SSL_CERT_FILE"] == ""
    assert services["localai"]["environment"]["SSL_CERT_FILE"] == ""


def test_generate_ssl_cert_override_removes_file_for_internal_keycloak(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    # First create the file as if a prior external-OIDC run wrote it
    gen_override.generate_ssl_cert_override(config_dir, "external_oidc")
    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    assert out_path.is_file()

    # Switching back to internal_keycloak must remove it
    gen_override.generate_ssl_cert_override(config_dir, "internal_keycloak")
    assert not out_path.exists()


def _write_paperless_deployment(config_dir: Path, active: bool) -> None:
    import yaml as _yaml

    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["addons"] = [{"name": "paperless", "active": active, "path": "/some/path"}]
    common.atomic_write(
        deployment_path,
        _yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )


def test_paperless_addon_ssl_cert_override_created_for_external_oidc(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    _write_paperless_deployment(config_dir, active=True)

    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "external_oidc")

    out_path = config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    assert out_path.is_file()
    override = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    assert override["services"]["paperless"]["environment"]["REQUESTS_CA_BUNDLE"] == ""
    assert override["services"]["paperless-mcp"]["environment"]["SSL_CERT_FILE"] == ""


def test_paperless_addon_ssl_cert_override_removed_for_internal_keycloak(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    _write_paperless_deployment(config_dir, active=True)

    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "external_oidc")
    out_path = config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    assert out_path.is_file()

    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "internal_keycloak")
    assert not out_path.exists()


def test_paperless_addon_ssl_cert_override_removed_when_addon_inactive(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    _write_paperless_deployment(config_dir, active=True)

    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "external_oidc")
    out_path = config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    assert out_path.is_file()

    _write_paperless_deployment(config_dir, active=False)
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "external_oidc")
    assert not out_path.exists()


def test_paperless_addon_ssl_cert_override_not_created_without_deployment(config_dir, repo_root):
    bootstrap.init(config_dir, repo_root, env_name="papaia")
    # deployment.yaml has no addons entry → paperless not active
    gen_override.generate_paperless_addon_ssl_cert_override(config_dir, "external_oidc")
    out_path = config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    assert not out_path.exists()
