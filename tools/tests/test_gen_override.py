from __future__ import annotations

from pathlib import Path

import yaml

from lib import common, envtree, gen_override

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_generate_overrides_empty_on_lean_core(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
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
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_ssl_cert_override(config_dir, "external_oidc")

    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    assert out_path.is_file()
    override = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    services = override["services"]
    assert services["litellm"]["environment"]["SSL_CERT_FILE"] == ""
    assert services["oauth2-proxy"]["environment"]["SSL_CERT_FILE"] == ""
    assert services["localai"]["environment"]["SSL_CERT_FILE"] == ""


def test_generate_ssl_cert_override_removes_file_for_internal_keycloak(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    # First create the file as if a prior external-OIDC run wrote it
    gen_override.generate_ssl_cert_override(config_dir, "external_oidc")
    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    assert out_path.is_file()

    # Switching back to internal_keycloak must remove it
    gen_override.generate_ssl_cert_override(config_dir, "internal_keycloak")
    assert not out_path.exists()


def _localai_override(config_dir: Path) -> Path:
    return config_dir / "overrides" / "docker-compose.localai-gpu.override.yml"


def test_localai_gpu_override_inherits_the_pinned_version(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "nvidia-cuda-13")

    override = yaml.safe_load(_localai_override(config_dir).read_text(encoding="utf-8"))
    localai = override["services"]["localai"]
    # v9.9.9 is the fixture's pin — proof the version is read back from the
    # compose file rather than stored in the config dir.
    assert localai["image"] == "localai/localai:v9.9.9-gpu-nvidia-cuda-13"
    device = localai["deploy"]["resources"]["reservations"]["devices"][0]
    assert device["driver"] == "nvidia"


def test_localai_gpu_override_intel_passes_dri(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")

    localai = yaml.safe_load(_localai_override(config_dir).read_text(encoding="utf-8"))["services"][
        "localai"
    ]
    assert localai["image"] == "localai/localai:v9.9.9-gpu-intel"
    assert localai["devices"] == ["/dev/dri:/dev/dri"]
    assert "deploy" not in localai


def test_localai_gpu_override_hipblas_passes_kfd(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "hipblas")

    localai = yaml.safe_load(_localai_override(config_dir).read_text(encoding="utf-8"))["services"][
        "localai"
    ]
    assert localai["image"] == "localai/localai:v9.9.9-gpu-hipblas"
    assert localai["devices"] == ["/dev/dri:/dev/dri", "/dev/kfd:/dev/kfd"]
    assert localai["group_add"] == ["video"]


def test_localai_gpu_override_vulkan_uses_present_devices(config_dir, repo_root, tmp_path):
    envtree.init(config_dir, repo_root, env_name="papaia")
    dev_root = tmp_path / "dev"
    (dev_root / "dri").mkdir(parents=True)

    gen_override.generate_localai_gpu_override(config_dir, repo_root, "vulkan", dev_root)

    localai = yaml.safe_load(_localai_override(config_dir).read_text(encoding="utf-8"))["services"][
        "localai"
    ]
    assert localai["image"] == "localai/localai:v9.9.9-gpu-vulkan"
    assert localai["devices"] == ["/dev/dri:/dev/dri"]


def test_localai_gpu_override_removed_for_cpu(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")
    assert _localai_override(config_dir).is_file()

    # Switching a host back to CPU has to take the override away again,
    # otherwise the GPU image would keep being pulled.
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "cpu")
    assert not _localai_override(config_dir).exists()


def test_localai_gpu_override_removed_for_unset_variant(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "")
    assert not _localai_override(config_dir).exists()


def test_localai_gpu_override_ignores_unknown_variant(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "quantum")
    assert not _localai_override(config_dir).exists()


def test_localai_gpu_override_declares_no_external_networks(config_dir, repo_root):
    """The start-up loop skips overrides whose external networks are absent —
    this one must never be skipped."""
    envtree.init(config_dir, repo_root, env_name="papaia")
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")
    assert gen_override.external_networks(_localai_override(config_dir)) == []


def test_localai_gpu_override_skipped_when_image_is_unpinned(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    compose = repo_root / "src/ai/localai/docker-compose.yml"
    compose.write_text(
        "services:\n  localai:\n    image: localai/localai\n", encoding="utf-8"
    )
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")
    assert not _localai_override(config_dir).exists()


def test_localai_gpu_override_skipped_when_compose_is_missing(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    (repo_root / "src/ai/localai/docker-compose.yml").unlink()
    gen_override.generate_localai_gpu_override(config_dir, repo_root, "intel")
    assert not _localai_override(config_dir).exists()


def _write_addon_deployment(config_dir: Path, addons: list[dict]) -> None:
    deployment_path = config_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    deployment["addons"] = addons
    common.atomic_write(
        deployment_path,
        yaml.safe_dump(deployment, sort_keys=False, default_flow_style=False),
    )


def _paperless_entry(active: bool) -> dict:
    return {
        "name": "paperless",
        "active": active,
        "path": str(FIXTURES_DIR / "addon-paperless"),
    }


def test_addon_ssl_cert_override_created_for_external_oidc(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _write_addon_deployment(config_dir, [_paperless_entry(active=True)])

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)

    out_path = (
        config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    )
    assert out_path.is_file()
    override = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    assert override["services"]["paperless"]["environment"]["REQUESTS_CA_BUNDLE"] == ""
    assert override["services"]["paperless-mcp"]["environment"]["SSL_CERT_FILE"] == ""


def test_addon_ssl_cert_override_removed_for_internal_keycloak(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _write_addon_deployment(config_dir, [_paperless_entry(active=True)])

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)
    out_path = (
        config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    )
    assert out_path.is_file()

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "internal_keycloak", repo_root)
    assert not out_path.exists()


def test_addon_ssl_cert_override_removed_when_addon_inactive(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    _write_addon_deployment(config_dir, [_paperless_entry(active=True)])

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)
    out_path = (
        config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    )
    assert out_path.is_file()

    _write_addon_deployment(config_dir, [_paperless_entry(active=False)])
    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)
    assert not out_path.exists()


def test_addon_ssl_cert_override_not_created_without_deployment(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    # deployment.yaml has no addons entry → nothing to generate
    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)
    out_path = (
        config_dir / "overrides" / "addons" / "docker-compose.paperless-ssl-cert.override.yml"
    )
    assert not out_path.exists()


def test_addon_ssl_cert_override_skipped_without_local_ca_env(config_dir, repo_root, tmp_path):
    envtree.init(config_dir, repo_root, env_name="papaia")
    addon_dir = tmp_path / "addon-plain"
    addon_dir.mkdir()
    (addon_dir / "papaia-app.yaml").write_text(
        "name: plain\nnetworks:\n  app_network: papaia-plain-net\n  attach: [librechat]\n",
        encoding="utf-8",
    )
    _write_addon_deployment(
        config_dir, [{"name": "plain", "active": True, "path": str(addon_dir)}]
    )

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)

    out_path = config_dir / "overrides" / "addons" / "docker-compose.plain-ssl-cert.override.yml"
    assert not out_path.exists()


def test_addon_ssl_cert_override_generated_per_addon(config_dir, repo_root, tmp_path):
    envtree.init(config_dir, repo_root, env_name="papaia")
    addon_dir = tmp_path / "addon-other"
    addon_dir.mkdir()
    (addon_dir / "papaia-app.yaml").write_text(
        "name: other\nlocal_ca_env:\n  other-svc: [SSL_CERT_FILE]\n",
        encoding="utf-8",
    )
    _write_addon_deployment(
        config_dir,
        [
            _paperless_entry(active=True),
            {"name": "other", "active": True, "path": str(addon_dir)},
        ],
    )

    gen_override.generate_addon_ssl_cert_overrides(config_dir, "external_oidc", repo_root)

    addons_dir = config_dir / "overrides" / "addons"
    assert (addons_dir / "docker-compose.paperless-ssl-cert.override.yml").is_file()
    other = yaml.safe_load(
        (addons_dir / "docker-compose.other-ssl-cert.override.yml").read_text(encoding="utf-8")
    )
    assert other["services"]["other-svc"]["environment"]["SSL_CERT_FILE"] == ""
