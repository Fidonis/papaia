"""The hosted reference model is a test-stack matter only.

A production render (no test switch) carries no route to a model outside the stack, and
papaia-ctl refuses one from any layer. With `PAPAIA_TEST_EXTERNAL_MODEL=1` the render keeps
the hosted route, marks it `test_backend`, lets LiteLLM out through papaia-egress to that
one host only, and keeps the key out of the configuration, the backups and the messages.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from lib import (
    age,
    backup,
    cluster_data,
    common,
    egress,
    envtree,
    gen_override,
    hosted_model,
    render_core,
    resolve,
    secrets,
    topology,
)

TOOLS = Path(__file__).resolve().parents[1]
REAL_REPO = TOOLS.parent
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
BASH = shutil.which("bash")
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Synthetic; never a real key of any provider.
KEY_VALUE = "synthetic-hosted-key-0000"
KEY_VAR = "TEST_HOSTED_API_KEY"
HOSTED = {
    "model_name": "test-hosted-chat",
    "litellm_params": {
        "model": "openai/reference-chat",
        "api_base": "https://api.example.org/v1",
        "api_key": f"os.environ/{KEY_VAR}",
    },
}


def _setup(repo_root: Path, config_dir: Path) -> None:
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree = secrets.generate_missing_secrets(tree, envtree.load_seed_tree(repo_root))
    args = resolve.SetupArgs(
        config_dir=config_dir, app_host="http://host.docker.internal", non_interactive=True
    )
    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_reverse_proxy(tree, args)
    envtree.persist_tree(tree, config_dir, repo_root)


def _set_root(config_dir: Path, **values: str) -> None:
    path = config_dir / ".env"
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.partition("=")[0] not in values
    ]
    lines.extend(f"{key}={value}" for key, value in values.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _overlay(config_dir: Path, *entries: dict) -> None:
    path = config_dir / "overlay" / "ai" / "litellm" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"model_list": list(entries)}), encoding="utf-8")


def _key_file(config_dir: Path, text: str | None = None, mode: int = 0o600) -> Path:
    path = config_dir / hosted_model.KEY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{KEY_VAR}={KEY_VALUE}\n" if text is None else text, encoding="utf-8")
    path.chmod(mode)
    return path


def _test_stack(repo_root: Path, config_dir: Path, *entries: dict) -> None:
    _setup(repo_root, config_dir)
    _set_root(config_dir, **{hosted_model.FLAG: "1"})
    _overlay(config_dir, *(entries or (HOSTED,)))
    _key_file(config_dir)


def _stack_service(repo_root: Path, name: str) -> None:
    """A service of the core compose (no profile, so always on), included like the real ones."""
    compose = repo_root / "src" / "ai" / name / "docker-compose.yml"
    compose.parent.mkdir(parents=True, exist_ok=True)
    compose.write_text(yaml.safe_dump({"services": {name: {"image": "stub"}}}), encoding="utf-8")
    root = repo_root / "src" / "docker-compose.yml"
    doc = yaml.safe_load(root.read_text(encoding="utf-8")) or {}
    doc.setdefault("include", []).append({"path": f"./ai/{name}/docker-compose.yml"})
    root.write_text(yaml.safe_dump(doc), encoding="utf-8")


def _inside(api_base: str, **params: str) -> dict:
    return {
        "model_name": "inside",
        "litellm_params": {"model": "openai/inside", "api_base": api_base, **params},
    }


def _rendered_models(config_dir: Path) -> list[dict]:
    path = config_dir / render_core.LITELLM_CONFIG
    return yaml.safe_load(path.read_text(encoding="utf-8")).get("model_list") or []


def _egress_sources(config_dir: Path) -> list[dict]:
    return json.loads((config_dir / egress.CONFIG_FILE).read_text(encoding="utf-8"))["sources"]


def _override(config_dir: Path) -> dict:
    return yaml.safe_load(hosted_model.override_path(config_dir).read_text(encoding="utf-8"))


def _hosted_entry(**params: str) -> dict:
    entry = json.loads(json.dumps(HOSTED))
    entry["litellm_params"].update(params)
    return entry


# ─────────────────────────────────────────────────────────────────────────
# production profile: no hosted route
# ─────────────────────────────────────────────────────────────────────────


def test_the_production_render_contains_no_hosted_model_route(repo_root, config_dir):
    _setup(repo_root, config_dir)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    assert all(hosted_model.is_local(e, config_dir) for e in _rendered_models(config_dir))
    assert not any(
        (e.get("model_info") or {}).get("test_backend") for e in _rendered_models(config_dir)
    )
    assert [s["name"] for s in _egress_sources(config_dir)] == []
    assert not hosted_model.override_path(config_dir).exists()


@pytest.mark.parametrize(
    "params",
    [
        {"api_base": "https://api.example.org/v1"},
        {"api_base": "http://203.0.113.5:8000/v1"},
        {"api_base": "http://localai.example.org:8080/v1"},
        {"api_base": "os.environ/HOSTED_API_BASE"},
        # No api_base: the provider's own endpoint on the internet.
        {"api_base": None},
    ],
)
def test_the_production_render_refuses_a_hosted_route(repo_root, config_dir, params):
    _setup(repo_root, config_dir)
    entry = _hosted_entry()
    for key, value in params.items():
        if value is None:
            entry["litellm_params"].pop(key)
        else:
            entry["litellm_params"][key] = value
    _overlay(config_dir, entry)

    with pytest.raises(render_core.RenderError, match="test-hosted-chat") as caught:
        render_core.render(config_dir, repo_root)
    assert hosted_model.FLAG in str(caught.value)


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "01", "on"])
def test_only_the_exact_switch_value_one_opens_the_test_stack(repo_root, config_dir, value):
    _setup(repo_root, config_dir)
    _set_root(config_dir, **{hosted_model.FLAG: value})
    _overlay(config_dir, HOSTED)
    _key_file(config_dir)

    with pytest.raises(render_core.RenderError, match="test-hosted-chat"):
        render_core.render(config_dir, repo_root)


def test_a_hosted_route_from_an_addon_fragment_is_refused_as_well(repo_root, config_dir):
    _setup(repo_root, config_dir)
    fragment = repo_root / "src" / "ai" / "rag" / "integration" / "ai" / "litellm" / "config.yaml"
    fragment.parent.mkdir(parents=True, exist_ok=True)
    fragment.write_text(yaml.safe_dump({"model_list": [HOSTED]}), encoding="utf-8")
    profiles = common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"]
    _set_root(config_dir, COMPOSE_PROFILES=f"{profiles},rag")

    with pytest.raises(render_core.RenderError, match="test-hosted-chat"):
        render_core.render(config_dir, repo_root)


@pytest.mark.parametrize(
    "api_base", ["http://pruefmodell:8080/v1", "https://keycloak:8443", "http://PRUEFMODELL:8080"]
)
def test_a_route_to_a_service_inside_the_stack_needs_no_switch(repo_root, config_dir, api_base):
    _stack_service(repo_root, "pruefmodell")
    _stack_service(repo_root, "keycloak")
    _setup(repo_root, config_dir)
    entry = _inside(api_base)
    # Claimed by the overlay; only the render decides what is a test backend.
    entry["model_info"] = {"test_backend": True}
    _overlay(config_dir, entry)

    render_core.render(config_dir, repo_root)

    [rendered] = _rendered_models(config_dir)
    assert rendered["litellm_params"]["api_base"] == api_base
    assert "test_backend" not in (rendered.get("model_info") or {})
    assert _egress_sources(config_dir) == []


@pytest.mark.parametrize(
    "api_base",
    [
        # A short name the stack does not define: Docker's DNS forwards it to the host's
        # resolver and its search domains, which can answer with a host outside the stack.
        "http://intranet-llm:8000/v1",
        # IPv4 written as one decimal or hex number, or octal parts: the resolver turns
        # them into public addresses.
        "http://3627734862/v1",
        "http://0xd83ad6ce/v1",
        "http://0330.0072.0326.0316/v1",
        # Parsers differ on a backslash: urlsplit sees the host 'pruefmodell', a
        # WHATWG-style client sees 'evil.example'.
        "http://evil.example\\@pruefmodell:8080/v1",
        "http://user@pruefmodell:8080/v1",
        "http://pruef modell:8080/v1",
        "http://pruefmodell:8080/v1\n",
        "http://pruefmodell:8080/v1?",
        "http://pruefmodell:99999/v1",
        "ftp://pruefmodell/v1",
    ],
)
def test_only_a_named_service_of_the_stack_is_inside_it(repo_root, config_dir, api_base):
    _stack_service(repo_root, "pruefmodell")
    _setup(repo_root, config_dir)
    _overlay(config_dir, _inside(api_base))

    with pytest.raises(render_core.RenderError, match="inside") as caught:
        render_core.render(config_dir, repo_root)
    assert hosted_model.FLAG in str(caught.value)


def test_a_service_of_an_inactive_profile_is_not_inside_the_stack(repo_root, config_dir):
    # The fixture's chatterbox belongs to the voice profile, which is off.
    voice = repo_root / "src" / "docker-compose.yml"
    doc = yaml.safe_load(voice.read_text(encoding="utf-8"))
    doc["include"].append({"path": "./ai/voice/docker-compose.yml"})
    voice.write_text(yaml.safe_dump(doc), encoding="utf-8")
    _setup(repo_root, config_dir)
    _overlay(config_dir, _inside("http://chatterbox:8004/v1"))

    with pytest.raises(render_core.RenderError, match="inside"):
        render_core.render(config_dir, repo_root)

    profiles = common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"]
    _set_root(config_dir, COMPOSE_PROFILES=f"{profiles},voice")
    render_core.render(config_dir, repo_root)
    assert [e["model_name"] for e in _rendered_models(config_dir)][-1] == "inside"


def test_a_service_of_an_active_addon_is_inside_the_stack(tmp_path, repo_root, config_dir):
    _setup(repo_root, config_dir)
    addon = tmp_path / "addons" / "modelserver"
    addon.mkdir(parents=True)
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump({"name": "modelserver", "version": "1.0.0"}), encoding="utf-8"
    )
    (addon / "docker-compose.yml").write_text(
        yaml.safe_dump(
            {
                "services": {
                    "modelserver": {
                        "image": "stub",
                        "networks": {"default": {"aliases": ["modelserver-api"]}},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    deployed["addons"] = [{"name": "modelserver", "path": str(addon), "active": True}]
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")
    _overlay(config_dir, _inside("http://modelserver-api:8000/v1"))

    render_core.render(config_dir, repo_root)

    assert _rendered_models(config_dir)[-1]["litellm_params"]["api_base"] == (
        "http://modelserver-api:8000/v1"
    )


@pytest.mark.parametrize(
    "entry",
    [
        # A second endpoint next to a local api_base.
        _inside("http://pruefmodell:8080/v1", base_url="https://api.example.org/v1"),
        # A provider that takes its endpoint from the cloud account, not from api_base.
        {
            "model_name": "inside",
            "litellm_params": {
                "model": "bedrock/reference-chat",
                "api_base": "http://pruefmodell:8080/v1",
                "aws_region_name": "eu-central-1",
            },
        },
        _inside("http://pruefmodell:8080/v1", vertex_project="reference"),
        _inside("http://pruefmodell:8080/v1", azure_ad_token="os.environ/AZURE"),
        # A credential of credential_list may carry its own api_base and api_key.
        _inside("http://pruefmodell:8080/v1", litellm_credential_name="shared"),
    ],
)
def test_an_entry_naming_another_endpoint_is_refused(repo_root, config_dir, entry):
    _stack_service(repo_root, "pruefmodell")
    _setup(repo_root, config_dir)
    _overlay(config_dir, entry)

    with pytest.raises(render_core.RenderError, match="inside"):
        render_core.render(config_dir, repo_root)


@pytest.mark.parametrize(
    "params",
    [
        {"model": "bedrock/reference-chat"},
        {"model": "reference-chat"},
        {"custom_llm_provider": "vertex_ai"},
    ],
)
def test_an_entry_inside_the_stack_needs_a_provider_that_uses_api_base(
    repo_root, config_dir, params
):
    _stack_service(repo_root, "pruefmodell")
    _setup(repo_root, config_dir)
    _overlay(config_dir, _inside("http://pruefmodell:8080/v1", **params))

    with pytest.raises(render_core.RenderError, match="inside"):
        render_core.render(config_dir, repo_root)


def _overlay_settings(config_dir: Path, settings: dict, *entries: dict) -> None:
    path = config_dir / "overlay" / "ai" / "litellm" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({**settings, "model_list": list(entries)}), encoding="utf-8")


CREDENTIALS = {
    "credential_list": [
        {
            "credential_name": "shared",
            "credential_values": {
                "api_base": "https://api.example.org/v1",
                "api_key": f"os.environ/{KEY_VAR}",
            },
        }
    ]
}


@pytest.mark.parametrize("switch", ["", "1"])
def test_a_credential_list_is_refused_with_and_without_the_switch(repo_root, config_dir, switch):
    _stack_service(repo_root, "pruefmodell")
    _setup(repo_root, config_dir)
    _set_root(config_dir, **{hosted_model.FLAG: switch})
    _key_file(config_dir)
    _overlay_settings(config_dir, CREDENTIALS, _inside("http://pruefmodell:8080/v1"))

    with pytest.raises(render_core.RenderError, match="credential_list") as caught:
        render_core.render(config_dir, repo_root)
    assert KEY_VALUE not in str(caught.value)


def test_an_empty_credential_list_is_no_route(repo_root, config_dir):
    _stack_service(repo_root, "pruefmodell")
    _setup(repo_root, config_dir)
    _overlay_settings(config_dir, {"credential_list": []}, _inside("http://pruefmodell:8080/v1"))

    render_core.render(config_dir, repo_root)

    assert _rendered_models(config_dir)[-1]["model_name"] == "inside"


@pytest.mark.parametrize(
    "name", ["NO_PROXY", "no_proxy", "HTTPS_PROXY", "Http_Proxy", "ALL_PROXY", "all_proxy"]
)
@pytest.mark.parametrize("switch", ["", "1"])
def test_the_proxy_variables_cannot_be_set_from_the_configuration(
    repo_root, config_dir, name, switch
):
    # environment_variables of LiteLLM's configuration would empty the proxy override.
    _setup(repo_root, config_dir)
    _set_root(config_dir, **{hosted_model.FLAG: switch})
    _key_file(config_dir)
    _overlay_settings(config_dir, {"environment_variables": {name: "*"}}, HOSTED)

    with pytest.raises(render_core.RenderError, match=name):
        render_core.render(config_dir, repo_root)


def test_other_environment_variables_of_the_configuration_stay(repo_root, config_dir):
    _setup(repo_root, config_dir)
    _overlay_settings(config_dir, {"environment_variables": {"LITELLM_LOG": "INFO"}})

    render_core.render(config_dir, repo_root)

    path = config_dir / render_core.LITELLM_CONFIG
    rendered = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert rendered["environment_variables"] == {"LITELLM_LOG": "INFO"}


def test_a_rendered_file_edited_by_hand_is_classified_against_the_stack(repo_root, config_dir):
    # The rendered file is not the control; a short name the stack does not define that
    # was written into it after the render is no model service inside the stack.
    _test_stack(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    path = config_dir / render_core.LITELLM_CONFIG
    rendered = yaml.safe_load(path.read_text(encoding="utf-8"))
    rendered["model_list"].append(_inside("http://intranet-llm:8000/v1"))
    path.write_text(yaml.safe_dump(rendered), encoding="utf-8")

    with pytest.raises(hosted_model.HostedModelError, match="inside"):
        gen_override.generate_overrides(config_dir, repo_root)
    with pytest.raises(egress.EgressError, match="inside"):
        egress.render(config_dir, repo_root)


def test_the_preview_refuses_a_hosted_route_without_the_switch(repo_root, config_dir):
    _setup(repo_root, config_dir)
    draft = yaml.safe_dump({"model_list": [HOSTED]})

    with pytest.raises(render_core.RenderError, match="test-hosted-chat"):
        render_core.preview(config_dir, repo_root, render_core.LITELLM_CONFIG, draft)


# ─────────────────────────────────────────────────────────────────────────
# test profile: one hosted route, out through papaia-egress to one host
# ─────────────────────────────────────────────────────────────────────────


def test_the_test_profile_render_contains_the_hosted_route(repo_root, config_dir):
    _test_stack(repo_root, config_dir)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    [entry] = _rendered_models(config_dir)
    assert entry["model_name"] == "test-hosted-chat"
    assert entry["model_info"]["test_backend"] is True
    assert entry["litellm_params"]["api_key"] == f"os.environ/{KEY_VAR}"
    assert _egress_sources(config_dir) == [
        {
            "name": hosted_model.SOURCE,
            "alias": egress.alias(hosted_model.SOURCE),
            "allow": [{"host": "api.example.org", "ports": [443]}],
            "internal": [],
        }
    ]


def test_the_test_profile_puts_litellm_behind_the_exit(repo_root, config_dir):
    _test_stack(repo_root, config_dir)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    override = _override(config_dir)
    network = "papaia-litellm-egress"
    assert override["networks"] == {network: {"name": network, "internal": True}}
    litellm = override["services"]["litellm"]
    assert set(litellm["networks"]) == {"papaia-net", network}
    proxy = f"http://{egress.alias(hosted_model.SOURCE)}:{egress.PORT}"
    assert litellm["environment"]["HTTPS_PROXY"] == proxy
    assert litellm["environment"]["https_proxy"] == proxy
    # Plain http to a host outside the stack is denied at the exit, not sent directly.
    assert litellm["environment"]["HTTP_PROXY"] == proxy
    assert litellm["environment"]["http_proxy"] == proxy
    no_proxy = litellm["environment"]["NO_PROXY"].split(",")
    assert "keycloak" in no_proxy and "localhost" in no_proxy
    assert "api.example.org" not in no_proxy
    # The browser-facing login endpoint is not called by LiteLLM itself.
    assert "host.docker.internal" not in no_proxy
    assert litellm["env_file"] == [
        {"path": f"${{PAPAIA_CONFIG_DIR}}/{hosted_model.KEY_FILE}", "required": True}
    ]
    assert override["services"][egress.SERVICE]["networks"] == {
        egress.EGRESS_NETWORK: {},
        network: {"aliases": [egress.alias(hosted_model.SOURCE)]},
    }
    text = hosted_model.override_path(config_dir).read_text(encoding="utf-8")
    assert KEY_VALUE not in text


def test_model_services_inside_the_stack_bypass_the_exit(repo_root, config_dir):
    _stack_service(repo_root, "pruefmodell")
    _test_stack(repo_root, config_dir, HOSTED, _inside("https://pruefmodell:8443/v1"))

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    environment = _override(config_dir)["services"]["litellm"]["environment"]
    assert "pruefmodell" in environment["NO_PROXY"].split(",")
    assert environment["no_proxy"] == environment["NO_PROXY"]


def test_only_the_configured_login_host_bypasses_the_exit(repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    env = config_dir / "ai" / "litellm" / ".env"
    env.write_text(
        env.read_text(encoding="utf-8")
        + "GENERIC_EXTRA_URL=https://elsewhere.example.com/x\n"
        + "GENERIC_USERINFO_ENDPOINT=https://login.example.com/userinfo\n",
        encoding="utf-8",
    )

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    no_proxy = _override(config_dir)["services"]["litellm"]["environment"]["NO_PROXY"]
    assert "keycloak" in no_proxy.split(",")
    assert "elsewhere.example.com" not in no_proxy
    assert "login.example.com" not in no_proxy


def test_switching_the_test_profile_off_removes_route_source_and_override(
    repo_root, config_dir
):
    _test_stack(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    _set_root(config_dir, **{hosted_model.FLAG: ""})
    (config_dir / "overlay" / "ai" / "litellm" / "config.yaml").unlink()
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    assert _rendered_models(config_dir) == []
    assert _egress_sources(config_dir) == []
    assert not hosted_model.override_path(config_dir).exists()


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ({"api_key": KEY_VALUE}, "os.environ/"),
        ({"api_key": "os.environ/lower_case"}, "os.environ/"),
        ({"api_base": "os.environ/HOSTED_API_BASE"}, "https"),
        ({"api_base": "http://api.example.org/v1"}, "https"),
        ({"api_base": "https://user@api.example.org/v1"}, "https"),
        # A key in the URL would land in the rendered file, which every backup carries.
        ({"api_base": "https://api.example.org/v1?key=synthetic"}, "query"),
        ({"api_base": "https://api.example.org/v1#key"}, "query"),
        ({"api_base": "https://api.example.org\\@other.example.net/v1"}, "https"),
        ({"base_url": "https://other.example.net/v1"}, "base_url"),
        ({"aws_region_name": "eu-central-1"}, "aws_region_name"),
        ({"litellm_credential_name": "shared"}, "litellm_credential_name"),
        # A provider that may take its endpoint from region or project variables of the
        # container, not only from api_base.
        ({"model": "vertex_ai/reference-chat"}, "provider"),
        ({"model": "bedrock/reference-chat"}, "provider"),
        ({"model": "reference-chat"}, "provider"),
        ({"custom_llm_provider": "vertex_ai"}, "provider"),
        # Only a variable of its own namespace: a name the LiteLLM container sets itself
        # (DATABASE_URL with the database password) would go to the hosted host as bearer.
        ({"api_key": "os.environ/DATABASE_URL"}, "TEST_HOSTED_"),
        ({"api_key": "os.environ/LITELLM_MASTER_KEY"}, "TEST_HOSTED_"),
    ],
)
def test_the_test_profile_refuses_an_unusable_hosted_route(
    repo_root, config_dir, params, reason
):
    _test_stack(repo_root, config_dir, _hosted_entry(**params))

    with pytest.raises(render_core.RenderError) as caught:
        render_core.render(config_dir, repo_root)
    assert reason in str(caught.value)
    # The key never reaches a message.
    assert KEY_VALUE not in str(caught.value)


def test_the_test_profile_allows_exactly_one_hosted_host(repo_root, config_dir):
    second = _hosted_entry(api_base="https://other.example.net/v1")
    second["model_name"] = "second"
    _test_stack(repo_root, config_dir, HOSTED, second)

    with pytest.raises(render_core.RenderError, match="one host"):
        render_core.render(config_dir, repo_root)


def test_two_aliases_on_the_one_host_are_one_allow_list_entry(repo_root, config_dir):
    second = _hosted_entry()
    second["model_name"] = "test-hosted-embed"
    _test_stack(repo_root, config_dir, HOSTED, second)

    render_core.render(config_dir, repo_root)

    assert [e["model_name"] for e in _rendered_models(config_dir)] == [
        "test-hosted-chat",
        "test-hosted-embed",
    ]
    assert _egress_sources(config_dir)[0]["allow"] == [{"host": "api.example.org", "ports": [443]}]


@pytest.mark.parametrize(
    ("key_text", "mode", "reason"),
    [
        (None, 0o644, "0600"),
        ("OTHER=1\n", 0o600, KEY_VAR),
        (f"{KEY_VAR}=\n", 0o600, KEY_VAR),
        # Nothing else: the file is an env_file of LiteLLM and could change its settings.
        (f"{KEY_VAR}={KEY_VALUE}\nNO_PROXY=*\n", 0o600, "NO_PROXY"),
        (f"{KEY_VAR}={KEY_VALUE}\nTEST_HOSTED_UNUSED=x\n", 0o600, "TEST_HOSTED_UNUSED"),
    ],
)
def test_the_test_profile_needs_the_key_in_its_own_private_file(
    repo_root, config_dir, key_text, mode, reason
):
    _test_stack(repo_root, config_dir)
    _key_file(config_dir, key_text, mode)

    with pytest.raises(render_core.RenderError, match=reason) as caught:
        render_core.render(config_dir, repo_root)
    assert KEY_VALUE not in str(caught.value)


def test_the_key_file_may_not_be_a_symbolic_link(repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    path = config_dir / hosted_model.KEY_FILE
    # A target inside the configuration directory would be archived with the key.
    target = config_dir / "ai" / "key.env"
    path.rename(target)
    path.symlink_to(target)

    with pytest.raises(render_core.RenderError, match="regular file"):
        render_core.render(config_dir, repo_root)


def test_the_key_file_must_be_a_regular_file(repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    path = config_dir / hosted_model.KEY_FILE
    path.unlink()
    path.mkdir(mode=0o700)

    with pytest.raises(render_core.RenderError, match="regular file"):
        render_core.render(config_dir, repo_root)


def test_the_key_file_must_belong_to_the_installing_user(repo_root, config_dir, monkeypatch):
    _test_stack(repo_root, config_dir)
    owner = (config_dir / hosted_model.KEY_FILE).lstat().st_uid
    monkeypatch.setattr(hosted_model, "_owners", lambda _config_dir: {owner + 1})

    with pytest.raises(render_core.RenderError, match="belong"):
        render_core.render(config_dir, repo_root)


def test_an_empty_variable_of_the_same_name_in_the_litellm_env_is_no_key(
    repo_root, config_dir
):
    _test_stack(repo_root, config_dir)
    env = config_dir / "ai" / "litellm" / ".env"
    env.write_text(env.read_text(encoding="utf-8") + f"{KEY_VAR}=\n", encoding="utf-8")

    render_core.render(config_dir, repo_root)

    assert _rendered_models(config_dir)[0]["model_info"]["test_backend"] is True


def test_the_test_profile_without_the_key_file_is_refused(repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    (config_dir / hosted_model.KEY_FILE).unlink()

    with pytest.raises(render_core.RenderError, match="test-hosted.env"):
        render_core.render(config_dir, repo_root)


def test_the_key_must_not_sit_in_the_backed_up_litellm_env(repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    env = config_dir / "ai" / "litellm" / ".env"
    env.write_text(env.read_text(encoding="utf-8") + f"{KEY_VAR}={KEY_VALUE}\n", encoding="utf-8")

    with pytest.raises(render_core.RenderError, match="ai/litellm/.env") as caught:
        render_core.render(config_dir, repo_root)
    assert KEY_VALUE not in str(caught.value)


def test_the_test_profile_is_refused_on_a_distributed_installation(
    repo_root, config_dir, monkeypatch
):
    _test_stack(repo_root, config_dir)
    monkeypatch.setattr(topology, "is_distributed", lambda _config_dir: True)

    with pytest.raises(render_core.RenderError, match="single host"):
        render_core.render(config_dir, repo_root)


def test_an_addon_cannot_take_the_name_of_the_gateway_source(tmp_path, repo_root, config_dir):
    _test_stack(repo_root, config_dir)
    addon = tmp_path / "addons" / "litellm"
    addon.mkdir(parents=True)
    network = "papaia-litellm-egress"
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "litellm",
                "version": "1.0.0",
                "networks": {"egress": {"network": network, "allow": []}},
            }
        ),
        encoding="utf-8",
    )
    (addon / "docker-compose.yml").write_text(
        yaml.safe_dump({"networks": {"egress": {"name": network, "internal": True}}}),
        encoding="utf-8",
    )
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))
    deployed["addons"] = [{"name": "litellm", "path": str(addon), "active": True}]
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")

    with pytest.raises(render_core.RenderError, match="litellm"):
        render_core.render(config_dir, repo_root)


# ─────────────────────────────────────────────────────────────────────────
# the key stays out of every backup
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_the_config_dir_backup_leaves_the_key_file_out(tmp_path):
    log = tmp_path / "calls.log"
    source = tmp_path / "config"
    source.mkdir()
    archive = "papaia-config.tar.gz.age"
    harness = f"""
set -euo pipefail
info() {{ :; }}
warn() {{ :; }}
source "{BACKUP_SH.as_posix()}"
_docker_hostpath() {{ printf '%s' "$1"; }}
_docker_run() {{ printf '%s\\n' "$*" >> "{log.as_posix()}"; }}
_pause_containers() {{ :; }}
_unpause_all() {{ :; }}
py_cli() {{ cat >/dev/null; }}
_backup_artifact "{tmp_path.as_posix()}" configdir {archive} "{source.as_posix()}" core
"""
    done = subprocess.run([BASH, "-c", harness], capture_output=True, text=True, timeout=30)

    assert done.returncode == 0, done.stderr
    call = log.read_text(encoding="utf-8")
    assert f"--exclude=./{hosted_model.KEY_FILE}" in call
    assert call.index("--exclude") < call.index(" -C /src .")


def test_the_distributed_config_dir_backup_leaves_the_key_file_out(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def run(argv, stdout=None, **_kwargs):
        calls.append(argv)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.addfile(tarfile.TarInfo("./deployment.yaml"), io.BytesIO(b""))
        stdout.write(buf.getvalue())
        return subprocess.CompletedProcess(argv, 0)

    _identity, recipient = age.generate_identity()
    plan = SimpleNamespace(recipients=[backup.Recipient("betrieb", recipient)])
    monkeypatch.setattr(cluster_data.backup, "read_plan", lambda _snapshot: plan)
    monkeypatch.setattr(cluster_data.subprocess, "run", run)
    fake = type("Cluster", (), {"config_dir": tmp_path / "config"})()

    assert cluster_data._archive_config_dir(fake, tmp_path, "papaia-config.tar.gz.age")
    [argv] = calls
    exclude = f"--exclude=./{hosted_model.KEY_FILE}"
    assert exclude in argv
    assert argv.index(exclude) < argv.index("-C")


def test_the_key_file_name_is_what_the_backup_shell_excludes():
    text = BACKUP_SH.read_text(encoding="utf-8")
    assert f"--exclude=./{hosted_model.KEY_FILE}" in text
    assert os.path.basename(hosted_model.KEY_FILE) == "test-hosted.env"


# ─────────────────────────────────────────────────────────────────────────
# shipped files: no call outside the stack, no hosted key in a backed-up file
# ─────────────────────────────────────────────────────────────────────────


def test_litellm_reads_its_model_cost_map_from_the_image():
    compose = yaml.safe_load(
        (REAL_REPO / "src" / "ai" / "litellm" / "docker-compose.yml").read_text(encoding="utf-8")
    )
    # Without it LiteLLM fetches the map from the internet at every start.
    environment = compose["services"]["litellm"]["environment"]
    assert environment["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"


def test_the_litellm_env_example_asks_for_no_hosted_provider_key():
    env = common.parse_env_file(REAL_REPO / "src" / "ai" / "litellm" / ".env.example")
    keys = {k for k in env if k.endswith(("_API_KEY", "_API_BASE"))}
    assert keys == {"LOCALAI_API_KEY", "VOICE_API_KEY"}


def test_the_shipped_hosted_example_passes_the_test_stack(repo_root, config_dir):
    text = (REAL_REPO / "src" / "ai" / "litellm" / "config.yaml").read_text(encoding="utf-8")
    block = text.split("# >>> hosted example\n", 1)[1].split("# <<< hosted example", 1)[0]
    example = yaml.safe_load("\n".join(line.strip()[2:] for line in block.splitlines()))
    _test_stack(repo_root, config_dir, *example)

    render_core.render(config_dir, repo_root)

    assert all(e["model_info"]["test_backend"] for e in _rendered_models(config_dir))
