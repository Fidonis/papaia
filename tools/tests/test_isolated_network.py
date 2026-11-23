"""Isolated add-on networks (addon_api 16, ADR 0026).

An add-on may declare internal networks next to its `app_network` that the core joins
with LiteLLM and nothing else:

    networks:
      app_network: ${PAPAIA_PROJECT:-papaia}-<name>-net
      attach: [...]
      isolated:
        - network: ${PAPAIA_PROJECT:-papaia}-<name>-reader-net
          attach: [litellm]

The override generation puts exactly the listed services on each isolated network and
leaves every other attachment where it was; the compatibility check refuses every
declaration that would widen the isolation.
"""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

import pytest
import yaml

from lib import cli_addon, common, compat, deployment, envtree, gen_override

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GOLDEN = Path(__file__).parent / "golden" / "addon-overrides"
REPO = Path(__file__).resolve().parents[2]
UPDATE = os.environ.get("PAPAIA_UPDATE_GOLDEN") == "1"

READER = "${PAPAIA_PROJECT:-papaia}-reader-reader-net"
PARSER = "${PAPAIA_PROJECT:-papaia}-reader-parse-net"


def _manifest(isolated: object = None, **networks: object) -> dict:
    body: dict = {
        "app_network": "${PAPAIA_PROJECT:-papaia}-reader-net",
        "attach": ["nginx-proxy-manager", "keycloak"],
        **networks,
    }
    if isolated is not None:
        body["isolated"] = isolated
    return {"name": "reader", "requires": {"addon_api": [16]}, "networks": body}


def _compose(*networks: str, internal: bool = True) -> dict:
    """The add-on's own compose file: a reader only on the isolated networks, an app
    service on the app network."""
    declared: dict = {"app": {"name": "${PAPAIA_PROJECT:-papaia}-reader-net"}}
    for index, name in enumerate(networks):
        declared[f"iso{index}"] = {"name": name, "internal": internal}
    return {
        "services": {
            "app": {"image": "busybox", "networks": ["app"]},
            "reader": {"image": "busybox", "networks": [f"iso{i}" for i in range(len(networks))]},
        },
        "networks": declared,
    }


def _addon(tmp_path: Path, compose: dict | None) -> Path:
    path = tmp_path / "addons" / "reader"
    path.mkdir(parents=True)
    if compose is not None:
        (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    return path


def _render(manifest: dict, config_dir: Path, addon_path: Path | None) -> dict:
    (config_dir / "overrides").mkdir(parents=True, exist_ok=True)
    out = gen_override.generate_override(manifest, config_dir, addon_path)
    assert out is not None
    return yaml.safe_load(out.read_text(encoding="utf-8"))


# ── rendering ─────────────────────────────────────────────────────────────────


def test_litellm_joins_the_isolated_network_and_no_other_addon_network(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest([{"network": READER, "attach": ["litellm"]}])
    override = _render(manifest, tmp_path / "config", addon)

    assert override["services"]["litellm"] == {"networks": ["papaia-reader-reader-net"]}
    # The app network keeps exactly the attachments it had; nothing else joins the
    # isolated network.
    assert override["services"]["nginx-proxy-manager"] == {"networks": ["papaia-reader-net"]}
    assert override["services"]["keycloak"] == {"networks": ["papaia-reader-net"]}
    assert override["networks"] == {
        "papaia-reader-net": {"external": True},
        "papaia-reader-reader-net": {"external": True},
    }


def test_litellm_on_the_app_network_as_well_keeps_both(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest(
        [{"network": READER, "attach": ["litellm"]}],
        attach=["nginx-proxy-manager", "litellm"],
    )
    override = _render(manifest, tmp_path / "config", addon)

    assert override["services"]["litellm"] == {
        "networks": ["papaia-reader-net", "papaia-reader-reader-net"]
    }
    assert override["services"]["nginx-proxy-manager"] == {"networks": ["papaia-reader-net"]}


def test_app_network_attachments_are_unchanged_by_the_isolated_key(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    plain = _render(_manifest(), tmp_path / "plain", addon)
    isolated = _render(
        _manifest([{"network": READER, "attach": ["litellm"]}]), tmp_path / "isolated", addon
    )
    del isolated["services"]["litellm"]
    del isolated["networks"]["papaia-reader-reader-net"]
    assert isolated == plain


def test_two_isolated_networks_render_independently(tmp_path):
    addon = _addon(tmp_path, _compose(READER, PARSER))
    manifest = _manifest(
        [
            {"network": READER, "attach": ["litellm"]},
            {"network": PARSER, "attach": ["litellm"]},
        ]
    )
    override = _render(manifest, tmp_path / "config", addon)

    assert override["services"]["litellm"] == {
        "networks": ["papaia-reader-reader-net", "papaia-reader-parse-net"]
    }
    for service in ("nginx-proxy-manager", "keycloak"):
        assert override["services"][service] == {"networks": ["papaia-reader-net"]}
    assert set(override["networks"]) == {
        "papaia-reader-net",
        "papaia-reader-reader-net",
        "papaia-reader-parse-net",
    }


def test_the_isolated_network_follows_the_deployment_scope(config_dir, repo_root, tmp_path):
    envtree.init(config_dir, repo_root, env_name="papaia")
    env = common.parse_env_file(config_dir / ".env")
    env["PAPAIA_PROJECT"] = "acme"
    common.write_env_file(config_dir / ".env", env)
    addon = _addon(tmp_path, _compose(READER))
    override = _render(
        _manifest([{"network": READER, "attach": ["litellm"]}]), config_dir, addon
    )
    assert override["services"]["litellm"] == {"networks": ["acme-reader-reader-net"]}
    assert override["services"]["keycloak"] == {"networks": ["acme-reader-net"]}


def test_the_ingress_proxy_stays_on_the_app_network_only(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest([{"network": READER, "attach": ["litellm"]}], attach=[])
    manifest["integration"] = {"nginx": [{"host_key": "reader", "service": "app", "port": 8080}]}
    override = _render(manifest, tmp_path / "config", addon)

    assert override["services"] == {
        "nginx-proxy-manager": {"networks": ["papaia-reader-net"]},
        "litellm": {"networks": ["papaia-reader-reader-net"]},
    }


def test_an_isolated_network_without_app_attachments_still_renders(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    override = _render(
        _manifest([{"network": READER, "attach": ["litellm"]}], attach=[]),
        tmp_path / "config",
        addon,
    )
    assert override == {
        "services": {"litellm": {"networks": ["papaia-reader-reader-net"]}},
        "networks": {"papaia-reader-reader-net": {"external": True}},
    }


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"network": READER, "attach": ["keycloak"]}, "keycloak"),
        ({"network": READER, "attach": []}, "attach"),
        ({"network": "${PAPAIA_PROJECT:-papaia}-reader-net", "attach": ["litellm"]}, "app_network"),
    ],
)
def test_the_render_refuses_what_the_check_refuses(tmp_path, entry, message):
    addon = _addon(tmp_path, _compose(READER))
    (tmp_path / "config" / "overrides").mkdir(parents=True)
    with pytest.raises(ValueError, match=r"networks\.isolated\[0\]") as caught:
        gen_override.generate_override(_manifest([entry]), tmp_path / "config", addon)
    assert message in str(caught.value)
    assert not list((tmp_path / "config" / "overrides").glob("*.yml"))


def test_the_render_refuses_a_network_that_is_not_internal(tmp_path):
    addon = _addon(tmp_path, _compose(READER, internal=False))
    (tmp_path / "config" / "overrides").mkdir(parents=True)
    with pytest.raises(ValueError, match="internal: true"):
        gen_override.generate_override(
            _manifest([{"network": READER, "attach": ["litellm"]}]), tmp_path / "config", addon
        )


def test_the_render_needs_the_addon_directory_to_check_internal(tmp_path):
    (tmp_path / "config" / "overrides").mkdir(parents=True)
    with pytest.raises(ValueError, match="internal: true"):
        gen_override.generate_override(
            _manifest([{"network": READER, "attach": ["litellm"]}]), tmp_path / "config", None
        )


def test_generate_overrides_refuses_an_isolated_network_another_addon_claims(
    config_dir, repo_root, tmp_path
):
    envtree.init(config_dir, repo_root, env_name="papaia")
    reader = _addon(tmp_path, _compose("papaia-reader-x-net"))
    (reader / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            _manifest([{"network": "papaia-reader-x-net", "attach": ["litellm"]}])
        ),
        encoding="utf-8",
    )
    other = tmp_path / "addons" / "reader-x"
    other.mkdir()
    (other / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            {"name": "reader-x", "networks": {"app_network": "papaia-reader-x-net",
                                              "attach": ["keycloak"]}}
        ),
        encoding="utf-8",
    )
    deployed = deployment.load(config_dir)
    deployed["addons"] = [
        {"name": "reader", "path": str(reader), "active": True},
        {"name": "reader-x", "path": str(other), "active": False},
    ]
    deployment.save(config_dir, deployed)
    with pytest.raises(ValueError, match="reader-x"):
        gen_override.generate_overrides(config_dir, repo_root)


# ── golden: no isolated key, byte-identical output ────────────────────────────


def _golden_cases(tmp_path: Path) -> dict[str, tuple[dict, Path | None]]:
    paperless = yaml.safe_load(
        (FIXTURES_DIR / "addon-paperless" / "papaia-app.yaml").read_text(encoding="utf-8")
    )
    ingress = yaml.safe_load(
        (FIXTURES_DIR / "addon-ingress-apps" / "papaia-app.yaml").read_text(encoding="utf-8")
    )
    return {
        "literal": (
            {"name": "docs", "networks": {"app_network": "papaia-docs-net",
                                          "attach": ["librechat", "litellm"]}},
            None,
        ),
        "templated": (
            {"name": "docs", "networks": {"app_network": "${PAPAIA_PROJECT:-papaia}-docs-net",
                                          "attach": ["nginx-proxy-manager", "keycloak",
                                                     "litellm", "papaia-audit", "smtp-relay"]}},
            None,
        ),
        "paperless-front": (paperless, None),
        "ingress": (ingress, None),
    }


@pytest.mark.parametrize("case", ["literal", "templated", "paperless-front", "ingress"])
def test_without_the_key_the_override_is_byte_identical(tmp_path, case):
    manifest, addon_path = _golden_cases(tmp_path)[case]
    config_dir = tmp_path / "config"
    (config_dir / "overrides").mkdir(parents=True)
    out = gen_override.generate_override(manifest, config_dir, addon_path)
    assert out is not None
    text = out.read_text(encoding="utf-8")
    # Kept as .golden: the exact bytes yaml.safe_dump writes, whose indentation yamllint flags.
    golden = GOLDEN / f"{case}.override.yml.golden"
    if UPDATE:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")


# ── compatibility check ───────────────────────────────────────────────────────


def _core(addon_api: tuple[int, int] = (1, 16), networks: frozenset[str] | None = None):
    return compat.CoreTarget(
        platform_version="1.10.0",
        addon_api=addon_api,
        services={"litellm": ["litellm"], "keycloak": ["keycloak"],
                  "nginx-proxy-manager": ["nginx"], "papaia-audit-db": ["audit"]},
        networks=networks,
    )


def _evaluate(manifest: dict, addon_path: Path | None, core=None) -> compat.CompatResult:
    return compat.evaluate_addon("reader", manifest, core or _core(), addon_path=addon_path)


def test_a_valid_isolated_network_is_compatible(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    result = _evaluate(_manifest([{"network": READER, "attach": ["litellm"]}]), addon)
    assert result.status == compat.STATUS_OK, result.reason
    assert result.warnings == ()


def test_a_missing_internal_flag_is_refused_with_the_entry_named(tmp_path):
    addon = _addon(tmp_path, _compose(READER, internal=False))
    result = _evaluate(_manifest([{"network": READER, "attach": ["litellm"]}]), addon)
    assert result.status == compat.STATUS_ERROR
    assert result.axis == compat.ISOLATED_AXIS
    assert "networks.isolated[0]" in result.reason
    assert "internal: true" in result.reason


def test_a_network_the_compose_file_does_not_create_is_refused(tmp_path):
    addon = _addon(tmp_path, _compose(PARSER))
    result = _evaluate(_manifest([{"network": READER, "attach": ["litellm"]}]), addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[0]" in result.reason


def test_an_addon_without_a_compose_file_is_refused(tmp_path):
    addon = _addon(tmp_path, None)
    result = _evaluate(_manifest([{"network": READER, "attach": ["litellm"]}]), addon)
    assert result.status == compat.STATUS_ERROR
    assert "internal: true" in result.reason


@pytest.mark.parametrize(
    ("attach", "named"),
    [
        (["keycloak"], "'keycloak'"),
        (["nginx-proxy-manager"], "'nginx-proxy-manager'"),
        (["litellm", "keycloak"], "'keycloak'"),
        (["papaia-audit-db"], "'papaia-audit-db'"),
        (["papaia-docker-gate"], "'papaia-docker-gate'"),
    ],
)
def test_a_service_outside_the_allow_list_is_refused(tmp_path, attach, named):
    addon = _addon(tmp_path, _compose(READER))
    result = _evaluate(_manifest([{"network": READER, "attach": attach}]), addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[0]" in result.reason
    assert named in result.reason


def test_every_never_attachable_service_is_outside_the_allow_list():
    assert not compat.ISOLATED_ATTACHABLE & compat.NEVER_ATTACHABLE
    assert compat.ISOLATED_ATTACHABLE == frozenset({"litellm"})


@pytest.mark.parametrize(
    ("entry", "fragment"),
    [
        ({"network": READER, "attach": []}, "attach"),
        ({"network": READER}, "attach"),
        ({"network": READER, "attach": "litellm"}, "attach"),
        ({"network": READER, "attach": ["litellm", "litellm"]}, "twice"),
        ({"network": READER, "attach": ["litellm"], "aliases": ["x"]}, "unknown field"),
        ({"attach": ["litellm"]}, "network"),
        ({"network": 7, "attach": ["litellm"]}, "network"),
        ({"network": "papaia-other-reader-net", "attach": ["litellm"]}, "scoped"),
        ({"network": "${HOME}-reader-x-net", "attach": ["litellm"]}, "scoped"),
        ({"network": "${PAPAIA_PROJECT:-papaia}-reader-", "attach": ["litellm"]}, "scoped"),
        ("litellm", "mapping"),
    ],
)
def test_a_malformed_entry_is_refused_with_the_entry_named(tmp_path, entry, fragment):
    addon = _addon(tmp_path, _compose(READER))
    result = _evaluate(_manifest([entry]), addon)
    assert result.status == compat.STATUS_ERROR
    assert result.axis == compat.ISOLATED_AXIS
    assert "networks.isolated[0]" in result.reason
    assert fragment in result.reason


@pytest.mark.parametrize("isolated", [[], {"network": READER}, "x"])
def test_the_key_must_be_a_non_empty_list(tmp_path, isolated):
    addon = _addon(tmp_path, _compose(READER))
    result = _evaluate(_manifest(isolated), addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated" in result.reason


def test_too_many_entries_are_refused(tmp_path):
    names = [f"${{PAPAIA_PROJECT:-papaia}}-reader-n{i}-net" for i in range(9)]
    addon = _addon(tmp_path, _compose(*names))
    result = _evaluate(_manifest([{"network": n, "attach": ["litellm"]} for n in names]), addon)
    assert result.status == compat.STATUS_ERROR
    assert "at most 8" in result.reason


@pytest.mark.parametrize(
    "app_network", ["${PAPAIA_PROJECT:-papaia}-reader-net", "papaia-reader-net"]
)
def test_the_app_network_cannot_be_isolated(tmp_path, app_network):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest(
        [{"network": "${PAPAIA_PROJECT:-papaia}-reader-net", "attach": ["litellm"]}],
        app_network=app_network,
    )
    result = _evaluate(manifest, addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[0]" in result.reason
    assert "app_network" in result.reason


def test_two_entries_cannot_name_the_same_network(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest(
        [
            {"network": READER, "attach": ["litellm"]},
            {"network": "papaia-reader-reader-net", "attach": ["litellm"]},
        ]
    )
    result = _evaluate(manifest, addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[1]" in result.reason
    assert "networks.isolated[0]" in result.reason


def test_the_egress_network_cannot_be_isolated(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest(
        [{"network": READER, "attach": ["litellm"]}],
        egress={"network": READER, "allow": []},
    )
    result = _evaluate(manifest, addon)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[0]" in result.reason
    assert "egress" in result.reason


def test_a_core_network_cannot_be_isolated(tmp_path):
    # An add-on named `audit` could otherwise put LiteLLM on the audit database's network.
    path = tmp_path / "addons" / "audit"
    path.mkdir(parents=True)
    compose = {"networks": {"x": {"name": "papaia-audit-net", "internal": True}}}
    (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    manifest = {
        "name": "audit",
        "networks": {
            "app_network": "papaia-audit-app-net",
            "attach": ["keycloak"],
            "isolated": [{"network": "papaia-audit-net", "attach": ["litellm"]}],
        },
    }
    core = _core(networks=compat.resolve_core_networks(REPO))
    result = compat.evaluate_addon("audit", manifest, core, addon_path=path)
    assert result.status == compat.STATUS_ERROR
    assert "networks.isolated[0]" in result.reason
    assert "core network" in result.reason


def test_the_core_networks_include_every_declared_network():
    networks = compat.resolve_core_networks(REPO)
    assert networks is not None
    for key in ("papaia-net", "papaia-audit-net", "papaia-egress-net", "papaia-prefs-db-net"):
        assert key in networks
        assert f"papaia_{key}" in networks
    assert {"bridge", "host", "none"} <= networks
    assert compat.resolve_core_target(REPO).networks == networks


def test_the_core_networks_of_a_checkout_without_compose_are_unknown(tmp_path):
    assert compat.resolve_core_networks(tmp_path) is None


def test_a_core_below_the_generation_refuses_the_key(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest([{"network": READER, "attach": ["litellm"]}])
    manifest["requires"] = {"addon_api": [7, 16]}
    result = _evaluate(manifest, addon, _core(addon_api=(1, 15)))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "`networks.isolated` (addon_api 16)" in result.reason
    assert "missing generation 16" in result.reason
    assert compat.gate([result], mode=compat.MODE_ENFORCE) == 2


def test_the_key_above_the_declared_generations_warns(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    manifest = _manifest([{"network": READER, "attach": ["litellm"]}])
    manifest["requires"] = {"addon_api": [12]}
    result = _evaluate(manifest, addon)
    assert result.status == compat.STATUS_OK
    assert any("networks.isolated" in warning for warning in result.warnings)


def test_without_the_addon_directory_the_internal_flag_is_reported_unchecked():
    result = _evaluate(_manifest([{"network": READER, "attach": ["litellm"]}]), None)
    assert result.status == compat.STATUS_OK
    assert any("internal: true" in warning for warning in result.warnings)


def test_a_refused_declaration_cannot_be_forced(tmp_path):
    addon = _addon(tmp_path, _compose(READER))
    result = _evaluate(_manifest([{"network": READER, "attach": ["keycloak"]}]), addon)
    assert compat.gate([result], mode=compat.MODE_WARN, force=True) == 2


def test_addon_check_reads_the_compose_file_of_each_addon(config_dir, repo_root, tmp_path):
    envtree.init(config_dir, repo_root, env_name="papaia")
    addon = _addon(tmp_path, _compose(READER, internal=False))
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump(_manifest([{"network": READER, "attach": ["litellm"]}])), "utf-8"
    )
    deployed = deployment.load(config_dir)
    deployed["addons"] = [{"name": "reader", "path": str(addon), "active": True}]
    (results,) = [cli_addon.evaluate_active_addons(deployed, repo_root, _core())]
    assert [r.status for r in results] == [compat.STATUS_ERROR]
    assert "internal: true" in results[0].reason


def test_install_refuses_an_isolated_network_that_is_not_internal(
    config_dir, repo_root, tmp_path, capsys
):
    envtree.init(config_dir, repo_root, env_name="papaia")
    shutil.copy(REPO / "ADDON_API", repo_root / "ADDON_API")
    addon = _addon(tmp_path, _compose(READER, internal=False))
    (addon / "papaia-app.yaml").write_text(
        yaml.safe_dump(_manifest([{"network": READER, "attach": ["litellm"]}])), "utf-8"
    )
    before = (config_dir / "deployment.yaml").read_text(encoding="utf-8")
    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name="reader",
        path=str(addon), version=None, force=True,
    )
    code = cli_addon.cmd_addon_install(args)
    assert code == 2
    assert "internal: true" in capsys.readouterr().err
    assert (config_dir / "deployment.yaml").read_text(encoding="utf-8") == before
