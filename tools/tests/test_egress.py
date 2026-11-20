"""papaia-egress, the single exit of the stack: the compose service, the configuration
`papaia-ctl` renders for it, the attachment to the egress network of each add-on, and the
decisions of the proxy itself.

The proxy (`src/infra/egress/egress.py`) runs in a stock Python image, so its decision
logic is imported here straight from the checkout. The end-to-end check with real
containers is `test_egress_docker.py`.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import sys
import types
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation

from lib import common, compat, deployment, egress, gen_override, render_core, resolve, topology

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "egress"
NET = "papaia-probe-egress"  # the egress network of the add-on `probe` in project `papaia`
UUID7 = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def _proxy():
    """The proxy module, loaded without leaving a bytecode cache in the source tree."""
    path = MODULE_DIR / "egress.py"
    module = types.ModuleType("papaia_egress_proxy")
    module.__file__ = str(path)
    # Dataclasses look their module up while the class is created.
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


proxy = _proxy()


def _compose() -> dict:
    return yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


def _service() -> dict:
    return _compose()["services"][egress.SERVICE]


# ─────────────────────────────────────────────────────────────────────────
# compose service
# ─────────────────────────────────────────────────────────────────────────


def test_the_root_compose_includes_the_service_under_the_egress_profile():
    services = compat.resolve_core_services(REPO)

    assert services[egress.SERVICE] == [egress.PROFILE]


def test_the_service_has_no_published_port_and_only_its_own_network():
    compose = _compose()
    service = _service()

    assert set(compose["services"]) == {egress.SERVICE}
    assert "ports" not in service
    assert service["networks"] == [egress.EGRESS_NETWORK]
    # The one network with a way out; nothing in papaia-net can bypass the allow list
    # by talking to the proxy, and the proxy cannot reach the internal services.
    assert set(compose["networks"]) == {egress.EGRESS_NETWORK}
    assert not (compose["networks"][egress.EGRESS_NETWORK] or {}).get("internal")


def test_the_service_runs_without_privileges_on_a_pinned_image():
    service = _service()

    pinned = r"python:\d+\.\d+\.\d+-alpine\d+\.\d+@sha256:[0-9a-f]{64}"
    assert re.fullmatch(pinned, service["image"])
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["user"] == "${UID:-1000}:${GID:-1000}"
    assert service["profiles"] == [egress.PROFILE]


def test_the_service_reads_its_configuration_read_only_from_the_config_dir():
    mounts = {m["target"]: m for m in _service()["volumes"]}

    config = mounts["/etc/papaia-egress"]
    assert config["source"] == "${PAPAIA_CONFIG_DIR}/infra/egress"
    assert config["read_only"] is True
    assert config["bind"]["create_host_path"] is False
    program = mounts["/opt/papaia-egress/egress.py"]
    assert program["source"] == "./egress.py"
    assert program["read_only"] is True


def test_the_healthcheck_looks_for_the_listener_of_the_proxy_port():
    test = " ".join(_service()["healthcheck"]["test"])

    assert f":{egress.PORT:04X} " in test


def test_egress_is_an_always_active_core_profile_in_the_shipped_defaults():
    env_example = (REPO / "src" / ".env.example").read_text(encoding="utf-8")
    profiles = re.search(r"^COMPOSE_PROFILES=(.*)$", env_example, re.M).group(1).split(",")
    template = yaml.safe_load((REPO / "tools" / "deployment.template.yaml").read_text())

    assert egress.PROFILE in profiles
    assert egress.PROFILE in template["core"]["profiles"]


def test_setup_always_activates_the_egress_profile():
    tree = {"": {"COMPOSE_PROFILES": "keycloak,litellm"}}

    tree = resolve.resolve_core_profiles(tree)
    tree = resolve.resolve_core_profiles(tree)

    assert tree[""]["COMPOSE_PROFILES"].split(",") == ["keycloak", "litellm", "egress"]


def test_the_egress_service_stays_on_the_controller():
    assert topology.service_of_profile(egress.PROFILE) == "egress"
    assert "egress" in topology.CONTROLLER_ONLY


def test_every_compose_variable_of_the_service_is_documented():
    text = (MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    documented = (REPO / "src" / ".env.example").read_text(encoding="utf-8")

    for var in set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)", code)):
        assert re.search(rf"^{var}=", documented, re.M), var


# ─────────────────────────────────────────────────────────────────────────
# rendered configuration
# ─────────────────────────────────────────────────────────────────────────


def _env(config_dir: Path, **values: str) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    lines = {"PAPAIA_PROJECT": "papaia", **values}
    (config_dir / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in lines.items()), encoding="utf-8"
    )


def _addon(
    tmp_path: Path, config_dir: Path, name: str, networks: dict, active=True, compose=None
) -> Path:
    """One add-on checkout in deployment.yaml. Unless `compose` says otherwise, its compose
    file creates the declared egress network as `internal: true`, as the contract asks."""
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    manifest = {"name": name, "version": "1.0.0", "networks": networks}
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    if compose is None:
        declared = networks.get("egress") if isinstance(networks, dict) else None
        network = declared.get("network") if isinstance(declared, dict) else None
        if isinstance(network, str):
            compose = {"networks": {"egress": {"name": network, "internal": True}}}
    if compose is not None:
        (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    deployed = deployment.load(config_dir) or {"addons": []}
    deployed["addons"].append({"name": name, "path": str(path), "active": active})
    deployment.save(config_dir, deployed)
    return path


def _protected(config_dir: Path, entries) -> None:
    path = config_dir / egress.PROTECTED_HOSTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(entries), encoding="utf-8")


def _internal_targets(config_dir: Path, entries) -> None:
    path = config_dir / egress.INTERNAL_TARGETS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(entries), encoding="utf-8")


def _rendered(config_dir: Path) -> dict:
    return json.loads((config_dir / egress.CONFIG_FILE).read_text(encoding="utf-8"))


def test_a_fresh_installation_renders_no_target_at_all(config_dir, repo_root):
    _env(config_dir)

    egress.render(config_dir)

    config = _rendered(config_dir)
    assert config == {
        "format": egress.CONFIG_FORMAT,
        "sources": [],
        "protected": [],
        "upstream": None,
    }
    # The protected hosts list is seeded empty for the operator to fill in, and so is the
    # list of internal targets: no add-on reaches an internal address by default.
    assert yaml.safe_load((config_dir / egress.PROTECTED_HOSTS_FILE).read_text()) == []
    assert yaml.safe_load((config_dir / egress.INTERNAL_TARGETS_FILE).read_text()) == []


def test_setup_renders_the_exit_and_turns_its_profile_on(tmp_path):
    inst = Installation(tmp_path, [])
    inst.setup("--app-host=https://papaia.example.org")

    assert _rendered(inst.config)["sources"] == []
    profiles = common.parse_env_file(inst.config / ".env")["COMPOSE_PROFILES"].split(",")
    assert egress.PROFILE in profiles
    assert egress.PROFILE in deployment.load(inst.config)["core"]["profiles"]


def test_an_invalid_protected_hosts_list_stops_the_core_render(tmp_path):
    inst = Installation(tmp_path, [])
    inst.setup("--app-host=https://papaia.example.org")
    _protected(inst.config, [{"name": "erp", "hosts": ["*"]}])

    with pytest.raises(render_core.RenderError, match="protected-hosts.yaml"):
        render_core.render(inst.config, inst.repo)


def test_each_active_addon_with_an_egress_network_is_one_source(tmp_path, config_dir):
    _env(config_dir, PAPAIA_PROJECT="papaia-dev")
    allow = [{"host": "API.Example.org.", "ports": [443]}, {"host": "192.0.2.10", "ports": [8443]}]
    _addon(
        tmp_path,
        config_dir,
        "probe",
        {"egress": {"network": "${PAPAIA_PROJECT:-papaia}-probe-egress", "allow": allow}},
    )
    _addon(tmp_path, config_dir, "idle", {"egress": {"network": "idle-egress"}}, active=False)
    _addon(tmp_path, config_dir, "plain", {"app_network": "plain-net", "attach": ["litellm"]})

    egress.render(config_dir)

    assert _rendered(config_dir)["sources"] == [
        {
            "name": "probe",
            "alias": "egress-probe",
            "allow": [
                {"host": "api.example.org", "ports": [443]},
                {"host": "192.0.2.10", "ports": [8443]},
            ],
            "internal": [],
        }
    ]


def test_the_protected_hosts_list_is_validated_and_passed_on(config_dir):
    _env(config_dir)
    entry = {
        "name": "erp",
        "hosts": ["ERP-sql.firma.local", "10.20.0.15/32", "2001:db8::/64"],
        "ports": [1433],
        "catalog_entry": "mssql.erp",
    }
    _protected(config_dir, [entry])

    egress.render(config_dir)

    assert _rendered(config_dir)["protected"] == [
        {"name": "erp", "hosts": ["erp-sql.firma.local", "10.20.0.15/32", "2001:db8::/64"]}
    ]


@pytest.mark.parametrize(
    "entries",
    [
        {"name": "erp"},  # not a list
        [{"name": "erp", "hosts": ["db"], "comment": "x"}],  # unknown field
        [{"name": "erp", "hosts": []}],
        [{"name": "erp", "hosts": ["db_server"]}],
        [{"name": "erp", "hosts": ["*.firma.local"]}],
        [{"name": "erp", "hosts": ["db"], "ports": [0]}],
        [{"name": "erp", "hosts": ["db"], "ports": [True]}],
        [{"name": "Erp Server", "hosts": ["db"]}],
        [{"hosts": ["db"]}],
    ],
)
def test_an_invalid_protected_hosts_list_fails_the_render(config_dir, entries):
    _env(config_dir)
    _protected(config_dir, entries)

    with pytest.raises(egress.EgressError, match="protected-hosts.yaml"):
        egress.render(config_dir)


@pytest.mark.parametrize(
    "declaration",
    [
        {"network": NET, "allow": [{"host": "*.example.org", "ports": [443]}]},
        {"network": NET, "allow": [{"host": "example.org"}]},
        {"network": NET, "allow": [{"host": "example.org", "ports": [70000]}]},
        {"network": NET, "allow": [{"host": "10.0.0.0/8", "ports": [443]}]},
        {"network": NET, "allow": [{"host": "example.org", "ports": [443], "via": "x"}]},
        {"network": NET, "proxy": "x"},
        # Internal targets are opened by the operator, never by the add-on itself.
        {"network": NET, "internal": ["10.0.0.0/8"]},
        {"allow": []},
        {"network": "bad name"},
    ],
)
def test_an_invalid_egress_declaration_fails_the_render(tmp_path, config_dir, declaration):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": declaration})

    with pytest.raises(egress.EgressError, match="probe"):
        egress.render(config_dir)


@pytest.mark.parametrize(
    "host",
    [
        # A single label is a service name inside the stack (Docker DNS), not the outside.
        "allowed-target",
        "keycloak",
        "localhost",
        # The proxy's own aliases and the stack's services, also with a domain.
        "egress-other",
        "egress-other.example.org",
        "papaia-keycloak.example.org",
        # The Docker host.
        "host.docker.internal",
        "gateway.docker.internal",
        "api.localhost",
    ],
)
def test_an_allow_list_cannot_name_a_host_inside_the_stack(tmp_path, config_dir, host):
    _env(config_dir)
    _addon(
        tmp_path,
        config_dir,
        "probe",
        {"egress": {"network": NET, "allow": [{"host": host, "ports": [3128]}]}},
    )

    with pytest.raises(egress.EgressError, match="probe"):
        egress.render(config_dir)


@pytest.mark.parametrize(
    "network",
    [
        # Not scoped to this deployment and this add-on.
        "probe-egress",
        "papaia-other-egress",
        "papaia-proberx-egress",
        # The core network, Docker's own networks and the exit network of the proxy.
        "papaia-net",
        "bridge",
        "host",
        "none",
        "papaia-egress-net",
        "papaia_papaia-egress-net",
    ],
)
def test_the_egress_network_must_belong_to_the_addon(tmp_path, config_dir, network):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": network}})

    with pytest.raises(egress.EgressError, match="probe"):
        egress.render(config_dir)
    with pytest.raises(egress.EgressError, match="probe"):
        gen_override.generate_overrides(config_dir, tmp_path)
    assert not egress.override_path(config_dir, "probe").exists()


def test_the_egress_network_cannot_be_the_core_network_of_the_deployment(tmp_path, config_dir):
    # The core network name is configurable; a name that fits the add-on's prefix is
    # still refused when the deployment uses it for papaia-net.
    _env(config_dir, DOCKER_NETWORK="papaia-probe-net")
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": "papaia-probe-net"}})

    with pytest.raises(egress.EgressError, match="DOCKER_NETWORK|core"):
        egress.render(config_dir)


def test_the_egress_network_cannot_be_the_addons_own_app_network(tmp_path, config_dir):
    # Core services join the app network through `attach`; on the egress network they
    # would count as the add-on and use its allow list.
    _env(config_dir)
    networks = {
        "app_network": "${PAPAIA_PROJECT:-papaia}-probe-net",
        "attach": ["nginx"],
        "egress": {"network": "${PAPAIA_PROJECT}-probe-net"},
    }
    _addon(tmp_path, config_dir, "probe", networks)

    with pytest.raises(egress.EgressError, match="app_network"):
        egress.render(config_dir)


def test_the_egress_network_cannot_be_a_network_of_another_addon(tmp_path, config_dir):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": "papaia-probe-x-egress"}})
    _addon(tmp_path, config_dir, "probe-x", {"egress": {"network": "papaia-probe-x-egress"}})

    with pytest.raises(egress.EgressError, match="probe-x"):
        egress.render(config_dir)


def test_the_egress_network_cannot_be_the_app_network_of_another_addon(tmp_path, config_dir):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}})
    other = {"app_network": NET, "attach": ["librechat"]}
    _addon(tmp_path, config_dir, "other", other, active=False)

    with pytest.raises(egress.EgressError, match="other"):
        egress.render(config_dir)


@pytest.mark.parametrize(
    "compose",
    [
        # Not internal: the add-on's services would have a way out around the proxy.
        {"networks": {"egress": {"name": NET}}},
        {"networks": {"egress": {"name": NET, "internal": False}}},
        {"networks": {"egress": {"name": NET, "internal": "true"}}},
        # Created elsewhere: nothing guarantees it is internal.
        {"networks": {"egress": {"name": NET, "internal": True, "external": True}}},
        # Not declared by the add-on at all.
        {"networks": {"other": {"name": "papaia-probe-other", "internal": True}}},
        {"services": {}},
        "not a mapping",
    ],
)
def test_the_egress_network_must_be_internal_in_the_addons_compose_file(
    tmp_path, config_dir, compose
):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}}, compose=compose)

    with pytest.raises(egress.EgressError, match="internal"):
        egress.render(config_dir)
    with pytest.raises(egress.EgressError, match="internal"):
        gen_override.generate_overrides(config_dir, tmp_path)


def test_an_addon_without_a_compose_file_gets_no_egress(tmp_path, config_dir):
    _env(config_dir)
    path = _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}})
    (path / "docker-compose.yml").unlink()

    with pytest.raises(egress.EgressError, match="docker-compose.yml"):
        egress.render(config_dir)


def test_an_unusable_declaration_removes_the_attachment_and_stops(tmp_path, config_dir):
    _env(config_dir)
    path = _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}})
    gen_override.generate_overrides(config_dir, tmp_path)
    override = egress.override_path(config_dir, "probe")
    assert override.is_file()

    (path / "docker-compose.yml").write_text(
        yaml.safe_dump({"networks": {"egress": {"name": NET}}}), encoding="utf-8"
    )

    with pytest.raises(egress.EgressError):
        gen_override.generate_overrides(config_dir, tmp_path)
    assert not override.exists()


def test_internal_targets_are_opened_by_the_operator_per_addon(tmp_path, config_dir):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}})
    _addon(tmp_path, config_dir, "other", {"egress": {"network": "papaia-other-egress"}})
    _internal_targets(
        config_dir,
        [
            {"name": "llm", "ranges": ["10.20.30.0/24", "fd12:3456::/48"], "addons": ["probe"]},
            {"name": "dms", "ranges": ["10.40.0.7"], "addons": ["probe", "gone"]},
        ],
    )

    egress.render(config_dir)

    internal = {s["name"]: s["internal"] for s in _rendered(config_dir)["sources"]}
    assert internal == {
        "probe": ["10.20.30.0/24", "fd12:3456::/48", "10.40.0.7/32"],
        "other": [],
    }


@pytest.mark.parametrize(
    "entries",
    [
        {"name": "llm"},  # not a list
        [{"name": "llm", "ranges": ["10.0.0.0/8"], "addons": ["probe"], "x": 1}],
        [{"name": "llm", "ranges": [], "addons": ["probe"]}],
        [{"name": "llm", "ranges": ["10.0.0.0/8"], "addons": []}],
        [{"name": "llm", "ranges": ["llm.firma.local"], "addons": ["probe"]}],
        [{"name": "llm", "ranges": ["10.0.0.0/33"], "addons": ["probe"]}],
        [{"name": "llm", "ranges": ["10.0.0.0/8"], "addons": ["Probe X"]}],
        [{"ranges": ["10.0.0.0/8"], "addons": ["probe"]}],
    ],
)
def test_an_invalid_internal_targets_list_fails_the_render(config_dir, entries):
    _env(config_dir)
    _internal_targets(config_dir, entries)

    with pytest.raises(egress.EgressError, match="egress-internal-targets.yaml"):
        egress.render(config_dir)


def test_the_corporate_proxy_is_taken_from_the_root_env(config_dir):
    _env(
        config_dir,
        PAPAIA_EGRESS_UPSTREAM_PROXY="http://svc-papaia@proxy.corp.example:3128",
        PAPAIA_EGRESS_NO_PROXY="corp.example, .intra.example",
    )
    password = config_dir / egress.UPSTREAM_PASSWORD_FILE
    password.parent.mkdir(parents=True, exist_ok=True)
    password.write_text("not-a-real-password\n", encoding="utf-8")
    password.chmod(0o600)

    egress.render(config_dir)

    assert _rendered(config_dir)["upstream"] == {
        "host": "proxy.corp.example",
        "port": 3128,
        "user": "svc-papaia",
        "no_proxy": ["corp.example", "intra.example"],
    }
    # The password stays in its own file and never reaches the rendered configuration.
    assert "not-a-real-password" not in (config_dir / egress.CONFIG_FILE).read_text()


@pytest.mark.parametrize(
    "url",
    [
        "https://proxy.corp.example:3128",
        "http://user:secret@proxy.corp.example:3128",
        "http://proxy.corp.example",
        "http://proxy.corp.example:3128/path",
        "proxy.corp.example:3128",
    ],
)
def test_an_unusable_corporate_proxy_fails_the_render(config_dir, url):
    _env(config_dir, PAPAIA_EGRESS_UPSTREAM_PROXY=url)

    with pytest.raises(egress.EgressError, match="PAPAIA_EGRESS_UPSTREAM_PROXY"):
        egress.render(config_dir)


def test_a_proxy_user_without_a_private_password_file_fails_the_render(config_dir):
    _env(config_dir, PAPAIA_EGRESS_UPSTREAM_PROXY="http://svc@proxy.corp.example:3128")

    with pytest.raises(egress.EgressError, match="upstream-proxy-password"):
        egress.render(config_dir)

    password = config_dir / egress.UPSTREAM_PASSWORD_FILE
    password.parent.mkdir(parents=True, exist_ok=True)
    password.write_text("x", encoding="utf-8")
    password.chmod(0o644)
    with pytest.raises(egress.EgressError, match="0600"):
        egress.render(config_dir)


# ─────────────────────────────────────────────────────────────────────────
# attachment to the egress network of an add-on
# ─────────────────────────────────────────────────────────────────────────


def test_the_egress_proxy_joins_the_egress_network_of_each_active_addon(tmp_path, config_dir):
    _env(config_dir, PAPAIA_PROJECT="papaia-dev")
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": "${PAPAIA_PROJECT}-probe-egress"}})

    gen_override.generate_overrides(config_dir, tmp_path)

    override = config_dir / "overrides" / "docker-compose.probe.egress.override.yml"
    assert yaml.safe_load(override.read_text()) == {
        "services": {
            egress.SERVICE: {
                "networks": {
                    egress.EGRESS_NETWORK: {},
                    "papaia-dev-probe-egress": {"aliases": ["egress-probe"]},
                }
            }
        },
        "networks": {"papaia-dev-probe-egress": {"external": True}},
    }
    # The dispatcher only applies an override whose external networks exist.
    assert gen_override.external_networks(override) == ["papaia-dev-probe-egress"]


def test_the_attachment_goes_away_with_the_addon(tmp_path, config_dir):
    _env(config_dir)
    _addon(tmp_path, config_dir, "probe", {"egress": {"network": NET}})
    gen_override.generate_overrides(config_dir, tmp_path)
    override = config_dir / "overrides" / "docker-compose.probe.egress.override.yml"
    assert override.is_file()

    deployed = deployment.load(config_dir)
    deployed["addons"][0]["active"] = False
    deployment.save(config_dir, deployed)
    gen_override.generate_overrides(config_dir, tmp_path)

    assert not override.exists()


# ─────────────────────────────────────────────────────────────────────────
# decisions of the proxy
# ─────────────────────────────────────────────────────────────────────────


def _config(**overrides):
    data = {
        "format": egress.CONFIG_FORMAT,
        "sources": [
            {
                "name": "probe",
                "alias": "egress-probe",
                "allow": [
                    {"host": "api.example.org", "ports": [443]},
                    {"host": "erp-sql.firma.local", "ports": [1433]},
                    {"host": "16.0.0.7", "ports": [443]},
                    {"host": "10.0.0.5", "ports": [443]},
                ],
                "internal": [],
            },
            {
                "name": "other",
                "alias": "egress-other",
                "allow": [{"host": "api.example.org", "ports": [443]}],
                "internal": [],
            },
        ],
        "protected": [{"name": "erp", "hosts": ["erp-sql.firma.local", "10.20.0.0/24"]}],
        "upstream": None,
    }
    data.update(overrides)
    return proxy.load_config(data)


def _ips(*values: str):
    return [ipaddress.ip_address(v) for v in values]


# Addresses in the decisions below are never contacted. 16.0.0.0/8 stands for a host on
# the internet: the documentation ranges (RFC 5737) are not global and are refused.


def test_an_allowed_host_and_port_of_the_source_passes():
    decision = proxy.decide(_config(), "probe", "api.example.org", 443, _ips("16.0.0.5"), [])

    assert (decision.result, decision.error_code, decision.event) == ("allowed", None, "operation")


def test_the_allow_list_is_per_source_and_per_port():
    config = _config()
    address = _ips("16.0.0.5")

    for source, host, port in (
        ("other", "16.0.0.7", 443),
        ("probe", "api.example.org", 80),
        ("probe", "example.org", 443),
    ):
        assert proxy.decide(config, source, host, port, address, []).error_code == "not_allowed"


def test_an_unknown_source_is_refused():
    decision = proxy.decide(_config(), None, "api.example.org", 443, _ips("16.0.0.5"), [])

    assert (decision.result, decision.error_code) == ("denied", "unknown_source")


def test_the_protected_list_overrides_the_allow_list_by_name():
    decision = proxy.decide(_config(), "probe", "erp-sql.firma.local", 1433, [], [])

    assert (decision.result, decision.error_code, decision.event) == (
        "denied",
        "protected_host",
        "protected_host_denied",
    )


def test_the_protected_list_compares_the_resolved_address():
    # An allowed name that resolves into a protected network, and an allowed name that
    # resolves to the address a protected name resolves to.
    config = _config()
    into_network = proxy.decide(config, "probe", "api.example.org", 443, _ips("10.20.0.15"), [])
    same_address = proxy.decide(
        config, "probe", "api.example.org", 443, _ips("16.0.0.5"), _ips("16.0.0.5")
    )

    assert into_network.error_code == "protected_host"
    assert same_address.error_code == "protected_host"


def test_a_protected_host_is_refused_even_when_not_on_any_allow_list():
    decision = proxy.decide(_config(), "other", "10.20.0.99", 5432, _ips("10.20.0.99"), [])

    assert decision.event == "protected_host_denied"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "::ffff:7f00:1",
        "::ffff:0:7f00:1",  # IPv4-translated (SIIT) loopback
    ],
)
def test_loopback_link_local_and_unspecified_addresses_are_never_reached(address):
    decision = proxy.decide(_config(), "probe", "api.example.org", 443, _ips(address), [])

    assert (decision.result, decision.error_code) == ("denied", "blocked_address")


def test_an_allowed_ip_literal_matches_in_normal_form():
    decision = proxy.decide(_config(), "probe", "16.0.0.7", 443, _ips("16.0.0.7"), [])

    assert decision.result == "allowed"


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",  # RFC 1918
        "172.17.0.1",  # the Docker bridge gateway, that is the host
        "192.168.1.10",
        "100.64.0.1",  # carrier-grade NAT
        "198.18.0.1",  # benchmarking
        "192.0.2.10",  # documentation
        "fd00::1",  # unique local
        "::a00:5",  # IPv4-compatible
        "64:ff9b::a00:5",  # NAT64 of 10.0.0.5
        "64:ff9b:1::a00:5",  # local-use NAT64
        "2002:a00:5::1",  # 6to4 of 10.0.0.5
        "::ffff:0:a00:5",  # IPv4-translated (SIIT) 10.0.0.5
        "fec0::1",  # deprecated site-local, global to Python's `is_global`
    ],
)
def test_an_allowed_name_that_resolves_to_an_internal_address_is_refused(address):
    # DNS of an allowed name pointing inward (rebinding, a Docker name) must not open
    # the inside of the stack or the host.
    decision = proxy.decide(_config(), "probe", "api.example.org", 443, _ips(address), [])

    assert (decision.result, decision.error_code) == ("denied", "blocked_address")


def test_an_internal_address_literal_is_refused_even_on_the_allow_list():
    decision = proxy.decide(_config(), "probe", "10.0.0.5", 443, [], [])

    assert (decision.result, decision.error_code) == ("denied", "blocked_address")


def test_an_address_behind_nat64_is_judged_by_the_embedded_ipv4_address():
    config = _config()

    outside = proxy.decide(config, "probe", "api.example.org", 443, _ips("64:ff9b::1000:5"), [])
    # 10.20.0.15 is in the protected range 10.20.0.0/24.
    nat64 = proxy.decide(config, "probe", "api.example.org", 443, _ips("64:ff9b::a14:f"), [])
    sixtofour = proxy.decide(config, "probe", "api.example.org", 443, _ips("2002:a14:f::1"), [])
    siit = proxy.decide(config, "probe", "api.example.org", 443, _ips("::ffff:0:a14:f"), [])

    assert outside.result == "allowed"
    assert nat64.error_code == "protected_host"
    assert sixtofour.error_code == "protected_host"
    assert siit.error_code == "protected_host"


def _with_internal(ranges):
    data = {
        "format": egress.CONFIG_FORMAT,
        "sources": [
            {
                "name": "probe",
                "alias": "egress-probe",
                "allow": [{"host": "llm.firma.example", "ports": [443]}],
                "internal": ranges,
            },
            {
                "name": "other",
                "alias": "egress-other",
                "allow": [{"host": "llm.firma.example", "ports": [443]}],
                "internal": [],
            },
        ],
        "protected": [],
        "upstream": None,
    }
    return proxy.load_config(data)


def test_internal_targets_pass_only_for_the_addon_the_operator_opened_them_for():
    config = _with_internal(["10.20.30.0/24"])
    address = _ips("10.20.30.5")

    probe = proxy.decide(config, "probe", "llm.firma.example", 443, address, [])
    other = proxy.decide(config, "other", "llm.firma.example", 443, address, [])
    outside_range = proxy.decide(config, "probe", "llm.firma.example", 443, _ips("10.20.31.5"), [])

    assert probe.result == "allowed"
    assert other.error_code == "blocked_address"
    assert outside_range.error_code == "blocked_address"


LOCAL = proxy.Local(
    # The proxy's own addresses: on its exit network and on the egress network of `other`.
    own=frozenset(_ips("10.210.0.2", "172.30.5.2", "fd00:0:0:5::2")),
    gateways=frozenset(_ips("10.210.0.1")),
    # The egress networks of the add-ons the proxy is attached to.
    attached=(ipaddress.ip_network("172.30.5.0/24"), ipaddress.ip_network("fd00:0:0:5::/64")),
)


@pytest.mark.parametrize(
    "address",
    [
        "10.210.0.2",  # the proxy itself on its exit network
        "172.30.5.2",  # the proxy itself as egress-other: the self-alias hop
        "10.210.0.1",  # the gateway, that is the host
        "172.30.5.9",  # a service of another add-on on its egress network
        "fd00:0:0:5::9",
        "64:ff9b::ac1e:509",  # the same service through NAT64
    ],
)
def test_the_proxy_and_the_networks_it_is_attached_to_are_never_reached(address):
    # Not even when the operator opened every private range for the add-on.
    config = _with_internal(["10.0.0.0/8", "172.16.0.0/12", "fc00::/7"])

    decision = proxy.decide(config, "probe", "llm.firma.example", 443, _ips(address), [], LOCAL)

    assert (decision.result, decision.error_code) == ("denied", "blocked_address")


def test_an_opened_range_on_the_exit_network_is_reachable_apart_from_the_proxy_and_gateway():
    config = _with_internal(["10.210.0.0/24"])

    decision = proxy.decide(
        config, "probe", "llm.firma.example", 443, _ips("10.210.0.9"), [], LOCAL
    )

    assert decision.result == "allowed"


def _fake_proc(root: Path) -> Path:
    """/proc/net of a container on an exit network (eth0, default route) and on the
    internal egress network of an add-on (eth1)."""
    net = root / "net"
    net.mkdir(parents=True)
    (net / "route").write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0100D20A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t0000D20A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        "eth1\t00051EAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
        encoding="utf-8",
    )
    (net / "fib_trie").write_text(
        "Main:\n"
        "  +-- 0.0.0.0/0 3 0 5\n"
        "     |-- 0.0.0.0\n"
        "        /0 universe UNICAST\n"
        "Local:\n"
        "  +-- 10.210.0.0/24 2 0 2\n"
        "     |-- 10.210.0.2\n"
        "        /32 host LOCAL\n"
        "     |-- 10.210.0.255\n"
        "        /32 link BROADCAST\n"
        "  +-- 127.0.0.0/8 2 0 2\n"
        "     |-- 127.0.0.1\n"
        "        /32 host LOCAL\n"
        "  +-- 172.30.5.0/24 2 0 2\n"
        "     |-- 172.30.5.2\n"
        "        /32 host LOCAL\n",
        encoding="utf-8",
    )
    (net / "if_inet6").write_text(
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "fd000000000000050000000000000002 03 40 00 80     eth1\n"
        "fe80000000000000004200fffeac1e05 03 40 20 80     eth1\n",
        encoding="utf-8",
    )
    (net / "ipv6_route").write_text(
        "fd000000000000050000000000000000 40 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth1\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n",
        encoding="utf-8",
    )
    return root


def test_the_proxy_learns_its_own_addresses_and_networks_from_proc(tmp_path):
    local = proxy.read_local(_fake_proc(tmp_path))

    assert local.own == frozenset(_ips("10.210.0.2", "172.30.5.2", "fd00:0:0:5::2"))
    assert local.gateways == frozenset(_ips("10.210.0.1"))
    # The exit network (default route) is not "attached": its other hosts are judged as
    # private addresses like any other.
    assert set(local.attached) == {
        ipaddress.ip_network("172.30.5.0/24"),
        ipaddress.ip_network("fd00:0:0:5::/64"),
    }
    # Every network the proxy has an address on, the exit network included.
    assert set(local.links) == {
        ipaddress.ip_network("10.210.0.0/24"),
        ipaddress.ip_network("172.30.5.0/24"),
        ipaddress.ip_network("fd00:0:0:5::/64"),
    }


@pytest.mark.parametrize(
    ("arrived_at", "peer", "expected"),
    [
        ("172.30.5.2", "172.30.5.9", True),  # a service on the egress network it arrived on
        ("fd00:0:0:5::2", "fd00:0:0:5::9", True),
        # A container on another network routing to the proxy's address on this one
        # (weak host model): it must not be taken for this network's add-on.
        ("172.30.5.2", "10.210.0.9", False),
        ("172.30.5.2", "172.30.6.9", False),
        ("10.210.0.2", "172.30.5.9", False),
        ("172.30.5.2", "fd00:0:0:5::9", False),
    ],
)
def test_a_connection_counts_only_when_the_peer_is_on_the_network_it_arrived_on(
    tmp_path, arrived_at, peer, expected
):
    local = proxy.read_local(_fake_proc(tmp_path))

    assert proxy.on_link(local, _ips(arrived_at)[0], _ips(peer)[0]) is expected


def test_without_proc_no_connection_is_on_link(tmp_path):
    local = proxy.read_local(tmp_path / "missing")

    assert proxy.on_link(local, _ips("172.30.5.2")[0], _ips("172.30.5.9")[0]) is False


def test_without_proc_the_proxy_refuses_every_address(tmp_path):
    local = proxy.read_local(tmp_path / "missing")
    config = _with_internal([])

    decision = proxy.decide(config, "probe", "llm.firma.example", 443, _ips("16.0.0.5"), [], local)

    assert decision.error_code == "blocked_address"


def _write_config(path: Path, sources) -> None:
    data = {"format": egress.CONFIG_FORMAT, "sources": sources, "protected": [], "upstream": None}
    path.write_text(json.dumps(data), encoding="utf-8")


def test_the_source_map_is_refreshed_after_a_while_and_with_a_new_configuration(
    tmp_path, monkeypatch
):
    path = tmp_path / "egress.json"
    _write_config(path, [{"name": "probe", "alias": "egress-probe", "allow": [], "internal": []}])
    answers = {"egress-probe": _ips("172.30.5.2")}

    async def fake_resolve(host):
        return answers.get(host, [])

    monkeypatch.setattr(proxy, "_resolve", fake_resolve)
    instance = proxy.Proxy(path, proc=_fake_proc(tmp_path))
    instance.load()
    address = ipaddress.ip_address("172.30.5.2")
    peer = ipaddress.ip_address("172.30.5.9")

    assert asyncio.run(instance.source_of(address, peer)) == "probe"
    # The alias moved (network reconnected, address reused by another add-on).
    answers["egress-probe"] = _ips("172.30.5.3")
    instance.sources_at -= proxy.SOURCE_REFRESH_SECONDS + 1
    assert asyncio.run(instance.source_of(address, peer)) is None

    answers["egress-probe"] = _ips("172.30.5.2")
    instance.sources_at -= proxy.SOURCE_REFRESH_SECONDS + 1
    assert asyncio.run(instance.source_of(address, peer)) == "probe"
    _write_config(path, [{"name": "probe2", "alias": "egress-probe2", "allow": [], "internal": []}])
    instance.load()
    assert instance.sources == {}


class _Writer:
    """The writer side of a connection the proxy got: where it arrived and from where."""

    def __init__(self, sockname, peername):
        self.extra = {"sockname": sockname, "peername": peername}
        self.sent = b""
        self.closed = False

    def get_extra_info(self, name):
        return self.extra[name]

    def write(self, data):
        self.sent += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True


def _reader(data: bytes) -> asyncio.StreamReader:
    """A reader with the request already received; call inside the running loop."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _sent_error(writer: _Writer) -> tuple[int, str | None]:
    lines = writer.sent.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
    return int(lines[0].split()[1]), headers.get("X-Papaia-Error")


def test_a_peer_from_another_network_is_not_taken_for_the_addon(tmp_path, monkeypatch, capsys):
    # A container on another network that routes to the proxy's address on the egress
    # network of `probe` must not get probe's allow list.
    path = tmp_path / "egress.json"
    _write_config(
        path,
        [
            {
                "name": "probe",
                "alias": "egress-probe",
                "allow": [{"host": "16.0.0.5", "ports": [443]}],
                "internal": [],
            }
        ],
    )

    async def fake_resolve(host):
        return _ips("172.30.5.2") if host == "egress-probe" else []

    monkeypatch.setattr(proxy, "_resolve", fake_resolve)
    instance = proxy.Proxy(path, proc=_fake_proc(tmp_path))
    instance.load()
    writer = _Writer(("172.30.5.2", 3128), ("10.210.0.9", 40000))

    async def scenario():
        await instance.handle(_reader(b"CONNECT 16.0.0.5:443 HTTP/1.1\r\n\r\n"), writer)

    asyncio.run(scenario())

    assert _sent_error(writer) == (403, "unknown_source")
    rows = _audit_rows(capsys.readouterr().out)
    assert [(r["error_code"], r["detail"]["source"]) for r in rows] == [("unknown_source", None)]


def _protected_config(path: Path, internal) -> None:
    data = {
        "format": egress.CONFIG_FORMAT,
        "sources": [
            {
                "name": "probe",
                "alias": "egress-probe",
                "allow": [
                    {"host": "llm.firma.example", "ports": [443]},
                    {"host": "alias.firma.example", "ports": [443]},
                ],
                "internal": internal,
            }
        ],
        "protected": [{"name": "erp", "hosts": ["erp-sql.firma.local"]}],
        "upstream": None,
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def _decide_now(instance, host: str, address: str):
    return proxy.decide(
        instance.config,
        "probe",
        host,
        443,
        _ips(address),
        instance.protected_addresses,
        proxy.Local(),
        protected_complete=instance.protected_complete,
    )


def test_a_protected_name_keeps_its_addresses_when_its_resolution_fails(tmp_path, monkeypatch):
    # erp-sql.firma.local is 10.20.0.15; the operator opened 10.20.0.0/16 for the add-on.
    path = tmp_path / "egress.json"
    _protected_config(path, ["10.20.0.0/16"])
    answers: dict = {"erp-sql.firma.local": _ips("10.20.0.15")}

    async def fake_lookup(host, timeout):
        return answers.get(host)

    monkeypatch.setattr(proxy, "_lookup", fake_lookup)
    instance = proxy.Proxy(path, proc=tmp_path)
    instance.load()
    asyncio.run(instance.refresh_protected())
    assert _decide_now(instance, "llm.firma.example", "10.20.0.99").result == "allowed"

    # The resolver stops answering for the protected name.
    answers["erp-sql.firma.local"] = None
    asyncio.run(instance.refresh_protected())

    # A second name pointing at the protected address is still refused...
    assert _decide_now(instance, "alias.firma.example", "10.20.0.15").error_code == (
        "protected_host"
    )
    # ...and while a protected name cannot be resolved, no opened internal range is used.
    assert _decide_now(instance, "llm.firma.example", "10.20.0.99").error_code == (
        "blocked_address"
    )
    assert _decide_now(instance, "llm.firma.example", "16.0.0.5").result == "allowed"

    answers["erp-sql.firma.local"] = _ips("10.20.0.16")
    asyncio.run(instance.refresh_protected())
    # Back to normal; the address learned before is not forgotten.
    assert _decide_now(instance, "llm.firma.example", "10.20.0.99").result == "allowed"
    assert instance.protected_addresses >= set(_ips("10.20.0.15", "10.20.0.16"))


def test_a_protected_name_that_never_resolved_closes_the_internal_ranges(tmp_path, monkeypatch):
    path = tmp_path / "egress.json"
    _protected_config(path, ["10.20.0.0/16"])

    async def fake_lookup(host, timeout):
        return []

    monkeypatch.setattr(proxy, "_lookup", fake_lookup)
    instance = proxy.Proxy(path, proc=tmp_path)
    instance.load()
    # Before the first round and after a round without an answer alike.
    assert _decide_now(instance, "llm.firma.example", "10.20.0.99").error_code == (
        "blocked_address"
    )
    asyncio.run(instance.refresh_protected())
    assert _decide_now(instance, "llm.firma.example", "10.20.0.99").error_code == (
        "blocked_address"
    )


def test_a_request_never_waits_for_the_protected_names(tmp_path, monkeypatch, capsys):
    # The protected names are resolved in the background; a slow resolver for one of
    # them must not stall the requests of every source.
    path = tmp_path / "egress.json"
    _protected_config(path, [])
    looked_up: list = []

    async def fake_lookup(host, timeout):
        looked_up.append(host)
        return _ips("16.0.0.5") if host == "llm.firma.example" else None

    async def stub_source(_address, _peer):
        return "probe"

    monkeypatch.setattr(proxy, "_lookup", fake_lookup)
    instance = proxy.Proxy(path, proc=_fake_proc(tmp_path))
    instance.load()
    instance.source_of = stub_source
    writer = _Writer(("172.30.5.2", 3128), ("172.30.5.9", 40000))

    async def scenario():
        await asyncio.wait_for(
            instance._handle(
                _reader(b"CONNECT llm.firma.example:443 HTTP/1.1\r\n\r\n"), writer, "probe"
            ),
            timeout=2,
        )

    # No route to 16.0.0.5 is needed: the decision is what is checked.
    monkeypatch.setattr(proxy, "_open_direct", _refuse_open)
    asyncio.run(scenario())

    assert "erp-sql.firma.local" not in looked_up
    rows = _audit_rows(capsys.readouterr().out)
    assert [r["result"] for r in rows] == ["allowed"]


async def _refuse_open(*_args):
    raise OSError("not in tests")


def test_a_hanging_resolver_is_given_up_after_the_timeout(monkeypatch):
    import socket
    import time as clock

    def hanging(*_args, **_kwargs):
        clock.sleep(1)
        raise OSError("late")

    monkeypatch.setattr(socket, "getaddrinfo", hanging)

    async def scenario():
        started = asyncio.get_running_loop().time()
        found = await proxy._lookup("erp-sql.firma.local", 0.2)
        return found, asyncio.get_running_loop().time() - started

    found, elapsed = asyncio.run(scenario())

    assert found is None
    assert elapsed < 0.8


async def _serve(instance):
    server = await asyncio.start_server(instance.handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _status(port: int, data: bytes = b"") -> tuple[int, str | None]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    if data:
        writer.write(data)
        await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    writer.close()
    lines = head.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
    return int(lines[0].split()[1]), headers.get("X-Papaia-Error")


def _audit_rows(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


@pytest.mark.parametrize(("total", "per_source"), [(1, 10), (10, 1)])
def test_connections_over_the_cap_are_refused_and_audited(tmp_path, capsys, total, per_source):
    path = tmp_path / "egress.json"
    _write_config(path, [{"name": "probe", "alias": "egress-probe", "allow": [], "internal": []}])
    instance = proxy.Proxy(path, proc=tmp_path, max_connections=total, max_per_source=per_source)
    instance.load()

    async def stub_source(_address, _peer):
        return "probe"

    instance.source_of = stub_source

    async def scenario():
        server, port = await _serve(instance)
        # The first connection holds its slot while it has not sent its request.
        _, holder = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        try:
            return await _status(port)
        finally:
            holder.close()
            server.close()

    assert asyncio.run(scenario()) == (503, "too_many_connections")
    rows = _audit_rows(capsys.readouterr().out)
    refused = [r for r in rows if r["error_code"] == "too_many_connections"]
    assert [(r["result"], r["detail"]["source"]) for r in refused] == [("denied", "probe")]


def test_a_malformed_request_is_refused_and_audited(tmp_path, capsys):
    path = tmp_path / "egress.json"
    _write_config(path, [])
    instance = proxy.Proxy(path, proc=tmp_path)
    instance.load()

    async def scenario():
        server, port = await _serve(instance)
        try:
            return await _status(port, b"GET http://api.example.org/ HTTP/1.1\r\n\r\n")
        finally:
            server.close()

    assert asyncio.run(scenario()) == (405, "bad_request")
    rows = _audit_rows(capsys.readouterr().out)
    assert [(r["result"], r["error_code"], r["detail"]["host"]) for r in rows] == [
        ("denied", "bad_request", None)
    ]


def test_an_idle_tunnel_is_closed(tmp_path):
    async def scenario():
        accepted: asyncio.Queue = asyncio.Queue()

        async def keep(reader, writer):
            await accepted.put((reader, writer))

        server = await asyncio.start_server(keep, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client_side = await asyncio.open_connection("127.0.0.1", port)
        proxy_side = await accepted.get()
        remote_side = await asyncio.open_connection("127.0.0.1", port)
        far_end = await accepted.get()
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(proxy._tunnel(*proxy_side, *remote_side, idle=0.3), timeout=5)
        elapsed = asyncio.get_running_loop().time() - started
        # Both ends see the tunnel closed.
        assert await asyncio.wait_for(client_side[0].read(), 2) == b""
        assert await asyncio.wait_for(far_end[0].read(), 2) == b""
        for writer in (client_side[1], far_end[1]):
            writer.close()
        server.close()
        return elapsed

    assert asyncio.run(scenario()) < 3


def test_through_the_corporate_proxy_the_checked_addresses_are_the_targets():
    # The corporate proxy must not resolve the name again into a protected or internal
    # address; when the name resolved inside the stack, it gets the checked addresses.
    assert proxy.upstream_targets("api.example.org", _ips("16.0.0.5", "16.0.0.6")) == [
        "16.0.0.5",
        "16.0.0.6",
    ]
    assert proxy.upstream_targets("api.example.org", []) == ["api.example.org"]


def test_through_the_corporate_proxy_every_checked_address_is_tried(tmp_path):
    # The first address cannot be reached (the corporate proxy answers 502); the tunnel
    # goes to the next checked address, as a direct connection would.
    seen: list = []

    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        seen.append(head.split(b"\r\n", 1)[0].decode())
        if b"16.0.0.5" in head:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await writer.drain()
        data = await reader.read(100)
        writer.write(data.upper())
        await writer.drain()
        writer.close()

    async def scenario():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        upstream = proxy.Upstream("127.0.0.1", port, "", ())
        try:
            reader, writer = await proxy._open_upstream_any(
                upstream, tmp_path, ["16.0.0.5", "16.0.0.6"], 443
            )
            writer.write(b"ping")
            await writer.drain()
            reply = await reader.read(100)
            writer.close()
            return reply
        finally:
            server.close()

    assert asyncio.run(scenario()) == b"PING"
    assert seen == ["CONNECT 16.0.0.5:443 HTTP/1.1", "CONNECT 16.0.0.6:443 HTTP/1.1"]


def test_when_no_checked_address_is_reachable_the_corporate_proxy_tunnel_fails(tmp_path):
    async def scenario():
        server = await asyncio.start_server(
            _fake_upstream(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", []), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        upstream = proxy.Upstream("127.0.0.1", port, "", ())
        try:
            with pytest.raises(proxy.RequestError):
                await proxy._open_upstream_any(upstream, tmp_path, ["16.0.0.5", "16.0.0.6"], 443)
        finally:
            server.close()

    asyncio.run(scenario())


def test_the_proxy_rejects_unknown_fields_in_its_configuration():
    with pytest.raises(ValueError):
        _config(extra=True)
    with pytest.raises(ValueError):
        _config(format="papaia.egress/0")
    with pytest.raises(ValueError):
        _config(sources=[{"name": "probe", "alias": "egress-probe", "allow": [], "x": 1}])


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"CONNECT api.example.org:443 HTTP/1.1\r\nHost: x\r\n\r\n", ("api.example.org", 443)),
        (b"CONNECT API.Example.org.:443 HTTP/1.1\r\n\r\n", ("api.example.org", 443)),
        (b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n", ("2001:db8::1", 443)),
    ],
)
def test_a_connect_request_is_parsed(head, expected):
    host, port, _ = proxy.parse_request(head)

    assert (host, port) == expected


@pytest.mark.parametrize(
    ("head", "status"),
    [
        (b"GET http://api.example.org/ HTTP/1.1\r\n\r\n", 405),
        (b"CONNECT api.example.org HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT api.example.org:0 HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT bad_host:443 HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT api.example.org:443 HTTP/1.0 extra\r\n\r\n", 400),
        (b"\xff\xfe\r\n\r\n", 400),
    ],
)
def test_a_malformed_or_other_request_is_refused(head, status):
    with pytest.raises(proxy.RequestError) as caught:
        proxy.parse_request(head)

    assert caught.value.status == status


def test_the_correlation_id_is_taken_over_only_when_valid():
    valid = {"x-papaia-correlation-id": "c0a8-4e2f-91"}
    too_long = {"x-papaia-correlation-id": "a" * 65}
    odd = {"x-papaia-correlation-id": "a b"}

    assert proxy.correlation_id(valid) == "c0a8-4e2f-91"
    for headers in (too_long, odd, {}):
        generated = proxy.correlation_id(headers)
        assert re.fullmatch(UUID7, generated)


def test_one_audit_row_per_decision_without_content():
    decision = proxy.decide(_config(), "probe", "erp-sql.firma.local", 1433, [], [])

    row = proxy.audit_row(decision, "probe", "erp-sql.firma.local", 1433, "c0a8-4e2f-91")

    assert row["format"] == "papaia.audit/1"
    assert row["writer"] == "papaia-egress"
    assert row["correlation_id"] == "c0a8-4e2f-91"
    assert row["identity_kind"] == "service"
    assert (row["operation"], row["effect"]) == ("connect", "send")
    assert (row["result"], row["error_code"], row["event"]) == (
        "denied",
        "protected_host",
        "protected_host_denied",
    )
    assert row["detail"] == {"source": "probe", "host": "erp-sql.firma.local", "port": 1433}


def _fake_upstream(answer: bytes, seen: list):
    async def handle(reader, writer):
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(answer)
        await writer.drain()
        data = await reader.read(100)
        writer.write(data.upper())
        await writer.drain()
        writer.close()

    return handle


def test_the_tunnel_through_the_corporate_proxy_authenticates_with_the_password_file(tmp_path):
    (tmp_path / proxy.PASSWORD_FILE).write_text("pw-from-file\n", encoding="utf-8")
    seen: list = []

    async def scenario():
        server = await asyncio.start_server(
            _fake_upstream(b"HTTP/1.1 200 OK\r\n\r\n", seen), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        upstream = proxy.Upstream("127.0.0.1", port, "svc", ())
        reader, writer = await proxy._open_upstream(upstream, tmp_path, "api.example.org", 443)
        writer.write(b"ping")
        await writer.drain()
        reply = await reader.read(100)
        writer.close()
        server.close()
        return reply

    assert asyncio.run(scenario()) == b"PING"
    token = base64.b64encode(b"svc:pw-from-file").decode()
    assert seen[0].decode().split("\r\n")[:3] == [
        "CONNECT api.example.org:443 HTTP/1.1",
        "Host: api.example.org:443",
        f"Proxy-Authorization: Basic {token}",
    ]


def test_a_tunnel_the_corporate_proxy_refuses_is_an_error(tmp_path):
    async def scenario():
        server = await asyncio.start_server(
            _fake_upstream(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", []),
            "127.0.0.1",
            0,
        )
        port = server.sockets[0].getsockname()[1]
        upstream = proxy.Upstream("127.0.0.1", port, "", ())
        try:
            with pytest.raises(proxy.RequestError):
                await proxy._open_upstream(upstream, tmp_path, "api.example.org", 443)
        finally:
            server.close()

    asyncio.run(scenario())


def test_an_egress_network_needs_a_core_of_generation_7():
    # papaia-egress became attachable with generation 7; an older core would install the
    # add-on with the declaration unread, so the gate names the generation instead.
    manifest = {"networks": {"egress": {"network": "probe-egress"}}}

    assert compat.manifest_generation_features(manifest) == [("networks.egress", 7)]
    assert compat.manifest_generation_features({"networks": {"app_network": "n"}}) == []
