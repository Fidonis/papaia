"""The address range of the installation's Docker networks (`setup --subnet-pool=CIDR`).

With `PAPAIA_SUBNET_POOL` every network the core's Compose project declares, and every
network an active add-on's compose file creates without a range of its own, gets an
explicit subnet: blocks of the pool in a fixed order, the same on every render. Without
the variable nothing is written and an installation behaves as before.

The run with real Docker networks is `test_subnet_pool_docker.py`.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation, run_cli
from test_doctor import NOW, healthy_docker, probes, result, set_env

from lib import (
    cli,
    doctor,
    egress,
    federation,
    gen_override,
    hosted_model,
    render_core,
    subnet_pool,
)
from lib.doctor import FAIL, PASS, SKIP
from lib.status import CommandResult

POOL = "10.212.0.0/16"
OTHER_POOL = "172.20.0.0/16"
APP_HOST = "--app-host=https://papaia.example.org"


class HostNetworks:
    """`docker network ls` and `docker network inspect` of a host with the given networks
    (name -> (compose project, [subnets]))."""

    def __init__(self, networks: dict[str, tuple[str, list[str]]] | None = None):
        self.networks = networks or {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=None):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "network", "ls"]:
            return CommandResult(0, "".join(f"{n}\n" for n in self.networks), "")
        if cmd[:3] == ["docker", "network", "inspect"] and cmd[3] == "--format":
            lines = []
            for name in cmd[5:]:
                project, subnets = self.networks[name]
                lines.append(f"{name}\t{project}\t{' '.join(subnets)}\n")
            return CommandResult(0, "".join(lines), "")
        raise AssertionError(f"unexpected command: {cmd}")


@pytest.fixture(autouse=True)
def _host(monkeypatch):
    """No real Docker host: a host without networks unless a test says otherwise."""
    host = HostNetworks()
    monkeypatch.setattr(subnet_pool, "run", host)
    return host


def _core_override(config: Path) -> dict:
    path = config / "overrides" / subnet_pool.OVERRIDE
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _declared_core_networks(repo: Path) -> set[str]:
    """Every network the core's Compose project declares, read from its fragments."""
    src = repo / "src"
    names: set[str] = set()
    root = yaml.safe_load((src / "docker-compose.yml").read_text(encoding="utf-8"))
    files = [src / "docker-compose.yml"]
    for entry in root.get("include") or []:
        files.append(src / (entry["path"] if isinstance(entry, dict) else entry))
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        names.update((doc.get("networks") or {}).keys())
    return names


def _subnets(override: dict) -> dict[str, ipaddress.IPv4Network]:
    found = {}
    for key, body in override["networks"].items():
        configs = body["ipam"]["config"]
        assert len(configs) == 1, key
        found[key] = ipaddress.ip_network(configs[0]["subnet"])
    return found


# ─────────────────────────────────────────────────────────────────────────
# the value
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["10.0.0.0/8", "172.20.0.0/16", "192.168.16.0/20", POOL])
def test_a_private_ipv4_pool_from_8_to_20_is_accepted(value):
    assert str(subnet_pool.parse_pool(value, 24)) == value


@pytest.mark.parametrize(
    "value, cause",
    [
        ("8.8.0.0/16", "private"),
        ("100.64.0.0/16", "private"),
        ("169.254.0.0/16", "private"),
        ("127.0.0.0/16", "private"),
        ("fd00::/48", "IPv4"),
        ("10.0.0.0/7", "/8"),
        ("10.212.0.0/21", "/20"),
        ("10.212.0.1/16", "address range"),
        ("10.212.0.0", "address range"),
        ("", "address range"),
        ("10.212.0.0/16 ", "address range"),
    ],
)
def test_a_pool_outside_the_rules_is_refused_with_its_cause(value, cause):
    with pytest.raises(subnet_pool.SubnetPoolError, match=cause.replace("/", "/")):
        subnet_pool.parse_pool(value, 24)


def test_smaller_blocks_allow_a_smaller_pool():
    assert str(subnet_pool.parse_pool("10.212.145.0/24", 28)) == "10.212.145.0/24"
    with pytest.raises(subnet_pool.SubnetPoolError, match="/24"):
        subnet_pool.parse_pool("10.212.145.0/25", 28)


@pytest.mark.parametrize("value", ["23", "29", "x", "24.5", "/24"])
def test_a_block_size_outside_24_to_28_is_refused(value):
    with pytest.raises(subnet_pool.SubnetPoolError, match="24 to 28"):
        subnet_pool.parse_block(value)


# ─────────────────────────────────────────────────────────────────────────
# render
# ─────────────────────────────────────────────────────────────────────────


def test_without_a_pool_there_is_no_override(tmp_path, _host):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST)

    assert not (inst.config / "overrides" / subnet_pool.OVERRIDE).exists()
    assert not (inst.config / subnet_pool.STATE_FILE).exists()
    assert subnet_pool.run is _host and not _host.calls
    env = (inst.config / ".env").read_text(encoding="utf-8")
    assert f"{subnet_pool.POOL_KEY}=\n" in env


def test_every_core_network_gets_a_block_of_the_pool_once(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")

    pool = ipaddress.ip_network(POOL)
    subnets = _subnets(_core_override(inst.config))
    assert _declared_core_networks(inst.repo) <= set(subnets)
    for key, net in subnets.items():
        assert net.subnet_of(pool), key
        assert net.prefixlen == 24, key
    values = list(subnets.values())
    for index, net in enumerate(values):
        assert not any(net.overlaps(other) for other in values[index + 1:])
    root = (inst.config / ".env").read_text(encoding="utf-8")
    assert f"{subnet_pool.POOL_KEY}={POOL}\n" in root


def test_the_blocks_follow_a_fixed_order_and_stay_on_the_next_render(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    first = _core_override(inst.config)

    inst.setup()
    run_cli(inst.repo, inst.config, "render")

    assert _core_override(inst.config) == first
    subnets = _subnets(first)
    assert subnets["papaia-net"] == ipaddress.ip_network("10.212.0.0/24")
    blocks = list(ipaddress.ip_network(POOL).subnets(new_prefix=24))
    for index, key in enumerate(subnet_pool.CORE_NETWORKS):
        assert subnets[key] == blocks[index], key


def test_the_pool_is_sticky_and_no_subnet_pool_removes_it(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    inst.setup()
    assert (inst.config / "overrides" / subnet_pool.OVERRIDE).is_file()

    inst.setup("--no-subnet-pool")

    assert not (inst.config / "overrides" / subnet_pool.OVERRIDE).exists()
    assert not (inst.config / subnet_pool.STATE_FILE).exists()
    assert f"{subnet_pool.POOL_KEY}=\n" in (inst.config / ".env").read_text(encoding="utf-8")


def test_the_core_list_names_every_network_the_core_declares():
    repo = Path(__file__).resolve().parents[2]
    assert set(subnet_pool.CORE_NETWORKS) == _declared_core_networks(repo)
    assert subnet_pool.CORE_NETWORKS[0] == "papaia-net"


def _addon(inst: Installation, name: str, networks: dict, services: dict | None = None) -> Path:
    path = inst.workspace / "addons" / name
    path.mkdir(parents=True)
    (path / "papaia-app.yaml").write_text(
        yaml.safe_dump({"name": name, "version": "1.0.0"}), encoding="utf-8"
    )
    compose = {
        "services": services or {"app": {"image": "example/app:1", "networks": list(networks)}},
        "networks": networks,
    }
    (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    manifest = yaml.safe_load((inst.config / "deployment.yaml").read_text(encoding="utf-8"))
    manifest.setdefault("addons", [])
    manifest["addons"] = [*(manifest["addons"] or []), {"name": name, "path": str(path),
                                                         "active": True}]
    (inst.config / "deployment.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return path


def test_addon_networks_get_sticky_blocks_after_the_core(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _addon(
        inst,
        "notes",
        {
            "notes-net": {"name": "${PAPAIA_PROJECT:-papaia}-notes-net"},
            "notes-db": {"internal": True},
            "shared": {"external": True},
            "fixed": {"ipam": {"config": [{"subnet": "10.99.0.0/24"}]}},
        },
    )
    run_cli(inst.repo, inst.config, "render")

    path = subnet_pool.addon_override_path(inst.config, "notes")
    override = yaml.safe_load(path.read_text(encoding="utf-8"))
    subnets = _subnets(override)
    # External networks belong to someone else, a range of its own stays the add-on's.
    assert set(subnets) == {"notes-net", "notes-db"}
    core = set(_subnets(_core_override(inst.config)).values())
    pool = ipaddress.ip_network(POOL)
    for net in subnets.values():
        assert net.subnet_of(pool)
        assert net not in core
    first = dict(subnets)

    # A second add-on installed later does not move the blocks of the first.
    _addon(inst, "alpha", {"alpha-net": {}})
    run_cli(inst.repo, inst.config, "render")
    assert _subnets(yaml.safe_load(path.read_text(encoding="utf-8"))) == first
    alpha = _subnets(yaml.safe_load(
        subnet_pool.addon_override_path(inst.config, "alpha").read_text(encoding="utf-8")
    ))
    assert not set(alpha.values()) & set(first.values())


def test_an_addon_service_without_networks_puts_the_default_network_in_the_pool(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _addon(inst, "plain", {}, services={"app": {"image": "example/app:1"}})
    run_cli(inst.repo, inst.config, "render")

    override = yaml.safe_load(
        subnet_pool.addon_override_path(inst.config, "plain").read_text(encoding="utf-8")
    )
    assert set(_subnets(override)) == {"default"}


def test_a_pool_too_small_for_the_networks_is_refused(tmp_path, capsys):
    inst = Installation(tmp_path, [APP_HOST])
    # 16 blocks of /24: the core takes all but two of them.
    inst.setup(APP_HOST, "--subnet-pool=10.212.0.0/20")
    _addon(inst, "big", {f"net{i}": {} for i in range(3)})
    capsys.readouterr()

    with pytest.raises(subnet_pool.SubnetPoolError, match="too small"):
        subnet_pool.generate_overrides(inst.config, inst.repo)
    assert cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "render"]) == 3
    assert "too small" in capsys.readouterr().err


def test_setup_refuses_a_pool_too_small_before_writing(tmp_path, capsys):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST)
    _addon(inst, "big", {f"net{i}": {} for i in range(3)})
    before = (inst.config / ".env").read_text(encoding="utf-8")

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "setup", "--subnet-pool=10.212.0.0/20"])

    assert code == cli.SETUP_REFUSED
    assert "too small" in capsys.readouterr().err
    assert (inst.config / ".env").read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "flags, cause",
    [
        (["--subnet-pool=8.8.0.0/16"], "private"),
        (["--subnet-pool=10.212.0.0/22"], "/20"),
        (["--subnet-pool=10.212.0.0/16", "--subnet-block=30"], "24 to 28"),
        (["--subnet-pool=10.212.0.0/16", "--no-subnet-pool"], "--no-subnet-pool"),
    ],
)
def test_setup_refuses_an_unusable_pool_and_changes_nothing(tmp_path, capsys, flags, cause):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST)
    before = (inst.config / ".env").read_text(encoding="utf-8")

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "setup", *flags])

    assert code == cli.SETUP_REFUSED
    assert cause in capsys.readouterr().err
    assert (inst.config / ".env").read_text(encoding="utf-8") == before


def test_setup_refuses_a_pool_overlapping_a_foreign_docker_network(tmp_path, capsys, _host):
    _host.networks = {"other-stack_default": ("other-stack", ["10.212.7.0/24"])}
    inst = Installation(tmp_path, [APP_HOST])

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "setup", "--env=papaia", APP_HOST, f"--subnet-pool={POOL}"])

    assert code == cli.SETUP_REFUSED
    err = capsys.readouterr().err
    assert "other-stack_default" in err and "10.212.7.0/24" in err
    assert not (inst.config / ".env").exists()


def test_networks_of_the_installation_itself_are_no_overlap(tmp_path, _host):
    _host.networks = {
        "papaia-net": ("papaia", ["10.212.0.0/24"]),
        "papaia_papaia-egress-net": ("papaia", ["10.212.1.0/24"]),
    }
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")

    assert subnet_pool.start_problems(inst.config, inst.repo) == []


def test_setup_names_the_networks_to_remove_after_a_change_of_the_pool(tmp_path, capsys, _host):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _host.networks = {"papaia-net": ("papaia", ["10.212.0.0/24"])}
    capsys.readouterr()

    inst.setup(f"--subnet-pool={OTHER_POOL}")

    out = capsys.readouterr()
    text = out.out + out.err
    assert "papaia-net" in text
    assert "stop --clean-up --addons" in text
    assert _subnets(_core_override(inst.config))["papaia-net"] == ipaddress.ip_network(
        "172.20.0.0/24"
    )


def test_start_refuses_a_network_of_the_installation_outside_the_pool(tmp_path, capsys, _host):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _host.networks = {"papaia-net": ("papaia", ["172.18.0.0/16"])}

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "subnet-pool-check"])

    assert code == 2
    err = capsys.readouterr().err
    assert "papaia-net" in err and "172.18.0.0/16" in err and "stop --clean-up" in err


def test_start_refuses_a_pool_overlapping_a_foreign_network(tmp_path, capsys, _host):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _host.networks = {"bridge": ("", ["10.212.200.0/24"])}

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "subnet-pool-check"])

    assert code == 2
    assert "bridge" in capsys.readouterr().err


def test_the_start_check_passes_without_a_pool_and_never_asks_docker(tmp_path, _host):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST)

    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "subnet-pool-check"])

    assert code == 0
    assert not _host.calls


def test_the_sql_uplink_must_not_overlap_a_block_of_the_pool(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    set_env({"config": inst.config}, PAPAIA_SQL_UPLINK_SUBNET="10.212.0.8/29")

    with pytest.raises(subnet_pool.SubnetPoolError, match="PAPAIA_SQL_UPLINK_SUBNET"):
        subnet_pool.generate_overrides(inst.config, inst.repo)
    with pytest.raises(render_core.RenderError, match="PAPAIA_SQL_UPLINK_SUBNET"):
        gen_override.generate_addon_join_overrides(inst.config, inst.repo)


# An add-on network that declares its own range (FLOW-055 for Flow) keeps it: it is not
# placed, not reported as outside the pool, and refused when it overlaps an assigned block.
OWN_FLOW_NETWORKS = {
    "flow-net": {
        "name": "${PAPAIA_PROJECT:-papaia}-flow-net",
        "ipam": {"config": [{"subnet": "${FLOW_NET_SUBNET:-10.231.21.0/24}"}]},
    },
    "flow-db": {"internal": True, "ipam": {"config": [{"subnet": "10.231.22.0/24"}]}},
    "flow-app": {},
}


def test_an_addon_network_with_its_own_range_outside_the_pool_passes_start(
    tmp_path, capsys, _host
):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    _addon(inst, "flow", OWN_FLOW_NETWORKS)
    run_cli(inst.repo, inst.config, "render")
    app = str(_subnets(yaml.safe_load(
        subnet_pool.addon_override_path(inst.config, "flow").read_text(encoding="utf-8")
    ))["flow-app"])
    _host.networks = {
        "papaia-net": ("papaia", ["10.212.0.0/24"]),
        "papaia-flow-net": ("flow", ["10.231.21.0/24"]),
        "flow_flow-db": ("flow", ["10.231.22.0/24"]),
        "flow_flow-app": ("flow", [app]),
    }

    assert subnet_pool.start_problems(inst.config, inst.repo) == []
    assert cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "subnet-pool-check"]) == 0

    # A network of the add-on without a range of its own is still checked.
    _host.networks["flow_flow-app"] = ("flow", ["172.18.0.0/16"])
    problems = subnet_pool.start_problems(inst.config, inst.repo)
    assert len(problems) == 1 and "flow_flow-app" in problems[0]


def test_an_addon_range_of_its_own_overlapping_an_assigned_block_is_refused(tmp_path, capsys):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    path = _addon(inst, "flow", OWN_FLOW_NETWORKS)
    # The block of papaia-audit-ingest-net, through the add-on's own variable.
    (path / ".env").write_text("FLOW_NET_SUBNET=10.212.3.0/24\n", encoding="utf-8")
    capsys.readouterr()

    with pytest.raises(subnet_pool.SubnetPoolError, match="papaia-flow-net.*10.212.3.0/24"):
        subnet_pool.generate_overrides(inst.config, inst.repo)
    assert cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "render"]) == 3
    assert "papaia-flow-net" in capsys.readouterr().err

    before = (inst.config / ".env").read_text(encoding="utf-8")
    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "setup", f"--subnet-pool={POOL}", "--subnet-block=25"])
    assert code == cli.SETUP_REFUSED
    assert "papaia-flow-net" in capsys.readouterr().err
    assert (inst.config / ".env").read_text(encoding="utf-8") == before

    # Outside the pool the same network is fine.
    (path / ".env").write_text("FLOW_NET_SUBNET=10.231.21.0/24\n", encoding="utf-8")
    run_cli(inst.repo, inst.config, "render")


def test_an_inactive_addon_with_an_overlapping_range_of_its_own_is_not_refused(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    path = _addon(inst, "flow", OWN_FLOW_NETWORKS)
    (path / ".env").write_text("FLOW_NET_SUBNET=10.212.3.0/24\n", encoding="utf-8")
    manifest = yaml.safe_load((inst.config / "deployment.yaml").read_text(encoding="utf-8"))
    manifest["addons"][-1]["active"] = False
    (inst.config / "deployment.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")

    subnet_pool.generate_overrides(inst.config, inst.repo)


def test_the_block_of_a_core_network_that_is_gone_is_freed(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}")
    state_path = inst.config / subnet_pool.STATE_FILE
    state = json.loads(state_path.read_text(encoding="utf-8"))
    # A core exit network that was on (its override existed) and is off now.
    state["networks"]["core:papaia-switched-off-net"] = "10.212.200.0/24"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    run_cli(inst.repo, inst.config, "render")

    kept = json.loads(state_path.read_text(encoding="utf-8"))["networks"]
    assert "core:papaia-switched-off-net" not in kept
    assert "10.212.200.0/24" not in kept.values()


def test_a_distributed_installation_refuses_the_pool(tmp_path, capsys):
    inst = Installation(tmp_path, [APP_HOST])
    code = cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config),
                     "setup", "--env=papaia", APP_HOST, "--topology=distributed",
                     "--node=internal=10.0.2.10", "--node=edge=10.0.1.10",
                     "--preset=dmz-split", f"--subnet-pool={POOL}"])

    assert code == cli.SETUP_REFUSED
    assert "distributed" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────
# addresses derived from the networks
# ─────────────────────────────────────────────────────────────────────────


def test_the_mail_relay_accepts_only_the_pool(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={OTHER_POOL}")

    override = _core_override(inst.config)
    relay = override["services"]["smtp-relay"]["environment"]
    assert relay["POSTFIX_mynetworks"] == f"127.0.0.0/8,{OTHER_POOL}"


def test_an_operator_list_of_mail_clients_stays(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={OTHER_POOL}")
    set_env({"config": inst.config}, SMTP_RELAY_ALLOWED_CLIENTS="127.0.0.0/8,172.20.0.0/24")
    run_cli(inst.repo, inst.config, "render")

    assert "services" not in _core_override(inst.config)


def test_an_operator_list_of_mail_clients_in_the_relay_env_stays(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={OTHER_POOL}")
    relay_env = inst.config / "infra" / "smtp-relay" / ".env"
    relay_env.parent.mkdir(parents=True, exist_ok=True)
    with relay_env.open("a", encoding="utf-8") as handle:
        handle.write("\nSMTP_RELAY_ALLOWED_CLIENTS=127.0.0.0/8,172.20.0.0/24\n")
    run_cli(inst.repo, inst.config, "render")

    assert "services" not in _core_override(inst.config)


def test_without_a_pool_the_proxy_settings_name_no_range(tmp_path):
    env = {"PAPAIA_PROJECT": "papaia"}
    assert subnet_pool.core_subnet(env, "papaia-net") is None
    assert hosted_model.no_proxy_ranges(env) == []
    assert federation.no_proxy_ranges(env) == []


def test_no_proxy_lists_the_assigned_subnet_of_the_shared_network():
    env = {"PAPAIA_PROJECT": "papaia", subnet_pool.POOL_KEY: OTHER_POOL}
    papaia_net = subnet_pool.core_subnet(env, "papaia-net")
    lifecycle = subnet_pool.core_subnet(env, "papaia-lifecycle-net")

    assert papaia_net == "172.20.0.0/24"
    assert hosted_model.no_proxy_ranges(env) == [papaia_net]
    assert federation.no_proxy_ranges(env) == [lifecycle]
    # The exit network of LiteLLM is never a direct route.
    assert subnet_pool.core_subnet(env, "papaia-egress-net") not in hosted_model.no_proxy_ranges(
        env
    )


def _internal_targets(config: Path, ranges: list[str]) -> None:
    path = config / egress.INTERNAL_TARGETS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump([{"name": "company", "ranges": ranges, "addons": ["notes"]}]),
        encoding="utf-8",
    )


def test_an_internal_egress_target_inside_the_pool_is_refused(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={OTHER_POOL}")
    _internal_targets(inst.config, ["172.20.4.0/24"])

    with pytest.raises(egress.EgressError, match=OTHER_POOL):
        egress.render(inst.config, inst.repo)


def test_an_internal_egress_target_outside_the_pool_stays_open(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={OTHER_POOL}")
    _internal_targets(inst.config, ["10.20.30.0/24"])

    path = egress.render(inst.config, inst.repo)

    assert json.loads(path.read_text(encoding="utf-8"))["format"] == egress.CONFIG_FORMAT


# ─────────────────────────────────────────────────────────────────────────
# doctor network
# ─────────────────────────────────────────────────────────────────────────


class DoctorHost(HostNetworks):
    """HostNetworks for the doctor, which also asks the healthy stack's other probes."""

    def __init__(self, networks):
        super().__init__(networks)
        self.base = healthy_docker()

    def __call__(self, cmd, timeout=None):
        if list(cmd[:3]) in (["docker", "network", "ls"], ["docker", "network", "inspect"]):
            return super().__call__(cmd, timeout)
        return self.base(cmd, timeout)


def _doctor_network(stack, runner) -> doctor.CheckResult:
    report = doctor.run_checks(
        stack["config"], stack["repo"], run=runner, probes=probes(), now=NOW
    )
    return result(report, "network")


def test_doctor_network_passes_when_every_network_lies_in_the_pool(stack):
    set_env(stack, **{subnet_pool.POOL_KEY: POOL, "COMPOSE_PROJECT_NAME": "papaia"})
    runner = DoctorHost({
        "papaia-net": ("papaia", ["10.212.0.0/24"]),
        "papaia_papaia-audit-net": ("papaia", ["10.212.2.0/24"]),
        "someone-else": ("other", ["172.30.0.0/16"]),
    })

    check = _doctor_network(stack, runner)

    assert check.status == PASS, check.summary
    assert check.details["subnet_pool"] == POOL


def test_doctor_network_fails_for_a_network_outside_the_pool_and_names_the_fix(stack):
    set_env(stack, **{subnet_pool.POOL_KEY: POOL, "COMPOSE_PROJECT_NAME": "papaia"})
    runner = DoctorHost({"papaia-net": ("papaia", ["172.18.0.0/16"])})

    check = _doctor_network(stack, runner)

    assert check.status == FAIL
    assert "papaia-net" in check.summary and "172.18.0.0/16" in check.summary
    assert "stop --clean-up" in check.summary


def test_doctor_network_passes_for_an_addon_network_with_its_own_range(stack):
    set_env(stack, **{subnet_pool.POOL_KEY: POOL, "COMPOSE_PROJECT_NAME": "papaia"})
    (stack["addon"] / "docker-compose.yml").write_text(yaml.safe_dump({
        "services": {"paperless": {"image": "x", "networks": ["own", "placed"]}},
        "networks": {
            "own": {"ipam": {"config": [{"subnet": "10.231.24.0/24"}]}},
            "placed": {},
        },
    }), encoding="utf-8")
    runner = DoctorHost({
        "papaia-net": ("papaia", ["10.212.0.0/24"]),
        "paperless_own": ("paperless", ["10.231.24.0/24"]),
    })

    check = _doctor_network(stack, runner)

    assert check.status == PASS, check.summary

    runner.networks["paperless_placed"] = ("paperless", ["172.18.0.0/16"])
    check = _doctor_network(stack, runner)
    assert check.status == FAIL and "paperless_placed" in check.summary


def test_doctor_network_without_pool_and_sql_source_still_skips(stack):
    runner = DoctorHost({"papaia-net": ("papaia", ["172.18.0.0/16"])})

    check = _doctor_network(stack, runner)

    assert check.status == SKIP
    assert not [c for c in runner.calls if c[:3] == ["docker", "network", "ls"]]
