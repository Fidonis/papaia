"""The direct route to the SQL source and the communication matrix.

`security/comm-matrix.yaml` is the one list of connections (docs/network.md). Its only
direct route to a production system is K-14: `mcp-mssql` on the network
`papaia-sql-uplink`, created only with a SQL source (a protected host with a catalog
entry `mssql.<name>`), and host rules in `DOCKER-USER` that let only the protected
hosts and their ports out of it. `papaia-ctl topology firewall` prints the routes and
the host rules, `papaia-ctl doctor network` compares them with the host.

The run with real containers and a real `DOCKER-USER` chain is
`test_sql_uplink_docker.py`.
"""

from __future__ import annotations

import copy
import json
import stat
from pathlib import Path

import pytest
import yaml
from stack_helpers import FakeDocker, healthy_addon, healthy_core
from test_doctor import NOW, probes, result

from lib import cli, comm_matrix, deployment, doctor, egress, gen_override, reporting, sql_uplink
from lib.doctor import FAIL, PASS, SKIP, WARN
from lib.status import CommandResult

REPO = Path(__file__).resolve().parents[2]
SUBNET = "10.255.254.0/29"
ERP = {
    "name": "erp",
    "hosts": ["erp-sql.example.test", "192.0.2.15/32"],
    "ports": [1433],
    "catalog_entry": "mssql.erp",
}


def _env(config_dir: Path, **values: str) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    lines = {"PAPAIA_PROJECT": "papaia", **values}
    (config_dir / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in lines.items()), encoding="utf-8"
    )


def _protected(config_dir: Path, entries) -> None:
    path = config_dir / egress.PROTECTED_HOSTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(entries), encoding="utf-8")


def _addon(tmp_path: Path, config_dir: Path, name: str, services: dict, active=True) -> Path:
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    manifest = {"name": name, "version": "1.0.0"}
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    compose = {"services": services}
    (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    deployed = deployment.load(config_dir) or {"addons": []}
    deployed.setdefault("addons", []).append({"name": name, "path": str(path), "active": active})
    deployment.save(config_dir, deployed)
    return path


def _sql_addon(tmp_path: Path, config_dir: Path, active=True) -> Path:
    return _addon(
        tmp_path,
        config_dir,
        "mssql",
        {
            "mcp-mssql": {"image": "x", "networks": ["mcp"]},
            "mssql-helper": {"image": "x"},
        },
        active=active,
    )


def _override(config_dir: Path, name: str = "mssql") -> Path:
    return config_dir / "overrides" / "addons" / f"docker-compose.{name}-sql-uplink.override.yml"


# ─────────────────────────────────────────────────────────────────────────
# communication matrix
# ─────────────────────────────────────────────────────────────────────────


def _matrix() -> dict:
    return yaml.safe_load((REPO / comm_matrix.MATRIX_FILE).read_text(encoding="utf-8"))


def test_the_shipped_matrix_is_valid_and_lists_every_row():
    rows = comm_matrix.load(REPO)

    ids = [r["id"] for r in rows]
    assert ids == [f"K-{n:02d}" for n in range(1, 22)]
    for row in rows:
        if row["direction"] == "outbound":
            assert row["via"] in ("egress", "direct"), row["id"]
        else:
            assert "via" not in row, row["id"]
    direct = {r["id"] for r in rows if r.get("via") == "direct"}
    assert direct == {"K-12", "K-14", "K-15"}
    sql = next(r for r in rows if r["id"] == "K-14")
    assert (sql["from"], sql["from_network"], sql["ports"]) == (
        sql_uplink.SERVICE,
        sql_uplink.NETWORK,
        [1433],
    )
    # The operator's model server leaves through the exit, like mail, SIEM and federation.
    for row_id in ("K-10", "K-11", "K-16", "K-17", "K-20"):
        assert next(r for r in rows if r["id"] == row_id)["via"] == "egress"


def _mutated(change) -> dict:
    doc = copy.deepcopy(_matrix())
    change(doc)
    return doc


def _row(doc: dict, row_id: str) -> dict:
    return next(r for r in doc["rows"] if r["id"] == row_id)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(extra=1),
        lambda d: _row(d, "K-01").update(colour="red"),
        lambda d: _row(d, "K-02").update(via="egress"),
        lambda d: _row(d, "K-10").pop("via"),
        lambda d: _row(d, "K-10").update(via="direct"),
        lambda d: _row(d, "K-14").update(via="tunnel"),
        lambda d: _row(d, "K-14").update(ports=[70000]),
        lambda d: _row(d, "K-14").update(ports=["1433"]),
        lambda d: _row(d, "K-14").update(direction="sideways"),
        lambda d: _row(d, "K-14").update(required="yes"),
        lambda d: _row(d, "K-14").update(purpose="x" * 1001),
        lambda d: _row(d, "K-14").pop("purpose"),
        lambda d: _row(d, "K-02").update(id="K-01"),
        lambda d: _row(d, "K-02").update(id="X-02"),
        lambda d: d.update(version=2),
    ],
)
def test_the_matrix_refuses_unknown_fields_and_bad_values(change):
    with pytest.raises(comm_matrix.MatrixError):
        comm_matrix.validate(_mutated(change))


# ─────────────────────────────────────────────────────────────────────────
# the uplink network
# ─────────────────────────────────────────────────────────────────────────


def test_without_a_sql_source_there_is_no_uplink(tmp_path, config_dir):
    _env(config_dir)
    _protected(config_dir, [{"name": "dms", "hosts": ["192.0.2.30"]}])
    _sql_addon(tmp_path, config_dir)

    gen_override.generate_addon_join_overrides(config_dir, tmp_path)

    assert sql_uplink.targets(config_dir) == []
    assert not _override(config_dir).exists()
    assert sql_uplink.render_rules(config_dir) is None
    assert not (config_dir / sql_uplink.RULES_FILE).exists()


def test_only_mcp_mssql_joins_the_uplink_next_to_its_networks(tmp_path, config_dir):
    _env(config_dir, PAPAIA_PROJECT="papaia-dev")
    _protected(config_dir, [ERP])
    _sql_addon(tmp_path, config_dir)

    gen_override.generate_addon_join_overrides(config_dir, tmp_path)

    override = yaml.safe_load(_override(config_dir).read_text(encoding="utf-8"))
    bridge = sql_uplink.bridge(sql_uplink.root_env(config_dir))
    assert override == {
        "services": {sql_uplink.SERVICE: {"networks": ["mcp", sql_uplink.NETWORK]}},
        "networks": {
            sql_uplink.NETWORK: {
                "name": "papaia-dev-sql-uplink",
                "driver": "bridge",
                "driver_opts": {"com.docker.network.bridge.name": bridge},
                "internal": False,
                # IPv4 only: no IPv6 range that the host rules would not cover, also when
                # the daemon turns IPv6 on for new networks by default.
                "enable_ipv6": False,
                "ipam": {"config": [{"subnet": SUBNET}]},
                "labels": {"de.fidonis.network": "sql-uplink"},
            }
        },
    }


def test_the_bridge_name_is_per_installation_and_a_valid_interface_name(config_dir, tmp_path):
    _env(config_dir, PAPAIA_PROJECT="papaia")
    other = tmp_path / "other"
    _env(other, PAPAIA_PROJECT="papaia-dev")

    names = {sql_uplink.bridge(sql_uplink.root_env(d)) for d in (config_dir, other)}

    assert len(names) == 2
    for name in names:
        # Linux allows 15 characters for an interface name.
        assert name.startswith("psql-") and len(name) <= 15 and name.isascii()


def test_the_uplink_goes_away_with_the_addon_or_the_sql_source(tmp_path, config_dir):
    _env(config_dir)
    _protected(config_dir, [ERP])
    _sql_addon(tmp_path, config_dir)
    gen_override.generate_addon_join_overrides(config_dir, tmp_path)
    assert _override(config_dir).is_file()

    deployed = deployment.load(config_dir)
    deployed["addons"][0]["active"] = False
    deployment.save(config_dir, deployed)
    gen_override.generate_addon_join_overrides(config_dir, tmp_path)
    assert not _override(config_dir).exists()

    deployed["addons"][0]["active"] = True
    deployment.save(config_dir, deployed)
    _protected(config_dir, [])
    gen_override.generate_addon_join_overrides(config_dir, tmp_path)
    assert not _override(config_dir).exists()


def test_an_addon_without_mcp_mssql_never_joins(tmp_path, config_dir):
    _env(config_dir)
    _protected(config_dir, [ERP])
    _addon(tmp_path, config_dir, "other", {"worker": {"image": "x"}})

    gen_override.generate_addon_join_overrides(config_dir, tmp_path)

    assert not _override(config_dir, "other").exists()


def test_two_addons_with_mcp_mssql_are_refused(tmp_path, config_dir):
    _env(config_dir)
    _protected(config_dir, [ERP])
    _sql_addon(tmp_path, config_dir)
    _addon(tmp_path, config_dir, "second", {"mcp-mssql": {"image": "x"}})

    with pytest.raises(sql_uplink.SqlUplinkError, match="mcp-mssql"):
        sql_uplink.generate_override(config_dir, tmp_path)
    assert not _override(config_dir).exists()
    assert not _override(config_dir, "second").exists()


@pytest.mark.parametrize(
    "entry",
    [
        {**ERP, "ports": None},
        {k: v for k, v in ERP.items() if k != "ports"},
        {**ERP, "hosts": ["erp-sql.example.test"]},
        {**ERP, "hosts": ["2001:db8::15"]},
        {**ERP, "hosts": ["0.0.0.0/0"]},
    ],
)
def test_a_sql_source_needs_ports_and_ipv4_addresses(config_dir, entry):
    _env(config_dir)
    _protected(config_dir, [{k: v for k, v in entry.items() if v is not None}])

    with pytest.raises((sql_uplink.SqlUplinkError, egress.EgressError)):
        sql_uplink.targets(config_dir)


@pytest.mark.parametrize(
    "subnet", ["8.8.8.0/29", "10.0.0.0/8", "10.255.254.0/30", "not-a-net", "fd00::/64"]
)
def test_the_uplink_subnet_must_be_a_small_private_ipv4_range(config_dir, subnet):
    _env(config_dir, PAPAIA_SQL_UPLINK_SUBNET=subnet)

    with pytest.raises(sql_uplink.SqlUplinkError, match="PAPAIA_SQL_UPLINK_SUBNET"):
        sql_uplink.subnet(sql_uplink.root_env(config_dir))


def test_the_uplink_subnet_must_not_contain_a_sql_host(config_dir):
    _env(config_dir, PAPAIA_SQL_UPLINK_SUBNET="192.0.2.8/29")
    _protected(config_dir, [{**ERP, "hosts": ["192.0.2.12"]}])

    with pytest.raises(sql_uplink.SqlUplinkError, match="overlaps"):
        sql_uplink.expected_rules(config_dir)


# ─────────────────────────────────────────────────────────────────────────
# host rules
# ─────────────────────────────────────────────────────────────────────────


def test_the_host_rules_let_only_the_listed_addresses_and_ports_out(config_dir):
    _env(config_dir)
    _protected(
        config_dir,
        [ERP, {"name": "dwh", "hosts": ["198.51.100.0/28"], "ports": [1433, 14330],
               "catalog_entry": "mssql.dwh"}],
    )
    env = sql_uplink.root_env(config_dir)
    chain, br = sql_uplink.chain(env), sql_uplink.bridge(env)

    assert chain.startswith("PAPAIA-SQL-") and len(chain) <= 28
    assert sql_uplink.expected_rules(config_dir) == [
        f"-N {chain}",
        # Only from the uplink's own bridge: a forged uplink address on another bridge
        # never matches.
        f"-A {chain} -s {SUBNET} -d 192.0.2.15/32 -i {br} -p tcp -m tcp --dport 1433 -j RETURN",
        f"-A {chain} -s {SUBNET} -d 198.51.100.0/28 -i {br} -p tcp -m tcp --dport 1433"
        " -j RETURN",
        f"-A {chain} -s {SUBNET} -d 198.51.100.0/28 -i {br} -p tcp -m tcp --dport 14330"
        " -j RETURN",
        f"-A {chain} -s {SUBNET} -j DROP",
        f"-A {chain} -i {br} -j DROP",
        # Every other container: never to the protected hosts, never to a SQL port.
        f"-A {chain} -d 192.0.2.15/32 -j DROP",
        f"-A {chain} -d 198.51.100.0/28 -j DROP",
        f"-A {chain} -p tcp -m tcp --dport 1433 -j DROP",
        f"-A {chain} -p tcp -m tcp --dport 14330 -j DROP",
    ]
    assert sql_uplink.jump_rule(chain) == f"-A DOCKER-USER -j {chain}"


def test_the_chain_name_is_per_installation(config_dir, tmp_path):
    _env(config_dir, PAPAIA_PROJECT="papaia")
    other = tmp_path / "other"
    _env(other, PAPAIA_PROJECT="papaia-dev")

    assert sql_uplink.chain(sql_uplink.root_env(config_dir)) != sql_uplink.chain(
        sql_uplink.root_env(other)
    )


def test_the_rules_script_loads_the_chain_atomically_and_jumps_once(config_dir):
    _env(config_dir)
    _protected(config_dir, [ERP])
    chain = sql_uplink.chain(sql_uplink.root_env(config_dir))

    path = sql_uplink.render_rules(config_dir)

    assert path == config_dir / sql_uplink.RULES_FILE
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text
    assert "iptables-restore --noflush" in text
    assert f":{chain} - [0:0]" in text
    for line in sql_uplink.expected_rules(config_dir)[1:]:
        assert line in text
    assert (
        f"iptables -C DOCKER-USER -j {chain} 2>/dev/null"
        f" || iptables -I DOCKER-USER 1 -j {chain}" in text
    )
    # Readable for the operator, written by nobody else.
    assert stat.S_IMODE(path.stat().st_mode) & 0o022 == 0

    _protected(config_dir, [])
    assert sql_uplink.render_rules(config_dir) is None
    assert not path.exists()


def test_compare_names_missing_unexpected_and_misplaced_rules():
    chain = "PAPAIA-SQL-0123ABCD"
    expected = [f"-N {chain}", f"-A {chain} -s {SUBNET} -j DROP", f"-A {chain} -p tcp -j DROP"]
    live = f"-N {chain}\n-A {chain} -s {SUBNET} -j DROP\n-A {chain} -s {SUBNET} -j ACCEPT\n"
    docker_user = f"-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n-A DOCKER-USER -j {chain}\n"

    problems = sql_uplink.compare(expected, chain, live, docker_user)

    assert f"missing: -A {chain} -p tcp -j DROP" in problems
    assert f"unexpected: -A {chain} -s {SUBNET} -j ACCEPT" in problems
    assert any("first rule of DOCKER-USER" in p for p in problems)
    good_user = f"-N DOCKER-USER\n-A DOCKER-USER -j {chain}\n-A DOCKER-USER -j RETURN\n"
    assert sql_uplink.compare(expected, chain, "\n".join(expected) + "\n", good_user) == []


# ─────────────────────────────────────────────────────────────────────────
# doctor network
# ─────────────────────────────────────────────────────────────────────────


class HostRules:
    """`docker` of the healthy stack plus the uplink network, its members and `iptables`."""

    def __init__(self, chain_text, docker_user, *, network=None, members=None, iptables=None):
        self.base = FakeDocker(healthy_core() + healthy_addon())
        self.chain_text = chain_text
        self.docker_user = docker_user
        self.network = network
        default = "papaia-mssql-mcp-mssql-1\tmcp-mssql\tmssql\n"
        self.members = members if members is not None else default
        self.iptables = iptables
        # The other networks of mcp-mssql, by name: internal ones carry no default route.
        self.others = {"papaia-mssql-mcp": {"Name": "papaia-mssql-mcp", "Internal": True}}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            if cmd[-1] in self.others:
                return CommandResult(0, json.dumps(self.others[cmd[-1]]) + "\n", "")
            if self.network is None or cmd[-1] != "papaia-sql-uplink":
                return CommandResult(1, "", "Error: No such network")
            return CommandResult(0, json.dumps(self.network) + "\n", "")
        if cmd[:2] == ["docker", "inspect"] and "{{json .NetworkSettings.Networks}}" in cmd:
            attached = {"papaia-sql-uplink": {}, **{name: {} for name in self.others}}
            return CommandResult(0, json.dumps(attached) + "\n", "")
        if cmd[:3] == ["docker", "ps", "--filter"] and any("network=" in c for c in cmd):
            return CommandResult(0, self.members, "")
        if cmd[0] == "iptables":
            if self.iptables is not None:
                return self.iptables
            if cmd[-1] == "DOCKER-USER":
                return CommandResult(0, self.docker_user, "")
            if self.chain_text is None:
                return CommandResult(1, "", "iptables: No chain/target/match by that name.")
            return CommandResult(0, self.chain_text, "")
        return self.base(cmd, timeout)


def _network(subnet=SUBNET, internal=False, ipv6=False, bridge=None) -> dict:
    configs = [{"Subnet": subnet}]
    if ipv6:
        configs.append({"Subnet": "fd00:dead:beef::/64"})
    return {
        "Name": "papaia-sql-uplink",
        "Internal": internal,
        "EnableIPv6": ipv6,
        "IPAM": {"Config": configs},
        "Options": {
            "com.docker.network.bridge.name": bridge
            or sql_uplink.bridge({"PAPAIA_PROJECT": "papaia"})
        },
    }


@pytest.fixture
def sql_stack(stack):
    _protected(stack["config"], [ERP])
    _sql_addon(stack["config"].parent, stack["config"])
    return stack


def _good(stack) -> HostRules:
    expected = sql_uplink.expected_rules(stack["config"])
    chain = sql_uplink.chain(sql_uplink.root_env(stack["config"]))
    return HostRules(
        "\n".join(expected) + "\n",
        f"-N DOCKER-USER\n-A DOCKER-USER -j {chain}\n-A DOCKER-USER -j RETURN\n",
        network=_network(),
    )


def _network_check(stack, runner, **probe_overrides) -> doctor.CheckResult:
    report = doctor.run_checks(
        stack["config"], stack["repo"], run=runner, probes=probes(**probe_overrides), now=NOW
    )
    return result(report, "network")


def test_doctor_network_skips_without_a_sql_source(stack):
    runner = HostRules(None, "")

    check = _network_check(stack, runner)

    assert check.status == SKIP
    assert not [c for c in runner.calls if c[0] == "iptables"]


def test_doctor_network_passes_when_network_and_rules_match(sql_stack):
    check = _network_check(sql_stack, _good(sql_stack))

    assert check.status == PASS, check.summary
    assert check.details["network"] == "papaia-sql-uplink"
    assert check.details["members"] == ["papaia-mssql-mcp-mssql-1"]


def test_a_drifted_host_rule_makes_doctor_network_fail(sql_stack):
    runner = _good(sql_stack)
    runner.chain_text = runner.chain_text.replace(
        "--dport 1433 -j RETURN", "--dport 1434 -j RETURN"
    )

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "--dport 1434" in check.summary
    assert "sql-uplink-rules.sh" in check.summary


def test_a_missing_jump_or_chain_makes_doctor_network_fail(sql_stack):
    runner = _good(sql_stack)
    runner.docker_user = "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"
    assert _network_check(sql_stack, runner).status == FAIL

    runner = _good(sql_stack)
    runner.chain_text = None
    check = _network_check(sql_stack, runner)
    assert check.status == FAIL
    assert "not loaded" in check.summary


@pytest.mark.parametrize(
    "answer",
    [
        CommandResult(127, "", "iptables: command not found"),
        CommandResult(4, "", "iptables v1.8.9: Permission denied (you must be root)"),
    ],
)
def test_unreadable_host_rules_are_a_warning_not_a_pass(sql_stack, answer):
    runner = _good(sql_stack)
    runner.iptables = answer

    check = _network_check(sql_stack, runner)

    assert check.status == WARN
    assert "not verified" in check.summary


def test_another_member_of_the_uplink_makes_doctor_network_fail(sql_stack):
    runner = _good(sql_stack)
    runner.members += "papaia-librechat-1\tlibrechat\tpapaia\n"

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "papaia-librechat-1" in check.summary


@pytest.mark.parametrize("network", [_network(subnet="10.255.253.0/29"), _network(internal=True)])
def test_an_uplink_other_than_rendered_makes_doctor_network_fail(sql_stack, network):
    runner = _good(sql_stack)
    runner.network = network

    assert _network_check(sql_stack, runner).status == FAIL


def test_an_uplink_with_ipv6_makes_doctor_network_fail(sql_stack):
    runner = _good(sql_stack)
    runner.network = _network(ipv6=True)

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "IPv6" in check.summary


def test_an_uplink_with_an_ipv6_range_but_no_flag_makes_doctor_network_fail(sql_stack):
    runner = _good(sql_stack)
    runner.network = _network(ipv6=True)
    runner.network["EnableIPv6"] = False

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "IPv6" in check.summary


def test_an_uplink_on_another_bridge_than_the_host_rules_name_fails(sql_stack):
    runner = _good(sql_stack)
    runner.network = _network(bridge="br-0123456789ab")

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "br-0123456789ab" in check.summary


def test_a_second_network_with_a_route_out_makes_doctor_network_fail(sql_stack):
    # Docker may put the default route of mcp-mssql on any network that is not internal;
    # the SQL traffic would then leave with a source the host rules drop.
    runner = _good(sql_stack)
    runner.others["papaia-net"] = {"Name": "papaia-net", "Internal": False}

    check = _network_check(sql_stack, runner)

    assert check.status == FAIL
    assert "papaia-net" in check.summary


def test_an_uplink_not_created_yet_is_a_warning(sql_stack):
    runner = _good(sql_stack)
    runner.network = None

    check = _network_check(sql_stack, runner)

    assert check.status == WARN
    assert "not created" in check.summary


# ─────────────────────────────────────────────────────────────────────────
# topology firewall on one host
# ─────────────────────────────────────────────────────────────────────────


def _firewall(stack, capsys, fmt: str) -> str:
    code = cli.main(
        [
            "--repo-root",
            str(REPO),
            "--config-dir",
            str(stack["config"]),
            "topology-firewall",
            f"--format={fmt}",
        ]
    )
    assert code == 0
    return capsys.readouterr().out


def test_topology_firewall_prints_the_routes_and_host_rules_of_one_host(sql_stack, capsys):
    printed = json.loads(_firewall(sql_stack, capsys, "json"))

    sql = [r for r in printed["routes"] if r["id"] == "K-14"]
    assert sql == [
        {
            "id": "K-14",
            "from": "mcp-mssql",
            "from_network": "papaia-sql-uplink",
            "to": "erp (mssql.erp)",
            "to_address": "192.0.2.15/32",
            "ports": [1433],
            "protocol": "tcp",
            "via": "direct",
            "purpose": sql[0]["purpose"],
            "pending": "",
        }
    ]
    assert {r["id"] for r in printed["routes"]} >= {"K-12", "K-13", "K-14", "K-15", "K-19"}
    assert printed["host_rules"] == sql_uplink.expected_rules(sql_stack["config"])
    assert printed["rules_file"] == str(sql_stack["config"] / sql_uplink.RULES_FILE)

    table = _firewall(sql_stack, capsys, "table")
    assert "K-14" in table and "192.0.2.15/32" in table and "DOCKER-USER" in table
    csv = _firewall(sql_stack, capsys, "csv")
    assert csv.splitlines()[0] == "id,from,from_network,to,to_address,ports,protocol,via,pending"


def test_topology_firewall_without_a_sql_source_has_no_direct_database_route(stack, capsys):
    printed = json.loads(_firewall(stack, capsys, "json"))

    assert "K-14" not in {r["id"] for r in printed["routes"]}
    assert printed["host_rules"] == []


# ─────────────────────────────────────────────────────────────────────────
# where the model is: setup summary
# ─────────────────────────────────────────────────────────────────────────


def test_the_setup_summary_says_the_model_stays_inside(config_dir, monkeypatch, capsys):
    monkeypatch.setattr(reporting.hosted_model, "route", lambda config, names: None)
    monkeypatch.setattr(
        reporting.hosted_model, "rendered_stack_names", lambda config, repo: frozenset()
    )

    reporting.print_model_location(config_dir, REPO)

    out = capsys.readouterr().out
    assert "inside the installation" in out
    assert reporting.MODEL_OUTSIDE_NOTICE not in out


def test_the_setup_summary_warns_when_the_model_is_outside(config_dir, monkeypatch, capsys):
    monkeypatch.setattr(
        reporting.hosted_model, "route", lambda config, names: ("models.example.test", 8443)
    )
    monkeypatch.setattr(
        reporting.hosted_model, "rendered_stack_names", lambda config, repo: frozenset()
    )

    reporting.print_model_location(config_dir, REPO)

    out = capsys.readouterr().out
    assert "outside the installation (models.example.test:8443)" in out
    assert (
        "Inhalte der Anfragen verlassen Ihr Netz. Prüfen Sie Auftragsverarbeitung und"
        " Übermittlung."
    ) in out
