"""The direct route to the SQL source with real containers and real host rules.

A "SQL test server" (a TCP listener) sits on a network outside the stack. `mcp-mssql` of
an add-on joins `papaia-sql-uplink` through the override `papaia-ctl` writes; another
container sits on an ordinary network with a route out. The host rules `papaia-ctl`
renders are loaded into the host's `DOCKER-USER` chain. Then:

  * `mcp-mssql` reaches the SQL test server on its listed port;
  * the other container does not;
  * `doctor network` passes, and fails after one rule of the chain is changed.

The host rules are changed in the network namespace of the Docker host (on Docker
Desktop: of its VM) through a privileged helper container, and removed again at the
end. Because the test changes the firewall of the host it runs on, it runs only when
asked for with PAPAIA_HOST_RULES_TEST=1 and Docker is available. The port of the test
server (PAPAIA_SQL_UPLINK_TEST_PORT, default 14330, never 1433 so that no other SQL
Server on the host is affected), the Compose project (PAPAIA_SQL_UPLINK_TEST_PROJECT)
and the address range (PAPAIA_SQL_UPLINK_TEST_SUBNET, a /24) can be set.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from test_doctor import NOW, probes, result

from lib import deployment, doctor, egress, sql_uplink, status

PROJECT = os.environ.get("PAPAIA_SQL_UPLINK_TEST_PROJECT", "papaia-sql-uplink-test")
SUBNET = ipaddress.ip_network(os.environ.get("PAPAIA_SQL_UPLINK_TEST_SUBNET", "10.250.81.0/24"))
PORT = int(os.environ.get("PAPAIA_SQL_UPLINK_TEST_PORT", "14330"))
# The pinned base of the core's own images (src/infra/egress/Dockerfile); Debian, so it
# carries nsenter for the helper that reaches the host's network namespace.
IMAGE = (
    "python:3.12.16-slim-trixie"
    "@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


pytestmark = [
    pytest.mark.skipif(
        os.environ.get("PAPAIA_HOST_RULES_TEST") != "1",
        reason="changes the host firewall; set PAPAIA_HOST_RULES_TEST=1 to run it",
    ),
    pytest.mark.skipif(not _docker_available(), reason="Docker is not available"),
]

_LISTENER = (
    "import socket\n"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('',{PORT}));s.listen()\n"
    "while True:\n"
    "    c,_=s.accept();c.sendall(b'sql');c.close()\n"
)
_PROBE = (
    "import socket,sys\n"
    "try:\n"
    f"    c=socket.create_connection((sys.argv[1],{PORT}),timeout=5);print(c.recv(3).decode())\n"
    "except OSError as e:\n"
    "    print(type(e).__name__)\n"
)


def _run(*args: str, stdin: str | None = None, check: bool = True):
    return subprocess.run(
        list(args), input=stdin, capture_output=True, text=True, timeout=300, check=check
    )


def _on_host(*argv: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """A command in the network and mount namespace of the Docker host."""
    return _run(
        "docker", "run", "--rm", "-i", "--privileged", "--pid=host", "--network=host",
        "--name", f"{PROJECT}-host-rules", IMAGE,
        "nsenter", "-t", "1", "-m", "-n", *argv,
        stdin=stdin, check=False,
    )


def _host_runner(cmd, timeout):
    """doctor's runner: iptables on the Docker host, everything else as usual."""
    cmd = list(cmd)
    if cmd[0] == "iptables":
        done = _on_host(*cmd)
        return status.CommandResult(done.returncode, done.stdout, done.stderr)
    return status.run_command(cmd, timeout)


@pytest.fixture
def uplink(tmp_path: Path):
    blocks = list(SUBNET.subnets(new_prefix=28))
    uplink_net, outside, other = blocks[0], blocks[1], blocks[2]
    server_ip = str(outside.network_address + 10)
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir()
    (config_dir / ".env").write_text(
        f"PAPAIA_PROJECT={PROJECT}\nCOMPOSE_PROJECT_NAME={PROJECT}\n"
        f"PAPAIA_SQL_UPLINK_SUBNET={uplink_net}\n",
        encoding="utf-8",
    )
    (config_dir / egress.PROTECTED_HOSTS_FILE).parent.mkdir(parents=True)
    (config_dir / egress.PROTECTED_HOSTS_FILE).write_text(
        yaml.safe_dump(
            [{"name": "erp", "hosts": [f"{server_ip}/32"], "ports": [PORT],
              "catalog_entry": "mssql.erp"}]
        ),
        encoding="utf-8",
    )
    addon = tmp_path / "addons" / PROJECT
    addon.mkdir(parents=True)
    (addon / "papaia-app.yaml").write_text("name: mssql\nversion: 1.0.0\n", encoding="utf-8")
    sleeper = {"image": IMAGE, "command": ["sleep", "infinity"], "init": True}
    compose = {
        "services": {
            "mcp-mssql": {**sleeper, "networks": ["mcp"]},
            "other": {**sleeper, "networks": ["other"]},
            "sql-test": {
                "image": IMAGE,
                "command": ["python3", "-c", _LISTENER],
                "networks": {"outside": {"ipv4_address": server_ip}},
            },
        },
        "networks": {
            "mcp": {"name": f"{PROJECT}-mcp", "internal": True},
            "outside": {"name": f"{PROJECT}-outside",
                        "ipam": {"config": [{"subnet": str(outside)}]}},
            "other": {"name": f"{PROJECT}-other", "ipam": {"config": [{"subnet": str(other)}]}},
        },
    }
    (addon / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    deployment.save(config_dir, {"addons": [{"name": "mssql", "path": str(addon), "active": True}]})

    override = sql_uplink.generate_override(config_dir, tmp_path)
    rules = sql_uplink.render_rules(config_dir)
    assert override is not None and rules is not None
    files = ["-f", str(addon / "docker-compose.yml"), "-f", str(override)]
    chain = sql_uplink.chain(sql_uplink.root_env(config_dir))
    try:
        up = _run("docker", "compose", "-p", PROJECT, *files, "up", "-d", "--wait", check=False)
        assert up.returncode == 0, up.stderr
        loaded = _on_host("sh", "-s", stdin=rules.read_text(encoding="utf-8"))
        assert loaded.returncode == 0, loaded.stderr
        yield {"config": config_dir, "repo": tmp_path, "project": PROJECT, "files": files,
               "server": server_ip, "chain": chain, "uplink_net": uplink_net}
    finally:
        _on_host("sh", "-c", f"iptables -D DOCKER-USER -j {chain}; iptables -F {chain};"
                             f" iptables -X {chain}; true")
        _run("docker", "compose", "-p", PROJECT, *files, "down", "-v", "--remove-orphans",
             check=False)


def _probe(ctx: dict, service: str) -> str:
    done = _run("docker", "compose", "-p", ctx["project"], *ctx["files"], "exec", "-T", service,
                "python3", "-c", _PROBE, ctx["server"], check=False)
    return done.stdout.strip()


_DEFAULT_GATEWAY = (
    "import ipaddress,socket,struct\n"
    "for line in open('/proc/net/route').read().splitlines()[1:]:\n"
    "    f=line.split()\n"
    "    if f[1]=='00000000':\n"
    "        print(socket.inet_ntoa(struct.pack('<L',int(f[2],16))))\n"
)


def _default_gateway(ctx: dict, service: str) -> str:
    done = _run("docker", "compose", "-p", ctx["project"], *ctx["files"], "exec", "-T", service,
                "python3", "-c", _DEFAULT_GATEWAY, check=False)
    return done.stdout.strip()


def test_only_mcp_mssql_reaches_the_sql_server_and_doctor_sees_drift(uplink):
    # The default route of mcp-mssql is the uplink's (its other network is internal), so
    # the SQL traffic leaves with the source the host rules let out.
    gateway = _default_gateway(uplink, "mcp-mssql")
    assert gateway and ipaddress.ip_address(gateway) in uplink["uplink_net"], gateway
    assert _probe(uplink, "mcp-mssql") == "sql"
    assert _probe(uplink, "other") in ("TimeoutError", "ConnectionRefusedError", "OSError")

    report = doctor.run_checks(uplink["config"], uplink["repo"], run=_host_runner,
                               probes=probes(), now=NOW)
    assert result(report, "network").status == doctor.PASS, result(report, "network").summary

    chain = uplink["chain"]
    drift = _on_host("iptables", "-R", chain, "1", "-s", str(SUBNET), "-j", "RETURN")
    assert drift.returncode == 0, drift.stderr
    report = doctor.run_checks(uplink["config"], uplink["repo"], run=_host_runner,
                               probes=probes(), now=NOW)
    assert result(report, "network").status == doctor.FAIL
