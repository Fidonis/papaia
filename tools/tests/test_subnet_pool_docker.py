"""The address range of the installation's networks with real Docker networks.

`setup --subnet-pool=<test pool> --subnet-block=28` runs against a copy of this checkout,
then Compose creates the core project of the default profile set with the overrides
`papaia-ctl start` hands it. Every network Docker creates for the project lies in the
pool, in the block the override names; `doctor network` and the start check pass. A
foreign network inside the pool makes the start check refuse and name it.

The services are created, not started, and each is reduced to a bare container of the
pinned base image (a test overlay resets its image, mounts, secrets and dependencies):
the test is about the networks Compose creates, not about the services behind them.
The full stack with its smoke test runs in the joint test of the release.

Needs Docker; skipped without it. The Compose project and the pool (a /24) can be set
with PAPAIA_SUBNET_POOL_TEST_PROJECT and PAPAIA_SUBNET_POOL_TEST_SUBNET so the test does not
collide with other stacks on the same host.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path

import live_names
import pytest
import yaml
from install_helpers import Installation, run_cli
from test_doctor import NOW, probes, result

from lib import common, doctor, images, status, subnet_pool

PROJECT = live_names.project("subnet-pool-test", "PAPAIA_SUBNET_POOL_TEST_PROJECT")
SUBNET = live_names.subnet("PAPAIA_SUBNET_POOL_TEST_SUBNET")
# The pool of the installation under test (a /24 by default).
POOL = str(SUBNET)
BLOCK = 28
# The pinned base image of the core's own images (src/infra/egress/Dockerfile).
IMAGE = (
    "python:3.12.16-slim-trixie@sha256:"
    "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
APP_HOST = "--app-host=https://papaia.example.org"


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


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")


class _Reset(str):
    """A YAML value Compose reads as `!reset` (drop what the other files set)."""


def _reset_representer(dumper: yaml.SafeDumper, data: _Reset) -> yaml.Node:
    if data == "{}":
        return dumper.represent_mapping("!reset", {})
    return dumper.represent_sequence("!reset", [])


yaml.SafeDumper.add_representer(_Reset, _reset_representer)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=300, check=False
    )
    if check and done.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)}: {done.stderr or done.stdout}")
    return done


def _set_root(config: Path, **values: str) -> None:
    path = config / ".env"
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        key = line.partition("=")[0]
        if key in values:
            line = f"{key}={values.pop(key)}"
        out.append(line)
    out += [f"{k}={v}" for k, v in values.items()]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


@pytest.fixture
def installation(tmp_path):
    inst = Installation(tmp_path, [APP_HOST])
    inst.setup(APP_HOST, f"--subnet-pool={POOL}", f"--subnet-block={BLOCK}")
    # The Docker names of this test, never the ones of a real installation on the host.
    _set_root(
        inst.config,
        COMPOSE_PROJECT_NAME=PROJECT,
        PAPAIA_PROJECT=PROJECT,
        DOCKER_NETWORK=f"{PROJECT}-net",
    )
    run_cli(inst.repo, inst.config, "materialize-core")
    run_cli(inst.repo, inst.config, "render")
    return inst


def _compose(inst: Installation, overlay: Path, *args: str) -> list[str]:
    files = ["-f", str(inst.repo / "src" / "docker-compose.yml")]
    for path in sorted((inst.config / "overrides").glob("docker-compose.*.override.yml")):
        files += ["-f", str(path)]
    files += ["-f", str(overlay)]
    return ["compose", "-p", PROJECT, *files, "--env-file", str(inst.repo / "src" / ".env"),
            *args]


def _bare_overlay(inst: Installation, path: Path) -> None:
    root = common.parse_env_file(inst.config / ".env")
    profiles = {p.strip() for p in root.get("COMPOSE_PROFILES", "").split(",") if p.strip()}
    services = images.project_services(inst.repo, profiles)
    body = {
        "image": IMAGE,
        "entrypoint": ["python3", "-c", "import time; time.sleep(3600)"],
        "command": _Reset("[]"),
        "volumes": _Reset("[]"),
        "secrets": _Reset("[]"),
        "env_file": _Reset("[]"),
        "depends_on": _Reset("{}"),
        "ports": _Reset("[]"),
        "healthcheck": {"disable": True},
        "user": "65534:65534",
    }
    overlay = {"services": {name: dict(body) for name in sorted(services)}}
    path.write_text(yaml.safe_dump(overlay, sort_keys=False), encoding="utf-8")


def _project_networks() -> dict[str, list[str]]:
    names = _docker(
        "network", "ls", "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--format", "{{.Name}}",
    ).stdout.split()
    found = {}
    for name in names:
        data = json.loads(_docker("network", "inspect", name).stdout)[0]
        found[name] = [c["Subnet"] for c in (data.get("IPAM") or {}).get("Config") or []]
    return found


def test_the_networks_of_the_project_lie_in_the_pool(installation, tmp_path, capsys):
    inst = installation
    overlay = tmp_path / "bare.override.yml"
    _bare_overlay(inst, overlay)
    expected = {
        key: body["ipam"]["config"][0]["subnet"]
        for key, body in yaml.safe_load(
            (inst.config / "overrides" / subnet_pool.OVERRIDE).read_text(encoding="utf-8")
        )["networks"].items()
    }
    foreign = f"{PROJECT}-foreign"
    try:
        _docker(*_compose(inst, overlay, "create"))
        networks = _project_networks()

        pool = ipaddress.ip_network(POOL)
        assert f"{PROJECT}-net" in networks
        assert len(networks) >= 4, networks
        for name, subnets in networks.items():
            assert subnets, name
            for subnet in subnets:
                assert ipaddress.ip_network(subnet).subnet_of(pool), (name, subnet)
            key = name if name == f"{PROJECT}-net" else name.removeprefix(f"{PROJECT}_")
            key = "papaia-net" if key == f"{PROJECT}-net" else key
            assert subnets == [expected[key]], (name, subnets)

        # The start check and doctor network agree with the host.
        assert subnet_pool.start_problems(inst.config, inst.repo) == []
        report = doctor.run_checks(
            inst.config, inst.repo, run=status.run_command, probes=probes(), now=NOW
        )
        check = result(report, "network")
        assert check.status == doctor.PASS, check.summary

        # A network of another stack inside the pool: the start check refuses and names it.
        free = [
            str(b) for b in pool.subnets(new_prefix=BLOCK) if str(b) not in expected.values()
        ]
        _docker("network", "create", "--subnet", free[-1], foreign)
        problems = subnet_pool.start_problems(inst.config, inst.repo)
        assert any(foreign in p and free[-1] in p for p in problems), problems
    finally:
        _docker("network", "rm", foreign, check=False)
        _docker(*_compose(inst, overlay, "down", "-v", "--remove-orphans"), check=False)
    assert not _project_networks()
