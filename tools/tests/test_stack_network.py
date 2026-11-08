"""`start` in a container joins the stack's network before it provisions.

papaia-manager's runners are started with `docker run` and cannot join the network up
front (`docker compose down` removes it, and an attached container makes that fail), so
`start` joins it once `up` has created it. Docker is stubbed: these tests run nothing.
"""

from __future__ import annotations

import subprocess

import pytest

from lib import common, npm_provision, stack_network


class FakeDocker:
    def __init__(self, networks: str = '{"bridge":{}}', inspect_rc: int = 0, connect_rc: int = 0):
        self.calls: list[tuple[str, ...]] = []
        self.networks = networks
        self.inspect_rc = inspect_rc
        self.connect_rc = connect_rc

    def __call__(self, *args: str) -> subprocess.CompletedProcess:
        self.calls.append(args)
        if args[0] == "inspect":
            return subprocess.CompletedProcess(args, self.inspect_rc, self.networks + "\n", "")
        err = (
            ""
            if self.connect_rc == 0
            else "Error response from daemon: network papaia-net not found"
        )
        return subprocess.CompletedProcess(args, self.connect_rc, "", err)


@pytest.fixture
def in_container(monkeypatch):
    monkeypatch.setattr(common, "in_container", lambda: True)
    monkeypatch.setattr(stack_network.socket, "gethostname", lambda: "0123456789ab")


def test_on_the_host_nothing_happens(monkeypatch):
    monkeypatch.setattr(common, "in_container", lambda: False)
    docker = FakeDocker()
    monkeypatch.setattr(stack_network, "_docker", docker)
    assert stack_network.join("papaia-net") == (True, "")
    assert docker.calls == []


def test_a_runner_off_the_network_joins_it(monkeypatch, in_container):
    docker = FakeDocker()
    monkeypatch.setattr(stack_network, "_docker", docker)
    assert stack_network.join("papaia-net") == (True, "joined the stack network papaia-net")
    assert docker.calls[-1] == ("network", "connect", "papaia-net", "0123456789ab")


def test_a_container_already_on_the_network_stays_as_it_is(monkeypatch, in_container):
    # The manager itself is on papaia-net through its Compose file.
    docker = FakeDocker(networks='{"papaia-net":{}}')
    monkeypatch.setattr(stack_network, "_docker", docker)
    assert stack_network.join("papaia-net") == (True, "")
    assert [c[0] for c in docker.calls] == ["inspect"]


@pytest.mark.parametrize(
    "docker, fragment",
    [
        (FakeDocker(inspect_rc=1), "cannot find this container"),
        (FakeDocker(connect_rc=1), "network papaia-net not found"),
    ],
)
def test_a_failure_to_join_is_reported(monkeypatch, in_container, docker, fragment):
    monkeypatch.setattr(stack_network, "_docker", docker)
    done, message = stack_network.join("papaia-net")
    assert done is False and fragment in message


def test_npm_is_reached_on_the_stack_network_in_a_container(monkeypatch):
    nginx = {"NPM_API_LOCAL_PORT": "8282"}
    monkeypatch.setattr(common, "in_container", lambda: False)
    assert npm_provision._api_base_url(nginx) == "http://localhost:8282"
    monkeypatch.setattr(common, "in_container", lambda: True)
    assert npm_provision._api_base_url(nginx) == "http://nginx-proxy-manager:81"
