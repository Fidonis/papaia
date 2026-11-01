"""Put the container `papaia-ctl` runs in onto the stack's network.

On the host, `start` reaches the stack through its published ports. papaia-manager runs
`papaia-ctl` in containers of its own: the manager itself, which is on the stack's network,
and its detached runners (upgrade, restore, a whole-stack restart), which are started with
`docker run` and are not. A runner cannot join the network when it starts: `stop
--clean-up` (`docker compose down`) removes the network, and a container still attached to
it makes that removal fail. So `start` joins it once `docker compose up` has created it
again, before the provisioning steps that need it (the NPM API at `nginx-proxy-manager:81`,
Keycloak at `keycloak:8443`).
"""

from __future__ import annotations

import json
import socket
import subprocess

from . import common

DEFAULT_NETWORK = "papaia-net"


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60, check=False
    )


def join(network: str) -> tuple[bool, str]:
    """Attach this container to `network`. (done, message): done is False only when it
    should have joined and could not. Outside a container there is nothing to do."""
    if not common.in_container():
        return True, ""
    # Docker names a container's host after its id unless told otherwise, and `docker`
    # accepts the id's prefix.
    self_id = socket.gethostname()
    try:
        inspected = _docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", self_id)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot run docker: {exc}"
    if inspected.returncode != 0:
        return False, f"cannot find this container ({self_id}) in docker"
    try:
        attached = json.loads(inspected.stdout or "{}") or {}
    except ValueError:
        attached = {}
    if network in attached:
        return True, ""
    try:
        connected = _docker("network", "connect", network, self_id)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot run docker: {exc}"
    if connected.returncode != 0:
        detail = (connected.stderr or connected.stdout).strip().splitlines()
        if detail:
            return False, detail[-1]
        return False, f"docker network connect exited {connected.returncode}"
    return True, f"joined the stack network {network}"
