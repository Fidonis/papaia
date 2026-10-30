"""How the controller runs a node verb: on itself, or over SSH.

Both executors end up in the same place, `papaia-ctl node-shell` on the node (see
lib/node_shell.py), with the requested command in `SSH_ORIGINAL_COMMAND`:

* `local` runs the shim directly, for the controller's own node. Nothing else changes
  about how the controller's containers are managed than which env files they start with.
* `ssh` connects as the node's unprivileged user with the node's own key, a host key
  pinned at enrolment and no fallback to a password or an unknown host. The node's
  `authorized_keys` forces the shim, so the command sent here is only a request.

A resident node daemon could be added later as a third executor with the same interface.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .topology import NODES_DIR, Node, Topology

SSH_DIR = "ssh"
KEY_NAME = "id_ed25519"
KNOWN_HOSTS = "known_hosts"
CONNECT_TIMEOUT = 10

_WORD_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9._:=,+-]{0,127}|--[a-z][a-z-]{0,30}=[A-Za-z0-9._:,+-]{1,64})$"
)


class ExecutorError(Exception):
    """A node that cannot be asked at all (no key, no pinned host key)."""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def ssh_dir(config_dir: Path, node: str) -> Path:
    return config_dir / NODES_DIR / node / SSH_DIR


def _check(command: list[str]) -> None:
    if not command:
        raise ExecutorError("no command")
    for word in command:
        if not _WORD_RE.match(word):
            raise ExecutorError(f"not a node command word: {word!r}")


class Executor:
    """Runs one node verb and returns its exit code; output streams unless captured."""

    def __init__(self, node: Node):
        self.node = node

    def argv(self, command: list[str]) -> tuple[list[str], dict[str, str]]:
        raise NotImplementedError

    def run(
        self,
        command: list[str],
        *,
        stdin: bytes | BinaryIO | None = None,
        capture: bool = False,
        stdout: BinaryIO | None = None,
        timeout: float | None = None,
    ) -> Result:
        """`stdin` is uploaded (bytes or a file), `stdout` receives a download as is.
        With `capture` the output comes back in the result instead of streaming."""
        _check(command)
        argv, env = self.argv(command)
        kwargs: dict = {"env": env, "timeout": timeout, "check": False}
        if isinstance(stdin, bytes):
            kwargs["input"] = stdin
        elif stdin is not None:
            kwargs["stdin"] = stdin
        else:
            kwargs["stdin"] = subprocess.DEVNULL
        if stdout is not None:
            kwargs["stdout"] = stdout
            kwargs["stderr"] = subprocess.PIPE if capture else None
        elif capture:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        try:
            done = subprocess.run(argv, **kwargs)  # noqa: S603 - fixed argv, no shell
        except FileNotFoundError as exc:
            return Result(127, "", f"{argv[0]}: command not found ({exc})")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"node '{self.node.name}' did not answer within {timeout}s")
        out = done.stdout.decode("utf-8", "replace") if isinstance(done.stdout, bytes) else ""
        err = done.stderr.decode("utf-8", "replace") if isinstance(done.stderr, bytes) else ""
        return Result(done.returncode, out, err)


class LocalExecutor(Executor):
    def __init__(self, node: Node, *, repo_root: Path, config_dir: Path):
        super().__init__(node)
        self.repo_root = repo_root
        self.config_dir = config_dir

    def argv(self, command: list[str]) -> tuple[list[str], dict[str, str]]:
        env = dict(os.environ)
        env["SSH_ORIGINAL_COMMAND"] = " ".join(command)
        env.pop("SSH_CLIENT", None)
        bash = shutil.which("bash") or "bash"
        return (
            [
                bash,
                str(self.repo_root / "tools" / "papaia-ctl"),
                "node-shell",
                f"--controller-config={self.config_dir}",
                f"--node={self.node.name}",
            ],
            env,
        )


class SshExecutor(Executor):
    def __init__(self, node: Node, *, config_dir: Path):
        super().__init__(node)
        directory = ssh_dir(config_dir, node.name)
        self.key = directory / KEY_NAME
        self.known_hosts = directory / KNOWN_HOSTS

    def argv(self, command: list[str]) -> tuple[list[str], dict[str, str]]:
        if not self.key.is_file():
            raise ExecutorError(
                f"no SSH key for node '{self.node.name}' ({self.key}); run"
                f" 'papaia-ctl node add {self.node.name}' first"
            )
        if not self.known_hosts.is_file():
            raise ExecutorError(
                f"the host key of node '{self.node.name}' is not pinned yet; run"
                f" 'papaia-ctl node check {self.node.name}'"
            )
        return ssh_argv(self.node, self.key, self.known_hosts, command), dict(os.environ)


def ssh_argv(node: Node, key: Path, known_hosts: Path, command: list[str]) -> list[str]:
    return [
        "ssh",
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        f"ConnectTimeout={CONNECT_TIMEOUT}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "LogLevel=ERROR",
        "-p",
        str(node.ssh_port),
        f"{node.ssh_user}@{node.ssh_target}",
        "--",
        *command,
    ]


def for_node(topo: Topology, name: str, *, config_dir: Path, repo_root: Path) -> Executor:
    node = topo.nodes[name]
    if node.is_local:
        return LocalExecutor(node, repo_root=repo_root, config_dir=config_dir)
    return SshExecutor(node, config_dir=config_dir)


def stream_result(result: Result) -> None:
    """Print a captured result the way it would have streamed."""
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
