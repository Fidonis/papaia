"""Enrolling nodes and handing them what they run.

A node is set up once, in one of two ways that end in the same state:

* **admin session**: the controller copies the join archive to the node with the operator's
  own admin login and runs its install script there with `sudo`. The admin credentials are
  the operator's own login and password prompt; nothing of them is stored.
* **join archive**: `papaia-ctl node join-bundle` writes the same archive to a file, and the
  operator installs it on the node by hand (`sudo ./install.sh`).

The archive holds the checkout of the running release, the install script, the node's
`authorized_keys` line and the fingerprint of the controller's key for the node. The
install script creates the unprivileged user `papaia` (in the Docker group), the node's
directory with its first checkout, and the `authorized_keys` entry that forces
`papaia-ctl node-shell`. It is idempotent.

Afterwards the controller pins the node's SSH host key (the fingerprint is shown and
confirmed, or given with `--host-key-fingerprint`) and talks to the node only through its
executor: `checkout-put` with `git archive` of the release, `bundle-put` with the node's
bundle, and the compose verbs. The node needs no Git and no access to GitHub.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
from dataclasses import replace
from pathlib import Path

from . import common, deployment, envtree, topology
from .executor import KEY_NAME, KNOWN_HOSTS, Executor, Result, for_node, ssh_dir
from .topology import NODES_DIR, Node, Topology

_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")

# What a checkout archive leaves out when it is built without git: everything setup writes
# into the checkout and nothing a node needs.
_CHECKOUT_EXCLUDE = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "node_modules"}
_CHECKOUT_EXCLUDE_FILES = {".env", "papaia-realm.json"}


class NodeError(Exception):
    """An operator-facing failure. The CLI turns it into exit 3 (or 2 for a refusal)."""


# ─────────────────────────────────────────────────────────────────────────
# topology edits
# ─────────────────────────────────────────────────────────────────────────


def load(config_dir: Path) -> tuple[dict, Topology]:
    manifest = deployment.load(config_dir)
    try:
        topo = topology.load(manifest)
    except topology.TopologyError as exc:
        raise NodeError(f"deployment.yaml: {exc}") from exc
    return manifest, topo


def require_distributed(config_dir: Path) -> tuple[dict, Topology]:
    manifest, topo = load(config_dir)
    if not topo.distributed:
        raise NodeError(
            "this installation runs on one host. Nodes belong to a distributed installation,"
            " which 'papaia-ctl setup --topology=distributed' creates for a new installation."
        )
    return manifest, topo


def save(config_dir: Path, manifest: dict, topo: Topology) -> None:
    manifest["topology"] = topo.to_dict()
    deployment.save(config_dir, manifest)


def register(config_dir: Path, node: Node) -> Topology:
    """Add a node to the topology, or update its address and access."""
    manifest, topo = require_distributed(config_dir)
    nodes = dict(topo.nodes)
    if node.name in nodes and nodes[node.name].is_local:
        raise NodeError(f"'{node.name}' is the controller; it cannot be enrolled")
    nodes[node.name] = node
    updated = replace(topo, nodes=nodes)
    save(config_dir, manifest, updated)
    return updated


def unregister(config_dir: Path, repo_root: Path, name: str) -> Topology:
    manifest, topo = require_distributed(config_dir)
    if name not in topo.nodes:
        raise NodeError(f"no node named '{name}'")
    if name == topo.controller:
        raise NodeError(f"'{name}' is the controller and cannot be removed")
    profiles = topology.validation_env(config_dir, repo_root).get("COMPOSE_PROFILES", "")
    active = topology.active_services([p for p in profiles.split(",") if p])
    placed = [s for s, n in topo.placement.items() if n == name and s in active]
    if placed:
        raise NodeError(
            f"node '{name}' still runs {', '.join(placed)}; place them on another node first"
        )
    nodes = {k: v for k, v in topo.nodes.items() if k != name}
    placement = {s: n for s, n in topo.placement.items() if n != name}
    updated = replace(topo, nodes=nodes, placement=placement)
    save(config_dir, manifest, updated)
    node_dir = config_dir / NODES_DIR / name
    if node_dir.is_dir():
        shutil.rmtree(node_dir)
    return updated


# ─────────────────────────────────────────────────────────────────────────
# keys
# ─────────────────────────────────────────────────────────────────────────


def _run(argv: list[str], *, input_text: str | None = None, timeout: float = 30) -> str:
    try:
        done = subprocess.run(
            argv, input=input_text, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise NodeError(f"{argv[0]} not found; it is needed to enrol nodes") from exc
    except subprocess.TimeoutExpired as exc:
        raise NodeError(f"{argv[0]} did not finish within {timeout}s") from exc
    if done.returncode != 0:
        lines = (done.stderr or done.stdout).strip().splitlines()
        raise NodeError(f"{argv[0]} failed: {lines[-1] if lines else done.returncode}")
    return done.stdout


def ensure_keypair(config_dir: Path, name: str) -> tuple[Path, str]:
    """The controller's key for this node: private half in the config tree (0600, never in a
    bundle), public half returned."""
    directory = ssh_dir(config_dir, name)
    key = directory / KEY_NAME
    if not key.is_file():
        common.ensure_dir(directory)
        os.chmod(directory, 0o700)
        _run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"papaia-controller@{name}",
                "-f",
                str(key),
            ]
        )
    os.chmod(key, 0o600)
    public = key.with_name(KEY_NAME + ".pub").read_text(encoding="utf-8").strip()
    return key, public


def key_fingerprint(public_key: str) -> str:
    out = _run(["ssh-keygen", "-l", "-E", "sha256", "-f", "-"], input_text=public_key + "\n")
    return out.split()[1] if out.split() else ""


def authorized_keys_line(topo: Topology, node: Node, public_key: str) -> str:
    """The node's entry for the controller: one forced command, from the controller only,
    no terminal, no forwarding."""
    controller = topo.nodes[topo.controller]
    command = f"bash {node.root}/checkout/tools/papaia-ctl node-shell --node-root={node.root}"
    return f'restrict,from="{controller.address}",command="{command}" {public_key}'


def scan_host_keys(node: Node) -> list[str]:
    out = _run(
        [
            "ssh-keyscan",
            "-T",
            "10",
            "-p",
            str(node.ssh_port),
            "-t",
            "ed25519,ecdsa,rsa",
            node.ssh_target,
        ],
        timeout=30,
    )
    lines = [line for line in out.splitlines() if line and not line.startswith("#")]
    if not lines:
        raise NodeError(f"no SSH host key received from {node.ssh_target}:{node.ssh_port}")
    return lines


def host_key_fingerprints(lines: list[str]) -> list[tuple[str, str, str]]:
    """(key type, SHA256 fingerprint, key) for every scanned host key."""
    found: list[tuple[str, str, str]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        out = _run(
            ["ssh-keygen", "-l", "-E", "sha256", "-f", "-"], input_text=f"{parts[1]} {parts[2]}\n"
        )
        fields = out.split()
        if len(fields) >= 2:
            found.append((parts[1], fields[1], parts[2]))
    return found


def pin_host_key(config_dir: Path, node: Node, fingerprint: str) -> str:
    """Scan again and keep exactly the host key with the confirmed fingerprint. A key that
    changed between showing and confirming is not pinned."""
    if not _FINGERPRINT_RE.match(fingerprint):
        raise NodeError(f"not a SHA256 host key fingerprint: {fingerprint!r}")
    for kind, found, key in host_key_fingerprints(scan_host_keys(node)):
        if found == fingerprint:
            directory = ssh_dir(config_dir, node.name)
            common.ensure_dir(directory)
            host = (
                node.ssh_target if node.ssh_port == 22 else f"[{node.ssh_target}]:{node.ssh_port}"
            )
            common.atomic_write_private(directory / KNOWN_HOSTS, f"{host} {kind} {key}\n")
            return kind
    raise NodeError(
        f"{node.ssh_target} does not offer a host key with fingerprint {fingerprint};"
        " nothing was pinned"
    )


def host_key_pinned(config_dir: Path, name: str) -> bool:
    return (ssh_dir(config_dir, name) / KNOWN_HOSTS).is_file()


# ─────────────────────────────────────────────────────────────────────────
# archives
# ─────────────────────────────────────────────────────────────────────────


def checkout_archive(repo_root: Path, ref: str = "HEAD") -> bytes:
    """The checkout as a tar archive: `git archive` of `ref` when this is a git checkout,
    else the files on disk minus everything setup writes into it."""
    if (repo_root / ".git").exists():
        try:
            done = subprocess.run(
                ["git", "-C", str(repo_root), "archive", "--format=tar", ref],
                capture_output=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            done = None
        if done is not None and done.returncode == 0:
            return done.stdout
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in sorted(repo_root.rglob("*")):
            rel = path.relative_to(repo_root)
            if any(part in _CHECKOUT_EXCLUDE for part in rel.parts):
                continue
            if path.is_symlink() or not path.is_file() or path.name in _CHECKOUT_EXCLUDE_FILES:
                continue
            tar.add(path, arcname=rel.as_posix(), recursive=False)
    return buffer.getvalue()


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def bundle_archive(config_dir: Path, name: str) -> bytes:
    """A node's bundle as a gzipped tar, with the modes the render gave each file."""
    source = topology.bundle_dir(config_dir, name)
    if not (source / topology.NODE_MANIFEST).is_file():
        raise NodeError(f"node '{name}' has no bundle yet; run 'papaia-ctl setup' or 'start'")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(source.rglob("*")):
            if path.is_file() and not path.is_symlink():
                tar.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
    return buffer.getvalue()


# The install script of a join archive. Its @NODE@, @USER@, @ROOT@ and @VERSION@ are filled
# in per node.
INSTALL_SCRIPT = Path(__file__).with_name("node-install.sh")


_README = """papAIa node join archive for node '{node}'

On the node, as root:

    tar -xzf {archive}
    cd papaia-join-{node}
    sudo ./install.sh

Prerequisites on the node: Docker with the compose plugin, python3 (3.10 or newer) with
PyYAML, an SSH server. The script creates the user '{user}', the directory {root} and the
authorized_keys entry for the controller. Then, on the controller:

    papaia-ctl node check {node}

which shows the node's host key fingerprint for you to confirm against the one the script
printed.
"""


def join_archive(config_dir: Path, repo_root: Path, name: str) -> bytes:
    """The archive that sets a node up: checkout, install script, authorized_keys line."""
    _manifest, topo = require_distributed(config_dir)
    if name not in topo.nodes:
        raise NodeError(f"no node named '{name}'")
    node = topo.nodes[name]
    if node.is_local:
        raise NodeError(f"'{name}' is the controller; it needs no join archive")
    _key, public = ensure_keypair(config_dir, name)
    version = envtree.resolve_platform_version(repo_root)
    script = (
        INSTALL_SCRIPT.read_text(encoding="utf-8")
        .replace("@NODE@", node.name)
        .replace("@USER@", node.ssh_user)
        .replace("@ROOT@", node.root.rstrip("/"))
        .replace("@VERSION@", version)
    )
    prefix = f"papaia-join-{node.name}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        _add_bytes(tar, f"{prefix}/install.sh", script.encode("utf-8"), 0o755)
        _add_bytes(tar, f"{prefix}/checkout.tar", checkout_archive(repo_root))
        _add_bytes(
            tar,
            f"{prefix}/authorized_keys",
            (authorized_keys_line(topo, node, public) + "\n").encode("utf-8"),
            0o600,
        )
        _add_bytes(
            tar,
            f"{prefix}/controller.fingerprint",
            (key_fingerprint(public) + "\n").encode("utf-8"),
        )
        _add_bytes(
            tar,
            f"{prefix}/README.txt",
            _README.format(
                node=node.name, archive=f"{prefix}.tar.gz", user=node.ssh_user, root=node.root
            ).encode("utf-8"),
        )
    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────────────────
# talking to nodes
# ─────────────────────────────────────────────────────────────────────────


def executor(config_dir: Path, repo_root: Path, name: str) -> Executor:
    _manifest, topo = require_distributed(config_dir)
    if name not in topo.nodes:
        raise NodeError(f"no node named '{name}'")
    return for_node(topo, name, config_dir=config_dir, repo_root=repo_root)


def push_checkout(config_dir: Path, repo_root: Path, name: str) -> Result:
    ex = executor(config_dir, repo_root, name)
    if ex.node.is_local:
        return Result(0)
    version = envtree.resolve_platform_version(repo_root)
    return ex.run(["checkout-put", version], stdin=checkout_archive(repo_root))


def push_bundle(config_dir: Path, repo_root: Path, name: str) -> Result:
    ex = executor(config_dir, repo_root, name)
    if ex.node.is_local:
        return Result(0)
    return ex.run(["bundle-put"], stdin=bundle_archive(config_dir, name))


def node_version(config_dir: Path, repo_root: Path, name: str) -> dict:
    """What the node reports about itself, plus how far its clock is off ours."""
    ex = executor(config_dir, repo_root, name)
    asked = time.time()
    result = ex.run(["version"], capture=True, timeout=60)
    answered = time.time()
    if not result.ok:
        reason = (result.stderr or result.stdout).strip().splitlines()
        return {
            "node": name,
            "reachable": False,
            "reason": reason[-1] if reason else f"exit {result.returncode}",
        }
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"node": name, "reachable": False, "reason": "unreadable answer"}
    data["reachable"] = True
    # The node's clock against the middle of the round trip.
    if isinstance(data.get("time"), (int, float)):
        data["clock_offset"] = round(data["time"] - (asked + answered) / 2, 3)
    return data


def record_state(config_dir: Path, name: str, **fields) -> None:
    """What the controller last did to a node (installed release, bundle push)."""
    path = config_dir / NODES_DIR / name / "state.json"
    state = {}
    if path.is_file():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            state = {}
    state.update(fields)
    common.atomic_write(path, json.dumps(state, indent=2, sort_keys=True) + "\n")


def read_state(config_dir: Path, name: str) -> dict:
    path = config_dir / NODES_DIR / name / "state.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
