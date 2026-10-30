"""Multi-node topology: which service runs on which node, and what each node is given.

An installation is either `single` (one host, one Docker daemon, one Compose project --
everything that existed before this module) or `distributed`. A distributed installation
is described by the `topology` block of `deployment.yaml`:

    topology:
      mode: distributed
      controller: internal          # holds the config tree, the CA keys and papaia-manager
      link:
        port: 7443                  # the one port each node's link gateway listens on
      nodes:
        internal:
          address: 10.0.2.10
          executor: local           # the controller itself
        edge:
          address: 10.0.1.10
          executor: ssh
          ssh: {user: papaia, port: 22}
          root: /srv/papaia-node    # the node's directory; its config dir is <root>/config
      placement:                    # service -> node; unlisted services stay on the controller
        nginx: edge
        keycloak: edge
        smtp: edge
        litellm: edge

A missing block means `single`. `setup` and `upgrade` never add the block to an existing
`deployment.yaml`; it is written once, by a distributed `setup` of a new installation.

**The unit of placement is a service of the catalogue** (`CATALOGUE`), not a container: a
service is one or two Compose profiles plus everything they always bring along (databases,
sidecars). Dependencies inside a profile are hard, while every `depends_on` that crosses a
profile is optional (`tests/test_compose_profiles.py` enforces it), so a profile can live
on one node and its optional peers on another.

**Two profile levels.** On a node, `COMPOSE_PROFILES` decides what starts there.
`PAPAIA_ACTIVE_MODULES` carries the profiles of the whole installation, for what is
decided cluster-wide: which realm clients exist, which proxy hosts the Nginx Proxy
Manager gets, whether the mail relay is part of the installation. A single-node `.env`
never has the second key, and `common.cluster_profiles` falls back to the first.

**Projection.** In distributed mode every render also writes one bundle per node to
`$PAPAIA_CONFIG_DIR/nodes/<name>/bundle/`: the root `.env` with the node's profiles, the
`.env` files and rendered configuration of the services placed there, the certificates
they need and the core overrides. Secrets of services placed elsewhere are left out --
also the ones in the root `.env`, which are blanked unless a Compose file of the node's
own services references them. The local CA key and the SSH keys never enter a bundle.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import backup, common, compat, envtree, render_core
from . import deployment as deployment_module

SINGLE = "single"
DISTRIBUTED = "distributed"
MODES = (SINGLE, DISTRIBUTED)

EXECUTOR_LOCAL = "local"
EXECUTOR_SSH = "ssh"
EXECUTORS = (EXECUTOR_LOCAL, EXECUTOR_SSH)

DEFAULT_LINK_PORT = 7443
DEFAULT_SSH_USER = "papaia"
DEFAULT_SSH_PORT = 22
DEFAULT_NODE_ROOT = "/srv/papaia-node"

# Hardware hints a node may carry for the LocalAI check: what accelerator it has.
GPU_HINTS = ("none", "nvidia", "amd", "intel", "vulkan")

NODES_DIR = "nodes"
BUNDLE_DIR = "bundle"
NODE_MANIFEST = "node.json"

# The key of a node's root .env naming the profiles of the whole installation.
ACTIVE_MODULES_KEY = common.ACTIVE_MODULES_KEY

_NODE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
_ADDRESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class TopologyError(Exception):
    """A `topology` block that cannot be read at all (wrong types, unknown mode)."""


# ─────────────────────────────────────────────────────────────────────────
# Service catalogue
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ServiceSpec:
    """One unit of placement.

    `profiles` are the Compose profiles the service consists of; the containers that
    always go with it are whatever those profiles enable. `env_dirs` are the directories
    (relative to `src/`) whose `.env` belongs to the service alone. `start_group` orders
    `start` (ascending) and `stop` (descending). `public_url` names where the service's
    browser-facing URL is stored, as (env dir, key)."""

    name: str
    label: str
    profiles: tuple[str, ...]
    env_dirs: tuple[str, ...]
    start_group: int
    public_url: tuple[str, str] | None = None
    # Certificates of $PAPAIA_CONFIG_DIR/certs the service needs beyond the CA certificate.
    certs: tuple[str, ...] = ()


CATALOGUE: dict[str, ServiceSpec] = {
    spec.name: spec
    for spec in (
        ServiceSpec(
            "nginx",
            "Nginx Proxy Manager",
            ("nginx", "oauth2-proxy"),
            ("infra/nginx", "infra/oauth2-proxy"),
            start_group=3,
        ),
        ServiceSpec(
            "keycloak",
            "Keycloak",
            ("keycloak",),
            ("infra/keycloak",),
            start_group=0,
            public_url=("", "AUTH_HOST"),
            certs=("keycloak.crt", "keycloak.key"),
        ),
        ServiceSpec(
            "litellm",
            "LiteLLM",
            ("litellm",),
            ("ai/litellm",),
            start_group=1,
            public_url=("", "LITELLM_PUBLIC_URL"),
        ),
        ServiceSpec(
            "librechat",
            "LibreChat",
            ("librechat",),
            ("ai/librechat",),
            start_group=2,
            public_url=("ai/librechat", "DOMAIN_SERVER"),
        ),
        ServiceSpec(
            "websearch",
            "LibreChat web search",
            ("librechat-websearch",),
            ("services/searxng", "services/firecrawl", "ai/jinaai"),
            start_group=2,
        ),
        ServiceSpec(
            "localai",
            "LocalAI",
            ("localai",),
            ("ai/localai",),
            start_group=2,
            public_url=("", "LOCALAI_PUBLIC_URL"),
        ),
        ServiceSpec(
            "rag",
            "RAG system",
            ("rag",),
            ("ai/rag",),
            start_group=2,
            public_url=("", "QDRANT_PUBLIC_URL"),
        ),
        ServiceSpec(
            "smtp",
            "SMTP relay",
            ("smtp",),
            ("infra/smtp-relay",),
            start_group=0,
        ),
        ServiceSpec(
            "manager",
            "papaia-manager",
            ("manager",),
            ("manager",),
            start_group=2,
            public_url=("", "MANAGER_PUBLIC_URL"),
        ),
    )
}

# Services that must run where the configuration tree is: the manager mounts the whole
# config dir and the Docker socket of the host that runs `papaia-ctl`, and the RAG
# ingester keeps its catalogue and the operator's documents inside the config dir.
CONTROLLER_ONLY = ("manager", "rag")

# The bundled reverse proxy. Its profile, not the `nginx` service, says whether it runs.
PROXY_PROFILE = "nginx"

# Placed together: web search is a LibreChat feature and talks to nothing else.
COLOCATED = (("websearch", "librechat"),)

# The core overrides `setup` writes into $PAPAIA_CONFIG_DIR/overrides. Everything else in
# that directory belongs to an add-on.
CORE_OVERRIDES = (
    "docker-compose.ssl-cert.override.yml",
    "docker-compose.localai-gpu.override.yml",
)

# Root keys that point at the controller's own directories. On another node they are
# replaced by the node's directory (see `_node_paths`).
_PATH_KEYS = ("PAPAIA_CONFIG_DIR", "PAPAIA_WORKSPACE_DIR", "PAPAIA_BACKUP_DIR")

_SECRET_NAME_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|_KEY)$")


def service_of_profile(profile: str) -> str | None:
    for spec in CATALOGUE.values():
        if profile in spec.profiles:
            return spec.name
    return None


def active_services(profiles: list[str] | set[str]) -> list[str]:
    """Catalogue services with at least one active profile, in catalogue order."""
    wanted = set(profiles)
    return [name for name, spec in CATALOGUE.items() if wanted.intersection(spec.profiles)]


# ─────────────────────────────────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Node:
    name: str
    address: str = ""
    executor: str = EXECUTOR_SSH
    ssh_user: str = DEFAULT_SSH_USER
    ssh_port: int = DEFAULT_SSH_PORT
    ssh_host: str = ""
    root: str = DEFAULT_NODE_ROOT
    # The address the node's published ports bind to (HOST_IP there). Empty: derived.
    bind_ip: str = ""
    gpu: str = ""

    @property
    def is_local(self) -> bool:
        return self.executor == EXECUTOR_LOCAL

    @property
    def ssh_target(self) -> str:
        return self.ssh_host or self.address

    @property
    def config_dir(self) -> str:
        """Where the node keeps its configuration (the installed bundle)."""
        return f"{self.root.rstrip('/')}/config"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"address": self.address, "executor": self.executor}
        if self.executor == EXECUTOR_SSH:
            ssh: dict[str, Any] = {"user": self.ssh_user, "port": self.ssh_port}
            if self.ssh_host:
                ssh["host"] = self.ssh_host
            data["ssh"] = ssh
            data["root"] = self.root
        if self.bind_ip:
            data["bind_ip"] = self.bind_ip
        if self.gpu:
            data["gpu"] = self.gpu
        return data


@dataclass(frozen=True)
class Topology:
    mode: str = SINGLE
    controller: str = ""
    nodes: dict[str, Node] = field(default_factory=dict)
    placement: dict[str, str] = field(default_factory=dict)
    link_port: int = DEFAULT_LINK_PORT

    @property
    def distributed(self) -> bool:
        return self.mode == DISTRIBUTED

    def node_of(self, service: str) -> str:
        """The node a service runs on: its placement, else the controller."""
        return self.placement.get(service) or self.controller

    def services_on(self, node: str, active: list[str]) -> list[str]:
        return [service for service in active if self.node_of(service) == node]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "controller": self.controller,
            "link": {"port": self.link_port},
            "nodes": {name: node.to_dict() for name, node in self.nodes.items()},
            "placement": dict(self.placement),
        }


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TopologyError(f"{what} must be a number, got {value!r}")
    try:
        return int(value)
    except ValueError as exc:
        raise TopologyError(f"{what} must be a number, got {value!r}") from exc


def _str(value: Any, what: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise TopologyError(f"{what} must be a string, got {value!r}")
    return str(value).strip()


def _parse_node(name: str, raw: Any) -> Node:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise TopologyError(f"topology.nodes.{name} must be a mapping")
    ssh = raw.get("ssh") or {}
    if not isinstance(ssh, dict):
        raise TopologyError(f"topology.nodes.{name}.ssh must be a mapping")
    return Node(
        name=name,
        address=_str(raw.get("address"), f"topology.nodes.{name}.address"),
        executor=_str(raw.get("executor"), f"topology.nodes.{name}.executor") or EXECUTOR_SSH,
        ssh_user=_str(ssh.get("user"), f"topology.nodes.{name}.ssh.user") or DEFAULT_SSH_USER,
        ssh_port=_int(ssh.get("port", DEFAULT_SSH_PORT), f"topology.nodes.{name}.ssh.port"),
        ssh_host=_str(ssh.get("host"), f"topology.nodes.{name}.ssh.host"),
        root=_str(raw.get("root"), f"topology.nodes.{name}.root") or DEFAULT_NODE_ROOT,
        bind_ip=_str(raw.get("bind_ip"), f"topology.nodes.{name}.bind_ip"),
        gpu=_str(raw.get("gpu"), f"topology.nodes.{name}.gpu").lower(),
    )


def parse(raw: Any) -> Topology:
    """Read a `topology` block. None (no block) is a single-node installation."""
    if raw is None:
        return Topology()
    if not isinstance(raw, dict):
        raise TopologyError("topology must be a mapping")
    mode = _str(raw.get("mode"), "topology.mode") or SINGLE
    if mode not in MODES:
        raise TopologyError(f"topology.mode must be one of {', '.join(MODES)}, got {mode!r}")
    nodes_raw = raw.get("nodes") or {}
    if not isinstance(nodes_raw, dict):
        raise TopologyError("topology.nodes must be a mapping of node name to node")
    nodes = {str(name): _parse_node(str(name), body) for name, body in nodes_raw.items()}
    placement_raw = raw.get("placement") or {}
    if not isinstance(placement_raw, dict):
        raise TopologyError("topology.placement must be a mapping of service to node")
    placement = {
        str(service): _str(node, f"topology.placement.{service}")
        for service, node in placement_raw.items()
    }
    link = raw.get("link") or {}
    if not isinstance(link, dict):
        raise TopologyError("topology.link must be a mapping")
    return Topology(
        mode=mode,
        controller=_str(raw.get("controller"), "topology.controller"),
        nodes=nodes,
        placement=placement,
        link_port=_int(link.get("port", DEFAULT_LINK_PORT), "topology.link.port"),
    )


def load(deployment: dict | None) -> Topology:
    return parse((deployment or {}).get("topology"))


def load_config(config_dir: Path) -> Topology:
    from . import deployment as deployment_module

    return load(deployment_module.load(config_dir))


def is_distributed(config_dir: Path) -> bool:
    try:
        return load_config(config_dir).distributed
    except TopologyError:
        # A broken block is reported by `validate`; here it must not pass for single.
        return True


# ─────────────────────────────────────────────────────────────────────────
# Building a topology from setup's flags
# ─────────────────────────────────────────────────────────────────────────

_NODE_OPTIONS = ("ssh", "root", "gpu", "bind_ip")


def parse_node_spec(spec: str) -> tuple[str, dict[str, str]]:
    """`NAME=ADDR[,ssh=USER@HOST[:PORT]][,root=DIR][,gpu=HINT][,bind_ip=IP]`."""
    name, sep, rest = spec.partition("=")
    if not sep or not name or not rest:
        raise TopologyError(f"--node needs NAME=ADDRESS[,ssh=USER@HOST[:PORT]], got {spec!r}")
    address, *options = rest.split(",")
    values: dict[str, str] = {"address": address.strip()}
    for option in options:
        key, sep, value = option.partition("=")
        key = key.strip().replace("-", "_")
        if not sep or key not in _NODE_OPTIONS:
            raise TopologyError(
                f"unknown node option {option!r} in {spec!r} (one of {', '.join(_NODE_OPTIONS)})"
            )
        values[key] = value.strip()
    return name.strip(), values


def _node_from_spec(name: str, values: dict[str, str], *, local: bool) -> Node:
    if local:
        return Node(
            name,
            address=values["address"],
            executor=EXECUTOR_LOCAL,
            bind_ip=values.get("bind_ip", ""),
            gpu=values.get("gpu", ""),
        )
    user, host, port = DEFAULT_SSH_USER, "", DEFAULT_SSH_PORT
    ssh = values.get("ssh", "")
    if ssh:
        user_part, at, host_part = ssh.rpartition("@")
        if at:
            user = user_part or DEFAULT_SSH_USER
        else:
            host_part = ssh
        host_part, colon, port_part = host_part.partition(":")
        host = host_part
        if colon:
            if not port_part.isdigit():
                raise TopologyError(f"node '{name}': ssh port {port_part!r} is not a number")
            port = int(port_part)
    return Node(
        name,
        address=values["address"],
        executor=EXECUTOR_SSH,
        ssh_user=user,
        ssh_port=port,
        ssh_host="" if host == values["address"] else host,
        root=values.get("root") or DEFAULT_NODE_ROOT,
        bind_ip=values.get("bind_ip", ""),
        gpu=values.get("gpu", ""),
    )


def from_flags(
    *,
    node_specs: list[str],
    places: list[str],
    preset: str | None,
    controller: str | None,
    link_port: int | None,
) -> Topology:
    """The topology a distributed `setup` asks for. A node without `ssh=` is local, which
    only the controller may be; `--controller` names it when that is ambiguous."""
    parsed = [parse_node_spec(spec) for spec in node_specs]
    names = [name for name, _ in parsed]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise TopologyError(f"node named twice: {', '.join(duplicates)}")
    if not controller:
        local = [name for name, values in parsed if "ssh" not in values]
        if len(local) != 1:
            raise TopologyError(
                "name the controller with --controller=NAME (the node papaia-ctl runs on;"
                " it is the one --node without ssh=)"
            )
        controller = local[0]
    nodes = {
        name: _node_from_spec(name, values, local=name == controller) for name, values in parsed
    }
    placement: dict[str, str] = {}
    if preset:
        others = [n for n in nodes if n != controller]
        if len(others) != 1:
            raise TopologyError(
                f"preset {preset!r} places services on one edge node; this topology has"
                f" {len(others)} nodes besides the controller (use --place instead)"
            )
        placement.update(preset_placement(preset, others[0]))
    for place in places:
        service, sep, node = place.partition("=")
        if not sep or not service or not node:
            raise TopologyError(f"--place needs SERVICE=NODE, got {place!r}")
        placement[service.strip()] = node.strip()
    # A service placed on the controller is the default; keep the block short.
    placement = {s: n for s, n in placement.items() if n != controller}
    return Topology(
        mode=DISTRIBUTED,
        controller=controller,
        nodes=nodes,
        placement=placement,
        link_port=link_port or DEFAULT_LINK_PORT,
    )


def from_file(path: Path) -> Topology:
    """A topology file: a YAML document holding the `topology` block (or the block alone)."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TopologyError(f"cannot read {path}: {exc}") from exc
    if isinstance(document, dict) and "topology" in document:
        document = document["topology"]
    topo = parse(document)
    if not topo.distributed:
        raise TopologyError(f"{path}: topology.mode is not 'distributed'")
    return topo


# ─────────────────────────────────────────────────────────────────────────
# Presets
# ─────────────────────────────────────────────────────────────────────────

# Services each preset puts on the edge node. Everything else stays on the controller.
PRESETS: dict[str, tuple[str, ...]] = {
    # Ingress, identity, mail and the LLM gateway at the edge; data behind it.
    "dmz-split": ("nginx", "keycloak", "smtp", "litellm"),
    # Ingress and the LLM gateway at the edge; identity stays internal.
    "dmz-edge": ("nginx", "litellm"),
}


def preset_placement(preset: str, edge: str) -> dict[str, str]:
    if preset not in PRESETS:
        raise TopologyError(f"unknown preset {preset!r} (one of {', '.join(PRESETS)})")
    return {service: edge for service in PRESETS[preset]}


# ─────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Findings:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# LocalAI image variant -> the hardware hints it runs on.
_VARIANT_HARDWARE = {
    "nvidia-cuda-12": ("nvidia",),
    "nvidia-cuda-13": ("nvidia",),
    "hipblas": ("amd",),
    "intel": ("intel",),
    "vulkan": ("nvidia", "amd", "intel", "vulkan"),
}


def _is_subdomain_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return False
    if not parts.scheme or not host or port is not None:
        return False
    if host in ("localhost", "host.docker.internal") or re.fullmatch(r"[0-9.]+", host):
        return False
    return "." in host


def _published_ports(repo_root: Path, profiles: set[str], env: dict[str, str]) -> dict[int, str]:
    """Host port -> compose service, for the services the profiles enable."""
    root = repo_root / "src" / "docker-compose.yml"
    found: dict[int, str] = {}
    if not root.is_file():
        return found
    for path in compat.compose_files(root):
        if not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            declared = set((body or {}).get("profiles") or [])
            if declared and not declared & profiles:
                continue
            for entry in (body or {}).get("ports") or []:
                if not isinstance(entry, str):
                    continue
                parts = backup.expand(entry, env).rsplit(":", 2)
                host_port = parts[-2] if len(parts) >= 2 else ""
                if host_port.isdigit():
                    found.setdefault(int(host_port), name)
    return found


def validate(
    topo: Topology,
    *,
    active_profiles: list[str],
    env: dict[str, str] | None = None,
    repo_root: Path | None = None,
) -> Findings:
    """Everything that makes a topology unusable (errors) or suspicious (warnings).

    Runs before anything changes. `env` is the root `.env` merged with the service
    `.env` files that hold public URLs; without it the URL and port checks are skipped."""
    found = Findings()
    if not topo.distributed:
        if topo.placement:
            found.warnings.append("topology.placement is ignored while topology.mode is 'single'")
        return found

    env = env or {}
    active = active_services(active_profiles)

    # --- nodes -----------------------------------------------------------
    if len(topo.nodes) < 2:
        found.errors.append("a distributed installation needs at least two nodes")
    for node in topo.nodes.values():
        where = f"node '{node.name}'"
        if not _NODE_NAME_RE.match(node.name):
            found.errors.append(
                f"{where}: names are lowercase letters, digits and '-', starting with a letter"
            )
        if node.executor not in EXECUTORS:
            found.errors.append(
                f"{where}: executor must be one of {', '.join(EXECUTORS)}, got {node.executor!r}"
            )
        if not node.address:
            found.errors.append(f"{where}: an address is required")
        elif not _ADDRESS_RE.match(node.address):
            found.errors.append(f"{where}: {node.address!r} is not a host name or IP address")
        if node.bind_ip and not _ADDRESS_RE.match(node.bind_ip):
            found.errors.append(f"{where}: bind_ip {node.bind_ip!r} is not an IP address")
        if node.gpu and node.gpu not in GPU_HINTS:
            found.errors.append(
                f"{where}: gpu must be one of {', '.join(GPU_HINTS)}, got {node.gpu!r}"
            )
        if node.executor == EXECUTOR_SSH:
            if not _SSH_USER_RE.match(node.ssh_user):
                found.errors.append(f"{where}: {node.ssh_user!r} is not a valid user name")
            if not 1 <= node.ssh_port <= 65535:
                found.errors.append(f"{where}: ssh port {node.ssh_port} is out of range")
            if not node.root.startswith("/") or ".." in node.root.split("/"):
                found.errors.append(f"{where}: root must be an absolute path, got {node.root!r}")

    if not topo.controller:
        found.errors.append("topology.controller is not set")
    elif topo.controller not in topo.nodes:
        found.errors.append(f"controller '{topo.controller}' is not one of the nodes")
    else:
        controller = topo.nodes[topo.controller]
        if not controller.is_local:
            found.errors.append(
                f"the controller '{topo.controller}' must use the 'local' executor:"
                " it is the machine papaia-ctl runs on"
            )
    for node in topo.nodes.values():
        if node.is_local and node.name != topo.controller:
            found.errors.append(
                f"node '{node.name}' uses the 'local' executor but is not the controller;"
                " every other node is reached over SSH"
            )

    # --- placement -------------------------------------------------------
    for service, node in topo.placement.items():
        if service not in CATALOGUE:
            found.errors.append(
                f"placement names unknown service '{service}' (one of {', '.join(CATALOGUE)})"
            )
            continue
        if node not in topo.nodes:
            found.errors.append(f"placement puts '{service}' on unknown node '{node}'")
            continue
        if service not in active:
            found.warnings.append(
                f"placement of '{service}' has no effect: the service is not switched on"
            )
    for service in CONTROLLER_ONLY:
        if service in active and topo.node_of(service) != topo.controller:
            found.errors.append(
                f"'{service}' must run on the controller '{topo.controller}'"
                f" (it is placed on '{topo.node_of(service)}'): it works on the"
                " configuration directory, which only the controller has"
            )
    for service, partner in COLOCATED:
        if (
            service in active
            and partner in active
            and topo.node_of(service) != topo.node_of(partner)
        ):
            found.errors.append(
                f"'{service}' must run on the node of '{partner}'"
                f" ('{topo.node_of(partner)}'), not on '{topo.node_of(service)}'"
            )
    if (
        "smtp" in active
        and "keycloak" in active
        and topo.node_of("smtp") != topo.node_of("keycloak")
    ):
        found.warnings.append(
            "the SMTP relay is not on Keycloak's node: Keycloak reaches it through the link,"
            " but 'start' does not update the mail server of an existing realm there"
        )

    # --- LocalAI hardware ------------------------------------------------
    if "localai" in active and topo.node_of("localai") in topo.nodes:
        node = topo.nodes[topo.node_of("localai")]
        variant = env.get("LOCALAI_IMAGE_VARIANT", "") or "cpu"
        needs = _VARIANT_HARDWARE.get(variant)
        if needs:
            if not node.gpu:
                found.warnings.append(
                    f"LocalAI runs the '{variant}' image on '{node.name}', whose hardware is"
                    " not recorded (nodes.<name>.gpu); the preflight checks it"
                )
            elif node.gpu not in needs:
                found.errors.append(
                    f"LocalAI runs the '{variant}' image, but node '{node.name}' has"
                    f" gpu: {node.gpu}"
                )

    # --- link and ports --------------------------------------------------
    if not 1024 <= topo.link_port <= 65535:
        found.errors.append(f"link port {topo.link_port} must be between 1024 and 65535")
    elif repo_root is not None:
        for node in topo.nodes.values():
            profiles = {
                p
                for p in active_profiles
                if service_of_profile(p) in topo.services_on(node.name, active)
            }
            ports = _published_ports(repo_root, profiles, env)
            if topo.link_port in ports:
                found.errors.append(
                    f"link port {topo.link_port} collides with the port '{ports[topo.link_port]}'"
                    f" publishes on node '{node.name}'"
                )

    # --- public URLs -----------------------------------------------------
    # The `nginx` profile, not the service: `oauth2-proxy` also runs in front of an
    # external proxy.
    if PROXY_PROFILE in active_profiles:
        for service in active:
            spec = CATALOGUE[service]
            if spec.public_url is None:
                continue
            url = env.get(spec.public_url[1], "")
            if url and not _is_subdomain_url(url):
                found.errors.append(
                    f"the public URL of {spec.label} ({url}) must be a host name without a"
                    " port in distributed mode: Nginx Proxy Manager serves it on"
                    f" '{topo.node_of('nginx')}'"
                )
    elif active:
        found.warnings.append(
            "no bundled Nginx Proxy Manager: the external proxy has to reach every service"
            " on the node it runs on"
        )
    return found


# ─────────────────────────────────────────────────────────────────────────
# Compose introspection
# ─────────────────────────────────────────────────────────────────────────

_VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)|\$([A-Za-z_][A-Za-z0-9_]*)")
_CONFIG_REF_RE = re.compile(r"^\$\{PAPAIA_CONFIG_DIR\}/?(.*)$")


@dataclass
class ComposeService:
    name: str
    profiles: tuple[str, ...]
    body: dict
    text: str  # the YAML of the service, for variable references

    def config_mounts(self) -> list[str]:
        """Paths under ${PAPAIA_CONFIG_DIR} the service bind-mounts, relative to it."""
        found: list[str] = []
        for entry in self.body.get("volumes") or []:
            if isinstance(entry, dict):
                source = str(entry.get("source") or "")
            elif isinstance(entry, str):
                source = entry.split(":", 1)[0]
            else:
                continue
            match = _CONFIG_REF_RE.match(source)
            if match and match.group(1).strip("/") not in found:
                found.append(match.group(1).strip("/"))
        return found


def compose_services(repo_root: Path) -> list[ComposeService]:
    root = repo_root / "src" / "docker-compose.yml"
    if not root.is_file():
        return []
    found: list[ComposeService] = []
    for path in compat.compose_files(root):
        if not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            body = body or {}
            found.append(
                ComposeService(
                    name=name,
                    profiles=tuple(body.get("profiles") or ()),
                    body=body,
                    text=yaml.safe_dump(body, sort_keys=True),
                )
            )
    return found


def services_of(repo_root: Path, catalogue_services: list[str]) -> list[ComposeService]:
    """The Compose services the catalogue services consist of."""
    profiles = {p for name in catalogue_services for p in CATALOGUE[name].profiles}
    return [s for s in compose_services(repo_root) if profiles.intersection(s.profiles)]


def referenced_variables(services: list[ComposeService]) -> set[str]:
    names: set[str] = set()
    for service in services:
        for match in _VAR_REF_RE.finditer(service.text):
            names.add(match.group(1) or match.group(2))
    return names


# ─────────────────────────────────────────────────────────────────────────
# Add-ons
# ─────────────────────────────────────────────────────────────────────────


def addon_node(topo: Topology, entry: dict) -> str:
    """The node an add-on runs on: its `node` in deployment.yaml, else the controller."""
    return str(entry.get("node") or "") or topo.controller


def attached_services(repo_root: Path, manifest: dict) -> list[str]:
    """The catalogue services whose containers an add-on's Seam-1 override attaches to its
    network (`networks.attach`). Names the core does not have are left to the
    compatibility check, which reports them."""
    attach = ((manifest or {}).get("networks") or {}).get("attach") or []
    by_name = {s.name: s for s in compose_services(repo_root)}
    found: list[str] = []
    for name in attach if isinstance(attach, list) else []:
        service = by_name.get(str(name))
        if service is None:
            continue
        for profile in service.profiles:
            owner = service_of_profile(profile)
            if owner and owner not in found:
                found.append(owner)
    return found


def placement_problem(
    topo: Topology, repo_root: Path, manifest: dict, node: str, active: list[str]
) -> str | None:
    """Why an add-on cannot run on `node`, or None. An add-on's network exists on one
    Docker daemon only, so every core service it attaches to has to run on its node."""
    if node not in topo.nodes:
        return f"unknown node '{node}'"
    elsewhere = [
        f"{service} ({topo.node_of(service)})"
        for service in attached_services(repo_root, manifest)
        if service in active and topo.node_of(service) != node
    ]
    if elsewhere:
        return (
            f"not placeable on '{node}': it attaches to {', '.join(elsewhere)}, and its"
            " network exists on one node only"
        )
    return None


def default_addon_node(topo: Topology, repo_root: Path, manifest: dict, active: list[str]) -> str:
    """Where an add-on goes when `--node` is not given: the node of the services it attaches
    to when they share one, else the controller."""
    nodes = {topo.node_of(s) for s in attached_services(repo_root, manifest) if s in active}
    return nodes.pop() if len(nodes) == 1 else topo.controller


# ─────────────────────────────────────────────────────────────────────────
# Projection
# ─────────────────────────────────────────────────────────────────────────


def is_secret_key(key: str, seed_value: str | None) -> bool:
    """Whether a root `.env` key holds a secret: marked for generation in the shipped
    template, or named like one."""
    if seed_value is not None and common.marks_generated_secret(seed_value):
        return True
    return bool(_SECRET_NAME_RE.search(key))


def bundle_dir(config_dir: Path, node: str) -> Path:
    return config_dir / NODES_DIR / node / BUNDLE_DIR


def node_config_dir(topo: Topology, node: Node, config_dir: Path) -> str:
    """$PAPAIA_CONFIG_DIR as the node sees it. The controller keeps the full tree."""
    return str(config_dir) if node.name == topo.controller else node.config_dir


def node_bundle_root(topo: Topology, node: Node, config_dir: Path) -> str:
    """Where the node reads its bundle's own files (link certificates, overrides)."""
    if node.name == topo.controller:
        return str(bundle_dir(config_dir, node.name))
    return node.config_dir


def _node_paths(topo: Topology, node: Node, config_dir: Path, root: dict[str, str]) -> dict:
    if node.name == topo.controller:
        return {key: root.get(key, "") for key in _PATH_KEYS}
    base = node.root.rstrip("/")
    return {
        "PAPAIA_CONFIG_DIR": node.config_dir,
        "PAPAIA_WORKSPACE_DIR": base,
        "PAPAIA_BACKUP_DIR": f"{base}/backup",
    }


def _bind_ip(node: Node, cluster_profiles: list[str]) -> str:
    if node.bind_ip:
        return node.bind_ip
    # Behind the bundled proxy nothing needs a published port from outside the node:
    # the proxy and the link gateway reach the services over the Docker network, and the
    # provisioning steps use localhost. Without it the external proxy needs the address.
    return "127.0.0.1" if PROXY_PROFILE in cluster_profiles else node.address


# What an add-on's directory carries that a node does not need, or must not get.
_ADDON_EXCLUDE = shutil.ignore_patterns(".git", ".env", "__pycache__", "node_modules", ".venv")


def _copy_addon(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    if source.is_dir():
        shutil.copytree(source, dest, ignore=_ADDON_EXCLUDE)


def _copy_path(source: Path, dest: Path) -> None:
    if source.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source, dest)
    elif source.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)


@dataclass
class NodeBundle:
    node: str
    path: Path
    services: list[str]
    profiles: list[str]
    compose_services: list[str]
    state_dirs: list[str]
    manifest: dict


def _render_dirs() -> set[str]:
    return {target for target in render_core.BASE_RENDER_TARGETS} | {"infra/keycloak/realm-import"}


def project_node(
    config_dir: Path,
    repo_root: Path,
    topo: Topology,
    node: Node,
    *,
    tree: envtree.EnvTree,
    seed: envtree.EnvTree,
    cluster_profiles: list[str],
    extra_profiles: list[str] | None = None,
    writer: Callable[[Path], None] | None = None,
) -> NodeBundle:
    """Write one node's bundle. Replaces whatever bundle the node had."""
    active = active_services(cluster_profiles)
    services = topo.services_on(node.name, active)
    profiles = [p for p in cluster_profiles if service_of_profile(p) in services]
    profiles += [p for p in extra_profiles or [] if p not in profiles]
    own = services_of(repo_root, services)
    referenced = referenced_variables(own)

    target = bundle_dir(config_dir, node.name)
    staging = target.with_name(BUNDLE_DIR + ".new")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    # --- root .env -------------------------------------------------------
    root = dict(tree.get("", {}))
    seed_root = seed.get("", {})
    for key in list(root):
        if is_secret_key(key, seed_root.get(key)) and key not in referenced:
            # Blank rather than absent: Compose interpolates the fragments of disabled
            # services too and warns about every variable that is not set at all.
            root[key] = ""
    root["COMPOSE_PROFILES"] = ",".join(profiles)
    root[ACTIVE_MODULES_KEY] = ",".join(cluster_profiles)
    root["PAPAIA_NODE"] = node.name
    root["HOST_IP"] = _bind_ip(node, cluster_profiles)
    root.update(_node_paths(topo, node, config_dir, root))
    librechat_url = tree.get("ai/librechat", {}).get("DOMAIN_SERVER", "")
    if librechat_url:
        # npm_provision reads the LibreChat URL from LibreChat's own .env, which only
        # LibreChat's node has. The URL is not a secret; every node gets it here.
        root["LIBRECHAT_PUBLIC_URL"] = librechat_url
    template = repo_root / "src" / ".env.example"
    common.write_env_file(
        staging / ".env", root, template_path=template if template.is_file() else None
    )

    # --- service .env files ----------------------------------------------
    env_dirs = [d for name in services for d in CATALOGUE[name].env_dirs]
    for rel_dir in env_dirs:
        if rel_dir not in tree:
            continue
        template = repo_root / "src" / rel_dir / ".env.example"
        common.write_env_file(
            staging / rel_dir / ".env",
            tree[rel_dir],
            template_path=template if template.is_file() else None,
        )

    # --- rendered configuration and certificates -------------------------
    controller = node.name == topo.controller
    render_dirs = _render_dirs()
    state_dirs: list[str] = []
    for service in own:
        for rel in service.config_mounts():
            if rel in ("", "certs"):
                continue
            source = config_dir / rel
            if source.is_dir() and rel not in render_dirs:
                # State the service keeps on its own node (the proxy's database and
                # certificates, the ingester's catalogue). Created there, never shipped.
                if rel not in state_dirs:
                    state_dirs.append(rel)
                continue
            if not controller:
                _copy_path(source, staging / rel)
    certs = ["local-ca.crt"] + [c for name in services for c in CATALOGUE[name].certs]
    for cert in certs:
        source = config_dir / "certs" / cert
        if source.is_file():
            _copy_path(source, staging / "certs" / cert)

    # --- core overrides --------------------------------------------------
    for name in CORE_OVERRIDES:
        source = config_dir / "overrides" / name
        if source.is_file():
            _copy_path(source, staging / "overrides" / name)

    # --- add-ons placed on this node ------------------------------------
    node_addons: list[dict] = []
    for entry in deployment_module.active_addons(deployment_module.load(config_dir)):
        name = str(entry.get("name") or "")
        if not name or addon_node(topo, entry) != node.name:
            continue
        local_path = deployment_module.resolve_addon_path(entry, repo_root)
        if controller:
            node_path = str(local_path)
        else:
            node_path = f"{node.config_dir}/addons/{name}/src"
            _copy_addon(local_path, staging / "addons" / name / "src")
        bundle_env = config_dir / "addons" / name / ".env"
        if bundle_env.is_file():
            _copy_path(bundle_env, staging / "addons" / name / ".env")
        override = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
        if override.is_file():
            _copy_path(override, staging / "overrides" / override.name)
        addon_overrides = config_dir / "overrides" / "addons"
        if addon_overrides.is_dir():
            for path in sorted(addon_overrides.glob(f"docker-compose.{name}-*.override.yml")):
                _copy_path(path, staging / "overrides" / "addons" / path.name)
        node_addons.append({**entry, "path": node_path})

    # What the node's own `status` and `doctor` read: the profiles that run there. The
    # add-ons placed on the node are added with them (see `addon --node`).
    node_manifest = {
        "customer": root.get("COMPOSE_PROJECT_NAME", "papaia"),
        "platform_version": envtree.resolve_platform_version(repo_root),
        "node": node.name,
        "core": {"profiles": profiles},
        "addons": node_addons,
    }
    common.atomic_write(
        staging / "deployment.yaml",
        yaml.safe_dump(node_manifest, sort_keys=False, default_flow_style=False),
    )

    if writer is not None:
        writer(staging)

    manifest = {
        "node": node.name,
        "controller": topo.controller,
        "papaia_version": envtree.resolve_platform_version(repo_root),
        "services": services,
        "profiles": profiles,
        "compose_services": sorted(
            s.name for s in compose_services(repo_root) if set(profiles).intersection(s.profiles)
        ),
        "state_dirs": state_dirs,
        "config_dir": node_config_dir(topo, node, config_dir),
        "bundle_root": node_bundle_root(topo, node, config_dir),
    }
    common.atomic_write(
        staging / NODE_MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    if target.exists():
        shutil.rmtree(target)
    staging.rename(target)
    return NodeBundle(
        node=node.name,
        path=target,
        services=services,
        profiles=profiles,
        compose_services=manifest["compose_services"],
        state_dirs=state_dirs,
        manifest=manifest,
    )


def project(config_dir: Path, repo_root: Path, topo: Topology) -> list[NodeBundle]:
    """Write every node's bundle and remove the bundles of nodes that are gone.

    Each bundle also carries the node's link gateway: its configuration, its leaf
    certificate and the CA certificate (see lib/link.py)."""
    if not topo.distributed:
        return []
    # Local import: link builds on this module's model.
    from . import link

    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    seed = envtree.load_seed_tree(repo_root)
    cluster = [p for p in tree.get("", {}).get("COMPOSE_PROFILES", "").split(",") if p]
    env = validation_env(config_dir, repo_root)
    link_plan = link.plan(topo, cluster, env)

    def writer_for(node: Node) -> Callable[[Path], None]:
        bundle_root = node_bundle_root(topo, node, config_dir)
        return lambda staging: link.write_node_files(
            staging, config_dir, link_plan, node, bundle_root
        )

    bundles = [
        project_node(
            config_dir,
            repo_root,
            topo,
            node,
            tree=tree,
            seed=seed,
            cluster_profiles=cluster,
            extra_profiles=[link.GATEWAY_PROFILE],
            writer=writer_for(node),
        )
        for node in topo.nodes.values()
    ]
    nodes_root = config_dir / NODES_DIR
    if nodes_root.is_dir():
        for child in nodes_root.iterdir():
            stale = child / BUNDLE_DIR
            if child.name not in topo.nodes and stale.is_dir():
                shutil.rmtree(stale)
    return bundles


def validation_env(config_dir: Path, repo_root: Path) -> dict[str, str]:
    """The root `.env` plus the public URL keys that live in a service's `.env`."""
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    env = dict(tree.get("", {}))
    for spec in CATALOGUE.values():
        if spec.public_url and spec.public_url[0]:
            rel_dir, key = spec.public_url
            value = tree.get(rel_dir, {}).get(key)
            if value is not None:
                env.setdefault(key, value)
    return env


def validate_config(config_dir: Path, repo_root: Path, topo: Topology) -> Findings:
    env = validation_env(config_dir, repo_root)
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
    return validate(topo, active_profiles=profiles, env=env, repo_root=repo_root)


# ─────────────────────────────────────────────────────────────────────────
# Rendering
# ─────────────────────────────────────────────────────────────────────────


def format_table(topo: Topology, active_profiles: list[str]) -> str:
    if not topo.distributed:
        return "Topology: single (one host)"
    active = active_services(active_profiles)
    lines = [
        f"Topology: distributed, controller '{topo.controller}', link port {topo.link_port}",
        "",
    ]
    rows = [("NODE", "ADDRESS", "ACCESS", "SERVICES")]
    for node in topo.nodes.values():
        access = "local" if node.is_local else f"ssh {node.ssh_user}@{node.ssh_target}"
        if node.executor == EXECUTOR_SSH and node.ssh_port != DEFAULT_SSH_PORT:
            access += f":{node.ssh_port}"
        rows.append(
            (node.name, node.address, access, ", ".join(topo.services_on(node.name, active)) or "-")
        )
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(3)) + "  " + row[3])
    return "\n".join(lines)
