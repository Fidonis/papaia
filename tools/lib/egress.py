"""papaia-egress: the configuration of the single exit and its place in the networks.

Every way out of the stack is one chain (docs/egress.md):

    service -> egress network of its add-on -> papaia-egress -> [corporate proxy] -> outside

An add-on that needs the outside declares its egress network (an `internal: true`
network its own compose file creates, named `${PAPAIA_PROJECT}-<name>-...`) and what it
needs to reach:

    networks:
      egress:
        network: "${PAPAIA_PROJECT:-papaia}-<name>-egress"
        allow:
          - host: api.example.org
            ports: [443]

This module turns that into two things:

  * `$PAPAIA_CONFIG_DIR/infra/egress/egress.json`, the configuration the proxy reads
    (re-read within seconds after every render): one source per active add-on with its
    allow list, the protected hosts and the corporate proxy;
  * one override per such add-on that puts `papaia-egress` on the add-on's egress
    network under the alias `egress-<name>`. The alias is how the proxy tells the
    sources apart, so a service can only use the allow list of its own add-on.

The protected hosts (`$PAPAIA_CONFIG_DIR/security/protected-hosts.yaml`, maintained by
the operator) override every allow list. Internal addresses (private ranges and the
like) are refused by the proxy unless the operator opens a range for an add-on in
`$PAPAIA_CONFIG_DIR/security/egress-internal-targets.yaml`; a manifest cannot. A fresh
installation has no source and no target: nothing leaves the stack until an add-on
asks for it.

The egress network is where the proxy tells the sources apart, so it must belong to
exactly one add-on: scoped to its name, internal, never a core or Docker network, never
a network another add-on declares and never the add-on's own app network (core services
join that one). Anything else stops the render and removes the attachments.
"""

from __future__ import annotations

import ipaddress
import json
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import common, deployment

SERVICE = "papaia-egress"
PROFILE = "egress"
PORT = 3128
EGRESS_NETWORK = "papaia-egress-net"
CONFIG_FORMAT = "papaia.egress/1"
CONFIG_FILE = "infra/egress/egress.json"
UPSTREAM_PASSWORD_FILE = "infra/egress/upstream-proxy-password"
PROTECTED_HOSTS_FILE = "security/protected-hosts.yaml"
INTERNAL_TARGETS_FILE = "security/egress-internal-targets.yaml"
UPSTREAM_KEY = "PAPAIA_EGRESS_UPSTREAM_PROXY"
NO_PROXY_KEY = "PAPAIA_EGRESS_NO_PROXY"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,54}$")
_NETWORK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CATALOG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MAX_ENTRIES = 256
# Docker's own networks; an add-on never gets to put the proxy on one of them.
_DOCKER_NETWORKS = ("bridge", "host", "none")
# First labels of names inside the stack: the proxy's own aliases and the services.
_STACK_PREFIXES = ("egress-", "papaia-")

_PROTECTED_SEED = """\
# Protected hosts: source systems (for example the database of the ERP) that no
# service may reach through papaia-egress, whatever an add-on's allow list says.
# Host names are compared by name and by the addresses they resolve to; list each
# system by its addresses or ranges as well, so its protection never depends on DNS.
# Also list the Docker host's own LAN and public addresses: the proxy blocks only its
# own gateways by itself.
#
# - name: erp
#   hosts: [erp-sql.example.local, 10.20.0.15/32]
#   ports: [1433]
#   catalog_entry: mssql.erp
[]
"""


_INTERNAL_SEED = """\
# Internal targets: address ranges inside the company network that an add-on may reach
# through papaia-egress. papaia-egress refuses every address that is not global
# (private, shared, unique local, ...) unless a range here opens it for the add-on.
# The protected hosts still win, and the proxy itself, its gateways and the egress
# networks of the add-ons are never reachable. A range must not contain the Docker
# host's own addresses, or these must be listed as protected hosts.
#
# - name: company-llm
#   ranges: [10.20.30.0/24]
#   addons: [my-addon]
[]
"""


class EgressError(ValueError):
    """A configuration of the exit that cannot be used; nothing is rendered."""


def normalise_host(value: object, *, networks: bool = False) -> str:
    """A host name in lower case without its trailing dot, or an IP address (or, with
    `networks`, an address range) in normal form. Wildcards and URLs are refused."""
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"not a host: {value!r}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if networks and "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError(f"not an address range: {value!r}") from None
    host = value.lower().rstrip(".")
    if not _HOST_RE.match(host):
        raise ValueError(f"not a host: {value!r}")
    return host


def _check_fields(obj: object, required: set[str], optional: set[str]) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("expected a mapping")
    unknown = sorted(set(obj) - required - optional)
    missing = sorted(required - set(obj))
    if unknown:
        raise ValueError(f"unknown field(s) {', '.join(unknown)}")
    if missing:
        raise ValueError(f"missing field(s) {', '.join(missing)}")
    return obj


def _ports(value: object) -> list[int]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise ValueError("ports must be a list of 1 to 64 ports")
    for port in value:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"not a port: {port!r}")
    return sorted(set(value))


def _list(value: object, what: str) -> list:
    if not isinstance(value, list) or len(value) > _MAX_ENTRIES:
        raise ValueError(f"{what} must be a list of at most {_MAX_ENTRIES} entries")
    return value


def load_protected_entries(config_dir: Path) -> list[dict]:
    """The validated protected hosts with every field: `name`, `hosts` (normalised),
    `ports` (sorted, or None) and `catalog_entry` (or None). Seeds an empty list on
    first use."""
    path = config_dir / PROTECTED_HOSTS_FILE
    if not path.is_file():
        common.atomic_write(path, _PROTECTED_SEED)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = []
        for item in _list([] if raw is None else raw, "the list"):
            item = _check_fields(item, {"name", "hosts"}, {"ports", "catalog_entry"})
            name = item["name"]
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ValueError(f"bad name {name!r}")
            hosts = _list(item["hosts"], "hosts")
            if not hosts:
                raise ValueError(f"{name}: hosts must not be empty")
            # The ports are for the host rules of the direct route (lib/sql_uplink.py).
            ports = _ports(item["ports"]) if "ports" in item else None
            catalog = item.get("catalog_entry")
            if catalog is not None and not (
                isinstance(catalog, str) and _CATALOG_RE.match(catalog)
            ):
                raise ValueError(f"{name}: bad catalog_entry")
            entries.append(
                {
                    "name": name,
                    "hosts": [normalise_host(h, networks=True) for h in hosts],
                    "ports": ports,
                    "catalog_entry": catalog,
                }
            )
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise EgressError(f"{path}: {exc}") from exc
    return entries


def load_protected_hosts(config_dir: Path) -> list[dict]:
    """The validated protected hosts as the proxy reads them (name and hosts)."""
    return [
        {"name": e["name"], "hosts": e["hosts"]} for e in load_protected_entries(config_dir)
    ]


def load_internal_targets(config_dir: Path) -> dict[str, list[str]]:
    """The ranges the operator opened, per add-on; seeds an empty list on first use."""
    path = config_dir / INTERNAL_TARGETS_FILE
    if not path.is_file():
        common.atomic_write(path, _INTERNAL_SEED)
    opened: dict[str, list[str]] = {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        for item in _list([] if raw is None else raw, "the list"):
            item = _check_fields(item, {"name", "ranges", "addons"}, set())
            name = item["name"]
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ValueError(f"bad name {name!r}")
            ranges = _list(item["ranges"], "ranges")
            addons = _list(item["addons"], "addons")
            if not ranges or not addons:
                raise ValueError(f"{name}: ranges and addons must not be empty")
            networks = []
            for value in ranges:
                if not isinstance(value, str):
                    raise ValueError(f"{name}: not an address range: {value!r}")
                try:
                    networks.append(str(ipaddress.ip_network(value, strict=False)))
                except ValueError:
                    raise ValueError(f"{name}: not an address range: {value!r}") from None
            for addon in addons:
                if not isinstance(addon, str) or not _SOURCE_RE.match(addon):
                    raise ValueError(f"{name}: bad add-on name {addon!r}")
                known = opened.setdefault(addon, [])
                known.extend(n for n in networks if n not in known)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise EgressError(f"{path}: {exc}") from exc
    return opened


def _project(env: dict[str, str]) -> str:
    return env.get("PAPAIA_PROJECT") or env.get("COMPOSE_PROJECT_NAME") or "papaia"


def _core_networks(env: dict[str, str]) -> dict[str, str]:
    """Every name a core network can have on this host, with what it is."""
    project = _project(env)
    core = {"papaia-net": "the core network", EGRESS_NETWORK: "the exit network"}
    docker_network = env.get("DOCKER_NETWORK") or "papaia-net"
    core[docker_network] = "the core network (DOCKER_NETWORK)"
    names = {name: "a Docker network" for name in _DOCKER_NETWORKS}
    for key, what in core.items():
        names[key] = what
        names[f"{project}_{key}"] = what
    return names


def allowed_host(value: object) -> str:
    """An allow-list host that is outside the stack by its name: no single label (a
    service name in Docker's DNS), not one of the proxy's aliases or the stack's
    services, not the Docker host."""
    host = normalise_host(value)
    with_address = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        with_address = False
    if with_address:
        return host
    labels = host.split(".")
    if len(labels) == 1:
        raise ValueError(f"{host!r} is a single label, which names a service inside the stack")
    if labels[0].startswith(_STACK_PREFIXES):
        raise ValueError(f"{host!r} names a service of the stack")
    if host.endswith((".docker.internal", ".localhost")):
        raise ValueError(f"{host!r} names the Docker host")
    return host


def _check_internal(addon_path: Path, network: str, config_dir: Path) -> None:
    """The add-on's own compose file must create the egress network as internal, or its
    services would reach the outside around the proxy."""
    from . import gen_override  # the template rule of networks.app_network

    compose = addon_path / "docker-compose.yml"
    if not compose.is_file():
        raise ValueError(f"{compose} not found; it must create {network!r} as internal: true")
    try:
        doc = yaml.safe_load(compose.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{compose} is not valid YAML: {exc}") from None
    networks = doc.get("networks") if isinstance(doc, dict) else None
    for config in networks.values() if isinstance(networks, dict) else ():
        name = config.get("name") if isinstance(config, dict) else None
        if (
            not isinstance(name, str)
            or gen_override.resolve_app_network(name, config_dir) != network
        ):
            continue
        if config.get("internal") is True and not config.get("external"):
            return
        break
    raise ValueError(f"{compose.name} must create the network {network!r} with internal: true")


def addon_egress(manifest: dict, config_dir: Path, addon_path: Path) -> dict | None:
    """The validated `networks.egress` declaration of one add-on manifest, with the
    network name resolved against the root .env, or None when it declares none."""
    from . import gen_override  # the template rule of networks.app_network

    networks = manifest.get("networks") or {}
    declared = networks.get("egress") if isinstance(networks, dict) else None
    if declared is None:
        return None
    name = manifest.get("name")
    env = common.parse_env_file(config_dir / ".env")
    try:
        if not isinstance(name, str) or not _SOURCE_RE.match(name):
            raise ValueError(f"add-on name {name!r} cannot name an egress source")
        declared = _check_fields(declared, {"network"}, {"allow"})
        if not isinstance(declared["network"], str):
            raise ValueError("network must be a string")
        network = gen_override.resolve_app_network(declared["network"], config_dir)
        if not _NETWORK_RE.match(network):
            raise ValueError(f"bad network name {network!r}")
        core = _core_networks(env)
        if network in core:
            raise ValueError(f"{network!r} is {core[network]}")
        prefix = f"{_project(env)}-{name}-"
        if not network.startswith(prefix) or network == prefix:
            raise ValueError(
                f"{network!r} must be scoped to the add-on: ${{PAPAIA_PROJECT}}-{name}-..."
            )
        app_network = networks.get("app_network")
        if isinstance(app_network, str) and (
            gen_override.resolve_app_network(app_network, config_dir) == network
        ):
            raise ValueError(f"{network!r} is the add-on's own networks.app_network")
        _check_internal(addon_path, network, config_dir)
        allow = []
        for rule in _list(declared.get("allow", []), "allow"):
            rule = _check_fields(rule, {"host", "ports"}, set())
            allow.append({"host": allowed_host(rule["host"]), "ports": _ports(rule["ports"])})
    except ValueError as exc:
        raise EgressError(f"add-on '{name}': networks.egress: {exc}") from exc
    return {"name": name, "network": network, "allow": allow}


def _claims(manifest: dict, fallback: str, config_dir: Path) -> list[tuple[str, str, str]]:
    """(network, add-on, kind) for every network an add-on manifest names."""
    from . import gen_override

    name = manifest.get("name") if isinstance(manifest.get("name"), str) else fallback
    networks = manifest.get("networks") or {}
    if not isinstance(networks, dict):
        return []
    found = []
    if isinstance(networks.get("app_network"), str):
        raw = networks["app_network"]
        found.append((gen_override.resolve_app_network(raw, config_dir), name, "app_network"))
    declared = networks.get("egress")
    if isinstance(declared, dict) and isinstance(declared.get("network"), str):
        raw = declared["network"]
        found.append((gen_override.resolve_app_network(raw, config_dir), name, "egress network"))
    return found


def declarations(config_dir: Path, repo_root: Path | None = None) -> list[dict]:
    """The validated egress declarations of all active add-ons. Raises EgressError when
    one is unusable or names a network another add-on (active or not) declares."""
    base = repo_root if repo_root is not None else Path.cwd()
    found, claims = [], []
    for addon in deployment.load(config_dir).get("addons") or []:
        if not addon.get("path"):
            continue
        path = deployment.resolve_addon_path(addon, base)
        manifest, _ = deployment.load_addon_manifest(path)
        if manifest is None:
            continue
        claims.extend(_claims(manifest, str(addon.get("name")), config_dir))
        if addon.get("active"):
            declaration = addon_egress(manifest, config_dir, path)
            if declaration is not None:
                found.append(declaration)
    for declaration in found:
        name, network = declaration["name"], declaration["network"]
        for claimed, other, kind in claims:
            if claimed == network and other != name:
                raise EgressError(
                    f"add-on '{name}': networks.egress: {network!r} is also the {kind}"
                    f" of add-on '{other}'"
                )
    return found


def alias(source: str) -> str:
    return f"egress-{source}"


def upstream_proxy(env: dict[str, str], config_dir: Path) -> dict | None:
    """The corporate proxy from the root .env, or None. Only `http://[user@]host:port`:
    the password lives in its own file (mode 0600), never in the URL or the .env."""
    raw = env.get(UPSTREAM_KEY, "").strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise EgressError(f"{UPSTREAM_KEY}: {exc}") from exc
    if (
        parts.scheme != "http"
        or not parts.hostname
        or port is None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise EgressError(
            f"{UPSTREAM_KEY} must be http://[user@]host:port (the password goes into"
            f" $PAPAIA_CONFIG_DIR/{UPSTREAM_PASSWORD_FILE}), got {raw!r}"
        )
    user = parts.username or ""
    if user:
        password = config_dir / UPSTREAM_PASSWORD_FILE
        if not password.is_file():
            raise EgressError(f"{UPSTREAM_KEY} names a user but {password} is missing")
        if stat.S_IMODE(password.stat().st_mode) & 0o077:
            raise EgressError(f"{password} must have mode 0600")
    try:
        no_proxy = [
            normalise_host(h.strip().lstrip("."))
            for h in env.get(NO_PROXY_KEY, "").split(",")
            if h.strip()
        ]
        host = normalise_host(parts.hostname)
    except ValueError as exc:
        raise EgressError(f"{UPSTREAM_KEY}/{NO_PROXY_KEY}: {exc}") from exc
    return {"host": host, "port": port, "user": user, "no_proxy": no_proxy}


def render(config_dir: Path, repo_root: Path | None = None) -> Path:
    """Write the proxy configuration. Raises EgressError, writing nothing, when the
    protected hosts, the internal targets, an add-on's declaration or the corporate
    proxy are unusable."""
    from . import hosted_model  # reads the rendered LiteLLM configuration

    env = common.parse_env_file(config_dir / ".env")
    opened = load_internal_targets(config_dir)
    sources = [
        {
            "name": d["name"],
            "alias": alias(d["name"]),
            "allow": d["allow"],
            "internal": opened.get(d["name"], []),
        }
        for d in declarations(config_dir, repo_root)
    ]
    # The test stack's hosted model: LiteLLM is one more source, allowed to its one host.
    try:
        gateway = hosted_model.egress_source(config_dir, repo_root)
    except hosted_model.HostedModelError as exc:
        raise EgressError(str(exc)) from exc
    if gateway is not None:
        if any(s["name"] == gateway["name"] for s in sources):
            raise EgressError(
                f"add-on '{gateway['name']}': networks.egress: the name is the source of the"
                " model gateway while the hosted test model is on"
            )
        sources.append(gateway)
    # papaia-audit to its SIEM target, while one is set (lib/audit.py).
    from . import audit

    try:
        siem = audit.egress_source(config_dir)
    except audit.AuditError as exc:
        raise EgressError(str(exc)) from exc
    if siem is not None:
        if any(s["name"] == siem["name"] for s in sources):
            raise EgressError(f"the source name '{siem['name']}' belongs to papaia-audit")
        sources.append(siem)
    # The federation's status sync: papaia-lifecycle to the host of the directory.
    from . import federation

    try:
        status_sync = federation.egress_source(config_dir)
    except federation.FederationError as exc:
        raise EgressError(str(exc)) from exc
    if status_sync is not None:
        if any(s["name"] == status_sync["name"] for s in sources):
            raise EgressError(
                f"add-on '{status_sync['name']}': networks.egress: the name is the source of "
                "papaia-lifecycle while the federation is on"
            )
        sources.append(status_sync)
    config = {
        "format": CONFIG_FORMAT,
        "sources": sources,
        "protected": load_protected_hosts(config_dir),
        "upstream": upstream_proxy(env, config_dir),
    }
    path = config_dir / CONFIG_FILE
    common.atomic_write(path, json.dumps(config, indent=2) + "\n")
    return path


def override_path(config_dir: Path, name: str) -> Path:
    return config_dir / "overrides" / f"docker-compose.{name}.egress.override.yml"


def generate_overrides(config_dir: Path, repo_root: Path) -> list[Path]:
    """Write the attachment override of every active add-on with an egress network and
    remove it for every other add-on in deployment.yaml. When a declaration is unusable,
    every attachment is removed and EgressError is raised: the proxy is never put on a
    network that was not checked."""
    names = [
        a["name"]
        for a in deployment.load(config_dir).get("addons") or []
        if isinstance(a.get("name"), str) and a["name"]
    ]
    try:
        valid = {d["name"]: d for d in declarations(config_dir, repo_root)}
    except EgressError:
        for name in names:
            override_path(config_dir, name).unlink(missing_ok=True)
        raise
    written = []
    for name in names:
        out = override_path(config_dir, name)
        declaration = valid.get(name)
        if declaration is None:
            out.unlink(missing_ok=True)
            continue
        network = declaration["network"]
        override = {
            "services": {
                SERVICE: {
                    "networks": {
                        EGRESS_NETWORK: {},
                        network: {"aliases": [alias(declaration["name"])]},
                    }
                }
            },
            "networks": {network: {"external": True}},
        }
        common.atomic_write(
            out, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
        )
        written.append(out)
    return written
