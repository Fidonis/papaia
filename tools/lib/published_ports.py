"""Ratchet on the host ports the core publishes.

Only the edge proxy publishes ports: HTTP and HTTPS, bound to HOST_IP (or to
INGRESS_HOST_IP when that is set) through INGRESS_HTTP_EXT_PORT and
INGRESS_HTTPS_EXT_PORT, declared once in the edge's own fragment. Every other `ports:`
entry of a core compose fragment must stand on the legacy list in
`security/published-ports.yaml`, and no core service may use the host network.

The legacy list is a frozen inventory, not a permission. It records the ports that were
published before the edge rule existed, each with its reason and the change that removes
it. Entries are only removed: the list must equal `FROZEN_INVENTORY` below, so removing a
port removes its key here in the same change, and bringing a port back means growing this
inventory in code, which review refuses. The single
documented exception is the link gateway of a distributed installation, whose port is
written into the node's generated override (`link.gateway_override`) and is reached with
mutual TLS only.

`lint()` checks the compose fragments of a checkout and returns one message per finding;
an empty list means the checkout passes. The test suite runs it on every change.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

ALLOW_LIST = Path("security") / "published-ports.yaml"

EDGE_SERVICE = "nginx-proxy-manager"
EDGE_FILE = "src/infra/nginx/docker-compose.yml"
# The edge's published ports, verbatim. INGRESS_HOST_IP is empty unless a node of a
# distributed installation binds the edge to its own address while HOST_IP keeps the
# legacy ports on loopback.
EDGE_BIND = "${INGRESS_HOST_IP:-${HOST_IP:-0.0.0.0}}"
EDGE_ENTRIES: tuple[str, ...] = (
    f"{EDGE_BIND}:${{INGRESS_HTTP_EXT_PORT:-80}}:80",
    f"{EDGE_BIND}:${{INGRESS_HTTPS_EXT_PORT:-443}}:443",
)

SOURCE_COMPOSE = "compose"
SOURCE_GENERATED = "generated"
BIND_HOST_IP = "HOST_IP"
BIND_LOOPBACK = "127.0.0.1"
BIND_NODE_ADDRESS = "node-address"

# (source, service, variable, target, bind). Equal to the legacy list. Shrinks with every
# port that moves behind the edge, in the same change as the list; never grows.
FROZEN_INVENTORY: frozenset[tuple[str, str, str, int | None, str]] = frozenset(
    {
        (SOURCE_COMPOSE, "nginx-proxy-manager", "NPM_API_LOCAL_PORT", 81, BIND_LOOPBACK),
        (SOURCE_COMPOSE, "nginx-proxy-manager-auth", "NPM_ADMIN_EXT_PORT", 4180, BIND_HOST_IP),
        (SOURCE_COMPOSE, "oauth2-proxy", "OAUTH2_PROXY_EXT_PORT", 4180, BIND_HOST_IP),
        (SOURCE_COMPOSE, "keycloak", "KEYCLOAK_EXT_PORT", 8443, BIND_HOST_IP),
        (SOURCE_COMPOSE, "papaia-manager", "MANAGER_EXT_PORT", 8000, BIND_HOST_IP),
        (SOURCE_COMPOSE, "librechat", "LIBRECHAT_EXT_PORT", 3080, BIND_HOST_IP),
        (SOURCE_COMPOSE, "litellm", "LITELLM_EXT_PORT", 4000, BIND_HOST_IP),
        (SOURCE_COMPOSE, "localai", "LOCALAI_EXT_PORT", 8080, BIND_HOST_IP),
        (SOURCE_COMPOSE, "qdrant", "QDRANT_EXT_PORT", 6333, BIND_HOST_IP),
        (SOURCE_COMPOSE, "qdrant-ingest", "QDRANT_INGEST_EXT_PORT", 8300, BIND_HOST_IP),
        (SOURCE_GENERATED, "link-gateway", "topology.link.port", None, BIND_NODE_ADDRESS),
    }
)

_TOP_FIELDS = {"version", "entries"}
_ENTRY_FIELDS = {"service", "source", "file", "variable", "target", "bind", "reason", "removed_by"}
_REQUIRED_COMPOSE = _ENTRY_FIELDS
_REQUIRED_GENERATED = _ENTRY_FIELDS - {"target"}
_BINDS = {
    SOURCE_COMPOSE: {BIND_HOST_IP, BIND_LOOPBACK},
    SOURCE_GENERATED: {BIND_NODE_ADDRESS},
}
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_COMPOSE_VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_GENERATED_VARIABLE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
_MAX_TEXT = 1000
_MAX_SHORT = 200
_COMPOSE_NAMES = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")

# `<bind>:${VAR}:<target>` or `<bind>:${VAR:-1234}:<target>`, optionally `/tcp|/udp`.
_ENTRY = re.compile(
    r"^(?P<bind>\$\{(?P<bind_var>[A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}|[0-9.]+|\[[0-9a-fA-F:]+\])"
    r":\$\{(?P<variable>[A-Za-z_][A-Za-z0-9_]*)(?::-[0-9]{1,5})?\}"
    r":(?P<target>[0-9]{1,5})(?:/(?:tcp|udp))?$"
)


class AllowListError(ValueError):
    """The legacy list is missing or malformed."""


@dataclass(frozen=True)
class AllowEntry:
    service: str
    source: str
    file: str
    variable: str
    target: int | None
    bind: str
    reason: str
    removed_by: str

    @property
    def key(self) -> tuple[str, str, str, int | None, str]:
        return (self.source, self.service, self.variable, self.target, self.bind)


# ─────────────────────────────────────────────────────────────────────────
# the legacy list
# ─────────────────────────────────────────────────────────────────────────


def _text(entry: dict[str, Any], key: str, where: str, limit: int) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value.strip():
        raise AllowListError(f"{where}: {key} must be a non-empty string")
    if len(value) > limit:
        raise AllowListError(f"{where}: {key} is longer than {limit} characters")
    return value


def _entry(raw: Any, index: int, repo_root: Path) -> AllowEntry:
    where = f"{ALLOW_LIST} entry {index}"
    if not isinstance(raw, dict):
        raise AllowListError(f"{where}: must be a mapping")
    unknown = set(raw) - _ENTRY_FIELDS
    if unknown:
        raise AllowListError(f"{where}: unknown field(s) {', '.join(sorted(map(str, unknown)))}")
    source = raw.get("source")
    if source not in _BINDS:
        raise AllowListError(f"{where}: source must be one of {', '.join(sorted(_BINDS))}")
    required = _REQUIRED_COMPOSE if source == SOURCE_COMPOSE else _REQUIRED_GENERATED
    missing = required - set(raw)
    if missing:
        raise AllowListError(f"{where}: missing field(s) {', '.join(sorted(missing))}")
    if source == SOURCE_GENERATED and "target" in raw:
        raise AllowListError(f"{where}: target is the published port itself for a generated entry")

    service = _text(raw, "service", where, 63)
    if not _NAME.match(service):
        raise AllowListError(f"{where}: service '{service}' is not a compose service name")
    where = f"{ALLOW_LIST} entry '{service}'"

    variable = _text(raw, "variable", where, 64)
    pattern = _COMPOSE_VARIABLE if source == SOURCE_COMPOSE else _GENERATED_VARIABLE
    if not pattern.match(variable):
        raise AllowListError(f"{where}: variable '{variable}' is malformed")

    target: int | None = None
    if source == SOURCE_COMPOSE:
        value = raw["target"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise AllowListError(f"{where}: target must be a port number between 1 and 65535")
        target = value

    bind = _text(raw, "bind", where, 32)
    if bind not in _BINDS[source]:
        raise AllowListError(
            f"{where}: bind '{bind}' must be one of {', '.join(sorted(_BINDS[source]))}"
        )

    file = _text(raw, "file", where, _MAX_SHORT)
    rel = PurePosixPath(file)
    if rel.is_absolute() or ".." in rel.parts or not (repo_root / rel).is_file():
        raise AllowListError(f"{where}: file '{file}' is not a file of this repository")
    in_core = rel.parts[0] == "src" and rel.name.startswith("docker-compose")
    if source == SOURCE_COMPOSE and not in_core:
        raise AllowListError(f"{where}: file '{file}' is not a core compose fragment")

    return AllowEntry(
        service=service,
        source=source,
        file=file,
        variable=variable,
        target=target,
        bind=bind,
        reason=_text(raw, "reason", where, _MAX_TEXT),
        removed_by=_text(raw, "removed_by", where, _MAX_SHORT),
    )


def load_allow_list(repo_root: Path) -> list[AllowEntry]:
    path = repo_root / ALLOW_LIST
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AllowListError(f"{ALLOW_LIST} cannot be read: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise AllowListError(f"{ALLOW_LIST} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise AllowListError(f"{ALLOW_LIST} must be a mapping")
    unknown = set(doc) - _TOP_FIELDS
    if unknown:
        names = ", ".join(sorted(map(str, unknown)))
        raise AllowListError(f"{ALLOW_LIST}: unknown field(s) {names}")
    if doc.get("version") != 1:
        raise AllowListError(f"{ALLOW_LIST}: version must be 1")
    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list):
        raise AllowListError(f"{ALLOW_LIST}: entries must be a list")

    entries: list[AllowEntry] = []
    seen: set[tuple[str, str, int | None]] = set()
    for index, raw in enumerate(raw_entries):
        entry = _entry(raw, index, repo_root)
        identity = (entry.service, entry.variable, entry.target)
        if identity in seen:
            raise AllowListError(f"{ALLOW_LIST}: duplicate entry for '{entry.service}'")
        seen.add(identity)
        entries.append(entry)
    return entries


# ─────────────────────────────────────────────────────────────────────────
# compose fragments
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Published:
    variable: str
    target: int
    bind: str


def _parse(raw: str) -> _Published | None:
    """The parts of one short-syntax entry, or None when it is not of the one accepted
    shape: an explicit bind address, the host port from a variable, a container port."""
    match = _ENTRY.match(raw)
    if not match:
        return None
    bind = match.group("bind_var") or match.group("bind")
    return _Published(match.group("variable"), int(match.group("target")), bind)


def compose_fragments(repo_root: Path) -> list[Path]:
    """Every compose file under src/, included by the root file or not: a fragment
    that is only added with `-f` (the link gateway) publishes as much as any other."""
    src = repo_root / "src"
    found = {
        p
        for pattern in _COMPOSE_NAMES
        for p in src.rglob(pattern)
        if p.is_file()
    }
    return sorted(found)


def lint(repo_root: Path) -> list[str]:
    try:
        allow = load_allow_list(repo_root)
    except AllowListError as exc:
        return [str(exc)]

    findings = [
        f"{ALLOW_LIST}: '{e.service}' ({e.variable}) is not in the frozen inventory;"
        " the list only shrinks -- publish through the edge instead"
        for e in allow
        if e.key not in FROZEN_INVENTORY
    ]
    listed = {e.key for e in allow}
    findings += [
        f"{ALLOW_LIST}: '{service}' ({variable}) is in FROZEN_INVENTORY but not on the list;"
        " remove it from FROZEN_INVENTORY in the same change"
        for (_, service, variable, _, _) in sorted(
            FROZEN_INVENTORY - listed, key=lambda k: (k[1], k[2])
        )
    ]
    by_key = {
        (e.service, e.variable, e.target, e.bind): e for e in allow if e.source == SOURCE_COMPOSE
    }
    used: set[tuple[str, str, int | None, str]] = set()
    edge_seen: list[str] = []

    for path in compose_fragments(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            findings.append(f"{rel}: cannot be read: {exc}")
            continue
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, dict):
            continue
        for name, body in services.items():
            if isinstance(body, dict) and str(body.get("network_mode", "")).strip() == "host":
                findings.append(
                    f"{rel}: '{name}' uses network_mode: host, which publishes every port it"
                    " listens on; only the edge proxy publishes ports"
                )
            ports = (body or {}).get("ports") if isinstance(body, dict) else None
            if ports is None:
                continue
            if not isinstance(ports, list):
                findings.append(f"{rel}: '{name}' has a ports: value that is not a list")
                continue
            for raw in ports:
                if not isinstance(raw, str):
                    findings.append(
                        f"{rel}: '{name}' publishes a port in long syntax; use the short"
                        " syntax <bind>:${VAR}:<container port> so the ratchet can read it"
                    )
                    continue
                if raw in EDGE_ENTRIES:
                    if name != EDGE_SERVICE or rel != EDGE_FILE:
                        findings.append(
                            f"{rel}: '{name}' publishes the edge port '{raw}'; only"
                            f" '{EDGE_SERVICE}' in {EDGE_FILE} publishes it"
                        )
                    elif raw in edge_seen:
                        findings.append(
                            f"{rel}: the edge proxy publishes '{raw}' more than once"
                        )
                    else:
                        edge_seen.append(raw)
                    continue
                parsed = _parse(raw)
                if parsed is None:
                    findings.append(
                        f"{rel}: '{name}' publishes '{raw}': only the edge publishes ports;"
                        " a legacy port needs an explicit bind address and its host port"
                        " from a variable"
                    )
                    continue
                key = (name, parsed.variable, parsed.target, parsed.bind)
                entry = by_key.get(key)
                if entry is None or entry.file != rel:
                    findings.append(
                        f"{rel}: '{name}' publishes '{raw}', which is neither an edge port nor"
                        f" on the legacy list {ALLOW_LIST}; only the edge proxy"
                        f" '{EDGE_SERVICE}' publishes ports"
                    )
                    continue
                used.add(key)

    for entry in EDGE_ENTRIES:
        if entry not in edge_seen:
            findings.append(f"the edge proxy '{EDGE_SERVICE}' does not publish '{entry}'")
    for key, entry in by_key.items():
        if key not in used:
            findings.append(
                f"{ALLOW_LIST}: '{entry.service}' ({entry.variable}) no longer publishes its"
                " port; remove the entry so the port cannot come back"
            )
    return findings


def check_generated(service: str, ports: list[str], allow: list[AllowEntry]) -> list[str]:
    """Findings for the `ports:` of a generated override (the link gateway's).

    The port is published on the node's address (an IP literal, bracketed for IPv6, or
    every address when the node is known by name) and maps to the same container port.
    The generated override is not part of the checkout, so the test suite runs this
    against `link.gateway_override`."""
    allowed = {e.service for e in allow if e.source == SOURCE_GENERATED}
    if service not in allowed:
        return [f"'{service}' publishes {ports} from generated configuration, which only"
                " the documented exception on the legacy list may do"]
    findings = []
    for raw in ports:
        parts = str(raw).rsplit(":", 2)
        if len(parts) != 3:
            findings.append(f"'{service}' publishes '{raw}' without a bind address")
            continue
        address, host, target = parts
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            findings.append(f"'{service}' publishes '{raw}' without an IP bind address")
            continue
        if not host.isdigit() or host != target:
            findings.append(f"'{service}' publishes '{raw}' on another container port")
    return findings
