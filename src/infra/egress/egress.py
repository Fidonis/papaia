"""papaia-egress: the single exit of the stack.

A forward proxy that only tunnels (HTTP CONNECT). Every connection is decided against
the configuration `papaia-ctl` renders into /etc/papaia-egress/egress.json:

  1. The source is the add-on whose egress network the connection arrived on. The proxy
     joins that network under the alias `egress-<add-on>`; the local address a
     connection arrives at is matched against what that alias resolves to, and the
     peer must sit in the subnet of that same network. Anything else (another network,
     an unknown alias, a peer routed in from elsewhere) is refused.
  2. The protected hosts (security/protected-hosts.yaml) are refused for every source,
     whatever its allow list says: by name, and by address after resolution. Protected
     names are resolved in the background; an address once learned is kept, and while a
     protected name cannot be resolved no opened internal range is used.
  3. Never reached: loopback, link-local, multicast and unspecified addresses, the
     proxy's own addresses, its gateways and the egress networks of the add-ons it is
     attached to. Other addresses of the Docker host are not known here; the operator
     lists them as protected hosts.
  4. Addresses that are not global (private, shared, unique local, site-local, ...) are
     refused unless the operator opened the range for this source
     (security/egress-internal-targets.yaml). IPv4 addresses embedded in IPv6 (mapped,
     translated, NAT64, 6to4) are judged like the IPv4 address itself.
  5. Otherwise only `host:port` pairs on the allow list of the source pass.

Names that are not on an allow list are never resolved, so a source cannot use the
proxy's resolver as a way out. The proxy connects to the address it checked, never to
a second resolution of the name. With a corporate proxy configured, the tunnel is
opened through it instead, to the checked addresses (one after another) whenever the
name resolved here.

Connections are capped in total and per source, and a tunnel without traffic in either
direction is closed after a while, so one source cannot use up the exit of the others.

Each decision is one JSON line on stdout in the shape of `papaia.audit/1`; hosts and
ports only, never content. Operational messages go to stderr.

Standard library only; runs as an unprivileged user on a read-only file system.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FORMAT = "papaia.egress/1"
PASSWORD_FILE = "upstream-proxy-password"
DEFAULT_PORT = 3128
MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT_SECONDS = 10
CONNECT_TIMEOUT_SECONDS = 10
RELOAD_SECONDS = 5
SOURCE_REFRESH_SECONDS = 2
LOCAL_REFRESH_SECONDS = 2
PROTECTED_REFRESH_SECONDS = 30
RESOLVE_TIMEOUT_SECONDS = 5
IDLE_TIMEOUT_SECONDS = 300
MAX_CONNECTIONS = 512
MAX_CONNECTIONS_PER_SOURCE = 128

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")

# Never a destination, whatever a list says: the proxy itself, the metadata service of
# a cloud host, and addresses that are no single host.
_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/3",
        "::/96",  # unspecified, loopback and IPv4-compatible
        "::ffff:0:0/96",
        "fe80::/10",
        "ff00::/8",
    )
)
# Not global, whatever the Python release thinks of `is_global`: refused unless the
# operator opened the range for the source.
_INTERNAL = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "fc00::/7",
        "fec0::/10",  # deprecated site-local
        "64:ff9b:1::/48",
        "2002::/16",
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")  # IPv4-translated (SIIT)


class RequestError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status


@dataclass(frozen=True)
class Upstream:
    host: str
    port: int
    user: str
    no_proxy: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    aliases: dict[str, str] = field(default_factory=dict)  # source -> alias
    allow: dict[str, frozenset[tuple[str, int]]] = field(default_factory=dict)
    internal: dict[str, tuple] = field(default_factory=dict)  # source -> opened ranges
    protected_names: frozenset[str] = frozenset()
    protected_networks: tuple = ()
    upstream: Upstream | None = None


@dataclass(frozen=True)
class Local:
    """Where the proxy itself sits: its own addresses, its gateways, the networks it
    is attached to apart from its exit network (the one with the default route), and
    every network it has an address on (`links`, the exit network included)."""

    own: frozenset = frozenset()
    gateways: frozenset = frozenset()
    attached: tuple = ()
    links: tuple = ()


_NO_LOCAL = Local()
# Used when the proxy cannot tell where it sits: then every address counts as attached.
_UNKNOWN_LOCAL = Local(attached=(ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")))


@dataclass(frozen=True)
class Decision:
    result: str
    error_code: str | None
    event: str


# ─────────────────────────────────────────────────────────────────────────
# configuration
# ─────────────────────────────────────────────────────────────────────────


def normalise_host(value: object) -> str:
    """A host name in lower case without the trailing dot, or an IP address in normal
    form. Raises ValueError for anything else (wildcards, ranges, URLs)."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"not a host: {value!r}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    host = value.lower().rstrip(".")
    if not _HOST_RE.match(host):
        raise ValueError(f"not a host: {value!r}")
    return host


def _fields(obj: object, required: set[str], optional: set[str], where: str) -> dict:
    if not isinstance(obj, dict):
        raise ValueError(f"{where}: expected an object")
    unknown = set(obj) - required - optional
    missing = required - set(obj)
    if unknown or missing:
        raise ValueError(f"{where}: unknown {sorted(unknown)}, missing {sorted(missing)}")
    return obj


def _port(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{where}: not a port: {value!r}")
    return value


def load_config(data: object) -> Config:
    """Validate the rendered configuration; unknown fields are an error."""
    top = _fields(data, {"format", "sources", "protected", "upstream"}, set(), "config")
    if top["format"] != CONFIG_FORMAT:
        raise ValueError(f"config: format {top['format']!r} is not {CONFIG_FORMAT}")
    aliases: dict[str, str] = {}
    allow: dict[str, frozenset[tuple[str, int]]] = {}
    internal: dict[str, tuple] = {}
    for source in top["sources"] if isinstance(top["sources"], list) else [None]:
        entry = _fields(source, {"name", "alias", "allow", "internal"}, set(), "source")
        name = entry["name"]
        if not isinstance(name, str) or not _NAME_RE.match(name) or name in aliases:
            raise ValueError(f"source: bad or repeated name {name!r}")
        aliases[name] = normalise_host(entry["alias"])
        pairs = set()
        for rule in entry["allow"] if isinstance(entry["allow"], list) else [None]:
            rule = _fields(rule, {"host", "ports"}, set(), f"source {name}: allow")
            host = normalise_host(rule["host"])
            ports = rule["ports"] if isinstance(rule["ports"], list) and rule["ports"] else [0]
            pairs.update((host, _port(p, f"source {name}: {host}")) for p in ports)
        allow[name] = frozenset(pairs)
        ranges = entry["internal"] if isinstance(entry["internal"], list) else [None]
        try:
            internal[name] = tuple(ipaddress.ip_network(r, strict=False) for r in ranges)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"source {name}: bad internal range") from exc
    names, networks = set(), []
    for item in top["protected"] if isinstance(top["protected"], list) else [None]:
        item = _fields(item, {"name", "hosts"}, set(), "protected")
        for host in item["hosts"] if isinstance(item["hosts"], list) else [None]:
            try:
                networks.append(ipaddress.ip_network(host, strict=False))
            except (TypeError, ValueError):
                names.add(normalise_host(host))
    upstream = None
    if top["upstream"] is not None:
        up = _fields(top["upstream"], {"host", "port", "user", "no_proxy"}, set(), "upstream")
        if not isinstance(up["user"], str) or not isinstance(up["no_proxy"], list):
            raise ValueError("upstream: bad user or no_proxy")
        upstream = Upstream(
            normalise_host(up["host"]),
            _port(up["port"], "upstream"),
            up["user"],
            tuple(normalise_host(h) for h in up["no_proxy"]),
        )
    return Config(aliases, allow, internal, frozenset(names), tuple(networks), upstream)


# ─────────────────────────────────────────────────────────────────────────
# decisions
# ─────────────────────────────────────────────────────────────────────────


def forms(address) -> list:
    """The address and every IPv4 address embedded in it (IPv4-mapped, IPv4-translated,
    6to4, NAT64), so that a check of an IPv4 range also holds for its IPv6 spellings."""
    found = [address]
    if address.version == 6:
        if address.ipv4_mapped is not None:
            found.append(address.ipv4_mapped)
        if address.sixtofour is not None:
            found.append(address.sixtofour)
        if address in _NAT64 or address in _TRANSLATED:
            found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    return found


def _within(address, networks) -> bool:
    return any(address.version == n.version and address in n for n in networks)


def _protected(config: Config, host: str, addresses, protected_addresses) -> bool:
    if host in config.protected_names:
        return True
    for address in addresses:
        for form in forms(address):
            if form in protected_addresses or _within(form, config.protected_networks):
                return True
    return False


def _blocked(address, opened, local: Local) -> bool:
    for form in forms(address):
        if _within(form, _BLOCKED) or form in local.own or form in local.gateways:
            return True
        if _within(form, local.attached):
            return True
        internal = not form.is_global or _within(form, _INTERNAL)
        if internal and not _within(form, opened):
            return True
    return False


def decide(
    config: Config,
    source,
    host: str,
    port: int,
    addresses,
    protected_addresses,
    local: Local = _NO_LOCAL,
    *,
    protected_complete: bool = True,
):
    """The decision for one CONNECT. `addresses` are what `host` resolved to (empty when
    it was not resolved), `protected_addresses` what the protected names resolve to,
    `local` where the proxy itself sits. `protected_complete` is false while a protected
    name has no current answer: then no opened internal range is used, since the
    protected host may sit in it under an address not known here."""
    if source is None or source not in config.allow:
        return Decision("denied", "unknown_source", "operation")
    literal = []
    with contextlib.suppress(ValueError):
        literal = [ipaddress.ip_address(host)]
    candidates = list(addresses) + literal
    if _protected(config, host, candidates, protected_addresses):
        return Decision("denied", "protected_host", "protected_host_denied")
    opened = config.internal.get(source, ()) if protected_complete else ()
    if any(_blocked(address, opened, local) for address in candidates):
        return Decision("denied", "blocked_address", "operation")
    if (host, port) not in config.allow[source]:
        return Decision("denied", "not_allowed", "operation")
    return Decision("allowed", None, "operation")


def parse_request(head: bytes) -> tuple[str, int, dict[str, str]]:
    """Parse the request head of a CONNECT. Raises RequestError with the HTTP status."""
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RequestError(400, "request is not ASCII") from exc
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise RequestError(400, "malformed request line")
    method, target, _ = parts
    if method != "CONNECT":
        raise RequestError(405, "only CONNECT is supported")
    host, sep, port_text = target.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not sep or not port_text.isdigit():
        raise RequestError(400, "target is not host:port")
    port = int(port_text)
    try:
        host = normalise_host(host)
        _port(port, "target")
    except ValueError as exc:
        raise RequestError(400, str(exc)) from exc
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return host, port, headers


def _ipv4_le(text: str):
    return ipaddress.IPv4Address(struct.pack("<I", int(text, 16)))


def _ipv6_hex(text: str):
    return ipaddress.IPv6Address(bytes.fromhex(text))


def read_local(proc: Path = Path("/proc")) -> Local:
    """Where the proxy sits, from the kernel's view of its network namespace: its own
    addresses, its gateways, and the subnets of every interface except the one with the
    default route (the exit network). Without that view every address counts as
    attached, so nothing is reached."""
    net = proc / "net"
    own, gateways, subnets = set(), set(), []
    links: list = []
    exits = {"lo"}
    try:
        for line in (net / "route").read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            iface, destination, gateway, mask = fields[0], fields[1], fields[2], fields[7]
            if int(destination, 16) == 0 and int(mask, 16) == 0:
                exits.add(iface)
                if int(gateway, 16):
                    gateways.add(_ipv4_le(gateway))
            else:
                network = ipaddress.ip_network(
                    f"{_ipv4_le(destination)}/{_ipv4_le(mask)}", strict=False
                )
                subnets.append((iface, network))
                if int(gateway, 16) == 0:  # on the link, not routed through a gateway
                    links.append((iface, network))
        leaf = None
        for line in (net / "fib_trie").read_text(encoding="ascii").splitlines():
            text = line.strip()
            if text.startswith("|-- "):
                leaf = ipaddress.ip_address(text[4:])
            elif text == "/32 host LOCAL" and leaf is not None and not leaf.is_loopback:
                own.add(leaf)
        inet6 = net / "if_inet6"
        if inet6.is_file():
            for line in (net / "ipv6_route").read_text(encoding="ascii").splitlines():
                fields = line.split()
                if int(fields[0], 16) == 0 and int(fields[1], 16) == 0 and fields[9] != "lo":
                    exits.add(fields[9])
                    if int(fields[4], 16):
                        gateways.add(_ipv6_hex(fields[4]))
            for line in inet6.read_text(encoding="ascii").splitlines():
                fields = line.split()
                address, length, iface = _ipv6_hex(fields[0]), int(fields[2], 16), fields[5]
                if iface == "lo" or address.is_link_local:
                    continue
                own.add(address)
                network = ipaddress.ip_network(f"{address}/{length}", strict=False)
                subnets.append((iface, network))
                links.append((iface, network))
    except (OSError, ValueError, IndexError):
        return _UNKNOWN_LOCAL
    attached = tuple(dict.fromkeys(n for iface, n in subnets if iface not in exits))
    on_links = tuple(dict.fromkeys(n for iface, n in links if iface != "lo"))
    return Local(frozenset(own), frozenset(gateways), attached, on_links)


def on_link(local: Local, arrived_at, peer) -> bool:
    """Whether `peer` sits in the subnet of the network whose address `arrived_at` the
    connection came in on. A container elsewhere that routes to the proxy's address on
    another network (weak host model) fails this, so it is not taken for that network's
    add-on."""
    return any(
        arrived_at.version == n.version == peer.version and arrived_at in n and peer in n
        for n in local.links
    )


def upstream_targets(host: str, addresses) -> list[str]:
    """What the corporate proxy is asked to connect to, in this order: the addresses
    checked here when the name resolved inside the stack, so it cannot resolve the name
    into a protected or internal address of its own; the name only when it did not
    resolve here."""
    return [str(a) for a in addresses] if addresses else [host]


def _uuid7() -> str:
    millis = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (millis & (2**48 - 1)) << 80 | 7 << 76 | (rand >> 62 & 0xFFF) << 64
    value |= 2 << 62 | rand & (2**62 - 1)
    return str(uuid.UUID(int=value))


def correlation_id(headers: dict[str, str]) -> str:
    value = headers.get("x-papaia-correlation-id", "")
    return value if _CORRELATION_RE.match(value) else _uuid7()


def audit_row(decision: Decision, source, host, port, correlation: str) -> dict:
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1000):03d}Z"
    return {
        "format": "papaia.audit/1",
        "time": stamp,
        "correlation_id": correlation,
        "writer": "papaia-egress",
        "role": "egress",
        "sub": None,
        "identity_kind": "service",
        "azp": None,
        "catalog_id": None,
        "operation": "connect",
        "effect": "send",
        "result": decision.result,
        "error_code": decision.error_code,
        "event": decision.event,
        "detail": {"source": source, "host": host, "port": port},
    }


# ─────────────────────────────────────────────────────────────────────────
# server
# ─────────────────────────────────────────────────────────────────────────


def _log(message: str) -> None:
    print(f"papaia-egress: {message}", file=sys.stderr, flush=True)


async def _lookup(host: str, timeout: float) -> list | None:
    """The addresses of `host`, or None when the resolver failed or took longer than
    `timeout` seconds."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout
        )
    except (OSError, UnicodeError, asyncio.TimeoutError):
        return None
    seen = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if address not in seen:
            seen.append(address)
    return seen


async def _resolve(host: str) -> list:
    return await _lookup(host, RESOLVE_TIMEOUT_SECONDS) or []


class Proxy:
    def __init__(
        self,
        config_path: Path,
        proc: Path = Path("/proc"),
        max_connections: int = MAX_CONNECTIONS,
        max_per_source: int = MAX_CONNECTIONS_PER_SOURCE,
    ):
        self.config_path = config_path
        self.proc = proc
        self.max_connections = max_connections
        self.max_per_source = max_per_source
        self.config = Config()
        self.stamp: tuple[int, int] | None = None
        self.sources: dict = {}  # local address -> source
        self.sources_at = 0.0
        self.local = _UNKNOWN_LOCAL
        self.local_at = 0.0
        # Protected name -> every address it was ever seen with under this configuration;
        # names without a current answer are `protected_failing`.
        self.protected_known: dict = {}
        self.protected_failing: set = set()
        self.protected_addresses: set = set()
        self.protected_due = asyncio.Event()
        self.active = 0
        self.active_per_source: dict = {}

    def load(self) -> None:
        stat = self.config_path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self.stamp:
            return
        self.stamp = stamp
        try:
            self.config = load_config(json.loads(self.config_path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            # Fail closed: a broken configuration allows nothing until it is fixed.
            self.config = Config()
            _log(f"configuration refused, nothing is allowed: {exc}")
        else:
            _log(f"configuration loaded: {len(self.config.allow)} source(s)")
        # Sources and aliases may have changed: nothing learned before still holds.
        self.sources = {}
        self.sources_at = self.local_at = 0.0
        # Protected names: what is known of names still listed is kept; names that have
        # no answer yet count as failing until the next round resolves them.
        names = self.config.protected_names
        self.protected_known = {n: a for n, a in self.protected_known.items() if n in names}
        self.protected_failing = {n for n in names if n not in self.protected_known}
        self._protected_union()
        self.protected_due.set()

    async def watch(self) -> None:
        while True:
            await asyncio.sleep(RELOAD_SECONDS)
            try:
                self.load()
            except OSError as exc:
                self.config, self.stamp, self.sources = Config(), None, {}
                _log(f"configuration unreadable, nothing is allowed: {exc}")

    async def source_of(self, local_address, peer) -> str | None:
        """The source a connection from `peer` arriving at `local_address` comes from,
        None unless the peer sits on the network of that address. The map is rebuilt at
        most every SOURCE_REFRESH_SECONDS and never trusted for longer, so a moved alias
        or a reused address is not mistaken for its old owner."""
        if not on_link(self.where(), local_address, peer):
            return None
        if time.monotonic() - self.sources_at > SOURCE_REFRESH_SECONDS:
            mapping: dict = {}
            for name, alias in self.config.aliases.items():
                for address in await _resolve(alias):
                    # An address claimed by two aliases identifies neither.
                    mapping[address] = None if address in mapping else name
            self.sources, self.sources_at = mapping, time.monotonic()
        return self.sources.get(local_address)

    def where(self) -> Local:
        if time.monotonic() - self.local_at > LOCAL_REFRESH_SECONDS:
            self.local, self.local_at = read_local(self.proc), time.monotonic()
        return self.local

    @property
    def protected_complete(self) -> bool:
        return not self.protected_failing

    def _protected_union(self) -> None:
        found: set = set()
        for addresses in self.protected_known.values():
            found |= addresses
        self.protected_addresses = found

    async def refresh_protected(self) -> None:
        """One round over the protected names. A name that resolves adds its addresses;
        one that fails keeps what was learned before and counts as failing."""
        names = self.config.protected_names
        answers = await asyncio.gather(
            *(_lookup(name, RESOLVE_TIMEOUT_SECONDS) for name in sorted(names))
        )
        if names != self.config.protected_names:
            return  # a new configuration came in meanwhile; its own round follows
        failing = set()
        for name, found in zip(sorted(names), answers, strict=True):
            if found:
                self.protected_known[name] = self.protected_known.get(name, set()) | set(found)
            else:
                failing.add(name)
        if failing - self.protected_failing:
            _log(f"protected name(s) not resolvable, internal ranges closed: {sorted(failing)}")
        self.protected_failing = failing
        self._protected_union()

    async def keep_protected(self) -> None:
        """Resolve the protected names off the request path: every
        PROTECTED_REFRESH_SECONDS, and at once after a new configuration."""
        while True:
            self.protected_due.clear()
            try:
                await self.refresh_protected()
            except Exception as exc:  # the refresh must never stop; failing names stay
                _log(f"protected names not refreshed: {type(exc).__name__}")
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.protected_due.wait(), PROTECTED_REFRESH_SECONDS)

    async def handle(self, reader, writer) -> None:
        source = None
        counted = False
        try:
            local = _address_of(writer.get_extra_info("sockname"))
            peer = _address_of(writer.get_extra_info("peername"))
            source = await self.source_of(local, peer)
            if (
                self.active >= self.max_connections
                or self.active_per_source.get(source, 0) >= self.max_per_source
            ):
                decision = Decision("denied", "too_many_connections", "operation")
                _audit(decision, source, None, None, _uuid7())
                await _reply(writer, 503, decision.error_code)
                return
            self.active += 1
            self.active_per_source[source] = self.active_per_source.get(source, 0) + 1
            counted = True
            await self._handle(reader, writer, source)
        except Exception as exc:  # one broken connection must not stop the proxy
            _log(f"connection failed: {type(exc).__name__}")
        finally:
            if counted:
                self.active -= 1
                self.active_per_source[source] -= 1
                if not self.active_per_source[source]:
                    del self.active_per_source[source]
            with contextlib.suppress(Exception):
                writer.close()

    async def _handle(self, reader, writer, source) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT_SECONDS)
            host, port, headers = parse_request(head[:-4])
        except (
            RequestError,
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ) as exc:
            # Probing is visible: a refused request head is a decision like any other.
            _audit(Decision("denied", "bad_request", "operation"), source, None, None, _uuid7())
            await _reply(writer, getattr(exc, "status", 400), "bad_request")
            return
        correlation = correlation_id(headers)
        config = self.config
        upstream = config.upstream
        direct = upstream is None or any(
            host == h or host.endswith("." + h) for h in upstream.no_proxy
        )
        local = self.where()
        preliminary = decide(config, source, host, port, [], set(), local)
        addresses = []
        if preliminary.result == "allowed":
            addresses = await _resolve(host)
        decision = decide(
            config,
            source,
            host,
            port,
            addresses,
            self.protected_addresses,
            local,
            protected_complete=self.protected_complete,
        )
        if decision.result == "allowed" and not addresses and direct:
            decision = Decision("denied", "unresolvable", "operation")
        _audit(decision, source, host, port, correlation)
        if decision.result != "allowed":
            await _reply(writer, 403, decision.error_code, correlation)
            return
        try:
            if direct:
                remote = await _open_direct(addresses, port)
            else:
                targets = upstream_targets(host, addresses)
                remote = await _open_upstream_any(upstream, self.config_path.parent, targets, port)
        except (OSError, asyncio.TimeoutError, RequestError):
            await _reply(writer, 502, "upstream_failed", correlation)
            return
        await _reply(writer, 200, None, correlation)
        await _tunnel(reader, writer, *remote)


def _address_of(sockaddr):
    address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _audit(decision: Decision, source, host, port, correlation: str) -> None:
    print(json.dumps(audit_row(decision, source, host, port, correlation)), flush=True)


async def _reply(writer, status: int, error: str | None, correlation: str | None = None) -> None:
    reasons = {200: "Connection Established", 400: "Bad Request", 403: "Forbidden"}
    reasons.update({405: "Method Not Allowed", 502: "Bad Gateway", 503: "Service Unavailable"})
    lines = [f"HTTP/1.1 {status} {reasons[status]}"]
    if error:
        lines.append(f"X-Papaia-Error: {error}")
    if correlation:
        lines.append(f"X-Papaia-Correlation-Id: {correlation}")
    if status != 200:
        lines += ["Content-Length: 0", "Connection: close"]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()


async def _open_direct(addresses, port: int):
    last: Exception = OSError("no address")
    for address in addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(str(address), port), CONNECT_TIMEOUT_SECONDS
            )
        except (OSError, asyncio.TimeoutError) as exc:
            last = exc
    raise last


async def _open_upstream(upstream: Upstream, config_dir: Path, host: str, port: int):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(upstream.host, upstream.port), CONNECT_TIMEOUT_SECONDS
    )
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if upstream.user:
        password = (config_dir / PASSWORD_FILE).read_text(encoding="utf-8").rstrip("\r\n")
        token = base64.b64encode(f"{upstream.user}:{password}".encode()).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), CONNECT_TIMEOUT_SECONDS)
    status = head.split(b"\r\n", 1)[0].split(b" ")
    if len(status) < 2 or status[1] != b"200":
        writer.close()
        raise RequestError(502, "the corporate proxy refused the tunnel")
    return reader, writer


async def _open_upstream_any(upstream: Upstream, config_dir: Path, targets, port: int):
    """A tunnel through the corporate proxy to the first of `targets` it can reach."""
    last: Exception = OSError("no target")
    for target in targets:
        try:
            return await _open_upstream(upstream, config_dir, target, port)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, RequestError) as exc:
            last = exc
    raise last


async def _tunnel(
    client_reader, client_writer, remote_reader, remote_writer, idle=IDLE_TIMEOUT_SECONDS
) -> None:
    """Copy both directions until either side closes or no byte has moved in either
    direction for `idle` seconds; then close both sides."""
    last = [time.monotonic()]
    check = min(idle, 5)

    async def pipe(reader, writer) -> None:
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(65536), check)
                except asyncio.TimeoutError:
                    if time.monotonic() - last[0] >= idle:
                        break
                    continue
                if not data:
                    break
                last[0] = time.monotonic()
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    await asyncio.gather(pipe(client_reader, remote_writer), pipe(remote_reader, client_writer))


async def serve(config_path: Path, port: int) -> None:
    proxy = Proxy(config_path)
    proxy.load()
    server = await asyncio.start_server(proxy.handle, port=port, limit=MAX_HEADER_BYTES)
    _log(f"listening on port {port}")
    async with server:
        await asyncio.gather(server.serve_forever(), proxy.watch(), proxy.keep_protected())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    try:
        asyncio.run(serve(args.config, args.port))
    except OSError as exc:
        _log(f"cannot start: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
