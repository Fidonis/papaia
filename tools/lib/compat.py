"""Core-addon compatibility evaluation and gating.

The core declares the addon-contract window it serves in the static
`ADDON_API` file at the repo root (sibling of `VERSION`); addons declare
the generation they are built against via `requires.addon_api` in
papaia-app.yaml. Evaluation precedence per addon:

  1. `requires.addon_api` present and the core exposes a window
     -> integer window-intersection check (authoritative).
  2. else `papaia_compat` present and the core's platform version known
     -> SemVer range check (keeps pre-contract addons working).
  3. else -> UNKNOWN: warn, never hard-fail. A manifest that predates the
     contract cannot be allowed to break the install path, and this is
     what lets core and addon repos release independently.

Both resolvers read plain static files, so they work identically against
the running checkout and against an update candidate (`addon check
--target-core=PATH`, a git worktree or unpacked tarball).

Additionally, `networks.attach` entries are validated structurally against
the core compose's service names -- the one seam break that has actually
happened (a core service rename) is detectable without any version number.

`requires.addons` (addon_api 4) names other addons an addon builds on;
`evaluate_required_addons` checks it against the addons active in a
deployment.

From generation 7 on, a manifest key of a generation is never silently
ignored by an older core: `manifest_generation_features` lists the keys a
manifest uses, and a core whose window ends below one of them reports the
addon INCOMPATIBLE with the missing generation named, whatever
`requires.addon_api` lists.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import client_addresses, erasure_journal, exposes, semver

STATUS_OK = "OK"
STATUS_INCOMPATIBLE = "INCOMPATIBLE"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_ERROR = "ERROR"

# The binding meaning of every contract generation (all additive, `min` stays 1).
# The ADDON_API file carries the same table as a comment; the contract snapshot
# (tools/tests/test_contract_surface.py) pins both.
ADDON_API_GENERATIONS: dict[int, str] = {
    1: (
        "base contract: `networks.app_network`, `networks.attach`, `integration.<service>`"
        " fragments, Keycloak clients, `env_prompts`, `requires.addon_api`"
    ),
    2: "`networks.app_network` may be the `${PAPAIA_PROJECT:-papaia}-<name>-net` template",
    3: "`smtp-relay` (profile `smtp`) attachable",
    4: (
        "`requires.addons`, `networks.join_addons`, `exports`,"
        " `env_prompts.<key>.default_from_addon`, `actions`, LibreChat agents and prompts,"
        " managed Keycloak clients"
    ),
    5: (
        "`speaches` and `chatterbox` (profile `voice`) attachable, render target"
        " `ai/voice/chatterbox.yaml`"
    ),
    6: "`knowledge:` (ADR 0014)",
    7: (
        "`exposes:` (also `exposes.yaml` of core profiles), rendering of `services.json` and"
        " `groups.json`, declared roles, exchange scopes `aud-<addon>`, service accounts,"
        " `models.needs`; `keycloak`, `litellm`, `papaia-audit`, `papaia-egress` attachable"
        " (ADR 0017, 0018)"
    ),
    8: "`personal_settings:`; `me-web` and `prefs` attachable (ADR 0020)",
    9: "`connections` attachable, registry client (ADR 0021)",
    10: (
        "install-time approval hook: approval at install up to the highest declared class"
        " (ADR 0017 addendum)"
    ),
    11: "`pki:`, internal TLS under the `kritis` security profile (ADR 0019, 0022)",
    12: "add-on ingress `integration.nginx` (ADR 0023)",
    13: "`volumes[]` with `backup: include|exclude` and a reason, read by `backup`",
    14: (
        "reserved `actions` `erasure-replay` and `post-restore`, run by `restore` before the"
        " add-on starts"
    ),
    15: (
        "reserved `actions` `person-export`, `person-erase` and `transfer-ownership`, run by"
        " `papaia-ctl person export|erase`"
    ),
    16: "`networks.isolated`: internal add-on networks only `litellm` joins (ADR 0026)",
    17: (
        "`networks.join_addons[].network`: join the internal network a required add-on offers"
        " through an `exposes` entry instead of its `app_network` (ADR 0027)"
    ),
    18: (
        "`client_addresses`: the realm sync sets the sign-in addresses of a client the add-on"
        " owns as exact paths on its own interface (ADR 0028)"
    ),
}

# Manifest keys that need a core of at least this generation. A core below it
# would install the addon with the key unread, so the gate names the generation
# instead. `integration.nginx` counts only in its list form (ingress entries);
# the fragment-path form is generation 1.
GENERATION_FEATURES: dict[str, int] = {
    "exposes": 7,
    # The add-on's way out through papaia-egress (lib/egress.py).
    "networks.egress": 7,
    "personal_settings": 8,
    "pki": 11,
    "integration.nginx": 12,
    # A core below 13 would put a volume the add-on excludes (a key) into the backup.
    "volumes": 13,
    # A core below 14 would start a restored add-on without applying its erasure journal.
    "actions.erasure-replay": 14,
    "actions.post-restore": 14,
    # A core below 15 would install the add-on and never export or erase the data of a
    # person whose account is gone.
    "actions.person-export": 15,
    "actions.person-erase": 15,
    "actions.transfer-ownership": 15,
    # A core below 16 would start the add-on without putting LiteLLM on its isolated
    # network, and the service there would reach nothing at all.
    "networks.isolated": 16,
    # A core below 17 would read the entry without `network` and join the target's
    # app_network, where every route of its API is reachable.
    "networks.join_addons.network": 17,
    # A core below 18 would install the add-on and set none of its clients' sign-in
    # addresses, so nobody could sign in there without an entry by hand.
    "client_addresses": 18,
}

INGRESS_AXIS = "integration.nginx"
ISOLATED_AXIS = "networks.isolated"
JOIN_AXIS = "networks.join_addons"
ERASURE_JOURNAL_AXIS = "erasure_journal"
EXPOSES_AXIS = "exposes"
KNOWLEDGE_AXIS = "knowledge"
CLIENT_ADDRESSES_AXIS = client_addresses.KEY

MODE_ENFORCE = "enforce"
MODE_WARN = "warn"

# deployment.yaml speaks operator vocabulary (production/dev), the env var
# speaks policy vocabulary (enforce/warn); both map onto the same two modes.
_MODE_SYNONYMS = {
    "enforce": MODE_ENFORCE,
    "production": MODE_ENFORCE,
    "prod": MODE_ENFORCE,
    "warn": MODE_WARN,
    "dev": MODE_WARN,
    "development": MODE_WARN,
}


@dataclass(frozen=True)
class CoreTarget:
    """The compatibility-relevant surface of one core (current or candidate).

    Any field may be unknown (None): a manual `--target-version` knows no
    addon_api window, `--target-addon-api` knows no platform version, and a
    synthetic repo may ship no compose file. Unknown axes are skipped, never
    guessed."""

    platform_version: str | None = None
    addon_api: tuple[int, int] | None = None  # (min, current)
    services: dict[str, list[str]] | None = None  # service name -> profiles
    # Every name a core network can have (key, `name:`, `<project>_<key>`), addon_api 16.
    networks: frozenset[str] | None = None


@dataclass(frozen=True)
class CompatResult:
    name: str
    status: str
    axis: str | None = None
    requirement: object = None
    core_value: object = None
    reason: str | None = None
    warnings: tuple[str, ...] = ()


def resolve_addon_api_window(repo_root: Path) -> tuple[int, int] | None:
    """Read the served contract window from <repo_root>/ADDON_API as
    (min, current).

    Returns None when the file is absent (a core predating the contract, or
    a downgrade target) so callers skip the addon_api axis and fall back to
    `papaia_compat`. A present-but-malformed file raises ValueError: unlike
    an old core, a broken window declaration is a bug worth surfacing."""
    path = repo_root / "ADDON_API"
    if not path.is_file():
        return None
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.split("#", 1)[0].strip()
    try:
        current = int(values["current"])
        minimum = int(values.get("min", values["current"]))
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Malformed ADDON_API file: {path} ({exc})") from exc
    if minimum > current:
        raise ValueError(f"Malformed ADDON_API file: {path} (min {minimum} > current {current})")
    return (minimum, current)


def compose_files(root_compose: Path) -> list[Path]:
    doc = yaml.safe_load(root_compose.read_text(encoding="utf-8")) or {}
    files = [root_compose]
    for entry in doc.get("include") or []:
        if isinstance(entry, str):
            rel_paths = [entry]
        elif isinstance(entry, dict):
            path_value = entry.get("path")
            rel_paths = path_value if isinstance(path_value, list) else [path_value or ""]
        else:
            rel_paths = []
        files.extend(root_compose.parent / rel for rel in rel_paths if rel)
    return files


# Core services no add-on network may reach: the audit database is on
# papaia-audit-net only (docs/audit.md), like its one-shot schema step; add-ons deliver
# events to papaia-audit. The Docker socket broker shares its network with papaia-manager
# alone (docs/docker-gate.md). The preference database is on papaia-prefs-db-net with
# prefs alone; add-ons attach `prefs` (addon_api 8, ADR 0020). Add-ons attach the
# registry `connections` (addon_api 9), never its database or its init container.
NEVER_ATTACHABLE = frozenset(
    {
        "papaia-audit-db",
        "papaia-audit-schema",
        "papaia-docker-gate",
        "prefs-db",
        # The registry's database and the container holding its owner login (ADR 0021).
        "connections-db",
        "connections-migrate",
        # The edge's start gate check: only the proxy asks it (sicherheit §4.9 (2a)).
        "papaia-startgate-check",
        # The start gate's deletions in chat and gateway: papaia-lifecycle alone calls it.
        "papaia-replay",
        # The chat relay holds the chat token for one call: the chat alone calls it, and
        # the core alone decides which add-on networks it joins (ADR 0029).
        "papaia-chat-relay",
    }
)


# The core services an add-on may put on one of its isolated networks (addon_api 16,
# ADR 0026): the model gateway and nothing else. A service that reads foreign content
# runs there and must not reach the proxy, the identity provider, the audit store, the
# mail relay or anything of the add-on. The set is closed on purpose: widening it is a
# new contract generation with its own decision record.
ISOLATED_ATTACHABLE = frozenset({"litellm"})

_MAX_ISOLATED = 8
_ISOLATED_FIELDS = frozenset({"network", "attach"})
# Docker's own networks; no add-on network may take one of their names.
_DOCKER_NETWORKS = frozenset({"bridge", "host", "none"})
_DEFAULT_REF_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-([^}]*))?\}")


def _with_defaults(raw: str) -> str:
    """A compose network name with every `${VAR:-default}` replaced by its default and
    every bare `${VAR}` by nothing: the name on a host that sets none of them. Two
    declarations that agree here name the same network on every host."""
    return _DEFAULT_REF_RE.sub(lambda match: match.group(1) or "", raw)


def resolve_core_networks(repo_root: Path) -> frozenset[str] | None:
    """Every name a core network can have: its compose key, its `name:` with defaults,
    `papaia_<key>` (the name Compose gives it under the default project) and Docker's
    own networks. None when src/docker-compose.yml is absent, like
    `resolve_core_services`."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return None
    names = set(_DOCKER_NETWORKS) | {"papaia-net", "papaia_papaia-net"}
    for compose_path in compose_files(root_compose):
        if not compose_path.is_file():
            continue
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        networks = doc.get("networks") if isinstance(doc, dict) else None
        for key, config in (networks or {}).items() if isinstance(networks, dict) else ():
            names.update({str(key), f"papaia_{key}"})
            name = config.get("name") if isinstance(config, dict) else None
            if isinstance(name, str) and _with_defaults(name):
                names.add(_with_defaults(name))
    return frozenset(names)


def isolated_networks(
    manifest: dict, core_networks: frozenset[str] | None = None
) -> list[tuple[str, list[str]]]:
    """The `networks.isolated` entries (addon_api 16) as (network, [service, ...]), in
    manifest order; [] when the key is absent.

    Each entry is `{network, attach}` and nothing else. `network` follows the template
    rule of `app_network` (`${PAPAIA_PROJECT:-papaia}-<name>-...` or its literal
    default), is neither the add-on's `app_network` nor its egress network nor another
    entry's network nor a core network; `attach` lists services of
    ISOLATED_ATTACHABLE, at least one, each once. Raises ValueError naming the entry.
    Whether the add-on's compose file creates the network as internal is checked by
    `check_isolated_internal`, which needs the add-on's directory."""
    networks = manifest.get("networks")
    if networks is None:
        return []
    if not isinstance(networks, dict):
        raise ValueError("networks: must be a mapping")
    entries = networks.get("isolated")
    if entries is None:
        return []
    if not isinstance(entries, list) or not entries:
        raise ValueError("networks.isolated must be a non-empty list")
    if len(entries) > _MAX_ISOLATED:
        raise ValueError(f"networks.isolated must have at most {_MAX_ISOLATED} entries")
    name = manifest.get("name")
    if not isinstance(name, str) or not _REQUIREMENT_NAME_RE.match(name):
        raise ValueError("networks.isolated needs a valid add-on `name`")
    scoped = re.compile(
        r"^(?:\$\{PAPAIA_PROJECT:-papaia\}|papaia)-" + re.escape(name)
        + r"-[a-z0-9][a-z0-9_.-]{0,62}$"
    )
    taken: dict[str, str] = {}
    for key in ("app_network",):
        if isinstance(networks.get(key), str):
            taken[_with_defaults(networks[key])] = "the add-on's app_network"
    egress = networks.get("egress")
    if isinstance(egress, dict) and isinstance(egress.get("network"), str):
        taken[_with_defaults(egress["network"])] = "the add-on's egress network"
    core = (core_networks or frozenset()) | _DOCKER_NETWORKS | {"papaia-net"}
    result: list[tuple[str, list[str]]] = []
    for index, entry in enumerate(entries):
        where = f"networks.isolated[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} must be a mapping with `network` and `attach`")
        unknown = sorted(str(key) for key in set(entry) - _ISOLATED_FIELDS)
        if unknown:
            raise ValueError(f"{where} has unknown field(s): {', '.join(unknown)}")
        network = entry.get("network")
        if not isinstance(network, str) or not network:
            raise ValueError(f"{where}.network must be a network name")
        if not scoped.match(network):
            raise ValueError(
                f"{where}.network {network!r} must be scoped to the add-on:"
                f" ${{PAPAIA_PROJECT:-papaia}}-{name}-..."
            )
        resolved = _with_defaults(network)
        if resolved in core:
            raise ValueError(f"{where}.network {network!r} is a core network")
        if resolved in taken:
            raise ValueError(f"{where}.network {network!r} is {taken[resolved]}")
        attach = entry.get("attach")
        if not isinstance(attach, list) or not attach:
            raise ValueError(f"{where}.attach must list at least one service")
        if not all(isinstance(service, str) for service in attach):
            raise ValueError(f"{where}.attach must list service names")
        twice = sorted({service for service in attach if attach.count(service) > 1})
        if twice:
            raise ValueError(f"{where}.attach names {', '.join(twice)} twice")
        sealed = [service for service in attach if service in NEVER_ATTACHABLE]
        if sealed:
            raise ValueError(
                f"{where}: no add-on may attach " + ", ".join(f"'{s}'" for s in sealed)
            )
        outside = [service for service in attach if service not in ISOLATED_ATTACHABLE]
        if outside:
            raise ValueError(
                f"{where}: " + ", ".join(f"'{s}'" for s in outside)
                + " may not join an isolated network; only "
                + ", ".join(sorted(ISOLATED_ATTACHABLE)) + " may"
            )
        taken[resolved] = where
        result.append((network, list(attach)))
    return result


def check_isolated_internal(
    entries: list[tuple[str, list[str]]], addon_path: Path
) -> None:
    """The add-on's own compose file must create every isolated network with
    `internal: true` (and not as `external`), or the service on it would have a route
    out of the host. Raises ValueError naming the entry."""
    if not entries:
        return
    compose = addon_path / "docker-compose.yml"
    declared: dict[str, dict] = {}
    if compose.is_file():
        try:
            doc = yaml.safe_load(compose.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"{compose.name} is not valid YAML: {exc}") from None
        networks = doc.get("networks") if isinstance(doc, dict) else None
        for config in networks.values() if isinstance(networks, dict) else ():
            name = config.get("name") if isinstance(config, dict) else None
            if isinstance(name, str):
                declared.setdefault(_with_defaults(name), config)
    for index, (network, _) in enumerate(entries):
        config = declared.get(_with_defaults(network))
        if config is None or config.get("internal") is not True or config.get("external"):
            raise ValueError(
                f"networks.isolated[{index}]: the add-on's docker-compose.yml must create"
                f" the network {network!r} (as its `name:`) with internal: true"
            )


@dataclass(frozen=True)
class AddonJoin:
    """One `networks.join_addons` entry: the services of this add-on that join a network of
    the required add-on `addon`. `network` (addon_api 17) is the network the target offers
    through an `exposes` entry; None joins the target's `app_network` (addon_api 4)."""

    addon: str
    services: list[str]
    network: str | None
    index: int


_JOIN_FIELDS = frozenset({"addon", "services", "network"})
_JOIN_GENERATION = 17
_MAX_JOINS = 64


def _scoped_network_re(name: str) -> re.Pattern[str]:
    """The template rule of `app_network` for a network of add-on `name`:
    `${PAPAIA_PROJECT:-papaia}-<name>-...` or its literal default."""
    return re.compile(
        r"^(?:\$\{PAPAIA_PROJECT:-papaia\}|papaia)-" + re.escape(name)
        + r"-[a-z0-9][a-z0-9_.-]{0,62}$"
    )


def join_entries(
    manifest: dict, core_networks: frozenset[str] | None = None
) -> list[AddonJoin]:
    """The `networks.join_addons` entries, in manifest order; [] when the key is absent.

    Each entry is `{addon, services, network?}` and nothing else: `addon` names an add-on
    from `requires.addons`, `services` at least one service of this add-on. `network`
    (addon_api 17) follows the template rule of `app_network` for the target
    (`${PAPAIA_PROJECT:-papaia}-<target>-...`), is not a core network, and needs a manifest
    whose `requires.addon_api` names only generations from 17 on, so that an older core
    refuses the add-on instead of joining the target's `app_network`. Whether the target
    offers the network is checked by `check_join_offer`, which needs the target. Raises
    ValueError naming the entry."""
    networks = manifest.get("networks") or {}
    if not isinstance(networks, dict):
        raise ValueError("networks: must be a mapping")
    entries = networks.get("join_addons")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError("networks.join_addons must be a list")
    if len(entries) > _MAX_JOINS:
        raise ValueError(f"networks.join_addons must have at most {_MAX_JOINS} entries")
    required = {name for name, _ in required_addons(manifest)}
    core = (core_networks or frozenset()) | _DOCKER_NETWORKS | {"papaia-net"}
    result: list[AddonJoin] = []
    for index, entry in enumerate(entries):
        where = f"networks.join_addons[{index}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("addon"), str):
            raise ValueError("networks.join_addons entries must be mappings with 'addon'")
        unknown = sorted(str(key) for key in set(entry) - _JOIN_FIELDS)
        if unknown:
            raise ValueError(f"{where} has unknown field(s): {', '.join(unknown)}")
        target = entry["addon"]
        services = entry.get("services")
        if (
            not isinstance(services, list)
            or not services
            or not all(isinstance(s, str) and s for s in services)
        ):
            raise ValueError(
                f"networks.join_addons '{target}': services must be a non-empty list"
            )
        if target not in required:
            raise ValueError(
                f"networks.join_addons '{target}' is not listed in requires.addons"
            )
        network = entry.get("network")
        if "network" in entry:
            if not isinstance(network, str) or not network:
                raise ValueError(f"{where}.network must be a network name")
            if not _scoped_network_re(target).match(network):
                raise ValueError(
                    f"{where}.network {network!r} must be scoped to the add-on '{target}':"
                    f" ${{PAPAIA_PROJECT:-papaia}}-{target}-..."
                )
            if _with_defaults(network) in core:
                raise ValueError(f"{where}.network {network!r} is a core network")
            _require_join_generation(manifest, where)
        result.append(AddonJoin(target, list(services), network, index))
    offered = {join.addon for join in result if join.network is not None}
    for join in result:
        if join.network is None and join.addon in offered:
            # The app network carries every route of the target: joining it next to the
            # offered network would widen the join the other entry narrows.
            raise ValueError(
                f"networks.join_addons[{join.index}] joins the app_network of"
                f" '{join.addon}', which another entry joins through the network it offers"
            )
    return result


def _require_join_generation(manifest: dict, where: str) -> None:
    """An older core does not know `network` and would join the target's `app_network`.
    Only a manifest that names no generation below 17 is refused there by the gate."""
    requires = manifest.get("requires") or {}
    declared = requires.get("addon_api") if isinstance(requires, dict) else None
    try:
        generations = _normalize_generations(declared) if declared is not None else []
    except ValueError:
        generations = []
    if not generations or min(generations) < _JOIN_GENERATION:
        raise ValueError(
            f"{where}.network needs requires.addon_api to name only generations from"
            f" {_JOIN_GENERATION} on (for example [{_JOIN_GENERATION}]): an older core would"
            " otherwise join the app_network"
        )


def check_join_offer(
    join: AddonJoin, target_manifest: dict, target_path: Path
) -> None:
    """The target offers `join.network`: its compose file creates the network under that
    `name` with `internal: true` (not `external`), the `address.service` of one of its
    `exposes` entries joins it, and it is not the target's `app_network`, egress network
    or an isolated network. Raises ValueError naming the entry."""
    if join.network is None:
        return
    where = f"networks.join_addons[{join.index}]"
    wanted = _with_defaults(join.network)
    networks = target_manifest.get("networks") if isinstance(target_manifest, dict) else None
    networks = networks if isinstance(networks, dict) else {}
    if isinstance(networks.get("app_network"), str) and (
        _with_defaults(networks["app_network"]) == wanted
    ):
        raise ValueError(
            f"{where}.network {join.network!r} is the app_network of '{join.addon}';"
            " only a network it offers through an exposes entry may be joined"
        )
    egress = networks.get("egress")
    if isinstance(egress, dict) and isinstance(egress.get("network"), str) and (
        _with_defaults(egress["network"]) == wanted
    ):
        raise ValueError(f"{where}.network {join.network!r} is the egress network of"
                         f" '{join.addon}'")
    isolated = networks.get("isolated")
    for entry in isolated if isinstance(isolated, list) else ():
        if isinstance(entry, dict) and isinstance(entry.get("network"), str) and (
            _with_defaults(entry["network"]) == wanted
        ):
            raise ValueError(f"{where}.network {join.network!r} is an isolated network of"
                             f" '{join.addon}'")
    compose = target_path / "docker-compose.yml"
    doc: object = None
    if compose.is_file():
        try:
            doc = yaml.safe_load(compose.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            doc = None
    declared = doc.get("networks") if isinstance(doc, dict) else None
    key, config = None, None
    for candidate, body in declared.items() if isinstance(declared, dict) else ():
        name = body.get("name") if isinstance(body, dict) else None
        if isinstance(name, str) and _with_defaults(name) == wanted:
            key, config = candidate, body
            break
    if config is None:
        raise ValueError(
            f"{where}: the docker-compose.yml of '{join.addon}' does not create the network"
            f" {join.network!r} (as its `name:`)"
        )
    if config.get("internal") is not True or config.get("external"):
        raise ValueError(
            f"{where}: '{join.addon}' does not create the network {join.network!r} with"
            " internal: true"
        )
    services = doc.get("services") if isinstance(doc, dict) else None
    services = services if isinstance(services, dict) else {}
    for exposed in target_manifest.get("exposes") or ():
        address = exposed.get("address") if isinstance(exposed, dict) else None
        service = address.get("service") if isinstance(address, dict) else None
        body = services.get(service) if isinstance(service, str) else None
        joined = body.get("networks") if isinstance(body, dict) else None
        if isinstance(joined, (list, dict)) and key in joined:
            return
    raise ValueError(
        f"{where}: no exposes entry of '{join.addon}' has its address on the network"
        f" {join.network!r}; '{join.addon}' does not offer it"
    )


def resolve_core_services(repo_root: Path) -> dict[str, list[str]] | None:
    """Map every core compose service to its `profiles` list, walking the
    root compose's `include:` entries.

    Returns None when src/docker-compose.yml is absent (synthetic contexts
    such as minimal test repos), so callers skip the structural check
    instead of reporting false incompatibilities. A dangling include entry
    is tolerated: the remaining files still describe the core."""
    root_compose = repo_root / "src" / "docker-compose.yml"
    if not root_compose.is_file():
        return None
    services: dict[str, list[str]] = {}
    for compose_path in compose_files(root_compose):
        if not compose_path.is_file():
            continue
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        for name, service in (doc.get("services") or {}).items():
            profiles = (service or {}).get("profiles") or []
            services[name] = list(profiles)
    return services


def resolve_core_target(repo_root: Path) -> CoreTarget:
    """Snapshot one core checkout's compatibility surface. Works equally
    for the running checkout and for a `--target-core` candidate."""
    from . import envtree

    return CoreTarget(
        platform_version=envtree.resolve_platform_version(repo_root),
        addon_api=resolve_addon_api_window(repo_root),
        services=resolve_core_services(repo_root),
        networks=resolve_core_networks(repo_root),
    )


def resolve_mode(deployment: dict | None) -> str:
    """Gate policy precedence: PAPAIA_COMPAT_MODE env var, then
    deployment.yaml's `mode:`, then enforce. Unrecognized values fall
    through to the next source rather than failing a start path."""
    for candidate in (os.environ.get("PAPAIA_COMPAT_MODE"), (deployment or {}).get("mode")):
        if isinstance(candidate, str) and candidate.lower() in _MODE_SYNONYMS:
            return _MODE_SYNONYMS[candidate.lower()]
    return MODE_ENFORCE


def _normalize_generations(value: object) -> list[int]:
    items = value if isinstance(value, list) else [value]
    if not items:
        raise ValueError("requires.addon_api must not be empty")
    generations: list[int] = []
    for item in items:
        # bool is an int subclass; `addon_api: true` must still be rejected.
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"requires.addon_api entries must be integers, got {item!r}")
        generations.append(item)
    return sorted(set(generations))


def _join_features_beyond(manifest: dict, window_current: int) -> str:
    """The offered-network entries (generation 17) a core whose window ends at
    `window_current` cannot serve, named per entry; "" when there are none."""
    try:
        used = manifest_generation_features(manifest)
    except ValueError:
        return ""
    return ", ".join(
        f"`{key}` (addon_api {generation})"
        for key, generation in used
        if key.startswith("networks.join_addons[") and generation > window_current
    )


def _fmt_generations(generations: list[int]) -> str:
    return ",".join(str(g) for g in generations)


def _missing_generations(window_current: int, needed: list[int]) -> str:
    """'missing generation(s) <n, ...>; <n>: <meaning>' for the generations an addon
    needs above the core's window. Generations are cumulative, so every one between
    the window and the highest need is missing; the meaning is given for the
    generations the addon names."""
    top = max(needed)
    missing = list(range(window_current + 1, top + 1))
    label = "generation" if len(missing) == 1 else "generations"
    meanings = "; ".join(
        f"{generation}: {ADDON_API_GENERATIONS.get(generation, 'unknown to this core')}"
        for generation in sorted({g for g in needed if g > window_current})
    )
    return f"missing {label} {', '.join(str(g) for g in missing)}; {meanings}"


_HOST_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_SERVICE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
_MAX_BODY_RE = re.compile(r"^[1-9][0-9]{0,5}[kmg]?$")
_INGRESS_FIELDS = {"host_key", "service", "port", "websocket", "max_body"}


def _validate_ingress_entries(entries: list) -> None:
    """Shape of the generation-12 `integration.nginx` list. Raises ValueError."""
    if not entries:
        raise ValueError("integration.nginx must not be an empty list")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"integration.nginx[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} must be a mapping")
        unknown = sorted(str(key) for key in set(entry) - _INGRESS_FIELDS)
        if unknown:
            raise ValueError(f"{where} has unknown field(s): {', '.join(unknown)}")
        host_key = entry.get("host_key")
        if not isinstance(host_key, str) or not _HOST_KEY_RE.match(host_key):
            raise ValueError(f"{where}.host_key must match [a-z][a-z0-9-]*")
        if host_key in seen:
            raise ValueError(f"{where}.host_key '{host_key}' is declared twice")
        seen.add(host_key)
        service = entry.get("service")
        if not isinstance(service, str) or not _SERVICE_RE.match(service):
            raise ValueError(f"{where}.service must be a compose service name")
        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"{where}.port must be an integer from 1 to 65535")
        if not isinstance(entry.get("websocket", False), bool):
            raise ValueError(f"{where}.websocket must be true or false")
        max_body = entry.get("max_body")
        if max_body is not None and (
            not isinstance(max_body, str) or not _MAX_BODY_RE.match(max_body)
        ):
            raise ValueError(f"{where}.max_body must be a size such as 10m")


def manifest_generation_features(manifest: dict) -> list[tuple[str, int]]:
    """The generation-gated keys a manifest uses, as (key, generation) in
    GENERATION_FEATURES order. Raises ValueError for a malformed
    `integration.nginx`; the other keys are only detected here, their schema
    is checked where they are rendered."""
    used: list[tuple[str, int]] = []
    for key in ("exposes", "personal_settings", "pki", "volumes"):
        if manifest.get(key) is not None:
            used.append((key, GENERATION_FEATURES[key]))
    networks = manifest.get("networks")
    if isinstance(networks, dict) and networks.get("egress") is not None:
        used.append(("networks.egress", GENERATION_FEATURES["networks.egress"]))
    integration = manifest.get("integration")
    if integration is not None and not isinstance(integration, dict):
        raise ValueError("integration: must be a mapping")
    nginx = (integration or {}).get("nginx")
    if isinstance(nginx, list):
        _validate_ingress_entries(nginx)
        used.append(("integration.nginx", GENERATION_FEATURES["integration.nginx"]))
    elif nginx is not None and not isinstance(nginx, str):
        raise ValueError(
            "integration.nginx must be a fragment path or a list of ingress entries"
        )
    actions = manifest.get("actions")
    if isinstance(actions, dict):
        for name in (
            "erasure-replay", "post-restore", "person-export", "person-erase",
            "transfer-ownership",
        ):
            if name in actions:
                used.append((f"actions.{name}", GENERATION_FEATURES[f"actions.{name}"]))
    if isinstance(networks, dict) and networks.get("isolated") is not None:
        used.append(("networks.isolated", GENERATION_FEATURES["networks.isolated"]))
    joins = networks.get("join_addons") if isinstance(networks, dict) else None
    for index, entry in enumerate(joins if isinstance(joins, list) else ()):
        # Named per entry, so the generation gate names the entry it refuses.
        if isinstance(entry, dict) and "network" in entry:
            used.append((
                f"networks.join_addons[{index}].network",
                GENERATION_FEATURES["networks.join_addons.network"],
            ))
    if manifest.get(client_addresses.KEY) is not None:
        used.append((client_addresses.KEY, GENERATION_FEATURES[client_addresses.KEY]))
    return used


def evaluate_addon(
    name: str,
    manifest: object,
    core: CoreTarget,
    *,
    active_profiles: list[str] | None = None,
    addon_path: Path | None = None,
) -> CompatResult:
    """Evaluate one addon manifest against one core target.

    `addon_path` is the add-on's directory; with it, the add-on's compose file is
    checked for what the manifest promises about it (isolated networks are internal).

    Returns ERROR only for malformed manifests -- those are bugs, not
    policy calls, and `gate()` treats them as fatal even under --force."""
    if not isinstance(manifest, dict):
        return CompatResult(name, STATUS_ERROR, reason="papaia-app.yaml is not a mapping")

    requires = manifest.get("requires")
    if requires is not None and not isinstance(requires, dict):
        return CompatResult(name, STATUS_ERROR, reason="requires: must be a mapping")
    api_requirement = (requires or {}).get("addon_api")
    compat_range = manifest.get("papaia_compat")
    if compat_range is not None and not isinstance(compat_range, str):
        return CompatResult(name, STATUS_ERROR, reason="papaia_compat: must be a string range")

    generations: list[int] | None = None
    if api_requirement is not None:
        try:
            generations = _normalize_generations(api_requirement)
        except ValueError as exc:
            return CompatResult(name, STATUS_ERROR, reason=str(exc))

    status = STATUS_UNKNOWN
    axis: str | None = None
    requirement: object = None
    core_value: object = None
    reason: str | None = None

    if generations is not None and core.addon_api is not None:
        window_min, window_current = core.addon_api
        axis = "addon_api"
        requirement = generations
        core_value = [window_min, window_current]
        if any(window_min <= generation <= window_current for generation in generations):
            status = STATUS_OK
        else:
            status = STATUS_INCOMPATIBLE
            if all(generation < window_min for generation in generations):
                reason = (
                    f"core no longer serves addon_api {_fmt_generations(generations)}"
                    f" (min {window_min})"
                )
            else:
                reason = (
                    f"core serves addon_api [{window_min}..{window_current}], addon is built"
                    f" against {_fmt_generations(generations)}; "
                    + _missing_generations(window_current, generations)
                )
                beyond = _join_features_beyond(manifest, window_current)
                if beyond:
                    reason += "; addon uses " + beyond
    elif compat_range is not None and core.platform_version is not None:
        axis = "papaia_compat"
        requirement = compat_range
        core_value = core.platform_version
        try:
            # A pre-release core (1.10.0-rc.1) is the candidate of its release and serves
            # the add-ons of that release, as the suite matrix judges it (suite.matrix_rows).
            if semver.satisfies(semver.release_of(core.platform_version), compat_range):
                status = STATUS_OK
            else:
                status = STATUS_INCOMPATIBLE
                reason = (
                    f"core version {core.platform_version} does not satisfy '{compat_range}'"
                )
        except ValueError as exc:
            return CompatResult(
                name, STATUS_ERROR, axis="papaia_compat", requirement=compat_range,
                reason=str(exc),
            )
    elif generations is not None or compat_range is not None:
        reason = (
            "core does not expose an addon_api window"
            if generations is not None and compat_range is None
            else "core platform version unknown; papaia_compat range not evaluated"
        )
    else:
        reason = "manifest declares no compatibility requirement"

    try:
        addon_actions(manifest)
    except ValueError as exc:
        return CompatResult(name, STATUS_ERROR, axis="actions", reason=str(exc))

    try:
        features = manifest_generation_features(manifest)
    except ValueError as exc:
        return CompatResult(name, STATUS_ERROR, axis=INGRESS_AXIS, reason=str(exc))

    # The section the catalog is rendered from (generation 7): a declaration the kit
    # schema refuses is a malformed manifest, whatever the core serves.
    if manifest.get("exposes") is not None:
        try:
            exposes.check(manifest["exposes"], name)
        except exposes.ExposesError as exc:
            return CompatResult(name, STATUS_ERROR, axis=EXPOSES_AXIS, reason=str(exc))
        try:
            exposes.check_key_tools(manifest.get("knowledge"), manifest["exposes"], name)
        except exposes.ExposesError as exc:
            return CompatResult(name, STATUS_ERROR, axis=KNOWLEDGE_AXIS, reason=str(exc))

    # Isolated networks (generation 16): a declaration that would widen the isolation is
    # a malformed manifest, whatever the core serves, so not even --force lets it in.
    try:
        isolated = isolated_networks(manifest, core.networks)
        if addon_path is not None:
            check_isolated_internal(isolated, addon_path)
    except ValueError as exc:
        return CompatResult(name, STATUS_ERROR, axis=ISOLATED_AXIS, reason=str(exc))

    # Offered networks (generation 17): an entry that names a core network, a network not
    # scoped to its target, or a manifest an older core would read as a join of the
    # target's app_network is malformed. Whether the target offers the network is checked
    # against the target (cli_addon.join_offer_result).
    try:
        join_entries(manifest, core.networks)
    except ValueError as exc:
        return CompatResult(name, STATUS_ERROR, axis=JOIN_AXIS, reason=str(exc))

    # Sign-in addresses (generation 18): a client the add-on does not own, a core client, a
    # client that signs nobody in through the browser, an unknown host key or a path that
    # is not exact is a malformed manifest, whatever the core serves.
    try:
        client_addresses.check_manifest(manifest, name)
    except client_addresses.ClientAddressError as exc:
        return CompatResult(name, STATUS_ERROR, axis=CLIENT_ADDRESSES_AXIS, reason=str(exc))

    # The erasure journals at the backup target (PLT-66): the core alone mounts them, each
    # module its own file. A compose file that mounts the target would let the add-on write
    # the journal of another module, so not even --force lets it in.
    if addon_path is not None:
        mounts = erasure_journal.compose_problems(addon_path)
        if mounts:
            return CompatResult(
                name, STATUS_ERROR, axis=ERASURE_JOURNAL_AXIS,
                reason="the backup target and its erasure journals are mounted by the core"
                " only (each module gets its own journal file); write refused: "
                + "; ".join(mounts),
            )

    warnings: list[str] = []
    if isolated and addon_path is None:
        warnings.append(
            "networks.isolated: internal: true not checked without the add-on's directory"
        )
    if features and generations is not None:
        for key, generation in features:
            if generation > max(generations):
                warnings.append(
                    f"`{key}` needs addon_api {generation}, but requires.addon_api names"
                    f" only {_fmt_generations(generations)}"
                )
    if features and core.addon_api is None:
        warnings.extend(
            f"core does not expose an addon_api window; `{key}` (addon_api {generation})"
            " not checked"
            for key, generation in features
        )
    elif features and status in (STATUS_OK, STATUS_UNKNOWN):
        window_min, window_current = core.addon_api
        beyond = [(key, generation) for key, generation in features if generation > window_current]
        if beyond:
            needed = [generation for _, generation in beyond]
            status = STATUS_INCOMPATIBLE
            axis = "addon_api"
            requirement = sorted(set(needed))
            core_value = [window_min, window_current]
            uses = ", ".join(f"`{key}` (addon_api {generation})" for key, generation in beyond)
            reason = (
                f"addon uses {uses}; core serves addon_api [{window_min}..{window_current}]; "
                + _missing_generations(window_current, needed)
            )

    attach = (manifest.get("networks") or {}).get("attach") or []
    if attach and not isinstance(attach, list):
        return CompatResult(name, STATUS_ERROR, reason="networks.attach must be a list")
    if attach and core.services is not None and status in (STATUS_OK, STATUS_UNKNOWN):
        unknown = [service for service in attach if service not in core.services]
        sealed = [service for service in attach if service in NEVER_ATTACHABLE]
        if sealed:
            status = STATUS_INCOMPATIBLE
            axis = "attach"
            requirement = list(attach)
            core_value = None
            reason = "no add-on may attach " + ", ".join(f"'{service}'" for service in sealed)
        elif unknown:
            status = STATUS_INCOMPATIBLE
            axis = "attach"
            requirement = list(attach)
            core_value = None
            reason = "core has no service " + ", ".join(f"'{service}'" for service in unknown)
        elif active_profiles is not None:
            active = set(active_profiles)
            for service in attach:
                profiles = core.services.get(service) or []
                if profiles and not active.intersection(profiles):
                    warnings.append(
                        f"service '{service}' belongs to inactive profile(s):"
                        f" {', '.join(profiles)}"
                    )

    return CompatResult(
        name,
        status,
        axis=axis,
        requirement=requirement,
        core_value=core_value,
        reason=reason,
        warnings=tuple(warnings),
    )


REQUIRES_AXIS = "requires"

_ACTION_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def addon_actions(manifest: dict) -> dict[str, dict]:
    """The `actions` block (addon_api 4) as {name: {service, args, description,
    destructive}}.

    Each action names a service of the addon's own compose file and optional fixed
    string arguments; `destructive: true` asks callers such as papaia-manager to
    confirm before running it. Raises ValueError for a malformed block."""
    actions = manifest.get("actions")
    if actions is None:
        return {}
    if not isinstance(actions, dict):
        raise ValueError("actions: must be a mapping")
    result: dict[str, dict] = {}
    for name, spec in actions.items():
        if not isinstance(name, str) or not _ACTION_NAME_RE.match(name):
            raise ValueError(f"actions: '{name}' is not a valid name (a-z, 0-9, -)")
        if not isinstance(spec, dict) or not isinstance(spec.get("service"), str):
            raise ValueError(f"actions.{name}: needs a 'service'")
        args = spec.get("args") or []
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError(f"actions.{name}.args must be a list of strings")
        description = spec.get("description") or ""
        if not isinstance(description, str):
            raise ValueError(f"actions.{name}.description must be a string")
        destructive = spec.get("destructive", False)
        if not isinstance(destructive, bool):
            raise ValueError(f"actions.{name}.destructive must be true or false")
        result[name] = {
            "service": spec["service"],
            "args": list(args),
            "description": description,
            "destructive": destructive,
        }
    return result


@dataclass(frozen=True)
class Requirement:
    """One `requires.addons` entry. An `optional` one is a soft dependency: the add-on
    runs without it and only loses what the other one adds (Studio -> Data)."""

    name: str
    version: str | None = None
    optional: bool = False


_REQUIREMENT_KEYS = frozenset({"name", "id", "version", "optional"})
_REQUIREMENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def addon_requirements(manifest: dict) -> list[Requirement]:
    """The `requires.addons` entries of a manifest.

    An entry is a name or a mapping with `name` (or `id`, the platform kit's word for
    it), an optional SemVer `version` range and `optional: true|false`. Unknown keys
    are refused. Raises ValueError for a malformed list, entry or range."""
    requires = manifest.get("requires") or {}
    if not isinstance(requires, dict):
        raise ValueError("requires: must be a mapping")
    entries = requires.get("addons")
    if entries is None:
        return []
    if not isinstance(entries, list) or len(entries) > 64:
        raise ValueError("requires.addons must be a list of at most 64 entries")
    malformed = "requires.addons entries must be a name or a mapping with 'name'"
    result: list[Requirement] = []
    for entry in entries:
        if isinstance(entry, str):
            if not _REQUIREMENT_NAME_RE.match(entry):
                raise ValueError(malformed)
            result.append(Requirement(entry))
            continue
        if not isinstance(entry, dict):
            raise ValueError(malformed)
        unknown = sorted(str(key) for key in entry if key not in _REQUIREMENT_KEYS)
        if unknown:
            raise ValueError(f"requires.addons: unknown field {', '.join(unknown)}")
        if "name" in entry and "id" in entry:
            raise ValueError("requires.addons entries name an add-on by 'name' or 'id', not both")
        name = entry.get("name", entry.get("id"))
        if not isinstance(name, str) or not _REQUIREMENT_NAME_RE.match(name):
            raise ValueError(malformed)
        version = entry.get("version")
        if version is not None:
            if not isinstance(version, str):
                raise ValueError(f"requires.addons '{name}': version must be a string")
            semver.parse_constraint(version)
        optional = entry.get("optional", False)
        if not isinstance(optional, bool):
            raise ValueError(f"requires.addons '{name}': optional must be true or false")
        result.append(Requirement(name, version, optional))
    return result


def required_addons(manifest: dict) -> list[tuple[str, str | None]]:
    """The `requires.addons` entries of a manifest as (name, version range or None),
    optional ones included. Raises ValueError for a malformed list, entry or range."""
    return [(r.name, r.version) for r in addon_requirements(manifest)]


def joined_addons(manifest: dict) -> list[tuple[str, list[str]]]:
    """The `networks.join_addons` entries as (addon, [service, ...]), whichever network
    each joins (`join_entries` tells them apart).

    Each entry names an addon from `requires.addons` and the services of this
    addon that join a network of that addon. Raises ValueError for a malformed
    entry or an addon that is not required."""
    return [(join.addon, list(join.services)) for join in join_entries(manifest)]


def evaluate_required_addons(
    name: str, manifest: dict, active: dict[str, str | None]
) -> CompatResult | None:
    """Check `requires.addons` against the active addons of a deployment.

    `active` maps each active addon's name to its version (None when unknown).
    Returns None when the manifest requires nothing or every requirement is met;
    an ERROR result for a malformed field; otherwise an INCOMPATIBLE result naming
    what is missing. A requirement on a version the active addon does not state
    passes with a warning."""
    try:
        requirements = addon_requirements(manifest)
        joined_addons(manifest)
    except ValueError as exc:
        return CompatResult(name, STATUS_ERROR, axis=REQUIRES_AXIS, reason=str(exc))
    if not requirements:
        return None
    problems: list[str] = []
    warnings: list[str] = []
    for requirement in requirements:
        required, version_range = requirement.name, requirement.version
        if required not in active:
            if requirement.optional:
                # A soft dependency: the add-on runs, what the other one adds is off.
                warnings.append(
                    f"optional add-on '{required}' is not installed and active;"
                    f" '{name}' runs without what it adds"
                )
            else:
                problems.append(f"add-on '{required}' is not installed and active")
            continue
        if version_range is None:
            continue
        version = active[required]
        if version is None:
            warnings.append(
                f"add-on '{required}' states no version; '{version_range}' not checked"
            )
            continue
        try:
            ok = semver.satisfies(version, version_range)
        except ValueError:
            warnings.append(
                f"add-on '{required}' has version '{version}'; '{version_range}' not checked"
            )
            continue
        if not ok:
            problems.append(
                f"add-on '{required}' {version} does not satisfy '{version_range}'"
            )
    if not problems and not warnings:
        return None
    return CompatResult(
        name,
        STATUS_INCOMPATIBLE if problems else STATUS_OK,
        axis=REQUIRES_AXIS,
        requirement=[
            (r.name if r.version is None else f"{r.name} {r.version}")
            + (" (optional)" if r.optional else "")
            for r in requirements
        ],
        reason="; ".join(problems) if problems else None,
        warnings=tuple(warnings),
    )


def dependency_order(names: list[str], manifests: dict[str, dict]) -> list[str]:
    """`names` with every add-on after the add-ons it requires, optional ones included
    (Data before Studio), otherwise in the given order. A malformed `requires.addons`
    counts as requiring nothing, and a cycle keeps the given order for the add-ons in
    it: the order is a preference of `start` and `upgrade`, the gate refuses the rest."""
    present = set(names)
    needs: dict[str, set[str]] = {}
    for name in names:
        try:
            requirements = addon_requirements(manifests.get(name) or {})
        except ValueError:
            requirements = []
        needs[name] = {r.name for r in requirements if r.name in present and r.name != name}
    ordered: list[str] = []
    placed: set[str] = set()
    remaining = list(names)
    while remaining:
        ready = [n for n in remaining if needs[n] <= placed]
        if not ready:
            ready = remaining[:1]  # a cycle: take the next one as given
        for name in ready:
            ordered.append(name)
            placed.add(name)
        remaining = [n for n in remaining if n not in placed]
    return ordered


def gate(results: list[CompatResult], *, mode: str, force: bool = False) -> int:
    """Exit code (0 or 2) for a set of results under the given policy.

    ERROR is always fatal -- a malformed manifest is a bug, not a policy
    call, so not even --force degrades it. INCOMPATIBLE is fatal in enforce
    mode unless --force (or warn mode) degrades it. UNKNOWN never fails: a
    manifest predating the contract cannot break anything."""
    exit_code = 0
    for result in results:
        if result.status == STATUS_ERROR:
            return 2
        if result.status == STATUS_INCOMPATIBLE and mode != MODE_WARN and not force:
            exit_code = 2
    return exit_code


def _fmt_requirement(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _fmt_core_value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return f"[{value[0]}..{value[1]}]"
    return str(value)


def format_table(results: list[CompatResult], *, core_label: str = "CORE") -> str:
    """Render results as an aligned table; reasons and warnings become
    indented continuation lines under their row."""
    header = ("ADDON", "AXIS", "REQUIRES", core_label, "STATUS")
    rows = [
        (
            result.name,
            result.axis or "-",
            _fmt_requirement(result.requirement),
            _fmt_core_value(result.core_value),
            result.status,
        )
        for result in results
    ]
    widths = [
        max(len(header[column]), *(len(row[column]) for row in rows))
        if rows
        else len(header[column])
        for column in range(len(header))
    ]
    lines = ["  ".join(header[i].ljust(widths[i]) for i in range(len(header))).rstrip()]
    for result, row in zip(results, rows, strict=True):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(row))).rstrip())
        if result.reason:
            lines.append(f"  reason: {result.reason}")
        for warning in result.warnings:
            lines.append(f"  warning: {warning}")
    return "\n".join(lines)


def to_json(results: list[CompatResult]) -> str:
    return json.dumps(
        [
            {
                "name": result.name,
                "axis": result.axis,
                "requirement": result.requirement,
                "core_value": result.core_value,
                "status": result.status,
                "reason": result.reason,
            }
            for result in results
        ]
    )
