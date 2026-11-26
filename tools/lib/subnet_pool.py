"""The address range of the installation's Docker networks (`setup --subnet-pool=CIDR`).

Without a range of their own, Docker gives every network a block of its default address
pools. On a host whose default pools overlap the company network the operator could only
change the Docker daemon, which restarts every container on the host. With
`PAPAIA_SUBNET_POOL` (a private IPv4 range, docs/network.md) papaia-ctl places every
network of the installation in that range instead:

  * The pool is cut into blocks of `/PAPAIA_SUBNET_BLOCK` (default /24). The networks of
    the core's Compose project take the first blocks in the fixed order of
    CORE_NETWORKS, so the address of a network never depends on what else is installed.
  * Every other network gets the lowest free block once and keeps it: the networks the
    core's own overrides declare (the exits of LiteLLM, papaia-audit and papaia-lifecycle)
    and the networks an active add-on's compose file creates without a range of its own
    (its app, egress and isolated networks, ADR 0026, and the networks it offers, ADR
    0027). These assignments are kept in $PAPAIA_CONFIG_DIR/subnet-pool.json; an
    add-on's blocks are freed when it leaves deployment.yaml.
  * The blocks reach Compose through generated overrides: one beside the image mirror
    override for the core project, one per add-on in overrides/addons/. A network that
    declares its own range (`ipam` in an add-on's or the core's files; the SQL uplink with
    PAPAIA_SQL_UPLINK_SUBNET) keeps it and never counts as outside the pool; the render
    refuses such a range of the core or of an active add-on that overlaps an assigned
    block. The block of a core exit is freed when the exit is switched off.
  * `setup` and `start` refuse a pool that overlaps a Docker network of the host that does
    not belong to this installation and name it; a network of the installation outside
    the pool (after the pool changed) has to be removed: `stop --clean-up --addons`, then
    `start`. papaia-ctl never removes or changes a network that is not its own.

Without the variable nothing is written and Docker's default pools apply as before.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterable
from pathlib import Path

import yaml

from . import backup, common, compat, deployment, status

POOL_KEY = "PAPAIA_SUBNET_POOL"
BLOCK_KEY = "PAPAIA_SUBNET_BLOCK"
DEFAULT_BLOCK = 24
_BLOCKS = range(24, 29)
_MIN_POOL_PREFIX = 8
# A pool holds at least 16 blocks: /20 for blocks of /24.
_SPARE_BITS = 4
_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
OVERRIDE = "docker-compose.subnet-pool.override.yml"
ADDON_SUFFIX = "subnets"
STATE_FILE = "subnet-pool.json"
STATE_FORMAT = "papaia.subnet-pool/1"
PROJECT_LABEL = "com.docker.compose.project"
RELAY_SERVICE = "smtp-relay"
RELAY_CLIENTS_KEY = "SMTP_RELAY_ALLOWED_CLIENTS"
DOCKER_TIMEOUT_SECONDS = 30

# The networks of the core's Compose project, in the order of their blocks. Append only:
# a reordered or removed entry moves the networks of every installation that has a pool.
CORE_NETWORKS = (
    "papaia-net",
    "papaia-egress-net",
    "papaia-audit-net",
    "papaia-audit-ingest-net",
    "papaia-audit-idp-net",
    "papaia-lifecycle-net",
    "papaia-replay-net",
    "papaia-replay-chat-net",
    "papaia-replay-gw-net",
    "papaia-chat-relay-net",
    "papaia-docker-gate-net",
    "papaia-prefs-db-net",
    "papaia-connections-net",
    "papaia-connections-db-net",
)

_INSPECT_FORMAT = (
    "{{.Name}}\t{{index .Labels \"" + PROJECT_LABEL + "\"}}\t"
    "{{range .IPAM.Config}}{{.Subnet}} {{end}}"
)

Runner = Callable[..., status.CommandResult]
# The injection point of the tests; `docker` otherwise.
run: Runner = status.run_command


class SubnetPoolError(ValueError):
    """A range setting that cannot be used, or a pool too small; nothing is rendered."""


# ─────────────────────────────────────────────────────────────────────────
# the values
# ─────────────────────────────────────────────────────────────────────────


def parse_block(raw: object) -> int:
    """The prefix length of one block: 24 to 28."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text.isdigit() or int(text) not in _BLOCKS:
        raise SubnetPoolError(
            f"{BLOCK_KEY}: the block size is a prefix length from 24 to 28, not {raw!r}"
        )
    return int(text)


def parse_pool(raw: object, block: int) -> ipaddress.IPv4Network:
    """The pool: an IPv4 range in CIDR form (network address, no host bits) inside
    10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16, from /8 to the size that holds 16
    blocks (/20 for blocks of /24)."""
    text = raw if isinstance(raw, str) else ""
    try:
        if not text or text != text.strip() or "/" not in text:
            raise ValueError
        net = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise SubnetPoolError(
            f"{POOL_KEY}: not an address range in CIDR form: {raw!r}"
        ) from None
    if not isinstance(net, ipaddress.IPv4Network):
        raise SubnetPoolError(f"{POOL_KEY}: {text} is not an IPv4 range")
    largest = block - _SPARE_BITS
    if not _MIN_POOL_PREFIX <= net.prefixlen <= largest:
        raise SubnetPoolError(
            f"{POOL_KEY}: {text} must have a prefix from /{_MIN_POOL_PREFIX} to /{largest}"
            f" (at least {2 ** _SPARE_BITS} blocks of /{block})"
        )
    if not any(net.subnet_of(p) for p in _PRIVATE):
        raise SubnetPoolError(
            f"{POOL_KEY}: {text} is not a private range (inside 10.0.0.0/8, 172.16.0.0/12"
            " or 192.168.0.0/16)"
        )
    return net


def settings(env: dict[str, str]) -> tuple[ipaddress.IPv4Network, int] | None:
    """(pool, block size) of the root .env, or None without a pool."""
    raw = (env.get(POOL_KEY) or "").strip()
    if not raw:
        return None
    block_raw = (env.get(BLOCK_KEY) or "").strip()
    block = parse_block(block_raw) if block_raw else DEFAULT_BLOCK
    return parse_pool(raw, block), block


def blocks(pool: ipaddress.IPv4Network, block: int) -> list[ipaddress.IPv4Network]:
    return list(pool.subnets(new_prefix=block))


def core_subnet(env: dict[str, str], key: str) -> str | None:
    """The block of the core network `key` (one of CORE_NETWORKS), or None without a
    pool. Depends on the pool alone, so a render can name it before the overrides exist."""
    found = settings(env)
    if found is None:
        return None
    return str(blocks(*found)[CORE_NETWORKS.index(key)])


def project(env: dict[str, str]) -> str:
    return env.get("COMPOSE_PROJECT_NAME") or env.get("PAPAIA_PROJECT") or "papaia"


# ─────────────────────────────────────────────────────────────────────────
# the networks to place
# ─────────────────────────────────────────────────────────────────────────


def _load_yaml(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _created(doc: dict) -> list[str]:
    """The networks a compose document creates without a range of its own: neither
    `external` nor with `ipam`."""
    found = []
    for key, body in (doc.get("networks") or {}).items():
        body = body if isinstance(body, dict) else {}
        if body.get("external") or body.get("ipam"):
            continue
        found.append(str(key))
    return found


def _own(doc: dict, env: dict[str, str], project_name: str) -> list[dict]:
    """[{key, name, subnets}] of the networks a compose document creates with a range of
    its own (`ipam`, not `external`): the Docker name as Compose gives it and the IPv4
    ranges, `${VAR}` resolved against `env` the way Compose does."""
    found = []
    for key, body in (doc.get("networks") or {}).items():
        if not isinstance(body, dict) or body.get("external") or not body.get("ipam"):
            continue
        ipam = body["ipam"] if isinstance(body["ipam"], dict) else {}
        subnets = []
        for entry in ipam.get("config") or []:
            raw = entry.get("subnet") if isinstance(entry, dict) else None
            if not isinstance(raw, str):
                continue
            try:
                net = ipaddress.ip_network(backup.expand(raw, env).strip(), strict=False)
            except ValueError:
                continue  # Compose refuses it when it creates the network
            if isinstance(net, ipaddress.IPv4Network):
                subnets.append(net)
        name = body.get("name")
        found.append({
            "key": str(key),
            "name": backup.expand(name, env) if isinstance(name, str) and name
            else f"{project_name}_{key}",
            "subnets": subnets,
        })
    return found


def _uses_default(doc: dict) -> bool:
    """Whether a service of the document is on the project's `default` network."""
    for body in (doc.get("services") or {}).values():
        if not isinstance(body, dict) or body.get("network_mode"):
            continue
        networks = body.get("networks")
        if not networks or "default" in networks:
            return True
    return False


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def core_keys(config_dir: Path, repo_root: Path) -> list[str]:
    """The networks of the core's Compose project: its fragments, then the networks the
    core's overrides add (this module's own override aside)."""
    keys: list[str] = []
    root = repo_root / "src" / "docker-compose.yml"
    if root.is_file():
        for path in compat.compose_files(root):
            doc = _load_yaml(path)
            keys += _created(doc)
            if _uses_default(doc):
                keys.append("default")
    folder = config_dir / "overrides"
    if folder.is_dir():
        for path in sorted(folder.glob("docker-compose.*.override.yml")):
            if path.name != OVERRIDE:
                keys += _created(_load_yaml(path))
    return _unique(keys)


def addon_override_path(config_dir: Path, name: str) -> Path:
    return config_dir / deployment.ADDON_OVERRIDES / (
        f"docker-compose.{name}-{ADDON_SUFFIX}.override.yml"
    )


def addon_keys(config_dir: Path, repo_root: Path, addon: dict, deployed: dict) -> list[str]:
    """The networks the add-on's project creates without a range of its own: its compose
    file and the files of overrides/addons/ that belong to it."""
    name = str(addon["name"])
    path = deployment.resolve_addon_path(addon, repo_root)
    doc = _load_yaml(path / "docker-compose.yml")
    keys = _created(doc)
    if doc and _uses_default(doc):
        keys.append("default")
    own = addon_override_path(config_dir, name)
    for file in deployment.addon_override_files(config_dir, name, deployed):
        if file != own:
            keys += _created(_load_yaml(file))
    return _unique(keys)


def addon_env(config_dir: Path, addon_path: Path) -> dict[str, str]:
    """What Compose interpolates an add-on's files with: the root .env, then the add-on's
    own .env (lib/sh/addon.sh passes both, the add-on's second)."""
    env = common.parse_env_file(config_dir / ".env")
    env.update(common.parse_env_file(addon_path / ".env"))
    return env


def own_networks(
    config_dir: Path, repo_root: Path, *, active_only: bool, deployed: dict | None = None
) -> list[dict]:
    """[{owner, key, name, subnets}] of the networks with a range of their own: those of
    the core's fragments and overrides (owner "core") and those of the add-ons'
    compose files and overrides (owner "addon:<name>"; with `active_only` the active
    add-ons only). They keep their range and are not placed in the pool."""
    deployed = deployment.load(config_dir) if deployed is None else deployed
    env = common.parse_env_file(config_dir / ".env")
    found: list[dict] = []
    files: list[Path] = []
    root = repo_root / "src" / "docker-compose.yml"
    if root.is_file():
        files += compat.compose_files(root)
    folder = config_dir / "overrides"
    if folder.is_dir():
        files += [p for p in sorted(folder.glob("docker-compose.*.override.yml"))
                  if p.name != OVERRIDE]
    for path in files:
        found += [{"owner": "core", **n} for n in _own(_load_yaml(path), env, project(env))]
    for addon in _addons(deployed):
        if active_only and not addon.get("active"):
            continue
        name = addon["name"]
        path = deployment.resolve_addon_path(addon, repo_root)
        values = addon_env(config_dir, path)
        own = addon_override_path(config_dir, name)
        docs = [path / "docker-compose.yml"] + [
            f for f in deployment.addon_override_files(config_dir, name, deployed) if f != own
        ]
        for file in docs:
            found += [
                {"owner": f"addon:{name}", **n}
                for n in _own(_load_yaml(file), values, path.name)
            ]
    return found


def _addons(deployed: dict) -> list[dict]:
    return [
        a for a in deployed.get("addons") or []
        if isinstance(a, dict) and isinstance(a.get("name"), str) and a["name"] and a.get("path")
    ]


# ─────────────────────────────────────────────────────────────────────────
# the assignment
# ─────────────────────────────────────────────────────────────────────────


def _load_state(config_dir: Path, pool: ipaddress.IPv4Network, block: int) -> dict[str, str]:
    """The kept assignments, or {} when there are none for this pool and block size."""
    path = config_dir / STATE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if (
        not isinstance(data, dict)
        or data.get("format") != STATE_FORMAT
        or data.get("pool") != str(pool)
        or data.get("block") != block
        or not isinstance(data.get("networks"), dict)
    ):
        return {}
    return {str(k): str(v) for k, v in data["networks"].items()}


def plan(
    config_dir: Path,
    repo_root: Path,
    pool: ipaddress.IPv4Network,
    block: int,
    env: dict[str, str],
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """({"core" | "addon:<name>": {network key: subnet}}, kept assignments) for the files
    as they are now. SubnetPoolError when the pool is too small or a block would overlap
    the SQL uplink."""
    deployed = deployment.load(config_dir)
    every = blocks(pool, block)
    placed: dict[str, dict[str, str]] = {"core": {}}
    used: set[ipaddress.IPv4Network] = set()
    for index, key in enumerate(CORE_NETWORKS):
        placed["core"][key] = str(every[index])
        used.add(every[index])

    wanted: list[tuple[str, str, str]] = []  # (id, owner, key)
    for key in core_keys(config_dir, repo_root):
        if key not in CORE_NETWORKS:
            wanted.append((f"core:{key}", "core", key))
    installed = set()
    for addon in _addons(deployed):
        name = addon["name"]
        installed.add(name)
        if not addon.get("active"):
            continue
        for key in addon_keys(config_dir, repo_root, addon, deployed):
            wanted.append((f"addon:{name}:{key}", f"addon:{name}", key))

    current_core = {w[0] for w in wanted if w[1] == "core"}
    kept: dict[str, str] = {}
    for ident, value in sorted(_load_state(config_dir, pool, block).items()):
        owner = ident.split(":")[1] if ident.startswith("addon:") else None
        if owner is not None and owner not in installed:
            continue  # the add-on is gone; its blocks are free again
        if ident.startswith("core:") and ident not in current_core:
            continue  # the core network is switched off; its block is free again
        try:
            net = ipaddress.ip_network(value)
        except ValueError:
            continue
        if net not in every or net in used:
            continue
        kept[ident] = str(net)
        used.add(net)

    free = (b for b in every[len(CORE_NETWORKS):] if b not in used)
    needed = len(CORE_NETWORKS) + len(kept) + sum(1 for w in wanted if w[0] not in kept)
    for ident, owner, key in wanted:
        if ident not in kept:
            net = next(free, None)
            if net is None:
                raise SubnetPoolError(
                    f"{POOL_KEY} {pool} is too small: it holds {len(every)} blocks of /{block},"
                    f" the installation needs {needed} networks (a larger pool, or smaller"
                    f" blocks with {BLOCK_KEY})"
                )
            kept[ident] = str(net)
            used.add(net)
        placed.setdefault(owner, {})[key] = kept[ident]

    _check_uplink(env, used)
    _check_own(own_networks(config_dir, repo_root, active_only=True, deployed=deployed), used)
    return placed, kept


def _check_uplink(env: dict[str, str], used: set[ipaddress.IPv4Network]) -> None:
    from . import sql_uplink  # it reaches this module through lib/egress.py

    try:
        uplink = sql_uplink.subnet(env)
    except sql_uplink.SqlUplinkError:
        return  # refused by the uplink's own render
    for net in sorted(used):
        if net.overlaps(uplink):
            raise SubnetPoolError(
                f"{sql_uplink.SUBNET_KEY} {uplink} overlaps the block {net} of {POOL_KEY};"
                f" choose a range for the SQL uplink outside the pool's blocks"
            )


def _check_own(networks: list[dict], used: set[ipaddress.IPv4Network]) -> None:
    """A network with a range of its own must not overlap a block of the pool: Docker
    would refuse to create one of the two ("Pool overlaps")."""
    for net in networks:
        for own in net["subnets"]:
            for block in sorted(used):
                if own.overlaps(block):
                    who = "the core" if net["owner"] == "core" else net["owner"].split(":", 1)[1]
                    raise SubnetPoolError(
                        f"the network {net['name']} of {who} declares the range {own}, which"
                        f" overlaps the block {block} of {POOL_KEY}; choose a pool that"
                        " leaves it out, or give that network a range outside the pool"
                    )


def relay_clients_set(config_dir: Path) -> bool:
    """Whether the operator set SMTP_RELAY_ALLOWED_CLIENTS: in infra/smtp-relay/.env (its
    documented place) or in the root .env, the two files Compose interpolates the relay
    with."""
    for path in (config_dir / "infra" / "smtp-relay" / ".env", config_dir / ".env"):
        if (common.parse_env_file(path).get(RELAY_CLIENTS_KEY) or "").strip():
            return True
    return False


def _override(subnets: dict[str, str]) -> dict:
    return {
        "networks": {
            key: {"ipam": {"config": [{"subnet": subnet}]}} for key, subnet in subnets.items()
        }
    }


def _write(path: Path, document: dict) -> None:
    common.atomic_write(path, yaml.safe_dump(document, sort_keys=False, default_flow_style=False))


def generate_overrides(config_dir: Path, repo_root: Path) -> list[Path]:
    """Write or remove the override of the core project and of every add-on, and the kept
    assignments. Run after every other override is written: the networks the core's
    overrides and the add-ons' overrides declare are placed as well."""
    env = common.parse_env_file(config_dir / ".env")
    deployed = deployment.load(config_dir)
    core_path = config_dir / "overrides" / OVERRIDE
    found = settings(env)
    if found is None:
        core_path.unlink(missing_ok=True)
        (config_dir / STATE_FILE).unlink(missing_ok=True)
        for addon in _addons(deployed):
            addon_override_path(config_dir, addon["name"]).unlink(missing_ok=True)
        return []
    pool, block = found
    placed, kept = plan(config_dir, repo_root, pool, block, env)
    common.atomic_write(
        config_dir / STATE_FILE,
        json.dumps(
            {"format": STATE_FORMAT, "pool": str(pool), "block": block, "networks": kept},
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    written = []
    core = _override(placed["core"])
    if not relay_clients_set(config_dir):
        # The relay takes mail from its own networks only, and all of them are in the pool
        # (its default would be every private range).
        core["services"] = {
            RELAY_SERVICE: {"environment": {"POSTFIX_mynetworks": f"127.0.0.0/8,{pool}"}}
        }
    _write(core_path, core)
    written.append(core_path)
    for addon in _addons(deployed):
        name = addon["name"]
        path = addon_override_path(config_dir, name)
        subnets = placed.get(f"addon:{name}")
        if not subnets:
            path.unlink(missing_ok=True)
            continue
        _write(path, _override(subnets))
        written.append(path)
    return written


# ─────────────────────────────────────────────────────────────────────────
# the host
# ─────────────────────────────────────────────────────────────────────────


def host_networks(runner: Runner | None = None) -> list[dict] | None:
    """[{name, project, subnets}] of every Docker network on the host (IPv4 ranges only),
    or None when Docker does not answer."""
    runner = runner if runner is not None else run
    listed = runner(["docker", "network", "ls", "--format", "{{.Name}}"], DOCKER_TIMEOUT_SECONDS)
    if listed.returncode != 0:
        return None
    names = [n for n in listed.stdout.split() if n]
    if not names:
        return []
    shown = runner(
        ["docker", "network", "inspect", "--format", _INSPECT_FORMAT, *names],
        DOCKER_TIMEOUT_SECONDS,
    )
    # A network removed between the two calls fails the call but not the others' lines.
    if shown.returncode != 0 and not shown.stdout.strip():
        return None
    found = []
    for line in shown.stdout.splitlines():
        parts = (line.split("\t") + ["", ""])[:3]
        if not parts[0].strip():
            continue
        subnets = []
        for value in parts[2].split():
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                subnets.append(net)
        label = parts[1].strip()
        found.append({
            "name": parts[0].strip(),
            "project": "" if label == "<no value>" else label,
            "subnets": subnets,
        })
    return found


def installation_projects(config_dir: Path, repo_root: Path, env: dict[str, str]) -> set[str]:
    """The Compose projects of this installation: the core's and one per add-on."""
    projects = {project(env)}
    for addon in _addons(deployment.load(config_dir)):
        projects.add(deployment.resolve_addon_path(addon, repo_root).name)
    return projects


def review(
    pool: ipaddress.IPv4Network,
    networks: list[dict],
    projects: set[str],
    exempt: Iterable[str] = (),
) -> tuple[list[dict], list[dict]]:
    """(networks of the installation outside the pool, foreign networks in it)."""
    skip = set(exempt)
    outside, foreign = [], []
    for net in networks:
        if net["name"] in skip:
            continue
        ours = net["project"] in projects
        if ours and any(not s.subnet_of(pool) for s in net["subnets"]):
            outside.append(net)
        elif not ours and any(s.overlaps(pool) for s in net["subnets"]):
            foreign.append(net)
    return outside, foreign


def _ranges(net: dict) -> str:
    return ", ".join(str(s) for s in net["subnets"])


def foreign_message(pool: ipaddress.IPv4Network, net: dict) -> str:
    return (
        f"{POOL_KEY} {pool} overlaps the Docker network {net['name']} ({_ranges(net)}),"
        " which does not belong to this installation; choose another range with"
        " 'papaia-ctl setup --subnet-pool=CIDR'"
    )


def outside_message(pool: ipaddress.IPv4Network, net: dict) -> str:
    return (
        f"the network {net['name']} of this installation has the range {_ranges(net)},"
        f" outside {POOL_KEY} {pool}; remove it with 'papaia-ctl stop --clean-up --addons',"
        " then run 'papaia-ctl start'"
    )


def uplink_name(env: dict[str, str]) -> str:
    from . import sql_uplink  # it reaches this module through lib/egress.py

    return sql_uplink.network_name(env)


def exempt(config_dir: Path, repo_root: Path, env: dict[str, str]) -> set[str]:
    """The networks of the installation that keep a range of their own and are therefore
    never "outside the pool": the SQL uplink and every network the core or an installed
    add-on declares with `ipam` (plan() refuses such a range when it overlaps a block)."""
    names = {uplink_name(env)}
    names.update(n["name"] for n in own_networks(config_dir, repo_root, active_only=False))
    return names


def findings(
    config_dir: Path, repo_root: Path, runner: Runner | None = None
) -> dict | None:
    """None without a pool; otherwise {pool, outside, foreign, unavailable} for the host
    as it is now. SubnetPoolError for an unusable setting."""
    env = common.parse_env_file(config_dir / ".env")
    found = settings(env)
    if found is None:
        return None
    pool = found[0]
    networks = host_networks(runner)
    if networks is None:
        return {"pool": pool, "outside": [], "foreign": [], "unavailable": True}
    outside, foreign = review(
        pool,
        networks,
        installation_projects(config_dir, repo_root, env),
        exempt(config_dir, repo_root, env),
    )
    return {"pool": pool, "outside": outside, "foreign": foreign, "unavailable": False}


def start_problems(
    config_dir: Path, repo_root: Path, runner: Runner | None = None
) -> list[str]:
    """Why `start` must not bring the stack up with the pool: a foreign network in it, a
    network of the installation outside it, or no answer from Docker. [] without a pool."""
    try:
        found = findings(config_dir, repo_root, runner)
    except SubnetPoolError as exc:
        return [str(exc)]
    if found is None:
        return []
    if found["unavailable"]:
        return [f"Docker did not list its networks; {POOL_KEY} {found['pool']} is not checked"]
    pool = found["pool"]
    return [foreign_message(pool, n) for n in found["foreign"]] + [
        outside_message(pool, n) for n in found["outside"]
    ]
