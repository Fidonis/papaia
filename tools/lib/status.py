"""Live status of the stack: the declared state next to what Docker reports.

`collect()` evaluates and returns a structured `StatusReport`; rendering
(`format_table`, `to_json`) is separate, so the Bash dispatcher, `doctor` and
any Python caller read the same result -- the shape `compat.py` follows.

Containers come from a single unfiltered `docker ps -a`. What `docker ps`
cannot say is what is *not* there: a service whose profile was never started
and one whose container was removed both show up as nothing. The declared half
is therefore read from the Compose files themselves (core fragments filtered by
`COMPOSE_PROFILES`, add-on files named by `deployment.yaml`), and a declared
service without a container is reported as `missing` ("not deployed").

Decisions that are easy to get wrong:

* `docker ps -a`, not `docker ps`. A stopped Keycloak has to read as down, and
  without `-a` its container is absent, which looks the same as never deployed.
* No `--filter`. Add-ons run in their own Compose project (one per add-on
  directory), so a project filter would exclude them, and filtering on the
  module label would drop containers that carry none. One unfiltered call
  answers all of it; the partition by `com.docker.compose.project` happens in
  Python, which also keeps several papAIa environments on one host apart.
* A container without a healthcheck counts as healthy while it runs. Treating
  its absence as a problem would paint half a working deployment yellow.
* `Exited (0)` alone does not mean "finished one-shot job": a service stopped
  through `papaia-ctl stop` ends just as cleanly. The restart policy
  (`always` / `unless-stopped`) separates the two; it is not part of the
  `docker ps` output, hence the narrowly scoped `docker inspect`.
* An unreachable Docker socket yields a report without modules and with
  `docker.reachable = false`, never a stack full of missing services. Not
  knowing is not the same as knowing it is gone.

A "module" is a `de.fidonis.module` label, not a Compose profile. The mapping
is many-to-many (`librechat-websearch` brings up four modules, `oauth2-proxy`
is labelled `auth`), so it is read out of the fragments, never derived from the
profile name.

Reading is all this module does: it starts, stops and writes nothing.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from . import common, compat, deployment, envtree

SCHEMA_VERSION = 1

DOCKER_TIMEOUT_SECONDS = 5.0

DEFAULT_PROJECT = "papaia"

# Containers that carry no module label at all: a core service whose label was
# dropped in a local edit, or an add-on that never set one.
UNGROUPED_MODULE = "other"

_MODULE_PREFIX = "papaia-"

# Fields requested from `docker ps`, tab-separated. Tab rather than a printable
# separator because no field can contain one; `.Status` and `.Ports` are
# generated text.
_PS_FORMAT = "\t".join(
    (
        "{{.Names}}",
        "{{.State}}",
        "{{.Status}}",
        '{{.Label "com.docker.compose.project"}}',
        '{{.Label "com.docker.compose.service"}}',
        '{{.Label "de.fidonis.module"}}',
        '{{.Label "de.fidonis.role"}}',
        "{{.Ports}}",
    )
)
_PS_FIELD_COUNT = 8

# Container name plus restart policy. `.Name` comes back with a leading slash.
_INSPECT_FORMAT = "\t".join(("{{.Name}}", "{{.HostConfig.RestartPolicy.Name}}"))

# Restart policies of a container that was meant to keep running. Everything
# else (`no`, `on-failure`, none) describes a job that is allowed to finish.
_SERVICE_RESTART_POLICIES = frozenset({"always", "unless-stopped"})

# `Exited (0) 2 days ago`: the exit code separates a completed one-shot
# container from a crashed service.
_EXIT_CODE_RE = re.compile(r"^Exited \((\d+)\)")

# Published host ports out of `0.0.0.0:8000->3080/tcp, :::8000->3080/tcp`.
_HOST_PORT_RE = re.compile(r":(\d+)->")

_MISSING_STATE = "missing"
_MISSING_STATUS_TEXT = "not deployed"


class StatusError(Exception):
    """A user-facing, non-traceback-worthy failure (bad flag value)."""


class Health(str, Enum):
    """Derived state of a container or of a whole module."""

    MISSING = "missing"
    STOPPED = "stopped"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    UNKNOWN = "unknown"
    COMPLETED = "completed"
    HEALTHY = "healthy"


# Lower is worse. `worst()` walks this order, so it is the single place that
# decides what a section shows when several things are wrong at once. `MISSING`
# outranks `STOPPED`: a container that exited at least got as far as being
# created, and its logs are still there to read.
_SEVERITY: dict[Health, int] = {
    Health.MISSING: 0,
    Health.STOPPED: 1,
    Health.UNHEALTHY: 2,
    Health.STARTING: 3,
    Health.UNKNOWN: 4,
    Health.COMPLETED: 5,
    Health.HEALTHY: 6,
}


# ─────────────────────────────────────────────────────────────────────────
# command execution
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], float], CommandResult]


def run_command(cmd: Sequence[str], timeout: float = DOCKER_TIMEOUT_SECONDS) -> CommandResult:
    """Run a probe command and never raise.

    A missing binary and a timeout come back as shell-style codes (127, 124)
    with a message in `stderr`, so callers can tell them apart from a command
    that ran and failed. This is the injection point tests replace.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(cmd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(127, "", f"{cmd[0]}: command not found")
    except subprocess.TimeoutExpired:
        return CommandResult(124, "", f"{cmd[0]} timed out after {timeout:g}s")
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(126, "", f"{cmd[0]}: {exc}")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# ─────────────────────────────────────────────────────────────────────────
# model
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Container:
    """One container of the stack.

    A declared service with no container is represented too, with an empty
    `name` (Docker never assigned one) and `MISSING` health; what is shown about
    it comes from the Compose file.
    """

    name: str
    service: str
    role: str
    state: str
    status_text: str
    health: Health = Health.UNKNOWN
    host_ports: list[int] = field(default_factory=list)

    @property
    def sort_key(self) -> str:
        # Missing containers fall back to the service name; otherwise every
        # placeholder would sort to the front on its empty name.
        return self.name or self.service


@dataclass
class Module:
    """All containers sharing one `de.fidonis.module` label of one project."""

    name: str
    kind: str  # "core" | "addon"
    compose_project: str
    containers: list[Container] = field(default_factory=list)
    profiles: tuple[str, ...] = ()
    declared: bool = False

    @property
    def status(self) -> Health:
        return worst(c.health for c in self.containers)

    @property
    def summary(self) -> str:
        """Short human-readable verdict for the table row."""
        total = len(self.containers)
        missing = sum(1 for c in self.containers if c.health == Health.MISSING)
        stopped = sum(1 for c in self.containers if c.health == Health.STOPPED)
        if missing == total and total:
            return "not deployed"
        if missing and stopped:
            return f"{missing + stopped} of {total} containers missing or stopped"
        if missing:
            return f"{missing} of {total} containers not deployed"
        if stopped:
            return f"{stopped} of {total} containers stopped"
        if self.status == Health.UNHEALTHY:
            return "healthcheck failing"
        if self.status == Health.STARTING:
            return "starting"
        if self.status == Health.COMPLETED:
            return "completed"
        return f"{total} container" if total == 1 else f"{total} containers"


@dataclass(frozen=True)
class Group:
    """One Compose profile: the granularity `start` / `stop --profiles` act on.

    Health is aggregated over everything the profile brings up, because a group
    is up only if all of it is.
    """

    profile: str
    modules: tuple[str, ...]
    containers: int
    status: Health


@dataclass(frozen=True)
class DockerState:
    reachable: bool
    reason: str | None = None


@dataclass
class StatusReport:
    generated_at: str
    platform_version: str
    compose_project: str
    docker: DockerState
    core: list[Module] = field(default_factory=list)
    addons: list[Module] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    include_addons: bool = False
    # Aggregates: None when the section was not asked for or has nothing in it.
    aggregate_core: Health | None = None
    aggregate_addons: Health | None = None

    @property
    def modules(self) -> list[Module]:
        return [*self.core, *self.addons]

    def host_ports_in_use(self) -> dict[int, str]:
        """Host port -> container name, for containers that hold the port now."""
        ports: dict[int, str] = {}
        for module in self.modules:
            for container in module.containers:
                if container.state in ("running", "restarting"):
                    for port in container.host_ports:
                        ports.setdefault(port, container.name)
        return ports

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "platform_version": self.platform_version,
            "compose_project": self.compose_project,
            "docker": {"reachable": self.docker.reachable, "reason": self.docker.reason},
            "modules": [_module_dict(m) for m in self.modules],
            "groups": [
                {
                    "profile": g.profile,
                    "modules": list(g.modules),
                    "containers": g.containers,
                    "status": g.status.value,
                }
                for g in self.groups
            ],
            "aggregate": {
                "core": self.aggregate_core.value if self.aggregate_core else None,
                "addons": self.aggregate_addons.value if self.aggregate_addons else None,
            },
        }


def _module_dict(module: Module) -> dict[str, Any]:
    return {
        "name": module.name,
        "kind": module.kind,
        "compose_project": module.compose_project,
        "profiles": list(module.profiles),
        "declared": module.declared,
        "status": module.status.value,
        "containers": [
            {
                "name": c.name,
                "service": c.service,
                "role": c.role,
                "state": c.state,
                "health": c.health.value,
                "status_text": c.status_text,
                "host_ports": list(c.host_ports),
            }
            for c in module.containers
        ],
    }


# ─────────────────────────────────────────────────────────────────────────
# aggregation and parsing
# ─────────────────────────────────────────────────────────────────────────


def worst(values: Iterable[Health]) -> Health:
    """The most severe value, ignoring completed one-shots.

    A finished `Exited (0)` container says nothing about whether its module is
    serving traffic, so it must not outrank the long-running container next to
    it (`localai` is model-init plus the inference engine, and only the second
    one matters). When *everything* has completed the group reads as completed.

    An empty input is `UNKNOWN`: it means Docker told us nothing, not that
    everything is fine.
    """
    items = list(values)
    if not items:
        return Health.UNKNOWN
    serving = [v for v in items if v != Health.COMPLETED]
    if not serving:
        return Health.COMPLETED
    return min(serving, key=lambda v: _SEVERITY[v])


def derive_health(state: str, status_text: str) -> Health:
    """Map Docker's state plus status text onto a health value.

    `state` is the machine-readable field (`running`, `exited`, ...); the
    healthcheck result only appears in the human-readable `status_text`, as one
    of `(healthy)`, `(unhealthy)` or `(health: starting)`.
    """
    if state == "running":
        if "(unhealthy)" in status_text:
            return Health.UNHEALTHY
        if "(health: starting)" in status_text:
            return Health.STARTING
        # `(healthy)` or no healthcheck defined at all.
        return Health.HEALTHY
    if state == "created":
        return Health.STARTING
    if state == "restarting":
        # A crash loop keeps flipping back to `running`; reporting it as
        # starting would let a container that never stays up look fine.
        return Health.UNHEALTHY
    if state == "exited":
        match = _EXIT_CODE_RE.match(status_text)
        if match and match.group(1) == "0":
            return Health.COMPLETED
        return Health.STOPPED
    if state in ("paused", "dead", "removing"):
        return Health.STOPPED
    return Health.UNKNOWN


def module_display_name(label: str) -> str:
    """The `de.fidonis.module` label as it is grouped and shown by.

    Shared by the live view and the declared state: they have to agree exactly,
    or every module would render twice, once expected and once running.
    """
    return label.removeprefix(_MODULE_PREFIX) if label else UNGROUPED_MODULE


def _parse_host_ports(raw: str) -> list[int]:
    """Published host ports, deduplicated, in the order Docker listed them.

    Docker reports the IPv4 and IPv6 binding of one publish separately.
    """
    seen: list[int] = []
    for match in _HOST_PORT_RE.finditer(raw):
        port = int(match.group(1))
        if port not in seen:
            seen.append(port)
    return seen


def parse_ps_line(line: str) -> tuple[str, str, Container] | None:
    """Parse one `docker ps` line into (project, module, container).

    None for a line that does not carry all fields, which is what a truncated
    read or a changed format looks like.
    """
    parts = line.split("\t")
    if len(parts) != _PS_FIELD_COUNT:
        return None
    name, state, status_text, project, service, module, role, ports = (p.strip() for p in parts)
    if not name:
        return None
    return (
        project,
        module_display_name(module),
        Container(
            name=name,
            service=service or name,
            role=role,
            state=state,
            status_text=status_text,
            health=derive_health(state, status_text),
            host_ports=_parse_host_ports(ports),
        ),
    )


def parse_ps_output(output: str) -> dict[str, list[tuple[str, Container]]]:
    """Group `docker ps` output by Compose project.

    Each entry is (module name, container). Containers with no project label
    are collected under the empty string, so a caller that only knows named
    projects drops them without special-casing.
    """
    grouped: dict[str, list[tuple[str, Container]]] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        parsed = parse_ps_line(line)
        if parsed is None:
            continue
        project, module_name, container = parsed
        grouped.setdefault(project, []).append((module_name, container))
    return grouped


def parse_inspect_output(output: str) -> dict[str, str]:
    """Container name -> restart policy. Docker prefixes the name with a slash."""
    policies: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        name, policy = (p.strip() for p in parts)
        if name:
            policies[name.removeprefix("/")] = policy
    return policies


def apply_restart_policies(modules: Iterable[Module], policies: Mapping[str, str]) -> None:
    """Re-read completed containers in the light of their restart policy.

    A container Docker was told to keep alive has no business being gone, so its
    exit is an outage regardless of the code it exited with. A container missing
    from `policies` keeps its parsed value: when Docker gives no answer, an
    unfounded outage is worse than a stopped container reading as completed.
    """
    for module in modules:
        for container in module.containers:
            if (
                container.health is Health.COMPLETED
                and policies.get(container.name) in _SERVICE_RESTART_POLICIES
            ):
                container.health = Health.STOPPED


def _worst_first(modules: Iterable[Module]) -> list[Module]:
    """Worst first, ties broken by name so the list does not reshuffle."""
    return sorted(modules, key=lambda m: (_SEVERITY[m.status], m.name))


# ─────────────────────────────────────────────────────────────────────────
# declared state
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExpectedService:
    """One Compose service this deployment is supposed to be running.

    `service` is the Compose service name, which is what
    `com.docker.compose.service` reports on the running container. `profiles`
    holds the *active* profiles the service belongs to (empty for an add-on).
    `ports` are the raw `ports:` entries, uninterpolated, for `doctor`.
    """

    service: str
    module: str
    role: str
    profiles: frozenset[str] = frozenset()
    ports: tuple[str, ...] = ()


def active_profiles(config_dir: Path) -> set[str]:
    """Compose profiles enabled for this deployment, from the core `.env`.

    Absent or empty `COMPOSE_PROFILES` yields an empty set and therefore an
    empty core inventory, which is right: Compose would start nothing either.
    """
    env = common.parse_env_file(config_dir / ".env")
    return {p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",") if p.strip()}


def compose_project(config_dir: Path) -> str:
    """Compose project name of this deployment, from the core `.env`."""
    env = common.parse_env_file(config_dir / ".env")
    return env.get("COMPOSE_PROJECT_NAME") or DEFAULT_PROJECT


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """One Compose file, or None if it cannot be read: a missing fragment must
    cost the caller that fragment, not the whole report."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return document if isinstance(document, dict) else None


def _services(document: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    services = (document or {}).get("services") or {}
    if not isinstance(services, dict):
        return {}
    return {name: body for name, body in services.items() if isinstance(body, dict)}


def _profiles_of(body: dict[str, Any]) -> set[str]:
    raw = body.get("profiles") or []
    return {p for p in raw if isinstance(p, str)} if isinstance(raw, list) else set()


def _labels_of(body: dict[str, Any]) -> dict[str, str]:
    """Container labels from either Compose spelling (mapping or `key=value`)."""
    raw = body.get("labels")
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        pairs = (str(item).partition("=") for item in raw)
        return {key.strip(): value.strip() for key, _, value in pairs if key.strip()}
    return {}


def _ports_of(body: dict[str, Any]) -> tuple[str, ...]:
    raw = body.get("ports") or []
    if not isinstance(raw, list):
        return ()
    return tuple(item for item in raw if isinstance(item, str))


def _expected(
    service: str, body: dict[str, Any], *, fallback_module: str, active: set[str] | None
) -> ExpectedService:
    labels = _labels_of(body)
    module = labels.get("de.fidonis.module")
    declared = _profiles_of(body)
    return ExpectedService(
        service=service,
        module=module_display_name(module) if module else fallback_module,
        role=labels.get("de.fidonis.role", ""),
        profiles=frozenset(declared & active) if active is not None else frozenset(),
        ports=_ports_of(body),
    )


def core_inventory(repo_root: Path, active: set[str]) -> list[ExpectedService]:
    """Core services enabled by `active`, read from the shipped fragments.

    Follows the `include:` list of `src/docker-compose.yml` (via
    `compat.compose_files`) rather than globbing, so a fragment that is not part
    of the stack cannot leak into the target state. Static YAML parsing, not
    `docker compose config`: the fields needed here (`profiles`, two labels,
    `ports`) are literals in the shipped fragments, and `config` needs every
    enabled profile's env file rendered and forks a process.
    """
    root = repo_root / "src" / "docker-compose.yml"
    try:
        files = compat.compose_files(root)
    except (OSError, yaml.YAMLError):
        return []
    expected: list[ExpectedService] = []
    for path in files:
        for service, body in _services(_load_yaml(path)).items():
            declared = _profiles_of(body)
            # A service without `profiles` is unconditional in Compose.
            if declared and not (declared & active):
                continue
            expected.append(
                _expected(service, body, fallback_module=UNGROUPED_MODULE, active=active)
            )
    return expected


def addon_inventory(addon_path: Path, fallback_module: str) -> list[ExpectedService]:
    """Every service of one add-on's Compose file (`addon.sh` reads the same).

    Add-on fragments carry no `profiles`: an active add-on is expected in full.
    `de.fidonis.module` is not part of the add-on contract, hence the fallback
    to the add-on's own name; without it such an add-on would land in `other`.
    """
    document = _load_yaml(addon_path / "docker-compose.yml")
    return [
        _expected(service, body, fallback_module=fallback_module, active=None)
        for service, body in _services(document).items()
    ]


def declared_profiles(expected: Iterable[ExpectedService]) -> set[str]:
    return {profile for item in expected for profile in item.profiles}


# ─────────────────────────────────────────────────────────────────────────
# merging
# ─────────────────────────────────────────────────────────────────────────


def assemble_modules(
    live: Iterable[tuple[str, Container]],
    expected: Iterable[ExpectedService],
    *,
    kind: str,
    project: str,
) -> list[Module]:
    """Merge one project's live containers with its declared services.

    Matching is by Compose service name, unique inside a project; that is why
    this works per project and not across the host. A declared service Docker
    did not report gets a `missing` placeholder, and a module that exists only in
    the target state is created, which is what makes an enabled-but-never-started
    profile visible at all. Containers Docker reported that nothing declared are
    kept: they are running, and the report has no business hiding that because
    the manifest disagrees.
    """
    expected = list(expected)
    declared_module = {item.service: item.module for item in expected}

    modules: dict[str, Module] = {}
    for module_name, container in live:
        # A container without the module label belongs to whatever module its
        # declared service names. Add-ons are allowed to set no label at all, and
        # their declared module is then the add-on's own name; without this the
        # running containers would sit in `other` next to a declared module that
        # reads as empty.
        if module_name == UNGROUPED_MODULE and container.service in declared_module:
            module_name = declared_module[container.service]
        module = modules.setdefault(
            module_name, Module(name=module_name, kind=kind, compose_project=project)
        )
        module.containers.append(container)

    seen = {c.service for m in modules.values() for c in m.containers}
    profiles: dict[str, set[str]] = {}
    declared: set[str] = set()
    for item in expected:
        declared.add(item.module)
        profiles.setdefault(item.module, set()).update(item.profiles)
        if item.service in seen:
            continue
        module = modules.setdefault(
            item.module, Module(name=item.module, kind=kind, compose_project=project)
        )
        module.containers.append(
            Container(
                name="",
                service=item.service,
                role=item.role,
                state=_MISSING_STATE,
                status_text=_MISSING_STATUS_TEXT,
                health=Health.MISSING,
            )
        )

    for module in modules.values():
        module.containers.sort(key=lambda c: c.sort_key)
        module.profiles = tuple(sorted(profiles.get(module.name, ())))
        module.declared = module.name in declared
    return _worst_first(modules.values())


def build_groups(modules: Iterable[Module]) -> list[Group]:
    """Invert the modules' profile lists into the groups `--profiles` acts on.

    Derived from the merged modules, so it reflects the restart-policy
    correction too. A profile with no module behind it cannot appear here.
    """
    members: dict[str, list[Module]] = {}
    for module in modules:
        for profile in module.profiles:
            members.setdefault(profile, []).append(module)
    groups = [
        Group(
            profile=profile,
            modules=tuple(sorted(m.name for m in found)),
            containers=sum(len(m.containers) for m in found),
            status=worst(m.status for m in found),
        )
        for profile, found in members.items()
    ]
    return sorted(groups, key=lambda g: (_SEVERITY[g.status], g.profile))


# ─────────────────────────────────────────────────────────────────────────
# docker queries
# ─────────────────────────────────────────────────────────────────────────


def query_containers(run: Runner) -> tuple[str | None, str | None]:
    """(`docker ps -a` output, None) or (None, reason).

    Unfiltered on purpose, see the module docstring.
    """
    result = run(["docker", "ps", "-a", "--format", _PS_FORMAT], DOCKER_TIMEOUT_SECONDS)
    if result.returncode != 0:
        reason = first_line(result.stderr) or f"docker ps exited with {result.returncode}"
        return None, reason
    return result.stdout, None


def query_restart_policies(run: Runner, names: Sequence[str]) -> dict[str, str]:
    """Restart policy per container name, empty on failure.

    Asked only about completed containers, so a healthy deployment costs one
    lookup for the model-init job and nothing else.
    """
    if not names:
        return {}
    result = run(
        ["docker", "inspect", "--type", "container", "--format", _INSPECT_FORMAT, *names],
        DOCKER_TIMEOUT_SECONDS,
    )
    # A container removed between `ps` and `inspect` makes Docker exit non-zero
    # while still reporting the ones it did find, so stdout is worth parsing.
    return parse_inspect_output(result.stdout)


# ─────────────────────────────────────────────────────────────────────────
# collect
# ─────────────────────────────────────────────────────────────────────────


def _timestamp(now: datetime | None) -> str:
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(
    config_dir: Path,
    repo_root: Path,
    *,
    profiles: Sequence[str] | None = None,
    include_addons: bool = False,
    run: Runner | None = None,
    now: datetime | None = None,
) -> StatusReport:
    """Read the stack as it is and as it should be.

    `profiles` narrows the core section to those Compose profiles; a profile
    that is not active in this deployment raises `StatusError`. Add-ons are
    reported only with `include_addons`, mirroring `start` / `stop --addons`.
    """
    run = run or run_command
    active = active_profiles(config_dir)
    project = compose_project(config_dir)
    expected_core = core_inventory(repo_root, active)

    wanted: set[str] | None = None
    if profiles:
        wanted = {p.strip() for p in profiles if p.strip()}
        known = declared_profiles(expected_core)
        unknown = sorted(wanted - known)
        if unknown:
            raise StatusError(
                f"Unknown or inactive profile(s): {', '.join(unknown)}."
                f" Active profiles with services: {', '.join(sorted(known)) or '(none)'}."
            )

    deployed = deployment.load(config_dir)
    addon_projects: list[tuple[str, list[ExpectedService]]] = []
    if include_addons:
        for entry in deployment.active_addons(deployed):
            name = str(entry.get("name") or "")
            if not name or not entry.get("path"):
                continue
            path = deployment.resolve_addon_path(entry, repo_root)
            addon_projects.append((path.name, addon_inventory(path, name)))

    report = StatusReport(
        generated_at=_timestamp(now),
        platform_version=envtree.resolve_platform_version(repo_root),
        compose_project=project,
        docker=DockerState(reachable=True),
        include_addons=include_addons,
    )

    output, reason = query_containers(run)
    if output is None:
        # Not knowing is not the same as knowing it is gone: no modules, no
        # invented outage, and an explicit "unknown" for the sections asked for.
        report.docker = DockerState(reachable=False, reason=reason)
        report.aggregate_core = Health.UNKNOWN
        report.aggregate_addons = Health.UNKNOWN if include_addons else None
        return report

    by_project = parse_ps_output(output)
    core = assemble_modules(
        by_project.get(project, []), expected_core, kind="core", project=project
    )
    addons: list[Module] = []
    for addon_project, expected in sorted(addon_projects, key=lambda t: t[0]):
        addons.extend(
            assemble_modules(
                by_project.get(addon_project, []), expected, kind="addon", project=addon_project
            )
        )

    completed = [
        c.name
        for module in (*core, *addons)
        for c in module.containers
        if c.health is Health.COMPLETED
    ]
    policies = query_restart_policies(run, completed)
    apply_restart_policies(core, policies)
    apply_restart_policies(addons, policies)
    core = _worst_first(core)
    addons = _worst_first(addons)

    groups = build_groups(core)
    if wanted is not None:
        core = [m for m in core if wanted & set(m.profiles)]
        groups = [g for g in groups if g.profile in wanted]

    report.core = core
    report.addons = addons
    report.groups = groups
    report.aggregate_core = worst(m.status for m in core) if core else None
    report.aggregate_addons = worst(m.status for m in addons) if addons else None
    return report


# ─────────────────────────────────────────────────────────────────────────
# rendering
# ─────────────────────────────────────────────────────────────────────────

_QUIET_HEALTH = frozenset({Health.HEALTHY, Health.COMPLETED})


def _format_rows(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]
    lines = ["  ".join(header[i].ljust(widths[i]) for i in range(len(header))).rstrip()]
    lines.extend("  ".join(r[i].ljust(widths[i]) for i in range(len(r))).rstrip() for r in rows)
    return lines


def _section_lines(title: str, modules: Sequence[Module], aggregate: Health | None) -> list[str]:
    lines = [f"{title}: {aggregate.value if aggregate else 'no modules'}"]
    if not modules:
        return lines
    rows = [(m.name, m.status.value, ",".join(m.profiles) or "-", m.summary) for m in modules]
    lines.extend(_format_rows(("MODULE", "STATUS", "PROFILES", "DETAIL"), rows))
    for module in modules:
        for container in module.containers:
            if container.health not in _QUIET_HEALTH:
                role = f" ({container.role})" if container.role else ""
                lines.append(f"  {module.name}/{container.service}{role}: {container.status_text}")
    return lines


def format_table(report: StatusReport) -> str:
    """Render the report for a terminal."""
    lines = [f"papAIa {report.platform_version} - compose project '{report.compose_project}'"]
    if not report.docker.reachable:
        lines.append(f"Docker is not reachable ({report.docker.reason}). Status unknown.")
        return "\n".join(lines)
    lines.append("")
    lines.extend(_section_lines("CORE", report.core, report.aggregate_core))
    if report.include_addons:
        lines.append("")
        lines.extend(_section_lines("ADD-ONS", report.addons, report.aggregate_addons))
    return "\n".join(lines)


def to_json(report: StatusReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
