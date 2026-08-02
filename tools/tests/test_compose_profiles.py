"""Guards the profile-restricted lifecycle commands against silently
degrading into whole-stack operations.

`papaia-ctl start|stop --profiles=LIST` runs docker compose with
COMPOSE_PROFILES set to LIST, which disables every service outside those
profiles. If a service inside the selection declares a hard `depends_on` on a
service that got disabled, the project no longer loads:

    service "librechat" depends on undefined service "litellm":
    invalid compose project

`up` refuses at that point, but `stop` and `down` do not: they fall back to
project-name-only mode and derive their target set from the running containers
labelled with the project name -- so `stop --profiles=librechat` stopped all 24
containers of the stack and still reported success.

The fix is per-edge (`required: false` on the dependency), so nothing structural
stops the next cross-profile dependency from reintroducing it. This test does:
every hard dependency must be reachable from every profile that can enable its
dependent.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from lib import compat

REPO = Path(__file__).resolve().parents[2]

_CROSS_PROFILE = (
    "Hard cross-profile depends_on. Under COMPOSE_PROFILES={profiles} the"
    " dependency is disabled and the project becomes invalid, which turns"
    " `papaia-ctl stop --profiles=...` into a whole-stack stop. Either add"
    " '{target}' to the same profile(s) as '{service}', or mark the dependency"
    " 'required: false' the way the keycloak edges do."
)


def _depends_on_edges(repo_root: Path) -> list[tuple[str, str, bool]]:
    """(service, dependency, required) for every depends_on edge in the core.

    Both notations are covered: the mapping form, which may carry `required`,
    and the list form, which cannot -- so its edges are always required."""
    edges: list[tuple[str, str, bool]] = []
    for compose_path in compat.compose_files(repo_root / "src" / "docker-compose.yml"):
        if not compose_path.is_file():
            continue
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        for name, service in (doc.get("services") or {}).items():
            depends_on = (service or {}).get("depends_on") or {}
            if isinstance(depends_on, list):
                edges.extend((name, target, True) for target in depends_on)
                continue
            for target, spec in depends_on.items():
                required = (spec or {}).get("required", True) if isinstance(spec, dict) else True
                edges.append((name, target, bool(required)))
    return edges


def test_hard_depends_on_never_crosses_a_profile_boundary():
    services = compat.resolve_core_services(REPO)
    assert services, "src/docker-compose.yml resolved to no services"

    for service, target, required in _depends_on_edges(REPO):
        if not required:
            continue
        assert target in services, (
            f"'{service}' depends on unknown service '{target}'"
        )
        service_profiles = set(services[service])
        target_profiles = set(services[target])
        # A profile-less service is always enabled, so it satisfies every
        # dependent. Otherwise the target must be enabled by every profile that
        # enables the dependent.
        if not target_profiles:
            continue
        assert service_profiles <= target_profiles, _CROSS_PROFILE.format(
            profiles=",".join(sorted(service_profiles - target_profiles)),
            service=service,
            target=target,
        )


def test_every_profile_resolves_to_a_non_empty_service_set():
    """Each profile must be startable on its own -- `--profiles=<one>` is a
    documented entry point (README, docs/deployment.md)."""
    services = compat.resolve_core_services(REPO)
    profiles = {profile for names in services.values() for profile in names}
    assert profiles, "no compose profiles found in the core"

    for profile in sorted(profiles):
        selected = {name for name, names in services.items() if profile in names}
        assert selected, f"profile '{profile}' enables no service"
