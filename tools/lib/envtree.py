"""Env-tree I/O: discovery, seeding, persistence, and version stamping.

The "env tree" is a dict mapping a service's directory (relative to `src/`,
POSIX-style, "" for the repo-root `src/.env`) to that service's flat
key/value dict. Using (dir, key) pairs rather than one flat global dict is
required because a few key names (e.g. LITELLM_API_KEY) are reused, with
independent meaning, across more than one service's .env file.

See docs/configuration.md for the user-facing description of the algorithms
built on top of this tree (secret stickiness lives in secrets.py, hostname
derivation in resolve.py).
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import common

EnvTree = dict[str, dict[str, str]]


def discover_env_examples(repo_root: Path) -> dict[str, Path]:
    """Map every service directory (relative to src/, "" = root) to its
    .env.example file."""
    src = repo_root / "src"
    result: dict[str, Path] = {}
    for example in sorted(src.rglob(".env.example")):
        rel_dir = example.parent.relative_to(src).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        result[rel_dir] = example
    return result


def load_seed_tree(repo_root: Path) -> EnvTree:
    """Build the env tree from every shipped .env.example."""
    tree: EnvTree = {}
    for rel_dir, example_path in discover_env_examples(repo_root).items():
        tree[rel_dir] = common.parse_env_file(example_path)
    return tree


def load_config_dir_tree(config_dir: Path, repo_root: Path) -> EnvTree:
    """Load the current state of the config dir's .env files, falling back
    to the shipped seed for any directory not yet materialized there."""
    seed = load_seed_tree(repo_root)
    tree: EnvTree = {}
    for rel_dir in seed:
        target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        if target.is_file():
            tree[rel_dir] = common.parse_env_file(target)
        else:
            tree[rel_dir] = dict(seed[rel_dir])
    return tree


def init(
    config_dir: Path, repo_root: Path, *, env_name: str = "papaia", force: bool = False
) -> None:
    """Create and seed $PAPAIA_CONFIG_DIR. Does not generate secrets or
    touch src/**/.env -- purely seeds the config dir from shipped defaults."""
    common.ensure_dir(config_dir / "overlay")
    common.ensure_dir(config_dir / "overrides")
    common.ensure_dir(config_dir / "overrides" / "addons")
    common.ensure_dir(config_dir / "certs")

    seed = load_seed_tree(repo_root)
    for rel_dir, values in seed.items():
        target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        if target.is_file() and not force:
            continue
        common.atomic_write(target, _render_env_lines(values))

    deployment_path = config_dir / "deployment.yaml"
    if not deployment_path.is_file() or force:
        # Local import: deployment.seed() resolves the platform version via
        # this module, so a top-level import would be circular.
        from . import deployment

        deployment.seed(deployment_path, repo_root, env_name)


def _render_env_lines(values: dict[str, str]) -> str:
    return "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"


def resolve_platform_version(repo_root: Path) -> str:
    """Platform version, in order of trust: the VERSION file (single source
    of truth -- static so it also works from a tarball without .git),
    CHANGELOG.md's first `## [x.y.z]` header (checkouts predating VERSION),
    then "0.0.0-dev" (e.g. a branch whose only section is [Unreleased])."""
    version_file = repo_root / "VERSION"
    if version_file.is_file():
        text = version_file.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", text):
            return text
    changelog = repo_root / "CHANGELOG.md"
    if not changelog.is_file():
        return "0.0.0-dev"
    match = re.search(
        r"^## \[(\d+\.\d+\.\d+)\]", changelog.read_text(encoding="utf-8"), re.MULTILINE
    )
    return match.group(1) if match else "0.0.0-dev"


def stamp_platform_version(tree: EnvTree, repo_root: Path) -> EnvTree:
    """Populate the root .env's PAPAIA_VERSION (a blank, "do not edit"
    placeholder in src/.env.example) with the resolved platform version, so
    it always reflects the checkout setup last ran against."""
    tree.setdefault("", {})["PAPAIA_VERSION"] = resolve_platform_version(repo_root)
    return tree


def stamp_config_dir(tree: EnvTree, config_dir: Path) -> EnvTree:
    """Populate the root .env's PAPAIA_CONFIG_DIR with the actually-resolved
    config directory, so docker compose's ${PAPAIA_CONFIG_DIR} bind mounts
    resolve to the same place render_core just wrote to, instead of the
    placeholder shipped in src/.env.example."""
    tree.setdefault("", {})["PAPAIA_CONFIG_DIR"] = str(config_dir)
    return tree


# The placeholder shipped in src/.env.example -- treated as "not customised"
# so it is overwritten by the derived path rather than kept sticky.
_WORKSPACE_DIR_PLACEHOLDER = "/srv/papaia/workspace"


def stamp_workspace_dir(tree: EnvTree, repo_root: Path) -> EnvTree:
    """Populate the root .env's PAPAIA_WORKSPACE_DIR with the parent of this
    checkout, so the optional papaia-manager's path-parity holds automatically.

    The manager mounts ${PAPAIA_WORKSPACE_DIR} at the same path inside its
    container and imports lib.* from ${PAPAIA_WORKSPACE_DIR}/papaia/tools (and
    reads ${PAPAIA_WORKSPACE_DIR}/papaia/VERSION), so the workspace dir must be
    the directory that *contains* this `papaia` checkout. Deriving it from
    repo_root removes a hand-editing step that otherwise silently breaks addon
    operations.

    The derivation only applies when the checkout is named `papaia` (the
    manager's hard-coded subpath); an operator who renamed the checkout, or
    who set a real non-placeholder value by hand, keeps their value."""
    root = tree.setdefault("", {})
    current = root.get("PAPAIA_WORKSPACE_DIR", "")
    if current and current != _WORKSPACE_DIR_PLACEHOLDER:
        return tree  # operator-customised -- leave it sticky
    # Resolve first so a relative repo_root (e.g. "..") yields a real basename.
    resolved = repo_root.resolve()
    if resolved.name == "papaia":
        root["PAPAIA_WORKSPACE_DIR"] = str(resolved.parent)
    return tree


# The placeholder shipped in src/.env.example -- treated as "not customised"
# so it is overwritten by the detected socket GID rather than kept sticky.
_DOCKER_GID_PLACEHOLDER = "999"
_DOCKER_SOCKET = "/var/run/docker.sock"


def stamp_docker_gid(tree: EnvTree, *, socket_path: str = _DOCKER_SOCKET) -> EnvTree:
    """Populate the root .env's DOCKER_GID with the GID that actually owns the
    Docker socket on this host, so the optional papaia-manager's non-root 'app'
    user can reach the Docker API without a hand-editing step.

    The manager joins this GID via `group_add`; a wrong value makes every
    docker.sock access inside the container fail with EACCES. The owning GID
    varies by host and context -- e.g. 999 on a stock Linux `docker` group,
    but 1001 under Docker Desktop's WSL2 integration -- so it cannot be a fixed
    shipped default, and a bare reseed (uninstall --clean-up + setup) would
    otherwise silently restore the wrong placeholder.

    Sticky, like stamp_workspace_dir: an operator who set a real, non-placeholder
    value by hand keeps it. The placeholder shipped in .env.example, or an empty
    value, is replaced by the detected socket GID. If the socket cannot be
    stat'd (setup run on a host without a local Docker socket, e.g. a remote
    daemon), the current value is left untouched."""
    root = tree.setdefault("", {})
    current = root.get("DOCKER_GID", "")
    if current and current != _DOCKER_GID_PLACEHOLDER:
        return tree  # operator-customised -- leave it sticky
    try:
        gid = os.stat(socket_path).st_gid
    except OSError:
        return tree  # no local socket to probe -- keep the existing value
    root["DOCKER_GID"] = str(gid)
    return tree


# ─────────────────────────────────────────────────────────────────────────
# Run summary
# ─────────────────────────────────────────────────────────────────────────


def write_run_summary(config_dir: Path, tree: EnvTree, *, fresh_init: bool, force: bool) -> None:
    root = tree.get("", {})
    summary = {
        "papaia_version": root.get("PAPAIA_VERSION", ""),
        "deployed_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "config_dir": str(config_dir),
        "env": root.get("COMPOSE_PROJECT_NAME", "papaia"),
        "app_host": root.get("PAPAIA_HOST", ""),
        "auth_host": root.get("AUTH_HOST", ""),
        "auth_provider": root.get("AUTH_PROVIDER", "internal_keycloak"),
        "reverse_proxy_provider": root.get("REVERSE_PROXY_PROVIDER", "internal_nginx"),
        "external_reverse_proxy": "nginx" not in root.get("COMPOSE_PROFILES", "").split(","),
        "fresh_init": fresh_init,
        "force": force,
    }
    common.atomic_write(
        config_dir / "deployed.lock", json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )


# ─────────────────────────────────────────────────────────────────────────
# Persistence: write the tree to both $PAPAIA_CONFIG_DIR and src/**/.env
# ─────────────────────────────────────────────────────────────────────────


def persist_tree(tree: EnvTree, config_dir: Path, repo_root: Path) -> None:
    seed = load_seed_tree(repo_root)
    for rel_dir, values in tree.items():
        template = seed.get(rel_dir)
        template_path = (
            (repo_root / "src" / rel_dir / ".env.example")
            if rel_dir
            else (repo_root / "src" / ".env.example")
        )
        config_target = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        repo_target = (
            repo_root / "src" / rel_dir / ".env" if rel_dir else repo_root / "src" / ".env"
        )
        if template is None:
            continue
        common.write_env_file(
            config_target, values, template_path=template_path if template_path.is_file() else None
        )
        common.write_env_file(
            repo_target, values, template_path=template_path if template_path.is_file() else None
        )


def materialize_core_env(config_dir: Path, repo_root: Path) -> None:
    """Copy each core .env from the config bundle into the checkout before compose up.

    Mirrors addons.materialize_addon_env for the core stack: the config
    bundle in config_dir is the single source of truth; the checkout copies
    under repo_root/src/ are derived and must be refreshed before every
    start so that a git-clean checkout or a manually deleted src/.env never
    causes a silent stale-env start.
    """
    seed = load_seed_tree(repo_root)
    for rel_dir in seed:
        bundle_env = config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env"
        checkout_env = (
            repo_root / "src" / rel_dir / ".env" if rel_dir else repo_root / "src" / ".env"
        )
        if bundle_env.is_file():
            checkout_env.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bundle_env, checkout_env)
