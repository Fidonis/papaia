"""The optional modules (LocalAI, web search, the RAG system, the mail relay): what each owns.

Switching a module off removes its containers and keeps everything else (`stop --clean-up`,
then `setup --no-<module>`). Two things can follow, and they are separate on purpose:

* **Delete the module's data**: its named Docker volumes. `stop --clean-up --volumes
  --profiles=<profile>` removes the anonymous volumes of its containers with them, and
  `purge_data` removes the named ones by name, from the compose files' own table of who mounts
  what (`backup.resolve_core_volume_owners`), so a volume of a module that is already off is
  found as well.
* **Delete the module's settings**: `reset_config` puts the module's `.env` files back to what
  the release ships, removes the files it keeps outside them (the mail password, the RAG
  catalog) and regenerates its secrets where that is safe.

A module's settings and its data can be bound to each other. The RAG system encrypts the
ingester's stored credentials with `QI_CONNECTIONS_SECRET` and keeps the grants of its
collections in the Qdrant volume; settings reset with the data kept would leave data nobody can
read. `ModuleSpec.settings_need_data` marks such a module, and `purge` refuses its settings
without its data.

A module can also have **questions**: the ones `setup` asks when the module is switched on
(the public URL of LocalAI, of Qdrant). `info` lists them with the value that would be
stored and whether the question is still open, so a caller that switches the module on (the
manager's Modules tab) can ask them in a dialog and hand the answers to `setup`. A question is
open when the stored value is empty, a placeholder or what the release ships (`setup` does not
keep such a value either); the settings reset puts the values back to that state.

Nothing here touches another module, the stack's always-on services, Keycloak or the
Nginx Proxy Manager. The documents folder of the RAG system holds the operator's own files and is
never deleted.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import backup, common, envtree, resolve, secrets


class ModuleError(Exception):
    """A request the module operations refuse or cannot finish. The message says why."""


@dataclass(frozen=True)
class Question:
    """A question `setup` asks when a module is switched on: the public URL of a service."""

    key: str  # the key of the root `.env` that holds the answer
    option: str  # the `setup` option that sets it
    label: str  # the question, as `setup` words it
    derive: Callable[[str, str], str]  # (app host, port) -> the default
    port_key: str
    default_port: str


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    profile: str
    # Directories (relative to `src/`) whose `.env` belongs to the module alone.
    env_dirs: tuple[str, ...]
    # Keys of the root `.env` the module's settings own.
    root_keys: tuple[str, ...] = ()
    # Files under the configuration directory removed with the settings (a trailing `/*`
    # means the files directly inside that directory, which stays).
    files: tuple[str, ...] = ()
    # Whether regenerating the module's secrets is safe for the rest of the stack.
    regenerate_secrets: bool = False
    # Whether settings reset with the data kept would leave data that cannot be read.
    settings_need_data: bool = False
    # What `setup` asks when the module is switched on.
    questions: tuple[Question, ...] = ()


MODULES: dict[str, ModuleSpec] = {
    "localai": ModuleSpec(
        name="localai",
        profile="localai",
        env_dirs=("ai/localai",),
        root_keys=("LOCALAI_IMAGE_VARIANT", "LOCALAI_PUBLIC_URL"),
        questions=(
            Question(
                key="LOCALAI_PUBLIC_URL",
                option="--localai-host",
                label="Public URL of LocalAI",
                derive=resolve.derive_localai_url_default,
                port_key="LOCALAI_EXT_PORT",
                default_port="8080",
            ),
        ),
    ),
    "web-search": ModuleSpec(
        name="web-search",
        profile="librechat-websearch",
        env_dirs=("services/searxng", "services/firecrawl", "ai/jinaai"),
    ),
    "rag": ModuleSpec(
        name="rag",
        profile="rag",
        env_dirs=("ai/rag",),
        root_keys=("QDRANT_PUBLIC_URL",),
        files=("ai/rag/catalog/*",),
        regenerate_secrets=True,
        settings_need_data=True,
        questions=(
            Question(
                key="QDRANT_PUBLIC_URL",
                option="--qdrant-host",
                label="Public URL of Qdrant",
                derive=resolve.derive_qdrant_url_default,
                port_key="QDRANT_EXT_PORT",
                default_port="6333",
            ),
        ),
    ),
    "mail": ModuleSpec(
        name="mail",
        profile="smtp",
        env_dirs=("infra/smtp-relay",),
        files=("infra/smtp-relay/upstream-password",),
    ),
}

# Named volumes are `<project>_<key>` and the key is a plain compose name. Checked before a
# name reaches `docker volume rm`.
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _docker(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        argv, capture_output=True, text=True, timeout=60, check=False
    )


def spec(name: str) -> ModuleSpec:
    found = MODULES.get(name)
    if found is None:
        raise ModuleError(f"unknown module {name!r} (one of {', '.join(sorted(MODULES))})")
    return found


def _project(config_dir: Path) -> str:
    return common.parse_env_file(config_dir / ".env").get("COMPOSE_PROJECT_NAME") or "papaia"


def _active_profiles(config_dir: Path) -> set[str]:
    raw = common.parse_env_file(config_dir / ".env").get("COMPOSE_PROFILES", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def volume_keys(repo_root: Path, module: ModuleSpec) -> list[str]:
    """The named volumes the module's services mount, by their key in the compose files.

    Selected by profile, not by module label: the web search profile covers four modules and
    only one of them owns volumes."""
    owners = backup.resolve_core_volume_owners(repo_root)
    return sorted(key for key, owner in owners.items() if module.profile in owner.profiles)


def _existing_volumes(runner: Runner) -> set[str] | None:
    """The names of the Docker volumes that exist, or None when Docker cannot be asked."""
    try:
        done = runner(["docker", "volume", "ls", "--format", "{{.Name}}"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return {line.strip() for line in done.stdout.splitlines() if line.strip()}


def questions(config_dir: Path, name: str) -> list[dict]:
    """What `setup` asks for the module, with the default and whether it is still open.

    `value` is what is stored when that is worth keeping (`setup` keeps a stored URL unless it
    is empty, a placeholder or the one the release ships); `default` is what `setup` would
    derive from the stack's host. `ask` is true when there is no such stored value."""
    module = spec(name)
    root = common.parse_env_file(config_dir / ".env")
    app_host = root.get("PAPAIA_HOST", "")
    found = []
    for question in module.questions:
        port = root.get(question.port_key) or question.default_port
        kept = resolve.sticky_service_url(root.get(question.key, ""), question.derive, port)
        found.append(
            {
                "key": question.key,
                "option": question.option,
                "label": question.label,
                "default": question.derive(app_host, port),
                "value": kept,
                "ask": not kept,
            }
        )
    return found


def info(config_dir: Path, repo_root: Path, name: str, *, runner: Runner | None = None) -> dict:
    """What switching the module off could delete, for the dialog that asks.

    `exists` is None when Docker cannot be asked (a manager without the socket, a host without
    Docker): the volumes are then listed by name only."""
    module = spec(name)
    project = _project(config_dir)
    existing = _existing_volumes(runner or _docker)
    volumes = []
    for key in volume_keys(repo_root, module):
        real = f"{project}_{key}"
        volumes.append(
            {"key": key, "name": real, "exists": None if existing is None else real in existing}
        )
    return {
        "module": module.name,
        "profile": module.profile,
        "active": module.profile in _active_profiles(config_dir),
        "volumes": volumes,
        "settings": {
            "dirs": list(module.env_dirs),
            "root_keys": list(module.root_keys),
            "files": list(module.files),
            "regenerates_secrets": module.regenerate_secrets,
        },
        "settings_need_data": module.settings_need_data,
        "questions": questions(config_dir, name),
    }


def purge_data(
    config_dir: Path, repo_root: Path, name: str, *, runner: Runner | None = None
) -> list[str]:
    """Remove the module's named volumes. Returns the names that were removed.

    Refused while the module's profile is still on: its containers hold the volumes, and the
    caller switches the module off first. A volume that is still in use is reported, never
    forced."""
    module = spec(name)
    if module.profile in _active_profiles(config_dir):
        raise ModuleError(
            f"{module.name} is still switched on; switch it off before deleting its data"
        )
    run = runner or _docker
    project = _project(config_dir)
    existing = _existing_volumes(run)
    if existing is None:
        raise ModuleError("Docker did not answer, so no volume was removed")
    removed: list[str] = []
    failed: list[str] = []
    for key in volume_keys(repo_root, module):
        real = f"{project}_{key}"
        if real not in existing:
            continue
        if not _VOLUME_NAME_RE.match(real):
            raise ModuleError(f"refusing to remove a volume named {real!r}")
        done = run(["docker", "volume", "rm", real])
        if done.returncode == 0:
            removed.append(real)
        else:
            lines = (done.stderr or done.stdout).strip().splitlines()
            failed.append(f"{real}: {lines[-1] if lines else 'failed'}"[:200])
    if failed:
        raise ModuleError("could not remove " + "; ".join(failed))
    return removed


def _placeholder_keys(seed_dir: dict[str, str]) -> set[str]:
    return {key for key, value in seed_dir.items() if value.startswith("GENERATE_")}


def reset_config(config_dir: Path, repo_root: Path, name: str) -> list[str]:
    """Put the module's settings back to what the release ships. Returns what was touched.

    Operator-chosen values go back to the shipped defaults. Generated secrets stay as they
    are (other modules hold copies of some of them), unless the module regenerates them. The
    module's files outside the `.env` files are removed. Does not run `setup`: a later `setup`
    fills what is missing, so the module's `.env` is never absent for long."""
    module = spec(name)
    if module.profile in _active_profiles(config_dir):
        raise ModuleError(
            f"{module.name} is still switched on; switch it off before resetting its settings"
        )
    seed = envtree.load_seed_tree(repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    touched: list[str] = []

    for rel_dir in module.env_dirs:
        shipped = seed.get(rel_dir)
        if shipped is None:
            continue
        current = tree.get(rel_dir, {})
        generated = _placeholder_keys(shipped)
        fresh = dict(shipped)
        if not module.regenerate_secrets:
            for key in generated:
                fresh[key] = current.get(key, shipped[key])
        tree[rel_dir] = fresh
        touched.append(f"{rel_dir}/.env")

    if module.root_keys:
        root = tree.setdefault("", {})
        for key in module.root_keys:
            root[key] = seed.get("", {}).get(key, "")
        touched.append(".env")

    if module.regenerate_secrets:
        tree = secrets.generate_missing_secrets(tree, seed)

    dirs = [*module.env_dirs, *([""] if module.root_keys else [])]
    for rel_dir in dirs:
        template = (
            repo_root / "src" / rel_dir / ".env.example"
            if rel_dir
            else repo_root / "src" / ".env.example"
        )
        for target in (
            config_dir / rel_dir / ".env" if rel_dir else config_dir / ".env",
            repo_root / "src" / rel_dir / ".env" if rel_dir else repo_root / "src" / ".env",
        ):
            common.write_env_file(
                target, tree[rel_dir], template_path=template if template.is_file() else None
            )

    for entry in module.files:
        if entry.endswith("/*"):
            directory = config_dir / entry[:-2]
            if directory.is_dir():
                for item in sorted(directory.iterdir()):
                    if item.is_file():
                        item.unlink()
                        touched.append(item.relative_to(config_dir).as_posix())
        else:
            target = config_dir / entry
            if target.is_file():
                target.unlink()
                touched.append(entry)
    return touched
