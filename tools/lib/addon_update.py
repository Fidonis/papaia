"""Moving an installed add-on to another version of itself, and one step back.

An update never touches the directory the add-on is registered at. The new
version is a directory of its own (`--path`), and applying it repoints the
deployment entry; the entry it replaces is kept as `previous`, so a rollback is
the same repointing the other way and the old files are still there.

Everything that decides what an update does is a pure function of the two
manifests, the two `.env.example` files and the configuration bundle
(`plan_update`), so `addon update --dry-run` shows what the real run will do.
Nothing in this module calls docker; stopping, backing up and recreating
containers is bash's half of the split.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from . import addons, common, components, deployment, semver

SCHEMA_VERSION = 1

# Classes of a key that is new in the candidate's .env.example.
KEY_GENERATED = "generated"
KEY_CHANGE_ME = "change_me"
KEY_REPLACE_SECRET = "replace_secret"
KEY_LITERAL = "literal"

_SECRET_HINTS = ("PASS", "SECRET", "TOKEN", "KEY")


class UpdateError(Exception):
    """A precondition of update or rollback is not met. Nothing was changed."""


@dataclass(frozen=True)
class Candidate:
    """The registered add-on and the version it would move to."""

    name: str
    entry: dict
    current_path: Path
    current_manifest: dict
    new_path: Path
    new_manifest: dict


def registered_entry(deployed: dict, name: str) -> dict:
    entry = next((a for a in deployed.get("addons") or [] if a.get("name") == name), None)
    if entry is None:
        raise UpdateError(f"addon '{name}' is not registered.")
    if not entry.get("active"):
        raise UpdateError(
            f"addon '{name}' is not active. Run 'papaia-ctl addon install {name}' first."
        )
    return entry


def _load_manifest(path: Path, name: str, what: str) -> dict:
    manifest, error = deployment.load_addon_manifest(path)
    if manifest is None:
        raise UpdateError(str(error))
    if manifest.get("name") != name:
        raise UpdateError(
            f"{what} {path} is the manifest of '{manifest.get('name')}', not of '{name}'."
        )
    return manifest


def _check_same_directory_name(name: str, current_path: Path, new_path: Path) -> None:
    # Compose derives the project name from the directory name (see
    # _addon_compose); another name would leave the running project orphaned.
    if new_path.name != current_path.name:
        raise UpdateError(
            f"the directory of the new version is called '{new_path.name}', but addon"
            f" '{name}' is registered in a directory called '{current_path.name}'. Compose"
            " names the project after the directory, so the two must match."
        )


def prepare(deployed: dict, repo_root: Path, name: str, new_path: Path) -> Candidate:
    """Resolve and check everything an update needs before the gate runs."""
    entry = registered_entry(deployed, name)
    if not new_path.is_dir():
        raise UpdateError(f"--path is not a directory: {new_path}")
    new_path = new_path.resolve()
    current_path = deployment.resolve_addon_path(entry, repo_root)
    _check_same_directory_name(name, current_path, new_path)
    current_manifest, error = deployment.load_addon_manifest(current_path)
    if current_manifest is None:
        raise UpdateError(f"cannot read the installed version: {error}")
    new_manifest = _load_manifest(new_path, name, "the new version at")
    return Candidate(name, entry, current_path, current_manifest, new_path, new_manifest)


def manifest_version(manifest: dict) -> str | None:
    version = manifest.get("version")
    return str(version) if version is not None else None


def _direction(old: str | None, new: str | None) -> str:
    if old is None or new is None:
        return "unknown"
    try:
        order = semver.compare(old, new)
    except ValueError:
        return "unknown"
    return "same" if order == 0 else "upgrade" if order < 0 else "downgrade"


def _classify(key: str, value: str, manifest: dict) -> str:
    if common.marks_generated_secret(value):
        return KEY_GENERATED
    if value == "CHANGE_ME":
        return KEY_CHANGE_ME
    if value.startswith("REPLACE_WITH_") or key in (manifest.get("env_replace_secrets") or {}):
        return KEY_REPLACE_SECRET
    return KEY_LITERAL


def _prompt_default(key: str, manifest: dict, core_env: dict[str, str]) -> str | None:
    """What a new CHANGE_ME key falls back to without an answer, if anything."""
    cfg = (manifest.get("env_prompts") or {}).get(key) or {}
    from_core = core_env.get(cfg.get("default_from_core", ""), "")
    if from_core and from_core != "CHANGE_ME" and not common.marks_generated_secret(from_core):
        return from_core
    default = cfg.get("default")
    return str(default) if default else None


def _env_delta(
    candidate: Candidate,
    current_example: dict[str, str],
    new_example: dict[str, str],
    bundle_env: dict[str, str],
    core_env: dict[str, str],
) -> dict:
    manifest = candidate.new_manifest
    prompts = manifest.get("env_prompts") or {}
    new_keys = []
    for key, value in new_example.items():
        if key in bundle_env:
            continue
        kind = _classify(key, value, manifest)
        item: dict = {"key": key, "class": kind, "value": None, "default": None, "label": None}
        if kind == KEY_LITERAL:
            item["value"] = value
        elif kind == KEY_CHANGE_ME:
            item["default"] = _prompt_default(key, manifest, core_env)
            item["label"] = (prompts.get(key) or {}).get("label")
        elif kind == KEY_REPLACE_SECRET:
            item["label"] = ((manifest.get("env_replace_secrets") or {}).get(key) or {}).get("hint")
        new_keys.append(item)
    return {
        "new": new_keys,
        "removed": [k for k in current_example if k not in new_example],
        "default_changed": [
            {"key": k, "from": current_example[k], "to": v}
            for k, v in new_example.items()
            if k in current_example
            and current_example[k] != v
            and _classify(k, v, manifest) == KEY_LITERAL
            and _classify(k, current_example[k], candidate.current_manifest) == KEY_LITERAL
        ],
    }


def _component_delta(old: dict, new: dict) -> dict:
    before = {c["id"]: c for c in components.parse(old)}
    after = {c["id"]: c for c in components.parse(new)}
    return {
        "added": [
            {"id": i, "name": c["name"], "version": c["version"]}
            for i, c in after.items()
            if i not in before
        ],
        "removed": [
            {"id": i, "name": c["name"], "version": c["version"]}
            for i, c in before.items()
            if i not in after
        ],
        "changed": [
            {"id": i, "name": c["name"], "from": before[i]["version"], "to": c["version"]}
            for i, c in after.items()
            if i in before and before[i]["version"] != c["version"]
        ],
    }


def _as_list(value: object) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _keycloak(manifest: dict) -> tuple[list, dict]:
    cfg = (manifest.get("integration") or {}).get("keycloak") or {}
    return _as_list(cfg.get("clients")), cfg.get("client_mappers") or {}


def _manifest_delta(old: dict, new: dict) -> dict:
    old_attach = _as_list((old.get("networks") or {}).get("attach"))
    new_attach = _as_list((new.get("networks") or {}).get("attach"))
    old_clients, old_mappers = _keycloak(old)
    new_clients, new_mappers = _keycloak(new)
    return {
        "version": {"from": manifest_version(old), "to": manifest_version(new)},
        "addon_api": {
            "from": (old.get("requires") or {}).get("addon_api"),
            "to": (new.get("requires") or {}).get("addon_api"),
        },
        "attach": {
            "added": [s for s in new_attach if s not in old_attach],
            "removed": [s for s in old_attach if s not in new_attach],
        },
        "replace_secrets_added": [
            k
            for k in (new.get("env_replace_secrets") or {})
            if k not in (old.get("env_replace_secrets") or {})
        ],
        "keycloak": {
            "clients_added": [c for c in new_clients if c not in old_clients],
            "mappers_added": {
                client: [p for p in _as_list(paths) if p not in _as_list(old_mappers.get(client))]
                for client, paths in new_mappers.items()
                if any(p not in _as_list(old_mappers.get(client)) for p in _as_list(paths))
            },
        },
    }


def plan_update(
    candidate: Candidate,
    *,
    current_example: dict[str, str],
    new_example: dict[str, str],
    bundle_env: dict[str, str],
    core_env: dict[str, str],
) -> dict:
    """What moving to the candidate changes. Pure: reads nothing, writes nothing.

    Values in the configuration bundle are sticky -- an update only ever adds
    keys -- so a key is "new" when the bundle lacks it, whichever example it
    came from."""
    env = _env_delta(candidate, current_example, new_example, bundle_env, core_env)
    old_version = manifest_version(candidate.current_manifest)
    new_version = manifest_version(candidate.new_manifest)
    needs_input = [
        item["key"]
        for item in env["new"]
        if item["class"] == KEY_CHANGE_ME and item["default"] is None
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "name": candidate.name,
        "current": {"version": old_version, "path": str(candidate.current_path)},
        "candidate": {"version": new_version, "path": str(candidate.new_path)},
        "direction": _direction(old_version, new_version),
        "in_place": candidate.new_path == candidate.current_path,
        "env": env,
        "components": _component_delta(candidate.current_manifest, candidate.new_manifest),
        "manifest": _manifest_delta(candidate.current_manifest, candidate.new_manifest),
        "needs_input": needs_input,
    }


def build_plan(candidate: Candidate, config_dir: Path) -> dict:
    """`plan_update` fed from the files on disk."""
    name = candidate.name
    return plan_update(
        candidate,
        current_example=common.parse_env_file(candidate.current_path / ".env.example"),
        new_example=common.parse_env_file(candidate.new_path / ".env.example"),
        bundle_env=common.parse_env_file(config_dir / "addons" / name / ".env"),
        core_env=common.parse_env_file(config_dir / ".env"),
    )


def answerable_keys(plan: dict) -> set[str]:
    """The keys an answers file may set: the ones the plan itself asks about."""
    return {
        item["key"]
        for item in plan["env"]["new"]
        if item["class"] in (KEY_CHANGE_ME, KEY_REPLACE_SECRET)
    }


def read_answers(path: Path) -> dict[str, str]:
    """KEY=VALUE lines. Warns when other users can read the file; never prints values."""
    if not path.is_file():
        raise UpdateError(f"--answers-file not found: {path}")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        print(
            f"WARNING: {path} is readable by other users; it holds values for the add-on.",
            file=sys.stderr,
        )
    return common.parse_env_file(path)


def _looks_secret(key: str) -> bool:
    return any(hint in key.upper() for hint in _SECRET_HINTS)


def collect_answers(plan: dict, given: dict[str, str], *, interactive: bool) -> dict[str, str]:
    """The answers for a real run: the given ones, plus a prompt for each missing key.

    Raises UpdateError, listing every problem, when a key the plan needs has no
    value or a given key is not one the plan asks about."""
    allowed = answerable_keys(plan)
    unknown = sorted(k for k in given if k not in allowed)
    if unknown:
        raise UpdateError(
            "the answers file sets keys this update does not ask for: " + ", ".join(unknown)
        )
    answers = {k: v for k, v in given.items() if v}
    labels = {item["key"]: item["label"] for item in plan["env"]["new"]}
    missing = [k for k in plan["needs_input"] if k not in answers]
    if missing and interactive:
        import getpass

        print("\nThis version needs values for new settings:\n")
        for key in missing:
            ask = getpass.getpass if _looks_secret(key) else input
            try:
                value = ask(f"  {labels.get(key) or key}: ").strip()
            except EOFError:
                break
            if value:
                answers[key] = value
        print()
        missing = [k for k in plan["needs_input"] if k not in answers]
    if missing:
        raise UpdateError(
            "no value for: "
            + ", ".join(missing)
            + ". Pass them with --answers-file=FILE (KEY=VALUE lines) or run on a terminal."
        )
    return answers


def write_answers(path: Path, answers: dict[str, str]) -> None:
    common.atomic_write_private(path, "".join(f"{k}={v}\n" for k, v in answers.items()))


def apply_update(
    candidate: Candidate,
    plan: dict,
    answers: dict[str, str],
    *,
    config_dir: Path,
    restore_point: str | None,
) -> dict:
    """Seed the new keys, take the answers, repoint the entry. Returns the new entry.

    The caller saves `deployed` afterwards and renders; the bundle and the
    checkout `.env` are written here because they must exist before either."""
    name = candidate.name
    entry = candidate.entry
    addons.seed_addon_env(candidate.new_path, config_dir)

    bundle_env_path = config_dir / "addons" / name / ".env"
    chosen = dict(answers)
    for item in plan["env"]["new"]:
        if item["class"] == KEY_CHANGE_ME and item["key"] not in chosen and item["default"]:
            chosen[item["key"]] = item["default"]
    if chosen:
        common.write_env_file(bundle_env_path, chosen)
    addons.materialize_addon_env(config_dir, candidate.new_path, name)

    new_version = manifest_version(candidate.new_manifest)
    if plan["in_place"]:
        entry.pop("previous", None)
    else:
        previous: dict = {
            "path": entry["path"],
            "version": plan["current"]["version"] or entry.get("version"),
        }
        if restore_point:
            previous["restore_point"] = restore_point
        entry["previous"] = {k: v for k, v in previous.items() if v}
    entry["path"] = str(candidate.new_path)
    if new_version is not None:
        entry["version"] = new_version
    return entry


def rollback_target(deployed: dict, repo_root: Path, name: str) -> tuple[dict, Path, dict]:
    """The entry, the directory it would go back to, and that directory's manifest."""
    entry = registered_entry(deployed, name)
    previous = entry.get("previous")
    if not isinstance(previous, dict) or not previous.get("path"):
        raise UpdateError(f"addon '{name}' has no previous version to go back to.")
    target = deployment.resolve_addon_path(previous, repo_root)
    if not target.is_dir():
        raise UpdateError(f"the previous version of '{name}' is gone: {target}")
    _check_same_directory_name(name, deployment.resolve_addon_path(entry, repo_root), target)
    return entry, target, _load_manifest(target, name, "the previous version at")


def apply_rollback(entry: dict, target: Path, manifest: dict, *, config_dir: Path) -> dict:
    """Repoint the entry at the previous version and forget it. Returns the new entry."""
    name = entry["name"]
    addons.seed_addon_env(target, config_dir)
    addons.materialize_addon_env(config_dir, target, name)
    entry["path"] = entry["previous"]["path"]
    version = manifest_version(manifest)
    if version is not None:
        entry["version"] = version
    del entry["previous"]
    return entry


def format_plan(plan: dict) -> str:
    """The review a terminal operator reads before confirming."""
    cur, new = plan["current"], plan["candidate"]
    lines = [
        f"Update {plan['name']}: {cur['version'] or 'unknown'} -> {new['version'] or 'unknown'}"
    ]
    if plan["direction"] == "downgrade":
        lines.append("  This is a DOWNGRADE.")
    if plan["in_place"]:
        lines.append("  Same directory as the installed version: there will be no way back.")
    lines += [f"  from {cur['path']}", f"  to   {new['path']}"]
    verdict = plan.get("compat")
    if verdict:
        reason = f" ({verdict['reason']})" if verdict["reason"] else ""
        lines.append(f"Compatibility with this core: {verdict['status']}{reason}")

    env = plan["env"]
    if env["new"]:
        lines.append(f"New settings ({len(env['new'])}):")
        for item in env["new"]:
            lines.append(f"  {item['key']}: {_describe_key(item)}")
    if env["removed"]:
        lines.append(
            "No longer in .env.example (your .env keeps them): " + ", ".join(env["removed"])
        )
    for item in env["default_changed"]:
        lines.append(
            f"Default changed, your value stays: {item['key']}: {item['from']} -> {item['to']}"
        )

    delta = plan["components"]
    if delta["added"] or delta["removed"] or delta["changed"]:
        lines.append("Components:")
        lines += [f"  + {c['name']} {c['version']}" for c in delta["added"]]
        lines += [f"  - {c['name']} {c['version']}" for c in delta["removed"]]
        lines += [f"  ~ {c['name']} {c['from']} -> {c['to']}" for c in delta["changed"]]

    man = plan["manifest"]
    if man["addon_api"]["from"] != man["addon_api"]["to"]:
        lines.append(f"Requires add-on API: {man['addon_api']['from']} -> {man['addon_api']['to']}")
    for verb, key in (("+", "added"), ("-", "removed")):
        if man["attach"][key]:
            lines.append(f"Attached core services {verb} " + ", ".join(man["attach"][key]))
    if man["keycloak"]["clients_added"] or man["keycloak"]["mappers_added"]:
        lines.append("New Keycloak clients or mappers: they have to be imported by hand.")
    if plan["needs_input"]:
        lines.append("Needs a value before it can run: " + ", ".join(plan["needs_input"]))
    return "\n".join(lines)


def _describe_key(item: dict) -> str:
    kind = item["class"]
    if kind == KEY_GENERATED:
        return "a secret is generated"
    if kind == KEY_LITERAL:
        return f"set to {item['value']}"
    if kind == KEY_REPLACE_SECRET:
        hint = f" ({item['label']})" if item["label"] else ""
        return "a Keycloak client secret to copy in" + hint
    if item["default"] is not None:
        return f"asks for a value, default {item['default']}"
    return "needs a value"
