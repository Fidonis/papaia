"""The module actions a restore runs before an add-on starts (RE-06, BE-16, BE-17).

A restore point brings back every record a module deleted after it was taken. Each module
therefore keeps an erasure journal at the backup target, and only `restore` (and a rollback
through it) has the module apply it again: the add-on declares the reserved action
`erasure-replay` under `actions:` (contract generation 14), a one-off service of its own
compose project that reads its journal and deletes again what it lists. A holder of
delegations declares `post-restore` as well (new sealing key, emptied `delegations` table,
halted triggers and runs). Both run with `docker compose run --rm`, which starts the
service's databases first, and before any service of the add-on starts.

`restore` records what is due in `$PAPAIA_CONFIG_DIR/module-actions.pending` once it wrote
anything; every start of the add-on (`start`, the restart of a scoped restore, `addon
start`) runs the due actions first and starts the add-on only when they succeeded. A
failed action stays due, so the next start runs it again; the actions are idempotent. A
pending file that cannot be read keeps every add-on with a pending step down: what is due
is unknown, and starting a module that may hold deleted records is the failure this
prevents. For the same reason a scoped restore refuses to replace such a file (only a whole
restore does), and the stack is not started again.

`addon run` does not run these actions and does not list them: their only caller is the
restore, with the trigger it names in `PAPAIA_ERASURE_TRIGGER` and the correlation id of
the restore in `PAPAIA_CORRELATION_ID`. Every run is one `papaia.audit/1` row in the
host's audit journal, with the exit code and without content.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import common, compat, deployment, images

MARKER = "module-actions.pending"
FORMAT = "papaia.module-actions-pending/1"
# In the order they run: the deletions first, then the holder's own step.
RESERVED = ("erasure-replay", "post-restore")
# Reserved as well (contract generation 15), run only by `papaia-ctl person export|erase`
# (lib/person.py), never by a restore and never by `addon run`.
PERSON_ACTIONS = ("person-export", "person-erase", "transfer-ownership")
TRIGGERS = ("restore", "rollback")
GENERATION = 14

_ADDON_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_SERVICE_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\Z")
_POINT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_CID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# One argument per tab-separated field of the line bash reads.
_ARG_RE = re.compile(r"\A[^\t\n\r\x00]{1,512}\Z")
_FIELDS = {"format", "trigger", "correlation_id", "restore_point", "modules"}
_STATES = ("none", "pending", "ok")
_RESULTS = ("ok", "partial", "failed")


class ModuleActionError(Exception):
    """A pending file, a request or a manifest the step cannot act on safely."""


def is_reserved(name: str) -> bool:
    return name in RESERVED or name in PERSON_ACTIONS


def reserved_actions(manifest: dict) -> list[str]:
    """The reserved actions a manifest declares, in the order they run."""
    try:
        declared = compat.addon_actions(manifest)
    except ValueError as exc:
        raise ModuleActionError(str(exc)) from None
    return [name for name in RESERVED if name in declared]


def _marker(config_dir: Path) -> Path:
    return Path(config_dir) / MARKER


def _check_trigger(trigger: object) -> str:
    if trigger not in TRIGGERS:
        raise ModuleActionError(f"trigger must be one of {', '.join(TRIGGERS)}")
    return str(trigger)


def _check(doc: object) -> dict:
    if not isinstance(doc, dict) or set(doc) != _FIELDS or doc.get("format") != FORMAT:
        raise ModuleActionError("not a pending file of this format")
    _check_trigger(doc["trigger"])
    if not isinstance(doc["correlation_id"], str) or not _CID_RE.match(doc["correlation_id"]):
        raise ModuleActionError("correlation_id is not a lowercase UUID")
    if not isinstance(doc["restore_point"], str) or not _POINT_RE.match(doc["restore_point"]):
        raise ModuleActionError("restore_point is not a restore point id")
    modules = doc["modules"]
    if not isinstance(modules, dict) or len(modules) > 200:
        raise ModuleActionError("modules must be a mapping")
    for name, actions in modules.items():
        if not isinstance(name, str) or not _ADDON_RE.match(name):
            raise ModuleActionError("modules names an add-on that is not a valid name")
        if (
            not isinstance(actions, list)
            or not actions
            or len(set(actions)) != len(actions)
            or not all(a in RESERVED for a in actions)
        ):
            raise ModuleActionError(f"modules.{name} must list reserved actions")
    return doc


def load(config_dir: Path) -> dict | None:
    """The pending file, or None without one. Raises ModuleActionError when it cannot be
    read as one: the caller then starts no add-on with a pending step."""
    path = _marker(config_dir)
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise ModuleActionError(f"{path} is not a regular file")
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ModuleActionError(f"{path} is too large")
        doc = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ModuleActionError(f"{path} cannot be read: {exc}") from None
    try:
        return _check(doc)
    except ModuleActionError as exc:
        raise ModuleActionError(f"{path}: {exc}") from None


def _store(config_dir: Path, doc: dict) -> None:
    path = _marker(config_dir)
    if not doc["modules"]:
        path.unlink(missing_ok=True)
        return
    common.atomic_write_private(path, json.dumps(doc, sort_keys=True, indent=1) + "\n")


def _manifest(config_dir: Path, repo_root: Path, name: str) -> dict | None:
    entry = next(
        (a for a in (deployment.load(config_dir) or {}).get("addons") or []
         if a.get("name") == name),
        None,
    )
    if entry is None:
        return None
    manifest, problem = deployment.load_addon_manifest(
        deployment.resolve_addon_path(entry, repo_root)
    )
    if manifest is None:
        raise ModuleActionError(f"add-on {name}: {problem}")
    return manifest


def mark(
    config_dir: Path,
    repo_root: Path,
    *,
    addons: list[str] | None,
    trigger: str,
    restore_point: str,
    correlation_id: str,
) -> dict[str, list[str]]:
    """Record the reserved actions every active add-on of the restore declares (all of
    them, or the ones in `addons` for a scoped restore). Returns {add-on: actions}.

    Replaces an older pending file: the restore just wrote older data again, so every
    action is due once more, for every add-on of this restore. A scoped restore keeps the
    steps still due for the add-ons outside it, so it refuses a pending file it cannot
    read: what is due for them is unknown, and dropping it would let such an add-on start
    with records its journal deletes. Only a whole restore, which marks every add-on
    again, replaces a damaged file."""
    _check_trigger(trigger)
    if not isinstance(restore_point, str) or not _POINT_RE.match(restore_point):
        raise ModuleActionError("restore point id is not valid")
    if not isinstance(correlation_id, str) or not _CID_RE.match(correlation_id):
        raise ModuleActionError("correlation id is not a lowercase UUID")
    wanted = None if addons is None else set(addons)
    previous = None
    try:
        previous = load(config_dir)
    except ModuleActionError as exc:
        if wanted is not None:
            raise ModuleActionError(
                f"{exc}; it may still hold steps due for add-ons outside this scoped "
                "restore, so it is not replaced. Run a whole restore (without --only), "
                "which marks every add-on again"
            ) from None
    modules: dict[str, list[str]] = {}
    if previous is not None:
        # Steps a scoped restore did not touch stay due.
        modules.update({k: v for k, v in previous["modules"].items()
                        if wanted is not None and k not in wanted})
    for entry in deployment.active_addons(deployment.load(config_dir)):
        name = entry.get("name") or ""
        if wanted is not None and name not in wanted:
            continue
        if not _ADDON_RE.match(name):
            raise ModuleActionError(f"add-on name {name!r} is not valid")
        manifest, problem = deployment.load_addon_manifest(
            deployment.resolve_addon_path(entry, repo_root)
        )
        if manifest is None:
            raise ModuleActionError(f"add-on {name}: {problem}")
        actions = reserved_actions(manifest)
        if actions:
            modules[name] = actions
    _store(config_dir, {
        "format": FORMAT,
        "trigger": trigger,
        "correlation_id": correlation_id,
        "restore_point": restore_point,
        "modules": dict(sorted(modules.items())),
    })
    return {k: v for k, v in sorted(modules.items()) if wanted is None or k in wanted}


def pending(config_dir: Path, repo_root: Path, name: str) -> tuple[str, str, list]:
    """(trigger, correlation id, [(action, service, args)]) due for add-on `name` before
    it starts; ("", "", []) when nothing is due."""
    if not isinstance(name, str) or not _ADDON_RE.match(name):
        raise ModuleActionError("add-on name is not valid")
    doc = load(config_dir)
    if doc is None or name not in doc["modules"]:
        return "", "", []
    manifest = _manifest(config_dir, repo_root, name)
    if manifest is None:
        raise ModuleActionError(
            f"add-on {name} has a pending restore step but is no longer registered"
        )
    try:
        declared = compat.addon_actions(manifest)
    except ValueError as exc:
        raise ModuleActionError(f"add-on {name}: {exc}") from None
    steps = []
    for action in doc["modules"][name]:
        spec = declared.get(action)
        if spec is None:
            raise ModuleActionError(
                f"add-on {name} no longer declares the action {action} that the restore of "
                f"{doc['restore_point']} still has to run; install a version that declares "
                "it, or restore again"
            )
        if not _SERVICE_RE.match(spec["service"]):
            raise ModuleActionError(f"actions.{action}.service of {name} is not a service name")
        if len(spec["args"]) > 32 or not all(_ARG_RE.match(a) for a in spec["args"]):
            raise ModuleActionError(
                f"actions.{action}.args of {name}: at most 32 arguments of one line each"
            )
        steps.append((action, spec["service"], list(spec["args"])))
    return doc["trigger"], doc["correlation_id"], steps


def _row(operation: str, event: str, effect: str, result: str, error_code: str | None,
         detail: dict, correlation_id: str) -> dict:
    now = time.time()
    return {
        "format": "papaia.audit/1",
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int(now % 1 * 1000):03d}Z",
        "correlation_id": correlation_id,
        "writer": "papaia-ctl",
        "role": "operator",
        "sub": None,
        "identity_kind": "host",
        "azp": None,
        "catalog_id": None,
        "operation": operation,
        "effect": effect,
        "result": result,
        "error_code": error_code,
        "event": event,
        "detail": {**detail, "confirmed_by": images.confirming_user()},
    }


def done(config_dir: Path, name: str, action: str, exit_code: int) -> bool:
    """Record one run of a due action: one audit row, and on exit code 0 the step is no
    longer due. Returns whether the add-on has further steps due."""
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        raise ModuleActionError("exit code must be 0..255")
    doc = load(config_dir)
    if doc is None or name not in doc["modules"] or action not in doc["modules"][name]:
        raise ModuleActionError(f"{action} of add-on {name} is not due")
    ok = exit_code == 0
    images.append_audit(config_dir, _row(
        doc["trigger"], "module_action_run",
        "delete" if action == "erasure-replay" else "write",
        "allowed" if ok else "error",
        None if ok else "module_action_failed",
        {"addon": name, "action": action, "trigger": doc["trigger"],
         "restore_point": doc["restore_point"], "exit_code": exit_code},
        doc["correlation_id"],
    ))
    if ok:
        doc["modules"][name] = [a for a in doc["modules"][name] if a != action]
        if not doc["modules"][name]:
            del doc["modules"][name]
        _store(config_dir, doc)
    return bool(doc["modules"].get(name))


def record_restore(
    config_dir: Path,
    *,
    restore_point: str,
    operation: str,
    result: str,
    duration_s: int,
    post_restore: str,
    module_actions_state: str,
    artifacts: str,
    encrypted: bool,
    correlation_id: str,
) -> None:
    """The audit row of one restore, with how long it took (the measured RTO from the
    confirmation to the stack being up again)."""
    if operation not in ("restore", "restore-scoped") or result not in _RESULTS:
        raise ModuleActionError("operation or result is not valid")
    if module_actions_state not in _STATES or post_restore not in (
        "ok", "failed", "pending", "skipped"
    ):
        raise ModuleActionError("post-restore or module action state is not valid")
    if type(duration_s) is not int or duration_s < 0:
        raise ModuleActionError("duration must be a non-negative integer")
    if not _POINT_RE.match(restore_point) or not re.fullmatch(r"\d{1,6}/\d{1,6}", artifacts):
        raise ModuleActionError("restore point or artifact count is not valid")
    if not _CID_RE.match(correlation_id):
        raise ModuleActionError("correlation id is not a lowercase UUID")
    images.append_audit(config_dir, _row(
        operation, "restore_applied", "write",
        "allowed" if result == "ok" else "error",
        None if result == "ok" else f"restore_{result}",
        {"id": restore_point, "result": result, "artifacts": artifacts,
         "duration_s": duration_s, "post_restore": post_restore,
         "module_actions": module_actions_state, "encrypted": bool(encrypted)},
        correlation_id,
    ))


def state(config_dir: Path, marked: bool) -> str:
    """For the restore's log line: `none` when nothing was due, `pending` while a step is
    still due (or the pending file cannot be read), `ok` when every step ran."""
    if not marked:
        return "none"
    try:
        return "pending" if load(config_dir) is not None else "ok"
    except ModuleActionError:
        return "pending"


def env_correlation() -> str:
    """The correlation id of the current papaia-ctl run (bash exports it)."""
    return images.correlation_id(os.environ.get("PAPAIA_CORRELATION_ID") or None)
