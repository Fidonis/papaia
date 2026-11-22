"""Staged upgrade: stage plan, restore point R0, write lock and the stage-0 key check.

`papaia-ctl upgrade` runs these stages in this order (docs/deployment.md):

    0 preflight      add-on and suite-matrix check, image check, operator key check
    1 restore-point  R0, encrypted to the backup recipients; the write lock starts here
    2 core           tag change, core migrations, render, start
    3-7 modules      me, data, studio, flow, assist: `addon upgrade` per module
    8 finish         the write lock ends; stage durations are reported

After stage 2 the module stages may run one by one and in any order (`--stage=`); only
`requires.addons` is enforced. A module without a new checkout stays at its version when
the target core still accepts it (suite N-1); one the target does not accept stops the
upgrade before anything changes, or, with `--force`, is stopped and marked `blocked`.

The state of a run lives in `$PAPAIA_CONFIG_DIR/state/upgrade.json` (host only). The write
lock is `state/write-lock.json`, next to the halt file and in the same folder that every
service mounts read-only (docs/halt.md): a service that finds it active accepts reads only
and answers every write with LOCK_MESSAGE. A lock file that cannot be read counts as
active. The lock stays after a failed stage, so the way back loses no data; it ends with
the finish stage or with `upgrade --release-lock` after the restore of R0.

Until a rollback key exists for the run, stage 0 needs the operator's backup key
(`--identity=FILE|-`): it must open a check block encrypted to PAPAIA_BACKUP_RECIPIENTS,
otherwise nothing is started. The key is only held in memory.
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import age, backup_crypt, common, deployment, halt, semver

STATE_FILE = "upgrade.json"
LOCK_FILE = "write-lock.json"
STATE_SCHEMA = "papaia.upgrade-state/1"
LOCK_SCHEMA = "papaia.write-lock/1"
MAX_FILE_BYTES = 64 * 1024

CORE_STAGES = ("preflight", "restore-point", "core")
MODULE_STAGES = (
    ("me", "papaia-me"),
    ("data", "papaia-data"),
    ("studio", "papaia-studio"),
    ("flow", "papaia-flow"),
    ("assist", "papaia-assist"),
)
FINAL_STAGE = "finish"
STAGES = (*CORE_STAGES, *(s for s, _ in MODULE_STAGES), FINAL_STAGE)
SELECTABLE = ("core", *(s for s, _ in MODULE_STAGES), FINAL_STAGE)
STATUSES = ("pending", "ok", "failed", "skipped", "kept", "blocked")
ACTIONS = ("upgrade", "keep", "block", "absent")
_DONE = ("ok", "skipped", "kept", "blocked")

LOCK_MESSAGE = (
    "The installation is being updated. Your change was not saved. "
    "Please try again once the update has finished."
)
NO_KEY_MESSAGE = (
    "Without a matching backup key there is no way back; the upgrade was not started."
)

_NAME_RE = re.compile(r"\A[a-z][a-z0-9-]{0,62}\Z")
_POINT_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z_.-]{0,63}\Z")
_STATE_FIELDS = {"schema", "id", "from", "to", "started", "finished", "abandoned",
                 "restore_point", "stages", "steps"}
_STEP_FIELDS = {"stage", "addon", "action", "path", "reason"}
_LOCK_FIELDS = {"schema", "active", "since", "upgrade_id", "from", "to", "message"}


class StageError(Exception):
    """A refusal; the message is shown as it is and nothing was changed."""


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def _audit(config_dir: Path, operation: str, event: str, detail: dict,
           result: str = "allowed") -> None:
    """One `papaia.audit/1` row per write; versions, stage names and ids only."""
    backup_crypt.audit(config_dir, operation, event, detail, result=result)


# ─────────────────────────────────────────────────────────────────────────
# stage selection
# ─────────────────────────────────────────────────────────────────────────


def _module_of(stage: str) -> str | None:
    return dict(MODULE_STAGES).get(stage)


def _stage_of(addon: str) -> str | None:
    return {a: s for s, a in MODULE_STAGES}.get(addon)


def _status(state: dict | None, stage: str) -> str:
    if state is None:
        return "pending"
    return str(((state.get("stages") or {}).get(stage) or {}).get("status", "pending"))


def select_stages(requested: str | None, state: dict | None,
                  requires: dict[str, list[str]]) -> list[str]:
    """The stages to run now, in order.

    Without a selection: every stage still pending, in the default order. With one
    (`core,data`): those stages in the given order. Without a run in progress the core
    stage must be among them, and preflight and restore point come first. A module stage
    needs the core stage before it; a module that requires another (`requires.addons`)
    needs that module's stage done or earlier in the list; `finish` needs every module
    stage done or earlier in the list."""
    if requested is None:
        names = [s for s in STAGES if _status(state, s) not in _DONE]
    else:
        names = [n.strip() for n in requested.split(",") if n.strip()]
        if not names:
            raise StageError("--stage: name at least one stage")
        for name in names:
            if name not in SELECTABLE:
                raise StageError(
                    f"--stage: unknown stage {name!r}; valid: {', '.join(SELECTABLE)}"
                )
        if len(set(names)) != len(names):
            raise StageError("--stage: a stage is named twice")
        if state is None or _status(state, "restore-point") != "ok":
            names = [s for s in ("preflight", "restore-point") if s not in names] + names
    done = {s for s in STAGES if _status(state, s) in _DONE}
    for index, name in enumerate(names):
        before = done | set(names[:index])
        module = _module_of(name)
        if module is not None:
            if "core" not in before:
                raise StageError(f"stage {name!r} needs the core stage first (--stage=core)")
            for required in requires.get(module, []):
                stage = _stage_of(required)
                if stage is not None and stage not in before and _status(state, stage) \
                        not in _DONE:
                    raise StageError(
                        f"stage {name!r}: {module} requires {required}; run stage "
                        f"{stage!r} first"
                    )
        if name == FINAL_STAGE:
            missing = [s for s, _ in MODULE_STAGES if s not in before]
            if missing:
                raise StageError(
                    f"stage 'finish' needs the module stages first: {', '.join(missing)}"
                )
    return names


# ─────────────────────────────────────────────────────────────────────────
# module plan
# ─────────────────────────────────────────────────────────────────────────


def parse_addon_paths(items: list[str], active: set[str]) -> dict[str, Path]:
    """`NAME=DIR` per item: an active add-on and an existing directory, each at most once."""
    paths: dict[str, Path] = {}
    for item in items:
        if not isinstance(item, str) or len(item) > 4096:
            raise StageError("--addon-path: expected NAME=DIR")
        name, sep, raw = item.partition("=")
        if not sep or not _NAME_RE.match(name) or not raw:
            raise StageError(f"--addon-path: expected NAME=DIR, got {item[:80]!r}")
        if name not in active:
            raise StageError(f"--addon-path: {name!r} is not an active add-on")
        if name in paths:
            raise StageError(f"--addon-path: {name!r} is given twice")
        path = Path(raw).expanduser()
        if not path.is_dir():
            raise StageError(f"--addon-path: {raw!r} is not a directory")
        paths[name] = path
    return paths


def _row_cell(matrix: dict | None, target: str, addon: str) -> str | None:
    if matrix is None or addon not in matrix.get("components", []):
        return None
    from . import suite

    row, _ = suite.matrix_rows(matrix, target)
    return None if row is None else row["versions"].get(addon)


def plan_modules(results: list[dict], versions: dict[str, str | None], matrix: dict | None,
                 target: str, addon_paths: dict[str, Path], force: bool
                 ) -> tuple[list[dict], list[str]]:
    """One step per module stage plus one per other add-on the target refuses.

    `results` is the `addon check --json` verdict of the active add-ons against the
    target core. An add-on with a new checkout (`addon_paths`) is upgraded in its stage;
    `addon upgrade` checks that checkout. Without one it stays when the target accepts
    it, with a warning when only the suite before the target's lists it (BE-13a). One
    the target refuses stops the plan, or with `force` is blocked. ERROR is never
    degraded."""
    verdicts = {str(r.get("name")): r for r in results if isinstance(r, dict)}
    steps: list[dict] = []
    warnings: list[str] = []
    problems: list[str] = []

    def judge(stage: str, addon: str) -> dict:
        path = addon_paths.get(addon)
        verdict = verdicts.get(addon) or {}
        status = verdict.get("status")
        reason = str(verdict.get("reason") or "")
        if status == "ERROR":
            problems.append(f"{addon}: {reason or 'the add-on check failed'}")
            return {}
        if path is not None:
            return {"stage": stage, "addon": addon, "action": "upgrade", "path": str(path),
                    "reason": ""}
        if status == "INCOMPATIBLE":
            if not force:
                problems.append(f"{addon}: {reason or 'not compatible with the target core'}")
                return {}
            return {"stage": stage, "addon": addon, "action": "block", "path": "",
                    "reason": reason or "not compatible with the target core"}
        version = versions.get(addon)
        cell = _row_cell(matrix, target, addon)
        if version and cell:
            try:
                behind = not semver.satisfies(version, cell)
            except ValueError:
                behind = False
            if behind:
                warnings.append(
                    f"{addon} {version} is compatible with core {target}; "
                    "an update is recommended"
                )
        return {"stage": stage, "addon": addon, "action": "keep", "path": "", "reason": ""}

    for stage, addon in MODULE_STAGES:
        if addon not in versions:
            steps.append({"stage": stage, "addon": addon, "action": "absent", "path": "",
                          "reason": "not installed"})
            continue
        step = judge(stage, addon)
        if step:
            steps.append(step)
    modules = {a for _, a in MODULE_STAGES}
    for addon in sorted(set(versions) - modules):
        if addon in addon_paths:
            raise StageError(
                f"--addon-path: {addon} has no upgrade stage; upgrade it with "
                f"'papaia-ctl addon upgrade {addon} --path=DIR' after the upgrade"
            )
        verdict = verdicts.get(addon) or {}
        if verdict.get("status") in ("ERROR", "INCOMPATIBLE"):
            step = judge(FINAL_STAGE, addon)
            if step:
                steps.append(step)
    if problems:
        raise StageError(
            "The target core does not accept these add-ons (nothing has been changed): "
            + "; ".join(problems)
            + ". Pass a newer checkout with --addon-path=NAME=DIR, or --force to stop them."
        )
    return steps, warnings


def describe(steps: list[dict], stages: list[str]) -> list[str]:
    """The plan as lines for the operator, one per stage and module step."""
    lines: list[str] = []
    titles = {
        "preflight": "add-on, image and key check",
        "restore-point": "restore point R0, write lock on",
        "core": "core and manager: tag change, migrations, render, start",
        FINAL_STAGE: "write lock off, report",
    }
    for stage in stages:
        number = STAGES.index(stage) if stage in STAGES else -1
        own = [s for s in steps if s["stage"] == stage]
        if stage in titles:
            lines.append(f"stage {number} {stage}: {titles[stage]}")
        if stage == "restore-point":
            blocked = [s["addon"] for s in steps if s["action"] == "block"]
            if blocked:
                lines.append(f"stage {number} {stage}: stop and block {', '.join(blocked)}")
        for step in own:
            text = f"stage {number} {stage}: {step['action']} {step['addon']}"
            if step["path"]:
                text += f" from {step['path']}"
            if step["reason"]:
                text += f" ({step['reason']})"
            lines.append(text)
    return lines


# ─────────────────────────────────────────────────────────────────────────
# stage 0: the operator key
# ─────────────────────────────────────────────────────────────────────────


def check_identity(config_dir: Path, identities: list[str]) -> list[str]:
    """Open a fresh check block, encrypted to every backup recipient, with the given keys.

    Returns the recipient names the keys belong to. A missing recipient list, no key or
    a key of no recipient is a StageError starting with NO_KEY_MESSAGE."""
    try:
        recipients = backup_crypt.load_recipients(config_dir)
    except backup_crypt.BackupError as exc:
        raise StageError(f"{NO_KEY_MESSAGE} ({exc})") from None
    if not recipients:
        raise StageError(f"{NO_KEY_MESSAGE} (no backup recipient is configured)")
    if not identities:
        raise StageError(f"{NO_KEY_MESSAGE} (no key was given)")
    probe = os.urandom(32)
    sealed = io.BytesIO()
    with age.Encryptor(sealed, [r.key for r in recipients]) as encryptor:
        encryptor.write(probe)
    opened = io.BytesIO()
    try:
        age.decrypt(io.BytesIO(sealed.getvalue()), opened, identities)
    except age.AgeError:
        raise StageError(
            f"{NO_KEY_MESSAGE} (the key belongs to none of the recipients "
            f"{', '.join(r.name for r in recipients)})"
        ) from None
    if opened.getvalue() != probe:
        raise StageError(NO_KEY_MESSAGE)
    try:
        mine = {age.recipient_of(i) for i in identities}
    except age.AgeError:
        mine = set()
    return [r.name for r in recipients if r.key in mine]


# ─────────────────────────────────────────────────────────────────────────
# write lock
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LockState:
    active: bool
    doc: dict = field(default_factory=dict)
    # Why the file could not be used; such a lock counts as active.
    problem: str | None = None


def lock_path(config_dir: Path) -> Path:
    return halt.state_dir(config_dir) / LOCK_FILE


def parse_lock(raw: bytes) -> LockState:
    if len(raw) > MAX_FILE_BYTES:
        return LockState(True, problem="the lock file is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return LockState(True, problem="the lock file is not JSON")
    if not isinstance(doc, dict) or set(doc) != _LOCK_FIELDS or doc.get("schema") != LOCK_SCHEMA \
            or not isinstance(doc.get("active"), bool):
        return LockState(True, problem="the lock file does not match " + LOCK_SCHEMA)
    return LockState(doc["active"], doc)


def read_lock(config_dir: Path) -> LockState:
    """The lock as a reader sees it: missing is no lock, anything unusable is a lock."""
    path = lock_path(config_dir)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return LockState(False)
    except OSError as exc:
        return LockState(True, problem=f"the lock file cannot be read ({exc.strerror})")
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return LockState(True, problem="the lock file is not a regular file")
        return parse_lock(handle.read(MAX_FILE_BYTES + 1))


def _write_json(path: Path, doc: dict, mode: int) -> None:
    data = json.dumps(doc, sort_keys=True, indent=1) + "\n"
    common.atomic_write(path, data)
    os.chmod(path, mode)


def _set_lock(config_dir: Path, state: dict) -> None:
    folder = halt.ensure_dir(config_dir)
    _write_json(folder / LOCK_FILE, {
        "schema": LOCK_SCHEMA, "active": True, "since": int(time.time()),
        "upgrade_id": state["id"], "from": state["from"], "to": state["to"],
        "message": LOCK_MESSAGE,
    }, 0o644)


def _clear_lock(config_dir: Path) -> None:
    try:
        lock_path(config_dir).unlink()
    except FileNotFoundError:
        pass


# ─────────────────────────────────────────────────────────────────────────
# state
# ─────────────────────────────────────────────────────────────────────────


def state_path(config_dir: Path) -> Path:
    return halt.state_dir(config_dir) / STATE_FILE


def _check_version(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise StageError(f"{STATE_FILE}: {what} must be a version")
    try:
        semver.parse_version(value)
    except ValueError:
        raise StageError(f"{STATE_FILE}: {what} {value!r} is not a version") from None
    return value


def _check_state(doc: object) -> dict:
    if not isinstance(doc, dict):
        raise StageError(f"{STATE_FILE}: not an object")
    unknown = sorted(set(doc) - _STATE_FIELDS)
    if unknown:
        raise StageError(f"{STATE_FILE}: unknown field(s) {', '.join(unknown)}")
    missing = sorted(_STATE_FIELDS - set(doc))
    if missing:
        raise StageError(f"{STATE_FILE}: missing field(s) {', '.join(missing)}")
    if doc["schema"] != STATE_SCHEMA:
        raise StageError(f"{STATE_FILE}: schema must be {STATE_SCHEMA}")
    try:
        uuid.UUID(str(doc["id"]))
    except ValueError:
        raise StageError(f"{STATE_FILE}: id is not a UUID") from None
    _check_version(doc["from"], "from")
    _check_version(doc["to"], "to")
    if not isinstance(doc["restore_point"], str) or not _POINT_RE.match(doc["restore_point"]):
        raise StageError(f"{STATE_FILE}: restore_point is not a restore point id")
    for key in ("started", "finished", "abandoned"):
        value = doc[key]
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise StageError(f"{STATE_FILE}: {key} must be a time")
    stages = doc["stages"]
    if not isinstance(stages, dict) or set(stages) != set(STAGES):
        raise StageError(f"{STATE_FILE}: stages must name every stage")
    for name, entry in stages.items():
        if not isinstance(entry, dict) or set(entry) != {"status", "seconds"} \
                or entry["status"] not in STATUSES \
                or not (entry["seconds"] is None or isinstance(entry["seconds"], int)):
            raise StageError(f"{STATE_FILE}: stage {name!r} is malformed")
    steps = doc["steps"]
    if not isinstance(steps, list):
        raise StageError(f"{STATE_FILE}: steps must be a list")
    for step in steps:
        if not isinstance(step, dict) or set(step) != _STEP_FIELDS \
                or step["stage"] not in STAGES or step["action"] not in ACTIONS \
                or not all(isinstance(step[k], str) for k in _STEP_FIELDS) \
                or not _NAME_RE.match(step["addon"]):
            raise StageError(f"{STATE_FILE}: a step is malformed")
    return doc


def load_state(config_dir: Path) -> dict | None:
    """The state of the last run, or None. A file that is there but unusable is refused:
    an upgrade must never start over a run it cannot read."""
    path = state_path(config_dir)
    if not path.exists():
        return None
    if not path.is_file() or path.is_symlink():
        raise StageError(f"{path} is not a regular file")
    raw = path.read_bytes()[: MAX_FILE_BYTES + 1]
    if len(raw) > MAX_FILE_BYTES:
        raise StageError(f"{path} is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StageError(f"{path} is not JSON") from None
    return _check_state(doc)


def _save(config_dir: Path, state: dict) -> None:
    halt.ensure_dir(config_dir)
    _write_json(state_path(config_dir), _check_state(state), 0o600)


def _unfinished(state: dict | None) -> bool:
    return state is not None and state["finished"] is None and state["abandoned"] is None


def restore_point_for(config_dir: Path, target: str) -> str | None:
    """R0 of an unfinished run to the same target (a retry keeps it: the bundle may
    already be migrated in part), None without one; another target is refused."""
    state = load_state(config_dir)
    if not _unfinished(state):
        return None
    if state["to"] != target:
        raise StageError(
            f"An upgrade from {state['from']} to {state['to']} is unfinished (restore point "
            f"{state['restore_point']}). Finish it with 'papaia-ctl upgrade --resume' or "
            "go back to its restore point and run 'papaia-ctl upgrade --release-lock'."
        )
    return state["restore_point"]


def begin(config_dir: Path, *, source: str, target: str, restore_point: str,
          steps: list[dict]) -> dict:
    """Stages 0 and 1 done: record R0 and the plan, switch the write lock on."""
    existing = restore_point_for(config_dir, target)
    previous = load_state(config_dir) if existing else None
    state = {
        "schema": STATE_SCHEMA,
        "id": previous["id"] if previous else str(uuid.uuid4()),
        "from": _check_version(source, "from"),
        "to": _check_version(target, "to"),
        "started": previous["started"] if previous else int(time.time()),
        "finished": None,
        "abandoned": None,
        "restore_point": existing or restore_point,
        "stages": {s: {"status": "pending", "seconds": None} for s in STAGES},
        "steps": steps,
    }
    state["stages"]["preflight"]["status"] = "ok"
    state["stages"]["restore-point"]["status"] = "ok"
    _save(config_dir, state)
    _set_lock(config_dir, state)
    _audit(config_dir, "upgrade.begin", "write lock on", {
        "upgrade_id": state["id"], "from": source, "to": target,
        "restore_point": state["restore_point"], "retry": bool(previous),
    })
    return state


def _require_running(config_dir: Path) -> dict:
    state = load_state(config_dir)
    if not _unfinished(state):
        raise StageError("No upgrade is in progress.")
    return state


def record(config_dir: Path, stage: str, result: str, seconds: int | None) -> dict:
    if stage not in STAGES or result not in STATUSES or result == "pending":
        raise StageError(f"cannot record {result!r} for stage {stage!r}")
    if seconds is not None and not 0 <= seconds < 10**7:
        raise StageError("--seconds out of range")
    state = _require_running(config_dir)
    state["stages"][stage] = {"status": result, "seconds": seconds}
    _save(config_dir, state)
    _audit(config_dir, "upgrade.stage", f"stage {stage} {result}", {
        "upgrade_id": state["id"], "stage": stage, "status": result, "seconds": seconds,
    }, result="error" if result == "failed" else "allowed")
    return state


def block_addons(config_dir: Path) -> list[str]:
    """Stop the add-ons the plan blocks from coming back: inactive in deployment.yaml and
    marked `blocked` with the reason; their data stays where it is."""
    state = _require_running(config_dir)
    blocked = [s for s in state["steps"] if s["action"] == "block"]
    if not blocked:
        return []
    deployed = deployment.load(config_dir)
    entries = {e.get("name"): e for e in deployed.get("addons") or []}
    names = []
    for step in blocked:
        entry = entries.get(step["addon"])
        if entry is None:
            continue
        entry["active"] = False
        entry["state"] = "stopped"
        entry["blocked"] = {"reason": step["reason"], "core": state["to"],
                            "since": int(time.time())}
        names.append(step["addon"])
    deployment.save(config_dir, deployed)
    for name in names:
        _audit(config_dir, "upgrade.block-addon", f"{name} blocked", {
            "upgrade_id": state["id"], "addon": name, "core": state["to"],
        })
    return names


def steps_to_run(config_dir: Path, selection: str | None,
                 requires: dict[str, list[str]]) -> tuple[dict, list[str]]:
    """The stages after the core stage still to run now, for a run in progress."""
    state = _require_running(config_dir)
    stages = [s for s in select_stages(selection, state, requires)
              if s not in ("preflight", "restore-point") and _status(state, s) not in _DONE]
    return state, stages


def finish(config_dir: Path) -> dict:
    """Stage 8: every module stage is done; the write lock ends."""
    state = _require_running(config_dir)
    pending = [s for s in STAGES[:-1] if state["stages"][s]["status"] not in _DONE]
    if pending:
        raise StageError(f"stage 'finish' needs these stages first: {', '.join(pending)}")
    state["stages"][FINAL_STAGE] = {"status": "ok", "seconds": 0}
    state["finished"] = int(time.time())
    _save(config_dir, state)
    _clear_lock(config_dir)
    _audit(config_dir, "upgrade.finish", "write lock off", {
        "upgrade_id": state["id"], "from": state["from"], "to": state["to"],
        "seconds": {s: v["seconds"] for s, v in state["stages"].items()},
    })
    return state


def release_lock(config_dir: Path, *, bundle_version: str, checkout_version: str) -> dict:
    """End the write lock of a run that is not continued: only once both the checkout
    and the configuration are back at the release the run started from (R0)."""
    state = _require_running(config_dir)
    if bundle_version != state["from"] or checkout_version != state["from"]:
        raise StageError(
            f"The installation is not back at {state['from']} (checkout {checkout_version}, "
            f"configuration {bundle_version}). Restore {state['restore_point']} after "
            f"checking out v{state['from']}, or continue with 'papaia-ctl upgrade --resume'."
        )
    state["abandoned"] = int(time.time())
    _save(config_dir, state)
    _clear_lock(config_dir)
    _audit(config_dir, "upgrade.release-lock", "write lock off after the way back", {
        "upgrade_id": state["id"], "from": state["from"], "to": state["to"],
        "restore_point": state["restore_point"],
    })
    return state


def report(state: dict) -> list[str]:
    """Stage durations for the operator (the downtime of each stage)."""
    lines = ["Stage durations:"]
    for stage in STAGES:
        entry = state["stages"][stage]
        seconds = "-" if entry["seconds"] is None else f"{entry['seconds']} s"
        lines.append(f"  {stage:<14} {entry['status']:<8} {seconds}")
    return lines
