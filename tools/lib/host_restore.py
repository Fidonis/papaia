"""Restore after the loss of the host (BE-18a, RE-88).

When only the backup target and the operator's key are left, the operator must find the
release the newest point was taken with before there is a checkout to run `papaia-ctl`
from, and must be able to see that deletions made after that point did not come back.

* Every restore point holds an unencrypted file `<target>/<point>/RELEASE` with the core
  tag, the suite version and the installation id (no person, no key). `<target>/latest/`
  holds a copy of the `RELEASE` of the newest good point of the whole stack and its id in
  `POINT`, so `latest/RELEASE` is readable with any text editor or file browser.
* `restore --from=<target>` reads the point's `RELEASE` and stops before anything is
  touched when the checkout is another release; the message names `git checkout <tag>`.
* The erasure probe, after the modules have started again: every object the journal at
  the target lists as deleted since the point is back in the restored data, so the module
  owning it must have applied its journal (`erasure-replay`) in this restore. The probe
  passes for a module only with that run in the host's audit journal (same correlation id,
  same point, exit 0) and nothing left due; otherwise it fails and names the module. The
  core's own sources (`identity`, `core-chat`, `model-gateway`) are replayed by the core,
  not by an add-on, and are listed without deciding the result.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import backup, backup_crypt, common, deployment, envtree, images, module_actions, suite

RELEASE_NAME = "RELEASE"
LATEST_DIR = "latest"
POINT_NAME = "POINT"
JOURNAL_FOLDER = "erasure-journal"
CORE_SOURCES = ("identity", "core-chat", "model-gateway")

MAX_RELEASE_BYTES = 2048
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_LINE = 4096
MAX_AUDIT_BYTES = 256 * 1024 * 1024
MAX_MODULES = 200

_RELEASE_FIELDS = {"id", "tag", "suite", "installation_id"}
_REQUIRED = {"id", "tag", "suite"}
_POINT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_TAG_RE = re.compile(r"\Av\d{1,4}\.\d{1,4}\.\d{1,4}(-[0-9A-Za-z.-]{1,32})?\Z")
_SUITE_RE = re.compile(r"\A(\d{1,4}\.\d{1,4}\.\d{1,4}(-[0-9A-Za-z.-]{1,32})?|none)\Z")
_UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_MODULE_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_LINE_RE = re.compile(r"\A([a-z_]{1,32}): ([^\s]{1,80})\Z")


class CheckoutMismatchError(backup.BackupError):
    """The checkout is another release than the restore point was taken with."""


# ─────────────────────────────────────────────────────────────────────────
# RELEASE
# ─────────────────────────────────────────────────────────────────────────


def core_tag(repo_root: Path) -> str:
    """The release tag of the checkout: `v` and the VERSION file."""
    return "v" + envtree.resolve_platform_version(Path(repo_root))


def suite_version(repo_root: Path) -> str:
    """The suite of the compatibility matrix whose core range holds the checkout."""
    try:
        matrix = suite.load_matrix(Path(repo_root))
    except suite.SuiteError:
        return "none"
    if matrix is None:
        return "none"
    row, _before = suite.matrix_rows(matrix, envtree.resolve_platform_version(Path(repo_root)))
    return str(row["suite"]) if row else "none"


def release_text(point_id: str, tag: str, suite_name: str, installation_id: str | None) -> str:
    lines = [
        "# papaia restore point. Before restoring it on a new host, check out this tag:",
        f"#   git checkout {tag}",
        f"id: {point_id}",
        f"tag: {tag}",
        f"suite: {suite_name}",
    ]
    if installation_id:
        lines.append(f"installation_id: {installation_id}")
    return "\n".join(lines) + "\n"


def write_release(snapshot: Path, point_id: str, repo_root: Path, config_dir: Path) -> dict:
    """Write `<snapshot>/RELEASE` for the point and return its fields."""
    installation = backup_crypt.installation_id(Path(config_dir))
    text = release_text(point_id, core_tag(repo_root), suite_version(repo_root), installation)
    release = _parse_release(text, "RELEASE")
    common.atomic_write(Path(snapshot) / RELEASE_NAME, text)
    return release


def _parse_release(text: str, where: str) -> dict:
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE_RE.match(line)
        if match is None or match.group(1) not in _RELEASE_FIELDS or match.group(1) in fields:
            raise backup.BackupError(f"{where} is not a RELEASE file of a restore point")
        fields[match.group(1)] = match.group(2)
    missing = _REQUIRED - set(fields)
    if missing:
        raise backup.BackupError(f"{where} lacks {', '.join(sorted(missing))}")
    checks = (("id", _POINT_RE), ("tag", _TAG_RE), ("suite", _SUITE_RE),
              ("installation_id", _UUID_RE))
    for name, pattern in checks:
        if name in fields and not pattern.match(fields[name]):
            raise backup.BackupError(f"{where}: {name} is not valid")
    return fields


def read_release(path: Path) -> dict:
    """The fields of a RELEASE file; BackupError when it is not one."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise backup.BackupError(f"{path} is missing or not a regular file")
    with open(path, "rb") as fh:
        raw = fh.read(MAX_RELEASE_BYTES + 1)
    if len(raw) > MAX_RELEASE_BYTES:
        raise backup.BackupError(f"{path} is too large to be a RELEASE file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise backup.BackupError(f"{path} is not text") from None
    return _parse_release(text, str(path))


def point_release(snapshot: Path) -> dict | None:
    """The RELEASE of a point, or None for a point taken before RELEASE files existed."""
    path = Path(snapshot) / RELEASE_NAME
    if not path.exists() and not path.is_symlink():
        return None
    return read_release(path)


def update_latest(backup_dir: Path) -> str | None:
    """Point `<target>/latest/` at the newest good point of the whole stack; remove it when
    there is none. Returns the id it names."""
    backup_dir = Path(backup_dir)
    latest = backup_dir / LATEST_DIR
    if latest.is_symlink() or (latest.exists() and not latest.is_dir()):
        raise backup.BackupError(f"{latest} is not a directory papaia-ctl wrote")
    entry = backup.latest_entry(backup.load_index(backup_dir))
    release = None
    if entry is not None:
        try:
            release = point_release(backup.snapshot_path(backup_dir, entry))
        except backup.BackupError:
            release = None
    if entry is None or release is None:
        for name in (POINT_NAME, RELEASE_NAME):
            (latest / name).unlink(missing_ok=True)
        if latest.is_dir() and not any(latest.iterdir()):
            latest.rmdir()
        return None
    text = release_text(release["id"], release["tag"], release["suite"],
                        release.get("installation_id"))
    common.atomic_write(latest / RELEASE_NAME, text)
    common.atomic_write(latest / POINT_NAME, str(entry["id"]) + "\n")
    return str(entry["id"])


def check_checkout(release: dict, repo_root: Path) -> None:
    """Refuse a checkout of another release than the point's."""
    current = core_tag(repo_root)
    if release["tag"] != current:
        raise CheckoutMismatchError(
            f"Restore point {release['id']} was taken with papaia {release['tag']}; this "
            f"checkout is {current}. Check out the release of the point, then run the "
            f"restore again:\n  git checkout {release['tag']}\nNothing was changed."
        )


def check_point_target(backup_dir: Path, release: dict | None, *, required: bool) -> None:
    """The target is a confirmed backup target (`.papaia-target`, BE-15) and the point
    belongs to its installation. `required` for a fresh host, which has nothing else to
    tell an unmounted share or a wrong directory from the target."""
    target_id = backup_crypt.target_installation(Path(backup_dir))
    if target_id is None:
        if required:
            raise backup.BackupError(
                f"{backup_dir} is not a confirmed backup target (no "
                f"{backup_crypt.TARGET_FILE}). Mount the target and name it with --from."
            )
        return
    point_id = (release or {}).get("installation_id")
    if point_id and point_id != target_id:
        raise backup.BackupError(
            f"Restore point {release['id']} belongs to another installation ({point_id}) "
            f"than the target {backup_dir} ({target_id}). Nothing was changed."
        )


# ─────────────────────────────────────────────────────────────────────────
# erasure probe
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ModuleProbe:
    module: str
    journaled: int
    result: str  # pass | fail | core
    reason: str


@dataclass
class ProbeResult:
    modules: list[ModuleProbe] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(m.result != "fail" for m in self.modules)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _since(path: Path, module: str, created: datetime) -> int:
    """How many entries of the journal were written at or after `created`. ValueError
    when the file cannot be read as the journal of `module`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError("unreadable") from None
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_JOURNAL_BYTES + 1)
    if len(data) > MAX_JOURNAL_BYTES:
        raise ValueError("too large")
    count = 0
    # A last line without a line break is a write that never completed.
    for raw in data[: data.rfind(b"\n") + 1].splitlines():
        if len(raw) > MAX_JOURNAL_LINE:
            raise ValueError("line too long")
        try:
            line = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("not json") from None
        if (
            not isinstance(line, dict)
            or line.get("module") != module
            or type(line.get("seq")) is not int
            or not isinstance(line.get("kind"), str)
            or not isinstance(line.get("object_ref"), str)
        ):
            raise ValueError("not an entry of this journal")
        at = _timestamp(line.get("at"))
        if at is None:
            raise ValueError("no valid time")
        if at >= created:
            count += 1
    return count


def _replays(config_dir: Path, restore_point: str, correlation_id: str) -> dict[str, str]:
    """{add-on: allowed|error} of the `erasure-replay` runs of this restore in the host's
    audit journal; the last run of an add-on counts."""
    path = Path(config_dir) / images.AUDIT_LOG
    runs: dict[str, str] = {}
    if not path.is_file():
        return runs
    if path.stat().st_size > MAX_AUDIT_BYTES:
        raise backup.BackupError(f"{path} is too large to search")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if correlation_id not in raw:
                continue
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            detail = row.get("detail") if isinstance(row, dict) else None
            if (
                not isinstance(detail, dict)
                or row.get("event") != "module_action_run"
                or row.get("correlation_id") != correlation_id
                or detail.get("action") != "erasure-replay"
                or detail.get("restore_point") != restore_point
                or not isinstance(detail.get("addon"), str)
            ):
                continue
            runs[detail["addon"]] = "allowed" if row.get("result") == "allowed" else "error"
    return runs


def erasure_probe(
    config_dir: Path,
    repo_root: Path,
    backup_dir: Path,
    *,
    restore_point: str,
    created_at: str,
    correlation_id: str,
    addons: list[str] | None = None,
) -> ProbeResult:
    """Check every journal at the target after a restore of `restore_point` (taken at
    `created_at`). `addons` narrows it to the add-ons of a scoped restore."""
    if not _POINT_RE.match(restore_point or ""):
        raise backup.BackupError("restore point id is not valid")
    if not _UUID_RE.match(correlation_id or ""):
        raise backup.BackupError("correlation id is not a lowercase UUID")
    created = _timestamp(created_at)
    if created is None:
        raise backup.BackupError(f"restore point {restore_point} has no valid creation time")
    folder = Path(backup_dir) / JOURNAL_FOLDER
    if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
        raise backup.BackupError(f"{folder} is not a directory")
    journals = sorted(folder.glob("*.jsonl")) if folder.is_dir() else []
    if len(journals) > MAX_MODULES:
        raise backup.BackupError(f"{folder} holds more journals than modules can exist")

    installed: dict[str, dict] = {}
    for entry in deployment.active_addons(deployment.load(Path(config_dir)) or {}):
        name = str(entry.get("name") or "")
        if _MODULE_RE.match(name):
            installed[name] = entry
    wanted = None if addons is None else set(addons)
    modules = set(wanted or ()) | {p.stem for p in journals}
    pending = None
    try:
        pending = module_actions.load(Path(config_dir))
    except module_actions.ModuleActionError:
        pending = {"modules": {name: ["erasure-replay"] for name in modules}}
    replays = _replays(Path(config_dir), restore_point, correlation_id)

    result = ProbeResult()
    for module in sorted(modules):
        if wanted is not None and module not in wanted:
            continue
        if not _MODULE_RE.match(module):
            result.modules.append(ModuleProbe(module[:64], 0, "fail", "journal_unreadable"))
            continue
        path = folder / f"{module}.jsonl"
        try:
            count = _since(path, module, created) if path.exists() else 0
        except ValueError:
            result.modules.append(ModuleProbe(module, 0, "fail", "journal_unreadable"))
            continue
        if module in CORE_SOURCES:
            result.modules.append(ModuleProbe(module, count, "core", "core_source"))
            continue
        if count == 0:
            result.modules.append(ModuleProbe(module, 0, "pass", "nothing_journaled"))
            continue
        result.modules.append(ModuleProbe(module, count, *_module_state(
            module, installed, repo_root, pending, replays)))
    return result


def _module_state(module: str, installed: dict, repo_root: Path, pending: dict | None,
                  replays: dict[str, str]) -> tuple[str, str]:
    entry = installed.get(module)
    if entry is None:
        return "fail", "not_installed"
    manifest, _problem = deployment.load_addon_manifest(
        deployment.resolve_addon_path(entry, Path(repo_root))
    )
    try:
        declared = module_actions.reserved_actions(manifest) if manifest else []
    except module_actions.ModuleActionError:
        declared = []
    if "erasure-replay" not in declared:
        return "fail", "no_replay_action"
    if replays.get(module) == "error":
        return "fail", "replay_failed"
    if replays.get(module) != "allowed":
        return "fail", "replay_missing"
    if pending and "erasure-replay" in (pending.get("modules") or {}).get(module, []):
        return "fail", "replay_pending"
    return "pass", "replayed"


def record_probe(config_dir: Path, restore_point: str, result: ProbeResult,
                 correlation_id: str) -> None:
    """One papaia.audit/1 row for the probe, with counts per module and no content."""
    passed = result.passed
    images.append_audit(Path(config_dir), module_actions._row(
        "restore", "erasure_probe", "check",
        "allowed" if passed else "error",
        None if passed else "erasure_probe_failed",
        {"id": restore_point, "result": "pass" if passed else "fail",
         "modules": {m.module: {"journaled": m.journaled, "result": m.result,
                                "reason": m.reason} for m in result.modules}},
        correlation_id,
    ))
