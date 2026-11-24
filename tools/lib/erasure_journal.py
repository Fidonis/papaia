"""The erasure journal of each module, isolated at the backup target (PLT-66, RE-06, BE-16).

Every module keeps one journal, `$PAPAIA_BACKUP_DIR/erasure-journal/<module>.jsonl`, and
its `erasure-replay` deletes again what the journal lists. A module that could write the
journal of another module could drop entries of it, or add an `erase` line that deletes
data of that module at the next replay. So a module sees one file there, its own:

* The core creates `<module>.jsonl` (empty, mode 0600, the account that owns the
  configuration directory) when it renders the add-on; the kit's journal writer never
  creates it, and Compose must not either. A symbolic link, a second name (hard link), a
  file of another account or one other accounts may write in its place stops the render.
  The folder itself is made once per target by the lifecycle profile (lib/render_core.py);
  a missing folder is an unmounted target and is never created here.
* A generated override of the add-on's own project
  (`overrides/addons/docker-compose.<name>-erasure-journal.override.yml`) gives each writer
  service an empty folder of its own at `/var/lib/papaia-backup/erasure-journal` (tmpfs)
  and binds the module's file into it read-write. Writer services are the services of the
  reserved actions `erasure-replay` and `person-erase` and the service behind the add-on's
  personal-area entry (`exposes` kind `me`), which deletes on the person's request. No
  other service of the add-on, and no other add-on, gets anything of the target.
* `epoch` and the journals of the core (`identity`, `core-chat`, `model-gateway`) stay with
  the core: papaia-lifecycle alone mounts the folder read-write (it writes `identity` and
  `epoch` and compares every journal); a module checks its own journal at start.
* The add-on's own compose file may not mount the backup target or anything in it
  (`compose_problems`, an error of the compatibility gate that `--force` does not pass).
* `doctor erasure_journal` (`inspect_folder`, `inspect_mounts`) reports a shared mount, a
  journal another account or another module can write, and a line of one module planted
  in the journal of another, which the kit refuses to replay.

Root on the host can still write every file; against that the journal relies on the
mirror outside the house, the audit trail and the mail to the operations address
(sicherheit §3.3, named residual risk).
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from . import common

JOURNAL_FOLDER = "erasure-journal"
# Where a module finds its journal; the same path papaia-lifecycle uses for the folder.
CONTAINER_DIR = "/var/lib/papaia-backup/erasure-journal"
# The folder a writer service sees: empty but for the bound file, private to the
# container, so the writer finds the writable folder it needs and nothing of anyone else.
TMPFS = f"{CONTAINER_DIR}:size=1m,mode=1777"
EPOCH_FILE = "epoch"
CORE_SOURCES = ("identity", "core-chat", "model-gateway")
LIFECYCLE_SERVICE = "papaia-lifecycle"
WRITER_ACTIONS = ("erasure-replay", "person-erase")
OVERRIDE_TAG = "erasure-journal"

PASS = "pass"
WARN = "warn"
FAIL = "fail"

# The kit's rules for a module name and a journal line.
_MODULE_RE = re.compile(r"\A[a-z][a-z0-9-]{0,39}\Z")
_SERVICE_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\Z")
MAX_LINE_BYTES = 4096
# What doctor reads of one journal and how many files it looks at; a larger journal or
# folder is reported, never read without bound.
MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 4096

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class ErasureJournalError(Exception):
    """A journal file or a declaration the core cannot hand to a module safely."""


@dataclass(frozen=True)
class Finding:
    """One result of `doctor erasure_journal`: a file of the folder or a container."""

    subject: str
    status: str
    text: str


# ── configuration ───────────────────────────────────────────────────────────


def journal_folder(config_dir: Path) -> Path | None:
    """`$PAPAIA_BACKUP_DIR/erasure-journal`, or None while the lifecycle profile is off
    (then no journal exists)."""
    env = common.parse_env_file(Path(config_dir) / ".env")
    profiles = {p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",") if p.strip()}
    backup = env.get("PAPAIA_BACKUP_DIR", "")
    if "lifecycle" not in profiles or not backup:
        return None
    if not Path(backup).is_absolute():
        raise ErasureJournalError(f"PAPAIA_BACKUP_DIR must be an absolute path, not {backup!r}")
    return Path(backup) / JOURNAL_FOLDER


def check_module_name(name: object) -> str:
    """An add-on name usable as the name of its journal: the kit's module rule, and none
    of the core's own journals."""
    if not isinstance(name, str) or not _MODULE_RE.match(name):
        raise ErasureJournalError(
            f"add-on '{name}': its name cannot name an erasure journal "
            "(a-z, 0-9 and '-', starting with a letter, at most 40 characters)"
        )
    if name in CORE_SOURCES:
        raise ErasureJournalError(
            f"add-on '{name}': the erasure journal '{name}' belongs to the core"
        )
    return name


def writer_services(manifest: dict) -> list[str]:
    """The services that write the add-on's journal: those of the reserved actions
    `erasure-replay` and `person-erase` and the one behind its personal-area entry."""
    found: list[str] = []
    actions = manifest.get("actions")
    if isinstance(actions, dict):
        for action in WRITER_ACTIONS:
            spec = actions.get(action)
            if isinstance(spec, dict) and isinstance(spec.get("service"), str):
                found.append(spec["service"])
    exposes = manifest.get("exposes")
    if isinstance(exposes, list):
        for entry in exposes:
            if not isinstance(entry, dict) or entry.get("kind") != "me":
                continue
            address = entry.get("address")
            if isinstance(address, dict) and isinstance(address.get("service"), str):
                found.append(address["service"])
    bad = sorted({s for s in found if not _SERVICE_RE.match(s)})
    if bad:
        raise ErasureJournalError(f"not a service name: {', '.join(repr(s) for s in bad)}")
    return sorted(set(found))


def override_path(config_dir: Path, name: str) -> Path:
    return (
        Path(config_dir) / "overrides" / "addons"
        / f"docker-compose.{name}-{OVERRIDE_TAG}.override.yml"
    )


# ── the module's file ───────────────────────────────────────────────────────


def file_problem(path: Path, owner: int) -> str | None:
    """Why `path` is not a file only its own writer can change, or None."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "is missing"
    if stat.S_ISLNK(st.st_mode):
        return "is a symbolic link"
    if not stat.S_ISREG(st.st_mode):
        return "is not a regular file"
    if st.st_nlink != 1:
        return "has a second name (hard link)"
    if st.st_uid != owner:
        return "belongs to another account"
    if stat.S_IMODE(st.st_mode) & 0o022:
        return "can be written by other accounts"
    return None


def ensure_journal_file(folder: Path, module: str, owner: int) -> None:
    """Create `<folder>/<module>.jsonl` empty with mode 0600, or check the one there. A
    missing folder (an unmounted target) is left alone: the mount then refuses to start
    the module, which is the safe outcome."""
    if not folder.is_dir():
        return
    path = folder / f"{check_module_name(module)}.jsonl"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                     0o600)
    except FileExistsError:
        problem = file_problem(path, owner)
        if problem is not None:
            raise ErasureJournalError(
                f"the erasure journal {path} {problem}; it is not handed to the module. "
                "Check who changed it, restore it from the mirror or the local copy, and "
                "render again."
            ) from None
        return
    os.close(fd)


def module_override(folder: Path, module: str, services: list[str]) -> dict:
    """The compose override that hands `module` its own journal file and nothing else."""
    def bind() -> dict:
        return {
            "type": "bind",
            "source": str(folder / f"{module}.jsonl"),
            "target": f"{CONTAINER_DIR}/{module}.jsonl",
            "read_only": False,
            # An unmounted target must not turn into an empty journal on the host's disk.
            "bind": {"create_host_path": False},
        }
    return {"services": {s: {"tmpfs": [TMPFS], "volumes": [bind()]} for s in services}}


def _compose_services(addon_path: Path) -> set[str]:
    try:
        document = yaml.safe_load((addon_path / "docker-compose.yml").read_text("utf-8"))
    except (OSError, yaml.YAMLError):
        return set()
    services = document.get("services") if isinstance(document, dict) else None
    return {str(s) for s in services} if isinstance(services, dict) else set()


def generate_overrides(config_dir: Path, repo_root: Path) -> list[Path]:
    """Write the journal override of every active add-on with writer services and create
    its journal file; remove the override of every other add-on, and of all while the
    lifecycle profile is off. Raises ErasureJournalError for a file the core cannot hand
    over safely, so the add-on does not start with it."""
    from . import deployment  # deployment imports compat, which imports this module

    config_dir = Path(config_dir)
    folder = journal_folder(config_dir)
    deployed = deployment.load(config_dir) or {}
    owner = os.stat(config_dir).st_uid
    written: list[Path] = []
    for addon in deployed.get("addons") or []:
        name = addon.get("name") if isinstance(addon, dict) else None
        if not isinstance(name, str) or not name or "/" in name:
            continue
        out = override_path(config_dir, name)
        services: list[str] = []
        if folder is not None and addon.get("active") and addon.get("path"):
            path = deployment.resolve_addon_path(addon, repo_root)
            manifest, _ = deployment.load_addon_manifest(path)
            if manifest:
                try:
                    declared = writer_services(manifest)
                except ErasureJournalError as exc:
                    raise ErasureJournalError(f"add-on '{name}': {exc}") from None
                present = _compose_services(path)
                services = [s for s in declared if s in present]
        if not services or folder is None:
            out.unlink(missing_ok=True)
            continue
        check_module_name(name)
        ensure_journal_file(folder, name, owner)
        out.parent.mkdir(parents=True, exist_ok=True)
        common.atomic_write(
            out,
            yaml.safe_dump(module_override(folder, name, services), sort_keys=False,
                           default_flow_style=False),
        )
        written.append(out)
    return written


# ── the add-on's own compose file ───────────────────────────────────────────


def _short_source(volume: str) -> str | None:
    """The source of a short-syntax volume `src:dst[:mode]`; a `${VAR:-default}` in it
    may itself hold a colon."""
    depth = 0
    for index, char in enumerate(volume):
        if char == "{" and volume[index - 1:index] == "$":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
        elif char == ":" and not depth:
            return volume[:index]
    return None


def _touches_target(source: str) -> bool:
    if "PAPAIA_BACKUP_DIR" in source:
        return True
    return JOURNAL_FOLDER in PurePosixPath(source).parts


def compose_problems(addon_path: Path) -> list[str]:
    """Mounts of the add-on's compose file that reach the backup target or the journal
    folder: a bind source or a local volume's `device` naming `PAPAIA_BACKUP_DIR` or a
    path through `erasure-journal`. Only the core mounts the journal (its override)."""
    try:
        document = yaml.safe_load((Path(addon_path) / "docker-compose.yml").read_text("utf-8"))
    except (OSError, yaml.YAMLError):
        return []  # a missing or broken file is reported where it is started
    if not isinstance(document, dict):
        return []
    problems: list[str] = []
    services = document.get("services")
    for service, body in (services.items() if isinstance(services, dict) else ()):
        volumes = body.get("volumes") if isinstance(body, dict) else None
        for volume in volumes if isinstance(volumes, list) else ():
            if isinstance(volume, str):
                source = _short_source(volume)
            elif isinstance(volume, dict):
                source = volume.get("source")
            else:
                source = None
            if isinstance(source, str) and _touches_target(source):
                problems.append(f"service '{service}' mounts {source}")
    volumes = document.get("volumes")
    for volume, body in (volumes.items() if isinstance(volumes, dict) else ()):
        options = body.get("driver_opts") if isinstance(body, dict) else None
        device = options.get("device") if isinstance(options, dict) else None
        if isinstance(device, str) and _touches_target(device):
            problems.append(f"volume '{volume}' binds {device}")
    return problems


# ── doctor ──────────────────────────────────────────────────────────────────


def _line_problem(path: Path, module: str) -> str | None:
    """The first line of `path` that is not a journal line of `module`: a line of another
    module (planted; the kit refuses to replay the file) or one that cannot be read."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError as exc:
        return f"cannot be read ({exc.strerror})"
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_JOURNAL_BYTES + 1)
    if len(data) > MAX_JOURNAL_BYTES:
        return f"is larger than {MAX_JOURNAL_BYTES // (1024 * 1024)} MiB"
    # A last line without a line break is a write that never completed; the kit ignores it.
    complete = data[: data.rfind(b"\n") + 1]
    for number, raw in enumerate(complete.splitlines(), start=1):
        if len(raw) > MAX_LINE_BYTES:
            return f"line {number} is too long"
        try:
            record = json.loads(raw)
        except ValueError:
            return f"line {number} cannot be read"
        owner = record.get("module") if isinstance(record, dict) else None
        if not isinstance(owner, str):
            return f"line {number} names no module"
        if owner != module:
            shown = owner if _MODULE_RE.match(owner) else "?"
            return (
                f"line {number} is a line of another module ({shown}): planted, so the "
                "journal is not replayed; find who wrote it before removing the line"
            )
    return None


def inspect_folder(folder: Path, owner: int | None = None) -> list[Finding]:
    """Every file of the journal folder: no link, one name, the installation's account,
    not writable by others; every journal holds lines of its own module only."""
    owner = os.stat(folder).st_uid if owner is None else owner
    findings: list[Finding] = []
    mode = stat.S_IMODE(os.stat(folder).st_mode)
    if mode & 0o022:
        # Another account could add, replace or remove a journal file in it.
        findings.append(Finding(JOURNAL_FOLDER, FAIL, "can be written by other accounts"))
    with os.scandir(folder) as scan:
        names = sorted(entry.name for entry in scan)
    if len(names) > MAX_FILES:
        return [*findings, Finding(JOURNAL_FOLDER, FAIL, f"holds more than {MAX_FILES} files")]
    for name in names:
        path = folder / name
        problem = file_problem(path, owner)
        if problem is None and name.endswith(".jsonl"):
            module = name[: -len(".jsonl")]
            if not _MODULE_RE.match(module):
                problem = "is no journal of a module"
            else:
                problem = _line_problem(path, module)
        findings.append(
            Finding(name, PASS, "ok") if problem is None else Finding(name, FAIL, problem)
        )
    return findings


def _forms(path: Path | str) -> set[PurePosixPath]:
    """A path as given and with its links resolved: Docker reports the bind source as
    Compose named it, which may run through a link (/tmp on macOS)."""
    return {PurePosixPath(os.path.normpath(str(path))),
            PurePosixPath(os.path.realpath(str(path)))}


def inspect_mounts(
    container: str, mounts: object, folder: Path, *, role: str, own: str | None = None
) -> list[Finding]:
    """The bind mounts of one container that reach the journal folder.

    `role` is `lifecycle` (papaia-lifecycle, may write the folder), `core` (may read it)
    or `module` (may mount `own`, its journal file, and nothing else there)."""
    findings: list[Finding] = []
    folders = _forms(folder)
    for mount in mounts if isinstance(mounts, list) else ():
        if not isinstance(mount, dict) or mount.get("Type") != "bind":
            continue
        source = mount.get("Source")
        if not isinstance(source, str) or not source.startswith("/"):
            continue
        writable = mount.get("RW") is not False
        sources = _forms(source)
        whole = any(s == f or f.is_relative_to(s) for s in sources for f in folders)
        inside = not whole and any(s.is_relative_to(f) for s in sources for f in folders)
        if not whole and not inside or role == "lifecycle":
            continue
        if inside and own is not None and any(s.name == own and s.parent in folders
                                              for s in sources):
            continue
        if whole:
            what = "every erasure journal and epoch"
            if writable:
                findings.append(Finding(container, FAIL, (
                    f"shared read-write mount of {source} ({what}); only papaia-lifecycle "
                    "may write the journal folder: remove the mount")))
            elif role == "module":
                findings.append(Finding(container, WARN, f"reads {what} through {source}"))
            continue
        name = PurePosixPath(source).name
        if writable:
            findings.append(Finding(container, FAIL, (
                f"can write {name} of the erasure journal folder, which is not its own: "
                "remove the mount")))
        elif role == "module":
            findings.append(Finding(container, WARN, f"reads {name}, which is not its own"))
    return findings
