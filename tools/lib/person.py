"""`papaia-ctl person export|erase`: information and erasure for a person whose account is
gone (OPS-08, OPS-03).

A person whose account is disabled or deleted cannot reach the personal area any more,
yet the modules still hold data under her `sub`. The operator therefore runs, for every
installed module, the reserved person actions the module declares under `actions:`
(contract generation 15), as `docker compose run --rm` of the declared service in the
module's own project. bash runs each step (`papaia-ctl person`), this module plans the
steps and checks every answer:

* `person-export` prints the person's data as one JSON object, the same answer the
  module gives its personal-area export (`data.export` of the personal-area contract
  v2). The run packs every answer into the archive format of the personal area
  (`index.json`, `<module>.json`, `<module>.schema.json`, `LIESMICH.txt`) and writes it
  to `state/person-export/<request>.zip.age`, encrypted with age to the one-time
  passphrase that only the confirming person saw (lib/person_request.py). The plain
  archive is built in memory; the module answers wait in the run folder (mode 0700)
  until it is written.
* `transfer-ownership` (with `--transfer-to`) hands the objects the person owns to
  another person before anything is erased; it prints `{"transferred", "halted"}`.
* `person-erase` deletes the person's data, writes the module's erasure journal through
  the module's journal writer and prints a receipt per category: `done` with the number
  deleted, or `kept` with the date until which a retention duty (`legal_obligation`) or
  a deletion lock (`legal_hold`) keeps it. The receipt names the journal entries; the
  core reads them at the backup target and checks that they name this person
  (`subject_ref` = HMAC of the installation key `erasure-hmac` over the `sub`).

Nothing runs without a request that a second person confirmed in the manager
(lib/person_request.py): `begin` takes the request id, moves the request to `running`
and uses it as the correlation id of every audit row; `finish` reports `done` or
`partial` back.

The module learns the person from `PAPAIA_PERSON_SUB`, the step from
`PAPAIA_PERSON_OPERATION`, the new owner from `PAPAIA_NEW_OWNER_SUB` and the run from
`PAPAIA_CORRELATION_ID`. The step runs inside the module's project with the module's own
rights: no client, role, token or network is created for it, and the right lasts as long
as the one-off container.

The core services without a module contract have paths of their own (lib/person_core.py):
the chat by `sub`, the model gateway's usage by `sub`, chat account or mail, the identity
provider's account and sessions through papaia-lifecycle (`svc-papaia-lifecycle`). An
erasure runs in a fixed order (security 1.14 no. 2): the account is disabled and its
sessions and consents end first, then transfers, modules, chat and gateway erase, the
journal entries `core-chat` and `model-gateway` are written, and the account is deleted
last, only when every step before succeeded; otherwise it stays disabled and the request
is `partial`, so the `sub` stays assigned. Last, the reconciliation (governance GV-30 for
the core services) asks chat, gateway and identity provider again for anything that
still names the person by `sub`, chat account or mail; every find makes the run
`partial`.

Every row of the records of processing (an `exposes` entry with `personal_data: true`)
is named in the result: included, or not included with the reason (a module without the
action, a core service or a part whose path is not part of this version). Every module
call and every call of a core path is one `papaia.audit/1` row in the core's audit
outbox, with the person as `object_ref` and the host account as the acting identity,
never with content.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from . import age, catalog, common, compat, deployment, exposes, topology
from . import person_core as pc
from . import person_request as pr
from . import realm_sync as rs

EXPORT = "person-export"
ERASE = "person-erase"
TRANSFER = "transfer-ownership"
ACTIONS = (EXPORT, ERASE, TRANSFER)
GENERATION = 15

ENV_SUB = "PAPAIA_PERSON_SUB"
ENV_NEW_OWNER = "PAPAIA_NEW_OWNER_SUB"
ENV_OPERATION = "PAPAIA_PERSON_OPERATION"
ENV_CORRELATION = "PAPAIA_CORRELATION_ID"

# The personal-area export limit (100 MiB); a larger answer is `truncated`.
MAX_EXPORT_BYTES = 100 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024

WRITER = "papaia-ctl/person"
# No token is presented: the authorized party of the call is the core tool itself.
AZP = "papaia-ctl"
# The catalog id of the core's own step (the archive write).
CORE_CATALOG_ID = "core.person"
KEY_FILE = Path("security") / "erasure-hmac"
JOURNAL_FOLDER = "erasure-journal"
KEPT_REASONS = ("legal_obligation", "legal_hold")

# Core services that hold personal data without a module contract, by compose profile:
# (profile, row name, entry, core path or None).
_NO_PATH = "core service: no path for one person in this version"
CORE_SERVICES = (
    ("librechat", "core:chat", "librechat", pc.CHAT),
    ("librechat", "core:chat", "librechat-files", None),
    ("litellm", "core:model-gateway", "litellm", pc.GATEWAY),
    ("keycloak", "core:identity", "keycloak", pc.IDENTITY),
    ("lifecycle", "core:lifecycle", "papaia-lifecycle", None),
    ("audit", "core:audit", "papaia-audit", None),
)
# (reason for export, reason for erase) of the rows without a core path.
_CORE_REASONS = {
    "librechat-files": (
        "the contents of uploaded files on the chat's file volume and its search index are "
        "not part of this version (the file records are)",
    ) * 2,
    "papaia-lifecycle": (
        _NO_PATH,
        "kept: the tombstone stays as long as the erasure journal (security 1.14 no. 2b)",
    ),
    "papaia-audit": (_NO_PATH, "kept: the audit trail is evidence and is not erased"),
}
_NO_LIFECYCLE = (
    "needs the lifecycle profile: the identity provider is reached as svc-papaia-lifecycle"
)
# Steps of the core paths in the queue of a run: [service, "core:<operation>"].
CORE_STEP = "core:"
RECONCILE = "core"
_CORE_JOURNAL_LOCAL = Path("state") / "erasure-journal"

_SUB_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}")
_ADDON_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SERVICE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
_ARG_RE = re.compile(r"[^\t\n\r\x00]{1,512}")
_CATALOG_RE = re.compile(r"[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*")
_UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

README = """\
Auskunft über gespeicherte Daten / Information about stored data

Dieses Archiv enthält die Daten, die die Module dieser Installation zu Ihrer Kennung
gespeichert haben, je Modul als JSON-Datei (<modul>.json) mit ihrem Schema
(<modul>.schema.json). index.json nennt je Modul den Stand:
  ok           vollständig enthalten
  truncated    größer als 100 MiB, nicht enthalten; bitte bei der Ansprechstelle für
               Datenschutz anfordern
  unavailable  das Modul hat nicht geantwortet; nicht enthalten
Unter not_connected stehen Teile, die nicht enthalten sind, mit dem Grund.
Fragen richten Sie an die Ansprechstelle für Datenschutz der Installation.

This archive holds the data the modules of this installation stored under your id, one
JSON file per module (<module>.json) with its schema (<module>.schema.json). index.json
names the state per module: ok (complete), truncated (larger than 100 MiB, not included;
ask the data protection contact), unavailable (the module did not answer; not included).
not_connected lists the parts that are not included, with the reason. Please address
questions to the data protection contact of the installation.
"""


class PersonError(ValueError):
    """Input, an installation or a declaration the command cannot act on; nothing ran."""


class _Invalid(ValueError):
    """A module answer outside the contract."""


@dataclass(frozen=True)
class Step:
    """One run of a reserved person action of one module."""

    addon: str
    path: Path
    action: str
    service: str
    args: tuple[str, ...]
    env: dict


@dataclass(frozen=True)
class Outcome:
    exit_code: int
    stdout: bytes


Runner = Callable[[Step], Outcome]


@dataclass(frozen=True)
class Row:
    """One row of the records of processing: included or not, with the reason."""

    module: str
    entry: str
    included: bool
    reason: str = ""


@dataclass
class Module:
    name: str
    path: Path
    actions: dict
    entries: list[str]
    categories: list[str]
    catalog_id: str
    title: str
    contract: int | None
    schema: str | None


@dataclass
class Report:
    operation: str
    sub: str
    rows: list[Row]
    ok: bool = True
    modules: dict[str, str] = field(default_factory=dict)
    proof: list[dict] = field(default_factory=list)
    transfers: list[dict] = field(default_factory=list)
    archive: Path | None = None
    # The reconciliation after an erasure: what still names the person, by place.
    findings: list[dict] = field(default_factory=list)
    reconciled: bool = False

    @property
    def state(self) -> str:
        return "done" if self.ok else "partial"


# ── input ────────────────────────────────────────────────────────────────────


def check_sub(value: object, flag: str = "--sub") -> str:
    """A subject id: 1 to 255 characters of letters, digits and `._:@+-`, starting with a
    letter or digit, so it is safe in an environment variable, a path and an audit row."""
    if not isinstance(value, str) or not _SUB_RE.fullmatch(value):
        raise PersonError(
            f"{flag} must be a sub: 1 to 255 of A-Z a-z 0-9 . _ : @ + -, starting with a "
            "letter or digit"
        )
    return value


# ── scope ────────────────────────────────────────────────────────────────────


def _module(name: str, path: Path, manifest: dict, personal: list[dict]) -> Module:
    try:
        actions = compat.addon_actions(manifest)
    except ValueError as exc:
        raise PersonError(f"add-on {name}: {exc}") from None
    for action in ACTIONS:
        spec = actions.get(action)
        if spec is None:
            continue
        if not _SERVICE_RE.fullmatch(spec["service"]):
            raise PersonError(f"add-on {name}: actions.{action}.service is not a service name")
        if len(spec["args"]) > 32 or not all(_ARG_RE.fullmatch(a) for a in spec["args"]):
            raise PersonError(f"add-on {name}: actions.{action}.args: at most 32 one-line args")
    categories: list[str] = []
    for entry in personal:
        for category in entry["storage"]["categories"]:
            if category["id"] not in categories:
                categories.append(category["id"])
    me = [e for e in manifest.get("exposes") or [] if e.get("kind") == "me"]
    catalog_id = (me or personal)[0]["id"]
    if not _CATALOG_RE.fullmatch(catalog_id):
        raise PersonError(f"add-on {name}: entry id {catalog_id!r} cannot name it in the audit")
    schema = next(
        (e["export"]["exit"]["schema"] for e in personal if "export" in e), None
    )
    title = personal[0]["title"]
    settings = manifest.get("personal_settings")
    contract = settings.get("api") if isinstance(settings, dict) else None
    return Module(
        name=name,
        path=path,
        actions=actions,
        entries=[e["id"] for e in personal],
        categories=categories,
        catalog_id=catalog_id,
        title=str(title.get("de") or title.get("en")),
        contract=contract if type(contract) is int else None,
        schema=schema,
    )


def collect(config_dir: Path, repo_root: Path) -> tuple[list[Module], list[tuple]]:
    """The add-ons with personal data, and the rows of the records of processing no module
    action can serve (core profiles and core services) as (row name, entry, reason for
    export, reason for erase)."""
    try:
        sources = catalog.installation_sources(config_dir, repo_root)
    except catalog.CatalogError as exc:
        raise PersonError(str(exc)) from None
    paths = {
        str(entry.get("name")): deployment.resolve_addon_path(entry, repo_root)
        for entry in deployment.active_addons(deployment.load(config_dir) or {})
    }
    modules: list[Module] = []
    core: list[tuple] = []
    for source in sorted(sources, key=lambda s: s.provider):
        try:
            exposes.check(source.section, source.provider)
        except exposes.ExposesError as exc:
            raise PersonError(str(exc)) from None
        personal = [
            e for e in source.section if (e.get("storage") or {}).get("personal_data") is True
        ]
        if not personal:
            continue
        if source.provider.startswith("core:"):
            core += [(source.provider, e["id"], _NO_PATH, _NO_PATH, None) for e in personal]
            continue
        if not _ADDON_RE.fullmatch(source.provider):
            raise PersonError(f"add-on name {source.provider!r} is not valid")
        path = paths[source.provider]
        manifest, problem = deployment.load_addon_manifest(path)
        if manifest is None:
            raise PersonError(f"add-on {source.provider}: {problem}")
        modules.append(_module(source.provider, path, manifest, personal))
    profiles = common.cluster_profiles(common.parse_env_file(config_dir / ".env"))
    for profile, row, entry, path in CORE_SERVICES:
        if profile not in profiles:
            continue
        export_reason, erase_reason = _CORE_REASONS.get(entry, (None, None))
        if path == pc.IDENTITY and "lifecycle" not in profiles:
            export_reason = erase_reason = _NO_LIFECYCLE
        core.append((row, entry, export_reason, erase_reason,
                     path if export_reason is None else None))
    return modules, core


def _core_paths(core: list[tuple]) -> list[str]:
    """The core paths this installation has, in the order of security 1.14 no. 2."""
    return [p for p in pc.SERVICES if any(row[4] == p for row in core)]


def _rows(modules: list[Module], core: list[tuple], action: str) -> list[Row]:
    rows = []
    for module in modules:
        for entry in module.entries:
            if action in module.actions:
                rows.append(Row(module.name, entry, True))
            else:
                rows.append(Row(module.name, entry, False,
                                f"the module declares no {action} action"))
    for name, entry, export_reason, erase_reason, _ in core:
        reason = erase_reason if action == ERASE else export_reason
        rows.append(Row(name, entry, reason is None, reason or ""))
    return rows


# ── audit ────────────────────────────────────────────────────────────────────


def _audit(config_dir: Path) -> rs.AuditLog:
    try:
        return rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (OSError, rs.RealmSyncError) as exc:
        raise PersonError(f"the audit outbox cannot be written: {exc}") from None


def _record(log: rs.AuditLog, *, catalog_id: str, operation: str, effect: str, sub: str,
            error: str | None, detail: dict | None, event: str = "operation") -> None:
    log.append({
        "role": "caller",
        "sub": log.host_account,
        "identity_kind": "person",
        "service_account": None,
        "azp": AZP,
        "aud": None,
        "origin_azp": None,
        "origin_source": None,
        "origin_asserted_by": None,
        "context": None,
        "catalog_id": catalog_id,
        "operation": operation,
        "effect": effect,
        "object_ref": {"type": "person", "id": sub},
        "data_class": None,
        "result": "allowed" if error is None else "error",
        "error_code": error,
        "client_ip": None,
        "detail": detail or None,
        "event": event,
    })


def _step(module: Module, action: str, env: dict) -> Step:
    spec = module.actions[action]
    return Step(module.name, module.path, action, spec["service"], tuple(spec["args"]), env)


def _object(data: bytes, limit: int) -> dict:
    """One JSON object without duplicate keys, at most `limit` bytes."""
    if len(data) > limit:
        raise _Invalid("too_large")

    def unique(pairs: list) -> dict:
        found = dict(pairs)
        if len(found) != len(pairs):
            raise _Invalid("duplicate key")
        return found

    try:
        doc = json.loads(data, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        raise _Invalid("not JSON") from None
    if not isinstance(doc, dict):
        raise _Invalid("not an object")
    return doc


# ── export ───────────────────────────────────────────────────────────────────


def _export_part(outcome: Outcome) -> tuple[str, bytes | None, str | None]:
    """(status, the module's answer, audit error code)."""
    if outcome.exit_code != 0:
        return "unavailable", None, f"exit_{outcome.exit_code}"
    if len(outcome.stdout) > MAX_EXPORT_BYTES:
        return "truncated", None, "too_large"
    try:
        _object(outcome.stdout, MAX_EXPORT_BYTES)
    except _Invalid:
        return "unavailable", None, "invalid_export"
    return "ok", outcome.stdout, None


def _schema(module: Module) -> bytes | None:
    """The module's export schema when it is a JSON file inside the add-on checkout."""
    if not module.schema or module.schema.startswith("https://"):
        return None
    root = module.path.resolve()
    path = (root / module.schema).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    data = path.read_bytes()[: MAX_SCHEMA_BYTES + 1]
    try:
        _object(data, MAX_SCHEMA_BYTES)
    except _Invalid:
        return None
    return data


def _archive(config_dir: Path, parts: list, rows: list[Row], now: datetime) -> bytes:
    stamp = now.astimezone(timezone.utc).timetuple()[:6]
    buffer = io.BytesIO()
    entries = []
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:

        def put(name: str, data: bytes) -> None:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)

        for module, status, data in parts:
            file = f"{module.name}.json" if data is not None else None
            if file:
                put(file, data)
            schema = _schema(module)
            if schema is not None:
                put(f"{module.name}.schema.json", schema)
            entries.append({
                "module": module.name,
                "title": module.title,
                "contract_version": module.contract,
                "status": status,
                "file": file,
                "schema": f"{module.name}.schema.json" if schema is not None else module.schema,
                "bytes": len(data) if data is not None else 0,
            })
        index = {
            "created_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "installation": catalog.installation_name(config_dir),
            "modules": entries,
            "not_connected": [
                {"module": r.module, "entry": r.entry, "reason": r.reason}
                for r in rows if not r.included
            ],
        }
        put("index.json", json.dumps(index, indent=1, ensure_ascii=False).encode() + b"\n")
        put("LIESMICH.txt", README.encode())
    return buffer.getvalue()


def _write_encrypted(out: Path, data: bytes, key: pr.ArchiveKey) -> int:
    """Write the age file (to the passphrase behind `key`) next to `out`, then link it
    into place: an existing file is never replaced, and a half-written file never carries
    the name."""
    tmp = out.with_name(f".{out.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            encryptor = age.Encryptor(fh, scrypt=(key.salt, key.log_n, key.key))
            encryptor.write(data)
            encryptor.close()
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, out)
        return out.stat().st_size
    except FileExistsError:
        raise PersonError(f"{out} exists; the archive of this request was written") from None
    except OSError as exc:
        raise PersonError(f"{out} cannot be written: {exc.strerror}") from None
    finally:
        tmp.unlink(missing_ok=True)


# ── erase ────────────────────────────────────────────────────────────────────


def _lifecycle(repo_root: Path):
    # The erasure journal code of papaia-lifecycle, so the key is read by one rule.
    from . import model_gateway

    return model_gateway._lifecycle_module(repo_root)


def _journal_setup(config_dir: Path, repo_root: Path) -> tuple[bytes, Path]:
    key_file = config_dir / KEY_FILE
    if not key_file.is_file():
        raise PersonError(
            f"the erasure journal is not set up ({key_file} is missing; the lifecycle profile "
            "creates it). Nothing was erased"
        )
    lifecycle = _lifecycle(repo_root)
    try:
        key = lifecycle.read_erasure_key(key_file)
    except lifecycle.LifecycleError as exc:
        raise PersonError(f"erasure journal: {exc}") from None
    backup = common.parse_env_file(config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if not backup or not Path(backup).is_absolute():
        raise PersonError("the erasure journal needs an absolute PAPAIA_BACKUP_DIR")
    folder = Path(backup) / JOURNAL_FOLDER
    if not folder.is_dir():
        raise PersonError(
            f"the erasure journal {folder} is missing: the backup target is not mounted. "
            "Nothing was erased"
        )
    return key, folder


def _receipt(data: bytes, categories: list[str]) -> dict:
    doc = _object(data, MAX_RECEIPT_BYTES)
    if set(doc) != {"categories", "journal"}:
        raise _Invalid("fields")
    named = doc["categories"]
    if not isinstance(named, list) or not 0 < len(named) <= 100:
        raise _Invalid("categories")
    seen = []
    for item in named:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or item.get("state") not in ("done", "kept")
        ):
            raise _Invalid("category")
        if item["state"] == "done":
            if set(item) != {"id", "state", "deleted"}:
                raise _Invalid("category fields")
            if type(item["deleted"]) is not int or not 0 <= item["deleted"] <= 2**53:
                raise _Invalid("deleted")
        else:
            if set(item) != {"id", "state", "until", "reason"}:
                raise _Invalid("category fields")
            if item["reason"] not in KEPT_REASONS or not isinstance(item["until"], str):
                raise _Invalid("kept")
            if not _DATE_RE.fullmatch(item["until"]):
                raise _Invalid("until")
            try:
                date.fromisoformat(item["until"])
            except ValueError:
                raise _Invalid("until") from None
        seen.append(item["id"])
    if sorted(seen) != sorted(categories) or len(set(seen)) != len(seen):
        raise _Invalid("the categories are not the declared ones")
    journal = doc["journal"]
    if not isinstance(journal, list) or len(journal) > 1000:
        raise _Invalid("journal")
    for item in journal:
        if not isinstance(item, dict) or set(item) != {"id", "seq"}:
            raise _Invalid("journal entry")
        if not isinstance(item["id"], str) or not _UUID4_RE.fullmatch(item["id"]):
            raise _Invalid("journal id")
        if type(item["seq"]) is not int or not 0 < item["seq"] <= 2**53 - 1:
            raise _Invalid("journal seq")
    return doc


def _journal_entries(folder: Path, module: str) -> dict[str, dict]:
    """The entries of the module's journal at the backup target, by id. Raises _Invalid
    when the file cannot be read as a journal."""
    try:
        fd = os.open(folder / f"{module}.jsonl", os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError:
        raise _Invalid("journal_unreadable") from None
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_JOURNAL_BYTES + 1)
    if len(data) > MAX_JOURNAL_BYTES:
        raise _Invalid("journal_unreadable")
    entries = {}
    # A last line without a line break is a write that never completed.
    for raw in data[: data.rfind(b"\n") + 1].splitlines():
        try:
            line = json.loads(raw)
        except (ValueError, RecursionError):
            raise _Invalid("journal_unreadable") from None
        if not isinstance(line, dict) or not isinstance(line.get("id"), str):
            raise _Invalid("journal_unreadable")
        entries[line["id"]] = line
    return entries


def _journal_state(folder: Path, module: str, receipt: dict, subject_ref: str) -> tuple:
    """(state, kind, highest seq, error) of the entries the receipt names: `at_target`,
    `pending` (named, not yet at the backup target: the module delivers it later) or
    `none`; error `journal_mismatch` when an entry names another module, kind or person."""
    named = receipt["journal"]
    if not named:
        return "none", None, None, None
    found = _journal_entries(folder, module)
    state, kind = "at_target", None
    for item in named:
        line = found.get(item["id"])
        if line is None:
            state = "pending"
            continue
        if (
            line.get("module") != module
            or line.get("kind") not in ("erase", "erase_subject")
            or not isinstance(line.get("subject_ref"), str)
            or not hmac.compare_digest(line["subject_ref"], subject_ref)
        ):
            return state, None, None, "journal_mismatch"
        kind = line["kind"]
    return state, kind, max(item["seq"] for item in named), None


def _transfer(module: Module, outcome: Outcome, log: rs.AuditLog, sub: str) -> dict | None:
    result, error = None, f"exit_{outcome.exit_code}"
    if outcome.exit_code == 0:
        try:
            doc = _object(outcome.stdout, MAX_RECEIPT_BYTES)
            if set(doc) != {"transferred", "halted"} or not all(
                type(doc[k]) is int and 0 <= doc[k] <= 2**53 for k in doc
            ):
                raise _Invalid("fields")
            result, error = {"module": module.name, **doc}, None
        except _Invalid:
            error = "invalid_receipt"
    _record(log, catalog_id=module.catalog_id, operation="person.transfer_ownership",
            effect="write", sub=sub, error=error, event="ownership_transferred",
            detail={"count": result["transferred"]} if result else None)
    return result


def _erase_module(module: Module, outcome: Outcome, log: rs.AuditLog, sub: str,
                  folder: Path, subject_ref: str) -> list[dict] | None:
    receipt, error = None, f"exit_{outcome.exit_code}" if outcome.exit_code else None
    state = kind = seq = None
    if error is None:
        try:
            receipt = _receipt(outcome.stdout, module.categories)
            state, kind, seq, error = _journal_state(folder, module.name, receipt, subject_ref)
        except _Invalid as exc:
            error = "journal_unreadable" if str(exc) == "journal_unreadable" else "invalid_receipt"
    deleted = sum(c.get("deleted", 0) for c in receipt["categories"]) if receipt else 0
    if error is None and deleted and state == "none":
        error = "no_journal_entry"
    detail: dict = {"count": deleted}
    if kind is not None:
        detail.update(kind=kind, seq=seq)
    _record(log, catalog_id=module.catalog_id, operation="person.erase", effect="delete",
            sub=sub, error=error, detail=detail)
    if error is not None:
        return None
    proof = []
    for item in receipt["categories"]:
        entry = {"module": module.name, "category": item["id"], "state": item["state"]}
        if item["state"] == "done":
            entry.update(deleted=item["deleted"], journal=state if item["deleted"] else "none")
        else:
            entry.update(until=item["until"], reason=item["reason"])
        proof.append(entry)
    return proof


# ── output ───────────────────────────────────────────────────────────────────


def render(report: Report) -> str:
    """The operator's summary: no content, only states, counts and reasons."""
    lines = [f"person {report.operation} {report.sub}: {report.state}"]
    for row in report.rows:
        if row.included:
            lines.append(f"  included      {row.module} ({row.entry})")
        else:
            lines.append(f"  not included  {row.module} ({row.entry}): {row.reason}")
    for item in report.transfers:
        lines.append(
            f"  transferred   {item['module']}: {item['transferred']} handed over, "
            f"{item['halted']} halted"
        )
    for name, state in sorted(report.modules.items()):
        if report.operation == "export" or state != "done":
            lines.append(f"  {name}: {state}")
    for item in report.proof:
        where = f"{item['module']}/{item['category']}"
        if item["state"] == "done":
            journal = {"at_target": "journal at the backup target",
                       "pending": "journal entry pending, not yet at the backup target",
                       "via_event": "journaled by papaia-lifecycle from the deletion event",
                       "none": "nothing to journal"}[item["journal"]]
            lines.append(f"  erased        {where}: {item['deleted']} ({journal})")
        elif item["state"] == "kept":
            lines.append(f"  kept          {where}: until {item['until']} ({item['reason']})")
        elif item["state"] == "held":
            lines.append(f"  kept          {where}: disabled, not deleted (a step failed; the "
                         "sub stays assigned until a new request succeeds)")
        else:
            lines.append(f"  failed        {where}")
    if report.reconciled:
        for item in report.findings:
            count = "could not be checked" if item["count"] is None else item["count"]
            lines.append(f"  left          {item['place']}: {count}")
        if not report.findings:
            lines.append("  reconciliation: nothing of the person left in the core services")
    return "\n".join(lines) + "\n"


# ── a run in steps ───────────────────────────────────────────────────────────
#
# `papaia-ctl person` runs the module steps from bash, as `addon run` and the restore steps
# do: `person-begin` checks the request and plans the steps, `person-next` takes in the
# answer of the step that ran and names the next one, `person-finish` writes the archive
# or the proof. Between the calls the run lives in a folder only the operator's account
# can open, which bash creates and removes: `state.json`, the answer of the step that ran
# (`step.out`) and the export answers (`part-<module>.json`) until the archive is written.

STATE = "state.json"
STEP_OUT = "step.out"
STATE_FORMAT = "papaia.person-run/1"
_OPERATIONS = {EXPORT: "export", ERASE: "erase", TRANSFER: "transfer"}
_STATE_FIELDS = {
    "format", "operation", "sub", "transfer_to", "request", "correlation_id",
    "queue", "pending", "ok", "modules", "proof", "transfers", "core",
}


def _work(work: Path | str) -> Path:
    path = Path(work)
    try:
        info = os.lstat(path)
    except OSError:
        raise PersonError(f"{path} is not the folder of a run") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PersonError(f"{path} must be a folder only this account can open (mode 0700)")
    return path


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _read_private(path: Path, limit: int) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as fh:
        return fh.read(limit + 1)


def _save(work: Path, state: dict) -> None:
    _write_private(work / STATE, json.dumps(state, sort_keys=True).encode())


def _load(work: Path) -> dict:
    data = _read_private(work / STATE, 4 * 1024 * 1024)
    try:
        state = json.loads(data) if data is not None else None
    except ValueError:
        state = None
    if not isinstance(state, dict) or set(state) != _STATE_FIELDS:
        raise PersonError(f"{work / STATE} is not the state of a run")
    if state["format"] != STATE_FORMAT:
        raise PersonError(f"{work / STATE} is not the state of a run")
    return state


def _log(config_dir: Path, state: dict) -> rs.AuditLog:
    try:
        return rs.AuditLog(rs.audit_path(config_dir), state["correlation_id"], writer=WRITER)
    except (OSError, rs.RealmSyncError) as exc:
        raise PersonError(f"the audit outbox cannot be written: {exc}") from None


def _single_host(config_dir: Path) -> None:
    try:
        topo = topology.load_config(config_dir)
    except topology.TopologyError as exc:
        raise PersonError(f"deployment.yaml: {exc}") from None
    if topo.distributed:
        raise PersonError(
            "person export and erase run on a single host installation; in a distributed "
            "installation run the module's person action on its node"
        )


def _gate_call(call: Callable, *args):
    try:
        return call(*args)
    except pr.RequestError as exc:
        raise PersonError(str(exc)) from None


def begin(config_dir: Path, repo_root: Path, work: Path | str, *, request: str,
          gate: pr.Gate) -> None:
    """Check the confirmed request and plan the steps, then mark the request `running`;
    no module step has run yet. Raises PersonError (the request is left as it was when
    a check before the start fails)."""
    work = _work(work)
    if (work / STATE).exists():
        raise PersonError(f"{work} already holds a run")
    config_dir, repo_root = Path(config_dir), Path(repo_root)
    request = _gate_call(pr.check_request_id, request)
    view = _gate_call(pr.get, gate, request)
    if view["state"] != "confirmed":
        label = pr.STATE_LABELS.get(view["state"], view["state"])
        raise PersonError(
            f"request {request} is {view['state']} ({label}); it runs once the person it "
            "names as confirming has confirmed it in the manager, within a day"
        )
    operation, sub = view["operation"], check_sub(view["person"])
    transfer_to = view.get("transfer_to")
    _single_host(config_dir)
    if operation == "export":
        pr.archive_dir(config_dir, create=True)
        out = pr.archive_path(config_dir, request)
        if out.exists() or out.is_symlink():
            raise PersonError(f"{out} exists; the archive of this request was written")
    elif operation == "erase":
        if transfer_to is not None:
            transfer_to = check_sub(transfer_to, "--transfer-to")
            if transfer_to == sub:
                raise PersonError("--transfer-to must name another person than --sub")
        _journal_setup(config_dir, repo_root)
    else:
        raise PersonError("the operation is export or erase")
    modules, core = collect(config_dir, repo_root)
    paths = _core_paths(core)
    if operation == "export":
        queue = [[m.name, EXPORT] for m in modules if EXPORT in m.actions]
        queue += [[p, CORE_STEP + "export"] for p in paths]
    else:
        # Sessions and consents end first; the account goes last (security 1.14 no. 2).
        queue = [[pc.IDENTITY, CORE_STEP + "revoke"]] if pc.IDENTITY in paths else []
        queue += [[m.name, TRANSFER] for m in modules
                  if transfer_to is not None and TRANSFER in m.actions]
        queue += [[m.name, ERASE] for m in modules if ERASE in m.actions]
        queue += [[p, CORE_STEP + "erase"] for p in (pc.CHAT, pc.GATEWAY) if p in paths]
        if pc.IDENTITY in paths:
            queue.append([pc.IDENTITY, CORE_STEP + "delete"])
        if paths:
            queue.append([RECONCILE, CORE_STEP + "check"])
    _gate_call(pr.start, gate, request)
    _save(work, {
        "format": STATE_FORMAT,
        "operation": operation,
        "sub": sub,
        "transfer_to": transfer_to,
        "request": request,
        # The audit rows of every module call carry the request id.
        "correlation_id": request,
        "queue": queue,
        "pending": None,
        "ok": True,
        "modules": {},
        "proof": [],
        "transfers": [],
        # What the core paths learned about the person (chat account ids, mail
        # addresses) for the gateway and the reconciliation; only in the run folder.
        "core": {"paths": paths, "accounts": [], "mails": [], "findings": [],
                 "reconciled": False},
    })


def _take(config_dir: Path, repo_root: Path, work: Path, state: dict, module: Module,
          action: str, outcome: Outcome) -> None:
    """Take in the answer of one step: check it, audit it, keep what the result needs."""
    sub = state["sub"]
    with _log(config_dir, state) as log:
        if action == EXPORT:
            status, data, error = _export_part(outcome)
            _record(log, catalog_id=module.catalog_id, operation="person.export",
                    effect="read", sub=sub, error=error,
                    detail={"bytes": len(data)} if data is not None else None)
            state["modules"][module.name] = status
            state["ok"] = state["ok"] and status == "ok"
            if data is not None:
                _write_private(work / f"part-{module.name}.json", data)
        elif action == TRANSFER:
            result = _transfer(module, outcome, log, sub)
            if result is None:
                state["ok"] = False
                state["modules"][module.name] = "transfer_failed"
                # Nothing is erased while an object could not be handed over; the account
                # stays disabled (the deletion step finds the run failed and holds it).
                state["queue"] = [step for step in state["queue"] if step[1] not in (
                    ERASE, CORE_STEP + "erase", CORE_STEP + "check")]
            else:
                state["transfers"].append(result)
        else:
            key, folder = _journal_setup(config_dir, repo_root)
            subject_ref = hmac.new(key, sub.encode("utf-8"), hashlib.sha256).hexdigest()
            proof = _erase_module(module, outcome, log, sub, folder, subject_ref)
            if proof is None:
                state["ok"] = False
                state["modules"][module.name] = "failed"
                state["proof"] += [
                    {"module": module.name, "category": c, "state": "failed"}
                    for c in module.categories
                ]
            else:
                state["modules"][module.name] = "done"
                state["proof"] += proof


def _core_module(repo_root: Path, service: str) -> Module:
    """A core path as a part of the archive."""
    return Module(name=service, path=repo_root, actions={}, entries=[], categories=[],
                  catalog_id=pc.CATALOG_IDS[service], title=pc.TITLES[service],
                  contract=None, schema=None)


def _core_request(state: dict, service: str) -> dict:
    known = state["core"]
    if service == pc.CHAT:
        return {"sub": state["sub"], "mails": known["mails"], "accounts": known["accounts"]}
    if service == pc.GATEWAY:
        ids = [state["sub"], *known["accounts"], *known["mails"]]
        return {"ids": list(dict.fromkeys(ids))}
    return {"sub": state["sub"]}


def _core_call(core, state: dict, service: str, operation: str) -> tuple[dict | None, str | None]:
    """(answer, error code) of one core path; what it learned is kept for the next ones."""
    try:
        answer = pc.check_answer(service, operation,
                                 core.call(service, operation, _core_request(state, service)))
    except pc.CoreError as exc:
        return None, str(exc) or "backend_failed"
    known = state["core"]
    for name in ("accounts", "mails"):
        for value in answer.get(name, []):
            if value not in known[name] and len(known[name]) < pc.MAX_ACCOUNTS:
                known[name].append(value)
    return answer, None


def _core_journal(config_dir: Path, repo_root: Path, service: str, sub: str,
                  request: str) -> tuple[str, int]:
    """The entry `erase_subject` of the core journal `core-chat` or `model-gateway`
    (written by the host, as lib/model_gateway.py writes `key_revoke`): (`at_target` or
    `pending`, seq). Raises PersonError when no journal can take it."""
    key, folder = _journal_setup(config_dir, repo_root)
    lifecycle = _lifecycle(repo_root)
    local = config_dir / _CORE_JOURNAL_LOCAL
    try:
        local.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        journal = lifecycle.ErasureJournal(service, key=key, target_dir=folder, local_dir=local)
        entry = journal.record("erase_subject", object_ref=f"person_request:{request}",
                               sub=sub, reason="person_erase")
        at_target = entry["id"] in _journal_entries(folder, service)
    except (OSError, lifecycle.LifecycleError, _Invalid):
        raise PersonError(f"the erasure journal {service} cannot take the entry") from None
    return ("at_target" if at_target else "pending"), entry["seq"]


def _core_step(config_dir: Path, repo_root: Path, work: Path, state: dict, service: str,
               operation: str, core) -> None:
    """Run one step of a core path and take in its answer: audited, journaled, proven."""
    sub = state["sub"]
    with _log(config_dir, state) as log:
        if operation == "check":
            _reconcile(log, state, core)
            return
        if operation == "delete" and not state["ok"]:
            # A step failed: the account stays disabled and the sub stays assigned.
            state["modules"][service] = "held"
            state["proof"].append({"module": service, "category": "account", "state": "held"})
            return
        catalog_id = pc.CATALOG_IDS[service]
        answer, error = _core_call(core, state, service, operation)
        if operation == "export":
            data = None
            if answer is not None:
                part = {"service": service, "data": answer["data"]}
                if "found" in answer:
                    part["found"] = answer["found"]
                if service == pc.CHAT:
                    part["not_exported"] = {
                        "collections": list(pc.CHAT_NOT_EXPORTED),
                        "reason": "sign-in material of the chat account, not data about you",
                    }
                data = json.dumps(part, ensure_ascii=False, sort_keys=True).encode("utf-8")
            status = "ok" if data is not None else "unavailable"
            if data is not None and len(data) > MAX_EXPORT_BYTES:
                status, data, error = "truncated", None, "too_large"
            _record(log, catalog_id=catalog_id, operation="person.export", effect="read",
                    sub=sub, error=error,
                    detail={"bytes": len(data)} if data is not None else None)
            state["modules"][service] = status
            state["ok"] = state["ok"] and status == "ok"
            if data is not None:
                _write_private(work / f"part-{service}.json", data)
            return
        counts = answer["counts"] if answer is not None else {}
        if operation in ("revoke", "delete"):
            _record(log, catalog_id=catalog_id, operation=f"person.identity_{operation}",
                    effect="write" if operation == "revoke" else "delete", sub=sub,
                    error=error, detail={"count": sum(counts.values())})
            if error is not None:
                state["ok"] = False
                state["modules"][service] = "failed"
            elif operation == "revoke":
                state["modules"][service] = "disabled" if answer["found"] else "no account"
            else:
                state["modules"][service] = "done"
                state["proof"].append({
                    "module": service, "category": "account", "state": "done",
                    "deleted": counts.get("identity_accounts", 0), "journal": "via_event",
                })
            return
        journal = seq = None
        if error is None:
            try:
                journal, seq = _core_journal(config_dir, repo_root, service, sub,
                                             state["request"])
            except PersonError:
                error = "journal_failed"
        if error is not None:
            _record(log, catalog_id=catalog_id, operation="person.erase", effect="delete",
                    sub=sub, error=error, detail=None)
            state["ok"] = False
            state["modules"][service] = "failed"
            state["proof"].append({"module": service, "category": "all", "state": "failed"})
            return
        # One row per collection or kind, with its count (security 1.14 no. 2a).
        for name, count in sorted(counts.items()):
            _record(log, catalog_id=catalog_id, operation="person.erase", effect="delete",
                    sub=sub, error=None,
                    detail={"objects": [name], "count": count, "kind": "erase_subject",
                            "seq": seq})
            state["proof"].append({"module": service, "category": name, "state": "done",
                                   "deleted": count, "journal": journal})
        state["modules"][service] = "done"


def _reconcile(log: rs.AuditLog, state: dict, core) -> None:
    """GV-30 for the core paths after an erasure: every place that still names the person
    by sub, chat account or mail is a find; a path that cannot be asked is one too."""
    known = state["core"]
    findings: list[dict] = []
    for service in known["paths"]:
        answer, error = _core_call(core, state, service, "check")
        if error is not None:
            findings.append({"place": service, "count": None})
            continue
        findings += [{"place": f"{service}/{name}", "count": count}
                     for name, count in sorted(answer["counts"].items()) if count]
    known["findings"], known["reconciled"] = findings, True
    if findings:
        state["ok"] = False
    _record(log, catalog_id=CORE_CATALOG_ID, operation="person.reconcile", effect="read",
            sub=state["sub"], error=None, detail={"count": len(findings)})


def advance(config_dir: Path, repo_root: Path, work: Path | str,
            exit_code: int | None = None, *, core=None) -> Step | None:
    """Take in the answer of the step that ran (its exit code, its output in `step.out`)
    and return the next step, or None when every step ran. The steps of the core paths
    run here, through `core` (lib/person_core.py; DockerCore when not given)."""
    work = _work(work)
    config_dir, repo_root = Path(config_dir), Path(repo_root)
    state = _load(work)
    modules = {m.name: m for m in collect(config_dir, repo_root)[0]}

    def module(name: str) -> Module:
        if name not in modules:
            raise PersonError(f"add-on {name} no longer declares personal data or is gone")
        return modules[name]

    if state["pending"] is not None:
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            raise PersonError("the exit code (0 to 255) of the step that ran is missing")
        name, action = state["pending"]
        stdout = _read_private(work / STEP_OUT, MAX_EXPORT_BYTES) or b""
        (work / STEP_OUT).unlink(missing_ok=True)
        _take(config_dir, repo_root, work, state, module(name), action,
              Outcome(exit_code, stdout))
        state["pending"] = None
    elif exit_code is not None:
        raise PersonError("no step of this run is running")
    step = None
    while state["queue"]:
        name, action = state["queue"].pop(0)
        if action.startswith(CORE_STEP):
            if core is None:
                core = pc.DockerCore(config_dir, repo_root)
            _core_step(config_dir, repo_root, work, state, name, action[len(CORE_STEP):], core)
            _save(work, state)
            continue
        env = {ENV_SUB: state["sub"], ENV_OPERATION: _OPERATIONS[action],
               ENV_CORRELATION: state["correlation_id"]}
        if action == TRANSFER:
            env[ENV_NEW_OWNER] = state["transfer_to"]
        step = _step(module(name), action, env)
        state["pending"] = [name, action]
        break
    _save(work, state)
    return step


def finish(config_dir: Path, repo_root: Path, work: Path | str, *, gate: pr.Gate,
           now: datetime | None = None) -> Report:
    """The result of a run whose steps all ran: the archive written (export) or the proof
    (erase); the request is `done`, or `partial` when a module failed or the archive could
    not be written."""
    work = _work(work)
    config_dir, repo_root = Path(config_dir), Path(repo_root)
    state = _load(work)
    if state["pending"] is not None or state["queue"]:
        raise PersonError("the run still has steps to take")
    try:
        report = _result(config_dir, repo_root, work, state, gate,
                         now or datetime.now(timezone.utc))
    except PersonError:
        _gate_call(pr.finish, gate, state["request"], "partial")
        raise
    _gate_call(pr.finish, gate, state["request"], report.state)
    return report


def _result(config_dir: Path, repo_root: Path, work: Path, state: dict, gate: pr.Gate,
            now: datetime) -> Report:
    modules, core = collect(config_dir, repo_root)
    operation = state["operation"]
    report = Report(
        operation, state["sub"], _rows(modules, core, EXPORT if operation == "export" else ERASE),
        ok=state["ok"], modules=dict(state["modules"]), proof=list(state["proof"]),
        transfers=list(state["transfers"]), findings=list(state["core"]["findings"]),
        reconciled=state["core"]["reconciled"],
    )
    if operation == "export":
        modules += [_core_module(repo_root, p) for p in state["core"]["paths"]]
        parts = [
            (m, state["modules"][m.name], _read_private(work / f"part-{m.name}.json",
                                                        MAX_EXPORT_BYTES))
            for m in modules if m.name in state["modules"]
        ]
        archive = _archive(config_dir, parts, report.rows, now)
        for m in modules:
            (work / f"part-{m.name}.json").unlink(missing_ok=True)
        key = _gate_call(pr.take_key, gate, state["request"])
        out = pr.archive_path(config_dir, state["request"])
        size = _write_encrypted(out, archive, key)
        pr.record_archive(config_dir, state["request"], now)
        report.archive = out
        with _log(config_dir, state) as log:
            _record(log, catalog_id=CORE_CATALOG_ID, operation="person.export_archive",
                    effect="write", sub=state["sub"], error=None, detail={"bytes": size})
    return report


def step_line(step: Step) -> str:
    """The step as bash runs it: the add-on, then the `docker compose run` arguments after
    `--rm -T` (`-e NAME=value` pairs, the service, its fixed arguments), tab-separated."""
    fields = [step.addon]
    for name, value in sorted(step.env.items()):
        fields += ["-e", f"{name}={value}"]
    fields += [step.service, *step.args]
    return "\t".join(fields)


def _drive(config_dir: Path, repo_root: Path, work: Path, runner: Runner, core=None) -> None:
    code = None
    while (step := advance(config_dir, repo_root, work, code, core=core)) is not None:
        outcome = runner(step)
        _write_private(work / STEP_OUT, outcome.stdout)
        code = outcome.exit_code


def run(config_dir: Path, repo_root: Path, *, request: str, gate: pr.Gate, runner: Runner,
        now: datetime | None = None, core=None) -> Report:
    """A whole confirmed request in one process, each step run by `runner`. An erasure
    runs the transfers first; a failed transfer stops before anything is erased, a failed
    erasure leaves the run `partial` and the other modules go ahead."""
    with tempfile.TemporaryDirectory(prefix="papaia-person-") as work:
        begin(config_dir, repo_root, work, request=request, gate=gate)
        _drive(config_dir, repo_root, Path(work), runner, core)
        return finish(config_dir, repo_root, work, gate=gate, now=now)
