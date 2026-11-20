"""The internal certificate authority of the optional `pki` profile (ADR 0019, docs/pki.md).

One CA per installation issues the certificates services use among themselves: a server
certificate with the names a service is reached under, a client certificate whose subject
CN names the service, and the CA bundle every one of them trusts. Modules ask for them in
the `pki:` block of their manifest (`papaia-app.yaml`); a core module asks the same way in
a `pki.yaml` next to its compose file. The files land in

    <PAPAIA_PKI_DIR>/ca-bundle.crt, inventory.json
    <PAPAIA_PKI_DIR>/<module>/<service>/{ca.crt, tls.crt, tls.key, client.crt,
                                         client.key, generation}

with every directory and key owned by the numeric user of the service that reads it.

This module does what needs no key: it reads the requests, keeps the profile's settings in
the root `.env`, writes the request list for the issuer and reads its inventory. Signing
happens in the one-shot `pki-issuer` container (src/infra/pki/), the only place the CA key
is ever mounted; `tools/lib/sh/pki.sh` runs it and restarts what it changed.

Nothing here runs while the profile is off: no key in `.env`, no file, no container.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import common, deployment, topology

PROFILE = "pki"
KEY_DIR = "PAPAIA_PKI_DIR"
KEY_MODE = "PAPAIA_PKI_MODE"
KEY_LEAF_DAYS = "PAPAIA_PKI_LEAF_DAYS"
MODES = ("issue", "external")
DEFAULT_MODE = "issue"
DEFAULT_LEAF_DAYS = 90
MAX_LEAF_DAYS = 90
DEFAULT_SUBDIR = "pki"

# The module name of requests made by core modules (src/**/pki.yaml).
CORE_MODULE = "core"
CORE_REQUEST_FILE = "pki.yaml"

COMPOSE_FILE = Path("src") / "infra" / "pki" / "docker-compose.yml"
REQUESTS_FILE = "requests.tsv"
INVENTORY_FILE = "inventory.json"
BUNDLE_FILE = "ca-bundle.crt"
CA_VOLUME = "pki-ca"
FORMAT = "papaia.platform-pki/1"

# `papaia-ctl pki status` and `doctor` warn this many days before a certificate ends. A leaf
# is renewed when a third of its lifetime is left (30 days of 90), so a warning means the
# renewal did not run.
EXPIRY_WARN_DAYS = 14

_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_MODULE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_DNS_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_MAX_UID = 2**31 - 1


class PkiError(Exception):
    """A request, a setting or a directory the PKI cannot work with. The message says why."""


@dataclass(frozen=True)
class ServiceRequest:
    module: str
    name: str
    uid: int
    dns: tuple[str, ...] = ()
    client: bool = False

    def line(self) -> str:
        dns = ",".join(self.dns) or "-"
        return f"{self.module}\t{self.name}\t{self.uid}\t{dns}\t{1 if self.client else 0}"


# ─────────────────────────────────────────────────────────────────────────
# requests
# ─────────────────────────────────────────────────────────────────────────


def parse_request(block: object, module: str, source: str) -> list[ServiceRequest]:
    """The service requests of one `pki:` block. `source` names the file in messages."""
    if block is None:
        return []
    if not _MODULE_RE.match(module):
        raise PkiError(f"{source}: '{module}' cannot name a directory of the PKI")
    if not isinstance(block, dict):
        raise PkiError(f"{source}: `pki` must be a mapping with a `services` list")
    services = block.get("services")
    if services is None:
        return []
    if not isinstance(services, list):
        raise PkiError(f"{source}: `pki.services` must be a list")
    found: list[ServiceRequest] = []
    seen: set[str] = set()
    for index, entry in enumerate(services):
        where = f"{source}: pki.services[{index}]"
        if not isinstance(entry, dict):
            raise PkiError(f"{where} must be a mapping")
        unknown = set(entry) - {"name", "uid", "server", "client"}
        if unknown:
            raise PkiError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
        name = entry.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise PkiError(f"{where}.name must be a DNS label (a-z, 0-9, -), not {name!r}")
        if name in seen:
            raise PkiError(f"{where}.name '{name}' is requested twice")
        seen.add(name)
        uid = entry.get("uid")
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= _MAX_UID:
            raise PkiError(f"{where}.uid must be the numeric user of the service, not {uid!r}")
        dns: list[str] = []
        server = entry.get("server")
        if server is not None:
            if not isinstance(server, dict) or not isinstance(server.get("dns"), list):
                raise PkiError(f"{where}.server must be a mapping with a `dns` list")
            for value in server["dns"]:
                if not isinstance(value, str) or not _DNS_RE.match(value.lower()):
                    raise PkiError(f"{where}.server.dns: {value!r} is not a DNS name")
                if value.lower() not in dns:
                    dns.append(value.lower())
            if not dns:
                raise PkiError(f"{where}.server.dns must name at least one DNS name")
        client = entry.get("client", False)
        if not isinstance(client, bool):
            raise PkiError(f"{where}.client must be true or false")
        found.append(ServiceRequest(module, name, uid, tuple(dns), client))
    return found


def core_requests(repo_root: Path, profiles: set[str]) -> list[ServiceRequest]:
    """Requests of core modules: a `pki.yaml` (`profile:` plus a `pki:` block) next to a
    module's compose file, honoured while that profile is on."""
    found: list[ServiceRequest] = []
    for path in sorted((repo_root / "src").rglob(CORE_REQUEST_FILE)):
        source = path.relative_to(repo_root).as_posix()
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PkiError(f"{source} is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("profile"), str):
            raise PkiError(f"{source} must name the `profile` its services belong to")
        if doc["profile"] in profiles:
            found += parse_request(doc.get("pki"), CORE_MODULE, source)
    return found


@dataclass
class Plan:
    requests: list[ServiceRequest]
    # Add-ons whose requests are not served here, with the reason.
    skipped: list[str]


def collect(config_dir: Path, repo_root: Path) -> Plan:
    """Everything requested by the core modules that are on and the active add-ons.

    In a distributed installation the CA stays on the controller, and so do the files it
    writes: an add-on placed on another node is reported, not served."""
    root = common.parse_env_file(config_dir / ".env")
    profiles = common.cluster_profiles(root)
    requests = core_requests(repo_root, profiles)
    skipped: list[str] = []
    manifest = deployment.load(config_dir)
    try:
        topo = topology.load(manifest)
    except topology.TopologyError:
        topo = None
    for entry in deployment.active_addons(manifest):
        name = str(entry.get("name") or "")
        path = deployment.resolve_addon_path(entry, repo_root)
        addon_manifest, _reason = deployment.load_addon_manifest(path)
        if not addon_manifest or addon_manifest.get("pki") is None:
            continue
        if name == CORE_MODULE:
            raise PkiError(f"the add-on name '{CORE_MODULE}' is reserved for the core's requests")
        node = str(entry.get("node") or "")
        if topo is not None and topo.distributed and node and node != topo.controller:
            skipped.append(
                f"{name}: runs on node '{node}'; the PKI serves add-ons on the controller"
                f" '{topo.controller}' only"
            )
            continue
        requests += parse_request(addon_manifest.get("pki"), name, f"{name}/papaia-app.yaml")
    return Plan(requests, skipped)


# ─────────────────────────────────────────────────────────────────────────
# settings
# ─────────────────────────────────────────────────────────────────────────


def _profiles(root: dict[str, str]) -> list[str]:
    return [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]


def enabled(config_dir: Path) -> bool:
    root = common.parse_env_file(config_dir / ".env")
    return PROFILE in _profiles(root) and bool(root.get(KEY_DIR, "").strip())


def default_dir(config_dir: Path) -> Path:
    return config_dir / DEFAULT_SUBDIR


def check_dir(path: Path, config_dir: Path) -> Path:
    """The PKI directory, refused where clearing it would hurt: it is emptied by
    `pki purge` and every service directory in it is handed to another user."""
    if not path.is_absolute():
        raise PkiError(f"{KEY_DIR} must be an absolute path, not '{path}'")
    resolved = Path(str(path)).resolve()
    config = config_dir.resolve()
    if resolved == resolved.parent:
        raise PkiError(f"{KEY_DIR} cannot be the root directory")
    if resolved == config or resolved in config.parents:
        raise PkiError(f"{KEY_DIR} must be a directory of its own, not {resolved}")
    return path


def settings(config_dir: Path) -> dict[str, str]:
    """The profile's settings as the issuer gets them, validated."""
    root = common.parse_env_file(config_dir / ".env")
    raw_dir = root.get(KEY_DIR, "").strip()
    directory = check_dir(Path(raw_dir), config_dir) if raw_dir else default_dir(config_dir)
    mode = root.get(KEY_MODE, "").strip() or DEFAULT_MODE
    if mode not in MODES:
        raise PkiError(f"{KEY_MODE} must be one of {', '.join(MODES)}, not '{mode}'")
    raw_days = root.get(KEY_LEAF_DAYS, "").strip() or str(DEFAULT_LEAF_DAYS)
    if not raw_days.isdigit() or not 1 <= int(raw_days) <= MAX_LEAF_DAYS:
        raise PkiError(f"{KEY_LEAF_DAYS} must be between 1 and {MAX_LEAF_DAYS}, not '{raw_days}'")
    project = root.get("COMPOSE_PROJECT_NAME") or "papaia"
    return {
        "PKI_ENABLED": "true" if enabled(config_dir) else "false",
        "PKI_DIR": str(directory),
        "PKI_MODE": mode,
        "PKI_LEAF_DAYS": raw_days,
        "PKI_PROJECT": project,
        "PKI_CA_NAME": "papAIa internal CA",
        "PKI_INSIDE_CONFIG": "true" if _inside(directory, config_dir) else "false",
    }


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def configure(
    config_dir: Path, repo_root: Path, *, enable: bool | None, directory: str | None = None
) -> bool:
    """Switches the profile on or off in the root `.env` (config dir and checkout) and in
    `deployment.yaml`; None keeps the stored choice. Returns whether it is on.

    Off removes `PAPAIA_PKI_DIR`, so an add-on sees the same `.env` as on an installation
    that never had the profile; the files already issued stay until `pki purge`."""
    env_path = config_dir / ".env"
    root = common.parse_env_file(env_path)
    profiles = _profiles(root)
    on = (PROFILE in profiles) if enable is None else enable
    before = dict(root)
    if on:
        if PROFILE not in profiles:
            profiles.append(PROFILE)
            root["COMPOSE_PROFILES"] = ",".join(profiles)
        current = directory or root.get(KEY_DIR, "").strip()
        chosen = Path(current) if current else default_dir(config_dir)
        root[KEY_DIR] = str(check_dir(chosen, config_dir))
    else:
        if PROFILE in profiles:
            profiles = [p for p in profiles if p != PROFILE]
            root["COMPOSE_PROFILES"] = ",".join(profiles)
        root.pop(KEY_DIR, None)
    if root != before:
        template = repo_root / "src" / ".env.example"
        for target in (env_path, repo_root / "src" / ".env"):
            if target == env_path or target.is_file():
                common.write_env_file(
                    target, root, template_path=template if template.is_file() else None
                )
                if KEY_DIR not in root:
                    _drop_key(target, KEY_DIR)
        manifest = deployment.load(config_dir)
        if manifest:
            manifest.setdefault("core", {})["profiles"] = profiles
            deployment.save(config_dir, manifest)
    return on


def _drop_key(path: Path, key: str) -> None:
    """Removes `key` from a `.env` file, and the papaia-ctl banner when nothing is left
    under it: written from the file itself, `write_env_file` keeps a key it is not given."""
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.split("=", 1)[0].strip() != key]
    while kept and kept[-1].strip() == "":
        kept.pop()
    if kept and kept[-1].startswith("# --- Generated by papaia-ctl"):
        kept.pop()
        while kept and kept[-1].strip() == "":
            kept.pop()
    if kept != lines:
        common.atomic_write(path, "\n".join(kept) + "\n")


def write_requests(config_dir: Path, repo_root: Path) -> Plan:
    """Writes the request list into the PKI directory for the issuer."""
    plan = collect(config_dir, repo_root)
    directory = Path(settings(config_dir)["PKI_DIR"])
    common.ensure_dir(directory)
    lines = ["# Written by papaia-ctl from the pki requests; read by the pki-issuer."]
    lines += [request.line() for request in plan.requests]
    target = directory / REQUESTS_FILE
    content = "\n".join(lines) + "\n"
    if not target.is_file() or target.read_text(encoding="utf-8") != content:
        common.atomic_write(target, content)
    return plan


# ─────────────────────────────────────────────────────────────────────────
# inventory
# ─────────────────────────────────────────────────────────────────────────


def read_inventory(directory: Path) -> dict | None:
    path = directory / INVENTORY_FILE
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def certificates(inventory: dict) -> list[dict]:
    """Every certificate of the inventory as {label, kind, not_after}: the CAs first."""
    rows: list[dict] = []
    for ca in inventory.get("ca") or []:
        if isinstance(ca, dict):
            rows.append(
                {
                    "label": f"CA {ca.get('subject', '?')} ({ca.get('role', '?')})",
                    "kind": "ca",
                    "not_after": _parse_time(ca.get("not_after")),
                }
            )
    for service in inventory.get("services") or []:
        if not isinstance(service, dict):
            continue
        base = f"{service.get('module', '?')}/{service.get('name', '?')}"
        for kind, file_name in (("server", "tls.crt"), ("client", "client.crt")):
            entry = service.get(kind)
            if isinstance(entry, dict):
                rows.append(
                    {
                        "label": f"{base}/{file_name}",
                        "kind": kind,
                        "not_after": _parse_time(entry.get("not_after")),
                    }
                )
    return rows


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def status(config_dir: Path, *, now: datetime | None = None) -> dict:
    """What `papaia-ctl pki status` shows: the settings, the certificates and their days
    left, and `attention` when one ends within EXPIRY_WARN_DAYS or is unreadable."""
    now = now or datetime.now(timezone.utc)
    report: dict = {"enabled": enabled(config_dir), "certificates": [], "attention": False}
    try:
        values = settings(config_dir)
    except PkiError as exc:
        report["error"] = str(exc)
        report["attention"] = True
        return report
    report.update(
        {"dir": values["PKI_DIR"], "mode": values["PKI_MODE"], "leaf_days": values["PKI_LEAF_DAYS"]}
    )
    inventory = read_inventory(Path(values["PKI_DIR"]))
    if inventory is None:
        report["attention"] = report["enabled"]
        return report
    report["generated_at"] = inventory.get("generated_at")
    for row in certificates(inventory):
        not_after = row["not_after"]
        days = None if not_after is None else (not_after - now).days
        state = "ok"
        if days is None or days < 0:
            state = "expired" if days is not None else "unknown"
        elif days < EXPIRY_WARN_DAYS:
            state = "expiring"
        if state != "ok":
            report["attention"] = True
        report["certificates"].append(
            {
                "certificate": row["label"],
                "not_after": None if not_after is None else _iso(not_after),
                "days_left": days,
                "state": state,
            }
        )
    return report


def format_status(report: dict) -> str:
    lines = [f"PKI: {'on' if report.get('enabled') else 'off'}"]
    if report.get("error"):
        lines.append(f"  error: {report['error']}")
        return "\n".join(lines) + "\n"
    lines.append(f"  directory: {report.get('dir')}")
    lines.append(f"  mode:      {report.get('mode')}  (leaves live {report.get('leaf_days')} days)")
    if not report.get("certificates"):
        lines.append("  no certificates issued yet")
        return "\n".join(lines) + "\n"
    width = max(len(row["certificate"]) for row in report["certificates"])
    for row in report["certificates"]:
        days = "?" if row["days_left"] is None else f"{row['days_left']} days"
        end = row["not_after"] or "?"
        lines.append(f"  {row['certificate']:<{width}}  {end:<20}  {days:>9}  {row['state']}")
    return "\n".join(lines) + "\n"


def doctor_items(config_dir: Path, now: datetime) -> list[dict]:
    """The issued certificates for `doctor`'s certs check, as {path, not_after}. Empty
    while the profile is off, so nothing changes in the report of such an installation."""
    if not enabled(config_dir):
        return []
    try:
        directory = Path(settings(config_dir)["PKI_DIR"])
    except PkiError:
        return []
    inventory = read_inventory(directory)
    if inventory is None:
        return []
    return [
        {"path": f"pki:{row['label']}", "not_after": row["not_after"], "kind": row["kind"]}
        for row in certificates(inventory)
    ]
