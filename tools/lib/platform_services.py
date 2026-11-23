"""The platform services catalogue (`papaia.platform-services/1`).

What the core profiles and the add-ons of an installation offer to other modules -- an MCP
server, a REST API -- rendered into `$PAPAIA_CONFIG_DIR/platform/services.json`, which
consumers mount read-only. The file holds no secrets and grants nothing: it is an offer, and
each consumer decides whether and how to connect an entry.

Declarations travel with what they describe:

- core modules declare their entries in an `exposes.yaml` next to their compose file
  (`MODULE_EXPOSES`); a module bound to a profile is listed only while it is active;
- add-ons declare theirs under the manifest key `exposes:` (addon_api 7).

The core adds `addon` (`core` or the add-on's name), `version` and, for core modules, `profile`.
The services are sorted by id and covered by a digest; `generated_at` is kept while the digest
does not change, so a render without changes leaves the file byte-identical.

LibreChat's own configuration is not touched by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml

from . import common, compat, deployment

FORMAT = "papaia.platform-services/1"
CATALOGUE_REL_PATH = "platform/services.json"

# Core modules with an `exposes.yaml`, and the Compose profile that switches them on (None:
# part of every installation).
MODULE_EXPOSES: tuple[tuple[str | None, str], ...] = (
    (None, "src/ai/mcp-firecrawl"),
    ("rag", "src/ai/rag"),
    ("knowledge-map", "src/ai/knowledge-map"),
)

KINDS = ("mcp", "rest", "llm_api", "task_feed", "flow_provider")
AUTHS = ("oidc_bearer", "own_oauth", "none")
DATA_CLASSES = (
    "public",
    "internal",
    "partner_contact",
    "personal",
    "employee",
    "confidential",
    "special",
    "professional_secret",
)
TOOL_ACCESS = ("read", "write", "delete")
CONTEXT_ASSERTIONS = ("log", "enforce")
MAX_SERVICES = 500

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,40}$")
_TOOL = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_URL = re.compile(r"^https?://\S+$")

# The fields an entry may carry; the core adds addon, version and profile itself.
_ENTRY_KEYS = frozenset(
    {
        "id",
        "kind",
        "title",
        "description",
        "url",
        "auth",
        "audience",
        "token_exchange",
        "context_assertion",
        "max_class",
        "data_owner_group",
        "suggested_tools",
        "classification_hint",
        "links",
        "consumable",
        "reason",
    }
)


class ServicesError(Exception):
    """A declaration that cannot go into the catalogue; the message names its origin."""


# --- validation ------------------------------------------------------------------------------


def _text(value, where: str) -> dict:
    if not isinstance(value, dict) or set(value) - {"de", "en"}:
        raise ServicesError(f"{where}: expected a mapping with 'de' and optionally 'en'")
    if not isinstance(value.get("de"), str) or not value["de"].strip():
        raise ServicesError(f"{where}: 'de' is required")
    for lang, text in value.items():
        if not isinstance(text, str) or not text.strip() or len(text) > 200:
            raise ServicesError(f"{where}.{lang}: 1 to 200 characters")
    return {lang: value[lang] for lang in ("de", "en") if lang in value}


def _string(value, where: str, *, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ServicesError(f"{where}: a string of 1 to {limit} characters")
    return value


def validate_entry(raw, origin: str) -> dict:
    """A checked copy of one entry, with the fields of `papaia.platform-services/1`.

    The rules of the format: `oidc_bearer` needs an `audience`, `own_oauth` cannot be
    consumable, and `consumable: false` needs a `reason`."""
    if not isinstance(raw, dict):
        raise ServicesError(f"{origin}: an exposes entry must be a mapping")
    service_id = raw.get("id")
    if not isinstance(service_id, str) or not _ID.match(service_id):
        raise ServicesError(f"{origin}: id {service_id!r} must match {_ID.pattern}")
    where = f"{origin}: service {service_id!r}"
    unknown = sorted(set(raw) - _ENTRY_KEYS)
    if unknown:
        raise ServicesError(f"{where}: unknown field(s) {', '.join(unknown)}")

    entry: dict = {"id": service_id}
    if raw.get("kind") not in KINDS:
        raise ServicesError(f"{where}: kind must be one of {', '.join(KINDS)}")
    entry["kind"] = raw["kind"]
    entry["title"] = _text(raw.get("title"), f"{where}: title")
    if "description" in raw:
        entry["description"] = _text(raw["description"], f"{where}: description")
    url = raw.get("url")
    if not isinstance(url, str) or len(url) > 1000 or not _URL.match(url):
        raise ServicesError(f"{where}: url must be an http(s) address")
    entry["url"] = url
    if raw.get("auth") not in AUTHS:
        raise ServicesError(f"{where}: auth must be one of {', '.join(AUTHS)}")
    entry["auth"] = raw["auth"]
    if "audience" in raw:
        entry["audience"] = _string(raw["audience"], f"{where}: audience", limit=255)
    if entry["auth"] == "oidc_bearer" and "audience" not in entry:
        raise ServicesError(f"{where}: auth oidc_bearer needs an audience")
    if "token_exchange" in raw:
        if not isinstance(raw["token_exchange"], bool):
            raise ServicesError(f"{where}: token_exchange must be true or false")
        entry["token_exchange"] = raw["token_exchange"]
    if "context_assertion" in raw:
        modes = raw["context_assertion"]
        if (
            not isinstance(modes, list)
            or len(set(modes)) != len(modes)
            or any(m not in CONTEXT_ASSERTIONS for m in modes)
        ):
            raise ServicesError(f"{where}: context_assertion is a list of log, enforce")
        entry["context_assertion"] = list(modes)
    if "max_class" in raw:
        if raw["max_class"] not in DATA_CLASSES:
            raise ServicesError(f"{where}: max_class must be one of {', '.join(DATA_CLASSES)}")
        entry["max_class"] = raw["max_class"]
    if "data_owner_group" in raw:
        entry["data_owner_group"] = _string(
            raw["data_owner_group"], f"{where}: data_owner_group", limit=255
        )
    if "suggested_tools" in raw:
        entry["suggested_tools"] = _tools(raw["suggested_tools"], where)
    if "classification_hint" in raw:
        hint = raw["classification_hint"]
        if (
            not isinstance(hint, dict)
            or set(hint) != {"attribute", "match_on"}
            or hint.get("match_on") not in ("name", "id")
        ):
            raise ServicesError(f"{where}: classification_hint needs attribute and match_on")
        entry["classification_hint"] = {
            "attribute": _string(hint["attribute"], f"{where}: attribute", limit=128),
            "match_on": hint["match_on"],
        }
    if "links" in raw:
        links = raw["links"]
        item = links.get("item") if isinstance(links, dict) else None
        if not isinstance(links, dict) or set(links) - {"item"} or (
            item is not None
            and (not isinstance(item, str) or len(item) > 1000 or not item.startswith("https://"))
        ):
            raise ServicesError(f"{where}: links.item must be an https address")
        entry["links"] = dict(links)
    if not isinstance(raw.get("consumable"), bool):
        raise ServicesError(f"{where}: consumable must be true or false")
    entry["consumable"] = raw["consumable"]
    if "reason" in raw:
        entry["reason"] = _string(raw["reason"], f"{where}: reason", limit=300)
    if not entry["consumable"] and "reason" not in entry:
        raise ServicesError(f"{where}: consumable false needs a reason")
    if entry["auth"] == "own_oauth" and entry["consumable"]:
        raise ServicesError(f"{where}: auth own_oauth cannot be consumable")
    return entry


def _tools(value, where: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > 100:
        raise ServicesError(f"{where}: suggested_tools is a list of at most 100 tools")
    tools = []
    for tool in value:
        if (
            not isinstance(tool, dict)
            or set(tool) - {"name", "access", "class", "title"}
            or not isinstance(tool.get("name"), str)
            or not _TOOL.match(tool["name"])
            or tool.get("access") not in TOOL_ACCESS
            or tool.get("class") not in DATA_CLASSES
        ):
            raise ServicesError(f"{where}: a suggested tool needs name, access and class")
        checked = {"name": tool["name"], "access": tool["access"], "class": tool["class"]}
        if "title" in tool:
            checked["title"] = _text(tool["title"], f"{where}: tool {tool['name']} title")
        tools.append(checked)
    return tools


def manifest_entries(manifest: dict, origin: str) -> list[dict]:
    """The checked `exposes:` entries of an add-on manifest; raises ServicesError."""
    raw = manifest.get("exposes")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ServicesError(f"{origin}: 'exposes' must be a list of entries")
    entries = [validate_entry(item, origin) for item in raw]
    ids = [e["id"] for e in entries]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ServicesError(f"{origin}: duplicate service id(s) {', '.join(duplicates)}")
    return entries


# --- collecting ------------------------------------------------------------------------------


def _core_version(repo_root: Path) -> str:
    path = repo_root / "VERSION"
    version = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
    return version if _VERSION.match(version) else "0.0.0"


def _module_entries(repo_root: Path, module_path: str) -> list[dict]:
    path = repo_root / module_path / "exposes.yaml"
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ServicesError(f"{path}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise ServicesError(f"{path}: expected a mapping with an 'exposes' list")
    return manifest_entries(data, f"{module_path}/exposes.yaml")


def collect(
    repo_root: Path, active_profiles: set[str], active_addons: list[dict]
) -> list[dict]:
    """Every entry of the active core modules and add-ons, with addon, version and profile,
    sorted by id. Ids must be unique across all of them."""
    services: dict[str, dict] = {}
    origins: dict[str, str] = {}

    def add(entries: list[dict], origin: str, extra: dict) -> None:
        for entry in entries:
            if entry["id"] in services:
                raise ServicesError(
                    f"duplicate service id {entry['id']!r} ({origins[entry['id']]} vs {origin})"
                )
            services[entry["id"]] = {"id": entry["id"], **extra, **entry}
            origins[entry["id"]] = origin

    core_version = _core_version(repo_root)
    for profile, module_path in MODULE_EXPOSES:
        if profile is not None and profile not in active_profiles:
            continue
        extra = {"addon": "core", "version": core_version}
        if profile is not None:
            extra["profile"] = profile
        add(_module_entries(repo_root, module_path), module_path, extra)

    for addon in active_addons:
        addon_path = deployment.resolve_addon_path(addon, repo_root)
        if not (addon_path / "papaia-app.yaml").is_file():
            continue
        manifest, reason = deployment.load_addon_manifest(addon_path)
        if manifest is None:
            raise ServicesError(reason or f"{addon_path}: manifest not readable")
        name = str(manifest.get("name") or addon.get("name") or addon_path.name)
        version = str(manifest.get("version") or addon.get("version") or "0.0.0")
        if not _NAME.match(name):
            raise ServicesError(f"addon {name!r}: the name cannot be used in the catalogue")
        if not _VERSION.match(version):
            version = "0.0.0"
        origin = f"addon '{name}'"
        add(manifest_entries(manifest, origin), origin, {"addon": name, "version": version})

    if len(services) > MAX_SERVICES:
        raise ServicesError(f"more than {MAX_SERVICES} services in the catalogue")
    return [services[key] for key in sorted(services)]


# --- rendering -------------------------------------------------------------------------------


def _digest(services: list[dict]) -> str:
    canonical = json.dumps(services, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _previous(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def render(
    config_dir: Path, repo_root: Path, active_profiles: set[str], active_addons: list[dict]
) -> Path:
    """Write the catalogue atomically and return its path; raises ServicesError."""
    services = collect(repo_root, active_profiles, active_addons)
    digest = _digest(services)
    path = config_dir / CATALOGUE_REL_PATH
    previous = _previous(path)
    generated_at = previous.get("generated_at") if previous.get("digest") == digest else None
    if not isinstance(generated_at, str):
        generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    document: dict = {"format": FORMAT, "generated_at": generated_at}
    try:
        window = compat.resolve_addon_api_window(repo_root)
    except ValueError:
        window = None
    if window is not None:
        document["addon_api"] = window[1]
    document["digest"] = digest
    document["services"] = services
    common.atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    return path
