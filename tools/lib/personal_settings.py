"""Renders the registry of personal settings from module and add-on declarations.

Each module that keeps personal settings for a person declares their structure once:
core modules in `personal-settings.yaml` in their module directory, add-ons in the
`personal_settings:` key of `papaia-app.yaml`. The personal area (profile `me`) builds
its pages from the rendered registry and talks to each module over the module API of
docs/personal-settings-contract.md. Values are never part of a declaration: every module
stores and checks its own, the area stores nothing.

Like the knowledge map and the baked realm this is a generated artifact with its own
render function, not a layered merge target. It is rendered only while the profile `me`
is on, so a stack without the area writes nothing new.

A declaration is foreign text that ends up on a page every person of the installation
sees, so it is checked here against the contract (the same rules as
tools/schemas/personal-settings.schema.json, plus what a schema cannot say) and a
declaration that breaks one is refused with a named error instead of being rendered:

- closed field types; for each type only its own properties;
- defaults among the options and within the bounds, patterns that compile;
- plain text only: control characters are removed, markup, links and text shaped like
  instructions to a model are refused, titles stay within 80 and hints within 300
  characters;
- an add-on may only name an audience that is one of its own Keycloak clients, and its
  module name is its add-on name; a core module only its fixed audience.

The registry is written as JSON. JSON is YAML, so any YAML reader reads the file, and the
realm sync (keycloak_role_sync.py, standard library only) reads the audiences from it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from pathlib import Path

import yaml

from . import common, deployment

REGISTRY_REL = "personal-settings/registry.yaml"
MODULE_FILE = "personal-settings.yaml"

# Contract generations of the section this core renders. A declaration outside the window
# is skipped with a warning: a newer add-on must not stop the render of an older core.
API_MIN = 1
API_CURRENT = 1

# Version of the registry file itself (not of the module API).
REGISTRY_FORMAT = 1

# Core modules that may declare personal settings: profile -> (directory, audience). The
# audience is fixed here because the module's Keycloak client is part of the core's
# realm, not of the declaration. A module installed as an add-on declares in its own
# manifest instead (papaia-flow), so every module has exactly one declaration.
MODULE_DECLARATIONS: dict[str, tuple[str, str]] = {
    "assist": ("src/ai/assist", "assist-api"),
}

# Add-ons whose Keycloak client is created by their own realm setup (an action of the
# add-on) rather than by a client fragment the core registers: add-on name -> clients.
# The core already relies on these names elsewhere (papaia-manager exchanges for the
# audience `flow` to approve a Flow link), so they are fixed here and no other add-on can
# claim them.
ADDON_REALM_CLIENTS: dict[str, tuple[str, ...]] = {
    "papaia-flow": ("flow",),
}

# Platform services that keep personal data but declare no personal settings. The area
# names them on "my data" so its overview never claims a completeness it does not have.
# (id, profile that must be on or None for always, title, hint)
NOT_CONNECTED: tuple[tuple[str, str | None, dict[str, str], dict[str, str]], ...] = (
    (
        "chat",
        None,
        {"de": "Chat", "en": "Chat"},
        {
            "de": "Gespräche und hochgeladene Dateien im Chat. Auskunft und Löschung über"
            " die Datenschutzbeauftragten.",
            "en": "Conversations and uploaded files in the chat. Information and erasure"
            " through the data protection officer.",
        },
    ),
    (
        "model-gateway",
        None,
        {"de": "Zugang zu den Sprachmodellen", "en": "Language model gateway"},
        {
            "de": "Nutzungsdaten je Anfrage an ein Sprachmodell. Auskunft über die"
            " Datenschutzbeauftragten.",
            "en": "Usage data of every request to a language model. Information through the"
            " data protection officer.",
        },
    ),
    (
        "identity",
        None,
        {"de": "Anmeldung und Konto", "en": "Sign-in and account"},
        {
            "de": "Name, E-Mail-Adresse, Passwort, zweiter Faktor und Sitzungen. Einsicht"
            " und Änderung in der Kontoverwaltung der Anmeldung.",
            "en": "Name, e-mail address, password, second factor and sessions. See and"
            " change them in the account console of the sign-in.",
        },
    ),
    (
        "manager",
        "manager",
        {"de": "Verwaltung", "en": "Administration"},
        {
            "de": "Die Sprache, die Sie in der Verwaltung gewählt haben. Auskunft über die"
            " Datenschutzbeauftragten.",
            "en": "The language you chose in the administration. Information through the"
            " data protection officer.",
        },
    ),
)

FIELD_TYPES = (
    "boolean",
    "choice",
    "multi_choice",
    "ordered_multi_choice",
    "integer",
    "text",
    "time_range",
    "date",
    "person",
)
DATA_CLASSES = ("public", "internal", "confidential", "personal", "special")
ERASURE = ("none", "self", "request")
LANGUAGES = ("de", "en")
TITLE_MAX = 80
HINT_MAX = 300
TEXT_MAX_LENGTH = 1000
MAX_GROUPS = 32
MAX_SETTINGS = 64
MAX_ITEM_FIELDS = 16
MAX_OPTIONS = 64
MAX_OPERATIONS = 8
MAX_DAYS = 3660

_MODULE_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_OPTION_RE = re.compile(r"^[a-z0-9/][a-z0-9_./-]{0,254}$")
# The integer range JSON numbers keep exactly.
_INT_LIMIT = 2**53 - 1
_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_AUDIENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_PATH_RE = re.compile(r"^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$")
_CLOCK_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")

# Text a person reads on the area's pages. The area escapes everything it shows; these
# rules keep a declaration from even trying: no markup, no links, no smuggled characters,
# nothing shaped like an instruction to a model (the area may hand titles to the search
# or to an assistant later). Every hit refuses the declaration.
_FORBIDDEN_TEXT: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"<\s*/?\s*[A-Za-z!?]"), "markup"),
    (re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://"), "a link"),
    (re.compile(r"\bwww\.", re.IGNORECASE), "a link"),
    (re.compile(r"\b(javascript|data|vbscript)\s*:", re.IGNORECASE), "a script link"),
    (re.compile(r"!?\[[^\]]*\]\s*\("), "a Markdown link"),
    (re.compile(r"<\|[a-z_]+\|>", re.IGNORECASE), "a model control token"),
    (
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b"
            r".{0,40}\binstructions?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "instruction text",
    ),
    (
        re.compile(r"\byou\s+must\s+(not\s+)?(tell|reveal|mention)\b", re.IGNORECASE),
        "instruction text",
    ),
    # Zero-width and direction-changing characters have no use in a title and can make a
    # text read differently from what it is. ZWNJ and ZWJ stay allowed: some scripts need
    # them.
    (re.compile("[​⁠﻿‪-‮⁦-⁩]"), "an invisible character"),
)


class PersonalSettingsError(Exception):
    """A declaration the registry must not take (broken contract, foreign audience …)."""


class _Checker:
    """Walks one section and builds its normalised copy. Every error names the origin
    (module or add-on) and the place in the section."""

    def __init__(self, origin: str) -> None:
        self.origin = origin

    def fail(self, where: str, message: str) -> None:
        raise PersonalSettingsError(f"{self.origin}: personal_settings{where}: {message}")

    def mapping(self, value, where: str, required: tuple[str, ...], allowed: tuple[str, ...]):
        if not isinstance(value, dict):
            self.fail(where, f"must be a mapping, got {type(value).__name__}")
        for key in value:
            if not isinstance(key, str) or key not in allowed:
                self.fail(where, f"unknown key {key!r} (allowed: {', '.join(allowed)})")
        for key in required:
            if key not in value:
                self.fail(where, f"{key} is missing")
        return value

    def string(self, value, where: str, pattern: re.Pattern, what: str) -> str:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            self.fail(where, f"{value!r} is not {what}")
        return value

    def integer(self, value, where: str, low: int | None = None, high: int | None = None) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            self.fail(where, f"{value!r} is not an integer")
        if (low is not None and value < low) or (high is not None and value > high):
            self.fail(where, f"{value} is outside {low}..{high}")
        return value

    def text(self, value, where: str, limit: int) -> dict:
        """A plain text in de and/or en, cleaned of control characters."""
        self.mapping(value, where, (), LANGUAGES)
        if not value:
            self.fail(where, "needs at least one of de and en")
        clean = {}
        for language in LANGUAGES:
            if language not in value:
                continue
            raw = value[language]
            if not isinstance(raw, str):
                self.fail(f"{where}.{language}", "must be a string")
            text = "".join(ch for ch in raw if unicodedata.category(ch) != "Cc").strip()
            if not text:
                self.fail(f"{where}.{language}", "is empty")
            if len(text) > limit:
                self.fail(f"{where}.{language}", f"is longer than {limit} characters")
            for pattern, what in _FORBIDDEN_TEXT:
                if pattern.search(text):
                    self.fail(f"{where}.{language}", f"contains {what}; only plain text is allowed")
            clean[language] = text
        return clean


def _field(check: _Checker, raw, where: str) -> dict:
    if not isinstance(raw, dict):
        check.fail(where, "must be a mapping")
    field_type = raw.get("type")
    if field_type not in FIELD_TYPES:
        check.fail(f"{where}.type", f"{field_type!r} is not one of {', '.join(FIELD_TYPES)}")
    common_keys = ("key", "type", "title", "hint", "replaces")
    extra = {
        "boolean": ("default",),
        "choice": ("options", "default"),
        "multi_choice": ("options", "default"),
        "ordered_multi_choice": ("options", "default"),
        "integer": ("min", "max", "default"),
        "text": ("max_length", "pattern", "default"),
        "time_range": ("default",),
        "date": ("max_days",),
        "person": (),
    }[field_type]
    required = {
        "choice": ("options",),
        "multi_choice": ("options",),
        "ordered_multi_choice": ("options",),
        "integer": ("min", "max"),
        "text": ("max_length",),
    }.get(field_type, ())
    check.mapping(raw, where, ("key", "type", "title", *required), common_keys + extra)

    out: dict = {
        "key": check.string(raw["key"], f"{where}.key", _KEY_RE, "a key ([a-z][a-z0-9_]*)"),
        "type": field_type,
        "title": check.text(raw["title"], f"{where}.title", TITLE_MAX),
    }
    if "hint" in raw:
        out["hint"] = check.text(raw["hint"], f"{where}.hint", HINT_MAX)
    if "replaces" in raw:
        old = check.string(raw["replaces"], f"{where}.replaces", _KEY_RE, "a key")
        if old == out["key"]:
            check.fail(f"{where}.replaces", "names the key itself")
        out["replaces"] = old

    if field_type == "boolean":
        if "default" in raw:
            if not isinstance(raw["default"], bool):
                check.fail(f"{where}.default", "must be true or false")
            out["default"] = raw["default"]

    elif field_type in ("choice", "multi_choice", "ordered_multi_choice"):
        options = raw["options"]
        # Typed: 1, True and "1" are three different values (JSON keeps them apart).
        values: list[tuple[type, OptionValue]] | None = None
        if options == "runtime":
            out["options"] = "runtime"
        else:
            if not isinstance(options, list) or not 1 <= len(options) <= MAX_OPTIONS:
                check.fail(f"{where}.options", f"must be 'runtime' or a list of 1..{MAX_OPTIONS}")
            out["options"] = []
            values = []
            for index, option in enumerate(options):
                at = f"{where}.options[{index}]"
                check.mapping(option, at, ("value", "title"), ("value", "title"))
                value = _option_value(check, option["value"], f"{at}.value")
                if values and type(value) is not values[0][0]:
                    check.fail(f"{at}.value", "is of another type than the first option")
                if (type(value), value) in values:
                    check.fail(f"{at}.value", f"{value!r} is listed twice")
                values.append((type(value), value))
                out["options"].append(
                    {"value": value, "title": check.text(option["title"], f"{at}.title", TITLE_MAX)}
                )
        if "default" in raw:
            default = raw["default"]
            if field_type == "choice":
                default = _option_value(check, default, f"{where}.default")
                chosen = [default]
            else:
                if not isinstance(default, list) or len(default) > MAX_OPTIONS:
                    check.fail(f"{where}.default", "must be a list of option values")
                chosen = [_option_value(check, v, f"{where}.default") for v in default]
                if len({(type(v), v) for v in chosen}) != len(chosen):
                    check.fail(f"{where}.default", "lists a value twice")
                default = list(chosen)
            if values is not None:
                for value in chosen:
                    if (type(value), value) not in values:
                        check.fail(f"{where}.default", f"{value!r} is not among the options")
            out["default"] = default

    elif field_type == "integer":
        low = check.integer(raw["min"], f"{where}.min")
        high = check.integer(raw["max"], f"{where}.max")
        if low > high:
            check.fail(where, f"min {low} is above max {high}")
        out["min"], out["max"] = low, high
        if "default" in raw:
            out["default"] = check.integer(raw["default"], f"{where}.default", low, high)

    elif field_type == "text":
        out["max_length"] = check.integer(
            raw["max_length"], f"{where}.max_length", 1, TEXT_MAX_LENGTH
        )
        compiled = None
        if "pattern" in raw:
            pattern = raw["pattern"]
            if not isinstance(pattern, str) or not 1 <= len(pattern) <= 200:
                check.fail(f"{where}.pattern", "must be a string of 1..200 characters")
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                check.fail(f"{where}.pattern", f"does not compile: {exc}")
            out["pattern"] = pattern
        if "default" in raw:
            default = raw["default"]
            if not isinstance(default, str) or len(default) > out["max_length"]:
                check.fail(f"{where}.default", f"must be a text of at most {out['max_length']}")
            if compiled is not None and not compiled.fullmatch(default):
                check.fail(f"{where}.default", "does not match the pattern")
            out["default"] = default

    elif field_type == "time_range":
        if "default" in raw:
            default = raw["default"]
            check.mapping(default, f"{where}.default", ("start", "end"), ("start", "end"))
            out["default"] = {
                part: check.string(default[part], f"{where}.default.{part}", _CLOCK_RE, "HH:MM")
                for part in ("start", "end")
            }

    elif field_type == "date":
        if "max_days" in raw:
            out["max_days"] = check.integer(raw["max_days"], f"{where}.max_days", 1, MAX_DAYS)

    return out


OptionValue = str | int | bool


def _option_value(check: _Checker, value, where: str) -> OptionValue:
    """A string of the option grammar, an integer JSON keeps exactly, or a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -_INT_LIMIT <= value <= _INT_LIMIT:
            check.fail(where, f"{value} is outside the integers JSON keeps exactly")
        return value
    return check.string(value, where, _OPTION_RE, "an option value")


def _fields(check: _Checker, raw, where: str, limit: int) -> list[dict]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= limit:
        check.fail(where, f"must be a list of 1..{limit} fields")
    fields = [_field(check, item, f"{where}[{i}]") for i, item in enumerate(raw)]
    keys = [f["key"] for f in fields]
    for key in keys:
        if keys.count(key) > 1:
            check.fail(where, f"key {key!r} is declared twice")
    return fields


def _group(check: _Checker, raw, where: str) -> dict:
    if not isinstance(raw, dict):
        check.fail(where, "must be a mapping")
    kind = raw.get("kind", "settings")
    common_keys = ("id", "kind", "title", "description", "data_class", "sensitive")
    if kind == "settings":
        check.mapping(
            raw, where, ("id", "title", "data_class", "settings"), common_keys + ("settings",)
        )
    elif kind == "collection":
        check.mapping(
            raw,
            where,
            ("id", "title", "data_class", "item", "operations"),
            common_keys + ("item", "operations"),
        )
    else:
        check.fail(f"{where}.kind", f"{kind!r} is neither settings nor collection")

    out: dict = {
        "id": check.string(raw["id"], f"{where}.id", _KEY_RE, "a group id ([a-z][a-z0-9_]*)"),
        "kind": kind,
        "title": check.text(raw["title"], f"{where}.title", TITLE_MAX),
    }
    if "description" in raw:
        out["description"] = check.text(raw["description"], f"{where}.description", HINT_MAX)
    if raw["data_class"] not in DATA_CLASSES:
        check.fail(f"{where}.data_class", f"{raw['data_class']!r} is not one of {DATA_CLASSES}")
    out["data_class"] = raw["data_class"]
    sensitive = raw.get("sensitive", False)
    if not isinstance(sensitive, bool):
        check.fail(f"{where}.sensitive", "must be true or false")
    out["sensitive"] = sensitive

    if kind == "settings":
        out["settings"] = _fields(check, raw["settings"], f"{where}.settings", MAX_SETTINGS)
    else:
        item = check.mapping(raw["item"], f"{where}.item", ("fields",), ("fields",))
        out["item"] = {
            "fields": _fields(check, item["fields"], f"{where}.item.fields", MAX_ITEM_FIELDS)
        }
        operations = raw["operations"]
        if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
            check.fail(f"{where}.operations", f"must be a list of 1..{MAX_OPERATIONS}")
        names = [
            check.string(o, f"{where}.operations", _OPERATION_RE, "an operation name")
            for o in operations
        ]
        if len(set(names)) != len(names):
            check.fail(f"{where}.operations", "lists an operation twice")
        out["operations"] = names
    return out


def validate_section(
    section,
    origin: str,
    *,
    addon_name: str | None = None,
    addon_clients: tuple[str, ...] | list[str] = (),
    module_audience: str | None = None,
) -> dict:
    """Check one `personal_settings` section and return its normalised copy.

    For an add-on pass `addon_name` and the client IDs it registers; for a core module the
    one audience the core gives it. The input is never changed."""
    check = _Checker(origin)
    section = copy.deepcopy(section)
    check.mapping(
        section,
        "",
        ("api", "module", "title", "endpoint", "data", "groups"),
        ("api", "module", "title", "endpoint", "data", "groups"),
    )
    if section["api"] != API_CURRENT or isinstance(section["api"], bool):
        check.fail(".api", f"{section['api']!r} is not a generation this core serves")
    module = check.string(section["module"], ".module", _MODULE_RE, "a module name")
    if addon_name is not None and module != addon_name:
        check.fail(".module", f"{module!r} must be the add-on's name {addon_name!r}")

    endpoint = check.mapping(
        section["endpoint"],
        ".endpoint",
        ("service", "port", "base_path", "audience"),
        ("service", "scheme", "port", "base_path", "audience"),
    )
    scheme = endpoint.get("scheme", "http")
    if scheme not in ("http", "https"):
        check.fail(".endpoint.scheme", f"{scheme!r} is neither http nor https")
    audience = check.string(endpoint["audience"], ".endpoint.audience", _AUDIENCE_RE, "a client ID")
    if module_audience is not None and audience != module_audience:
        check.fail(
            ".endpoint.audience", f"{audience!r} is not the module's audience {module_audience!r}"
        )
    if addon_name is not None and audience not in addon_clients:
        owned = ", ".join(addon_clients) or "none"
        check.fail(
            ".endpoint.audience",
            f"{audience!r} is not a Keycloak client of this add-on (its clients: {owned});"
            " an add-on without a client of its own cannot offer personal settings",
        )
    clean_endpoint = {
        "service": check.string(
            endpoint["service"], ".endpoint.service", _SERVICE_RE, "a service name"
        ),
        "scheme": scheme,
        "port": check.integer(endpoint["port"], ".endpoint.port", 1, 65535),
        "base_path": check.string(
            endpoint["base_path"], ".endpoint.base_path", _PATH_RE, "an absolute path"
        ),
        "audience": audience,
    }

    data = check.mapping(
        section["data"], ".data", ("summary", "export", "erasure"), ("summary", "export", "erasure")
    )
    if data["erasure"] not in ERASURE:
        check.fail(".data.erasure", f"{data['erasure']!r} is not one of {ERASURE}")
    clean_data = {
        "summary": check.string(data["summary"], ".data.summary", _PATH_RE, "an absolute path"),
        "export": check.string(data["export"], ".data.export", _PATH_RE, "an absolute path"),
        "erasure": data["erasure"],
    }

    groups = section["groups"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        check.fail(".groups", f"must be a list of 1..{MAX_GROUPS} groups")
    clean_groups = [_group(check, g, f".groups[{i}]") for i, g in enumerate(groups)]
    ids = [g["id"] for g in clean_groups]
    for group_id in ids:
        if ids.count(group_id) > 1:
            check.fail(".groups", f"group id {group_id!r} is declared twice")

    return {
        "api": section["api"],
        "module": module,
        "title": check.text(section["title"], ".title", TITLE_MAX),
        "endpoint": clean_endpoint,
        "data": clean_data,
        "groups": clean_groups,
    }


def _load_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PersonalSettingsError(f"{path} is not valid YAML: {exc}") from exc


def _addon_clients(addon_path: Path, manifest: dict) -> list[str]:
    """The client IDs that belong to an add-on: those it registers through its Keycloak
    fragments (Seam 2) and those its own realm setup creates (ADDON_REALM_CLIENTS)."""
    own = list(ADDON_REALM_CLIENTS.get(str(manifest.get("name", "")), ()))
    return own + _fragment_clients(addon_path, manifest)


def _fragment_clients(addon_path: Path, manifest: dict) -> list[str]:
    """The client IDs an add-on registers through its Keycloak fragments (Seam 2)."""
    files = (((manifest.get("integration") or {}).get("keycloak") or {}).get("clients")) or []
    clients = []
    for rel in files if isinstance(files, list) else []:
        path = (addon_path / str(rel)).resolve()
        if not path.is_relative_to(addon_path) or not path.is_file():
            continue
        try:
            client = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(client, dict) and isinstance(client.get("clientId"), str):
            clients.append(client["clientId"])
    return clients


def _generation_warning(section, origin: str) -> str | None:
    """A warning for a section of a generation this core does not serve, else None."""
    api = section.get("api") if isinstance(section, dict) else None
    if isinstance(api, int) and not isinstance(api, bool) and not API_MIN <= api <= API_CURRENT:
        return (
            f"{origin}: personal_settings api {api} is not served by this core"
            f" ({API_MIN}..{API_CURRENT}); the module is left out of the personal area"
        )
    return None


def collect(
    repo_root: Path, active_profiles: set[str], active_addons: list[dict]
) -> tuple[list[dict], list[str]]:
    """All valid declarations of the active profiles and add-ons, sorted by module, and
    the warnings for those left out."""
    modules: dict[str, dict] = {}
    warnings: list[str] = []

    def add(section, origin: str, **kwargs) -> None:
        if not isinstance(section, dict):
            raise PersonalSettingsError(
                f"{origin}: personal_settings must be a mapping, got {type(section).__name__}"
            )
        warning = _generation_warning(section, origin)
        if warning:
            warnings.append(warning)
            return
        clean = validate_section(section, origin, **kwargs)
        if clean["module"] in modules:
            raise PersonalSettingsError(
                f"module {clean['module']!r} is declared twice"
                f" ({modules[clean['module']]['declared_by']} and {origin})"
            )
        clean["declared_by"] = origin
        modules[clean["module"]] = clean

    for profile, (rel, audience) in MODULE_DECLARATIONS.items():
        path = repo_root / rel / MODULE_FILE
        if profile not in active_profiles or not path.is_file():
            continue
        data = _load_yaml(path)
        if not isinstance(data, dict) or "personal_settings" not in data:
            raise PersonalSettingsError(
                f"{path}: expected a mapping with a 'personal_settings' key"
            )
        add(data["personal_settings"], f"module:{profile}", module_audience=audience)

    for addon in active_addons:
        addon_path = deployment.resolve_addon_path(addon, repo_root)
        manifest, reason = deployment.load_addon_manifest(addon_path)
        if manifest is None:
            raise PersonalSettingsError(reason)
        if "personal_settings" not in manifest:
            continue
        name = str(manifest.get("name", addon_path.name))
        clients = _addon_clients(addon_path, manifest)
        # A client the realm setup of another add-on creates is not this add-on's, even
        # when it ships a fragment of that name.
        taken = {c for owner, cs in ADDON_REALM_CLIENTS.items() if owner != name for c in cs}
        add(
            manifest["personal_settings"],
            f"addon:{name}@{manifest.get('version', '?')}",
            addon_name=name,
            addon_clients=[c for c in clients if c not in taken],
        )

    return [modules[name] for name in sorted(modules)], warnings


def not_connected(active_profiles: set[str]) -> list[dict]:
    """The platform services with personal data and without a declaration, in a fixed
    order: always the chat, the model gateway and the identity provider, and the
    services of the active profiles."""
    return [
        {"id": entry_id, "title": dict(title), "hint": dict(hint)}
        for entry_id, profile, title, hint in NOT_CONNECTED
        if profile is None or profile in active_profiles
    ]


def render(
    config_dir: Path, repo_root: Path, active_profiles: set[str], active_addons: list[dict]
) -> list[str]:
    """Write personal-settings/registry.yaml and return the warnings.

    The caller runs this only while the profile `me` is on."""
    modules, warnings = collect(repo_root, active_profiles, active_addons)
    canonical = json.dumps(modules, sort_keys=True, ensure_ascii=False)
    registry = {
        "registry": REGISTRY_FORMAT,
        "api": {"min": API_MIN, "current": API_CURRENT},
        "digest": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "modules": modules,
        "not_connected": not_connected(active_profiles),
    }
    path = config_dir / REGISTRY_REL
    common.ensure_dir(path.parent)
    common.atomic_write(path, json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
    return warnings
