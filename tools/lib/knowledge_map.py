"""Renders the knowledge map from module and add-on declarations.

The map (ADR 0011/0012) tells the LLM layer WHERE knowledge lives: one entry
per source, contributed by the software that provides it — core modules
through a `knowledge.yaml` in their module directory, add-ons through the
`knowledge:` key of `papaia-app.yaml`. Because the declarations travel with
the software, the rendered map cannot disagree with what is installed.

Like the realm-secret baking this is a generated artifact with its own render
function, not a layered merge target: the output is computed from many inputs
plus stamped metadata (hash, generation time, TTL), which the 3-layer file
merge cannot express. Operator knowledge joins as the last layer through
`overlay/knowledge-map/overrides.yaml`, merged per source id — manual edits
augment generated entries, they never fork them.

Validation here is the intake control of the map: entries are model-facing
text, so free-text fields are scanned for instruction-injection patterns and
a hit refuses the render. Softer findings (two sources sharing a topic
without mutual delimitation) are returned as warnings.

Governance metadata (ADR 0014) comes from a separate operator file; only the
effective handling enums reach a manifest, the rest feeds policy findings in
lints.yaml. The map documents — it does not enforce.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import common, deployment

# Where the rendered map lands inside $PAPAIA_CONFIG_DIR.
MAP_DIR = "knowledge-map"
OVERRIDES_REL_PATH = "overlay/knowledge-map/overrides.yaml"
# Operator declarations: sources the operator adds in the same schema as an
# add-on's `knowledge:` key — own MCP servers, places without any connector
# (kind: reference), Agent2Agent agents. Overrides still cannot create entries;
# declarations can.
SOURCES_REL_PATH = "overlay/knowledge-map/sources.yaml"
# Operator governance metadata (ADR 0014): classification, personal data,
# model tiers, policy and accepted exceptions. Kept apart from overrides.yaml
# because it is not model-facing: only the effective `handling` enums reach a
# manifest, everything else feeds the governance findings in lints.yaml.
GOVERNANCE_REL_PATH = "overlay/knowledge-map/governance.yaml"
# The merged chat-client configuration the inventory reads. render_core
# renders the map AFTER the layered merge, so this file already holds every
# MCP server of the core, the active profiles, add-ons and the overlay.
LIBRECHAT_CONFIG_REL_PATH = "ai/librechat/librechat.yaml"
LIBRECHAT_ENV_REL_PATH = "ai/librechat/.env"
LINTS_FILE = "lints.yaml"

# The map's own server is not a knowledge source.
SELF_SERVER = "KnowledgeMap"

_VALID_KINDS = ("source", "reference", "mcp", "agent")
_VALID_VIAS = ("mcp", "rag", "a2a", "none")
# A render that would delete more than this share of a map with at least
# _MASS_PRUNE_MIN_ENTRIES entries keeps the old manifests instead: a broken
# input (an unreadable chat config, a failed add-on scan) must not make most
# of the map vanish silently. The next good render prunes as usual.
_MASS_PRUNE_SHARE = 0.5
_MASS_PRUNE_MIN_ENTRIES = 4

# A map a renderer has not touched for a week deserves distrust: consumers
# serve entries past valid_until as stale (marked, never dropped).
TTL_DAYS = 7

# Core modules that may declare knowledge sources, and the profile each one
# requires. The declaration file is `<path>/knowledge.yaml`.
MODULE_KNOWLEDGE: dict[str, str] = {"rag": "src/ai/rag"}

_VALID_ON_DENIED = ("hidden", "acknowledge")

# ---- governance vocabulary (ADR 0014) ----
# Ordered from least to most restrictive; the order is the comparison.
CLASSIFICATIONS = ("public", "internal", "confidential", "strictly_confidential")
# The handling label of an entry the operator has not classified.
UNCLASSIFIED = "unclassified"
PERSONAL_DATA = ("none", "ordinary", "special", "criminal", "unknown")
DATA_SUBJECTS = (
    "employees", "applicants", "customers", "suppliers", "patients", "minors", "other",
)
# Ordered from least to most exposed; a model not listed counts as the last.
MODEL_TIERS = ("local", "eu_hosted", "third_country_contracted", "third_country")
# Keys a declaration or override must not carry: the operator sets governance
# values in governance.yaml, the renderer writes `handling` itself. A
# declaration may only *propose* through `governance_proposal`.
_RESERVED_GOVERNANCE_KEYS = (
    "governance", "handling", "classification", "personal_data", "data_subjects",
)
_PROPOSAL_KEYS = ("classification", "personal_data", "data_subjects")
# Entry keys the governance checks read but no manifest carries: the add-on
# proposal and the inventory facts (free-chat selectability, shared
# credentials, an agent's model).
_INTERNAL_KEYS = ("governance_proposal", "chat_menu", "static_credentials", "model")

# A source id becomes the manifest file name, so its shape is a security
# boundary: dot-separated lowercase segments only. Anything else (slashes,
# leading dots, absolute paths) could escape the map directory on write.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*$")

# Model-facing text is an injection surface. These patterns cover the known
# attack shapes (hidden instruction blocks, instruction overrides, zero-width
# smuggling); a hit is an error, not a warning — an attacker-shaped entry must
# never reach a rendered map.
_INJECTION_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"<\s*/?\s*(important|system|instructions?)\s*>", re.IGNORECASE),
    re.compile(
        r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b"
        r".{0,40}\binstructions?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"\byou\s+must\s+(not\s+)?(tell|reveal|mention)\b", re.IGNORECASE),
    # Zero-width smuggling characters with no legitimate use in these fields:
    # ZWSP, word joiner, BOM. ZWNJ/ZWJ are deliberately NOT matched — they
    # are orthographically required in Persian/Indic text and part of every
    # composed emoji sequence.
    re.compile("[​⁠﻿]"),
    re.compile(r"<\|[a-z_]+\|>", re.IGNORECASE),
)


class KnowledgeMapError(Exception):
    """A declaration the map must not accept (duplicate id, injection, …)."""


def _load_yaml(path: Path) -> dict:
    """Load a declaration file, turning YAML errors into named map errors so
    the render pipeline reports them instead of crashing on a stack trace."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise KnowledgeMapError(f"{path} is not valid YAML: {exc}") from exc


def _string_fields(value, path: str = "") -> list[tuple[str, str]]:
    """Every string anywhere in the entry, with its field path.

    Deliberately exhaustive rather than an allowlist of known keys: the
    renderer passes unknown keys through to the manifest (forward
    compatibility) and the MCP server serves the full manifest to the model,
    so a field the scan does not know about would be an injection bypass."""
    if isinstance(value, str):
        return [(path or "<root>", value)]
    texts: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            # Keys are strings the model will read too (the server serves the
            # raw manifest), so they are scanned like any value.
            if isinstance(key, str):
                texts.append((key_path, key))
            texts.extend(_string_fields(item, key_path))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            texts.extend(_string_fields(item, path))
    return texts


def _validate_shape(value, origin: str, source_id: str, path: str = "") -> None:
    """Only plain YAML data may enter the map: string keys, scalar leaves,
    mappings and sequences. Anything else (a !!set node, a non-string key
    like an unquoted `on:` or a date key) would either dodge the injection
    scan or crash the content hashing with an unnamed TypeError."""
    where = f"{origin}: source {source_id!r}" + (f", field {path!r}" if path else "")
    if value is None or isinstance(value, (str, int, float, bool, date, datetime)):
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise KnowledgeMapError(
                    f"{where}: mapping key {key!r} is not a string — quote "
                    f"YAML keys that parse as booleans or dates"
                )
            _validate_shape(item, origin, source_id, f"{path}.{key}" if path else key)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_shape(item, origin, source_id, path)
        return
    raise KnowledgeMapError(
        f"{where}: unsupported value type {type(value).__name__} — only "
        f"plain scalars, mappings and sequences may enter the map"
    )


def _scan_for_injection(entry: dict, origin: str) -> None:
    for field, text in _string_fields(entry):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                raise KnowledgeMapError(
                    f"{origin}: field {field!r} of source "
                    f"{entry.get('id', '?')!r} matches an instruction-injection "
                    f"pattern; refusing to render it into the map"
                )


def _validate_entry(entry: dict, origin: str) -> None:
    source_id = str(entry.get("id", "")).strip()
    if not source_id:
        raise KnowledgeMapError(f"{origin}: knowledge source without an id")
    if not _ID_RE.fullmatch(source_id):
        raise KnowledgeMapError(
            f"{origin}: knowledge source id {source_id!r} is not a valid id "
            f"(dot-separated lowercase segments of [a-z0-9_-]) — the id names "
            f"the manifest file, so nothing path-shaped is accepted"
        )
    on_denied = entry.get("on_denied", "hidden")
    if on_denied not in _VALID_ON_DENIED:
        raise KnowledgeMapError(
            f"{origin}: source {source_id!r} has unknown on_denied value "
            f"{on_denied!r} (expected one of {_VALID_ON_DENIED})"
        )
    _validate_shape(entry, origin, source_id)
    _validate_kind_and_access(entry, origin, source_id)
    _validate_governance_proposal(entry, origin, source_id)
    _scan_for_injection(entry, origin)


def _validate_governance_proposal(entry: dict, origin: str, source_id: str) -> None:
    """Declarations may suggest a classification, never set one: the operator
    decides in governance.yaml, and a proposal alone is never effective."""
    for key in _RESERVED_GOVERNANCE_KEYS:
        if key in entry:
            raise KnowledgeMapError(
                f"{origin}: source {source_id!r} sets {key!r} — governance fields "
                f"live in {GOVERNANCE_REL_PATH}; a declaration may only suggest "
                f"values through 'governance_proposal'"
            )
    proposal = entry.get("governance_proposal")
    if proposal is None:
        return
    where = f"{origin}: source {source_id!r}: governance_proposal"
    if not isinstance(proposal, dict):
        raise KnowledgeMapError(f"{where} must be a mapping")
    unknown = sorted(set(proposal) - set(_PROPOSAL_KEYS))
    if unknown:
        raise KnowledgeMapError(
            f"{where} has unknown key(s) {unknown} (expected {list(_PROPOSAL_KEYS)})"
        )
    _check_enum(proposal.get("classification"), CLASSIFICATIONS, f"{where}.classification")
    _check_enum(proposal.get("personal_data"), PERSONAL_DATA, f"{where}.personal_data")
    _check_enum_list(proposal.get("data_subjects"), DATA_SUBJECTS, f"{where}.data_subjects")


def _check_enum(value, allowed: tuple, where: str) -> None:
    if value is not None and value not in allowed:
        raise KnowledgeMapError(
            f"{where}: unknown value {value!r} (expected one of {list(allowed)})"
        )


def _check_enum_list(value, allowed: tuple, where: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise KnowledgeMapError(f"{where} must be a list")
    for item in value:
        _check_enum(item, allowed, where)


def _validate_kind_and_access(entry: dict, origin: str, source_id: str) -> None:
    kind = entry.get("kind", "source")
    if kind not in _VALID_KINDS:
        raise KnowledgeMapError(
            f"{origin}: source {source_id!r} has unknown kind {kind!r} "
            f"(expected one of {_VALID_KINDS})"
        )
    access = entry.get("access")
    if isinstance(access, list):
        for path in access:
            if not isinstance(path, dict):
                raise KnowledgeMapError(
                    f"{origin}: source {source_id!r}: every access path must be a mapping"
                )
            via = path.get("via", "mcp")
            if via not in _VALID_VIAS:
                raise KnowledgeMapError(
                    f"{origin}: source {source_id!r} has an access path of unknown "
                    f"type {via!r} (expected one of {_VALID_VIAS})"
                )
            if via in ("mcp", "rag", "a2a") and not path.get("target"):
                raise KnowledgeMapError(
                    f"{origin}: source {source_id!r}: a {via} access path needs a target"
                )
    elif access is not None and not isinstance(access, dict):
        raise KnowledgeMapError(
            f"{origin}: source {source_id!r}: access must be a list of paths"
        )
    paths = access if isinstance(access, list) else []
    if kind == "reference" and not (
        entry.get("location") or any(p.get("location") for p in paths)
    ):
        raise KnowledgeMapError(
            f"{origin}: reference {source_id!r} needs a location — a reference "
            f"exists to tell people where to look"
        )


def _topic_ids(entry: dict) -> set[str]:
    ids: set[str] = set()
    for topic in entry.get("topics") or []:
        if isinstance(topic, dict) and topic.get("id"):
            ids.add(str(topic["id"]))
        elif isinstance(topic, str):
            ids.add(topic)
    return ids


def _redirects_to(entry: dict, other_id: str) -> bool:
    """Does `entry` carry a not_covered redirect pointing at `other_id`?"""
    return any(
        isinstance(item, dict) and item.get("instead") == other_id
        for item in entry.get("not_covered") or []
    )


def _sot_claims(entry: dict, shared: set[str]) -> set[str]:
    return shared & set(entry.get("source_of_truth_for") or [])


def _routable(entry: dict) -> bool:
    return entry.get("kind", "source") in ("source", "reference")


def _collision_warnings(entries: dict[str, dict]) -> list[str]:
    warnings: list[str] = []
    ids = sorted(i for i in entries if _routable(entries[i]))
    for i, a_id in enumerate(ids):
        for b_id in ids[i + 1 :]:
            a, b = entries[a_id], entries[b_id]
            shared = _topic_ids(a) & _topic_ids(b)
            if not shared:
                continue
            if _redirects_to(a, b_id) or _redirects_to(b, a_id):
                continue
            # source_of_truth_for only delimits when exactly ONE side claims
            # shared topics — mirroring the runtime tiebreak, which compares
            # any()-ownership over all shared topics per pair: both claiming
            # (even disjoint splits) leaves the tiebreak undecided, so it
            # must warn.
            a_sot, b_sot = _sot_claims(a, shared), _sot_claims(b, shared)
            if bool(a_sot) != bool(b_sot):
                continue
            warnings.append(
                f"knowledge map: {a_id} and {b_id} share topic(s) "
                f"{sorted(shared)} without a not_covered/source_of_truth_for "
                f"delimitation — routing between them will be guesswork"
            )
    return warnings


def _content_hash(entry: dict) -> str:
    """Hash over the declaration itself (ADR 0012) — provenance is metadata
    about where it came from, so e.g. an add-on version bump alone must not
    churn every consumer's centroid cache."""
    declaration = {
        k: v for k, v in entry.items() if k != "provenance" and k not in _INTERNAL_KEYS
    }
    canonical = json.dumps(declaration, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _merge_override(entry: dict, override: dict) -> dict:
    """Merge one operator override onto a declared entry.

    Mappings merge key-wise; scalars and LISTS are replaced wholesale. List
    replacement is deliberate — it lets an operator remove a wrong declared
    item, which appending never could — but it means an override of e.g.
    `not_covered` must repeat the declared items it wants to keep. The docs
    state this next to the example."""
    merged = dict(entry)
    for key, value in override.items():
        if isinstance(merged.get(key), dict) and isinstance(value, dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def collect_sources(
    repo_root: Path,
    config_dir: Path,
    active_profiles: set[str],
    active_addons: list[dict],
) -> tuple[dict[str, dict], list[str]]:
    """All declared sources by id, plus soft warnings.

    Precedence per source id: module/add-on declaration, then the operator
    override. Two declarations claiming the same id are an error — identity
    must stay unambiguous, silence would hide a squatting attempt."""
    entries: dict[str, dict] = {}
    origins: dict[str, str] = {}

    def _add(sources: list, origin: str) -> None:
        for raw in sources or []:
            if not isinstance(raw, dict):
                raise KnowledgeMapError(f"{origin}: knowledge source must be a mapping")
            entry = dict(raw)
            _validate_entry(entry, origin)
            source_id = str(entry["id"])
            if source_id in entries:
                raise KnowledgeMapError(
                    f"duplicate knowledge source id {source_id!r} "
                    f"({origins[source_id]} vs {origin})"
                )
            entry["provenance"] = {"declared_by": origin}
            entries[source_id] = entry
            origins[source_id] = origin

    for profile, module_path in MODULE_KNOWLEDGE.items():
        if profile not in active_profiles:
            continue
        knowledge_path = repo_root / module_path / "knowledge.yaml"
        if not knowledge_path.is_file():
            continue
        data = _load_yaml(knowledge_path)
        if not isinstance(data, dict):
            raise KnowledgeMapError(
                f"{knowledge_path}: expected a mapping with a 'sources' key, "
                f"got {type(data).__name__}"
            )
        _add(data.get("sources") or [], f"module:{profile}")

    for addon in active_addons:
        # Resolved exactly as every other reader of the add-on layer resolves
        # it; a malformed manifest becomes a named error, not a stack trace.
        addon_path = deployment.resolve_addon_path(addon, repo_root)
        if not (addon_path / "papaia-app.yaml").is_file():
            continue
        manifest, reason = deployment.load_addon_manifest(addon_path)
        if manifest is None:
            raise KnowledgeMapError(reason)
        knowledge = manifest.get("knowledge") or {}
        if not isinstance(knowledge, dict):
            raise KnowledgeMapError(
                f"{addon_path / 'papaia-app.yaml'}: 'knowledge' must be a "
                f"mapping with a 'sources' key, got {type(knowledge).__name__}"
            )
        _add(
            knowledge.get("sources") or [],
            f"addon:{manifest.get('name', addon_path.name)}"
            f"@{manifest.get('version', '?')}",
        )

    operator_path = config_dir / SOURCES_REL_PATH
    if operator_path.is_file():
        data = _load_yaml(operator_path)
        if not isinstance(data, dict) or not isinstance(data.get("sources") or [], list):
            raise KnowledgeMapError(
                f"{SOURCES_REL_PATH}: expected a mapping with a 'sources' list"
            )
        _add(data.get("sources") or [], "operator")

    inventory_warnings = _add_inventory(config_dir, entries)

    override_warnings: list[str] = list(inventory_warnings)
    overrides_path = config_dir / OVERRIDES_REL_PATH
    if overrides_path.is_file():
        overrides = _load_yaml(overrides_path)
        if not isinstance(overrides, dict) or not isinstance(
            overrides.get("sources") or {}, dict
        ):
            raise KnowledgeMapError(
                f"{OVERRIDES_REL_PATH}: expected a mapping of the form "
                f"'sources: {{<id>: {{<field>: <value>}}}}'"
            )
        if "governance" in overrides:
            raise KnowledgeMapError(
                f"{OVERRIDES_REL_PATH}: governance fields live in "
                f"{GOVERNANCE_REL_PATH}, not in the overrides"
            )
        for source_id, override in (overrides.get("sources") or {}).items():
            if source_id not in entries:
                # A warning, not an error: a typo or a left-behind override
                # for a removed add-on must not block rendering the entire
                # installation. Overrides still cannot introduce sources —
                # the entry simply does not exist.
                override_warnings.append(
                    f"{OVERRIDES_REL_PATH}: override for unknown source "
                    f"{source_id!r} ignored — overrides augment declared "
                    f"entries, they cannot introduce sources (stale after an "
                    f"add-on removal? remove the override)"
                )
                continue
            if not isinstance(override, dict):
                raise KnowledgeMapError(
                    f"{OVERRIDES_REL_PATH}: override for {source_id!r} must be a mapping"
                )
            if "governance_proposal" in override:
                raise KnowledgeMapError(
                    f"{OVERRIDES_REL_PATH}: override for {source_id!r} sets "
                    f"'governance_proposal' — proposals come from the declaration; "
                    f"the operator's values live in {GOVERNANCE_REL_PATH}"
                )
            if "id" in override and str(override["id"]) != source_id:
                # The id is the entry's identity AND its manifest file name;
                # rewriting it would bypass the duplicate-id check here and
                # explode as a duplicate at serve time instead.
                raise KnowledgeMapError(
                    f"{OVERRIDES_REL_PATH}: override for {source_id!r} must "
                    f"not change the id (found {override['id']!r})"
                )
            merged = _merge_override(entries[source_id], override)
            _validate_entry(merged, f"{OVERRIDES_REL_PATH}:{source_id}")
            merged.setdefault("provenance", {})["overridden"] = True
            entries[source_id] = merged

    return entries, override_warnings + _collision_warnings(entries)



def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")
    return slug or "unnamed"


def _declared_targets(entries: dict[str, dict]) -> set[str]:
    """MCP server names some declared entry reaches — over an mcp or rag
    path, or the v0.1 single-path fields."""
    targets: set[str] = set()
    for entry in entries.values():
        access = entry.get("access")
        if isinstance(access, list):
            targets.update(
                str(p["target"]) for p in access
                if isinstance(p, dict) and p.get("via", "mcp") in ("mcp", "rag") and p.get("target")
            )
        elif isinstance(access, dict) and access.get("mcp_server"):
            targets.add(str(access["mcp_server"]))
        if entry.get("mcp_server"):
            targets.add(str(entry["mcp_server"]))
    return targets


def librechat_servers(config_dir: Path) -> dict[str, dict] | None:
    """MCP servers of the merged chat-client configuration; None when the
    file cannot be read (then nothing is inventoried and no path is judged
    dead — an unreadable input must not look like an empty installation)."""
    path = config_dir / LIBRECHAT_CONFIG_REL_PATH
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return {}
    return {str(k): v if isinstance(v, dict) else {} for k, v in servers.items()}


def _agents_dir(config_dir: Path) -> Path | None:
    env = common.parse_env_file(config_dir / LIBRECHAT_ENV_REL_PATH)
    raw = (env.get("LIBRECHAT_AGENTS_DIR") or "").strip()
    if not raw:
        return None
    path = Path(raw)
    # Relative paths resolve like the compose bind mount does: against the
    # module directory that holds the compose file.
    return path if path.is_absolute() else config_dir / "ai/librechat" / path


def _inventory_entry(entry: dict, entries: dict[str, dict], origin: str) -> str | None:
    """Add one inventoried entry; returns a warning instead of raising — an
    odd description in someone's chat config must not block the render."""
    source_id = entry["id"]
    if source_id in entries:
        return (
            f"knowledge map: inventory entry {source_id!r} collides with a "
            f"declared id; the declaration wins"
        )
    try:
        _validate_entry(entry, origin)
    except KnowledgeMapError as exc:
        # Keep the entry without its free text: knowing that the server
        # exists is what prevents a wrong abstention.
        stripped = {k: v for k, v in entry.items() if k not in ("coverage",)}
        try:
            _validate_entry(stripped, origin)
        except KnowledgeMapError:
            return f"knowledge map: inventory entry {source_id!r} skipped: {exc}"
        entry = stripped
    entry["provenance"] = {"declared_by": origin}
    entries[source_id] = entry
    return None


_CREDENTIAL_HEADER_RE = re.compile(r"authorization|api[-_]?key|token", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


def _is_static_value(value, user_vars: set[str]) -> bool:
    """A credential value shared by every user of the server: not empty and
    not resolved per user (a `{{LIBRECHAT_...}}` placeholder, or a
    `{{VAR}}` the server declares under customUserVars)."""
    text = str(value or "").strip()
    if not text or "{{LIBRECHAT_" in text:
        return False
    return not any(name in user_vars for name in _PLACEHOLDER_RE.findall(text))


def _has_static_credentials(cfg: dict) -> bool:
    """Does the server authenticate with a credential that is the same for
    every caller? Then the target system no longer sees who asks."""
    user_vars = cfg.get("customUserVars")
    user_vars = set(user_vars) if isinstance(user_vars, dict) else set()
    headers = cfg.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if _CREDENTIAL_HEADER_RE.search(str(key)) and _is_static_value(value, user_vars):
                return True
    api_key = cfg.get("apiKey")
    if isinstance(api_key, dict):
        # LibreChat: source "user" means every user enters an own key.
        if api_key.get("source", "admin") != "user" and _is_static_value(
            api_key.get("key"), user_vars
        ):
            return True
    elif isinstance(api_key, str) and _is_static_value(api_key, user_vars):
        return True
    return False


def _add_inventory(config_dir: Path, entries: dict[str, dict]) -> list[str]:
    """Every connected MCP server and every provisioned chat agent becomes an
    entry, so the map knows everything a caller could reach — otherwise its
    'not available' would be a lie whenever an undeclared server exists."""
    warnings: list[str] = []
    servers = librechat_servers(config_dir)
    declared = _declared_targets(entries)
    for name, cfg in sorted((servers or {}).items()):
        if name == SELF_SERVER:
            continue
        description = " ".join(str(cfg.get("description") or "").split())
        entry = {
            "id": f"mcp.{_slug(name)}",
            "kind": "mcp",
            "system": str(cfg.get("title") or name),
            "coverage": description[:500],
            "undeclared": name not in declared,
            "access": [{"via": "mcp", "target": name}],
            # Selectable in free chat with any model unless chatMenu: false.
            "chat_menu": cfg.get("chatMenu", True) is not False,
            # Only whether a shared credential is configured — never its value.
            "static_credentials": _has_static_credentials(cfg),
        }
        warning = _inventory_entry(entry, entries, "inventory:librechat")
        if warning:
            warnings.append(warning)

    agents_dir = _agents_dir(config_dir)
    if agents_dir is not None and agents_dir.is_dir():
        for path in sorted(agents_dir.glob("*.y*ml")):
            try:
                data = _load_yaml(path)
            except KnowledgeMapError as exc:
                warnings.append(f"knowledge map: agent file skipped: {exc}")
                continue
            if not isinstance(data, dict) or not data.get("id"):
                continue
            uses = [str(m) for m in data.get("mcpServers") or [] if str(m) != SELF_SERVER]
            entry = {
                "id": f"agent.{_slug(str(data['id']))}",
                "kind": "agent",
                "system": str(data.get("name") or data["id"]),
                "coverage": " ".join(str(data.get("description") or "").split())[:500],
                "uses": uses,
                "access": [],
            }
            if data.get("model"):
                entry["model"] = {
                    "provider": str(data.get("provider") or "") or None,
                    "name": str(data["model"]),
                }
            warning = _inventory_entry(entry, entries, "inventory:librechat-agents")
            if warning:
                warnings.append(warning)
    return warnings


def lint(entries: dict[str, dict], servers: dict[str, dict] | None) -> list[dict]:
    """Findings that weaken the map, for the management view. Severity is
    about the effect on answers: `high` can produce a wrong answer."""
    findings: list[dict] = []

    def add(severity: str, code: str, target: str | None, message: str) -> None:
        findings.append(_finding(severity, code, target, message, "quality"))

    ids = set(entries)
    for source_id in sorted(entries):
        entry = entries[source_id]
        kind = entry.get("kind", "source")
        if kind == "mcp" and entry.get("undeclared"):
            add("high", "undeclared_server", source_id,
                f"{entry.get('system')} is connected but describes no knowledge; "
                f"abstentions may be wrong")
        if kind in ("source", "reference"):
            if not entry.get("not_covered") and kind == "source":
                add("medium", "missing_negative_knowledge", source_id,
                    f"{entry.get('system')} declares nothing it does NOT cover")
            if not entry.get("example_queries"):
                add("low", "missing_examples", source_id,
                    f"{entry.get('system')} has no example questions")
        for item in entry.get("not_covered") or []:
            target = item.get("instead") if isinstance(item, dict) else None
            if target and target not in ids:
                add("medium", "dangling_reference", source_id,
                    f"{source_id} redirects to unknown entry {target!r}")
        for dep in entry.get("depends_on") or []:
            if dep not in ids:
                add("medium", "dangling_reference", source_id,
                    f"{source_id} depends on unknown entry {dep!r}")
        access = entry.get("access")
        if servers and isinstance(access, list) and kind != "mcp":
            for path in access:
                if (
                    isinstance(path, dict)
                    and path.get("via", "mcp") in ("mcp", "rag")
                    and path.get("target") not in servers
                ):
                    add("high", "dead_access_path", source_id,
                        f"{source_id} points at MCP server {path.get('target')!r}, "
                        f"which is not connected")
    for warning in _collision_warnings(entries):
        add("medium", "shared_topic_undelimited", None, warning.removeprefix("knowledge map: "))
    return findings


def _finding(
    severity: str,
    code: str,
    target: str | None,
    message: str,
    category: str,
    fix: str | None = None,
) -> dict:
    """One lints.yaml finding. `origin` tells the management view which
    component produced it (the manager adds its own live checks); governance
    findings carry a concrete `fix` — the map never changes anything itself."""
    finding = {
        "severity": severity,
        "code": code,
        "target": target,
        "message": message,
        "origin": "render",
        "category": category,
    }
    if fix is not None:
        finding["fix"] = fix
    return finding


# ---- governance metadata and policy findings (ADR 0014) ----
#
# The map documents; it does not enforce. Data access is enforced by the
# target systems (with the user's token), model use by LiteLLM teams/keys and
# the agents' model bindings. These findings name where the wiring and the
# operator's declared handling disagree, each with a concrete fix.

GOVERNANCE_FINDINGS = (
    "classification_open",
    "classification_downgraded",
    "personal_data_unknown",
    "personal_data_without_ropa",
    "open_confidential",
    "special_data_broad_access",
    "rag_copy_sensitive",
    "embedding_model_policy",
    "agent_model_policy",
    "unclassified_model_in_use",
    "confidential_in_free_chat",
    "mcp_static_credentials",
)
# Live checks of the management interface against the model gateway; an
# exception in governance.yaml may name them too.
MANAGER_FINDINGS = ("model_tier_contradiction", "unclassified_model")
# The bundled classification reminder has no single subject to accept.
_EXCEPTABLE_FINDINGS = tuple(
    code for code in GOVERNANCE_FINDINGS + MANAGER_FINDINGS if code != "classification_open"
)

DEFAULT_GOVERNANCE_POLICY: dict = {
    "allowed_tiers": {
        "public": ["local", "eu_hosted", "third_country_contracted", "third_country"],
        "internal": ["local", "eu_hosted", "third_country_contracted"],
        "confidential": ["local", "eu_hosted"],
        "strictly_confidential": ["local"],
    },
    "personal_data_tiers": {"special": ["local"], "criminal": ["local"]},
    "broad_roles": ["user"],
    "embedding_model": "nomic-embed-text",
}

_SENSITIVE_PERSONAL_DATA = ("special", "criminal")
_RECORDED_PERSONAL_DATA = ("ordinary", "special", "criminal")

# field -> checker kind; see _check_field.
_SOURCE_FIELDS = {
    "owner": "str",
    "classification": ("enum", CLASSIFICATIONS),
    "personal_data": ("enum", PERSONAL_DATA),
    "data_subjects": ("enum_list", DATA_SUBJECTS),
    "ropa_ref": "str",
}
_MODEL_FIELDS = {"tier": ("enum", MODEL_TIERS), "role": "str"}
_EXCEPTION_FIELDS = {
    "finding": ("enum", _EXCEPTABLE_FINDINGS),
    "subject": "str",
    "expires": "date",
    "reason": "str",
    "risk_ref": "str",
}
_EXCEPTION_REQUIRED = ("finding", "subject", "expires")
_POLICY_KEYS = tuple(DEFAULT_GOVERNANCE_POLICY)
_GOVERNANCE_TOP_KEYS = ("sources", "models", "policy", "exceptions")


def _gov_error(where: str, message: str) -> KnowledgeMapError:
    return KnowledgeMapError(f"{GOVERNANCE_REL_PATH}: {where}: {message}")


def _as_date(value, where: str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise _gov_error(where, f"{value!r} is not a date (YYYY-MM-DD)") from None


def _check_field(value, kind, where: str):
    """Validate one governance value and return its normalised form; a null
    value means 'not set' and is returned as None."""
    if value is None:
        return None
    if kind == "str":
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise _gov_error(where, "must be a string")
        return str(value)
    if kind == "date":
        return _as_date(value, where)
    if kind == "list_str":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise _gov_error(where, "must be a list of strings")
        return list(value)
    if kind[0] == "enum":
        if value not in kind[1]:
            raise _gov_error(where, f"unknown value {value!r} (expected one of {list(kind[1])})")
        return value
    # enum_list
    if not isinstance(value, list):
        raise _gov_error(where, "must be a list")
    for item in value:
        if item not in kind[1]:
            raise _gov_error(where, f"unknown value {item!r} (expected one of {list(kind[1])})")
    return list(value)


def _check_record(record, fields: dict, where: str, unknown: list[str]) -> dict:
    if not isinstance(record, dict):
        raise _gov_error(where, "must be a mapping")
    result = {}
    for key, value in record.items():
        if key not in fields:
            unknown.append(f"{where}.{key}")
            continue
        result[key] = _check_field(value, fields[key], f"{where}.{key}")
    return result


def load_governance(config_dir: Path) -> dict:
    """The operator's governance.yaml, validated and with the policy defaults
    filled in. Shape errors are render errors; unknown keys are collected in
    `unknown_keys` and reported as low findings (forward compatibility)."""
    path = config_dir / GOVERNANCE_REL_PATH
    data = _load_yaml(path) if path.is_file() else {}
    if not isinstance(data, dict):
        raise _gov_error("<root>", f"expected a mapping, got {type(data).__name__}")
    unknown: list[str] = [key for key in data if key not in _GOVERNANCE_TOP_KEYS]

    sources_raw = data.get("sources") or {}
    if not isinstance(sources_raw, dict):
        raise _gov_error("sources", "must be a mapping keyed by entry id")
    sources = {
        str(key): _check_record(value or {}, _SOURCE_FIELDS, f"sources.{key}", unknown)
        for key, value in sources_raw.items()
    }

    models_raw = data.get("models") or {}
    if not isinstance(models_raw, dict):
        raise _gov_error("models", "must be a mapping keyed by model name")
    models = {}
    for name, value in models_raw.items():
        record = _check_record(value or {}, _MODEL_FIELDS, f"models.{name}", unknown)
        if not record.get("tier"):
            raise _gov_error(f"models.{name}", f"needs a tier (one of {list(MODEL_TIERS)})")
        models[str(name)] = record

    policy = _load_policy(data.get("policy"), unknown)

    exceptions_raw = data.get("exceptions") or []
    if not isinstance(exceptions_raw, list):
        raise _gov_error("exceptions", "must be a list")
    exceptions = []
    for index, value in enumerate(exceptions_raw):
        where = f"exceptions[{index}]"
        record = _check_record(value, _EXCEPTION_FIELDS, where, unknown)
        missing = [key for key in _EXCEPTION_REQUIRED if not record.get(key)]
        if missing:
            # Accepted risk is always time-boxed and always about one thing.
            raise _gov_error(where, f"missing {missing} — every exception names "
                             f"the finding, its subject and an expiry date")
        exceptions.append(record)

    return {
        "sources": sources,
        "models": models,
        "policy": policy,
        "exceptions": exceptions,
        "unknown_keys": unknown,
    }


def _load_policy(raw, unknown: list[str]) -> dict:
    policy = json.loads(json.dumps(DEFAULT_GOVERNANCE_POLICY))
    if raw is None:
        return policy
    if not isinstance(raw, dict):
        raise _gov_error("policy", "must be a mapping")
    for key, value in raw.items():
        where = f"policy.{key}"
        if key not in _POLICY_KEYS:
            unknown.append(where)
            continue
        if key in ("allowed_tiers", "personal_data_tiers"):
            allowed_keys = CLASSIFICATIONS if key == "allowed_tiers" else PERSONAL_DATA
            if not isinstance(value, dict):
                raise _gov_error(where, "must be a mapping")
            for sub, tiers in value.items():
                if sub not in allowed_keys:
                    raise _gov_error(
                        f"{where}.{sub}", f"unknown key (expected one of {list(allowed_keys)})"
                    )
                policy[key][sub] = _check_field(
                    tiers, ("enum_list", MODEL_TIERS), f"{where}.{sub}"
                ) or []
        elif key == "broad_roles":
            policy[key] = _check_field(value, "list_str", where) or []
        else:  # embedding_model
            policy[key] = _check_field(value, "str", where)
    return policy


def effective_handling(entry_id: str, governance: dict) -> dict:
    """What a manifest may say about an entry: enum values only, and only
    what the operator confirmed."""
    record = governance["sources"].get(entry_id) or {}
    return {
        "classification": record.get("classification") or UNCLASSIFIED,
        "personal_data": record.get("personal_data") or "unknown",
    }


def _rank(classification: str) -> int:
    return CLASSIFICATIONS.index(classification)


def _entry_paths(entry: dict) -> list[dict]:
    """The entry's access paths, the v0.1 single-path fields included."""
    access = entry.get("access")
    paths = [p for p in access if isinstance(p, dict)] if isinstance(access, list) else []
    if isinstance(access, dict) and access.get("mcp_server"):
        paths.append({"via": "mcp", "target": access["mcp_server"]})
    if entry.get("mcp_server"):
        paths.append({"via": "mcp", "target": entry["mcp_server"]})
    return paths


def _has_rag_path(entry: dict) -> bool:
    return any(p.get("via") == "rag" for p in _entry_paths(entry))


def _model_name(entry: dict) -> str | None:
    model = entry.get("model")
    if isinstance(model, dict):
        model = model.get("name")
    return str(model) if model else None


class _GovernanceView:
    """Effective governance values per entry, as the findings evaluate them."""

    def __init__(self, entries: dict[str, dict], governance: dict):
        self.entries = entries
        self.gov = governance
        self.policy = governance["policy"]
        self.broad = set(self.policy["broad_roles"])
        self.reach = self._reached_by_server()

    def record(self, entry_id: str) -> dict:
        return self.gov["sources"].get(entry_id) or {}

    def proposal(self, entry_id: str) -> dict:
        proposal = self.entries[entry_id].get("governance_proposal")
        return proposal if isinstance(proposal, dict) else {}

    def classification(self, entry_id: str) -> str:
        """The class the checks use. The operator's value wins; an
        unconfirmed proposal counts but never below internal, so an add-on
        cannot declare itself public; nothing at all counts as confidential."""
        operator = self.record(entry_id).get("classification")
        if operator:
            return operator
        proposed = self.proposal(entry_id).get("classification")
        if proposed:
            return CLASSIFICATIONS[max(_rank(proposed), _rank("internal"))]
        return "confidential"

    def personal_data(self, entry_id: str) -> str:
        return self.record(entry_id).get("personal_data") or "unknown"

    def open_roles(self, roles) -> bool:
        """Practically everyone can see it: no roles, or a broad role."""
        roles = [str(r) for r in roles or []]
        return not roles or any(r in self.broad for r in roles)

    def tier(self, model: str) -> str:
        # Fail-closed: a model nobody classified counts as the most exposed.
        return (self.gov["models"].get(model) or {}).get("tier") or MODEL_TIERS[-1]

    def allowed_tiers(self, classification: str, personal_data: str) -> list[str]:
        allowed = self.policy["allowed_tiers"].get(classification, [])
        pd_tiers = self.policy["personal_data_tiers"].get(personal_data)
        return [t for t in allowed if pd_tiers is None or t in pd_tiers]

    def sensitive(self, entry_id: str) -> bool:
        return (
            _rank(self.classification(entry_id)) >= _rank("confidential")
            or self.personal_data(entry_id) in _SENSITIVE_PERSONAL_DATA
        )

    def _reached_by_server(self) -> dict[str, list[str]]:
        """MCP server name -> ids of the entries reachable over it.
        Inventoried server entries count only when the operator classified
        them; otherwise the declared sources behind the server speak."""
        reach: dict[str, set[str]] = {}
        for entry_id, entry in self.entries.items():
            kind = entry.get("kind", "source")
            if kind == "agent" or (kind == "mcp" and entry_id not in self.gov["sources"]):
                continue
            for path in _entry_paths(entry):
                if path.get("via", "mcp") in ("mcp", "rag") and path.get("target"):
                    reach.setdefault(str(path["target"]), set()).add(entry_id)
        return {server: sorted(ids) for server, ids in reach.items()}


def governance_lint(
    entries: dict[str, dict], governance: dict, today: date
) -> list[dict]:
    """Governance findings for lints.yaml, exceptions applied."""
    view = _GovernanceView(entries, governance)
    findings: list[dict] = []

    def add(severity: str, code: str, target: str | None, message: str, fix: str) -> None:
        findings.append(_finding(severity, code, target, message, "governance", fix))

    for key in governance["unknown_keys"]:
        add("low", "governance_unknown_key", key,
            f"{GOVERNANCE_REL_PATH}: unknown key {key!r} ignored",
            f"remove {key!r} from {GOVERNANCE_REL_PATH}")
    for entry_id in sorted(set(governance["sources"]) - set(entries)):
        add("low", "governance_unknown_entry", entry_id,
            f"{GOVERNANCE_REL_PATH} describes {entry_id!r}, which is not on the map",
            f"remove sources.{entry_id} from {GOVERNANCE_REL_PATH} or fix the id")

    _classification_findings(view, findings, add)
    for entry_id in sorted(entries):
        _entry_findings(view, entry_id, add)
    _rag_findings(view, add)
    _server_findings(view, add)
    _agent_findings(view, add)
    return _apply_exceptions(findings, governance["exceptions"], today)


def _classification_findings(view: _GovernanceView, findings: list[dict], add) -> None:
    open_ids = [
        entry_id for entry_id in sorted(view.entries)
        if view.entries[entry_id].get("kind", "source") in ("source", "reference")
        and not view.record(entry_id).get("classification")
    ]
    if open_ids:
        # One bundled reminder instead of one finding per entry.
        proposed = [i for i in open_ids if view.proposal(i).get("classification")]
        add("medium", "classification_open", None,
            f"{len(open_ids)} entries not yet classified"
            + (f", {len(proposed)} with an add-on proposal" if proposed else ""),
            "confirm the add-on proposals or set a classification in "
            f"{GOVERNANCE_REL_PATH} for: {', '.join(open_ids)}")
        findings[-1]["subjects"] = open_ids


def _entry_findings(view: _GovernanceView, entry_id: str, add) -> None:
    entry = view.entries[entry_id]
    if entry.get("kind", "source") not in ("source", "reference"):
        return
    record = view.record(entry_id)
    proposal = view.proposal(entry_id)
    name = entry.get("system") or entry_id
    pd = view.personal_data(entry_id)
    cls = view.classification(entry_id)

    operator_class = record.get("classification")
    proposed_class = proposal.get("classification")
    if operator_class and proposed_class and _rank(operator_class) < _rank(proposed_class):
        add("high", "classification_downgraded", entry_id,
            f"{name}: classified {operator_class!r}, below the add-on's "
            f"suggestion {proposed_class!r}",
            f"set sources.{entry_id}.classification to {proposed_class} in "
            f"{GOVERNANCE_REL_PATH}, or record an exception with the reason")
    if pd == "unknown":
        has_rag = _has_rag_path(entry)
        add("high" if has_rag else "medium", "personal_data_unknown", entry_id,
            f"{name}: whether it holds personal data is not documented"
            + (" (its content is copied into the vector index)" if has_rag else ""),
            f"set sources.{entry_id}.personal_data in {GOVERNANCE_REL_PATH}")
    # Record-of-processing references are checked only once the operator uses
    # them at all; an installation that keeps its record elsewhere stays quiet.
    if any(r.get("ropa_ref") for r in view.gov["sources"].values()) and not record.get(
        "ropa_ref"
    ):
        fix = f"set sources.{entry_id}.ropa_ref in {GOVERNANCE_REL_PATH}"
        if record.get("personal_data") in _RECORDED_PERSONAL_DATA:
            add("high", "personal_data_without_ropa", entry_id,
                f"{name} holds {pd} personal data but has no record-of-processing "
                f"reference", fix)
        elif not record.get("personal_data") and (
            proposal.get("personal_data") in _RECORDED_PERSONAL_DATA
        ):
            add("medium", "personal_data_without_ropa", entry_id,
                f"{name}: the add-on suggests {proposal['personal_data']} personal "
                f"data; no record-of-processing reference", fix)

    if view.open_roles(entry.get("required_roles")):
        restrict = (
            f"set required_roles for {entry_id} in overrides.yaml to the roles "
            f"that need it"
        )
        if _rank(cls) >= _rank("confidential"):
            add("high", "open_confidential", entry_id,
                f"{name} ({cls}"
                + (", not yet classified" if not operator_class else "")
                + ") is visible without required roles or to a broad role",
                restrict + (", or classify it if it is less sensitive"
                            if not operator_class else ""))
        if pd in _SENSITIVE_PERSONAL_DATA:
            add("high", "special_data_broad_access", entry_id,
                f"{name} holds {pd} personal data and is visible without required "
                f"roles or to a broad role", restrict)


def _rag_findings(view: _GovernanceView, add) -> None:
    embedding = view.policy["embedding_model"]
    rag_entries = []
    for entry_id in sorted(view.entries):
        entry = view.entries[entry_id]
        if not _has_rag_path(entry):
            continue
        rag_entries.append(entry_id)
        name = entry.get("system") or entry_id
        cls = view.classification(entry_id)
        pd = view.personal_data(entry_id)
        keep_out = (
            f"take {entry_id} out of the vector index, or restrict its collection "
            f"to the roles of the source and re-ingest after deletions"
        )
        if cls == "strictly_confidential" or pd in _SENSITIVE_PERSONAL_DATA:
            add("high", "rag_copy_sensitive", entry_id,
                f"{name}: the vector index holds a copy of {cls}"
                f"{' / ' + pd + ' personal data' if pd in _SENSITIVE_PERSONAL_DATA else ''} "
                f"content that bypasses the source's rights and deletions", keep_out)
        elif cls == "confidential":
            add("medium", "rag_copy_sensitive", entry_id,
                f"{name}: the vector index holds a copy of confidential content that "
                f"bypasses the source's rights and deletions", keep_out)
        if embedding:
            tier = view.tier(embedding)
            allowed = view.allowed_tiers(cls, pd)
            if tier not in allowed:
                add("high", "embedding_model_policy", entry_id,
                    f"{name}: the embedding model {embedding!r} (tier {tier}) is not "
                    f"allowed for {cls} content"
                    + (f" with {pd} personal data" if pd != "unknown" else ""),
                    f"set policy.embedding_model to a model of tier {allowed or ['none']}, "
                    f"or take {entry_id} out of the vector index")
    if rag_entries and embedding and embedding not in view.gov["models"]:
        add("high", "unclassified_model_in_use", f"model:{embedding}",
            f"embedding model {embedding!r} has no tier (counted as third_country); "
            f"used for {', '.join(rag_entries)}",
            f"add models.{embedding}: {{tier: <tier>}} to {GOVERNANCE_REL_PATH}")


def _server_findings(view: _GovernanceView, add) -> None:
    for entry_id in sorted(view.entries):
        entry = view.entries[entry_id]
        if entry.get("kind") != "mcp":
            continue
        paths = _entry_paths(entry)
        server = str(paths[0].get("target")) if paths else ""
        reached = view.reach.get(server, [])
        name = entry.get("system") or server
        if entry.get("chat_menu", True) is not False:
            sensitive = [e for e in reached if view.sensitive(e)]
            if sensitive:
                add("medium", "confidential_in_free_chat", entry_id,
                    f"{name} reaches {', '.join(sensitive)} and can be selected in "
                    f"free chat with any model",
                    f"set chatMenu: false for {server} in librechat.yaml and use it "
                    f"through agents whose model the policy allows")
        if entry.get("static_credentials"):
            exposed = [
                e for e in reached
                if _rank(view.classification(e)) >= _rank("internal")
                or view.personal_data(e) != "none"
            ]
            if exposed:
                add("high", "mcp_static_credentials", entry_id,
                    f"{name} uses a shared credential to reach {', '.join(exposed)}; "
                    f"the target system no longer sees which user asks",
                    f"switch the {server} MCP server to the user's token "
                    f"({{{{LIBRECHAT_OPENID_ACCESS_TOKEN}}}}) instead of a shared credential")


def _agent_findings(view: _GovernanceView, add) -> None:
    unlisted: dict[str, list[str]] = {}
    for entry_id in sorted(view.entries):
        entry = view.entries[entry_id]
        if entry.get("kind") != "agent":
            continue
        model = _model_name(entry)
        if not model:
            continue
        if model not in view.gov["models"]:
            unlisted.setdefault(model, []).append(entry_id)
        reached = sorted({
            e for server in entry.get("uses") or [] for e in view.reach.get(str(server), [])
        })
        tier = view.tier(model)
        blocked = [
            e for e in reached
            if tier not in view.allowed_tiers(view.classification(e), view.personal_data(e))
        ]
        if blocked:
            allowed = sorted(
                set(MODEL_TIERS).intersection(*(
                    view.allowed_tiers(view.classification(e), view.personal_data(e))
                    for e in blocked
                )),
                key=MODEL_TIERS.index,
            )
            add("high", "agent_model_policy", entry_id,
                f"{entry.get('system') or entry_id} uses model {model!r} (tier {tier}), "
                f"which the policy does not allow for {', '.join(blocked)}",
                f"switch {entry_id} to a model of tier {allowed or ['none']} and "
                f"restrict its LiteLLM team/key to such models")
    for model, agents in sorted(unlisted.items()):
        add("high", "unclassified_model_in_use", f"model:{model}",
            f"model {model!r} has no tier (counted as third_country); used by "
            f"{', '.join(agents)}",
            f"add models.{model}: {{tier: <tier>}} to {GOVERNANCE_REL_PATH}")


def _apply_exceptions(findings: list[dict], exceptions: list[dict], today: date) -> list[dict]:
    """An active exception marks its finding as accepted risk (it stays in the
    list, flagged); an expired one lets the finding return unmarked and adds
    `exception_expired` so the acceptance gets renewed or removed."""
    result = list(findings)
    active = {}
    for exc in exceptions:
        key = (exc["finding"], exc["subject"])
        if today < exc["expires"]:
            active[key] = exc
        else:
            result.append(_finding(
                "medium", "exception_expired", exc["subject"],
                f"the accepted exception for {exc['finding']} on {exc['subject']} "
                f"expired on {exc['expires'].isoformat()}",
                "governance",
                f"fix the {exc['finding']} finding, or renew the exception in "
                f"{GOVERNANCE_REL_PATH} with a new expires date",
            ))
    for finding in result:
        exc = active.get((finding["code"], finding["target"]))
        if exc:
            finding["exception"] = {
                key: (value.isoformat() if isinstance(value, date) else value)
                for key, value in exc.items()
                if key in ("expires", "reason", "risk_ref") and value is not None
            }
    return result


def render(
    config_dir: Path,
    repo_root: Path,
    active_profiles: set[str],
    active_addons: list[dict],
    now: datetime | None = None,
    today: date | None = None,
) -> list[str]:
    """Write index.yaml and manifests/, prune removed sources, return warnings.

    Runs only while the knowledge-map profile is active (the caller gates), so
    a lean installation renders nothing new. `today` dates the governance
    exception expiry check (injectable for tests)."""
    entries, warnings = collect_sources(
        repo_root, config_dir, active_profiles, active_addons
    )
    governance = load_governance(config_dir)
    today = today if today is not None else date.today()

    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    generated_at = stamp.isoformat()
    valid_until = (stamp + timedelta(days=TTL_DAYS)).isoformat()

    map_dir = config_dir / MAP_DIR
    manifest_dir = map_dir / "manifests"
    common.ensure_dir(manifest_dir)
    # Snapshot BEFORE writing: the mass-prune guard compares against the map
    # as it was, not as this render leaves it.
    existing_before = {f.name for f in manifest_dir.glob("*.yaml")}
    # The service mounts the operator directory; create it so the bind mount
    # does not make Docker create it root-owned.
    common.ensure_dir(config_dir / "overlay" / MAP_DIR)

    index_sources = []
    for source_id in sorted(entries):
        entry = dict(entries[source_id])
        # Manifests are model-facing: of the governance data only the
        # effective handling enums travel — never proposals, owners or
        # references, nor the inventory facts the checks use (ADR 0014).
        for key in _INTERNAL_KEYS:
            entry.pop(key, None)
        entry["handling"] = effective_handling(source_id, governance)
        entry["content_hash"] = _content_hash(entries[source_id])
        entry["generated_at"] = generated_at
        entry["valid_until"] = valid_until
        common.atomic_write(
            manifest_dir / f"{source_id}.yaml",
            yaml.safe_dump(entry, sort_keys=False, allow_unicode=True),
        )
        first_hint = None
        not_covered = entry.get("not_covered") or []
        if not_covered and isinstance(not_covered[0], dict):
            first_hint = {
                "what": not_covered[0].get("what"),
                "instead": not_covered[0].get("instead"),
            }
        index_sources.append(
            {
                # `or` instead of dict defaults: an explicit YAML null must
                # not become None / the literal string "None" in the index.
                "id": source_id,
                "kind": entry.get("kind") or "source",
                "system": entry.get("system") or source_id,
                "coverage": str(entry.get("coverage") or "").split("\n")[0][:200],
                "topics": [
                    (t.get("label") or t.get("id") or "") if isinstance(t, dict) else t
                    for t in entry.get("topics") or []
                ],
                "not_covered_hint": first_hint,
            }
        )

    # Prune manifests of sources no longer declared: a removed add-on must
    # take its map entry with it, or the map routes into a void. A render that
    # would remove most of a populated map is distrusted instead (see
    # _MASS_PRUNE_SHARE): it keeps the old manifests and says so.
    declared = {f"{source_id}.yaml" for source_id in entries}
    vanished = sorted(existing_before - declared)
    mass_prune = (
        len(existing_before) >= _MASS_PRUNE_MIN_ENTRIES
        and len(vanished) > len(existing_before) * _MASS_PRUNE_SHARE
    )
    if mass_prune and _read_prune_marker(map_dir) != vanished:
        warnings.append(
            f"knowledge map: this render would remove {len(vanished)} of "
            f"{len(existing_before)} entries — kept them; check the add-on and "
            f"chat configuration. If the removal is intended, render again: an "
            f"identical second render prunes."
        )
        _write_prune_marker(map_dir, vanished)
    else:
        for name in vanished:
            (manifest_dir / name).unlink(missing_ok=True)
        _write_prune_marker(map_dir, [])

    common.atomic_write(
        map_dir / LINTS_FILE,
        yaml.safe_dump(
            {
                "generated_at": generated_at,
                "findings": lint(entries, librechat_servers(config_dir))
                + governance_lint(entries, governance, today),
                "warnings": warnings,
                # Add-on suggestions for the management view ("suggested by
                # add-on"); never effective and never in a manifest.
                "proposals": {
                    source_id: entries[source_id]["governance_proposal"]
                    for source_id in sorted(entries)
                    if isinstance(entries[source_id].get("governance_proposal"), dict)
                },
                # The model each inventoried agent runs on, for the management
                # view's model policy table; never in a manifest.
                "agent_models": {
                    source_id: entries[source_id]["model"]
                    for source_id in sorted(entries)
                    if isinstance(entries[source_id].get("model"), dict)
                },
            },
            sort_keys=False,
            allow_unicode=True,
        ),
    )
    common.atomic_write(
        map_dir / "index.yaml",
        yaml.safe_dump(
            {"generated_at": generated_at, "sources": index_sources},
            sort_keys=False,
            allow_unicode=True,
        ),
    )
    return warnings


_PRUNE_MARKER = ".pending-prune"


def _read_prune_marker(map_dir: Path) -> list[str] | None:
    marker = map_dir / _PRUNE_MARKER
    if not marker.is_file():
        return None
    return [line for line in marker.read_text(encoding="utf-8").splitlines() if line]


def _write_prune_marker(map_dir: Path, names: list[str]) -> None:
    """Remember a withheld mass prune. When the very next render withholds
    the same set again, the change is deliberate (an operator removed most
    add-ons) and goes through."""
    marker = map_dir / _PRUNE_MARKER
    if not names:
        if marker.exists():
            marker.unlink()
        return
    common.atomic_write(marker, "\n".join(names) + "\n")
