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
    _scan_for_injection(entry, origin)


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
    declaration = {k: v for k, v in entry.items() if k != "provenance"}
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
            warning = _inventory_entry(entry, entries, "inventory:librechat-agents")
            if warning:
                warnings.append(warning)
    return warnings


def lint(entries: dict[str, dict], servers: dict[str, dict] | None) -> list[dict]:
    """Findings that weaken the map, for the management view. Severity is
    about the effect on answers: `high` can produce a wrong answer."""
    findings: list[dict] = []

    def add(severity: str, code: str, target: str | None, message: str) -> None:
        findings.append(
            {"severity": severity, "code": code, "target": target, "message": message}
        )

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

def render(
    config_dir: Path,
    repo_root: Path,
    active_profiles: set[str],
    active_addons: list[dict],
    now: datetime | None = None,
) -> list[str]:
    """Write index.yaml and manifests/, prune removed sources, return warnings.

    Runs only while the knowledge-map profile is active (the caller gates), so
    a lean installation renders nothing new."""
    entries, warnings = collect_sources(
        repo_root, config_dir, active_profiles, active_addons
    )

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
                "findings": lint(entries, librechat_servers(config_dir)),
                "warnings": warnings,
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
