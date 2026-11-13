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
    _scan_for_injection(entry, origin)


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


def _collision_warnings(entries: dict[str, dict]) -> list[str]:
    warnings: list[str] = []
    ids = sorted(entries)
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

    override_warnings: list[str] = []
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
    # take its map entry with it, or the map routes into a void.
    declared = {f"{source_id}.yaml" for source_id in entries}
    for stale_file in manifest_dir.glob("*.yaml"):
        if stale_file.name not in declared:
            stale_file.unlink()

    common.atomic_write(
        map_dir / "index.yaml",
        yaml.safe_dump(
            {"generated_at": generated_at, "sources": index_sources},
            sort_keys=False,
            allow_unicode=True,
        ),
    )
    return warnings
