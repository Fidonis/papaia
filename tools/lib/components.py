"""The software an add-on bundles, as its manifest declares it.

An add-on's `version` counts changes to the bundle, not to the software in it:
`paperless` 1.1.0 does not say it runs Paperless-ngx 3.0.5. The catalog states
that in a `components` list of the manifest, and this module reads it for
`papaia-ctl addon components` and for the summary `addon install` prints.

The tag in the manifest is the catalog's default. An operator can pin another
one by setting the component's `image_var` in the add-on's `.env` in the config
directory, which leaves no trace in the manifest, so the listing reads that file
too and says where the two differ.

A manifest may come from any catalog and is printed to a terminal, so entries of
the wrong shape are skipped and control characters are dropped from every text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import common, deployment

SCHEMA_VERSION = 1
ROLES = ("primary", "sidecar")

_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_COMPONENTS = 32
_MAX_TEXT = 80
_MAX_REF = 200


def image_tag(ref: str) -> str:
    """Tag of an image reference (`registry/name:tag[@digest]`); `latest` without one."""
    last = ref.split("@", 1)[0].rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else "latest"


def _text(value: object, limit: int = _MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join("".join(ch for ch in value if ch.isprintable() or ch.isspace()).split())
    return cleaned[:limit] or None


def parse(manifest: dict | None) -> list[dict[str, Any]]:
    """The usable `components` entries of a manifest, in manifest order."""
    declared = (manifest or {}).get("components")
    if not isinstance(declared, list):
        return []
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in declared[:_MAX_COMPONENTS]:
        if not isinstance(entry, dict):
            continue
        ident = _text(entry.get("id"))
        name = _text(entry.get("name"))
        version = _text(entry.get("version"))
        if ident is None or name is None or version is None or ident in seen:
            continue
        seen.add(ident)
        role = _text(entry.get("role"))
        var = entry.get("image_var")
        source = _text(entry.get("source"), 200)
        parsed.append(
            {
                "id": ident,
                "name": name,
                "role": role if role in ROLES else "sidecar",
                "kind": _text(entry.get("kind")) or "upstream",
                "version": version,
                "image_var": var if isinstance(var, str) and _VAR_RE.match(var) else None,
                "source": source if source and source.startswith("https://") else None,
                "floating": entry.get("pinned") is False,
            }
        )
    return parsed


def describe(name: str, manifest: dict, *, active: bool, bundle_env: dict[str, str]) -> dict:
    """One add-on with its components and, per component, the tag `.env` pins instead."""
    components = parse(manifest)
    for component in components:
        override = None
        var = component["image_var"]
        if var:
            ref = bundle_env.get(var, "").strip()
            if ref and image_tag(ref) != component["version"]:
                override = ref[:_MAX_REF]
        component["override_version"] = image_tag(override) if override else None
        component["override_ref"] = override
    return {
        "name": name,
        "version": _text(manifest.get("version")) or "unknown",
        "active": active,
        "components": components,
        "error": None,
    }


def collect(
    deployed: dict, config_dir: Path, repo_root: Path, only: str | None = None
) -> list[dict]:
    """Every registered add-on (or just `only`), active or not, with its components."""
    results: list[dict] = []
    for entry in deployed.get("addons") or []:
        name = entry.get("name")
        if not name or (only is not None and name != only):
            continue
        manifest, error = deployment.load_addon_manifest(
            deployment.resolve_addon_path(entry, repo_root)
        )
        if manifest is None:
            results.append(
                {
                    "name": name,
                    "version": "unknown",
                    "active": bool(entry.get("active")),
                    "components": [],
                    "error": _text(error, 300),
                }
            )
            continue
        bundle_env = common.parse_env_file(config_dir / "addons" / name / ".env")
        active = bool(entry.get("active"))
        results.append(describe(name, manifest, active=active, bundle_env=bundle_env))
    return results


def format_text(addons: list[dict]) -> str:
    """The listing `addon components` prints, one block per add-on."""
    lines: list[str] = []
    for addon in addons:
        state = "active" if addon["active"] else "inactive"
        lines.append(f"{addon['name']} {addon['version']} ({state})")
        if addon["error"]:
            lines.append(f"  cannot read the manifest: {addon['error']}")
            continue
        components = addon["components"]
        if not components:
            lines.append("  (no components declared)")
            continue
        widths = [max(len(c[key] or "") for c in components) for key in ("name", "version", "role")]
        for c in components:
            notes = []
            if c["floating"]:
                notes.append("floating")
            if c["override_version"]:
                notes.append(f"overridden in .env: {c['override_version']}")
            row = (
                f"  {c['name']:<{widths[0]}}  {c['version']:<{widths[1]}}  "
                f"{c['role']:<{widths[2]}}  {c['image_var'] or '-'}"
            )
            lines.append(row + (f"  ({', '.join(notes)})" if notes else ""))
    return "\n".join(lines)


def to_json(addons: list[dict]) -> str:
    return json.dumps({"schema_version": SCHEMA_VERSION, "addons": addons})
