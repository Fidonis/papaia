"""3-layer config merge + Keycloak realm-secret baking.

Renders the effective core configuration into $PAPAIA_CONFIG_DIR:

    repo base (src/<target>)
      + active-addon fragments (addons/<name>/integration/<target>)
      + customer overlay ($PAPAIA_CONFIG_DIR/overlay/<target>)
      --render--> $PAPAIA_CONFIG_DIR/<target>

On the lean core, `deployment.yaml`'s `addons` list is always empty, so
the addon layer is a real loop that iterates zero times -- not a stub.

Realm-secret baking supersedes Keycloak's native `${env.VAR}` import-time
substitution (found unreliable in practice): secrets are substituted into
the realm JSON before Keycloak ever sees the file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from . import common

# Mirrors sync-config.sh's FILES/DIRS list, minus the stale `ai/n8n/nginx.conf`
# entry (ai/n8n was deleted by #92's lean-out commit; sync-config.sh just
# never had that line removed). LocalAI entries are kept since LocalAI
# remains in the lean-core keep-list.
BASE_RENDER_TARGETS: list[str] = [
    "ai/librechat/librechat.yaml",
    "ai/litellm/config.yaml",
    "ai/litellm/prometheus.yml",
    "ai/localai/models.txt",
    "ai/localai/models",
    "services/searxng/settings.yml",
    "infra/keycloak/keycloak.conf",
    "services/homepage/config",
]

_STRUCTURED_SUFFIXES = {".yaml", ".yml", ".json"}


class RenderError(Exception):
    """A user-facing rendering failure (e.g. an unresolved realm placeholder)."""


def render(config_dir: Path, repo_root: Path) -> None:
    deployment_path = config_dir / "deployment.yaml"
    deployment = {}
    if deployment_path.is_file():
        deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8")) or {}
    active_addons = [a for a in (deployment.get("addons") or []) if a.get("active")]

    for target in BASE_RENDER_TARGETS:
        base_path = repo_root / "src" / target
        if base_path.is_dir():
            _render_dir(target, repo_root, config_dir, active_addons)
        else:
            _render_file(target, repo_root, config_dir, active_addons)

    bake_realm_secrets(repo_root, config_dir)


def _load_structured(path: Path):
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def _dump_structured(suffix: str, data) -> str:
    if suffix in (".yaml", ".yml"):
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    if suffix == ".json":
        return json.dumps(data, indent=2, sort_keys=False) + "\n"
    raise RenderError(f"Cannot serialize unstructured suffix: {suffix}")


def _deep_merge(base, overlay):
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            merged[key] = _deep_merge(merged[key], value) if key in merged else value
        return merged
    # Scalars and lists: the higher layer replaces the lower one wholesale.
    return overlay


def _render_file(
    rel_path: str, repo_root: Path, config_dir: Path, active_addons: list[dict]
) -> None:
    base_path = repo_root / "src" / rel_path
    if not base_path.is_file():
        return  # missing-source: mirrors sync-config.sh's [missing-source] skip

    if base_path.suffix in _STRUCTURED_SUFFIXES:
        merged = _load_structured(base_path)
        for addon in active_addons:
            frag_path = repo_root / addon["path"] / "integration" / rel_path
            if frag_path.is_file():
                merged = _deep_merge(merged, _load_structured(frag_path))
        overlay_path = config_dir / "overlay" / rel_path
        if overlay_path.is_file():
            merged = _deep_merge(merged, _load_structured(overlay_path))
        content = _dump_structured(base_path.suffix, merged)
    else:
        # Non-structured file: the highest layer present replaces the base
        # wholesale (no line-level diffing).
        content_path = base_path
        for addon in active_addons:
            frag_path = repo_root / addon["path"] / "integration" / rel_path
            if frag_path.is_file():
                content_path = frag_path
        overlay_path = config_dir / "overlay" / rel_path
        if overlay_path.is_file():
            content_path = overlay_path
        content = content_path.read_text(encoding="utf-8")

    common.atomic_write(config_dir / rel_path, content)


def _render_dir(
    rel_path: str, repo_root: Path, config_dir: Path, active_addons: list[dict]
) -> None:
    base_dir = repo_root / "src" / rel_path
    if not base_dir.is_dir():
        return
    src_root = repo_root / "src"
    for file_path in sorted(base_dir.rglob("*")):
        if file_path.is_file():
            sub_rel = file_path.relative_to(src_root).as_posix()
            _render_file(sub_rel, repo_root, config_dir, active_addons)


def bake_realm_secrets(repo_root: Path, config_dir: Path) -> None:
    template_path = repo_root / "src/infra/keycloak/realm-import/papaia-realm.json.template"
    template = template_path.read_text(encoding="utf-8")

    env: dict[str, str] = {}
    env.update(common.parse_env_file(config_dir / ".env"))
    env.update(common.parse_env_file(config_dir / "infra/keycloak/.env"))

    def replace(match: re.Match) -> str:
        var = match.group(1)
        if var not in env:
            raise RenderError(f"Realm template references undefined ${{env.{var}}}: {var}")
        return env[var]

    resolved = re.sub(r"\$\{env\.([^}]+)\}", replace, template)
    json.loads(resolved)  # validate the substitution didn't break the JSON

    out_dir = config_dir / "infra/keycloak/realm-import"
    common.ensure_dir(out_dir)
    common.atomic_write(out_dir / "papaia-realm.json", resolved)
