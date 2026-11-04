"""3-layer config merge + Keycloak realm-secret baking.

Renders the effective core configuration into $PAPAIA_CONFIG_DIR:

    repo base (src/<target>)
      + active-profile fragments (src/<module>/integration/<target>, PROFILE_FRAGMENTS)
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

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

import yaml

from . import common, deployment, smtp

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
    "infra/keycloak/themes/papaia",
]

_STRUCTURED_SUFFIXES = {".yaml", ".yml", ".json"}

# Core modules that ship integration fragments of their own (same layout as an
# add-on: `<path>/integration/<target>`), merged only while the module's Compose
# profile is active -- a stack without the RAG system must not list its MCP
# servers in LibreChat. The fragments sit between the repo base and the add-on
# layer.
PROFILE_FRAGMENTS: dict[str, str] = {"rag": "src/ai/rag"}


class RenderError(Exception):
    """A user-facing rendering failure (e.g. an unresolved realm placeholder).

    `line` and `column` (1-based) are set when the failure is a position in a file."""

    def __init__(self, message: str, *, line: int | None = None, column: int | None = None):
        super().__init__(message)
        self.line = line
        self.column = column


def _profile_layers(config_dir: Path) -> list[dict]:
    """One add-on-shaped layer per active profile that ships fragments.

    COMPOSE_PROFILES is read from the root .env, which is what compose itself
    uses; deployment.yaml only mirrors it."""
    raw = common.parse_env_file(config_dir / ".env").get("COMPOSE_PROFILES", "")
    active = {p.strip() for p in raw.split(",") if p.strip()}
    return [{"path": path} for profile, path in PROFILE_FRAGMENTS.items() if profile in active]


def _active_layers(config_dir: Path) -> list[dict]:
    """The fragment layers between the repo base and the overlay, in merge order."""
    return _profile_layers(config_dir) + deployment.active_addons(deployment.load(config_dir))


def render(config_dir: Path, repo_root: Path) -> None:
    active_addons = _active_layers(config_dir)

    for target in BASE_RENDER_TARGETS:
        base_path = repo_root / "src" / target
        if base_path.is_dir():
            _render_dir(target, repo_root, config_dir, active_addons)
        else:
            _render_file(target, repo_root, config_dir, active_addons)

    render_librechat_addon_content(config_dir, repo_root)
    bake_realm_secrets(repo_root, config_dir)


# Agents and prompts an add-on contributes to LibreChat (addon_api 4): files under
# <addon>/integration/ai/librechat/{agents,prompts}/, rendered as <addon>__<file> into
# $PAPAIA_CONFIG_DIR/ai/librechat/addon-{agents,prompts}/ and mounted by a generated
# override, whose label carries a hash of the content so `start` recreates LibreChat
# when it changes. Its init scripts upsert the files and delete what an add-on no
# longer provides.
LIBRECHAT_ADDON_CONTENT: dict[str, tuple[str, tuple[str, ...]]] = {
    "agents": ("addon-agents", (".yaml", ".yml")),
    "prompts": ("addon-prompts", (".md", ".markdown")),
}
LIBRECHAT_ADDON_OVERRIDE = "overrides/docker-compose.librechat-addons.override.yml"
_LIBRECHAT_DATA = "/app/api/data"


def _agent_problem(path: Path, mcp_servers: set[str]) -> str | None:
    """Why an add-on agent file cannot be provisioned, or None. An agent that names
    an MCP server the rendered librechat.yaml lacks would appear without its tools."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return f"not valid YAML ({exc})"
    if not isinstance(doc, dict):
        return "not a mapping"
    missing = [k for k in ("id", "name", "provider", "model") if not doc.get(k)]
    if missing:
        return "missing " + ", ".join(missing)
    unknown = [s for s in doc.get("mcpServers") or [] if s not in mcp_servers]
    if unknown:
        return "names MCP servers librechat.yaml does not define: " + ", ".join(unknown)
    return None


def render_librechat_addon_content(config_dir: Path, repo_root: Path) -> list[str]:
    """Render the LibreChat agents and prompts of the active add-ons and write or
    remove their override. Returns the warnings printed for skipped files."""
    rendered_yaml = config_dir / "ai" / "librechat" / "librechat.yaml"
    try:
        librechat = yaml.safe_load(rendered_yaml.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        librechat = {}
    mcp_servers = set((librechat.get("mcpServers") or {}) if isinstance(librechat, dict) else {})

    warnings: list[str] = []
    digest = hashlib.sha256()
    mounts: list[dict] = []
    addons = [a for a in deployment.active_addons(deployment.load(config_dir)) if a.get("name")]
    for kind, (dirname, suffixes) in LIBRECHAT_ADDON_CONTENT.items():
        out_dir = config_dir / "ai" / "librechat" / dirname
        if out_dir.exists():
            shutil.rmtree(out_dir)
        written = 0
        for addon in addons:
            src_dir = repo_root / addon["path"] / "integration" / "ai" / "librechat" / kind
            if not src_dir.is_dir():
                continue
            for src in sorted(src_dir.iterdir()):
                if not src.is_file() or src.suffix.lower() not in suffixes:
                    continue
                if kind == "agents":
                    problem = _agent_problem(src, mcp_servers)
                    if problem:
                        warnings.append(f"addon '{addon['name']}': agent {src.name} {problem}")
                        continue
                name = f"{addon['name']}__{src.name}"
                content = src.read_text(encoding="utf-8")
                common.atomic_write(out_dir / name, content)
                digest.update(f"{kind}/{name}\0{content}\0".encode())
                written += 1
        if written:
            mounts.append(
                {
                    "type": "bind",
                    "source": str(out_dir),
                    "target": f"{_LIBRECHAT_DATA}/{dirname}",
                    "read_only": True,
                }
            )

    for warning in warnings:
        print(f"WARNING: {warning} -- skipped", file=sys.stderr)

    override_path = config_dir / LIBRECHAT_ADDON_OVERRIDE
    if not mounts:
        # Removing the override changes LibreChat's labels too, so the next start
        # recreates it and its init scripts delete the agents and prompts of the
        # removed add-ons.
        override_path.unlink(missing_ok=True)
        return warnings
    override = {
        "services": {
            "librechat": {
                "volumes": mounts,
                "labels": {"org.papaia.addon-content": digest.hexdigest()[:16]},
            }
        }
    }
    common.atomic_write(
        override_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )
    return warnings


def _parse_structured(suffix: str, text: str, label: str):
    """Parse one layer. A layer that does not parse is a RenderError that names it (`label`)
    and, when the parser says, the line -- not a traceback: `start` renders before it brings
    anything up, so a typo in a hand-edited overlay would otherwise stop it with no hint."""
    if suffix in (".yaml", ".yml"):
        try:
            return yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            reason = str(getattr(exc, "problem", None) or "invalid YAML")
            if mark is None:
                raise RenderError(f"{label}: invalid YAML: {reason}") from exc
            line, column = mark.line + 1, mark.column + 1
            raise RenderError(
                f"{label}: invalid YAML at line {line}, column {column}: {reason}",
                line=line,
                column=column,
            ) from exc
    if suffix == ".json":
        try:
            return json.loads(text)
        except ValueError as exc:
            line = getattr(exc, "lineno", None)
            column = getattr(exc, "colno", None)
            where = f" at line {line}, column {column}" if line else ""
            raise RenderError(
                f"{label}: invalid JSON{where}: {getattr(exc, 'msg', exc)}",
                line=line,
                column=column,
            ) from exc
    return None


def _load_structured(path: Path, label: str | None = None):
    return _parse_structured(path.suffix, path.read_text(encoding="utf-8"), label or str(path))


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
    if isinstance(base, list) and isinstance(overlay, list):
        # Append-and-dedup: overlay items not already present are appended.
        # repr() gives a stable content-identity key for dicts/lists/scalars.
        seen = {repr(x) for x in base}
        return list(base) + [x for x in overlay if repr(x) not in seen]
    # Scalars: the higher layer replaces the lower one wholesale.
    return overlay


# Stands for "the overlay file on disk" where `_effective_text` is also given a draft.
_ON_DISK = object()


def _merge_layer(merged, layer, label: str):
    """Merge one parsed layer onto what is below it. A mapping below takes only a mapping:
    anything else would replace the whole configuration with it."""
    if isinstance(merged, dict) and not isinstance(layer, dict):
        raise RenderError(
            f"{label}: the top level must be a mapping (key: value)", line=1, column=1
        )
    return _deep_merge(merged, layer)


def _effective_text(
    rel_path: str,
    repo_root: Path,
    config_dir: Path,
    active_addons: list[dict],
    overlay_text=_ON_DISK,
) -> str | None:
    """What `rel_path` renders to, or None when the repository has no such file.

    `overlay_text` stands in for the overlay: the default reads it from disk, as `render`
    does, a string is used as if the file held it, and None means there is no overlay.
    Shared by `render` and `preview`, so a preview cannot drift from what a render writes."""
    base_path = repo_root / "src" / rel_path
    if not base_path.is_file():
        return None  # missing-source: mirrors sync-config.sh's [missing-source] skip

    overlay_path = config_dir / "overlay" / rel_path
    overlay_label = f"overlay/{rel_path}"
    if base_path.suffix in _STRUCTURED_SUFFIXES:
        merged = _load_structured(base_path, f"src/{rel_path}")
        for addon in active_addons:
            frag_path = repo_root / addon["path"] / "integration" / rel_path
            if frag_path.is_file():
                label = f"{addon['path']}/integration/{rel_path}"
                merged = _merge_layer(merged, _load_structured(frag_path, label), label)
        if overlay_text is _ON_DISK:
            if overlay_path.is_file():
                layer = _load_structured(overlay_path, overlay_label)
                merged = _merge_layer(merged, layer, overlay_label)
        elif overlay_text is not None:
            layer = _parse_structured(base_path.suffix, overlay_text, overlay_label)
            merged = _merge_layer(merged, layer, overlay_label)
        return _dump_structured(base_path.suffix, merged)

    # Non-structured file: the highest layer present replaces the base
    # wholesale (no line-level diffing).
    content_path = base_path
    for addon in active_addons:
        frag_path = repo_root / addon["path"] / "integration" / rel_path
        if frag_path.is_file():
            content_path = frag_path
    if overlay_text is _ON_DISK:
        if overlay_path.is_file():
            content_path = overlay_path
    elif overlay_text is not None:
        return overlay_text
    return content_path.read_text(encoding="utf-8")


def _render_file(
    rel_path: str, repo_root: Path, config_dir: Path, active_addons: list[dict]
) -> None:
    content = _effective_text(rel_path, repo_root, config_dir, active_addons)
    if content is None:
        return
    common.atomic_write(config_dir / rel_path, content)


def preview(config_dir: Path, repo_root: Path, rel_path: str, overlay_text: str | None) -> dict:
    """The effective text of one target with `overlay_text` as its overlay, next to the text it
    has with the overlay on disk. Writes nothing.

    `overlay_text` None means "no overlay" and "" an empty one (nothing is merged). Only the
    file targets of BASE_RENDER_TARGETS qualify; a layer that does not parse is a RenderError,
    as it is in `render`."""
    if rel_path not in BASE_RENDER_TARGETS:
        raise RenderError(f"{rel_path}: not a render target")
    base_path = repo_root / "src" / rel_path
    if base_path.is_dir():
        raise RenderError(f"{rel_path}: is a directory; preview one file of it at a time")
    layers = _active_layers(config_dir)
    current = _effective_text(rel_path, repo_root, config_dir, layers)
    if current is None:
        raise RenderError(f"{rel_path}: the repository has no such file")
    draft = _effective_text(rel_path, repo_root, config_dir, layers, overlay_text)
    assert draft is not None
    return {
        "target": rel_path,
        "structured": base_path.suffix in _STRUCTURED_SUFFIXES,
        "current": current,
        "preview": draft,
        "changed": current != draft,
    }


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
    realm = json.loads(resolved)  # validate the substitution didn't break the JSON

    # The mail relay is optional, so its block cannot sit in the template: a
    # placeholder substitution cannot leave an object out. The relay needs no
    # login, which is also why no secret is baked in here. While the profile is off
    # the file stays exactly as the template resolved.
    relay = smtp.Settings.load(config_dir)
    if relay.active:
        realm["smtpServer"] = smtp.realm_smtp_server(relay)
        # A reset link is only worth offering where it can be delivered.
        realm["resetPasswordAllowed"] = True
        resolved = json.dumps(realm, indent=2, ensure_ascii=False) + "\n"

    out_dir = config_dir / "infra/keycloak/realm-import"
    common.ensure_dir(out_dir)
    common.atomic_write(out_dir / "papaia-realm.json", resolved)
