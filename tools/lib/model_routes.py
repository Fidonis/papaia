"""The data class of every model route (ADR 0031, docs/model-gateway.md).

Each alias of LiteLLM's rendered configuration carries the highest data class its route
may receive, as `model_info.papaia_max_class`, one class of the kit scale (the vendored
schema `platform-services.v1`, `$defs.DataClass`; this module keeps no list of its own):

* the value of the alias's entry in the operator overlay
  (`$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`);
* otherwise `PAPAIA_MODEL_MAX_CLASS` of the root `.env`, for every alias;
* otherwise `internal`, so a route the operator decided nothing about stays low.

A value outside the scale (another spelling, empty, surrounding text) stops the render with
the model and the value; it never falls back to the default. A value written by a layer
below the overlay (repo base, profile or add-on fragment) is dropped and reported, so an
add-on cannot raise the class of a route. A hosted test backend (`test_backend: true`,
lib/hosted_model.py) is capped at `internal`. An alias whose name has several deployments,
or that falls back to or is grouped onto other models, gets the lowest class of every
deployment it can reach.

The render writes the classes of the aliases into the route file
`$PAPAIA_CONFIG_DIR/ai/litellm/model-routes.json` (format, generation time, alias ->
class; no endpoint, no key), mode 0644, mounted read-only into the gateway. The file is
rewritten only when a class changes, and each alias whose class changed is one
`config_changed` row of `papaia.audit/1`. The platform catalog lists every alias with its
class, features, context and test flag in its `models` block (catalog_models).
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from functools import cache
from pathlib import Path

import yaml

from . import common, exposes, hosted_model

logger = logging.getLogger(__name__)

LITELLM_CONFIG = "ai/litellm/config.yaml"
ROUTES_FILE = "ai/litellm/model-routes.json"
FORMAT = "papaia.model-routes/1"
ROOT_VAR = "PAPAIA_MODEL_MAX_CLASS"
CLASS_KEY = "papaia_max_class"
FEATURES_KEY = "papaia_features"
CONTEXT_KEY = "papaia_context"
PROFILE = "litellm"
DEFAULT_CLASS = "internal"
# A hosted test backend sees synthetic data only (M-04, docs/hosted-test-model.md).
TEST_BACKEND_CEILING = "internal"
# The smallest context of a shipped model, for a route that names none.
DEFAULT_CONTEXT = 4096
MAX_CONTEXT = 16_777_216
ALIAS_RE = re.compile(r"papaia-[a-z0-9-]{1,40}")
# The features of an alias the overlay names none for, by its purpose.
PURPOSE_FEATURES: dict[str, tuple[str, ...]] = {
    "papaia-chat": ("chat", "tools", "stream"),
    "papaia-structured": ("chat", "json_schema", "json_object", "stream"),
    "papaia-embed": ("embeddings",),
}
# Where LiteLLM's configuration sends a request of one model to another.
_FALLBACK_SECTIONS = ("router_settings", "litellm_settings")
_FALLBACK_KEYS = ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks")
_DEFAULT_FALLBACKS = "default_fallbacks"
_GROUP_ALIAS = "model_group_alias"
_SHIPPED_MODELS = Path("src") / "ai" / "localai" / "models"
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_FILE_FIELDS = frozenset({"format", "generated_at", "routes"})
MAX_FILE_BYTES = 256 * 1024
AUDIT_WRITER = "papaia-ctl"
AUDIT_OPERATION = "model_route.class"


class ModelRoutesError(ValueError):
    """A route class that cannot be rendered or read; nothing was written."""


# ── the scale ─────────────────────────────────────────────────────────────


@cache
def scale() -> tuple[str, ...]:
    """The data classes of the kit, lowest first."""
    schema = exposes.load_schema(exposes.SERVICES_SCHEMA)
    return tuple(schema["$defs"]["DataClass"]["enum"])


@cache
def features() -> tuple[str, ...]:
    """The model features the kit's `ModelAlias` names."""
    schema = exposes.load_schema(exposes.SERVICES_SCHEMA)
    return tuple(schema["$defs"]["ModelAlias"]["properties"]["features"]["items"]["enum"])


def rank(data_class: str) -> int:
    return scale().index(data_class)


def lowest(classes: Iterable[str]) -> str:
    return min(classes, key=rank)


def highest(classes: Iterable[str]) -> str:
    return max(classes, key=rank)


def shown(value: object) -> str:
    """A value for a message: its repr, cut short."""
    text = repr(value)
    return text if len(text) <= 48 else text[:45] + "..."


def check_class(value: object, where: str) -> str:
    """`value` when it is exactly one class of the scale; otherwise ModelRoutesError."""
    if not isinstance(value, str) or value not in scale():
        raise ModelRoutesError(
            f"{where}: {shown(value)} is not a data class of the scale "
            f"({', '.join(scale())})"
        )
    return value


# ── render ─────────────────────────────────────────────────────────────────


def _entries(config: object) -> list[dict]:
    models = config.get("model_list") if isinstance(config, dict) else None
    if not isinstance(models, list):
        return []
    return [e for e in models if isinstance(e, dict) and isinstance(e.get("model_name"), str)]


def _info(entry: dict) -> dict:
    info = entry.get("model_info")
    if info is None:
        return {}
    if not isinstance(info, dict):
        raise ModelRoutesError(f"model '{entry['model_name']}': model_info must be a mapping")
    return info


def drop_layer_classes(config: object) -> list[str]:
    """Remove `model_info.papaia_max_class` from every entry of the layers below the overlay
    (call before the overlay is merged); returns one report per dropped value."""
    reports = []
    for entry in _entries(config):
        info = entry.get("model_info")
        if isinstance(info, dict) and CLASS_KEY in info:
            del info[CLASS_KEY]
            if not info:
                del entry["model_info"]
            reports.append(
                f"model '{entry['model_name']}': model_info.{CLASS_KEY} of a layer below the "
                f"overlay is ignored; only $PAPAIA_CONFIG_DIR/overlay/{LITELLM_CONFIG} sets "
                "the data class of a route"
            )
    return reports


def _names(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ModelRoutesError(f"{where} must be a list of model names")
    return value


def _edges(config: dict, names: set[str]) -> dict[str, set[str]]:
    """Model name -> the model names a request to it may end at besides itself."""
    edges: dict[str, set[str]] = {name: set() for name in names}
    for section in _FALLBACK_SECTIONS:
        part = config.get(section)
        if part is None:
            continue
        if not isinstance(part, dict):
            raise ModelRoutesError(f"{section} must be a mapping")
        for key in _FALLBACK_KEYS:
            rules = part.get(key)
            if rules is None:
                continue
            where = f"{section}.{key}"
            if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
                raise ModelRoutesError(f"{where} must be a list of {{model: [fallbacks]}}")
            for rule in rules:
                for source, targets in rule.items():
                    edges.setdefault(str(source), set()).update(
                        _names(targets, f"{where}[{source}]")
                    )
        if part.get(_DEFAULT_FALLBACKS) is not None:
            targets = _names(part[_DEFAULT_FALLBACKS], f"{section}.{_DEFAULT_FALLBACKS}")
            for name in names:
                edges[name].update(targets)
        groups = part.get(_GROUP_ALIAS)
        if groups is not None:
            if not isinstance(groups, dict):
                raise ModelRoutesError(f"{section}.{_GROUP_ALIAS} must be a mapping")
            for source, target in groups.items():
                if isinstance(target, dict):
                    target = target.get("model")
                if not isinstance(target, str):
                    raise ModelRoutesError(f"{section}.{_GROUP_ALIAS}[{source}] names no model")
                edges.setdefault(str(source), set()).add(target)
    return edges


def _reach(config: dict, names: set[str]) -> dict[str, set[str]]:
    """Every model name of `names` a request to each name of `names` can end at."""
    edges = _edges(config, names)
    found: dict[str, set[str]] = {}
    for start in names:
        seen = {start}
        todo = [start]
        while todo:
            for nxt in edges.get(todo.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        found[start] = seen & names
    return found


def _check_features(value: object, where: str) -> list[str]:
    allowed = features()
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(f, str) and f in allowed for f in value)
        or len(set(value)) != len(value)
    ):
        raise ModelRoutesError(
            f"{where}: {shown(value)} must list distinct features of {', '.join(allowed)}"
        )
    return list(value)


def _check_context(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (
        1024 <= value <= MAX_CONTEXT
    ):
        raise ModelRoutesError(
            f"{where}: {shown(value)} must be an integer from 1024 to {MAX_CONTEXT}"
        )
    return value


def apply(config: dict, env: dict[str, str]) -> tuple[dict, list[str]]:
    """The rendered configuration with `model_info.papaia_max_class` on every model entry;
    returns it and the reports for the operator. Runs after the aliases are added and the
    hosted routes are marked (model_gateway.apply, hosted_model.guard)."""
    if ROOT_VAR in env:
        default = check_class(env[ROOT_VAR], f"{ROOT_VAR} in $PAPAIA_CONFIG_DIR/.env")
    else:
        default = DEFAULT_CLASS
    reports: list[str] = []
    entries = _entries(config)
    own: dict[str, list[str]] = {}
    for entry in entries:
        name = entry["model_name"]
        info = _info(entry)
        where = f"model '{name}': model_info"
        if CLASS_KEY in info:
            value = check_class(info[CLASS_KEY], f"{where}.{CLASS_KEY}")
        else:
            value = default
        if FEATURES_KEY in info:
            _check_features(info[FEATURES_KEY], f"{where}.{FEATURES_KEY}")
        if CONTEXT_KEY in info:
            _check_context(info[CONTEXT_KEY], f"{where}.{CONTEXT_KEY}")
        if info.get(hosted_model.MARK) is True and rank(value) > rank(TEST_BACKEND_CEILING):
            reports.append(
                f"model '{name}': a hosted test model receives at most "
                f"'{TEST_BACKEND_CEILING}' (synthetic data only), not '{value}'"
            )
            value = TEST_BACKEND_CEILING
        own.setdefault(name, []).append(value)
    if not own:
        return config, reports
    if not isinstance(config, dict):
        raise ModelRoutesError("the configuration must be a mapping")
    reach = _reach(config, set(own))
    final = {
        name: lowest(c for target in reach[name] for c in own[target]) for name in own
    }
    for entry in entries:
        info = entry.get("model_info")
        entry["model_info"] = {**(info or {}), CLASS_KEY: final[entry["model_name"]]}
    return config, reports


def routes_of(config: object) -> dict[str, str]:
    """Alias -> class of a rendered configuration, sorted; every alias entry must carry a
    class of the scale (the lowest counts when an alias has several entries)."""
    found: dict[str, list[str]] = {}
    for entry in _entries(config):
        name = entry["model_name"]
        if not ALIAS_RE.fullmatch(name):
            continue
        value = _info(entry).get(CLASS_KEY)
        found.setdefault(name, []).append(
            check_class(value, f"model '{name}': model_info.{CLASS_KEY}")
        )
    return {name: lowest(found[name]) for name in sorted(found)}


def load_rendered(config_dir: Path) -> dict:
    """LiteLLM's rendered configuration; ModelRoutesError when it cannot be read."""
    path = Path(config_dir) / LITELLM_CONFIG
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ModelRoutesError(f"$PAPAIA_CONFIG_DIR/{LITELLM_CONFIG} is missing") from None
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ModelRoutesError(
            f"$PAPAIA_CONFIG_DIR/{LITELLM_CONFIG} cannot be read: {exc.__class__.__name__}"
        ) from None
    if not isinstance(config, dict):
        raise ModelRoutesError(f"$PAPAIA_CONFIG_DIR/{LITELLM_CONFIG} is not a mapping")
    return config


def gateway_on(config_dir: Path) -> bool:
    env = common.parse_env_file(Path(config_dir) / ".env")
    return PROFILE in common.cluster_profiles(env)


# ── route file ─────────────────────────────────────────────────────────────


def read_route_file(config_dir: Path) -> dict[str, str]:
    """The routes of the route file; ModelRoutesError when it is missing or malformed."""
    path = Path(config_dir) / ROUTES_FILE
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        raise ModelRoutesError(f"the route file $PAPAIA_CONFIG_DIR/{ROUTES_FILE} is missing"
                               ) from None
    except OSError as exc:
        raise ModelRoutesError(f"the route file cannot be read: {exc.strerror}") from None
    where = f"$PAPAIA_CONFIG_DIR/{ROUTES_FILE}"
    if len(data) > MAX_FILE_BYTES:
        raise ModelRoutesError(f"{where} is larger than {MAX_FILE_BYTES} bytes")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ModelRoutesError(f"{where} is not JSON") from None
    if not isinstance(doc, dict) or set(doc) != _FILE_FIELDS:
        raise ModelRoutesError(f"{where} must hold exactly {', '.join(sorted(_FILE_FIELDS))}")
    if doc["format"] != FORMAT:
        raise ModelRoutesError(f"{where}: format {shown(doc['format'])} is not {FORMAT}")
    if not isinstance(doc["generated_at"], str) or not _STAMP.fullmatch(doc["generated_at"]):
        raise ModelRoutesError(f"{where}: generated_at is not a UTC time")
    routes = doc["routes"]
    if not isinstance(routes, dict):
        raise ModelRoutesError(f"{where}: routes must be a mapping")
    for alias, value in routes.items():
        if not ALIAS_RE.fullmatch(alias):
            raise ModelRoutesError(f"{where}: {shown(alias)} is not an alias")
        check_class(value, f"{where}: routes[{alias}]")
    return dict(routes)


def _stamp(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: Path, data: bytes) -> None:
    """Beside the file, mode 0644 (the gateway reads it under its own uid), then renamed
    into place, so a reader sees the old or the new file, never a part."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o644)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _audit_log(config_dir: Path):
    from . import realm_sync as rs  # it imports the render path

    try:
        return rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(),
                           writer=AUDIT_WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        raise ModelRoutesError(f"the audit outbox cannot be written: {exc}") from None


def audit_fields(alias: str, data_class: str, result: str = "allowed",
                 error_code: str | None = None) -> dict:
    """The fields of one `config_changed` row for a changed route class (ADR 0031, row 2)."""
    return {
        "role": None,
        "sub": None,
        "identity_kind": None,
        "catalog_id": None,
        "operation": AUDIT_OPERATION,
        "effect": "write",
        "object_ref": {"type": "model_alias", "id": alias},
        "data_class": data_class,
        "result": result,
        "error_code": error_code,
        "detail": None,
        "event": "config_changed",
    }


def render(config_dir: Path, now: datetime | None = None) -> list[str]:
    """Write the route file from the rendered configuration while the gateway profile is
    on; returns the aliases whose class changed (one audit row each). The file is left as
    it is when no class changed."""
    config_dir = Path(config_dir)
    if not gateway_on(config_dir):
        return []
    routes = routes_of(load_rendered(config_dir))
    path = config_dir / ROUTES_FILE
    try:
        before: dict[str, str] | None = read_route_file(config_dir)
    except ModelRoutesError:
        before = None
    if before == routes:
        return []
    changed = sorted(a for a, c in routes.items() if (before or {}).get(a) != c)
    doc = {"format": FORMAT, "generated_at": _stamp(now), "routes": routes}
    data = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    with _audit_log(config_dir) as audit:
        try:
            _write(path, data)
        except OSError:
            for alias in changed:
                audit.append(audit_fields(alias, routes[alias], "error", "io"))
            raise
        for alias in changed:
            audit.append(audit_fields(alias, routes[alias]))
    return changed


# ── catalog ────────────────────────────────────────────────────────────────


@cache
def _shipped_contexts(models_dir: Path) -> dict[str, int]:
    """name -> context_size of the LocalAI model descriptions the repository ships."""
    found: dict[str, int] = {}
    if not models_dir.is_dir():
        return found
    for path in sorted(models_dir.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue
        name, size = doc.get("name"), doc.get("context_size")
        if isinstance(name, str) and isinstance(size, int) and not isinstance(size, bool):
            if 1024 <= size <= MAX_CONTEXT:
                found[name] = size
    return found


def _entry_features(alias: str, info: dict) -> list[str]:
    if FEATURES_KEY in info:
        return _check_features(info[FEATURES_KEY], f"model '{alias}': model_info.{FEATURES_KEY}")
    if alias in PURPOSE_FEATURES:
        return list(PURPOSE_FEATURES[alias])
    return ["embeddings"] if info.get("mode") == "embedding" else ["chat"]


def _entry_context(alias: str, entry: dict, info: dict, shipped: dict[str, int]) -> int:
    if CONTEXT_KEY in info:
        return _check_context(info[CONTEXT_KEY], f"model '{alias}': model_info.{CONTEXT_KEY}")
    params = entry.get("litellm_params")
    model = params.get("model") if isinstance(params, dict) else None
    if isinstance(model, str) and "/" in model:
        # `<provider>/<name>`: the name LocalAI serves the shipped model under.
        return shipped.get(model.split("/", 1)[1], DEFAULT_CONTEXT)
    return DEFAULT_CONTEXT


def catalog_models(config_dir: Path, repo_root: Path) -> list[dict]:
    """The `models` block of the platform catalog: one kit `ModelAlias` per alias of the
    rendered configuration, sorted by alias; empty without the gateway profile or before
    the first render. An alias with several deployments shows what all of them offer: the
    common features, the smallest context and the lowest class."""
    config_dir = Path(config_dir)
    if not gateway_on(config_dir) or not (config_dir / LITELLM_CONFIG).is_file():
        return []
    config = load_rendered(config_dir)
    classes = routes_of(config)
    shipped = _shipped_contexts((Path(repo_root) / _SHIPPED_MODELS).resolve())
    grouped: dict[str, list[dict]] = {}
    for entry in _entries(config):
        if ALIAS_RE.fullmatch(entry["model_name"]):
            grouped.setdefault(entry["model_name"], []).append(entry)
    models = []
    for alias in sorted(grouped):
        feature_sets = []
        contexts = []
        test_backend = False
        for entry in grouped[alias]:
            info = _info(entry)
            feature_sets.append(_entry_features(alias, info))
            contexts.append(_entry_context(alias, entry, info, shipped))
            test_backend = test_backend or info.get(hosted_model.MARK) is True
        common_features = [f for f in feature_sets[0] if all(f in s for s in feature_sets)]
        models.append({
            "alias": alias,
            "features": common_features,
            "context": min(contexts),
            "max_class": classes[alias],
            "test_backend": test_backend,
        })
    return models


# ── start rule ─────────────────────────────────────────────────────────────


def above_route(need_classes: dict[str, str], aliases: Iterable[str],
                routes: dict[str, str]) -> tuple[list[dict], list[str], list[str]]:
    """What a module's needs say about the routes: the needs above their route
    ({alias, need_class, route_class}), the aliases it needs without a route, and the
    aliases it needs without a declared class (judged as the highest class)."""
    above = []
    missing = []
    undeclared = []
    for alias in sorted(set(aliases)):
        route = routes.get(alias)
        if route is None:
            missing.append(alias)
            continue
        need = need_classes.get(alias)
        if need is None:
            undeclared.append(alias)
        elif rank(need) > rank(route):
            above.append({"alias": alias, "need_class": need, "route_class": route})
    return above, missing, undeclared
