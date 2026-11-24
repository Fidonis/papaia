"""The model gateway (LiteLLM): aliases only, one key per module, no stored contents.

Modules reach models through LiteLLM alone and name aliases, never a model or a provider
(docs/model-gateway.md):

* Aliases. The render adds `papaia-chat` and `papaia-structured` (mapped onto
  `PAPAIA_DEFAULT_MODEL`) and `papaia-embed` (onto `PAPAIA_DEFAULT_EMBED_MODEL`) to
  LiteLLM's model_list, each with the parameters of the model it names. An alias the
  overlay defines itself is kept as it is. `setup --local-ai` names the shipped default
  model, whose download the render adds to LocalAI's list, so nothing is entered by hand.
* No contents. The rendered configuration keeps prompts out of the spend logs, turns off
  message logging, redacts key information, and registers no logging callback other than
  the metrics and the listing filter. A layer that changes any of that is refused.
* Module keys. A module that declares `models.needs` in its `exposes:` gets a virtual key
  of its own: alias `module-<name>`, its aliases as the only models, budget tag
  `module:<name>`. The key goes into the add-on's `.env` as `PAPAIA_MODEL_KEY`; the master
  key stays inside the LiteLLM container, where the management calls run
  (`docker exec`). Before a key is revoked or replaced, `key_revoke` with the key id (the
  SHA-256 LiteLLM stores, never the key) goes into the erasure journal `model-gateway`,
  so a restored database cannot bring the key back unnoticed. A revocation LiteLLM
  cannot take at that moment is kept and done at the next `start`.

Every key that is made or revoked is one `papaia.audit/1` row in the host's audit
journal, with the key id and never the key.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote

from . import common, images

logger = logging.getLogger(__name__)

KEY_VAR = "PAPAIA_MODEL_KEY"
DEFAULT_MODEL_VAR = "PAPAIA_DEFAULT_MODEL"
DEFAULT_EMBED_VAR = "PAPAIA_DEFAULT_EMBED_MODEL"

# Alias -> the root variable that names the model it maps onto (M-01).
ALIASES: dict[str, str] = {
    "papaia-chat": DEFAULT_MODEL_VAR,
    "papaia-structured": DEFAULT_MODEL_VAR,
    "papaia-embed": DEFAULT_EMBED_VAR,
}
EMBED_ALIAS = "papaia-embed"

# The shipped default models (E-32) and where LocalAI downloads them. Each has a model
# description in src/ai/localai/models/ whose `parameters.model` is the file name.
CPU_DEFAULT = "qwen2.5-7b-instruct-q4"
GPU_DEFAULT = "qwen2.5-7b-instruct-q8"
SMALL_DEFAULT = "qwen2.5-1.5b-instruct"
LOCAL_DEFAULTS: dict[str, str] = {
    CPU_DEFAULT: "https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/"
    "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    GPU_DEFAULT: "https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/"
    "Qwen2.5-7B-Instruct-Q8_0.gguf",
    SMALL_DEFAULT: "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/"
    "qwen2.5-1.5b-instruct-q4_k_m.gguf",
}

# (section, key, value) the rendered configuration must carry (M-06).
NO_CONTENT_SETTINGS: tuple[tuple[str, str, bool], ...] = (
    ("general_settings", "store_prompts_in_spend_logs", False),
    ("litellm_settings", "turn_off_message_logging", True),
    ("litellm_settings", "redact_user_api_key_info", True),
)
# prometheus counts, the listing filter hides routes, the halt hook refuses requests while
# the platform halt is active (docs/halt.md); none of them passes on a request body.
ALLOWED_CALLBACKS = frozenset({
    "prometheus",
    "papaia_hooks.papaia_listing_filter",
    "papaia_hooks.papaia_platform_halt",
})
_CALLBACK_KEYS = (
    "callbacks",
    "success_callback",
    "failure_callback",
    "service_callback",
    "input_callback",
    "_async_success_callback",
    "_async_failure_callback",
)

# Response caching that stays inside the LiteLLM process; every other type (redis, s3,
# disk, the semantic caches, ...) would keep prompts and answers outside it.
_PROCESS_CACHE_TYPES = frozenset({"local"})

# What a module may say about a model need (manifest field `models`, architecture §
# manifest: `{needs: [{alias, features[], min_context, max_class}]}`).
_MODELS_FIELDS = frozenset({"needs"})
_NEED_FIELDS = frozenset({"alias", "features", "min_context", "max_class"})
_FEATURES = frozenset({"chat", "tools", "json_schema", "json_object", "stream", "embeddings"})
_MIN_CONTEXT = 1024
_CLASS_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")

_ALIAS_RE = re.compile(r"papaia-[a-z0-9-]{1,40}")
_MODULE_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_TOKEN_RE = re.compile(r"[0-9a-f]{64}")
_PENDING_FIELDS = frozenset({"key_id", "module"})
_PLACEHOLDERS = frozenset({"", "CHANGE_ME", "__GENERATED__"})

SERVICE = "litellm"
JOURNAL_SOURCE = "model-gateway"
JOURNAL_LOCAL_DIR = Path("state") / "erasure-journal"
PENDING_FILE = Path("state") / "model-gateway" / "pending-revocations.json"
_LIFECYCLE = Path("src") / "infra" / "lifecycle" / "lifecycle.py"
EXEC_TIMEOUT_SECONDS = 60
DOCKER_TIMEOUT_SECONDS = 30

# The management paths the core calls; anything else is refused before it is sent.
_ADMIN_PATHS = (
    ("POST", "/key/generate"),
    ("POST", "/key/delete"),
    ("GET", "/key/list?"),
    ("GET", "/health/readiness"),
    # Usage per end user, for `papaia-ctl person export|erase` (lib/person_core.py).
    ("GET", "/customer/info?"),
    ("POST", "/customer/delete"),
)

# Runs inside the LiteLLM container with `python -I -c`; the request comes in on stdin
# and the master key from the container's own environment, so it never leaves the
# container. Prints one JSON line {"status", "body"}; status 0 when LiteLLM did not answer.
_ADMIN_SCRIPT = (
    "import json,os,sys,urllib.error,urllib.request\n"
    "r=json.load(sys.stdin)\n"
    "data=None if r['body'] is None else json.dumps(r['body']).encode()\n"
    "q=urllib.request.Request('http://127.0.0.1:4000'+r['path'],data=data,method=r['method'],"
    "headers={'Authorization':'Bearer '+os.environ['LITELLM_MASTER_KEY'],"
    "'Content-Type':'application/json'})\n"
    "o=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "try:\n"
    "    with o.open(q,timeout=30) as s: st,b=s.status,s.read()\n"
    "except urllib.error.HTTPError as e: st,b=e.code,e.read()\n"
    "except OSError: st,b=0,b''\n"
    "print(json.dumps({'status':st,'body':b.decode('utf-8','replace')}))\n"
)

Runner = Callable[[list[str], "str | None", int], subprocess.CompletedProcess]


class ModelGatewayError(Exception):
    """A configuration or key operation that must not go ahead."""


class Unavailable(ModelGatewayError):
    """LiteLLM does not run here or does not answer."""


# ── render ─────────────────────────────────────────────────────────────────


def with_default_download(models_text: str, env: dict[str, str]) -> str:
    """LocalAI's download list with the line of the shipped default model, when one is
    named and its file is not on the list yet."""
    url = LOCAL_DEFAULTS.get(env.get(DEFAULT_MODEL_VAR, "").strip())
    if url is None:
        return models_text
    wanted = url.rsplit("/", 1)[-1]
    for line in models_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.rsplit("/", 1)[-1] == wanted:
            return models_text
    text = models_text if not models_text or models_text.endswith("\n") else models_text + "\n"
    return f"{text}\n# Default model ({DEFAULT_MODEL_VAR}), added by the render\n{url}\n"


def _check_no_contents(config: dict) -> None:
    for section, key, value in NO_CONTENT_SETTINGS:
        part = config.get(section)
        if part is None:
            part = config[section] = {}
        if not isinstance(part, dict):
            raise ModelGatewayError(f"model gateway: {section} must be a mapping")
        if key not in part:
            part[key] = value
        elif part[key] is not value:
            raise ModelGatewayError(
                f"model gateway: {section}.{key} must stay {str(value).lower()}; the gateway "
                "stores no request or response contents (docs/model-gateway.md)"
            )
    settings = config["litellm_settings"]
    if settings.get("set_verbose") not in (None, False):
        raise ModelGatewayError(
            "model gateway: litellm_settings.set_verbose would log request contents"
        )
    _check_no_cache(settings)
    if config["general_settings"].get("alerting") not in (None, []):
        raise ModelGatewayError(
            "model gateway: general_settings.alerting would send request details to a "
            "third place (docs/model-gateway.md)"
        )
    for key in _CALLBACK_KEYS:
        if key not in settings:
            continue
        value = settings[key]
        names = value if isinstance(value, list) else [value]
        unknown = [n for n in names if not isinstance(n, str) or n not in ALLOWED_CALLBACKS]
        if unknown:
            raise ModelGatewayError(
                f"model gateway: litellm_settings.{key} may name only "
                f"{', '.join(sorted(ALLOWED_CALLBACKS))}, not {unknown!r}: a logging "
                "callback would ship request contents (docs/model-gateway.md)"
            )


def _check_no_cache(settings: dict) -> None:
    """Response caching keeps prompts and answers; only a cache inside the process (gone
    with it) is accepted."""
    params = settings.get("cache_params")
    if params is not None:
        # The proxy's default cache type is redis.
        kind = params.get("type", "redis") if isinstance(params, dict) else params
        if kind not in _PROCESS_CACHE_TYPES:
            raise ModelGatewayError(
                f"model gateway: litellm_settings.cache_params type {kind!r} would store "
                "prompts and answers (docs/model-gateway.md)"
            )
    elif settings.get("cache") not in (None, False):
        raise ModelGatewayError(
            "model gateway: litellm_settings.cache without cache_params type 'local' would "
            "store prompts and answers (docs/model-gateway.md)"
        )


# Log levels of LiteLLM that print request and response bodies.
_PAYLOAD_LOG_LEVELS = frozenset({"DEBUG"})


def check_gateway_env(env: dict[str, str]) -> None:
    """LiteLLM's own environment (ai/litellm/.env) must not raise the log level to one
    that prints request bodies."""
    level = env.get("LITELLM_LOG", "").strip().upper()
    if level in _PAYLOAD_LOG_LEVELS:
        raise ModelGatewayError(
            f"model gateway: LITELLM_LOG={level} in ai/litellm/.env would log request and "
            "response contents; use INFO or higher (docs/model-gateway.md)"
        )


def _alias_entries(model_list: list, env: dict[str, str]) -> tuple[list[dict], list[str]]:
    present = {e.get("model_name") for e in model_list if isinstance(e, dict)}
    added: list[dict] = []
    warnings: list[str] = []
    for alias, variable in ALIASES.items():
        if alias in present:
            continue  # the overlay (or a fragment) defines it itself
        target = env.get(variable, "").strip()
        if not target:
            continue
        sources = [
            e for e in model_list if isinstance(e, dict) and e.get("model_name") == target
        ]
        if not sources:
            warnings.append(
                f"{variable}={target} names no model of LiteLLM's model_list; "
                f"the alias {alias} is not registered"
            )
            continue
        for source in sources:
            entry = copy.deepcopy(source)
            entry["model_name"] = alias
            added.append(entry)
    return added, warnings


def apply(config: dict, env: dict[str, str]) -> tuple[dict, list[str]]:
    """The merged LiteLLM configuration with the no-content settings checked and the
    aliases added; returns it and the warnings for the operator."""
    if not isinstance(config, dict):
        raise ModelGatewayError("model gateway: the configuration must be a mapping")
    _check_no_contents(config)
    model_list = config.get("model_list")
    if model_list is None:
        model_list = []
    if not isinstance(model_list, list):
        raise ModelGatewayError("model gateway: model_list must be a list")
    added, warnings = _alias_entries(model_list, env)
    config["model_list"] = model_list + added
    return config, warnings


def default_model_for(variant: str | None) -> str:
    """The shipped default model for the LocalAI image variant: Q8_0 for an accelerator,
    Q4_K_M otherwise (E-32)."""
    return CPU_DEFAULT if variant in (None, "", "cpu", "auto") else GPU_DEFAULT


# ── what a module needs ─────────────────────────────────────────────────────


def _unknown(found: dict, allowed: frozenset[str], where: str) -> None:
    extra = sorted(str(k) for k in found if k not in allowed)
    if extra:
        raise ModelGatewayError(
            f"{where}: unknown field {', '.join(map(repr, extra))} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )


def _check_need(need: object) -> str:
    """One entry of `models.needs`; returns its alias."""
    if not isinstance(need, dict):
        raise ModelGatewayError(f"models.needs: {need!r} is not a mapping")
    _unknown(need, _NEED_FIELDS, "models.needs")
    alias = need.get("alias")
    if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
        raise ModelGatewayError(f"models.needs: {alias!r} is not an alias (papaia-<purpose>)")
    if "features" in need:
        features = need["features"]
        if not isinstance(features, list) or not all(
            isinstance(f, str) and f in _FEATURES for f in features
        ):
            raise ModelGatewayError(
                f"models.needs[{alias}].features must list only {', '.join(sorted(_FEATURES))}"
            )
    if "min_context" in need:
        context = need["min_context"]
        if isinstance(context, bool) or not isinstance(context, int) or context < _MIN_CONTEXT:
            raise ModelGatewayError(
                f"models.needs[{alias}].min_context must be an integer of at least {_MIN_CONTEXT}"
            )
    if "max_class" in need:
        data_class = need["max_class"]
        if not isinstance(data_class, str) or not _CLASS_RE.fullmatch(data_class):
            raise ModelGatewayError(f"models.needs[{alias}].max_class is not a data class")
    return alias


def module_aliases(manifest: dict) -> list[str]:
    """The aliases a module's manifest declares under `exposes[].models.needs`, sorted.
    Every need is checked; a field the contract does not name is refused."""
    exposes = manifest.get("exposes") if isinstance(manifest, dict) else None
    if exposes is None:
        return []
    if not isinstance(exposes, list):
        raise ModelGatewayError("exposes must be a list")
    aliases: set[str] = set()
    for entry in exposes:
        models = entry.get("models") if isinstance(entry, dict) else None
        if models is None:
            continue
        if not isinstance(models, dict):
            raise ModelGatewayError("models must be a mapping")
        _unknown(models, _MODELS_FIELDS, "models")
        needs = models.get("needs")
        if not isinstance(needs, list):
            raise ModelGatewayError("models.needs must be a list")
        aliases.update(_check_need(need) for need in needs)
    return sorted(aliases)


def key_alias(module: str) -> str:
    return f"module-{module}"


def key_id(key: str) -> str:
    """The id LiteLLM stores for a key (its SHA-256), which names it without revealing it."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _check_module(module: object) -> str:
    if not isinstance(module, str) or len(module) > 64 or not _MODULE_RE.fullmatch(module):
        raise ModelGatewayError(f"{module!r} is not a module name")
    return module


# ── the management connection ─────────────────────────────────────────────


def _run(argv: list[str], stdin: str | None, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Unavailable(f"docker did not answer: {exc}") from None


class Admin:
    """LiteLLM's management API, called inside its container."""

    def __init__(self, container: str, runner: Runner) -> None:
        self.container = container
        self.runner = runner

    def call(self, method: str, path: str, body: object = None) -> tuple[int, object]:
        if not any(method == m and (path == p or (p.endswith("?") and path.startswith(p)))
                   for m, p in _ADMIN_PATHS):
            raise ModelGatewayError(f"{method} {path} is not a key management call")
        request = json.dumps({"method": method, "path": path, "body": body})
        argv = ["docker", "exec", "-i", self.container, "python", "-I", "-c", _ADMIN_SCRIPT]
        result = self.runner(argv, request, EXEC_TIMEOUT_SECONDS)
        lines = (result.stdout or "").strip().splitlines()
        try:
            doc = json.loads(lines[-1]) if result.returncode == 0 and lines else None
        except ValueError:
            doc = None
        if not isinstance(doc, dict) or not doc.get("status"):
            raise Unavailable("LiteLLM did not answer")
        try:
            payload = json.loads(doc.get("body") or "null")
        except ValueError:
            payload = None
        return int(doc["status"]), payload


def connect(config_dir: Path, *, runner: Runner | None = None) -> Admin:
    """The management connection of this installation's running LiteLLM. Raises
    Unavailable when it does not run on this host."""
    runner = runner or _run
    env = common.parse_env_file(Path(config_dir) / ".env")
    project = env.get("COMPOSE_PROJECT_NAME") or "papaia"
    result = runner(
        [
            "docker", "ps", "-q",
            "--filter", f"label=com.docker.compose.project={project}",
            "--filter", f"label=com.docker.compose.service={SERVICE}",
            "--filter", "status=running",
        ],
        None,
        DOCKER_TIMEOUT_SECONDS,
    )  # fmt: skip
    ids = (result.stdout or "").split() if result.returncode == 0 else []
    if len(ids) != 1:
        raise Unavailable("LiteLLM does not run on this host")
    return Admin(ids[0], runner)


class Offline:
    """Stands in for a LiteLLM that does not run here: every call is Unavailable."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def call(self, method: str, path: str, body: object = None) -> tuple[int, object]:
        raise Unavailable(self.reason)


def admin_for(config_dir: Path):
    """The management connection, or an Offline one when LiteLLM does not run here."""
    try:
        return connect(config_dir)
    except Unavailable as exc:
        return Offline(str(exc))


def wait_ready(admin, timeout: int = 120) -> None:
    """Wait until LiteLLM answers its readiness check (database connected)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            status, _ = admin.call("GET", "/health/readiness")
            if status == 200:
                return
        except Unavailable:
            pass
        if time.monotonic() >= deadline:
            raise Unavailable(f"LiteLLM was not ready within {timeout}s")
        time.sleep(2)


# ── journal and audit ───────────────────────────────────────────────────────


def _lifecycle_module(repo_root: Path):
    """The erasure journal writer of papaia-lifecycle, so both write one format. Taken
    from the checkout this tool runs from, which ships the service's code."""
    path = Path(__file__).resolve().parents[2] / _LIFECYCLE
    name = "papaia_lifecycle_journal"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ModelGatewayError(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    # No bytecode cache next to the service's code in the checkout.
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        sys.modules[name] = module
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    finally:
        sys.dont_write_bytecode = keep
    return module


def _journal(config_dir: Path, repo_root: Path):
    """The writer of the journal `model-gateway`, or None without the lifecycle profile
    (no erasure journal at all). The local copy lives in the configuration directory."""
    env = common.parse_env_file(Path(config_dir) / ".env")
    if "lifecycle" not in common.cluster_profiles(env):
        return None
    backup = env.get("PAPAIA_BACKUP_DIR", "")
    if not backup or not Path(backup).is_absolute():
        raise ModelGatewayError("the erasure journal needs an absolute PAPAIA_BACKUP_DIR")
    lifecycle = _lifecycle_module(repo_root)
    try:
        key = lifecycle.read_erasure_key(Path(config_dir) / "security" / "erasure-hmac")
    except lifecycle.LifecycleError as exc:
        raise ModelGatewayError(f"erasure journal: {exc}") from None
    local = Path(config_dir) / JOURNAL_LOCAL_DIR
    local.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return lifecycle.ErasureJournal(
        JOURNAL_SOURCE,
        key=key,
        target_dir=Path(backup) / "erasure-journal",
        local_dir=local,
    )


def _journal_revocation(config_dir: Path, repo_root: Path, module: str, token: str,
                        reason: str) -> str | None:
    """Write `key_revoke` for one key; returns `model-gateway:<seq>` or None without a
    journal. A journal that cannot take the entry stops the revocation."""
    journal = _journal(config_dir, repo_root)
    if journal is None:
        return None
    lifecycle = _lifecycle_module(repo_root)
    try:
        entry = journal.record(
            "key_revoke", object_ref=token, sub=key_alias(module), reason=reason
        )
    except lifecycle.LifecycleError as exc:
        raise ModelGatewayError(f"erasure journal: {exc}") from None
    return f"{entry['module']}:{entry['seq']}"


def _audit(config_dir: Path, event: str, detail: dict, correlation: str) -> None:
    command = "addon-uninstall" if detail.get("reason") == "addon_uninstall" else "model-key"
    images.append_audit(config_dir, images._row(command, event, detail, correlation))


def new_correlation(value: str | None = None) -> str:
    """The correlation id of one command run (the given one, checked, or a new one), so
    every audit row of that run carries the same id."""
    try:
        return images.correlation_id(value)
    except images.ImageError as exc:
        raise ModelGatewayError(str(exc)) from None


# ── module keys ─────────────────────────────────────────────────────────────


def _env_path(config_dir: Path, module: str) -> Path:
    return Path(config_dir) / "addons" / module / ".env"


def _current_key(config_dir: Path, module: str) -> str | None:
    value = common.parse_env_file(_env_path(config_dir, module)).get(KEY_VAR, "").strip()
    return None if value in _PLACEHOLDERS else value


def _write_key(config_dir: Path, module: str, key: str | None) -> None:
    path = _env_path(config_dir, module)
    values = common.parse_env_file(path)
    if key is None:
        if KEY_VAR not in values:
            return
        lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().partition("=")[0].strip() != KEY_VAR
        ]
        text = "\n".join(lines) + ("\n" if lines else "")
    else:
        values[KEY_VAR] = key
        common.write_env_file(path, values)
        text = path.read_text(encoding="utf-8")
    common.atomic_write(path, text)
    os.chmod(path, 0o600)


def _listed(admin, module: str) -> list[dict]:
    path = f"/key/list?key_alias={quote(key_alias(module))}&return_full_object=true"
    status, body = admin.call("GET", path)
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise ModelGatewayError(f"LiteLLM refused to list the keys of {module} ({status})")
    rows = []
    for row in body["keys"]:
        if isinstance(row, dict) and isinstance(row.get("token"), str) and _TOKEN_RE.fullmatch(
            row["token"]
        ) and row.get("key_alias") == key_alias(module):
            rows.append(row)
    return rows


def _delete(admin, tokens: list[str]) -> None:
    status, _ = admin.call("POST", "/key/delete", {"keys": tokens})
    if status not in (200, 404):  # 404: none of them exists (any more)
        raise ModelGatewayError(f"LiteLLM refused to delete a key ({status})")


def _revoke_tokens(config_dir, repo_root, admin, module, tokens, reason, correlation) -> None:
    for token in tokens:
        place = _journal_revocation(config_dir, repo_root, module, token, reason)
        _delete(admin, [token])
        _audit(config_dir, "model_key_revoked",
               {"module": module, "key_alias": key_alias(module), "key_id": token,
                "reason": reason, "journal": place}, correlation)


def ensure_module_key(config_dir: Path, repo_root: Path, module: str, aliases: list[str],
                      admin, *, correlation: str | None = None) -> str:
    """Give `module` a key for exactly `aliases`. Returns `none` (no need, no key),
    `unchanged`, `created`, `replaced`, `revoked` (the need is gone) or `unavailable`
    (LiteLLM does not answer). With `unavailable` the `.env` keeps its key, unless LiteLLM
    stopped after old keys were deleted: then the key leaves the `.env`, so no add-on
    starts with a deleted key (a key cannot be made before the old one goes, since LiteLLM
    keeps key aliases unique)."""
    module = _check_module(module)
    correlation = new_correlation(correlation)
    for alias in aliases:
        if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
            raise ModelGatewayError(f"{alias!r} is not an alias")
    wanted = sorted(set(aliases))
    current = _current_key(config_dir, module)
    if not wanted:
        if current is None:
            return "none"
        return revoke_module_key(config_dir, repo_root, module, admin,
                                 reason="model_need_removed", correlation=correlation)
    stale: list[str] = []
    try:
        rows = _listed(admin, module)
        current_id = key_id(current) if current else None
        matching = [r for r in rows if r["token"] == current_id]
        if matching and len(rows) == 1 and sorted(matching[0].get("models") or []) == wanted:
            return "unchanged"
        stale = [r["token"] for r in rows]
        _revoke_tokens(config_dir, repo_root, admin, module, stale, "key_replaced", correlation)
        status, body = admin.call("POST", "/key/generate", {
            "key_alias": key_alias(module),
            "models": wanted,
            "metadata": {"tags": [f"module:{module}"]},
        })
    except Unavailable:
        if stale and current is not None:
            _write_key(config_dir, module, None)
        return "unavailable"
    key = body.get("key") if isinstance(body, dict) else None
    if status != 200 or not isinstance(key, str) or not key.startswith("sk-"):
        raise ModelGatewayError(f"LiteLLM refused to make the key of {module} ({status})")
    _write_key(config_dir, module, key)
    _audit(config_dir, "model_key_created",
           {"module": module, "key_alias": key_alias(module), "key_id": key_id(key),
            "models": wanted}, correlation)
    return "replaced" if stale else "created"


def _pending_item(item: object) -> bool:
    return (
        isinstance(item, dict)
        and set(item) == _PENDING_FIELDS
        and isinstance(item["key_id"], str)
        and bool(_TOKEN_RE.fullmatch(item["key_id"]))
        and isinstance(item["module"], str)
        and len(item["module"]) <= 64
        and bool(_MODULE_RE.fullmatch(item["module"]))
    )


def pending_revocations(config_dir: Path) -> list[dict[str, str]]:
    """The revocations kept while LiteLLM was down: `{key_id, module}` each."""
    path = Path(config_dir) / PENDING_FILE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        raise ModelGatewayError(f"{path} cannot be read: {exc}") from None
    items = doc.get("tokens") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not all(_pending_item(t) for t in items):
        raise ModelGatewayError(f"{path} is malformed")
    return items


def _save_pending(config_dir: Path, items: list[dict[str, str]]) -> None:
    path = Path(config_dir) / PENDING_FILE
    if not items:
        path.unlink(missing_ok=True)
        return
    unique = {(i["key_id"], i["module"]) for i in items}
    doc = {"tokens": [{"key_id": t, "module": m} for t, m in sorted(unique)]}
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    common.atomic_write(path, json.dumps(doc) + "\n")
    os.chmod(path, 0o600)


def revoke_module_key(config_dir: Path, repo_root: Path, module: str, admin, *, reason: str,
                      correlation: str | None = None) -> str:
    """Revoke the key of `module` (journal entry first, then the deletion) and take it out
    of the `.env`. Returns `none` (it has none), `revoked`, or `pending` when LiteLLM does
    not answer: the entry is journaled and the deletion is done by the next `sync`."""
    module = _check_module(module)
    correlation = new_correlation(correlation)
    current = _current_key(config_dir, module)
    tokens = [key_id(current)] if current else []
    try:
        rows = _listed(admin, module)
        tokens = sorted(set(tokens) | {r["token"] for r in rows})
    except Unavailable:
        if not tokens:
            return "none"
        token = tokens[0]
        place = _journal_revocation(config_dir, repo_root, module, token, reason)
        _save_pending(
            config_dir, pending_revocations(config_dir) + [{"key_id": token, "module": module}]
        )
        _write_key(config_dir, module, None)
        _audit(config_dir, "model_key_revocation_pending",
               {"module": module, "key_alias": key_alias(module), "key_id": token,
                "reason": reason, "journal": place}, correlation)
        return "pending"
    if not tokens:
        return "none"
    _revoke_tokens(config_dir, repo_root, admin, module, tokens, reason, correlation)
    _write_key(config_dir, module, None)
    return "revoked"


def sync(config_dir: Path, repo_root: Path, admin, *, correlation: str | None = None
         ) -> tuple[list[str], list[str]]:
    """Delete the revocations kept while LiteLLM was down, then give every active module
    the key its needs call for. Returns the modules whose key changed (their containers
    must be recreated to see it) and the modules whose key could not be checked (a
    malformed manifest or a refused key operation; logged, the others go on). Raises
    Unavailable when LiteLLM stops answering. One correlation id covers every row."""
    from . import deployment

    correlation = new_correlation(correlation)
    pending = pending_revocations(config_dir)
    if pending:
        _delete(admin, [p["key_id"] for p in pending])
        for item in pending:
            _audit(config_dir, "model_key_revoked",
                   {"module": item["module"], "key_alias": key_alias(item["module"]),
                    "key_id": item["key_id"], "reason": "pending_revocation"}, correlation)
        _save_pending(config_dir, [])
    changed: list[str] = []
    failed: list[str] = []
    for addon in deployment.active_addons(deployment.load(config_dir) or {}):
        name = str(addon.get("name"))
        manifest, reason = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, Path(repo_root))
        )
        if manifest is None:
            logger.warning("add-on %s: %s", name, reason)
            continue
        try:
            aliases = module_aliases(manifest)
            if not aliases and _current_key(config_dir, name) is None:
                continue
            outcome = ensure_module_key(config_dir, repo_root, name, aliases, admin,
                                        correlation=correlation)
        except Unavailable:
            raise
        except ModelGatewayError as exc:
            logger.error("add-on %s: model key: %s", name, exc)
            failed.append(name)
            continue
        if outcome == "unavailable":
            raise Unavailable("LiteLLM stopped answering")
        if outcome in ("created", "replaced", "revoked"):
            changed.append(name)
    return changed, failed
