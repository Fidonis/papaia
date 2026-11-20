"""The hosted reference model: a route of LiteLLM to a model outside the stack, allowed in
the test stack only (docs/hosted-test-model.md).

The model the stack ships stays local. A production installation renders no route to a
host outside the stack: an entry of LiteLLM's model_list from any layer (repo base,
profile or add-on fragment, operator overlay) that leaves the stack stops the render.
"Inside the stack" is decided positively: an entry is local only when a provider that
sends to `api_base` addresses a service the rendered stack defines (core compose services
of the active profiles, services of the active add-ons, their aliases) or the native
LocalAI of this host, and names no other endpoint. Everything else is a hosted route. Only
with the test switch `PAPAIA_TEST_EXTERNAL_MODEL=1` in the root .env does the render keep
such a route, and then only when

  * every hosted entry uses a provider that sends to `api_base` only, names its endpoint
    as an `https://host[:port]` URL there and its key as `os.environ/TEST_HOSTED_<NAME>`,
    never the key itself;
  * all hosted entries share exactly one host and port;
  * the key sits in `$PAPAIA_CONFIG_DIR/ai/litellm/test-hosted.env` (mode 0600, nothing
    but the referenced variables), a file no backup archives, and not in
    `ai/litellm/.env`, which every backup carries;
  * the installation runs on one host (the exit runs next to the add-ons on the
    controller, LiteLLM may not).

The render marks each hosted entry `model_info.test_backend: true`; the mark from a layer
is never trusted. papaia-egress then gets one more source, `litellm`, whose allow list is
that one host and port, and a generated override puts LiteLLM on an internal network of
its own with papaia-egress as its HTTP(S) proxy.

With or without the switch, the configuration may not carry a `credential_list` (a
credential can bring its own `api_base` and key) nor set a proxy variable through
`environment_variables` (it would empty the proxy of the override).
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

import yaml

from . import common

FLAG = "PAPAIA_TEST_EXTERNAL_MODEL"
KEY_FILE = "ai/litellm/test-hosted.env"
LITELLM_ENV = "ai/litellm/.env"
LITELLM_CONFIG = "ai/litellm/config.yaml"
SERVICE = "litellm"
# The source name of the gateway at papaia-egress; an add-on cannot take it while the
# hosted route is on.
SOURCE = "litellm"
MARK = "test_backend"
_ENV_REF = re.compile(r"^os\.environ/([A-Z][A-Z0-9_]{0,63})$")
# The namespace of the hosted key: no variable the LiteLLM container sets itself
# (DATABASE_URL, LITELLM_MASTER_KEY, ...) can be sent to the hosted host as its bearer.
_KEY_VAR = re.compile(r"^TEST_HOSTED_[A-Z0-9_]{1,52}$")
# Proxy variables, in any spelling, that environment_variables of the configuration
# may not set: LiteLLM exports them into its process, over the override's values.
_PROXY_VARS = frozenset({"http_proxy", "https_proxy", "no_proxy", "all_proxy"})
_LOCAL_NAMES = ("localhost", "127.0.0.1", "::1")
# A service name in Docker's DNS: a letter first, so never a number or a hex address.
_LABEL = re.compile(r"[a-z](?:[a-z0-9_-]{0,61}[a-z0-9])?")
# Providers whose only endpoint is `api_base`; any other provider may take its endpoint
# from a cloud account, a region or its own default. A local and a hosted entry alike must
# use one of them.
LOCAL_PROVIDERS = frozenset(
    {"openai", "text-completion-openai", "hosted_vllm", "ollama", "ollama_chat"}
)
# litellm_params keys that name or select an endpoint besides `api_base`; a credential
# name pulls api_base and api_key from the credential_list.
_ENDPOINT_KEY = re.compile(
    r"url|endpoint|base|region|location|project|credential|^aws_|^vertex|^azure|^api_version$"
    r"|^watsonx|^databricks|^sagemaker|^bedrock"
)
# The endpoints LiteLLM calls itself for its login; the browser-facing ones it never calls.
_LOGIN_KEYS = ("GENERIC_TOKEN_ENDPOINT", "GENERIC_USERINFO_ENDPOINT")
# Where the root .env names the identity provider the installation is configured with.
_IDP_KEYS = ("OIDC_ISSUER", "OIDC_TOKEN_URL")


class HostedModelError(ValueError):
    """A hosted route the render refuses; the message never carries a key."""


def enabled(env: dict[str, str]) -> bool:
    """The test switch is on only for the exact value `1`."""
    return env.get(FLAG) == "1"


def _root_env(config_dir: Path) -> dict[str, str]:
    return common.parse_env_file(config_dir / ".env")


def _native_api_base(env: dict[str, str]) -> str | None:
    from . import localai_native  # imports gen_override, which imports egress

    if localai_native.runtime(env) != localai_native.NATIVE:
        return None
    return localai_native.api_base(env).rstrip("/")


def _compose_names(path: Path, profiles: set[str] | None) -> set[str]:
    """The names a compose file's services answer to in Docker's DNS: the service name,
    `container_name` and network aliases. With `profiles`, only services that are on."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return set()
    services = doc.get("services") if isinstance(doc, dict) else None
    found: set[str] = set()
    for name, body in (services or {}).items() if isinstance(services, dict) else ():
        body = body if isinstance(body, dict) else {}
        wanted = body.get("profiles") or []
        if profiles is not None and wanted and not profiles.intersection(map(str, wanted)):
            continue
        found.add(str(name))
        if isinstance(body.get("container_name"), str):
            found.add(body["container_name"])
        networks = body.get("networks")
        for net in networks.values() if isinstance(networks, dict) else ():
            aliases = net.get("aliases") if isinstance(net, dict) else None
            found.update(str(a) for a in aliases or [] if isinstance(aliases, list))
    return {n.lower() for n in found if _LABEL.fullmatch(n.lower())}


def stack_names(repo_root: Path, config_dir: Path, active_addons: list[dict]) -> frozenset[str]:
    """Every name a service of the rendered stack answers to: the core compose services of
    the active profiles (and those without a profile) and the services of the active
    add-ons. A short name outside this set is not a service of the stack: Docker's DNS
    forwards it to the host's resolver, whose search domains may reach any host."""
    from . import compat, deployment

    raw = _root_env(config_dir).get("COMPOSE_PROFILES", "")
    profiles = {p.strip() for p in raw.split(",") if p.strip()}
    names: set[str] = set()
    root = repo_root / "src" / "docker-compose.yml"
    if root.is_file():
        for path in compat.compose_files(root):
            names |= _compose_names(path, profiles)
    for addon in active_addons:
        if not addon.get("name"):
            continue  # a profile layer: its services are in the core compose
        path = deployment.resolve_addon_path(addon, repo_root) / "docker-compose.yml"
        names |= _compose_names(path, None)
    return frozenset(names)


def _clean_url(value: object) -> SplitResult | None:
    """The parts of an http(s) URL every client reads alike, or None: printable ASCII
    only, no backslash, no user information, a valid port, and urlsplit gives back the
    very same string."""
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if any(not "\x21" <= char <= "\x7e" for char in value):
        return None
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 -- raises ValueError for a port out of range
    except ValueError:
        return None
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or "@" in parts.netloc
        or parts.geturl() != value
    ):
        return None
    return parts


def _params(entry: object) -> dict | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("litellm_params"), dict):
        return None
    return entry["litellm_params"]


def _provider(params: dict) -> str | None:
    custom = params.get("custom_llm_provider")
    if custom is not None:
        return custom if isinstance(custom, str) else None
    model = params.get("model")
    if not isinstance(model, str) or "/" not in model:
        return None  # LiteLLM would guess the provider from the model name
    return model.split("/", 1)[0]


def _endpoint_keys(params: dict) -> list[str]:
    """Keys besides api_base that name or select an endpoint."""
    return sorted(
        str(key)
        for key in params
        if key != "api_base" and _ENDPOINT_KEY.search(str(key).lower())
    )


def is_local(
    entry: object,
    config_dir: Path,
    env: dict[str, str] | None = None,
    names: frozenset[str] | None = None,
) -> bool:
    """True when the entry routes to a service inside the stack or to the native LocalAI
    of this host. An entry without litellm_params is no route at all.

    Local means all of: a provider whose only endpoint is api_base (LOCAL_PROVIDERS), no
    other endpoint key, and an api_base whose host is one of `names` (stack_names) or the
    exact address of the native LocalAI. With `names` None only the service-name grammar
    is checked; the render, the exit and the override always pass the stack's names.
    Everything else -- no api_base, one from the environment, a name with a domain, an
    address, a short name the stack does not define, a URL clients read differently --
    leaves the stack."""
    params = _params(entry)
    if params is None:
        return True
    if _provider(params) not in LOCAL_PROVIDERS or _endpoint_keys(params):
        return False
    base = params.get("api_base")
    parts = _clean_url(base)
    if parts is None:
        return False
    env = _root_env(config_dir) if env is None else env
    native = _native_api_base(env)
    if native is not None and base.rstrip("/") == native:
        return True
    host = parts.hostname
    if not _LABEL.fullmatch(host):
        return False
    return names is None or host in names


def _name(entry: object) -> str:
    name = entry.get("model_name") if isinstance(entry, dict) else None
    return name if isinstance(name, str) and name else "<unnamed>"


def _endpoint(entry: dict) -> tuple[str, int]:
    """The host and port of a hosted entry, which must be an explicit https URL."""
    from . import egress

    name = _name(entry)
    params = entry["litellm_params"]
    if _provider(params) not in LOCAL_PROVIDERS:
        allowed = ", ".join(f"{p}/" for p in sorted(LOCAL_PROVIDERS))
        raise HostedModelError(
            f"model '{name}': a hosted model needs a provider that sends to api_base only"
            f" ({allowed}), as the model prefix or custom_llm_provider"
        )
    base = params.get("api_base")
    if not isinstance(base, str) or base.startswith("os.environ/"):
        raise HostedModelError(
            f"model '{name}': a hosted model needs api_base as an explicit https://host URL,"
            " so the exit can allow exactly that host"
        )
    others = _endpoint_keys(params)
    if others:
        raise HostedModelError(
            f"model '{name}': litellm_params.{others[0]} names another endpoint; a hosted"
            " model sends only to its api_base"
        )
    parts = _clean_url(base)
    if parts is None or parts.scheme != "https":
        raise HostedModelError(
            f"model '{name}': api_base must be an https://host[:port] URL without user"
            " information"
        )
    if parts.query or parts.fragment:
        # A key in the URL would sit in the rendered file, which every backup carries.
        raise HostedModelError(
            f"model '{name}': api_base must not carry a query or fragment; the key belongs in"
            f" $PAPAIA_CONFIG_DIR/{KEY_FILE}"
        )
    port = parts.port or 443
    try:
        host = egress.allowed_host(parts.hostname)
    except ValueError as exc:
        raise HostedModelError(f"model '{name}': api_base: {exc}") from None
    return host, port


def _key_var(entry: dict) -> str:
    key = entry["litellm_params"].get("api_key")
    match = _ENV_REF.match(key) if isinstance(key, str) else None
    if match is None or not _KEY_VAR.fullmatch(match.group(1)):
        # The value is never repeated: it may be the key itself.
        raise HostedModelError(
            f"model '{_name(entry)}': api_key must be os.environ/TEST_HOSTED_<NAME> (upper"
            f" case), with the key in $PAPAIA_CONFIG_DIR/{KEY_FILE}"
        )
    return match.group(1)


def _owners(config_dir: Path) -> set[int]:
    """Who may own the key file: the user running papaia-ctl and the owner of the
    configuration directory (the installing user, when papaia-ctl runs as root)."""
    return {os.geteuid(), config_dir.stat().st_uid}


def _check_key_file(config_dir: Path, variables: set[str]) -> None:
    path = config_dir / KEY_FILE
    try:
        # lstat: a symbolic link is refused, not followed. The backups leave out the
        # link only; a target inside the configuration directory would be archived.
        info = path.lstat()
    except FileNotFoundError:
        raise HostedModelError(
            f"$PAPAIA_CONFIG_DIR/{KEY_FILE} is missing; it holds the key of the hosted model"
        ) from None
    if not stat.S_ISREG(info.st_mode):
        raise HostedModelError(
            f"$PAPAIA_CONFIG_DIR/{KEY_FILE} must be a regular file, not a symbolic link or"
            " anything else"
        )
    if info.st_uid not in _owners(config_dir):
        raise HostedModelError(
            f"$PAPAIA_CONFIG_DIR/{KEY_FILE} must belong to the user who installed papAIa"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise HostedModelError(f"$PAPAIA_CONFIG_DIR/{KEY_FILE} must have mode 0600")
    keys = common.parse_env_file(path)
    for var in sorted(variables):
        if not keys.get(var):
            raise HostedModelError(f"$PAPAIA_CONFIG_DIR/{KEY_FILE} does not set {var}")
    others = sorted(set(keys) - variables)
    if others:
        # The file is an env_file of LiteLLM: any other variable would change its settings.
        raise HostedModelError(
            f"$PAPAIA_CONFIG_DIR/{KEY_FILE} sets {', '.join(others)}; it may hold only the"
            " keys the hosted models reference"
        )
    backed_up = common.parse_env_file(config_dir / LITELLM_ENV)
    for var in sorted(variables):
        # An empty variable there is no key; the key file, loaded after it, wins.
        if backed_up.get(var):
            raise HostedModelError(
                f"{var} is set in $PAPAIA_CONFIG_DIR/{LITELLM_ENV}, which every backup"
                f" carries; keep it only in $PAPAIA_CONFIG_DIR/{KEY_FILE}"
            )


def _check_settings(config: object) -> None:
    """Top-level keys that would open a route the model_list check does not see."""
    if not isinstance(config, dict):
        return
    if config.get("credential_list"):
        # A credential brings its own api_base and key; an entry would use them over the
        # checked api_base, and a key would sit in the rendered file.
        raise HostedModelError(
            f"{LITELLM_CONFIG}: credential_list is not supported; give each model its"
            " api_base and api_key: os.environ/<VAR>"
        )
    variables = config.get("environment_variables")
    if isinstance(variables, dict):
        found = sorted(str(k) for k in variables if str(k).lower() in _PROXY_VARS)
        if found:
            raise HostedModelError(
                f"{LITELLM_CONFIG}: environment_variables may not set {', '.join(found)}; the"
                " proxy of LiteLLM is set by the render"
            )


def guard(config: dict, config_dir: Path, names: frozenset[str]) -> dict:
    """LiteLLM's merged configuration as the render may write it. Raises HostedModelError
    for a hosted route without the test switch, or one the test stack cannot use. `names`
    are the service names of the rendered stack (stack_names)."""
    from . import topology

    _check_settings(config)
    models = config.get("model_list") if isinstance(config, dict) else None
    if not isinstance(models, list):
        return config
    env = _root_env(config_dir)
    hosted = []
    for entry in models:
        if isinstance(entry, dict) and isinstance(entry.get("model_info"), dict):
            entry["model_info"].pop(MARK, None)  # only the render decides
            if not entry["model_info"]:
                del entry["model_info"]
        if not is_local(entry, config_dir, env, names):
            hosted.append(entry)
    if not hosted:
        return config
    names = ", ".join(f"'{_name(e)}'" for e in hosted)
    if not enabled(env):
        raise HostedModelError(
            f"{LITELLM_CONFIG}: model(s) {names} route outside the stack. A hosted model is"
            f" allowed only in the test stack ({FLAG}=1 in $PAPAIA_CONFIG_DIR/.env); the"
            " shipped model stays local"
        )
    if topology.is_distributed(config_dir):
        raise HostedModelError(
            f"{FLAG}=1: the hosted test model runs on a single host only, not on a"
            " distributed installation"
        )
    endpoints = {_endpoint(e) for e in hosted}
    if len(endpoints) != 1:
        found = ", ".join(f"{h}:{p}" for h, p in sorted(endpoints))
        raise HostedModelError(
            f"{LITELLM_CONFIG}: the hosted models must share one host and port, found {found}"
        )
    _check_key_file(config_dir, {_key_var(e) for e in hosted})
    for entry in hosted:
        info = entry.get("model_info")
        entry["model_info"] = {**(info if isinstance(info, dict) else {}), MARK: True}
    return config


def _rendered_models(config_dir: Path) -> list:
    path = config_dir / LITELLM_CONFIG
    if not path.is_file():
        return []
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return []
    models = config.get("model_list") if isinstance(config, dict) else None
    return models if isinstance(models, list) else []


def rendered_stack_names(config_dir: Path, repo_root: Path | None) -> frozenset[str]:
    """stack_names of the installation as the render sees it: the active profile layers
    and add-ons of deployment.yaml, add-on paths relative to `repo_root` (else the
    working directory, as gen_override and egress resolve them)."""
    from . import deployment

    base = repo_root if repo_root is not None else Path.cwd()
    addons = deployment.active_addons(deployment.load(config_dir))
    return stack_names(base, config_dir, addons)


def route(config_dir: Path, names: frozenset[str]) -> tuple[str, int] | None:
    """The one host and port the rendered configuration sends the hosted model to, or
    None without the test switch or without a hosted entry. Read from the rendered file
    and classified again against the stack's `names`, not taken from the mark: the
    rendered file is not trusted, a hand edit after the render cannot add a local route."""
    env = _root_env(config_dir)
    if not enabled(env):
        return None
    hosted = [
        e for e in _rendered_models(config_dir) if not is_local(e, config_dir, env, names)
    ]
    if not hosted:
        return None
    endpoints = {_endpoint(e) for e in hosted}
    if len(endpoints) != 1:
        raise HostedModelError(f"{LITELLM_CONFIG}: the hosted models must share one host")
    return next(iter(endpoints))


def network(env: dict[str, str]) -> str:
    project = env.get("PAPAIA_PROJECT") or env.get("COMPOSE_PROJECT_NAME") or "papaia"
    return f"{project}-{SOURCE}-egress"


def override_path(config_dir: Path) -> Path:
    return config_dir / "overrides" / f"docker-compose.{SERVICE}.hosted-model.override.yml"


def _no_proxy(config_dir: Path, host: str, stack: frozenset[str]) -> str:
    """The names LiteLLM reaches without the proxy: itself, the model services inside the
    stack, and the host of its login -- the token and userinfo endpoints, and only where
    they point at the identity provider the root .env configures (bundled Keycloak or the
    external issuer). Everything else goes to papaia-egress, which allows only the hosted
    model."""
    names = set(_LOCAL_NAMES)
    env = _root_env(config_dir)
    idp: set[str] = set()
    for key in _IDP_KEYS:
        parts = _clean_url(env.get(key))
        if parts is not None:
            idp.add(parts.hostname)
    for entry in _rendered_models(config_dir):
        params = _params(entry)
        if params is None or not is_local(entry, config_dir, env, stack):
            continue
        try:
            found = urlsplit(str(params["api_base"])).hostname
        except ValueError:
            continue
        if found:
            names.add(found.lower())
    login = common.parse_env_file(config_dir / LITELLM_ENV)
    for key in _LOGIN_KEYS:
        parts = _clean_url(login.get(key))
        if parts is not None and parts.hostname in idp:
            names.add(parts.hostname)
    names.discard(host)
    return ",".join(sorted(names))


def generate_override(config_dir: Path, repo_root: Path | None = None) -> Path | None:
    """Write the override that puts LiteLLM behind papaia-egress while the hosted route
    is on; remove it otherwise."""
    from . import egress

    out = override_path(config_dir)
    names = rendered_stack_names(config_dir, repo_root)
    found = route(config_dir, names)
    if found is None:
        out.unlink(missing_ok=True)
        return None
    env = _root_env(config_dir)
    net = network(env)
    proxy = f"http://{egress.alias(SOURCE)}:{egress.PORT}"
    no_proxy = _no_proxy(config_dir, found[0], names)
    override = {
        "services": {
            SERVICE: {
                "env_file": [{"path": f"${{PAPAIA_CONFIG_DIR}}/{KEY_FILE}", "required": True}],
                # HTTP_PROXY as well: plain http to a host outside the stack is then
                # denied at the exit instead of sent directly over papaia-net.
                "environment": {
                    "HTTPS_PROXY": proxy,
                    "https_proxy": proxy,
                    "HTTP_PROXY": proxy,
                    "http_proxy": proxy,
                    "NO_PROXY": no_proxy,
                    "no_proxy": no_proxy,
                },
                # `papaia-net` is the key of the core network in the compose files.
                "networks": {"papaia-net": {}, net: {}},
            },
            egress.SERVICE: {
                "networks": {
                    egress.EGRESS_NETWORK: {},
                    net: {"aliases": [egress.alias(SOURCE)]},
                }
            },
        },
        "networks": {net: {"name": net, "internal": True}},
    }
    common.atomic_write(out, yaml.safe_dump(override, sort_keys=False, default_flow_style=False))
    return out


def egress_source(config_dir: Path, repo_root: Path | None = None) -> dict | None:
    """The source of LiteLLM at papaia-egress while the hosted route is on."""
    from . import egress

    found = route(config_dir, rendered_stack_names(config_dir, repo_root))
    if found is None:
        return None
    host, port = found
    return {
        "name": SOURCE,
        "alias": egress.alias(SOURCE),
        "allow": [{"host": host, "ports": [port]}],
        "internal": [],
    }
