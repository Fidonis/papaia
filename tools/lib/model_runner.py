"""Docker Model Runner: the model list, host detection and the runner's API.

Docker Desktop runs the Model Runner on the host (llama.cpp with Metal, MLX through
vllm-metal) and serves it to containers at `model-runner.docker.internal`. The stack's
`model-runner` module only pulls the models of its `models.txt` there and registers them in
LiteLLM; see docs/adr/0011-local-inference-on-apple-silicon-through-docker-model-runner.md.

Like `gpu_detect`, detection and everything else are split. `detect()` forks `docker` and
runs during `papaia-ctl setup` only. Parsing the model list is pure,
so a render never blocks on Docker. The runner itself is reached two ways: through the
`docker model` CLI plugin on the host, and through its HTTP API from inside a container
(papaia-manager), where the plugin does not exist.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

PROFILE = "model-runner"
MODELS_FILE = "ai/model-runner/models.txt"

# The address Docker Desktop gives the runner inside every container. Docker Engine on
# Linux serves it on port 12434 behind an `extra_hosts` entry instead; that host is out
# of scope (ADR 0011), so the address is fixed rather than configurable.
BASE_URL = "http://model-runner.docker.internal"
OPENAI_BASE_URL = f"{BASE_URL}/engines/v1"

# What `docker model pull` accepts, and nothing a shell or a URL path would read
# differently. The init job applies the same character set.
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")

# Docker Desktop release that brought MLX models through vllm-metal.
MIN_DESKTOP_FOR_VLLM = (4, 62)
_DESKTOP_VERSION_RE = re.compile(r"Docker Desktop (\d+)\.(\d+)(?:\.(\d+))?")


# ─────────────────────────────────────────────────────────────────────────
# Model list (pure, safe on every render)


@dataclass(frozen=True)
class Model:
    reference: str  # as written in models.txt
    alias: str  # the name LiteLLM shows

    @property
    def is_mlx(self) -> bool:
        """Whether the model needs vllm-metal. Docker Hub marks MLX tags with `-mlx`;
        on Hugging Face the mlx-community organisation publishes nothing else."""
        ref = self.reference.lower()
        return "-mlx" in ref or "/mlx-community/" in ref


@dataclass
class ModelList:
    models: list[Model] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # "line N: why", for doctor and render


def default_alias(reference: str) -> str:
    """The reference's last path segment: `ai/qwen3:4b` -> `qwen3:4b`."""
    return reference.rstrip("/").rsplit("/", 1)[-1]


def parse_models(text: str) -> ModelList:
    """Read models.txt: `<reference> [<alias>]` per line, `#` comments, blank lines.

    A malformed line is reported and left out rather than failing the whole list, the
    way the init job skips it. A second line with the same alias is reported too: LiteLLM
    would route the name to either model."""
    result = ModelList()
    seen: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        reference = parts[0]
        if not _REFERENCE_RE.match(reference):
            result.errors.append(f"line {number}: {reference!r} is not a model reference")
            continue
        alias = parts[1] if len(parts) > 1 else default_alias(reference)
        if len(parts) > 2:
            result.errors.append(f"line {number}: only a reference and an alias are read")
        if not _ALIAS_RE.match(alias):
            result.errors.append(f"line {number}: {alias!r} is not a usable model name")
            continue
        if alias in seen:
            result.errors.append(
                f"line {number}: the name {alias!r} is already used on line {seen[alias]}"
            )
            continue
        seen[alias] = number
        result.models.append(Model(reference=reference, alias=alias))
    return result


def litellm_entries(models: list[Model]) -> list[dict]:
    """LiteLLM `model_list` entries for the models, in list order.

    The `openai/` provider sends the rest of the name as the request's `model`, which is
    the reference as models.txt holds it; the runner resolves that form itself. The runner
    takes no key, but LiteLLM's OpenAI client refuses to send a request without one."""
    return [
        {
            "model_name": model.alias,
            "litellm_params": {
                "model": f"openai/{model.reference}",
                "api_base": OPENAI_BASE_URL,
                "api_key": "not-needed",
            },
        }
        for model in models
    ]


def normalise(reference: str) -> str:
    """The name the runner lists a model under: `ai/x` -> `docker.io/ai/x:latest`,
    `hf.co/Org/Repo` -> `huggingface.co/org/repo:latest`.

    The runner reports pulled models in this form (`GET /models` tags, `/engines/v1/models`
    ids), while models.txt holds what the operator typed."""
    ref = reference
    name, _, digest = ref.partition("@")
    last = name.rsplit("/", 1)[-1]
    if ":" not in last and not digest:
        name = f"{name}:latest"
    first = name.split("/", 1)[0]
    if first in ("hf.co", "huggingface.co"):
        name = "huggingface.co/" + name.split("/", 1)[1].lower()
    elif "." not in first and ":" not in first and first != "localhost":
        name = f"docker.io/{name}"
    return f"{name}@{digest}" if digest else name


# ─────────────────────────────────────────────────────────────────────────
# Runner access: the CLI plugin on the host, the HTTP API in a container


def run_command(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str] | None:
    """Run a probe. None when the binary is missing or the call times out."""
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


class RunnerError(Exception):
    """The runner could not be asked, or refused."""


def http_request(
    method: str, path: str, *, body: dict | None = None, timeout: float = 10.0
) -> tuple[int, str]:
    """One request against the runner's API from inside a container. (status, body)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(  # noqa: S310 - fixed scheme and host
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RunnerError(f"{BASE_URL} does not answer: {getattr(exc, 'reason', exc)}") from exc


def model_path(reference: str) -> str:
    """The URL path of one model in the native API; the reference keeps its slashes."""
    return "/models/" + urllib.parse.quote(reference, safe="/:@")


def remove_model(
    reference: str,
    *,
    in_container: bool,
    run: Callable[..., subprocess.CompletedProcess[str] | None] = run_command,
    request: Callable[..., tuple[int, str]] = http_request,
) -> bool:
    """Remove one model from the runner. True when it was there and is gone, False when it
    was not there; RunnerError otherwise."""
    if in_container:
        status, text = request("DELETE", model_path(reference))
        if status == 404:
            return False
        if status >= 300:
            raise RunnerError(f"{reference}: {text.strip()[:200] or status}")
        return True
    done = run(["docker", "model", "rm", reference], 60.0)
    if done is None:
        raise RunnerError("the docker model plugin did not answer")
    if done.returncode == 0:
        return True
    message = (done.stderr or done.stdout).strip()
    # `docker model rm` says "no such model"; the API, behind it, "model not found".
    if "no such model" in message.lower() or "not found" in message.lower():
        return False
    raise RunnerError(f"{reference}: {message.splitlines()[-1][:200] if message else 'failed'}")


# ─────────────────────────────────────────────────────────────────────────
# Detection (setup-time only)


@dataclass
class Detection:
    available: bool = False
    label: str = ""  # what was found, or why the runner is not offered
    desktop_version: str = ""  # "4.95.0", empty when not Docker Desktop
    engines: dict[str, str] = field(default_factory=dict)  # engine -> status text
    warning: str = ""  # an unmet prerequisite that does not disqualify

    @property
    def running_engines(self) -> list[str]:
        return [name for name, state in self.engines.items() if state.startswith("Running")]


def desktop_version(text: str) -> tuple[int, int, int] | None:
    match = _DESKTOP_VERSION_RE.search(text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def parse_status(text: str) -> tuple[bool, dict[str, str]]:
    """`docker model status --json` -> (running, engine -> status)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False, {}
    if not isinstance(data, dict):
        return False, {}
    backends = data.get("backends") if isinstance(data.get("backends"), dict) else {}
    return bool(data.get("running")), {str(k): str(v) for k, v in backends.items()}


def detect(
    *,
    system: str | None = None,
    machine: str | None = None,
    run: Callable[..., subprocess.CompletedProcess[str] | None] = run_command,
) -> Detection:
    """Whether this host can run the `model-runner` module. Never raises.

    Only Apple Silicon under Docker Desktop qualifies: Intel Macs have no Metal path the
    runner uses, and Docker Engine serves the runner on another address (ADR 0011)."""
    system = system if system is not None else platform.system()
    machine = machine if machine is not None else platform.machine()
    if system != "Darwin":
        return Detection(label="Docker Model Runner is offered on Apple Silicon Macs only")
    if machine != "arm64":
        return Detection(label="Docker Model Runner needs an Apple Silicon Mac")

    found = Detection()
    version = run(["docker", "version", "--format", "{{.Server.Platform.Name}}"], 10.0)
    parsed = desktop_version(version.stdout if version and version.returncode == 0 else "")
    if parsed is None:
        found.label = "Docker Desktop not found (Docker Model Runner is part of it)"
        return found
    found.desktop_version = ".".join(str(part) for part in parsed)

    status = run(["docker", "model", "status", "--json"], 15.0)
    if status is None or (status.returncode != 0 and not status.stdout.strip()):
        found.label = (
            f"Docker Desktop {found.desktop_version}, but the docker model plugin did not"
            " answer; enable Docker Model Runner in Settings > AI"
        )
        return found
    running, engines = parse_status(status.stdout)
    found.engines = engines
    if not running:
        found.label = (
            f"Docker Desktop {found.desktop_version}, Docker Model Runner is switched off;"
            " enable it in Settings > AI"
        )
        return found

    found.available = True
    serving = found.running_engines
    found.label = f"Docker Desktop {found.desktop_version}, engines: " + (
        ", ".join(serving) if serving else "none running yet"
    )
    if "vllm" not in serving:
        if parsed[:2] < MIN_DESKTOP_FOR_VLLM:
            found.warning = (
                "MLX models need Docker Desktop 4.62 or newer; GGUF models run as they are"
            )
        else:
            found.warning = (
                "MLX models need the vllm engine: docker model install-runner --backend vllm"
            )
    return found


def detection_vars(detection: Detection) -> dict[str, str]:
    """Flatten a Detection into the KEY=VALUE map the bash wizard reads."""
    return {
        "MODEL_RUNNER_AVAILABLE": "true" if detection.available else "false",
        "MODEL_RUNNER_LABEL": detection.label,
        "MODEL_RUNNER_WARN": detection.warning,
        "MODEL_RUNNER_DESKTOP_VERSION": detection.desktop_version,
        "MODEL_RUNNER_ENGINES": ",".join(detection.running_engines),
    }


# ─────────────────────────────────────────────────────────────────────────
# Runner state, for `doctor` and `status`

# The port Docker Desktop serves the runner on when host-side TCP is on. `docker desktop
# enable model-runner` switches it on with this port unless told otherwise.
HOST_TCP_PORT = 12434

_COLUMNS_RE = re.compile(r"\s{2,}")


@dataclass
class RunnerState:
    reachable: bool
    reason: str = ""  # why not, when not reachable
    engines: dict[str, str] = field(default_factory=dict)  # engine -> status text
    models: list[dict] = field(default_factory=list)  # {name, tags, format, size}
    loaded: list[dict] = field(default_factory=list)  # {model, engine, mode}
    source: str = ""  # "cli" on the host, "api" inside a container

    @property
    def running_engines(self) -> list[str]:
        return [name for name, state in self.engines.items() if state.startswith("Running")]

    def tags(self) -> set[str]:
        return {tag for model in self.models for tag in model["tags"]}

    def missing(self, models: list[Model]) -> list[str]:
        """The references of `models` the runner does not have."""
        present = self.tags()
        return [m.reference for m in models if normalise(m.reference) not in present]

    def to_dict(self) -> dict:
        return {
            "reachable": self.reachable,
            "reason": self.reason or None,
            "source": self.source,
            "engines": self.engines,
            "models": self.models,
            "loaded": self.loaded,
        }


def _model_entries(data) -> list[dict]:
    """`GET /models` and `docker model list --json`, which share their shape."""
    entries = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        tags = [str(t) for t in item.get("tags") or []]
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        entries.append(
            {
                "name": tags[0] if tags else str(item.get("id", "")),
                "tags": tags,
                "format": str(config.get("format", "")),
                "size": str(config.get("size", "")),
            }
        )
    return entries


def _loaded_from_api(data) -> list[dict]:
    return [
        {
            "model": str(item.get("model_name", "")),
            "engine": str(item.get("backend_name", "")),
            "mode": str(item.get("mode", "")),
        }
        for item in (data if isinstance(data, list) else [])
        if isinstance(item, dict)
    ]


def parse_ps_table(text: str) -> list[dict]:
    """`docker model ps`, which has no JSON output: MODEL NAME, BACKEND, MODE, UNTIL."""
    rows = []
    lines = [line for line in (text or "").splitlines() if line.strip()]
    for line in lines[1:] if lines and lines[0].startswith("MODEL") else lines:
        columns = _COLUMNS_RE.split(line.strip())
        if len(columns) >= 3:
            rows.append({"model": columns[0], "engine": columns[1], "mode": columns[2]})
    return rows


def _json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def probe(
    *,
    in_container: bool,
    run: Callable[..., object] = run_command,
    request: Callable[..., tuple[int, str]] = http_request,
) -> RunnerState:
    """Ask the runner what it has. Never raises.

    On the host through the `docker model` plugin, inside a container (papaia-manager,
    which has no plugin) through the runner's API. `run` may return a CompletedProcess
    or anything with returncode, stdout and stderr, or None when nothing could run."""
    if in_container:
        try:
            status, body = request("GET", "/engines/status")
        except RunnerError as exc:
            return RunnerState(False, str(exc), source="api")
        if status != 200:
            return RunnerState(False, f"{BASE_URL} answered {status}", source="api")
        state = RunnerState(True, source="api")
        engines = _json(body)
        state.engines = (
            {str(k): str(v) for k, v in engines.items()} if isinstance(engines, dict) else {}
        )
        for path, attr, parse in (
            ("/models", "models", _model_entries),
            ("/engines/ps", "loaded", _loaded_from_api),
        ):
            try:
                code, text = request("GET", path)
            except RunnerError:
                continue
            if code == 200:
                setattr(state, attr, parse(_json(text)))
        return state

    done = run(["docker", "model", "status", "--json"], 15.0)
    if done is None or getattr(done, "returncode", 127) == 127:
        return RunnerState(False, "the docker model plugin is not installed", source="cli")
    running, engines = parse_status(getattr(done, "stdout", ""))
    if not running:
        return RunnerState(
            False, "Docker Model Runner is not running", engines=engines, source="cli"
        )
    state = RunnerState(True, engines=engines, source="cli")
    listed = run(["docker", "model", "list", "--json"], 15.0)
    if listed is not None and getattr(listed, "returncode", 1) == 0:
        state.models = _model_entries(_json(getattr(listed, "stdout", "")))
    ps = run(["docker", "model", "ps"], 15.0)
    if ps is not None and getattr(ps, "returncode", 1) == 0:
        state.loaded = parse_ps_table(getattr(ps, "stdout", ""))
    return state
