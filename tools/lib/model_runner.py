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
