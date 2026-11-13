"""LocalAI as a host process on an Apple Silicon Mac (`LOCALAI_RUNTIME=native`).

Docker Desktop's Linux VM has no access to the Apple GPU, so a LocalAI container on a Mac
always runs on the CPU. LocalAI publishes a signed macOS binary with every release; run
natively, it uses Metal with the same model list and the same LiteLLM registration as the
container (docs/adr/0012-serve-local-inference-on-apple-silicon-through-a-native-localai.md).

Everything lives below one directory per installation, `localai_home`:

    <PAPAIA_WORKSPACE_DIR>/localai/<COMPOSE_PROJECT_NAME>/
        bin/local-ai-<version>   the verified binary of the pinned release
        run-localai              the start script (mode 0700, no key inside)
        models/                  model files and YAMLs (bind-mounted into the init job)
        backends/                the Metal backend LocalAI downloads on its first start
        data/, configuration/    LocalAI's own state (written into its working directory)
        logs/localai.log         stdout and stderr of the launchd job

It lies outside $PAPAIA_CONFIG_DIR, which the backup archives in full, and below /Users,
which Docker Desktop shares with its VM (the init job writes the models there).

launchd runs the process as a LaunchAgent of the logged-in user,
`~/Library/LaunchAgents/de.fidonis.papaia.<COMPOSE_PROJECT_NAME>.localai.plist`, so it
survives the shell that started it and comes back after a login. `start` enables and loads
the job, `stop` unloads and disables it: a stopped stack stays stopped after a restart.
"""

from __future__ import annotations

import hashlib
import os
import platform
import plistlib
import re
import shlex
import shutil
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from . import common, gen_override, status

RUNTIME_KEY = "LOCALAI_RUNTIME"
CONTAINER = "container"
NATIVE = "native"
RUNTIMES = (CONTAINER, NATIVE)

OVERRIDE_NAME = "docker-compose.localai-runtime.override.yml"

RELEASE_BASE = "https://github.com/mudler/LocalAI/releases/download"
_ASSET = "local-ai-{version}-darwin-arm64"
_CHECKSUMS = "LocalAI-{version}-checksums.txt"
_BINARY_PREFIX = "local-ai-"

# What `setup` puts into the overlay model list when the runtime becomes native: one chat
# model and the embedding model RAG_EMBEDDINGS_MODEL names. Qwen2.5-7B (Q5_K_M, 5.4 GB)
# because it runs at about 58 tokens/s on Metal and fits a 16 GB Mac next to the stack
# (ADR 0012); the 1.5B line of the shipped list stays available for smaller machines.
NATIVE_DEFAULT_MODELS = (
    "https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/"
    "Qwen2.5-7B-Instruct-Q5_K_M.gguf",
    "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/"
    "nomic-embed-text-v1.5.Q8_0.gguf",
)

_MODELS_OVERLAY = "overlay/ai/localai/models.txt"
_SHIPPED_MODELS = "src/ai/localai/models.txt"

DOWNLOAD_TIMEOUT_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 3
_CHUNK = 1 << 20

Opener = Callable[[str], IO[bytes]]


class InstallError(Exception):
    """A binary that could not be installed: the network, the checksum, the pin."""


class LaunchdError(Exception):
    """A launchctl call that failed; the message carries what launchctl said."""


def _open(url: str) -> IO[bytes]:
    return urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS)  # noqa: S310 - fixed https URL


# ── settings ────────────────────────────────────────────────────────────────


def runtime(root_env: dict[str, str]) -> str:
    """The stored runtime; anything but `native` is the container."""
    return NATIVE if root_env.get(RUNTIME_KEY, "").strip() == NATIVE else CONTAINER


def stored_runtime(config_dir: Path) -> str:
    return runtime(common.parse_env_file(config_dir / ".env"))


def localai_home(root_env: dict[str, str]) -> Path:
    """`<PAPAIA_WORKSPACE_DIR>/localai/<COMPOSE_PROJECT_NAME>`: derived, not a setting.

    The project name keeps several installations on one Mac apart."""
    from . import envtree

    workspace = root_env.get("PAPAIA_WORKSPACE_DIR", "").strip()
    if (
        not workspace
        or common.is_placeholder(workspace)
        or workspace == envtree._WORKSPACE_DIR_PLACEHOLDER
    ):
        raise InstallError("PAPAIA_WORKSPACE_DIR is not set; run 'papaia-ctl setup' first")
    project = root_env.get("COMPOSE_PROJECT_NAME", "").strip() or status.DEFAULT_PROJECT
    return Path(workspace) / "localai" / project


def port(root_env: dict[str, str]) -> str:
    return root_env.get("LOCALAI_EXT_PORT", "").strip() or "8080"


def public_url(root_env: dict[str, str]) -> str:
    """The web UI is reachable on the Mac only."""
    return f"http://localhost:{port(root_env)}"


def api_base(root_env: dict[str, str]) -> str:
    """Where LiteLLM's container reaches the host process. Docker Desktop resolves the
    name itself; LocalAI listens on 127.0.0.1, which Docker Desktop forwards to."""
    return f"http://host.docker.internal:{port(root_env)}/v1"


def pinned_version(repo_root: Path) -> str:
    """The version of the `localai` image in the core compose file, read on every run: one
    pin serves both runtimes, and an upgrade that moves it moves the binary too."""
    base = gen_override._localai_base_image(repo_root)
    if base is None:
        raise InstallError("the LocalAI image in src/ai/localai/docker-compose.yml is not pinned")
    return base[1]


def asset_name(version: str) -> str:
    return _ASSET.format(version=version)


def binary_url(version: str) -> str:
    return f"{RELEASE_BASE}/{version}/{asset_name(version)}"


def checksums_url(version: str) -> str:
    return f"{RELEASE_BASE}/{version}/{_CHECKSUMS.format(version=version)}"


def binary_path(home: Path, version: str) -> Path:
    return home / "bin" / f"{_BINARY_PREFIX}{version}"


def script_path(home: Path) -> Path:
    return home / "run-localai"


def installed_version(home: Path) -> str | None:
    """The version of the newest binary in `bin/`, or None."""
    found = sorted(
        p.name[len(_BINARY_PREFIX) :]
        for p in (home / "bin").glob(f"{_BINARY_PREFIX}*")
        if p.is_file() and not p.name.endswith(".part")
    )
    return found[-1] if found else None


# ── host ────────────────────────────────────────────────────────────────────


def host_supported(
    *,
    system: str | None = None,
    machine: str | None = None,
    docker_desktop: Callable[[], bool] | None = None,
) -> tuple[bool, str]:
    """(supported, why not): Darwin on arm64 with Docker Desktop, not inside a container."""
    if common.in_container():
        return False, "papaia-ctl runs inside a container here, not on the Mac"
    system = system if system is not None else platform.system()
    machine = machine if machine is not None else platform.machine()
    if system != "Darwin" or machine != "arm64":
        return (
            False,
            f"the native LocalAI runs on Apple Silicon Macs only (this is {system}/{machine})",
        )
    if docker_desktop is None:
        from . import envtree

        docker_desktop = envtree._is_docker_desktop
    if not docker_desktop():
        return (
            False,
            "the native LocalAI needs Docker Desktop (it is reached at host.docker.internal)",
        )
    return True, ""


# ── install ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InstallResult:
    version: str
    binary: Path
    script: Path
    # True when this run put a new binary in place; False for an idempotent rerun.
    changed: bool
    # The version installed before, when it was another one.
    replaced: str | None = None
    # True when the start script changed (a new port, a new binary path).
    script_changed: bool = False


def _expected_sha256(text: str, version: str) -> str:
    wanted = asset_name(version)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == wanted:
            digest = parts[0].lower()
            if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                return digest
    raise InstallError(f"{_CHECKSUMS.format(version=version)} has no checksum for {wanted}")


def install(
    home: Path, version: str, *, opener: Opener | None = None
) -> tuple[Path, bool, str | None]:
    """Put the verified binary of `version` at `bin/local-ai-<version>`.

    Download to a temporary file next to the target, compare its sha256 with the release's
    checksum file, make it executable and rename it into place. Binaries of other versions
    are removed afterwards. A present binary of this version is kept (idempotent). Returns
    (path, changed, replaced version)."""
    opener = opener or _open
    target = binary_path(home, version)
    before = installed_version(home)
    if target.is_file():
        _remove_other_binaries(home, keep=target)
        return target, False, None
    try:
        with opener(checksums_url(version)) as response:
            expected = _expected_sha256(response.read().decode("utf-8", "replace"), version)
        common.ensure_dir(target.parent)
        partial = target.with_name(target.name + ".part")
        digest = hashlib.sha256()
        with opener(binary_url(version)) as response, open(partial, "wb") as handle:
            while chunk := response.read(_CHUNK):
                digest.update(chunk)
                handle.write(chunk)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        _discard(target)
        raise InstallError(f"could not download LocalAI {version}: {exc}") from exc
    if digest.hexdigest() != expected:
        _discard(target)
        raise InstallError(
            f"the downloaded LocalAI {version} does not match its published checksum;"
            " nothing was installed"
        )
    os.chmod(partial, 0o755)
    os.replace(partial, target)
    _remove_other_binaries(home, keep=target)
    return target, True, before if before and before != version else None


def _discard(target: Path) -> None:
    target.with_name(target.name + ".part").unlink(missing_ok=True)


def _remove_other_binaries(home: Path, *, keep: Path) -> None:
    for path in (home / "bin").glob(f"{_BINARY_PREFIX}*"):
        if path != keep:
            path.unlink(missing_ok=True)


def run_script(home: Path, binary: Path, config_dir: Path, listen_port: str) -> str:
    """The start script. It reads the key from the LocalAI `.env` each time it runs, so
    the key is in no file but the two `.env` files, and a changed key needs no new script.

    No LOCALAI_AUTH: the darwin binary is built without the SQLite user database and does
    not start with it. The key alone protects /v1, /api and /metrics; /readyz is open.
    LocalAI writes data/ and configuration/ into its working directory, hence the cd."""
    q = shlex.quote
    env_file = config_dir / "ai" / "localai" / ".env"
    return (
        "#!/bin/sh\n"
        "# Starts the native LocalAI of this papAIa installation. Written by papaia-ctl start;\n"
        "# changes are overwritten.\n"
        "set -eu\n"
        f"cd {q(str(home))}\n"
        f"key=$(sed -n 's/^LOCALAI_API_KEY=//p' {q(str(env_file))} | tail -n 1)\n"
        'if [ -z "$key" ]; then\n'
        f'    echo "LOCALAI_API_KEY is missing in {env_file}; run papaia-ctl start." >&2\n'
        "    exit 1\n"
        "fi\n"
        'LOCALAI_API_KEY="$key"\n'
        f"LOCALAI_ADDRESS=127.0.0.1:{listen_port}\n"
        f"LOCALAI_MODELS_PATH={q(str(home / 'models'))}\n"
        f"LOCALAI_BACKENDS_PATH={q(str(home / 'backends'))}\n"
        "LOCALAI_EXTERNAL_BACKENDS=llama-cpp\n"
        "export LOCALAI_API_KEY LOCALAI_ADDRESS LOCALAI_MODELS_PATH LOCALAI_BACKENDS_PATH"
        " LOCALAI_EXTERNAL_BACKENDS\n"
        f"exec {q(str(binary))} run\n"
    )


def write_run_script(home: Path, binary: Path, config_dir: Path, listen_port: str) -> bool:
    """Write the start script; True when its content changed."""
    path = script_path(home)
    content = run_script(home, binary, config_dir, listen_port)
    changed = _read_text(path) != content
    common.atomic_write_private(path, content)
    os.chmod(path, 0o700)
    return changed


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def install_for(
    config_dir: Path, repo_root: Path, *, opener: Opener | None = None
) -> InstallResult:
    """The `start` step: binary, start script and the models directory of this installation."""
    root = common.parse_env_file(config_dir / ".env")
    home = localai_home(root)
    version = pinned_version(repo_root)
    for sub in ("models", "backends"):
        common.ensure_dir(home / sub)
    binary, changed, replaced = install(home, version, opener=opener)
    script_changed = write_run_script(home, binary, config_dir, port(root))
    return InstallResult(
        version, binary, script_path(home), changed, replaced, script_changed=script_changed
    )


# ── models ──────────────────────────────────────────────────────────────────


def seed_models(config_dir: Path, repo_root: Path) -> Path | None:
    """Write the overlay model list once: the shipped list plus NATIVE_DEFAULT_MODELS as
    active lines. An existing overlay list is the operator's and stays as it is; so does
    the seeded one when the runtime goes back to `container`. Returns the path written."""
    target = config_dir / _MODELS_OVERLAY
    if target.exists():
        return None
    shipped = (repo_root / _SHIPPED_MODELS).read_text(encoding="utf-8")
    block = (
        "\n# ── Native runtime on Apple Silicon (seeded once by papaia-ctl setup) ──────\n"
        + "".join(f"{url}\n" for url in NATIVE_DEFAULT_MODELS)
    )
    common.atomic_write(target, shipped.rstrip("\n") + "\n" + block)
    return target


# ── probe ───────────────────────────────────────────────────────────────────


def probe_url(root_env: dict[str, str], *, inside_container: bool) -> str:
    host = "host.docker.internal" if inside_container else "127.0.0.1"
    return f"http://{host}:{port(root_env)}/readyz"


def probe(url: str, *, opener: Opener | None = None) -> bool:
    """Whether /readyz answers (it needs no key)."""
    try:
        with (opener or _probe_open)(url) as response:
            return 200 <= getattr(response, "status", 200) < 300
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return False


def _probe_open(url: str) -> IO[bytes]:
    return urllib.request.urlopen(url, timeout=PROBE_TIMEOUT_SECONDS)  # noqa: S310 - local URL


def wait_ready(
    url: str,
    timeout: float,
    *,
    ready: Callable[[str], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    interval: float = 1.0,
) -> bool:
    """Probe `url` until it answers or `timeout` seconds have passed."""
    ready = ready or probe
    deadline = clock() + timeout
    while True:
        if ready(url):
            return True
        if clock() >= deadline:
            return False
        sleep(interval)


# ── protected folders ───────────────────────────────────────────────────────

# Folders macOS guards with its privacy controls (TCC). A launchd job has no app a prompt
# could be shown for, so access below them may be denied.
PROTECTED_FOLDERS = ("Documents", "Desktop", "Downloads")


def protected_folder(home: Path, *, user_home: Path | None = None) -> str | None:
    """`~/Documents`, `~/Desktop` or `~/Downloads` when `home` lies below one of them."""
    base = user_home if user_home is not None else Path.home()
    for name in PROTECTED_FOLDERS:
        try:
            home.relative_to(base / name)
        except ValueError:
            continue
        return f"~/{name}"
    return None


# ── launchd ─────────────────────────────────────────────────────────────────

LABEL_PREFIX = "de.fidonis.papaia"
READY_TIMEOUT_SECONDS = 60
THROTTLE_SECONDS = 10
LAUNCHCTL_TIMEOUT_SECONDS = 60
UNLOAD_WAIT_SECONDS = 10
# `launchctl print` of a service that is not loaded: "Could not find service".
_NOT_LOADED = 113
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def label(project: str) -> str:
    """One job per installation: the project name keeps several on one Mac apart."""
    name = f"{LABEL_PREFIX}.{project}.localai"
    if not _LABEL_RE.match(project) or not _LABEL_RE.match(name):
        raise LaunchdError(f"COMPOSE_PROJECT_NAME {project!r} cannot name a launchd job")
    return name


def label_for(root_env: dict[str, str]) -> str:
    return label(root_env.get("COMPOSE_PROJECT_NAME", "").strip() or status.DEFAULT_PROJECT)


def plist_path(job_label: str, *, user_home: Path | None = None) -> Path:
    base = user_home if user_home is not None else Path.home()
    return base / "Library" / "LaunchAgents" / f"{job_label}.plist"


def log_path(home: Path) -> Path:
    return home / "logs" / "localai.log"


def plist_document(job_label: str, home: Path) -> dict:
    """The job: only the start script, so the key is in no plist. Restarted when it exits
    with an error (not after a clean exit), at most every THROTTLE_SECONDS."""
    log = str(log_path(home))
    return {
        "Label": job_label,
        "ProgramArguments": [str(script_path(home))],
        "WorkingDirectory": str(home),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": THROTTLE_SECONDS,
        "ProcessType": "Interactive",
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }


def write_plist(path: Path, document: dict) -> bool:
    """Write the plist; True when its content changed."""
    content = plistlib.dumps(document, sort_keys=True).decode("utf-8")
    if _read_text(path) == content:
        return False
    common.atomic_write(path, content)
    return True


def launchd_host(*, system: str | None = None) -> tuple[bool, str]:
    """(available, why not): launchctl of the logged-in user, i.e. a Mac, not a container.

    Looser than host_supported: stopping and removing a job must not depend on Docker
    Desktop answering."""
    if common.in_container():
        return False, "papaia-ctl runs inside a container here, not on the Mac"
    system = system if system is not None else platform.system()
    if system != "Darwin":
        return False, f"launchd exists on macOS only (this is {system})"
    return True, ""


def domain(uid: int | None = None) -> str:
    return f"gui/{os.getuid() if uid is None else uid}"


def service_target(job_label: str, uid: int | None = None) -> str:
    return f"{domain(uid)}/{job_label}"


@dataclass(frozen=True)
class JobState:
    loaded: bool
    # launchd's word for it: "running", "not running", "spawn scheduled", ...
    state: str | None = None
    pid: int | None = None
    last_exit: str | None = None

    @property
    def running(self) -> bool:
        return self.state == "running"

    def to_dict(self) -> dict:
        return {
            "loaded": self.loaded,
            "state": self.state,
            "pid": self.pid,
            "last_exit": self.last_exit,
        }


# The top level of `launchctl print`: one tab, `key = value`. Nested blocks have more tabs.
_PRINT_LINE = re.compile(r"^\t([a-z][a-z ]*?) = (.*)$")


def parse_print(text: str) -> JobState:
    """The state of a loaded job from `launchctl print gui/<uid>/<label>`."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _PRINT_LINE.match(line)
        if match and match.group(1) not in fields:
            fields[match.group(1)] = match.group(2).strip()
    pid = fields.get("pid", "")
    return JobState(
        loaded=True,
        state=fields.get("state"),
        pid=int(pid) if pid.isdigit() else None,
        last_exit=fields.get("last exit code"),
    )


def _runner(run: status.Runner | None) -> status.Runner:
    # Looked up at call time, so a test that replaces status.run_command reaches it here.
    return run or status.run_command


def _launchctl(run: status.Runner, *argv: str) -> status.CommandResult:
    result = run(["launchctl", *argv], LAUNCHCTL_TIMEOUT_SECONDS)
    if result.returncode == 127:
        raise LaunchdError("launchctl was not found on PATH")
    return result


def _failure(argv: tuple[str, ...], result: status.CommandResult) -> LaunchdError:
    said = status.first_line(result.stderr) or status.first_line(result.stdout)
    return LaunchdError(
        f"launchctl {' '.join(argv)} failed (exit {result.returncode})"
        + (f": {said}" if said else "")
    )


def _must(run: status.Runner, *argv: str) -> None:
    result = _launchctl(run, *argv)
    if result.returncode != 0:
        raise _failure(argv, result)


def state(job_label: str, *, run: status.Runner | None = None, uid: int | None = None) -> JobState:
    """Loaded or not, and if so its state and pid. `launchctl print` fails for a job that
    is not loaded."""
    result = _launchctl(_runner(run), "print", service_target(job_label, uid))
    if result.returncode != 0:
        return JobState(loaded=False)
    return parse_print(result.stdout)


def _wait_unloaded(
    job_label: str, run: status.Runner, uid: int | None, sleep: Callable[[float], None]
) -> None:
    """bootout returns before launchd has let go of the job, and a bootstrap in that
    moment fails; wait until `print` no longer finds it."""
    for _ in range(UNLOAD_WAIT_SECONDS * 2):
        if not state(job_label, run=run, uid=uid).loaded:
            return
        sleep(0.5)
    raise LaunchdError(f"{job_label} was still loaded {UNLOAD_WAIT_SECONDS} s after bootout")


def _bootout(
    job_label: str, run: status.Runner, uid: int | None, sleep: Callable[[float], None]
) -> bool:
    """Unload the job; False when it was not loaded. A "not loaded" error is no error."""
    if not state(job_label, run=run, uid=uid).loaded:
        return False
    argv = ("bootout", service_target(job_label, uid))
    result = _launchctl(run, *argv)
    if result.returncode != 0 and state(job_label, run=run, uid=uid).loaded:
        raise _failure(argv, result)
    _wait_unloaded(job_label, run, uid, sleep)
    return True


@dataclass(frozen=True)
class StartResult:
    # "loaded" (bootstrapped, RunAtLoad starts it), "restarted", "started" (was loaded but
    # not running) or "running" (left alone).
    action: str
    plist: Path
    log: Path


def start_job(
    home: Path,
    job_label: str,
    plist: Path,
    *,
    restart: bool = False,
    run: status.Runner | None = None,
    uid: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> StartResult:
    """Enable the job, write its plist and load it; restart it when `restart` (a new
    binary or start script). A changed plist is only read by a new bootstrap, so a loaded
    job with a changed plist is unloaded first."""
    run = _runner(run)
    common.ensure_dir(log_path(home).parent)
    plist_changed = write_plist(plist, plist_document(job_label, home))
    target = service_target(job_label, uid)
    # Before bootstrap: launchd refuses to load a disabled job, and `stop` disables it.
    _must(run, "enable", target)
    loaded = state(job_label, run=run, uid=uid).loaded
    if loaded and plist_changed:
        _bootout(job_label, run, uid, sleep)
        loaded = False
    if not loaded:
        _must(run, "bootstrap", domain(uid), str(plist))
        return StartResult("loaded", plist, log_path(home))
    if restart:
        _must(run, "kickstart", "-k", target)
        return StartResult("restarted", plist, log_path(home))
    if not state(job_label, run=run, uid=uid).running:
        _must(run, "kickstart", target)
        return StartResult("started", plist, log_path(home))
    return StartResult("running", plist, log_path(home))


def stop_job(
    job_label: str,
    *,
    run: status.Runner | None = None,
    uid: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Unload and disable the job; True when it was loaded. Without `disable` launchd
    would load it again at the next login although the stack is stopped."""
    run = _runner(run)
    was_loaded = _bootout(job_label, run, uid, sleep)
    _must(run, "disable", service_target(job_label, uid))
    return was_loaded


# What LocalAI downloads and writes for itself; the model files come from the init job.
DATA_DIRS = ("models", "backends")
_STATE_DIRS = ("logs", "data", "configuration")


def purge_data(home: Path) -> list[Path]:
    """Delete the models and backends of the installation. Returns what was removed."""
    removed = []
    for name in DATA_DIRS:
        path = home / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
            removed.append(path)
    return removed


def uninstall(
    home: Path,
    job_label: str,
    plist: Path,
    *,
    purge: bool = False,
    run: status.Runner | None = None,
    uid: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Path]:
    """Stop the job and remove the plist, the start script and `bin/`; with `purge` also
    the models, the backends, the logs and LocalAI's own state, and the directory itself
    when nothing else is left in it. Returns what was removed."""
    stop_job(job_label, run=run, uid=uid, sleep=sleep)
    removed: list[Path] = []
    for path in (plist, script_path(home)):
        if path.is_file():
            path.unlink()
            removed.append(path)
    targets = ["bin", *(DATA_DIRS + _STATE_DIRS if purge else ())]
    for name in targets:
        path = home / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
            removed.append(path)
    if purge:
        for directory in (home, home.parent):
            try:
                directory.rmdir()
            except OSError:
                break
            removed.append(directory)
    return removed
