"""The runtime environment of papaia-ctl: the one interpreter that runs `lib.cli`.

`tools/runtime.lock` names the runtime set (PyYAML, the kit and the kit's dependencies),
every wheel pinned by hash. `setup` and `upgrade` build it with the base interpreter into
`tools/.runtime/<sha256 of runtime.lock>/` and point the link `tools/.runtime/current` at
it; every other command only checks it and runs `tools/.runtime/current/bin/python` by
absolute path, so neither PATH nor sudo's `secure_path` decides which Python runs.

This file is also run as a script by the base interpreter (`python3 -I ctl_runtime.py
build ...`), before anything outside the standard library is installed: it imports nothing
else and refuses a Python below the floor with a plain message instead of a traceback.

    build --tools=DIR [--runtime=DIR] [--no-switch]   build (or reuse) and switch `current`
    check --tools=DIR                                 run by the environment's interpreter
    prune --runtime=DIR [--keep=SHA256 ...]           remove environments nobody needs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys

MIN_PYTHON = (3, 12)
FORMAT = "papaia.ctl-runtime/1"
LOCK_NAME = "runtime.lock"
KIT_LOCK_NAME = "kit.lock"
RUNTIME_NAME = ".runtime"
CURRENT = "current"
MARKER = "papaia-ctl-runtime.json"
# What the environment must import for `lib.cli` to run at all.
REQUIRED_IMPORTS = ("yaml", "papaia_kit.erasure")
# pip reads these from the operator's environment (a mirror, a wheel directory, a proxy
# certificate); every other PIP_* variable is dropped so it cannot loosen the install.
# PIP_CONFIG_FILE names a pip configuration file that may set further options; the hash
# pin (--require-hashes and the --hash of every runtime.lock line) is on the command line
# and stays in force whatever that file sets.
PIP_PASSED = (
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX",
    "PIP_TRUSTED_HOST", "PIP_CERT", "PIP_CLIENT_CERT", "PIP_PROXY", "PIP_TIMEOUT",
    "PIP_RETRIES", "PIP_CONFIG_FILE",
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_HASH = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!-]+$")
_KIT_PATH = re.compile(r"^(?:\./)?(vendor/papaia-kit/[0-9A-Za-z.+-]+/papaia_kit-[^/\s]+\.whl)$")
_CREDENTIALS = re.compile(r"://[^/@\s]+@")
_SETUP_FIX = "run 'papaia-ctl setup'"


def _version(parts: tuple) -> str:
    return ".".join(str(part) for part in parts)


class RuntimeEnvError(Exception):
    """The environment cannot be built or used; the message is one line for the operator."""


# --- the lock -----------------------------------------------------------------------


def digest_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def lock_digest(tools: str) -> str:
    path = os.path.join(tools, LOCK_NAME)
    try:
        return digest_file(path)
    except OSError as exc:
        raise RuntimeEnvError(f"{path} cannot be read: {exc.strerror}") from None


def parse_lock(text: str) -> list[tuple[str, list[str]]]:
    """The requirements of runtime.lock with their sha256 hashes. Only requirements and
    `--hash` options are allowed, and every requirement needs at least one hash: an option
    such as `--index-url` or `-e` would let the file decide more than what is installed."""
    entries: list[tuple[str, list[str]]] = []
    logical = ""
    lines = text.splitlines()
    for number, raw in enumerate(lines, 1):
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            logical += line[:-1] + " "
            if number < len(lines):
                continue
            line = ""
        logical += line
        if not logical.strip():
            logical = ""
            continue
        entries.append(_lock_entry(logical.strip(), number))
        logical = ""
    if not entries:
        raise RuntimeEnvError(f"{LOCK_NAME} names no package")
    return entries


def _lock_entry(line: str, number: int) -> tuple[str, list[str]]:
    if line.startswith("-"):
        raise RuntimeEnvError(
            f"{LOCK_NAME} line {number}: only requirements with hashes are allowed, "
            f"not '{line.split()[0]}'"
        )
    requirement, _, rest = line.partition(" --")
    rest = f"--{rest}" if rest else ""
    hashes = []
    for option in rest.split():
        match = _HASH.match(option)
        if not match:
            raise RuntimeEnvError(f"{LOCK_NAME} line {number}: unexpected option '{option}'")
        hashes.append(match.group(1))
    requirement = requirement.strip()
    name = requirement.split(";", 1)[0].strip()
    if not hashes:
        raise RuntimeEnvError(
            f"{LOCK_NAME} line {number}: {name} has no hash; every package is installed "
            "by hash"
        )
    if not (_NAME.match(name) or _KIT_PATH.match(name)):
        raise RuntimeEnvError(
            f"{LOCK_NAME} line {number}: '{name}' is neither a pinned package nor the "
            "vendored kit wheel"
        )
    return requirement, hashes


def kit_lock_wheel(tools: str) -> tuple[str, str]:
    """(path relative to tools, sha256) of the kit wheel kit.lock pins."""
    path = os.path.join(tools, KIT_LOCK_NAME)
    try:
        import tomllib

        with open(path, "rb") as handle:
            lock = tomllib.load(handle)
    except (OSError, ValueError) as exc:
        raise RuntimeEnvError(f"{path} cannot be read: {exc}") from None
    wheels = [
        entry for entry in lock.get("files") or []
        if isinstance(entry, dict) and str(entry.get("path", "")).endswith(".whl")
    ]
    if len(wheels) != 1 or not _DIGEST.match(str(wheels[0].get("sha256", ""))):
        raise RuntimeEnvError(f"{path} does not pin exactly one kit wheel by sha256")
    return str(wheels[0]["path"]), str(wheels[0]["sha256"])


def verify_lock(tools: str) -> list[tuple[str, list[str]]]:
    """runtime.lock parsed and checked against kit.lock, and the vendored kit wheel against
    its sha256 in kit.lock: before anything is installed."""
    path = os.path.join(tools, LOCK_NAME)
    try:
        with open(path, encoding="utf-8") as handle:
            entries = parse_lock(handle.read())
    except OSError as exc:
        raise RuntimeEnvError(f"{path} cannot be read: {exc.strerror}") from None
    wheel, sha = kit_lock_wheel(tools)
    kits = [(req, hashes) for req, hashes in entries if _KIT_PATH.match(req.split(";")[0])]
    if len(kits) != 1:
        raise RuntimeEnvError(f"{LOCK_NAME} must name the vendored kit wheel exactly once")
    requirement, hashes = kits[0]
    if _KIT_PATH.match(requirement.split(";")[0].strip()).group(1) != wheel or hashes != [sha]:
        raise RuntimeEnvError(
            f"{LOCK_NAME} names another kit wheel or hash than {KIT_LOCK_NAME} ({wheel})"
        )
    try:
        actual = digest_file(os.path.join(tools, wheel))
    except OSError as exc:
        raise RuntimeEnvError(f"the kit wheel {wheel} cannot be read: {exc.strerror}") from None
    if actual != sha:
        raise RuntimeEnvError(
            f"the kit wheel {wheel} does not match its sha256 in {KIT_LOCK_NAME}; "
            "nothing was installed"
        )
    return entries


# --- ownership ------------------------------------------------------------------------


def allowed_owners(tools: str) -> set[int]:
    """root and the account that owns the checkout's tools/ directory."""
    return {0, os.stat(tools).st_uid}


def unsafe(path: str, owners: set[int], *, recursive: bool = True) -> str | None:
    """Why `path` (and everything below it) cannot be trusted to run as root: writable by
    the group or by everyone, or owned by another account. None when it can."""
    found = _unsafe_one(path, owners)
    if found or not recursive or not os.path.isdir(path) or os.path.islink(path):
        return found
    for top, dirs, files in os.walk(path):
        for name in [*dirs, *files]:
            found = _unsafe_one(os.path.join(top, name), owners)
            if found:
                return found
    return None


def _unsafe_one(path: str, owners: set[int]) -> str | None:
    info = os.lstat(path)
    if info.st_uid not in owners:
        return f"{path} is owned by uid {info.st_uid}, neither root nor the owner of tools/"
    if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022:
        return f"{path} is group- or world-writable"
    return None


def _clear_group_write(path: str) -> None:
    """A umask of 002 must not leave the environment writable by the group."""
    for top, dirs, files in os.walk(path):
        for name in [top, *(os.path.join(top, n) for n in [*dirs, *files])]:
            info = os.lstat(name)
            if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022:
                os.chmod(name, stat.S_IMODE(info.st_mode) & ~0o022)


# --- the environment ------------------------------------------------------------------


def env_python(env: str) -> str:
    return os.path.join(env, "bin", "python")


def read_marker(env: str) -> dict:
    try:
        with open(os.path.join(env, MARKER), encoding="utf-8") as handle:
            marker = json.load(handle)
    except (OSError, ValueError):
        return {}
    return marker if isinstance(marker, dict) else {}


def env_problem(env: str, digest: str) -> str | None:
    """Why the environment at `env` cannot run lib.cli for the lock `digest`, or None."""
    marker = read_marker(env)
    if marker.get("format") != FORMAT:
        return "has no marker"
    if marker.get("lock_sha256") != digest:
        return f"was built for another {LOCK_NAME}"
    code = "import " + ", ".join(REQUIRED_IMPORTS)
    try:
        done = _run([env_python(env), "-I", "-c", code], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return "has an interpreter that does not run"
    if done.returncode != 0:
        return "cannot import " + ", ".join(REQUIRED_IMPORTS)
    return None


def _run(argv: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None,
         timeout: float | None = None) -> subprocess.CompletedProcess:
    """The three programs of this module, without a shell: the base interpreter
    (`-m venv`) and the environment's interpreter (`-m pip install` of runtime.lock, the
    import check). The options are literals; the values are paths of the checkout."""
    return subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, capture_output=True,
                          text=True, check=False)


def _pip_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    env.update({k: os.environ[k] for k in PIP_PASSED if k in os.environ})
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    return env


def _pip_failure(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    errors = [line for line in lines if line.startswith("ERROR:")]
    reason = (errors or lines or ["pip gave no reason"])[0]
    # pip already hides passwords in URLs; a user name in an index URL goes as well.
    return _CREDENTIALS.sub("://***@", reason)


def _sweep(runtime: str) -> None:
    """Left-overs of an interrupted build whose process is gone."""
    for name in os.listdir(runtime):
        if not name.startswith((".build-", ".current-", ".stale-")):
            continue
        pid = name.rsplit("-", 1)[-1]
        if pid.isdigit() and _alive(int(pid)):
            continue
        path = os.path.join(runtime, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            shutil.rmtree(path, ignore_errors=True)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return pid != os.getpid()


def switch(runtime: str, digest: str) -> None:
    """Point `current` at the environment `digest`: a new link renamed over the old one."""
    link = os.path.join(runtime, CURRENT)
    if os.path.lexists(link) and not os.path.islink(link):
        raise RuntimeEnvError(f"{link} is not a link; remove it and run 'papaia-ctl setup'")
    temporary = os.path.join(runtime, f".current-{os.getpid()}")
    if os.path.lexists(temporary):
        os.unlink(temporary)
    os.symlink(digest, temporary)
    os.replace(temporary, link)


def build(tools: str, runtime: str, *, switch_current: bool = True,
          log=print) -> str:
    """Build (or reuse) the environment of `tools/runtime.lock` under `runtime` and return
    its directory. Every hash is checked before pip runs; the environment is built beside
    the others and renamed into place, and `current` changes only after it imports."""
    if sys.version_info[:2] < MIN_PYTHON:
        raise RuntimeEnvError(
            f"papaia-ctl requires Python {_version(MIN_PYTHON)} or newer with the venv "
            f"module; {sys.executable} is {_version(sys.version_info[:2])}"
        )
    tools = os.path.abspath(tools)
    runtime = os.path.abspath(runtime)
    verify_lock(tools)
    digest = lock_digest(tools)
    owners = allowed_owners(os.path.dirname(runtime))
    os.makedirs(runtime, mode=0o755, exist_ok=True)
    problem = unsafe(runtime, owners, recursive=False)
    if problem:
        raise RuntimeEnvError(problem)
    _sweep(runtime)
    env = os.path.join(runtime, digest)
    if os.path.isdir(env) and not unsafe(env, owners) and env_problem(env, digest) is None:
        if switch_current:
            switch(runtime, digest)
        return env
    building = os.path.join(runtime, f".build-{digest[:12]}-{os.getpid()}")
    try:
        _create(building, tools, digest, log)
        if os.path.lexists(env):
            stale = os.path.join(runtime, f".stale-{digest[:12]}-{os.getpid()}")
            os.rename(env, stale)
            shutil.rmtree(stale, ignore_errors=True)
        os.rename(building, env)
    finally:
        if os.path.isdir(building):
            shutil.rmtree(building, ignore_errors=True)
    if switch_current:
        switch(runtime, digest)
    return env


def _create(path: str, tools: str, digest: str, log) -> None:
    log(f"Building the runtime environment of papaia-ctl ({digest[:12]}) with {sys.executable}...")
    done = _run([sys.executable, "-m", "venv", path], env=_pip_env())
    if done.returncode != 0:
        raise RuntimeEnvError(
            f"{sys.executable} -m venv failed ({_pip_failure(done.stderr + done.stdout)}); "
            "install the venv module (Debian/Ubuntu: python3-venv)"
        )
    done = _run(
        [env_python(path), "-I", "-m", "pip", "install", "--require-hashes", "--no-deps",
         "--only-binary=:all:", "--no-input", "--no-cache-dir", "--quiet",
         "-r", LOCK_NAME],
        cwd=tools, env=_pip_env(),
    )
    if done.returncode != 0:
        raise RuntimeEnvError(
            f"installing {LOCK_NAME} failed: {_pip_failure(done.stderr + done.stdout)}; "
            "without the public package index set PIP_INDEX_URL (a mirror) or "
            "PIP_FIND_LINKS (a wheel directory)"
        )
    marker = {
        "format": FORMAT,
        "lock_sha256": digest,
        "python": _version(sys.version_info[:3]),
        "base": os.path.abspath(sys.executable),
    }
    with open(os.path.join(path, MARKER), "w", encoding="utf-8") as handle:
        json.dump(marker, handle, indent=2, sort_keys=True)
        handle.write("\n")
    _clear_group_write(path)
    problem = env_problem(path, digest)
    if problem:
        raise RuntimeEnvError(f"the new environment {problem}")


def prune(runtime: str, keep: set[str]) -> list[str]:
    """Remove every environment that is neither `current` nor in `keep`."""
    if not os.path.isdir(runtime):
        return []
    current = os.readlink(os.path.join(runtime, CURRENT)) if os.path.islink(
        os.path.join(runtime, CURRENT)) else ""
    removed = []
    for name in sorted(os.listdir(runtime)):
        if _DIGEST.match(name) and name != current and name not in keep:
            shutil.rmtree(os.path.join(runtime, name))
            removed.append(name)
    return removed


def check(tools: str) -> str | None:
    """Run by the environment's own interpreter: why it cannot run lib.cli, or None."""
    if sys.version_info[:2] < MIN_PYTHON:
        return f"runs Python {_version(sys.version_info[:2])}, below {_version(MIN_PYTHON)}"
    try:
        digest = lock_digest(tools)
    except RuntimeEnvError as exc:
        return str(exc)
    marker = read_marker(sys.prefix)
    if marker.get("format") != FORMAT:
        return "has no marker"
    if marker.get("lock_sha256") != digest:
        return f"is stale: it was built for another {LOCK_NAME}"
    try:
        import yaml  # noqa: F401
    except ImportError:
        return "cannot import yaml"
    try:
        import papaia_kit.erasure  # noqa: F401
    except ImportError:
        return "cannot import papaia_kit"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ctl_runtime")
    sub = parser.add_subparsers(dest="action", required=True)
    p_build = sub.add_parser("build")
    p_build.add_argument("--tools", required=True)
    p_build.add_argument("--runtime", default=None)
    p_build.add_argument("--no-switch", action="store_true")
    p_check = sub.add_parser("check")
    p_check.add_argument("--tools", required=True)
    p_prune = sub.add_parser("prune")
    p_prune.add_argument("--runtime", required=True)
    p_prune.add_argument("--keep", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.action == "build":
            runtime = args.runtime or os.path.join(args.tools, RUNTIME_NAME)
            env = build(args.tools, runtime, switch_current=not args.no_switch,
                        log=lambda text: print(text, file=sys.stderr))
            print(env_python(env))
        elif args.action == "check":
            problem = check(os.path.abspath(args.tools))
            if problem:
                print(problem)
                return 1
        else:
            keep = {value for value in args.keep if _DIGEST.match(value)}
            for name in prune(os.path.abspath(args.runtime), keep):
                print(f"removed {name}")
    except RuntimeEnvError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
