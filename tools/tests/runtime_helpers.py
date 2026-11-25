"""The runtime environment of papaia-ctl in tests (lib/ctl_runtime.py).

`wheelhouse()` downloads the wheels runtime.lock pins for this platform once (by hash) into
the pytest cache, so every environment a test builds installs from a local wheel directory
through PIP_FIND_LINKS, the way an operator without the public index does.
`ensure_checkout_runtime()` gives this checkout the environment that `papaia-ctl setup`
builds, so the tests that run tools/papaia-ctl find it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent

# What a checkout copy leaves out: the repository, the tests and every local environment.
_IGNORED = shutil.ignore_patterns(
    ".git", ".venv", ".runtime", "__pycache__", ".pytest_cache", ".ruff_cache", "*.pyc",
    "node_modules", ".env", "papaia-realm.json",
)


def _lock_digest() -> str:
    sys.path.insert(0, str(TOOLS))
    from lib import ctl_runtime

    return ctl_runtime.lock_digest(str(TOOLS))


def wheelhouse(cache_dir: Path) -> Path:
    """A wheel directory with every package of runtime.lock for this platform."""
    house = cache_dir / "wheels"
    done_marker = house / f".complete-{_lock_digest()}"
    if done_marker.is_file():
        return house
    house.mkdir(parents=True, exist_ok=True)
    pip_env = cache_dir / "pip-env"
    if not (pip_env / "bin" / "python").exists():
        subprocess.run([sys.executable, "-m", "venv", str(pip_env)], check=True,
                       capture_output=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    done = subprocess.run(
        [str(pip_env / "bin" / "python"), "-m", "pip", "download", "--require-hashes",
         "--no-deps", "--only-binary=:all:", "--disable-pip-version-check", "--quiet",
         "-d", str(house), "-r", "runtime.lock"],
        cwd=TOOLS, capture_output=True, text=True, check=False, env=env,
    )
    assert done.returncode == 0, (
        "the wheels of tools/runtime.lock could not be downloaded for the tests:\n"
        + done.stderr
    )
    done_marker.write_text("")
    return house


def pip_offline(house: Path) -> dict[str, str]:
    """pip settings of a host without the package index: a wheel directory only."""
    return {"PIP_FIND_LINKS": str(house), "PIP_NO_INDEX": "1"}


def ensure_checkout_runtime(house: Path) -> None:
    """Build or reuse this checkout's tools/.runtime/current, as `papaia-ctl setup` does."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    env.update(pip_offline(house))
    done = subprocess.run(
        [sys.executable, "-I", str(TOOLS / "lib" / "ctl_runtime.py"), "build",
         f"--tools={TOOLS}"],
        capture_output=True, text=True, check=False, env=env,
    )
    assert done.returncode == 0, done.stderr


def checkout_copy(dest: Path) -> Path:
    """A checkout as an operator has it, from this working tree, without tests."""
    shutil.copytree(REPO, dest, ignore=_ignore_tests)
    return dest


def _ignore_tests(directory: str, names: list[str]) -> set[str]:
    ignored = set(_IGNORED(directory, names))
    if Path(directory) == TOOLS:
        ignored.add("tests")
    return ignored
