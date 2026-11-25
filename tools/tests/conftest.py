from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import runtime_helpers
from stack_helpers import build_stack

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    """A synthetic repo root (mirroring src/ + tools/deployment.template.yaml
    + CHANGELOG.md) copied into a tmp dir per test, so tests can freely
    write into it without mutating the checked-in fixture or the real repo."""
    dest = tmp_path / "repo"
    shutil.copytree(FIXTURES_DIR / "repo", dest)
    return dest


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    return tmp_path / "papaia-config"


@pytest.fixture
def stack(tmp_path: Path) -> dict[str, Path]:
    """A synthetic checkout with core fragments, a config dir and one active
    add-on; see stack_helpers.build_stack."""
    return build_stack(tmp_path)


@pytest.fixture(autouse=True)
def _no_real_launchd(monkeypatch: pytest.MonkeyPatch) -> None:
    """`setup`, `start` and `stop` remove a launchd job of the native LocalAI when they find
    its plist below the user's home. On a Mac with such a job a test must not reach the real
    launchctl: tests that exercise launchd patch this back and pass a fake runner."""
    from lib import localai_native

    monkeypatch.setattr(
        localai_native, "launchd_host", lambda: (False, "launchd is not used in tests")
    )


@pytest.fixture(scope="session")
def ctl_wheelhouse(request: pytest.FixtureRequest, tmp_path_factory) -> Path:
    """The wheels of tools/runtime.lock for this platform, downloaded once by hash."""
    cache = getattr(request.config, "cache", None)
    folder = Path(cache.mkdir("ctl-runtime")) if cache else tmp_path_factory.mktemp("ctl")
    return runtime_helpers.wheelhouse(folder)


@pytest.fixture(scope="session", autouse=True)
def _ctl_runtime(ctl_wheelhouse: Path) -> None:
    """tools/papaia-ctl runs lib.cli from tools/.runtime/current only; give this checkout the
    environment `papaia-ctl setup` would build (reused when it is already there)."""
    runtime_helpers.ensure_checkout_runtime(ctl_wheelhouse)
