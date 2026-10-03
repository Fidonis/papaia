from __future__ import annotations

import shutil
from pathlib import Path

import pytest
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
