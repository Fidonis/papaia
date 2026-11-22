"""Static checks of the CI: the kit's static suite over the server code of the core.

The CI job `static` runs `papaia-kit conformance static` over the code that runs on an
installation (`tools/lib`, `tools/migrations`, `src`) with `--require-approved`: a
finding passes only through an entry of `static-exceptions.toml`, and an entry passes
only with the security officer's countersignature. These tests run the same command,
show that it passes on this repository and that a seeded violation fails it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
EXCEPTIONS = REPO / "static-exceptions.toml"
# The server code of the core: what papaia-ctl and the core services run.
STATIC_PATHS = ("tools/lib", "tools/migrations", "src")

needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")


def _toml(path: Path) -> dict:
    import tomllib

    return tomllib.loads(path.read_text(encoding="utf-8"))


def _static(root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    script = Path(sys.executable).with_name("papaia-kit")
    assert script.is_file(), "papaia-kit is not installed: uv sync --locked --extra dev"
    return subprocess.run(
        [str(script), "conformance", "static", "--root", ".", *extra, *STATIC_PATHS],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


def _tracked(rel: str) -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", rel],
        cwd=REPO,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [p for p in listed.split("\0") if p]


@pytest.fixture(scope="module")
def server_code(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The scanned folders and the exception list, as git tracks them."""
    dest = tmp_path_factory.mktemp("static") / "repo"
    for rel in [p for path in STATIC_PATHS for p in _tracked(path)] + ["static-exceptions.toml"]:
        source = REPO / rel
        if source.is_file() and not source.is_symlink():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    return dest


def _copy(server_code: Path, tmp_path: Path) -> Path:
    copy = tmp_path / "repo"
    shutil.copytree(server_code, copy)
    return copy


def _countersigned(root: Path) -> None:
    """The exception list as the security officer signs it off (the wording the gate reads)."""
    path = root / "static-exceptions.toml"
    lines = [
        'approved_by = "security officer"' if line.startswith("approved_by = ") else line
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- the job --------------------------------------------------------------------------


def _static_job() -> dict:
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    return workflow["jobs"]["static"]


def test_the_static_job_scans_the_server_code_and_requires_the_countersignature():
    job = _static_job()
    commands = " ".join(step.get("run", "") for step in job["steps"])
    assert "papaia-kit conformance static" in commands
    assert "--require-approved" in commands
    assert "--root ." in commands
    for path in STATIC_PATHS:
        assert f" {path}" in commands
    # no step of the job may turn a failure into a pass
    assert not any(step.get("continue-on-error") for step in job["steps"])


def test_every_exception_names_place_input_reason_expiry_and_approver():
    document = _toml(EXCEPTIONS)
    assert document["version"] == 1
    entries = document["exception"]
    assert entries
    for entry in entries:
        assert entry["input"] in {"fixed", "operator-config"}, entry
        assert len(entry["reason"]) >= 40, entry
        assert entry["expires"].year <= 2027, entry
        assert entry["path"].startswith(tuple(f"{p}/" for p in STATIC_PATHS)), entry
        assert entry["approved_by"].strip(), entry
    # no exception for a scope built from strings: those go through the kit
    assert not [e for e in entries if e["rule"] == "scope-build"]


# --- the suite on this repository -------------------------------------------------------


@needs_kit
def test_the_server_code_passes_the_static_suite_with_its_exceptions(server_code: Path):
    result = _static(server_code)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "scope-build" not in result.stdout + result.stderr


@needs_kit
def test_a_countersigned_list_passes_the_static_job(server_code: Path, tmp_path: Path):
    copy = _copy(server_code, tmp_path)
    _countersigned(copy)
    result = _static(copy, "--require-approved")
    assert result.returncode == 0, result.stdout + result.stderr


@needs_kit
def test_an_entry_without_countersignature_fails_the_static_job(server_code: Path, tmp_path: Path):
    copy = _copy(server_code, tmp_path)
    _countersigned(copy)
    path = copy / "static-exceptions.toml"
    text = path.read_text(encoding="utf-8")
    first = text.index('approved_by = "security officer"')
    path.write_text(
        text[:first]
        + 'approved_by = "core maintainers (security officer countersignature pending)"'
        + text[first + len('approved_by = "security officer"') :],
        encoding="utf-8",
    )
    result = _static(copy, "--require-approved")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "approval pending" in result.stdout + result.stderr


@needs_kit
def test_a_seeded_string_built_scope_fails_the_static_job(server_code: Path, tmp_path: Path):
    copy = _copy(server_code, tmp_path)
    _countersigned(copy)
    planted = copy / "tools" / "lib" / "planted_scope.py"
    planted.write_text(
        'def scope(audience: str) -> str:\n    return f"aud-{audience}"\n', encoding="utf-8"
    )
    result = _static(copy, "--require-approved")
    assert result.returncode == 1, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert "tools/lib/planted_scope.py:2" in output
    assert "scope-build" in output


@needs_kit
def test_a_bare_scope_prefix_fails_the_static_job(server_code: Path, tmp_path: Path):
    copy = _copy(server_code, tmp_path)
    _countersigned(copy)
    planted = copy / "src" / "infra" / "planted_prefix.py"
    planted.write_text(
        'def is_exchange(name: str) -> bool:\n    return name.startswith("aud-")\n',
        encoding="utf-8",
    )
    result = _static(copy, "--require-approved")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "src/infra/planted_prefix.py:2" in result.stdout + result.stderr


@needs_kit
def test_an_exception_whose_place_is_gone_fails_the_static_job(server_code: Path, tmp_path: Path):
    copy = _copy(server_code, tmp_path)
    _countersigned(copy)
    entry = _toml(copy / "static-exceptions.toml")["exception"][0]
    path = copy / entry["path"]
    shutil.move(path, path.with_name("renamed_" + path.name))
    result = _static(copy, "--require-approved")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "matches no finding" in result.stdout + result.stderr
