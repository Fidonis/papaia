"""Repository checks of the CI: vendored kit, licenses, denied words and secrets.

The CI jobs `licenses`, `words` and `secrets` run the same commands as these tests. Each
check is shown to pass on this repository and to fail on a seeded violation, so a check
that silently stopped checking is noticed here.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
FIXTURES = Path(__file__).parent / "fixtures" / "licenses"
# Kit 0.1.0, the release build of this commit of the kit (test_kit_vendor.py pins its record).
KIT_VERSION = "0.1.0"
KIT_COMMIT = "849e344064472d94a5c934170f58162ef296c94c"
KIT_WHEEL = f"vendor/papaia-kit/{KIT_VERSION}/papaia_kit-{KIT_VERSION}-py3-none-any.whl"

# The kit needs Python 3.12, the floor of papaia-ctl as well (CI runs 3.12).
needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")

# The secret scan tests need the gitleaks binary. CI installs the pinned release and sets
# PAPAIA_REQUIRE_GITLEAKS so a missing binary fails instead of skipping.
_GITLEAKS = shutil.which("gitleaks")
if _GITLEAKS is None and os.environ.get("PAPAIA_REQUIRE_GITLEAKS"):
    raise RuntimeError("PAPAIA_REQUIRE_GITLEAKS is set but gitleaks is not installed")
needs_gitleaks = pytest.mark.skipif(_GITLEAKS is None, reason="gitleaks not installed")


def _toml(path: Path) -> dict:
    import tomllib

    return tomllib.loads(path.read_text(encoding="utf-8"))


def _kit(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run the kit's command from the environment that runs this test."""
    script = Path(sys.executable).with_name("papaia-kit")
    assert script.is_file(), "papaia-kit is not installed: uv sync --locked --extra dev"
    return subprocess.run(
        [str(script), *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- vendored kit -------------------------------------------------------------------


@needs_kit
def test_kit_lock_pins_every_vendored_file():
    lock = _toml(TOOLS / "kit.lock")
    assert lock["version"] == KIT_VERSION
    assert lock["commit"] == KIT_COMMIT
    listed = {entry["path"]: entry["sha256"] for entry in lock["files"]}
    vendored = {
        path.relative_to(TOOLS).as_posix()
        for path in (TOOLS / "vendor" / "papaia-kit").rglob("*")
        if path.is_file()
    }
    assert set(listed) == vendored
    for rel, digest in listed.items():
        assert _sha256(TOOLS / rel) == digest, rel


@needs_kit
def test_uv_lock_and_pyproject_bind_the_same_kit_wheel():
    lock = _toml(TOOLS / "kit.lock")
    wheel = next(entry for entry in lock["files"] if entry["path"] == KIT_WHEEL)
    uv_lock = _toml(TOOLS / "uv.lock")
    (kit,) = [package for package in uv_lock["package"] if package["name"] == "papaia-kit"]
    assert kit["version"] == KIT_VERSION
    assert kit["source"] == {"path": KIT_WHEEL}
    assert [w["hash"] for w in kit["wheels"]] == [f"sha256:{wheel['sha256']}"]
    pyproject = _toml(TOOLS / "pyproject.toml")
    assert pyproject["tool"]["uv"]["sources"]["papaia-kit"] == {"path": KIT_WHEEL}


def test_the_kit_is_a_runtime_dependency_on_python_3_12():
    pyproject = _toml(TOOLS / "pyproject.toml")
    assert pyproject["project"]["requires-python"] == ">=3.12"
    runtime = pyproject["project"]["dependencies"]
    assert f"papaia-kit=={KIT_VERSION}" in runtime
    assert any(dep.startswith("PyYAML") for dep in runtime)
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    assert not any(dep.startswith("papaia-kit") for dep in dev)


def _runtime_lock() -> dict[str, list[str]]:
    """{requirement without marker: hashes} of runtime.lock."""
    sys.path.insert(0, str(TOOLS))
    from lib import ctl_runtime

    text = (TOOLS / "runtime.lock").read_text(encoding="utf-8")
    return {req.split(";")[0].strip(): hashes for req, hashes in ctl_runtime.parse_lock(text)}


def _runtime_closure(uv_lock: dict) -> set[str]:
    """The packages of uv.lock that papaia-ctl needs at runtime: its dependencies and theirs."""
    packages = {package["name"]: package for package in uv_lock["package"]}
    todo = [dep["name"] for dep in packages["papaia-ctl"].get("dependencies", [])]
    seen: set[str] = set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(dep["name"] for dep in packages[name].get("dependencies", []))
    return seen


def test_runtime_lock_uv_lock_and_kit_lock_are_in_step():
    uv_lock = _toml(TOOLS / "uv.lock")
    packages = {package["name"]: package for package in uv_lock["package"]}
    lock = _runtime_lock()
    kit = next(entry for entry in _toml(TOOLS / "kit.lock")["files"]
               if entry["path"] == KIT_WHEEL)
    assert lock.pop(f"./{KIT_WHEEL}") == [kit["sha256"]]
    pinned = {}
    for requirement, hashes in lock.items():
        name, _, version = requirement.partition("==")
        pinned[name.lower()] = (version, set(hashes))
    closure = _runtime_closure(uv_lock) - {"papaia-kit"}
    assert set(pinned) == closure
    for name in closure:
        package = packages[name]
        locked = {w["hash"].removeprefix("sha256:") for w in package.get("wheels", [])}
        if "sdist" in package:
            locked.add(package["sdist"]["hash"].removeprefix("sha256:"))
        version, hashes = pinned[name]
        assert version == package["version"], name
        # Every wheel of every platform uv.lock lists, nothing else.
        assert hashes == locked, name


# --- licenses -----------------------------------------------------------------------


def _license_check(*extra: str) -> subprocess.CompletedProcess[str]:
    return _kit(
        "licenses",
        "check",
        "--python-project",
        ".",
        "--records",
        "../licenses/base-images.json",
        "--exceptions",
        "../license-exceptions.toml",
        *extra,
        cwd=TOOLS,
    )


@needs_kit
def test_locked_dependencies_and_base_images_pass_the_license_policy():
    result = _license_check()
    assert result.returncode == 0, result.stdout + result.stderr


@needs_kit
def test_a_seeded_forbidden_license_fails_the_license_check():
    result = _license_check("--records", str(FIXTURES / "seeded-forbidden.json"))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "seeded-forbidden-license 1.0.0" in result.stdout + result.stderr


# --- denied words -------------------------------------------------------------------

# Built at run time so that this file holds no denied term itself.
_NEW_TERM = "vibe" + "coded"


def _copy_of_this_repository(dest: Path) -> Path:
    """Tracked and new files of the checkout in a fresh git repository: the word check
    reads the file list from git."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO,
        capture_output=True,
        check=True,
    ).stdout.decode()
    for rel in filter(None, listed.split("\0")):
        source = REPO / rel
        if source.is_file() and not source.is_symlink():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    subprocess.run(["git", "init", "-q", str(dest)], check=True)
    subprocess.run(["git", "add", "-A"], cwd=dest, check=True)
    return dest


def _word_check(root: Path) -> subprocess.CompletedProcess[str]:
    return _kit("repo", "words", "--root", ".", "--baseline", "words-baseline.toml", cwd=root)


@pytest.fixture(scope="module")
def repo_copy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _copy_of_this_repository(tmp_path_factory.mktemp("words") / "repo")


@needs_kit
def test_the_word_check_passes_with_the_frozen_baseline(repo_copy: Path):
    result = _word_check(repo_copy)
    assert result.returncode == 0, result.stdout + result.stderr


@needs_kit
def test_a_new_word_hit_outside_the_baseline_fails(repo_copy: Path, tmp_path: Path):
    copy = tmp_path / "repo"
    shutil.copytree(repo_copy, copy)
    planted = copy / "docs" / "planted.md"
    planted.write_text(f"This text was {_NEW_TERM}.\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=copy, check=True)
    result = _word_check(copy)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "docs/planted.md:1" in result.stdout + result.stderr


@needs_kit
def test_an_edited_line_of_the_baseline_fails(repo_copy: Path, tmp_path: Path):
    copy = tmp_path / "repo"
    shutil.copytree(repo_copy, copy)
    baseline = _toml(copy / "words-baseline.toml")
    entry = baseline["entry"][0]
    path = copy / entry["path"]
    path.write_text(path.read_text(encoding="utf-8") + f"\n{entry['term']} edited\n", "utf-8")
    result = _word_check(copy)
    assert result.returncode == 1, result.stdout + result.stderr


# --- secrets ------------------------------------------------------------------------


def _ignore_entries() -> list[tuple[str, list[str]]]:
    """Each fingerprint of .gitleaksignore with the comment lines above it."""
    entries: list[tuple[str, list[str]]] = []
    comments: list[str] = []
    for line in (REPO / ".gitleaksignore").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            comments.append(line)
        elif line.strip():
            entries.append((line, list(comments)))
        else:
            comments = []
    return entries


def test_every_ignored_finding_is_one_fingerprint_with_a_reason():
    entries = _ignore_entries()
    assert entries
    for fingerprint, comments in entries:
        assert re.fullmatch(r"[0-9a-f]{40}:[^:\s]+:[a-z0-9-]+:\d+", fingerprint), fingerprint
        assert any(len(c.strip("# ")) > 10 for c in comments), f"no reason for {fingerprint}"
    fingerprints = [fingerprint for fingerprint, _ in entries]
    assert len(fingerprints) == len(set(fingerprints))


def test_the_burned_searxng_key_stays_listed_with_its_historic_commits():
    commits = {fp[:7] for fp, _ in _ignore_entries() if "searxng/settings" in fp}
    assert {"0ad5fae", "7a712e4"} <= commits


def _scan_repository(tmp_path: Path, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """gitleaks over the history of a fresh repository holding `files` and this
    repository's gitleaks configuration and ignore file."""
    repo = tmp_path / "scan"
    repo.mkdir()
    for name in (".gitleaks.toml", ".gitleaksignore"):
        shutil.copyfile(REPO / name, repo / name)
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    git = ["git", "-c", "user.name=test", "-c", "user.email=test@example.org"]
    subprocess.run(["git", "init", "-q", "."], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "seed"], cwd=repo, check=True)
    return subprocess.run(
        [
            str(_GITLEAKS),
            "git",
            "--no-banner",
            "--redact",
            "--verbose",
            "--exit-code",
            "1",
            "--config",
            ".gitleaks.toml",
            "--gitleaks-ignore-path",
            ".gitleaksignore",
            ".",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


@needs_gitleaks
def test_a_planted_secret_fails_the_secret_scan(tmp_path: Path):
    planted = f'service_api_key = "{secrets.token_urlsafe(30)}"\n'
    result = _scan_repository(tmp_path, {"src/planted.py": planted})
    assert result.returncode == 1, result.stdout + result.stderr
    assert "src/planted.py" in result.stdout + result.stderr


@needs_gitleaks
def test_file_digests_of_the_golden_snapshots_are_no_finding(tmp_path: Path):
    digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    golden = f'{{\n  "files": {{\n    "secrets/gate/secret": "{digest}"\n  }}\n}}\n'
    result = _scan_repository(tmp_path, {"tools/tests/golden/single-node.json": golden})
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_an_unsigned_token_without_claims_is_no_finding(tmp_path: Path):
    fixture = '{"set": {"token": "eyJhbGciOiJub25lIn0.e30."}, "reason": "token field"}\n'
    result = _scan_repository(tmp_path, {"tools/tests/fixtures/audit.json": fixture})
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_a_token_with_claims_is_still_found(tmp_path: Path):
    payload = f'{{"sub":"{secrets.token_hex(8)}"}}'.encode()
    claims = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    fixture = f'{{"set": {{"token": "eyJhbGciOiJub25lIn0.{claims}."}}}}\n'
    result = _scan_repository(tmp_path, {"tools/tests/fixtures/audit.json": fixture})
    assert result.returncode == 1, result.stdout + result.stderr


@needs_gitleaks
def test_the_same_value_outside_the_golden_snapshots_is_still_found(tmp_path: Path):
    digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    result = _scan_repository(tmp_path, {"src/config.json": f'{{"api_secret": "{digest}"}}\n'})
    assert result.returncode == 1, result.stdout + result.stderr


@needs_gitleaks
def test_canary_labels_in_the_tests_are_no_finding(tmp_path: Path):
    canary = f"canary-key-revocation-{secrets.randbelow(1000)}"
    test = f'volumes = {{\n    "papaia_papaia-lifecycle-key": "{canary}",\n}}\n'
    result = _scan_repository(tmp_path, {"tools/tests/test_backup.py": test})
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_a_random_key_in_the_tests_is_still_found(tmp_path: Path):
    test = f'volumes = {{\n    "papaia_papaia-lifecycle-key": "{secrets.token_urlsafe(30)}",\n}}\n'
    result = _scan_repository(tmp_path, {"tools/tests/test_backup.py": test})
    assert result.returncode == 1, result.stdout + result.stderr


@needs_gitleaks
def test_a_canary_label_outside_the_tests_is_still_found(tmp_path: Path):
    canary = f"canary-key-revocation-{secrets.randbelow(1000)}"
    config = f'volumes = {{\n    "papaia_papaia-lifecycle-key": "{canary}",\n}}\n'
    result = _scan_repository(tmp_path, {"tools/lib/backup_config.py": config})
    assert result.returncode == 1, result.stdout + result.stderr
