"""The vendored kit release and what the core takes from it.

The core vendors one kit release (`kit.lock`, `vendor/papaia-kit/<version>/`). Three
files are snapshots of that release: the contract schemas under `schemas/kit/` with
`snapshot.json`, and the naming register `lib/names_register.json`. `kit_snapshot.py`
writes all of them from the installed vendored kit; the tests here check that every
snapshot is exactly what the tool builds, so nothing in them is edited by hand.

The kit versions of the candidate suite live in `compat/suite-kit.yaml`. CI runs the
kit's own suite check (`pk-check bom`) over it; the tests run the same command and show
that it refuses a composition the kit forbids.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import kit_snapshot
from lib import suite

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
SUITE_KIT = REPO / "compat" / "suite-kit.yaml"
needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")


def _lock() -> dict:
    import tomllib

    return tomllib.loads((TOOLS / "kit.lock").read_text(encoding="utf-8"))


def _json(rel: str) -> dict:
    return json.loads((TOOLS / rel).read_text(encoding="utf-8"))


def _suite_kit() -> dict:
    return yaml.safe_load(SUITE_KIT.read_text(encoding="utf-8"))


# --- snapshots of the vendored release -------------------------------------------------


def test_every_snapshot_names_the_locked_kit_release():
    lock = _lock()
    release = {"package": "papaia-kit", "version": lock["version"], "commit": lock["commit"]}
    assert _json("schemas/kit/snapshot.json")["source"] == release
    register = _json("lib/names_register.json")
    assert register["source"] == release
    assert register["exchange_scopes"]["kit"] == lock["version"]


@needs_kit
def test_the_snapshots_are_exactly_what_the_tool_builds_from_the_vendored_kit():
    assert kit_snapshot.stale(TOOLS) == [], (
        "refresh the snapshots: cd tools && uv run --locked --extra dev python kit_snapshot.py"
        " write"
    )


def _copy_snapshot_inputs(dest: Path) -> Path:
    for rel in ("kit.lock", *kit_snapshot.OUTPUTS):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(TOOLS / rel, target)
    return dest


@needs_kit
def test_write_restores_every_snapshot_and_check_then_passes(tmp_path: Path):
    root = _copy_snapshot_inputs(tmp_path / "tools")
    for rel in kit_snapshot.OUTPUTS:
        (root / rel).write_text("{}\n", encoding="utf-8")
    assert sorted(kit_snapshot.stale(root)) == sorted(kit_snapshot.OUTPUTS)
    assert kit_snapshot.main(["write", "--root", str(root)]) == 0
    assert kit_snapshot.main(["check", "--root", str(root)]) == 0
    for rel in kit_snapshot.OUTPUTS:
        assert (root / rel).read_bytes() == (TOOLS / rel).read_bytes(), rel


@needs_kit
def test_check_names_the_stale_file_and_fails(tmp_path: Path, capsys: pytest.CaptureFixture):
    root = _copy_snapshot_inputs(tmp_path / "tools")
    register = root / "lib" / "names_register.json"
    register.write_text(register.read_text("utf-8").replace('"flow"', '"flow2"', 1), "utf-8")
    assert kit_snapshot.main(["check", "--root", str(root)]) == 1
    assert "lib/names_register.json" in capsys.readouterr().err


@needs_kit
def test_the_tool_refuses_a_kit_other_than_the_locked_release(tmp_path: Path):
    root = _copy_snapshot_inputs(tmp_path / "tools")
    lock = root / "kit.lock"
    lock.write_text(re.sub(r'(?m)^version = ".*"$', 'version = "9.9.9"', lock.read_text()))
    with pytest.raises(kit_snapshot.SnapshotError, match="9.9.9"):
        kit_snapshot.stale(root)
    assert kit_snapshot.main(["write", "--root", str(root)]) == 2


def test_the_tool_refuses_unknown_commands_and_roots(tmp_path: Path):
    with pytest.raises(SystemExit):
        kit_snapshot.main(["refresh"])
    assert kit_snapshot.main(["check", "--root", str(tmp_path / "missing")]) == 2


@needs_kit
def test_the_register_snapshot_keeps_the_names_the_core_relies_on():
    """The register of the release carries the core's own audience `papaia-people`
    (audit finding E2E-R8): the realm sync reads it from the snapshot."""
    register = _json("lib/names_register.json")
    entries = {(e["name"], e["kind"]) for e in register["entries"]}
    assert {("papaia-people", "audience"), ("papaia-people", "client")} <= entries
    assert {"audience": "papaia-people", "scope": "aud-papaia-people"} in register[
        "exchange_scopes"
    ]["scopes"]


# --- kit versions of the candidate suite ----------------------------------------------


def _pk_check(path: Path) -> subprocess.CompletedProcess[str]:
    script = Path(sys.executable).with_name("pk-check")
    assert script.is_file(), "papaia-kit is not installed: uv sync --locked --extra dev"
    return subprocess.run(
        [str(script), "bom", str(path)], cwd=TOOLS, capture_output=True, text=True, check=False
    )


@needs_kit
def test_the_candidate_suite_passes_the_kit_suite_check():
    result = _pk_check(SUITE_KIT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "may be combined" in result.stdout


@needs_kit
def test_the_suite_check_refuses_the_core_on_another_kit(tmp_path: Path):
    """Audit finding KIT-R4: the core on a kit outside the release matrix next to modules
    on the release is refused, and the refusal names the core."""
    doc = _suite_kit()
    for repo in doc["repos"]:
        if repo["name"] == "papaia":
            repo["kit"]["version"] = "0.2.3"
    seeded = tmp_path / "suite-kit.yaml"
    seeded.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    result = _pk_check(seeded)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "papaia" in result.stdout + result.stderr
    assert "refused" in result.stdout + result.stderr


def test_the_candidate_suite_carries_this_core_on_its_vendored_kit():
    doc = _suite_kit()
    assert doc["schema"] == suite.BOM_SCHEMA
    matrix = yaml.safe_load((REPO / "compat" / "suite.yaml").read_text(encoding="utf-8"))
    (candidate,) = [row for row in matrix["suites"] if row["status"] == "candidate"]
    assert doc["suite"] == candidate["suite"]
    repos = {repo["name"]: repo for repo in doc["repos"]}
    version = _lock()["version"]
    assert repos["papaia"]["kit"] == {"version": version, "renders_ui": False}
    assert repos["papaia-kit"]["role"] == "kit" and repos["papaia-kit"]["version"] == version
    assert "kit" not in repos["papaia-kit"]


def test_the_candidate_suite_names_every_component_of_the_candidate_row():
    matrix = yaml.safe_load((REPO / "compat" / "suite.yaml").read_text(encoding="utf-8"))
    (candidate,) = [row for row in matrix["suites"] if row["status"] == "candidate"]
    # Components that are not their repo's name: the manager and the Paperless add-on.
    repo_of = {"manager": "papaia-manager", "paperless": "papaia-addons"}
    names = {repo["name"] for repo in _suite_kit()["repos"]}
    missing = {repo_of.get(c, c) for c in candidate["versions"]} - names
    assert missing == set()


def test_every_kit_field_of_the_candidate_suite_passes_the_core_validator():
    for index, repo in enumerate(_suite_kit()["repos"]):
        if repo["role"] == "kit":
            continue
        suite.validate_module_kit(repo["kit"], f"repos[{index}].kit")
        assert isinstance(repo["kit"]["renders_ui"], bool), repo["name"]


@needs_kit
def test_the_core_schema_takes_the_kit_field_from_the_vendored_kit_unchanged():
    from importlib import resources

    data = resources.files("papaia_kit") / "_data" / "contract" / "suite-bom-kit.schema.json"
    kit_schema = json.loads(data.read_text(encoding="utf-8"))
    core_schema = _json("schemas/suite-bom.schema.json")
    assert core_schema["$defs"]["module_kit"] == kit_schema["$defs"]["module_kit"]
    assert core_schema["$defs"]["repo"]["properties"]["kit"] == {"$ref": "#/$defs/module_kit"}
