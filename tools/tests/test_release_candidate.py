"""The release candidate 1.10.0-rc.1: version, manager pin, start check and notes.

The candidate core belongs to suite 1.10.0. Its compose files pin the manager of that
suite, the start check verifies the pinned manager against a signed bill of materials
of suite 1.10.0, and the architecture document, the README and the changelog name the
same versions (PLT-37-A4).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from test_images import FakeRegistry, _bom, _core, _image, _new_keypair

from lib import images, semver, suite

REPO = Path(__file__).resolve().parents[2]
CANDIDATE = "1.10.0-rc.1"
SUITE = "1.10.0"
MANAGER = "ghcr.io/fidonis/papaia-manager"


def _manager_pin() -> str:
    doc = yaml.safe_load((REPO / "src/manager/docker-compose.yml").read_text("utf-8"))
    return doc["services"]["papaia-manager"]["image"]


def _manager_version() -> str:
    tag = images.parse_ref(_manager_pin()).tag
    assert tag is not None
    return tag


def test_the_core_is_the_first_candidate_of_suite_1_10_0():
    version = images.core_version(REPO)

    assert version == CANDIDATE
    assert images.is_candidate(version)
    assert images.suite_version(version) == SUITE
    assert images.bom_path(REPO, version) == REPO / "compat" / f"suite-{SUITE}.yaml"


def test_the_manager_is_pinned_by_digest_in_the_range_of_suite_1_10_0():
    pin = _manager_pin()
    ref = images.parse_ref(pin)
    row, _ = suite.matrix_rows(suite.load_matrix(REPO), CANDIDATE)

    assert images.pin_problem(pin) is None
    assert ref.registry == "ghcr.io" and ref.repository == "fidonis/papaia-manager"
    assert row is not None and row["suite"] == SUITE
    assert semver.satisfies(_manager_version(), row["versions"]["manager"])
    assert not semver.parse_version(_manager_version()).prerelease


def _candidate_core(tmp_path: Path, keypair: tuple[Path, str], manager: str) -> Path:
    """A candidate checkout whose signed bill of materials of suite 1.10.0 lists
    `manager` (a pinned reference) as the image of the manager."""
    ref = images.parse_ref(manager)
    bom = _bom(keypair[1], [], version=SUITE)
    entry = _image(MANAGER, ref.tag or "", ref.digest or "")
    (row,) = [r for r in bom["repos"] if r["role"] == "manager"]
    row.update(version=ref.tag, tag=f"v{ref.tag}", containers=1, images=[entry])
    bom["totals"] = {"containers": 1, "images": 1}
    root = _core(tmp_path, keypair, bom=bom, version=SUITE)
    (root / "VERSION").write_text(f"{CANDIDATE}\n", encoding="utf-8")
    return root


def test_the_start_check_accepts_the_pinned_manager_under_suite_1_10_0(tmp_path):
    keypair = _new_keypair(tmp_path)
    pin = _manager_pin()
    ref = images.parse_ref(pin)
    root = _candidate_core(tmp_path, keypair, pin)
    registry = FakeRegistry()
    registry.add_signature(ref.registry, ref.repository, ref.digest, keypair[0], tmp_path)

    bom = images.load_trusted_bom(root)

    assert bom["suite"] == SUITE
    (manager,) = [r for r in bom["repos"] if r["role"] == "manager"]
    row, _ = suite.matrix_rows(suite.load_matrix(REPO), images.core_version(root))
    assert semver.satisfies(manager["version"], row["versions"]["manager"])
    assert images.verify_images([pin], bom, registry=registry) == []


def test_the_start_check_refuses_a_manager_the_bill_of_materials_does_not_list(tmp_path):
    keypair = _new_keypair(tmp_path)
    old = f"{MANAGER}:1.7.0@sha256:{'9' * 64}"
    root = _candidate_core(tmp_path, keypair, old)
    pin = _manager_pin()
    ref = images.parse_ref(pin)
    registry = FakeRegistry()
    registry.add_signature(ref.registry, ref.repository, ref.digest, keypair[0], tmp_path)

    problems = images.verify_images([pin], images.load_trusted_bom(root), registry=registry)

    assert [p.ref for p in problems] == [pin]


def _architecture_field(name: str) -> str:
    text = (REPO / "docs/architecture.md").read_text("utf-8")
    match = re.search(rf"^\| \*\*{re.escape(name)}\*\* \| (.+?) \|$", text, re.M)
    assert match, f"docs/architecture.md has no field {name}"
    return match.group(1)


def test_the_architecture_document_names_the_candidate_and_its_manager():
    assert _architecture_field("Version") == CANDIDATE
    assert _architecture_field("Manager") == f"papaia-manager {_manager_version()}"
    assert CANDIDATE in _architecture_field("Status")


def test_the_readme_names_the_candidate():
    text = (REPO / "README.md").read_text("utf-8")

    assert f"This is the **{CANDIDATE}** release candidate" in text


@pytest.fixture(scope="module")
def changelog_entry() -> str:
    text = (REPO / "CHANGELOG.md").read_text("utf-8")
    match = re.search(rf"^## \[{re.escape(CANDIDATE)}\] - \d{{4}}-\d{{2}}-\d{{2}}$(.*?)^## \[",
                      text, re.M | re.S)
    assert match, f"CHANGELOG.md has no entry for {CANDIDATE}"
    return match.group(1)


def test_the_changelog_has_an_entry_for_the_candidate(changelog_entry):
    assert f"papaia-manager {_manager_version()}" in changelog_entry
    for name in ("papaia-audit", "papaia-docker-gate", "papaia-egress", "papaia-lifecycle",
                 "papaia-people"):
        assert name in changelog_entry
    assert "tools/check-image-pins" in changelog_entry


def test_the_candidate_entry_follows_unreleased():
    text = (REPO / "CHANGELOG.md").read_text("utf-8")
    headings = re.findall(r"^## \[([^\]]+)\]", text, re.M)

    assert headings[:3] == ["Unreleased", CANDIDATE, "1.9.0"]
