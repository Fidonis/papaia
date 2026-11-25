"""Release version check of a version tag (tools/lib/release_version.py).

A core whose `VERSION` carries a pre-release part accepts the test trust anchor
(ADR 0030, lib/prerelease_anchor.py). A tag `vX.Y.Z` must therefore never be built
while `VERSION` is anything but exactly `X.Y.Z`: the `release-version` job of
.github/workflows/images.yml runs this check first on every `v*` tag, and every job
that builds, signs or publishes needs it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

from lib import release_version

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "images.yml"
COMPATIBILITY = REPO / "docs" / "compatibility.md"
ADR_0030 = REPO / "docs" / "adr" / "0030-accept-a-test-trust-anchor-for-pre-release-cores.md"
ADR_INDEX = REPO / "docs" / "adr" / "README.md"


def _root(tmp_path: Path, content: bytes | None) -> Path:
    if content is not None:
        (tmp_path / "VERSION").write_bytes(content)
    return tmp_path


def _run(tmp_path: Path, version: bytes | None, tag: str, capsys) -> tuple[int, str]:
    root = _root(tmp_path, version)
    code = release_version.main(["check", "--tag", tag, "--root", str(root)])
    out = capsys.readouterr()
    return code, out.out + out.err


# ── the check ────────────────────────────────────────────────────────────────


def test_a_release_version_with_its_tag_passes(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"1.10.0\n", "v1.10.0", capsys)

    assert code == 0, text
    assert "1.10.0" in text


def test_the_tag_may_be_given_as_a_full_ref(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"1.10.0\n", "refs/tags/v1.10.0", capsys)

    assert code == 0, text


def test_a_version_file_without_a_trailing_newline_passes(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"2.0.0", "v2.0.0", capsys)

    assert code == 0, text


def test_a_pre_release_version_is_refused_and_both_values_are_named(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"1.10.0-rc.1\n", "v1.10.0", capsys)

    assert code != 0
    assert "1.10.0-rc.1" in text
    assert "v1.10.0" in text
    assert "pre-release" in text


def test_a_tag_that_differs_from_the_version_is_refused(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"1.10.0\n", "v1.10.1", capsys)

    assert code != 0
    assert "1.10.0" in text and "v1.10.1" in text


def test_build_metadata_is_refused(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"1.10.0+build\n", "v1.10.0", capsys)

    assert code != 0
    assert "1.10.0+build" in text


def test_an_empty_version_file_is_refused(tmp_path: Path, capsys):
    code, text = _run(tmp_path, b"", "v1.10.0", capsys)

    assert code != 0
    assert "VERSION" in text


def test_a_missing_version_file_is_refused(tmp_path: Path, capsys):
    code, text = _run(tmp_path, None, "v1.10.0", capsys)

    assert code != 0
    assert "VERSION" in text


@pytest.mark.parametrize(
    "content",
    [
        b"1.10.0\n\n",
        b" 1.10.0\n",
        b"1.10.0 \n",
        b"1.10.0\r\n",
        b"v1.10.0\n",
        b"1.10\n",
        b"1.10.0.1\n",
        b"1.10.0-rc.1+build\n",
        b"\xd9\xa1.10.0\n",  # ARABIC-INDIC DIGIT ONE: not an ASCII digit
        b"\xff\xfe\n",
        b"1." * 40 + b"0\n",
    ],
    ids=repr,
)
def test_anything_but_exactly_x_y_z_is_refused(tmp_path: Path, capsys, content: bytes):
    code, _text = _run(tmp_path, content, "v1.10.0", capsys)

    assert code != 0


@pytest.mark.parametrize(
    "tag",
    ["", "1.10.0", "v1.10.0-rc.1", "v1.10.0\n", "refs/heads/v1.10.0", "v" + "1" * 300 + ".0.0"],
    ids=repr,
)
def test_a_malformed_tag_is_refused(tmp_path: Path, capsys, tag: str):
    code, _text = _run(tmp_path, b"1.10.0\n", tag, capsys)

    assert code != 0


def test_a_version_file_that_is_not_a_regular_file_is_refused(tmp_path: Path, capsys):
    (tmp_path / "VERSION").mkdir()

    code, text = _run(tmp_path, None, "v1.10.0", capsys)

    assert code != 0
    assert "VERSION" in text


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_as_version_file_is_refused_without_blocking(tmp_path: Path, capsys):
    os.mkfifo(tmp_path / "VERSION")

    code, _text = _run(tmp_path, None, "v1.10.0", capsys)

    assert code != 0


def test_the_check_function_returns_the_version(tmp_path: Path):
    _root(tmp_path, b"3.1.4\n")

    assert release_version.check(tmp_path, "v3.1.4") == "3.1.4"
    with pytest.raises(release_version.ReleaseVersionError):
        release_version.check(tmp_path, "v3.1.5")


def test_the_checked_out_candidate_would_be_refused_as_a_release():
    version = (REPO / "VERSION").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-.+", version):
        pytest.skip(f"VERSION {version} is not a pre-release")
    release = version.split("-", 1)[0]

    with pytest.raises(release_version.ReleaseVersionError):
        release_version.check(REPO, f"v{release}")


# ── the tag job ──────────────────────────────────────────────────────────────


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _needs(job: dict) -> set[str]:
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def _closure(jobs: dict, name: str) -> set[str]:
    seen: set[str] = set()
    todo = list(_needs(jobs[name]))
    while todo:
        dep = todo.pop()
        if dep not in seen:
            seen.add(dep)
            todo.extend(_needs(jobs[dep]))
    return seen


def test_the_release_version_job_runs_the_check_on_every_version_tag():
    job = _jobs()["release-version"]

    assert "needs" not in job, "the check runs first"
    assert "permissions" not in job or job["permissions"] == {"contents": "read"}
    checks = [s for s in job["steps"] if "lib.release_version check" in s.get("run", "")]
    assert len(checks) == 1
    step = checks[0]
    assert step.get("if") == "startsWith(github.ref, 'refs/tags/v')"
    assert '--tag "${GITHUB_REF}"' in step["run"]


def test_every_build_sign_and_publish_job_needs_the_release_version_job():
    jobs = _jobs()

    for name in jobs:
        if name != "release-version":
            assert "release-version" in _closure(jobs, name), name
    # Signing needs it directly, not only through the scan job.
    assert "release-version" in _needs(jobs["publish"])


def test_no_step_of_the_release_version_job_uses_a_secret():
    job = _jobs()["release-version"]

    assert "secrets." not in yaml.safe_dump(job)


# ── docs ─────────────────────────────────────────────────────────────────────


def test_adr_0030_is_accepted():
    head = ADR_0030.read_text(encoding="utf-8").split("\n---\n", 1)[0]

    assert "\nstatus: Accepted\n" in head
    row = next(line for line in ADR_INDEX.read_text("utf-8").splitlines()
               if line.startswith("| [0030]"))
    assert "| Accepted |" in row


def test_the_release_gate_names_the_version_check():
    text = COMPATIBILITY.read_text(encoding="utf-8")
    gate = text.split("### Release gate: what every release must deliver", 1)[1]
    gate = gate.split("\n### ", 1)[0]

    assert "`VERSION` is exactly `X.Y.Z`" in gate
    assert "lib.release_version" in gate
    assert "release-version" in gate
