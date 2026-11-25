"""CI of the own images (.github/workflows/images.yml) and its publish side.

The workflow builds every image of compat/own-images.yaml for both platforms, scans
each built digest (test_image_scan.py) and keeps the CycloneDX SBOMs. Only a version
tag signs: the `publish` job rebuilds, checks that the digests are the scanned ones
and the ones compose pins, signs each digest with the workflow identity and attaches
the SBOMs as cosign attestations. Only that job may request an OIDC token.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import images, own_images

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "images.yml"
SHA_PIN = re.compile(r"\A[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}\Z")
DIGEST_PIN = re.compile(r"\A\S+:\S+@sha256:[0-9a-f]{64}\Z")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    return doc.get("on", doc.get(True))


# ── workflow ─────────────────────────────────────────────────────────────────


def test_the_workflow_runs_on_pull_requests_pushes_tags_and_nightly():
    on = _on(_workflow())

    assert "pull_request" in on
    assert on["push"]["tags"] == ["v*"]
    assert {"main", "releases/**"} <= set(on["push"]["branches"])
    assert on["schedule"], "the published digests are scanned again every night"


def test_only_the_publish_job_may_request_an_oidc_token_or_write_packages():
    doc = _workflow()

    assert doc["permissions"] == {"contents": "read"}
    for name, job in doc["jobs"].items():
        perms = job.get("permissions", {})
        if name == "publish":
            assert perms == {"contents": "read", "packages": "write", "id-token": "write"}
        else:
            assert "id-token" not in perms and "packages" not in perms, name


def test_the_publish_job_runs_only_for_a_version_tag_after_the_scan():
    job = _workflow()["jobs"]["publish"]

    assert job["needs"] == ["release-version", "build-scan"]
    assert "startsWith(github.ref, 'refs/tags/v')" in job["if"]


def test_every_action_is_pinned_by_commit_and_every_image_by_digest():
    doc = _workflow()
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert SHA_PIN.match(step["uses"]), step["uses"]
        for service in job.get("services", {}).values():
            assert DIGEST_PIN.match(service["image"]), service["image"]
    for key in ("BUILDKIT_IMAGE",):
        assert DIGEST_PIN.match(doc["env"][key]), key


def test_the_scan_job_runs_the_gate_self_test_on_the_seeded_critical_report():
    steps = _workflow()["jobs"]["build-scan"]["steps"]
    runs = "\n".join(step.get("run", "") for step in steps)

    assert "tests/fixtures/trivy/seeded-critical.json" in runs
    assert "lib.image_scan scan" in runs
    assert "lib.own_images" in runs and " build " in runs


def _scan_steps() -> dict[str, dict]:
    return {step.get("name", ""): step for step in _workflow()["jobs"]["build-scan"]["steps"]}


def test_the_scan_job_keeps_both_seeded_self_tests():
    steps = _scan_steps()

    fixable = steps["Seeded critical finding fails the gate"]["run"]
    assert "tests/fixtures/trivy/seeded-critical.json" in fixable
    # The gate must fail it (exit 1) and name both findings, or the step fails.
    assert '-ne 1' in fixable and "CVE-2099-0001" in fixable and "CVE-2099-0002" in fixable

    no_fix = steps["Seeded finding without a fix passes"]["run"]
    assert "tests/fixtures/trivy/seeded-no-fix.json" in no_fix
    assert "--no-fix" in no_fix and "CVE-2099-0003" in no_fix and "CVE-2099-0004" in no_fix
    assert "-ne 0" in no_fix


def test_the_scan_writes_the_no_fix_list_into_the_artifact_and_the_summary():
    steps = _scan_steps()

    scan = steps["Scan every platform of every built digest"]["run"]
    assert '--summary "${GITHUB_STEP_SUMMARY}"' in scan
    collect = steps["Collect the builds file, reports and SBOMs"]["run"]
    assert "no-fix.txt" in collect
    upload = next(step for step in steps.values()
                  if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "images-report"
    assert upload["with"]["retention-days"] == 90


def test_the_scan_has_no_filter_that_drops_findings_before_the_gate():
    runs = "\n".join(step.get("run", "") for step in _scan_steps().values())
    source = (REPO / "tools" / "lib" / "image_scan.py").read_text(encoding="utf-8")

    for flag in ("--ignore-unfixed", "--severity"):
        assert flag not in runs and f'"{flag}"' not in source


def test_checkouts_keep_no_credentials():
    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_the_compose_image_scan_leaves_only_the_own_images_to_this_workflow():
    """The own images are scanned here on the built digest; the module images the core
    pins (papaia-me among them) are not built here and are scanned by image-scan.yml."""
    text = (REPO / ".github" / "workflows" / "image-scan.yml").read_text(encoding="utf-8")

    assert "compat/own-images.yaml" in text and 'grep -vF "${own}"' in text
    assert "grep -v '^ghcr\\.io/fidonis/'" not in text


# ── verify: the built digests are the pinned ones ────────────────────────────


def _pinned_builds(tmp_path: Path, **change) -> Path:
    services = images.compose_services(REPO)
    entries = []
    for image in own_images.load(REPO):
        ref = images.parse_ref(services[image.services[0]])
        entries.append({"name": image.name, "tag": ref.tag, "digest": ref.digest,
                        "revision": "a" * 40})
    for name, digest in change.items():
        for entry in entries:
            if entry["name"].endswith("/" + name.replace("_", "-")):
                entry["digest"] = digest
    path = tmp_path / "builds.json"
    own_images.write_builds(path, "", entries)
    return path


def test_verify_passes_when_every_build_is_the_pinned_digest(tmp_path: Path):
    _, entries = own_images.read_builds(_pinned_builds(tmp_path))

    assert own_images.pin_mismatches(REPO, entries) == []


def test_verify_names_a_build_that_is_not_the_pinned_digest(tmp_path: Path):
    other = "sha256:" + "e" * 64
    _, entries = own_images.read_builds(_pinned_builds(tmp_path, papaia_egress=other))

    problems = own_images.pin_mismatches(REPO, entries)

    assert len(problems) == 1
    assert "ghcr.io/fidonis/papaia-egress" in problems[0] and other in problems[0]


def test_verify_names_a_declared_image_that_was_not_built(tmp_path: Path):
    _, entries = own_images.read_builds(_pinned_builds(tmp_path))

    problems = own_images.pin_mismatches(REPO, entries[1:])

    assert problems == [f"{entries[0]['name']}: not built"]


# ── sign-keyless: the workflow identity signs and attests on a tag ───────────


class Recorder:
    def __init__(self, fail: bool = False):
        self.calls: list[tuple[list[str], dict | None]] = []
        self.fail = fail

    def __call__(self, cmd, env=None):
        self.calls.append((cmd, env))
        return subprocess.CompletedProcess(cmd, 1 if self.fail else 0, "", "denied")


D1 = "sha256:" + "1" * 64


def _entries() -> list[dict]:
    return [{"name": "ghcr.io/fidonis/papaia-egress", "tag": "1.10.0", "digest": D1,
             "revision": "a" * 40}]


def _sboms(tmp_path: Path, archs=("amd64", "arm64"), doc=None) -> Path:
    folder = tmp_path / "sboms"
    folder.mkdir(parents=True)
    for arch in archs:
        (folder / f"papaia-egress-{arch}.cdx.json").write_text(
            json.dumps(doc or {"bomFormat": "CycloneDX", "specVersion": "1.6"}),
            encoding="utf-8")
    return folder


def test_sign_keyless_signs_each_digest_and_attests_both_sboms(tmp_path: Path):
    run = Recorder()
    sboms = _sboms(tmp_path)

    own_images.sign_keyless("", _entries(), sboms=sboms, cosign="/opt/cosign",
                            env={"COSIGN_REPOSITORY": "elsewhere", "PATH": "/usr/bin"}, run=run)

    cmds = [cmd for cmd, _ in run.calls]
    ref = f"ghcr.io/fidonis/papaia-egress@{D1}"
    assert cmds[0] == ["/opt/cosign", "sign", "--yes", ref]
    assert cmds[1:] == [
        ["/opt/cosign", "attest", "--yes", "--type", "cyclonedx", "--predicate",
         str(sboms / f"papaia-egress-{arch}.cdx.json"), ref]
        for arch in ("amd64", "arm64")
    ]
    for cmd, env in run.calls:
        assert "--key" not in cmd
        # Keyless signatures stay next to the image; the release key's go elsewhere.
        assert "COSIGN_REPOSITORY" not in env


def test_sign_keyless_refuses_a_local_registry_and_missing_or_foreign_sboms(tmp_path: Path):
    run = Recorder()
    with pytest.raises(own_images.OwnImageError, match="release registry"):
        own_images.sign_keyless("localhost:5000/unpublished/", _entries(),
                                sboms=_sboms(tmp_path), cosign="/opt/cosign", run=run)

    with pytest.raises(own_images.OwnImageError, match="arm64"):
        own_images.sign_keyless("", _entries(), sboms=_sboms(tmp_path / "a", archs=("amd64",)),
                                cosign="/opt/cosign", run=run)

    with pytest.raises(own_images.OwnImageError, match="CycloneDX"):
        own_images.sign_keyless("", _entries(), sboms=_sboms(tmp_path / "b", doc={"spdx": 1}),
                                cosign="/opt/cosign", run=run)
    assert run.calls == [], "nothing is signed before every SBOM is checked"


def test_sign_keyless_stops_at_a_failed_signature(tmp_path: Path):
    with pytest.raises(own_images.OwnImageError, match="denied"):
        own_images.sign_keyless("", _entries(), sboms=_sboms(tmp_path), cosign="/opt/cosign",
                                run=Recorder(fail=True))
