"""Vulnerability gate of the own images (lib/image_scan.py, security/exceptions.yaml).

The CI job `images` builds every own image, scans each platform of the built digest
with Trivy and runs this gate over the report:

- a critical finding always fails; there is no exception for it;
- a high finding passes only with an unexpired, dated entry in security/exceptions.yaml;
- an expired entry fails, and so does an exception file with an unknown field.

Trivy is replaced by a recording runner here; the CI job runs the pinned image.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from lib import image_scan, own_images

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
TODAY = date(2026, 11, 22)
DIGEST = "sha256:" + "1" * 64
PREFIX = "localhost:5000/unpublished/"
ARTIFACT = f"{PREFIX}ghcr.io/fidonis/papaia-egress@{DIGEST}"


def _vuln(vid: str, package: str, severity: str, **extra) -> dict:
    return {"VulnerabilityID": vid, "PkgName": package, "Severity": severity,
            "InstalledVersion": "1.0", **extra}


def _report(path: Path, vulns: list[dict], artifact: str = ARTIFACT) -> Path:
    doc = {
        "SchemaVersion": 2,
        "ArtifactName": artifact,
        "ArtifactType": "container_image",
        "Results": [
            {"Target": "debian 13.2", "Class": "os-pkgs", "Type": "debian",
             "Vulnerabilities": vulns},
            {"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg"},
        ],
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _entry(**overrides) -> dict:
    entry = {
        "id": "CVE-2026-1001",
        "package": "libexample",
        "severity": "HIGH",
        "reason": "The service never loads the affected library code path.",
        "expires": TODAY + timedelta(days=30),
        "approved_by": "security officer",
    }
    entry.update(overrides)
    return entry


def _exceptions(path: Path, entries: list[dict], **top) -> Path:
    doc = {"version": 1, "exceptions": entries, **top}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def _gate(tmp_path: Path, vulns: list[dict], entries: list[dict]) -> list[str]:
    accepted = image_scan.load_exceptions(_exceptions(tmp_path / "exc.yaml", entries), TODAY)
    artifact, findings = image_scan.read_report(_report(tmp_path / "r.json", vulns))
    assert artifact == ARTIFACT
    return image_scan.gate(findings, accepted, TODAY)


# ── the gate ─────────────────────────────────────────────────────────────────


def test_a_seeded_critical_vulnerability_fails_the_gate(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "CRITICAL")], [])

    assert len(problems) == 1
    assert "CRITICAL CVE-2026-1001 in libexample" in problems[0]


def test_a_critical_finding_fails_even_when_an_entry_names_it(tmp_path: Path):
    # An entry for a critical finding cannot be written (see the refusals below), so
    # an entry for the same id and package as HIGH does not let it through either.
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "CRITICAL")], [_entry()])

    assert len(problems) == 1 and "CRITICAL" in problems[0]


def test_a_high_finding_fails_without_an_entry(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH")], [])

    assert len(problems) == 1
    assert "HIGH CVE-2026-1001 in libexample" in problems[0]
    assert "security/exceptions.yaml" in problems[0]


def test_a_high_finding_passes_with_an_unexpired_entry(tmp_path: Path):
    assert _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH")], [_entry()]) == []


def test_an_entry_may_name_the_source_package(tmp_path: Path):
    vuln = _vuln("CVE-2026-1001", "libexample1", "HIGH", SrcName="libexample")

    assert _gate(tmp_path, [vuln], [_entry()]) == []


def test_an_entry_for_another_package_does_not_cover_the_finding(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "other", "HIGH")], [_entry()])

    assert len(problems) == 1


def test_an_expired_high_exception_fails(tmp_path: Path):
    expired = _entry(expires=TODAY - timedelta(days=1))

    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH")], [expired])

    assert any("HIGH CVE-2026-1001 in libexample" in p for p in problems)
    assert any("expired on" in p for p in problems)


def test_an_expired_entry_fails_even_when_no_finding_needs_it(tmp_path: Path):
    expired = _entry(expires=TODAY - timedelta(days=1))

    problems = _gate(tmp_path, [], [expired])

    assert len(problems) == 1 and "expired on" in problems[0]


def test_an_entry_expiring_today_still_holds(tmp_path: Path):
    entry = _entry(expires=TODAY)

    assert _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH")], [entry]) == []


def test_medium_low_and_unknown_findings_do_not_fail(tmp_path: Path):
    vulns = [_vuln("CVE-2026-1", "a", "MEDIUM"), _vuln("CVE-2026-2", "b", "LOW"),
             _vuln("CVE-2026-3", "c", "UNKNOWN")]

    assert _gate(tmp_path, vulns, []) == []


# ── the exception file ───────────────────────────────────────────────────────


def test_an_exception_file_with_an_unknown_field_is_refused(tmp_path: Path):
    path = _exceptions(tmp_path / "exc.yaml", [_entry(ticket="SEC-1")])

    with pytest.raises(image_scan.ScanError, match="ticket"):
        image_scan.load_exceptions(path, TODAY)


def test_an_unknown_top_level_field_is_refused(tmp_path: Path):
    path = _exceptions(tmp_path / "exc.yaml", [], owner="someone")

    with pytest.raises(image_scan.ScanError, match="owner"):
        image_scan.load_exceptions(path, TODAY)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"severity": "CRITICAL"}, "severity"),
        ({"id": "not-an-id"}, "id"),
        ({"package": ""}, "package"),
        ({"reason": "short"}, "reason"),
        ({"approved_by": ""}, "approved_by"),
        ({"expires": "someday"}, "expires"),
        ({"expires": TODAY + timedelta(days=91)}, "90 days"),
    ],
)
def test_invalid_entries_are_refused(tmp_path: Path, overrides: dict, message: str):
    path = _exceptions(tmp_path / "exc.yaml", [_entry(**overrides)])

    with pytest.raises(image_scan.ScanError, match=message):
        image_scan.load_exceptions(path, TODAY)


def test_a_missing_field_and_a_duplicate_entry_are_refused(tmp_path: Path):
    entry = _entry()
    del entry["approved_by"]
    with pytest.raises(image_scan.ScanError, match="approved_by"):
        image_scan.load_exceptions(_exceptions(tmp_path / "a.yaml", [entry]), TODAY)

    with pytest.raises(image_scan.ScanError, match="twice"):
        image_scan.load_exceptions(_exceptions(tmp_path / "b.yaml", [_entry(), _entry()]), TODAY)


def test_a_wrong_version_is_refused(tmp_path: Path):
    path = tmp_path / "exc.yaml"
    path.write_text("version: 2\nexceptions: []\n", encoding="utf-8")

    with pytest.raises(image_scan.ScanError, match="version"):
        image_scan.load_exceptions(path, TODAY)


def test_the_shipped_exception_file_is_valid_and_unexpired():
    accepted = image_scan.load_exceptions(REPO / image_scan.EXCEPTIONS_PATH, date.today())

    assert image_scan.expired(accepted, date.today()) == []


# ── the report ───────────────────────────────────────────────────────────────


def test_a_report_without_the_trivy_schema_is_refused(tmp_path: Path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"SchemaVersion": 1, "ArtifactName": ARTIFACT}), encoding="utf-8")
    with pytest.raises(image_scan.ScanError, match="SchemaVersion"):
        image_scan.read_report(path)

    path.write_text(json.dumps({"SchemaVersion": 2, "ArtifactName": ARTIFACT,
                                "Results": [{"Target": "x", "Vulnerabilities": [
                                    {"VulnerabilityID": "CVE-1", "PkgName": "a",
                                     "Severity": "SEVERE"}]}]}), encoding="utf-8")
    with pytest.raises(image_scan.ScanError, match="Severity"):
        image_scan.read_report(path)


def test_the_seeded_fixture_is_a_critical_finding():
    artifact, findings = image_scan.read_report(FIXTURES / "seeded-critical.json")

    assert artifact.startswith(PREFIX + "ghcr.io/fidonis/papaia-egress@sha256:")
    assert [f.severity for f in findings] == ["CRITICAL"]


# ── command line (the CI steps) ──────────────────────────────────────────────


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "lib.image_scan", "--repo-root", str(REPO), *args],
        cwd=TOOLS, capture_output=True, text=True, check=False,
    )


def test_the_cli_gate_fails_the_seeded_critical_report():
    artifact, _ = image_scan.read_report(FIXTURES / "seeded-critical.json")

    done = _cli("gate", "--report", str(FIXTURES / "seeded-critical.json"),
                "--artifact", artifact)

    assert done.returncode == 1, done.stderr
    assert "CVE-2099-0001" in done.stderr


def test_the_cli_gate_refuses_a_report_of_another_digest():
    done = _cli("gate", "--report", str(FIXTURES / "seeded-critical.json"),
                "--artifact", f"{PREFIX}ghcr.io/fidonis/papaia-egress@sha256:{'9' * 64}")

    assert done.returncode == 2
    assert "not of" in done.stderr


def test_the_cli_refuses_an_exception_file_with_an_unknown_field(tmp_path: Path):
    path = _exceptions(tmp_path / "exc.yaml", [_entry(expires=date.today(), ticket="x")])

    done = _cli("check", "--exceptions", str(path))

    assert done.returncode == 2
    assert "ticket" in done.stderr


def test_the_cli_check_fails_an_expired_entry(tmp_path: Path):
    path = _exceptions(tmp_path / "exc.yaml",
                       [_entry(expires=date.today() - timedelta(days=1))])

    done = _cli("check", "--exceptions", str(path))

    assert done.returncode == 1
    assert "expired on" in done.stderr


def test_the_cli_check_passes_the_shipped_file():
    done = _cli("check")

    assert done.returncode == 0, done.stderr


# ── scan: every platform of every built digest ───────────────────────────────


class FakeTrivy:
    """Records the docker commands and writes the report Trivy would write."""

    def __init__(self, vulns: dict[str, list[dict]] | None = None, artifact: str | None = None,
                 fail: bool = False):
        self.calls: list[list[str]] = []
        self.vulns = vulns or {}
        self.artifact = artifact
        self.fail = fail

    def __call__(self, cmd, env=None):
        self.calls.append(cmd)
        if self.fail:
            return subprocess.CompletedProcess(cmd, 1, "", "registry unreachable")
        mounts = dict(cmd[i + 1].split(":", 1)[::-1] for i, part in enumerate(cmd)
                      if part == "-v")
        out = Path(mounts["/out:rw"])
        target = Path(cmd[cmd.index("--output") + 1].replace("/out", str(out), 1))
        if cmd[cmd.index(image_scan.TRIVY_IMAGE) + 1] == "image":
            platform = cmd[cmd.index("--platform") + 1]
            ref = cmd[-1]
            _report(target, self.vulns.get(platform, []), self.artifact or ref)
        else:
            target.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}),
                              encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def _builds(tmp_path: Path) -> Path:
    path = tmp_path / "builds.json"
    own_images.write_builds(path, PREFIX, [
        {"name": "ghcr.io/fidonis/papaia-egress", "tag": "1.10.0", "digest": DIGEST,
         "revision": "a" * 40},
        {"name": "ghcr.io/fidonis/papaia-audit", "tag": "1.10.0",
         "digest": "sha256:" + "2" * 64, "revision": "b" * 40},
    ])
    return path


def test_scan_scans_both_platforms_of_each_built_digest_and_writes_sboms(tmp_path: Path):
    run = FakeTrivy()
    out = tmp_path / "out"
    exc = _exceptions(tmp_path / "exc.yaml", [])

    problems = image_scan.scan(_builds(tmp_path), exc, out, tmp_path / "cache", TODAY, run=run)

    assert problems == []
    scans = [c for c in run.calls if c[c.index(image_scan.TRIVY_IMAGE) + 1] == "image"]
    assert sorted((c[c.index("--platform") + 1], c[-1]) for c in scans) == sorted([
        ("linux/amd64", ARTIFACT), ("linux/arm64", ARTIFACT),
        ("linux/amd64", f"{PREFIX}ghcr.io/fidonis/papaia-audit@sha256:{'2' * 64}"),
        ("linux/arm64", f"{PREFIX}ghcr.io/fidonis/papaia-audit@sha256:{'2' * 64}"),
    ])
    for cmd in run.calls:
        assert cmd[:3] == ["docker", "run", "--rm"]
        assert image_scan.TRIVY_IMAGE in cmd
        assert "--cap-drop" in cmd and "ALL" in cmd
    for cmd in scans:
        # The digest is scanned, never a tag that could move.
        assert "@sha256:" in cmd[-1]
        assert "--list-all-pkgs" in cmd and cmd[cmd.index("--scanners") + 1] == "vuln"
    for name in ("papaia-egress", "papaia-audit"):
        for arch in ("amd64", "arm64"):
            assert (out / f"{name}-{arch}.trivy.json").is_file()
            sbom = json.loads((out / f"{name}-{arch}.cdx.json").read_text(encoding="utf-8"))
            assert sbom["bomFormat"] == "CycloneDX"


def test_scan_fails_on_a_critical_finding_of_one_platform(tmp_path: Path):
    run = FakeTrivy({"linux/arm64": [_vuln("CVE-2026-7", "zlib", "CRITICAL")]})

    problems = image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", []),
                               tmp_path / "out", tmp_path / "cache", TODAY, run=run)

    assert len(problems) == 2  # both images carry the finding on arm64
    assert all("linux/arm64" in p and "CRITICAL CVE-2026-7 in zlib" in p for p in problems)


def test_scan_refuses_a_report_of_another_artifact(tmp_path: Path):
    run = FakeTrivy(artifact=f"{PREFIX}ghcr.io/fidonis/papaia-egress:1.10.0")

    with pytest.raises(image_scan.ScanError, match="not of"):
        image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", []),
                        tmp_path / "out", tmp_path / "cache", TODAY, run=run)


def test_scan_stops_when_trivy_fails(tmp_path: Path):
    with pytest.raises(image_scan.ScanError, match="registry unreachable"):
        image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", []),
                        tmp_path / "out", tmp_path / "cache", TODAY, run=FakeTrivy(fail=True))


def test_scan_reports_an_expired_entry_once(tmp_path: Path):
    exc = _exceptions(tmp_path / "exc.yaml", [_entry(expires=TODAY - timedelta(days=3))])

    problems = image_scan.scan(_builds(tmp_path), exc, tmp_path / "out", tmp_path / "cache",
                               TODAY, run=FakeTrivy())

    assert len(problems) == 1 and "expired on" in problems[0]


def test_the_trivy_image_is_pinned_by_tag_and_digest():
    name, _, digest = image_scan.TRIVY_IMAGE.partition("@")
    assert name.startswith("aquasec/trivy:0.") and digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64

