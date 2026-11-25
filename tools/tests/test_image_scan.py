"""Vulnerability gate of the own images (lib/image_scan.py, security/exceptions.yaml).

The CI job `images` builds every own image, scans each platform of the built digest
with Trivy and runs this gate over the report:

- a critical or high finding with a fix fails; a finding without a fix passes and is
  listed in no-fix.txt and the step summary;
- for an own image a critical finding with a fix always fails, a high one passes only
  with an unexpired, dated entry in security/exceptions.yaml;
- for a third-party image only a digest-scoped entry of at most 14 days waives a
  finding with a fix;
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


def _vuln(vid: str, package: str, severity: str, fixed: str | None = "1.1",
          **extra) -> dict:
    """A finding; `fixed=None` is a finding without a fix."""
    vuln = {"VulnerabilityID": vid, "PkgName": package, "Severity": severity,
            "InstalledVersion": "1.0", **extra}
    if fixed is not None:
        vuln["FixedVersion"] = fixed
    return vuln


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


def test_the_seeded_fixture_is_a_critical_and_a_high_finding_with_a_fix():
    artifact, findings = image_scan.read_report(FIXTURES / "seeded-critical.json")

    assert artifact.startswith(PREFIX + "ghcr.io/fidonis/papaia-egress@sha256:")
    assert [f.severity for f in findings] == ["CRITICAL", "HIGH"]
    assert all(f.fixed for f in findings)


def test_the_seeded_no_fix_fixture_is_a_critical_and_a_high_finding_without_a_fix():
    artifact, findings = image_scan.read_report(FIXTURES / "seeded-no-fix.json")

    assert artifact.startswith(PREFIX + "ghcr.io/fidonis/papaia-egress@sha256:")
    assert [f.severity for f in findings] == ["CRITICAL", "HIGH"]
    assert not any(f.fixed for f in findings)


def test_the_report_keeps_the_installed_and_the_fixed_version(tmp_path: Path):
    path = _report(tmp_path / "r.json", [
        _vuln("CVE-2026-1", "a", "HIGH", fixed="1.2"),
        _vuln("CVE-2026-2", "b", "HIGH", fixed=None),
        _vuln("CVE-2026-3", "c", "HIGH", fixed=""),
    ])

    _, findings = image_scan.read_report(path)

    assert [(f.installed, f.fixed) for f in findings] == [("1.0", "1.2"), ("1.0", ""),
                                                          ("1.0", "")]


@pytest.mark.parametrize("field", ["PkgName", "InstalledVersion", "VulnerabilityID"])
def test_a_report_field_with_a_line_break_is_refused(tmp_path: Path, field: str):
    vuln = _vuln("CVE-2026-1", "a", "HIGH")
    vuln[field] = vuln[field] + "\nFAIL: forged"
    path = _report(tmp_path / "r.json", [vuln])

    with pytest.raises(image_scan.ScanError, match=field):
        image_scan.read_report(path)


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



# ── rule E: findings with a fix block, findings without a fix are reported ───


def test_only_unfixed_high_and_critical_findings_and_no_entry_give_no_problem(tmp_path: Path):
    vulns = [_vuln("CVE-2026-1", "ncurses-base", "CRITICAL", fixed=None),
             _vuln("CVE-2026-2", "libssl3", "HIGH", fixed=None),
             _vuln("CVE-2026-3", "libsqlite3-0", "HIGH", fixed="")]

    assert _gate(tmp_path, vulns, []) == []


def test_a_high_finding_with_a_fix_and_no_entry_fails(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH", fixed="1.1")], [])

    assert len(problems) == 1 and "HIGH CVE-2026-1001 in libexample" in problems[0]
    assert "fixed in 1.1" in problems[0]


def test_a_critical_finding_with_a_fix_fails_even_with_an_own_entry(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "CRITICAL", fixed="1.1")],
                     [_entry()])

    assert len(problems) == 1 and "CRITICAL CVE-2026-1001 in libexample" in problems[0]


def test_an_entry_that_covers_only_a_finding_without_a_fix_fails(tmp_path: Path):
    # Such entries are removed; the report lists the finding instead.
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH", fixed=None)],
                     [_entry()])

    assert len(problems) == 1
    assert "covers only findings without a fix" in problems[0]


def test_an_entry_awaiting_the_countersignature_waives_nothing(tmp_path: Path):
    problems = _gate(tmp_path, [_vuln("CVE-2026-1001", "libexample", "HIGH")],
                     [_entry(approved_by="pending (security officer)")])

    assert len(problems) == 1 and "not countersigned" in problems[0]


def test_evaluate_counts_failing_excepted_without_fix_and_other(tmp_path: Path):
    accepted = image_scan.load_exceptions(_exceptions(tmp_path / "e.yaml", [_entry()]), TODAY)
    _, findings = image_scan.read_report(_report(tmp_path / "r.json", [
        _vuln("CVE-2026-1001", "libexample", "HIGH"),          # excepted
        _vuln("CVE-2026-1002", "zlib1g", "CRITICAL"),          # failing
        _vuln("CVE-2026-1003", "ncurses-base", "HIGH", fixed=None),  # without fix
        _vuln("CVE-2026-1004", "libc6", "MEDIUM"),             # other
    ]))

    verdict = image_scan.evaluate(ARTIFACT, findings, accepted, TODAY, own=True)

    assert (len(verdict.problems), verdict.excepted, len(verdict.no_fix), verdict.other) == (
        1, 1, 1, 1)
    assert verdict.no_fix[0].id == "CVE-2026-1003"


def test_a_no_fix_line_names_image_platform_id_package_version_and_severity(tmp_path: Path):
    _, findings = image_scan.read_report(_report(tmp_path / "r.json", [
        _vuln("CVE-2026-1003", "ncurses-base", "HIGH", fixed=None)]))

    line = image_scan.no_fix_line(ARTIFACT, "linux/arm64", findings[0])

    assert line.split("\t") == [ARTIFACT, "linux/arm64", "CVE-2026-1003", "ncurses-base",
                                "1.0", "HIGH"]


# ── third-party images: digest-scoped entries of at most 14 days ─────────────

PG = "docker.io/library/postgres"
PG_DIGEST = "sha256:" + "a" * 64
PG_ARTIFACT = f"postgres:16.16@{PG_DIGEST}"


def _pinned() -> frozenset[str]:
    return frozenset({image_scan.pin_key(f"{PG}:16.16@{PG_DIGEST}")})


def _third(**overrides) -> dict:
    entry = {
        "image": f"{PG}@{PG_DIGEST}",
        "id": "CVE-2026-124851",
        "package": "libzstd1",
        "severity": "HIGH",
        "reason": "Debian ships the fix; the upstream image is not rebuilt yet.",
        "added": TODAY - timedelta(days=2),
        "expires": TODAY - timedelta(days=2) + timedelta(days=14),
        "approved_by": "security officer",
    }
    entry.update(overrides)
    return entry


def _gate_third(tmp_path: Path, vulns: list[dict], entries: list[dict],
                artifact: str = PG_ARTIFACT, pinned=None) -> list[str]:
    pinned = _pinned() if pinned is None else pinned
    accepted = image_scan.load_exceptions(_exceptions(tmp_path / "exc.yaml", entries), TODAY,
                                          pinned=pinned)
    name, findings = image_scan.read_report(_report(tmp_path / "r.json", vulns, artifact))
    return image_scan.gate(findings, accepted, TODAY, artifact=name, own=False)


def test_a_14_day_entry_with_the_scanned_digest_waives_exactly_that_finding(tmp_path: Path):
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "HIGH"),
             _vuln("CVE-2026-85091", "zlib1g", "HIGH")]

    problems = _gate_third(tmp_path, vulns, [_third()])

    assert len(problems) == 1 and "CVE-2026-85091 in zlib1g" in problems[0]


def test_a_third_party_entry_may_cover_a_critical_finding_with_a_fix(tmp_path: Path):
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "CRITICAL")]

    assert _gate_third(tmp_path, vulns, [_third(severity="CRITICAL")]) == []


def test_a_third_party_entry_of_another_severity_waives_nothing(tmp_path: Path):
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "CRITICAL")]

    assert len(_gate_third(tmp_path, vulns, [_third()])) == 1


def test_a_third_party_entry_of_15_days_is_refused(tmp_path: Path):
    entry = _third(expires=TODAY - timedelta(days=2) + timedelta(days=15))

    with pytest.raises(image_scan.ScanError, match="14 days"):
        _gate_third(tmp_path, [], [entry])


def test_a_dated_entry_without_a_digest_is_refused(tmp_path: Path):
    entry = _third()
    del entry["image"]
    with pytest.raises(image_scan.ScanError, match="added"):
        _gate_third(tmp_path, [], [entry])

    with pytest.raises(image_scan.ScanError, match="digest"):
        _gate_third(tmp_path, [], [_third(image=f"{PG}:16.16")])


def test_a_third_party_entry_without_added_is_refused(tmp_path: Path):
    entry = _third()
    del entry["added"]

    with pytest.raises(image_scan.ScanError, match="added"):
        _gate_third(tmp_path, [], [entry])


def test_a_third_party_entry_added_in_the_future_is_refused(tmp_path: Path):
    entry = _third(added=TODAY + timedelta(days=1), expires=TODAY + timedelta(days=5))

    with pytest.raises(image_scan.ScanError, match="added"):
        _gate_third(tmp_path, [], [entry])


def test_a_third_party_entry_for_a_digest_no_longer_pinned_is_refused(tmp_path: Path):
    with pytest.raises(image_scan.ScanError, match="no longer pinned"):
        _gate_third(tmp_path, [], [_third()], pinned=frozenset())


def test_a_third_party_entry_for_an_own_image_is_refused(tmp_path: Path):
    own = f"ghcr.io/fidonis/papaia-egress@{DIGEST}"
    pinned = frozenset({image_scan.pin_key(f"ghcr.io/fidonis/papaia-egress:1.10.0@{DIGEST}")})

    with pytest.raises(image_scan.ScanError, match="own image"):
        image_scan.load_exceptions(_exceptions(tmp_path / "e.yaml", [_third(image=own)]),
                                   TODAY, pinned=pinned,
                                   own_names=("ghcr.io/fidonis/papaia-egress",))


def test_a_third_party_entry_for_another_digest_waives_nothing(tmp_path: Path):
    other = f"postgres:16.16@sha256:{'b' * 64}"
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "HIGH")]

    problems = _gate_third(tmp_path, vulns, [_third()], artifact=other)

    assert len(problems) == 1 and "CVE-2026-124851 in libzstd1" in problems[0]


def test_an_own_entry_does_not_waive_a_finding_of_a_third_party_image(tmp_path: Path):
    vulns = [_vuln("CVE-2026-1001", "libexample", "HIGH")]

    problems = _gate_third(tmp_path, vulns, [_entry()])

    assert any("CVE-2026-1001 in libexample" in p for p in problems)


def test_a_third_party_entry_does_not_waive_a_finding_of_an_own_image(tmp_path: Path):
    accepted = image_scan.load_exceptions(_exceptions(tmp_path / "e.yaml", [_third()]), TODAY,
                                          pinned=_pinned())
    _, findings = image_scan.read_report(_report(tmp_path / "r.json", [
        _vuln("CVE-2026-124851", "libzstd1", "HIGH")]))

    assert len(image_scan.gate(findings, accepted, TODAY, artifact=ARTIFACT, own=True)) == 1


def test_an_expired_third_party_entry_fails_the_run(tmp_path: Path):
    entry = _third(added=TODAY - timedelta(days=15), expires=TODAY - timedelta(days=1))
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "HIGH")]

    problems = _gate_third(tmp_path, vulns, [entry])

    assert any("expired on" in p for p in problems)
    assert any("CVE-2026-124851 in libzstd1" in p for p in problems)


def test_a_third_party_entry_covering_only_a_finding_without_a_fix_fails(tmp_path: Path):
    vulns = [_vuln("CVE-2026-124851", "libzstd1", "HIGH", fixed=None)]

    problems = _gate_third(tmp_path, vulns, [_third()])

    assert len(problems) == 1 and "covers only findings without a fix" in problems[0]


def test_the_same_finding_may_be_listed_for_two_digests(tmp_path: Path):
    second = f"{PG}@sha256:{'b' * 64}"
    pinned = _pinned() | {image_scan.pin_key(f"{PG}:16.17@sha256:{'b' * 64}")}

    accepted = image_scan.load_exceptions(
        _exceptions(tmp_path / "e.yaml", [_third(), _third(image=second)]), TODAY,
        pinned=pinned)

    assert len(accepted) == 2


def test_the_pins_of_the_checkout_are_the_pin_keys():
    pinned = image_scan.pinned_keys(REPO)

    assert pinned and all("@sha256:" in key for key in pinned)


# ── command line: report files and step summary ──────────────────────────────


def test_the_cli_gate_names_both_seeded_fixable_findings():
    artifact, _ = image_scan.read_report(FIXTURES / "seeded-critical.json")

    done = _cli("gate", "--report", str(FIXTURES / "seeded-critical.json"),
                "--artifact", artifact)

    assert done.returncode == 1, done.stderr
    for text in ("CVE-2099-0001", "seeded-critical-package", "CVE-2099-0002",
                 "seeded-high-package"):
        assert text in done.stderr


def test_the_cli_gate_passes_the_seeded_no_fix_report_and_lists_it(tmp_path: Path):
    artifact, _ = image_scan.read_report(FIXTURES / "seeded-no-fix.json")
    no_fix = tmp_path / "no-fix.txt"
    summary = tmp_path / "summary.md"

    done = _cli("gate", "--report", str(FIXTURES / "seeded-no-fix.json"), "--artifact", artifact,
                "--platform", "linux/amd64", "--no-fix", str(no_fix), "--summary", str(summary))

    assert done.returncode == 0, done.stderr
    lines = no_fix.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for vid in ("CVE-2099-0003", "CVE-2099-0004"):
        assert sum(vid in line for line in lines) == 1
        assert vid in done.stdout
    assert "| failing | excepted | without fix |" in summary.read_text(encoding="utf-8")
    assert "Seeded" not in summary.read_text(encoding="utf-8"), "titles are not printed"


def test_the_cli_gate_refuses_an_invalid_platform(tmp_path: Path):
    artifact, _ = image_scan.read_report(FIXTURES / "seeded-no-fix.json")

    done = _cli("gate", "--report", str(FIXTURES / "seeded-no-fix.json"), "--artifact", artifact,
                "--platform", "linux/amd64\nFAIL")

    assert done.returncode == 2


def test_scan_writes_the_no_fix_list_and_the_counts_of_every_image(tmp_path: Path):
    run = FakeTrivy({"linux/arm64": [_vuln("CVE-2026-7", "ncurses-base", "CRITICAL",
                                           fixed=None),
                                     _vuln("CVE-2026-8", "libc6", "LOW")]})
    out = tmp_path / "out"
    summary = tmp_path / "summary.md"

    problems = image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", []), out,
                               tmp_path / "cache", TODAY, run=run, summary=summary)

    assert problems == []
    lines = (out / "no-fix.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # both images on arm64
    assert all("\tlinux/arm64\tCVE-2026-7\tncurses-base\t1.0\tCRITICAL" in line
               for line in lines)
    text = summary.read_text(encoding="utf-8")
    assert text.count("| linux/") == 4
    assert f"| {ARTIFACT} | linux/arm64 | 0 | 0 | 1 | 1 |" in text


def test_scan_writes_an_empty_no_fix_list_when_every_finding_has_a_fix(tmp_path: Path):
    out = tmp_path / "out"

    image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", []), out,
                    tmp_path / "cache", TODAY, run=FakeTrivy())

    assert (out / "no-fix.txt").read_text(encoding="utf-8") == ""


def test_scan_fails_an_entry_that_covers_only_findings_without_a_fix(tmp_path: Path):
    run = FakeTrivy({"linux/arm64": [_vuln("CVE-2026-1001", "libexample", "HIGH",
                                           fixed=None)]})

    problems = image_scan.scan(_builds(tmp_path), _exceptions(tmp_path / "exc.yaml", [_entry()]),
                               tmp_path / "out", tmp_path / "cache", TODAY, run=run)

    assert len(problems) == 1 and "covers only findings without a fix" in problems[0]
