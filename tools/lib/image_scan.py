"""Vulnerability gate of the core's own images (tools/scan-images, CI job `images`).

Every platform of every built digest (the builds file of `build-images build`) is
scanned with a pinned Trivy image. The JSON report, which lists every package, is
also converted to a CycloneDX SBOM; a release attaches it to the image as a cosign
attestation (`build-images sign-keyless`).

The gate over each report:

- a CRITICAL finding always fails; no exception can be written for it;
- a HIGH finding passes only with an entry in `security/exceptions.yaml` that names
  its id and package (or the source package) and has not expired;
- an expired entry fails on its own, so it is reviewed or removed;
- MEDIUM, LOW and UNKNOWN findings are kept in the report and do not fail.

An entry carries `id`, `package`, `severity` (HIGH), `reason`, `expires`
(YYYY-MM-DD, at most 90 days ahead) and `approved_by` (the security officer's
countersignature). Unknown fields, duplicates and invalid values are refused, and a
report that is not of the scanned digest is refused.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import yaml

from . import own_images, suite

EXCEPTIONS_PATH = Path("security") / "exceptions.yaml"
# Trivy 0.76.2 (amd64 and arm64).
TRIVY_IMAGE = (
    "aquasec/trivy:0.76.2"
    "@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAX_DAYS = 90
MAX_ENTRIES = 500
MAX_EXCEPTIONS_BYTES = 256 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 900

_ENTRY_KEYS = ("id", "package", "severity", "reason", "expires", "approved_by")
_ID_RE = re.compile(r"\A(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\Z")
_PACKAGE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9+._:/@-]{0,213}\Z")
_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


class ScanError(ValueError):
    """An exception file, a report or a scan that cannot be used; the message says why."""


@dataclass(frozen=True)
class Accepted:
    id: str
    package: str
    reason: str
    expires: date
    approved_by: str


@dataclass(frozen=True)
class Finding:
    id: str
    package: str
    source: str
    severity: str
    target: str


Runner = Callable[..., subprocess.CompletedProcess]


def _run(cmd: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=SCAN_TIMEOUT_SECONDS, check=False)


def _read(path: Path, limit: int, what: str) -> bytes:
    try:
        return suite._read_limited(Path(path), limit, what)
    except suite.SuiteError as exc:
        raise ScanError(str(exc)) from exc


# ── exception file ───────────────────────────────────────────────────────────


def _text(entry: dict, key: str, where: str, low: int, high: int) -> str:
    value = entry[key]
    if not isinstance(value, str) or not low <= len(value.strip()) <= high:
        raise ScanError(f"{where}: {key} must be text of {low} to {high} characters")
    return value.strip()


def _expires(value: object, where: str, today: date) -> date:
    if isinstance(value, str) and _DATE_RE.match(value):
        try:
            value = date.fromisoformat(value)
        except ValueError:
            pass
    # datetime is a subclass of date; a time of day is not a review date.
    if not isinstance(value, date) or type(value) is not date:
        raise ScanError(f"{where}: expires must be a date (YYYY-MM-DD)")
    if value > today + timedelta(days=MAX_DAYS):
        raise ScanError(f"{where}: expires {value} is more than {MAX_DAYS} days ahead")
    return value


def _entry(entry: object, where: str, today: date) -> Accepted:
    if not isinstance(entry, dict):
        raise ScanError(f"{where}: must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in _ENTRY_KEYS)
    if unknown:
        raise ScanError(f"{where}: unknown field(s) {', '.join(unknown)}")
    missing = [key for key in _ENTRY_KEYS if key not in entry]
    if missing:
        raise ScanError(f"{where}: missing field(s) {', '.join(missing)}")
    if not isinstance(entry["id"], str) or not _ID_RE.match(entry["id"]):
        raise ScanError(f"{where}: id must be a CVE or GHSA id")
    if not isinstance(entry["package"], str) or not _PACKAGE_RE.match(entry["package"]):
        raise ScanError(f"{where}: package must name one package")
    if entry["severity"] != "HIGH":
        raise ScanError(f"{where}: severity must be HIGH; a critical finding is never "
                        "excepted, fix it instead")
    return Accepted(
        id=entry["id"],
        package=entry["package"],
        reason=_text(entry, "reason", where, 20, 1000),
        expires=_expires(entry["expires"], where, today),
        approved_by=_text(entry, "approved_by", where, 3, 200),
    )


def load_exceptions(path: Path, today: date) -> list[Accepted]:
    """The entries of an exception file; ScanError when it is not valid."""
    try:
        doc = yaml.safe_load(_read(path, MAX_EXCEPTIONS_BYTES, "exception file"))
    except yaml.YAMLError as exc:
        raise ScanError(f"exception file {path}: not YAML") from exc
    if not isinstance(doc, dict):
        raise ScanError(f"exception file {path}: expected version and exceptions")
    unknown = sorted(str(key) for key in doc if key not in ("version", "exceptions"))
    if unknown:
        raise ScanError(f"exception file {path}: unknown field(s) {', '.join(unknown)}")
    if doc.get("version") != 1:
        raise ScanError(f"exception file {path}: version must be 1")
    entries = doc.get("exceptions")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ScanError(f"exception file {path}: exceptions must be a list of at most "
                        f"{MAX_ENTRIES} entries")
    accepted: list[Accepted] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        item = _entry(entry, f"exception file {path}: exceptions[{index}]", today)
        if (item.id, item.package) in seen:
            raise ScanError(f"exception file {path}: {item.id} for {item.package} is "
                            "listed twice")
        seen.add((item.id, item.package))
        accepted.append(item)
    return accepted


def expired(accepted: list[Accepted], today: date) -> list[str]:
    return [f"exception {item.id} for {item.package} expired on {item.expires}: review "
            f"or remove it in {EXCEPTIONS_PATH}" for item in accepted if item.expires < today]


# ── report and gate ──────────────────────────────────────────────────────────


def _str(value: object, where: str, key: str, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not 0 < len(value) <= 300:
        raise ScanError(f"{where}: {key} must be text")
    return value


def read_report(path: Path) -> tuple[str, list[Finding]]:
    """(artifact, findings) of a Trivy JSON report (schema version 2)."""
    try:
        doc = json.loads(_read(path, MAX_REPORT_BYTES, "scan report"))
    except ValueError as exc:
        raise ScanError(f"scan report {path}: not JSON") from exc
    if not isinstance(doc, dict) or doc.get("SchemaVersion") != 2:
        raise ScanError(f"scan report {path}: expected a Trivy report with SchemaVersion 2")
    artifact = _str(doc.get("ArtifactName"), f"scan report {path}", "ArtifactName")
    results = doc.get("Results") or []
    if not isinstance(results, list):
        raise ScanError(f"scan report {path}: Results must be a list")
    findings: list[Finding] = []
    for r_index, result in enumerate(results):
        where = f"scan report {path}: Results[{r_index}]"
        if not isinstance(result, dict):
            raise ScanError(f"{where}: must be a mapping")
        target = _str(result.get("Target"), where, "Target")
        vulns = result.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            raise ScanError(f"{where}: Vulnerabilities must be a list")
        for v_index, vuln in enumerate(vulns):
            at = f"{where}.Vulnerabilities[{v_index}]"
            if not isinstance(vuln, dict):
                raise ScanError(f"{at}: must be a mapping")
            severity = vuln.get("Severity")
            if severity not in SEVERITIES:
                raise ScanError(f"{at}: Severity must be one of {', '.join(SEVERITIES)}")
            findings.append(Finding(
                id=_str(vuln.get("VulnerabilityID"), at, "VulnerabilityID"),
                package=_str(vuln.get("PkgName"), at, "PkgName"),
                source=_str(vuln.get("SrcName"), at, "SrcName", required=False),
                severity=severity,
                target=target,
            ))
    return artifact, findings


def failing(findings: list[Finding], accepted: list[Accepted], today: date) -> list[str]:
    """Every finding that fails the gate."""
    valid = {(item.id, item.package) for item in accepted if item.expires >= today}
    problems: list[str] = []
    for finding in findings:
        label = f"{finding.severity} {finding.id} in {finding.package} ({finding.target})"
        if finding.severity == "CRITICAL":
            problems.append(f"{label}: critical findings always fail; rebuild on a fixed "
                            "base or update the package")
        elif finding.severity == "HIGH" and not (
            (finding.id, finding.package) in valid
            or (finding.source and (finding.id, finding.source) in valid)
        ):
            problems.append(f"{label}: no unexpired entry in {EXCEPTIONS_PATH}")
    return problems


def gate(findings: list[Finding], accepted: list[Accepted], today: date) -> list[str]:
    """The problems of one report: every failing finding, then every expired entry."""
    return failing(findings, accepted, today) + expired(accepted, today)


# ── scan ─────────────────────────────────────────────────────────────────────


def _trivy(out: Path, cache: Path, *args: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "host",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "-e", "TRIVY_CACHE_DIR=/cache", "-e", "HOME=/tmp", "--tmpfs", "/tmp",
        "-v", f"{cache.resolve()}:/cache:rw", "-v", f"{out.resolve()}:/out:rw",
        TRIVY_IMAGE, *args,
    ]  # fmt: skip


def scan(builds: Path, exceptions: Path, out: Path, cache: Path, today: date,
         run: Runner = _run) -> list[str]:
    """Scan both platforms of every built digest; the gate's problems, prefixed with
    the image and platform. Reports and SBOMs are written to `out`."""
    accepted = load_exceptions(exceptions, today)
    prefix, entries = own_images.read_builds(builds)
    out.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    for entry in entries:
        ref = f"{prefix}{entry['name']}@{entry['digest']}"
        short = entry["name"].rsplit("/", 1)[1]
        for platform in own_images.PLATFORMS:
            stem = f"{short}-{platform.split('/', 1)[1]}"
            steps = (
                ("image", "--quiet", "--scanners", "vuln", "--list-all-pkgs",
                 "--platform", platform, "--format", "json",
                 "--output", f"/out/{stem}.trivy.json", ref),
                ("convert", "--quiet", "--format", "cyclonedx",
                 "--output", f"/out/{stem}.cdx.json", f"/out/{stem}.trivy.json"),
            )
            for args in steps:
                done = run(_trivy(out, cache, *args))
                if done.returncode != 0:
                    raise ScanError(f"trivy {args[0]} of {ref} ({platform}) failed:\n"
                                    f"{(done.stderr or '')[-2000:]}")
            artifact, findings = read_report(out / f"{stem}.trivy.json")
            if artifact != ref:
                raise ScanError(f"report {stem}.trivy.json is of {artifact}, not of {ref}")
            problems += [f"{ref} {platform}: {problem}"
                         for problem in failing(findings, accepted, today)]
    return problems + expired(accepted, today)


# ── command line (tools/scan-images) ─────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scan-images", description=__doc__.split("\n")[0])
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    sub = parser.add_subparsers(dest="action", required=True)
    actions = {
        "check": "validate the exception file; expired entries fail",
        "gate": "run the gate over one Trivy JSON report",
        "scan": "scan every platform of every built digest",
    }
    parsers = {name: sub.add_parser(name, help=text) for name, text in actions.items()}
    for p in parsers.values():
        p.add_argument("--exceptions", default=None, help=f"default: {EXCEPTIONS_PATH}")
    parsers["gate"].add_argument("--report", required=True)
    parsers["gate"].add_argument("--artifact", required=True, help="the scanned reference")
    parsers["scan"].add_argument("--builds", required=True, help="builds file of the build")
    parsers["scan"].add_argument("--out", required=True, help="folder for reports and SBOMs")
    parsers["scan"].add_argument("--cache", default=None, help="Trivy cache folder")
    args = parser.parse_args(argv)
    root = Path(args.repo_root)
    exceptions = Path(args.exceptions) if args.exceptions else root / EXCEPTIONS_PATH
    today = date.today()
    try:
        if args.action == "check":
            accepted = load_exceptions(exceptions, today)
            problems = expired(accepted, today)
            summary = f"{len(accepted)} exception(s), none expired."
        elif args.action == "gate":
            accepted = load_exceptions(exceptions, today)
            artifact, findings = read_report(Path(args.report))
            if artifact != args.artifact:
                raise ScanError(f"report {args.report} is of {artifact}, not of {args.artifact}")
            problems = gate(findings, accepted, today)
            summary = f"{artifact}: {len(findings)} finding(s), none failing."
        else:
            out = Path(args.out)
            cache = Path(args.cache) if args.cache else out / ".trivy-cache"
            problems = scan(Path(args.builds), exceptions, out, cache, today)
            summary = "every platform of every built image passed the gate."
    except (ScanError, own_images.OwnImageError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(summary)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
