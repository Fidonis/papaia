"""Vulnerability gate of the core's own images (tools/scan-images, CI job `images`).

Every platform of every built digest (the builds file of `build-images build`) is
scanned with a pinned Trivy image. The JSON report, which lists every package, is
also converted to a CycloneDX SBOM; a release attaches it to the image as a cosign
attestation (`build-images sign-keyless`).

The scanner always writes the complete report (every severity, with and without a
fix); the gate decides from it (docs/compatibility.md, "Image scan rule"):

- a CRITICAL or HIGH finding with a fix (`FixedVersion`) fails unless an entry of
  `security/exceptions.yaml` allowed below covers it;
- a CRITICAL or HIGH finding without a fix passes and is listed (`no-fix.txt`, one
  line per finding, and the counts in the step summary); the list is reviewed monthly;
- MEDIUM, LOW and UNKNOWN findings are counted and do not fail;
- an expired entry fails on its own, so it is reviewed or removed, and so does an entry
  that covers only findings without a fix.

An entry for an own image carries `id`, `package`, `severity` (HIGH), `reason`,
`expires` (YYYY-MM-DD, at most 90 days ahead) and `approved_by` (the security
officer's countersignature); a CRITICAL finding with a fix of an own image is never
excepted. An entry for a third-party image additionally names `image`
(`repository@sha256:<digest>`, a digest the checkout pins) and `added`; it may name
HIGH or CRITICAL and ends at most 14 days after `added`. An entry whose
countersignature is still pending waives nothing. Unknown fields, duplicates and
invalid values are refused, and a report that is not of the scanned digest is refused.
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

from . import image_pins, images, own_images, suite

EXCEPTIONS_PATH = Path("security") / "exceptions.yaml"
# Trivy 0.76.2 (amd64 and arm64).
TRIVY_IMAGE = (
    "aquasec/trivy:0.76.2"
    "@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
GATED = ("CRITICAL", "HIGH")
MAX_DAYS = 90
THIRD_PARTY_MAX_DAYS = 14
NO_FIX_NAME = "no-fix.txt"
MAX_ENTRIES = 500
MAX_EXCEPTIONS_BYTES = 256 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 900

_ENTRY_KEYS = ("id", "package", "severity", "reason", "expires", "approved_by")
_THIRD_PARTY_KEYS = ("image", "id", "package", "severity", "reason", "added", "expires",
                     "approved_by")
_PLATFORM_RE = re.compile(r"\A[a-z0-9]{1,16}/[a-z0-9]{1,16}(?:/[a-z0-9]{1,16})?\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
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
    severity: str = "HIGH"
    # Pin key (registry/repository@digest) of a third-party image; empty for own images.
    image: str = ""
    added: date | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.image, self.id, self.package)

    @property
    def signed(self) -> bool:
        return "pending" not in self.approved_by.lower()

    @property
    def label(self) -> str:
        scope = f" of {self.image}" if self.image else ""
        return f"exception {self.id} for {self.package}{scope}"


@dataclass(frozen=True)
class Finding:
    id: str
    package: str
    source: str
    severity: str
    target: str
    installed: str = ""
    fixed: str = ""  # empty: no fix is available


@dataclass
class Verdict:
    """The decision over one report."""

    problems: list[str]
    excepted: int
    no_fix: list[Finding]
    other: int
    used: set[tuple[str, str, str]]  # entries that waived a finding with a fix
    no_fix_hits: set[tuple[str, str, str]]  # entries that matched a finding without a fix


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


def _date(value: object, where: str, key: str) -> date:
    if isinstance(value, str) and _DATE_RE.match(value):
        try:
            value = date.fromisoformat(value)
        except ValueError:
            pass
    # datetime is a subclass of date; a time of day is not a review date.
    if not isinstance(value, date) or type(value) is not date:
        raise ScanError(f"{where}: {key} must be a date (YYYY-MM-DD)")
    return value


def _expires(value: object, where: str, today: date) -> date:
    value = _date(value, where, "expires")
    if value > today + timedelta(days=MAX_DAYS):
        raise ScanError(f"{where}: expires {value} is more than {MAX_DAYS} days ahead")
    return value


def pin_key(text: str) -> str:
    """`registry/repository@digest` of an image reference with a digest."""
    try:
        ref = images.parse_ref(text)
    except images.ImageError as exc:
        raise ScanError(str(exc)) from exc
    if not ref.digest:
        raise ScanError(f"image {text[:120]!r} names no digest")
    return f"{ref.registry}/{ref.repository}@{ref.digest}"


def _artifact_key(artifact: str) -> str | None:
    try:
        return pin_key(artifact)
    except ScanError:
        return None


def is_own(artifact: str, own_names: tuple[str, ...] | list[str]) -> bool:
    """True when the artifact is one of the own images, under any registry prefix."""
    try:
        ref = images.parse_ref(artifact)
    except images.ImageError:
        return False
    name = f"{ref.registry}/{ref.repository}"
    return any(name == own or name.endswith("/" + own) for own in own_names)


def _common(entry: dict, where: str) -> tuple[str, str]:
    if not isinstance(entry["id"], str) or not _ID_RE.match(entry["id"]):
        raise ScanError(f"{where}: id must be a CVE or GHSA id")
    if not isinstance(entry["package"], str) or not _PACKAGE_RE.match(entry["package"]):
        raise ScanError(f"{where}: package must name one package")
    return entry["id"], entry["package"]


def _fields(entry: dict, keys: tuple[str, ...], where: str) -> None:
    unknown = sorted(str(key) for key in entry if key not in keys)
    if unknown:
        raise ScanError(f"{where}: unknown field(s) {', '.join(unknown)}")
    missing = [key for key in keys if key not in entry]
    if missing:
        raise ScanError(f"{where}: missing field(s) {', '.join(missing)}")


def _own_entry(entry: dict, where: str, today: date) -> Accepted:
    _fields(entry, _ENTRY_KEYS, where)
    vid, package = _common(entry, where)
    if entry["severity"] != "HIGH":
        raise ScanError(f"{where}: severity must be HIGH; a critical finding is never "
                        "excepted, fix it instead")
    return Accepted(
        id=vid,
        package=package,
        reason=_text(entry, "reason", where, 20, 1000),
        expires=_expires(entry["expires"], where, today),
        approved_by=_text(entry, "approved_by", where, 3, 200),
    )


def _third_party_entry(entry: dict, where: str, today: date, pinned: frozenset[str],
                       own_names: tuple[str, ...]) -> Accepted:
    if "image" not in entry:
        raise ScanError(f"{where}: an entry with added is for a third-party image and needs "
                        "image (repository@sha256:<digest>)")
    _fields(entry, _THIRD_PARTY_KEYS, where)
    vid, package = _common(entry, where)
    image = entry["image"]
    if not isinstance(image, str) or "@sha256:" not in image or len(image) > 512:
        raise ScanError(f"{where}: image must be repository@sha256:<digest>")
    if ":" in image.split("@", 1)[0].rsplit("/", 1)[-1]:
        raise ScanError(f"{where}: image must be repository@sha256:<digest> without a tag")
    key = pin_key(image)
    if is_own(image, own_names):
        raise ScanError(f"{where}: {image} is an own image; its entries name no image and "
                        f"no added date")
    if key not in pinned:
        raise ScanError(f"{where}: {image} is no longer pinned in this checkout; remove "
                        "the entry")
    if entry["severity"] not in GATED:
        raise ScanError(f"{where}: severity must be HIGH or CRITICAL")
    added = _date(entry["added"], where, "added")
    if added > today:
        raise ScanError(f"{where}: added {added} is in the future")
    expires = _date(entry["expires"], where, "expires")
    if not added <= expires <= added + timedelta(days=THIRD_PARTY_MAX_DAYS):
        raise ScanError(f"{where}: expires {expires} must be at most "
                        f"{THIRD_PARTY_MAX_DAYS} days after added {added}")
    return Accepted(
        id=vid,
        package=package,
        reason=_text(entry, "reason", where, 20, 1000),
        expires=expires,
        approved_by=_text(entry, "approved_by", where, 3, 200),
        severity=entry["severity"],
        image=key,
        added=added,
    )


def _entry(entry: object, where: str, today: date, pinned: frozenset[str],
           own_names: tuple[str, ...]) -> Accepted:
    if not isinstance(entry, dict):
        raise ScanError(f"{where}: must be a mapping")
    if "image" in entry or "added" in entry:
        return _third_party_entry(entry, where, today, pinned, own_names)
    return _own_entry(entry, where, today)


def load_exceptions(path: Path, today: date, pinned: frozenset[str] = frozenset(),
                    own_names: tuple[str, ...] = ()) -> list[Accepted]:
    """The entries of an exception file; ScanError when it is not valid. `pinned` holds
    the pin keys of the checkout: a third-party entry must name one of them."""
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
    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(entries):
        item = _entry(entry, f"exception file {path}: exceptions[{index}]", today,
                      frozenset(pinned), tuple(own_names))
        if item.key in seen:
            raise ScanError(f"exception file {path}: {item.label} is listed twice")
        seen.add(item.key)
        accepted.append(item)
    return accepted


def pinned_keys(repo_root: Path) -> frozenset[str]:
    """The pin keys of every image the checkout pins by digest."""
    try:
        pins = image_pins.collect(Path(repo_root))
    except image_pins.PinError as exc:
        raise ScanError(f"pins of the checkout: {exc}") from exc
    keys = set()
    for pin in pins:
        try:
            keys.add(pin_key(pin.ref))
        except ScanError:
            continue  # a pin without a digest cannot carry a third-party entry
    return frozenset(keys)


def own_image_names(repo_root: Path) -> tuple[str, ...]:
    return tuple(image.name for image in own_images.load(Path(repo_root)))


def expired(accepted: list[Accepted], today: date) -> list[str]:
    return [f"{item.label} expired on {item.expires}: review or remove it in "
            f"{EXCEPTIONS_PATH}" for item in accepted if item.expires < today]


def only_no_fix(accepted: list[Accepted], used: set, no_fix_hits: set) -> list[str]:
    """Entries that matched findings without a fix and waived none with a fix."""
    return [f"{item.label} covers only findings without a fix: remove it from "
            f"{EXCEPTIONS_PATH}; the report lists them" for item in accepted
            if item.key in no_fix_hits and item.key not in used]


# ── report and gate ──────────────────────────────────────────────────────────


def _str(value: object, where: str, key: str, required: bool = True,
         limit: int = 300) -> str:
    if (value is None or value == "") and not required:
        return ""
    if (not isinstance(value, str) or not 0 < len(value) <= limit
            or _CONTROL_RE.search(value)):
        raise ScanError(f"{where}: {key} must be text of at most {limit} characters "
                        "without control characters")
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
                installed=_str(vuln.get("InstalledVersion"), at, "InstalledVersion",
                               required=False),
                fixed=_str(vuln.get("FixedVersion"), at, "FixedVersion", required=False,
                           limit=1000),
            ))
    return artifact, findings


def evaluate(artifact: str, findings: list[Finding], accepted: list[Accepted], today: date,
             own: bool) -> Verdict:
    """Decide over the findings of one report of `artifact` (an own image or not)."""
    target_key = "" if own else _artifact_key(artifact)
    applicable = [item for item in accepted
                  if item.expires >= today and target_key is not None
                  and item.image == target_key]
    verdict = Verdict([], 0, [], 0, set(), set())
    for finding in findings:
        if finding.severity not in GATED:
            verdict.other += 1
            continue
        matching = [item for item in applicable
                    if item.id == finding.id and item.severity == finding.severity
                    and item.package in {finding.package, finding.source} - {""}]
        if not finding.fixed:
            verdict.no_fix.append(finding)
            verdict.no_fix_hits.update(item.key for item in matching)
            continue
        signed = [item for item in matching if item.signed]
        if signed:
            verdict.excepted += 1
            verdict.used.update(item.key for item in signed)
            continue
        label = (f"{finding.severity} {finding.id} in {finding.package} ({finding.target}): "
                 f"fixed in {finding.fixed}")
        if matching:
            verdict.problems.append(f"{label}; the entry in {EXCEPTIONS_PATH} is not "
                                    "countersigned yet")
        elif own and finding.severity == "CRITICAL":
            verdict.problems.append(f"{label}; a critical finding with a fix always fails: "
                                    "rebuild on a fixed base or update the package")
        elif own:
            verdict.problems.append(f"{label}; no unexpired entry in {EXCEPTIONS_PATH}: "
                                    "take the fix into the image")
        else:
            verdict.problems.append(f"{label}; no unexpired entry for this digest in "
                                    f"{EXCEPTIONS_PATH}: re-pin a rebuilt image")
    return verdict


def failing(findings: list[Finding], accepted: list[Accepted], today: date,
            artifact: str = "", own: bool = True) -> list[str]:
    """Every finding that fails the gate."""
    return evaluate(artifact, findings, accepted, today, own).problems


def gate(findings: list[Finding], accepted: list[Accepted], today: date,
         artifact: str = "", own: bool = True) -> list[str]:
    """The problems of one report: every failing finding, every entry that covers only
    findings without a fix, then every expired entry."""
    verdict = evaluate(artifact, findings, accepted, today, own)
    return (verdict.problems + only_no_fix(accepted, verdict.used, verdict.no_fix_hits)
            + expired(accepted, today))


# ── report: no-fix list and step summary ─────────────────────────────────────


def no_fix_line(ref: str, platform: str, finding: Finding) -> str:
    """One line of no-fix.txt: image, platform, id, package, installed version, severity."""
    return "\t".join((ref, platform, finding.id, finding.package, finding.installed or "-",
                      finding.severity))


SUMMARY_HEAD = (
    "### Image scan\n\n"
    "A CRITICAL or HIGH finding with a fix fails; one without a fix is listed in "
    f"`{NO_FIX_NAME}` of the `images-report` artefact. Other counts MEDIUM, LOW and "
    "UNKNOWN.\n\n"
    "| image | platform | failing | excepted | without fix | other |\n"
    "|---|---|---:|---:|---:|---:|\n"
)


def summary_row(ref: str, platform: str, verdict: Verdict) -> str:
    cells = (ref.replace("|", "\\|"), platform, len(verdict.problems), verdict.excepted,
             len(verdict.no_fix), verdict.other)
    return "| " + " | ".join(str(cell) for cell in cells) + " |\n"


def _write(path: Path, text: str, mode: str) -> None:
    path = Path(path)
    if path.is_symlink():
        raise ScanError(f"{path}: refusing to write through a symbolic link")
    with path.open(mode, encoding="utf-8") as handle:
        handle.write(text)


def _lines(lines: list[str]) -> str:
    return "".join(line + "\n" for line in lines)


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
         run: Runner = _run, summary: Path | None = None,
         pinned: frozenset[str] = frozenset(), own_names: tuple[str, ...] = ()) -> list[str]:
    """Scan both platforms of every built digest; the gate's problems, prefixed with
    the image and platform. Reports, SBOMs and no-fix.txt are written to `out`; the
    counts per image and platform are appended to `summary`."""
    accepted = load_exceptions(exceptions, today, pinned, own_names)
    prefix, entries = own_images.read_builds(builds)
    out.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    no_fix: list[str] = []
    rows: list[str] = []
    used: set = set()
    hits: set = set()
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
            verdict = evaluate(ref, findings, accepted, today, own=True)
            problems += [f"{ref} {platform}: {problem}" for problem in verdict.problems]
            no_fix += [no_fix_line(ref, platform, finding) for finding in verdict.no_fix]
            rows.append(summary_row(ref, platform, verdict))
            used |= verdict.used
            hits |= verdict.no_fix_hits
    _write(out / NO_FIX_NAME, _lines(no_fix), "w")
    if summary is not None:
        _write(summary, SUMMARY_HEAD + "".join(rows) + "\n", "a")
    return problems + only_no_fix(accepted, used, hits) + expired(accepted, today)


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
    parsers["gate"].add_argument("--platform", default="-", help="platform of the report")
    parsers["gate"].add_argument("--no-fix", default=None,
                                 help=f"write the findings without a fix here ({NO_FIX_NAME})")
    for name in ("gate", "scan"):
        parsers[name].add_argument("--summary", default=None,
                                   help="append the counts (e.g. $GITHUB_STEP_SUMMARY)")
    parsers["scan"].add_argument("--builds", required=True, help="builds file of the build")
    parsers["scan"].add_argument("--out", required=True, help="folder for reports and SBOMs")
    parsers["scan"].add_argument("--cache", default=None, help="Trivy cache folder")
    args = parser.parse_args(argv)
    root = Path(args.repo_root)
    exceptions = Path(args.exceptions) if args.exceptions else root / EXCEPTIONS_PATH
    today = date.today()
    try:
        own_names = own_image_names(root)
        pinned = pinned_keys(root)
        accepted = load_exceptions(exceptions, today, pinned, own_names)
        if args.action == "check":
            problems = expired(accepted, today)
            summary = f"{len(accepted)} exception(s), none expired."
        elif args.action == "gate":
            if args.platform != "-" and not _PLATFORM_RE.match(args.platform):
                raise ScanError("--platform must be os/arch, e.g. linux/amd64")
            artifact, findings = read_report(Path(args.report))
            if artifact != args.artifact:
                raise ScanError(f"report {args.report} is of {artifact}, not of {args.artifact}")
            own = is_own(artifact, own_names)
            verdict = evaluate(artifact, findings, accepted, today, own)
            problems = (verdict.problems
                        + only_no_fix(accepted, verdict.used, verdict.no_fix_hits)
                        + expired(accepted, today))
            lines = [no_fix_line(artifact, args.platform, f) for f in verdict.no_fix]
            for line in lines:
                print(f"NO FIX: {line}")
            if args.no_fix:
                _write(Path(args.no_fix), _lines(lines), "w")
            if args.summary:
                _write(Path(args.summary),
                       SUMMARY_HEAD + summary_row(artifact, args.platform, verdict) + "\n", "a")
            summary = (f"{artifact}: {len(findings)} finding(s), {len(lines)} without a fix "
                       "(listed), none failing.")
        else:
            out = Path(args.out)
            cache = Path(args.cache) if args.cache else out / ".trivy-cache"
            problems = scan(Path(args.builds), exceptions, out, cache, today,
                            summary=Path(args.summary) if args.summary else None,
                            pinned=pinned, own_names=own_names)
            count = len((out / NO_FIX_NAME).read_text(encoding="utf-8").splitlines())
            print(f"{count} finding(s) without a fix listed in {out / NO_FIX_NAME}")
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
