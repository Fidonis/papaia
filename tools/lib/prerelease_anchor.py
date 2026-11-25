"""The test trust anchor of a pre-release core (ADR 0030).

A release candidate is tested end to end before the release: the core starts, upgrades and
confirms pairings against a bill of materials of candidate images. Those images are signed
with a local test key, because the release key signs deliveries only. The option
`--test-trust-anchor=FILE` lets exactly one `papaia-ctl` command (`start`, `upgrade`,
`pairing confirm`, `pairing list`, `suite verify`) accept a bill of materials of scope
`test` signed with the public key in FILE. Its limits:

- **Pre-release cores only.** The core `VERSION` must carry a SemVer pre-release part
  (`1.10.0-rc.1`). The version is read first; on a release version, or on any doubt about
  it, the option is refused before the key, the bill of materials or anything else is read.
- **Scope `test` only.** A `delivery` bill of materials keeps requiring the release key
  pinned in `compat/release-key.pub`; this module never reads, changes or replaces that key.
  A `test` bill of materials without the option is refused as before.
- **Exactly that key.** The embedded key of the bill of materials must hash to the
  fingerprint of the given key and the signature must hold with it; image signatures are
  then checked against that same key (lib/images.py).
- **Never implicit.** Only the command line sets it: no environment variable, configuration
  file or stored state is read here, and nothing of it is written except the audit row.
- **Visible.** A banner on standard error at the start and end of the command, and one
  `papaia.audit/1` row in the host's audit journal for every bill of materials checked with
  the anchor: command, key fingerprint, digest of the bill of materials, operator and
  correlation id, `allowed` or `denied`.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import images, suite

FLAG = "--test-trust-anchor"
SCOPE = "test"
EVENT = "test_trust_anchor_used"
VERSION_PATH = Path("VERSION")
MAX_VERSION_BYTES = 64
MAX_KEY_BYTES = 4096
MAX_PATH_CHARS = 4096
# The papaia-ctl commands that take the option; each names itself in banner and audit.
COMMANDS = ("start", "upgrade", "pairing-confirm", "pairing-list", "suite-verify")
# The image checks such a command runs inside it (lib/sh/lifecycle.sh `_verify_images`):
# the restore step of `start` and the module stages of `upgrade` among them.
AUDIT_COMMANDS = (*COMMANDS, "restore", "addon-install", "addon-start", "addon-upgrade",
                  "addon-rollback")

# A SemVer 2.0.0 version with a pre-release part and no build metadata: numeric
# identifiers without leading zeros, one optional trailing newline, nothing else.
_IDENT = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_PRERELEASE_RE = re.compile(
    rf"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-{_IDENT}(?:\.{_IDENT})*\Z"
)
_FINGERPRINT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class AnchorError(ValueError):
    """The test trust anchor may not be used; nothing was accepted."""


@dataclass(frozen=True)
class Anchor:
    """An opened test trust anchor: the key file, its fingerprint, the core version."""

    path: Path
    fingerprint: str
    version: str


def require_prerelease(repo_root: Path) -> str:
    """The core version when it is a pre-release; AnchorError otherwise. Reads `VERSION`
    and nothing else."""
    path = Path(repo_root) / VERSION_PATH
    try:
        raw = suite._read_limited(path, MAX_VERSION_BYTES, "VERSION")
    except suite.SuiteError as exc:
        raise AnchorError(f"{exc}; {FLAG} is accepted by pre-release cores only") from None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    version = text[:-1] if text.endswith("\n") else text
    if not _PRERELEASE_RE.match(version):
        shown = version[:40] if version.isprintable() else repr(version[:40])
        raise AnchorError(
            f"core VERSION {shown!r} is not a pre-release; {FLAG} is accepted by "
            "pre-release cores only (for example 1.10.0-rc.1). Nothing else was read."
        )
    return version


def _key_path(value: object) -> Path:
    if isinstance(value, Path):
        value = str(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PATH_CHARS
        or any(ch in value for ch in "\0\n\r")
    ):
        raise AnchorError(f"{FLAG}: a path to a public key file is expected")
    return Path(value)


def open_anchor(repo_root: Path, key_file: object) -> Anchor:
    """Refuse on a release core first; then read and check the public key in `key_file`
    (an ECDSA P-256 PEM key, as `cosign generate-key-pair` writes it)."""
    version = require_prerelease(repo_root)
    path = _key_path(key_file)
    try:
        raw = suite._read_limited(path, MAX_KEY_BYTES, "test trust anchor")
        # A key file copied on Windows has CRLF line endings; it is the same key.
        pem = raw.decode("ascii").replace("\r\n", "\n")
        fingerprint = suite.key_fingerprint(pem)
    except UnicodeDecodeError:
        raise AnchorError(f"test trust anchor {path}: not a PEM public key") from None
    except suite.SuiteError as exc:
        message = str(exc)
        if not message.startswith("test trust anchor"):
            message = f"test trust anchor {path}: {message}"
        raise AnchorError(message) from None
    return Anchor(path, fingerprint, version)


def _label(command: str) -> str:
    if command not in AUDIT_COMMANDS:
        raise AnchorError(f"command {command[:40]!r} does not take {FLAG}")
    return command


def audit_row(
    command: str,
    anchor: Anchor,
    bom_digest: str | None,
    correlation: str | None,
    *,
    result: str = "allowed",
) -> dict:
    """The `papaia.audit/1` row of one use of the anchor. No key material, no content of
    the bill of materials: its digest only."""
    row = images._row(
        _label(command),
        EVENT,
        {
            "command": command,
            "flag": FLAG,
            "scope": SCOPE,
            "fingerprint": anchor.fingerprint,
            "bom_digest": bom_digest,
            "core_version": anchor.version,
            "operator": images.confirming_user(),
        },
        correlation,
    )
    if result == "denied":
        row["result"] = "denied"
        row["error_code"] = "bom_refused"
    return row


def verified_bom(
    repo_root: Path,
    config_dir: Path,
    anchor: Anchor,
    command: str,
    correlation: str | None,
    *,
    bom_path: Path | None = None,
    signature_path: Path | None = None,
    expected_suite: str | None = None,
) -> dict:
    """The bill of materials of this core (or `bom_path`), verified against the anchor:
    signed with exactly that key, scope `test`, the suite of the core version (or
    `expected_suite`). Writes one audit row, `allowed` or `denied`."""
    try:
        correlation = images.correlation_id(correlation)
        path = Path(bom_path) if bom_path is not None else images.bom_path(
            Path(repo_root), anchor.version)
        expected = (expected_suite if expected_suite is not None
                    else images.suite_version(anchor.version))
    except images.ImageError as exc:
        raise AnchorError(str(exc)) from None
    signature = Path(signature_path) if signature_path is not None else Path(f"{path}.sig")
    try:
        doc, digest = suite.verify_bom_with_digest(
            path, signature, fingerprint=anchor.fingerprint, require_scope=SCOPE,
            expected_suite=expected,
        )
    except suite.SuiteError as exc:
        images.append_audit(
            config_dir, audit_row(command, anchor, None, correlation, result="denied"))
        raise AnchorError(f"bill of materials {path.name}: {exc}") from None
    images.append_audit(config_dir, audit_row(command, anchor, digest, correlation))
    print(
        f"WARNING: TEST TRUST ANCHOR {anchor.fingerprint}: bill of materials {path.name} "
        f"(scope '{SCOPE}', {digest}) accepted for '{command}'. Not for production. "
        f"Audit correlation id {correlation}.",
        file=sys.stderr,
    )
    return doc


_RULE = "=" * 74


def begin_banner(command: str, anchor: Anchor, correlation: str) -> str:
    return "\n".join((
        _RULE,
        f" TEST TRUST ANCHOR: {FLAG} is set for this '{command}' only.",
        f" Key {anchor.fingerprint}, scope '{SCOPE}', core {anchor.version}.",
        f" A bill of materials of scope '{SCOPE}' signed with this key is accepted;",
        " the release key and the 'delivery' scope are not used for it.",
        " NOT FOR PRODUCTION. Each use is recorded in the audit journal",
        f" (correlation id {correlation}). The next command is strict again.",
        _RULE,
    ))


def end_banner(command: str, fingerprint: str, exit_code: int, correlation: str) -> str:
    return "\n".join((
        _RULE,
        f" TEST TRUST ANCHOR: '{command}' ended with exit code {exit_code}.",
        f" Key {fingerprint}, scope '{SCOPE}'. NOT FOR PRODUCTION.",
        f" Audit correlation id {correlation}.",
        _RULE,
    ))


def cmd_test_anchor(args) -> int:
    """`test-anchor --phase=begin|end`: the gate papaia-ctl runs around a command given
    `--test-trust-anchor=FILE`. `begin` refuses on a release core before anything else,
    checks the key, prints the banner and, on standard output, `<fingerprint>\\t<correlation
    id>`; `end` prints the closing banner and reads nothing."""
    try:
        correlation = images.correlation_id(args.correlation_id)
    except images.ImageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    label = args.command.replace("-", " ")
    if args.phase == "begin":
        if args.fingerprint is not None or args.exit_code is not None:
            print("ERROR: --fingerprint and --exit-code go with --phase=end", file=sys.stderr)
            return 2
        try:
            anchor = open_anchor(Path(args.repo_root), args.test_trust_anchor)
        except AnchorError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(begin_banner(label, anchor, correlation), file=sys.stderr)
        print(f"{anchor.fingerprint}\t{correlation}")
        return 0
    if args.test_trust_anchor is not None:
        print(f"ERROR: {FLAG} goes with --phase=begin", file=sys.stderr)
        return 2
    if not isinstance(args.fingerprint, str) or not _FINGERPRINT_RE.match(args.fingerprint):
        print("ERROR: --fingerprint=sha256:<64 hex digits> is required", file=sys.stderr)
        return 2
    if args.exit_code is None or not 0 <= args.exit_code <= 255:
        print("ERROR: --exit-code=0..255 is required", file=sys.stderr)
        return 2
    print(end_banner(label, args.fingerprint, args.exit_code, correlation), file=sys.stderr)
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("test-anchor")
    p.add_argument("--phase", choices=("begin", "end"), required=True)
    p.add_argument("--command", choices=COMMANDS, required=True)
    p.add_argument(FLAG, dest="test_trust_anchor", default=None)
    p.add_argument("--fingerprint", default=None)
    p.add_argument("--exit-code", type=int, default=None)
    p.add_argument("--correlation-id", default=None)
    p.set_defaults(func=cmd_test_anchor)
