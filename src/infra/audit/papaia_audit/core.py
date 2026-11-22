"""papaia-audit core: submission checks, canonical JSON, the hash chain and its verification.

Standard library and jsonschema only. The database driver, TLS server and signing key
live in `__main__.py`, so this logic runs (and is tested) without them.

Rules (docs/audit.md):

- A request carries 1 to 500 lines of JSON, one submission per line, ascending
  `source_seq`. Lines are handled in order; the first line that is not stored ends the
  request, and the lines before it are acknowledged.
- A submission is checked against the vendored `papaia.audit/1` schema (submission form)
  plus the rules the schema cannot express: size, depth and string limits before any
  pattern runs, no fractions or exponents, no duplicate keys, a date that exists. Its
  `writer` must name the source of the client certificate.
- The chain per source is `hash = SHA-256(prev_hash || JCS(body))` (RFC 8785); the first
  event of a source has 32 zero bytes as `prev_hash`.

Error texts carry codes and positions only, never a value of the submission.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

FORMAT = "papaia.audit/1"
HEADS_FORMAT = "papaia.audit-heads/1"
SOURCES_FORMAT = "papaia.audit-sources/1"
SCHEMA_FILE = Path(__file__).with_name("audit.v1.schema.json")
SCHEMA_ID = "https://schemas.papaia.dev/audit.v1.schema.json"

MAX_LINES = 500
MAX_EVENT_BYTES = 16 * 1024
MAX_BODY_BYTES = MAX_LINES * (MAX_EVENT_BYTES + 1)
MAX_STRING = 256
MAX_DEPTH = 3
MAX_NODES = 512
ZERO_HASH = bytes(32)

# error_code of a refused line or request (contract of the platform kit, "Storing a batch").
INVALID = "audit.invalid_submission"
UNSUPPORTED = "audit.unsupported_format"
GAP = "audit.source_seq_gap"
INVALID_REQUEST = "audit.invalid_request"
UNKNOWN_SOURCE = "audit.unknown_source"
STORAGE = "audit.storage_unavailable"

SOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# Columns of audit.event that repeat a field of the body, for search; verify compares them.
DERIVED_COLUMNS = ("source_seq", "time", "sub", "event", "correlation_id", "catalog_id", "result")


class Refused(Exception):
    """A line or request that is not stored; `code` is the response's `error_code`."""

    def __init__(self, code: str, status: int = 422) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


# ─────────────────────────────────────────────────────────────────────────
# canonical JSON (RFC 8785)
# ─────────────────────────────────────────────────────────────────────────


def canonical_json(value: Any) -> bytes:
    """The RFC 8785 canonical form of `value`; ValueError for anything without one."""
    parts: list[str] = []
    _write(value, parts)
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("lone surrogate") from None


def _write(value: Any, out: list[str]) -> None:
    if value is None or value is True or value is False:
        out.append({None: "null", True: "true", False: "false"}[value])
    elif isinstance(value, int):
        out.append(_integer(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, Mapping):
        keys = list(value)
        if not all(isinstance(key, str) for key in keys):
            raise ValueError("object keys must be strings")
        keys.sort(key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        out.append("{")
        for index, key in enumerate(keys):
            out.append("," if index else "")
            out.append(json.dumps(key, ensure_ascii=False) + ":")
            _write(value[key], out)
        out.append("}")
    elif isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        out.append("[")
        for index, item in enumerate(value):
            out.append("," if index else "")
            _write(item, out)
        out.append("]")
    else:
        # Events carry no fractions (`papaia.audit/1`), so floats have no place here.
        raise ValueError(f"{type(value).__name__} is not allowed in an event")


def _integer(value: int) -> str:
    """ECMAScript Number::toString for an integer; only values a double holds exactly."""
    if abs(value) <= 2**53:
        return str(value)
    as_double = float(value)
    if not math.isfinite(as_double) or int(as_double) != value:
        raise ValueError("integer outside the exact range of a double")
    _, digit_tuple, exponent = Decimal(repr(abs(as_double))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    point = int(exponent) + len(digit_tuple)
    sign = "-" if value < 0 else ""
    if point <= 21:
        return sign + digits + "0" * (point - len(digits))
    mantissa = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    return f"{sign}{mantissa}e+{point - 1}"


def chain_hash(prev_hash: bytes, canonical: bytes) -> bytes:
    return hashlib.sha256(prev_hash + canonical).digest()


def hash_text(value: bytes) -> str:
    return "sha256:" + value.hex()


# ─────────────────────────────────────────────────────────────────────────
# submissions
# ─────────────────────────────────────────────────────────────────────────


def _no_fraction(_text: str) -> Any:
    raise ValueError("fraction")


def _no_constant(_text: str) -> Any:
    raise ValueError("constant")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # A repeated key is read differently by different parsers; the stored body and the
    # hash must not depend on which one a verifier uses.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _is_event_time(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    try:
        datetime.strptime(instance, _TIME_FORMAT)
    except ValueError:
        return False
    return True


def _within_limits(event: Mapping[str, Any]) -> bool:
    """Strings, keys, depth and node count, checked without recursion before the schema."""
    stack: list[tuple[Any, int]] = [(event, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            return False
        if isinstance(node, str):
            if len(node) > MAX_STRING:
                return False
        elif isinstance(node, dict | list):
            if depth > MAX_DEPTH:
                return False
            children = node.items() if isinstance(node, dict) else enumerate(node)
            for key, child in children:
                if isinstance(key, str) and len(key) > MAX_STRING:
                    return False
                stack.append((child, depth + 1))
    return True


class SubmissionCheck:
    """Turns one line of a request into a checked event and its canonical form."""

    def __init__(self, schema_file: Path = SCHEMA_FILE) -> None:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        if schema.get("$id") != SCHEMA_ID:
            raise RuntimeError(f"{schema_file.name} carries an unexpected $id")
        registry: Registry[Any] = Registry().with_resource(
            SCHEMA_ID, Resource.from_contents(schema)
        )
        formats = FormatChecker(("ipv4", "ipv6"))
        formats.checks("date-time")(_is_event_time)
        self._validator = Draft202012Validator(
            {"$ref": f"{SCHEMA_ID}#/$defs/submission"},
            registry=registry,
            format_checker=formats,
        )

    def check(self, line: bytes, source: str) -> tuple[dict[str, Any], bytes]:
        if len(line) > MAX_EVENT_BYTES:
            raise Refused(INVALID)
        try:
            event = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_unique_keys,
                parse_float=_no_fraction,
                parse_constant=_no_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise Refused(INVALID) from None
        if not isinstance(event, dict):
            raise Refused(INVALID)
        fmt = event.get("format")
        if isinstance(fmt, str) and fmt != FORMAT and fmt.startswith("papaia.audit/"):
            raise Refused(UNSUPPORTED)
        if not _within_limits(event):
            raise Refused(INVALID)
        if next(self._validator.iter_errors(event), None) is not None:
            raise Refused(INVALID)
        # The writer names its source; a certificate of one source cannot write for another.
        if event["writer"].split("/", 1)[0] != source:
            raise Refused(INVALID)
        try:
            canonical = canonical_json(event)
        except ValueError:
            raise Refused(INVALID) from None
        return event, canonical


def split_batch(body: bytes) -> list[bytes]:
    """The lines of a request body; a final newline is allowed, empty lines are not."""
    if not body or len(body) > MAX_BODY_BYTES:
        raise Refused(INVALID_REQUEST, 400)
    lines = body.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if not lines or len(lines) > MAX_LINES or any(not line.strip() for line in lines):
        raise Refused(INVALID_REQUEST, 400)
    return lines


class Store(Protocol):
    def append(self, source: str, canonical: str) -> int:
        """Store one event (or find the repeat) and return its `seq`.

        Raises Refused(GAP) when `source_seq` is not the next one of the source and
        Refused(STORAGE, 503) when the store fails.
        """
        ...


@dataclass
class BatchResult:
    acknowledged: list[dict[str, int]]
    refused: Refused | None = None


def ingest(store: Store, check: SubmissionCheck, source: str, lines: list[bytes]) -> BatchResult:
    acknowledged: list[dict[str, int]] = []
    previous = 0
    for line in lines:
        try:
            event, canonical = check.check(line, source)
            source_seq = event["source_seq"]
            if source_seq <= previous:
                raise Refused(INVALID)
            seq = store.append(source, canonical.decode("utf-8"))
        except Refused as refused:
            return BatchResult(acknowledged, refused)
        acknowledged.append({"source_seq": source_seq, "seq": seq})
        previous = source_seq
    return BatchResult(acknowledged)


def parse_sources(data: Any) -> dict[str, str]:
    """`sources.json` -> {certificate fingerprint: source}. ValueError when malformed."""
    if not isinstance(data, dict) or set(data) != {"format", "sources"}:
        raise ValueError("sources.json: expected format and sources")
    if data["format"] != SOURCES_FORMAT or not isinstance(data["sources"], dict):
        raise ValueError("sources.json: unknown format")
    by_fingerprint: dict[str, str] = {}
    for source, fingerprints in data["sources"].items():
        if not SOURCE_RE.match(source) or not isinstance(fingerprints, list):
            raise ValueError("sources.json: invalid source entry")
        for fingerprint in fingerprints:
            if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.match(fingerprint):
                raise ValueError("sources.json: invalid fingerprint")
            if by_fingerprint.setdefault(fingerprint, source) != source:
                raise ValueError("sources.json: one certificate for two sources")
    return by_fingerprint


# ─────────────────────────────────────────────────────────────────────────
# verification and chain heads
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class StoredRow:
    seq: int
    prev_hash: bytes
    hash: bytes
    columns: dict[str, Any]
    body: dict[str, Any]


@dataclass
class ChainReport:
    source: str
    valid: bool
    count: int = 0
    head_seq: int = 0
    broken_at: int | None = None
    reason: str | None = None
    # seq of the last event a retention run removed; the chain is checked from there.
    anchor_seq: int = 0
    # Hashes at the positions a heads file names, for the comparison.
    seen: dict[int, bytes] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "valid": self.valid,
            "count": self.count,
            "head_seq": self.head_seq,
            "broken_at": self.broken_at,
            "reason": self.reason,
            "anchor_seq": self.anchor_seq,
        }


def derived_columns(body: Mapping[str, Any]) -> dict[str, Any]:
    return {name: body.get(name) for name in DERIVED_COLUMNS}


def verify_chain(
    source: str,
    rows: Iterable[StoredRow],
    wanted: Iterable[int] = (),
    anchor: tuple[int, bytes] | None = None,
) -> ChainReport:
    """Walk one source's rows in `seq` order: gapless `seq` from 1, or from the event after
    the anchor `(seq, hash)` a retention run left; links, hashes, columns."""
    wanted_seqs = set(wanted)
    report = ChainReport(source, valid=True)
    expected, prev = 1, ZERO_HASH
    if anchor is not None:
        report.anchor_seq, prev = anchor
        expected = report.anchor_seq + 1
        report.head_seq = report.anchor_seq
        report.seen[report.anchor_seq] = prev
    for row in rows:
        reason = None
        if row.seq != expected:
            reason = "missing events"
        elif row.prev_hash != prev:
            reason = "link to the previous event changed"
        else:
            try:
                canonical = canonical_json(row.body)
            except ValueError:
                canonical = None
            if canonical is None or chain_hash(prev, canonical) != row.hash:
                reason = "event changed"
            elif derived_columns(row.body) != row.columns:
                reason = "search columns changed"
        if reason is not None:
            report.valid, report.broken_at, report.reason = False, expected, reason
            return report
        if row.seq in wanted_seqs:
            report.seen[row.seq] = row.hash
        report.count, report.head_seq = report.count + 1, row.seq
        prev, expected = row.hash, expected + 1
    return report


def heads_document(heads: Iterable[tuple[str, int, bytes]], signed_at: str) -> dict[str, Any]:
    """The signed statement of every source's last event (without the signature)."""
    return {
        "format": HEADS_FORMAT,
        "signed_at": signed_at,
        "heads": [
            {"source": source, "seq": seq, "hash": hash_text(digest)}
            for source, seq, digest in sorted(heads)
        ],
    }


def heads_payload(document: Mapping[str, Any]) -> bytes:
    """The bytes the signature covers: the canonical document without `signature`."""
    return canonical_json({key: value for key, value in document.items() if key != "signature"})


def parse_heads_line(line: str) -> tuple[dict[str, Any], bytes]:
    """One line of a heads file -> (document, signature). ValueError when malformed."""
    document = json.loads(line, object_pairs_hook=_unique_keys, parse_float=_no_fraction)
    if not isinstance(document, dict) or set(document) != {
        "format",
        "signed_at",
        "heads",
        "signature",
    }:
        raise ValueError("not a heads document")
    signature = document["signature"]
    if document["format"] != HEADS_FORMAT or not isinstance(signature, str):
        raise ValueError("not a heads document")
    if not signature.startswith("ed25519:") or not isinstance(document["heads"], list):
        raise ValueError("not a heads document")
    for head in document["heads"]:
        if not (
            isinstance(head, dict)
            and set(head) == {"source", "seq", "hash"}
            and isinstance(head["source"], str)
            and SOURCE_RE.match(head["source"])
            and isinstance(head["seq"], int)
            and head["seq"] >= 1
            and isinstance(head["hash"], str)
            and _FINGERPRINT_RE.match(head["hash"])
        ):
            raise ValueError("not a heads document")
    return document, base64.b64decode(signature.removeprefix("ed25519:"), validate=True)


def check_heads(reports: Mapping[str, ChainReport], heads: Iterable[Mapping[str, Any]]) -> None:
    """Mark a chain broken where it no longer holds a signed head; updates `reports`."""
    for head in heads:
        report = reports.get(head["source"])
        if report is None:
            continue
        seq = head["seq"]
        if not report.valid and report.broken_at is not None and report.broken_at <= seq:
            continue
        if seq < report.anchor_seq:
            # Removed by a retention run; the anchor itself is checked by check_anchors.
            continue
        if seq not in report.seen:
            report.valid, report.reason = False, "events after a signed head are missing"
            report.broken_at = min(report.head_seq + 1, report.broken_at or seq)
        elif hash_text(report.seen[seq]) != head["hash"]:
            report.valid, report.reason = False, "chain differs from a signed head"
            report.broken_at = min(seq, report.broken_at or seq)


def check_anchors(
    reports: Mapping[str, ChainReport], anchors: Mapping[str, tuple[int, bytes]], attested: set[str]
) -> None:
    """Mark a chain broken whose anchor no `retention_run` event of papaia-audit names.

    `attested` holds the `object_ref` ids (`<source>:<seq>:<hash hex>`) of the
    `retention_run` events in the verified chain of papaia-audit. An anchor that was set or
    moved by hand, to hide removed events, has none."""
    for source, (seq, digest) in anchors.items():
        report = reports.get(source)
        if report is None or not report.valid:
            continue
        if f"{source}:{seq}:{digest.hex()}" not in attested:
            report.valid, report.broken_at = False, seq + 1
            report.reason = "anchor not recorded by a retention run"
