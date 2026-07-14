"""Stdlib-only SemVer subset for the `papaia_compat` fallback axis.

Supported constraint grammar (comma = AND, e.g. ">=0.8.0,<2.0.0"):

    >=X.Y.Z  >X.Y.Z  <X.Y.Z  <=X.Y.Z  ==X.Y.Z  !=X.Y.Z
    ^X.Y.Z   caret: locks the leftmost non-zero component
             (^0.8.0 == [0.8.0, 0.9.0); ^1.2.3 == [1.2.3, 2.0.0))
    ~X.Y.Z   tilde: locks the minor, allows patch bumps
    X.Y.Z    bare version, shorthand for ==X.Y.Z

Pre-releases order per SemVer 2.0.0 (1.0.0-rc.1 < 1.0.0-rc.2 < 1.0.0). A
pre-release only satisfies a constraint when one of its bounds carries a
pre-release on the same (major, minor, patch) triple -- this keeps
`1.0.0-rc` from satisfying `>=0.8.0` while still allowing an explicit
`>=1.0.0-rc.1` opt-in.

Deliberately not a `packaging`/`semver` dependency: tools/ ships with
PyYAML only, so it keeps working from an offline tarball install. Malformed
input raises ValueError.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"  # build metadata: valid, ignored
)

# Longest first so ">=" wins over ">".
_OPERATORS = (">=", "<=", "==", "!=", ">", "<")

_OP_ACCEPTS: dict[str, tuple[int, ...]] = {
    ">=": (0, 1),
    ">": (1,),
    "<": (-1,),
    "<=": (-1, 0),
    "==": (0,),
    "!=": (-1, 1),
}


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @property
    def triple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


@dataclass(frozen=True)
class Clause:
    op: str
    bound: Version


def parse_version(text: str) -> Version:
    match = _VERSION_RE.match(text.strip())
    if not match:
        raise ValueError(f"Malformed version: {text!r}")
    pre = match.group("pre")
    return Version(
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        tuple(pre.split(".")) if pre else (),
    )


def _prerelease_key(identifiers: tuple[str, ...]) -> list[tuple[int, int, str]]:
    # SemVer item 11: numeric identifiers compare numerically and rank below
    # alphanumeric ones; when all shared identifiers are equal, the longer
    # set ranks higher (which plain list comparison already yields).
    return [(0, int(part), "") if part.isdigit() else (1, 0, part) for part in identifiers]


def compare(a: Version | str, b: Version | str) -> int:
    """Three-way SemVer precedence comparison: -1 (a < b), 0, or 1."""
    va = parse_version(a) if isinstance(a, str) else a
    vb = parse_version(b) if isinstance(b, str) else b
    if va.triple != vb.triple:
        return -1 if va.triple < vb.triple else 1
    if va.prerelease == vb.prerelease:
        return 0
    # A release outranks any pre-release of the same triple.
    if not va.prerelease:
        return 1
    if not vb.prerelease:
        return -1
    key_a, key_b = _prerelease_key(va.prerelease), _prerelease_key(vb.prerelease)
    if key_a == key_b:
        return 0
    return -1 if key_a < key_b else 1


def _caret_upper(lower: Version) -> Version:
    if lower.major > 0:
        return Version(lower.major + 1, 0, 0)
    if lower.minor > 0:
        return Version(0, lower.minor + 1, 0)
    return Version(0, 0, lower.patch + 1)


def parse_constraint(text: str) -> tuple[Clause, ...]:
    """Parse a constraint string into AND-ed clauses (caret/tilde expand to
    a >= lower bound plus a < upper bound)."""
    clauses: list[Clause] = []
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError(f"Malformed constraint: {text!r}")
        if part.startswith("^"):
            lower = parse_version(part[1:])
            clauses.append(Clause(">=", lower))
            clauses.append(Clause("<", _caret_upper(lower)))
        elif part.startswith("~"):
            lower = parse_version(part[1:])
            clauses.append(Clause(">=", lower))
            clauses.append(Clause("<", Version(lower.major, lower.minor + 1, 0)))
        else:
            for op in _OPERATORS:
                if part.startswith(op):
                    clauses.append(Clause(op, parse_version(part[len(op) :])))
                    break
            else:
                clauses.append(Clause("==", parse_version(part)))
    return tuple(clauses)


def satisfies(version: Version | str, constraint: str | tuple[Clause, ...]) -> bool:
    """Whether `version` satisfies every clause of `constraint`."""
    v = parse_version(version) if isinstance(version, str) else version
    clauses = parse_constraint(constraint) if isinstance(constraint, str) else constraint
    if v.prerelease and not any(
        clause.bound.prerelease and clause.bound.triple == v.triple for clause in clauses
    ):
        return False
    return all(compare(v, clause.bound) in _OP_ACCEPTS[clause.op] for clause in clauses)
