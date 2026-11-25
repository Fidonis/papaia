"""Release version check of a version tag.

A core whose `VERSION` carries a pre-release part accepts the test trust anchor
(ADR 0030, lib/prerelease_anchor.py). A tag `vX.Y.Z` is therefore refused unless
`VERSION` is exactly `X.Y.Z` (no pre-release part, no build metadata, one optional
trailing newline) and the tag is `v` + `VERSION`. The `release-version` job of
.github/workflows/images.yml runs this check first on every `v*` tag; every job that
builds, signs or publishes needs it (docs/compatibility.md, "Release gate").

    python -m lib.release_version check --tag <tag or refs/tags/tag> [--root <checkout>]

The check reads `VERSION` and the tag only. Standard library only, so it runs before
anything is installed.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

VERSION_PATH = Path("VERSION")
MAX_VERSION_BYTES = 64
MAX_TAG_CHARS = 128
TAG_REF_PREFIX = "refs/tags/"

# Exactly X.Y.Z with ASCII digits; nothing before, nothing after.
_RELEASE_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_TAG_RE = re.compile(r"\Av[0-9]+\.[0-9]+\.[0-9]+\Z")


class ReleaseVersionError(ValueError):
    """The tag may not be released from this checkout."""


def _shown(value: str) -> str:
    """A value for a message: at most 40 characters, non-printable ones escaped."""
    cut = value[:40]
    return repr(cut) if cut.isprintable() else ascii(cut)


def _read_version(root: Path) -> str:
    path = Path(root) / VERSION_PATH
    try:
        # O_NONBLOCK keeps a FIFO from blocking the open; fstat on the opened descriptor
        # leaves no window to swap the file.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ReleaseVersionError(f"VERSION not readable: {path}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseVersionError(f"VERSION is not a regular file: {path}")
        raw = os.read(fd, MAX_VERSION_BYTES + 1)
    except OSError:
        raise ReleaseVersionError(f"VERSION not readable: {path}") from None
    finally:
        os.close(fd)
    if len(raw) > MAX_VERSION_BYTES:
        raise ReleaseVersionError(f"VERSION is longer than {MAX_VERSION_BYTES} bytes")
    if not raw:
        raise ReleaseVersionError("VERSION is empty")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ReleaseVersionError(f"VERSION is not ASCII: {raw[:40]!r}") from None
    return text[:-1] if text.endswith("\n") else text


def _tag_name(tag: object) -> str:
    if not isinstance(tag, str) or not tag:
        raise ReleaseVersionError("no tag given")
    if len(tag) > MAX_TAG_CHARS:
        raise ReleaseVersionError(f"tag is longer than {MAX_TAG_CHARS} characters")
    name = tag[len(TAG_REF_PREFIX):] if tag.startswith(TAG_REF_PREFIX) else tag
    if not _TAG_RE.match(name):
        raise ReleaseVersionError(
            f"tag {_shown(tag)} is not a release tag vX.Y.Z (or refs/tags/vX.Y.Z)"
        )
    return name


def check(root: Path, tag: object) -> str:
    """The release version when `tag` may be released from the checkout at `root`;
    ReleaseVersionError otherwise. Reads `VERSION` and nothing else."""
    name = _tag_name(tag)
    version = _read_version(root)
    if not _RELEASE_RE.match(version):
        raise ReleaseVersionError(
            f"VERSION {_shown(version)} is not a release version X.Y.Z (a pre-release "
            f"part or build metadata is not allowed); tag {name} refused: a pre-release "
            "core accepts the test trust anchor (ADR 0030). Set VERSION to "
            f"{name[1:]} before tagging {name}."
        )
    if name != f"v{version}":
        raise ReleaseVersionError(
            f"tag {name} does not name VERSION {version}; the tag must be v{version}"
        )
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_version",
        description="Refuse a release tag unless VERSION is exactly X.Y.Z and the tag is vX.Y.Z.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    chk = sub.add_parser("check", help="check a version tag against VERSION")
    chk.add_argument("--tag", required=True, help="vX.Y.Z or refs/tags/vX.Y.Z")
    chk.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2],
                     help="checkout root holding VERSION (default: this checkout)")
    args = parser.parse_args(argv)

    try:
        version = check(args.root, args.tag)
    except ReleaseVersionError as exc:
        print(f"release version check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release version check passed: VERSION {version}, tag v{version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
