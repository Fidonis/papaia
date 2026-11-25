"""Module images published only on the release day (compat/release-day-images.yaml).

A module (papaia-me, papaia-connections, the manager) publishes its image on its own
release tag, on the release day; no module image is pushed to a remote registry before.
Until then the core pins the candidate built from the module milestone. This list names
each such image with the candidate digest the pins carry and where it was built from:

    schema: papaia.release-day-images/1
    images:
      - image: ghcr.io/fidonis/papaia-me     # registry/repository, no tag
        tag: 0.1.0
        digest: sha256:<64 hex>               # the candidate digest of the pins
        module: papaia-me                     # the module repository
        source: <40 hex>                      # commit of the module milestone
        built: 2026-11-25                     # date of the candidate build

`tools/check-image-pins` reports a listed pin in candidate mode as a release-day notice
instead of asking the published registry, and refuses release mode while the list has an
entry (lib/image_pins.py). The list holds module images under `ghcr.io/fidonis/` only:
a third-party image or an own image of the core can never be exempted through it.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import images, own_images, suite

LIST_PATH = Path("compat/release-day-images.yaml")
SCHEMA = "papaia.release-day-images/1"
NAMESPACE = "ghcr.io/fidonis/"
MAX_BYTES = 64 * 1024
MAX_ENTRIES = 32

_KEYS = {"image", "tag", "digest", "module", "source", "built"}
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_MODULE_RE = re.compile(r"\A[a-z0-9][a-z0-9-]{0,62}\Z")


class ReleaseDayError(ValueError):
    """A release-day list the check refuses; the message says why."""


@dataclass(frozen=True)
class Entry:
    image: str
    tag: str
    digest: str
    module: str
    source: str
    built: str  # ISO date
    line: int  # 1-based line of the entry in the list

    @property
    def ref(self) -> str:
        return f"{self.image}:{self.tag}@{self.digest}"

    @property
    def named(self) -> str:
        return f"{self.image}:{self.tag}"


def _image(value: object, where: str, own: set[str]) -> str:
    if not isinstance(value, str) or len(value) > 200:
        raise ReleaseDayError(f"{where}.image: a repository name expected")
    try:
        ref = images.parse_ref(value)
    except images.ImageError as exc:
        raise ReleaseDayError(f"{where}.image: {exc}") from exc
    if ref.tag is not None or ref.digest is not None:
        raise ReleaseDayError(f"{where}.image: a repository without tag or digest expected")
    if own_images._loopback_registry(ref.registry):
        raise ReleaseDayError(f"{where}.image: names a loopback test registry; the list "
                              "names the published image")
    if not value.startswith(NAMESPACE) or f"{ref.registry}/{ref.repository}" != value:
        raise ReleaseDayError(f"{where}.image: only module images under {NAMESPACE} can be "
                              "published on the release day")
    if value in own:
        raise ReleaseDayError(f"{where}.image: {value} is an own image of the core "
                              "(compat/own-images.yaml); it is built and pinned with the core")
    return value


def _built(value: object, where: str) -> str:
    if isinstance(value, datetime.datetime):
        raise ReleaseDayError(f"{where}.built: a date (YYYY-MM-DD) expected")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return datetime.date.fromisoformat(value).isoformat()
        except ValueError:
            pass
    raise ReleaseDayError(f"{where}.built: a date (YYYY-MM-DD) expected")


def _entry(value: object, where: str, line: int, own: set[str]) -> Entry:
    if not isinstance(value, dict) or set(value) != _KEYS:
        keys = set(value) if isinstance(value, dict) else set()
        unknown = sorted(map(str, keys - _KEYS))
        missing = sorted(_KEYS - keys)
        raise ReleaseDayError(
            f"{where}: needs exactly {', '.join(sorted(_KEYS))}"
            + (f" (unknown: {', '.join(unknown)})" if unknown else "")
            + (f" (missing: {', '.join(missing)})" if missing else ""))
    image = _image(value["image"], where, own)
    tag = value["tag"]
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise ReleaseDayError(f"{where}.tag: a version tag expected")
    digest = value["digest"]
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise ReleaseDayError(f"{where}.digest: sha256:<64 hex> expected")
    why = images.pin_problem(f"{image}:{tag}@{digest}")
    if why is not None:
        raise ReleaseDayError(f"{where}.tag: {why}")
    module = value["module"]
    if not isinstance(module, str) or not _MODULE_RE.match(module):
        raise ReleaseDayError(f"{where}.module: a repository name expected")
    source = value["source"]
    if not isinstance(source, str) or not _COMMIT_RE.match(source):
        raise ReleaseDayError(f"{where}.source: the full 40-hex commit of the module "
                              "milestone expected")
    return Entry(image, tag, digest, module, source, _built(value["built"], where), line)


def load(repo_root: Path) -> list[Entry]:
    """The validated list; empty when the checkout has none."""
    root = Path(repo_root)
    path = root / LIST_PATH
    if not path.exists() and not path.is_symlink():
        return []
    where = LIST_PATH.as_posix()
    try:
        data = suite._read_limited(path, MAX_BYTES, where)
        doc = suite._parse_yaml(data, where)
    except suite.SuiteError as exc:
        raise ReleaseDayError(f"{where}: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema", "images"} or doc["schema"] != SCHEMA:
        raise ReleaseDayError(f"{where}: expected exactly schema {SCHEMA} and images")
    if not isinstance(doc["images"], list) or len(doc["images"]) > MAX_ENTRIES:
        raise ReleaseDayError(f"{where}: images must be a list of at most {MAX_ENTRIES}")
    lines = _entry_lines(data, len(doc["images"]))
    try:
        own = {image.name for image in own_images.load(root)}
    except own_images.OwnImageError as exc:
        raise ReleaseDayError(str(exc)) from exc
    entries: list[Entry] = []
    for index, value in enumerate(doc["images"]):
        entry = _entry(value, f"{where}: images[{index}]", lines[index], own)
        if any(entry.image == seen.image for seen in entries):
            raise ReleaseDayError(f"{where}: images[{index}] names {entry.image} twice")
        entries.append(entry)
    return entries


def _entry_lines(data: bytes, count: int) -> list[int]:
    """The line of each entry's `image` key (of the entry itself when it has none)."""
    node = yaml.compose(data)
    found: list[int] = []
    for key, value in node.value if isinstance(node, yaml.MappingNode) else []:
        if key.value == "images" and isinstance(value, yaml.SequenceNode):
            for item in value.value:
                line = item.start_mark.line + 1
                for k, _ in item.value if isinstance(item, yaml.MappingNode) else []:
                    if k.value == "image":
                        line = k.start_mark.line + 1
                found.append(line)
    return found if len(found) == count else [1] * count


# ── candidate digests of a module build ─────────────────────────────────────


_DIGEST_KEYS = {"image", "tag", "digest"}


def load_candidate_digests(path: Path) -> dict[str, tuple[str, str]]:
    """{image: (tag, digest)} of a module milestone build: a JSON or YAML list of
    `image`, `tag`, `digest`."""
    where = f"--candidate-digests {path}"
    try:
        doc = suite._parse_yaml(suite._read_limited(Path(path), MAX_BYTES, where), where)
    except suite.SuiteError as exc:
        raise ReleaseDayError(str(exc)) from exc
    if not isinstance(doc, list) or len(doc) > MAX_ENTRIES:
        raise ReleaseDayError(f"{where}: a list of at most {MAX_ENTRIES} entries expected")
    found: dict[str, tuple[str, str]] = {}
    for index, value in enumerate(doc):
        at = f"{where}: [{index}]"
        if not isinstance(value, dict) or set(value) != _DIGEST_KEYS:
            unknown = sorted(map(str, set(value) - _DIGEST_KEYS)) if isinstance(value, dict) \
                else []
            raise ReleaseDayError(f"{at}: needs exactly image, tag, digest"
                                  + (f" (unknown: {', '.join(unknown)})" if unknown else ""))
        image, tag, digest = value["image"], value["tag"], value["digest"]
        if not isinstance(image, str) or not image.startswith(NAMESPACE) or len(image) > 200:
            raise ReleaseDayError(f"{at}.image: a module image under {NAMESPACE} expected")
        if not isinstance(tag, str) or not _TAG_RE.match(tag):
            raise ReleaseDayError(f"{at}.tag: a version tag expected")
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise ReleaseDayError(f"{at}.digest: sha256:<64 hex> expected")
        if image in found:
            raise ReleaseDayError(f"{at}: names {image} twice")
        found[image] = (tag, digest)
    return found
