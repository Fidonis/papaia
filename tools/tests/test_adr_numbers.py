"""Keeps the numbering of docs/adr/ unambiguous.

Other repositories cite core decisions by number, so a number must name exactly one
record, and the numbers reserved for the contract generations 7 to 12 must stay
reserved for the topics they were given.
"""

from __future__ import annotations

import re
from pathlib import Path

ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"

_FILE_RE = re.compile(r"^(\d{4})-[a-z0-9-]+\.md$")

# Reserved numbers and their topics (docs/adr/README.md, "Reserved numbers").
RESERVED = {
    "0017": "Add-on contract generations 7 to 12",
    "0018": "Identity: roles, exchange scopes and service accounts",
    "0019": "Internal PKI",
    "0020": "Personal area",
    "0021": "Connection registry",
    "0022": "Security profile",
    "0023": "Add-on ingress and delivery",
    "0024": "Design source",
}


def _numbered_files() -> list[tuple[str, str]]:
    found = []
    for path in sorted(ADR_DIR.glob("*.md")):
        match = _FILE_RE.match(path.name)
        if match:
            found.append((match.group(1), path.name))
    return found


def _readme() -> str:
    return (ADR_DIR / "README.md").read_text(encoding="utf-8")


def _reservation_rows() -> dict[str, str]:
    section = _readme().split("## Reserved numbers", 1)
    assert len(section) == 2, "docs/adr/README.md has no 'Reserved numbers' section"
    body = section[1].split("\n## ", 1)[0]
    rows = {}
    for line in body.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and re.fullmatch(r"\d{4}", cells[0]):
            rows[cells[0]] = cells[1]
    return rows


def test_every_adr_number_is_used_once():
    numbers = [number for number, _ in _numbered_files()]
    duplicates = sorted({n for n in numbers if numbers.count(n) > 1})
    assert duplicates == [], f"ADR numbers used more than once: {duplicates}"


def _index_numbers() -> set[str]:
    return set(re.findall(r"^\| \[(\d{4})\]", _readme(), flags=re.MULTILINE))


def test_readme_reserves_0017_to_0024():
    # A reserved number leaves the reservation table when its record is written and
    # listed in the index; until then it is reserved for exactly its topic.
    rows = _reservation_rows()
    recorded = _index_numbers()
    assert set(rows) <= set(RESERVED)
    for number, topic in RESERVED.items():
        if number in recorded:
            assert number not in rows, f"ADR {number} is both reserved and recorded"
        else:
            assert rows.get(number) == topic, f"ADR {number} must stay reserved for {topic!r}"


def test_reserved_numbers_have_no_unlisted_record():
    files = {number for number, _ in _numbered_files()}
    for number in _reservation_rows():
        assert number not in files, f"ADR {number} has a file but is still only reserved"


def test_every_record_is_listed_in_the_index():
    files = {number for number, _ in _numbered_files() if number != "0000"}
    assert files == _index_numbers()
