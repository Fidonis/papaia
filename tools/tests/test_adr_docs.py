"""Docs check of docs/adr/: index, status and links.

Every record is listed in the index with the status of its front matter, every relative
link of a record resolves, and the decision on the chat path of tool servers outside the
suite (ADR 0029) states what it promises and is reachable from docs/architecture.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADR_DIR = ROOT / "docs" / "adr"
ARCHITECTURE = ROOT / "docs" / "architecture.md"

_FILE_RE = re.compile(r"^(\d{4})-[a-z0-9-]+\.md$")
_INDEX_ROW = re.compile(
    r"^\| \[(\d{4})\]\(\./([^)]+)\) \| (.+?) \| (Proposed|Accepted|Deprecated|Superseded) \| "
    r"(\d{4}-\d{2}-\d{2}) \|$",
    flags=re.MULTILINE,
)
_LINK = re.compile(r"\]\(([^)\s]+)\)")

NON_SUITE_CHAT = "0029-reach-a-tool-server-outside-the-suite-through-a-core-chat-relay.md"


def _records() -> dict[str, Path]:
    found = {}
    for path in sorted(ADR_DIR.glob("*.md")):
        match = _FILE_RE.match(path.name)
        if match and match.group(1) != "0000":
            found[match.group(1)] = path
    return found


def _front_matter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path.name} has no front matter"
    head = text[4:].split("\n---\n", 1)[0]
    fields = {}
    for line in head.splitlines():
        if line and not line.startswith((" ", "-")) and ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def _index() -> dict[str, tuple[str, str, str, str]]:
    readme = (ADR_DIR / "README.md").read_text(encoding="utf-8")
    return {m.group(1): m.group(2, 3, 4, 5) for m in _INDEX_ROW.finditer(readme)}


def _section(text: str, heading: str) -> str:
    parts = text.split(f"\n## {heading}\n", 1)
    assert len(parts) == 2, f"no section '## {heading}'"
    return parts[1].split("\n## ", 1)[0]


# --- every record ---------------------------------------------------------------------


def test_index_rows_match_the_front_matter():
    index = _index()
    for number, path in _records().items():
        assert number in index, f"ADR {number} has no index row"
        # The index may format the title (code spans), so only the plain fields are compared.
        filename, _title, status, date = index[number]
        meta = _front_matter(path)
        assert filename == path.name, number
        assert meta.get("adr") == number, number
        assert meta.get("status") == status, number
        assert meta.get("date") == date, number


@pytest.mark.parametrize(
    "path", [*_records().values(), ADR_DIR / "README.md"], ids=lambda p: p.name
)
def test_relative_links_resolve(path: Path):
    broken = []
    for target in _LINK.findall(path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        file_part = target.split("#", 1)[0]
        if not (path.parent / file_part).exists():
            broken.append(target)
    assert broken == []


# --- ADR 0029: chat path of a tool server outside the suite ---------------------------


def _non_suite_chat() -> str:
    path = ADR_DIR / NON_SUITE_CHAT
    assert path.is_file(), f"docs/adr/{NON_SUITE_CHAT} is missing"
    return path.read_text(encoding="utf-8")


def test_the_non_suite_chat_decision_is_accepted_and_indexed():
    _non_suite_chat()
    meta = _front_matter(ADR_DIR / NON_SUITE_CHAT)
    assert meta["adr"] == "0029"
    assert meta["status"] == "Accepted"
    assert "0029" in _index()


def test_architecture_points_to_the_non_suite_chat_decision():
    seam = ARCHITECTURE.read_text(encoding="utf-8").split("### Seam 3", 1)[1].split("\n### ", 1)[0]
    assert f"(adr/{NON_SUITE_CHAT})" in seam


DECISION_FACTS = (
    # the relay path
    "`papaia-chat-relay`",
    "RFC 8693",
    "`scope=aud-<audience>`",
    "never forwards the chat token",
    # token scope
    "exactly one audience",
    "no refresh token",
    "`azp`",
    "300 s",
    # trust level and opt-in
    "`trust: addon`",
    "off by default",
    "addon chat allow <addon>",
    "addon chat revoke <addon>",
    "`approvals.four_eyes`",
    # audit
    "`papaia.audit/1`",
    "`chat_relay.tool_call`",
    "`chat_relay.allow`",
    "`chat_relay.revoke`",
    "correlation id",
    # data class and failure
    "`data_class_max`",
    "fails closed",
)


def test_the_decision_states_path_scope_opt_in_and_audit():
    text = _non_suite_chat()
    body = _section(text, "Decision") + _section(text, "Security assessment")
    assert [fact for fact in DECISION_FACTS if fact not in body] == []


REJECTED = (
    "Add the add-on to the suite",
    "A sign-in client per add-on in the chat",
    "Pass the shared chat token",
)


def test_the_rejected_alternatives_are_named_with_a_reason():
    alternatives = _section(_non_suite_chat(), "Alternatives considered")
    for option in REJECTED:
        entry = alternatives.split(f"**{option}", 1)
        assert len(entry) == 2, f"alternative '{option}' is missing"
        assert "Rejected" in entry[1].split("\n- **", 1)[0], f"'{option}' gives no reason"
