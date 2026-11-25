"""Docs check of docs/adr/: index, status and links.

Every record is listed in the index with the status of its front matter, every relative
link of a record resolves, and the decisions on the chat path of tool servers outside the
suite (ADR 0029) and on the data class of model routes (ADR 0031) state what they promise
and are reachable from docs/architecture.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

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
ROUTE_CLASS = "0031-give-every-model-route-a-data-class-and-refuse-above-it-at-the-gateway.md"
MODEL_GATEWAY = ROOT / "docs" / "model-gateway.md"
AUDIT_SCHEMA = ROOT / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json"


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


# --- ADR 0031: data class of a model route --------------------------------------------


def _route_class() -> str:
    path = ADR_DIR / ROUTE_CLASS
    assert path.is_file(), f"docs/adr/{ROUTE_CLASS} is missing"
    return path.read_text(encoding="utf-8")


def test_the_route_class_decision_is_accepted_and_indexed():
    _route_class()
    meta = _front_matter(ADR_DIR / ROUTE_CLASS)
    assert meta["adr"] == "0031"
    assert meta["status"] == "Accepted"
    assert "0031" in _index()


def test_architecture_and_gateway_docs_point_to_the_route_class_decision():
    sovereignty = ARCHITECTURE.read_text(encoding="utf-8").split("### ① Data sovereignty", 1)[1]
    assert f"(adr/{ROUTE_CLASS})" in sovereignty.split("\n### ", 1)[0]
    assert f"(adr/{ROUTE_CLASS})" in MODEL_GATEWAY.read_text(encoding="utf-8")


ROUTE_CLASS_FACTS = (
    # the scale and the route class with its source and default
    "`public` < `internal` < `partner_contact` < `personal` < `employee` < `confidential` "
    "< `special` < `professional_secret`",
    "`model_info.papaia_max_class`",
    "`PAPAIA_MODEL_MAX_CLASS`",
    "otherwise `internal`",
    "`test_backend: true`",
    "capped at `internal`",
    "stops the render",
    # the catalog block
    "`models` block",
    "`ModelAlias`",
    "`alias`, `features`, `context`, `max_class` and `test_backend`",
    # the request class
    "`x-papaia-data-class`",
    "`metadata.papaia_need_classes`",
    "highest class of the scale",
    # the refusals
    "before any backend call",
    "403",
    "`class_exceeded`",
    "400",
    "`invalid_data_class`",
    "503",
    "`route_class_unknown`",
    "fails closed",
    # the start rule
    "`papaia-ctl addon start`",
    "`papaia-ctl doctor`",
    # the audit row, in the fields the papaia.audit/1 schema requires of an operation
    "`papaia.audit/1`",
    "`result` `denied`",
    "`x-papaia-correlation-id`",
    "no message content",
    "`sub`, `azp` and `service_account` the key alias",
    "`catalog_id` `litellm.model_request`",
    "`detail` `null`",
    # a module key reaches only the routes the class guard judges
    "route allowlist",
    "`allowed_routes`",
    "every other route is refused for a module key",
    # keys made before the class guard
    "without `metadata.papaia_need_classes`",
    # the platform halt comes first
    "`platform_halt`",
)


def test_the_route_class_decision_states_source_catalog_refusal_start_rule_and_audit():
    text = _route_class()
    # Markdown wraps lines anywhere, so the facts are looked up in the joined text.
    body = " ".join((_section(text, "Decision") + _section(text, "Security assessment")).split())
    assert [fact for fact in ROUTE_CLASS_FACTS if fact not in body] == []


def test_the_route_class_audit_rows_are_valid_papaia_audit_submissions():
    # The rows the decision specifies must pass the ingest schema; otherwise papaia-audit
    # refuses them and a refusal leaves no trace (PLT-19).
    schema = json.loads(AUDIT_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/submission"})
    decision = _section(_route_class(), "Decision")
    rows = [json.loads(block) for block in re.findall(r"```json\n(.*?)\n```", decision, re.S)]
    events = sorted(row.get("event") for row in rows)
    assert events == ["config_changed", "operation"], "both audit rows are given as examples"
    for row in rows:
        errors = sorted(error.message for error in validator.iter_errors(row))
        assert errors == [], f"{row.get('event')} row: {errors}"
    refusal = next(row for row in rows if row["event"] == "operation")
    assert refusal["result"] == "denied"
    assert refusal["detail"] is None


def test_the_route_class_security_assessment_limits_module_keys_to_judged_routes():
    fail_closed = _section(_route_class(), "Security assessment").split("**Fail-closed", 1)
    assert len(fail_closed) == 2
    named = " ".join(fail_closed[1].split("\n- **", 1)[0].split())
    assert "route allowlist" in named


def test_the_route_class_decision_names_its_remaining_risks():
    risks = _section(_route_class(), "Security assessment").split("**Remaining risk", 1)
    assert len(risks) == 2, "no remaining risk is named"
    named = " ".join(risks[1].split())
    assert "own statement" in named  # the header is the module's word, not checked content
    assert "master key" in named  # the chat's requests are outside the rule


ROUTE_CLASS_REJECTED = (
    "Check the class in the modules only",
    "One gateway per class",
    "Classify the content at the gateway",
)


def test_the_route_class_alternatives_are_named_with_a_reason():
    alternatives = _section(_route_class(), "Alternatives considered")
    for option in ROUTE_CLASS_REJECTED:
        entry = alternatives.split(f"**{option}", 1)
        assert len(entry) == 2, f"alternative '{option}' is missing"
        assert "Rejected" in entry[1].split("\n- **", 1)[0], f"'{option}' gives no reason"
