"""The German delivery documents: license and sourcing, the texts for the data protection
officer and the works council, and the evidence with the shipped model.

The documents are hand-written. These tests hold what the acceptance criteria demand of
them: every relative link resolves (file and heading), no denied term appears, the criteria
of OPS-13 carry their origin prefix, the license document has a row for every component
and no undecided row, and the works council texts keep the sentences and the criteria the
specification fixes.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DE = REPO / "docs" / "de"
PRIVACY = DE / "datenschutz"
OPERATIONS = DE / "betrieb"

LICENSE_DOC = OPERATIONS / "lizenz-und-bezug.md"
MODEL_DOC = OPERATIONS / "modellnachweis.md"

REQUIRED = [
    PRIVACY / "index.md",
    PRIVACY / "protokollierung.md",
    PRIVACY / "keine-leistungskontrolle.md",
    PRIVACY / "dsfa-zuarbeit.md",
    PRIVACY / "tom.md",
    PRIVACY / "betriebsvereinbarung-eckpunkte.md",
    LICENSE_DOC,
    MODEL_DOC,
]

_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


def _documents() -> list[Path]:
    return sorted(DE.rglob("*.md"))


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _prose_lines(text: str) -> list[tuple[int, str]]:
    """Lines outside fenced code blocks, with their numbers."""
    lines, fenced = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append((number, line))
    return lines


def _slug(heading: str) -> str:
    """The anchor a Markdown renderer of the forge gives a heading: lower case, markup and
    punctuation removed (letters of any script, digits, hyphens and spaces stay), spaces
    become hyphens."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = unicodedata.normalize("NFC", text).lower()
    kept = "".join(
        ch for ch in text if ch in "- _" or unicodedata.category(ch)[0] in ("L", "N")
    )
    return kept.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    anchors = set()
    for _, line in _prose_lines(_text(path)):
        match = _HEADING.match(line)
        if not match:
            continue
        slug = _slug(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


def _table_rows(text: str, header_start: str) -> list[list[str]]:
    """The body rows of the first table whose header row starts with `header_start`."""
    rows: list[list[str]] = []
    inside = False
    for line in text.splitlines():
        if not inside:
            if line.startswith(f"| {header_start}"):
                inside = True
            continue
        if not line.startswith("|"):
            break
        if line.startswith("|---"):
            continue
        rows.append([cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1]])
    return rows


def _section(text: str, heading: str) -> str:
    """The text below the heading line `heading` up to the next heading of the same or a
    higher level."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group(2) == heading:
            level = len(match.group(1))
            body = []
            for following in lines[index + 1 :]:
                other = _HEADING.match(following)
                if other and len(other.group(1)) <= level:
                    break
                body.append(following)
            return "\n".join(body)
    raise AssertionError(f"no heading {heading!r}")


# --- every document -----------------------------------------------------------------


@pytest.mark.parametrize("path", REQUIRED, ids=lambda p: p.relative_to(REPO).as_posix())
def test_the_delivery_document_exists(path: Path):
    assert path.is_file()
    assert _text(path).startswith("# "), "a document starts with its title"


def test_every_relative_link_of_the_german_documents_resolves():
    problems = []
    for path in _documents():
        for number, line in _prose_lines(_text(path)):
            for target in _LINK.findall(line):
                if re.match(r"[a-z][a-z0-9+.-]*:", target):
                    continue
                file_part, _, anchor = target.partition("#")
                linked = (path.parent / file_part).resolve() if file_part else path
                where = f"{path.relative_to(REPO)}:{number}: {target}"
                if not linked.exists():
                    problems.append(f"{where}: no such file")
                elif anchor and linked.suffix == ".md" and anchor not in _anchors(linked):
                    problems.append(f"{where}: no such heading")
    assert problems == []


def test_the_link_check_finds_a_broken_link(tmp_path: Path):
    """The link check above is not blind: a missing heading has no anchor."""
    page = tmp_path / "seite.md"
    page.write_text("# Titel\n\n## Zweiter Teil: `a` und Ä\n", encoding="utf-8")
    assert _anchors(page) == {"titel", "zweiter-teil-a-und-ä"}
    assert "dritter-teil" not in _anchors(page)


def test_the_german_documents_hold_no_denied_term():
    pytest.importorskip("papaia_kit.repo", reason="papaia-kit needs Python 3.12")
    from papaia_kit.repo import find_denied_words

    hits = [
        f"{path.relative_to(REPO)}:{number}: {words}"
        for path in _documents()
        for number, line in enumerate(_text(path).splitlines(), start=1)
        if (words := find_denied_words(line))
    ]
    assert hits == []


def test_the_criteria_of_ops13_carry_their_origin_prefix():
    """Ä-46: PLT-69 and PLT-71 are other requirements of the frozen list; the criteria of
    OPS-13 are always written EXI-PLT-69-A* and EXK-PLT-71-A*."""
    bare = re.compile(r"(?<![A-Z]-)\bPLT-(?:69|71)-A\d")
    wrong = re.compile(r"\b(?:EXK-PLT-69|EXI-PLT-71|ISB-PLT-69|ISB-PLT-71)-A\d")
    problems = [
        f"{path.relative_to(REPO)}:{number}"
        for path in _documents()
        for number, line in enumerate(_text(path).splitlines(), start=1)
        if bare.search(line) or wrong.search(line)
    ]
    assert problems == []


# The criteria the two external reviews define for their own requirements PLT-58 to PLT-76:
# the highest A number per requirement. EXK is the kmu review, EXI the industrie review; their
# numbering differs. Criteria of earlier requirements (EXI-PLT-19-A9) are not checked here.
_EXK_CRITERIA = {
    58: 5, 59: 4, 60: 7, 61: 4, 62: 5, 63: 7, 64: 4, 65: 5, 66: 4, 67: 3,
    68: 6, 69: 3, 70: 2, 71: 4, 72: 3, 73: 2, 74: 2, 75: 3, 76: 3,
}
_EXI_CRITERIA = {
    58: 7, 59: 6, 60: 5, 61: 5, 62: 6, 63: 3, 64: 6, 65: 8, 66: 7, 67: 5, 68: 6, 69: 3,
}
_REVIEW_CRITERION = re.compile(r"\b(EXK|EXI)-PLT-(\d+)-A(\d+)\b")


def _unknown_review_criteria(text: str) -> list[str]:
    known = {"EXK": _EXK_CRITERIA, "EXI": _EXI_CRITERIA}
    return [
        match.group(0)
        for match in _REVIEW_CRITERION.finditer(text)
        if 58 <= int(match.group(2)) <= 76
        and not 1 <= int(match.group(3)) <= known[match.group(1)].get(int(match.group(2)), 0)
    ]


def test_every_review_criterion_cited_in_the_german_documents_exists():
    """EXK-PLT-65-A4: the acceptance report lists the cited criteria as passed, so a cited
    criterion has to exist in the review it is prefixed with."""
    problems = [
        f"{path.relative_to(REPO)}:{number}: {unknown}"
        for path in _documents()
        for number, line in enumerate(_text(path).splitlines(), start=1)
        for unknown in _unknown_review_criteria(line)
    ]
    assert problems == []


def test_the_criterion_check_finds_a_wrong_prefix():
    assert _unknown_review_criteria("EXK-PLT-65-A7, EXI-PLT-65-A7, EXK-PLT-65-A5") == [
        "EXK-PLT-65-A7"
    ]
    assert _unknown_review_criteria("EXI-PLT-71-A1 EXK-PLT-72-A4 EXI-PLT-19-A9") == [
        "EXI-PLT-71-A1",
        "EXK-PLT-72-A4",
    ]


def test_every_claim_of_a_technical_lock_names_its_criterion():
    """EXK-PLT-65-A4 for the hand-written texts as well, in the operations folder too."""
    from lib import privacy_pack

    problems = []
    for path in _documents():
        problems += privacy_pack._claims(path.relative_to(REPO).as_posix(), _text(path))
    assert problems == []


# --- license and sourcing (OPS-13) --------------------------------------------------

COMPONENTS = [
    "Kern",
    "Manager",
    "Studio",
    "Data",
    "Flow",
    "Flow als eigenständige Edition",
    "Assistant",
    "Mein Bereich",
    "Kit",
    "Verbindungsregister",
    "KI-Landkarte",
    "Add-on-Sammlung",
    "MCP-Server Qdrant",
    "MCP-Server Paperless",
    "MCP-Server MediaWiki",
    "MCP-Server SQL Server",
]


def _license_rows() -> dict[str, list[str]]:
    rows = _table_rows(_text(LICENSE_DOC), "Bestandteil")
    return {row[0].strip("*"): row for row in rows}


def test_the_license_document_has_a_full_row_for_every_own_component():
    rows = _license_rows()
    assert [name for name in COMPONENTS if name not in rows] == []
    for name in COMPONENTS:
        row = rows[name]
        assert len(row) == 5 and all(row), name
        assert row[2].split()[0] in {"ja", "nein"}, name
        assert row[3].split()[0] in {"ja", "nein"}, name


def test_every_shipped_third_party_service_and_model_has_a_full_row():
    text = _text(LICENSE_DOC)
    services = _table_rows(_section(text, "1.2 Mitgelieferte Fremddienste"), "Fremddienst")
    models = _table_rows(_section(text, "1.3 Modelle"), "Modell")
    names = {row[0] for row in services}
    for expected in ("Keycloak", "PostgreSQL", "LibreChat", "LiteLLM", "MongoDB", "SearXNG"):
        assert any(expected in name for name in names), expected
    assert any("qwen2.5-1.5b-instruct" in row[0] for row in models)
    for row in services + models:
        assert len(row) == 5 and all(row), row
        assert row[2].split()[0] in {"ja", "nein"}, row
        assert row[3].split()[0] in {"ja", "nein"}, row


def test_no_line_of_the_license_document_is_undecided():
    """EXK-PLT-71-A1: no row "undecided"."""
    undecided = re.compile(r"unentschieden|nicht entschieden|undecided|offen gelassen", re.I)
    lines = [line for line in _text(LICENSE_DOC).splitlines() if undecided.search(line)]
    assert lines == []


def test_every_core_image_is_listed_in_the_license_document():
    """The license document covers every image of the core's third-party list."""
    listed = re.findall(r"^\| `([^`]+)` \|", _text(REPO / "THIRD_PARTY_LICENSES.md"), re.M)
    assert listed
    text = _text(LICENSE_DOC)
    assert [image for image in listed if f"`{image}`" not in text] == []


def test_the_license_document_names_what_the_operator_obtains_himself():
    section = _section(_text(LICENSE_DOC), "2 Vom Betreiber selbst zu beschaffen")
    for expected in ("SQL Server", "ODBC Driver 18", "n8n", "Llama"):
        assert expected in section, expected


def test_the_license_document_names_sourcing_availability_support_and_reporting():
    text = _text(LICENSE_DOC)
    sourcing = _section(text, "3 Bezug der Images")
    assert "EXK-PLT-71-A2" in sourcing
    assert re.search(r"abrufbar.*\b\d+ (?:Jahre|Monate)\b", sourcing, re.S)
    assert "papaia-ctl export --exit" in sourcing and "EXI-PLT-69-A1" in sourcing
    start = _section(text, "4 Keine Lizenzprüfung beim Start")
    assert "EXK-PLT-71-A3" in start
    support = _section(text, "5 Unterstützung und Sicherheitskorrekturen")
    assert "EXK-PLT-71-A4" in support
    assert "https://github.com/Fidonis/papaia/security/advisories/new" in support
    assert re.search(r"\b14 Tage", support) and re.search(r"\b30 Tage", support)
    assert "drei Jahre" in _section(text, "6 Schriftliches Quellangebot")


def test_the_kit_row_names_where_its_license_files_lie():
    row = _license_rows()["Kit"]
    assert "`tools/vendor/papaia-kit/<version>/`" in row[4]
    assert "`LICENSE` und `NOTICE` liegen im Paket" in row[4]
    versions = [p for p in (REPO / "tools" / "vendor" / "papaia-kit").iterdir() if p.is_dir()]
    assert versions and all(any(v.glob("*.whl")) for v in versions)


def test_the_offline_archive_names_a_reference_image_for_n8n():
    """lizenzen §10 Nr. 3: name and source of an image outside the archive; the reference is
    the tag the add-on pins."""
    sourcing = _section(_text(LICENSE_DOC), "3 Bezug der Images")
    assert re.search(r"`docker\.io/n8nio/n8n:\d+\.\d+\.\d+`", sourcing)


def _scan_interval(name: str) -> str:
    """The interval word for the schedule of a workflow: täglich or wöchentlich."""
    workflow = _text(REPO / ".github" / "workflows" / name)
    cron = re.search(r'cron:\s*"([^"]+)"', workflow)
    assert cron, f"{name} has no schedule"
    minute, hour, day, month, weekday = cron.group(1).split()
    assert day == "*" and month == "*", f"{name}: unexpected schedule {cron.group(1)}"
    return "täglich" if weekday == "*" else "wöchentlich"


def _scan_clauses() -> dict[str, list[str]]:
    """The clauses of the scan statement in the license document and in the TOM row."""
    support = _section(_text(LICENSE_DOC), "5 Unterstützung und Sicherheitskorrekturen")
    statement = next(item for item in support.split("\n- ") if "**Prüfung.**" in item)
    row = next(line for line in _text(PRIVACY / "tom.md").splitlines() if "EXK-PLT-71-A4" in line)
    measure = row.strip("| ").split(" | ")[0]
    return {
        name: re.split(r"(?<=[.;])\s", re.sub(r"\s+", " ", text).strip())
        for name, text in (("lizenz-und-bezug.md", statement), ("tom.md", measure))
    }


def test_the_core_scans_its_own_images_on_every_change_and_upstream_images_apart():
    """images.yml scans the own images on pull requests and pushes; image-scan.yml scans the
    upstream images only, on changes under src/."""
    own = _text(REPO / ".github" / "workflows" / "images.yml")
    assert re.search(r"^  pull_request:", own, re.M) and re.search(r"^  push:", own, re.M)
    upstream = _text(REPO / ".github" / "workflows" / "image-scan.yml")
    assert 'paths: ["src/**"' in upstream
    assert "grep -v '^ghcr\\.io/fidonis/'" in upstream


def test_the_stated_scan_intervals_are_the_ones_the_core_runs():
    """Each stated interval is the schedule of its own workflow: images.yml for the own images,
    image-scan.yml for the upstream images. No sentence names a scan as not yet set up."""
    own_word = _scan_interval("images.yml")
    upstream_word = _scan_interval("image-scan.yml")
    for name, clauses in _scan_clauses().items():
        own = [c for c in clauses if "eigenen Images" in c]
        upstream = [c for c in clauses if "Fremd-Images" in c]
        assert own and upstream, name
        assert any(own_word in c for c in own), (name, own_word)
        assert any("bei jeder Änderung" in c for c in own), name
        if own_word == "täglich":
            assert any("Standardzweig" in c for c in own), name
        assert any(upstream_word in c for c in upstream), (name, upstream_word)
        assert any("bei jeder Änderung unter `src/`" in c for c in upstream), name
        assert not any("noch nicht" in c for c in clauses), name


# --- works council and data protection officer --------------------------------------

_BETRVG_SENTENCE = (
    "„Die Software bietet keine Funktion, mit der Leistung oder Verhalten einzelner "
    "Beschäftigter ausgewertet werden kann. Personen mit Zugriff auf den Server oder die "
    "Datenbanken können Protokolldaten jedoch technisch lesen. Ob die Software zur "
    "Überwachung geeignet ist im Sinne des § 87 Abs. 1 Nr. 6 BetrVG, beurteilen Arbeitgeber "
    "und Betriebsrat; diese Unterlage liefert dafür die Tatsachen.“"
)


def _joined(path: Path) -> str:
    """The text with line breaks inside paragraphs joined, for sentences across lines."""
    return re.sub(r"(?<=\S)\n(?=\S)", " ", _text(path))


def test_the_no_performance_control_text_keeps_the_sentence_for_the_agreement():
    assert _BETRVG_SENTENCE in _joined(PRIVACY / "keine-leistungskontrolle.md")


def test_the_no_performance_control_text_gives_seven_reasons_with_their_criteria():
    text = _text(PRIVACY / "keine-leistungskontrolle.md")
    reasons = re.findall(r"^\d\. .*", _section(text, "Gründe"), re.M)
    assert len(reasons) == 7
    for criterion in (
        "PLT-19-A4",
        "PLT-64-A1",
        "GV-03",
        "EXI-PLT-68-A2",
        "GV-28",
        "EXI-PLT-68-A4",
        "PLT-64",
    ):
        assert criterion in text, criterion


def test_the_remaining_paths_name_reading_storage_and_measure():
    rows = _table_rows(_text(PRIVACY / "keine-leistungskontrolle.md"), "Pfad")
    paths = " ".join(row[0] for row in rows)
    for expected in ("Root", "Docker-Socket", "papaia-audit-db", "Sicherungsschlüssel", "SIEM"):
        assert expected in paths, expected
    for row in rows:
        assert len(row) == 4 and all(row), row


def test_the_dpia_input_lists_every_risk_with_measure_and_criterion():
    rows = _table_rows(_text(PRIVACY / "dsfa-zuarbeit.md"), "Risiko")
    risks = " ".join(row[0] for row in rows)
    for expected in (
        "Gedächtnis",
        "Gruppenraum",
        "Nutzungsauswertung",
        "Audit",
        "SQL",
        "Modellanbieter",
        "Föderation",
        "Host-Zugriff",
    ):
        assert expected in risks, expected
    for row in rows:
        assert len(row) == 3 and all(row), row


_NO_CRITERION = "keines (organisatorische Maßnahme des Betreibers)"


def test_the_toms_follow_article_32_and_name_a_criterion_per_measure():
    text = _text(PRIVACY / "tom.md")
    for heading in (
        "Vertraulichkeit",
        "Integrität",
        "Verfügbarkeit",
        "Belastbarkeit",
        "Wiederherstellung",
        "Überprüfung",
        "Pseudonymisierung",
        "Verschlüsselung",
    ):
        rows = _table_rows(_section(text, heading), "Maßnahme")
        assert rows, heading
        for row in rows:
            assert len(row) == 4 and all(row), (heading, row)
            # GV-* items are chapters of the specification, not acceptance criteria.
            assert not re.search(r"\bGV-\d+", row[1]), (heading, row)
            if row[1].startswith(_NO_CRITERION):
                assert row[3] == "Betreiber", (heading, row)
    for criterion in ("PLT-21", "PLT-50", "PLT-12", "PLT-23", "OPS-07", "PLT-35", "PLT-61"):
        assert criterion in text, criterion
    assert "Betreiber" in text


def test_the_logging_text_names_who_reads_and_how_long():
    text = _text(PRIVACY / "protokollierung.md")
    for expected in ("papaia-auditor", "PAPAIA_AUDIT_RETENTION_MONTHS", "12", "Pseudonym"):
        assert expected in text, expected


def test_the_agreement_points_leave_the_legal_review_to_the_operator():
    text = _text(PRIVACY / "betriebsvereinbarung-eckpunkte.md")
    assert "rechtliche Prüfung" in text
    assert len(re.findall(r"^\d+\. ", text, re.M)) >= 8


def test_the_index_lists_every_hand_written_document():
    text = _text(PRIVACY / "index.md")
    for path in REQUIRED:
        if path.parent == PRIVACY and path.name != "index.md":
            assert f"]({path.name})" in text, path.name
    assert "rechtliche Prüfung" in text


# --- evidence with the shipped model (OPS-14) ---------------------------------------


def test_the_model_evidence_names_the_variant_the_procedure_and_the_report():
    text = _text(MODEL_DOC)
    assert "qwen2.5-1.5b-instruct" in text
    assert "EXK-PLT-72-A2" in text
    assert "zehn von zehn" in text.lower()
    for module in ("Studio", "Data", "Flow", "Assistant"):
        assert module in text, module
    report = _table_rows(text, "Feld")
    assert len(report) >= 6 and all(len(row) == 2 and all(row) for row in report)
