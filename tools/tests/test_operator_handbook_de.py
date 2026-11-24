"""The German operator handbook under docs/de/betrieb/ (BE-30).

The handbook is hand-written, but most of what it states is also a fact of the repository:
the size profiles `doctor` enforces, the containers, images, volumes and published ports of
each core profile, the rows of `security/comm-matrix.yaml`, the sections of the
troubleshooting guide that `doctor` and the start gate cite, the commands of `papaia-ctl`.
These tests hold the handbook to those facts, so it cannot drift from the code:

- every chapter exists and the index links it; links and headings are checked for all
  German documents by test_operator_docs_de.py;
- the size profiles carry all of their figures and equal `host_size.PROFILES`; the default
  model names the aliases the model gateway installs;
- the share of each core profile (containers, images, volumes, published ports) equals the
  shipped Compose fragments;
- the communication matrix has exactly the rows of `security/comm-matrix.yaml` with the same
  direction, ports, protocol, duty and way; every row that leaves the host is in the egress
  list;
- the module matrix holds one of three values per pair and no cycle of "nötig";
- every section S-1 to S-10 and "Diagnose" exists with the five parts the specification
  names, and every section the code cites is there;
- every `papaia-ctl` command and every `doctor` check the handbook names exists: the usage
  text is read by running `papaia-ctl help`.

With `PAPAIA_HANDBOOK_ADDONS` set to the add-on directories of the suite (separated by the
path separator), two more tests compare the module rows with the add-on manifests and
Compose files: the shares and the `requires` of each module.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import compat, doctor, host_size, model_gateway, startgate
from tests.test_operator_docs_de import _HEADING, _prose_lines, _section, _table_rows

REPO = Path(__file__).resolve().parents[2]
OPERATIONS = REPO / "docs" / "de" / "betrieb"

INDEX = OPERATIONS / "handbuch.md"
SIZE = OPERATIONS / "groesse.md"
NETWORK = OPERATIONS / "netz.md"
MODULES = OPERATIONS / "module.md"
RESTART = OPERATIONS / "neustart-und-dauerlauf.md"
GUIDE = OPERATIONS / "stoerungen.md"
BACKUP = OPERATIONS / "sicherung.md"
REQUESTS = OPERATIONS / "auskunft-und-loeschung.md"

CHAPTERS = [SIZE, NETWORK, MODULES, RESTART, GUIDE, BACKUP, REQUESTS]
HANDBOOK = [INDEX, *CHAPTERS]

ADDONS_ENV = "PAPAIA_HANDBOOK_ADDONS"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _cells(rows: list[list[str]]) -> dict[str, list[str]]:
    """Rows keyed by their first cell, markup removed."""
    return {row[0].strip("*` "): row for row in rows}


def _number(cell: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*", cell)
    assert match, f"not a number: {cell!r}"
    return int(match.group(1))


# --- chapters -------------------------------------------------------------------------


@pytest.mark.parametrize("path", HANDBOOK, ids=lambda p: p.name)
def test_the_chapter_exists_and_starts_with_its_title(path: Path):
    assert path.is_file()
    assert _text(path).startswith("# ")


def test_the_index_links_every_chapter_and_the_documents_index_links_the_index():
    text = _text(INDEX)
    assert [p.name for p in CHAPTERS if f"]({p.name}" not in text] == []
    for linked in ("../wiederherstellung.md", "lizenz-und-bezug.md", "../datenschutz/index.md"):
        assert f"]({linked}" in text, linked
    assert "](./de/betrieb/handbuch.md)" in _text(REPO / "docs" / "README.md")


# --- size profiles (OPS-01) -----------------------------------------------------------


def _gb(cell: str) -> int:
    match = re.match(r"\s*(\d+) GB\b", cell)
    assert match, f"no size in GB: {cell!r}"
    return int(match.group(1))


def test_the_size_profiles_carry_every_figure_and_equal_what_doctor_enforces():
    """PLT-58-A1: both profiles (and the large one) with all their figures; the figures are
    the ones `doctor profile_size` checks."""
    rows = _cells(_table_rows(_text(SIZE), "Profil"))
    assert sorted(rows) == sorted(host_size.PROFILES)
    for name, profile in host_size.PROFILES.items():
        row = rows[name]
        assert len(row) == 6 and all(row), row
        assert _number(row[1].split()[0]) == profile.cores, name
        assert _gb(row[2]) * host_size.GB == profile.memory, name
        assert _gb(row[3]) * host_size.GB == profile.disk, name
        if profile.gpu_alternative:
            memory, vram = profile.gpu_alternative
            assert f"{memory // host_size.GB} GB" in row[2], name
            assert f"{vram // host_size.GB} GB" in row[2], name


def test_the_default_model_names_the_aliases_the_gateway_installs():
    section = _section(_text(SIZE), "Vorgabemodell")
    for alias in (model_gateway.CPU_DEFAULT, model_gateway.GPU_DEFAULT):
        assert f"`{alias}`" in section, alias
    for expected in (
        "Qwen2.5-7B-Instruct",
        "Q4_K_M",
        "Q8_0",
        "Apache-2.0",
        "qwen2.5-1.5b-instruct",
    ):
        assert expected in section, expected


def test_the_size_chapter_says_how_to_measure_and_what_is_measured():
    section = _section(_text(SIZE), "Messen")
    for expected in ("docker stats --no-stream", "docker system df", "85 %"):
        assert expected in section, expected


# --- share per core profile (PLT-58-A1, A4) -------------------------------------------


def _source(volume: object) -> str | None:
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    if isinstance(volume, dict) and volume.get("type") == "volume":
        return volume.get("source")
    return None


def _share(services: dict[str, dict], top_volumes: set[str]) -> tuple[int, int, int, int]:
    """Containers, images, named volumes, published ports of a set of services."""
    images, volumes, ports = set(), set(), 0
    for name, body in services.items():
        images.add(body.get("image") or f"build:{name}")
        volumes.update(
            source for source in map(_source, body.get("volumes") or []) if source in top_volumes
        )
        ports += len(body.get("ports") or [])
    return len(services), len(images), len(volumes), ports


def core_shares() -> dict[str, tuple[int, int, int, int]]:
    """{profile: share} from the fragments `src/docker-compose.yml` includes, and the whole
    core with every profile on under "gesamt" (images and volumes counted once)."""
    by_profile: dict[str, dict[str, dict]] = {}
    every: dict[str, dict] = {}
    top: set[str] = set()
    for path in compat.compose_files(REPO / "src" / "docker-compose.yml"):
        document = yaml.safe_load(_text(path)) or {}
        top |= set((document.get("volumes") or {}).keys())
        for name, body in (document.get("services") or {}).items():
            every[name] = body
            for profile in body.get("profiles") or ["(ohne Profil)"]:
                by_profile.setdefault(profile, {})[name] = body
    shares = {profile: _share(services, top) for profile, services in by_profile.items()}
    shares["gesamt"] = _share(every, top)
    return shares


def _share_rows(text: str) -> dict[str, tuple[int, int, int, int]]:
    rows = _cells(_table_rows(text, "Kern-Profil"))
    return {name: tuple(_number(cell) for cell in row[1:5]) for name, row in rows.items()}


def test_the_share_of_every_core_profile_equals_the_compose_fragments():
    assert _share_rows(_text(SIZE)) == core_shares()


def addon_share(directory: Path) -> tuple[int, int, int, int]:
    """The services `addon start` starts: those without a Compose profile."""
    document = yaml.safe_load(_text(directory / "docker-compose.yml")) or {}
    services = {
        name: body
        for name, body in (document.get("services") or {}).items()
        if not body.get("profiles")
    }
    return _share(services, set((document.get("volumes") or {}).keys()))


def _addon_dirs() -> list[Path]:
    raw = os.environ.get(ADDONS_ENV, "")
    if not raw:
        pytest.skip(f"{ADDONS_ENV} is not set: no add-on directories to compare with")
    return [Path(part) for part in raw.split(os.pathsep) if part]


def _manifest(directory: Path) -> dict:
    return yaml.safe_load(_text(directory / "papaia-app.yaml")) or {}


MODULE_NAMES = {
    "papaia-studio": "Studio",
    "papaia-data": "Data",
    "papaia-flow": "Flow",
    "papaia-assist": "Assistant",
    "paperless": "Paperless",
}


def test_the_share_of_every_module_equals_its_compose_file():
    shares = _cells(_table_rows(_text(SIZE), "Modul"))
    for directory in _addon_dirs():
        name = MODULE_NAMES[_manifest(directory)["name"]]
        row = shares[name]
        assert tuple(_number(cell) for cell in row[1:5]) == addon_share(directory), name


def test_the_module_share_table_has_a_row_per_module():
    rows = _cells(_table_rows(_text(SIZE), "Modul"))
    assert sorted(rows) == sorted(MODULE_NAMES.values())
    for row in rows.values():
        assert len(row) == 6 and all(row), row


# --- communication matrix and egress list (OPS-22, OPS-07) ---------------------------

_DIRECTIONS = {
    "eingehend": "inbound",
    "intern": "internal",
    "ausgehend": "outbound",
    "Host": "host",
}
_WAYS = {"–": None, "Ausgang": "egress", "direkt": "direct"}


def _matrix() -> list[dict]:
    return yaml.safe_load(_text(REPO / "security" / "comm-matrix.yaml"))["rows"]


def _ports(cell: str) -> tuple[list[int], str]:
    ports_part, _, protocol = cell.rpartition("/")
    ports = [int(p) for p in re.findall(r"\d+", ports_part)] if ports_part.strip("– ") else []
    return ports, protocol.strip()


def test_the_matrix_in_the_handbook_has_exactly_the_rows_of_comm_matrix():
    """PLT-65-A1: source, target, port, protocol, purpose, required or optional; inbound,
    between the Docker networks and outbound. The yaml is the one source, the table may
    differ only in language."""
    rows = _table_rows(_section(_text(NETWORK), "Kommunikationsmatrix"), "Nr")
    table = {row[0]: row for row in rows}
    matrix = _matrix()
    assert list(table) == [row["id"] for row in matrix]
    for row in matrix:
        cells = table[row["id"]]
        assert len(cells) == 10 and all(cells), cells
        assert _DIRECTIONS[cells[1]] == row["direction"], row["id"]
        assert _ports(cells[5]) == (row["ports"], row["protocol"]), row["id"]
        assert cells[8] == ("Pflicht" if row["required"] else "wahlweise"), row["id"]
        assert _WAYS[cells[9]] == row.get("via"), row["id"]


def test_every_pending_row_is_named_as_not_yet_in_place():
    section = _section(_text(NETWORK), "Noch nicht umgesetzt")
    named = set(re.findall(r"\bK-\d\d\b", section))
    assert named == {row["id"] for row in _matrix() if row.get("pending")}


def test_every_row_that_leaves_the_host_is_in_the_egress_list():
    """PLT-64-A2: the list of everything that leaves the network names every outbound row
    and every row made by the host; each of its rows says when and whether it can be
    switched off."""
    rows = _table_rows(_section(_text(NETWORK), "Ausgangsliste"), "Ziel")
    assert rows
    for row in rows:
        assert len(row) == 4 and all(row), row
    cited = set(re.findall(r"\bK-\d\d\b", " ".join(row[1] for row in rows)))
    leaving = {row["id"] for row in _matrix() if row["direction"] in ("outbound", "host")}
    assert leaving <= cited
    assert cited <= {row["id"] for row in _matrix()}


# --- module matrix (OPS-02) -----------------------------------------------------------

_MODULE_VALUE = re.compile(r"^(?:nötig|unabhängig|erweitert um .+|–)$")


def _module_matrix() -> tuple[list[str], dict[str, dict[str, str]]]:
    rows = _table_rows(_section(_text(MODULES), "Abhängigkeitsmatrix"), "braucht")
    header = next(line for line in _text(MODULES).splitlines() if line.startswith("| braucht"))
    columns = [cell.strip() for cell in header.strip("|").split("|")][1:]
    return columns, {row[0]: dict(zip(columns, row[1:], strict=True)) for row in rows}


def test_every_pair_of_the_module_matrix_holds_one_of_three_values():
    """PLT-59-A1: per pair exactly one of "nötig", "erweitert um <Funktion>",
    "unabhängig"; the diagonal is empty."""
    columns, matrix = _module_matrix()
    assert list(matrix) == columns
    for row, cells in matrix.items():
        for column, value in cells.items():
            assert _MODULE_VALUE.match(value), (row, column, value)
            assert (value == "–") == (row == column), (row, column, value)


def test_no_cycle_of_needed_modules():
    _, matrix = _module_matrix()
    needs = {row: {c for c, v in cells.items() if v == "nötig"} for row, cells in matrix.items()}

    def reaches(start: str, goal: str, seen: frozenset[str] = frozenset()) -> bool:
        return any(
            nxt == goal or (nxt not in seen and reaches(nxt, goal, seen | {nxt}))
            for nxt in needs[start]
        )

    assert [name for name in needs if reaches(name, name)] == []


def test_every_module_needs_the_core():
    _, matrix = _module_matrix()
    for name, cells in matrix.items():
        if name != "Kern":
            assert cells["Kern"] == "nötig", name
    assert all(v in ("–", "unabhängig") for v in matrix["Kern"].values())


def test_the_module_matrix_equals_the_requires_of_the_manifests():
    """PLT-59-A1 with the manifests: `requires.addons` without `optional` is "nötig", with
    `optional: true` "erweitert um …", no entry "unabhängig"."""
    _, matrix = _module_matrix()
    for directory in _addon_dirs():
        manifest = _manifest(directory)
        name = MODULE_NAMES[manifest["name"]]
        expected = {}
        for entry in (manifest.get("requires") or {}).get("addons") or []:
            other = MODULE_NAMES[entry.get("name") or entry.get("id")]
            expected[other] = "erweitert" if entry.get("optional") else "nötig"
        for column, value in matrix[name].items():
            if column in ("Kern", name):
                continue
            wanted = expected.get(column, "unabhängig")
            assert value.split()[0] == wanted, (name, column, value)


# --- troubleshooting guide (BE-29, BE-16a) -------------------------------------------

_GUIDE_SECTIONS = [f"S-{n}" for n in range(1, 11)]
_PARTS = ("Anzeichen.", "Prüfung.", "Behebung.", "Rückkehr.", "Eskalation.")


def _guide_headings() -> dict[str, str]:
    """{"S-1": "S-1 Modell-Gateway läuft nicht", "Diagnose": "Diagnose"}"""
    headings = {}
    for _, line in _prose_lines(_text(GUIDE)):
        match = _HEADING.match(line)
        if match and len(match.group(1)) == 2:
            title = match.group(2)
            headings[title.split()[0]] = title
    return headings


def test_the_guide_has_every_section_with_its_five_parts():
    headings = _guide_headings()
    assert [key for key in [*_GUIDE_SECTIONS, "Diagnose"] if key not in headings] == []
    text = _text(GUIDE)
    for key in _GUIDE_SECTIONS:
        section = _section(text, headings[key])
        assert [part for part in _PARTS if f"**{part}**" not in section] == [], key
        assert "papaia-ctl doctor" in section, key


def test_every_section_the_code_cites_is_in_the_guide():
    cited = set()
    for root in (REPO / "tools" / "lib", REPO / "src"):
        for path in root.rglob("*.py"):
            cited |= set(re.findall(r"Handbuch §(S-\d+)", _text(path)))
    assert cited
    assert sorted(cited - set(_guide_headings())) == []


def test_the_guide_quotes_the_sentences_doctor_prints():
    text = _text(GUIDE)
    headings = _guide_headings()
    for key, sentence in (
        ("S-1", "Das Modell-Gateway (LiteLLM) läuft nicht; Module können keine Modelle nutzen."),
        ("S-3", "Der Anmeldedienst (Keycloak) ist nicht erreichbar; niemand kann sich anmelden."),
    ):
        assert sentence in re.sub(r"\s+", " ", _section(text, headings[key])), key
    gate = _section(text, headings["S-10"])
    for code in startgate.MESSAGES:
        assert f"`{code}`" in gate, code


# --- commands -------------------------------------------------------------------------

_MENTION = re.compile(r"papaia-ctl ([^`\n]*)")
_WORD = re.compile(r"[a-z][a-z0-9_-]*")
_ALTERNATIVES = re.compile(r"[a-z][a-z-]*(?:\|[a-z][a-z-]*)*")


def _usage() -> dict[tuple[str, ...], set[str]]:
    """{words so far: the words that may follow} from the output of `papaia-ctl help`: the
    commands under (), their subcommands under (command,), and so on. A command whose next
    token is an argument (`<name>`, `[--flag]`, `REQUEST`) has no entry for its words."""
    result = subprocess.run(
        [str(REPO / "tools" / "papaia-ctl"), "help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    tree: dict[tuple[str, ...], set[str]] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*papaia-ctl\s+(.*)", line)
        if not match:
            continue
        prefixes: list[tuple[str, ...]] = [()]
        for token in match.group(1).split():
            if not _ALTERNATIVES.fullmatch(token):
                break
            words = token.split("|")
            for prefix in prefixes:
                tree.setdefault(prefix, set()).update(words)
            prefixes = [(*prefix, word) for prefix in prefixes for word in words]
    return tree


def _mentions(line: str) -> list[list[str]]:
    """The leading words of each `papaia-ctl …` on a line."""
    found = []
    for rest in _MENTION.findall(line):
        words = []
        for token in rest.split():
            if not _WORD.fullmatch(token):
                break
            words.append(token)
        found.append(words)
    return found


def _unknown(words: list[str], tree: dict[tuple[str, ...], set[str]], checks: set[str]) -> str:
    """Why `papaia-ctl <words>` is no command, or "" when it is one."""
    prefix: tuple[str, ...] = ()
    for word in words:
        if prefix == ("doctor",):
            return "" if word in checks else f"no such check {word!r}"
        allowed = tree.get(prefix)
        if not allowed:
            return ""
        if word not in allowed:
            return f"no such command {' '.join((*prefix, word))!r}"
        prefix = (*prefix, word)
    return ""


def test_every_command_and_check_the_handbook_names_exists():
    tree = _usage()
    checks = set(doctor.CHECK_NAMES) | set(doctor.DISTRIBUTED_CHECK_NAMES)
    problems = []
    for path in HANDBOOK:
        for number, line in enumerate(_text(path).splitlines(), start=1):
            for words in _mentions(line):
                if reason := _unknown(words, tree, checks):
                    problems.append(f"{path.name}:{number}: {reason}")
    assert problems == []


def test_the_command_check_is_not_blind():
    tree = _usage()
    checks = set(doctor.CHECK_NAMES)
    assert {"find", "export", "erase", "status"} <= tree[("person",)]
    assert _unknown(["recover-nothing"], tree, checks)
    assert _unknown(["backup", "target", "verify"], tree, checks)
    assert _unknown(["doctor", "no_such_check"], tree, checks)
    assert not _unknown(["backup", "target", "check"], tree, checks)
    assert not _unknown(["logs", "litellm"], tree, checks)
    assert _mentions("`papaia-ctl doctor startgate` meldet") == [["doctor", "startgate"]]


def _required_flags() -> dict[tuple[str, ...], set[frozenset[str]]]:
    """{command words: the flags its usage line requires} from `papaia-ctl help`: the `--flag`
    tokens outside brackets, each as the set of its alternatives (`--name=NAME|--email=MAIL`).
    A command with more than one usage line has several forms and no entry; so has a command
    that requires no flag."""
    result = subprocess.run(
        [str(REPO / "tools" / "papaia-ctl"), "help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    forms: dict[tuple[str, ...], list[set[frozenset[str]]]] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*papaia-ctl\s+(.*)", line)
        if not match:
            continue
        tokens = match.group(1).split(" \u2014 ")[0].split()
        words: list[str] = []
        while tokens and re.fullmatch(r"[a-z][a-z-]*", tokens[0]):
            words.append(tokens.pop(0))
        depth, flags = 0, set()
        for token in tokens:
            if depth == 0 and token.startswith("--"):
                flags.add(frozenset(part.split("=")[0] for part in token.split("|")))
            depth += token.count("[") - token.count("]")
        forms.setdefault(tuple(words), []).append(flags)
    return {path: found[0] for path, found in forms.items() if len(found) == 1 and found[0]}


def _calls(text: str) -> list[tuple[int, str]]:
    """(line, rest) of each `papaia-ctl …` in a text; a line ending in a backslash goes on."""
    found = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        joined, index = line, number
        while joined.endswith("\\") and index < len(lines):
            joined = joined[:-1] + " " + lines[index]
            index += 1
        found.extend((number, rest) for rest in _MENTION.findall(joined))
    return found


def test_every_call_the_handbook_names_carries_the_flags_its_command_requires():
    required = _required_flags()
    assert required[("startgate", "acknowledge")] == {
        frozenset({"--reason"}),
        frozenset({"--by"}),
    }
    assert frozenset({"--name", "--email"}) in required[("person", "find")]
    problems = []
    for path in HANDBOOK:
        for number, rest in _calls(_text(path)):
            words = tuple(rest.split())
            for command, flags in required.items():
                if words[: len(command)] != command:
                    continue
                given = {token.split("=")[0] for token in words if token.startswith("--")}
                if missing := sorted(min(flag) for flag in flags if not flag & given):
                    problems.append(f"{path.name}:{number}: {' '.join(command)} lacks {missing}")
    assert problems == []


# --- module names in `addon` calls (BE-30) --------------------------------------------

_ADDON_CALL = re.compile(
    r"papaia-ctl addon (install|start|stop|remove|uninstall|upgrade|rollback|run|components)"
    r"\s+([^\s`]+)"
)


def test_every_addon_call_names_a_module_by_its_manifest_name():
    """`addon install` registers a module under the name it is given; upgrade, the start order
    and the dependent modules match `requires.addons` against that name. A call in the handbook
    must therefore use the manifest name, or a placeholder."""
    problems = []
    seen = 0
    for path in HANDBOOK:
        for number, line in enumerate(_text(path).splitlines(), start=1):
            for verb, name in _ADDON_CALL.findall(line):
                if name.startswith(("<", "[", "-")):
                    continue
                seen += 1
                if name not in MODULE_NAMES:
                    problems.append(f"{path.name}:{number}: addon {verb} {name}")
    assert problems == []
    assert seen, "the handbook shows no addon call with a module name"


def test_the_module_chapter_says_the_name_is_the_manifest_name_and_lists_the_names():
    text = re.sub(r"\s+", " ", _text(MODULES))
    assert "Manifestname" in text
    for name in MODULE_NAMES:
        assert f"`{name}`" in text, name


# --- backups, snapshots, copies outside the house (BE-16, BE-16a) --------------------

_OFFSITE_SENTENCE = (
    "„Wird von einer Kopie außer Haus wiederhergestellt, kehren Löschungen nach dem Tag "
    "dieser Kopie zurück. Führen Sie danach für jede Person aus der Liste der Löschnachweise "
    "seit diesem Tag `person erase` erneut aus.“"
)


def _joined(path: Path) -> str:
    return re.sub(r"(?<=\S)\n(?=\S)", " ", _text(path))


def test_the_copies_outside_the_house_carry_the_literal_sentence():
    assert _OFFSITE_SENTENCE in _joined(BACKUP)


def test_the_hypervisor_section_states_the_rules_of_a_snapshot():
    section = re.sub(r"\s+", " ", _section(_text(BACKUP), "Sicherung durch den Hypervisor"))
    for expected in (
        "kein Ersatz",
        "verschlüsselt",
        "Rückwegschlüssel",
        "papaia-ctl doctor startgate",
        "§S-10",
    ):
        assert expected in section, expected


def test_the_data_subject_request_has_six_steps_and_the_deadline():
    text = _text(REQUESTS)
    steps = re.findall(r"^\d\. \*\*", _section(text, "Ablauf in sechs Schritten"), re.M)
    assert len(steps) == 6
    joined = re.sub(r"\s+", " ", text)
    assert "Art. 12 Abs. 3 DSGVO" in joined
    assert (
        "Wer `person export` ausführt und die Passphrase erhält, kann das Archiv lesen." in joined
    )
    assert "sicherung.md#kopien-außer-haus" in text
