"""The public install guide for the core profiles `me` and `connections`.

A reader must be able to enable, address and disable both profiles from the README alone,
and see what an upgrade and a backup do with them. These tests hold that:

- every relative link of the README and of docs/configuration.md resolves (file and heading);
- the service table has a row for each profile, and the toggle paragraph says how each is
  switched on;
- each profile has its section with the parts enable, address, disable, upgrade, and backup
  and restore, naming the commands and names the core really uses;
- the upgrade stage table does not send Me through `--addon-path`: the profile `me` runs
  from the core's pinned image (ADR 0020);
- every variable the sections name is one an `.env.example` ships, and the configuration
  page documents every variable of the profiles' `.env.example` files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.test_operator_docs_de import _FENCE, _HEADING, _LINK, _anchors, _prose_lines

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
CONFIGURATION = REPO / "docs" / "configuration.md"

ROOT_ENV = REPO / "src" / ".env.example"
ME_ENV = REPO / "src" / "infra" / "me" / ".env.example"
CONNECTIONS_ENV = REPO / "src" / "infra" / "connections" / ".env.example"

ME_SECTION = "Mein Bereich (`me`)"
CONNECTIONS_SECTION = "Connection registry (`connections`)"
PARTS = ("Enable.", "Address.", "Disable.", "Upgrade.", "Backup and restore.")

# Names in backticks that look like variables: upper case, digits and underscores, at least
# one underscore; a trailing `*` stands for a family (`CONNECTIONS_OPENBAO_*`).
_VARIABLE = re.compile(r"`([A-Z][A-Z0-9]*_[A-Z0-9_]*\*?)`")
_ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=", re.MULTILINE)
# Not variables of an .env file: placeholders of a command line and file names.
_NOT_VARIABLES = frozenset({"PAPAIA_CONFIG_DIR"})


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _env_names(path: Path) -> set[str]:
    return set(_ENV_LINE.findall(_text(path)))


def _shipped_names() -> set[str]:
    return _env_names(ROOT_ENV) | _env_names(ME_ENV) | _env_names(CONNECTIONS_ENV)


def _matches(name: str, names: set[str]) -> bool:
    """`name` is in `names`; a family `X_*` on either side stands for every name it starts."""
    if name.endswith("*"):
        return any(n.startswith(name[:-1]) for n in names)
    return any(n == name or (n.endswith("*") and name.startswith(n[:-1])) for n in names)


def _section(text: str, heading: str) -> str:
    """The text below the heading `heading` up to the next heading of the same or a higher
    level. Lines inside fenced code blocks are never headings: a shell comment such as
    `# $PAPAIA_CONFIG_DIR/.env` in an example does not end the section."""
    lines = text.splitlines()
    fenced = False
    start = level = None
    body: list[str] = []
    for line in lines:
        if _FENCE.match(line):
            fenced = not fenced
        match = None if fenced or _FENCE.match(line) else _HEADING.match(line)
        if start is None:
            if match and match.group(2) == heading:
                start, level = True, len(match.group(1))
            continue
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    if start is None:
        raise AssertionError(f"no heading {heading!r}")
    return "\n".join(body)


def _broken_links(path: Path, root: Path = REPO) -> list[str]:
    problems = []
    for number, line in _prose_lines(_text(path)):
        for target in _LINK.findall(line):
            if re.match(r"[a-z][a-z0-9+.-]*:", target):
                continue
            file_part, _, anchor = target.partition("#")
            linked = (path.parent / file_part).resolve() if file_part else path
            where = f"{path.relative_to(root)}:{number}: {target}"
            if not linked.exists():
                problems.append(f"{where}: no such file")
            elif anchor and linked.suffix == ".md" and anchor not in _anchors(linked):
                problems.append(f"{where}: no such heading")
    return problems


def _table_after(text: str, heading: str) -> list[list[str]]:
    """The body rows of the first table below `heading`."""
    rows: list[list[str]] = []
    inside = False
    for line in _section(text, heading).splitlines():
        if line.startswith("|"):
            inside = True
            if not line.startswith("|---"):
                rows.append([cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1]])
        elif inside:
            break
    return rows[1:]


# --- links ----------------------------------------------------------------------------


@pytest.mark.parametrize("path", [README, CONFIGURATION], ids=lambda p: p.name)
def test_every_relative_link_resolves(path: Path):
    assert _broken_links(path) == []


def test_the_link_check_finds_a_missing_heading_and_file(tmp_path: Path):
    page = tmp_path / "page.md"
    page.write_text(
        "# Title\n\n[ok](#title) [gone](#installation-settings) [file](nowhere.md)\n"
        "\n```\n[in a fence](#not-checked)\n```\n",
        encoding="utf-8",
    )
    assert _broken_links(page, tmp_path) == [
        "page.md:3: #installation-settings: no such heading",
        "page.md:3: nowhere.md: no such file",
    ]


def test_a_comment_in_a_code_block_does_not_end_a_section():
    text = "## A\n\n```bash\n# a comment\nrun\n```\n\nafter\n\n## B\n\nother\n"
    body = _section(text, "A")
    assert "after" in body and "other" not in body


# --- service table and toggles --------------------------------------------------------


def test_the_service_table_has_a_row_for_each_profile():
    profiles = {row[1] for row in _table_after(_text(README), "Optional")}
    assert {"`me`", "`connections`"} <= profiles


def test_the_toggle_paragraph_says_how_each_profile_is_switched_on():
    optional = _section(_text(README), "Optional")
    assert "`--connections`" in optional
    assert re.search(r"`me`[^.]*`COMPOSE_PROFILES`", optional), (
        "the toggle paragraph must say that `me` is switched on through COMPOSE_PROFILES"
    )
    assert f"[Mein Bereich](#{_slug_of(ME_SECTION)})" in optional
    assert f"[Connection registry](#{_slug_of(CONNECTIONS_SECTION)})" in optional


def _slug_of(heading: str) -> str:
    from tests.test_operator_docs_de import _slug

    return _slug(heading)


# --- the two sections -----------------------------------------------------------------


@pytest.mark.parametrize("heading", [ME_SECTION, CONNECTIONS_SECTION])
def test_each_profile_has_its_parts(heading: str):
    body = _section(_text(README), heading)
    missing = [part for part in PARTS if f"**{part}**" not in body]
    assert missing == []


ME_FACTS = (
    "COMPOSE_PROFILES",
    "`ME_PUBLIC_URL`",
    "`me.<domain>`",
    "proxy list",
    "stop --clean-up --profiles=me",
    "`prefs-pgdata`",
    "--only=module:me",
    "(docs/configuration.md#mein-bereich-variables)",
    "(docs/adr/0020-mein-bereich-and-the-preference-store-as-core-profile.md)",
)

CONNECTIONS_FACTS = (
    "setup --connections",
    "setup --no-connections",
    "https://connections:8080",
    "stop --clean-up --profiles=connections",
    "--volumes",
    "`connections-db`",
    "`connections-keys`",
    "--only=module:connections",
    "secrets rotate connections/credentials",
    "(docs/configuration.md#connection-registry-variables)",
    "(docs/adr/0021-connection-registry-as-a-core-profile.md)",
)


@pytest.mark.parametrize(
    ("heading", "facts"),
    [(ME_SECTION, ME_FACTS), (CONNECTIONS_SECTION, CONNECTIONS_FACTS)],
    ids=["me", "connections"],
)
def test_each_section_names_what_the_core_uses(heading: str, facts: tuple[str, ...]):
    body = _section(_text(README), heading)
    assert [fact for fact in facts if fact not in body] == []


def test_the_me_section_has_no_addon_path():
    """Me is a core profile from one pinned image, not an add-on checkout."""
    assert "--addon-path" not in _section(_text(README), ME_SECTION)


# --- upgrade stages -------------------------------------------------------------------


def test_the_stage_table_does_not_send_me_through_an_addon_checkout():
    """Stage 3 has its own row: the core profile `me` changes with the core (stage 2), and
    only an installation that runs Me as an add-on gets an `addon upgrade` there."""
    upgrade = _section(_text(README), "`upgrade`")
    rows = [line for line in upgrade.splitlines() if line.startswith("| 3 ")]
    assert len(rows) == 1, rows
    row = rows[0]
    assert row.startswith("| 3 `me` |"), row
    assert "profile `me`" in row and "stage 2" in row, row
    shared = [line for line in upgrade.splitlines() if line.startswith("| 4 `data`")]
    assert len(shared) == 1 and "--addon-path" in shared[0]


# --- variables ------------------------------------------------------------------------


@pytest.mark.parametrize("heading", [ME_SECTION, CONNECTIONS_SECTION])
def test_every_variable_a_section_names_is_shipped(heading: str):
    shipped = _shipped_names()
    named = set(_VARIABLE.findall(_section(_text(README), heading))) - _NOT_VARIABLES
    assert named, "the section names its variables"
    assert sorted(n for n in named if not _matches(n, shipped)) == []


@pytest.mark.parametrize(
    ("env", "heading"),
    [(ME_ENV, "Mein Bereich variables"), (CONNECTIONS_ENV, "Connection registry variables")],
    ids=["me", "connections"],
)
def test_the_configuration_page_documents_every_variable_of_the_profile(env: Path, heading: str):
    documented = set(_VARIABLE.findall(_section(_text(CONFIGURATION), heading)))
    assert documented, f"docs/configuration.md has a section {heading!r}"
    shipped = _env_names(env)
    assert sorted(n for n in shipped if not _matches(n, documented)) == [], "undocumented"
    assert sorted(
        n for n in documented if not _matches(n, shipped | _env_names(ROOT_ENV))
    ) == [], "documented but not shipped"


def test_the_headings_the_sections_rely_on_are_unique():
    """Two headings of the same text would give the second one a suffixed anchor."""
    headings = [
        match.group(2)
        for _, line in _prose_lines(_text(README))
        if (match := _HEADING.match(line))
    ]
    for heading in (ME_SECTION, CONNECTIONS_SECTION):
        assert headings.count(heading) == 1, heading
