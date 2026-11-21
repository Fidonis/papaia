"""The data protection package: `papaia-ctl privacy-pack`.

The records of processing (Art. 30 GDPR) are generated from what the modules declare,
so that they match the code they ship with. Every `exposes:` entry may carry a `storage`
section (kit schema exposes.v1: `personal_data`, `categories[]` with purpose, legal
basis, retention, data class and erasure path); its `volumes`, `address`, `downstream`
and `identity` complete the row.

- `privacy-pack [--out DIR]` writes `vvt/<module>.md` under `docs/de/datenschutz/` of the
  core repository from the declarations of the core profiles. Only the part between the
  markers BEGIN and END is generated; text around it is kept as written by hand.
- `privacy-pack --check [--out DIR]` renders again and fails when a generated part
  differs from the declarations, a module file is missing or stale, a table of a
  generated part has an empty cell, or a claim of a technical lock ("technisch
  gesperrt", "nicht möglich") anywhere in the package names no acceptance criterion.
- `privacy-pack --installation --format=html|pdf|md --out FILE` writes the package of
  this installation as one document: the records of every active core profile and
  installed add-on, the processors this installation actually sends data to (the hosted
  model route, the mail server behind the relay, the host service provider) and the
  places that keep copies, each with its deadline (backup target, copy off site). The
  write leaves one `papaia.audit/1` row.

The package states facts from declarations and configuration; it is no legal advice and
the legal review stays with the controller. Texts are German (`--lang=de`).
"""

from __future__ import annotations

import html
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import catalog, common, compat, exposes, hosted_model, smtp

BEGIN = "<!-- generiert: privacy-pack, nicht von Hand ändern -->"
END = "<!-- ende generiert -->"
REPO_OUT = Path("docs/de/datenschutz")
VVT_DIR = "vvt"
WRITER = "papaia-ctl/privacy-pack"
FORMATS = ("html", "pdf", "md")
MAX_DAYS = 36500
MAX_TEXT = 200

# Module files of the suite (governance GV-22); every other add-on gets addon-<name>.
MODULE_FILES = {
    "papaia-studio": ("studio", "Studio"),
    "papaia-data": ("data", "Data"),
    "papaia-flow": ("flow", "Flow"),
    "papaia-assist": ("assistenz", "Assistenz"),
    "papaia-me": ("mein-bereich", "Mein Bereich"),
    "papaia-connections": ("anbindungen", "Anbindungen"),
}
CORE_FILE = ("kern", "Kern")
_ADDON_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

COLUMNS = (
    "Datenkategorie",
    "Betroffene Personen",
    "Zweck",
    "Ort (Dienst, Volume)",
    "Aufbewahrung",
    "Empfänger",
    "Löschweg",
    "Zugriffsweg der Person",
    "Rechtsgrundlage",
    "Datenklasse",
    "Klartext/verschlüsselt",
)
DATA_CLASS = {
    "public": "öffentlich",
    "internal": "intern",
    "partner_contact": "Geschäftskontakt",
    "personal": "personenbezogen",
    "employee": "Beschäftigtendaten",
    "confidential": "vertraulich",
    "special": "besondere Kategorie (Art. 9 DSGVO)",
    "professional_secret": "Berufsgeheimnis",
}
UNTIL = {
    "account_deleted": "bis zur Löschung des Kontos",
    "deleted_by_person": "bis die Person die Daten löscht",
    "legal_obligation": "nach der gesetzlichen Aufbewahrungspflicht",
}
ERASURE = {
    "retention": "automatisch nach Ablauf der Aufbewahrung",
    "me_api": "durch die Person in Mein Bereich",
    "person_erase": "mit dem Löschantrag zur Person (person erase)",
}
ACCESS_ME = "Mein Bereich (Meine Daten)"
ACCESS_REQUEST = "Auskunft auf Antrag beim Verantwortlichen"
SUBJECTS_PERSON = "angemeldete Personen"
SUBJECTS_SERVICE = "Personen in Daten, die andere Module übergeben"
AT_REST = "Klartext im Volume (keine Verschlüsselung deklariert)"
RECIPIENTS_EXTERNAL = "extern: nur nach der Liste der Auftragsverarbeiter der Installation"
NO_EXTERNAL_MODEL = "kein Modell außerhalb der Installation eingerichtet"
NO_MAIL = "kein Mailserver eingerichtet"
NO_OFFSITE = "keine Kopie außer Haus angegeben"
HOST_PROVIDER = "Externer IT-Dienstleister mit Zugang zum Host"

# A claim of a technical lock must name the criterion that proves it (EXK-PLT-65-A4).
_CLAIM = re.compile(r"technisch gesperrt|nicht möglich", re.IGNORECASE)
_CRITERION = re.compile(r"\b(?:[A-Z]{2,4}-)+[A-Z]?\d+(?:-[A-Z]?\d+)*\b")


class PrivacyPackError(Exception):
    """The package cannot be generated or written; nothing was changed."""


# ─────────────────────────────────────────────────────────────────────────
# document blocks: one structure, three output forms
# ─────────────────────────────────────────────────────────────────────────

Block = tuple  # ("h1"|"h2"|"h3"|"p", text) | ("ul", [items]) | ("table", headers, rows)


@dataclass
class Module:
    stem: str
    title: str
    blocks: list[Block]


@dataclass
class Pack:
    modules: dict[str, Module] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def to_markdown(blocks: list[Block]) -> str:
    out: list[str] = []
    for block in blocks:
        kind = block[0]
        if kind in ("h1", "h2", "h3"):
            out.append("#" * int(kind[1]) + " " + block[1])
        elif kind == "p":
            out.append(block[1])
        elif kind == "ul":
            out.append("\n".join(f"- {item}" for item in block[1]))
        else:
            headers, rows = block[1], block[2]
            lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
            lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
            out.append("\n".join(lines))
    return "\n\n".join(out) + "\n"


def to_html(blocks: list[Block], title: str) -> str:
    esc = html.escape
    body: list[str] = []
    for block in blocks:
        kind = block[0]
        if kind in ("h1", "h2", "h3", "p"):
            body.append(f"<{kind}>{esc(block[1])}</{kind}>")
        elif kind == "ul":
            body.append("<ul>" + "".join(f"<li>{esc(i)}</li>" for i in block[1]) + "</ul>")
        else:
            head = "".join(f"<th>{esc(h)}</th>" for h in block[1])
            rows = "".join(
                "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in block[2]
            )
            body.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    style = (
        "body{font-family:sans-serif;font-size:10pt;margin:2em}"
        "table{border-collapse:collapse;width:100%;margin:1em 0}"
        "th,td{border:1px solid #888;padding:4px;vertical-align:top;text-align:left}"
        "th{background:#eee}"
    )
    return (
        '<!DOCTYPE html>\n<html lang="de"><head><meta charset="utf-8">'
        f"<title>{esc(title)}</title><style>{style}</style></head><body>\n"
        + "\n".join(body)
        + "\n</body></html>\n"
    )


def _wrap(text: str, width: int) -> list[str]:
    lines, line = [], ""
    for word in text.split():
        while len(word) > width:
            if line:
                lines.append(line)
                line = ""
            lines.append(word[:width])
            word = word[width:]
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    return lines + ([line] if line else [])


def _pdf_text(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def to_pdf(blocks: list[Block]) -> bytes:
    """A4 PDF with the standard fonts Helvetica and Helvetica-Bold (WinAnsiEncoding, so
    German letters print without embedding a font). Tables print as one record per row:
    the first cell as a heading, the others as `column: value`."""
    lines: list[tuple[str, int, str]] = []  # (font, size, text); size 0 = gap

    def add(text: str, font: str = "F1", size: int = 9, width: int = 100) -> None:
        lines.extend((font, size, part) for part in _wrap(text, width))

    for block in blocks:
        kind = block[0]
        if kind == "h1":
            add(block[1], "F2", 14, 64)
        elif kind == "h2":
            add(block[1], "F2", 12, 76)
        elif kind == "h3":
            add(block[1], "F2", 10, 90)
        elif kind == "p":
            add(block[1])
        elif kind == "ul":
            for item in block[1]:
                add(f"- {item}")
        else:
            headers, rows = block[1], block[2]
            for row in rows:
                add(row[0], "F2", 9)
                for header, value in zip(headers[1:], row[1:], strict=True):
                    add(f"{header}: {value}")
                lines.append(("F1", 0, ""))
        lines.append(("F1", 0, ""))

    pages: list[bytes] = []
    content: list[bytes] = []
    y = 792.0
    for font, size, text in lines:
        step = 6.0 if size == 0 else size * 1.35
        if y - step < 50 and content:
            pages.append(b"\n".join(content))
            content, y = [], 792.0
        y -= step
        if size:
            content.append(
                b"BT /%s %d Tf 50 %.1f Td (%s) Tj ET" % (font.encode(), size, y, _pdf_text(text))
            )
    pages.append(b"\n".join(content))

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",  # pages, filled below
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    ]
    kids = []
    for stream in pages:
        objects.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream) + 1, stream))
        content_id = len(objects)
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>" % content_id
        )
        kids.append(b"%d 0 R" % len(objects))
    objects[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(kids), len(kids))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, xref
    )
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────
# declarations -> records of processing
# ─────────────────────────────────────────────────────────────────────────


def _module_file(provider: str) -> tuple[str, str]:
    if provider.startswith("core:"):
        return CORE_FILE
    if provider in MODULE_FILES:
        return MODULE_FILES[provider]
    if not _ADDON_NAME.match(provider):
        raise PrivacyPackError(f"add-on name '{provider}' cannot name a file")
    return f"addon-{provider}", f"Erweiterung {provider}"


def _de(text: dict) -> str:
    return text.get("de") or text.get("en") or ""


def _retention(retention: dict) -> str:
    parts = []
    if "days" in retention:
        parts.append(f"{retention['days']} Tage")
    if "until" in retention:
        parts.append(UNTIL[retention["until"]])
    text = "; ".join(parts)
    note = _de(retention.get("note") or {})
    return f"{text} ({note})" if note else text


def _place(provider: str, entry: dict) -> str:
    parts = []
    if entry.get("address"):
        parts.append(f"Dienst {entry['address']['service']}")
    for volume in entry.get("volumes") or ():
        state = "in der Sicherung" if volume["backup"] == "include" else "nicht in der Sicherung"
        parts.append(f"Volume {volume['name']} ({state})")
    return "; ".join(parts) or f"Modul {provider} (kein Dienst und kein Volume deklariert)"


def _recipients(title: str, entry: dict) -> str:
    parts = [f"intern: {title}"]
    downstream = [d for d in entry.get("downstream") or () if isinstance(d, str)]
    if any(isinstance(d, dict) for d in entry.get("downstream") or ()):
        downstream.append("Quellen aus dem Katalog")
    if downstream:
        parts.append("weitergegeben an " + ", ".join(downstream))
    if entry.get("models"):
        parts.append("Modell-Gateway")
    parts.append(RECIPIENTS_EXTERNAL)
    return "; ".join(parts)


def _erasure(category: dict) -> str:
    if category["erasure"] != "on_request":
        return ERASURE[category["erasure"]]
    request = category["on_request"]
    return f"auf Antrag: {_de(request['way'])} Zuständig: {_de(request['responsible'])}"


def _row(provider: str, title: str, entry: dict, category: dict, has_me: bool) -> list[str]:
    access = ACCESS_ME if has_me or category["erasure"] == "me_api" else ACCESS_REQUEST
    row = [
        _de(category["title"]),
        SUBJECTS_PERSON if "person" in entry["identity"] else SUBJECTS_SERVICE,
        _de(category["purpose"]),
        _place(provider, entry),
        _retention(category["retention"]),
        _recipients(title, entry),
        _erasure(category),
        access,
        f"Vorschlag des Moduls: {_de(category['legal_basis'])}; vom Verantwortlichen zu prüfen",
        DATA_CLASS[category["data_class"]],
        AT_REST,
    ]
    for header, cell in zip(COLUMNS, row, strict=True):
        if not cell.strip():
            raise PrivacyPackError(
                f"{provider}: {entry['id']}/{category['id']}: column '{header}' would be empty"
            )
    return row


def _add_source(pack: Pack, provider: str, section: list) -> None:
    try:
        exposes.check(section, provider)
    except exposes.ExposesError as exc:
        raise PrivacyPackError(str(exc)) from None
    stem, title = _module_file(provider)
    module = pack.modules.setdefault(stem, Module(stem, title, []))
    has_me = any(entry["kind"] == "me" for entry in section)
    without, undeclared = [], []
    for entry in section:
        storage = entry.get("storage")
        if storage is None:
            undeclared.append(f"{entry['id']} ({provider})")
            pack.warnings.append(f"{provider}: {entry['id']} declares no storage")
            continue
        if not storage["personal_data"]:
            without.append(f"{entry['id']} ({provider})")
            continue
        rows = [_row(provider, title, entry, c, has_me) for c in storage["categories"]]
        module.blocks += [
            ("h3", f"{_de(entry['title'])} ({entry['id']}, {provider})"),
            ("p", f"Aufbewahrung insgesamt: {_retention(storage['retention'])}"),
            ("table", list(COLUMNS), rows),
        ]
    if without:
        module.blocks += [("p", "Ohne Personendaten deklariert:"), ("ul", without)]
    if undeclared:
        module.blocks += [
            ("p", "Ohne Angabe zur Speicherung (das Modul muss storage deklarieren):"),
            ("ul", undeclared),
        ]


def collect(repo_root: Path, config_dir: Path | None = None) -> Pack:
    """The records of processing. Without `config_dir`: every core profile of this
    repository (the package shipped in docs/de/datenschutz/). With it: the active core
    profiles and the installed add-ons of that installation."""
    try:
        if config_dir is None:
            sources = catalog.repository_sources(repo_root)
        else:
            sources = catalog.installation_sources(config_dir, repo_root)
    except catalog.CatalogError as exc:
        raise PrivacyPackError(str(exc)) from None
    pack = Pack()
    for source in sorted(sources, key=lambda s: s.provider):
        _add_source(pack, source.provider, source.section)
    return pack


# ─────────────────────────────────────────────────────────────────────────
# the files under docs/de/datenschutz/
# ─────────────────────────────────────────────────────────────────────────


def _generated_part(module: Module) -> str:
    return "\n" + to_markdown(module.blocks)


def _split(text: str, name: str) -> tuple[str, str, str]:
    if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
        raise PrivacyPackError(f"{name}: needs exactly one generated part ({BEGIN} ... {END})")
    head, rest = text.split(BEGIN)
    middle, tail = rest.split(END)
    return head, middle, tail


def _expected(pack: Pack, out_dir: Path) -> dict[str, tuple[Path, str]]:
    """Relative name -> (path, the file's content with the generated part replaced)."""
    result = {}
    for stem in sorted(pack.modules):
        module = pack.modules[stem]
        name = f"{VVT_DIR}/{stem}.md"
        path = out_dir / VVT_DIR / f"{stem}.md"
        if path.is_file():
            head, _, tail = _split(path.read_text(encoding="utf-8"), name)
        else:
            head = f"# Verzeichnis der Verarbeitungstätigkeiten: {module.title}\n\n"
            tail = "\n"
        result[name] = (path, head + BEGIN + _generated_part(module) + END + tail)
    return result


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def write(pack: Pack, out_dir: Path) -> list[str]:
    """Write the module files whose content changed; returns their names. Every file is
    read and checked before the first one is written."""
    expected = _expected(pack, out_dir)
    changed = [
        name for name, (path, text) in expected.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != text
    ]
    for name in changed:
        path, text = expected[name]
        _atomic_write(path, text.encode("utf-8"), 0o644)
    return changed


def _empty_cells(name: str, text: str) -> list[str]:
    problems = []
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        if BEGIN in line:
            inside = True
        elif END in line:
            inside = False
        elif inside and line.startswith("|") and not line.startswith("|---"):
            cells = re.split(r"(?<!\\)\|", line)[1:-1]
            if any(not cell.strip() for cell in cells):
                problems.append(f"{name}:{number}: empty cell in a generated table")
    return problems


def _claims(name: str, text: str) -> list[str]:
    return [
        f"{name}:{number}: claim of a technical lock names no acceptance criterion"
        for number, line in enumerate(text.splitlines(), start=1)
        if _CLAIM.search(line) and not _CRITERION.search(line)
    ]


def check(pack: Pack, out_dir: Path) -> list[str]:
    """Problems of the package in `out_dir`; empty when it is up to date."""
    problems: list[str] = []
    try:
        expected = _expected(pack, out_dir)
    except PrivacyPackError as exc:
        return [str(exc)]
    for name, (path, text) in expected.items():
        if not path.is_file():
            problems.append(f"{name}: missing (run privacy-pack)")
        elif path.read_text(encoding="utf-8") != text:
            problems.append(f"{name}: generated part differs from the declarations")
    vvt = out_dir / VVT_DIR
    for path in sorted(vvt.glob("*.md")) if vvt.is_dir() else ():
        name = f"{VVT_DIR}/{path.name}"
        if name not in expected:
            problems.append(f"{name}: no module of the declarations belongs to it")
    for path in sorted(out_dir.rglob("*.md")) if out_dir.is_dir() else ():
        name = path.relative_to(out_dir).as_posix()
        text = path.read_text(encoding="utf-8")
        problems += _empty_cells(name, text) + _claims(name, text)
    return problems


# ─────────────────────────────────────────────────────────────────────────
# the package of one installation
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Installation:
    """What only the operator can say: how long backups are kept, and where a copy off
    site lies and for how long."""

    backup_retention_days: int
    offsite: str | None = None
    offsite_retention_days: int | None = None

    def validate(self) -> None:
        def days(value: object, what: str) -> None:
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_DAYS:
                raise PrivacyPackError(f"{what} must be a whole number of days, 1 to {MAX_DAYS}")

        days(self.backup_retention_days, "backup retention")
        if (self.offsite is None) != (self.offsite_retention_days is None):
            raise PrivacyPackError("--offsite and --offsite-retention go together")
        if self.offsite is not None:
            if not 1 <= len(self.offsite) <= MAX_TEXT or not self.offsite.isprintable():
                raise PrivacyPackError(
                    f"offsite place must be one line of 1 to {MAX_TEXT} characters"
                )
            days(self.offsite_retention_days, "offsite retention")


def _processors(repo_root: Path, config_dir: Path) -> list[list[str]]:
    try:
        route = hosted_model.route(
            config_dir, hosted_model.rendered_stack_names(config_dir, repo_root)
        )
    except hosted_model.HostedModelError as exc:
        raise PrivacyPackError(f"model route: {exc}") from None
    model = f"{route[0]}:{route[1]}" if route else NO_EXTERNAL_MODEL
    relay = common.parse_env_file(config_dir / smtp.MODULE_DIR / ".env")
    host = relay.get(smtp.KEY_HOST, "")
    mail = f"{host}:{relay.get(smtp.KEY_PORT) or smtp.RELAY_PORT}" if host else NO_MAIL
    return [
        ["Modellserver", model, "Eingaben und Antworten an das Modell",
         "Modell-Gateway (ai/litellm/config.yaml)"],
        ["Mail-Ausgang", mail, "Mails der Plattform mit Empfängeradresse",
         f"Mail-Relais ({smtp.MODULE_DIR}/.env)"],
        [HOST_PROVIDER, "vom Betreiber einzutragen",
         "alle Daten auf dem Host und in den Sicherungen", "Vertrag des Betreibers"],
    ]


def installation_document(
    repo_root: Path, config_dir: Path, settings: Installation, now: datetime | None = None
) -> list[Block]:
    settings.validate()
    pack = collect(repo_root, config_dir)
    env = common.parse_env_file(config_dir / ".env")
    version = compat.resolve_core_target(repo_root).platform_version or "unbekannt"
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    backup_dir = env.get("PAPAIA_BACKUP_DIR") or "kein Sicherungsziel eingerichtet"
    offsite = (
        [settings.offsite, "Kopien der Sicherungen", f"{settings.offsite_retention_days} Tage"]
        if settings.offsite
        else [NO_OFFSITE, "entfällt", "entfällt"]
    )
    blocks: list[Block] = [
        ("h1", "Datenschutzunterlagen dieser Installation"),
        ("p", f"Stand {stamp}, papAIa {version}. Erzeugt aus den Deklarationen der Module und "
              "der Konfiguration dieser Installation. Die rechtliche Prüfung bleibt Sache des "
              "Verantwortlichen."),
        ("h2", "Auftragsverarbeiter dieser Installation"),
        ("table", ["Rolle", "Empfänger", "Daten", "Eingerichtet in"],
         _processors(repo_root, config_dir)),
        ("h2", "Orte mit Kopien und ihre Fristen"),
        ("table", ["Ort", "Inhalt", "Frist"], [
            [backup_dir, "Sicherungen der Volumes mit backup: include",
             f"{settings.backup_retention_days} Tage"],
            offsite,
        ]),
    ]
    for stem in sorted(pack.modules):
        module = pack.modules[stem]
        blocks.append(("h2", f"Verzeichnis der Verarbeitungstätigkeiten: {module.title}"))
        blocks += module.blocks
    return blocks


def write_installation(
    repo_root: Path,
    config_dir: Path,
    settings: Installation,
    target: Path,
    fmt: str,
    now: datetime | None = None,
) -> None:
    """Write the package of this installation to `target` and leave one audit row."""
    from . import realm_sync as rs  # it imports the render path

    if fmt not in FORMATS:
        raise PrivacyPackError(f"format must be one of {', '.join(FORMATS)}")
    blocks = installation_document(repo_root, config_dir, settings, now)
    title = "Datenschutzunterlagen dieser Installation"
    data = {
        "md": lambda: to_markdown(blocks).encode("utf-8"),
        "html": lambda: to_html(blocks, title).encode("utf-8"),
        "pdf": lambda: to_pdf(blocks),
    }[fmt]()
    change = rs.Change("file", target.name, f"data protection package written ({fmt})",
                       "installation_write")
    try:
        audit = rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        raise PrivacyPackError(f"the audit outbox cannot be written: {exc}") from None
    with audit:
        try:
            _atomic_write(target, data, 0o640)
        except OSError:
            audit.write(change, "error", "io", host=True)
            raise
        audit.write(change, "allowed", host=True)
