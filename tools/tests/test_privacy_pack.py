"""Data protection package: `papaia-ctl privacy-pack` renders the records of processing per
module from the `storage` declarations, `--check` compares the files with the
declarations, `--installation` writes the package of one installation as one document."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from lib import privacy_pack

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 21, 9, 30, 0, tzinfo=timezone.utc)

ROOT_ENV = {
    "OIDC_ISSUER": "https://auth.papaia.example/realms/papaia",
    "COMPOSE_PROFILES": "rag",
    "PAPAIA_BACKUP_DIR": "/srv/papaia/backup",
    "KC_ADMIN_PASSWORD": "not-a-real-password-value",
}


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))


def _install(tmp_path: Path, addons=(("privacy/addon-notes", "notes"),
                                       ("catalog/addon-console", "papaia-flow"))) -> Path:
    """The sample installation: profile rag, the notes add-on (personal data) and the
    flow console (no personal data)."""
    config_dir = tmp_path / "papaia-config"
    _write_env(config_dir / ".env", ROOT_ENV)
    entries = []
    for fixture, name in addons:
        path = tmp_path / "addons" / name
        shutil.copytree(FIXTURES / fixture, path)
        entries.append({"name": name, "path": str(path), "active": True, "state": "running"})
        _write_env(config_dir / "addons" / name / ".env", {"NOTES_TOKEN": "s3cr3t-notes-token"})
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries}))
    return config_dir


def _declared(name: str) -> list[dict]:
    path = FIXTURES / "privacy" / "addon-notes" / "papaia-app.yaml"
    assert name == "notes"
    return yaml.safe_load(path.read_text())["exposes"]


def _generated(text: str) -> str:
    start = text.index(privacy_pack.BEGIN) + len(privacy_pack.BEGIN)
    return text[start:text.index(privacy_pack.END)]


def _table(text: str) -> list[dict[str, str]]:
    """The rows of the first table of the generated part, header -> cell."""
    lines = [ln for ln in _generated(text).splitlines() if ln.startswith("|")]
    if not lines:
        return []
    split = [
        [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", ln)[1:-1]]
        for ln in lines
    ]
    header, rows = split[0], split[2:]
    return [dict(zip(header, row, strict=True)) for row in rows]


# ─────────────────────────────────────────────────────────────────────────
# records of processing from the declarations
# ─────────────────────────────────────────────────────────────────────────


def test_generated_tables_equal_the_declarations_of_the_sample_install(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)

    notes = (out / "vvt" / "addon-notes.md").read_text()
    rows = _table(notes)
    declared = _declared("notes")[0]
    categories = declared["storage"]["categories"]
    assert [r["Datenkategorie"] for r in rows] == [c["title"]["de"] for c in categories]
    for row, category in zip(rows, categories, strict=True):
        assert row["Zweck"] == category["purpose"]["de"]
        assert category["legal_basis"]["de"] in row["Rechtsgrundlage"]
        assert row["Datenklasse"] == privacy_pack.DATA_CLASS[category["data_class"]]
        assert "Dienst notes-mcp" in row["Ort (Dienst, Volume)"]
        assert "Volume notes-data (in der Sicherung)" in row["Ort (Dienst, Volume)"]
        assert "Volume notes-cache (nicht in der Sicherung)" in row["Ort (Dienst, Volume)"]
        assert "qdrant.collections" in row["Empfänger"]
        assert row["Betroffene Personen"]
        assert row["Klartext/verschlüsselt"]
    assert rows[0]["Aufbewahrung"] == "365 Tage"
    assert rows[1]["Aufbewahrung"] == privacy_pack.UNTIL["deleted_by_person"]
    assert rows[0]["Löschweg"] == privacy_pack.ERASURE["me_api"]
    assert categories[1]["on_request"]["way"]["de"] in rows[1]["Löschweg"]
    assert "Notizverwaltung" in rows[1]["Löschweg"]
    # The module has a personal-area interface, so the person reads her data there.
    assert all(r["Zugriffsweg der Person"] == privacy_pack.ACCESS_ME for r in rows)
    assert "notes.me" in _generated(notes)  # declared without personal data

    flow = (out / "vvt" / "flow.md").read_text()
    assert _table(flow) == []
    assert "flow.api" in _generated(flow) and "flow.console" in _generated(flow)

    kern = (out / "vvt" / "kern.md").read_text()
    # The rag profile declares no storage yet: shown, not hidden.
    assert "qdrant.collections" in _generated(kern)
    assert any("qdrant.collections" in w for w in pack.warnings)


def test_no_cell_of_a_generated_table_is_empty(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    privacy_pack.write(privacy_pack.collect(REPO, config_dir), out)
    for path in (out / "vvt").glob("*.md"):
        for row in _table(path.read_text()):
            assert all(cell for cell in row.values()), (path.name, row)


def test_check_passes_on_fresh_output_and_reports_a_changed_cell(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    assert privacy_pack.check(pack, out) == []

    path = out / "vvt" / "addon-notes.md"
    path.write_text(path.read_text().replace("365 Tage", "730 Tage"))
    problems = privacy_pack.check(pack, out)
    assert any("vvt/addon-notes.md" in p and "differs" in p for p in problems)


def test_check_fails_on_an_empty_cell(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    path = out / "vvt" / "addon-notes.md"
    path.write_text(path.read_text().replace("| 365 Tage |", "|  |"))
    assert any("empty cell" in p for p in privacy_pack.check(pack, out))


def test_check_fails_on_a_missing_or_a_stale_module_file(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    (out / "vvt" / "flow.md").unlink()
    (out / "vvt" / "addon-gone.md").write_text("# Alt\n")
    problems = privacy_pack.check(pack, out)
    assert any("vvt/flow.md" in p and "missing" in p for p in problems)
    assert any("vvt/addon-gone.md" in p and "no module" in p for p in problems)


def test_check_requires_a_criterion_for_every_claim_of_a_technical_lock(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    (out / "tom.md").write_text(
        "# Maßnahmen\n\nDas Lesen fremder Notizen ist technisch gesperrt (PLT-65-A4).\n\n"
        "Ein Export ohne Begründung ist nicht möglich.\n"
    )
    problems = privacy_pack.check(pack, out)
    assert len(problems) == 1
    assert "tom.md:5" in problems[0] and "criterion" in problems[0]


def test_write_keeps_hand_written_text_around_the_generated_part(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    path = out / "vvt" / "addon-notes.md"
    text = path.read_text()
    edited = text.replace(privacy_pack.BEGIN, "Von Hand davor.\n\n" + privacy_pack.BEGIN)
    edited += "\nVon Hand danach.\n"
    path.write_text(edited)
    assert privacy_pack.write(pack, out) == []  # nothing changed
    privacy_pack.write(pack, out)
    assert path.read_text() == edited


def test_a_file_with_broken_markers_is_refused_and_left_alone(tmp_path):
    config_dir = _install(tmp_path)
    out = tmp_path / "pack"
    pack = privacy_pack.collect(REPO, config_dir)
    privacy_pack.write(pack, out)
    path = out / "vvt" / "flow.md"
    path.write_text(f"# Flow\n{privacy_pack.BEGIN}\nkein Ende\n")
    with pytest.raises(privacy_pack.PrivacyPackError, match="vvt/flow.md"):
        privacy_pack.write(pack, out)
    assert path.read_text() == f"# Flow\n{privacy_pack.BEGIN}\nkein Ende\n"


def test_an_invalid_declaration_is_refused_with_its_place(tmp_path):
    config_dir = _install(tmp_path)
    manifest = tmp_path / "addons" / "notes" / "papaia-app.yaml"
    doc = yaml.safe_load(manifest.read_text())
    doc["exposes"][0]["storage"]["categories"][0]["retention"] = {"days": 0}
    manifest.write_text(yaml.safe_dump(doc, allow_unicode=True))
    with pytest.raises(privacy_pack.PrivacyPackError, match="notes: exposes/0/storage"):
        privacy_pack.collect(REPO, config_dir)


def test_the_repository_pack_is_current():
    """CI: docs/de/datenschutz/ equals what the declarations of the core render."""
    pack = privacy_pack.collect(REPO)
    assert privacy_pack.check(pack, REPO / privacy_pack.REPO_OUT) == []


# ─────────────────────────────────────────────────────────────────────────
# the package of one installation
# ─────────────────────────────────────────────────────────────────────────


def _installation(tmp_path: Path, *, hosted_model: bool = False, **options):
    config_dir = _install(tmp_path)
    _write_env(config_dir / "infra" / "smtp-relay" / ".env",
               {"SMTP_RELAY_UPSTREAM_HOST": "mail.example.net", "SMTP_RELAY_UPSTREAM_PORT": "587"})
    if hosted_model:
        # The test switch with one hosted route, as the render leaves it.
        _write_env(config_dir / ".env", {**ROOT_ENV, "PAPAIA_TEST_EXTERNAL_MODEL": "1"})
        litellm = config_dir / "ai" / "litellm" / "config.yaml"
        litellm.parent.mkdir(parents=True, exist_ok=True)
        litellm.write_text(yaml.safe_dump({"model_list": [{
            "model_name": "papaia-chat",
            "litellm_params": {"model": "hosted_vllm/reference", "api_base": "https://models.example.org",
                               "api_key": "os.environ/TEST_HOSTED_KEY"},
        }]}))
    settings = privacy_pack.Installation(
        backup_retention_days=options.get("backup_retention_days", 30),
        offsite=options.get("offsite", "Rechenzentrum Beispiel, Bandsicherung"),
        offsite_retention_days=options.get("offsite_retention_days", 90),
    )
    return config_dir, settings


def test_installation_lists_the_processors_and_places_with_their_deadlines(tmp_path):
    config_dir, settings = _installation(tmp_path, hosted_model=True)
    doc = privacy_pack.installation_document(REPO, config_dir, settings, now=NOW)
    text = privacy_pack.to_markdown(doc)
    assert "Auftragsverarbeiter dieser Installation" in text
    assert "models.example.org:443" in text
    assert "mail.example.net:587" in text
    assert "Rechenzentrum Beispiel, Bandsicherung" in text and "90 Tage" in text
    assert "/srv/papaia/backup" in text and "30 Tage" in text
    assert "Externer IT-Dienstleister mit Zugang zum Host" in text
    # The records of every module of this installation are part of the one document.
    assert "Notizen \\| Entwürfe" in text
    assert "Verzeichnis der Verarbeitungstätigkeiten: Flow" in text
    assert "s3cr3t" not in text and "not-a-real-password-value" not in text


def test_installation_without_external_model_or_mail_says_so(tmp_path):
    config_dir, settings = _installation(tmp_path, offsite=None, offsite_retention_days=None)
    (config_dir / "infra" / "smtp-relay" / ".env").unlink()
    text = privacy_pack.to_markdown(
        privacy_pack.installation_document(REPO, config_dir, settings, now=NOW)
    )
    assert privacy_pack.NO_EXTERNAL_MODEL in text
    assert privacy_pack.NO_MAIL in text
    assert privacy_pack.NO_OFFSITE in text


@pytest.mark.parametrize("fmt", ["html", "pdf", "md"])
def test_installation_writes_one_document_and_one_audit_row(tmp_path, fmt):
    config_dir, settings = _installation(tmp_path)
    target = tmp_path / "out" / f"datenschutz.{fmt}"
    privacy_pack.write_installation(REPO, config_dir, settings, target, fmt, now=NOW)
    data = target.read_bytes()
    if fmt == "pdf":
        assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
        assert b"Auftragsverarbeiter dieser Installation" in data
    elif fmt == "html":
        text = data.decode()
        assert text.startswith("<!DOCTYPE html>")
        assert "<table>" in text and "Notizen | Entwürfe" in text
        assert "<script" not in text
    else:
        assert b"Auftragsverarbeiter" in data
    rows = [
        json.loads(line)
        for line in (config_dir / "audit" / "outbox" / "papaia-ctl.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 1
    row = rows[0]
    assert row["format"] == "papaia.audit/1"
    assert row["operation"] == "privacy_pack.installation_write"
    assert row["result"] == "allowed" and row["correlation_id"]
    assert "s3cr3t" not in json.dumps(row)


def test_html_escapes_operator_text(tmp_path):
    # Declared texts cannot carry markup (exposes.v1 refuses < and >); the operator's
    # place of the copy off site can.
    config_dir, settings = _installation(tmp_path, offsite="<script>alert(1)</script> Band")
    target = tmp_path / "d.html"
    privacy_pack.write_installation(REPO, config_dir, settings, target, "html", now=NOW)
    text = target.read_text()
    assert "<script>" not in text and "&lt;script&gt;alert(1)&lt;/script&gt; Band" in text


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"backup_retention_days": 0}, "backup retention"),
        ({"backup_retention_days": 40000}, "backup retention"),
        ({"offsite": "Band", "offsite_retention_days": None}, "together"),
        ({"offsite": None, "offsite_retention_days": 90}, "together"),
        ({"offsite": "x" * 201}, "offsite"),
        ({"offsite": "Band\nzweite Zeile"}, "offsite"),
    ],
)
def test_installation_settings_are_validated(tmp_path, options, message):
    _, settings = _installation(tmp_path, **options)
    with pytest.raises(privacy_pack.PrivacyPackError, match=message):
        settings.validate()


def test_an_unknown_format_is_refused_and_nothing_is_written(tmp_path):
    config_dir, settings = _installation(tmp_path)
    target = tmp_path / "d.docx"
    with pytest.raises(privacy_pack.PrivacyPackError, match="format"):
        privacy_pack.write_installation(REPO, config_dir, settings, target, "docx", now=NOW)
    assert not target.exists()
    assert not (config_dir / "audit" / "outbox" / "papaia-ctl.jsonl").exists()


# ─────────────────────────────────────────────────────────────────────────
# command line
# ─────────────────────────────────────────────────────────────────────────


def _ctl(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(REPO / "tools" / "papaia-ctl"), *args],
        cwd=cwd, capture_output=True, text=True, check=False,
    )


def test_cli_check_of_the_repository_pack_passes():
    result = _ctl("privacy-pack", "--check")
    assert result.returncode == 0, result.stderr
    assert "up to date" in result.stdout


def test_cli_writes_and_checks_an_output_directory(tmp_path):
    out = tmp_path / "pack"
    assert _ctl("privacy-pack", "--lang=de", f"--out={out}").returncode == 0
    assert (out / "vvt" / "kern.md").is_file()
    assert _ctl("privacy-pack", "--check", f"--out={out}").returncode == 0
    path = out / "vvt" / "kern.md"
    path.write_text(path.read_text().replace("qdrant.collections", "qdrant.other"))
    result = _ctl("privacy-pack", "--check", f"--out={out}")
    assert result.returncode == 1
    assert "vvt/kern.md" in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("--lang=en",),
        ("--format=pdf",),  # only with --installation
        ("--installation", "--format=docx", "--out=x.docx", "--backup-retention=30"),
        ("--installation", "--check"),
        ("--bogus",),
    ],
)
def test_cli_refuses_bad_options(args):
    result = _ctl("privacy-pack", *args)
    assert result.returncode == 2, (result.stdout, result.stderr)
