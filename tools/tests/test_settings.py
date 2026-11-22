"""Installation settings: contact point, brand and the four-eyes rule (`papaia-ctl settings`).

Each change is stored in the operator overlay, renders the platform catalog at once and
leaves `papaia.audit/1` rows; `approvals.four_eyes` is `off` by default, switchable in
profile `standard` and always `on` in profile `kritis`, where switching it off is refused
and the refusal is audited (Ä-52 A4/A5, E-18). `doctor approvals` and `doctor
contact_point` report the values (BE-26)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lib import catalog, cli, doctor, schema_check, settings
from lib import realm_sync as rs
from tests.test_catalog import _install, _schema

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
CTL = TOOLS / "papaia-ctl"
BASH = shutil.which("bash")
NOW = datetime(2026, 11, 21, 9, 30, 0, tzinfo=timezone.utc)

needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
WEBP = b"RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def _config(tmp_path: Path, profile: str = "standard") -> Path:
    config_dir = _install(tmp_path, "", [])
    env = config_dir / ".env"
    env.write_text(
        env.read_text().replace(
            "PAPAIA_SECURITY_PROFILE=standard", f"PAPAIA_SECURITY_PROFILE={profile}"
        )
    )
    return config_dir


def _services(config_dir: Path) -> dict:
    return json.loads((config_dir / "platform" / "services.json").read_text())


def _rows(config_dir: Path) -> list[dict]:
    path = rs.audit_path(config_dir)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _settings_rows(config_dir: Path) -> list[dict]:
    return [r for r in _rows(config_dir) if r["writer"] == settings.WRITER]


def _set(config_dir: Path, key: str, value: str) -> settings.Outcome:
    return settings.set_value(config_dir, REPO, key, value)


def _validate(row: dict) -> None:
    from papaia_kit.audit import validate_event

    validate_event(row, stage="submission")


# ─────────────────────────────────────────────────────────────────────────
# approvals.four_eyes
# ─────────────────────────────────────────────────────────────────────────


def test_four_eyes_is_off_by_default_in_profile_standard(tmp_path):
    config_dir = _config(tmp_path)
    catalog.render(config_dir, REPO, now=NOW)

    assert _services(config_dir)["approvals"] == {"four_eyes": "off"}
    shown = settings.show(config_dir)
    assert shown["approvals"] == {"four_eyes": "off", "fixed": False}
    assert shown["security_profile"] == "standard"


def test_switching_four_eyes_on_and_off_is_audited_with_old_and_new_value(tmp_path):
    config_dir = _config(tmp_path)

    on = _set(config_dir, "approvals.four_eyes", "on")
    assert on.changed is True and on.catalog_written is True
    assert _services(config_dir)["approvals"] == {"four_eyes": "on"}
    off = _set(config_dir, "approvals.four_eyes", "off")
    assert off.changed is True
    assert _services(config_dir)["approvals"] == {"four_eyes": "off"}

    rows = [r for r in _settings_rows(config_dir) if r["event"] == "four_eyes_changed"]
    assert [(r["result"], r["detail"]) for r in rows] == [
        ("allowed", {"four_eyes_old": "off", "four_eyes_new": "on"}),
        ("allowed", {"four_eyes_old": "on", "four_eyes_new": "off"}),
    ]
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["sub"].startswith("host:")
        assert row["time"].endswith("Z")
        assert row["error_code"] is None
        assert row["operation"] == "settings.four_eyes_set"
        assert row["object_ref"] == {"type": "setting", "id": "approvals.four_eyes"}
        assert row["correlation_id"]
    assert rows[0]["correlation_id"] != rows[1]["correlation_id"]


@needs_kit
def test_the_four_eyes_rows_are_valid_audit_events(tmp_path):
    config_dir = _config(tmp_path)
    _set(config_dir, "approvals.four_eyes", "on")
    _set(config_dir, "branding.name", "Beispiel GmbH")
    kritis = _config(tmp_path / "k", "kritis")
    with pytest.raises(settings.RefusedError):
        _set(kritis, "approvals.four_eyes", "off")

    rows = _settings_rows(config_dir) + _settings_rows(kritis)
    assert len(rows) == 3
    for row in rows:
        _validate(row)


def test_setting_the_value_in_effect_is_no_change_and_writes_no_row(tmp_path):
    config_dir = _config(tmp_path)
    outcome = _set(config_dir, "approvals.four_eyes", "off")

    assert outcome.changed is False
    assert _settings_rows(config_dir) == []
    assert not (config_dir / settings.APPROVALS_OVERLAY).exists()


def test_switching_four_eyes_off_in_profile_kritis_is_refused_and_audited(tmp_path):
    config_dir = _config(tmp_path, "kritis")

    with pytest.raises(settings.RefusedError, match="kritis"):
        _set(config_dir, "approvals.four_eyes", "off")

    assert not (config_dir / settings.APPROVALS_OVERLAY).exists()
    (row,) = _settings_rows(config_dir)
    assert row["event"] == "four_eyes_changed"
    assert row["result"] == "denied"
    assert row["error_code"] == "PK-INPUT-001"
    assert row["detail"] == {"four_eyes_old": "on", "four_eyes_new": "off"}
    assert settings.show(config_dir)["approvals"] == {"four_eyes": "on", "fixed": True}
    catalog.render(config_dir, REPO, now=NOW)
    assert _services(config_dir)["approvals"] == {"four_eyes": "on"}


def test_switching_four_eyes_on_in_profile_kritis_is_no_change(tmp_path):
    config_dir = _config(tmp_path, "kritis")
    assert _set(config_dir, "approvals.four_eyes", "on").changed is False
    assert _settings_rows(config_dir) == []


def test_the_kritis_catalog_states_four_eyes_on_whatever_the_overlay_says(tmp_path):
    config_dir = _config(tmp_path, "kritis")
    overlay = config_dir / settings.APPROVALS_OVERLAY
    overlay.parent.mkdir(parents=True)
    overlay.write_text('four_eyes: "off"\n')

    catalog.render(config_dir, REPO, now=NOW)

    doc = _services(config_dir)
    assert doc["security_profile"] == "kritis"
    assert doc["approvals"] == {"four_eyes": "on"}
    schema_check.validate(doc, _schema("platform-services.v1.schema.json"))


def test_a_stored_off_in_profile_kritis_is_cleared_by_setting_on(tmp_path):
    """The remedy doctor names: the stored off is rewritten, with its own audit row, and
    doctor passes again."""
    config_dir = _config(tmp_path)
    _set(config_dir, "approvals.four_eyes", "on")
    _set(config_dir, "approvals.four_eyes", "off")
    env = config_dir / ".env"
    env.write_text(env.read_text().replace(
        "PAPAIA_SECURITY_PROFILE=standard", "PAPAIA_SECURITY_PROFILE=kritis"))
    assert _check(config_dir, "approvals").status == doctor.FAIL

    outcome = _set(config_dir, "approvals.four_eyes", "on")

    assert outcome.changed is True
    assert (config_dir / settings.APPROVALS_OVERLAY).read_text() == 'four_eyes: "on"\n'
    last = _settings_rows(config_dir)[-1]
    assert (last["event"], last["result"]) == ("four_eyes_changed", "allowed")
    assert last["detail"] == {"four_eyes_old": "off", "four_eyes_new": "on"}
    assert _check(config_dir, "approvals").status == doctor.PASS
    assert _services(config_dir)["approvals"] == {"four_eyes": "on"}
    assert _set(config_dir, "approvals.four_eyes", "on").changed is False


UNKNOWN_PROFILES = ["Kritis", "KRITIS", "kritisch", "strict", "standard,kritis"]


def _with_profile(config_dir: Path, raw: str) -> Path:
    env = config_dir / ".env"
    env.write_text("".join(
        (f"PAPAIA_SECURITY_PROFILE={raw}" if line.startswith("PAPAIA_SECURITY_PROFILE=")
         else line) + "\n"
        for line in env.read_text().splitlines()
    ))
    return config_dir


@pytest.mark.parametrize("raw", UNKNOWN_PROFILES)
def test_an_unknown_security_profile_refuses_every_four_eyes_change(tmp_path, raw, capsys):
    config_dir = _config(tmp_path)
    catalog.render(config_dir, REPO, now=NOW)
    before = (config_dir / "platform" / "services.json").read_bytes()
    _with_profile(config_dir, raw)

    for value in ("off", "on"):
        with pytest.raises(settings.SettingsError, match="PAPAIA_SECURITY_PROFILE"):
            _set(config_dir, "approvals.four_eyes", value)
    assert _cli(config_dir, "settings-set", "--key", "approvals.four_eyes", "--value", "off") == 2
    assert "PAPAIA_SECURITY_PROFILE" in capsys.readouterr().err
    assert _cli(config_dir, "settings-show") == 3  # show: the settings cannot be read
    assert not (config_dir / settings.APPROVALS_OVERLAY).exists()
    assert _settings_rows(config_dir) == []
    with pytest.raises(catalog.CatalogError, match="PAPAIA_SECURITY_PROFILE"):
        catalog.render(config_dir, REPO, now=NOW)
    assert (config_dir / "platform" / "services.json").read_bytes() == before


@pytest.mark.parametrize("raw", UNKNOWN_PROFILES)
def test_doctor_fails_on_an_unknown_security_profile(tmp_path, raw):
    config_dir = _with_profile(_config(tmp_path), raw)
    result = _check(config_dir, "approvals")
    assert result.status == doctor.FAIL
    assert "PAPAIA_SECURITY_PROFILE" in result.summary


def test_an_empty_security_profile_is_standard(tmp_path):
    config_dir = _with_profile(_config(tmp_path), "")
    assert settings.show(config_dir)["security_profile"] == "standard"
    assert _set(config_dir, "approvals.four_eyes", "on").changed is True


@needs_kit
@pytest.mark.parametrize(("profile", "value", "expected"), [
    ("standard", None, "off"),
    ("standard", "on", "on"),
    ("kritis", None, "on"),
])
def test_the_kit_reader_sees_the_rule_the_core_publishes(tmp_path, profile, value, expected):
    from papaia_kit.catalog import four_eyes_setting, parse_services

    config_dir = _config(tmp_path, profile)
    if value is not None:
        _set(config_dir, "approvals.four_eyes", value)
    catalog.render(config_dir, REPO, now=NOW)

    data = (config_dir / "platform" / "services.json").read_bytes()
    assert four_eyes_setting(parse_services(data)) == expected


@pytest.mark.parametrize("value", ["ON", "Off", "true", "yes", "1", "", " on", "on\n", "of"])
def test_an_unknown_four_eyes_value_is_refused_before_anything_changes(tmp_path, value):
    config_dir = _config(tmp_path)
    with pytest.raises(settings.SettingsError, match="on or off"):
        _set(config_dir, "approvals.four_eyes", value)
    assert not (config_dir / settings.APPROVALS_OVERLAY).exists()
    assert _settings_rows(config_dir) == []


@pytest.mark.parametrize("text", [
    "four_eyes: on\n",            # YAML 1.1 reads an unquoted on as a boolean
    'four_eyes: "maybe"\n',
    'four_eyes: "on"\nsingle_admin_exception: true\n',
    "- on\n",
])
def test_a_malformed_approvals_overlay_stops_the_render(tmp_path, text):
    config_dir = _config(tmp_path)
    overlay = config_dir / settings.APPROVALS_OVERLAY
    overlay.parent.mkdir(parents=True)
    overlay.write_text(text)

    with pytest.raises(catalog.CatalogError, match="approvals.yaml"):
        catalog.render(config_dir, REPO, now=NOW)
    assert not (config_dir / "platform" / "services.json").exists()


# ─────────────────────────────────────────────────────────────────────────
# branding and contact point
# ─────────────────────────────────────────────────────────────────────────


def test_a_branding_change_is_visible_in_the_catalog_at_once(tmp_path):
    config_dir = _config(tmp_path)
    catalog.render(config_dir, REPO, now=NOW)
    assert _services(config_dir)["branding"] == {"name": "papAIa"}

    assert _set(config_dir, "branding.name", "Beispiel GmbH").catalog_written is True
    _set(config_dir, "branding.suffix", "Arbeitsplattform")
    _set(config_dir, "contact.name", "IT-Service")
    _set(config_dir, "contact.mail", "it-service@beispiel.example")
    _set(config_dir, "contact.phone", "+49 991 1234-0")

    assert _services(config_dir)["branding"] == {
        "name": "Beispiel GmbH",
        "suffix": "Arbeitsplattform",
        "contact": {
            "name": "IT-Service",
            "mail": "it-service@beispiel.example",
            "phone": "+49 991 1234-0",
        },
    }
    rows = _settings_rows(config_dir)
    assert [(r["event"], r["operation"], r["object_ref"]["id"]) for r in rows] == [
        ("config_changed", "settings.branding_write", "branding.name"),
        ("config_changed", "settings.branding_write", "branding.suffix"),
        ("config_changed", "settings.branding_write", "contact.name"),
        ("config_changed", "settings.branding_write", "contact.mail"),
        ("config_changed", "settings.branding_write", "contact.phone"),
    ]
    text = json.dumps(rows)
    for value in ("Beispiel GmbH", "it-service@beispiel.example", "1234"):
        assert value not in text  # the audit names the setting, never its value


def test_unsetting_falls_back_to_the_product_name_and_removes_the_contact(tmp_path):
    config_dir = _config(tmp_path)
    _set(config_dir, "branding.name", "Beispiel GmbH")
    _set(config_dir, "branding.suffix", "Arbeitsplattform")
    _set(config_dir, "contact.name", "IT-Service")
    _set(config_dir, "contact.mail", "it@beispiel.example")

    settings.unset(config_dir, REPO, "contact.mail")
    assert _services(config_dir)["branding"]["contact"] == {"name": "IT-Service"}
    settings.unset(config_dir, REPO, "contact")
    settings.unset(config_dir, REPO, "branding.suffix")
    settings.unset(config_dir, REPO, "branding.name")

    assert _services(config_dir)["branding"] == {"name": "papAIa"}
    assert settings.unset(config_dir, REPO, "branding.suffix").changed is False
    deletes = [r for r in _settings_rows(config_dir) if r["effect"] == "delete"]
    assert [r["object_ref"]["id"] for r in deletes] == [
        "contact.mail", "contact", "branding.suffix", "branding.name",
    ]


@pytest.mark.parametrize(("key", "value", "reason"), [
    ("branding.name", "", "1 to 60"),
    ("branding.name", "x" * 61, "1 to 60"),
    ("branding.name", "Zeile\nzwei", "control character"),
    ("branding.suffix", "x" * 61, "1 to 60"),
    ("contact.name", "x" * 121, "1 to 120"),
    ("contact.name", "IT\tService", "control character"),
    ("contact.mail", "kein-at-zeichen", "mail address"),
    ("contact.mail", "a@b", "mail address"),
    ("contact.mail", "a@b.example\n", "mail address"),
    ("contact.phone", "call me", "phone number"),
    ("contact.phone", "12", "phone number"),
    ("colour", "red", "unknown setting"),
    ("branding.logo_sha256", "00", "unknown setting"),
    ("approvals.single_admin_exception", "true", "unknown setting"),
])
def test_invalid_values_are_refused_before_anything_changes(tmp_path, key, value, reason):
    config_dir = _config(tmp_path)
    _set(config_dir, "contact.name", "IT-Service")
    before = sorted(p.name for p in (config_dir / "overlay" / "platform").iterdir())
    rows = len(_rows(config_dir))

    with pytest.raises(settings.SettingsError, match=reason):
        _set(config_dir, key, value)

    assert sorted(p.name for p in (config_dir / "overlay" / "platform").iterdir()) == before
    assert len(_rows(config_dir)) == rows
    assert _services(config_dir)["branding"]["contact"] == {"name": "IT-Service"}


def test_a_contact_mail_needs_a_contact_name_first(tmp_path):
    config_dir = _config(tmp_path)
    with pytest.raises(settings.SettingsError, match="contact.name"):
        _set(config_dir, "contact.mail", "it@beispiel.example")
    with pytest.raises(settings.SettingsError, match="contact.name"):
        settings.unset(config_dir, REPO, "contact.name")


def test_a_change_waits_for_the_settings_lock(tmp_path):
    """Read, change and write of the overlay run under one lock: a second writer (the
    manager and a shell at once) waits instead of losing the first change."""
    import fcntl
    import threading

    config_dir = _config(tmp_path)
    lock = config_dir / settings.LOCK_FILE
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    worker = threading.Thread(target=_set, args=(config_dir, "branding.name", "Haus"))
    try:
        worker.start()
        worker.join(timeout=1.0)
        assert worker.is_alive()
        assert not (config_dir / catalog.BRANDING_OVERLAY).exists()
    finally:
        os.close(fd)
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert settings.show(config_dir)["branding"]["name"] == "Haus"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_the_overlay_files_are_written_atomically_and_readable(tmp_path):
    config_dir = _config(tmp_path)
    _set(config_dir, "branding.name", "Beispiel GmbH")
    _set(config_dir, "approvals.four_eyes", "on")
    for rel in (catalog.BRANDING_OVERLAY, settings.APPROVALS_OVERLAY):
        path = config_dir / rel
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o644, rel
    assert (config_dir / settings.APPROVALS_OVERLAY).read_text() == 'four_eyes: "on"\n'
    leftovers = [p.name for p in (config_dir / "overlay" / "platform").iterdir()
                 if p.name.endswith(".tmp")]
    assert leftovers == []


# ─────────────────────────────────────────────────────────────────────────
# logo
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("image", [PNG, JPEG, WEBP])
def test_a_logo_is_copied_next_to_the_catalog_with_its_digest(tmp_path, image):
    config_dir = _config(tmp_path)
    source = tmp_path / "logo.bin"
    source.write_bytes(image)

    _set(config_dir, "branding.logo", str(source))

    assert (config_dir / catalog.LOGO_OVERLAY).read_bytes() == image
    assert (config_dir / "platform" / catalog.LOGO_FILE).read_bytes() == image
    digest = hashlib.sha256(image).hexdigest()
    assert _services(config_dir)["branding"]["logo_sha256"] == digest
    assert settings.show(config_dir)["branding"]["logo_sha256"] == digest
    (row,) = [r for r in _settings_rows(config_dir) if r["object_ref"]["id"] == "branding.logo"]
    assert row["operation"] == "settings.branding_write" and row["result"] == "allowed"

    settings.unset(config_dir, REPO, "branding.logo")
    assert not (config_dir / catalog.LOGO_OVERLAY).exists()
    assert not (config_dir / "platform" / catalog.LOGO_FILE).exists()
    assert "logo_sha256" not in _services(config_dir)["branding"]


@pytest.mark.parametrize(("content", "reason"), [
    (SVG, "PNG, JPEG or WebP"),
    (b"GIF89a", "PNG, JPEG or WebP"),
    (b"", "empty"),
    (PNG + b"\x00" * (1024 * 1024), "larger than"),
])
def test_a_logo_that_is_no_small_raster_image_is_refused(tmp_path, content, reason):
    config_dir = _config(tmp_path)
    source = tmp_path / "logo.bin"
    source.write_bytes(content)
    with pytest.raises(settings.SettingsError, match=reason):
        _set(config_dir, "branding.logo", str(source))
    assert not (config_dir / catalog.LOGO_OVERLAY).exists()


def test_a_missing_logo_file_or_a_directory_is_refused(tmp_path):
    config_dir = _config(tmp_path)
    with pytest.raises(settings.SettingsError, match="not a readable file"):
        _set(config_dir, "branding.logo", str(tmp_path / "missing.png"))
    with pytest.raises(settings.SettingsError, match="not a readable file"):
        _set(config_dir, "branding.logo", str(tmp_path))


def test_the_render_refuses_a_hand_placed_svg_logo(tmp_path):
    config_dir = _config(tmp_path)
    overlay = config_dir / catalog.LOGO_OVERLAY
    overlay.parent.mkdir(parents=True)
    overlay.write_bytes(SVG)
    with pytest.raises(catalog.CatalogError, match="PNG, JPEG or WebP"):
        catalog.render(config_dir, REPO, now=NOW)


# ─────────────────────────────────────────────────────────────────────────
# command line
# ─────────────────────────────────────────────────────────────────────────


def _cli(config_dir: Path, *args: str) -> int:
    return cli.main(["--config-dir", str(config_dir), "--repo-root", str(REPO), *args])


def test_the_settings_commands_set_show_and_unset(tmp_path, capsys):
    config_dir = _config(tmp_path)

    assert _cli(config_dir, "settings-set", "--key", "approvals.four_eyes", "--value", "on") == 0
    assert "approvals.four_eyes set to on" in capsys.readouterr().out
    assert _cli(config_dir, "settings-set", "--key", "approvals.four_eyes", "--value", "on") == 0
    assert "unchanged" in capsys.readouterr().out
    assert _cli(config_dir, "settings-set", "--key", "contact.name", "--value", "IT-Service") == 0
    capsys.readouterr()
    assert _cli(config_dir, "settings-show", "--json") == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["approvals"] == {"four_eyes": "on", "fixed": False}
    assert shown["contact"] == {"name": "IT-Service"}
    assert _cli(config_dir, "settings-unset", "--key", "contact") == 0
    capsys.readouterr()
    assert _cli(config_dir, "settings-show") == 0
    out = capsys.readouterr().out
    assert "approvals.four_eyes  on" in out and "contact              not set" in out


def test_the_settings_commands_exit_1_on_a_refusal_and_2_on_bad_input(tmp_path, capsys):
    kritis = _config(tmp_path, "kritis")
    assert _cli(kritis, "settings-set", "--key", "approvals.four_eyes", "--value", "off") == 1
    assert "kritis" in capsys.readouterr().err
    assert _cli(kritis, "settings-set", "--key", "approvals.four_eyes", "--value", "maybe") == 2
    assert _cli(kritis, "settings-unset", "--key", "approvals.four_eyes") == 2
    assert "cannot be unset" in capsys.readouterr().err


def test_a_setting_is_stored_even_when_the_installation_has_no_catalog_yet(tmp_path, capsys):
    config_dir = _config(tmp_path)
    env = config_dir / ".env"
    env.write_text("".join(
        line + "\n" for line in env.read_text().splitlines() if "OIDC_ISSUER" not in line
    ))
    assert _cli(config_dir, "settings-set", "--key", "branding.name", "--value", "X") == 0
    assert "no platform catalog yet" in capsys.readouterr().out
    assert settings.show(config_dir)["branding"]["name"] == "X"


@needs_bash
def test_papaia_ctl_dispatches_the_settings_commands(tmp_path):
    config_dir = _config(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"

    def ctl(*args: str) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        return subprocess.run(
            [BASH, str(CTL), "settings", *args, f"--config-dir={config_dir}"],
            capture_output=True, text=True, timeout=60, check=False, env=env,
        )

    done = ctl("set", "approvals.four_eyes", "on")
    assert done.returncode == 0, done.stderr
    assert _services(config_dir)["approvals"] == {"four_eyes": "on"}
    shown = ctl("show", "--json")
    assert json.loads(shown.stdout)["approvals"]["four_eyes"] == "on"
    assert ctl("set", "approvals.four_eyes").returncode == 2
    assert ctl("frobnicate").returncode == 2
    help_text = subprocess.run([BASH, str(CTL), "help"], capture_output=True, text=True,
                               timeout=60, check=False, env=env).stdout
    assert "papaia-ctl settings set  <key> <value>" in help_text
    assert "papaia-ctl help" in help_text


# ─────────────────────────────────────────────────────────────────────────
# doctor approvals and contact_point
# ─────────────────────────────────────────────────────────────────────────


def _check(config_dir: Path, name: str) -> doctor.CheckResult:
    report = doctor.run_checks(
        config_dir, REPO, skip=[n for n in doctor.CHECK_NAMES if n != name], now=NOW
    )
    (result,) = [c for c in report.checks if c.name == name]
    return result


def test_doctor_reports_the_four_eyes_value(tmp_path):
    config_dir = _config(tmp_path)
    (config_dir / "deployment.yaml").write_text("addons: []\n")
    result = _check(config_dir, "approvals")
    assert result.status == doctor.PASS
    assert result.details == {"four_eyes": "off", "security_profile": "standard",
                              "stored": None}
    _set(config_dir, "approvals.four_eyes", "on")
    assert _check(config_dir, "approvals").details["four_eyes"] == "on"


def test_doctor_fails_on_four_eyes_off_in_profile_kritis(tmp_path):
    config_dir = _config(tmp_path, "kritis")
    assert _check(config_dir, "approvals").status == doctor.PASS
    overlay = config_dir / settings.APPROVALS_OVERLAY
    overlay.parent.mkdir(parents=True)
    overlay.write_text('four_eyes: "off"\n')

    result = _check(config_dir, "approvals")
    assert result.status == doctor.FAIL
    assert "kritis" in result.summary
    assert result.details == {"four_eyes": "on", "security_profile": "kritis", "stored": "off"}


def test_doctor_fails_on_a_malformed_approvals_overlay(tmp_path):
    config_dir = _config(tmp_path)
    overlay = config_dir / settings.APPROVALS_OVERLAY
    overlay.parent.mkdir(parents=True)
    overlay.write_text("four_eyes: on\n")
    assert _check(config_dir, "approvals").status == doctor.FAIL


def test_doctor_warns_while_no_contact_point_is_set(tmp_path):
    config_dir = _config(tmp_path)
    result = _check(config_dir, "contact_point")
    assert result.status == doctor.WARN
    assert "contact.name" in result.summary
    _set(config_dir, "contact.name", "IT-Service")
    _set(config_dir, "contact.mail", "it@beispiel.example")
    result = _check(config_dir, "contact_point")
    assert result.status == doctor.PASS
    assert result.details == {"contact": {"name": "IT-Service", "mail": "it@beispiel.example"}}


def test_doctor_skips_both_checks_before_setup(tmp_path):
    config_dir = tmp_path / "fresh"
    config_dir.mkdir()
    assert _check(config_dir, "approvals").status == doctor.SKIP
    assert _check(config_dir, "contact_point").status == doctor.SKIP
