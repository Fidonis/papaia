"""The security profile has exactly one definition (PLT-23-A1, ADR 0022).

`PAPAIA_SECURITY_PROFILE` is named, validated and given its meaning in
tools/lib/security_profile.py alone; every other part of the core asks that module, and
the table in docs/configuration.md says the same as the module's table.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lib import realm_hardening, security_profile

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "tools" / "lib"


def test_the_two_values_and_nothing_else():
    assert set(security_profile.PROFILES) == {"standard", "kritis"}
    assert security_profile.load({}).name == "standard"
    assert security_profile.load({"PAPAIA_SECURITY_PROFILE": "kritis"}).name == "kritis"
    with pytest.raises(security_profile.ProfileError, match="standard or kritis"):
        security_profile.load({"PAPAIA_SECURITY_PROFILE": "strict"})


def test_only_one_module_of_the_core_names_the_variable():
    naming = sorted(
        path.relative_to(LIB).as_posix()
        for path in LIB.rglob("*")
        if path.is_file()
        and path.suffix in (".py", ".sh")
        and "PAPAIA_SECURITY_PROFILE" in path.read_text(encoding="utf-8")
    )
    assert naming == ["security_profile.py"]


def test_kritis_requires_add_on_certificates_and_standard_does_not():
    kritis, standard = security_profile.PROFILES["kritis"], security_profile.PROFILES["standard"]

    assert kritis.addon_pki_required and kritis.ssl_required == "all"
    assert not standard.addon_pki_required and standard.ssl_required == "external"
    # No field promises TLS on links that the core does not encrypt (docs/pki.md).
    assert not any("tls" in field for field in security_profile.Profile.__dataclass_fields__)


def _tls_row() -> tuple[str, str, str]:
    rows = [row for row in security_profile.TABLE if row[0] == "TLS between containers"]
    assert len(rows) == 1
    return rows[0]


def test_the_table_promises_tls_only_where_the_core_provides_it():
    _, standard, kritis = _tls_row()
    assert "reverse proxy" in standard and "audit ingest" in standard
    assert "do not use TLS yet" in kritis
    # A core service named in the row must have its certificates mounted.
    for request in (REPO / "src" / "infra").glob("*/pki.yaml"):
        compose = (request.parent / "docker-compose.yml").read_text(encoding="utf-8")
        for name in re.findall(r"name:\s*([a-z0-9-]+)", request.read_text(encoding="utf-8")):
            if name in standard or name in kritis:
                assert "${PAPAIA_PKI_DIR}" in compose, f"{name} is named but has no certificates"


def test_realm_hardening_takes_its_values_from_the_profile():
    for name, profile in security_profile.PROFILES.items():
        settings = realm_hardening.load({security_profile.KEY: name}).settings
        assert settings.realm()["sslRequired"] == profile.ssl_required
        assert (settings.idle_days, settings.max_days) == (
            profile.offline_idle_days,
            profile.offline_max_days,
        )


def _documented_table() -> list[tuple[str, str, str]]:
    text = (REPO / "docs" / "configuration.md").read_text(encoding="utf-8")
    section = text.split("### What each security profile means", 1)
    assert len(section) == 2, "docs/configuration.md has no table of the security profiles"
    rows = []
    for line in section[1].split("\n#", 1)[0].splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and not re.fullmatch(r"-+", cells[0]) and cells[0] != "Setting":
            rows.append(tuple(cells))
    return rows


def test_the_documented_table_is_the_table_of_the_module():
    assert _documented_table() == list(security_profile.TABLE)
