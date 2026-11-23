"""Log rotation for every service (BE-27, EXK-PLT-68-A1).

Every service of the core fragments rotates its log (json-file, 5 x 10 MiB), every
service of an active add-on gets the same through a generated override, and the README
states the bound that follows from it.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from lib import compat, gen_override

REPO = Path(__file__).resolve().parents[2]
ROTATION = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "5"}}


def core_services() -> list[tuple[str, str]]:
    out = []
    for path in compat.compose_files(REPO / "src" / "docker-compose.yml"):
        document = yaml.safe_load(path.read_text("utf-8")) or {}
        for name, body in (document.get("services") or {}).items():
            out.append((path.relative_to(REPO).as_posix(), name, body))
    return out


def test_every_core_service_rotates_its_log():
    services = core_services()
    assert services
    wrong = [f"{path}: {name}" for path, name, body in services if body.get("logging") != ROTATION]
    assert wrong == []


def test_the_readme_states_the_bound_for_the_core():
    count = len(core_services())
    readme = (REPO / "README.md").read_text("utf-8")
    section = readme.split("### Logs and log rotation", 1)[1].split("\n### ", 1)[0]
    section = " ".join(section.split())
    assert "5 files of 10 MiB" in section
    assert f"{count} core services" in section
    total_mib = count * 50
    assert f"{total_mib} MiB" in section


def test_an_active_addon_gets_the_rotation_for_every_service(stack):
    gen_override.generate_addon_logging_overrides(stack["config"], stack["repo"])

    out = stack["config"] / "overrides" / "addons" / "docker-compose.paperless-logging.override.yml"
    assert yaml.safe_load(out.read_text("utf-8")) == {
        "services": {"paperless": {"logging": ROTATION}, "paperless-db": {"logging": ROTATION}}
    }
    assert not (
        stack["config"] / "overrides" / "addons" / "docker-compose.dormant-logging.override.yml"
    ).exists()


def test_the_override_goes_when_the_addon_is_deactivated(stack):
    gen_override.generate_addon_logging_overrides(stack["config"], stack["repo"])
    deployment = stack["config"] / "deployment.yaml"
    text = deployment.read_text("utf-8")
    deployment.write_text(re.sub(r"active: true", "active: false", text), encoding="utf-8")

    gen_override.generate_addon_logging_overrides(stack["config"], stack["repo"])

    assert not list((stack["config"] / "overrides" / "addons").glob("*-logging.override.yml"))


def test_the_override_is_written_with_the_other_addon_overrides(stack):
    gen_override.generate_addon_join_overrides(stack["config"], stack["repo"])

    assert (
        stack["config"] / "overrides" / "addons" / "docker-compose.paperless-logging.override.yml"
    ).is_file()
