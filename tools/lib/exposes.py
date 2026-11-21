"""The manifest section `exposes:` (contract generation 7, kit schema `exposes.v1`).

An add-on declares each surface it offers in `exposes:` of its papaia-app.yaml; a core
profile declares the same list in `exposes.yaml` next to its compose file. Every
section is checked against the kit schema vendored under tools/schemas/kit before the
core uses it: when an add-on is checked, installed, started or upgraded, and on every
catalog render. A section that does not pass is refused with the field and the reason.

Besides the schema, the checks the schema cannot express on one section: every `id`
is unique within the section (the catalog render checks uniqueness across the
installation), and `resource.id_field` names a property of the operation's
`input_schema`.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from . import schema_check

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "kit"
EXPOSES_SCHEMA = "exposes.v1.schema.json"
SERVICES_SCHEMA = "platform-services.v1.schema.json"
GROUPS_SCHEMA = "platform-groups.v1.schema.json"


class ExposesError(ValueError):
    """A section that is refused; the message names the owner, the field and the reason."""


@cache
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def check(section: object, where: str) -> None:
    """Refuse an `exposes:` section of `where` (add-on name or `core:<profile>`) that does
    not satisfy the kit schema and the checks beyond it. Raises ExposesError."""
    try:
        schema_check.validate(section, load_schema(EXPOSES_SCHEMA))
    except schema_check.SchemaError as exc:
        raise ExposesError(f"{where}: exposes{exc.path}: {exc.reason}") from None
    assert isinstance(section, list)  # the schema says so
    seen: set[str] = set()
    for index, entry in enumerate(section):
        if entry["id"] in seen:
            raise ExposesError(
                f"{where}: exposes/{index}/id: '{entry['id']}' is declared twice"
            )
        seen.add(entry["id"])
        for number, operation in enumerate(entry.get("operations") or ()):
            field = (operation.get("resource") or {}).get("id_field")
            properties = operation["input_schema"].get("properties")
            if field is not None and isinstance(properties, dict) and field not in properties:
                raise ExposesError(
                    f"{where}: exposes/{index}/operations/{number}/resource/id_field: "
                    f"'{field}' names no property of input_schema"
                )


def operation_names(section: list) -> set[str]:
    """The operation names a checked section declares, over all of its entries."""
    return {
        operation["name"]
        for entry in section
        for operation in entry.get("operations") or ()
    }


def check_key_tools(knowledge: object, section: list, where: str) -> None:
    """Refuse `key_tools` of a `knowledge:` declaration (contract generation 6) that are no
    operation of the module's own `exposes:` section, which must have passed `check`.

    Since generation 7 the operation names of `exposes` are the one description of the
    tools; a knowledge source repeats them for the model's next step and may not invent
    others (V-10 step 3). Only the shape this check reads is checked here; the rest of
    the declaration is the knowledge map's to check. Raises ExposesError."""
    if knowledge is None:
        return
    sources = knowledge.get("sources") if isinstance(knowledge, dict) else None
    if sources is None:
        return
    if not isinstance(sources, list):
        raise ExposesError(f"{where}: knowledge/sources: must be a list")
    names = operation_names(section)
    for number, source in enumerate(sources):
        access = source.get("access") if isinstance(source, dict) else None
        if not isinstance(access, list):
            continue
        for index, path in enumerate(access):
            tools = path.get("key_tools") if isinstance(path, dict) else None
            if tools is None:
                continue
            pointer = f"{where}: knowledge/sources/{number}/access/{index}/key_tools"
            if not isinstance(tools, list):
                raise ExposesError(f"{pointer}: must be a list of operation names")
            for position, tool in enumerate(tools):
                if not isinstance(tool, str) or tool not in names:
                    raise ExposesError(
                        f"{pointer}/{position}: {str(tool)[:80]!r} is no operation "
                        "of the module's exposes"
                    )
