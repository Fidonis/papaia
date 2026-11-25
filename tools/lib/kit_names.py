"""Exchange scopes as the platform kit builds them.

The kit's `papaia_kit.names.exchange_scope()` is the only builder of exchange scopes
(`aud-<audience>`, PLT-12). The naming register snapshot (`names_register.json`,
section `exchange_scopes`) carries the scope of every registered audience exactly as
the vendored kit builds it, and the form the kit's `has_exchange_prefix()` recognises.
The CI checks the section against the vendored kit (tests/test_kit_names.py).

This module never assembles a scope name: `exchange_scope()` looks it up, and a name
that is not a registered audience has none.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SNAPSHOT_PATH = Path(__file__).with_name("names_register.json")
SECTION = "exchange_scopes"
_SECTION_KEYS = frozenset({"kit", "prefix", "scopes"})
_ROW_KEYS = frozenset({"audience", "scope"})
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_PREFIX = re.compile(r"[a-z]+-")
MAX_NAME_LENGTH = 64


class UnknownAudience(ValueError):
    """The name is not a registered audience, so it has no exchange scope."""


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= MAX_NAME_LENGTH:
        raise ValueError(f"{SECTION}: {label} must be a name of 1 to {MAX_NAME_LENGTH} characters")
    return value


@dataclass(frozen=True)
class ExchangeScopes:
    """The exchange scopes of the registered audiences, from the kit."""

    kit: str
    prefix: str
    by_audience: dict[str, str]

    @classmethod
    def from_snapshot(cls, document: dict) -> ExchangeScopes:
        table = document.get(SECTION)
        if not isinstance(table, dict):
            raise ValueError(f"naming register: no {SECTION} section")
        if unknown := sorted(set(table) - _SECTION_KEYS):
            raise ValueError(f"{SECTION}: unknown field(s) {', '.join(unknown)}")
        kit, prefix, rows = table.get("kit"), table.get("prefix"), table.get("scopes")
        if not isinstance(kit, str) or not _VERSION.fullmatch(kit):
            raise ValueError(f"{SECTION}: kit must be the version of the kit that built it")
        if not isinstance(prefix, str) or not _PREFIX.fullmatch(prefix):
            raise ValueError(f"{SECTION}: prefix must be lower-case letters and '-'")
        if not isinstance(rows, list):
            raise ValueError(f"{SECTION}: scopes must be a list")
        by_audience: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or set(row) != _ROW_KEYS:
                fields = sorted(set(row) - _ROW_KEYS) if isinstance(row, dict) else []
                raise ValueError(
                    f"{SECTION}: each row has exactly audience and scope"
                    + (f" (unknown {', '.join(fields)})" if fields else "")
                )
            audience = _name(row["audience"], "audience")
            scope = _name(row["scope"], "scope")
            if not (scope.startswith(prefix) and scope[len(prefix) :] == audience):
                raise ValueError(
                    f"{SECTION}: {scope!r} does not have the exchange form of {audience!r}"
                )
            if audience in by_audience:
                raise ValueError(f"{SECTION}: {audience!r} is listed twice")
            by_audience[audience] = scope
        return cls(kit, prefix, by_audience)

    def scope(self, audience: object) -> str:
        if not isinstance(audience, str):
            raise TypeError(
                "exchange_scope takes exactly one audience as a string, "
                f"not {type(audience).__name__}"
            )
        try:
            return self.by_audience[audience]
        except KeyError:
            raise UnknownAudience(
                f"{audience!r} is not a registered audience and has no exchange scope"
            ) from None

    def has_prefix(self, name: object) -> bool:
        if not isinstance(name, str):
            raise TypeError(f"name must be a string, not {type(name).__name__}")
        return name.startswith(self.prefix)

    def audience(self, name: str) -> str | None:
        """The audience part of a name of the exchange form, registered or not."""
        return name[len(self.prefix) :] if self.has_prefix(name) else None


def load(path: Path = SNAPSHOT_PATH) -> ExchangeScopes:
    return ExchangeScopes.from_snapshot(json.loads(path.read_text(encoding="utf-8")))


_SCOPES = load()


def exchange_scope(audience: str) -> str:
    """The client scope that requests exactly this one registered audience (kit-built)."""
    return _SCOPES.scope(audience)


def has_exchange_prefix(name: str) -> bool:
    """Whether `name` has the form of an exchange scope, as the kit's function of that name
    reads it: the form only, so stale or hand-made exchange scopes are found too."""
    return _SCOPES.has_prefix(name)


def exchange_audience(name: str) -> str | None:
    """The audience an exchange scope names, or None for a name without that form."""
    return _SCOPES.audience(name)
