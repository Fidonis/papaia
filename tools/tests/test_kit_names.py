"""Exchange scopes come from the platform kit.

papaia-ctl runs on Python 3.10 and cannot import the kit (Python 3.12). The naming
register snapshot `lib/names_register.json` therefore carries the exchange scope of
every registered audience as the vendored kit's `exchange_scope()` builds it, and
`lib/kit_names.py` reads them from there. The tests that need the kit (CI runs 3.12)
check the snapshot against the vendored kit, so the two cannot drift apart.
"""

from __future__ import annotations

import json
import sys

import pytest

from lib import kit_names
from lib import realm_sync as rs

needs_kit = pytest.mark.skipif(sys.version_info < (3, 12), reason="papaia-kit needs Python 3.12")

SNAPSHOT = json.loads(rs.REGISTER_PATH.read_text(encoding="utf-8"))
AUDIENCES = sorted(e["name"] for e in SNAPSHOT["entries"] if e["kind"] == "audience")
# Names a realm may hold that are no exchange scope of any audience, and some that are.
SAMPLES = [
    "aud-flow",
    "aud-flow-engine",
    "aud-hand-made",
    "aud-",
    "aud",
    "audit",
    "audience-flow",
    "AUD-flow",
    "offline_access",
    "papaia-person",
    "basic",
    "",
]


@needs_kit
def test_the_snapshot_holds_the_exchange_scope_the_vendored_kit_builds_for_every_audience():
    from papaia_kit import __version__, names

    table = SNAPSHOT["exchange_scopes"]
    assert table["kit"] == __version__
    built = {a: names.exchange_scope(a) for a in AUDIENCES}
    assert {row["audience"]: row["scope"] for row in table["scopes"]} == built, (
        "regenerate exchange_scopes of lib/names_register.json from the vendored kit:\n"
        + json.dumps([{"audience": a, "scope": s} for a, s in built.items()], indent=1)
    )


@needs_kit
def test_the_exchange_form_is_the_vendored_kit_s():
    from papaia_kit import names

    for name in SAMPLES + [kit_names.exchange_scope(a) for a in AUDIENCES]:
        assert kit_names.has_exchange_prefix(name) is names.has_exchange_prefix(name), name


@needs_kit
def test_the_audience_of_a_scope_is_the_one_the_kit_built_it_from():
    from papaia_kit import names

    for audience in AUDIENCES:
        assert kit_names.exchange_audience(names.exchange_scope(audience)) == audience


def test_every_registered_audience_has_its_exchange_scope_in_the_register():
    scopes = {e["name"] for e in SNAPSHOT["entries"] if e["kind"] == "scope"}
    for audience in AUDIENCES:
        assert kit_names.exchange_scope(audience) in scopes


def test_the_realm_sync_builds_scopes_only_through_the_kit_binding():
    assert rs.exchange_scope is kit_names.exchange_scope


@pytest.mark.parametrize(
    "audience",
    ["flow-engine", "assist-gate", "unknown", "", "flow ", "FLOW", "aud-flow"],
)
def test_a_name_that_is_no_registered_audience_has_no_exchange_scope(audience):
    with pytest.raises(kit_names.UnknownAudience, match="not a registered audience"):
        kit_names.exchange_scope(audience)


@pytest.mark.parametrize("value", [None, 3, b"flow", ["flow"]])
def test_an_audience_that_is_not_a_string_is_refused(value):
    with pytest.raises(TypeError):
        kit_names.exchange_scope(value)
    with pytest.raises(TypeError):
        kit_names.has_exchange_prefix(value)


def test_the_audience_of_a_name_without_the_exchange_form_is_none():
    assert kit_names.exchange_audience("offline_access") is None
    assert kit_names.exchange_audience("aud-flow-engine") == "flow-engine"


@pytest.mark.parametrize(
    "table, message",
    [
        ({}, "exchange_scopes"),
        ({"kit": "0.1.0", "prefix": "aud-", "scopes": [], "extra": 1}, "unknown"),
        ({"kit": "0.1.0", "prefix": "", "scopes": []}, "prefix"),
        (
            {"kit": "0.1.0", "prefix": "aud-", "scopes": [{"audience": "flow", "scope": "x"}]},
            "does not have the exchange form",
        ),
        (
            {
                "kit": "0.1.0",
                "prefix": "aud-",
                "scopes": [{"audience": "flow", "scope": "aud-flow", "owner": "x"}],
            },
            "unknown",
        ),
        (
            {
                "kit": "0.1.0",
                "prefix": "aud-",
                "scopes": [
                    {"audience": "flow", "scope": "aud-flow"},
                    {"audience": "flow", "scope": "aud-flow"},
                ],
            },
            "twice",
        ),
    ],
)
def test_a_damaged_scope_table_is_refused(table, message):
    document = dict(SNAPSHOT)
    document.pop("exchange_scopes")
    if table:
        document["exchange_scopes"] = table
    with pytest.raises(ValueError, match=message):
        kit_names.ExchangeScopes.from_snapshot(document)
