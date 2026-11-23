from __future__ import annotations

from pathlib import Path

import pytest

from lib import compat

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REPO_NEXT = FIXTURES_DIR / "repo-next"


def _core(
    platform_version: str | None = "0.8.0",
    addon_api: tuple[int, int] | None = (1, 1),
    services: dict[str, list[str]] | None = None,
) -> compat.CoreTarget:
    return compat.CoreTarget(
        platform_version=platform_version, addon_api=addon_api, services=services
    )


# ── addon_api window check ────────────────────────────────────────────────────


def test_addon_api_within_window_is_ok():
    result = compat.evaluate_addon("a", {"requires": {"addon_api": 1}}, _core())
    assert result.status == compat.STATUS_OK
    assert result.axis == "addon_api"
    assert result.requirement == [1]
    assert result.core_value == [1, 1]


def test_addon_api_below_window_is_incompatible():
    result = compat.evaluate_addon("a", {"requires": {"addon_api": 1}}, _core(addon_api=(2, 2)))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "min 2" in result.reason


def test_addon_api_above_window_is_incompatible():
    result = compat.evaluate_addon("a", {"requires": {"addon_api": 3}}, _core(addon_api=(1, 2)))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "[1..2]" in result.reason


def test_addon_api_list_intersects_window():
    # An addon serving generations 1 and 2 runs on a core that only serves 2.
    result = compat.evaluate_addon(
        "a", {"requires": {"addon_api": [1, 2]}}, _core(addon_api=(2, 2))
    )
    assert result.status == compat.STATUS_OK


def test_addon_api_takes_precedence_over_papaia_compat():
    # papaia_compat would fail here, but the addon_api axis is authoritative.
    manifest = {"requires": {"addon_api": 1}, "papaia_compat": ">=99.0.0"}
    result = compat.evaluate_addon("a", manifest, _core())
    assert result.status == compat.STATUS_OK
    assert result.axis == "addon_api"


# ── papaia_compat fallback ────────────────────────────────────────────────────


def test_papaia_compat_fallback_when_addon_api_absent():
    result = compat.evaluate_addon("a", {"papaia_compat": ">=0.8.0"}, _core(addon_api=None))
    assert result.status == compat.STATUS_OK
    assert result.axis == "papaia_compat"


def test_papaia_compat_fallback_when_core_has_no_window():
    # Addon declares both; a core without ADDON_API falls back to the range.
    manifest = {"requires": {"addon_api": 1}, "papaia_compat": ">=0.8.0"}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=None))
    assert result.axis == "papaia_compat"
    assert result.status == compat.STATUS_OK


def test_papaia_compat_violation_is_incompatible():
    result = compat.evaluate_addon("a", {"papaia_compat": ">=99.0.0"}, _core(addon_api=None))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "0.8.0" in result.reason


# ── UNKNOWN and ERROR ─────────────────────────────────────────────────────────


def test_no_requirement_is_unknown_and_passes_gate():
    result = compat.evaluate_addon("a", {"name": "a"}, _core())
    assert result.status == compat.STATUS_UNKNOWN
    assert compat.gate([result], mode=compat.MODE_ENFORCE) == 0


def test_unevaluable_axes_are_unknown():
    # Manual --target-addon-api: platform version unknown, addon only has a range.
    result = compat.evaluate_addon(
        "a", {"papaia_compat": ">=0.8.0"}, _core(platform_version=None, addon_api=(2, 2))
    )
    assert result.status == compat.STATUS_UNKNOWN


@pytest.mark.parametrize(
    "manifest",
    [
        "not-a-mapping",
        {"requires": "not-a-mapping"},
        {"requires": {"addon_api": "one"}},
        {"requires": {"addon_api": True}},
        {"requires": {"addon_api": []}},
        {"papaia_compat": ">=not.a.version"},
        {"papaia_compat": 1},
        {"networks": {"attach": "librechat"}},
    ],
)
def test_malformed_manifest_is_error_and_fatal_even_with_force(manifest):
    result = compat.evaluate_addon("a", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert compat.gate([result], mode=compat.MODE_WARN, force=True) == 2


# ── gate policy ───────────────────────────────────────────────────────────────


def _incompatible() -> compat.CompatResult:
    return compat.CompatResult("a", compat.STATUS_INCOMPATIBLE)


def test_gate_enforce_fails_on_incompatible():
    assert compat.gate([_incompatible()], mode=compat.MODE_ENFORCE) == 2


def test_gate_warn_mode_degrades_incompatible():
    assert compat.gate([_incompatible()], mode=compat.MODE_WARN) == 0


def test_gate_force_degrades_incompatible():
    assert compat.gate([_incompatible()], mode=compat.MODE_ENFORCE, force=True) == 0


def test_gate_ok_and_unknown_pass():
    results = [
        compat.CompatResult("a", compat.STATUS_OK),
        compat.CompatResult("b", compat.STATUS_UNKNOWN),
    ]
    assert compat.gate(results, mode=compat.MODE_ENFORCE) == 0


# ── mode resolution ───────────────────────────────────────────────────────────


def test_resolve_mode_default_is_enforce(monkeypatch):
    monkeypatch.delenv("PAPAIA_COMPAT_MODE", raising=False)
    assert compat.resolve_mode({}) == compat.MODE_ENFORCE
    assert compat.resolve_mode(None) == compat.MODE_ENFORCE


def test_resolve_mode_reads_deployment(monkeypatch):
    monkeypatch.delenv("PAPAIA_COMPAT_MODE", raising=False)
    assert compat.resolve_mode({"mode": "warn"}) == compat.MODE_WARN
    assert compat.resolve_mode({"mode": "dev"}) == compat.MODE_WARN
    assert compat.resolve_mode({"mode": "production"}) == compat.MODE_ENFORCE


def test_resolve_mode_env_wins(monkeypatch):
    monkeypatch.setenv("PAPAIA_COMPAT_MODE", "warn")
    assert compat.resolve_mode({"mode": "production"}) == compat.MODE_WARN


def test_resolve_mode_ignores_unknown_values(monkeypatch):
    monkeypatch.setenv("PAPAIA_COMPAT_MODE", "nonsense")
    assert compat.resolve_mode({"mode": "also-nonsense"}) == compat.MODE_ENFORCE


# ── ADDON_API window resolution ───────────────────────────────────────────────


def test_resolve_addon_api_window_missing_file_is_none(tmp_path):
    assert compat.resolve_addon_api_window(tmp_path) is None


def test_resolve_addon_api_window_reads_fixture(repo_root):
    assert compat.resolve_addon_api_window(repo_root) == (1, 1)


def test_resolve_addon_api_window_tolerates_comments(tmp_path):
    (tmp_path / "ADDON_API").write_text(
        "# comment\ncurrent=3   # inline\nmin=2\n", encoding="utf-8"
    )
    assert compat.resolve_addon_api_window(tmp_path) == (2, 3)


def test_resolve_addon_api_window_min_defaults_to_current(tmp_path):
    (tmp_path / "ADDON_API").write_text("current=2\n", encoding="utf-8")
    assert compat.resolve_addon_api_window(tmp_path) == (2, 2)


@pytest.mark.parametrize("content", ["", "min=1\n", "current=abc\n", "current=1\nmin=2\n"])
def test_resolve_addon_api_window_malformed_raises(tmp_path, content):
    (tmp_path / "ADDON_API").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        compat.resolve_addon_api_window(tmp_path)


# ── core services (compose include-walk) ─────────────────────────────────────


def test_resolve_core_services_walks_includes(repo_root):
    services = compat.resolve_core_services(repo_root)
    assert services == {
        "nginx-proxy-manager": ["nginx"],
        "librechat": ["librechat"],
    }


def test_resolve_core_services_missing_compose_is_none(tmp_path):
    assert compat.resolve_core_services(tmp_path) is None


def test_resolve_core_services_tolerates_dangling_include(repo_root):
    (repo_root / "src" / "infra" / "nginx" / "docker-compose.yml").unlink()
    services = compat.resolve_core_services(repo_root)
    assert services == {"librechat": ["librechat"]}


# ── attach validation ─────────────────────────────────────────────────────────


def _fixture_services() -> dict[str, list[str]]:
    return {"nginx-proxy-manager": ["nginx"], "librechat": ["librechat"]}


def test_attach_unknown_service_is_incompatible():
    # The renamed-service class of breakage: attach still names `nginx`.
    manifest = {"papaia_compat": ">=0.8.0", "networks": {"attach": ["nginx", "librechat"]}}
    result = compat.evaluate_addon("a", manifest, _core(services=_fixture_services()))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert result.axis == "attach"
    assert "core has no service 'nginx'" in result.reason


def test_attach_known_services_stay_ok():
    manifest = {
        "papaia_compat": ">=0.8.0",
        "networks": {"attach": ["nginx-proxy-manager", "librechat"]},
    }
    result = compat.evaluate_addon("a", manifest, _core(services=_fixture_services()))
    assert result.status == compat.STATUS_OK


def test_attach_check_fails_open_without_compose():
    # No compose file in the core context -> the structural check is
    # skipped, never reported as a false incompatibility.
    manifest = {"papaia_compat": ">=0.8.0", "networks": {"attach": ["nginx"]}}
    result = compat.evaluate_addon("a", manifest, _core(services=None))
    assert result.status == compat.STATUS_OK


def test_attach_inactive_profile_warns_but_stays_ok():
    manifest = {"papaia_compat": ">=0.8.0", "networks": {"attach": ["nginx-proxy-manager"]}}
    result = compat.evaluate_addon(
        "a", manifest, _core(services=_fixture_services()), active_profiles=["librechat"]
    )
    assert result.status == compat.STATUS_OK
    assert any("nginx-proxy-manager" in warning for warning in result.warnings)


# ── target-core resolution (update dry-run) ───────────────────────────────────


def test_resolve_core_target_reads_candidate_checkout():
    target = compat.resolve_core_target(REPO_NEXT)
    assert target.platform_version == "1.0.0"
    assert target.addon_api == (2, 2)
    assert sorted(target.services) == ["ingress", "librechat"]


def test_target_core_window_drop_is_detected():
    target = compat.resolve_core_target(REPO_NEXT)
    result = compat.evaluate_addon("a", {"requires": {"addon_api": 1}}, target)
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "min 2" in result.reason


def test_target_core_service_rename_is_detected():
    # Even an addon matching the target window trips over the renamed service.
    target = compat.resolve_core_target(REPO_NEXT)
    manifest = {
        "requires": {"addon_api": 2},
        "networks": {"attach": ["nginx-proxy-manager"]},
    }
    result = compat.evaluate_addon("a", manifest, target)
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "core has no service 'nginx-proxy-manager'" in result.reason


# ── output formats ────────────────────────────────────────────────────────────


def test_format_table_shows_window_and_reason():
    result = compat.evaluate_addon("a", {"requires": {"addon_api": 1}}, _core(addon_api=(2, 2)))
    table = compat.format_table([result], core_label="CORE(target)")
    assert "CORE(target)" in table
    assert "[2..2]" in table
    assert "INCOMPATIBLE" in table
    assert "reason:" in table


def test_to_json_shape():
    import json

    result = compat.evaluate_addon("a", {"requires": {"addon_api": 1}}, _core())
    payload = json.loads(compat.to_json([result]))
    assert payload == [
        {
            "name": "a",
            "axis": "addon_api",
            "requirement": [1],
            "core_value": [1, 1],
            "status": "OK",
            "reason": None,
        }
    ]


# ── requires.addons ───────────────────────────────────────────────────────────


def test_required_addons_accepts_names_and_mappings():
    manifest = {"requires": {"addons": ["wiki", {"name": "crm", "version": ">=1.2.0"}]}}
    assert compat.required_addons(manifest) == [("wiki", None), ("crm", ">=1.2.0")]


def test_required_addons_absent_is_empty():
    assert compat.required_addons({"requires": {"addon_api": 4}}) == []
    assert compat.required_addons({}) == []


@pytest.mark.parametrize(
    "addons",
    ["wiki", [{"version": ">=1.0.0"}], [{"name": "wiki", "version": 1}], [""], [42]],
)
def test_malformed_required_addons_is_error(addons):
    result = compat.evaluate_required_addons("demo", {"requires": {"addons": addons}}, {})
    assert result is not None
    assert result.status == compat.STATUS_ERROR
    assert compat.gate([result], mode=compat.MODE_ENFORCE, force=True) == 2


def test_invalid_required_version_range_is_error():
    manifest = {"requires": {"addons": [{"name": "wiki", "version": ">=banana"}]}}
    result = compat.evaluate_required_addons("demo", manifest, {"wiki": "1.0.0"})
    assert result is not None and result.status == compat.STATUS_ERROR


def test_met_requirements_return_none():
    manifest = {"requires": {"addons": ["wiki", {"name": "crm", "version": ">=1.2.0"}]}}
    active = {"wiki": "1.0.0", "crm": "1.3.0"}
    assert compat.evaluate_required_addons("demo", manifest, active) is None


def test_missing_required_addon_is_incompatible():
    manifest = {"requires": {"addons": ["wiki", "crm"]}}
    result = compat.evaluate_required_addons("demo", manifest, {"wiki": "1.0.0"})
    assert result is not None
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert result.axis == compat.REQUIRES_AXIS
    assert "'crm' is not installed and active" in (result.reason or "")
    assert compat.gate([result], mode=compat.MODE_ENFORCE) == 2
    assert compat.gate([result], mode=compat.MODE_ENFORCE, force=True) == 0


def test_too_old_required_addon_is_incompatible():
    manifest = {"requires": {"addons": [{"name": "crm", "version": ">=2.0.0"}]}}
    result = compat.evaluate_required_addons("demo", manifest, {"crm": "1.3.0"})
    assert result is not None and result.status == compat.STATUS_INCOMPATIBLE
    assert "1.3.0 does not satisfy '>=2.0.0'" in (result.reason or "")


def test_required_addon_without_version_passes_with_warning():
    manifest = {"requires": {"addons": [{"name": "crm", "version": ">=2.0.0"}]}}
    result = compat.evaluate_required_addons("demo", manifest, {"crm": None})
    assert result is not None and result.status == compat.STATUS_OK
    assert result.warnings


# ── networks.join_addons ──────────────────────────────────────────────────────


def test_joined_addons_parses_entries():
    manifest = {
        "requires": {"addons": ["wiki"]},
        "networks": {"join_addons": [{"addon": "wiki", "services": ["job"]}]},
    }
    assert compat.joined_addons(manifest) == [("wiki", ["job"])]


@pytest.mark.parametrize(
    "join",
    [
        [{"addon": "crm", "services": ["job"]}],  # not in requires.addons
        [{"addon": "wiki", "services": []}],
        [{"addon": "wiki"}],
        [{"services": ["job"]}],
        {"addon": "wiki"},
    ],
)
def test_malformed_join_addons_is_a_manifest_error(join):
    manifest = {"requires": {"addons": ["wiki"]}, "networks": {"join_addons": join}}
    result = compat.evaluate_required_addons("demo", manifest, {"wiki": "1.0.0"})
    assert result is not None and result.status == compat.STATUS_ERROR


# ── actions ───────────────────────────────────────────────────────────────────


def test_addon_actions_parses_and_defaults():
    actions = {"reset": {"service": "job", "args": ["--all"]}, "check": {"service": "job"}}
    manifest = {"actions": actions}
    assert compat.addon_actions(manifest) == {
        "reset": {"service": "job", "args": ["--all"], "description": "", "destructive": False},
        "check": {"service": "job", "args": [], "description": "", "destructive": False},
    }


@pytest.mark.parametrize(
    "actions",
    [
        ["reset"],
        {"Reset": {"service": "job"}},
        {"reset": {"args": ["x"]}},
        {"reset": {"service": "job", "args": "x"}},
        {"reset": {"service": "job", "args": [1]}},
        {"reset": {"service": "job", "destructive": "yes"}},
    ],
)
def test_malformed_actions_are_a_manifest_error(actions):
    result = compat.evaluate_addon("a", {"actions": actions}, _core())
    assert result.status == compat.STATUS_ERROR
    assert result.axis == "actions"


# ── contract generations 7 to 12 ──────────────────────────────────────────────

# The window `papaia@v1.8.0` serves.
V1_8_0_WINDOW = (1, 3)

_INGRESS_ENTRY = {"host_key": "flow", "service": "flow-web", "port": 8080}

# A minimal `exposes:` section the kit schema accepts: one user interface.
_EXPOSES = [
    {
        "id": "a.ui",
        "kind": "ui",
        "title": {"en": "A"},
        "identity": ["person"],
        "ui": [
            {
                "id": "a",
                "title": {"en": "A"},
                "summary": {"en": "Does a"},
                "icon": "a",
                "order": 1,
                "host_key": "a",
                "path": "/",
                "visible_for_roles": ["a-user"],
            }
        ],
    }
]


def test_generation_12_requirement_names_the_missing_generation():
    result = compat.evaluate_addon(
        "flow", {"requires": {"addon_api": [12]}}, _core(addon_api=V1_8_0_WINDOW)
    )
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert result.axis == "addon_api"
    assert "missing generations 4, 5, 6, 7, 8, 9, 10, 11, 12" in result.reason
    assert "12: add-on ingress `integration.nginx`" in result.reason


def test_every_missing_generation_up_to_the_requirement_is_named():
    result = compat.evaluate_addon(
        "a", {"requires": {"addon_api": 9}}, _core(addon_api=(1, 6))
    )
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "missing generations 7, 8, 9" in result.reason


@pytest.mark.parametrize(
    ("manifest", "generation"),
    [
        ({"exposes": _EXPOSES}, 7),
        ({"personal_settings": {"schema": "s"}}, 8),
        ({"pki": {"server": True}}, 11),
        ({"integration": {"nginx": [_INGRESS_ENTRY]}}, 12),
    ],
)
def test_generation_feature_on_an_older_core_is_never_ignored(manifest, generation):
    # Any-match on `requires.addon_api` would pass ([3, 12] contains 3); the key used still
    # needs a core of its generation.
    manifest = {"requires": {"addon_api": [3, 12]}, **manifest}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=V1_8_0_WINDOW))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert result.axis == "addon_api"
    assert "missing generations 4," in result.reason
    assert f"{generation}: {compat.ADDON_API_GENERATIONS[generation]}" in result.reason


def test_generation_feature_without_addon_api_is_checked_against_the_window():
    result = compat.evaluate_addon(
        "a", {"papaia_compat": ">=0.8.0", "exposes": _EXPOSES}, _core(addon_api=(1, 6))
    )
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "uses `exposes` (addon_api 7)" in result.reason
    assert "missing generation 7;" in result.reason


def test_generation_features_pass_on_a_core_that_serves_them():
    manifest = {
        "requires": {"addon_api": [12]},
        "exposes": _EXPOSES,
        "personal_settings": {},
        "pki": {},
        "integration": {"nginx": [_INGRESS_ENTRY]},
    }
    result = compat.evaluate_addon("a", manifest, _core(addon_api=(1, 12)))
    assert result.status == compat.STATUS_OK
    assert result.warnings == ()


def test_feature_above_declared_generations_warns():
    manifest = {"requires": {"addon_api": [6]}, "exposes": _EXPOSES}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=(1, 12)))
    assert result.status == compat.STATUS_OK
    assert any("`exposes` needs addon_api 7" in w for w in result.warnings)


def test_feature_without_core_window_warns_instead_of_passing_silently():
    result = compat.evaluate_addon(
        "a", {"papaia_compat": ">=0.8.0", "pki": {}}, _core(addon_api=None)
    )
    assert result.status == compat.STATUS_OK
    assert any("`pki` (addon_api 11) not checked" in w for w in result.warnings)


def test_an_exposes_section_the_kit_schema_refuses_is_a_malformed_manifest():
    manifest = {"requires": {"addon_api": [7]}, "exposes": []}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=(1, 12)))
    assert result.status == compat.STATUS_ERROR
    assert result.axis == "exposes"
    assert result.reason == "a: exposes: must have at least 1 item(s)"


def test_fragment_path_nginx_stays_generation_1():
    manifest = {
        "requires": {"addon_api": 1},
        "integration": {"nginx": "integration/infra/nginx/app.conf"},
    }
    assert compat.manifest_generation_features(manifest) == []
    result = compat.evaluate_addon("a", manifest, _core())
    assert result.status == compat.STATUS_OK


def test_manifest_generation_features_lists_used_keys():
    manifest = {"exposes": [], "pki": {}, "integration": {"nginx": [_INGRESS_ENTRY]}}
    assert compat.manifest_generation_features(manifest) == [
        ("exposes", 7),
        ("pki", 11),
        ("integration.nginx", 12),
    ]


@pytest.mark.parametrize(
    "nginx",
    [
        42,
        [],
        ["flow"],
        [{"service": "flow-web", "port": 8080}],
        [{**_INGRESS_ENTRY, "port": 0}],
        [{**_INGRESS_ENTRY, "port": 65536}],
        [{**_INGRESS_ENTRY, "port": True}],
        [{**_INGRESS_ENTRY, "host_key": "Flow"}],
        [{**_INGRESS_ENTRY, "service": "flow web"}],
        [{**_INGRESS_ENTRY, "websocket": "yes"}],
        [{**_INGRESS_ENTRY, "max_body": "lots"}],
        [{**_INGRESS_ENTRY, "upstream": "http://elsewhere"}],
        [_INGRESS_ENTRY, _INGRESS_ENTRY],
    ],
)
def test_malformed_ingress_entries_are_a_manifest_error(nginx):
    manifest = {"requires": {"addon_api": 12}, "integration": {"nginx": nginx}}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=(1, 12)))
    assert result.status == compat.STATUS_ERROR
    assert result.axis == "integration.nginx"


def test_well_formed_ingress_entry_with_optional_fields_is_accepted():
    entry = {**_INGRESS_ENTRY, "websocket": True, "max_body": "50m"}
    manifest = {"requires": {"addon_api": 12}, "integration": {"nginx": [entry]}}
    result = compat.evaluate_addon("a", manifest, _core(addon_api=(1, 12)))
    assert result.status == compat.STATUS_OK


def test_generation_table_reaches_the_current_generation():
    assert sorted(compat.ADDON_API_GENERATIONS) == list(range(1, 17))
