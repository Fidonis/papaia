from __future__ import annotations

import pytest
import yaml

from lib import upgrade

TAGS = ["v0.8.0", "v1.0.0", "v1.0.0-rc.1", "v1.2.0", "v10.0.0"]

# ── tag parsing ───────────────────────────────────────────────────────────────


def test_parse_tags_accepts_plain_tag_list():
    assert upgrade.parse_tags(["v1.0.0", "v1.2.0"]) == ["1.0.0", "1.2.0"]


def test_parse_tags_accepts_ls_remote_output():
    lines = [
        "9f1c0d3\trefs/tags/v1.0.0",
        "2a4b6e8\trefs/tags/v1.2.0",
        # Annotated tags appear twice; the peeled ref is the same release.
        "7c5d9a1\trefs/tags/v1.2.0^{}",
    ]
    assert upgrade.parse_tags(lines) == ["1.0.0", "1.2.0"]


def test_parse_tags_ignores_unrelated_refs():
    lines = ["milestone-2", "v1.0.0", "vNext", "", "  ", "1.5.0"]
    assert upgrade.parse_tags(lines) == ["1.0.0"]


# ── target selection ──────────────────────────────────────────────────────────


def test_latest_release_skips_prereleases():
    assert upgrade.latest_release(["1.0.0", "1.1.0-rc.1"]) == "1.0.0"


def test_latest_release_compares_numerically_not_lexically():
    # The trap `sort` falls into: "10.0.0" < "9.0.0" as a string.
    assert upgrade.latest_release(["9.0.0", "10.0.0"]) == "10.0.0"


def test_latest_release_returns_none_without_releases():
    assert upgrade.latest_release(["1.0.0-rc.1"]) is None


def test_select_target_without_request_picks_latest_release():
    assert upgrade.select_target(upgrade.parse_tags(TAGS), None) == "10.0.0"


@pytest.mark.parametrize("requested", ["1.2.0", "v1.2.0", " V1.2.0 "])
def test_select_target_normalizes_the_requested_version(requested):
    assert upgrade.select_target(upgrade.parse_tags(TAGS), requested) == "1.2.0"


def test_select_target_allows_an_explicitly_requested_prerelease():
    assert upgrade.select_target(upgrade.parse_tags(TAGS), "1.0.0-rc.1") == "1.0.0-rc.1"


def test_select_target_rejects_an_unknown_version():
    with pytest.raises(upgrade.UpgradeError, match="v9.9.9"):
        upgrade.select_target(upgrade.parse_tags(TAGS), "9.9.9")


def test_select_target_rejects_a_malformed_version():
    with pytest.raises(upgrade.UpgradeError):
        upgrade.select_target(upgrade.parse_tags(TAGS), "1.2")


def test_select_target_without_any_tag_raises():
    with pytest.raises(upgrade.UpgradeError, match="No release tag"):
        upgrade.select_target([], None)


# ── direction ─────────────────────────────────────────────────────────────────


def test_check_direction_allows_forward():
    upgrade.check_direction("1.0.0", "1.2.0")


def test_check_direction_refuses_downgrade():
    with pytest.raises(upgrade.UpgradeError, match="Downgrades are not"):
        upgrade.check_direction("1.2.0", "1.0.0")


def test_check_direction_refuses_downgrade_to_own_prerelease():
    with pytest.raises(upgrade.UpgradeError):
        upgrade.check_direction("1.2.0", "1.2.0-rc.1")


def test_resolve_status_forward_is_ok():
    assert upgrade.resolve_status("1.0.0", "1.2.0", explicit=False) == upgrade.STATUS_OK


def test_resolve_status_same_version_is_up_to_date():
    assert upgrade.resolve_status("1.2.0", "1.2.0", explicit=True) == upgrade.STATUS_UP_TO_DATE


def test_resolve_status_without_request_reports_no_newer_release():
    # A checkout ahead of the newest tag (milestone branch before the release is
    # cut) is nothing to do -- not a downgrade attempt.
    assert upgrade.resolve_status("1.0.0", "0.8.0", explicit=False) == upgrade.STATUS_UP_TO_DATE


def test_resolve_status_refuses_an_explicitly_requested_downgrade():
    with pytest.raises(upgrade.UpgradeError, match="Downgrades are not"):
        upgrade.resolve_status("1.2.0", "1.0.0", explicit=True)


# ── current version ───────────────────────────────────────────────────────────


def _write_deployment(config_dir, value):
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"customer": "papaia", "platform_version": value}), encoding="utf-8"
    )


def test_resolve_current_version_prefers_the_deployment_manifest(config_dir, repo_root):
    # The bundle, not the checkout, is what the migrations start from: an
    # operator may have moved the checkout by hand without re-running setup.
    _write_deployment(config_dir, "0.8.0")
    (repo_root / "VERSION").write_text("1.2.0\n", encoding="utf-8")
    assert upgrade.resolve_current_version(config_dir, repo_root) == "0.8.0"


def test_resolve_current_version_falls_back_to_the_checkout(config_dir, repo_root):
    (repo_root / "VERSION").write_text("1.2.0\n", encoding="utf-8")
    assert upgrade.resolve_current_version(config_dir, repo_root) == "1.2.0"


def test_resolve_current_version_ignores_a_malformed_manifest_value(config_dir, repo_root):
    _write_deployment(config_dir, "not-a-version")
    (repo_root / "VERSION").write_text("1.2.0\n", encoding="utf-8")
    assert upgrade.resolve_current_version(config_dir, repo_root) == "1.2.0"
