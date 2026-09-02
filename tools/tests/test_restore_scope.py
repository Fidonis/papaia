"""Tests for partial restore: what a snapshot offers, and what a selection
resolves to.

Same boundary as test_backup.py -- everything here is filesystem- and
YAML-level. The scoped teardown and restart live in tools/lib/sh/backup.sh and
are exercised manually per the PR test plan, because they are `docker compose`
calls all the way down.

The refusals get more attention than the happy path on purpose. Every selector
reaches an argv and a path join, and the teardown half of a scoped restore is
irreversible by the time anything notices.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lib import backup

REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _artifact(
    kind: str,
    archive: str,
    target: str,
    owner: str = "core",
    *,
    module: str = "",
    profiles: list[str] | None = None,
    services: list[str] | None = None,
) -> dict:
    return {
        "kind": kind,
        "archive": archive,
        "target": target,
        "owner": owner,
        "project": "papaia",
        "module": module,
        "services": services or [],
        "profiles": profiles or [],
    }


def _manifest(*artifacts: dict, version: int = backup.MANIFEST_VERSION) -> dict:
    return {
        "version": version,
        "id": "2026-07-30_10-19-38",
        "core_project": "papaia",
        "artifacts": list(artifacts),
    }


def _stack_manifest() -> dict:
    """A snapshot shaped like a real one: the config dir, two core modules and
    one add-on that contributes both a volume and a data directory."""
    return _manifest(
        _artifact("configdir", "papaia-config.tar.gz", "/srv/papaia-config"),
        _artifact(
            "volume",
            "volumes/papaia_keycloak-postgresql.tar.gz",
            "papaia_keycloak-postgresql",
            module="keycloak",
            profiles=["keycloak"],
            services=["keycloak-postgres"],
        ),
        _artifact(
            "volume",
            "volumes/papaia_librechat-mongodb.tar.gz",
            "papaia_librechat-mongodb",
            module="librechat",
            profiles=["librechat"],
            services=["librechat-mongodb"],
        ),
        _artifact(
            "volume",
            "volumes/papaia_librechat-meilisearch.tar.gz",
            "papaia_librechat-meilisearch",
            module="librechat",
            profiles=["librechat"],
            services=["librechat-meilisearch"],
        ),
        _artifact(
            "volume",
            "volumes/paperless-dir_paperless-data.tar.gz",
            "paperless-dir_paperless-data",
            owner="addon:paperless",
            module="paperless",
        ),
        _artifact(
            "binddir",
            "binds/paperless--data-media.tar.gz",
            "/srv/addons/paperless/data/media",
            owner="addon:paperless",
            module="paperless",
        ),
    )


# ---------------------------------------------------------------------------
# volume ownership, against the real compose files
#
# Synthetic fixtures would pass while the shipped stack drifted. These read
# src/docker-compose.yml itself, the same technique test_contract_surface uses
# for the addon seam -- only then does an actual service rename fail CI.
# ---------------------------------------------------------------------------


def test_every_core_volume_resolves_to_a_module_and_a_profile():
    owners = backup.resolve_core_volume_owners(REPO)
    assert owners, "the shipped core declares volumes; resolving none is a bug"
    for key, owner in owners.items():
        assert owner.services, f"{key} is declared but nothing mounts it"
        assert owner.modules, f"{key} has no de.fidonis.module label to group under"
        assert owner.profiles, f"{key} resolves to no profile, so nothing could bounce it"


def test_no_core_volume_belongs_to_the_manager_profile():
    """The invariant the whole feature rests on.

    A selection that resolved to `manager` would tear down the container
    serving the request, which is why the whole-snapshot restore has to run
    detached in the first place. Nothing may quietly put a volume there."""
    owners = backup.resolve_core_volume_owners(REPO)
    for key, owner in owners.items():
        assert backup.SELF_PROFILE not in owner.profiles, (
            f"{key} resolves to the {backup.SELF_PROFILE!r} profile; a scoped "
            f"restore of it would stop the manager mid-operation"
        )


def test_a_volume_with_two_mounters_keeps_both_services():
    # localai-models is mounted by the init container and by localai itself.
    # This is why the grouping key is the module and `services` is a list.
    owners = backup.resolve_core_volume_owners(REPO)
    localai_models = owners["localai-models"]
    assert set(localai_models.services) == {"localai-model-init", "localai"}
    assert localai_models.modules == ("localai",)
    assert localai_models.profiles == ("localai",)


@pytest.mark.parametrize(
    ("volume", "service", "module", "profile"),
    [
        # The three cases a volume-name heuristic gets wrong: a service named
        # differently from its volume, twice, and the only key spelled with an
        # underscore, whose profile does not match its module either.
        ("litellm-postgresql", "litellm-db", "litellm", "litellm"),
        ("keycloak-postgresql", "keycloak-postgres", "keycloak", "keycloak"),
        ("searxng_config", "searxng", "searxng", "librechat-websearch"),
    ],
)
def test_volumes_whose_name_does_not_predict_their_owner(
    volume: str, service: str, module: str, profile: str
):
    owner = backup.resolve_core_volume_owners(REPO)[volume]
    assert owner.services == (service,)
    assert owner.modules == (module,)
    assert owner.profiles == (profile,)


def test_resolve_core_volume_owners_without_compose_file(tmp_path: Path):
    # Same degradation contract as resolve_core_volumes.
    assert backup.resolve_core_volume_owners(tmp_path / "nowhere") == {}


# ---------------------------------------------------------------------------
# selectors offered by a snapshot
# ---------------------------------------------------------------------------


def test_selectors_group_by_module_and_addon():
    offered = {item["selector"]: item for item in backup.selectors(_stack_manifest())}
    assert set(offered) == {"module:keycloak", "module:librechat", "addon:paperless"}
    assert offered["module:librechat"]["volumes"] == [
        "papaia_librechat-mongodb",
        "papaia_librechat-meilisearch",
    ]
    assert offered["module:librechat"]["profiles"] == ["librechat"]
    assert len(offered["addon:paperless"]["archives"]) == 2


def test_the_config_directory_is_never_offered_as_a_selector():
    """It is one monolithic archive whose restore wipes the target first, and
    it is what makes a restore unable to run in-process. It has no module, so
    the grammar cannot reach it -- this pins that."""
    for item in backup.selectors(_stack_manifest()):
        assert item["kind"] != "configdir"
        assert "config" not in item["selector"]


def test_a_v1_manifest_offers_nothing_to_select():
    # No grouping fields at all. Reconstructing them from volume names is
    # exactly what the three cases above show to be unsound, so the honest
    # answer is "restore this one as a whole".
    v1 = _manifest(
        {
            "kind": "volume",
            "archive": "volumes/papaia_librechat-mongodb.tar.gz",
            "target": "papaia_librechat-mongodb",
            "owner": "core",
        },
        version=1,
    )
    assert backup.selectors(v1) == []
    assert backup.manifest_artifacts(v1)[0].module == ""
    assert backup.manifest_artifacts(v1)[0].profiles == []


def test_an_empty_manifest_offers_nothing():
    assert backup.selectors(_manifest()) == []


# ---------------------------------------------------------------------------
# selector parsing -- refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "librechat",  # bare word: module, service, profile and volume prefix at once
        "profile:librechat",  # deliberately not in the grammar
        "module:../etc",
        "module:-y",
        "module:--restart-clean",
        "volume:../../etc/passwd",
        "volume:a b",
        "volume:x;rm -rf /",
        "volume:$(id)",
        "module:",
        ":librechat",
        "",
        "   ",
        ",",
    ],
)
def test_hostile_selectors_are_refused(raw: str):
    with pytest.raises(backup.BackupError):
        backup.parse_selectors(raw)


def test_the_manager_module_is_refused_by_name():
    with pytest.raises(backup.BackupError, match="cannot restore over itself"):
        backup.parse_selectors("module:manager")


def test_too_many_selectors_are_refused():
    raw = ",".join(f"module:m{i}" for i in range(backup.MAX_SELECTORS + 1))
    with pytest.raises(backup.BackupError, match="Too many selectors"):
        backup.parse_selectors(raw)


def test_selectors_are_parsed_and_deduplicated():
    assert backup.parse_selectors("module:librechat, addon:paperless,module:librechat") == [
        ("module", "librechat"),
        ("addon", "paperless"),
    ]


def test_a_volume_name_may_carry_underscores_and_dots():
    # Real names look like this: papaia_searxng_config, paperless-dir_paperless-data.
    assert backup.parse_selectors("volume:papaia_searxng_config") == [
        ("volume", "papaia_searxng_config")
    ]


# ---------------------------------------------------------------------------
# selection resolution
# ---------------------------------------------------------------------------


def test_a_module_selection_resolves_to_its_artifacts_and_profile():
    selection = backup.resolve_selection(_stack_manifest(), "module:librechat")
    assert [a.source for a in selection.artifacts] == [
        "papaia_librechat-mongodb",
        "papaia_librechat-meilisearch",
    ]
    assert selection.profiles == ["librechat"]
    assert selection.addons == []


def test_an_addon_selection_carries_the_addon_name_not_the_project():
    """`_addon_path` resolves a name through deployment.yaml, and the compose
    project is the directory basename -- here `paperless-dir`. Bash needs the
    name to find either, so that is what crosses the bridge."""
    selection = backup.resolve_selection(_stack_manifest(), "addon:paperless")
    assert selection.addons == ["paperless"]
    assert selection.profiles == []
    assert {a.kind for a in selection.artifacts} == {"volume", "binddir"}


def test_a_volume_selection_reaches_one_artifact():
    selection = backup.resolve_selection(_stack_manifest(), "volume:papaia_librechat-mongodb")
    assert [a.archive for a in selection.artifacts] == [
        "volumes/papaia_librechat-mongodb.tar.gz"
    ]
    assert selection.profiles == ["librechat"]


def test_a_mixed_selection_unions_profiles_and_addons():
    selection = backup.resolve_selection(
        _stack_manifest(), "module:keycloak,module:librechat,addon:paperless"
    )
    assert selection.profiles == ["keycloak", "librechat"]
    assert selection.addons == ["paperless"]
    assert len(selection.artifacts) == 5


def test_a_selection_never_pulls_in_the_config_directory():
    for raw in ("module:keycloak", "module:librechat", "addon:paperless"):
        selection = backup.resolve_selection(_stack_manifest(), raw)
        assert all(a.kind != "configdir" for a in selection.artifacts)


def test_an_unknown_selector_lists_what_is_available():
    with pytest.raises(backup.BackupError) as excinfo:
        backup.resolve_selection(_stack_manifest(), "module:nope")
    message = str(excinfo.value)
    assert "module:nope" in message
    assert "module:librechat" in message


def test_a_selection_against_a_v1_snapshot_says_so():
    v1 = _manifest(
        {
            "kind": "volume",
            "archive": "volumes/papaia_librechat-mongodb.tar.gz",
            "target": "papaia_librechat-mongodb",
            "owner": "core",
        },
        version=1,
    )
    with pytest.raises(backup.BackupError, match="predates selection"):
        backup.resolve_selection(v1, "module:librechat")


def test_a_selection_resolving_to_the_manager_profile_is_refused():
    """Defence in depth behind the name check: a snapshot could carry the
    profile on an artifact whose module is spelled differently."""
    tampered = _manifest(
        _artifact(
            "volume",
            "volumes/papaia_something.tar.gz",
            "papaia_something",
            module="something",
            profiles=["manager"],
        )
    )
    with pytest.raises(backup.BackupError, match="manager"):
        backup.resolve_selection(tampered, "module:something")


# ---------------------------------------------------------------------------
# manifest target validation
# ---------------------------------------------------------------------------


def test_a_volume_target_must_look_like_a_volume_name(tmp_path: Path):
    artifact = backup.Artifact(kind="volume", archive="a.tar.gz", source="../etc", owner="core")
    with pytest.raises(backup.BackupError, match="Refusing volume target"):
        backup.validate_target(artifact, tmp_path)


def test_a_directory_target_must_be_absolute(tmp_path: Path):
    artifact = backup.Artifact(kind="binddir", archive="a.tar.gz", source="./data", owner="core")
    with pytest.raises(backup.BackupError, match="Refusing relative target"):
        backup.validate_target(artifact, tmp_path)


def test_a_directory_target_may_not_contain_the_config_directory(tmp_path: Path):
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir()
    artifact = backup.Artifact(
        kind="binddir", archive="a.tar.gz", source=str(tmp_path), owner="core"
    )
    with pytest.raises(backup.BackupError, match="contains the config directory"):
        backup.validate_target(artifact, config_dir)


@pytest.mark.parametrize(
    "target", ["/srv/papaia-config/media", "C:\\papaia-config\\media", "C:/papaia-config/media"]
)
def test_an_absolute_target_is_accepted_in_either_platforms_spelling(
    target: str, tmp_path: Path
):
    """Path.is_absolute() answers for the running platform only, so a POSIX
    manifest read on Windows -- the manager container reading what its host
    wrote, and vice versa -- would otherwise have every directory target
    rejected, including on the unfiltered restore path that worked before."""
    artifact = backup.Artifact(kind="binddir", archive="a.tar.gz", source=target, owner="core")
    backup.validate_target(artifact, tmp_path / "elsewhere")


def test_ordinary_targets_pass_validation(tmp_path: Path):
    config_dir = tmp_path / "papaia-config"
    backup.validate_target(
        backup.Artifact(
            kind="volume", archive="a.tar.gz", source="papaia_searxng_config", owner="core"
        ),
        config_dir,
    )
    backup.validate_target(
        backup.Artifact(
            kind="binddir", archive="b.tar.gz", source=str(tmp_path / "media"), owner="core"
        ),
        config_dir,
    )
