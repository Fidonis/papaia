"""The `knowledge-map` choice in `papaia-ctl setup`: the profile toggle, its sticky
default, and that switching it on through `setup` leaves a module that can start --
its secrets generated and its map rendered -- on an installation that was set up
before the module existed."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from lib import cli, common, defaults, envtree, resolve

REAL_REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def real_repo(tmp_path: Path) -> Path:
    """A copy of the real checkout's src/: the synthetic fixture repo has no knowledge
    map, and the switch-on renders one."""
    root = tmp_path / "repo"
    shutil.copytree(
        REAL_REPO / "src",
        root / "src",
        ignore=shutil.ignore_patterns(".env", "node_modules", "__pycache__", "tests"),
    )
    (root / "tools").mkdir()
    shutil.copy(REAL_REPO / "tools" / "deployment.template.yaml", root / "tools")
    for name in ("VERSION", "ADDON_API"):
        shutil.copy(REAL_REPO / name, root / name)
    return root


def _args(repo_root, **kwargs) -> resolve.SetupArgs:
    kwargs.setdefault("non_interactive", True)
    return resolve.SetupArgs(config_dir=repo_root, **kwargs)


def _tree(repo_root) -> dict:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = "https://papaia.example.com"
    return tree


def test_enabling_adds_the_profile_once_and_keeps_the_others(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,rag"

    tree = resolve.resolve_knowledge_map(tree, _args(repo_root, enable_knowledge_map=True))
    tree = resolve.resolve_knowledge_map(tree, _args(repo_root, enable_knowledge_map=True))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat,rag,knowledge-map"


def test_disabling_removes_only_the_profile(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,knowledge-map,librechat"

    tree = resolve.resolve_knowledge_map(tree, _args(repo_root, enable_knowledge_map=False))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat"


@pytest.mark.parametrize("profiles", ["keycloak,librechat", "keycloak,knowledge-map,librechat"])
def test_no_flag_leaves_the_profiles_alone(repo_root, profiles):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = profiles

    tree = resolve.resolve_knowledge_map(tree, _args(repo_root))

    assert tree[""]["COMPOSE_PROFILES"] == profiles


def test_defaults_report_the_stored_choice_for_the_wizard(repo_root, config_dir):
    assert defaults.compute_defaults(config_dir, repo_root)["KNOWLEDGE_MAP_STICKY"] == ""

    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,knowledge-map"
    envtree.persist_tree(tree, config_dir, repo_root)

    assert defaults.compute_defaults(config_dir, repo_root)["KNOWLEDGE_MAP_STICKY"] == "true"


def _setup(repo_root, config_dir, *flags: str) -> int:
    return cli.main(
        [
            "--repo-root",
            str(repo_root),
            "--config-dir",
            str(config_dir),
            "setup",
            "--app-host=https://papaia.example.com",
            *flags,
        ]
    )


def _stored(config_dir, relative: str = "") -> dict[str, str]:
    path = config_dir / relative / ".env" if relative else config_dir / ".env"
    return common.parse_env_file(path)


def _profiles(config_dir) -> list[str]:
    return _stored(config_dir)["COMPOSE_PROFILES"].split(",")


def test_the_module_is_off_unless_asked_for(real_repo, config_dir):
    assert _setup(real_repo, config_dir) == 0

    assert "knowledge-map" not in _profiles(config_dir)
    assert not (config_dir / "knowledge-map").exists()


def test_switching_on_and_off_through_setup(real_repo, config_dir):
    assert _setup(real_repo, config_dir, "--enable-knowledge-map=true") == 0
    assert "knowledge-map" in _profiles(config_dir)
    assert (config_dir / "knowledge-map" / "index.yaml").is_file()

    # A re-run without the flag keeps the choice.
    assert _setup(real_repo, config_dir) == 0
    assert "knowledge-map" in _profiles(config_dir)

    assert _setup(real_repo, config_dir, "--enable-knowledge-map=false") == 0
    assert "knowledge-map" not in _profiles(config_dir)


def test_an_installation_older_than_the_module_gets_its_secrets_on_the_switch_on(
    real_repo, config_dir
):
    """`start` only copies the bundles that exist; a module that arrived with a newer
    checkout has none until `setup` writes it. The switch-on is that `setup`."""
    assert _setup(real_repo, config_dir) == 0
    shutil.rmtree(config_dir / "ai" / "knowledge-map")

    assert _setup(real_repo, config_dir, "--enable-knowledge-map=true") == 0

    stored = _stored(config_dir, "ai/knowledge-map")
    assert stored["KM_ADMIN_TOKEN"] and not stored["KM_ADMIN_TOKEN"].startswith("GENERATE_")
    assert stored["KM_EMBEDDING_API_KEY"] == _stored(config_dir, "ai/litellm")["LITELLM_MASTER_KEY"]
