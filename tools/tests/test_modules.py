"""The optional modules' data and settings: what switching one off can delete, and that nothing
else goes with it.

Works on a copy of the real compose files and `.env.example` files, so the tests follow what the
release ships. Docker is replaced by a recorder; no volume of the machine running the tests is
touched.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from lib import backup, cli, common, modules

REAL_REPO = Path(__file__).resolve().parents[2]
PROJECT = "papaia"

LOCALAI = {"localai-models", "localai-data"}
WEB_SEARCH = {"searxng_config", "searxng_data"}
RAG = {"qdrant-storage", "qdrant-ingest-cache", "qdrant-ingest-state"}
MAIL = {"smtp-relay-queue"}


@pytest.fixture
def real_repo(tmp_path: Path) -> Path:
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


def _setup(repo: Path, config: Path, *flags: str) -> None:
    code = cli.main(
        [
            "--repo-root",
            str(repo),
            "--config-dir",
            str(config),
            "setup",
            "--app-host=https://papaia.test",
            *flags,
        ]
    )
    assert code == 0


def _env(config: Path, relative: str = "") -> dict[str, str]:
    path = config / relative / ".env" if relative else config / ".env"
    return common.parse_env_file(path)


def _profiles(config: Path) -> set[str]:
    return set(_env(config)["COMPOSE_PROFILES"].split(","))


class _Docker:
    """`docker volume ls` and `docker volume rm`, over a set of volume names."""

    def __init__(self, volumes: set[str], busy: set[str] | None = None) -> None:
        self.volumes = set(volumes)
        self.busy = busy or set()
        self.calls: list[list[str]] = []
        self.reachable = True

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if not self.reachable:
            raise OSError("no docker")
        if argv[:3] == ["docker", "volume", "ls"]:
            return subprocess.CompletedProcess(argv, 0, "\n".join(sorted(self.volumes)) + "\n", "")
        if argv[:3] == ["docker", "volume", "rm"]:
            name = argv[3]
            if name in self.busy:
                return subprocess.CompletedProcess(argv, 1, "", f"volume {name} is in use")
            self.volumes.discard(name)
            return subprocess.CompletedProcess(argv, 0, name, "")
        raise AssertionError(argv)

    def removed(self) -> list[str]:
        return [c[3] for c in self.calls if c[:3] == ["docker", "volume", "rm"]]


def _all_volumes(keys: set[str], project: str = PROJECT) -> set[str]:
    return {f"{project}_{key}" for key in keys}


# -- who owns which volume ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "keys"),
    [("localai", LOCALAI), ("web-search", WEB_SEARCH), ("rag", RAG), ("mail", MAIL)],
)
def test_each_module_owns_exactly_its_volumes(name: str, keys: set[str]) -> None:
    assert set(modules.volume_keys(REAL_REPO, modules.spec(name))) == keys


def test_no_two_modules_share_a_volume_and_none_owns_one_of_the_always_on_services() -> None:
    seen: set[str] = set()
    for module in modules.MODULES.values():
        keys = set(modules.volume_keys(REAL_REPO, module))
        assert not keys & seen, module.name
        seen |= keys
    owners = backup.resolve_core_volume_owners(REAL_REPO)
    optional = {m.profile for m in modules.MODULES.values()}
    for key in seen:
        assert set(owners[key].profiles) <= optional, key


def test_the_profiles_are_the_ones_the_compose_files_use() -> None:
    declared = {
        p for owner in backup.resolve_core_volume_owners(REAL_REPO).values() for p in owner.profiles
    }
    assert {m.profile for m in modules.MODULES.values()} <= declared


def test_an_unknown_module_is_refused() -> None:
    with pytest.raises(modules.ModuleError, match="unknown module"):
        modules.spec("keycloak")


# -- info ---------------------------------------------------------------------------------


def test_info_lists_the_real_volume_names_and_whether_they_exist(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir, "--enable-rag=true")
    docker = _Docker({f"{PROJECT}_qdrant-storage", f"{PROJECT}_something-else"})

    document = modules.info(config_dir, real_repo, "rag", runner=docker)

    assert document["module"] == "rag" and document["profile"] == "rag"
    assert document["active"] is True
    assert {v["name"]: v["exists"] for v in document["volumes"]} == {
        f"{PROJECT}_qdrant-ingest-cache": False,
        f"{PROJECT}_qdrant-ingest-state": False,
        f"{PROJECT}_qdrant-storage": True,
    }
    assert document["settings_need_data"] is True
    assert document["settings"]["regenerates_secrets"] is True
    assert json.dumps(document), "the document is plain JSON"


def test_info_does_not_pretend_when_docker_cannot_be_asked(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir)
    docker = _Docker(set())
    docker.reachable = False

    document = modules.info(config_dir, real_repo, "localai", runner=docker)

    assert {v["exists"] for v in document["volumes"]} == {None}
    assert document["active"] is False


def test_the_volume_names_follow_the_project_name(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir, "--env=staging")

    document = modules.info(config_dir, real_repo, "mail", runner=_Docker(set()))

    assert [v["name"] for v in document["volumes"]] == ["papaia-staging_smtp-relay-queue"]


# -- delete the data ---------------------------------------------------------------------


def test_purge_data_removes_the_modules_volumes_and_nothing_else(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir)
    everything = _all_volumes(LOCALAI | WEB_SEARCH | RAG | MAIL) | {
        f"{PROJECT}_librechat-mongodb",
        f"{PROJECT}_keycloak-postgresql",
        "unrelated",
    }
    docker = _Docker(everything)

    removed = modules.purge_data(config_dir, real_repo, "web-search", runner=docker)

    assert sorted(removed) == sorted(_all_volumes(WEB_SEARCH))
    assert docker.volumes == everything - _all_volumes(WEB_SEARCH)
    assert set(docker.removed()) == _all_volumes(WEB_SEARCH)


def test_purge_data_skips_a_volume_that_does_not_exist(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir)
    docker = _Docker({f"{PROJECT}_localai-models"})

    removed = modules.purge_data(config_dir, real_repo, "localai", runner=docker)

    assert removed == [f"{PROJECT}_localai-models"]


def test_purge_data_is_refused_while_the_module_is_switched_on(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir, "--enable-local-ai=true")
    docker = _Docker(_all_volumes(LOCALAI))

    with pytest.raises(modules.ModuleError, match="still switched on"):
        modules.purge_data(config_dir, real_repo, "localai", runner=docker)

    assert docker.removed() == []


def test_purge_data_never_forces_a_volume_that_is_in_use(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir)
    docker = _Docker(_all_volumes(RAG), busy={f"{PROJECT}_qdrant-storage"})

    with pytest.raises(modules.ModuleError, match="qdrant-storage: volume .* is in use"):
        modules.purge_data(config_dir, real_repo, "rag", runner=docker)

    assert all(
        call[:3] != ["docker", "volume", "prune"] and "-f" not in call for call in docker.calls
    )


def test_purge_data_removes_nothing_when_docker_does_not_answer(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir)
    docker = _Docker(_all_volumes(RAG))
    docker.reachable = False

    with pytest.raises(modules.ModuleError, match="Docker did not answer"):
        modules.purge_data(config_dir, real_repo, "rag", runner=docker)


# -- reset the settings ------------------------------------------------------------------


def _bytes(config: Path, repo: Path, *relative: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for rel in relative:
        for base in (config / rel, repo / "src" / rel):
            if base.is_file():
                out[str(base)] = base.read_bytes()
    return out


def test_resetting_localai_restores_the_defaults_and_keeps_the_keycloak_secret(
    real_repo, config_dir
) -> None:
    _setup(real_repo, config_dir, "--enable-local-ai=true", "--localai-variant=intel")
    env_path = config_dir / "ai" / "localai" / ".env"
    text = env_path.read_text(encoding="utf-8").replace(
        "LOCALAI_ADMIN_EMAIL=", "LOCALAI_ADMIN_EMAIL=ops@example.org"
    )
    env_path.write_text(text, encoding="utf-8")
    secret = _env(config_dir, "ai/localai")["LOCALAI_OIDC_CLIENT_SECRET"]
    others = _bytes(config_dir, real_repo, "ai/rag/.env", "infra/keycloak/.env", "ai/litellm/.env")
    _setup(real_repo, config_dir, "--enable-local-ai=false")

    touched = modules.reset_config(config_dir, real_repo, "localai")

    assert "ai/localai/.env" in touched and ".env" in touched
    after = _env(config_dir, "ai/localai")
    assert after["LOCALAI_ADMIN_EMAIL"] == ""
    assert after["LOCALAI_OIDC_CLIENT_SECRET"] == secret
    assert _env(config_dir)["LOCALAI_IMAGE_VARIANT"] == "cpu"
    assert common.parse_env_file(real_repo / "src/ai/localai/.env")["LOCALAI_ADMIN_EMAIL"] == ""
    assert (
        _bytes(config_dir, real_repo, "ai/rag/.env", "infra/keycloak/.env", "ai/litellm/.env")
        == others
    )


def test_resetting_is_refused_while_the_module_is_switched_on(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir, "--enable-local-ai=true")
    before = _bytes(config_dir, real_repo, "ai/localai/.env", ".env")

    with pytest.raises(modules.ModuleError, match="still switched on"):
        modules.reset_config(config_dir, real_repo, "localai")

    assert _bytes(config_dir, real_repo, "ai/localai/.env", ".env") == before


def test_resetting_web_search_keeps_the_key_librechat_holds_a_copy_of(
    real_repo, config_dir
) -> None:
    _setup(real_repo, config_dir, "--enable-web-search=true", "--reranker-model=rerank/x")
    jina = _env(config_dir, "ai/jinaai")
    assert jina["RERANKER_MODEL"] == "rerank/x"
    librechat_before = _env(config_dir, "ai/librechat")
    _setup(real_repo, config_dir, "--enable-web-search=false")

    modules.reset_config(config_dir, real_repo, "web-search")

    after = _env(config_dir, "ai/jinaai")
    shipped = common.parse_env_file(real_repo / "src/ai/jinaai/.env.example")
    assert after["RERANKER_MODEL"] == shipped["RERANKER_MODEL"] != "rerank/x"
    assert after["JINAAI_RERANKER_API_KEY"] == jina["JINAAI_RERANKER_API_KEY"]
    assert _env(config_dir, "ai/librechat") == librechat_before


def test_resetting_rag_regenerates_its_secrets_and_clears_the_catalog_but_not_the_documents(
    real_repo, config_dir
) -> None:
    _setup(real_repo, config_dir, "--enable-rag=true")
    before = _env(config_dir, "ai/rag")
    catalog = config_dir / "ai" / "rag" / "catalog"
    documents = config_dir / "ai" / "rag" / "documents"
    catalog.mkdir(parents=True, exist_ok=True)
    documents.mkdir(parents=True, exist_ok=True)
    for name in ("connections.yaml", "jobs.yaml", "secrets.yaml"):
        (catalog / name).write_text("x: 1\n", encoding="utf-8")
    (documents / "mine.pdf").write_bytes(b"%PDF")
    _setup(real_repo, config_dir, "--enable-rag=false")

    touched = modules.reset_config(config_dir, real_repo, "rag")

    after = _env(config_dir, "ai/rag")
    for key in ("QDRANT_JWT_SECRET", "QI_CONNECTIONS_SECRET", "QI_API_TOKEN"):
        assert after[key] and not after[key].startswith("GENERATE_")
        assert after[key] != before[key], key
    assert sorted(p.name for p in catalog.iterdir()) == []
    assert catalog.is_dir()
    assert (documents / "mine.pdf").read_bytes() == b"%PDF"
    assert "ai/rag/catalog/jobs.yaml" in touched


def test_resetting_the_mail_relay_removes_the_password_and_the_settings(
    real_repo, config_dir
) -> None:
    _setup(
        real_repo,
        config_dir,
        "--enable-smtp=true",
        "--smtp-host=smtp.example.org",
        "--smtp-from=noreply@example.org",
        "--smtp-no-auth",
    )
    password_file = config_dir / "infra" / "smtp-relay" / "upstream-password"
    password_file.write_text("secret", encoding="utf-8")
    _setup(real_repo, config_dir, "--enable-smtp=false")

    modules.reset_config(config_dir, real_repo, "mail")

    after = _env(config_dir, "infra/smtp-relay")
    assert after["SMTP_RELAY_UPSTREAM_HOST"] == "" and after["SMTP_RELAY_FROM_ADDRESS"] == ""
    assert not password_file.exists()


def test_a_later_setup_does_not_bring_the_old_settings_back(real_repo, config_dir) -> None:
    _setup(real_repo, config_dir, "--enable-local-ai=true", "--localai-variant=intel")
    _setup(real_repo, config_dir, "--enable-local-ai=false")
    modules.reset_config(config_dir, real_repo, "localai")

    _setup(real_repo, config_dir)

    assert _env(config_dir)["LOCALAI_IMAGE_VARIANT"] == "cpu"
    assert "localai" not in _profiles(config_dir)


# -- the commands ------------------------------------------------------------------------


def _cli(real_repo: Path, config_dir: Path, *args: str) -> int:
    return cli.main(["--repo-root", str(real_repo), "--config-dir", str(config_dir), *args])


def test_module_info_prints_one_json_document(real_repo, config_dir, capsys, monkeypatch) -> None:
    _setup(real_repo, config_dir)
    monkeypatch.setattr(modules, "_docker", _Docker({f"{PROJECT}_localai-models"}))
    capsys.readouterr()

    code = _cli(real_repo, config_dir, "module-info", "--module=localai")

    out = capsys.readouterr().out
    assert code == 0
    document = json.loads(out)
    assert sorted(document) == [
        "active",
        "module",
        "profile",
        "settings",
        "settings_need_data",
        "volumes",
    ]
    assert out.count("\n") == 1


def test_module_purge_needs_to_be_told_what_to_delete(real_repo, config_dir, capsys) -> None:
    _setup(real_repo, config_dir)

    assert _cli(real_repo, config_dir, "module-purge", "--module=localai") == 2
    assert "name what to delete" in capsys.readouterr().err


def test_the_settings_of_rag_are_only_deleted_together_with_its_data(
    real_repo, config_dir, capsys, monkeypatch
) -> None:
    _setup(real_repo, config_dir)
    before = _bytes(config_dir, real_repo, "ai/rag/.env")
    docker = _Docker(_all_volumes(RAG))
    monkeypatch.setattr(modules, "_docker", docker)

    code = _cli(real_repo, config_dir, "module-purge", "--module=rag", "--config")

    assert code == 3
    assert "together with its data" in capsys.readouterr().err
    assert docker.removed() == []
    assert _bytes(config_dir, real_repo, "ai/rag/.env") == before


def test_module_purge_deletes_data_and_settings_in_that_order(
    real_repo, config_dir, capsys, monkeypatch
) -> None:
    _setup(real_repo, config_dir)
    docker = _Docker(_all_volumes(RAG))
    monkeypatch.setattr(modules, "_docker", docker)
    capsys.readouterr()

    code = _cli(real_repo, config_dir, "module-purge", "--module=rag", "--data", "--config")

    lines = capsys.readouterr().out.splitlines()
    assert code == 0
    assert [ln for ln in lines if ln.startswith("removed volume")] != []
    assert lines.index(next(ln for ln in lines if ln.startswith("reset"))) > lines.index(
        next(ln for ln in lines if ln.startswith("removed volume"))
    )
    assert docker.volumes == set()


def test_module_purge_refuses_a_module_that_is_on(
    real_repo, config_dir, capsys, monkeypatch
) -> None:
    _setup(real_repo, config_dir, "--enable-local-ai=true")
    docker = _Docker(_all_volumes(LOCALAI))
    monkeypatch.setattr(modules, "_docker", docker)

    code = _cli(real_repo, config_dir, "module-purge", "--module=localai", "--data")

    assert code == 3
    assert "still switched on" in capsys.readouterr().err
    assert docker.removed() == []


@pytest.mark.parametrize("name", ["keycloak", "manager", "librechat", "../x"])
def test_the_commands_only_know_the_optional_modules(real_repo, config_dir, name) -> None:
    _setup(real_repo, config_dir)
    with pytest.raises(SystemExit) as caught:
        _cli(real_repo, config_dir, "module-info", f"--module={name}")
    assert caught.value.code == 2


def test_this_machines_environment_is_not_what_the_tests_ran_against() -> None:
    assert not os.environ.get("PAPAIA_CONFIG_DIR", "").startswith(str(REAL_REPO))
