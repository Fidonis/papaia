"""The variables of the connection registry against the profile `connections`.

`src/infra/connections/service-env.json` is generated from the source of the pinned image
(`python -m lib.connections_env generate`): every name the registry reads, with the image
and its source commit. `connections_env.check` passes only when the registry's
`environment:` sets each of them or the name is on the core's default list with a reason,
when no development setting is set anywhere, and when both services of the image run the
listed image. The checks read the real checkout, so a drift fails CI; the drift cases run
against copies.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest
import yaml

from lib import common, connections_env

REPO = Path(__file__).resolve().parents[2]
PROFILE_DIR = REPO / "src" / "infra" / "connections"


def _compose(root: Path = REPO) -> dict:
    return yaml.safe_load((root / connections_env.COMPOSE_REL).read_text(encoding="utf-8"))


def _env_list(root: Path = REPO) -> dict:
    return json.loads((root / connections_env.ENV_LIST_REL).read_text(encoding="utf-8"))


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in (
        connections_env.COMPOSE_REL,
        connections_env.ENV_EXAMPLE_REL,
        connections_env.ENV_LIST_REL,
    ):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)
    return root


def _rewrite_compose(root: Path, change) -> None:
    doc = _compose(root)
    change(doc)
    path = root / connections_env.COMPOSE_REL
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _rewrite_list(root: Path, change) -> None:
    doc = _env_list(root)
    change(doc)
    path = root / connections_env.ENV_LIST_REL
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


# ── the real checkout ────────────────────────────────────────────────────────


def test_the_checkout_passes_the_check():
    assert connections_env.check(REPO) == []


def test_every_name_the_registry_reads_is_set_or_kept_at_its_default_with_a_reason():
    reads = set(_env_list()["reads"])
    environment = set(_compose()["services"]["connections"]["environment"])
    defaults = connections_env.DEFAULTS
    unset = connections_env.NEVER_SET
    for name, reason in {**defaults, **unset}.items():
        assert len(reason) >= 20, name
    assert reads <= environment | set(defaults) | set(unset)
    assert not environment & set(defaults)
    # The names the ticket asked about are decided on, one way or the other.
    for name in (
        "CONNECTIONS_PORT",
        "CONNECTIONS_OPENSSL_KRITIS_CONF",
        "CONNECTIONS_OPENBAO_KEY",
        "CONNECTIONS_OPENBAO_JOURNAL_KEY",
        "CONNECTIONS_WORM_DIR",
        "CONNECTIONS_WORM_S3_URL",
    ):
        assert name in reads, name
        assert name in environment or name in defaults, name


def test_the_development_owner_login_is_never_set():
    name = "CONNECTIONS_DEV_OWNER_LOGIN"
    assert name in _env_list()["reads"]
    assert name in connections_env.NEVER_SET
    for service in _compose()["services"].values():
        assert name not in (service.get("environment") or {})
    assert name not in common.parse_env_file(PROFILE_DIR / ".env.example")
    assert name not in (PROFILE_DIR / "docker-compose.yml").read_text(encoding="utf-8")


def test_the_owner_login_reaches_the_migration_only():
    services = _compose()["services"]
    assert "CONNECTIONS_MIGRATE_DB_URL" in services["connections-migrate"]["environment"]
    assert "CONNECTIONS_MIGRATE_DB_URL" not in services["connections"]["environment"]


def test_both_services_of_the_image_run_the_listed_image_with_its_source_commit():
    listed = _env_list()
    assert listed["format"] == connections_env.FORMAT
    assert listed["source"]["repository"] == "papaia-connections"
    commit = listed["source"]["commit"]
    assert len(commit) == 40 and int(commit, 16) >= 0
    services = _compose()["services"]
    assert services["connections"]["image"] == listed["image"]
    assert services["connections-migrate"]["image"] == listed["image"]
    # The commit is written next to the pin as well, for a reader of the compose file.
    text = (PROFILE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    assert f"papaia-connections {commit[:7]}" in text


# ── the check fails on every drift ───────────────────────────────────────────


def test_a_read_name_neither_set_nor_on_the_default_list_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_list(root, lambda d: d["reads"].append("CONNECTIONS_NEW_SETTING"))
    problems = connections_env.check(root)
    assert any("CONNECTIONS_NEW_SETTING" in p and "neither set" in p for p in problems)


def test_a_development_setting_in_the_compose_file_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(
        root,
        lambda d: d["services"]["connections"]["environment"].update(
            CONNECTIONS_DEV_OWNER_LOGIN="true"
        ),
    )
    problems = connections_env.check(root)
    assert any("CONNECTIONS_DEV_OWNER_LOGIN" in p and "never" in p for p in problems)


def test_a_development_setting_in_the_env_example_fails(tmp_path):
    root = _copy(tmp_path)
    path = root / connections_env.ENV_EXAMPLE_REL
    path.write_text(
        path.read_text(encoding="utf-8") + "CONNECTIONS_DEV_OWNER_LOGIN=\n", encoding="utf-8"
    )
    problems = connections_env.check(root)
    assert any("CONNECTIONS_DEV_OWNER_LOGIN" in p and ".env.example" in p for p in problems)


def test_the_owner_login_in_the_registry_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(
        root,
        lambda d: d["services"]["connections"]["environment"].update(
            CONNECTIONS_MIGRATE_DB_URL="postgresql://connections_owner@connections-db/c"
        ),
    )
    problems = connections_env.check(root)
    assert any("connections" in p and "CONNECTIONS_MIGRATE_DB_URL" in p for p in problems)


def test_a_name_the_image_does_not_read_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(
        root,
        lambda d: d["services"]["connections-migrate"]["environment"].update(
            CONNECTIONS_UNKNOWN="1"
        ),
    )
    problems = connections_env.check(root)
    assert any("connections-migrate" in p and "CONNECTIONS_UNKNOWN" in p for p in problems)


def test_a_default_for_a_name_the_image_no_longer_reads_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_list(root, lambda d: d["reads"].remove("CONNECTIONS_PORT"))
    problems = connections_env.check(root)
    assert any("CONNECTIONS_PORT" in p and "no longer read" in p for p in problems)


def test_a_second_image_fails(tmp_path):
    root = _copy(tmp_path)
    other = "ghcr.io/fidonis/papaia-connections:0.1.0@sha256:" + "b" * 64
    _rewrite_compose(root, lambda d: d["services"]["connections-migrate"].update(image=other))
    problems = connections_env.check(root)
    assert any("connections-migrate" in p and "listed image" in p for p in problems)


def test_a_floating_list_image_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_list(root, lambda d: d.update(image="ghcr.io/fidonis/papaia-connections:0.1.0"))
    problems = connections_env.check(root)
    assert any("not pinned by digest" in p for p in problems)


def test_the_cli_check_exits_non_zero_on_drift(tmp_path, capsys):
    root = _copy(tmp_path)
    assert connections_env.main(["check", "--repo", str(root)]) == 0
    _rewrite_list(root, lambda d: d["reads"].append("CONNECTIONS_NEW_SETTING"))
    assert connections_env.main(["check", "--repo", str(root)]) == 1
    assert "CONNECTIONS_NEW_SETTING" in capsys.readouterr().err


# ── the list is generated, not written by hand ───────────────────────────────

_MAIN = '''
DEV_OWNER_LOGIN = "CONNECTIONS_DEV_OWNER_LOGIN"
OWNER_URL = "CONNECTIONS_MIGRATE_DB_URL"


def settings(env):
    port = int(env.get("CONNECTIONS_PORT", "8080"))
    profile = env.get("PAPAIA_SECURITY_PROFILE", "standard")
    # A message is not a name: "set CONNECTIONS_PORT to a number".
    return port, profile, env["CONNECTIONS_DB_URL"]
'''

_TLS = '''
def kritis(env):
    return env.get("CONNECTIONS_OPENSSL_KRITIS_CONF", "/app/kritis.cnf")
'''


def _source(tmp_path: Path) -> Path:
    package = tmp_path / "papaia-connections" / "src" / "papaia_connections"
    package.mkdir(parents=True)
    (package / "main.py").write_text(textwrap.dedent(_MAIN), "utf-8")
    (package / "tls.py").write_text(textwrap.dedent(_TLS), "utf-8")
    (package / "migrations").mkdir()
    (package / "migrations" / "0001.sql").write_text("-- CONNECTIONS_IGNORED\n", "utf-8")
    return tmp_path / "papaia-connections"


def test_the_generator_reads_every_name_of_the_package(tmp_path):
    image = "ghcr.io/fidonis/papaia-connections:0.1.0@sha256:" + "a" * 64
    listed = connections_env.generate(_source(tmp_path), image=image, commit="1" * 40)
    assert listed == {
        "format": connections_env.FORMAT,
        "image": image,
        "source": {"repository": "papaia-connections", "commit": "1" * 40},
        "reads": [
            "CONNECTIONS_DB_URL",
            "CONNECTIONS_DEV_OWNER_LOGIN",
            "CONNECTIONS_MIGRATE_DB_URL",
            "CONNECTIONS_OPENSSL_KRITIS_CONF",
            "CONNECTIONS_PORT",
            "PAPAIA_SECURITY_PROFILE",
        ],
        "runtime": list(connections_env.RUNTIME_READS),
    }


def test_the_generator_refuses_a_floating_image_and_a_short_commit(tmp_path):
    source = _source(tmp_path)
    with pytest.raises(connections_env.ConnectionsEnvError, match="digest"):
        connections_env.generate(
            source, image="ghcr.io/fidonis/papaia-connections:0.1.0", commit="1" * 40
        )
    with pytest.raises(connections_env.ConnectionsEnvError, match="commit"):
        connections_env.generate(
            source, image="x:1@sha256:" + "a" * 64, commit="120b4e7"
        )


def test_the_generator_refuses_a_checkout_without_the_package(tmp_path):
    with pytest.raises(connections_env.ConnectionsEnvError, match="papaia_connections"):
        connections_env.generate(tmp_path, image="x:1@sha256:" + "a" * 64, commit="1" * 40)


def test_repin_names_the_generator_of_every_variable_list():
    from lib import image_pins

    lists = sorted(str(p.relative_to(REPO)) for p in (REPO / "src").rglob("service-env.json"))
    assert lists == sorted(image_pins.SERVICE_ENV_GENERATORS)
    assert image_pins.SERVICE_ENV_GENERATORS[str(connections_env.ENV_LIST_REL)] == (
        "lib.connections_env"
    )
