"""The 1.5.0 migration that builds LibreChat's tenant-scoped MongoDB indexes.

`docker` is replaced by a recorder, so the tests pin the sequence of calls and the failure
handling without a daemon: what must run, in which order, and that the throwaway MongoDB and
network are removed whatever happens.
"""

from __future__ import annotations

import importlib.util
import subprocess
import types
from pathlib import Path

import pytest

from lib import migrations

REAL_REPO = Path(__file__).resolve().parents[2]
SCRIPT = REAL_REPO / "tools" / "migrations" / "1.5.0__librechat-tenant-indexes.py"

LIBRECHAT_IMAGE = "ghcr.io/librechat-ai/librechat:v0.8.8"
MONGO_IMAGE = "mongo:8.0.20"


def _load():
    # The file name starts with a version, so it cannot be imported by name.
    spec = importlib.util.spec_from_file_location("librechat_tenant_indexes", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def mig():
    return _load()


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A repo root whose compose file pins the images, plus a config dir."""
    repo = tmp_path / "repo"
    compose = repo / "src" / "ai" / "librechat" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(
        "services:\n"
        "  librechat:\n"
        f"    image: {LIBRECHAT_IMAGE}\n"
        "  librechat-mongodb:\n"
        f"    image: {MONGO_IMAGE}\n",
        encoding="utf-8",
    )
    config = tmp_path / "config"
    config.mkdir()
    monkeypatch.setenv("PAPAIA_CONFIG_DIR", str(config))
    monkeypatch.setenv("PAPAIA_REPO_ROOT", str(repo))
    return {"repo": repo, "config": config}


class FakeDocker:
    """Answers `docker <args>` calls and records them. `fail` maps a leading argument
    sequence to a (returncode, stdout, stderr) answer; everything else succeeds, with the
    stdout the migration looks for."""

    def __init__(self, volume_exists=True, in_use="", fail=None):
        self.calls: list[tuple[str, ...]] = []
        self.volume_exists = volume_exists
        self.in_use = in_use
        self.fail = fail or {}

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        for prefix, (code, out, err) in self.fail.items():
            if args[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(args, code, out, err)
        if args[:2] == ("volume", "inspect"):
            if self.volume_exists:
                return subprocess.CompletedProcess(args, 0, "[]", "")
            return subprocess.CompletedProcess(
                args, 1, "[]", f"Error response from daemon: get {args[2]}: no such volume"
            )
        if args[:1] == ("ps",):
            return subprocess.CompletedProcess(args, 0, self.in_use, "")
        if args[:1] == ("exec",):
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def verbs(self):
        return [c[0] if c[0] not in ("volume", "network") else f"{c[0]} {c[1]}" for c in self.calls]

    def npm_scripts(self):
        return [c[-1] for c in self.calls if c[:1] == ("run",) and "--entrypoint" in c]


@pytest.fixture
def docker(monkeypatch, mig):
    def install(clock_step=1, **kwargs):
        fake = FakeDocker(**kwargs)
        monkeypatch.setattr(mig, "_docker", fake)
        # A fake clock inside the migration module only: no real waiting, and the
        # readiness deadline is reached after a known number of polls.
        now = iter(range(0, 1_000_000, clock_step))
        monkeypatch.setattr(
            mig, "time", types.SimpleNamespace(monotonic=lambda: next(now), sleep=lambda _s: None)
        )
        return fake

    return install


# ── discovery ────────────────────────────────────────────────────────────────


def test_the_real_file_name_parses_and_is_due_for_the_1_5_0_upgrade():
    found = migrations.discover(REAL_REPO)
    ids = [m.id for m in migrations.pending(found, "1.4.0", "1.5.0")]
    assert "1.5.0__librechat-tenant-indexes" in ids


def test_it_is_not_replayed_on_an_install_that_is_already_1_5_0():
    found = migrations.discover(REAL_REPO)
    ids = [m.id for m in migrations.pending(found, "1.5.0", "1.5.0")]
    assert "1.5.0__librechat-tenant-indexes" not in ids


# ── nothing to migrate ───────────────────────────────────────────────────────


def test_no_volume_is_a_no_op(mig, env, docker):
    fake = docker(volume_exists=False)
    assert mig.main() == 0
    # Nothing was started, so there is nothing to clean up either.
    assert fake.verbs() == ["volume inspect"]


def test_an_unreachable_daemon_is_an_error_not_a_skip(mig, env, docker, capsys):
    # "Cannot connect to the Docker daemon" must not read as "no such volume".
    docker(fail={("volume", "inspect"): (1, "", "Cannot connect to the Docker daemon")})
    assert mig.main() == 1
    assert "cannot inspect volume" in capsys.readouterr().err


def test_a_missing_docker_cli_is_an_error(mig, env, monkeypatch, capsys):
    def boom(*_a, **_k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(mig, "_docker", boom)
    assert mig.main() == 1
    assert "docker CLI was not found" in capsys.readouterr().err


# ── project naming ───────────────────────────────────────────────────────────


def test_the_volume_defaults_to_the_papaia_project(mig, env, docker):
    fake = docker(volume_exists=False)
    mig.main()
    assert fake.calls[0] == ("volume", "inspect", "papaia_librechat-mongodb")


def test_the_volume_follows_compose_project_name(mig, env, docker):
    (env["config"] / ".env").write_text("COMPOSE_PROJECT_NAME=papaia-dev\n", encoding="utf-8")
    fake = docker(volume_exists=False)
    mig.main()
    assert fake.calls[0] == ("volume", "inspect", "papaia-dev_librechat-mongodb")


# ── the run ──────────────────────────────────────────────────────────────────


def test_happy_path_runs_dry_run_then_apply_and_cleans_up(mig, env, docker):
    fake = docker()
    assert mig.main() == 0

    assert fake.npm_scripts() == ["migrate:tenant-indexes:dry-run", "migrate:tenant-indexes"]

    verbs = fake.verbs()
    start = verbs.index("network create")
    # leftovers are removed before the start and again after the last step
    assert verbs[:5] == ["volume inspect", "ps", "rm", "network rm", "network create"]
    assert verbs[start:].count("rm") == 1 and verbs[-2:] == ["rm", "network rm"]


def test_images_and_volume_come_from_the_release_not_the_script(mig, env, docker):
    fake = docker()
    mig.main()

    mongo_run = next(c for c in fake.calls if c[:2] == ("run", "-d"))
    assert MONGO_IMAGE in mongo_run
    assert "papaia_librechat-mongodb:/data/db" in mongo_run

    npm_run = next(c for c in fake.calls if c[:1] == ("run",) and "--entrypoint" in c)
    assert LIBRECHAT_IMAGE in npm_run
    # root npm scripts live in /app; the database is the one the stack uses
    assert npm_run[npm_run.index("-w") + 1] == "/app"
    assert "MONGO_URI=mongodb://papaia-librechat-migrate-mongo:27017/LibreChat" in npm_run


def test_a_failing_dry_run_stops_before_anything_is_changed(mig, env, docker, capsys):
    fake = docker(fail={("run", "--rm"): (3, "", "")})
    assert mig.main() == 1
    assert fake.npm_scripts() == ["migrate:tenant-indexes:dry-run"]
    assert "exit code 3" in capsys.readouterr().err
    assert fake.verbs()[-2:] == ["rm", "network rm"]


def test_a_failing_apply_fails_the_upgrade_and_cleans_up(mig, env, docker, monkeypatch):
    fake = docker()
    npm_runs = {"n": 0}

    def apply_fails(*args, capture=False):
        if args[:1] == ("run",) and "--entrypoint" in args:
            npm_runs["n"] += 1
            if npm_runs["n"] == 2:
                fake.calls.append(args)
                return subprocess.CompletedProcess(args, 1, "", "")
        return fake(*args, capture=capture)

    monkeypatch.setattr(mig, "_docker", apply_fails)
    assert mig.main() == 1
    assert fake.npm_scripts() == ["migrate:tenant-indexes:dry-run", "migrate:tenant-indexes"]
    assert fake.verbs()[-2:] == ["rm", "network rm"]


def test_a_volume_in_use_is_refused_before_anything_starts(mig, env, docker, capsys):
    fake = docker(in_use="3f2a9c1d\n")
    assert mig.main() == 1
    assert "in use by a running container" in capsys.readouterr().err
    assert "network create" not in fake.verbs()


def test_a_mongo_that_never_answers_fails_and_cleans_up(mig, env, docker, capsys):
    fake = docker(clock_step=40, fail={("exec",): (1, "", "not ready")})
    assert mig.main() == 1
    assert "was not ready" in capsys.readouterr().err
    assert fake.npm_scripts() == []
    assert ("logs", "--tail", "20", "papaia-librechat-migrate-mongo") in fake.calls
    assert fake.verbs()[-2:] == ["rm", "network rm"]


def test_a_compose_file_without_the_services_is_an_error(mig, env, docker, capsys):
    (env["repo"] / "src" / "ai" / "librechat" / "docker-compose.yml").write_text(
        "services: {}\n", encoding="utf-8"
    )
    fake = docker()
    assert mig.main() == 1
    assert "cannot find the librechat / librechat-mongodb images" in capsys.readouterr().err
    assert "network create" not in fake.verbs()


def test_a_mongo_that_cannot_start_reports_dockers_reason_and_cleans_up(mig, env, docker, capsys):
    fake = docker(fail={("run", "-d"): (125, "", "pull access denied for mongo")})
    assert mig.main() == 1
    assert "pull access denied for mongo" in capsys.readouterr().err
    assert fake.npm_scripts() == []
    assert fake.verbs()[-2:] == ["rm", "network rm"]
