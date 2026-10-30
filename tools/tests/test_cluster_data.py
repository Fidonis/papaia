"""Backup, restore, upgrade and add-ons of a distributed installation."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation, run_cli
from test_topology import FULL, dmz_split, write_topology

from lib import (
    backup,
    cli,
    cluster,
    cluster_data,
    deployment,
    executor,
    migrations,
    node_shell,
    nodes,
    topology,
)
from lib.executor import Result

FIXTURES = Path(__file__).parent / "fixtures"


class FakeNode:
    """A node's executor. Writes a small archive for `backup-stream`, records uploads."""

    def __init__(self, name: str, log: list, *, missing=(), fail=()):
        self.name = name
        self.node = topology.Node(name)
        self.log = log
        self.missing = set(missing)
        self.fail = set(fail)
        self.uploads: dict[str, bytes] = {}

    def run(self, command, *, stdin=None, capture=False, stdout=None, timeout=None):
        self.log.append((self.name, list(command)))
        key = " ".join(command)
        if any(item in key for item in self.fail):
            return Result(5, "", "boom")
        if command[0] == "backup-stream":
            if command[-1] in self.missing:
                return Result(node_shell.EXIT_MISSING, "", "no volume")
            stdout.write(f"archive of {key} on {self.name}".encode())
        if command[0] == "restore-put":
            data = stdin.read() if hasattr(stdin, "read") else stdin
            self.uploads[key] = data
        return Result(0, "", "")


@pytest.fixture
def distributed(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    run_cli(inst.repo, inst.config, "render")
    return inst


@pytest.fixture
def fake(distributed, monkeypatch):
    log: list = []
    fakes = {name: FakeNode(name, log) for name in ("internal", "edge")}
    monkeypatch.setattr(executor, "for_node", lambda topo, name, **kw: fakes[name])
    monkeypatch.setattr(cluster, "push", lambda c, names: log.append(("push", list(names))))

    def archive(found, snapshot, archive_name):
        (snapshot / archive_name).write_bytes(b"config archive")
        return True

    monkeypatch.setattr(cluster_data, "_archive_config_dir", archive)
    monkeypatch.setattr(cluster_data, "_restore_config_dir", lambda *a: True)
    return {"log": log, "nodes": fakes, "inst": distributed}


def load(inst: Installation) -> cluster.Cluster:
    return cluster.load(inst.config, inst.repo)


# ─────────────────────────────────────────────────────────────────────────
# plan
# ─────────────────────────────────────────────────────────────────────────


def test_every_volume_belongs_to_the_node_of_its_service(distributed, tmp_path):
    plan = cluster_data.build_plan(load(distributed), tmp_path / "backups")
    by_source = {a.source: a.node for a in plan.artifacts if a.kind == "volume"}
    assert by_source["papaia_keycloak-postgresql"] == "edge"
    assert by_source["papaia_litellm-postgresql"] == "edge"
    assert by_source["papaia_librechat-mongodb"] == "internal"
    assert by_source["papaia_qdrant-storage"] == "internal"
    configdir = [a for a in plan.artifacts if a.kind == "configdir"]
    assert len(configdir) == 1 and configdir[0].node == "internal"


def test_the_state_of_a_remote_node_is_backed_up(distributed, tmp_path):
    plan = cluster_data.build_plan(load(distributed), tmp_path / "backups")
    states = [a for a in plan.artifacts if a.kind == cluster_data.NODESTATE]
    assert {a.node for a in states} == {"edge"}
    assert {a.module for a in states} == {"nginx"}
    assert len(states) == 2  # the proxy's database and its certificates


def test_a_node_selector_takes_that_node_alone(distributed, tmp_path):
    plan = cluster_data.build_plan(load(distributed), tmp_path / "b", only="node:edge")
    assert plan.artifacts and {a.node for a in plan.artifacts} == {"edge"}
    assert not any(a.kind == "configdir" for a in plan.artifacts)
    assert plan.scope == ["node:edge"]


def test_a_selection_that_matches_nothing_is_refused(distributed, tmp_path):
    with pytest.raises(backup.SelectionError):
        cluster_data.build_plan(load(distributed), tmp_path / "b", only="node:dmz")


# ─────────────────────────────────────────────────────────────────────────
# backup
# ─────────────────────────────────────────────────────────────────────────


def test_a_backup_streams_every_node_into_one_restore_point(fake, tmp_path):
    inst = fake["inst"]
    backup_dir = tmp_path / "backups"
    backup_id, outcome = cluster_data.run_backup(load(inst), backup_dir)
    assert outcome == "ok"
    snapshot = backup_dir / backup_id
    manifest = yaml.safe_load((snapshot / "manifest.yaml").read_text())
    assert manifest["nodes"] == ["internal", "edge"]
    assert manifest["topology"]["controller"] == "internal"
    assert all(a.get("node") for a in manifest["artifacts"])
    keycloak = next(a for a in manifest["artifacts"] if a["target"] == "papaia_keycloak-postgresql")
    assert (snapshot / keycloak["archive"]).read_bytes().endswith(b"on edge")
    entry = backup.load_index(backup_dir)["backups"][0]
    assert entry["nodes"] == ["internal", "edge"] and entry["result"] == "ok"
    streamed = {node for node, cmd in fake["log"] if cmd[0] == "backup-stream"}
    assert streamed == {"internal", "edge"}


def test_a_volume_that_does_not_exist_is_skipped_not_failed(fake, tmp_path):
    fake["nodes"]["internal"].missing = {"papaia_localai-models"}
    backup_id, outcome = cluster_data.run_backup(load(fake["inst"]), tmp_path / "b")
    assert outcome == "ok"
    manifest = yaml.safe_load((tmp_path / "b" / backup_id / "manifest.yaml").read_text())
    assert "papaia_localai-models" not in {a["target"] for a in manifest["artifacts"]}


def test_a_node_that_fails_makes_the_point_partial(fake, tmp_path):
    fake["nodes"]["edge"].fail = {"backup-stream volume"}
    _backup_id, outcome = cluster_data.run_backup(load(fake["inst"]), tmp_path / "b")
    assert outcome == "partial"


def test_a_single_host_manifest_is_unchanged_by_the_node_field(tmp_path):
    plan = backup.BackupPlan(
        snapshot=tmp_path, backup_id="x", core_project="p", config_dir=tmp_path
    )
    plan.artifacts.append(backup.Artifact("volume", "volumes/a.tar.gz", "a", "core"))
    manifest = backup.write_manifest(
        tmp_path, plan, {"volumes/a.tar.gz": "ok"}, papaia_version="1.0.0"
    )
    assert "node" not in manifest["artifacts"][0]
    assert "nodes" not in manifest


# ─────────────────────────────────────────────────────────────────────────
# restore
# ─────────────────────────────────────────────────────────────────────────


def test_restoring_one_node_leaves_the_others_untouched(fake, tmp_path):
    inst = fake["inst"]
    backup_dir = tmp_path / "backups"
    backup_id, _ = cluster_data.run_backup(load(inst), backup_dir)
    fake["log"].clear()
    restore_id, outcome = cluster_data.run_restore(
        load(inst), backup_dir, restore_point=backup_id, only="node:edge"
    )
    assert (restore_id, outcome) == (backup_id, "ok")
    assert {node for node, _cmd in fake["log"]} == {"edge"}
    commands = [cmd for _node, cmd in fake["log"]]
    first_put = next(i for i, c in enumerate(commands) if c[0] == "restore-put")
    assert commands[0][0] == "compose-down" and first_put > 0
    assert commands[-1][0] == "compose-up"
    upload = fake["nodes"]["edge"].uploads["restore-put volume papaia_keycloak-postgresql"]
    assert upload.endswith(b"on edge")


def test_a_whole_restore_stops_everything_puts_the_config_back_and_starts(fake, tmp_path):
    inst = fake["inst"]
    backup_dir = tmp_path / "backups"
    backup_id, _ = cluster_data.run_backup(load(inst), backup_dir)
    fake["log"].clear()
    _id, outcome = cluster_data.run_restore(load(inst), backup_dir, restore_point=backup_id)
    assert outcome == "ok"
    kinds = [cmd[0] if node != "push" else "push" for node, cmd in fake["log"]]
    assert kinds.index("compose-down") < kinds.index("push") < kinds.index("restore-put")
    assert kinds[-1] in ("compose-up", "hook")


def test_a_single_host_restore_point_is_refused(fake, tmp_path):
    inst = fake["inst"]
    backup_dir = tmp_path / "backups"
    snapshot = backup_dir / "2026-01-01_00-00-00"
    snapshot.mkdir(parents=True)
    (snapshot / "manifest.yaml").write_text(
        yaml.safe_dump({"version": 2, "id": snapshot.name, "artifacts": []})
    )
    backup.save_index(
        backup_dir,
        {
            "version": 1,
            "backups": [
                {"id": snapshot.name, "created_at": "2026-01-01T00:00:00Z", "result": "ok"}
            ],
        },
    )
    with pytest.raises(backup.ScopedRestorePointError, match="single host"):
        cluster_data.run_restore(load(inst), backup_dir, restore_point=snapshot.name)


def test_the_manager_is_never_restored_over_itself(fake, tmp_path):
    inst = fake["inst"]
    backup_id, _ = cluster_data.run_backup(load(inst), tmp_path / "b")
    with pytest.raises(backup.SelectionError):
        cluster_data.run_restore(
            load(inst), tmp_path / "b", restore_point=backup_id, only="module:manager"
        )


def test_the_restore_plan_names_what_it_overwrites(fake, tmp_path, capsys):
    inst = fake["inst"]
    backup_id, _ = cluster_data.run_backup(load(inst), tmp_path / "b")
    capsys.readouterr()
    code = cli.main(
        [
            "--repo-root",
            str(inst.repo),
            "--config-dir",
            str(inst.config),
            "cluster-restore",
            "--plan",
            f"--backup-dir={tmp_path / 'b'}",
            f"--restore-point={backup_id}",
            "--only=node:edge",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert f"ID\t{backup_id}" in out
    assert "WILL\tnode edge:" in out and "node internal" not in out


# ─────────────────────────────────────────────────────────────────────────
# upgrade
# ─────────────────────────────────────────────────────────────────────────


def write_migration(inst: Installation, name: str, body: str) -> None:
    directory = inst.repo / "tools" / "migrations"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body, encoding="utf-8")


def test_a_migration_names_the_service_whose_data_it_reshapes(tmp_path):
    path = tmp_path / "1.9.0__x.sh"
    path.write_text("#!/usr/bin/env bash\n# papaia-migration: runs-with=keycloak\n")
    assert migrations._parse_name(path).runs_with == "keycloak"
    shipped = Path(__file__).resolve().parents[1] / "migrations"
    found = {m.id: m for m in migrations.discover(shipped.parents[1])}
    assert found["1.5.0__librechat-tenant-indexes"].runs_with == "librechat"


def test_migrations_run_where_their_data_lives_and_the_ledger_says_where(fake, monkeypatch):
    inst = fake["inst"]
    write_migration(
        inst,
        "9.9.0__keycloak-thing.sh",
        "#!/usr/bin/env bash\n# papaia-migration: runs-with=keycloak\nexit 0\n",
    )
    write_migration(inst, "9.9.0__config-thing.sh", "#!/usr/bin/env bash\nexit 0\n")
    local_runs: list[str] = []
    monkeypatch.setattr(cluster_data, "_run_local", lambda c, m, f, t: local_runs.append(m.id) or 0)
    assert cluster_data.run_migrations(load(inst), "9.8.0", "9.9.0") == 0
    remote = [cmd for node, cmd in fake["log"] if node == "edge"]
    assert remote == [["upgrade-step", "migrate", "9.9.0__keycloak-thing", "9.8.0", "9.9.0"]]
    assert local_runs == ["9.9.0__config-thing"]
    ledger = {e["id"]: e for e in migrations.load_state(inst.config)["applied"]}
    assert ledger["9.9.0__keycloak-thing"]["node"] == "edge"
    assert ledger["9.9.0__config-thing"]["node"] == "internal"


def test_a_failing_node_migration_stops_the_run(fake, monkeypatch, capsys):
    inst = fake["inst"]
    fake["nodes"]["edge"].fail = {"upgrade-step"}
    write_migration(inst, "9.9.0__keycloak-thing.sh", "# papaia-migration: runs-with=keycloak\n")
    assert cluster_data.run_migrations(load(inst), "9.8.0", "9.9.0") == 3
    assert "failed on node 'edge'" in capsys.readouterr().err
    assert migrations.load_state(inst.config)["applied"] == []


def test_the_upgrade_lock_blocks_until_cleared(distributed, capsys):
    found = load(distributed)
    assert cluster.skew(found) is None
    cluster.set_lock(found, from_version="1.8.0", to_version="1.9.0", restore_point="X")
    reason = cluster.skew(found)
    assert "has not finished" in reason and "--restore-point=X" in reason
    argv = ["--repo-root", str(distributed.repo), "--config-dir", str(distributed.config)]
    assert cli.main([*argv, "cluster-lock"]) == 2
    cluster.clear_lock(found)
    assert cli.main([*argv, "cluster-lock"]) == 0


def test_a_node_on_another_release_locks_the_installation(distributed):
    found = load(distributed)
    nodes.record_state(distributed.config, "edge", release="0.1.0")
    assert "edge runs 0.1.0" in cluster.skew(found)


BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize("in_upgrade, expected", [("0", 2), ("1", 0)])
def test_the_lock_check_steps_aside_for_the_upgrade(tmp_path, in_upgrade, expected):
    lifecycle = Path(__file__).resolve().parents[1] / "lib" / "sh" / "lifecycle.sh"
    script = (
        "set -euo pipefail\n"
        "py_cli() { return 2; }\n"
        f'source "{lifecycle}"\n'
        f"UPGRADE_IN_PROGRESS={in_upgrade}\n"
        "_cluster_require_unlocked\n"
    )
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert done.returncode == expected


# ─────────────────────────────────────────────────────────────────────────
# add-ons
# ─────────────────────────────────────────────────────────────────────────


def make_addon(tmp_path: Path, name: str, attach: list[str]) -> Path:
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    (path / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            {
                "name": name,
                "version": "1.0.0",
                "papaia_compat": ">=0.1.0",
                "networks": {"app_network": f"papaia-{name}-net", "attach": attach},
            }
        )
    )
    (path / ".env.example").write_text("SETTING=1\n")
    (path / "docker-compose.yml").write_text(
        yaml.safe_dump(
            {
                "services": {name: {"image": "example/x:1", "volumes": [f"{name}-data:/data"]}},
                "volumes": {f"{name}-data": {}},
            }
        )
    )
    return path


def install(inst: Installation, name: str, path: Path, *extra: str) -> int:
    return cli.main(
        [
            "--repo-root",
            str(inst.repo),
            "--config-dir",
            str(inst.config),
            "addon-install",
            f"--name={name}",
            f"--path={path}",
            *extra,
        ]
    )


def test_an_addon_that_spans_two_nodes_is_not_placeable(distributed, tmp_path, capsys):
    path = shutil.copytree(FIXTURES / "addon-paperless", tmp_path / "paperless")
    assert install(distributed, "paperless", path) == 2
    err = capsys.readouterr().err
    assert "not placeable" in err and "nginx (edge)" in err and "librechat (internal)" not in err
    assert not deployment.load(distributed.config).get("addons")
    # --force is a policy override; no policy makes a network span two daemons.
    assert install(distributed, "paperless", path, "--force") == 2


def test_an_addon_goes_to_the_node_of_the_services_it_attaches_to(distributed, tmp_path):
    path = make_addon(tmp_path, "docs", ["librechat"])
    assert install(distributed, "docs", path) == 0
    entry = deployment.load(distributed.config)["addons"][0]
    assert entry["node"] == "internal"


def test_an_addon_placed_on_a_remote_node_travels_in_its_bundle(distributed, tmp_path):
    path = make_addon(tmp_path, "edgecache", ["litellm"])
    assert install(distributed, "edgecache", path, "--node=edge") == 0
    run_cli(distributed.repo, distributed.config, "render")
    bundle = topology.bundle_dir(distributed.config, "edge")
    assert (bundle / "addons/edgecache/src/docker-compose.yml").is_file()
    assert (bundle / "addons/edgecache/.env").is_file()
    assert (bundle / "overrides/docker-compose.edgecache.override.yml").is_file()
    node_manifest = yaml.safe_load((bundle / "deployment.yaml").read_text())
    assert node_manifest["addons"][0]["path"] == "/srv/papaia-node/config/addons/edgecache/src"
    internal = topology.bundle_dir(distributed.config, "internal")
    assert not (internal / "addons").exists()
    plan = cluster_data.build_plan(load(distributed), tmp_path / "b", only="addon:edgecache")
    assert [(a.source, a.node) for a in plan.artifacts] == [("edgecache_edgecache-data", "edge")]


def test_node_is_refused_on_a_single_host(tmp_path, capsys):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    path = make_addon(tmp_path, "docs", ["librechat"])
    assert install(inst, "docs", path, "--node=edge") == 2
    assert "one host" in capsys.readouterr().err


def test_addon_check_reports_the_placement(distributed, tmp_path, capsys):
    path = make_addon(tmp_path, "docs", ["librechat"])
    install(distributed, "docs", path)
    manifest = deployment.load(distributed.config)
    manifest["addons"][0]["node"] = "edge"
    deployment.save(distributed.config, manifest)
    capsys.readouterr()
    code = cli.main(
        [
            "--repo-root",
            str(distributed.repo),
            "--config-dir",
            str(distributed.config),
            "addon-check",
            "--json",
        ]
    )
    rows = json.loads(capsys.readouterr().out)
    assert code == 2
    assert rows[0]["axis"] == "placement" and "not placeable on 'edge'" in rows[0]["reason"]


def test_addons_start_on_their_node_before_the_core(fake, tmp_path):
    inst = fake["inst"]
    path = make_addon(tmp_path, "edgecache", ["litellm"])
    install(inst, "edgecache", path, "--node=edge")
    assert cluster.start(load(inst), addons=True) == 0
    commands = [(n, c) for n, c in fake["log"] if n != "push"]
    addon_up = commands.index(("edge", ["compose-up", "addon:edgecache"]))
    first_core = next(
        i
        for i, (_n, c) in enumerate(commands)
        if c[0] == "compose-up" and c[1] not in ("link-gateway",) and not c[1].startswith("addon:")
    )
    assert addon_up < first_core


# ─────────────────────────────────────────────────────────────────────────
# the shim's side
# ─────────────────────────────────────────────────────────────────────────


def edge_shell(inst: Installation) -> node_shell.Context:
    ctx = node_shell.context_from_args(
        ["--repo-root", str(inst.repo), f"--controller-config={inst.config}", "--node=edge"]
    )
    ctx.run = lambda argv, **kw: 0
    return ctx


def test_the_shim_only_streams_its_own_node(distributed, capsys):
    ctx = edge_shell(distributed)
    assert node_shell.execute(ctx, "backup-stream volume papaia_librechat-mongodb") == 2
    assert "does not belong to node 'edge'" in capsys.readouterr().err
    assert node_shell.execute(ctx, "backup-stream state 7") == 2
    assert node_shell.execute(ctx, "backup-stream binddir nothing 0") == 2
    assert node_shell.execute(ctx, "restore-put volume ../../etc") == 2
    assert node_shell.execute(ctx, "backup-stream volume") == 2


def test_the_shim_only_runs_migrations_of_its_own_services(distributed, capsys):
    write_migration(distributed, "9.9.0__chat.sh", "# papaia-migration: runs-with=librechat\n")
    ctx = edge_shell(distributed)
    assert node_shell.execute(ctx, "upgrade-step migrate 9.9.0__chat 9.8.0 9.9.0") == 2
    assert "does not run on 'edge'" in capsys.readouterr().err
    assert node_shell.execute(ctx, "upgrade-step migrate 9.9.0__none 9.8.0 9.9.0") == 2
    assert node_shell.execute(ctx, "upgrade-step migrate 9.9.0__chat x y") == 2


def test_an_addon_target_must_be_placed_on_the_node(distributed, capsys):
    ctx = edge_shell(distributed)
    assert node_shell.execute(ctx, "compose-up addon:paperless") == 2
    assert "does not run on node 'edge'" in capsys.readouterr().err
    assert node_shell.execute(ctx, "compose-up addon:x keycloak") == 2


class Sink:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, chunk: bytes) -> None:
        self.data += chunk

    def close(self) -> None:
        self.closed = True


def test_restore_put_streams_into_docker(distributed, monkeypatch):
    ctx = edge_shell(distributed)
    started = {}

    class Proc:
        def __init__(self, argv, stdin):
            started["argv"] = argv
            self.stdin = Sink()
            started["stdin"] = self.stdin

        def wait(self):
            return 0

        def kill(self):
            started["killed"] = True

    monkeypatch.setattr(node_shell.subprocess, "Popen", Proc)
    monkeypatch.setattr(
        node_shell.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="", stderr=""),
    )
    ctx.stdin = io.BytesIO(b"archive bytes")
    assert node_shell.verb_restore_put(ctx, ["volume", "papaia_keycloak-postgresql"]) == 0
    assert started["argv"][:4] == ["docker", "run", "--rm", "-i"]
    assert "papaia_keycloak-postgresql:/target" in started["argv"]
    assert started["stdin"].data == b"archive bytes"
