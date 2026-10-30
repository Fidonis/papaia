"""Backup, restore and upgrade migrations of a distributed installation.

**Backup.** One restore point holds the whole installation and lives on the controller, in
the same catalogue (`$PAPAIA_BACKUP_DIR/backup.yaml`) as on one host. Its artifacts:

* the controller's configuration directory (the full tree: every node's bundle, the CA
  keys, the SSH keys), archived on the controller;
* every named volume of every node, streamed from the node through its executor
  (`backup-stream volume NAME`; the node pauses the writers for the length of the archive);
* the state a remote node keeps in its own config directory (the proxy's database and
  certificates), and the data directories of add-ons placed on a node.

Each artifact carries the `node` it came from, and `--only=node:NAME` selects one node.
Archives are written straight into the restore point; nothing stays at the edge, and a
restore needs only the controller and the nodes it touches.

The result is not a snapshot of one moment across nodes. The nodes are archived one after
another, so Keycloak's database and LibreChat's can come from points a few minutes apart.
That is the same as restoring one of them on its own, and it is documented as such.

**Restore.** A whole restore stops every node, puts the controller's configuration back,
renders and hands every node its bundle again, writes back each node's data and starts the
installation. A scoped one (`--only`, `node:NAME` among the selectors) stops only the
services whose data it replaces, on their nodes, and starts them again: the other nodes are
not touched. Restore points of a single host are refused here, and the other way round.

**Upgrade migrations.** A migration that reshapes a service's data names the service
(`# papaia-migration: runs-with=librechat`) and runs on that service's node; the others run
on the controller. The ledger records where each one ran.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import backup, common, envtree, migrations, nodes, topology
from .cluster import Cluster, ClusterError, _say
from .topology import CATALOGUE

DISTRIBUTED_SELECTOR_KINDS = (*backup.SELECTOR_KINDS, "node")
NODESTATE = "nodestate"


# ─────────────────────────────────────────────────────────────────────────
# plan
# ─────────────────────────────────────────────────────────────────────────


def _node_manifest(cluster: Cluster, name: str) -> dict:
    import json

    path = topology.bundle_dir(cluster.config_dir, name) / topology.NODE_MANIFEST
    if not path.is_file():
        raise ClusterError(f"node '{name}' has no bundle; run 'papaia-ctl start' first")
    return json.loads(path.read_text(encoding="utf-8"))


def _service_of_profiles(profiles: list[str]) -> str:
    for profile in profiles:
        service = topology.service_of_profile(profile)
        if service:
            return service
    return ""


def build_plan(
    cluster: Cluster, backup_dir: Path, *, only: str | None = None, now: datetime | None = None
) -> backup.BackupPlan:
    from . import deployment

    project = (
        common.parse_env_file(cluster.config_dir / ".env").get("COMPOSE_PROJECT_NAME") or "papaia"
    )
    stamp = (now or datetime.now()).strftime(backup._ID_FORMAT)
    plan = backup.BackupPlan(
        snapshot=backup_dir / stamp,
        backup_id=stamp,
        core_project=project,
        config_dir=cluster.config_dir,
    )
    controller = cluster.topology.controller
    plan.artifacts.append(
        backup.Artifact(
            kind="configdir",
            archive=backup.CONFIG_ARCHIVE,
            source=str(cluster.config_dir),
            owner="core",
            project=project,
            node=controller,
        )
    )
    owners = backup.resolve_core_volume_owners(cluster.repo_root)
    deployed = deployment.load(cluster.config_dir)
    for name, node in cluster.topology.nodes.items():
        manifest = _node_manifest(cluster, name)
        profiles = set(manifest.get("profiles") or [])
        for key, owner in owners.items():
            if not profiles.intersection(owner.profiles):
                continue
            volume = f"{project}_{key}"
            plan.artifacts.append(
                backup.Artifact(
                    kind="volume",
                    archive=f"volumes/{volume}.tar.gz",
                    source=volume,
                    owner="core",
                    project=project,
                    module=owner.modules[0] if owner.modules else "",
                    services=list(owner.services),
                    profiles=list(owner.profiles),
                    node=name,
                )
            )
        if not node.is_local:
            for index, rel in enumerate(manifest.get("state_dirs") or []):
                mounting = [
                    s
                    for s in topology.services_of(cluster.repo_root, manifest.get("services") or [])
                    if rel in s.config_mounts()
                ]
                service_profiles = sorted({p for s in mounting for p in s.profiles} & profiles)
                plan.artifacts.append(
                    backup.Artifact(
                        kind=NODESTATE,
                        archive=f"nodes/{name}/state-{index}.tar.gz",
                        source=str(index),
                        owner="core",
                        project=project,
                        module=_service_of_profiles(service_profiles),
                        services=[s.name for s in mounting],
                        profiles=service_profiles,
                        node=name,
                    )
                )
        for entry in deployment.active_addons(deployed):
            addon = str(entry.get("name") or "")
            if not addon or topology.addon_node(cluster.topology, entry) != name:
                continue
            path = deployment.resolve_addon_path(entry, cluster.repo_root)
            plan.addons.append(addon)
            for key in backup._top_level_volumes(path / "docker-compose.yml"):
                volume = f"{path.name}_{key}"
                plan.artifacts.append(
                    backup.Artifact(
                        kind="volume",
                        archive=f"volumes/{volume}.tar.gz",
                        source=volume,
                        owner=f"addon:{addon}",
                        project=path.name,
                        module=addon,
                        node=name,
                    )
                )
            env = common.parse_env_file(cluster.config_dir / ".env")
            env.update(common.parse_env_file(cluster.config_dir / "addons" / addon / ".env"))
            for index, _directory in enumerate(
                backup.addon_bind_dirs(path, env, cluster.config_dir)
            ):
                plan.artifacts.append(
                    backup.Artifact(
                        kind="binddir",
                        archive=f"binds/{name}--{addon}-{index}.tar.gz",
                        source=f"{addon}:{index}",
                        owner=f"addon:{addon}",
                        project=path.name,
                        module=addon,
                        node=name,
                    )
                )
    if only:
        plan = _scope(plan, only)
    return plan


def _scope(plan: backup.BackupPlan, raw: str) -> backup.BackupPlan:
    parsed = backup.parse_selectors(raw, DISTRIBUTED_SELECTOR_KINDS)
    candidates = [a for a in plan.artifacts if a.kind != "configdir"]
    unmatched = [
        f"{kind}:{name}"
        for kind, name in parsed
        if not any(backup._matches(a, kind, name) for a in candidates)
    ]
    if unmatched:
        raise backup.SelectionError(
            f"Nothing in this installation matches {', '.join(unmatched)}: nothing to back up."
        )
    plan.artifacts = [
        a for a in candidates if any(backup._matches(a, kind, name) for kind, name in parsed)
    ]
    plan.addons = sorted(
        {a.owner.split(":", 1)[1] for a in plan.artifacts if a.owner.startswith("addon:")}
    )
    plan.scope = [f"{kind}:{name}" for kind, name in parsed]
    return plan


def _stream_args(artifact: backup.Artifact) -> list[str]:
    if artifact.kind == "volume":
        return ["volume", artifact.source]
    if artifact.kind == NODESTATE:
        return ["state", artifact.source]
    if artifact.kind == "binddir":
        addon, _, index = artifact.source.partition(":")
        return ["binddir", addon, index]
    raise ClusterError(f"cannot stream an artifact of kind {artifact.kind!r}")


# ─────────────────────────────────────────────────────────────────────────
# backup
# ─────────────────────────────────────────────────────────────────────────


def _archive_config_dir(cluster: Cluster, snapshot: Path, archive: str) -> bool:
    """The controller's configuration directory, through a throwaway container as on one
    host: files the services wrote belong to their users, not to this one."""
    done = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{cluster.config_dir}:/src:ro",
            "-v",
            f"{snapshot}:/backup",
            backup_image(),
            "tar",
            "czf",
            f"/backup/{archive}",
            "-C",
            "/src",
            ".",
        ],
        check=False,
    )
    return done.returncode == 0


def backup_image() -> str:
    from . import node_shell

    return node_shell.BACKUP_IMAGE


def _log(backup_dir: Path, op: str, backup_id: str, result: str, details: str) -> None:
    line = (
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {op:<7} id={backup_id}"
        f" result={result} {details}\n"
    )
    try:
        common.ensure_dir(backup_dir)
        with open(backup_dir / backup.LOG_NAME, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass


def run_backup(
    cluster: Cluster,
    backup_dir: Path,
    *,
    only: str | None = None,
    retention_days: int | None = None,
) -> tuple[str, str]:
    """Take a restore point of the whole installation (or of `only`). Returns (id, result)."""
    started = time.monotonic()
    plan = build_plan(cluster, backup_dir, only=only)
    common.ensure_dir(plan.snapshot / "volumes")
    backup.write_plan(plan)
    if plan.scope:
        _say(f"Scope: {', '.join(plan.scope)} (the configuration directory is not included)")
    results: dict[str, str] = {}
    for artifact in plan.artifacts:
        target = plan.snapshot / artifact.archive
        common.ensure_dir(target.parent)
        if artifact.kind == "configdir":
            _say(f"  config dir {artifact.source} ({artifact.node})")
            ok = _archive_config_dir(cluster, plan.snapshot, artifact.archive)
            results[artifact.archive] = "ok" if ok else "failed"
            continue
        _say(f"  {artifact.kind} {artifact.source} ({artifact.node}, {artifact.owner})")
        with open(target, "wb") as out:
            result = cluster.executor(artifact.node).run(
                ["backup-stream", *_stream_args(artifact)], stdout=out, capture=True
            )
        if result.returncode == 0:
            results[artifact.archive] = "ok"
            continue
        target.unlink(missing_ok=True)
        from . import node_shell

        if result.returncode == node_shell.EXIT_MISSING:
            plan.skipped.append(f"{artifact.node}:{artifact.source}")
            results[artifact.archive] = "skipped"
            continue
        reason = (result.stderr or "").strip().splitlines()
        print(
            f"WARNING: failed: {artifact.archive} ({reason[-1] if reason else result.returncode})",
            file=sys.stderr,
            flush=True,
        )
        results[artifact.archive] = "failed"

    attempted = [a for a in plan.artifacts if results.get(a.archive) != "skipped"]
    failed = [a for a in attempted if results.get(a.archive) != "ok"]
    if not attempted or len(failed) == len(attempted):
        outcome = "failed"
    elif failed:
        outcome = "partial"
    else:
        outcome = "ok"
    manifest = backup.write_manifest(
        plan.snapshot,
        plan,
        results,
        papaia_version=envtree.resolve_platform_version(cluster.repo_root),
    )
    # What makes the point a distributed one: the nodes and the topology it was taken of.
    manifest["nodes"] = list(cluster.topology.nodes)
    manifest["topology"] = cluster.topology.to_dict()
    common.atomic_write(
        plan.snapshot / backup.MANIFEST_NAME,
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False, allow_unicode=True),
    )
    entry = backup.record_backup(backup_dir, plan, manifest, outcome)
    index = backup.load_index(backup_dir)
    for item in index["backups"]:
        if item.get("id") == entry["id"]:
            item["nodes"] = list(cluster.topology.nodes)
    backup.save_index(backup_dir, index)
    (plan.snapshot / backup.PLAN_NAME).unlink(missing_ok=True)
    for name in plan.skipped:
        print(f"WARNING: does not exist, skipped: {name}", file=sys.stderr, flush=True)
    _log(
        backup_dir,
        "backup",
        plan.backup_id,
        outcome,
        f"artifacts={len(attempted) - len(failed)}/{len(attempted)} size_mb={entry['size_mb']}"
        f" duration={int(time.monotonic() - started)}s nodes={','.join(cluster.topology.nodes)}"
        + (f" scope={','.join(plan.scope)}" if plan.scope else ""),
    )
    if retention_days is not None:
        for removed in backup.prune(backup_dir, retention_days):
            _say(f"  removed restore point: {removed}")
            _log(backup_dir, "prune", removed, "ok", f"reason=retention days={retention_days}")
    return plan.backup_id, outcome


# ─────────────────────────────────────────────────────────────────────────
# restore
# ─────────────────────────────────────────────────────────────────────────


def _restore_config_dir(cluster: Cluster, snapshot: Path, archive: str) -> bool:
    done = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            f"ARCHIVE={archive}",
            "-v",
            f"{cluster.config_dir}:/target",
            "-v",
            f"{snapshot}:/backup",
            backup_image(),
            "sh",
            "-c",
            "rm -rf /target/..?* /target/.[!.]* /target/* 2>/dev/null;"
            ' tar xzf "/backup/$ARCHIVE" -C /target',
        ],
        check=False,
    )
    return done.returncode == 0


def resolve(cluster: Cluster, backup_dir: Path, restore_point: str | None, only: str | None):
    """(entry, snapshot dir, manifest, artifacts to restore)."""
    entry, warnings = backup.resolve_restore_point(backup_dir, restore_point, whole_stack=not only)
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr, flush=True)
    snapshot = backup.snapshot_path(backup_dir, entry)
    manifest = backup.read_manifest(snapshot)
    if "nodes" not in manifest:
        raise backup.ScopedRestorePointError(
            f"Restore point {entry.get('id')} was taken of a single host; this installation"
            " is distributed. Restore it into a single-host installation."
        )
    artifacts = backup.manifest_artifacts(manifest)
    if only:
        parsed = backup.parse_selectors(only, DISTRIBUTED_SELECTOR_KINDS)
        chosen = [
            a
            for a in artifacts
            if a.kind != "configdir" and any(backup._matches(a, k, n) for k, n in parsed)
        ]
        if not chosen:
            raise backup.SelectionError(
                f"Nothing in restore point {entry.get('id')} matches {only}."
            )
        if any(backup.SELF_PROFILE in a.profiles for a in chosen):
            raise backup.SelectionError(
                f"Refusing a selection that resolves to the {backup.SELF_PROFILE!r} profile."
            )
        artifacts = chosen
    else:
        backup.require_whole_stack(manifest)
    for artifact in artifacts:
        if artifact.kind == "volume":
            backup.validate_target(artifact, cluster.config_dir)
    return entry, snapshot, manifest, artifacts


def describe(artifacts: list[backup.Artifact], *, scoped: bool) -> list[str]:
    lines = []
    if not scoped:
        lines.append("the configuration directory of the controller")
    by_node: dict[str, list[str]] = {}
    for artifact in artifacts:
        if artifact.kind == "configdir":
            continue
        by_node.setdefault(artifact.node, []).append(
            artifact.source if artifact.kind == "volume" else f"{artifact.kind} {artifact.source}"
        )
    for node, items in by_node.items():
        lines.append(f"node {node}: {', '.join(items)}")
    return lines


def _affected(artifacts: list[backup.Artifact]) -> dict[str, tuple[list[str], list[str]]]:
    """node -> (catalogue services, add-ons) whose containers a scoped restore bounces."""
    found: dict[str, tuple[list[str], list[str]]] = {}
    for artifact in artifacts:
        services, addons = found.setdefault(artifact.node, ([], []))
        if artifact.owner.startswith("addon:"):
            name = artifact.owner.split(":", 1)[1]
            if name not in addons:
                addons.append(name)
            continue
        for profile in artifact.profiles:
            service = topology.service_of_profile(profile)
            if service and service not in services:
                services.append(service)
    return found


def _put(cluster: Cluster, snapshot: Path, artifact: backup.Artifact) -> bool:
    path = snapshot / artifact.archive
    if not path.is_file():
        print(
            f"WARNING: archive missing in the restore point: {artifact.archive}",
            file=sys.stderr,
            flush=True,
        )
        return False
    _say(f"  {artifact.kind} {artifact.source} on {artifact.node}")
    with open(path, "rb") as stream:
        result = cluster.executor(artifact.node).run(
            ["restore-put", *_stream_args(artifact)], stdin=stream
        )
    return result.ok


def run_restore(
    cluster: Cluster,
    backup_dir: Path,
    *,
    restore_point: str | None = None,
    only: str | None = None,
    no_restart: bool = False,
) -> tuple[str, str]:
    """Restore a point of the whole installation, or the selected part of it."""
    from . import cluster as cluster_module

    started = time.monotonic()
    entry, snapshot, _manifest, artifacts = resolve(cluster, backup_dir, restore_point, only)
    restore_id = str(entry.get("id"))
    node_artifacts = [a for a in artifacts if a.kind != "configdir"]
    failed = 0

    if only:
        affected = _affected(node_artifacts)
        if not no_restart:
            for node, (services, addons) in affected.items():
                for addon in addons:
                    cluster.executor(node).run(["compose-down", f"addon:{addon}"])
                if services:
                    _say(f"node {node}: removing {', '.join(services)}")
                    if cluster.executor(node).run(["compose-down", *services]).returncode != 0:
                        raise ClusterError(f"node '{node}': could not stop {', '.join(services)}")
        for artifact in node_artifacts:
            if not _put(cluster, snapshot, artifact):
                failed += 1
        if not no_restart:
            for node, (services, addons) in affected.items():
                for addon in addons:
                    cluster.executor(node).run(["compose-up", f"addon:{addon}"])
                if services:
                    ordered = sorted(services, key=lambda s: CATALOGUE[s].start_group)
                    _say(f"node {node}: starting {', '.join(ordered)}")
                    cluster.executor(node).run(["compose-up", *ordered])
    else:
        if not no_restart:
            _say("Stopping and removing the containers of every node...")
            cluster_module.stop(cluster, clean_up=True, addons=True)
        configdir = next((a for a in artifacts if a.kind == "configdir"), None)
        if configdir is not None:
            _say(f"  config dir {cluster.config_dir}")
            if not _restore_config_dir(cluster, snapshot, configdir.archive):
                raise ClusterError("the configuration directory could not be restored")
        # The restored tree decides from here on: its topology, its bundles.
        restored = cluster_module.load(cluster.config_dir, cluster.repo_root)
        from . import cli

        if cli._project_bundles(restored.config_dir, restored.repo_root) != 0:
            raise ClusterError("the restored configuration does not render")
        cluster_module.push(restored, list(restored.topology.nodes))
        for artifact in node_artifacts:
            if not _put(restored, snapshot, artifact):
                failed += 1
        if not no_restart:
            cluster_module.start(restored, addons=True)

    total = len(node_artifacts)
    outcome = "ok" if failed == 0 else ("failed" if failed == total else "partial")
    _log(
        backup_dir,
        "restore-scoped" if only else "restore",
        restore_id,
        outcome,
        f"artifacts={total - failed}/{total} duration={int(time.monotonic() - started)}s",
    )
    return restore_id, outcome


# ─────────────────────────────────────────────────────────────────────────
# upgrade migrations
# ─────────────────────────────────────────────────────────────────────────


def run_migrations(cluster: Cluster, from_version: str, to_version: str) -> int:
    """The migrations due for `from` -> `to`, each where its data lives. Stops at the first
    failure; the ones before it are recorded and are skipped by the next run."""
    found = migrations.discover(cluster.repo_root)
    applied = migrations.applied_ids(migrations.load_state(cluster.config_dir))
    due = migrations.pending(found, from_version, to_version, applied)
    if not due:
        _say("No migrations to run.")
        return 0
    _say(f"Running {len(due)} migration(s)...")
    for migration in due:
        service = migration.runs_with
        node = cluster.topology.node_of(service) if service in cluster.active else ""
        if service and service not in CATALOGUE:
            node = ""
        started = time.monotonic()
        if node and node != cluster.topology.controller:
            _say(f"  {migration.id} (on {node})")
            code = (
                cluster.executor(node)
                .run(["upgrade-step", "migrate", migration.id, from_version, to_version])
                .returncode
            )
        else:
            node = cluster.topology.controller
            _say(f"  {migration.id}")
            code = _run_local(cluster, migration, from_version, to_version)
        if code != 0:
            print(
                f"ERROR: migration {migration.id} failed on node '{node}' (exit {code}).",
                file=sys.stderr,
                flush=True,
            )
            return 3
        migrations.record(
            cluster.config_dir,
            migration,
            duration_s=int(time.monotonic() - started),
            node=node,
        )
    return 0


def _run_local(cluster: Cluster, migration: migrations.Migration, frm: str, to: str) -> int:
    env = dict(os.environ)
    env.update(
        PAPAIA_CONFIG_DIR=str(cluster.config_dir),
        PAPAIA_REPO_ROOT=str(cluster.repo_root),
        PAPAIA_FROM_VERSION=frm,
        PAPAIA_TO_VERSION=to,
        PAPAIA_MIGRATION_VERSION=migration.version,
        PYTHONPATH=str(cluster.repo_root / "tools"),
    )
    interpreter = ["bash"] if migration.kind == "sh" else [sys.executable]
    return subprocess.run(
        [*interpreter, str(migration.path)], cwd=str(cluster.repo_root), env=env, check=False
    ).returncode


def check_ready_for_upgrade(cluster: Cluster) -> int:
    """Every node answers before an upgrade begins: stopping the world needs all of it."""
    unreachable = []
    for name in cluster.topology.nodes:
        data = nodes.node_version(cluster.config_dir, cluster.repo_root, name)
        if not data.get("reachable"):
            unreachable.append(f"{name} ({data.get('reason')})")
    if unreachable:
        print(
            f"ERROR: every node has to answer before an upgrade; unreachable: "
            f"{', '.join(unreachable)}. Nothing was changed.",
            file=sys.stderr,
        )
        return 3
    return 0
