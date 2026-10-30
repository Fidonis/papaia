"""Python entry point invoked by the `tools/papaia-ctl` bash dispatcher.

Bash owns interactive prompting (per the issue's stated split: "bash
handles arg-parsing, interactive prompts and docker compose calls; Python
handles all YAML / JSON / env / secret manipulation"). The flow is:

  1. bash calls `defaults` to learn sticky/derived values for its prompts.
  2. bash prompts the user (or reads flags / sticky values straight through
     in --non-interactive mode) and resolves every value itself.
  3. bash calls `setup` with the fully-resolved flags; this module never
     blocks on stdin -- it raises SetupError (exit code 3) if something
     required is still missing.

Invoked as `python3 -m lib.cli <subcommand> ...` with `tools/` on
PYTHONPATH (the bash dispatcher sets this up). Addon command handlers live
in cli_addon.py; this module keeps the parser, the dispatch, and the core
setup/render commands.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import (
    backup,
    cli_addon,
    cli_node,
    cluster,
    common,
    defaults,
    deployment,
    doctor,
    envtree,
    gen_override,
    gpu_detect,
    keycloak_role_sync,
    migrations,
    modules,
    nodes,
    npm_provision,
    render_core,
    reporting,
    resolve,
    secrets,
    status,
    topology,
    upgrade,
)


def _tristate(value: str | None) -> bool | None:
    if value is None:
        return None
    return value == "true"


def cmd_defaults(args: argparse.Namespace) -> int:
    """Print sticky/derived values as shell-safe KEY=VALUE lines, one per
    line, so the bash dispatcher can read them without a JSON parser."""
    out = defaults.compute_defaults(Path(args.config_dir), Path(args.repo_root))
    for key, value in out.items():
        print(f"{key}={value}")
    return 0


def cmd_localai_variants(args: argparse.Namespace) -> int:
    """Print the detected LocalAI image variants as shell-safe KEY=VALUE lines.

    Kept out of `defaults` on purpose: this probe forks nvidia-smi and docker,
    while `defaults` runs on every single papaia-ctl setup invocation. The
    wizard calls it only when it is about to ask the question."""
    for key, value in gpu_detect.detection_vars(gpu_detect.detect()).items():
        print(f"{key}={value}")
    return 0


def _requested_topology(
    args: argparse.Namespace, config_dir: Path
) -> topology.Topology | int | None:
    """The topology a distributed `setup` writes, None when there is nothing to write, or
    an exit code. Decided before anything is written: a refused request changes nothing.

    Only a new installation becomes distributed. One that has completed a setup before
    keeps its shape, whatever the flags say: moving a running installation's services to
    other machines is not something setup does."""
    asked = any(
        (args.topology, args.node, args.place, args.preset, args.controller, args.link_port,
         args.topology_file)
    )
    if not asked:
        return None
    root = common.parse_env_file(config_dir / ".env")
    existing = bool(root.get("PAPAIA_VERSION"))
    try:
        current = topology.load_config(config_dir)
    except topology.TopologyError as exc:
        print(f"ERROR: deployment.yaml: {exc}", file=sys.stderr)
        return 2
    if args.topology == topology.SINGLE and not (args.node or args.place or args.topology_file):
        if current.distributed:
            print(
                "ERROR: this installation is distributed; setup does not turn it back into"
                " a single host.",
                file=sys.stderr,
            )
            return 2
        return None
    try:
        if args.topology_file:
            requested = topology.from_file(Path(args.topology_file))
        else:
            requested = topology.from_flags(
                node_specs=args.node or [],
                places=args.place or [],
                preset=args.preset,
                controller=args.controller,
                link_port=args.link_port,
            )
    except topology.TopologyError as exc:
        print(f"ERROR: topology: {exc}", file=sys.stderr)
        return 2
    if existing and not current.distributed:
        print(
            "ERROR: --topology=distributed is for new installations, and"
            f" {config_dir} already holds one that runs on one host. Set the distributed"
            " installation up in a new config directory (--config-dir=PATH) and move the"
            " data over with 'papaia-ctl backup' and 'restore --only=...'. Nothing was"
            " changed.",
            file=sys.stderr,
        )
        return 2
    if existing and current.distributed:
        if requested.to_dict() != current.to_dict():
            print(
                "ERROR: setup does not change the topology of an existing installation."
                " Add or remove machines with 'papaia-ctl node add|remove'; moving a"
                " service with its data to another node is not supported. Nothing was"
                " changed.",
                file=sys.stderr,
            )
            return 2
        return None
    return requested


def cmd_setup(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    config_dir = Path(args.config_dir)

    requested_topology = _requested_topology(args, config_dir)
    if isinstance(requested_topology, int):
        return requested_topology

    fresh_init = not (config_dir / ".env").is_file()
    envtree.init(config_dir, repo_root, env_name=args.env, force=False)

    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    rag_was_enabled = "rag" in tree.get("", {}).get("COMPOSE_PROFILES", "").split(",")
    smtp_was_enabled = "smtp" in tree.get("", {}).get("COMPOSE_PROFILES", "").split(",")
    # Taken out of the environment so nothing started later inherits it. An empty
    # value means "keep the stored password" (--smtp-no-auth drops it).
    smtp_password = os.environ.pop("PAPAIA_SMTP_PASSWORD", "") or None
    setup_args = resolve.SetupArgs(
        config_dir=config_dir,
        env_name=args.env,
        host_ip=args.host_ip,
        app_host=args.app_host,
        auth_host=args.auth_host,
        librechat_host=args.librechat_host,
        litellm_host=args.litellm_host,
        localai_host=args.localai_host,
        manager_host=args.manager_host,
        qdrant_host=args.qdrant_host,
        npm_admin_host=args.npm_admin_host,
        auth_provider=args.auth_provider,
        oidc_issuer=args.oidc_issuer,
        reverse_proxy_provider=args.reverse_proxy_provider or None,
        external_reverse_proxy=_tristate(args.external_reverse_proxy),
        enable_web_search=_tristate(args.enable_web_search),
        enable_local_ai=_tristate(args.enable_local_ai),
        localai_variant=args.localai_variant or None,
        enable_manager=_tristate(args.enable_manager),
        enable_rag=_tristate(args.enable_rag),
        enable_smtp=_tristate(args.enable_smtp),
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        smtp_security=args.smtp_security,
        smtp_user=args.smtp_user,
        smtp_no_auth=args.smtp_no_auth,
        smtp_from=args.smtp_from,
        smtp_from_name=args.smtp_from_name,
        smtp_password=smtp_password,
        reranker_model=args.reranker_model or None,
        allow_direct_port_access=args.allow_direct_port_access,
        non_interactive=True,
        force=args.force,
        fresh_init=fresh_init,
    )

    effective_auth_provider = args.auth_provider or tree.get("", {}).get(
        "AUTH_PROVIDER", "internal_keycloak"
    )

    seed = envtree.load_seed_tree(repo_root)
    try:
        # Runs first: write_env_file appends any tree key missing from the
        # shipped template under a "generated by papaia-ctl" banner, so a
        # renamed or dropped key would otherwise be re-emitted on every run.
        tree = resolve.migrate_env_keys(tree)
        tree = secrets.generate_missing_secrets(
            tree, seed, force=args.force, auth_provider=effective_auth_provider
        )
        tree = resolve.resolve_multi_env(tree, setup_args)
        tree = resolve.resolve_hostnames(tree, setup_args)
        tree = resolve.resolve_reverse_proxy(tree, setup_args)
        tree = resolve.migrate_web_search_profiles(tree)
        tree = resolve.resolve_web_search(tree, setup_args)
        tree = resolve.resolve_local_ai(tree, setup_args)
        tree = resolve.resolve_localai_variant(tree, setup_args)
        tree = resolve.resolve_manager(tree, setup_args)
        tree = resolve.resolve_rag_hosts(tree, setup_args)
        tree = resolve.resolve_rag(tree, setup_args)
        tree = resolve.resolve_smtp(tree, setup_args)
        tree = resolve.resolve_reranker_model(tree, setup_args)
    except resolve.SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if requested_topology is not None:
        # Checked against the resolved values before any of them is written, so a rejected
        # topology leaves a configuration that a corrected setup run can still complete.
        env = dict(tree.get("", {}))
        env.setdefault("DOMAIN_SERVER", tree.get("ai/librechat", {}).get("DOMAIN_SERVER", ""))
        profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
        findings = topology.validate(
            requested_topology, active_profiles=profiles, env=env, repo_root=repo_root
        )
        _print_findings(findings)
        if not findings.ok:
            return 2

    tree = envtree.stamp_platform_version(tree, repo_root)
    tree = envtree.stamp_config_dir(tree, config_dir)
    tree = envtree.stamp_workspace_dir(tree, repo_root)
    # After stamp_workspace_dir: the derived default is <workspace>/backup.
    tree = envtree.stamp_backup_dir(tree, override=args.backup_dir)
    tree = envtree.stamp_docker_gid(tree)
    tree = envtree.stamp_host_uid_gid(tree)
    envtree.persist_tree(tree, config_dir, repo_root)
    deployment.sync_manifest(config_dir, tree, repo_root)
    if requested_topology is not None:
        manifest = deployment.load(config_dir)
        manifest["topology"] = requested_topology.to_dict()
        deployment.save(config_dir, manifest)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    gen_override.generate_ssl_cert_override(config_dir, effective_auth_provider)
    gen_override.generate_addon_ssl_cert_overrides(config_dir, effective_auth_provider, repo_root)
    gen_override.generate_localai_gpu_override(
        config_dir, repo_root, tree.get("", {}).get("LOCALAI_IMAGE_VARIANT", "")
    )

    envtree.write_run_summary(config_dir, tree, fresh_init=fresh_init, force=args.force)
    if _project_bundles(config_dir, repo_root) != 0:
        return 3
    print(
        "Setup complete. Run 'papaia-ctl start' to bring up the stack."
        f" PAPAIA_CONFIG_DIR={config_dir}"
    )
    # Only for the switch-on: confirming an already enabled RAG system needs no reminder.
    if setup_args.enable_rag and not rag_was_enabled:
        reporting.print_rag_next_steps(config_dir, tree)
    if setup_args.enable_smtp and not smtp_was_enabled:
        reporting.print_smtp_next_steps(tree)
    if effective_auth_provider == "external_oidc":
        reporting.print_external_oidc_checklist(config_dir, tree)
    return 0


def cmd_sync_env(args: argparse.Namespace) -> int:
    added = envtree.sync_new_env_keys(Path(args.config_dir), Path(args.repo_root))
    for rel_dir, keys in added.items():
        target = f"{rel_dir}/.env" if rel_dir else ".env"
        print(f"Added {len(keys)} new variable(s) to {target}: {', '.join(keys)}")
    return 0


def cmd_materialize(args: argparse.Namespace) -> int:
    envtree.materialize_core_env(Path(args.config_dir), Path(args.repo_root))
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_ssl_cert_override(config_dir, auth_provider)
    gen_override.generate_addon_ssl_cert_overrides(config_dir, auth_provider, repo_root)
    # Also regenerated here, not just in cmd_setup: `papaia-ctl start` renders
    # before bringing the stack up, so a stale override would otherwise survive
    # both an upgrade and a variant change.
    gen_override.generate_localai_gpu_override(
        config_dir, repo_root, tree.get("", {}).get("LOCALAI_IMAGE_VARIANT", "")
    )
    if _project_bundles(config_dir, repo_root) != 0:
        return 3
    print("Rendered.")
    return 0


# ─────────────────────────────────────────────────────────────────────────
# topology
#
# A single-node installation has no topology block and none of this prints or writes
# anything for it.
# ─────────────────────────────────────────────────────────────────────────


def _print_findings(findings: topology.Findings) -> None:
    for warning in findings.warnings:
        print(f"WARNING: topology: {warning}", file=sys.stderr)
    for error in findings.errors:
        print(f"ERROR: topology: {error}", file=sys.stderr)


def _load_topology(config_dir: Path) -> topology.Topology | None:
    try:
        return topology.load_config(config_dir)
    except topology.TopologyError as exc:
        print(f"ERROR: deployment.yaml: {exc}", file=sys.stderr)
        return None


def _project_bundles(config_dir: Path, repo_root: Path) -> int:
    """In distributed mode, validate the topology and write the node bundles. 0 when there
    is nothing to do or it worked, 3 when the topology is broken."""
    topo = _load_topology(config_dir)
    if topo is None:
        return 3
    if not topo.distributed:
        return 0
    findings = topology.validate_config(config_dir, repo_root, topo)
    _print_findings(findings)
    if not findings.ok:
        return 3
    for bundle in topology.project(config_dir, repo_root, topo):
        services = ", ".join(bundle.services) or "no services"
        print(f"Node bundle for '{bundle.node}' ({services}): {bundle.path}")
    return 0


def cmd_topology_mode(args: argparse.Namespace) -> int:
    topo = _load_topology(Path(args.config_dir))
    if topo is None:
        return 3
    print(topo.mode)
    return 0


def cmd_topology_show(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    topo = _load_topology(config_dir)
    if topo is None:
        return 3
    env = topology.validation_env(config_dir, Path(args.repo_root))
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
    if args.json:
        active = topology.active_services(profiles)
        document = topo.to_dict()
        document["services"] = {service: topo.node_of(service) for service in active}
        print(json.dumps(document, indent=2))
    else:
        print(topology.format_table(topo, profiles))
    return 0


def cmd_topology_validate(args: argparse.Namespace) -> int:
    """Exit 0 when the topology is usable (warnings allowed), 2 when it is not."""
    config_dir = Path(args.config_dir)
    topo = _load_topology(config_dir)
    if topo is None:
        return 2
    findings = topology.validate_config(config_dir, Path(args.repo_root), topo)
    _print_findings(findings)
    if findings.ok:
        print("Topology is valid." if topo.distributed else "Topology: single (one host).")
    return 0 if findings.ok else 2


def cmd_topology_node_of(args: argparse.Namespace) -> int:
    topo = _load_topology(Path(args.config_dir))
    if topo is None:
        return 3
    print(topo.node_of(args.service) if topo.distributed else "")
    return 0


def cmd_topology_project(args: argparse.Namespace) -> int:
    return _project_bundles(Path(args.config_dir), Path(args.repo_root))


def cmd_render_preview(args: argparse.Namespace) -> int:
    """Print the effective result of a draft overlay for one render target, as JSON.

    Read-only: the draft is read from `--overlay-file`, merged onto the same layers `render`
    uses, and nothing is written. Exit 0 whenever a document was printed -- a draft that does
    not parse is an answer (`"ok": false`), not a failure of the command. Exit 2 is a usage
    error: an unreadable draft file, or a target that is not a file of the render list."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    target = args.target
    if target not in render_core.BASE_RENDER_TARGETS or (repo_root / "src" / target).is_dir():
        print(f"ERROR: {target} is not a file target of the render", file=sys.stderr)
        return 2
    try:
        draft = Path(args.overlay_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"ERROR: cannot read {args.overlay_file}: {exc}", file=sys.stderr)
        return 2
    try:
        result = {"ok": True, **render_core.preview(config_dir, repo_root, target, draft)}
    except render_core.RenderError as exc:
        result = {"ok": False, "error": str(exc), "line": exc.line, "column": exc.column}
    print(json.dumps(result))
    return 0


def cmd_module_info(args: argparse.Namespace) -> int:
    """Print what switching an optional module off could delete, as JSON. Read-only."""
    try:
        document = modules.info(Path(args.config_dir), Path(args.repo_root), args.module)
    except modules.ModuleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document))
    return 0


def cmd_module_purge(args: argparse.Namespace) -> int:
    """Delete the data (volumes) and/or reset the settings of a module that is switched off.

    Both are separate options. The settings of a module whose data depends on them (the RAG
    system) are only deleted together with the data. Exit 3 when the request is refused or
    a step fails, with an `ERROR:` line."""
    if not (args.data or args.config):
        print("ERROR: name what to delete: --data, --config or both", file=sys.stderr)
        return 2
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    try:
        module = modules.spec(args.module)
        if args.config and module.settings_need_data and not args.data:
            raise modules.ModuleError(
                f"the settings of {module.name} can only be deleted together with its data"
                " (--data): its stored credentials and grants depend on them"
            )
        removed = modules.purge_data(config_dir, repo_root, args.module) if args.data else []
        touched = modules.reset_config(config_dir, repo_root, args.module) if args.config else []
    except modules.ModuleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    for name in removed:
        print(f"removed volume {name}")
    for item in touched:
        print(f"reset {item}")
    return 0


def cmd_override_external_nets(args: argparse.Namespace) -> int:
    """Print the external network names declared in one override file
    (one per line). Used by the bash dispatcher to skip overrides whose
    addon networks don't exist yet."""
    for net in gen_override.external_networks(Path(args.file)):
        print(net)
    return 0


def cmd_npm_provision(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    if not npm_provision.provision_npm_hosts(tree):
        return 1
    return 0


def cmd_keycloak_role_sync(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    if not keycloak_role_sync.sync_roles(tree, config_dir):
        return 1
    return 0


# ─────────────────────────────────────────────────────────────────────────
# backup / restore
#
# Output is TSV so the bash dispatcher can consume it with `read` and without
# a JSON parser -- same contract as override-external-nets above.
# ─────────────────────────────────────────────────────────────────────────


def _fail(exc: Exception) -> int:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 3


def _resolve_backup_dir(config_dir: Path, override: str | None) -> Path:
    """--backup-dir wins; otherwise PAPAIA_BACKUP_DIR from the config bundle's
    root .env, which setup stamps as <PAPAIA_WORKSPACE_DIR>/backup."""
    if override:
        return Path(override).expanduser()
    value = common.parse_env_file(config_dir / ".env").get("PAPAIA_BACKUP_DIR", "")
    if not value or common.is_placeholder(value):
        raise backup.BackupError(
            "PAPAIA_BACKUP_DIR is not set in the root .env. Pass --backup-dir=PATH,"
            " or re-run 'papaia-ctl setup --backup-dir=PATH'."
        )
    return Path(value).expanduser()


def cmd_backup_dir(args: argparse.Namespace) -> int:
    try:
        print(_resolve_backup_dir(Path(args.config_dir), args.backup_dir))
    except backup.BackupError as exc:
        return _fail(exc)
    return 0


def cmd_backup_plan(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
        existing = backup.parse_existing_volumes(
            Path(args.existing_volumes) if args.existing_volumes else None
        )
        plan = backup.build_plan(
            config_dir, Path(args.repo_root), backup_dir, existing=existing
        )
        if args.only:
            plan = backup.scope_plan(plan, args.only)
        common.ensure_dir(plan.snapshot / "volumes")
        common.ensure_dir(plan.snapshot / "binds")
        backup.write_plan(plan)
    except backup.SelectionError as exc:
        # Before anything is written: a selection that cannot be met leaves no
        # snapshot directory behind, let alone an archive.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except backup.BackupError as exc:
        return _fail(exc)
    for name in plan.skipped:
        print(f"WARNING: declared volume does not exist, skipping: {name}", file=sys.stderr)
    print(f"SNAPSHOT\t{plan.snapshot}")
    if plan.scope:
        print(f"SCOPE\t{','.join(plan.scope)}")
    for artifact in plan.artifacts:
        print(f"{artifact.kind}\t{artifact.archive}\t{artifact.source}\t{artifact.owner}")
    return 0


def cmd_backup_finish(args: argparse.Namespace) -> int:
    snapshot = Path(args.snapshot)
    try:
        backup_dir = _resolve_backup_dir(Path(args.config_dir), args.backup_dir)
        plan = backup.read_plan(snapshot)
        manifest = backup.write_manifest(
            snapshot,
            plan,
            backup.read_results(snapshot),
            papaia_version=envtree.resolve_platform_version(Path(args.repo_root)),
        )
        entry = backup.record_backup(backup_dir, plan, manifest, args.result)
    except backup.BackupError as exc:
        return _fail(exc)
    # Intermediate state; the manifest supersedes it. results.tsv stays as the
    # audit trail of which archives failed.
    (snapshot / backup.PLAN_NAME).unlink(missing_ok=True)
    print(f"ID\t{entry['id']}")
    print(f"SIZE_MB\t{entry['size_mb']}")
    print(f"ARTIFACTS\t{entry['artifacts']}")
    return 0


def cmd_backup_prune(args: argparse.Namespace) -> int:
    try:
        backup_dir = _resolve_backup_dir(Path(args.config_dir), args.backup_dir)
        removed = backup.prune(backup_dir, args.retention_period_days)
    except backup.BackupError as exc:
        return _fail(exc)
    for backup_id in removed:
        print(backup_id)
    return 0


def cmd_backup_list(args: argparse.Namespace) -> int:
    try:
        backup_dir = _resolve_backup_dir(Path(args.config_dir), args.backup_dir)
        index = backup.load_index(backup_dir)
    except backup.BackupError as exc:
        return _fail(exc)
    backups = index.get("backups") or []
    if not backups:
        print(f"No restore points recorded in {backup_dir}.")
        return 0
    print(f"Restore points in {backup_dir}:")
    print(f"  {'ID':<21} {'CREATED (UTC)':<21} {'SIZE (MB)':>10}  {'RESULT':<8} SCOPE")
    for entry in sorted(backups, key=lambda b: str(b.get("created_at", ""))):
        print(
            f"  {str(entry.get('id', '')):<21}"
            f" {str(entry.get('created_at', '')):<21}"
            f" {str(entry.get('size_mb', '')):>10}"
            f"  {str(entry.get('result', '')):<8}"
            f" {', '.join(backup.entry_scope(entry)) or 'all'}"
        )
    return 0


def cmd_backup_delete(args: argparse.Namespace) -> int:
    # --restore-point is repeatable, and each value may itself be a
    # comma-separated list -- bash passes one flag per id, an operator may do
    # either.
    ids: list[str] = []
    for chunk in args.restore_point or []:
        ids.extend(part.strip() for part in chunk.split(",") if part.strip())
    try:
        backup_dir = _resolve_backup_dir(Path(args.config_dir), args.backup_dir)
        removed = backup.delete_backups(backup_dir, ids)
    except backup.BackupError as exc:
        return _fail(exc)
    for backup_id in removed:
        print(backup_id)
    return 0


def cmd_restore_resolve(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
        entry, warnings = backup.resolve_restore_point(
            backup_dir, args.restore_point, whole_stack=not args.only
        )
        snapshot = backup.snapshot_path(backup_dir, entry)
        if not snapshot.is_dir():
            raise backup.BackupError(
                f"Restore point {entry.get('id')} is catalogued but its directory is"
                f" gone: {snapshot}"
            )
        manifest = backup.read_manifest(snapshot)
        if not args.only:
            backup.require_whole_stack(manifest)
        selection = backup.resolve_selection(manifest, args.only) if args.only else None
    except backup.ScopedRestorePointError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except backup.BackupError as exc:
        return _fail(exc)
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    print(f"SNAPSHOT\t{snapshot}")
    print(f"ID\t{entry.get('id')}")
    if selection is not None:
        # The teardown scope travels as its own line kinds rather than as extra
        # columns: bash reads artifact rows with `read -r kind archive target
        # owner`, which would fold a fifth column into $owner. Resolving it here
        # also keeps the compose parsing on the Python side of the split.
        print(f"PROFILES\t{','.join(selection.profiles)}")
        print(f"ADDONS\t{','.join(selection.addons)}")
        artifacts = selection.artifacts
    else:
        artifacts = backup.manifest_artifacts(manifest)
    for artifact in artifacts:
        try:
            backup.validate_target(artifact, config_dir)
        except backup.BackupError as exc:
            return _fail(exc)
        target = artifact.source
        if artifact.kind == "configdir":
            # Restore into the config dir the stack reads from *now*, not the
            # one recorded at backup time -- the snapshot may be replayed onto
            # a host that keeps its bundle somewhere else.
            target = str(config_dir)
        print(f"{artifact.kind}\t{artifact.archive}\t{target}\t{artifact.owner}")
    return 0


def cmd_restore_selectors(args: argparse.Namespace) -> int:
    """What a restore point offers a picker: SELECTOR<TAB>KIND<TAB>ARCHIVES<TAB>VOLUMES.

    Prints nothing for a v1 snapshot, which is the honest answer -- it carries
    no grouping, so it is restorable only as a whole."""
    config_dir = Path(args.config_dir)
    try:
        backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
        entry, _warnings = backup.resolve_restore_point(backup_dir, args.restore_point)
        manifest = backup.read_manifest(backup.snapshot_path(backup_dir, entry))
    except backup.BackupError as exc:
        return _fail(exc)
    for item in backup.selectors(manifest):
        print(
            f"{item['selector']}\t{item['kind']}\t{len(item['archives'])}"
            f"\t{','.join(item['volumes'])}\t{','.join(item['profiles'])}"
        )
    return 0


# ─────────────────────────────────────────────────────────────────────────
# upgrade
#
# The bash side owns every git call; these three commands own the version
# arithmetic and the migration ledger. Output is TSV for the same reason the
# backup commands use it -- `read` consumes it without a JSON parser.
# ─────────────────────────────────────────────────────────────────────────


def cmd_upgrade_resolve(args: argparse.Namespace) -> int:
    """Decide the target release from the tag list bash collected.

    STATUS is `up-to-date` when there is nothing to do (exit 0, the caller
    stops there) and `ok` otherwise. A downgrade is a refusal, not a status."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    try:
        tags = Path(args.tags_file).read_text(encoding="utf-8").splitlines()
        versions = upgrade.parse_tags(tags)
        current = upgrade.resolve_current_version(config_dir, repo_root)
        target = upgrade.select_target(versions, args.version)
        status = upgrade.resolve_status(current, target, explicit=args.version is not None)
    except (upgrade.UpgradeError, OSError) as exc:
        return _fail(exc)
    print(f"CURRENT\t{current}")
    print(f"TARGET\t{target}")
    print(f"TAG\t{upgrade.tag_for(target)}")
    print(f"STATUS\t{status}")
    return 0


def cmd_upgrade_plan(args: argparse.Namespace) -> int:
    """List the migrations due for `--from` -> `--to`, in execution order.

    Reads them from --repo-root, which after the checkout is the *target*
    release's tree -- the only tree that carries the intermediate steps of a
    multi-release jump."""
    config_dir = Path(args.config_dir)
    try:
        found = migrations.discover(Path(args.repo_root))
        applied = migrations.applied_ids(migrations.load_state(config_dir))
        due = migrations.pending(found, args.from_version, args.to_version, applied)
    except ValueError as exc:
        return _fail(exc)
    for migration in due:
        # as_posix(): the consumer is bash, which under Git Bash cannot resolve
        # the backslash form a WindowsPath would render.
        print(
            f"MIGRATION\t{migration.id}\t{migration.version}"
            f"\t{migration.path.as_posix()}\t{migration.kind}"
        )
    return 0


def cmd_upgrade_record(args: argparse.Namespace) -> int:
    """Append one successfully applied migration to the ledger."""
    config_dir = Path(args.config_dir)
    try:
        found = {m.id: m for m in migrations.discover(Path(args.repo_root))}
        migration = found.get(args.migration_id)
        if migration is None:
            raise ValueError(f"Unknown migration: {args.migration_id}")
        migrations.record(config_dir, migration, duration_s=args.duration)
    except ValueError as exc:
        return _fail(exc)
    return 0


# ─────────────────────────────────────────────────────────────────────────
# status and doctor
#
# Read-only. With --json the only thing written to stdout is the JSON document;
# a caller (the papaia-manager, a health gate) parses it as is.
# ─────────────────────────────────────────────────────────────────────────


def _csv(values: list[str] | None) -> list[str]:
    """--flag may be repeated and each value may itself be comma-separated."""
    items: list[str] = []
    for chunk in values or []:
        items.extend(part.strip() for part in chunk.split(",") if part.strip())
    return items


def cmd_status(args: argparse.Namespace) -> int:
    """Declared state next to live state. Exit 0 whenever a report was
    produced -- an unreachable Docker socket is part of the report
    (`docker.reachable`), not a failure of this command."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    if topology.is_distributed(config_dir):
        try:
            report = cluster.collect_status(
                cluster.load(config_dir, repo_root),
                profiles=_csv(args.profiles) or None,
                include_addons=args.addons,
            )
        except cluster.ClusterError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2) if args.json else cluster.format_status(report))
        return 0
    try:
        report = status.collect(
            config_dir,
            repo_root,
            profiles=_csv(args.profiles) or None,
            include_addons=args.addons,
        )
    except status.StatusError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(status.to_json(report) if args.json else status.format_table(report))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Preflight and diagnostics. Exit 2 if any check failed, else 0; `warn`
    and `skip` never fail the run. Works before `setup`."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        if topology.is_distributed(config_dir):
            report = cluster.run_doctor(cluster.load(config_dir, repo_root), skip=_csv(args.skip))
        else:
            report = doctor.run_checks(config_dir, repo_root, skip=_csv(args.skip))
    except cluster.ClusterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except doctor.DoctorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(doctor.to_json(report) if args.json else doctor.format_table(report))
    return report.exit_code


# ─────────────────────────────────────────────────────────────────────────
# distributed lifecycle
# ─────────────────────────────────────────────────────────────────────────


def _cluster(args: argparse.Namespace) -> cluster.Cluster | None:
    try:
        return cluster.load(Path(args.config_dir), Path(args.repo_root))
    except cluster.ClusterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None


def cmd_cluster_start(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    try:
        return cluster.start(found, node=args.node, profiles=_csv(args.profiles) or None)
    except (cluster.ClusterError, nodes.NodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


def cmd_cluster_stop(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    try:
        return cluster.stop(
            found,
            node=args.node,
            profiles=_csv(args.profiles) or None,
            clean_up=args.clean_up,
        )
    except cluster.ClusterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_cluster_preflight(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    return cluster.preflight(found)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="papaia-ctl-py")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--config-dir", required=True)
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync_env = sub.add_parser("sync-env")
    p_sync_env.set_defaults(func=cmd_sync_env)

    p_materialize = sub.add_parser("materialize-core")
    p_materialize.set_defaults(func=cmd_materialize)

    p_defaults = sub.add_parser("defaults")
    p_defaults.set_defaults(func=cmd_defaults)

    p_localai_variants = sub.add_parser("localai-variants")
    p_localai_variants.set_defaults(func=cmd_localai_variants)

    p_setup = sub.add_parser("setup")
    p_setup.add_argument("--env", default="papaia")
    p_setup.add_argument("--host-ip")
    p_setup.add_argument("--app-host")
    p_setup.add_argument("--auth-host")
    p_setup.add_argument("--librechat-host")
    p_setup.add_argument("--litellm-host")
    p_setup.add_argument("--localai-host")
    p_setup.add_argument("--manager-host")
    p_setup.add_argument("--qdrant-host")
    p_setup.add_argument("--npm-admin-host")
    p_setup.add_argument(
        "--auth-provider", choices=["internal_keycloak", "external_oidc"], default=None
    )
    p_setup.add_argument("--oidc-issuer")
    p_setup.add_argument(
        "--reverse-proxy-provider",
        choices=["internal_nginx", "external_proxy", "no_proxy"],
        default=None,
    )
    p_setup.add_argument("--external-reverse-proxy", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-web-search", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-local-ai", choices=["true", "false"], default=None)
    p_setup.add_argument("--localai-variant", choices=list(gpu_detect.VARIANTS), default=None)
    p_setup.add_argument("--enable-manager", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-rag", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-smtp", choices=["true", "false"], default=None)
    p_setup.add_argument("--smtp-host", default=None)
    p_setup.add_argument("--smtp-port", default=None)
    p_setup.add_argument("--smtp-security", choices=["starttls", "tls", "none"], default=None)
    p_setup.add_argument("--smtp-user", default=None)
    p_setup.add_argument("--smtp-no-auth", action="store_true")
    p_setup.add_argument("--smtp-from", default=None)
    p_setup.add_argument("--smtp-from-name", default=None)
    p_setup.add_argument("--reranker-model", default=None)
    p_setup.add_argument("--backup-dir", default=None)
    p_setup.add_argument("--allow-direct-port-access", action="store_true")
    p_setup.add_argument("--force", action="store_true")
    p_setup.add_argument("--topology", choices=list(topology.MODES), default=None)
    p_setup.add_argument("--node", action="append", default=None)
    p_setup.add_argument("--place", action="append", default=None)
    p_setup.add_argument("--preset", choices=sorted(topology.PRESETS), default=None)
    p_setup.add_argument("--controller", default=None)
    p_setup.add_argument("--link-port", type=int, default=None)
    p_setup.add_argument("--topology-file", default=None)
    p_setup.set_defaults(func=cmd_setup)

    p_render = sub.add_parser("render")
    p_render.set_defaults(func=cmd_render)

    p_topology_mode = sub.add_parser("topology-mode")
    p_topology_mode.set_defaults(func=cmd_topology_mode)

    p_topology_show = sub.add_parser("topology-show")
    p_topology_show.add_argument("--json", action="store_true")
    p_topology_show.set_defaults(func=cmd_topology_show)

    p_topology_validate = sub.add_parser("topology-validate")
    p_topology_validate.set_defaults(func=cmd_topology_validate)

    p_topology_project = sub.add_parser("topology-project")
    p_topology_project.set_defaults(func=cmd_topology_project)

    cli_node.add_parsers(sub)

    p_cluster_start = sub.add_parser("cluster-start")
    p_cluster_start.add_argument("--node", default=None)
    p_cluster_start.add_argument("--profiles", action="append", default=None)
    p_cluster_start.set_defaults(func=cmd_cluster_start)

    p_cluster_stop = sub.add_parser("cluster-stop")
    p_cluster_stop.add_argument("--node", default=None)
    p_cluster_stop.add_argument("--profiles", action="append", default=None)
    p_cluster_stop.add_argument("--clean-up", action="store_true")
    p_cluster_stop.set_defaults(func=cmd_cluster_stop)

    p_topology_node_of = sub.add_parser("topology-node-of")
    p_topology_node_of.add_argument("--service", required=True, choices=sorted(topology.CATALOGUE))
    p_topology_node_of.set_defaults(func=cmd_topology_node_of)

    p_cluster_preflight = sub.add_parser("cluster-preflight")
    p_cluster_preflight.set_defaults(func=cmd_cluster_preflight)

    p_module_info = sub.add_parser("module-info")
    p_module_info.add_argument("--module", required=True, choices=sorted(modules.MODULES))
    p_module_info.set_defaults(func=cmd_module_info)

    p_module_purge = sub.add_parser("module-purge")
    p_module_purge.add_argument("--module", required=True, choices=sorted(modules.MODULES))
    p_module_purge.add_argument("--data", action="store_true")
    p_module_purge.add_argument("--config", action="store_true")
    p_module_purge.set_defaults(func=cmd_module_purge)

    p_preview = sub.add_parser("render-preview")
    p_preview.add_argument("--target", required=True)
    p_preview.add_argument("--overlay-file", required=True)
    p_preview.set_defaults(func=cmd_render_preview)

    p_addon_install = sub.add_parser("addon-install")
    p_addon_install.add_argument("--name", required=True)
    p_addon_install.add_argument("--path", default=None)
    p_addon_install.add_argument("--version", default=None)
    p_addon_install.add_argument("--force", action="store_true")
    p_addon_install.set_defaults(func=cli_addon.cmd_addon_install)

    p_addon_start = sub.add_parser("addon-start")
    p_addon_start.add_argument("--name", required=True)
    p_addon_start.add_argument("--force", action="store_true")
    p_addon_start.set_defaults(func=cli_addon.cmd_addon_start)

    p_addon_check = sub.add_parser("addon-check")
    p_addon_check.add_argument("--target-core", default=None)
    p_addon_check.add_argument("--target-version", default=None)
    p_addon_check.add_argument("--target-addon-api", type=int, default=None)
    p_addon_check.add_argument("--target-min-addon-api", type=int, default=None)
    p_addon_check.add_argument("--json", action="store_true")
    p_addon_check.add_argument("--force", action="store_true")
    p_addon_check.set_defaults(func=cli_addon.cmd_addon_check)

    p_addon_components = sub.add_parser("addon-components")
    p_addon_components.add_argument("--name", default=None)
    p_addon_components.add_argument("--json", action="store_true")
    p_addon_components.set_defaults(func=cli_addon.cmd_addon_components)

    p_addon_upgrade_plan = sub.add_parser("addon-upgrade-plan")
    p_addon_upgrade_plan.add_argument("--name", required=True)
    p_addon_upgrade_plan.add_argument("--path", required=True)
    p_addon_upgrade_plan.add_argument("--force", action="store_true")
    p_addon_upgrade_plan.add_argument("--json", action="store_true")
    p_addon_upgrade_plan.add_argument("--answers-file", default=None)
    p_addon_upgrade_plan.add_argument("--answers-out", default=None)
    p_addon_upgrade_plan.set_defaults(func=cli_addon.cmd_addon_upgrade_plan)

    p_addon_upgrade_apply = sub.add_parser("addon-upgrade-apply")
    p_addon_upgrade_apply.add_argument("--name", required=True)
    p_addon_upgrade_apply.add_argument("--path", required=True)
    p_addon_upgrade_apply.add_argument("--force", action="store_true")
    p_addon_upgrade_apply.add_argument("--answers-file", default=None)
    p_addon_upgrade_apply.add_argument("--restore-point", default=None)
    p_addon_upgrade_apply.set_defaults(func=cli_addon.cmd_addon_upgrade_apply)

    p_addon_rollback_plan = sub.add_parser("addon-rollback-plan")
    p_addon_rollback_plan.add_argument("--name", required=True)
    p_addon_rollback_plan.add_argument("--force", action="store_true")
    p_addon_rollback_plan.set_defaults(func=cli_addon.cmd_addon_rollback_plan)

    p_addon_rollback_apply = sub.add_parser("addon-rollback-apply")
    p_addon_rollback_apply.add_argument("--name", required=True)
    p_addon_rollback_apply.add_argument("--force", action="store_true")
    p_addon_rollback_apply.set_defaults(func=cli_addon.cmd_addon_rollback_apply)

    p_addon_list = sub.add_parser("addon-list")
    p_addon_list.add_argument("--json", action="store_true")
    p_addon_list.set_defaults(func=cli_addon.cmd_addon_list)

    p_addon_remove = sub.add_parser("addon-remove")
    p_addon_remove.add_argument("--name", required=True)
    p_addon_remove.set_defaults(func=cli_addon.cmd_addon_remove)

    p_addon_uninstall = sub.add_parser("addon-uninstall")
    p_addon_uninstall.add_argument("--name", required=True)
    p_addon_uninstall.set_defaults(func=cli_addon.cmd_addon_uninstall)

    p_addon_networks = sub.add_parser("addon-networks")
    p_addon_networks.set_defaults(func=cli_addon.cmd_addon_networks)

    p_active_addons = sub.add_parser("active-addons")
    p_active_addons.set_defaults(func=cli_addon.cmd_active_addons)

    p_npm = sub.add_parser("npm-provision")
    p_npm.set_defaults(func=cmd_npm_provision)

    p_kc_role_sync = sub.add_parser("keycloak-role-sync")
    p_kc_role_sync.set_defaults(func=cmd_keycloak_role_sync)

    p_override_nets = sub.add_parser("override-external-nets")
    p_override_nets.add_argument("--file", required=True)
    p_override_nets.set_defaults(func=cmd_override_external_nets)

    p_addon_path = sub.add_parser("addon-path")
    p_addon_path.add_argument("--name", required=True)
    p_addon_path.set_defaults(func=cli_addon.cmd_addon_path)

    p_addon_override_files = sub.add_parser("addon-override-files")
    p_addon_override_files.add_argument("--name", required=True)
    p_addon_override_files.set_defaults(func=cli_addon.cmd_addon_override_files)

    p_backup_dir = sub.add_parser("backup-dir")
    p_backup_dir.add_argument("--backup-dir", default=None)
    p_backup_dir.set_defaults(func=cmd_backup_dir)

    p_backup_plan = sub.add_parser("backup-plan")
    p_backup_plan.add_argument("--backup-dir", default=None)
    p_backup_plan.add_argument("--existing-volumes", default=None)
    p_backup_plan.add_argument("--only", default=None)
    p_backup_plan.set_defaults(func=cmd_backup_plan)

    p_backup_finish = sub.add_parser("backup-finish")
    p_backup_finish.add_argument("--backup-dir", default=None)
    p_backup_finish.add_argument("--snapshot", required=True)
    p_backup_finish.add_argument("--result", choices=["ok", "partial", "failed"], default="ok")
    p_backup_finish.set_defaults(func=cmd_backup_finish)

    p_backup_prune = sub.add_parser("backup-prune")
    p_backup_prune.add_argument("--backup-dir", default=None)
    p_backup_prune.add_argument("--retention-period-days", type=int, required=True)
    p_backup_prune.set_defaults(func=cmd_backup_prune)

    p_backup_list = sub.add_parser("backup-list")
    p_backup_list.add_argument("--backup-dir", default=None)
    p_backup_list.set_defaults(func=cmd_backup_list)

    p_backup_delete = sub.add_parser("backup-delete")
    p_backup_delete.add_argument("--backup-dir", default=None)
    p_backup_delete.add_argument("--restore-point", action="append", required=True)
    p_backup_delete.set_defaults(func=cmd_backup_delete)

    p_upgrade_resolve = sub.add_parser("upgrade-resolve")
    p_upgrade_resolve.add_argument("--tags-file", required=True)
    p_upgrade_resolve.add_argument("--version", default=None)
    p_upgrade_resolve.set_defaults(func=cmd_upgrade_resolve)

    p_upgrade_plan = sub.add_parser("upgrade-plan")
    p_upgrade_plan.add_argument("--from", dest="from_version", required=True)
    p_upgrade_plan.add_argument("--to", dest="to_version", required=True)
    p_upgrade_plan.set_defaults(func=cmd_upgrade_plan)

    p_upgrade_record = sub.add_parser("upgrade-record")
    p_upgrade_record.add_argument("--migration-id", required=True)
    p_upgrade_record.add_argument("--duration", type=int, default=0)
    p_upgrade_record.set_defaults(func=cmd_upgrade_record)

    p_restore_resolve = sub.add_parser("restore-resolve")
    p_restore_resolve.add_argument("--backup-dir", default=None)
    p_restore_resolve.add_argument("--restore-point", default=None)
    p_restore_resolve.add_argument("--only", default=None)
    p_restore_resolve.set_defaults(func=cmd_restore_resolve)

    p_restore_selectors = sub.add_parser("restore-selectors")
    p_restore_selectors.add_argument("--backup-dir", default=None)
    p_restore_selectors.add_argument("--restore-point", default=None)
    p_restore_selectors.set_defaults(func=cmd_restore_selectors)

    p_status = sub.add_parser("status")
    p_status.add_argument("--profiles", action="append", default=None)
    p_status.add_argument("--addons", action="store_true")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_doctor = sub.add_parser("doctor")
    p_doctor.add_argument("--skip", action="append", default=None)
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except render_core.RenderError as exc:
        # A layer that does not parse (a typo in a hand-edited overlay), or a realm
        # placeholder without a value: say which file, not a traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
