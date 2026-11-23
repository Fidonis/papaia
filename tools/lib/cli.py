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
import re
import sys
import time
from pathlib import Path

import yaml

from . import (
    access_report,
    audit,
    backup,
    backup_crypt,
    breakglass,
    catalog,
    cli_addon,
    cli_node,
    cli_pki,
    cluster,
    cluster_data,
    common,
    compat,
    defaults,
    delegation_lifetime,
    deployment,
    direct_ports,
    doctor,
    envtree,
    gen_override,
    gpu_detect,
    halt,
    images,
    ingress,
    keycloak_admin_path,
    keycloak_role_sync,
    librechat_history,
    localai_native,
    migrations,
    module_actions,
    module_offer,
    modules,
    nodes,
    npm_provision,
    pairing_approval,
    paperless_gate,
    person,
    person_request,
    post_restore,
    privacy_pack,
    realm_sync,
    render_core,
    reporting,
    resolve,
    rollback_key,
    secrets,
    service_accounts,
    settings,
    stack_network,
    status,
    suite,
    topology,
    upgrade,
    upgrade_stages,
)


def _tristate(value: str | None) -> bool | None:
    if value is None:
        return None
    return value == "true"


def _apply_voice_gpu_override(config_dir: Path, repo_root: Path, tree: dict) -> None:
    """Write or remove the voice TTS accelerator override for this tree.

    The variant only materializes while the voice profile is active: a host that never
    runs the TTS engine must not carry a stray accelerator override (an empty variant
    removes the file)."""
    root = tree.get("", {})
    # Stripped like render_core parses the same value, so a hand-edited
    # profile list with spaces cannot activate the fragments while this
    # helper deletes the override.
    active = "voice" in {p.strip() for p in root.get("COMPOSE_PROFILES", "").split(",")}
    gen_override.generate_voice_gpu_override(
        config_dir, repo_root, root.get("VOICE_TTS_IMAGE_VARIANT", "") if active else "",
        mirror=_image_mirror(tree),
    )


def _image_mirror(tree: dict) -> str:
    """PAPAIA_IMAGE_MIRROR of the tree, validated (images.ImageError otherwise)."""
    return images.validate_mirror(tree.get("", {}).get(images.MIRROR_VAR, "").strip())


def _apply_image_overrides(config_dir: Path, repo_root: Path, tree: dict) -> str | None:
    """The accelerator overrides and then the mirror override; the error text of an
    invalid mirror setting, else None."""
    try:
        mirror = _image_mirror(tree)
    except images.ImageError as exc:
        return str(exc)
    gen_override.generate_localai_gpu_override(
        config_dir, repo_root, tree.get("", {}).get("LOCALAI_IMAGE_VARIANT", ""), mirror=mirror
    )
    _apply_voice_gpu_override(config_dir, repo_root, tree)
    gen_override.generate_image_mirror_override(config_dir, repo_root, mirror)
    return None


def cmd_defaults(args: argparse.Namespace) -> int:
    """Print sticky/derived values as shell-safe KEY=VALUE lines, one per
    line, so the bash dispatcher can read them without a JSON parser."""
    out = defaults.compute_defaults(Path(args.config_dir), Path(args.repo_root))
    for key, value in out.items():
        print(f"{key}={value}")
    return 0


def cmd_derive_auth_host(args: argparse.Namespace) -> int:
    """Print the Keycloak URL setup derives for an app host, for the interactive prompt."""
    print(resolve.derive_auth_host_default(args.app_host, args.keycloak_ext_port))
    return 0


def cmd_derive_edge_url(args: argparse.Namespace) -> int:
    """Print the URL a fresh setup derives for a core interface on the local edge, or
    nothing when the edge scheme does not apply; for the interactive prompt."""
    tree = envtree.load_config_dir_tree(Path(args.config_dir), Path(args.repo_root))
    project = "papaia" if args.env_name == "papaia" else f"papaia-{args.env_name}"
    try:
        url = resolve.edge_url_default(
            args.label,
            args.app_host,
            project,
            tree.get("", {}),
            provider=args.provider or None,
            allow_direct=args.allow_direct == "1",
        )
    except resolve.NoEdgeDomain as exc:
        # The prompt keeps its port pre-fill; `setup` refuses the address afterwards
        # with the same message, unless INGRESS_DOMAIN is set by then.
        print(f"WARNING: {exc}", file=sys.stderr)
        url = None
    except resolve.SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(url or "")
    return 0


def cmd_localai_variants(args: argparse.Namespace) -> int:
    """Print the detected LocalAI image variants as shell-safe KEY=VALUE lines.

    Kept out of `defaults` on purpose: this probe forks nvidia-smi and docker,
    while `defaults` runs on every single papaia-ctl setup invocation. The
    wizard calls it only when it is about to ask the question."""
    for key, value in gpu_detect.detection_vars(gpu_detect.detect()).items():
        print(f"{key}={value}")
    return 0


# A setup request that does not fit the installation (a topology for an existing one, a
# placement that cannot work). Distinct from argparse's 2, so that bash can tell a refusal
# (exit 2, nothing changed) from a failed run (exit 3) without changing the latter.
SETUP_REFUSED = 4


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
        return SETUP_REFUSED
    if args.topology == topology.SINGLE:
        if args.node or args.place or args.preset or args.controller or args.link_port or (
            args.topology_file
        ):
            print(
                "ERROR: --topology=single takes no nodes, placement or topology file.",
                file=sys.stderr,
            )
            return SETUP_REFUSED
        if current.distributed:
            print(
                "ERROR: this installation is distributed; setup does not turn it back into"
                " a single host.",
                file=sys.stderr,
            )
            return SETUP_REFUSED
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
        return SETUP_REFUSED
    if existing and not current.distributed:
        print(
            "ERROR: --topology=distributed is for new installations, and"
            f" {config_dir} already holds one that runs on one host. Set the distributed"
            " installation up in a new config directory (--config-dir=PATH) and move the"
            " data over with 'papaia-ctl backup' and 'restore --only=...'. Nothing was"
            " changed.",
            file=sys.stderr,
        )
        return SETUP_REFUSED
    if existing and current.distributed:
        if requested.to_dict() != current.to_dict():
            print(
                "ERROR: setup does not change the topology of an existing installation."
                " Add or remove machines with 'papaia-ctl node add|remove'; moving a"
                " service with its data to another node is not supported. Nothing was"
                " changed.",
                file=sys.stderr,
            )
            return SETUP_REFUSED
        return None
    return requested


def cmd_setup(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    config_dir = Path(args.config_dir)

    requested_topology = _requested_topology(args, config_dir)
    if isinstance(requested_topology, int):
        return requested_topology

    fresh_init = not (config_dir / ".env").is_file()
    # The native LocalAI lives below the workspace. Checked before the config directory is
    # seeded or anything is written, so a refused run leaves neither LOCALAI_RUNTIME=native
    # in the root .env nor, on a fresh config directory, template files a later setup would
    # take for an existing installation. It needs only the requested or stored runtime, the
    # stored PAPAIA_WORKSPACE_DIR and the checkout name.
    stored_root = {} if fresh_init else common.parse_env_file(config_dir / ".env")
    wanted_runtime = args.localai_runtime or localai_native.runtime(stored_root)
    if wanted_runtime == localai_native.NATIVE:
        workspace = envtree.stamp_workspace_dir({"": dict(stored_root)}, repo_root)
        try:
            localai_native.localai_home(workspace[""])
        except localai_native.InstallError as exc:
            print(f"ERROR: LOCALAI_RUNTIME=native: {exc}. Nothing was changed.", file=sys.stderr)
            return 3
    # The mail relay sends every mail under this name (PLT-78); read before anything
    # is written, so a broken brand overlay leaves the configuration as it was.
    try:
        installation_name = catalog.installation_name(config_dir)
    except catalog.CatalogError as exc:
        print(f"ERROR: platform catalog: {exc}. Nothing was changed.", file=sys.stderr)
        return 3
    envtree.init(config_dir, repo_root, env_name=args.env, force=False)

    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    runtime_before = localai_native.runtime(tree.get("", {})) if not fresh_init else ""
    rag_was_enabled = "rag" in tree.get("", {}).get("COMPOSE_PROFILES", "").split(",")
    smtp_was_enabled = "smtp" in tree.get("", {}).get("COMPOSE_PROFILES", "").split(",")
    # Taken out of the environment so nothing started later inherits it. An empty
    # value means "keep the stored password" (--smtp-no-auth drops it).
    smtp_password = os.environ.pop("PAPAIA_SMTP_PASSWORD", "") or None
    setup_args = resolve.SetupArgs(
        installation_name=installation_name,
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
        localai_runtime=args.localai_runtime or None,
        enable_manager=_tristate(args.enable_manager),
        enable_rag=_tristate(args.enable_rag),
        enable_voice=_tristate(args.enable_voice),
        enable_knowledge_map=_tristate(args.enable_knowledge_map),
        enable_connections=_tristate(args.enable_connections),
        voice_variant=args.voice_variant or None,
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
        tree = resolve.resolve_localai_runtime(tree, setup_args)
        tree = resolve.resolve_default_model(tree, setup_args)
        tree = resolve.resolve_manager(tree, setup_args)
        tree = resolve.resolve_rag_hosts(tree, setup_args)
        tree = resolve.resolve_rag(tree, setup_args)
        tree = resolve.resolve_voice(tree, setup_args)
        tree = resolve.resolve_voice_variant(tree, setup_args)
        tree = resolve.resolve_knowledge_map(tree, setup_args)
        tree = resolve.resolve_connections(tree, setup_args)
        tree = resolve.resolve_smtp(tree, setup_args)
        tree = resolve.resolve_reranker_model(tree, setup_args)
        tree = resolve.resolve_core_profiles(tree)
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
            return SETUP_REFUSED
    else:
        # A repeated setup of a distributed installation: the new values against the
        # placement it has, before anything is written.
        existing = _load_topology(config_dir)
        if existing is None:
            return 3
        if existing.distributed:
            env = dict(tree.get("", {}))
            env.setdefault("DOMAIN_SERVER", tree.get("ai/librechat", {}).get("DOMAIN_SERVER", ""))
            profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
            findings = topology.validate(
                existing, active_profiles=profiles, env=env, repo_root=repo_root
            )
            _print_findings(findings)
            if not findings.ok:
                return SETUP_REFUSED

    # Before anything is written: direct port access is refused while a service with
    # header identity, me-web or a module with delegation is installed (RE-21).
    refused = direct_ports.refusals(tree.get("", {}), config_dir, repo_root)
    if refused:
        for message in refused:
            print(f"ERROR: {message}", file=sys.stderr)
        return SETUP_REFUSED

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
    # Ports of the core services only with direct port access; removed otherwise.
    direct_ports.write(config_dir, common.parse_env_file(config_dir / ".env"))
    gen_override.generate_ssl_cert_override(config_dir, effective_auth_provider)
    gen_override.generate_addon_ssl_cert_overrides(config_dir, effective_auth_provider, repo_root)
    gen_override.generate_addon_join_overrides(config_dir, repo_root)
    image_problem = _apply_image_overrides(config_dir, repo_root, tree)
    if image_problem:
        print(f"ERROR: {image_problem}", file=sys.stderr)
        return 3
    runtime_problem = _localai_runtime_override(config_dir)
    if runtime_problem:
        print(f"ERROR: {runtime_problem}", file=sys.stderr)
        return 3
    _warn_protected_localai_home(config_dir)
    stored_root = common.parse_env_file(config_dir / ".env")
    if not _native_wanted(stored_root):
        # After a switch back to the container a job left from the native runtime would
        # hold the port until the next `stop` (quiet when there is none).
        _retire_native_job(stored_root)
    if localai_native.runtime(tree.get("", {})) == localai_native.NATIVE and (
        runtime_before != localai_native.NATIVE
    ):
        seeded = localai_native.seed_models(config_dir, repo_root)
        if seeded is not None:
            print(f"Seeded the LocalAI model list for the native runtime: {seeded}")
            # The render above ran before the list existed.
            render_core.render(config_dir, repo_root)

    try:
        # Before the bundles: the proxy's node gets the secret directory with them.
        paperless_gate.prepare(config_dir)
    except paperless_gate.GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    envtree.write_run_summary(config_dir, tree, fresh_init=fresh_init, force=args.force)
    if _project_bundles(config_dir, repo_root) != 0:
        return 3
    print(
        "Setup complete. Run 'papaia-ctl start' to bring up the stack."
        f" PAPAIA_CONFIG_DIR={config_dir}"
    )
    reporting.print_model_location(config_dir, repo_root)
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


def _localai_runtime_override(config_dir: Path) -> str | None:
    """Write or remove the runtime override; the reason when `native` cannot be set up."""
    root = common.parse_env_file(config_dir / ".env")
    runtime = localai_native.runtime(root)
    problem = None
    home = None
    if runtime == localai_native.NATIVE:
        try:
            home = localai_native.localai_home(root)
        except localai_native.InstallError as exc:
            problem = f"LOCALAI_RUNTIME=native: {exc}"
    gen_override.generate_localai_runtime_override(config_dir, runtime, home)
    return problem


def _warn_protected_localai_home(config_dir: Path) -> None:
    """The native LocalAI runs as a launchd job, which macOS may deny access to the folders
    it guards. Only a warning: whether access is denied depends on the Mac's settings."""
    root = common.parse_env_file(config_dir / ".env")
    if localai_native.runtime(root) != localai_native.NATIVE:
        return
    try:
        home = localai_native.localai_home(root)
    except localai_native.InstallError:
        return
    folder = localai_native.protected_folder(home)
    if folder is not None:
        print(
            f"WARNING: the native LocalAI keeps its files in {home}, below {folder}. macOS"
            " may deny its launchd job access to ~/Documents, ~/Desktop and ~/Downloads; a"
            " workspace outside these folders avoids that.",
            file=sys.stderr,
        )
    # The start script also reads the key from $PAPAIA_CONFIG_DIR/ai/localai/.env.
    folder = localai_native.protected_folder(config_dir.resolve())
    if folder is not None:
        print(
            f"WARNING: the configuration directory {config_dir} lies below {folder}. The"
            " launchd job of the native LocalAI reads its key from there, and macOS may deny"
            " it access to ~/Documents, ~/Desktop and ~/Downloads; a --config-dir outside"
            " these folders avoids that.",
            file=sys.stderr,
        )


def cmd_localai_native_install(args: argparse.Namespace) -> int:
    """The `start` step of the native LocalAI runtime. KEY=VALUE lines on stdout for the
    shell (LOCALAI_NATIVE = off | skipped | installed | unchanged), messages on stderr."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    root = common.parse_env_file(config_dir / ".env")
    if not _native_wanted(root):
        # Before `docker compose up`: a job left from the native runtime would keep the
        # port the container publishes.
        _retire_native_job(root)
        print("LOCALAI_NATIVE=off")
        return 0
    supported, why = localai_native.host_supported()
    if not supported:
        print(
            f"WARNING: native LocalAI skipped: {why}. 'papaia-ctl setup"
            " --localai-runtime=container' runs LocalAI in its container here.",
            file=sys.stderr,
        )
        print("LOCALAI_NATIVE=skipped")
        return 0
    try:
        result = localai_native.install_for(config_dir, repo_root, announce=_announce_install)
    except localai_native.InstallError as exc:
        print(f"ERROR: native LocalAI: {exc}", file=sys.stderr)
        return 1
    print(f"LOCALAI_NATIVE={'installed' if result.changed else 'unchanged'}")
    print(f"LOCALAI_NATIVE_VERSION={result.version}")
    print(f"LOCALAI_NATIVE_REPLACED={result.replaced or ''}")
    print(f"LOCALAI_NATIVE_SCRIPT={result.script}")
    # A running job has to be restarted to pick up a new binary, start script or key, also
    # when an earlier `start` ended before it got to the restart.
    print(f"LOCALAI_NATIVE_RESTART={1 if result.restart else 0}")
    return 0


def _announce_install(version: str) -> None:
    # stderr: stdout carries the KEY=VALUE lines the shell reads. The download is about
    # 200 MB and `start` would otherwise look stuck while it runs.
    print(f"Installing LocalAI {version} for the Apple GPU...", file=sys.stderr, flush=True)


def _native_wanted(root: dict[str, str]) -> bool:
    """Whether this installation runs the native LocalAI: the runtime and the profile."""
    return localai_native.runtime(root) == localai_native.NATIVE and "localai" in (
        common.cluster_profiles(root)
    )


def _retire_native_job(root: dict[str, str]) -> bool:
    """Unload and disable a launchd job the native LocalAI no longer needs, and remove its
    plist, so it neither keeps LOCALAI_EXT_PORT nor comes back at the next login. For
    `start` and `setup` after the runtime went back to the container (or LocalAI was
    switched off); `stop` handles the same case through localai-native-stop. Messages on
    stderr, so the KEY=VALUE output of the install step stays clean. False when a job is
    left behind."""
    try:
        label = localai_native.label_for(root)
    except localai_native.LaunchdError:
        return True
    plist = localai_native.plist_path(label)
    if not plist.is_file():
        return True
    available, why = localai_native.launchd_host()
    if not available:
        print(
            f"WARNING: the launchd job of the native LocalAI ({plist}) is still installed and"
            f" cannot be removed here: {why}. Run 'papaia-ctl stop' on the Mac.",
            file=sys.stderr,
        )
        return False
    try:
        localai_native.stop_job(label)
    except localai_native.LaunchdError as exc:
        print(
            f"WARNING: native LocalAI: {exc}. Its job may still hold port"
            f" {localai_native.port(root)}; run 'papaia-ctl stop' and check with"
            " 'papaia-ctl doctor'.",
            file=sys.stderr,
        )
        return False
    plist.unlink(missing_ok=True)
    print(
        f"Removed the launchd job of the native LocalAI ({label}): LocalAI runs in its"
        " container now.",
        file=sys.stderr,
    )
    return True


def _native_job(config_dir: Path) -> tuple[dict[str, str], Path, str] | None:
    """(root env, home, label) of the native LocalAI, or None when it has no home."""
    root = common.parse_env_file(config_dir / ".env")
    try:
        return root, localai_native.localai_home(root), localai_native.label_for(root)
    except (localai_native.InstallError, localai_native.LaunchdError) as exc:
        print(f"WARNING: native LocalAI: {exc}", file=sys.stderr)
        return None


def cmd_localai_native_start(args: argparse.Namespace) -> int:
    """The `start` step after `docker compose up`: load (or restart) the launchd job and
    wait for /readyz. A timeout warns with the log path; exit 1 when launchctl fails."""
    config_dir = Path(args.config_dir)
    root = common.parse_env_file(config_dir / ".env")
    if not _native_wanted(root):
        _retire_native_job(root)
        return 0
    supported, why = localai_native.host_supported()
    if not supported:
        print(f"WARNING: native LocalAI not started: {why}", file=sys.stderr)
        return 0
    job = _native_job(config_dir)
    if job is None:
        return 1
    root, home, label = job
    if not localai_native.script_path(home).is_file():
        print(
            "ERROR: native LocalAI: the start script is missing; run 'papaia-ctl start' again",
            file=sys.stderr,
        )
        return 1
    try:
        result = localai_native.start_job(
            home, label, localai_native.plist_path(label), restart=args.restart
        )
    except localai_native.LaunchdError as exc:
        print(f"ERROR: native LocalAI: {exc}", file=sys.stderr)
        return 1
    words = {
        "loaded": "LocalAI starts through launchd",
        "restarted": "LocalAI restarts through launchd",
        "started": "LocalAI starts through launchd",
        "running": "LocalAI runs through launchd",
    }
    print(f"{words[result.action]} ({label}); log: {result.log}")
    url = localai_native.probe_url(root, inside_container=False)
    timeout = args.wait if args.wait is not None else localai_native.READY_TIMEOUT_SECONDS
    if localai_native.wait_ready(url, timeout):
        print(f"LocalAI answers on {url}")
        return 0
    print(
        f"WARNING: LocalAI does not answer on {url} after {timeout:g} s. It keeps starting in"
        " the background (the first start downloads the Metal backend). Log: "
        f"{result.log}; state: launchctl print {localai_native.service_target(label)}",
        file=sys.stderr,
    )
    return 0


def _launchd_or_skip(root: dict[str, str], verb: str) -> bool:
    """Whether a stop or uninstall can reach launchd; says why not for the native runtime."""
    available, why = localai_native.launchd_host()
    if not available:
        if localai_native.runtime(root) == localai_native.NATIVE:
            print(f"WARNING: native LocalAI not {verb}: {why}", file=sys.stderr)
        return False
    return True


def cmd_localai_native_stop(args: argparse.Namespace) -> int:
    """Unload and disable the launchd job (before the Compose part of `stop`). With
    --purge-models also delete the models and backends. Quiet when there is no job."""
    config_dir = Path(args.config_dir)
    root = common.parse_env_file(config_dir / ".env")
    try:
        label = localai_native.label_for(root)
    except localai_native.LaunchdError as exc:
        print(f"WARNING: native LocalAI: {exc}", file=sys.stderr)
        return 0
    plist = localai_native.plist_path(label)
    native = localai_native.runtime(root) == localai_native.NATIVE
    if not native and not plist.is_file():
        return 0
    status_code = 0
    if _launchd_or_skip(root, "stopped"):
        try:
            if localai_native.stop_job(label):
                print(f"Stopped the native LocalAI ({label})")
        except localai_native.LaunchdError as exc:
            print(f"ERROR: native LocalAI: {exc}", file=sys.stderr)
            status_code = 1
    if args.purge_models and native:
        job = _native_job(config_dir)
        if job is not None:
            for path in localai_native.purge_data(job[1]):
                print(f"Deleted {path}")
    return status_code


def cmd_localai_native_state(args: argparse.Namespace) -> int:
    """KEY=VALUE lines: the launchd job of this installation. Exit 3 off a Mac."""
    root = common.parse_env_file(Path(args.config_dir) / ".env")
    available, why = localai_native.launchd_host()
    if not available:
        print(f"ERROR: {why}", file=sys.stderr)
        return 3
    try:
        label = localai_native.label_for(root)
        job = localai_native.state(label)
    except localai_native.LaunchdError as exc:
        print(f"ERROR: native LocalAI: {exc}", file=sys.stderr)
        return 1
    print(f"LABEL={label}")
    print(f"PLIST={localai_native.plist_path(label)}")
    print(f"LOADED={'yes' if job.loaded else 'no'}")
    print(f"STATE={job.state or ''}")
    print(f"PID={job.pid or ''}")
    print(f"LAST_EXIT={job.last_exit or ''}")
    return 0


def cmd_localai_native_uninstall(args: argparse.Namespace) -> int:
    """Stop the job and remove the plist, the script and the binary; with --purge also the
    models, backends, logs and the directory (`uninstall --clean-up`)."""
    config_dir = Path(args.config_dir)
    root = common.parse_env_file(config_dir / ".env")
    try:
        label = localai_native.label_for(root)
    except localai_native.LaunchdError as exc:
        print(f"WARNING: native LocalAI: {exc}", file=sys.stderr)
        return 0
    plist = localai_native.plist_path(label)
    try:
        home = localai_native.localai_home(root)
    except localai_native.InstallError:
        home = None
    if localai_native.runtime(root) != localai_native.NATIVE and not plist.is_file():
        if home is None or not home.is_dir():
            return 0
    if not _launchd_or_skip(root, "removed"):
        return 0
    try:
        if home is None:
            # No home to clean up; the job and its plist still go.
            localai_native.stop_job(label)
            plist.unlink(missing_ok=True)
            return 0
        removed = localai_native.uninstall(home, label, plist, purge=args.purge)
    except localai_native.LaunchdError as exc:
        print(f"ERROR: native LocalAI: {exc}", file=sys.stderr)
        return 1
    for path in removed:
        print(f"Removed {path}")
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
    gen_override.generate_addon_join_overrides(config_dir, repo_root)
    # Also regenerated here, not just in cmd_setup: `papaia-ctl start` renders
    # before bringing the stack up, so a stale override would otherwise survive
    # an upgrade, a variant change and a change of the image mirror.
    image_problem = _apply_image_overrides(config_dir, repo_root, tree)
    if image_problem:
        print(f"ERROR: {image_problem}", file=sys.stderr)
        return 3
    runtime_problem = _localai_runtime_override(config_dir)
    if runtime_problem:
        print(f"WARNING: {runtime_problem}", file=sys.stderr)
    if _project_bundles(config_dir, repo_root) != 0:
        return 3
    print("Rendered.")
    return 0


def cmd_catalog_render(args: argparse.Namespace) -> int:
    """`papaia-ctl catalog render`: write platform/services.json from the declarations
    of the installed add-ons and the active core profiles (groups.json is written by
    `realm sync`, which reads the groups from the identity provider)."""
    config_dir = Path(args.config_dir)
    try:
        written = catalog.render(config_dir, Path(args.repo_root))
    except catalog.CatalogError as exc:
        print(f"ERROR: platform catalog: {exc}", file=sys.stderr)
        return 3
    path = config_dir / catalog.CATALOG_DIR / catalog.SERVICES_FILE
    reason = catalog.skip_reason(config_dir, Path(args.repo_root))
    if reason is not None:
        print(f"ERROR: no platform catalog: {reason}.", file=sys.stderr)
        return 3
    print(f"Platform catalog {'written' if written else 'unchanged'}: {path}")
    return 0


def cmd_settings_show(args: argparse.Namespace) -> int:
    """`papaia-ctl settings show`: contact point, brand and four-eyes rule in effect."""
    try:
        shown = settings.show(Path(args.config_dir))
    except settings.SettingsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(shown, indent=2, ensure_ascii=False) if args.json
          else settings.format_table(shown))
    return 0


def _settings_change(args: argparse.Namespace, change) -> int:
    """Exit 0 done or unchanged, 1 refused (audited), 2 invalid, 3 stored but the catalog
    could not be rendered."""
    try:
        outcome = change()
    except settings.RefusedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except settings.SettingsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except catalog.CatalogError as exc:
        print(f"ERROR: setting stored, but the platform catalog was not rendered: {exc}",
              file=sys.stderr)
        return 3
    if not outcome.changed:
        print(f"{args.key} unchanged.")
    elif outcome.catalog_written is None:
        print(f"{args.key} stored; no platform catalog yet "
              f"({catalog.skip_reason(Path(args.config_dir), Path(args.repo_root))}).")
    return 0


def cmd_settings_set(args: argparse.Namespace) -> int:
    def change():
        outcome = settings.set_value(
            Path(args.config_dir), Path(args.repo_root), args.key, args.value
        )
        if outcome.changed and outcome.catalog_written is not None:
            shown = "the new logo" if args.key == settings.LOGO_KEY else args.value
            print(f"{args.key} set to {shown}; platform catalog rendered.")
        return outcome

    return _settings_change(args, change)


def cmd_settings_unset(args: argparse.Namespace) -> int:
    def change():
        outcome = settings.unset(Path(args.config_dir), Path(args.repo_root), args.key)
        if outcome.changed and outcome.catalog_written is not None:
            print(f"{args.key} removed; platform catalog rendered.")
        return outcome

    return _settings_change(args, change)


def _person_sweep(config_dir: Path) -> None:
    """Archives older than 14 days go at the start of every `person` command."""
    for request_id in person_request.sweep(config_dir):
        print(f"archive of request {request_id} deleted (older than "
              f"{person_request.ARCHIVE_DAYS} days)", file=sys.stderr)


def cmd_person_request(args: argparse.Namespace) -> int:
    """`papaia-ctl person export|erase --requested-by --confirmed-by`: file the request in
    papaia-audit and print its id; nothing runs. 2 when refused."""
    config_dir = Path(args.config_dir)
    try:
        _person_sweep(config_dir)
        sub = person.check_sub(args.sub)
        requested_by = person.check_sub(args.requested_by, "--requested-by")
        confirmed_by = person.check_sub(args.confirmed_by, "--confirmed-by")
        transfer_to = None
        if args.transfer_to is not None:
            transfer_to = person.check_sub(args.transfer_to, "--transfer-to")
        view = person_request.create(
            person_request.service_gate(config_dir), operation=args.operation, sub=sub,
            requested_by=requested_by, confirmed_by=confirmed_by, transfer_to=transfer_to,
        )
    except (person.PersonError, person_request.RequestError) as exc:
        print(f"ERROR: person {args.operation}: {exc}", file=sys.stderr)
        return 2
    print(person_request.render_request(view), end="")
    print(
        f"Nothing ran. {confirmed_by} confirms the request in the manager after signing "
        f"in again; then run: papaia-ctl person run {view['id']}"
    )
    return 0


def cmd_person_status(args: argparse.Namespace) -> int:
    """`papaia-ctl person status <request>`: the state of a request. 2 when refused."""
    config_dir = Path(args.config_dir)
    try:
        _person_sweep(config_dir)
        view = person_request.get(person_request.service_gate(config_dir), args.request)
        archive = None
        if view["operation"] == "export":
            path = person_request.archive_path(config_dir, view["id"])
            archive = path if path.exists() else None
    except person_request.RequestError as exc:
        print(f"ERROR: person status: {exc}", file=sys.stderr)
        return 2
    print(person_request.render_request(view), end="")
    if archive is not None:
        print(f"  archive       {archive} (hand it over, then: papaia-ctl person handover "
              f"{view['id']})")
    return 0


def cmd_person_find(args: argparse.Namespace) -> int:
    """`papaia-ctl person find --name=…|--email=…`: also deactivated and deleted accounts;
    sub, state and last sign-in, never content. 2 when refused."""
    config_dir = Path(args.config_dir)
    try:
        _person_sweep(config_dir)
        persons = person_request.find(config_dir, Path(args.repo_root), name=args.name,
                                      email=args.email)
    except person_request.RequestError as exc:
        print(f"ERROR: person find: {exc}", file=sys.stderr)
        return 2
    print(person_request.render_find(persons), end="")
    return 0


def cmd_person_handover(args: argparse.Namespace) -> int:
    """`papaia-ctl person handover <request>`: the archive was handed over and goes now."""
    try:
        gone = person_request.handover(Path(args.config_dir), args.request)
    except person_request.RequestError as exc:
        print(f"ERROR: person handover: {exc}", file=sys.stderr)
        return 2
    print(f"archive of request {args.request} deleted" if gone
          else f"no archive of request {args.request} (already deleted)")
    return 0


def cmd_person_sweep(args: argparse.Namespace) -> int:
    """`papaia-ctl person sweep`: delete every archive older than 14 days."""
    try:
        gone = person_request.sweep(Path(args.config_dir))
    except person_request.RequestError as exc:
        print(f"ERROR: person sweep: {exc}", file=sys.stderr)
        return 2
    print(f"{len(gone)} archive(s) older than {person_request.ARCHIVE_DAYS} days deleted")
    return 0


def cmd_person_begin(args: argparse.Namespace) -> int:
    """`papaia-ctl person run <request>`, first call: check the confirmed request, plan
    the module steps in the run folder --work and mark the request running. 2 when
    refused; nothing has run then."""
    config_dir = Path(args.config_dir)
    try:
        _person_sweep(config_dir)
        person.begin(
            config_dir, Path(args.repo_root), args.work, request=args.request,
            gate=person_request.service_gate(config_dir),
        )
    except (person.PersonError, person_request.RequestError) as exc:
        print(f"ERROR: person run: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_person_next(args: argparse.Namespace) -> int:
    """Take in the step that ran (--exit-code, its output in the run folder) and print the
    next one as a tab-separated line, or nothing when every step ran."""
    try:
        step = person.advance(Path(args.config_dir), Path(args.repo_root), args.work,
                              args.exit_code)
    except person.PersonError as exc:
        print(f"ERROR: person: {exc}", file=sys.stderr)
        return 2
    if step is not None:
        print(person.step_line(step))
    return 0


def cmd_person_finish(args: argparse.Namespace) -> int:
    """The result of the run: the archive written (export) or the proof (erase). 0 every
    module done, 1 a module missing or failed (named in the output), 2 refused."""
    config_dir = Path(args.config_dir)
    try:
        report = person.finish(config_dir, Path(args.repo_root), args.work,
                               gate=person_request.service_gate(config_dir))
    except person.PersonError as exc:
        print(f"ERROR: person: {exc}", file=sys.stderr)
        return 2
    print(person.render(report), end="")
    if report.archive is not None:
        print(f"Archive written to {report.archive} (age, to the passphrase the confirming "
              "person saw). Hand it over, then: papaia-ctl person handover "
              f"{report.archive.name.removesuffix(person_request.ARCHIVE_SUFFIX)}")
    return 0 if report.ok else 1


def cmd_privacy_pack(args: argparse.Namespace) -> int:
    """`papaia-ctl privacy-pack`: the data protection package from the declarations.
    Exit 0 done or up to date, 1 `--check` found problems, 2 bad options, 3 the
    declarations or the installation cannot be read."""
    repo_root = Path(args.repo_root)
    if args.installation:
        if args.check:
            print("ERROR: --check checks the package of the repository, not --installation.",
                  file=sys.stderr)
            return 2
        if not args.out or args.backup_retention is None:
            print("ERROR: --installation needs --out=FILE and --backup-retention=DAYS.",
                  file=sys.stderr)
            return 2
        settings = privacy_pack.Installation(
            args.backup_retention, args.offsite, args.offsite_retention
        )
        try:
            settings.validate()
            privacy_pack.write_installation(
                repo_root, Path(args.config_dir), settings, Path(args.out), args.format or "html"
            )
        except privacy_pack.PrivacyPackError as exc:
            print(f"ERROR: privacy-pack: {exc}", file=sys.stderr)
            return 3
        print(f"Data protection package of this installation written: {args.out}")
        return 0
    if args.format or args.backup_retention is not None or args.offsite or args.offsite_retention:
        print("ERROR: --format, --backup-retention and --offsite* need --installation.",
              file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else repo_root / privacy_pack.REPO_OUT
    try:
        pack = privacy_pack.collect(repo_root)
        for warning in pack.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
        if args.check:
            problems = privacy_pack.check(pack, out)
            for problem in problems:
                print(f"fail: {problem}", file=sys.stderr)
            if problems:
                return 1
            print(f"Data protection package up to date: {out}")
            return 0
        written = privacy_pack.write(pack, out)
    except privacy_pack.PrivacyPackError as exc:
        print(f"ERROR: privacy-pack: {exc}", file=sys.stderr)
        return 3
    for name in written:
        print(f"  written: {name}")
    print(f"Data protection package {'written' if written else 'unchanged'}: {out}")
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
    try:
        bundles = topology.project(config_dir, repo_root, topo)
    except topology.TopologyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    for bundle in bundles:
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
    if not topo.distributed:
        print("")
        return 0
    env = topology.validation_env(Path(args.config_dir), Path(args.repo_root))
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
    active = topology.active_services(profiles)
    if args.service == "nginx" and topology.PROXY_PROFILE not in profiles:
        # oauth2-proxy also runs in front of an external proxy; there is no Nginx Proxy
        # Manager to provision then.
        active = [s for s in active if s != "nginx"]
    # Empty for a service the installation does not run (external OIDC, an external proxy).
    print(topo.node_of(args.service) if args.service in active else "")
    return 0


def cmd_topology_project(args: argparse.Namespace) -> int:
    return _project_bundles(Path(args.config_dir), Path(args.repo_root))


def cmd_suite_verify(args: argparse.Namespace) -> int:
    """Verify a suite bill of materials: signature against a trusted release key,
    then structure, counts, scope and suite. Read-only; exit 0 when it can be
    trusted, else 2.

    Without --key or --fingerprint the release key pinned in this checkout
    (compat/release-key.pub) is the anchor; the key inside the file is never
    trusted on its own. Without --suite an older file signed with the same key
    also passes; the command warns and reports `suite_bound: false`."""
    if not args.bom:
        print("ERROR: --bom=FILE is required.", file=sys.stderr)
        return 2
    signature = Path(args.signature or f"{args.bom}.sig")
    key_path = Path(args.key) if args.key else None
    if key_path is None and args.fingerprint is None:
        pinned = Path(args.repo_root) / suite.RELEASE_KEY_PATH
        if not pinned.is_file():
            print(
                f"ERROR: no trust anchor: {suite.RELEASE_KEY_PATH} is not in this checkout; "
                "pass --key=FILE or --fingerprint=sha256:HEX.",
                file=sys.stderr,
            )
            return 2
        key_path = pinned
    try:
        doc = suite.verify_bom(
            Path(args.bom),
            signature,
            key_path=key_path,
            fingerprint=args.fingerprint,
            require_scope=args.scope,
            expected_suite=args.suite,
        )
    except suite.SuiteError as exc:
        print(f"ERROR: {args.bom}: {exc}", file=sys.stderr)
        return 2
    summary = {
        "verified": True,
        "suite": doc["suite"],
        "suite_bound": args.suite is not None,
        "scope": doc["scope"],
        "fingerprint": doc["signing_key"]["fingerprint"],
        "contract_generation": doc["contract_generation"],
        "repos": [
            {"name": r["name"], "role": r["role"], "version": r["version"], "commit": r["commit"]}
            for r in doc["repos"]
        ],
        "totals": doc["totals"],
    }
    if args.suite is None:
        print(
            f"WARNING: suite not bound: an older bill of materials signed with the same key "
            f"also passes; pass --suite={doc['suite']} to refuse any other suite.",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps(summary))
        return 0
    print(f"Suite {doc['suite']} ({doc['scope']}): signature OK, key {summary['fingerprint']}")
    for repo in summary["repos"]:
        print(f"  {repo['name']:<24} {repo['role']:<9} {repo['version']:<12} {repo['commit']}")
    print(f"  containers: {doc['totals']['containers']}, images: {doc['totals']['images']}")
    return 0


_INSECURE_BANNER = """\
==========================================================================
 INSECURE: --insecure-images is set for this '{command}' only.
 {count} image(s) are started although they are not verified against the
 signed bill of materials: neither digest nor signature is checked. This is
 recorded in the audit journal. The next command checks again.
=========================================================================="""


_IMAGE_COMMANDS = ("start", "upgrade", "addon-install", "addon-start", "addon-upgrade",
                   "addon-rollback", "restore")


def _read_image_lines(path: str) -> list[str]:
    raw = suite._read_limited(Path(path), 64 * 1024, "image list")
    return [line.strip() for line in raw.decode("utf-8", "replace").splitlines()
            if line.strip()]


def _image_groups(args: argparse.Namespace, repo_root: Path) -> list[tuple[str | None, list[str]]]:
    """Every image to check, by owner: (None, the core's: the pins of the tree with
    --from-checkout and the lines of --images-file) and (name, the add-on's) for each
    --addon-images=NAME=FILE. Without duplicates inside a group. Raises ValueError or
    images.ImageError on a bad source."""
    core: list[str] = []
    if args.from_checkout:
        # Every pin of the tree: all profiles and accelerator variants.
        core += [ref for _, ref in images.compose_image_refs(repo_root)]
    if args.images_file is not None:
        core += _read_image_lines(args.images_file)
    groups: list[tuple[str | None, list[str]]] = []
    if core:
        groups.append((None, list(dict.fromkeys(core))))
    seen: set[str] = set()
    for spec in args.addon_images or []:
        name, sep, path = spec.partition("=")
        if not sep or not path or not images.ADDON_NAME_RE.match(name) or name in seen:
            raise images.ImageError("--addon-images: NAME=FILE with a valid add-on name, "
                                    "once per add-on, expected")
        seen.add(name)
        groups.append((name, list(dict.fromkeys(_read_image_lines(path)))))
    return groups


def _print_refusal(problems: list[images.Problem], total: int) -> None:
    print(f"ERROR: {len(problems)} of {total} image(s) may not be started:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem.ref}: {problem.reason}", file=sys.stderr)
    if any(problem.transient for problem in problems):
        print("The registry could not be asked (no connection, a rate limit or a server "
              "error). Try again later; on Docker Hub, 'docker login' raises the limit.",
              file=sys.stderr)


def _write_pending(path: Path, refs: list[str]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, ("\n".join(refs) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def _addon_unlisted(args: argparse.Namespace, problems: list[images.Problem],
                    mirror: str) -> int:
    """addon install with images from repositories the bill of materials does not list:
    shown with what the add-on would bring and refused, or, with
    --accept-unlisted-images, handed to --pending-file. Nothing is accepted here:
    addon.sh records the acceptance with `image-accept` once the add-on is
    registered, so a failed install leaves nothing accepted. Exit code."""
    addon_path = Path(args.addon_path or ".")
    manifest, error = deployment.load_addon_manifest(addon_path)
    if manifest is None or not isinstance(manifest, dict):
        print(f"ERROR: {error or 'add-on manifest is not a mapping'}", file=sys.stderr)
        return 2
    # Recorded under the name the bill of materials would list, not the mirror's.
    refs = [problem.ref.removeprefix(mirror) if mirror else problem.ref
            for problem in problems]
    if not args.accept_unlisted_images:
        print(f"ERROR: add-on {args.addon} uses image(s) outside the signed bill of "
              "materials:", file=sys.stderr)
        for line in images.addon_disclosure(args.addon, addon_path, manifest, refs):
            print(line, file=sys.stderr)
        print("Nothing was installed. If you trust this add-on, re-run 'papaia-ctl addon "
              "install' with --accept-unlisted-images; exactly these digests are then "
              "accepted for this add-on and the decision is audited.", file=sys.stderr)
        return 2
    for line in images.addon_disclosure(args.addon, addon_path, manifest, refs):
        print(line)
    _write_pending(Path(args.pending_file), refs)
    print(f"{len(refs)} image(s) of add-on {args.addon} outside the bill of materials are "
          "accepted once the add-on is registered.")
    return 0


def cmd_image_verify(args: argparse.Namespace) -> int:
    """Check the images compose is about to start: listed with the same digest in the
    signed bill of materials of this core, and signed with its key. Exit 0 when all
    may start, 2 otherwise. `--insecure-images` skips the check for this one call,
    with a banner and one audit row; nothing of it is stored.

    The core's images come from --from-checkout and --images-file, each add-on's from
    its own --addon-images=NAME=FILE: an image accepted outside the bill of materials
    passes only for the add-on it was accepted for (images.load_accepted).

    `--anchor-fingerprint` is the release key of the installed core when this tree is
    the target of an upgrade (images.load_trusted_bom). At `addon install`, images from
    repositories the bill of materials does not list at all are shown with what the
    add-on brings and refused, unless `--accept-unlisted-images` hands exactly those
    digests to `--pending-file` for `image-accept`."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    if args.images_file is None and not args.from_checkout and not args.addon_images:
        print("ERROR: pass --images-file, --from-checkout or --addon-images", file=sys.stderr)
        return 2
    if (args.command == "addon-install") != bool(args.addon and args.addon_path):
        print("ERROR: --addon and --addon-path go with --command=addon-install, and only "
              "there", file=sys.stderr)
        return 2
    if args.accept_unlisted_images and args.command != "addon-install":
        print("ERROR: --accept-unlisted-images is for addon install", file=sys.stderr)
        return 2
    if args.accept_unlisted_images != bool(args.pending_file):
        print("ERROR: --accept-unlisted-images and --pending-file go together",
              file=sys.stderr)
        return 2
    if args.addon and not images.ADDON_NAME_RE.match(args.addon):
        print("ERROR: invalid add-on name", file=sys.stderr)
        return 2
    try:
        correlation = images.correlation_id(args.correlation_id)
        groups = _image_groups(args, repo_root)
    except images.ImageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (suite.SuiteError, OSError, yaml.YAMLError) as exc:
        print(f"ERROR: image list not readable: {exc}", file=sys.stderr)
        return 2
    total = sum(len(refs) for _, refs in groups)
    if total > images.MAX_IMAGES:
        print(f"ERROR: more than {images.MAX_IMAGES} images to check", file=sys.stderr)
        return 2

    if args.insecure_images:
        print(_INSECURE_BANNER.format(command=args.command, count=total), file=sys.stderr)
        row = images.append_audit(config_dir, images.audit_row(args.command, total, correlation))
        print(f"Audit: {row} (correlation id {correlation})", file=sys.stderr)
        return 0

    problems: list[images.Problem] = []
    owners: list[str | None] = []
    try:
        mirror, signatures = images.settings(common.parse_env_file(config_dir / ".env"),
                                             repo_root)
        bom = images.load_trusted_bom(repo_root, anchor=args.anchor_fingerprint)
        cache = images.SignatureCache(config_dir / images.CACHE_PATH)
        registry = images.Registry()
        for owner, refs in groups:
            # The core may use no acceptance; an add-on only its own.
            accepted = images.load_accepted(config_dir, owner) if owner else frozenset()
            found = images.verify_images(
                images.mirrored(refs, mirror), bom, registry=registry, mirror=mirror,
                signatures=signatures, cache=cache, accepted=accepted,
            )
            problems += found
            owners += [owner] * len(found)
        cache.save()
    except images.ImageError as exc:
        print(f"ERROR: image check: {exc}", file=sys.stderr)
        print(f"Nothing was started. To start anyway for this one command, re-run "
              f"'{_retry_hint(args.command)}' with --insecure-images.", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: image check: {exc}", file=sys.stderr)
        return 2
    if (args.command == "addon-install" and problems
            and all(p.unlisted for p in problems)
            and all(owner == args.addon for owner in owners)):
        return _addon_unlisted(args, problems, mirror)
    if problems:
        _print_refusal(problems, total)
        print(f"Nothing was started. To start anyway for this one command, re-run "
              f"'{_retry_hint(args.command)}' with --insecure-images.", file=sys.stderr)
        return 2
    candidate = " (candidate)" if images.is_candidate(images.core_version(repo_root)) else ""
    print(f"{total} image(s) verified against the bill of materials of suite "
          f"{bom['suite']}{candidate} (digest and signature).")
    return 0


def _retry_hint(command: str) -> str:
    """The papaia-ctl command an operator re-runs for an image check of `command`."""
    return "papaia-ctl " + {
        "addon-install": "addon install", "addon-start": "addon start",
        "addon-upgrade": "addon upgrade", "addon-rollback": "addon rollback",
    }.get(command, command)


def cmd_image_accept(args: argparse.Namespace) -> int:
    """Record the add-on images `addon install` showed and the operator accepted, once
    the add-on is registered (`--pending-file`), with one audit row; or, with
    `--forget`, drop what was accepted for an add-on that is uninstalled. The pending
    images are checked again against the bill of materials: only pinned images from
    repositories it does not list are recorded."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    if not images.ADDON_NAME_RE.match(args.addon):
        print("ERROR: invalid add-on name", file=sys.stderr)
        return 2
    if args.forget == bool(args.pending_file):
        print("ERROR: pass --pending-file or --forget", file=sys.stderr)
        return 2
    try:
        correlation = images.correlation_id(args.correlation_id)
        if args.forget:
            dropped = images.forget_accepted(config_dir, args.addon)
            if dropped:
                row = images.append_audit(
                    config_dir, images.forget_row(args.addon, dropped, correlation))
                print(f"Dropped {len(dropped)} accepted image(s) of add-on {args.addon}. "
                      f"Audit: {row}")
            return 0
        refs = _read_image_lines(args.pending_file)
        for ref in refs:
            images.parse_ref(ref)
        bom = images.load_trusted_bom(repo_root)
        images.accept_images(config_dir, args.addon, refs, bom)
    except (images.ImageError, suite.SuiteError, OSError) as exc:
        print(f"ERROR: image accept: {exc}", file=sys.stderr)
        return 2
    row = images.append_audit(config_dir, images.acceptance_row(args.addon, refs, correlation))
    print(f"Accepted {len(refs)} image(s) of add-on {args.addon} outside the bill of "
          f"materials. Audit: {row}")
    return 0


def cmd_image_trust_anchor(args: argparse.Namespace) -> int:
    """Print the fingerprint of the release key pinned in this checkout; exit 2
    without one. `upgrade` carries it into the check of the target."""
    try:
        print(images.anchor_fingerprint(Path(args.repo_root)))
    except images.ImageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_new_correlation_id(args: argparse.Namespace) -> int:
    """Print a new correlation id for the audit rows of one operator action."""
    print(images.correlation_id(None))
    return 0


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
    """Delete the data (volumes), reset the settings and/or delete the operator files of a
    module that is switched off.

    All three are separate options. The settings of a module whose data depends on them (the
    RAG system) are only deleted together with the data. Operator files go only when
    `--operator-files` asks for them. Exit 3 when the request is refused or a step fails, with
    an `ERROR:` line."""
    if not (args.data or args.config or args.operator_files):
        print(
            "ERROR: name what to delete: --data, --config, --operator-files or a combination",
            file=sys.stderr,
        )
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
        if args.operator_files and not module.operator_files:
            # Checked before anything is deleted, so a refused request changes nothing.
            raise modules.ModuleError(f"{module.name} keeps no operator files")
        removed = modules.purge_data(config_dir, repo_root, args.module) if args.data else []
        touched = modules.reset_config(config_dir, repo_root, args.module) if args.config else []
        operator = (
            modules.purge_operator_files(config_dir, args.module) if args.operator_files else []
        )
    except modules.ModuleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    for name in removed:
        # A native LocalAI keeps its data in directories, named by absolute path.
        print(f"removed {'directory' if name.startswith('/') else 'volume'} {name}")
    for item in touched:
        print(f"reset {item}")
    for item in operator:
        print(f"removed file {item}")
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
    if not npm_provision.provision_npm_hosts(tree, config_dir, repo_root):
        return 1
    return 0


def cmd_proxy_list(args: argparse.Namespace) -> int:
    """Host name -> internal target for every interface (lib/ingress.py): what an
    external proxy forwards, what the bundled proxy serves."""
    config_dir = Path(args.config_dir)
    tree = envtree.load_config_dir_tree(config_dir, Path(args.repo_root))
    provider = tree.get("", {}).get("REVERSE_PROXY_PROVIDER") or "internal_nginx"
    if args.if_external and provider != "external_proxy":
        return 0
    try:
        found = ingress.routes(tree, config_dir, Path(args.repo_root))
    except ingress.IngressError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(ingress.to_json(provider, found))
    else:
        if args.if_external:
            print("Forwards to set up at the external proxy (papaia-ctl proxy list):")
        print(ingress.format_table(provider, found), end="")
    return 0


def cmd_secrets_rotate(args: argparse.Namespace) -> int:
    """Replace one stored secret: the proxy's gate secret (lib/paperless_gate.py) or the
    key sealing the connection registry's credentials (lib/connections_profile.py)."""
    from . import connections_profile

    config_dir = Path(args.config_dir)
    targets = (*paperless_gate.ROTATE_TARGETS, *connections_profile.ROTATE_TARGETS)
    if args.target not in targets:
        print(
            f"ERROR: unknown secret '{args.target}'; this command rotates: {', '.join(targets)}",
            file=sys.stderr,
        )
        return 2
    if args.target in connections_profile.ROTATE_TARGETS:
        try:
            summary = connections_profile.rotate_credentials(
                config_dir, correlation=args.correlation_id
            )
        except (connections_profile.ConnectionsError, images.ImageError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"Rotated the secret {args.target}: {summary}")
        return 0
    try:
        paperless_gate.rotate(config_dir, args.target, correlation=args.correlation_id)
    except paperless_gate.GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except images.ImageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Rotated the secret {args.target}.")
    root = common.parse_env_file(config_dir / ".env")
    project = root.get("COMPOSE_PROJECT_NAME") or "papaia"
    if paperless_gate.reload_proxy(project):
        print("The proxy uses the new secret.")
    else:
        print("The proxy does not run here; it uses the new secret when it starts.")
    print(
        "The Paperless gate reads it when the add-on starts again:"
        " papaia-ctl addon start paperless"
    )
    return 0


def cmd_model_keys_sync(args: argparse.Namespace) -> int:
    """After `up`: delete the module keys revoked while LiteLLM was down and give every
    active module the key its model needs call for (docs/model-gateway.md). Prints one
    `MODEL_KEY_CHANGED=<add-on>` line per add-on whose key changed, for `start` to start
    them again. Exit 1 when LiteLLM cannot be reached or the key of an add-on could not be
    checked (the other add-ons are still served); nothing to do without the litellm
    profile."""
    from . import model_gateway

    config_dir = Path(args.config_dir)
    env = common.parse_env_file(config_dir / ".env")
    if "litellm" not in common.cluster_profiles(env):
        return 0
    try:
        admin = model_gateway.connect(config_dir)
        model_gateway.wait_ready(admin, timeout=args.timeout)
        changed, failed = model_gateway.sync(
            config_dir, Path(args.repo_root), admin, correlation=model_gateway.new_correlation()
        )
    except model_gateway.ModelGatewayError as exc:
        print(f"ERROR: module keys: {exc}", file=sys.stderr)
        return 1
    for name in changed:
        print(f"MODEL_KEY_CHANGED={name}")
    for name in failed:
        print(f"ERROR: module keys: addon '{name}': its model key could not be checked "
              "(see the log above)", file=sys.stderr)
    return 1 if failed else 0


def cmd_join_stack_network(args: argparse.Namespace) -> int:
    """Attach the container papaia-ctl runs in to the stack's network (a no-op on the
    host). A failure is a warning: the provisioning steps then report what they skip."""
    tree = envtree.load_config_dir_tree(Path(args.config_dir), Path(args.repo_root))
    network = tree.get("", {}).get("DOCKER_NETWORK") or stack_network.DEFAULT_NETWORK
    done, message = stack_network.join(network)
    if not done:
        print(f"WARNING: cannot join {network}: {message}", file=sys.stderr, flush=True)
    elif message:
        print(message, flush=True)
    return 0 if done else 1


def cmd_keycloak_role_sync(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    if not keycloak_role_sync.sync_roles(tree, config_dir, repo_root):
        return 1
    # The realm sync of declared clients, roles and exchange scopes follows on every start.
    return 0 if realm_sync.sync(tree, config_dir, repo_root) == 0 else 1


def cmd_realm_sync(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    return realm_sync.sync(tree, config_dir, repo_root, check=args.check)


def cmd_realm_keys_apply(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    return realm_sync.apply_keys(tree, config_dir, repo_root, args.module)


def cmd_post_restore(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    tree = envtree.load_config_dir_tree(config_dir, Path(args.repo_root))
    return post_restore.main(tree, config_dir, args.since)


def cmd_halt(args: argparse.Namespace) -> int:
    """The platform halt (lib/halt.py); reads no configuration but the folder itself, so it
    works while every service, Keycloak included, is down."""
    return halt.main(Path(args.config_dir), args.action, args.reason, as_json=args.json)


def cmd_delegation_lifetime(args: argparse.Namespace) -> int:
    """The delegation lifetime of the installation (lib/delegation_lifetime.py): shown
    without values, set with them. Reads the root .env and the settings file only, so it
    works while Keycloak is down; realm sync and catalog render apply a change."""
    return delegation_lifetime.main(
        Path(args.config_dir),
        args.idle_days,
        args.max_days,
        show=args.show,
        as_json=args.json,
    )


def cmd_service_account_list(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    tree = envtree.load_config_dir_tree(config_dir, Path(args.repo_root))
    return service_accounts.list_accounts(tree, config_dir, as_json=args.json)


def cmd_report_permissions(args: argparse.Namespace) -> int:
    """`papaia-ctl report permissions`: papaia-audit builds the report (as its read-only
    report account) and this prints it unchanged; no master admin, no realm read here.
    0 printed, 3 refused by papaia-audit, 1 papaia-audit unavailable or the report not
    buildable, 2 invalid input."""
    try:
        token = access_report.read_token(args.token_file)
        return access_report.run(
            args.by,
            args.format,
            token,
            access_report.service_gate(Path(args.config_dir)),
            sys.stdout,
        )
    except access_report.AuditUnavailable as exc:
        print(f"papaia-audit unavailable: {exc}", file=sys.stderr, flush=True)
        return 1
    except access_report.ReportError as exc:
        print(f"Report refused: {exc}", file=sys.stderr, flush=True)
        return 2


def cmd_report_confirm(args: argparse.Namespace) -> int:
    """`papaia-ctl report confirm`: one recertification through papaia-audit. 0 confirmed,
    3 refused by papaia-audit, 1 papaia-audit unavailable, 2 invalid input."""
    try:
        token = access_report.read_token(args.token_file)
        gate = access_report.service_gate(Path(args.config_dir))
        return access_report.confirm(args.key, args.digest, token, gate, sys.stdout)
    except access_report.AuditUnavailable as exc:
        print(f"papaia-audit unavailable: {exc}", file=sys.stderr, flush=True)
        return 1
    except access_report.ReportError as exc:
        print(f"Confirmation refused: {exc}", file=sys.stderr, flush=True)
        return 2


def cmd_breakglass(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    tree = envtree.load_config_dir_tree(config_dir, Path(args.repo_root))
    return breakglass.main(args.action, tree, config_dir, address=args.address)


def cmd_service_account_rotate(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    tree = envtree.load_config_dir_tree(config_dir, Path(args.repo_root))
    return service_accounts.rotate(tree, config_dir, args.id, grace=args.grace)


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
        # Before anything is written: no recipient, no confirmed target or no room means
        # no snapshot directory at all (BE-14, RE-33).
        plan.recipients = backup_crypt.require_recipients(config_dir)
        if args.rollback_key:
            # R0 of an upgrade: also encrypted to the run's rollback key (BE-11, RE-11).
            if args.only:
                raise backup.BackupError("--rollback-key is for a whole restore point only")
            extra = rollback_key.recipient(config_dir, args.rollback_key)
            if any(r.name == extra.name or r.key == extra.key for r in plan.recipients):
                raise backup.BackupError(
                    f"The rollback key collides with recipient {extra.name!r}"
                )
            plan.recipients = [*plan.recipients, extra]
        backup_crypt.check_target(config_dir, backup_dir)
        backup_crypt.check_free_space(backup_dir)
        common.ensure_dir(plan.snapshot / "volumes")
        common.ensure_dir(plan.snapshot / "binds")
        backup.write_plan(plan)
    except rollback_key.RollbackKeyError as exc:
        return _fail(exc)
    except backup.SelectionError as exc:
        # Before anything is written: a selection that cannot be met leaves no
        # snapshot directory behind, let alone an archive.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except backup.BackupError as exc:
        return _fail(exc)
    for name in plan.skipped:
        print(f"WARNING: declared volume does not exist, skipping: {name}", file=sys.stderr)
    _sweep_rollback_keys(config_dir, keep=args.rollback_key)
    if len(plan.recipients) == 1:
        print(
            "WARNING: only one backup recipient; a lost key makes every point unreadable."
            " Add a second one (emergency key).",
            file=sys.stderr,
        )
    print(f"SNAPSHOT\t{plan.snapshot}")
    if plan.scope:
        print(f"SCOPE\t{','.join(plan.scope)}")
    for artifact in plan.artifacts:
        print(f"{artifact.kind}\t{artifact.archive}\t{artifact.source}\t{artifact.owner}")
    return 0


def _sweep_rollback_keys(config_dir: Path, keep: str | None = None) -> None:
    """Remove rollback keys whose time is over (lib/rollback_key.py). A problem here is
    reported and never stops the command that asked for it; `doctor rollback_window`
    fails for a key that stays past its window."""
    try:
        state = upgrade_stages.load_state(config_dir)
        for upgrade_id in rollback_key.sweep(config_dir, state, keep=keep):
            print(f"Rollback key of upgrade {upgrade_id} deleted: its time is over.",
                  file=sys.stderr)
    except (rollback_key.RollbackKeyError, upgrade_stages.StageError, OSError) as exc:
        print(f"WARNING: rollback keys not checked: {exc}", file=sys.stderr)


def cmd_rollback_key(args: argparse.Namespace) -> int:
    """The rollback key of an upgrade run (lib/rollback_key.py).

    create    a new key pair; prints the upgrade id it belongs to
    identity  the private key of a run, to standard output only when that is no terminal
    discard   remove a key made for a run that never began
    sweep     remove keys whose time is over"""
    config_dir = Path(args.config_dir)
    try:
        if args.action == "create":
            rollback_key.window_hours(config_dir)
            upgrade_id, _public = rollback_key.create(config_dir)
            print(upgrade_id)
        elif args.action == "identity":
            if sys.stdout.isatty():
                raise rollback_key.RollbackKeyError(
                    "The rollback key is never written to a terminal"
                )
            print(rollback_key.identity(config_dir, args.upgrade_id or ""))
        elif args.action == "discard":
            rollback_key.discard_unbegun(
                config_dir, rollback_key.check_id(args.upgrade_id),
                upgrade_stages.load_state(config_dir),
            )
        elif args.action == "sweep":
            _sweep_rollback_keys(config_dir)
    except (rollback_key.RollbackKeyError, upgrade_stages.StageError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
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
        backup_crypt.audit(
            Path(args.config_dir), "backup", "backup_written",
            {"id": entry["id"], "result": args.result, "artifacts": entry["artifacts"],
             "recipients": [r.name for r in plan.recipients],
             "excluded": len(plan.excluded), "scope": plan.scope},
            result="allowed" if args.result != "failed" else "error",
        )
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
    if (args.retention_period_days is None) == (args.keep is None):
        print("ERROR: backup-prune needs --retention-period-days or --keep", file=sys.stderr)
        return 2
    try:
        backup_dir = _resolve_backup_dir(Path(args.config_dir), args.backup_dir)
        if args.keep is not None:
            removed = backup.prune_keep(backup_dir, args.keep)
        else:
            removed = backup.prune(backup_dir, args.retention_period_days)
        for backup_id in removed:
            backup_crypt.audit(
                Path(args.config_dir), "backup-prune", "backup_deleted",
                {"id": backup_id, "reason": "retention"}, effect="delete",
            )
    except backup.BackupError as exc:
        return _fail(exc)
    for backup_id in removed:
        print(backup_id)
    return 0


def cmd_backup_seal(args: argparse.Namespace) -> int:
    """Encrypt the tar.gz stream on standard input to <snapshot>/<archive>."""
    snapshot = Path(args.snapshot)
    try:
        plan = backup.read_plan(snapshot)
        if args.archive not in {a.archive for a in plan.artifacts}:
            raise backup.BackupError(f"{args.archive!r} is not an archive of this plan")
        if not plan.recipients:
            raise backup.BackupError("The plan names no recipient; nothing is written")
        digest = backup_crypt.seal(
            sys.stdin.buffer, snapshot / args.archive, [r.key for r in plan.recipients]
        )
        backup_crypt.record_checksum(snapshot, args.archive, digest)
    except backup.BackupError as exc:
        return _fail(exc)
    return 0


def cmd_backup_recipients(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        if args.action == "add":
            backup_crypt.add_recipient(config_dir, args.name or "", args.key or "")
            print(f"Recipient {args.name} added; it applies from the next backup on.")
        elif args.action == "remove":
            removed = backup_crypt.remove_recipient(config_dir, args.name or "")
            print(f"Recipient {removed.name} removed; the next backup is no longer readable "
                  "with its key.")
            try:
                backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
                points = backup_crypt.points_for_key(backup_dir, removed.key)
            except backup.BackupError:
                points = []
            if points:
                newest, taken = points[-1]
                print(f"Restore points taken up to {taken or 'an unknown date'} stay readable "
                      f"with it until retention or backup-delete removes them (the newest is "
                      f"{newest}, taken {taken or 'at an unknown date'}): "
                      f"{', '.join(point for point, _ in points)}")
        recipients = backup_crypt.load_recipients(config_dir)
    except backup.BackupError as exc:
        return _fail(exc)
    if args.action == "list":
        if not recipients:
            print("No backup recipient is configured.")
        for recipient in recipients:
            print(f"{recipient.name}\t{recipient.key}")
    return 0


def cmd_backup_keygen(args: argparse.Namespace) -> int:
    """Two key pairs (default names betrieb and notfall, for operations and emergencies):
    shown once on the terminal, never stored.

    Only the public keys are kept, and only after the operator typed back the last eight
    characters of the first private key, which proves it was written down."""
    config_dir = Path(args.config_dir)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("ERROR: keys are shown only on a terminal, never into a log or a pipe."
              " Run the command interactively.", file=sys.stderr)
        return 2
    try:
        names = [n.strip() for n in args.names.split(",") if n.strip()]
        if len(names) != 2 or len(set(names)) != 2:
            raise backup.BackupError("--names needs two different names")
        current = backup_crypt.load_recipients(config_dir)
        pairs = [(name, *backup_crypt.generate_pair()) for name in names]
        backup_crypt.parse_recipients(
            backup_crypt.format_recipients(
                [*current, *(backup.Recipient(n, r) for n, _i, r in pairs)]
            )
        )
    except backup.BackupError as exc:
        return _fail(exc)
    print("Two backup keys. Write each private key down or print it and keep the two")
    print("apart (operations at hand, emergency in a safe). They are shown only now and")
    print("are not stored anywhere by papaia-ctl.\n")
    for name, identity, recipient in pairs:
        print(f"  {name}")
        print(f"    private key: {identity}")
        print(f"    public key:  {recipient}\n")
    first_name, first_identity, _ = pairs[0]
    for _attempt in range(3):
        answer = input(f"Last eight characters of the private key '{first_name}': ").strip()
        if answer.upper() == first_identity[-8:]:
            break
        print("That does not match; check the copy.")
    else:
        print("ERROR: not confirmed; no recipient was stored.", file=sys.stderr)
        return 3
    print("\033[2J\033[H", end="")  # clear the screen the keys were shown on
    try:
        for name, _identity, recipient in pairs:
            backup_crypt.add_recipient(config_dir, name, recipient)
    except backup.BackupError as exc:
        return _fail(exc)
    print(f"Recipients {', '.join(names)} stored. Check the emergency key now:")
    print("  papaia-ctl backup key-check --identity=-   (paste the key, then Ctrl-D)")
    return 0


def cmd_backup_target(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
        if args.action == "init":
            installation = backup_crypt.init_target(config_dir, backup_dir)
            print(f"{backup_dir} is the backup target of installation {installation}.")
        else:
            installation = backup_crypt.check_target(config_dir, backup_dir)
            print(f"{backup_dir} is this installation's backup target ({installation}).")
    except backup.BackupError as exc:
        return _fail(exc)
    return 0


def cmd_backup_key_check(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    try:
        backup_dir = _resolve_backup_dir(config_dir, args.backup_dir)
        identities = backup_crypt.read_identities(args.identity)
        point, names = backup_crypt.key_check(
            config_dir, backup_dir, identities, args.restore_point
        )
        # A write: the check updates the record of checked keys (KEY_CHECK_FILE).
        backup_crypt.audit(config_dir, "backup-key-check", "backup_key_checked",
                           {"id": point, "recipients": names})
    except backup.BackupError as exc:
        return _fail(exc)
    print(f"Key opens restore point {point} as recipient {', '.join(names) or '(unnamed)'}.")
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
        identities = backup_crypt.read_identities(args.identity) if args.identity else None
        encrypted = backup_crypt.require_key(manifest, identities)
        if encrypted:
            chosen = selection.artifacts if selection is not None else (
                backup.manifest_artifacts(manifest)
            )
            # Before the stack is touched: the key opens every archive and none changed.
            backup_crypt.verify_archives(
                snapshot, manifest, [a.archive for a in chosen], identities or []
            )
    except (backup.ScopedRestorePointError, backup.EncryptedRestorePointError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except backup.BackupError as exc:
        return _fail(exc)
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    print(f"SNAPSHOT\t{snapshot}")
    print(f"ID\t{entry.get('id')}")
    if encrypted:
        print("ENCRYPTED\t1")
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


def _refuse_terminal(what: str) -> bool:
    if sys.stdout.isatty():
        print(f"ERROR: {what} is written into a pipe only, never onto a terminal.",
              file=sys.stderr)
        return True
    return False


def cmd_backup_identities(args: argparse.Namespace) -> int:
    """The age identities of --identity=FILE|-, one per line, for the restore in bash to
    hand to each archive it opens; read once, so a passphrase is asked for once. The key
    stays in memory: it is never written to a file or onto a terminal."""
    if _refuse_terminal("A backup key"):
        return 2
    try:
        identities = backup_crypt.read_identities(args.identity)
    except backup.BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write("".join(f"{i}\n" for i in identities))
    return 0


def cmd_restore_open(args: argparse.Namespace) -> int:
    """Decrypt one archive of a restore point to standard output, for `restore` to unpack.
    Exit 1 when the key does not open it or the file differs from the manifest."""
    if _refuse_terminal("An archive"):
        return 2
    snapshot = Path(args.snapshot)
    try:
        identities = backup_crypt.read_identities(args.identity)
        manifest = backup.read_manifest(snapshot)
        backup_crypt.open_archive(snapshot, manifest, args.archive, identities,
                                  sys.stdout.buffer)
        sys.stdout.buffer.flush()
    except backup.BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        print(f"ERROR: {args.archive}: the unpacking side stopped reading", file=sys.stderr)
        return 1
    return 0


def _addon_list(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    return [part for part in raw.split(",") if part]


def cmd_module_actions_mark(args: argparse.Namespace) -> int:
    """After a restore wrote something: record the reserved actions due before each add-on
    of the restore starts (lib/module_actions.py). Prints `<add-on>\t<actions>` per add-on."""
    try:
        marked = module_actions.mark(
            Path(args.config_dir), Path(args.repo_root),
            addons=_addon_list(args.addons), trigger=args.trigger,
            restore_point=args.restore_point,
            correlation_id=module_actions.env_correlation(),
        )
    except (module_actions.ModuleActionError, images.ImageError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    for name, actions in marked.items():
        print(f"{name}\t{','.join(actions)}")
    return 0


def cmd_module_actions_pending(args: argparse.Namespace) -> int:
    """What is due before add-on --name starts: `TRIGGER\t<trigger>\t<cid>`, then one
    `ACTION\t<action>\t<service>\t<arg>...` line per action; nothing when nothing is due.
    Exit 3 when the pending file or the manifest cannot be read: the add-on stays down."""
    try:
        trigger, cid, steps = module_actions.pending(
            Path(args.config_dir), Path(args.repo_root), args.name
        )
    except module_actions.ModuleActionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    if steps:
        print(f"TRIGGER\t{trigger}\t{cid}")
        for action, service, arguments in steps:
            print("\t".join(["ACTION", action, service, *arguments]))
    return 0


def cmd_module_actions_done(args: argparse.Namespace) -> int:
    try:
        module_actions.done(Path(args.config_dir), args.name, args.action, args.exit_code)
    except (module_actions.ModuleActionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    return 0


def cmd_module_actions_state(args: argparse.Namespace) -> int:
    print(module_actions.state(Path(args.config_dir), args.marked))
    return 0


def cmd_restore_record(args: argparse.Namespace) -> int:
    try:
        module_actions.record_restore(
            Path(args.config_dir), restore_point=args.restore_point,
            operation=args.operation, result=args.result, duration_s=args.duration,
            post_restore=args.post_restore, module_actions_state=args.module_actions,
            artifacts=args.artifacts, encrypted=args.encrypted,
            correlation_id=module_actions.env_correlation(),
        )
    except (module_actions.ModuleActionError, images.ImageError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
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
    if args.check_markers:
        problems = [m.marker_problem for m in due if m.marker_problem]
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        if problems:
            return 3
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


def _stage_requires(deployed: dict, repo_root: Path) -> dict[str, list[str]]:
    """`requires.addons` names of every active add-on; a malformed manifest is a refusal."""
    requires: dict[str, list[str]] = {}
    for addon in deployment.active_addons(deployed):
        manifest, _ = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        try:
            names = [n for n, _ in compat.required_addons(manifest or {})]
        except ValueError as exc:
            raise upgrade_stages.StageError(f"{addon.get('name')}: {exc}") from None
        requires[str(addon.get("name"))] = names
    return requires


def cmd_upgrade_stage(args: argparse.Namespace) -> int:
    """The staged upgrade's state, plan, write lock and key check (lib/upgrade_stages.py).

    Exit 2 is a refusal before any change; the message is on stderr."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    us = upgrade_stages
    try:
        if args.action == "plan":
            deployed = deployment.load(config_dir)
            versions = cli_addon.active_addon_versions(deployed, repo_root)
            requires = _stage_requires(deployed, repo_root)
            stages = us.select_stages(args.stage, None, requires)
            raw = Path(args.check_file).read_text(encoding="utf-8")
            # An add-on check that crashed leaves nothing behind; that is no "all kept".
            results = json.loads(raw) if raw.strip() else None
            if not isinstance(results, list):
                raise us.StageError("the add-on check gave no result list")
            matrix = suite.load_matrix(Path(args.target_core))
            paths = us.parse_addon_paths(args.addon_path or [], set(versions))
            steps, warnings = us.plan_modules(
                results, versions, matrix, upgrade.normalize_version(args.target), paths,
                args.force,
            )
            for warning in warnings:
                print(f"WARN: {warning}", file=sys.stderr)
            for line in us.describe(steps, stages):
                print(line)
            if args.out:
                common.atomic_write(Path(args.out), json.dumps(steps))
        elif args.action == "identity-check":
            if not args.identity:
                raise us.StageError(
                    f"{us.NO_KEY_MESSAGE} Pass the backup key of a recipient with "
                    "--identity=FILE, or --identity=- to read it from standard input."
                )
            names = us.check_identity(
                config_dir, backup_crypt.read_identities(args.identity)
            )
            print(f"Backup key of {', '.join(names) or 'a recipient'} confirmed.")
        elif args.action == "restore-point":
            point = us.restore_point_for(config_dir, upgrade.normalize_version(args.target))
            if point:
                print(point)
        elif args.action == "kept-key":
            kept = us.kept_run_has_key(config_dir, upgrade.normalize_version(args.target))
            print(f"ROLLBACK_KEY\t{int(kept)}")
        elif args.action == "begin":
            steps = json.loads(Path(args.steps_file).read_text(encoding="utf-8"))
            us.begin(config_dir, source=args.from_version, target=args.to_version,
                     restore_point=args.restore_point, steps=steps,
                     upgrade_id=args.upgrade_id)
        elif args.action == "block":
            for name in us.block_addons(config_dir):
                print(name)
        elif args.action == "record":
            us.record(config_dir, args.stage, args.result, args.seconds)
        elif args.action == "resume-check":
            state = us.load_state(config_dir)
            if state is None or state["finished"] is not None or state["abandoned"] is not None:
                raise us.StageError("No upgrade is in progress; nothing to resume.")
            if state["stages"]["core"]["status"] != "ok":
                raise us.StageError(
                    f"The core stage of the upgrade to {state['to']} has not completed; run "
                    f"'papaia-ctl upgrade --version={state['to']}' again."
                )
            checkout = envtree.resolve_platform_version(repo_root)
            if checkout != state["to"]:
                raise us.StageError(
                    f"The checkout is at {checkout}, the upgrade in progress goes to "
                    f"{state['to']}."
                )
            print(f"FROM\t{state['from']}")
            print(f"TO\t{state['to']}")
            print(f"RESTORE_POINT\t{state['restore_point']}")
            print(f"ROLLBACK_KEY\t{int(rollback_key.exists(config_dir, state['id']))}")
        elif args.action == "steps":
            deployed = deployment.load(config_dir)
            state, stages = us.steps_to_run(
                config_dir, args.stage, _stage_requires(deployed, repo_root)
            )
            if "core" in stages:
                raise us.StageError(
                    f"The core stage is still due; run 'papaia-ctl upgrade "
                    f"--version={state['to']}'."
                )
            by_stage = {s["stage"]: s for s in state["steps"] if s["stage"] != "finish"}
            for stage in stages:
                step = by_stage.get(stage) or {"addon": "-", "action": "-", "path": "-"}
                print(f"STAGE\t{stage}\t{step['addon']}\t{step['action']}\t"
                      f"{step['path'] or '-'}")
        elif args.action == "finish":
            state = us.finish(config_dir)
            for line in us.report(state):
                print(line)
            if rollback_key.exists(config_dir, state["id"]):
                # The upgrade has finished; a window broken during the run only changes
                # what is said about the key, never the result of the stage.
                try:
                    end = rollback_key.deadline(state, rollback_key.window_hours(config_dir))
                except rollback_key.RollbackKeyError as exc:
                    print(f"WARNING: {exc}. The rollback key of this upgrade stays until "
                          "the window is fixed or 'papaia-ctl upgrade --finalize -y' deletes "
                          "it; 'papaia-ctl doctor rollback_window' reports it.",
                          file=sys.stderr)
                else:
                    print(
                        "The rollback key of this upgrade stays until "
                        f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(end))}: until "
                        "then 'papaia-ctl rollback' goes back to the restore point without "
                        "the operator key. 'papaia-ctl upgrade --finalize -y' deletes it "
                        "earlier."
                    )
        elif args.action == "finalize":
            removed = us.finalize(config_dir)
            if removed:
                print(f"Rollback key(s) deleted: {', '.join(removed)}. Going back now needs "
                      "the operator key (--identity).")
            else:
                print("There is no rollback key left on this host.")
        elif args.action == "rollback-plan":
            plan = us.rollback_plan(config_dir, args.restore_point)
            print(f"ID\t{plan['id']}")
            print(f"FROM\t{plan['from']}")
            print(f"TO\t{plan['to']}")
            print(f"RESTORE_POINT\t{plan['restore_point']}")
            print(f"FINISHED\t{plan['finished'] if plan['finished'] is not None else '-'}")
            print(f"ROLLBACK_KEY\t{int(plan['key'])}")
        elif args.action == "rollback-done":
            bundle = upgrade.resolve_current_version(config_dir, repo_root)
            checkout = envtree.resolve_platform_version(repo_root)
            state = us.rollback_done(config_dir, upgrade_id=args.upgrade_id or "",
                                     bundle_version=bundle, checkout_version=checkout)
            print(f"Upgrade to {state['to']} rolled back; the installation is at "
                  f"{state['from']} again (restore point {state['restore_point']}).")
        elif args.action == "release-lock":
            bundle = upgrade.resolve_current_version(config_dir, repo_root)
            checkout = envtree.resolve_platform_version(repo_root)
            state = us.release_lock(config_dir, bundle_version=bundle, checkout_version=checkout)
            print(f"Write lock of the upgrade to {state['to']} released.")
        else:
            raise us.StageError(f"unknown action {args.action!r}")
    except (us.StageError, backup_crypt.BackupError, suite.SuiteError, upgrade.UpgradeError,
            rollback_key.RollbackKeyError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
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


def cmd_librechat_clear_history(args: argparse.Namespace) -> int:
    """Count (`--dry-run`) or remove one user's LibreChat history. Exit 2 for an
    address or date that is not one, 1 on every other failure, also when some files
    could not be removed from storage."""
    try:
        librechat_history.validate_email(args.email)
        if args.before is not None:
            librechat_history.validate_before(args.before)
    except librechat_history.ClearHistoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        result = librechat_history.clear_history(
            Path(args.repo_root),
            Path(args.config_dir),
            args.email,
            before=args.before,
            dry_run=args.dry_run,
        )
    except librechat_history.ClearHistoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(librechat_history.format_result(result, before=args.before))
    return 1 if result.get("files_failed") else 0


def cmd_audit_prepare(args: argparse.Namespace) -> int:
    """Create the missing keys, certificates and passwords of papaia-audit."""
    try:
        audit.prepare(Path(args.config_dir))
        audit.ensure_heads_folder(Path(args.config_dir))
    except (audit.AuditError, OSError) as exc:
        print(f"ERROR: audit store: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_audit_cert(args: argparse.Namespace) -> int:
    """Issue a client certificate for one audit source. Exit 2 for an unknown source."""
    if args.source not in audit.SOURCES:
        print(
            f"ERROR: '{args.source}' is not an audit source. Known: {', '.join(audit.SOURCES)}.",
            file=sys.stderr,
        )
        return 2
    try:
        out_dir = audit.issue_source_certificate(Path(args.config_dir), args.source)
    except (audit.AuditError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Client certificate for {args.source} written to {out_dir}.")
    print("It replaces the previous certificate of this source, which no longer works.")
    return 0


def cmd_audit_token_keys(args: argparse.Namespace) -> int:
    """Fetch the realm's signing keys for the read API of papaia-audit."""
    config_dir = Path(args.config_dir)
    root = envtree.load_config_dir_tree(config_dir, Path(args.repo_root)).get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        print("ERROR: audit token-keys needs the bundled Keycloak (AUTH_PROVIDER).",
              file=sys.stderr)
        return 2
    base_url, ctx = keycloak_role_sync._admin_connection(root, config_dir)
    try:
        discovery, jwks = audit.fetch_token_keys(base_url, ctx)
        path = audit.write_token_keys(config_dir, discovery, jwks)
    except (audit.AuditError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Signing keys of the realm written to {path}; papaia-audit reads them at once.")
    return 0


def cmd_audit_run(args: argparse.Namespace) -> int:
    """`verify`, `heads` or `retention` inside the running papaia-audit; its exit status
    passes through."""
    against = Path(args.against) if getattr(args, "against", None) else None
    try:
        argv, stdin = audit.service_command(
            args.audit_command,
            source=getattr(args, "source", None),
            against=against,
            as_json=getattr(args, "json", False),
        )
        return audit.run_in_service(Path(args.config_dir), argv, stdin)
    except audit.AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_audit_siem_skip(args: argparse.Namespace) -> int:
    """`audit siem skip`: release undelivered events of one source, with a reason."""
    try:
        argv, stdin = audit.siem_skip_command(args.source, args.until, args.reason, args.target)
        return audit.run_in_service(Path(args.config_dir), argv, stdin)
    except audit.AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_audit_idmap(args: argparse.Namespace) -> int:
    """`audit idmap`: one person, one direction, with a confirmed person filter. The token
    of the auditor comes from PAPAIA_AUDIT_TOKEN, never from the command line."""
    try:
        argv, stdin = audit.idmap_command(
            args.ticket, os.environ.get("PAPAIA_AUDIT_TOKEN", "").strip(),
            pseud=args.pseud, tid=args.tid, oid=args.oid,
        )
        return audit.run_in_service(Path(args.config_dir), argv, stdin)
    except audit.AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_doctor(args: argparse.Namespace) -> int:
    """Preflight and diagnostics. Exit 2 if any check failed, else 0; `warn`
    and `skip` never fail the run. Works before `setup`."""
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    skip = _csv(args.skip)
    only = list(dict.fromkeys(args.checks or []))
    try:
        if only:
            # `doctor lifecycle`: the named checks only; the others do not run.
            doctor.parse_skip(only)
            skip = [n for n in (*doctor.CHECK_NAMES, *doctor.DISTRIBUTED_CHECK_NAMES)
                    if n not in only or n in (skip or [])]
        if topology.is_distributed(config_dir):
            report = cluster.run_doctor(cluster.load(config_dir, repo_root), skip=skip)
        else:
            report = doctor.run_checks(config_dir, repo_root, skip=skip)
        if only:
            report.checks = [c for c in report.checks if c.name in only]
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
        return cluster.start(
            found, node=args.node, profiles=_csv(args.profiles) or None, addons=args.addons
        )
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
            addons=args.addons,
        )
    except cluster.ClusterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_cluster_addon(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    try:
        if args.verb == "up" and _project_bundles(found.config_dir, found.repo_root) != 0:
            return 3
        return cluster.addon_action(found, args.name, args.verb)
    except (cluster.ClusterError, nodes.NodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_cluster_lock(args: argparse.Namespace) -> int:
    """--check (the default): exit 2 with the reason while the installation is locked.
    --set / --clear: taken and released by a distributed upgrade."""
    found = _cluster(args)
    if found is None:
        return 2
    if args.set:
        cluster.set_lock(
            found,
            from_version=args.from_version or "?",
            to_version=args.to_version or "?",
            restore_point=args.restore_point or "",
        )
        return 0
    if args.clear:
        cluster.clear_lock(found)
        return 0
    reason = cluster.skew(found)
    if reason:
        print(f"ERROR: locked: {reason}", file=sys.stderr)
        return 2
    return 0


def cmd_cluster_backup(args: argparse.Namespace) -> int:
    """Back up every node into one restore point on the controller. Prints ID and RESULT
    lines (TSV) for bash; exit 2 for a selection that matches nothing, 3 on failure."""
    found = _cluster(args)
    if found is None:
        return 2
    try:
        backup_dir = _resolve_backup_dir(found.config_dir, args.backup_dir)
        backup_id, outcome = cluster_data.run_backup(
            found, backup_dir, only=args.only, retention_days=args.retention_period_days,
            keep=args.keep,
        )
    except backup.SelectionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (backup.BackupError, cluster.ClusterError) as exc:
        return _fail(exc)
    print(f"ID\t{backup_id}")
    print(f"RESULT\t{outcome}")
    return 3 if outcome == "failed" else 0


def cmd_cluster_restore(args: argparse.Namespace) -> int:
    """Restore a point of a distributed installation. With --plan: print what it would
    overwrite (ID and WILL lines) and change nothing."""
    found = _cluster(args)
    if found is None:
        return 2
    try:
        backup_dir = _resolve_backup_dir(found.config_dir, args.backup_dir)
        if args.plan:
            entry, _snapshot, _manifest, artifacts = cluster_data.resolve(
                found, backup_dir, args.restore_point, args.only
            )
            print(f"ID\t{entry.get('id')}")
            for line in cluster_data.describe(artifacts, scoped=bool(args.only)):
                print(f"WILL\t{line}")
            return 0
        restore_id, outcome = cluster_data.run_restore(
            found,
            backup_dir,
            restore_point=args.restore_point,
            only=args.only,
            no_restart=args.no_restart,
        )
    except (
        backup.ScopedRestorePointError, backup.EncryptedRestorePointError, backup.SelectionError
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (backup.BackupError, cluster.ClusterError, nodes.NodeError) as exc:
        return _fail(exc)
    print(f"ID\t{restore_id}")
    print(f"RESULT\t{outcome}")
    return 3 if outcome == "failed" else 0


def cmd_cluster_upgrade_check(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    return cluster_data.check_ready_for_upgrade(found)


def cmd_cluster_migrate(args: argparse.Namespace) -> int:
    found = _cluster(args)
    if found is None:
        return 2
    try:
        cluster.push(found, list(found.topology.nodes))
        return cluster_data.run_migrations(found, args.from_version, args.to_version)
    except (cluster.ClusterError, ValueError) as exc:
        return _fail(exc)


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

    p_derive_auth = sub.add_parser("derive-auth-host")
    p_derive_auth.add_argument("app_host")
    p_derive_auth.add_argument("keycloak_ext_port")
    p_derive_auth.set_defaults(func=cmd_derive_auth_host)

    p_derive_edge = sub.add_parser("derive-edge-url")
    p_derive_edge.add_argument("label", choices=sorted(resolve.EDGE_LABELS))
    p_derive_edge.add_argument("app_host")
    p_derive_edge.add_argument("env_name")
    p_derive_edge.add_argument("provider", nargs="?", default="")
    p_derive_edge.add_argument("allow_direct", nargs="?", default="0")
    p_derive_edge.set_defaults(func=cmd_derive_edge_url)

    p_localai_variants = sub.add_parser("localai-variants")
    p_localai_variants.set_defaults(func=cmd_localai_variants)

    p_native_install = sub.add_parser("localai-native-install")
    p_native_install.set_defaults(func=cmd_localai_native_install)

    p_native_start = sub.add_parser("localai-native-start")
    p_native_start.add_argument("--restart", action="store_true")
    # Seconds to wait for /readyz; the default is READY_TIMEOUT_SECONDS.
    p_native_start.add_argument("--wait", type=float, default=None)
    p_native_start.set_defaults(func=cmd_localai_native_start)

    p_native_stop = sub.add_parser("localai-native-stop")
    p_native_stop.add_argument("--purge-models", action="store_true")
    p_native_stop.set_defaults(func=cmd_localai_native_stop)

    p_native_state = sub.add_parser("localai-native-state")
    p_native_state.set_defaults(func=cmd_localai_native_state)

    p_native_uninstall = sub.add_parser("localai-native-uninstall")
    p_native_uninstall.add_argument("--purge", action="store_true")
    p_native_uninstall.set_defaults(func=cmd_localai_native_uninstall)

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
    p_setup.add_argument("--localai-runtime", choices=list(localai_native.RUNTIMES), default=None)
    p_setup.add_argument("--enable-manager", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-rag", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-voice", choices=["true", "false"], default=None)
    p_setup.add_argument("--voice-variant", choices=["cpu", "nvidia", "hipblas"], default=None)
    p_setup.add_argument("--enable-knowledge-map", choices=["true", "false"], default=None)
    p_setup.add_argument("--enable-connections", choices=["true", "false"], default=None)
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
    pairing_approval.add_parsers(sub)
    module_offer.add_parsers(sub)
    cli_pki.add_parsers(sub)

    p_cluster_start = sub.add_parser("cluster-start")
    p_cluster_start.add_argument("--node", default=None)
    p_cluster_start.add_argument("--profiles", action="append", default=None)
    p_cluster_start.add_argument("--addons", action="store_true")
    p_cluster_start.set_defaults(func=cmd_cluster_start)

    p_cluster_stop = sub.add_parser("cluster-stop")
    p_cluster_stop.add_argument("--node", default=None)
    p_cluster_stop.add_argument("--profiles", action="append", default=None)
    p_cluster_stop.add_argument("--clean-up", action="store_true")
    p_cluster_stop.add_argument("--addons", action="store_true")
    p_cluster_stop.set_defaults(func=cmd_cluster_stop)

    p_cluster_addon = sub.add_parser("cluster-addon")
    p_cluster_addon.add_argument("--name", required=True)
    p_cluster_addon.add_argument("--verb", required=True, choices=["up", "stop", "down"])
    p_cluster_addon.set_defaults(func=cmd_cluster_addon)

    p_cluster_backup = sub.add_parser("cluster-backup")
    p_cluster_backup.add_argument("--backup-dir", default=None)
    p_cluster_backup.add_argument("--only", default=None)
    p_cluster_backup.add_argument("--retention-period-days", type=int, default=None)
    p_cluster_backup.add_argument("--keep", type=int, default=None)
    p_cluster_backup.set_defaults(func=cmd_cluster_backup)

    p_cluster_restore = sub.add_parser("cluster-restore")
    p_cluster_restore.add_argument("--backup-dir", default=None)
    p_cluster_restore.add_argument("--restore-point", default=None)
    p_cluster_restore.add_argument("--only", default=None)
    p_cluster_restore.add_argument("--no-restart", action="store_true")
    p_cluster_restore.add_argument("--plan", action="store_true")
    p_cluster_restore.set_defaults(func=cmd_cluster_restore)

    p_cluster_upgrade_check = sub.add_parser("cluster-upgrade-check")
    p_cluster_upgrade_check.set_defaults(func=cmd_cluster_upgrade_check)

    p_cluster_migrate = sub.add_parser("cluster-migrate")
    p_cluster_migrate.add_argument("--from", dest="from_version", required=True)
    p_cluster_migrate.add_argument("--to", dest="to_version", required=True)
    p_cluster_migrate.set_defaults(func=cmd_cluster_migrate)

    p_cluster_lock = sub.add_parser("cluster-lock")
    p_cluster_lock.add_argument("--set", action="store_true")
    p_cluster_lock.add_argument("--clear", action="store_true")
    p_cluster_lock.add_argument("--from", dest="from_version", default=None)
    p_cluster_lock.add_argument("--to", dest="to_version", default=None)
    p_cluster_lock.add_argument("--restore-point", default=None)
    p_cluster_lock.set_defaults(func=cmd_cluster_lock)

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
    p_module_purge.add_argument("--operator-files", action="store_true")
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
    p_addon_install.add_argument("--node", default=None)
    p_addon_install.set_defaults(func=cli_addon.cmd_addon_install)

    p_addon_start = sub.add_parser("addon-start")
    p_addon_start.add_argument("--name", required=True)
    p_addon_start.add_argument("--force", action="store_true")
    # `start` creates the Keycloak clients after `up`; this only fills in their secrets.
    p_addon_start.add_argument("--no-keycloak", action="store_true")
    p_addon_start.set_defaults(func=cli_addon.cmd_addon_start)

    p_addon_check = sub.add_parser("addon-check")
    p_addon_check.add_argument("--target-core", default=None)
    p_addon_check.add_argument("--target-version", default=None)
    p_addon_check.add_argument("--target-addon-api", type=int, default=None)
    p_addon_check.add_argument("--target-min-addon-api", type=int, default=None)
    p_addon_check.add_argument("--json", action="store_true")
    p_addon_check.add_argument("--force", action="store_true")
    p_addon_check.set_defaults(func=cli_addon.cmd_addon_check)

    p_suite_verify = sub.add_parser("suite-verify")
    p_suite_verify.add_argument("--bom", default=None)
    p_suite_verify.add_argument("--signature", default=None)
    p_suite_verify.add_argument("--key", default=None)
    p_suite_verify.add_argument("--fingerprint", default=None)
    p_suite_verify.add_argument("--suite", default=None)
    p_suite_verify.add_argument("--scope", choices=suite.SCOPES, default="delivery")
    p_suite_verify.add_argument("--json", action="store_true")
    p_suite_verify.set_defaults(func=cmd_suite_verify)

    p_image_verify = sub.add_parser("image-verify")
    p_image_verify.add_argument("--images-file", default=None)
    p_image_verify.add_argument("--from-checkout", action="store_true")
    p_image_verify.add_argument("--command", choices=_IMAGE_COMMANDS, required=True)
    p_image_verify.add_argument("--insecure-images", action="store_true")
    p_image_verify.add_argument("--anchor-fingerprint", default=None)
    p_image_verify.add_argument("--correlation-id", default=None)
    p_image_verify.add_argument("--addon", default=None)
    p_image_verify.add_argument("--addon-path", default=None)
    p_image_verify.add_argument("--accept-unlisted-images", action="store_true")
    p_image_verify.add_argument("--pending-file", default=None)
    p_image_verify.add_argument("--addon-images", action="append", default=None)
    p_image_verify.set_defaults(func=cmd_image_verify)

    p_image_accept = sub.add_parser("image-accept")
    p_image_accept.add_argument("--addon", required=True)
    p_image_accept.add_argument("--pending-file", default=None)
    p_image_accept.add_argument("--forget", action="store_true")
    p_image_accept.add_argument("--correlation-id", default=None)
    p_image_accept.set_defaults(func=cmd_image_accept)

    p_image_anchor = sub.add_parser("image-trust-anchor")
    p_image_anchor.set_defaults(func=cmd_image_trust_anchor)

    p_correlation = sub.add_parser("new-correlation-id")
    p_correlation.set_defaults(func=cmd_new_correlation_id)

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

    p_addon_action = sub.add_parser("addon-action")
    p_addon_action.add_argument("--name", required=True)
    p_addon_action.add_argument("--action", required=True)
    p_addon_action.set_defaults(func=cli_addon.cmd_addon_action)

    p_addon_actions = sub.add_parser("addon-actions")
    p_addon_actions.add_argument("--name", required=True)
    p_addon_actions.add_argument("--json", action="store_true")
    p_addon_actions.set_defaults(func=cli_addon.cmd_addon_actions)

    p_addon_dependents = sub.add_parser("addon-dependents")
    p_addon_dependents.add_argument("--name", required=True)
    p_addon_dependents.add_argument("--force", action="store_true")
    p_addon_dependents.set_defaults(func=cli_addon.cmd_addon_dependents)

    p_addon_state = sub.add_parser("addon-state")
    p_addon_state.add_argument("--name", default=None)
    p_addon_state.add_argument("--all", action="store_true")
    p_addon_state.add_argument("--state", required=True)
    p_addon_state.set_defaults(func=cli_addon.cmd_addon_state)

    p_catalog_render = sub.add_parser("catalog-render")
    p_catalog_render.set_defaults(func=cmd_catalog_render)

    p_settings_show = sub.add_parser("settings-show")
    p_settings_show.add_argument("--json", action="store_true")
    p_settings_show.set_defaults(func=cmd_settings_show)

    p_settings_set = sub.add_parser("settings-set")
    p_settings_set.add_argument("--key", required=True)
    p_settings_set.add_argument("--value", required=True)
    p_settings_set.set_defaults(func=cmd_settings_set)

    p_settings_unset = sub.add_parser("settings-unset")
    p_settings_unset.add_argument("--key", required=True)
    p_settings_unset.set_defaults(func=cmd_settings_unset)

    p_privacy = sub.add_parser("privacy-pack")
    p_privacy.add_argument("--lang", choices=["de"], default="de")
    p_privacy.add_argument("--out", default=None)
    p_privacy.add_argument("--check", action="store_true")
    p_privacy.add_argument("--installation", action="store_true")
    p_privacy.add_argument("--format", choices=list(privacy_pack.FORMATS), default=None)
    p_privacy.add_argument("--backup-retention", type=int, default=None)
    p_privacy.add_argument("--offsite", default=None)
    p_privacy.add_argument("--offsite-retention", type=int, default=None)
    p_privacy.set_defaults(func=cmd_privacy_pack)

    p_person_request = sub.add_parser("person-request")
    p_person_request.add_argument("--operation", required=True, choices=("export", "erase"))
    p_person_request.add_argument("--sub", required=True)
    p_person_request.add_argument("--requested-by", required=True)
    p_person_request.add_argument("--confirmed-by", required=True)
    p_person_request.add_argument("--transfer-to", default=None)
    p_person_request.set_defaults(func=cmd_person_request)

    p_person_status = sub.add_parser("person-status")
    p_person_status.add_argument("--request", required=True)
    p_person_status.set_defaults(func=cmd_person_status)

    p_person_find = sub.add_parser("person-find")
    p_person_find.add_argument("--name", default=None)
    p_person_find.add_argument("--email", default=None)
    p_person_find.set_defaults(func=cmd_person_find)

    p_person_handover = sub.add_parser("person-handover")
    p_person_handover.add_argument("--request", required=True)
    p_person_handover.set_defaults(func=cmd_person_handover)

    p_person_sweep = sub.add_parser("person-sweep")
    p_person_sweep.set_defaults(func=cmd_person_sweep)

    p_person_begin = sub.add_parser("person-begin")
    p_person_begin.add_argument("--work", required=True)
    p_person_begin.add_argument("--request", required=True)
    p_person_begin.set_defaults(func=cmd_person_begin)

    p_person_next = sub.add_parser("person-next")
    p_person_next.add_argument("--work", required=True)
    p_person_next.add_argument("--exit-code", type=int, default=None)
    p_person_next.set_defaults(func=cmd_person_next)

    p_person_finish = sub.add_parser("person-finish")
    p_person_finish.add_argument("--work", required=True)
    p_person_finish.set_defaults(func=cmd_person_finish)

    p_addon_remove = sub.add_parser("addon-remove")
    p_addon_remove.add_argument("--name", required=True)
    p_addon_remove.set_defaults(func=cli_addon.cmd_addon_remove)

    p_addon_uninstall = sub.add_parser("addon-uninstall")
    p_addon_uninstall.add_argument("--name", required=True)
    p_addon_uninstall.add_argument("--purge-data", action="store_true")
    p_addon_uninstall.set_defaults(func=cli_addon.cmd_addon_uninstall)

    p_addon_networks = sub.add_parser("addon-networks")
    p_addon_networks.set_defaults(func=cli_addon.cmd_addon_networks)

    p_model_keys = sub.add_parser("model-keys-sync")
    p_model_keys.add_argument("--timeout", type=int, default=120)
    p_model_keys.set_defaults(func=cmd_model_keys_sync)

    p_active_addons = sub.add_parser("active-addons")
    p_active_addons.set_defaults(func=cli_addon.cmd_active_addons)

    p_proxy_list = sub.add_parser("proxy-list")
    p_proxy_list.add_argument("--json", action="store_true")
    # The end of `setup`: print the list only for an external proxy.
    p_proxy_list.add_argument("--if-external", action="store_true")
    p_proxy_list.set_defaults(func=cmd_proxy_list)

    p_npm = sub.add_parser("npm-provision")
    p_npm.set_defaults(func=cmd_npm_provision)

    p_secrets_rotate = sub.add_parser("secrets-rotate")
    p_secrets_rotate.add_argument("--target", required=True)
    p_secrets_rotate.add_argument("--correlation-id", default=None)
    p_secrets_rotate.set_defaults(func=cmd_secrets_rotate)

    p_join_net = sub.add_parser("join-stack-network")
    p_join_net.set_defaults(func=cmd_join_stack_network)

    p_kc_role_sync = sub.add_parser("keycloak-role-sync")
    p_kc_role_sync.set_defaults(func=cmd_keycloak_role_sync)

    p_realm_sync = sub.add_parser("realm-sync")
    p_realm_sync.add_argument("--check", action="store_true")
    p_realm_sync.set_defaults(func=cmd_realm_sync)

    p_realm_keys = sub.add_parser("realm-keys-apply")
    p_realm_keys.add_argument("--module", required=True)
    p_realm_keys.set_defaults(func=cmd_realm_keys_apply)

    p_addon_clients = sub.add_parser("addon-clients-sync")
    p_addon_clients.add_argument("--names", required=True)
    p_addon_clients.add_argument(
        "--wait", type=int, default=keycloak_role_sync.ADDON_CLIENTS_WAIT_SECONDS
    )
    p_addon_clients.set_defaults(func=cmd_addon_clients_sync)

    p_post_restore = sub.add_parser("post-restore")
    p_post_restore.add_argument("--since", default=None)
    p_post_restore.set_defaults(func=cmd_post_restore)

    p_halt = sub.add_parser("halt")
    p_halt.add_argument("--action", required=True, choices=("set", "clear", "status"))
    p_halt.add_argument("--reason", default=None)
    p_halt.add_argument("--json", action="store_true")
    p_halt.set_defaults(func=cmd_halt)

    p_lifetime = sub.add_parser("delegation-lifetime")
    p_lifetime.add_argument("--idle-days", default=None)
    p_lifetime.add_argument("--max-days", default=None)
    p_lifetime.add_argument("--show", action="store_true")
    p_lifetime.add_argument("--json", action="store_true")
    p_lifetime.set_defaults(func=cmd_delegation_lifetime)

    p_sa_list = sub.add_parser("service-account-list")
    p_sa_list.add_argument("--json", action="store_true")
    p_sa_list.set_defaults(func=cmd_service_account_list)

    p_report = sub.add_parser("report-permissions")
    p_report.add_argument("--by", choices=access_report.KINDS, required=True)
    p_report.add_argument("--format", choices=access_report.FORMATS, default="json")
    p_report.add_argument("--token-file", required=True)
    p_report.set_defaults(func=cmd_report_permissions)

    p_report_confirm = sub.add_parser("report-confirm")
    p_report_confirm.add_argument("--key", required=True)
    p_report_confirm.add_argument("--digest", required=True)
    p_report_confirm.add_argument("--token-file", required=True)
    p_report_confirm.set_defaults(func=cmd_report_confirm)

    p_breakglass = sub.add_parser("breakglass")
    p_breakglass.add_argument("--action", choices=("create", "rotate", "status"), required=True)
    p_breakglass.add_argument("--address", default=None)
    p_breakglass.set_defaults(func=cmd_breakglass)

    p_sa_rotate = sub.add_parser("service-account-rotate")
    p_sa_rotate.add_argument("--id", required=True)
    p_sa_rotate.add_argument("--grace", type=int, default=30)
    p_sa_rotate.set_defaults(func=cmd_service_account_rotate)

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
    p_backup_plan.add_argument("--rollback-key", default=None)
    p_backup_plan.set_defaults(func=cmd_backup_plan)

    p_rollback_key = sub.add_parser("rollback-key")
    p_rollback_key.add_argument("action", choices=["create", "identity", "discard", "sweep"])
    p_rollback_key.add_argument("--upgrade-id", default=None)
    p_rollback_key.set_defaults(func=cmd_rollback_key)

    p_backup_finish = sub.add_parser("backup-finish")
    p_backup_finish.add_argument("--backup-dir", default=None)
    p_backup_finish.add_argument("--snapshot", required=True)
    p_backup_finish.add_argument("--result", choices=["ok", "partial", "failed"], default="ok")
    p_backup_finish.set_defaults(func=cmd_backup_finish)

    p_backup_prune = sub.add_parser("backup-prune")
    p_backup_prune.add_argument("--backup-dir", default=None)
    p_backup_prune.add_argument("--retention-period-days", type=int, default=None)
    p_backup_prune.add_argument("--keep", type=int, default=None)
    p_backup_prune.set_defaults(func=cmd_backup_prune)

    p_backup_seal = sub.add_parser("backup-seal")
    p_backup_seal.add_argument("--snapshot", required=True)
    p_backup_seal.add_argument("--archive", required=True)
    p_backup_seal.set_defaults(func=cmd_backup_seal)

    p_backup_recipients = sub.add_parser("backup-recipients")
    p_backup_recipients.add_argument("action", choices=["list", "add", "remove"])
    p_backup_recipients.add_argument("--name", default=None)
    p_backup_recipients.add_argument("--key", default=None)
    p_backup_recipients.add_argument("--backup-dir", default=None)
    p_backup_recipients.set_defaults(func=cmd_backup_recipients)

    p_backup_keygen = sub.add_parser("backup-keygen")
    p_backup_keygen.add_argument("--names", default="betrieb,notfall")
    p_backup_keygen.set_defaults(func=cmd_backup_keygen)

    p_backup_target = sub.add_parser("backup-target")
    p_backup_target.add_argument("action", choices=["init", "check"])
    p_backup_target.add_argument("--backup-dir", default=None)
    p_backup_target.set_defaults(func=cmd_backup_target)

    p_backup_key_check = sub.add_parser("backup-key-check")
    p_backup_key_check.add_argument("--backup-dir", default=None)
    p_backup_key_check.add_argument("--identity", required=True)
    p_backup_key_check.add_argument("--restore-point", default=None)
    p_backup_key_check.set_defaults(func=cmd_backup_key_check)

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
    p_upgrade_plan.add_argument("--check-markers", action="store_true")
    p_upgrade_plan.set_defaults(func=cmd_upgrade_plan)

    p_upgrade_record = sub.add_parser("upgrade-record")
    p_upgrade_record.add_argument("--migration-id", required=True)
    p_upgrade_record.add_argument("--duration", type=int, default=0)
    p_upgrade_record.set_defaults(func=cmd_upgrade_record)

    p_upgrade_stage = sub.add_parser("upgrade-stage")
    p_upgrade_stage.add_argument(
        "action",
        choices=["plan", "identity-check", "restore-point", "kept-key", "begin", "block", "record",
                 "resume-check", "steps", "finish", "release-lock", "finalize",
                 "rollback-plan", "rollback-done"],
    )
    p_upgrade_stage.add_argument("--check-file", default=None)
    p_upgrade_stage.add_argument("--target", default=None)
    p_upgrade_stage.add_argument("--target-core", default=None)
    p_upgrade_stage.add_argument("--addon-path", action="append", default=None)
    p_upgrade_stage.add_argument("--force", action="store_true")
    p_upgrade_stage.add_argument("--stage", default=None)
    p_upgrade_stage.add_argument("--out", default=None)
    p_upgrade_stage.add_argument("--identity", default=None)
    p_upgrade_stage.add_argument("--from", dest="from_version", default=None)
    p_upgrade_stage.add_argument("--to", dest="to_version", default=None)
    p_upgrade_stage.add_argument("--restore-point", default=None)
    p_upgrade_stage.add_argument("--steps-file", default=None)
    p_upgrade_stage.add_argument("--result", default=None)
    p_upgrade_stage.add_argument("--seconds", type=int, default=None)
    p_upgrade_stage.add_argument("--upgrade-id", default=None)
    p_upgrade_stage.set_defaults(func=cmd_upgrade_stage)

    p_restore_resolve = sub.add_parser("restore-resolve")
    p_restore_resolve.add_argument("--backup-dir", default=None)
    p_restore_resolve.add_argument("--restore-point", default=None)
    p_restore_resolve.add_argument("--only", default=None)
    p_restore_resolve.add_argument("--identity", default=None)
    p_restore_resolve.set_defaults(func=cmd_restore_resolve)

    p_backup_identities = sub.add_parser("backup-identities")
    p_backup_identities.add_argument("--identity", required=True)
    p_backup_identities.set_defaults(func=cmd_backup_identities)

    p_restore_open = sub.add_parser("restore-open")
    p_restore_open.add_argument("--snapshot", required=True)
    p_restore_open.add_argument("--archive", required=True)
    p_restore_open.add_argument("--identity", required=True)
    p_restore_open.set_defaults(func=cmd_restore_open)

    p_restore_record = sub.add_parser("restore-record")
    p_restore_record.add_argument("--restore-point", required=True)
    p_restore_record.add_argument("--operation", required=True)
    p_restore_record.add_argument("--result", required=True)
    p_restore_record.add_argument("--duration", type=int, required=True)
    p_restore_record.add_argument("--post-restore", required=True)
    p_restore_record.add_argument("--module-actions", required=True)
    p_restore_record.add_argument("--artifacts", required=True)
    p_restore_record.add_argument("--encrypted", action="store_true")
    p_restore_record.set_defaults(func=cmd_restore_record)

    p_ma_mark = sub.add_parser("module-actions-mark")
    p_ma_mark.add_argument("--trigger", required=True)
    p_ma_mark.add_argument("--restore-point", required=True)
    p_ma_mark.add_argument("--addons", default=None)
    p_ma_mark.set_defaults(func=cmd_module_actions_mark)

    p_ma_pending = sub.add_parser("module-actions-pending")
    p_ma_pending.add_argument("--name", required=True)
    p_ma_pending.set_defaults(func=cmd_module_actions_pending)

    p_ma_done = sub.add_parser("module-actions-done")
    p_ma_done.add_argument("--name", required=True)
    p_ma_done.add_argument("--action", required=True)
    p_ma_done.add_argument("--exit-code", type=int, required=True)
    p_ma_done.set_defaults(func=cmd_module_actions_done)

    p_ma_state = sub.add_parser("module-actions-state")
    p_ma_state.add_argument("--marked", action="store_true")
    p_ma_state.set_defaults(func=cmd_module_actions_state)

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
    p_doctor.add_argument("checks", nargs="*", metavar="CHECK")
    p_doctor.add_argument("--skip", action="append", default=None)
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    p_clear = sub.add_parser("librechat-clear-history")
    p_clear.add_argument("--email", required=True)
    p_clear.add_argument("--before", default=None)
    p_clear.add_argument("--dry-run", action="store_true")
    p_clear.set_defaults(func=cmd_librechat_clear_history)

    p_audit_prepare = sub.add_parser("audit-prepare")
    p_audit_prepare.set_defaults(func=cmd_audit_prepare)

    p_audit_cert = sub.add_parser("audit-cert")
    p_audit_cert.add_argument("--source", required=True)
    p_audit_cert.set_defaults(func=cmd_audit_cert)

    p_audit_verify = sub.add_parser("audit-verify")
    p_audit_verify.add_argument("--source", default=None)
    p_audit_verify.add_argument("--against", default=None)
    p_audit_verify.add_argument("--json", action="store_true")
    p_audit_verify.set_defaults(func=cmd_audit_run, audit_command="verify")

    p_audit_token_keys = sub.add_parser("audit-token-keys")
    p_audit_token_keys.set_defaults(func=cmd_audit_token_keys)

    p_audit_heads = sub.add_parser("audit-heads")
    p_audit_heads.set_defaults(func=cmd_audit_run, audit_command="heads")
    p_audit_retention = sub.add_parser("audit-retention")
    p_audit_retention.set_defaults(func=cmd_audit_run, audit_command="retention")
    p_audit_siem_status = sub.add_parser("audit-siem-status")
    p_audit_siem_status.set_defaults(func=cmd_audit_run, audit_command="siem-status")
    p_audit_siem_skip = sub.add_parser("audit-siem-skip")
    p_audit_siem_skip.add_argument("--source", required=True)
    p_audit_siem_skip.add_argument("--until", required=True)
    p_audit_siem_skip.add_argument("--reason", default="")
    p_audit_siem_skip.add_argument("--target", default=None)
    p_audit_siem_skip.set_defaults(func=cmd_audit_siem_skip)
    p_audit_idmap = sub.add_parser("audit-idmap")
    p_audit_idmap.add_argument("--ticket", required=True)
    p_audit_idmap.add_argument("--pseud", default=None)
    p_audit_idmap.add_argument("--tid", default=None)
    p_audit_idmap.add_argument("--oid", default=None)
    p_audit_idmap.set_defaults(func=cmd_audit_idmap)

    return parser


_ADDON_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _admin_step_elsewhere(args: argparse.Namespace, argv: list[str]) -> int | None:
    """Run a Keycloak admin step in the one-shot container on the stack network when this
    process cannot reach the admin API: on the host, where Keycloak publishes no port.
    None when the step runs here."""
    if args.command not in keycloak_admin_path.ADMIN_COMMANDS:
        return None
    config_dir = Path(args.config_dir)
    root = common.parse_env_file(config_dir / ".env")
    if not keycloak_admin_path.needs_oneshot(root):
        return None
    command = argv[len(argv) - 1 - argv[::-1].index(args.command):]
    return keycloak_admin_path.run(root, config_dir, Path(args.repo_root), command)


def cmd_addon_clients_sync(args: argparse.Namespace) -> int:
    """The managed Keycloak clients of the named add-ons (`addon start` and `addon upgrade`
    on the host run this in the one-shot container)."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    names = {n for n in args.names.split(",") if n}
    if not names or not all(_ADDON_NAME.match(n) for n in names) or not 0 <= args.wait <= 300:
        print("ERROR: --names takes add-on names, --wait 0 to 300 seconds", file=sys.stderr)
        return 2
    ok = keycloak_role_sync.sync_addon_clients(
        tree, config_dir, repo_root, names, wait=args.wait
    )
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw)
    try:
        elsewhere = _admin_step_elsewhere(args, raw)
        if elsewhere is not None:
            return elsewhere
        return args.func(args)
    except render_core.RenderError as exc:
        # A layer that does not parse (a typo in a hand-edited overlay), or a realm
        # placeholder without a value: say which file, not a traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
