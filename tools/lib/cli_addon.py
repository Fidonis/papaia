"""Addon command handlers for the papaia-ctl Python CLI.

One cmd_* per `papaia-ctl addon <sub>` bash subcommand, plus the
`active-addons` enumeration view the bash dispatcher loops over. Parser
wiring stays in cli.build_parser; this module only implements the handlers
and the shared compatibility-gate helpers.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import (
    addons,
    common,
    compat,
    deployment,
    envtree,
    gen_override,
    render_core,
    reporting,
)


def _report_compat_result(result: compat.CompatResult, *, fatal: bool, force: bool) -> None:
    """Print the non-OK part of one gate verdict to stderr."""
    if result.status == compat.STATUS_ERROR:
        print(f"ERROR: addon '{result.name}': {result.reason}", file=sys.stderr)
    elif result.status == compat.STATUS_INCOMPATIBLE:
        if fatal:
            print(
                f"ERROR: addon '{result.name}' is incompatible with this core:"
                f" {result.reason}",
                file=sys.stderr,
            )
        else:
            cause = "--force" if force else "warn mode"
            print(
                f"WARNING: addon '{result.name}' is incompatible ({result.reason})"
                f" -- continuing due to {cause}",
                file=sys.stderr,
            )
    elif result.status == compat.STATUS_UNKNOWN:
        print(
            f"WARNING: addon '{result.name}': compatibility unknown ({result.reason})",
            file=sys.stderr,
        )
    for warning in result.warnings:
        print(f"WARNING: addon '{result.name}': {warning}", file=sys.stderr)


def _compat_gate_addon(
    name: str, manifest: dict, deployed: dict, repo_root: Path, *, force: bool
) -> int:
    """Evaluate one addon against this checkout's core and apply the gate
    policy. Returns 0 (proceed) or 2 (abort). Must run before any mutation,
    so a refused install/start leaves no trace."""
    core = compat.resolve_core_target(repo_root)
    profiles = (deployed.get("core") or {}).get("profiles")
    result = compat.evaluate_addon(name, manifest, core, active_profiles=profiles)
    mode = compat.resolve_mode(deployed)
    exit_code = compat.gate([result], mode=mode, force=force)
    _report_compat_result(result, fatal=bool(exit_code), force=force)
    return exit_code


def cmd_addon_install(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addon_entries: list[dict] = deployed.setdefault("addons", [])
    existing = next((a for a in addon_entries if a.get("name") == name), None)

    if existing is None and not args.path:
        print(
            f"ERROR: --path is required when installing a new addon '{name}'.",
            file=sys.stderr,
        )
        return 2

    # Resolve path + manifest and run the compatibility gate before the
    # deployment entry is touched or anything is seeded to disk, so a
    # refused install leaves deployment.yaml and the config dir unchanged.
    if args.path:
        addon_path = Path(args.path).resolve()
    else:
        addon_path = deployment.resolve_addon_path(existing, repo_root)

    manifest, manifest_error = deployment.load_addon_manifest(addon_path)
    if manifest is None:
        print(f"ERROR: {manifest_error}", file=sys.stderr)
        return 2
    if _compat_gate_addon(name, manifest, deployed, repo_root, force=args.force):
        return 2

    if existing:
        if args.path:
            existing["path"] = str(addon_path)
        if args.version:
            existing["version"] = args.version
        existing["active"] = True
    else:
        entry: dict = {"name": name, "path": str(addon_path), "active": True}
        if args.version:
            entry["version"] = args.version
        addon_entries.append(entry)

    addons.seed_addon_env(addon_path, config_dir)

    bundle_env_path = config_dir / "addons" / name / ".env"
    updates = addons.prompt_change_me_vars(bundle_env_path, manifest, config_dir)
    if updates:
        env_vals = common.parse_env_file(bundle_env_path)
        env_vals.update(updates)
        common.write_env_file(bundle_env_path, env_vals)

    deployment.save(config_dir, deployed)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)

    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_addon_ssl_cert_overrides(config_dir, auth_provider, repo_root)

    reporting.print_keycloak_checklist(name, manifest, addon_path, config_dir)
    print(f"Addon installed: {name}")
    return 0


def cmd_addon_start(args: argparse.Namespace) -> int:
    """Materialize .env into checkout and re-render. Docker compose up is done by bash."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployed = deployment.load(config_dir)
    addon_entries: list[dict] = deployed.get("addons") or []
    entry = next((a for a in addon_entries if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2
    if not entry.get("active"):
        print(
            f"ERROR: addon '{name}' is not active. Run 'papaia-ctl addon install {name}' first.",
            file=sys.stderr,
        )
        return 2

    addon_path = deployment.resolve_addon_path(entry, repo_root)

    # Re-check compatibility on every start: the core may have been
    # upgraded since the addon was installed.
    manifest, manifest_error = deployment.load_addon_manifest(addon_path)
    if manifest is None:
        print(f"ERROR: {manifest_error}", file=sys.stderr)
        return 2
    if _compat_gate_addon(name, manifest, deployed, repo_root, force=args.force):
        return 2

    addons.materialize_addon_env(config_dir, addon_path, name)
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    return 0


def cmd_addon_check(args: argparse.Namespace) -> int:
    """Evaluate every active addon against a core and report the verdict
    before anything changes.

    The core defaults to this checkout. `--target-core=PATH` points at an
    update candidate (git worktree, unpacked tarball) and reads VERSION,
    ADDON_API, and the compose services from there -- a service rename in
    the target is detected before the switch. `--target-version` /
    `--target-addon-api` are manual fallbacks when no candidate checkout is
    at hand; each evaluates only the axis it actually knows about."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)

    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    core_label = "CORE"
    try:
        if args.target_core:
            target_root = Path(args.target_core)
            if not target_root.is_dir():
                print(f"ERROR: --target-core path not found: {target_root}", file=sys.stderr)
                return 2
            core = compat.resolve_core_target(target_root)
            core_label = "CORE(target)"
        elif args.target_version or args.target_addon_api is not None:
            window = None
            if args.target_addon_api is not None:
                # Without an explicit min the window is assumed closed at the
                # target generation -- pessimistic (may block, never passes a
                # break through).
                minimum = (
                    args.target_min_addon_api
                    if args.target_min_addon_api is not None
                    else args.target_addon_api
                )
                if minimum > args.target_addon_api:
                    print(
                        "ERROR: --target-min-addon-api must be <= --target-addon-api",
                        file=sys.stderr,
                    )
                    return 2
                window = (minimum, args.target_addon_api)
            core = compat.CoreTarget(platform_version=args.target_version, addon_api=window)
            core_label = "CORE(target)"
        else:
            core = compat.resolve_core_target(repo_root)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    profiles = (deployed.get("core") or {}).get("profiles")
    results: list[compat.CompatResult] = []
    for addon in deployment.active_addons(deployed):
        name = addon.get("name", "?")
        manifest, manifest_error = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if manifest is None:
            results.append(compat.CompatResult(name, compat.STATUS_ERROR, reason=manifest_error))
            continue
        results.append(compat.evaluate_addon(name, manifest, core, active_profiles=profiles))

    mode = compat.resolve_mode(deployed)
    exit_code = compat.gate(results, mode=mode, force=args.force)
    if args.json:
        # Emitted even on exit 2 so fleet tooling can read `reason`.
        print(compat.to_json(results))
    elif results:
        print(compat.format_table(results, core_label=core_label))
    else:
        print("No active addons.")
    if not args.json and exit_code == 0:
        degraded = [r for r in results if r.status == compat.STATUS_INCOMPATIBLE]
        if degraded:
            cause = "--force" if args.force else "warn mode"
            print(
                f"WARNING: incompatibilities degraded to warnings ({cause}).",
                file=sys.stderr,
            )
    return exit_code


def cmd_addon_remove(args: argparse.Namespace) -> int:
    """Remove integration only: override gone, active=false, re-render. Bundle kept."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addon_entries: list[dict] = deployed.get("addons") or []
    entry = next((a for a in addon_entries if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    entry["active"] = False
    deployment.save(config_dir, deployed)

    override_file = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    override_file.unlink(missing_ok=True)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_addon_ssl_cert_overrides(config_dir, auth_provider, repo_root)

    print(f"Addon removed: {name}")
    return 0


def cmd_addon_uninstall(args: argparse.Namespace) -> int:
    """Remove integration + delete config bundle + deployment entry. Docker down done by bash."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2

    addon_entries: list[dict] = deployed.get("addons") or []
    entry = next((a for a in addon_entries if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    override_file = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    override_file.unlink(missing_ok=True)

    # The deployment entry is gone after this command, so the generic
    # regeneration below can no longer see the addon — unlink its ssl-cert
    # override explicitly, mirroring the network override above.
    ssl_override_file = (
        config_dir / "overrides" / "addons" / f"docker-compose.{name}-ssl-cert.override.yml"
    )
    ssl_override_file.unlink(missing_ok=True)

    bundle_dir = config_dir / "addons" / name
    if bundle_dir.is_dir():
        shutil.rmtree(bundle_dir)

    deployed["addons"] = [a for a in addon_entries if a.get("name") != name]
    deployment.save(config_dir, deployed)

    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_addon_ssl_cert_overrides(config_dir, auth_provider, repo_root)

    print(f"Addon uninstalled: {name}")
    return 0


def cmd_addon_networks(args: argparse.Namespace) -> int:
    """Print the Docker network name for each active addon (one per line).

    Used by papaia-ctl start to pre-create external networks before the core
    compose starts, so the stack comes up cleanly even when no addon container
    is running yet.
    """
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    deployed = deployment.load(config_dir)
    for addon in deployment.active_addons(deployed):
        manifest, _ = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if manifest is None:
            continue
        net = (manifest.get("networks") or {}).get("app_network")
        if net:
            print(net)
    return 0


def cmd_active_addons(args: argparse.Namespace) -> int:
    """Print the name of each active addon (one per line).

    Exists so the bash dispatcher can enumerate addons without parsing
    deployment.yaml itself -- the script header's stated contract."""
    deployed = deployment.load(Path(args.config_dir))
    for addon in deployment.active_addons(deployed):
        name = addon.get("name")
        if name:
            print(name)
    return 0


def cmd_addon_path(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    deployed = deployment.load(config_dir)
    addon_entries: list[dict] = deployed.get("addons") or []
    entry = next((a for a in addon_entries if a.get("name") == name), None)
    if entry is None:
        print(f"ERROR: addon '{name}' is not registered.", file=sys.stderr)
        return 2

    print(deployment.resolve_addon_path(entry, repo_root))
    return 0
