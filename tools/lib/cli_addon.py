"""Addon command handlers for the papaia-ctl Python CLI.

One cmd_* per `papaia-ctl addon <sub>` bash subcommand, plus the
`active-addons` enumeration view the bash dispatcher loops over. Parser
wiring stays in cli.build_parser; this module only implements the handlers
and the shared compatibility-gate helpers.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import (
    addon_update,
    addons,
    common,
    compat,
    components,
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


def _evaluate_gate(
    name: str, manifest: dict, deployed: dict, repo_root: Path, *, force: bool
) -> tuple[compat.CompatResult, int]:
    """The verdict on one addon against this checkout's core, and what the gate
    policy makes of it: 0 (proceed) or 2 (abort)."""
    core = compat.resolve_core_target(repo_root)
    profiles = (deployed.get("core") or {}).get("profiles")
    result = compat.evaluate_addon(name, manifest, core, active_profiles=profiles)
    mode = compat.resolve_mode(deployed)
    return result, compat.gate([result], mode=mode, force=force)


def _compat_gate_addon(
    name: str, manifest: dict, deployed: dict, repo_root: Path, *, force: bool
) -> int:
    """Evaluate one addon against this checkout's core and apply the gate
    policy. Returns 0 (proceed) or 2 (abort). Must run before any mutation,
    so a refused install/start leaves no trace."""
    result, exit_code = _evaluate_gate(name, manifest, deployed, repo_root, force=force)
    _report_compat_result(result, fatal=bool(exit_code), force=force)
    return exit_code


def _render_integration(config_dir: Path, repo_root: Path) -> None:
    """Re-render the core config and regenerate the addon overrides from
    deployment.yaml, as every addon verb that changes the registration does."""
    render_core.render(config_dir, repo_root)
    gen_override.generate_overrides(config_dir, repo_root)
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    auth_provider = tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak")
    gen_override.generate_addon_ssl_cert_overrides(config_dir, auth_provider, repo_root)


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
            if deployment.resolve_addon_path(existing, repo_root).resolve() != addon_path:
                # Registering another directory starts over: the version `previous` records
                # was the one before an update that this install does not continue.
                existing.pop("previous", None)
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
    _render_integration(config_dir, repo_root)

    reporting.print_keycloak_checklist(name, manifest, addon_path, config_dir)
    print(f"Addon installed: {name}")
    if components.parse(manifest):
        bundle_env = common.parse_env_file(bundle_env_path)
        described = components.describe(name, manifest, active=True, bundle_env=bundle_env)
        print(components.format_text([described]))
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


def evaluate_active_addons(
    deployed: dict, repo_root: Path, core: compat.CoreTarget
) -> list[compat.CompatResult]:
    """Evaluate every active addon of `deployed` against `core`.

    Shared by `addon check` and `doctor`, so the two cannot disagree about what
    a verdict is. An addon whose manifest cannot be loaded is an ERROR result,
    not an exception."""
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
    return results


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

    results = evaluate_active_addons(deployed, repo_root, core)

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


def cmd_addon_components(args: argparse.Namespace) -> int:
    """List the software each registered addon bundles, with its version.

    Read-only. An addon's own `version` counts changes to the bundle; the
    `components` of its manifest say what runs inside it, and the addon's `.env`
    in the config bundle can pin another tag than the catalog's, which is shown
    as an override."""
    config_dir = Path(args.config_dir)
    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2
    only = args.name
    if only is not None and not any(a.get("name") == only for a in deployed.get("addons") or []):
        print(f"ERROR: addon '{only}' is not registered.", file=sys.stderr)
        return 2
    found = components.collect(deployed, config_dir, Path(args.repo_root), only)
    if args.json:
        print(components.to_json(found))
    elif found:
        print(components.format_text(found))
    else:
        print("No addons registered.")
    return 0


def _compat_json(result: compat.CompatResult) -> dict:
    return {
        "status": result.status,
        "axis": result.axis,
        "requirement": result.requirement,
        "core_value": result.core_value,
        "reason": result.reason,
        "warnings": list(result.warnings),
    }


def _update_candidate(args: argparse.Namespace) -> tuple[dict, addon_update.Candidate] | None:
    """The deployment and the candidate version for `addon update`, or None
    after printing why the request cannot be met."""
    deployed = deployment.load(Path(args.config_dir))
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return None
    try:
        candidate = addon_update.prepare(deployed, Path(args.repo_root), args.name, Path(args.path))
    except addon_update.UpdateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
    return deployed, candidate


def cmd_addon_update_plan(args: argparse.Namespace) -> int:
    """Check an update and print what it would change. Changes nothing.

    With `--answers-out` this is also the first half of a real update: the
    values the plan needs come from `--answers-file` or, on a terminal, from a
    prompt, and are written (mode 0600) to that file for the apply step. Either
    way a request that cannot be met ends here with status 2, before anything
    on disk is touched."""
    if args.json and args.answers_out:
        print("ERROR: --json only goes with --dry-run.", file=sys.stderr)
        return 2
    found = _update_candidate(args)
    if found is None:
        return 2
    deployed, candidate = found

    result, exit_code = _evaluate_gate(
        args.name, candidate.new_manifest, deployed, Path(args.repo_root), force=args.force
    )
    plan = addon_update.build_plan(candidate, Path(args.config_dir))
    plan["compat"] = _compat_json(result)
    plan["blocked"] = bool(exit_code)
    # Printed even when the gate refuses, so fleet tooling can read `reason`.
    print(json.dumps(plan, indent=2) if args.json else addon_update.format_plan(plan))
    # A caller that merges stderr into stdout must get the document in one piece.
    sys.stdout.flush()
    _report_compat_result(result, fatal=bool(exit_code), force=args.force)
    if exit_code:
        return 2

    if args.answers_out:
        try:
            given = addon_update.read_answers(Path(args.answers_file)) if args.answers_file else {}
            answers = addon_update.collect_answers(plan, given, interactive=sys.stdin.isatty())
        except addon_update.UpdateError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        addon_update.write_answers(Path(args.answers_out), answers)
    return 0


def _print_update_followups(plan: dict, new_manifest: dict, bundle_env_path: Path) -> None:
    """What the operator still has to do by hand after the new version is in place."""
    steps: list[str] = []
    keycloak = plan["manifest"]["keycloak"]
    for client in keycloak["clients_added"]:
        steps.append(f"Import the Keycloak client {client} (Keycloak Admin UI -> Clients).")
    for client, paths in keycloak["mappers_added"].items():
        steps.append(f"Add the protocol mappers {', '.join(paths)} to the client '{client}'.")
    hints = new_manifest.get("env_replace_secrets") or {}
    for item in plan["env"]["new"]:
        if item["class"] == addon_update.KEY_REPLACE_SECRET:
            hint = (hints.get(item["key"]) or {}).get("hint")
            suffix = f" ({hint})." if hint else "."
            steps.append(f"Set {item['key']} in {bundle_env_path}{suffix}")
    if steps:
        print("\nStill to do by hand for this version:")
        for step in steps:
            print(f"  - {step}")


def cmd_addon_update_apply(args: argparse.Namespace) -> int:
    """Move the registration to the new version. Docker is bash's part: it has
    taken the restore point before this and recreates the containers after."""
    found = _update_candidate(args)
    if found is None:
        return 2
    deployed, candidate = found
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    name = args.name

    if _compat_gate_addon(name, candidate.new_manifest, deployed, repo_root, force=args.force):
        return 2
    plan = addon_update.build_plan(candidate, config_dir)
    try:
        given = addon_update.read_answers(Path(args.answers_file)) if args.answers_file else {}
        answers = addon_update.collect_answers(plan, given, interactive=False)
    except addon_update.UpdateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    addon_update.apply_update(
        candidate, plan, answers, config_dir=config_dir, restore_point=args.restore_point
    )
    deployment.save(config_dir, deployed)
    _render_integration(config_dir, repo_root)

    _print_update_followups(plan, candidate.new_manifest, config_dir / "addons" / name / ".env")
    print(
        f"Addon updated: {name} {plan['current']['version'] or 'unknown'}"
        f" -> {plan['candidate']['version'] or 'unknown'}"
    )
    return 0


def _rollback_target(args: argparse.Namespace) -> tuple[dict, dict, Path, dict] | None:
    """The deployment, the entry and what it would go back to, or None after
    printing why it cannot."""
    repo_root = Path(args.repo_root)
    deployed = deployment.load(Path(args.config_dir))
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return None
    try:
        entry, target, manifest = addon_update.rollback_target(deployed, repo_root, args.name)
    except addon_update.UpdateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
    if _compat_gate_addon(args.name, manifest, deployed, repo_root, force=args.force):
        return None
    return deployed, entry, target, manifest


def cmd_addon_rollback_plan(args: argparse.Namespace) -> int:
    """Check a rollback and print what bash needs to carry it out, one
    `KEY<TAB>value` line each. Changes nothing."""
    found = _rollback_target(args)
    if found is None:
        return 2
    _, entry, target, manifest = found
    current, _ = deployment.load_addon_manifest(
        deployment.resolve_addon_path(entry, Path(args.repo_root))
    )
    print(f"FROM\t{addon_update.manifest_version(current or {}) or entry.get('version', '')}")
    print(f"TO\t{addon_update.manifest_version(manifest) or ''}")
    print(f"PATH\t{target}")
    print(f"RESTORE_POINT\t{entry['previous'].get('restore_point', '')}")
    return 0


def cmd_addon_rollback_apply(args: argparse.Namespace) -> int:
    found = _rollback_target(args)
    if found is None:
        return 2
    deployed, entry, target, manifest = found
    config_dir = Path(args.config_dir)
    old_version = entry.get("version") or "unknown"

    addon_update.apply_rollback(entry, target, manifest, config_dir=config_dir)
    deployment.save(config_dir, deployed)
    _render_integration(config_dir, Path(args.repo_root))
    print(f"Addon rolled back: {args.name} {old_version} -> {entry.get('version') or 'unknown'}")
    return 0


def _list_row(entry: dict, deployed: dict, config_dir: Path, repo_root: Path) -> dict:
    name = entry["name"]
    path = deployment.resolve_addon_path(entry, repo_root)
    manifest, error = deployment.load_addon_manifest(path)
    row: dict = {
        "name": name,
        "active": bool(entry.get("active")),
        "path": str(path),
        "version": addon_update.manifest_version(manifest or {}) or entry.get("version"),
        "error": error,
        "components": [],
        "compat": None,
        "previous": None,
    }
    if manifest is not None:
        bundle_env = common.parse_env_file(config_dir / "addons" / name / ".env")
        row["components"] = components.describe(
            name, manifest, active=row["active"], bundle_env=bundle_env
        )["components"]
        core = compat.resolve_core_target(repo_root)
        profiles = (deployed.get("core") or {}).get("profiles")
        row["compat"] = _compat_json(
            compat.evaluate_addon(name, manifest, core, active_profiles=profiles)
        )
    previous = entry.get("previous")
    if isinstance(previous, dict) and previous.get("path"):
        previous_path = deployment.resolve_addon_path(previous, repo_root)
        row["previous"] = {
            "path": str(previous_path),
            "version": previous.get("version"),
            "restore_point": previous.get("restore_point"),
            "available": previous_path.is_dir(),
        }
    return row


def _format_addon_list(rows: list[dict]) -> str:
    table = [("NAME", "VERSION", "ACTIVE", "COMPAT", "PREVIOUS")]
    for row in rows:
        previous = row["previous"]
        table.append(
            (
                row["name"],
                str(row["version"] or "unknown"),
                "yes" if row["active"] else "no",
                (row["compat"] or {}).get("status") or compat.STATUS_ERROR,
                str(previous["version"] or previous["path"]) if previous else "-",
            )
        )
    widths = [max(len(line[i]) for line in table) for i in range(len(table[0]))]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in table
    )


def cmd_addon_list(args: argparse.Namespace) -> int:
    """Every registered addon: where it lives, which version, what it bundles,
    whether this core accepts it, and the version a rollback would go back to.

    Read-only. The verdict is the one `addon check` would give, also for an
    addon that is not active."""
    config_dir = Path(args.config_dir)
    repo_root = Path(args.repo_root)
    deployed = deployment.load(config_dir)
    if not deployed:
        print("ERROR: deployment.yaml not found. Run 'papaia-ctl setup' first.", file=sys.stderr)
        return 2
    rows = [
        _list_row(entry, deployed, config_dir, repo_root)
        for entry in deployed.get("addons") or []
        if entry.get("name")
    ]
    if args.json:
        core = compat.resolve_core_target(repo_root)
        document = {
            "schema_version": addon_update.SCHEMA_VERSION,
            "core": {
                "version": core.platform_version,
                "addon_api": list(core.addon_api) if core.addon_api else None,
            },
            "addons": rows,
        }
        print(json.dumps(document, indent=2))
    elif rows:
        print(_format_addon_list(rows))
    else:
        print("No addons registered.")
    return 0


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

    _render_integration(config_dir, repo_root)

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

    _render_integration(config_dir, repo_root)

    print(f"Addon uninstalled: {name}")
    return 0


def cmd_addon_networks(args: argparse.Namespace) -> int:
    """Print the Docker network name for each active addon (one per line).

    Used by papaia-ctl start to pre-create external networks before the core
    compose starts, so the stack comes up cleanly even when no addon container
    is running yet. Any `${PAPAIA_PROJECT:-...}` scoping in the manifest is
    resolved here against the rendered core .env, so the printed name matches the
    bridge the addon's own compose file creates.
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
            print(gen_override.resolve_app_network(net, config_dir))
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


def cmd_addon_override_files(args: argparse.Namespace) -> int:
    """Print the overrides/addons/ compose files that belong to one addon,
    one absolute path per line.

    Files there are named docker-compose.<segment>.override.yml, where
    <segment> is the addon name, optionally followed by a "-<suffix>" tag
    (the generated "-ssl-cert", or an operator's own e.g. "-ports"). Addon
    names contain hyphens themselves, so a bare "<name>-*" glob cannot tell
    addon "qdrant" apart from addon "qdrant-ingest" -- starting the former
    would otherwise sweep in the latter's overrides and hand docker compose
    a service with no image. Each file is attributed to the longest
    registered addon name that equals <segment> or is a prefix of it before
    a "-"; only the files owned by `name` are printed.
    """
    config_dir = Path(args.config_dir)
    addons_dir = config_dir / "overrides" / "addons"
    if not addons_dir.is_dir():
        return 0

    deployed = deployment.load(config_dir) or {}
    names = {a.get("name") for a in (deployed.get("addons") or []) if a.get("name")}
    # The addon being started is always registered by the time bash reaches
    # here, but tolerate a caller that races an install.
    names.add(args.name)

    prefix, suffix = "docker-compose.", ".override.yml"
    for path in sorted(addons_dir.glob(f"{prefix}*{suffix}")):
        segment = path.name[len(prefix) : -len(suffix)]
        owner = max(
            (n for n in names if segment == n or segment.startswith(f"{n}-")),
            key=len,
            default=None,
        )
        if owner == args.name:
            print(path)
    return 0
