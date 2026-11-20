"""`lib.cli` subcommands of the `pki` profile, called by tools/lib/sh/pki.sh."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import pki


def _paths(args: argparse.Namespace) -> tuple[Path, Path]:
    return Path(args.config_dir), Path(args.repo_root)


def _print_kv(values: dict[str, str]) -> None:
    for key, value in values.items():
        print(f"{key}={value}")


def _fail(exc: Exception) -> int:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 3


def cmd_pki_state(args: argparse.Namespace) -> int:
    """KEY=VALUE lines for the shell: whether the profile is on, and its settings."""
    config_dir, _repo = _paths(args)
    try:
        values = pki.settings(config_dir)
    except pki.PkiError as exc:
        return _fail(exc)
    _print_kv(values)
    return 0


def cmd_pki_configure(args: argparse.Namespace) -> int:
    config_dir, repo_root = _paths(args)
    enable = None if args.enable in (None, "") else args.enable == "true"
    try:
        on = pki.configure(config_dir, repo_root, enable=enable, directory=args.dir or None)
    except pki.PkiError as exc:
        return _fail(exc)
    print(f"PKI_ENABLED={'true' if on else 'false'}")
    return 0


def cmd_pki_plan(args: argparse.Namespace) -> int:
    """Writes the request list for the issuer and prints the settings. With the profile
    off it writes nothing, and names the add-ons that would like certificates."""
    config_dir, repo_root = _paths(args)
    if not pki.enabled(config_dir):
        # Off: a request that cannot be served is no reason to stop anything.
        try:
            modules = sorted({r.module for r in pki.collect(config_dir, repo_root).requests})
        except (pki.PkiError, OSError):
            modules = []
        if modules:
            print(
                f"Note: {', '.join(modules)} can use internal TLS certificates;"
                " 'papaia-ctl setup --pki' switches the PKI on.",
                file=sys.stderr,
            )
        print("PKI_ENABLED=false")
        return 0
    try:
        plan = pki.write_requests(config_dir, repo_root)
        values = pki.settings(config_dir)
    except pki.PkiError as exc:
        return _fail(exc)
    for line in plan.skipped:
        print(f"WARNING: no certificates for {line}", file=sys.stderr)
    _print_kv(values)
    return 0


def cmd_pki_status(args: argparse.Namespace) -> int:
    config_dir, _repo = _paths(args)
    report = pki.status(config_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        sys.stdout.write(pki.format_status(report))
    # Non-zero when something needs a look, so a timer or a monitor can act on it.
    return 1 if report.get("attention") else 0


def add_parsers(sub) -> None:
    p = sub.add_parser("pki-state")
    p.set_defaults(func=cmd_pki_state)

    p = sub.add_parser("pki-configure")
    p.add_argument("--enable", default=None, choices=["true", "false", ""])
    p.add_argument("--dir", default=None)
    p.set_defaults(func=cmd_pki_configure)

    p = sub.add_parser("pki-plan")
    p.set_defaults(func=cmd_pki_plan)

    p = sub.add_parser("pki-status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_pki_status)
