"""Subcommands of the platform PKI (tools/lib/pki.py, docs/pki.md)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import pki


def cmd_pki_issue(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    try:
        requests = pki.collect(config_dir, repo_root)
        result = pki.issue(config_dir, requests, force=args.force, rotate_ca=args.rotate_ca)
    except (pki.PkiError, OSError) as exc:
        print(f"ERROR: platform PKI: {exc}", file=sys.stderr)
        return 3
    if result.ca:
        print(f"  platform CA {result.ca}", flush=True)
    for verb, labels in (
        ("issued", result.issued),
        ("renewed", result.renewed),
        ("removed", result.removed),
        ("new CA bundle for", result.bundle_updated),
    ):
        for label in labels:
            print(f"  {verb} {label}", flush=True)
    for warning in result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    if result.renewed or result.bundle_updated:
        print(
            "  Running services read the new files when their `generation` changes or at"
            " their next start.",
            flush=True,
        )
    return 0


def cmd_pki_status(args: argparse.Namespace) -> int:
    report = pki.status(Path(args.config_dir))
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    if not report["certificates"]:
        print("No certificates issued yet; 'papaia-ctl start' issues them.")
        return 0
    width = max(len(row["certificate"]) for row in report["certificates"])
    for row in report["certificates"]:
        print(f"{row['certificate']:<{width}}  {row['not_after']}  {row['days_left']:>5} days")
    return 0


def cmd_pki_check_bundle(args: argparse.Namespace) -> int:
    try:
        count = len(pki.check_bundle(Path(args.file)))
    except pki.PkiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    print(f"{count} CA certificate(s) can be used.")
    return 0


def cmd_pki_import_bundle(args: argparse.Namespace) -> int:
    try:
        count = pki.import_bundle(Path(args.config_dir), Path(args.file))
    except (pki.PkiError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    print(f"  {count} company CA certificate(s) in {pki.trust_bundle_path(Path(args.config_dir))}")
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("pki-issue")
    p.add_argument("--force", action="store_true")
    p.add_argument("--rotate-ca", action="store_true")
    p.set_defaults(func=cmd_pki_issue)

    p = sub.add_parser("pki-status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_pki_status)

    p = sub.add_parser("pki-check-bundle")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_pki_check_bundle)

    p = sub.add_parser("pki-import-bundle")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_pki_import_bundle)
