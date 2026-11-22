"""The modules `setup` offers (operation BE-03 No. 6, E-38).

`setup` offers the modules Studio, Data, Flow, Assistant and Paperless in one choice.
Paperless takes the signed-in person from a request header and is safe only behind the
gate the Paperless add-on puts in front of it (README, "Paperless behind the proxy"). A
release offers Paperless only when its signed bill of materials names that gate: an image
with `component: paperless-gate`. The gate runs a generic proxy image, so its image name
cannot say it; the component does.

The rule fails closed:

- a bill of materials without the gate leaves Paperless out of the offer;
- a checkout without a bill of materials (a development checkout) offers no Paperless
  either; `addon install paperless --path=...` stays the development route there and
  checks the add-on's compose file for the gate (lib/cli_addon.py);
- a bill of materials that is there but does not verify is an error, never an offer.

`addon install`, `addon upgrade` and `addon rollback` run one check on the version they
would put in place (`_gate_refuses` in lib/cli_addon.py): its compose file must have the
gate, and with a signed bill of materials in the checkout that bill must list the gate as
well (`install_refusal`). So neither a release without the gate nor an add-on version
without it reaches Paperless by another route.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import images, suite

# The modules of the choice, in the order `setup` names them (BE-03 No. 6).
SELECTABLE = ("studio", "data", "flow", "assist", "paperless")
PAPERLESS = "paperless"
PAPERLESS_GATE = "paperless-gate"
# A module offered only when the bill of materials names the component it needs.
REQUIRED_COMPONENTS = {PAPERLESS: PAPERLESS_GATE}


class OfferError(Exception):
    """A bill of materials that is in the checkout but cannot be trusted."""


@dataclass(frozen=True)
class Offer:
    suite: str | None
    offered: tuple[str, ...]
    withheld: dict[str, str] = field(default_factory=dict)


def offer(doc: dict | None) -> Offer:
    """What `setup` offers from a verified bill of materials, or from none (`None`)."""
    present = suite.components(doc) if doc is not None else set()
    offered: list[str] = []
    withheld: dict[str, str] = {}
    for module in SELECTABLE:
        needed = REQUIRED_COMPONENTS.get(module)
        if needed is None or needed in present:
            offered.append(module)
        elif doc is None:
            withheld[module] = (
                f"no signed bill of materials in this checkout lists its gate '{needed}'"
            )
        else:
            withheld[module] = (
                f"the bill of materials of suite {doc['suite']} does not list its gate "
                f"'{needed}'"
            )
    return Offer(doc["suite"] if doc is not None else None, tuple(offered), withheld)


def load(repo_root: Path) -> dict | None:
    """The verified bill of materials of this checkout; None when the checkout has none.
    A file that is there but does not verify raises OfferError."""
    try:
        version = images.core_version(repo_root)
    except images.ImageError:
        return None
    if not images.bom_path(repo_root, version).is_file():
        return None
    try:
        return images.load_trusted_bom(repo_root)
    except images.ImageError as exc:
        raise OfferError(str(exc)) from None


def install_refusal(name: str, repo_root: Path) -> str | None:
    """Why `addon install <name>` is refused by the bill of materials, or None.

    Only a module that needs a component is checked, and only when the checkout carries a
    bill of materials; without one the add-on's own files are checked instead."""
    needed = REQUIRED_COMPONENTS.get(name)
    if needed is None:
        return None
    try:
        doc = load(repo_root)
    except OfferError as exc:
        return f"the bill of materials of this checkout cannot be trusted: {exc}"
    if doc is None:
        return None
    return offer(doc).withheld.get(name)


def cmd_offer(args: argparse.Namespace) -> int:
    try:
        doc = load(Path(args.repo_root))
    except OfferError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    result = offer(doc)
    if args.json:
        print(json.dumps({"bom": doc is not None, "suite": result.suite,
                          "offered": list(result.offered), "withheld": result.withheld}))
        return 0
    source = f"suite {result.suite}" if doc is not None else "this checkout"
    print(f"Modules offered by {source}: {', '.join(result.offered)}")
    for module, reason in result.withheld.items():
        print(f"Not offered: {module} ({reason}).")
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("module-offer")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_offer)
