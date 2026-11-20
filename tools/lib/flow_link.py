"""The `flow:` section of an add-on at its installation.

Two things happen when an add-on is installed:

1. Its `papaia-app.yaml` and the files below `integration/flow/` are kept in
   `$PAPAIA_CONFIG_DIR/addon-manifests/<name>/` -- nothing else, no `.env`,
   no compose file -- so the workflow module can read the declaration
   without seeing the add-on's secrets. Removing the add-on removes the copy;
   the workflow module then suspends the link.
2. When the workflow module (add-on `papaia-flow`) is installed, the
   operator is shown what the link may do and, on confirmation, the module is
   asked to approve exactly that declaration, named by its digest and the
   version of the add-on. The module decides by its own policy whether one
   administrator may approve it; otherwise it stays a proposal for a second
   person. The call carries the person token of the installing administrator
   (`--flow-token-file` or `PAPAIA_FLOW_TOKEN`) and runs the module's own
   command line inside its API container.

The core copies files and interprets none of the section beyond printing it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TextIO

FLOW_ADDON = "papaia-flow"
SECTION = "flow"
MANIFEST = "papaia-app.yaml"
MANIFESTS_DIR = "addon-manifests"
FLOW_FILES = Path("integration") / "flow"
TOKEN_ENV = "PAPAIA_FLOW_TOKEN"
REASON = "approved at the installation of the add-on"
# How long the installer waits for the workflow module to read the copy.
WAIT_S = 60.0
POLL_S = 2.0
# Inside the API container of the workflow module.
API_URL = "https://flow-api:8444"
API_CA = "/run/flow/api-ca.pem"
API_LABELS = ("de.fidonis.module=papaia-flow", "de.fidonis.flow.role=api")


class FlowError(Exception):
    """The workflow module could not be asked or refused the request."""


class FlowApi(Protocol):
    def show(self, addon: str) -> dict | None: ...

    def approve(self, addon: str, digest: str, version: str, reason: str) -> dict: ...


# ── the copy of the manifest ──────────────────────────────────────────────────


def manifests_dir(config_dir: Path) -> Path:
    return Path(config_dir) / MANIFESTS_DIR


def keep_manifest(addon_path: Path, config_dir: Path, name: str) -> Path | None:
    """Replace the kept copy of `name` with the manifest of `addon_path` and
    its regular files below `integration/flow/`. Linked files are skipped:
    a link could point at a secret outside the add-on."""
    source = Path(addon_path) / MANIFEST
    if source.is_symlink() or not source.is_file():
        return None
    dest = manifests_dir(config_dir) / name
    drop_manifest(config_dir, name)
    dest.mkdir(parents=True)
    shutil.copyfile(source, dest / MANIFEST)
    flow_dir = Path(addon_path) / FLOW_FILES
    if flow_dir.is_dir() and not flow_dir.is_symlink():
        root = flow_dir.resolve()
        for path in sorted(flow_dir.rglob("*")):
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                continue
            target = dest / FLOW_FILES / path.relative_to(flow_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    return dest


def drop_manifest(config_dir: Path, name: str) -> None:
    dest = manifests_dir(config_dir) / name
    if dest.is_dir() and not dest.is_symlink():
        shutil.rmtree(dest)
    elif dest.exists() or dest.is_symlink():
        dest.unlink()


# ── the workflow module ───────────────────────────────────────────────────────


def flow_installed(deployed: dict) -> bool:
    return any(
        a.get("name") == FLOW_ADDON and a.get("active")
        for a in (deployed or {}).get("addons") or []
    )


def token_from(token_file: str | None) -> str:
    """The person token of the installing administrator; never an argument
    on the command line (process list, shell history)."""
    if token_file:
        return Path(token_file).read_text(encoding="utf-8").strip()
    return os.environ.get(TOKEN_ENV, "").strip()


class DockerFlow:
    """The command line of the workflow module inside its API container."""

    def __init__(self, token: str, runner: Callable[..., Any] = subprocess.run) -> None:
        self.token = token
        self.runner = runner
        self._found = ""

    def _container(self) -> str:
        if self._found:
            return self._found
        argv = ["docker", "ps", "-q"]
        for label in API_LABELS:
            argv += ["--filter", f"label={label}"]
        done = self.runner(argv, capture_output=True, text=True, check=False)
        found = (done.stdout or "").split()
        if done.returncode != 0 or not found:
            raise FlowError("the API container of the workflow module is not running")
        self._found = found[0]
        return self._found

    def _flow(self, *args: str) -> tuple[int, str, str]:
        argv = ["docker", "exec", "-i", "-e", "FLOW_TOKEN", self._container()]
        argv += ["flow", "--api", API_URL, "--ca", API_CA, *args]
        env = {**os.environ, "FLOW_TOKEN": self.token}
        done = self.runner(argv, capture_output=True, text=True, check=False, env=env)
        return done.returncode, done.stdout or "", done.stderr or ""

    @staticmethod
    def _json(stdout: str) -> dict:
        try:
            data = json.loads(stdout)
        except ValueError as exc:
            raise FlowError("the workflow module gave no readable answer") from exc
        if not isinstance(data, dict):
            raise FlowError("the workflow module gave no readable answer")
        return data

    def show(self, addon: str) -> dict | None:
        status, stdout, stderr = self._flow("link", "show", addon)
        if status != 0:
            if "FLOW-API-NOT-FOUND" in stderr:
                return None
            raise FlowError(stderr.strip().splitlines()[0] if stderr.strip() else "failed")
        return self._json(stdout)

    def approve(self, addon: str, digest: str, version: str, reason: str) -> dict:
        status, stdout, stderr = self._flow(
            "link",
            "approve",
            addon,
            "--at-install",
            "--digest",
            digest,
            "--addon-version",
            version,
            "--reason",
            reason,
        )
        if status != 0:
            raise FlowError(stderr.strip() or "failed")
        return self._json(stdout)


def client(token: str) -> FlowApi:
    return DockerFlow(token)


# ── the link at installation ─────────────────────────────────────────────────


def summary(shown: dict) -> list[str]:
    """What the link may do, from the declaration as the module read it."""
    declaration = shown.get("declaration") or {}
    lines = [
        f"Flow link of {shown.get('addon')} {shown.get('addon_version')}"
        f" (declaration {shown.get('declaration_digest')}):"
    ]
    events = declaration.get("events") or []
    lines.append("  events (start or signal a workflow; their data stays untrusted):")
    for event in events:
        hint = event.get("data_class_hint", "none")
        lines.append(f"    - {event.get('name')} ({event.get('format')}, data class hint {hint})")
    if not events:
        lines.append("    (none)")
    actions = declaration.get("actions") or []
    lines.append("  actions (a workflow may call them):")
    for action in actions:
        if action.get("via") == "rest":
            where = f"rest {action.get('method')} {action.get('base_url')}{action.get('path')}"
        else:
            where = f"tools {action.get('server')}/{action.get('tool')}"
        limit = action.get("data_class_max", "no limit")
        lines.append(
            f"    - {action.get('name')}: {where}, identity {action.get('identity')},"
            f" effect {action.get('effect')}, data class up to {limit}"
        )
    if not actions:
        lines.append("    (none)")
    return lines


def _later(name: str, out: TextIO) -> None:
    print(
        f"  Approve later as an administrator of Flow: flow link show {name}, then"
        f" flow link approve {name} --at-install --digest <declaration_digest>"
        " --addon-version <version> --reason <text>",
        file=out,
    )


def _wait(
    api: FlowApi, name: str, version: str, wait_s: float, poll_s: float, sleep
) -> dict | None:
    """The link as the module shows it once it has read this version."""
    attempts = int(wait_s // poll_s) + 1 if poll_s > 0 else 1
    for attempt in range(attempts):
        shown = api.show(name)
        if shown is not None and str(shown.get("addon_version")) == version:
            return shown
        if attempt + 1 < attempts:
            sleep(poll_s)
    return None


def link_at_install(  # noqa: PLR0911, PLR0913 - one outcome per case
    name: str,
    manifest: dict,
    make_client: Callable[[str], FlowApi | None],
    *,
    approve: bool,
    ask: Callable[[str], str] | None,
    token: str,
    out: TextIO,
    wait_s: float = WAIT_S,
    poll_s: float = POLL_S,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Show the link of `name` and ask the module to approve it. Returns the
    outcome: none, no_token, not_read, unchanged, refused, approved,
    proposal or error. Nothing is approved without a confirmation (`approve`
    or a `y` from `ask`); a failure is reported and never fails the install."""
    if not manifest.get(SECTION):
        return "none"
    if not token:
        print(
            f"NOTE: {name} declares a Flow link; without a token of a Flow administrator"
            f" ({TOKEN_ENV} or --flow-token-file) it stays a proposal.",
            file=out,
        )
        _later(name, out)
        return "no_token"
    version = str(manifest.get("version", ""))[:64]
    api = make_client(token)
    try:
        shown = _wait(api, name, version, wait_s, poll_s, sleep)
        if shown is None:
            print(
                f"WARNING: Flow did not show the link of {name} {version}; is"
                f" PAPAIA_FLOW_ADDON_DIR the directory {MANIFESTS_DIR} of the config dir?",
                file=out,
            )
            _later(name, out)
            return "not_read"
        if not shown.get("pending"):
            print(
                f"Flow link of {name}: nothing to approve (state {shown.get('state')});"
                " the declaration in force stays.",
                file=out,
            )
            return "unchanged"
        for line in summary(shown):
            print(line, file=out)
        confirmed = approve
        if not confirmed and ask is not None:
            reply = ask(f"Approve the Flow link of {name} as shown? [y/N] ")
            confirmed = reply.strip().lower() in ("y", "yes")
        if not confirmed:
            print(
                f"Flow link of {name} not approved; it stays a proposal. Run the install"
                " again with --approve-flow-link to approve it as shown.",
                file=out,
            )
            _later(name, out)
            return "refused"
        answer = api.approve(name, str(shown["declaration_digest"]), version, REASON)
    except FlowError as exc:
        print(f"WARNING: Flow link of {name} not approved: {exc}", file=out)
        _later(name, out)
        return "error"
    if answer.get("approved_at_install"):
        print(f"Flow link of {name} approved at install.", file=out)
        return "approved"
    print(
        f"Flow link of {name} stays a proposal for a second person:"
        f" {', '.join(answer.get('reasons') or [])}",
        file=out,
    )
    if answer.get("widened"):
        print(
            f"  widened against the approved declaration: {', '.join(answer['widened'])}", file=out
        )
    return "proposal"
