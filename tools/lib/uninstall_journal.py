"""What `addon uninstall` still owes the identity provider and the bundled proxy.

`addon uninstall` removes the add-on's containers, networks, override files, bundle and
deployment entry at once. Its clients in the realm and its proxy hosts live in services
that may not run at that moment, so the command records them here and the steps that own
those services clear them:

- `realm sync` deletes every managed client (`papaia.managed=true`) whose
  `papaia.owner` is a recorded module that is not installed again; the module's service
  accounts and its `aud-*` scopes go anyway, because no installed module declares them
  any more;
- `npm-provision` deletes the proxy hosts of the recorded host names that no installed
  interface serves.

Each step clears its part after it ran without error; an entry with nothing left is
dropped. `addon install` drops the entry of the add-on it installs, so a reinstalled
module keeps its clients.

`$PAPAIA_CONFIG_DIR/security/uninstalled-modules.json`, mode 0600, format
`papaia.uninstalled-modules/1`. Names and host names only, no secret. Every value is
checked when read; a file that does not pass stops the step that reads it.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

FORMAT = "papaia.uninstalled-modules/1"
REALM = "realm"
PROXY = "proxy"
PARTS = (REALM, PROXY)
MAX_BYTES = 256 * 1024
MAX_MODULES = 256
MAX_HOSTS = 64

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9*](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


class JournalError(Exception):
    """The journal cannot be read or written; the message says why."""


def path(config_dir: Path) -> Path:
    return Path(config_dir) / "security" / "uninstalled-modules.json"


def _check_entry(name: object, entry: object) -> dict:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise JournalError(f"{name!r} is not a module name")
    if not isinstance(entry, dict) or set(entry) != {"pending", "proxy_hosts"}:
        raise JournalError(f"{name}: needs exactly pending and proxy_hosts")
    pending = entry["pending"]
    if not isinstance(pending, list) or not set(pending) <= set(PARTS) or not pending:
        raise JournalError(f"{name}: pending must name {' and/or '.join(PARTS)}")
    hosts = entry["proxy_hosts"]
    if (
        not isinstance(hosts, list)
        or len(hosts) > MAX_HOSTS
        or not all(isinstance(h, str) and _HOST_RE.match(h) for h in hosts)
    ):
        raise JournalError(f"{name}: proxy_hosts must be a list of host names")
    return {"pending": sorted(set(pending)), "proxy_hosts": sorted(set(hosts))}


def load(config_dir: Path) -> dict[str, dict]:
    """module -> {pending: [...], proxy_hosts: [...]}; empty without a journal."""
    file = path(config_dir)
    if not file.is_file():
        return {}
    if file.stat().st_size > MAX_BYTES:
        raise JournalError(f"{file} is larger than {MAX_BYTES} bytes")
    try:
        doc = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise JournalError(f"{file} cannot be read: {exc}") from None
    if not isinstance(doc, dict) or set(doc) != {"format", "modules"}:
        raise JournalError(f"{file}: needs exactly format and modules")
    if doc["format"] != FORMAT:
        raise JournalError(f"{file}: format is not {FORMAT}")
    modules = doc["modules"]
    if not isinstance(modules, dict) or len(modules) > MAX_MODULES:
        raise JournalError(f"{file}: modules must be a mapping of at most {MAX_MODULES}")
    try:
        return {name: _check_entry(name, entry) for name, entry in modules.items()}
    except JournalError as exc:
        raise JournalError(f"{file}: {exc}") from None


def _save(config_dir: Path, modules: dict[str, dict]) -> None:
    file = path(config_dir)
    if not modules:
        file.unlink(missing_ok=True)
        return
    file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = json.dumps({"format": FORMAT, "modules": modules}, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=file.parent, prefix=".uninstalled-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, file)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def record(config_dir: Path, name: str, proxy_hosts: list[str]) -> None:
    """Note that `name` was uninstalled: its realm clients and these proxy hosts go."""
    modules = load(config_dir)
    entry = _check_entry(name, {"pending": list(PARTS), "proxy_hosts": list(proxy_hosts)})
    if not entry["proxy_hosts"]:
        entry["pending"] = [REALM]
    modules[name] = entry
    _save(config_dir, modules)


def forget(config_dir: Path, name: str) -> None:
    """`name` is installed again: nothing of it is removed any more."""
    modules = load(config_dir)
    if modules.pop(name, None) is not None:
        _save(config_dir, modules)


def pending(config_dir: Path, part: str) -> dict[str, dict]:
    """The recorded modules for which `part` is still to be done."""
    return {n: e for n, e in load(config_dir).items() if part in e["pending"]}


def done(config_dir: Path, part: str, names: set[str]) -> None:
    """`part` is done for `names`; an entry with nothing left goes."""
    modules = load(config_dir)
    changed = False
    for name in names:
        entry = modules.get(name)
        if entry is None or part not in entry["pending"]:
            continue
        entry["pending"] = [p for p in entry["pending"] if p != part]
        if not entry["pending"]:
            del modules[name]
        changed = True
    if changed:
        _save(config_dir, modules)
