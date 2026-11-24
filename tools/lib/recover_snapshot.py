"""`papaia-ctl recover-snapshot`: one command after a VM or volume snapshot came back
(sicherheit §4.9 (3), betrieb BE-16a Nr. 4 and 5, RE-65, RE-84).

A snapshot of the hypervisor brings back the modules' data as it was, while the erasure
journal at the backup target goes on. The core start gate already keeps the edge closed
and replays the account sanctions; what is left is done here, in this order (lib/sh/
backup.sh, `cmd_recover_snapshot`):

1. The mirror's entries the target lacks go to the target (lib/erasure_mirror.py).
2. Every rollback key under `state/rollback/` is deleted: it came from the snapshot, and a
   way back afterwards needs the operator key (`rollback --identity`, BE-13).
3. The core post-restore (realm-wide "not before", the consents of the delegation
   holders) and every add-on's `erasure-replay` and `post-restore` are marked due with the
   trigger `recover-snapshot`, the add-ons are stopped, and `start --addons` runs the core
   step before the first add-on and each add-on's steps before it comes up.
4. One audit row with the counts per add-on; the generation of `epoch` at the target is
   confirmed for `doctor state_epoch`; `doctor` ends the command.

No operator key is needed, and nothing here reads one. This module holds the record of
step 4.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import images, module_actions

MAX_AUDIT_BYTES = 64 << 20


class RecoverError(Exception):
    pass


def _replays(config_dir: Path, correlation_id: str) -> dict[str, dict[str, int] | None]:
    """{add-on: counts} of the successful `erasure-replay` runs of this command."""
    path = Path(config_dir) / images.AUDIT_LOG
    found: dict[str, dict[str, int] | None] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            # The rows of this run are at the end; a huge journal is read from its tail.
            handle.seek(max(0, path.stat().st_size - MAX_AUDIT_BYTES))
            lines = handle.read().splitlines()
    except OSError:
        return found
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        detail = row.get("detail") if isinstance(row, dict) else None
        if (
            not isinstance(detail, dict)
            or row.get("event") != "module_action_run"
            or row.get("correlation_id") != correlation_id
            or row.get("result") != "allowed"
            or detail.get("action") != "erasure-replay"
            or detail.get("trigger") != "recover-snapshot"
        ):
            continue
        counts = detail.get("by_kind")
        found[str(detail.get("addon"))] = counts if isinstance(counts, dict) else None
    return found


def record(config_dir: Path, *, result: str, rollback_keys: int, mirror_added: int,
           duration_s: int, correlation_id: str) -> list[str]:
    """The audit row of one run; returns the operator lines, one per add-on."""
    if result not in ("ok", "failed"):
        raise RecoverError("result must be ok or failed")
    for value in (rollback_keys, mirror_added, duration_s):
        if type(value) is not int or value < 0:
            raise RecoverError("counts must be non-negative integers")
    replays = _replays(config_dir, correlation_id)
    modules = {
        name: None if counts is None else {
            "deletions": counts.get("erase", 0) + counts.get("erase_subject", 0),
            "revocations": counts.get("revoke", 0),
        }
        for name, counts in sorted(replays.items())
    }
    now = time.time()
    images.append_audit(Path(config_dir), {
        "format": "papaia.audit/1",
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int(now % 1 * 1000):03d}Z",
        "correlation_id": correlation_id,
        "writer": "papaia-ctl",
        "role": "operator",
        "sub": None,
        "identity_kind": "host",
        "azp": None,
        "catalog_id": None,
        "operation": "recover_snapshot",
        "effect": "delete",
        "result": "allowed" if result == "ok" else "error",
        "error_code": None if result == "ok" else "recover_snapshot_failed",
        "event": "operation",
        "detail": {"result": result, "modules": modules, "rollback_keys_deleted": rollback_keys,
                   "mirror_entries_added": mirror_added, "duration_s": duration_s,
                   "confirmed_by": images.confirming_user()},
    })
    return [f"{name}: {module_actions.summary(counts)}" for name, counts in sorted(replays.items())]
