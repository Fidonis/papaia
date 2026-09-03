"""Guards the phase-1 -> phase-2 handoff of `papaia-ctl upgrade`.

`upgrade` re-executes `tools/papaia-ctl` from the target tree after moving the
checkout (tools/lib/sh/upgrade.sh). Two things have to hold for that to work on
a normal Linux host, and neither is exercised by the rest of the suite:

  * the handoff must invoke the script through an interpreter, so it does not
    depend on the on-disk execute bit of a file that was just rewritten by
    `git checkout` (and may live on a noexec mount); and
  * `tools/papaia-ctl` must still be shipped executable, because that is how the
    README tells a manual installer to run it.

A regression in either one reproduces as `papaia-ctl upgrade` exiting 126 right
after "Moving the checkout to <tag>...", with the stack already stopped.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UPGRADE_SH = REPO / "tools" / "lib" / "sh" / "upgrade.sh"

_HANDOFF_VIA_INTERPRETER = 'exec "${BASH:-bash}" "$REPO_ROOT/tools/papaia-ctl" upgrade'
_HANDOFF_BY_PATH = 'exec "$REPO_ROOT/tools/papaia-ctl" upgrade'


def test_phase_handoff_runs_papaia_ctl_through_an_interpreter():
    body = UPGRADE_SH.read_text(encoding="utf-8")
    assert _HANDOFF_VIA_INTERPRETER in body, (
        "the upgrade phase handoff must run tools/papaia-ctl through bash, not by path"
    )
    assert _HANDOFF_BY_PATH not in body, (
        "the upgrade phase handoff still execs tools/papaia-ctl by path -- it will"
        " exit 126 wherever the execute bit is enforced"
    )


def test_papaia_ctl_is_tracked_executable():
    if shutil.which("git") is None:
        pytest.skip("git not available")
    out = subprocess.run(
        ["git", "ls-files", "-s", "--", "tools/papaia-ctl"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip("tools/papaia-ctl not tracked in a git checkout here")
    mode = out.stdout.split()[0]
    assert mode == "100755", f"tools/papaia-ctl is tracked as {mode}, expected 100755"
