"""`papaia-ctl help` prints a line range of the script's own header.

`usage()` runs `sed -n '2,Np'` over the entrypoint, so the range has to grow
with every command or flag line added to the header. If it does not, the new
lines silently vanish from `help` (too small) or the closing rule and the first
code line leak into it (too large).
"""

from __future__ import annotations

import re
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "papaia-ctl"


def _lines() -> list[str]:
    return CTL.read_text(encoding="utf-8").splitlines()


def _usage_range_end(lines: list[str]) -> int:
    for line in lines:
        match = re.search(r"sed -n '2,(\d+)p'", line)
        if match:
            return int(match.group(1))
    raise AssertionError("usage() no longer prints a fixed header range")


def test_usage_range_covers_exactly_the_header_comment():
    lines = _lines()
    end = _usage_range_end(lines)

    printed = lines[1:end]  # sed line numbers are 1-based and inclusive
    assert all(line.startswith("#") for line in printed), "range runs past the header"
    closing_rule = lines[end]
    assert closing_rule.startswith("# ═"), "range stops before the end of the header"
    assert not lines[end + 1].startswith("#"), "header continues past the closing rule"


def test_help_lists_every_dispatched_command():
    text = CTL.read_text(encoding="utf-8")
    header = "\n".join(_lines()[1 : _usage_range_end(_lines())])
    dispatched = re.findall(r"^    ([a-z][a-z-]*)\) +(?:cmd_|py_cli)", text, re.MULTILINE)

    assert {"status", "doctor"} <= set(dispatched)
    for command in dispatched:
        assert f"papaia-ctl {command}" in header, f"'{command}' missing from the help header"
