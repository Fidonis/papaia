"""papaia-ctl runs with `set -o pipefail`. A reader that stops at its first match or line
(`grep -q`, `grep -m`, `grep -l`, `head`, `sed -n '...q'`) closes the pipe while the writer
may still write; the writer dies of SIGPIPE (exit 141) and pipefail fails the whole
pipeline, so the check reads "no match" although there was one. Under load this refused a
valid `rollback`. Capture the output first, then match on it:

    text="$(git show ...)" || ...
    grep -q pattern <<< "$text"
"""

from __future__ import annotations

import re
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
SOURCES = [TOOLS / "papaia-ctl", *sorted((TOOLS / "lib").rglob("*.sh"))]

# One stage of a pipeline: `|` (not `||`), then the command up to the next separator
# outside quotes.
_STAGE = re.compile(r"""(?<!\|)\|(?!\|)\s*((?:'[^']*'|"[^"]*"|[^|;&)'"])*)""")
_GREP_EARLY = re.compile(r"(^|\s)(-[A-Za-z]*[qmlL][A-Za-z0-9]*|--quiet|--silent|--max-count\S*"
                         r"|--files-with(out)?-match(es)?)(\s|$)")


def _stops_early(stage: str) -> bool:
    words = stage.split()
    if not words:
        return False
    command, args = words[0], " ".join(words[1:])
    if command in ("grep", "egrep", "fgrep"):
        return bool(_GREP_EARLY.search(" " + args + " "))
    if command == "head":
        return True
    if command == "sed":
        return "-n" in words[1:] and bool(re.search(r"\dq|\$?q\b|/q", args))
    return False


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Joins lines continued with a trailing backslash or pipe, or by a leading pipe."""
    raw = text.splitlines()
    result: list[tuple[int, str]] = []
    i = 0
    while i < len(raw):
        start, line = i + 1, raw[i]
        while i + 1 < len(raw):
            tail = line.rstrip()
            following = raw[i + 1].lstrip()
            if tail.endswith("\\"):
                line = tail[:-1] + " " + following
            elif tail.endswith("|") and not tail.endswith("||"):
                line = tail + " " + following
            elif following.startswith("|") and not following.startswith("||"):
                line = tail + " " + following
            else:
                break
            i += 1
        result.append((start, line))
        i += 1
    return result


def early_readers(text: str) -> list[tuple[int, str]]:
    found = []
    for number, line in _logical_lines(text):
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#"):
            continue
        if any(_stops_early(m.group(1)) for m in _STAGE.finditer(code)):
            found.append((number, line.strip()))
    return found


def test_no_pipeline_ends_in_a_reader_that_stops_early():
    found = [
        f"{path.relative_to(TOOLS)}:{number}: {line}"
        for path in SOURCES
        for number, line in early_readers(path.read_text(encoding="utf-8"))
    ]
    assert not found, "capture the output first, then match on it:\n" + "\n".join(found)


def test_the_check_finds_every_shape_of_an_early_reader():
    seeded = {
        'git show "$c:f" | grep -q x': 1,
        'git show "$c:f" 2>/dev/null \\\n        | grep -q "^cmd_rollback()"': 1,
        "openssl x509 -text |\n    grep -qx foo || return 0": 1,
        "docker ps \\\n    | grep --quiet foo": 1,
        "cat f | grep -m1 x": 1,
        "cat f | grep -l x": 1,
        "cat f | head -n 1": 1,
        "cat f | sed -n '1p;1q'": 1,
        "a | b | grep -q c": 1,
    }
    for snippet, count in seeded.items():
        assert len(early_readers(snippet)) == count, snippet


def test_the_check_leaves_safe_shapes_alone():
    safe = [
        'grep -q x <<< "$text"',
        "cmd || grep -q x file",
        "cat f | grep -c x",
        "cat f | grep x",
        "cat f | sed -n '1p'",
        "# git show | grep -q x",
        'text="$(git show x)" || exit 2',
        'printf "%s\\n" "$out" | sed "s/^/    /"',
    ]
    for snippet in safe:
        assert early_readers(snippet) == [], snippet
