"""papaia-ctl runs under the Bash that ships with macOS (3.2). Before Bash 4.4, expanding an
empty array as "${arr[@]}" under `set -u` is an "unbound variable" error (#285)."""

from __future__ import annotations

import re
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
SOURCES = [TOOLS / "papaia-ctl", *sorted((TOOLS / "lib" / "sh").glob("*.sh"))]

# "${name[@]}" not preceded by `name[@]+`, the form that expands to nothing when empty.
_BARE = re.compile(r'(?<!\[@\]\+)"\$\{([A-Za-z_][A-Za-z0-9_]*)\[@\]\}"')


def test_no_array_expansion_fails_on_an_empty_array_under_bash_3_2():
    found = [
        f"{path.relative_to(TOOLS)}:{number}: {line.strip()}"
        for path in SOURCES
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _BARE.search(line)
    ]
    assert not found, 'use ${arr[@]+"${arr[@]}"}:\n' + "\n".join(found)
