"""Shards of the core test suite: read tools/tests/shards.toml and prove it covers the suite.

    python tests/shard_check.py files <shard>   the test files of one shard, one per line
    python tests/shard_check.py check           collect the whole suite and fail unless every
                                                collected test is in exactly one shard

Run from tools/. CI runs `check` before the shard jobs and `files` inside each shard job.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import tomllib

TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent
SHARDS = TESTS / "shards.toml"

_SHARD = re.compile(r"[a-z][a-z0-9-]{0,23}")
_PATTERN = re.compile(r"test_[A-Za-z0-9_*?\[\]-]*\.py")
_COLLECTED = re.compile(r"(tests/test_[A-Za-z0-9_]+\.py)::\S")


class ShardError(Exception):
    """The shard file is invalid or does not cover the suite."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Layout:
    shards: dict[str, tuple[str, ...]]
    catch_all: str | None


def load(path: Path = SHARDS) -> Layout:
    """The shard file; anything but the documented keys and shapes is refused."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ShardError([f"{path.name}: {error}"]) from error
    problems = [f"{path.name}: unknown key {key!r}" for key in data if key not in
                {"catch_all", "shards"}]  # fmt: skip
    table = data.get("shards")
    if not isinstance(table, dict) or not table:
        raise ShardError([*problems, f"{path.name}: no [shards.<name>] table"])
    shards: dict[str, tuple[str, ...]] = {}
    for name, shard in table.items():
        if not _SHARD.fullmatch(name):
            problems.append(f"shard {name!r}: name must match {_SHARD.pattern}")
        if not isinstance(shard, dict) or set(shard) != {"files"}:
            problems.append(f"shard {name!r}: only the key 'files' is allowed")
            continue
        files = shard["files"]
        if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
            problems.append(f"shard {name!r}: files must be a list of strings")
            continue
        bad = [f for f in files if not _PATTERN.fullmatch(f)]
        problems.extend(f"shard {name!r}: {f!r} is no test file name or glob" for f in bad)
        shards[name] = tuple(files)
    catch_all = data.get("catch_all")
    if catch_all is not None and catch_all not in table:
        problems.append(f"catch_all {catch_all!r} is no shard")
    if problems:
        raise ShardError(problems)
    return Layout(shards=shards, catch_all=catch_all)


def assign(layout: Layout, tests: Path = TESTS) -> dict[str, list[str]]:
    """The test files of every shard. A file in two shards, a file in none (without a
    catch-all shard) and a name or glob that matches no file are errors."""
    files = sorted(path.name for path in tests.glob("test_*.py"))
    owner: dict[str, str] = {}
    problems = []
    for shard, patterns in layout.shards.items():
        for pattern in patterns:
            matched = fnmatch.filter(files, pattern)
            if not matched:
                problems.append(f"shard {shard!r}: {pattern!r} matches no test file")
            for name in matched:
                if owner.setdefault(name, shard) != shard:
                    problems.append(f"{name} is in shard {owner[name]!r} and in {shard!r}")
    for name in files:
        if name not in owner:
            if layout.catch_all is None:
                problems.append(f"{name} is in no shard")
            else:
                owner[name] = layout.catch_all
    if problems:
        raise ShardError(problems)
    assignment: dict[str, list[str]] = {shard: [] for shard in layout.shards}
    for name, shard in sorted(owner.items()):
        assignment[shard].append(name)
    return assignment


def check(assignment: dict[str, list[str]], collected: list[str]) -> dict[str, int]:
    """Collected tests per shard; a collected test whose file is in no shard fails."""
    shard_of = {f"tests/{name}": shard for shard, names in assignment.items() for name in names}
    counts = dict.fromkeys(assignment, 0)
    outside = []
    for node in collected:
        shard = shard_of.get(node.split("::", 1)[0])
        if shard is None:
            outside.append(f"{node} belongs to no shard")
        else:
            counts[shard] += 1
    if outside:
        raise ShardError(outside)
    return counts


def collect() -> list[str]:
    """The node ids of the whole suite, as `pytest --collect-only -q` lists them."""
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        cwd=TOOLS, capture_output=True, text=True, check=False,
    )  # fmt: skip
    if done.returncode != 0:
        raise ShardError([f"collection failed (exit {done.returncode})", done.stdout[-4000:],
                          done.stderr[-4000:]])  # fmt: skip
    return [line for line in done.stdout.splitlines() if _COLLECTED.match(line)]


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "files":
            assignment = assign(load())
            if argv[1] not in assignment:
                raise ShardError([f"no shard {argv[1]!r}"])
            print("\n".join(f"tests/{name}" for name in assignment[argv[1]]))
            return 0
        if argv == ["check"]:
            assignment = assign(load())
            collected = collect()
            counts = check(assignment, collected)
            width = max(len(shard) for shard in counts)
            for shard, count in counts.items():
                print(f"{shard:<{width}}  {len(assignment[shard]):>4} files  {count:>6} tests")
            print(f"{'shards':<{width}}  {sum(map(len, assignment.values())):>4} files  "
                  f"{sum(counts.values()):>6} tests")  # fmt: skip
            print(f"{'suite':<{width}}  {len(list(TESTS.glob('test_*.py'))):>4} files  "
                  f"{len(collected):>6} tests")  # fmt: skip
            if sum(counts.values()) != len(collected) or len(set(collected)) != len(collected):
                raise ShardError(["the shards do not add up to the collected suite"])
            return 0
    except ShardError as error:
        print(error, file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
