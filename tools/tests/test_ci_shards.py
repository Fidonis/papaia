"""The core suite runs in CI as parallel shards (tools/tests/shards.toml, workflow "CI").

The shards must together run exactly the whole suite: every test file in exactly one
shard, no shard naming a file that is gone, and the workflow running one job per shard
under the aggregate check "Ruff and pytest". Two shards (or two local runs) may share one
Docker host, so the Docker live tests take their Compose project names and address ranges
per session instead of fixed defaults.
"""

from __future__ import annotations

import importlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent
REPO = TOOLS.parent
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
TEST_TOOLS_ACTION = REPO / ".github" / "actions" / "test-tools" / "action.yml"

# Docker live modules with an overridable Compose project or address range. The list is a
# floor: every module the search below finds is checked, these must be among them.
LIVE_MODULES = {
    "test_audit_docker",
    "test_edge_guard_docker",
    "test_egress_docker",
    "test_isolated_network_docker",
    "test_model_gateway_docker",
    "test_offered_network_docker",
    "test_own_images_registry",
    "test_paperless_gate_docker",
    "test_replay",
    "test_smtp_relay_docker",
    "test_sql_uplink_docker",
}
_LIVE_VARIABLE = re.compile(r'"PAPAIA_[A-Z_]+_TEST_(?:PROJECT|SUBNET)"')
# The settings a session takes its live names from; a simulated session starts without them.
_SESSION_VARIABLE = re.compile(
    r"PAPAIA_[A-Z_]+_TEST_(?:PROJECT|SUBNET|PORT)|PAPAIA_TEST_COMPOSE_PROJECT"
    r"|PAPAIA_TEST_(?:SHARD|SUBNET_POOL|SUBNET_SIZE|PROJECT_PREFIX)|GITHUB_RUN_ID"
)
# Tools a test file needs installed in its shard, recognised by what the file uses.
_TOOL_MARKERS = {
    "gitleaks": re.compile(r'which\("gitleaks"\)'),
    "haproxy": re.compile(r'which\("haproxy"\)'),
    "compose": re.compile(r"PAPAIA_REQUIRE_GOLDEN_COMPOSE"),
}


@pytest.fixture
def shards():
    return importlib.import_module("shard_check")


def _write_layout(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _tree(tmp_path: Path, names: list[str]) -> Path:
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in names:
        (tests / name).write_text("def test_one():\n    pass\n", encoding="utf-8")
    return tests


# ── the shard file ────────────────────────────────────────────────────────────


def test_the_shards_cover_every_test_file_exactly_once(shards):
    assignment = shards.assign(shards.load())
    files = {path.name for path in TESTS.glob("test_*.py")}
    named = [name for listed in assignment.values() for name in listed]

    assert set(named) == files
    assert len(named) == len(set(named)), "a test file is in more than one shard"
    assert all(assignment.values()), "a shard without test files"


def test_a_file_no_shard_names_goes_to_the_catch_all_shard_of_a_copy_of_the_tree(
    shards, tmp_path
):
    layout = shards.load()
    names = [path.name for path in TESTS.glob("test_*.py")]
    tests = _tree(tmp_path, [*names, "test_planted_extra.py"])

    assignment = shards.assign(layout, tests)

    assert layout.catch_all is not None
    assert "test_planted_extra.py" in assignment[layout.catch_all]
    others = [name for shard, listed in assignment.items() if shard != layout.catch_all
              for name in listed]  # fmt: skip
    assert "test_planted_extra.py" not in others


def test_a_file_no_shard_names_fails_without_a_catch_all_shard(shards, tmp_path):
    tests = _tree(tmp_path, ["test_a.py", "test_b.py", "test_planted_extra.py"])
    layout = shards.load(_write_layout(tmp_path / "shards.toml", (
        '[shards.one]\nfiles = ["test_a.py"]\n[shards.two]\nfiles = ["test_b.py"]\n'
    )))  # fmt: skip

    with pytest.raises(shards.ShardError) as error:
        shards.assign(layout, tests)
    assert "test_planted_extra.py" in str(error.value)


def test_a_file_named_by_two_shards_fails(shards, tmp_path):
    tests = _tree(tmp_path, ["test_a.py", "test_b.py"])
    layout = shards.load(_write_layout(tmp_path / "shards.toml", (
        'catch_all = "two"\n'
        '[shards.one]\nfiles = ["test_a.py"]\n[shards.two]\nfiles = ["test_*.py"]\n'
    )))  # fmt: skip

    with pytest.raises(shards.ShardError) as error:
        shards.assign(layout, tests)
    assert "test_a.py" in str(error.value) and "one" in str(error.value)


def test_a_shard_naming_a_missing_file_fails(shards, tmp_path):
    tests = _tree(tmp_path, ["test_a.py"])
    layout = shards.load(_write_layout(tmp_path / "shards.toml", (
        'catch_all = "one"\n[shards.one]\nfiles = ["test_a.py", "test_gone.py"]\n'
    )))  # fmt: skip

    with pytest.raises(shards.ShardError) as error:
        shards.assign(layout, tests)
    assert "test_gone.py" in str(error.value)


@pytest.mark.parametrize(
    "text",
    [
        '[shards.one]\nfiles = ["test_a.py"]\nskip = ["test_b.py"]\n',
        'catch_al = "one"\n[shards.one]\nfiles = ["test_a.py"]\n',
        'catch_all = "none"\n[shards.one]\nfiles = ["test_a.py"]\n',
        '[shards.One]\nfiles = ["test_a.py"]\n',
        '[shards.one]\nfiles = ["../test_a.py"]\n',
        '[shards.one]\nfiles = ["helpers.py"]\n',
        '[shards.one]\nfiles = "test_a.py"\n',
        "[shards]\n",
    ],
)
def test_an_invalid_shard_file_is_refused(shards, tmp_path, text):
    with pytest.raises(shards.ShardError):
        shards.load(_write_layout(tmp_path / "shards.toml", text))


def test_the_collection_check_refuses_a_test_outside_every_shard(shards):
    assignment = {"one": ["test_a.py"], "two": ["test_b.py"]}
    collected = ["tests/test_a.py::test_x", "tests/test_b.py::test_y", "tests/test_c.py::test_z"]

    with pytest.raises(shards.ShardError) as error:
        shards.check(assignment, collected)
    assert "tests/test_c.py::test_z" in str(error.value)

    counts = shards.check(assignment, collected[:2])
    assert counts == {"one": 1, "two": 1}


# ── the workflow ──────────────────────────────────────────────────────────────


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _matrix_job() -> tuple[str, dict]:
    found = [(key, job) for key, job in _jobs().items() if "matrix" in job.get("strategy", {})
             and any("pytest" in step.get("run", "") for step in job["steps"])]  # fmt: skip
    assert len(found) == 1, [key for key, _ in found]
    return found[0]


def _entries() -> list[dict]:
    return _matrix_job()[1]["strategy"]["matrix"]["include"]


def test_the_workflow_runs_one_job_per_shard_and_no_other(shards):
    key, job = _matrix_job()
    entries = _entries()

    assert sorted(entry["shard"] for entry in entries) == sorted(shards.load().shards)
    assert set(job["strategy"]["matrix"]) == {"include"}
    assert job["strategy"]["fail-fast"] is False
    run = "\n".join(step.get("run", "") for step in job["steps"])
    assert "shard_check.py files" in run and "--durations=25" in run
    assert job["env"]["PAPAIA_TEST_SHARD"] == "${{ matrix.shard }}"


def test_every_shard_job_has_a_timeout_of_at_most_thirty_minutes():
    _, job = _matrix_job()

    assert job["timeout-minutes"] == "${{ matrix.timeout }}"
    for entry in _entries():
        assert isinstance(entry["timeout"], int) and 0 < entry["timeout"] <= 30, entry


def test_the_shards_keep_the_job_environment_and_own_address_ranges():
    _, job = _matrix_job()

    for name in ("PAPAIA_REQUIRE_GOLDEN_COMPOSE", "PAPAIA_REQUIRE_OPENSSL",
                 "PAPAIA_REQUIRE_GITLEAKS"):  # fmt: skip
        assert job["env"][name] == "1", name
    assert job["env"]["PAPAIA_TEST_SUBNET_POOL"] == "${{ matrix.subnets }}"
    pools = [ipaddress.ip_network(entry["subnets"]) for entry in _entries()]
    for index, pool in enumerate(pools):
        assert pool.is_private and pool.prefixlen <= 20, pool
        assert not any(pool.overlaps(other) for other in pools[index + 1 :]), pool


def test_every_shard_installs_the_tools_its_files_need(shards):
    assignment = shards.assign(shards.load())
    entries = {entry["shard"]: entry for entry in _entries()}

    for shard, files in assignment.items():
        for name in files:
            text = (TESTS / name).read_text(encoding="utf-8")
            for tool, marker in _TOOL_MARKERS.items():
                if marker.search(text):
                    assert entries[shard][tool] is True, f"{name} needs {tool} in {shard}"
    _, job = _matrix_job()
    uses = [step for step in job["steps"] if step.get("uses") == "./.github/actions/test-tools"]
    assert len(uses) == 1
    assert uses[0]["with"] == {tool: f"${{{{ matrix.{tool} }}}}" for tool in _TOOL_MARKERS}


def test_the_shared_tool_steps_keep_their_checksum_checks():
    action = yaml.safe_load(TEST_TOOLS_ACTION.read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    text = "\n".join(step.get("run", "") for step in steps)

    assert action["runs"]["using"] == "composite"
    assert "sha256sum -c" in text  # Compose against its published checksum
    assert ".github/scripts/install-gitleaks.sh" in text  # gitleaks against the pinned sha256
    assert all(step.get("if") for step in steps)


def test_no_pytest_command_narrows_the_suite():
    narrowing = re.compile(r"(^|\s)(--deselect|-k|-m|--ignore(-glob)?)(\s|=|$)")
    for key, job in _jobs().items():
        for step in job.get("steps", []):
            for line in step.get("run", "").splitlines():
                if re.search(r"\bpytest\b", line):
                    arguments = re.split(r"\bpytest\b", line)[-1]  # after `python -m pytest`
                    assert not narrowing.search(arguments), (key, line)


def test_the_aggregate_check_needs_every_shard_the_shard_check_and_ruff():
    jobs = _jobs()
    aggregate = [job for job in jobs.values() if job.get("name") == "Ruff and pytest"]
    assert len(aggregate) == 1
    job = aggregate[0]
    key, _ = _matrix_job()
    check = [k for k, j in jobs.items()
             if any("shard_check.py check" in s.get("run", "") for s in j.get("steps", []))]
    ruff = [k for k, j in jobs.items()
            if any("ruff check" in s.get("run", "") for s in j.get("steps", []))]  # fmt: skip

    assert len(check) == 1 and len(ruff) == 1
    assert set(job["needs"]) == {key, check[0], ruff[0]}
    assert job["if"] == "${{ always() }}"
    run = "\n".join(step.get("run", "") for step in job["steps"])
    assert "toJSON(needs)" in json.dumps(job) and '"success"' in run
    assert check[0] in jobs[key]["needs"]


# ── per-session names of the Docker live tests ───────────────────────────────


def _live_modules() -> list[str]:
    found = sorted(
        path.stem for path in TESTS.glob("test_*.py")
        if path.stem != Path(__file__).stem
        and _LIVE_VARIABLE.search(path.read_text(encoding="utf-8"))
    )  # fmt: skip
    assert LIVE_MODULES <= set(found), LIVE_MODULES - set(found)
    return found


_SESSION = """
import importlib, json, sys
sys.path[:0] = [{tests!r}, {tools!r}]
names = {{}}
for module in {modules!r}:
    loaded = importlib.import_module(module)
    names[module] = {{key: str(getattr(loaded, key)) for key in ("PROJECT", "SUBNET", "LIVE_NAME")
                     if hasattr(loaded, key)}}
print(json.dumps(names), flush=True)
sys.stdin.readline()
"""


def _sessions(tmp_path: Path, envs: list[dict[str, str]]) -> list[dict[str, dict[str, str]]]:
    """Import every live module in one process per environment, all running at the same
    time (as two shards or two local runs on one host), and return their names."""
    modules = _live_modules()
    script = tmp_path / "session.py"
    script.write_text(_SESSION.format(tests=str(TESTS), tools=str(TOOLS), modules=modules),
                      encoding="utf-8")  # fmt: skip
    base = {key: value for key, value in os.environ.items() if not _SESSION_VARIABLE.fullmatch(key)}
    started = [
        subprocess.Popen([sys.executable, str(script)], cwd=TOOLS, env={**base, **env},
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)  # fmt: skip
        for env in envs
    ]
    results = []
    try:
        for process in started:
            line = process.stdout.readline()
            assert line, process.stderr.read()
            results.append(json.loads(line))
    finally:
        for process in started:
            process.communicate(input="\n", timeout=120)
    return results


def _assert_apart(first: dict, second: dict) -> None:
    assert first.keys() == second.keys()
    for module, names in first.items():
        assert names, f"{module} has no live names"
        for key, value in names.items():
            assert value != second[module][key], (module, key, value)
            if key == "SUBNET":
                assert not ipaddress.ip_network(value).overlaps(
                    ipaddress.ip_network(second[module][key])
                ), (module, value, second[module][key])


def _assert_disjoint_within(session: dict) -> None:
    subnets = [ipaddress.ip_network(n["SUBNET"]) for n in session.values() if "SUBNET" in n]
    for index, subnet in enumerate(subnets):
        assert not any(subnet.overlaps(other) for other in subnets[index + 1 :]), subnet


def test_live_names_differ_between_two_local_sessions(tmp_path):
    first, second = _sessions(tmp_path, [{}, {}])

    _assert_apart(first, second)
    _assert_disjoint_within(first)
    _assert_disjoint_within(second)
    for names in first.values():
        for key in ("PROJECT", "LIVE_NAME"):
            if key in names:
                assert names[key].startswith("papaia-"), names[key]


def test_live_names_differ_between_two_shards_of_one_run(tmp_path):
    entries = _entries()
    envs = [
        {"GITHUB_RUN_ID": "4242", "PAPAIA_TEST_SHARD": entry["shard"],
         "PAPAIA_TEST_SUBNET_POOL": entry["subnets"]}
        for entry in entries[:2]
    ]  # fmt: skip
    first, second = _sessions(tmp_path, envs)

    _assert_apart(first, second)
    for session, entry in ((first, entries[0]), (second, entries[1])):
        pool = ipaddress.ip_network(entry["subnets"])
        for names in session.values():
            if "SUBNET" in names:
                assert ipaddress.ip_network(names["SUBNET"]).subnet_of(pool), names
            for key in ("PROJECT", "LIVE_NAME"):
                if key in names:
                    assert f"-4242-{entry['shard']}-" in names[key], names[key]


def test_an_override_still_wins_over_the_session_names(tmp_path):
    (first,) = _sessions(tmp_path, [{
        "PAPAIA_EGRESS_TEST_PROJECT": "egress-fixed", "PAPAIA_EGRESS_TEST_SUBNET": "10.99.7.0/24",
        "PAPAIA_REPLAY_TEST_PROJECT": "replay-fixed",
    }])  # fmt: skip

    assert first["test_egress_docker"] == {"PROJECT": "egress-fixed", "SUBNET": "10.99.7.0/24"}
    assert first["test_replay"]["LIVE_NAME"] == "replay-fixed"


def test_no_live_module_keeps_a_fixed_default_name():
    fixed = re.compile(r'environ\.get\(\s*"PAPAIA_[A-Z_]+_TEST_(?:PROJECT|SUBNET)",\s*f?"')
    for module in _live_modules():
        text = (TESTS / f"{module}.py").read_text(encoding="utf-8")
        assert not fixed.search(text), module
        assert "live_names.project(" in text, module
