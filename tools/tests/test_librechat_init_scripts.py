"""LibreChat's init scripts against an in-memory stand-in for MongoDB.

`agents-init.js` and `prompts-init.js` run inside the LibreChat container on every
start. The harness in `fixtures/` replaces `mongodb` and `js-yaml` and maps
`/app/api/data` to a temporary directory, so the upserts and the deletion of what an
add-on no longer provides can be checked over several starts. Needs `node`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCHES = REPO / "src" / "ai" / "librechat" / "patches"
HARNESS = Path(__file__).parent / "fixtures" / "librechat_init_harness.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

ADMIN = {"_id": "oid900", "email": "admin@example.org", "role": "ADMIN"}
VIEWER = {"_id": "oid901", "accessRoleId": "agent_viewer"}


@pytest.fixture
def data(tmp_path: Path) -> Path:
    return tmp_path / "data"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"users": [ADMIN], "accessroles": [VIEWER]}), encoding="utf-8")
    return path


def _run(script: str, data: Path, db: Path) -> dict:
    result = subprocess.run(
        ["node", str(HARNESS), str(PATCHES / script), str(data), str(db)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    state = json.loads(db.read_text(encoding="utf-8"))
    state["log"] = result.stdout + result.stderr
    return state


def _write(path: Path, doc: dict | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")


def _agent(agent_id: object, name: str = "Docs") -> dict:
    return {"id": agent_id, "name": name, "provider": "Private-LLM", "model": "m"}


def _prompt(name: str, command: str) -> str:
    meta = json.dumps({"name": name, "category": "c", "command": command, "oneliner": "o"})
    return f"---\n{meta}\n---\nText of {command}.\n"


def _by_id(state: dict, agent_id: str) -> dict | None:
    return next((a for a in state["agents"] if a["id"] == agent_id), None)


# -- agents --------------------------------------------------------------------------------


def test_an_addon_agent_is_shared_and_removed_with_its_file(data: Path, db: Path) -> None:
    _write(data / "addon-agents" / "paperless__docs.yaml", _agent("docs"))
    state = _run("agents-init.js", data, db)
    agent = _by_id(state, "agent_docs")
    assert agent["papaia_managed_by"] == "paperless"
    public = [e for e in state["aclentries"] if e["principalType"] == "public"]
    assert [(e["resourceId"], e["roleId"]) for e in public] == [(agent["_id"], VIEWER["_id"])]

    (data / "addon-agents" / "paperless__docs.yaml").unlink()
    state = _run("agents-init.js", data, db)
    assert state["agents"] == []
    assert state["aclentries"] == []


def test_an_operator_agent_with_an_addon_id_wins_and_survives_the_addon(
    data: Path, db: Path
) -> None:
    _write(data / "addon-agents" / "paperless__docs.yaml", _agent("docs", "From the add-on"))
    first = _by_id(_run("agents-init.js", data, db), "agent_docs")

    _write(data / "agents" / "docs.yaml", _agent("docs", "From the operator"))
    state = _run("agents-init.js", data, db)
    agent = _by_id(state, "agent_docs")
    assert agent["name"] == "From the operator"
    assert "papaia_managed_by" not in agent
    assert "provided by the operator directory" in state["log"]

    (data / "addon-agents" / "paperless__docs.yaml").unlink()
    state = _run("agents-init.js", data, db)
    assert _by_id(state, "agent_docs")["_id"] == first["_id"]


def test_a_stored_bare_numeric_id_is_removed_with_its_acl_entry(data: Path, db: Path) -> None:
    state = json.loads(db.read_text(encoding="utf-8"))
    state["agents"] = [{"_id": "oid10", "id": 42, "name": "old"}]
    state["aclentries"] = [{"_id": "oid11", "resourceType": "agent", "resourceId": "oid10"}]
    db.write_text(json.dumps(state), encoding="utf-8")
    _write(data / "agents" / "old.yaml", _agent(42))

    state = _run("agents-init.js", data, db)

    assert [a["id"] for a in state["agents"]] == ["agent_42"]
    assert all(e["resourceId"] != "oid10" for e in state["aclentries"])


def test_a_broken_addon_file_removes_nothing(data: Path, db: Path) -> None:
    _write(data / "addon-agents" / "paperless__docs.yaml", _agent("docs"))
    _run("agents-init.js", data, db)
    _write(data / "addon-agents" / "paperless__docs.yaml", "{not json")

    state = _run("agents-init.js", data, db)

    assert _by_id(state, "agent_docs") is not None


# -- prompts -------------------------------------------------------------------------------


def test_an_operator_prompt_named_like_an_addon_prompt_leaves_it_alone(
    data: Path, db: Path
) -> None:
    _write(data / "addon-prompts" / "paperless__same.md", _prompt("Same", "addoncmd"))
    first = _run("prompts-init.js", data, db)
    [addon_group] = first["promptgroups"]

    _write(data / "prompts" / "same.md", _prompt("Same", "opcmd"))
    for _ in range(2):
        state = _run("prompts-init.js", data, db)
        groups = {g["command"]: g for g in state["promptgroups"]}
        assert set(groups) == {"addoncmd", "opcmd"}
        assert groups["addoncmd"]["_id"] == addon_group["_id"]
        assert "papaia_managed_by" not in groups["opcmd"]


def test_an_addon_prompt_is_removed_with_its_file(data: Path, db: Path) -> None:
    _write(data / "addon-prompts" / "paperless__sum.md", _prompt("Sum", "sum"))
    _run("prompts-init.js", data, db)
    (data / "addon-prompts" / "paperless__sum.md").unlink()

    state = _run("prompts-init.js", data, db)

    assert state["promptgroups"] == []
    assert state["prompts"] == []
    assert all(p["promptGroupIds"] == [] for p in state["projects"])
