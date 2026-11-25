"""The opt-in of an add-on outside the suite for the chat (ADR 0029 points 4 to 6).

`papaia-ctl addon chat allow <addon>` records a pairing of the core chat relay
`papaia-chat-relay` with the add-on's audience; only a confirmed opt-in puts the add-on
on the relay's list (`chat-relay/servers.json`) and renders its chat entry, which points
to the relay, never to the add-on. A write opt-in, and every opt-in while four eyes are
in effect, waits for a second host account. `addon chat revoke`, uninstalling or stopping
the add-on takes it off the list. Every decision is one `papaia.audit/1` row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml
from install_helpers import REPO, Installation
from jsonschema import Draft202012Validator

from lib import catalog, chat_optin, cli, cli_addon, render_core
from lib import pairing_approval as pa
from lib import realm_sync as rs
from tests.test_ctl_standalone_commands import BASH, needs_bash

FIXTURES = Path(__file__).parent / "fixtures" / "catalog"
LIBRECHAT = Path("ai/librechat/librechat.yaml")
REALM = Path("infra/keycloak/realm-import/papaia-realm.json")
SERVERS = Path("chat-relay/servers.json")
AUDIENCE = "mcp-wiki"
RELAY = "papaia-chat-relay"
RELAY_URL = f"http://papaia-chat-relay:8080/servers/{AUDIENCE}/mcp"
PROBE_NET = "${PAPAIA_PROJECT:-papaia}-probe-net"
OVERRIDE = Path("overrides/docker-compose.chat-relay-probe.override.yml")
ANNA = "host:anna"
BEN = "host:ben"
REGISTER = rs.load_register()

AUDIT_SCHEMA = json.loads(
    (REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text(encoding="utf-8")
)
SUBMISSION = Draft202012Validator(
    {**AUDIT_SCHEMA, "$ref": "#/$defs/submission", "required": [], "allOf": []}
)


def _relay_service():
    """The relay's own parser of the list (src/infra/chat-relay/relay.py)."""
    path = REPO / "src" / "infra" / "chat-relay" / "relay.py"
    module = types.ModuleType("papaia_chat_relay_optin")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


relay = _relay_service()


# ─────────────────────────────────────────────────────────────────────────
# an installation with a tool server outside the suite
# ─────────────────────────────────────────────────────────────────────────


def _probe(tmp_path: Path, *, writes: bool = True, **entry_changes) -> Path:
    """The probe add-on (not in the suite) serving the registered audience mcp-wiki to
    persons; without `writes` it declares its read and check operations only."""
    path = tmp_path / "addons" / "probe"
    shutil.copytree(FIXTURES / "addon-probe", path)
    manifest_path = path / "papaia-app.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["exposes"][0]
    entry["audience"] = AUDIENCE
    entry["identity"] = ["person"]
    manifest["service_accounts"] = []
    manifest["networks"] = {"app_network": PROBE_NET}
    if not writes:
        entry["operations"] = [op for op in entry["operations"] if op["effect"] != "write"]
    networks = entry_changes.pop("networks", None)
    if networks is not None:
        manifest["networks"] = networks
    entry.update(entry_changes)
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def _in_the_suite(repo: Path) -> None:
    matrix = yaml.safe_load((REPO / "compat" / "suite.yaml").read_text(encoding="utf-8"))
    matrix["components"].append("probe")
    for row in matrix["suites"]:
        row["versions"]["probe"] = ">=0.3.0,<0.4.0"
    (repo / "compat").mkdir(exist_ok=True)
    (repo / "compat" / "suite.yaml").write_text(yaml.safe_dump(matrix, sort_keys=False))


def _installation(tmp_path: Path, *, in_suite: bool = False) -> Installation:
    inst = Installation(tmp_path, ["--app-host=https://papaia.example.org"])
    if in_suite:
        _in_the_suite(inst.repo)
    inst.setup(*inst.flags)
    return inst


def _install(inst: Installation, path: Path, *, running: bool = True) -> None:
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="probe", path=str(path),
        version=None, force=False, node=None,
    )
    assert cli_addon.cmd_addon_install(args) == 0
    if running:
        _state(inst, "running")


def _state(inst: Installation, state: str) -> None:
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="probe", all=False,
        state=state,
    )
    assert cli_addon.cmd_addon_state(args) == 0


def _allow(inst: Installation, person: str, addon: str = "probe", approve: str = AUDIENCE):
    return chat_optin.allow(inst.config, inst.repo, addon, person=person, approve=approve)


def _revoke(inst: Installation, person: str = ANNA, addon: str = "probe"):
    return chat_optin.revoke(inst.config, inst.repo, addon, person=person)


def _relay_pairings(inst: Installation) -> list[rs.Pairing]:
    return [
        p for p in rs.load_pairings(rs.pairings_path(inst.config), REGISTER) if p.client == RELAY
    ]


def _rows(inst: Installation, prefix: str = "chat_relay.") -> list[dict]:
    path = rs.audit_path(inst.config)
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if (r.get("operation") or "").startswith(prefix)]


def _decisions(inst: Installation) -> list[dict]:
    return [r for r in _rows(inst) if r["operation"] != "chat_relay.list_write"]


def _render(inst: Installation) -> None:
    render_core.render(inst.config, inst.repo)


def _librechat(inst: Installation) -> dict:
    return yaml.safe_load((inst.config / LIBRECHAT).read_text(encoding="utf-8"))


def _chat_entries(inst: Installation) -> dict:
    return _librechat(inst).get("mcpServers") or {}


def _mapped_audiences(inst: Installation) -> set[str]:
    realm = json.loads((inst.config / REALM).read_text(encoding="utf-8"))
    client = next(c for c in realm["clients"] if c["clientId"] == "librechat")
    return {
        (m.get("config") or {}).get("included.client.audience")
        for m in client.get("protocolMappers", [])
    }


def _listed(inst: Installation) -> dict | None:
    path = inst.config / SERVERS
    if not path.exists():
        return None
    return relay.parse_servers(json.loads(path.read_text(encoding="utf-8")))


def _content_hashes(inst: Installation) -> dict[str, str]:
    doc = json.loads((inst.config / "platform" / "services.json").read_text(encoding="utf-8"))
    return {e["id"]: e["content_hash"] for e in doc["services"]}


def _four_eyes_on(inst: Installation) -> None:
    path = inst.config / catalog.APPROVALS_OVERLAY
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('four_eyes: "on"\n', encoding="utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────
# allow, approve, revoke
# ─────────────────────────────────────────────────────────────────────────


def test_a_read_only_opt_in_takes_effect_at_once_without_four_eyes(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))

    assert _allow(inst, ANNA) == "allowed"

    [pairing] = _relay_pairings(inst)
    assert (pairing.audience, pairing.effects, pairing.confirmed) == (AUDIENCE, ("r",), True)
    [row] = _decisions(inst)
    assert row["operation"] == "chat_relay.allow"
    assert row["writer"] == "papaia-ctl/chat-relay"
    assert row["event"] == "exchange_right_changed"
    assert row["result"] == "allowed"
    assert row["sub"] == ANNA
    assert row["object_ref"] == {"type": "addon", "id": "probe"}
    assert row["catalog_id"] == "probe.echo"
    assert row["data_class"] == "internal"
    assert list(SUBMISSION.iter_errors(row)) == []
    # Allowing again changes nothing and writes nothing.
    assert _allow(inst, BEN) == "unchanged"
    assert len(_decisions(inst)) == 1


def test_a_write_opt_in_waits_for_a_second_host_account(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path))

    assert _allow(inst, ANNA) == "waiting"
    [pairing] = _relay_pairings(inst)
    assert (pairing.effects, pairing.confirmed, pairing.requested_by) == (
        ("r", "w"), False, ANNA
    )
    assert _listed(inst) is None

    with pytest.raises(chat_optin.OptInError, match="second") as refused:
        _allow(inst, ANNA)
    assert refused.value.code == "same_person"
    assert not _relay_pairings(inst)[0].confirmed

    assert _allow(inst, BEN) == "allowed"
    [pairing] = _relay_pairings(inst)
    assert (pairing.confirmed, pairing.requested_by, pairing.confirmed_by) == (True, ANNA, BEN)

    rows = _decisions(inst)
    assert [(r["operation"], r["result"], r["error_code"], r["sub"]) for r in rows] == [
        ("chat_relay.allow", "allowed", None, ANNA),
        ("chat_relay.approve", "denied", "same_person", ANNA),
        ("chat_relay.approve", "allowed", None, BEN),
    ]
    assert {r["data_class"] for r in rows} == {"personal"}
    assert len({r["correlation_id"] for r in rows}) == 3
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == []


def test_with_four_eyes_a_read_only_opt_in_waits_too(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    _four_eyes_on(inst)

    assert _allow(inst, ANNA) == "waiting"
    assert not _relay_pairings(inst)[0].confirmed
    with pytest.raises(chat_optin.OptInError):
        _allow(inst, ANNA)
    assert _allow(inst, BEN) == "allowed"
    assert _relay_pairings(inst)[0].confirmed_by == BEN


def test_revoke_removes_the_opt_in_and_the_relay_list_at_once(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    _allow(inst, ANNA)
    assert AUDIENCE in _listed(inst)

    assert _revoke(inst, BEN) == [AUDIENCE]

    assert _relay_pairings(inst) == []
    assert _listed(inst) is None
    row = _decisions(inst)[-1]
    assert (row["operation"], row["result"], row["sub"]) == ("chat_relay.revoke", "allowed", BEN)
    assert row["effect"] == "delete"
    assert list(SUBMISSION.iter_errors(row)) == []


def test_revoke_also_removes_a_waiting_opt_in(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path))
    assert _allow(inst, ANNA) == "waiting"

    assert _revoke(inst) == [AUDIENCE]
    assert _relay_pairings(inst) == []


def test_revoking_an_add_on_that_is_not_allowed_is_refused_and_audited(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path))

    with pytest.raises(chat_optin.OptInError) as refused:
        _revoke(inst)
    assert refused.value.code == "not_allowed"
    [row] = _decisions(inst)
    assert (row["operation"], row["result"], row["error_code"]) == (
        "chat_relay.revoke", "denied", "not_allowed"
    )


@pytest.mark.parametrize(
    ("addon", "code"),
    [("nowhere", "unknown_addon"), ("probe", "suite_module")],
)
def test_suite_modules_and_unknown_names_are_refused_and_audited(tmp_path, addon, code):
    inst = _installation(tmp_path, in_suite=True)
    _install(inst, _probe(tmp_path))

    with pytest.raises(chat_optin.OptInError) as refused:
        _allow(inst, ANNA, addon=addon)

    assert refused.value.code == code
    assert _relay_pairings(inst) == []
    [row] = _decisions(inst)
    assert (row["operation"], row["result"], row["error_code"]) == (
        "chat_relay.allow", "denied", code
    )
    assert row["object_ref"] == {"type": "addon", "id": addon}
    assert list(SUBMISSION.iter_errors(row)) == []


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"identity": ["service"]}, "not_eligible"),
        ({"networks": {"app_network": PROBE_NET, "attach": ["librechat"]}}, "attaches_chat"),
        ({"networks": {}}, "not_eligible"),
    ],
)
def test_an_entry_the_relay_may_not_serve_is_refused(tmp_path, changes, code):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, **changes))

    with pytest.raises(chat_optin.OptInError) as refused:
        _allow(inst, ANNA)

    assert refused.value.code == code
    assert _relay_pairings(inst) == []
    assert _decisions(inst)[-1]["error_code"] == code


def test_the_approval_must_name_the_audience_that_was_shown(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))

    with pytest.raises(chat_optin.OptInError) as refused:
        _allow(inst, ANNA, approve="mcp-paperless")

    assert refused.value.code == "approval_mismatch"
    assert _relay_pairings(inst) == []


@pytest.mark.parametrize("name", ["Probe", "probe;rm", "", "a" * 65, "core:rag"])
def test_a_malformed_name_is_refused_before_anything_is_read(tmp_path, name):
    config = tmp_path / "papaia-config"
    with pytest.raises(chat_optin.OptInError) as refused:
        chat_optin.allow(config, REPO, name, person=ANNA, approve=AUDIENCE)
    assert refused.value.code == "invalid_name"
    assert not config.exists()


def test_the_pairing_commands_refuse_the_relay(tmp_path):
    config = tmp_path / "papaia-config"
    config.mkdir(mode=0o700)

    with pytest.raises(pa.PairingError, match="addon chat allow"):
        pa.approve(config, REGISTER, RELAY, AUDIENCE, ["r"], person=ANNA)
    with pytest.raises(pa.PairingError, match="addon chat revoke"):
        pa.revoke(config, REGISTER, RELAY, AUDIENCE, person=ANNA)
    bom = {"pairings": [{"client": RELAY, "audience": AUDIENCE, "effects": ["r"]}]}
    with pytest.raises(pa.PairingError, match="addon chat allow"):
        pa.bom_pairings(bom, REGISTER)


def test_show_names_the_audience_the_operations_and_the_data_class_cap(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path))

    shown = chat_optin.describe(inst.config, inst.repo, "probe")

    assert (shown.addon, shown.catalog_id, shown.audience) == ("probe", "probe.echo", AUDIENCE)
    assert shown.data_class_max == "personal"
    assert [(t["name"], t["effect"]) for t in shown.tools] == [
        ("echo", "read"), ("write_note", "write"), ("check_access", "check")
    ]
    assert shown.effects == ("r", "w")


# ─────────────────────────────────────────────────────────────────────────
# the rendered chat entry and the relay's list
# ─────────────────────────────────────────────────────────────────────────


def test_only_an_allowed_add_on_gets_a_chat_entry_that_points_to_the_relay(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path))
    suite_entries = dict(_chat_entries(inst))
    hashes = _content_hashes(inst)

    # Before the opt-in: no entry, no list.
    assert AUDIENCE not in _chat_entries(inst)
    assert _listed(inst) is None

    # Waiting for the second person: still nothing.
    assert _allow(inst, ANNA) == "waiting"
    _render(inst)
    assert AUDIENCE not in _chat_entries(inst)
    assert _listed(inst) is None

    # Approved: the entry points to the relay, never to the add-on.
    assert _allow(inst, BEN) == "allowed"
    _render(inst)
    entries = _chat_entries(inst)
    entry = entries[AUDIENCE]
    assert entry["url"] == RELAY_URL
    assert entry["type"] == "streamable-http"
    assert entry["title"] == "Probe connection"
    assert entry["description"].startswith("Echoes the input and writes notes.")
    assert entry["description"].endswith("Data class up to: personal.")
    assert entry["headers"] == {"Authorization": "Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}"}
    assert entry["startup"] is False
    assert "http://probe-mcp:8080" not in json.dumps(_librechat(inst))
    assert "http://papaia-chat-relay:8080" in _librechat(inst)["mcpSettings"]["allowedDomains"]
    # No mapper of the add-on's audience on the chat's client: its token never carries it.
    assert AUDIENCE not in _mapped_audiences(inst)
    # The suite's entries and the catalog stay as they were; the trust level stays.
    assert {k: v for k, v in entries.items() if k != AUDIENCE} == suite_entries
    assert _digest(_content_hashes(inst)) == _digest(hashes)
    doc = json.loads((inst.config / "platform" / "services.json").read_text(encoding="utf-8"))
    assert next(e for e in doc["services"] if e["id"] == "probe.echo")["trust"] == "addon"

    # The relay's list holds the catalog's address and operations.
    listed = _listed(inst)[AUDIENCE]
    assert listed.addon == "probe"
    assert listed.catalog_id == "probe.echo"
    assert listed.address == "http://probe-mcp:8080/mcp"
    assert listed.scope == "aud-mcp-wiki"
    assert listed.data_class_max == "personal"
    assert set(listed.tools) == {"echo", "write_note", "check_access"}
    assert listed.tools["write_note"].effect == "write"

    # Revoked: entry and list are gone.
    _revoke(inst)
    _render(inst)
    assert AUDIENCE not in _chat_entries(inst)
    assert _listed(inst) is None
    assert {k: v for k, v in _chat_entries(inst).items()} == suite_entries


def test_a_stopped_add_on_leaves_the_list_at_once_and_the_chat_at_the_next_render(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    _allow(inst, ANNA)
    _render(inst)
    assert AUDIENCE in _chat_entries(inst)

    _state(inst, "stopped")
    assert _listed(inst) is None
    _render(inst)
    assert AUDIENCE not in _chat_entries(inst)
    # The opt-in stays: starting the add-on brings it back.
    assert _relay_pairings(inst)[0].confirmed
    _state(inst, "running")
    _render(inst)
    assert AUDIENCE in _listed(inst)
    assert _chat_entries(inst)[AUDIENCE]["url"] == RELAY_URL


def test_list_writes_are_audited(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    _allow(inst, ANNA)
    _state(inst, "stopped")

    writes = [r for r in _rows(inst) if r["operation"] == "chat_relay.list_write"]
    assert [(r["effect"], r["object_ref"]["id"]) for r in writes] == [
        ("write", "chat-relay/servers.json"),
        ("delete", "chat-relay/servers.json"),
    ]
    for row in writes:
        assert list(SUBMISSION.iter_errors(row)) == []


def test_uninstall_removes_the_opt_in(tmp_path):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    _allow(inst, ANNA)
    args = argparse.Namespace(
        config_dir=str(inst.config), repo_root=str(inst.repo), name="probe", purge_data=False,
        force=False,
    )

    assert cli_addon.cmd_addon_uninstall(args) == 0

    assert _relay_pairings(inst) == []
    assert _listed(inst) is None
    assert AUDIENCE not in _chat_entries(inst)
    revoked = [r for r in _decisions(inst) if r["operation"] == "chat_relay.revoke"]
    assert [(r["result"], r["object_ref"]["id"]) for r in revoked] == [("allowed", "probe")]


def test_an_upgrade_that_adds_a_write_operation_drops_a_read_only_opt_in_from_the_list(
    tmp_path,
):
    inst = _installation(tmp_path)
    path = _probe(tmp_path, writes=False)
    _install(inst, path)
    _allow(inst, ANNA)
    assert AUDIENCE in _listed(inst)

    # The add-on now declares a write operation the opt-in never covered.
    shutil.rmtree(path)
    _probe(tmp_path)
    _render(inst)

    assert _listed(inst) is None
    assert AUDIENCE not in _chat_entries(inst)
    [row] = chat_optin.listing(inst.config, inst.repo)
    assert row["state"] == "allowed, not served"
    assert "effects" in row["reason"]


def test_the_relay_joins_the_app_network_of_a_served_add_on_only(tmp_path):
    from lib import gen_override

    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    gen_override.generate_overrides(inst.config, inst.repo)
    assert not (inst.config / OVERRIDE).exists()

    _allow(inst, ANNA)
    gen_override.generate_overrides(inst.config, inst.repo)
    doc = yaml.safe_load((inst.config / OVERRIDE).read_text(encoding="utf-8"))
    assert doc == {
        "services": {RELAY: {"networks": ["papaia-probe-net"]}},
        "networks": {"papaia-probe-net": {"external": True}},
    }
    # librechat stays off the add-on's network; only the relay joins it.
    assert "librechat" not in json.dumps(doc)
    writes = [r for r in _rows(inst) if r["operation"] == "chat_relay.override_write"]
    assert [(r["effect"], r["result"]) for r in writes] == [("write", "allowed")]

    _revoke(inst)
    gen_override.generate_overrides(inst.config, inst.repo)
    assert not (inst.config / OVERRIDE).exists()


# ─────────────────────────────────────────────────────────────────────────
# the commands
# ─────────────────────────────────────────────────────────────────────────


def _cli(inst: Installation, *argv: str) -> int:
    return cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config), *argv])


def test_the_commands_allow_list_and_revoke(tmp_path, capsys, monkeypatch):
    inst = _installation(tmp_path)
    _install(inst, _probe(tmp_path, writes=False))
    monkeypatch.setattr(pa, "acting_person", lambda: ANNA)
    capsys.readouterr()

    assert _cli(inst, "addon-chat-show", "--name=probe") == 0
    shown = capsys.readouterr().out
    assert AUDIENCE in shown and "echo" in shown and "internal" in shown
    assert _cli(inst, "addon-chat-show", "--name=probe", "--audience-only") == 0
    assert capsys.readouterr().out.strip() == AUDIENCE

    assert _cli(inst, "addon-chat-allow", "--name=probe", f"--approve={AUDIENCE}") == 0
    assert "allowed" in capsys.readouterr().out
    assert AUDIENCE in _chat_entries(inst)

    assert _cli(inst, "addon-chat-list", "--json") == 0
    [row] = json.loads(capsys.readouterr().out)["addons"]
    assert row == {
        "addon": "probe", "audience": AUDIENCE, "catalog_id": "probe.echo", "effects": "r",
        "state": "allowed", "reason": None, "requested_by": ANNA, "confirmed_by": ANNA,
    }

    assert _cli(inst, "addon-chat-revoke", "--name=probe") == 0
    assert "revoked" in capsys.readouterr().out
    assert AUDIENCE not in _chat_entries(inst)
    assert _cli(inst, "addon-chat-list", "--json") == 0
    assert json.loads(capsys.readouterr().out)["addons"] == []


def test_a_refused_command_exits_2_and_names_the_reason(tmp_path, capsys, monkeypatch):
    inst = _installation(tmp_path)
    monkeypatch.setattr(pa, "acting_person", lambda: ANNA)
    capsys.readouterr()

    assert _cli(inst, "addon-chat-allow", "--name=nowhere", f"--approve={AUDIENCE}") == 2
    assert "not installed" in capsys.readouterr().err


def test_papaia_ctl_dispatches_the_chat_commands():
    script = (REPO / "tools" / "papaia-ctl").read_text(encoding="utf-8")
    addon_sh = (REPO / "tools" / "lib" / "sh" / "addon.sh").read_text(encoding="utf-8")
    assert "chat)      cmd_addon_chat" in script
    for usage in ("addon chat allow", "addon chat revoke", "addon chat list"):
        assert f"papaia-ctl {usage}" in script
    for sub in ("addon-chat-allow", "addon-chat-revoke", "addon-chat-list", "addon-chat-show"):
        assert sub in addon_sh


ADDON_SH = REPO / "tools" / "lib" / "sh" / "addon.sh"
_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR=/no/such/config
error() { echo "ERROR: $*" >&2; }
warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*"; }
success() { echo "OK: $*"; }
usage() { echo usage; }
_require_setup_done() { :; }
is_tty() { [ "${FAKE_TTY:-0}" = 1 ]; }
confirm() { echo "ASKED: $1"; [ "${FAKE_ANSWER:-n}" = y ]; }
py_cli() {
    echo "py_cli $*" >&2
    case "$1" in
        addon-chat-show)
            if [ "${3:-}" = "--audience-only" ]; then echo "mcp-wiki"; return 0; fi
            echo "shown"; return 0 ;;
    esac
}
source "@ADDON@"
"""


def _chat(*args: str, tty: bool = False, answer: str = "n"):
    assert BASH is not None
    harness = _HARNESS.replace("@ADDON@", ADDON_SH.as_posix())
    quoted = " ".join(f"'{a}'" for a in args)
    env = {**os.environ, "FAKE_TTY": "1" if tty else "0", "FAKE_ANSWER": answer}
    return subprocess.run(
        [BASH, "-c", f"{harness}\ncmd_addon_chat {quoted}"],
        capture_output=True, text=True, timeout=30, check=False, env=env,
    )


@needs_bash
def test_the_shell_never_allows_with_y():
    done = _chat("allow", "probe", "-y")

    assert done.returncode == 2
    assert "takes no -y" in done.stderr
    assert "addon-chat-allow" not in done.stderr


@needs_bash
def test_without_a_terminal_the_shown_audience_must_be_named():
    refused = _chat("allow", "probe")
    assert refused.returncode == 2
    assert "--approve=<audience>" in refused.stderr
    assert "addon-chat-allow" not in refused.stderr

    named = _chat("allow", "probe", "--approve=mcp-wiki")
    assert named.returncode == 0
    assert "py_cli addon-chat-show --name=probe" in named.stderr
    assert "py_cli addon-chat-allow --name=probe --approve=mcp-wiki" in named.stderr


@needs_bash
def test_interactively_the_shown_audience_is_asked_for_and_allowed():
    yes = _chat("allow", "probe", tty=True, answer="y")
    assert "ASKED: Allow probe in the chat (audience mcp-wiki)?" in yes.stdout
    assert "py_cli addon-chat-allow --name=probe --approve=mcp-wiki" in yes.stderr

    no = _chat("allow", "probe", tty=True, answer="n")
    assert no.returncode == 1
    assert "addon-chat-allow" not in no.stderr


@needs_bash
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("grant", "probe"), "Valid: allow, revoke, list"),
        (("revoke",), "Usage: papaia-ctl addon chat revoke <name>"),
        (("list", "probe"), "takes no add-on name"),
        (("revoke", "probe", "--json"), "--json is an option of 'addon chat list' only"),
        (("allow", "probe", "other"), "takes one add-on name"),
    ],
)
def test_the_shell_refuses_malformed_calls(args, message):
    done = _chat(*args)

    assert done.returncode == 2
    assert message in done.stderr
