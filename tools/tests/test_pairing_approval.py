"""Exchange-right pairings at installation (lib/pairing_approval.py, security 1.4).

`setup` shows every pairing of the signed bill of materials with the sha256 of the list.
Confirming that list (interactively or with `--approve-pairings=<sha256>`, never with
`-y`) confirms the read pairings and leaves every write pairing waiting for a second
person; the realm sync assigns nothing that is waiting. `papaia-ctl pairing approve` by
another person than the one who requested it confirms a write pairing.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import cli, suite
from lib import pairing_approval as pa
from lib import realm_sync as rs
from tests.test_ctl_standalone_commands import BASH, needs_bash
from tests.test_suite import BOM_SCHEMA, _bom, _sign, keypair  # noqa: F401 (fixture)

REGISTER = rs.load_register()
REPO = Path(__file__).resolve().parents[2]
AUDIT_SCHEMA = json.loads(
    (REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text(encoding="utf-8")
)
SUBMISSION = Draft202012Validator(
    {**AUDIT_SCHEMA, "$ref": "#/$defs/submission", "required": [], "allOf": []}
)

READ_STUDIO = {"client": "papaia-studio-gateway", "audience": "mcp-paperless", "effects": ["r"]}
READ_FLOW = {"client": "papaia-studio-gateway", "audience": "flow", "effects": ["x"]}
WRITE_FLOW = {"client": "flow-engine", "audience": "mcp-paperless", "effects": ["r", "w", "d"]}
BOM_PAIRINGS = [READ_STUDIO, READ_FLOW, WRITE_FLOW]


def _bom_with(pairings: list[dict]) -> dict:
    doc = _bom()
    doc["pairings"] = pairings
    return doc


def _modules() -> list[rs.Module]:
    flow = rs.Module(
        "papaia-flow",
        [{"id": "flow.runs", "kind": "rest", "audience": "flow", "identity": ["person"],
          "roles": [{"name": "flow-member"}]}],
        {},
    )
    studio = rs.Module(
        "papaia-studio",
        [{"id": "studio.ui", "kind": "ui", "identity": ["person"],
          "ui": [{"id": "studio", "visible_for_roles": ["studio-member"]}],
          "roles": [{"name": "studio-member"}]}],
        {},
    )
    paperless = rs.Module(
        "paperless", [{"id": "paperless.mcp", "kind": "mcp", "audience": "mcp-paperless"}], {}
    )
    return [flow, studio, paperless]


def _assigned(config_dir: Path) -> dict[str, set[str]]:
    plan = rs.build_plan(
        REGISTER, _modules(), rs.load_pairings(rs.pairings_path(config_dir), REGISTER)
    )
    return {
        name: {s for s in spec.optional_scopes if s.startswith("aud-")}
        for name, spec in plan.clients.items()
        if name in ("papaia-studio-gateway", "flow-engine")
    }


def _rows(config_dir: Path) -> list[dict]:
    path = rs.audit_path(config_dir)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _config(tmp_path: Path) -> Path:
    config = tmp_path / "papaia-config"
    config.mkdir(mode=0o700)
    return config


# ─────────────────────────────────────────────────────────────────────────
# the pairings of the bill of materials
# ─────────────────────────────────────────────────────────────────────────


def test_the_bill_of_materials_may_name_pairings_and_both_validators_accept_them():
    doc = _bom_with(BOM_PAIRINGS)

    suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc)) == []


@pytest.mark.parametrize(
    ("pairings", "message"),
    [
        ({"client": "flow-engine"}, "list"),
        ([{**READ_STUDIO, "state": "confirmed"}], "unknown field"),
        ([{"client": "flow-engine", "audience": "flow"}], "missing field"),
        ([{**READ_STUDIO, "effects": []}], "effects"),
        ([{**READ_STUDIO, "effects": ["r", "r"]}], "effects"),
        ([{**READ_STUDIO, "effects": ["read"]}], "effects"),
        ([{**READ_STUDIO, "client": "Flow Engine"}], "client"),
        ([READ_STUDIO, READ_STUDIO], "twice"),
    ],
)
def test_malformed_pairings_in_the_bill_of_materials_are_refused(pairings, message):
    doc = _bom_with(pairings)

    with pytest.raises(suite.SuiteError, match=message):
        suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc)) or message == "twice"


def test_bill_of_materials_pairings_are_checked_against_the_register():
    unknown = {"client": "flow-engine", "audience": "mcp-nowhere", "effects": ["r"]}
    no_exchange = {"client": "flow", "audience": "mcp-paperless", "effects": ["r"]}

    with pytest.raises(pa.PairingError, match="mcp-nowhere"):
        pa.bom_pairings(_bom_with([unknown]), REGISTER)
    with pytest.raises(pa.PairingError, match="no token exchange"):
        pa.bom_pairings(_bom_with([no_exchange]), REGISTER)


def test_the_list_digest_is_independent_of_order_and_bound_to_every_effect():
    one = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    other = pa.bom_pairings(_bom_with(list(reversed(BOM_PAIRINGS))), REGISTER)
    narrower = pa.bom_pairings(
        _bom_with([READ_STUDIO, READ_FLOW, {**WRITE_FLOW, "effects": ["r", "w"]}]), REGISTER
    )

    assert pa.list_digest(one) == pa.list_digest(other)
    assert pa.list_digest(one) != pa.list_digest(narrower)
    assert pa.list_digest(one).startswith("sha256:") and len(pa.list_digest(one)) == 71


def test_read_and_write_pairings_are_told_apart_by_write_or_delete():
    entries = {(e.client, e.audience): e for e in pa.bom_pairings(_bom_with(BOM_PAIRINGS),
                                                                   REGISTER)}

    assert not entries[("papaia-studio-gateway", "mcp-paperless")].writes
    assert not entries[("papaia-studio-gateway", "flow")].writes
    assert entries[("flow-engine", "mcp-paperless")].writes


# ─────────────────────────────────────────────────────────────────────────
# confirmation at installation
# ─────────────────────────────────────────────────────────────────────────


def test_installation_confirms_read_pairings_and_leaves_write_pairings_unassigned(tmp_path):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)

    result = pa.confirm_installation(
        config, REGISTER, entries, pa.list_digest(entries), person="host:anna"
    )

    assert sorted((e.client, e.audience) for e in result.confirmed) == [
        ("papaia-studio-gateway", "flow"),
        ("papaia-studio-gateway", "mcp-paperless"),
    ]
    assert [(e.client, e.audience) for e in result.waiting] == [("flow-engine", "mcp-paperless")]
    stored = {(p.client, p.audience): p for p in
              rs.load_pairings(rs.pairings_path(config), REGISTER)}
    assert stored[("flow-engine", "mcp-paperless")].confirmed is False
    assert stored[("flow-engine", "mcp-paperless")].requested_by == "host:anna"
    assert stored[("papaia-studio-gateway", "mcp-paperless")].confirmed_by == "host:anna"
    assert _assigned(config) == {
        "papaia-studio-gateway": {"aud-mcp-paperless", "aud-flow"},
        "flow-engine": set(),
    }


def test_the_file_written_at_installation_is_private_to_the_host_account(tmp_path):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)

    pa.confirm_installation(config, REGISTER, entries, pa.list_digest(entries),
                            person="host:anna")

    path = rs.pairings_path(config)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["format"] == rs.PAIRINGS_FORMAT


def test_each_confirmed_or_requested_pairing_is_one_audit_row_with_host_account_and_time(
    tmp_path,
):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    digest = pa.list_digest(entries)

    pa.confirm_installation(config, REGISTER, entries, digest, person="host:anna")

    rows = _rows(config)
    assert len(rows) == 3
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == []
        assert row["event"] == "exchange_right_changed"
        assert row["sub"] == "host:anna"
        assert row["time"].endswith("Z")
        assert row["result"] == "allowed"
        assert row["detail"] == {"statement_hash": digest}
        assert row["identity_kind"] is None and row["azp"] is None
    assert len({row["correlation_id"] for row in rows}) == 1
    assert sorted((r["operation"], r["object_ref"]["id"]) for r in rows) == [
        ("pairing.confirm", "papaia-studio-gateway/flow"),
        ("pairing.confirm", "papaia-studio-gateway/mcp-paperless"),
        ("pairing.request", "flow-engine/mcp-paperless"),
    ]


@pytest.mark.parametrize("approved", ["sha256:" + "0" * 64, "0" * 64])
def test_another_list_than_the_approved_one_confirms_nothing(tmp_path, approved):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)

    with pytest.raises(pa.PairingError, match="differs"):
        pa.confirm_installation(config, REGISTER, entries, approved, person="host:anna")

    assert not rs.pairings_path(config).exists()
    (row,) = _rows(config)
    assert (row["result"], row["error_code"], row["event"]) == (
        "denied", "list_digest_mismatch", "exchange_right_changed"
    )
    assert list(SUBMISSION.iter_errors(row)) == []


@pytest.mark.parametrize("approved", ["", "yes", "y", "sha256:XYZ", "sha256:" + "a" * 63])
def test_an_approval_that_is_no_sha256_is_refused(tmp_path, approved):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)

    with pytest.raises(pa.PairingError, match="sha256"):
        pa.confirm_installation(config, REGISTER, entries, approved, person="host:anna")
    assert not rs.pairings_path(config).exists()


def test_the_bare_hex_form_of_the_digest_is_the_same_approval(tmp_path):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)

    result = pa.confirm_installation(
        config, REGISTER, entries, pa.list_digest(entries).removeprefix("sha256:"),
        person="host:anna",
    )

    assert len(result.confirmed) == 2


def test_a_second_confirmation_changes_nothing_and_never_upgrades_a_waiting_pairing(tmp_path):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    digest = pa.list_digest(entries)
    pa.confirm_installation(config, REGISTER, entries, digest, person="host:anna")
    before = rs.pairings_path(config).read_bytes()

    again = pa.confirm_installation(config, REGISTER, entries, digest, person="host:bert")

    assert again.confirmed == [] and again.waiting == []
    assert rs.pairings_path(config).read_bytes() == before
    assert len(_rows(config)) == 3


def test_pairings_already_recorded_by_hand_are_kept(tmp_path):
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    pa.approve(config, REGISTER, "flow-engine", "mcp-qdrant", ["r"], person="host:anna")

    pa.confirm_installation(config, REGISTER, entries, pa.list_digest(entries),
                            person="host:anna")

    stored = {(p.client, p.audience) for p in rs.load_pairings(rs.pairings_path(config),
                                                               REGISTER)}
    assert ("flow-engine", "mcp-qdrant") in stored and len(stored) == 4


# ─────────────────────────────────────────────────────────────────────────
# approval by a second person
# ─────────────────────────────────────────────────────────────────────────


def _installed(tmp_path: Path) -> Path:
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    pa.confirm_installation(config, REGISTER, entries, pa.list_digest(entries),
                            person="host:anna")
    return config


def test_approval_of_a_write_pairing_by_the_same_person_is_refused(tmp_path):
    config = _installed(tmp_path)

    with pytest.raises(pa.PairingError, match="second person"):
        pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None, person="host:anna")

    assert _assigned(config)["flow-engine"] == set()
    row = _rows(config)[-1]
    assert (row["operation"], row["result"], row["error_code"], row["sub"]) == (
        "pairing.approve", "denied", "same_person", "host:anna"
    )
    assert list(SUBMISSION.iter_errors(row)) == []


def test_approval_of_a_write_pairing_by_a_second_person_assigns_it(tmp_path):
    config = _installed(tmp_path)

    outcome = pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None,
                         person="host:bert")

    assert outcome == "confirmed"
    (pairing,) = [p for p in rs.load_pairings(rs.pairings_path(config), REGISTER)
                  if p.client == "flow-engine"]
    assert (pairing.confirmed, pairing.requested_by, pairing.confirmed_by) == (
        True, "host:anna", "host:bert"
    )
    assert _assigned(config)["flow-engine"] == {"aud-mcp-paperless"}
    row = _rows(config)[-1]
    assert (row["operation"], row["result"], row["sub"], row["event"]) == (
        "pairing.approve", "allowed", "host:bert", "exchange_right_changed"
    )


def test_a_new_write_pairing_waits_for_a_second_person(tmp_path):
    config = _config(tmp_path)

    first = pa.approve(config, REGISTER, "papaia-studio-gateway", "mcp-paperless", ["r", "w"],
                       person="host:anna")
    with pytest.raises(pa.PairingError, match="second person"):
        pa.approve(config, REGISTER, "papaia-studio-gateway", "mcp-paperless", None,
                   person="host:anna")
    second = pa.approve(config, REGISTER, "papaia-studio-gateway", "mcp-paperless", None,
                        person="host:bert")

    assert (first, second) == ("waiting", "confirmed")
    assert _assigned(config)["papaia-studio-gateway"] == {"aud-mcp-paperless"}


def test_a_read_pairing_outside_the_bill_of_materials_is_assigned_to_its_client_only(
    tmp_path,
):
    """PLT-59-A2: nothing without approval; after approval for Studio only Studio has it."""
    config = _config(tmp_path)
    assert _assigned(config) == {"papaia-studio-gateway": set(), "flow-engine": set()}

    outcome = pa.approve(config, REGISTER, "papaia-studio-gateway", "mcp-paperless", ["r"],
                         person="host:anna")

    assert outcome == "confirmed"
    assert _assigned(config) == {
        "papaia-studio-gateway": {"aud-mcp-paperless"}, "flow-engine": set()
    }


def test_a_waiting_pairing_without_a_requester_counts_the_first_approver_as_requester(
    tmp_path,
):
    config = _config(tmp_path)
    path = rs.pairings_path(config)
    path.parent.mkdir(mode=0o700)
    path.write_text(yaml.safe_dump({"format": rs.PAIRINGS_FORMAT, "pairings": [
        {**WRITE_FLOW, "state": "pending"}]}), encoding="utf-8")
    path.chmod(0o600)

    assert pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None,
                      person="host:anna") == "waiting"
    with pytest.raises(pa.PairingError, match="second person"):
        pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None, person="host:anna")
    assert pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None,
                      person="host:bert") == "confirmed"


@pytest.mark.parametrize(
    ("client", "audience", "effects", "message"),
    [
        ("flow-engine", "mcp-paperless", ["r"], "effects"),
        ("flow-engine", "mcp-qdrant", None, "--effects"),
        ("flow", "mcp-paperless", ["r"], "no token exchange"),
        ("flow-engine", "mcp-paperless", ["r", "q"], "effects"),
    ],
)
def test_an_approval_that_does_not_fit_is_refused_and_changes_nothing(
    tmp_path, client, audience, effects, message
):
    config = _installed(tmp_path)
    before = rs.pairings_path(config).read_bytes()

    with pytest.raises(pa.PairingError, match=message):
        pa.approve(config, REGISTER, client, audience, effects, person="host:bert")
    assert rs.pairings_path(config).read_bytes() == before


def test_an_unknown_acting_person_never_approves_a_write_pairing(tmp_path):
    config = _installed(tmp_path)

    with pytest.raises(pa.PairingError, match="second person"):
        pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None, person="unknown")


def test_revoke_removes_the_pairing_with_one_audit_row(tmp_path):
    config = _installed(tmp_path)

    pa.revoke(config, REGISTER, "papaia-studio-gateway", "mcp-paperless", person="host:bert")

    assert _assigned(config)["papaia-studio-gateway"] == {"aud-flow"}
    row = _rows(config)[-1]
    assert (row["operation"], row["object_ref"]["id"], row["result"]) == (
        "pairing.revoke", "papaia-studio-gateway/mcp-paperless", "allowed"
    )
    with pytest.raises(pa.PairingError, match="not recorded"):
        pa.revoke(config, REGISTER, "papaia-studio-gateway", "mcp-paperless",
                  person="host:bert")


def test_the_acting_person_trusts_sudo_user_only_under_root(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "mallory")
    if os.geteuid() != 0:
        assert pa.acting_person() != "host:mallory"
    monkeypatch.setattr(pa.os, "geteuid", lambda: 0)
    assert pa.acting_person() == "host:mallory"
    monkeypatch.setenv("SUDO_USER", "bad name;")
    assert pa.acting_person() == "unknown"


# ─────────────────────────────────────────────────────────────────────────
# the realm sync trusts no confirmed write pairing without two persons
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "extra",
    [{}, {"requested_by": "host:anna"}, {"confirmed_by": "host:anna"},
     {"requested_by": "host:anna", "confirmed_by": "host:anna"}],
)
def test_a_confirmed_write_pairing_needs_two_different_persons(extra):
    doc = {"format": rs.PAIRINGS_FORMAT, "pairings": [
        {**WRITE_FLOW, "state": "confirmed", **extra}]}

    with pytest.raises(rs.RealmSyncError, match="second person"):
        rs.parse_pairings(doc, REGISTER)


def test_a_confirmed_read_pairing_needs_no_second_person():
    doc = {"format": rs.PAIRINGS_FORMAT, "pairings": [{**READ_STUDIO, "state": "confirmed"}]}

    (pairing,) = rs.parse_pairings(doc, REGISTER)
    assert pairing.confirmed


@pytest.mark.parametrize("value", ["", "anna", "host:", "host:a b", "host:" + "a" * 70, 7])
def test_the_persons_of_a_pairing_are_host_accounts(value):
    doc = {"format": rs.PAIRINGS_FORMAT, "pairings": [
        {**READ_STUDIO, "state": "confirmed", "confirmed_by": value}]}

    with pytest.raises(rs.RealmSyncError, match="confirmed_by"):
        rs.parse_pairings(doc, REGISTER)


# ─────────────────────────────────────────────────────────────────────────
# the commands: a checkout with a signed bill of materials
# ─────────────────────────────────────────────────────────────────────────


def _checkout(tmp_path: Path, keypair, pairings: list[dict] | None) -> Path:  # noqa: F811
    private, public = keypair
    root = tmp_path / "papaia"
    (root / "compat").mkdir(parents=True)
    (root / "VERSION").write_text("1.10.0\n", encoding="utf-8")
    shutil.copyfile(public, root / suite.RELEASE_KEY_PATH)
    doc = _bom(public.read_text("ascii"))
    if pairings is not None:
        doc["pairings"] = pairings
    path = root / "compat" / "suite-1.10.0.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    _sign(private, path)
    return root


def _cli(root: Path, config: Path, *args: str) -> int:
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), *args])


def _listing(root: Path, config: Path, capsys) -> dict:
    capsys.readouterr()
    assert _cli(root, config, "pairing-list", "--json") == 0
    return json.loads(capsys.readouterr().out)


def test_the_list_shows_every_pairing_of_the_signed_bill_with_its_digest(
    tmp_path, keypair, capsys  # noqa: F811
):
    root = _checkout(tmp_path, keypair, BOM_PAIRINGS)
    config = _config(tmp_path)

    listing = _listing(root, config, capsys)

    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    assert listing["digest"] == pa.list_digest(entries)
    assert listing["suite"] == "1.10.0"
    assert [(p["client"], p["audience"], p["effects"], p["kind"], p["state"])
            for p in listing["pairings"]] == [
        ("flow-engine", "mcp-paperless", "rwd", "write", "not recorded"),
        ("papaia-studio-gateway", "flow", "x", "read", "not recorded"),
        ("papaia-studio-gateway", "mcp-paperless", "r", "read", "not recorded"),
    ]
    assert listing["pending_decision"] is True


def test_install_with_the_approval_answer_then_approval_by_the_same_person_is_refused(
    tmp_path, keypair, capsys, monkeypatch  # noqa: F811
):
    root = _checkout(tmp_path, keypair, BOM_PAIRINGS)
    config = _config(tmp_path)
    digest = _listing(root, config, capsys)["digest"]
    monkeypatch.setattr(pa, "acting_person", lambda: "host:anna")

    assert _cli(root, config, "pairing-confirm", f"--approve-pairings={digest}") == 0
    out = capsys.readouterr().out
    assert "waiting for approval: flow-engine -> mcp-paperless (rwd)" in out
    assert _assigned(config) == {
        "papaia-studio-gateway": {"aud-mcp-paperless", "aud-flow"}, "flow-engine": set()
    }
    assert _listing(root, config, capsys)["pending_decision"] is False

    assert _cli(root, config, "pairing-approve", "--client=flow-engine",
                "--audience=mcp-paperless") == 2
    assert "second person" in capsys.readouterr().err
    assert _assigned(config)["flow-engine"] == set()

    monkeypatch.setattr(pa, "acting_person", lambda: "host:bert")
    assert _cli(root, config, "pairing-approve", "--client=flow-engine",
                "--audience=mcp-paperless") == 0
    assert _assigned(config)["flow-engine"] == {"aud-mcp-paperless"}


def test_confirm_refuses_a_digest_of_another_list(tmp_path, keypair, capsys):  # noqa: F811
    root = _checkout(tmp_path, keypair, BOM_PAIRINGS)
    config = _config(tmp_path)

    assert _cli(root, config, "pairing-confirm", "--approve-pairings=" + "1" * 64) == 2
    assert "differs" in capsys.readouterr().err
    assert not rs.pairings_path(config).exists()


def test_a_tampered_bill_of_materials_is_never_offered(tmp_path, keypair, capsys):  # noqa: F811
    root = _checkout(tmp_path, keypair, BOM_PAIRINGS)
    config = _config(tmp_path)
    path = root / "compat" / "suite-1.10.0.yaml"
    path.write_text(path.read_text("utf-8").replace("effects:\n  - r\n  - w\n  - d",
                                                    "effects:\n  - r"), encoding="utf-8")

    assert _cli(root, config, "pairing-list", "--json") == 2
    assert "signature" in capsys.readouterr().err


def test_a_checkout_without_a_bill_of_materials_has_nothing_to_confirm(tmp_path, capsys):
    root = tmp_path / "papaia"
    root.mkdir()
    (root / "VERSION").write_text("1.10.0\n", encoding="utf-8")
    config = _config(tmp_path)

    assert _cli(root, config, "pairing-list", "--json") == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing == {"bom": False, "pairings": [], "digest": None, "suite": None,
                       "pending_decision": False}


# ─────────────────────────────────────────────────────────────────────────
# setup: `-y` never confirms
# ─────────────────────────────────────────────────────────────────────────

SETUP_SH = Path(__file__).resolve().parents[1] / "lib" / "sh" / "pairing.sh"

_HARNESS = """
set -euo pipefail
CONFIG_DIR=/no/such/config
error() { echo "ERROR: $*" >&2; }
warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*"; }
success() { echo "OK: $*"; }
is_tty() { [ "${FAKE_TTY:-0}" = 1 ]; }
confirm() { echo "ASKED: $1"; [ "${FAKE_ANSWER:-n}" = y ]; }
py_cli() {
    echo "py_cli $*" >&2
    case "$1" in
        pairing-list)
            if [ "${2:-}" = "--digest" ]; then echo "sha256:@DIGEST@"; return 0; fi
            echo "listing"; return 0 ;;
        pairing-confirm) return "${CONFIRM_RC:-0}" ;;
    esac
}
source "@PAIRING@"
"""


def _setup_step(*args: str, tty: bool = False, answer: str = "n", confirm_rc: int = 0):
    assert BASH is not None
    harness = _HARNESS.replace("@PAIRING@", SETUP_SH.as_posix()).replace("@DIGEST@", "a" * 64)
    quoted = " ".join(f"'{a}'" for a in args)
    env = {**os.environ, "FAKE_TTY": "1" if tty else "0", "FAKE_ANSWER": answer,
           "CONFIRM_RC": str(confirm_rc)}
    return subprocess.run(
        [BASH, "-c", f"{harness}\n_setup_pairings {quoted}"],
        capture_output=True, text=True, timeout=30, check=False, env=env,
    )


@needs_bash
def test_setup_with_y_never_confirms_pairings():
    done = _setup_step("1", "")

    assert done.returncode == 0
    assert "pairing-confirm" not in done.stderr
    assert "ASKED" not in done.stdout
    assert "-y never confirms" in done.stderr
    assert "papaia-ctl pairing confirm --approve-pairings=sha256:" + "a" * 64 in done.stderr


@needs_bash
def test_setup_with_y_and_the_digest_confirms_that_list_only():
    done = _setup_step("1", "sha256:" + "b" * 64)

    assert done.returncode == 0
    assert "py_cli pairing-confirm --approve-pairings=sha256:" + "b" * 64 in done.stderr


@needs_bash
def test_setup_returns_an_error_when_the_approved_list_differs():
    done = _setup_step("1", "sha256:" + "b" * 64, confirm_rc=2)

    assert done.returncode == 2


@needs_bash
def test_interactive_setup_asks_and_confirms_the_list_it_showed():
    done = _setup_step("0", "", tty=True, answer="y")

    assert "ASKED" in done.stdout
    assert "py_cli pairing-confirm --approve-pairings=sha256:" + "a" * 64 in done.stderr


@needs_bash
def test_interactive_setup_answered_no_confirms_nothing():
    done = _setup_step("0", "", tty=True, answer="n")

    assert done.returncode == 0
    assert "pairing-confirm" not in done.stderr


@needs_bash
def test_setup_passes_the_approval_flag_on_and_validates_it():
    text = (Path(__file__).resolve().parents[1] / "lib" / "sh" / "setup.sh").read_text("utf-8")

    assert "--approve-pairings=*)" in text
    assert '_setup_pairings "$pairing_interactive" "$approve_pairings"' in text
