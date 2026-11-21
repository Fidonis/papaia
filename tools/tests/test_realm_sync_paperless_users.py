"""papaia-ctl realm sync: the name list of the Paperless gate.

The gate in front of Paperless passes the identity header only for names on this list.
The realm sync writes it from the realm on every run; an account that is gone from the
realm, deactivated or without a Paperless role is gone from the list after the next run.
"""

from __future__ import annotations

import json
import os

import pytest
import yaml

from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_realm_sync import _flow, _tree, connected  # noqa: F401  (fixture)

PAPERLESS_ROLES = ("paperless-member", "paperless-admin")


def _register() -> rs.Register:
    """The shipped register plus the roles a Paperless add-on would declare."""
    data = json.loads(rs.REGISTER_PATH.read_text(encoding="utf-8"))
    data["entries"] += [{"name": r, "kind": "role", "owner": "paperless"} for r in PAPERLESS_ROLES]
    return rs.Register(data)


REGISTER = _register()


def _paperless(roles=PAPERLESS_ROLES) -> rs.Module:
    entry = {"id": "paperless.documents", "kind": "mcp", "audience": "mcp-paperless"}
    if roles:
        entry["roles"] = [{"name": r} for r in roles]
    return rs.Module("paperless", [entry], {})


def _plan(*modules) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), [])


def _list(config_dir) -> dict:
    return json.loads(rs.paperless_users_path(config_dir).read_text(encoding="utf-8"))


def _rows(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _realm_with_people() -> FakeRealm:
    realm = FakeRealm()
    for name in PAPERLESS_ROLES:
        realm.add_realm_role(name)
    realm.add_realm_role("buchhaltung-bundle", {"paperless-member"})
    archive = realm.add_group("archiv", {"paperless-member"})
    realm.add_user("anna", realm_roles={"paperless-member"})
    realm.add_user("ben", groups=(archive,))
    realm.add_user("carla", realm_roles={"buchhaltung-bundle"})
    realm.add_user("dora", realm_roles={"paperless-admin"})
    realm.add_user("erik")  # no Paperless role
    realm.add_user("frida", realm_roles={"paperless-member"}, enabled=False)
    return realm


# ─────────────────────────────────────────────────────────────────────────
# which roles count
# ─────────────────────────────────────────────────────────────────────────


def test_the_paperless_roles_are_the_roles_of_the_module_serving_mcp_paperless():
    plan = _plan(_flow(), _paperless())
    assert plan.paperless_roles == frozenset(PAPERLESS_ROLES)


def test_without_a_module_serving_mcp_paperless_there_is_no_list():
    assert _plan(_flow()).paperless_roles is None


def test_a_paperless_module_without_roles_admits_no_name_and_says_so():
    plan = _plan(_paperless(roles=()))
    assert plan.paperless_roles == frozenset()
    assert any("paperless" in note and "no role" in note for note in plan.notes)


# ─────────────────────────────────────────────────────────────────────────
# who is on the list
# ─────────────────────────────────────────────────────────────────────────


def test_only_active_persons_holding_a_paperless_role_are_listed():
    realm = _realm_with_people()
    names = rs.paperless_users(realm.call, frozenset(PAPERLESS_ROLES))
    # direct, through a group and through a composite role count; a person without the
    # role and a deactivated account do not
    assert names == ["anna", "ben", "carla", "dora"]


def test_service_accounts_are_never_listed():
    realm = _realm_with_people()
    realm.call("POST", "/clients", {"clientId": "svc-flow-d1", "serviceAccountsEnabled": True})
    realm.service_account_user("svc-flow-d1")["_realm"].add("paperless-member")
    assert "service-account-svc-flow-d1" not in rs.paperless_users(
        realm.call, frozenset(PAPERLESS_ROLES)
    )


def test_every_page_of_the_user_list_is_read():
    realm = FakeRealm()
    realm.add_realm_role("paperless-member")
    for index in range(rs.USER_PAGE * 2 + 3):
        realm.add_user(f"person{index:04d}", realm_roles={"paperless-member"})
    names = rs.paperless_users(realm.call, frozenset({"paperless-member"}))
    assert len(names) == rs.USER_PAGE * 2 + 3


def test_no_paperless_role_reads_no_user():
    realm = _realm_with_people()
    calls = []

    def spy(method, path, body=None):
        calls.append(path)
        return realm.call(method, path, body)

    assert rs.paperless_users(spy, frozenset()) == []
    assert calls == []


@pytest.mark.parametrize("name", ["anna maria", "anna\nben", "anna,ben", "x" * 256, "-anna"])
def test_a_name_that_cannot_travel_in_a_header_is_left_out_and_noted_by_id(name, capsys):
    realm = FakeRealm()
    realm.add_realm_role("paperless-member")
    uid = realm.add_user(name, realm_roles={"paperless-member"})
    assert rs.paperless_users(realm.call, frozenset({"paperless-member"})) == []
    out = capsys.readouterr().out
    assert uid in out
    assert name not in out


# ─────────────────────────────────────────────────────────────────────────
# the file
# ─────────────────────────────────────────────────────────────────────────


def test_the_list_is_written_for_a_read_only_mount_into_the_gate(tmp_path):
    realm = _realm_with_people()
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        changes = rs.sync_paperless_users(
            realm.call, _plan(_paperless()), tmp_path, apply=True, audit=audit
        )
    assert len(changes) == 1
    path = rs.paperless_users_path(tmp_path)
    assert path == tmp_path / "security" / "paperless-gate" / "users.json"
    assert _list(tmp_path) == {
        "format": "papaia.paperless-users/1",
        "users": ["anna", "ben", "carla", "dora"],
    }
    # the gate runs under its own uid: it reads, nobody but papaia-ctl writes
    assert path.stat().st_mode & 0o777 == 0o644
    assert path.parent.stat().st_mode & 0o777 == 0o755
    assert not [p for p in path.parent.iterdir() if p.name != path.name]


def test_one_audit_row_per_changed_list_without_any_name(tmp_path):
    realm = _realm_with_people()
    outbox = tmp_path / "audit.jsonl"
    with rs.AuditLog(outbox, "run-1") as audit:
        rs.sync_paperless_users(realm.call, _plan(_paperless()), tmp_path, apply=True, audit=audit)
    (row,) = _rows(outbox)
    assert row["format"] == "papaia.audit/1"
    assert row["correlation_id"] == "run-1"
    assert row["operation"] == "realm_sync.paperless_users.write"
    assert row["effect"] == "write"
    assert row["result"] == "allowed"
    assert row["object_ref"] == {"type": "file", "id": "security/paperless-gate/users.json"}
    for name in ("anna", "ben", "carla", "dora"):
        assert name not in outbox.read_text()

    # unchanged realm: no write, no row
    with rs.AuditLog(outbox, "run-2") as audit:
        assert (
            rs.sync_paperless_users(
                realm.call, _plan(_paperless()), tmp_path, apply=True, audit=audit
            )
            == []
        )
    assert len(_rows(outbox)) == 1


def test_check_reports_a_stale_list_and_writes_nothing(tmp_path, capsys):
    realm = _realm_with_people()
    plan = _plan(_paperless())
    rs.sync_paperless_users(realm.call, plan, tmp_path, apply=True, audit=None)
    before = rs.paperless_users_path(tmp_path).read_bytes()
    realm.add_user("gustav", realm_roles={"paperless-member"})
    capsys.readouterr()
    changes = rs.sync_paperless_users(realm.call, plan, tmp_path, apply=False, audit=None)
    assert len(changes) == 1
    assert "fail: file security/paperless-gate/users.json" in capsys.readouterr().out
    assert rs.paperless_users_path(tmp_path).read_bytes() == before


def test_a_list_left_by_a_removed_paperless_module_is_deleted(tmp_path):
    realm = _realm_with_people()
    rs.sync_paperless_users(realm.call, _plan(_paperless()), tmp_path, apply=True, audit=None)
    outbox = tmp_path / "audit.jsonl"
    with rs.AuditLog(outbox, "run-2") as audit:
        changes = rs.sync_paperless_users(
            realm.call, _plan(_flow()), tmp_path, apply=True, audit=audit
        )
    assert len(changes) == 1
    assert not rs.paperless_users_path(tmp_path).exists()
    (row,) = _rows(outbox)
    assert row["operation"] == "realm_sync.paperless_users.delete"
    assert row["effect"] == "delete"
    # nothing installed, nothing left: no further change
    assert rs.sync_paperless_users(realm.call, _plan(_flow()), tmp_path, apply=True) == []


def test_a_directory_behind_a_symlink_is_refused(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "security").mkdir()
    os.symlink(elsewhere, tmp_path / "security" / "paperless-gate")
    with pytest.raises(rs.RealmSyncError, match="symbolic link|safely"):
        rs.sync_paperless_users(
            _realm_with_people().call, _plan(_paperless()), tmp_path, apply=True
        )
    assert list(elsewhere.iterdir()) == []


def test_a_directory_writable_by_others_is_refused(tmp_path):
    directory = rs.paperless_users_path(tmp_path).parent
    directory.mkdir(parents=True)
    directory.chmod(0o777)
    with pytest.raises(rs.RealmSyncError, match="writable by group or others"):
        rs.sync_paperless_users(
            _realm_with_people().call, _plan(_paperless()), tmp_path, apply=True
        )


def test_a_list_file_that_is_a_symlink_is_replaced_not_followed(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("keep")
    path = rs.paperless_users_path(tmp_path)
    path.parent.mkdir(parents=True)
    os.symlink(target, path)
    rs.sync_paperless_users(_realm_with_people().call, _plan(_paperless()), tmp_path, apply=True)
    assert target.read_text() == "keep"
    assert not path.is_symlink()
    assert _list(tmp_path)["users"] == ["anna", "ben", "carla", "dora"]


# ─────────────────────────────────────────────────────────────────────────
# the command: removed accounts vanish within one sync
# ─────────────────────────────────────────────────────────────────────────


def _config(tmp_path):
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    addon = repo_root / "paperless"
    addon.mkdir(parents=True)
    manifest = {"name": "paperless", "exposes": _paperless().exposes}
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    config_dir.mkdir()
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "paperless", "path": str(addon), "active": True}]})
    )
    return config_dir, repo_root


def test_an_account_removed_from_the_realm_is_missing_from_the_list_after_the_next_sync(
    tmp_path,
    connected,  # noqa: F811
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(rs, "load_register", lambda *a: REGISTER)
    config_dir, repo_root = _config(tmp_path)
    assert rs.sync(_tree(), config_dir, repo_root) == 0  # creates the Paperless roles
    anna = connected.add_user("anna", realm_roles={"paperless-member"})
    connected.add_user("ben", realm_roles={"paperless-admin"})
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert _list(config_dir)["users"] == ["anna", "ben"]

    connected.call("DELETE", f"/users/{anna}")
    capsys.readouterr()
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 1
    assert "fail: file security/paperless-gate/users.json" in capsys.readouterr().out
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert _list(config_dir)["users"] == ["ben"]
    rows = _rows(rs.audit_path(config_dir))
    writes = [r for r in rows if r["operation"] == "realm_sync.paperless_users.write"]
    assert len(writes) == 3  # first (empty) list, anna and ben, ben alone
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0
