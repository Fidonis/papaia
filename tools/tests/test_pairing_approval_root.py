"""`sudo papaia-ctl pairing approve` by a second host account (lib/pairing_approval.py).

`pairings.yaml` belongs to the account that owns the configuration directory (it ran
`setup` and `pairing confirm`). A second account approves a write pairing as root through
sudo, so as root the pairing commands also trust `security/` and `pairings.yaml` when they
belong to the owner of the configuration directory, never a third account, never a file or
folder that group or others may write, never a symbolic link. Every write as root goes
through directory descriptors and hands what it creates to that owner, so nothing below
the configuration directory belongs to root afterwards and the owner's realm sync still
reads the file. Without root nothing changes.

Root is simulated: the effective uid is set to 0 and `fchown` is recorded instead of
called. The owner of the configuration directory is the account running the tests unless
a test injects another one.
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

from lib import cli
from lib import pairing_approval as pa
from lib import realm_sync as rs
from tests.test_pairing_approval import (
    BOM_PAIRINGS,
    REGISTER,
    SUBMISSION,
    _assigned,
    _bom_with,
    _config,
    _rows,
)

REAL_UID = os.getuid()
REAL_GID = os.getgid()
REAL_ROOT = REAL_UID == 0
# A uid that is neither root nor the account running the tests.
OTHER_UID = 4242 if REAL_UID != 4242 else 4243


def _installed(tmp_path: Path) -> Path:
    """`setup`'s pairing step run by the owner of the configuration directory: the write
    pairing flow-engine -> mcp-paperless waits, requested by host:operator."""
    config = _config(tmp_path)
    entries = pa.bom_pairings(_bom_with(BOM_PAIRINGS), REGISTER)
    pa.confirm_installation(config, REGISTER, entries, pa.list_digest(entries),
                            person="host:operator")
    return config


class Chowns:
    """fchown as root would do it, recorded by inode instead of changing anything."""

    def __init__(self) -> None:
        self.given: dict[tuple[int, int], tuple[int, int]] = {}

    def __call__(self, fd: int, uid: int, gid: int) -> None:
        st = os.fstat(fd)
        self.given[(st.st_dev, st.st_ino)] = (uid, gid)


@pytest.fixture
def as_root(monkeypatch):
    """papaia-ctl run through `sudo` by the account `approver`."""
    chowns = Chowns()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", chowns)
    monkeypatch.setenv("SUDO_USER", "approver")
    return chowns


def _owner(monkeypatch, uid: int, gid: int) -> None:
    """Inject the owner of the configuration directory."""
    monkeypatch.setattr("lib.config_owner.owner_of", lambda st: (uid, gid))


def _tree(config: Path) -> dict[tuple[int, int], Path]:
    found = {}
    for folder, dirs, files in os.walk(config, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(folder) / name
            st = path.lstat()
            found[(st.st_dev, st.st_ino)] = path
    return found


def _approve(config: Path) -> str:
    return pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None,
                      person=pa.acting_person())


def _give_away(path: Path, uid: int) -> None:
    """Make `path` belong to `uid`. Without real root the file stays the runner's, which
    the simulated root sees as a third account once another owner is injected."""
    if REAL_ROOT:
        os.chown(path, uid, -1, follow_symlinks=False)


# ─────────────────────────────────────────────────────────────────────────
# a second account approves as root
# ─────────────────────────────────────────────────────────────────────────


def test_a_second_account_approves_as_root_in_the_owners_configuration(tmp_path, as_root):
    config = _installed(tmp_path)

    outcome = _approve(config)

    assert outcome == "confirmed"
    (pairing,) = [p for p in pa._load(config, REGISTER) if p.client == "flow-engine"]
    assert (pairing.confirmed, pairing.requested_by, pairing.confirmed_by) == (
        True, "host:operator", "host:approver"
    )
    row = _rows(config)[-1]
    assert (row["operation"], row["result"], row["sub"], row["writer"]) == (
        "pairing.approve", "allowed", "host:approver", "papaia-ctl/pairing"
    )
    assert list(SUBMISSION.iter_errors(row)) == []


def test_the_command_as_root_confirms_and_names_the_second_account(
    tmp_path, as_root, capsys
):
    config = _installed(tmp_path)

    code = cli.main(["--repo-root", str(tmp_path / "no-checkout"), "--config-dir", str(config),
                     "pairing-approve", "--client=flow-engine", "--audience=mcp-paperless"])

    assert code == 0, capsys.readouterr().err
    assert "confirmed: flow-engine -> mcp-paperless" in capsys.readouterr().out
    assert _rows(config)[-1]["sub"] == "host:approver"


def test_everything_a_root_run_creates_is_handed_to_the_owner_with_mode_0600(
    tmp_path, as_root
):
    config = _installed(tmp_path)
    # A lock file and an audit outbox that do not exist yet are created by the root run.
    (rs.pairings_path(config).parent / pa.LOCK_FILE).unlink()
    shutil.rmtree(config / "audit")
    before = set(_tree(config))

    _approve(config)

    created = {key: path for key, path in _tree(config).items() if key not in before}
    names = {path.relative_to(config).as_posix() for path in created.values()}
    assert {"security/pairings.yaml", f"security/{pa.LOCK_FILE}", "audit", "audit/outbox",
            "audit/outbox/papaia-ctl.jsonl", "audit/outbox/papaia-ctl.seq"} <= names
    for key, path in created.items():
        assert as_root.given.get(key) == (REAL_UID, REAL_GID), path
        mode = stat.S_IMODE(path.lstat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path
    assert not [p for p in created.values() if p.name.endswith(".tmp")]


def test_the_owners_realm_sync_reads_the_file_a_root_run_wrote(tmp_path, monkeypatch):
    config = _installed(tmp_path)
    with monkeypatch.context() as root:
        root.setattr(os, "geteuid", lambda: 0)
        root.setattr(os, "fchown", Chowns())
        root.setenv("SUDO_USER", "approver")
        _approve(config)

    # Back to the owner: `start` runs the realm sync, which assigns the pairing.
    assert _assigned(config)["flow-engine"] == {"aud-mcp-paperless"}


# ─────────────────────────────────────────────────────────────────────────
# refusals as root
# ─────────────────────────────────────────────────────────────────────────


def test_the_same_person_through_sudo_is_refused_and_audited(tmp_path, as_root, monkeypatch):
    config = _installed(tmp_path)
    monkeypatch.setenv("SUDO_USER", "operator")
    before = rs.pairings_path(config).read_bytes()

    with pytest.raises(pa.PairingError, match="second person"):
        _approve(config)

    assert rs.pairings_path(config).read_bytes() == before
    row = _rows(config)[-1]
    assert (row["operation"], row["result"], row["error_code"], row["sub"]) == (
        "pairing.approve", "denied", "same_person", "host:operator"
    )


@pytest.mark.parametrize("what", ["file", "folder"])
def test_a_third_owner_is_refused_as_root(tmp_path, as_root, monkeypatch, what):
    config = _installed(tmp_path)
    path = rs.pairings_path(config)
    _give_away(path if what == "file" else path.parent, OTHER_UID)
    # The configuration directory belongs to yet another account.
    _owner(monkeypatch, OTHER_UID + 1, REAL_GID)
    before = path.read_bytes()

    with pytest.raises(pa.PairingError, match="owned by uid"):
        _approve(config)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("target", "mode"),
    [("file", 0o620), ("file", 0o602), ("folder", 0o770), ("folder", 0o707),
     ("config", 0o770), ("config", 0o707)],
)
def test_what_group_or_others_may_write_is_refused_as_root(tmp_path, as_root, target, mode):
    config = _installed(tmp_path)
    path = rs.pairings_path(config)
    {"file": path, "folder": path.parent, "config": config}[target].chmod(mode)
    before = path.read_bytes()

    with pytest.raises(pa.PairingError, match="writable by group or others"):
        _approve(config)

    assert path.read_bytes() == before


def test_a_security_folder_that_is_a_symbolic_link_is_refused_and_nothing_is_written(
    tmp_path, as_root
):
    config = _installed(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (config / "security").rename(elsewhere)
    (config / "security").symlink_to(elsewhere)
    before = {p.name: p.read_bytes() for p in elsewhere.iterdir()}

    with pytest.raises(pa.PairingError, match="symbolic link"):
        _approve(config)

    assert {p.name: p.read_bytes() for p in elsewhere.iterdir()} == before


def test_a_configuration_directory_that_is_a_symbolic_link_is_refused_as_root(
    tmp_path, as_root
):
    real = _installed(tmp_path)
    link = tmp_path / "config-link"
    link.symlink_to(real)
    before = {p.relative_to(real): p.read_bytes() for p in real.rglob("*") if p.is_file()}

    with pytest.raises(pa.PairingError, match="symbolic link"):
        _approve(link)

    assert {p.relative_to(real): p.read_bytes()
            for p in real.rglob("*") if p.is_file()} == before


def test_an_audit_outbox_with_a_second_link_is_never_written_as_root(tmp_path, as_root):
    """A hard link would let root append to, and hand over, a file elsewhere."""
    config = _installed(tmp_path)
    outbox = rs.audit_path(config)
    target = tmp_path / "elsewhere.jsonl"
    outbox.rename(target)
    os.link(target, outbox)
    before = target.read_bytes()

    with pytest.raises(pa.PairingError, match="link"):
        _approve(config)

    assert target.read_bytes() == before
    assert all(p.client != "flow-engine" or not p.confirmed
               for p in pa._load(config, REGISTER))


def test_a_lock_file_that_is_a_symbolic_link_is_refused_as_root(tmp_path, as_root):
    config = _installed(tmp_path)
    lock = rs.pairings_path(config).parent / pa.LOCK_FILE
    lock.unlink()
    target = tmp_path / "elsewhere.lock"
    lock.symlink_to(target)

    with pytest.raises(pa.PairingError, match="symbolic link"):
        _approve(config)

    assert not target.exists()


def test_an_audit_folder_made_with_a_group_umask_does_not_stop_the_approval(
    tmp_path, as_root
):
    """The owner's own runs make `audit/` with the umask of the login (0002 on hosts with
    a private group per user, so 0775). It grants nothing; root still opens it without a
    link and checks its owner and the files in it."""
    config = _installed(tmp_path)
    (config / "audit").chmod(0o775)

    assert _approve(config) == "confirmed"
    assert _rows(config)[-1]["sub"] == "host:approver"


# ─────────────────────────────────────────────────────────────────────────
# unchanged without root, and elsewhere
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(REAL_ROOT, reason="a file of another account needs a non-root runner")
def test_without_root_a_file_of_another_account_is_refused_as_before(tmp_path, monkeypatch):
    config = _installed(tmp_path)
    # The runner's file seen from another, non-root account.
    monkeypatch.setattr(os, "geteuid", lambda: OTHER_UID)

    with pytest.raises(pa.PairingError, match="not by the user running papaia-ctl"):
        pa.approve(config, REGISTER, "flow-engine", "mcp-paperless", None,
                   person="host:approver")


@pytest.mark.skipif(REAL_ROOT, reason="a root runner takes the root path")
def test_without_root_a_configuration_directory_behind_a_link_still_works(tmp_path):
    real = _installed(tmp_path)
    link = tmp_path / "config-link"
    link.symlink_to(real)

    assert pa.approve(link, REGISTER, "flow-engine", "mcp-paperless", None,
                      person="host:approver") == "confirmed"


@pytest.mark.skipif(REAL_ROOT, reason="a file of another account needs a non-root runner")
def test_the_realm_sync_keeps_its_rule_as_root(tmp_path, monkeypatch):
    """Only the pairing commands trust the owner of the configuration directory."""
    config = _installed(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(rs.RealmSyncError, match="not by the user running papaia-ctl"):
        rs.load_pairings(rs.pairings_path(config), REGISTER)


def test_the_list_as_root_reads_the_owners_file(tmp_path, as_root, capsys):
    config = _installed(tmp_path)
    before = set(_tree(config))

    code = cli.main(["--repo-root", str(tmp_path / "no-checkout"), "--config-dir", str(config),
                     "pairing-list", "--json"])

    assert code == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["bom"] is False
    assert set(_tree(config)) == before


def test_revoke_as_root_hands_the_new_file_to_the_owner(tmp_path, as_root):
    config = _installed(tmp_path)

    pa.revoke(config, REGISTER, "papaia-studio-gateway", "flow", person=pa.acting_person())

    st = rs.pairings_path(config).lstat()
    assert as_root.given[(st.st_dev, st.st_ino)] == (REAL_UID, REAL_GID)
    assert _rows(config)[-1]["sub"] == "host:approver"


def test_list_and_confirm_with_the_test_anchor_as_root_hand_the_journal_to_the_owner(
    tmp_path, as_root, capsys
):
    """With --test-trust-anchor the host's audit journal gets a row; as root it is written
    through descriptors and handed to the owner like everything else."""
    from tests.test_prerelease_anchor import _anchor_rows, _key_file, _new_keypair, _test_core

    key_pair = _new_keypair(tmp_path, "test-signing")
    root = _test_core(tmp_path, key_pair, pairings=BOM_PAIRINGS)
    config = _config(tmp_path)
    key = _key_file(tmp_path, key_pair[1])
    before = set(_tree(config))
    base = ["--repo-root", str(root), "--config-dir", str(config)]

    assert cli.main([*base, "pairing-list", "--json", f"--test-trust-anchor={key}"]) == 0
    digest = json.loads(capsys.readouterr().out)["digest"]
    assert cli.main([*base, "pairing-confirm", f"--approve-pairings={digest}",
                     f"--test-trust-anchor={key}"]) == 0, capsys.readouterr().err

    assert [row["operation"] for row in _anchor_rows(config)] == [
        "pairing-list", "pairing-confirm"]
    created = {k: p for k, p in _tree(config).items() if k not in before}
    assert config / "audit" / "papaia-ctl.jsonl" in created.values()
    for found, path in created.items():
        assert as_root.given.get(found) == (REAL_UID, REAL_GID), path


# ─────────────────────────────────────────────────────────────────────────
# end to end, where the test runner is root: two throwaway accounts and sudo
# ─────────────────────────────────────────────────────────────────────────

REPO = Path(__file__).resolve().parents[2]
_E2E_TOOLS = ("sudo", "useradd", "userdel", "bash")
needs_root_and_sudo = pytest.mark.skipif(
    not REAL_ROOT or any(shutil.which(t) is None for t in _E2E_TOOLS)
    or not (REPO / "tools" / ".runtime" / "current" / "bin" / "python").exists(),
    reason="needs a root runner with sudo, useradd and the runtime of papaia-ctl",
)


def _run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=120,
                          check=False, env=env)


@needs_root_and_sudo
def test_sudo_pairing_approve_by_a_second_account_end_to_end(tmp_path):
    owner, approver = "pp-owner-e2e", "pp-approver-e2e"
    sudoers = Path("/etc/sudoers.d/pp-approver-e2e")
    ctl = REPO / "tools" / "papaia-ctl"
    for name in (owner, approver):
        _run("userdel", "-r", name)
        assert _run("useradd", "-m", name).returncode == 0
    try:
        sudoers.write_text(f"{approver} ALL=(root) NOPASSWD: {ctl}\n", encoding="ascii")
        sudoers.chmod(0o440)
        home = Path(f"/home/{owner}")
        config = home / "config"
        config.mkdir(mode=0o700)
        (config / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
        (config / "deployment.yaml").write_text("core: {}\n", encoding="utf-8")
        uid, gid = int(_run("id", "-u", owner).stdout), int(_run("id", "-g", owner).stdout)
        for path in (config, config / ".env", config / "deployment.yaml"):
            os.chown(path, uid, gid)
        # `pairing confirm` of the owner, written as the owner.
        script = (
            "import json, sys; sys.path.insert(0, sys.argv[1]);"
            "from pathlib import Path;"
            "from lib import pairing_approval as pa, realm_sync as rs;"
            "reg = rs.load_register();"
            "e = pa.bom_pairings({'pairings': json.loads(sys.argv[3])}, reg);"
            "pa.confirm_installation(Path(sys.argv[2]), reg, e, pa.list_digest(e),"
            " person=pa.acting_person())"
        )
        python = str(REPO / "tools" / ".runtime" / "current" / "bin" / "python")
        done = _run("sudo", "-n", "-u", owner, python, "-I", "-c", script,
                    str(REPO / "tools"), str(config), json.dumps(BOM_PAIRINGS))
        assert done.returncode == 0, done.stderr

        done = _run("sudo", "-n", "-u", approver, "/usr/bin/sudo", "-n", str(ctl), "pairing",
                    "approve", "--client=flow-engine", "--audience=mcp-paperless",
                    f"--config-dir={config}")

        assert done.returncode == 0, done.stderr
        for path in [config, *config.rglob("*")]:
            assert path.lstat().st_uid == uid, path
        row = json.loads(rs.audit_path(config).read_text(encoding="utf-8").splitlines()[-1])
        assert (row["operation"], row["sub"]) == ("pairing.approve", f"host:{approver}")
        loaded = _run("sudo", "-n", "-u", owner, python, "-I", "-c",
                      "import sys; sys.path.insert(0, sys.argv[1]);"
                      "from pathlib import Path; from lib import realm_sync as rs;"
                      "print([p.confirmed for p in rs.load_pairings("
                      "rs.pairings_path(Path(sys.argv[2])), rs.load_register())"
                      " if p.client == 'flow-engine'])",
                      str(REPO / "tools"), str(config))
        assert loaded.stdout.strip() == "[True]", loaded.stderr
        assert yaml.safe_load(rs.pairings_path(config).read_text(encoding="utf-8"))
    finally:
        sudoers.unlink(missing_ok=True)
        for name in (owner, approver):
            _run("userdel", "-r", name)
