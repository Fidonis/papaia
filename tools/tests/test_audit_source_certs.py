"""The client certificates of the audit sources that `start` issues (docs/audit.md,
"Certificates of the sources").

Mein Bereich (`me-web`, `prefs`) and the connection registry (`connections`) mount
`infra/audit/clients/<source>` and refuse to run without a certificate of the ingest CA.
`start` issues it for each source of an enabled core profile when it is missing or
unusable, and never replaces a usable one; `papaia-ctl audit cert` stays the rotation.

The certificates are made with the real `openssl`, as in test_audit.py. The order of the
steps in `start` is checked with stubs that record their calls.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import audit, cli, realm_sync, topology

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
BASH = shutil.which("bash")
KNOWN = {"keycloak", "audit", "egress", "nginx", "me", "connections", "rag"}

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is needed")


def _openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _clients(config: Path) -> Path:
    return config / "infra" / "audit" / "clients"


def _outbox(config: Path) -> Path:
    return realm_sync.audit_path(config)


def _rows(config: Path) -> list[dict]:
    path = _outbox(config)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _snapshot(config: Path) -> dict[Path, tuple[bytes, int]]:
    return {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(config.rglob("*"))
        if path.is_file()
    }


def _prepared(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    audit.prepare(config)
    return config


def _run(config: Path, profiles, **kwargs) -> audit.SourceCertificates:
    return audit.ensure_source_certificates(config, profiles, known_profiles=KNOWN, **kwargs)


def _ensure(config: Path, profiles, **kwargs) -> list[audit.Issued]:
    return _run(config, profiles, **kwargs).issued


def _fingerprint(config: Path, source: str) -> str:
    return audit.fingerprint(_clients(config) / source / "client.crt")


# ─────────────────────────────────────────────────────────────────────────
# issuing what is missing
# ─────────────────────────────────────────────────────────────────────────


def test_enabled_profiles_get_their_source_certificates(tmp_path):
    config = _prepared(tmp_path)
    for source in ("papaia-me", "papaia-connections"):
        # The empty folders as an earlier `setup` or Docker left them.
        (_clients(config) / source).mkdir(parents=True)

    issued = _ensure(config, ["keycloak", "audit", "me", "connections"])

    assert [(entry.source, entry.reason) for entry in issued] == [
        ("papaia-me", "missing"),
        ("papaia-connections", "missing"),
    ]
    listed = audit.load_sources(config)
    ingest_ca = config / "infra" / "audit" / "pki" / "ca.crt"
    for source in ("papaia-me", "papaia-connections"):
        folder = _clients(config) / source
        assert _mode(folder) == 0o700
        assert _mode(folder / "client.key") == 0o600
        assert (folder / "ca.crt").read_bytes() == ingest_ca.read_bytes()
        _openssl("verify", "-CAfile", str(ingest_ca), "-purpose", "sslclient",
                 str(folder / "client.crt"))  # fmt: skip
        subject = _openssl("x509", "-in", str(folder / "client.crt"), "-noout", "-subject")
        assert f"CN={source}" in subject.replace(" = ", "=")
        assert listed[source] == [_fingerprint(config, source)]


def test_each_issue_writes_one_audit_row_without_key_material(tmp_path):
    config = _prepared(tmp_path)

    issued = _ensure(config, ["me", "connections"])

    rows = _rows(config)
    assert len(rows) == len(issued) == 2
    for row, entry in zip(rows, issued, strict=True):
        assert row["format"] == "papaia.audit/1"
        assert row["writer"] == "papaia-ctl/audit-cert"
        assert row["event"] == "config_changed"
        assert row["result"] == "allowed"
        assert row["effect"] == "write"
        assert row["operation"] == "audit_cert.issue_missing"
        assert row["object_ref"] == {
            "type": "audit_source_certificate",
            "id": f"{entry.source}/{entry.fingerprint}",
        }
        assert entry.fingerprint == _fingerprint(config, entry.source)
    # One correlation id for the run, never key material.
    assert len({row["correlation_id"] for row in rows}) == 1
    text = _outbox(config).read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in text and "BEGIN" not in text
    for source in ("papaia-me", "papaia-connections"):
        key = (_clients(config) / source / "client.key").read_text(encoding="ascii")
        body = "".join(line for line in key.splitlines() if not line.startswith("-----"))
        assert body[:40] not in text


def test_the_audit_rows_are_valid_papaia_audit_1_submissions(tmp_path, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    # As root: the hand-over of papaia-me and an issue for papaia-connections.
    _Owners(monkeypatch, euid=0)
    _ensure(config, ["me", "connections"])

    rows = _rows(config)
    assert [row["operation"] for row in rows] == [
        "audit_cert.issue_missing", "audit_cert.hand_over", "audit_cert.issue_missing",
    ]  # fmt: skip
    submission = {"$ref": "#/$defs/submission", "$defs": schema["$defs"]}
    for row in rows:
        jsonschema.validate(row, submission)


# ─────────────────────────────────────────────────────────────────────────
# never twice, never a usable one
# ─────────────────────────────────────────────────────────────────────────


def test_a_second_run_changes_nothing_and_writes_no_row(tmp_path, capsys):
    config = _prepared(tmp_path)
    _ensure(config, ["me", "connections"])
    before = _snapshot(config)

    assert _ensure(config, ["me", "connections"]) == []

    assert _snapshot(config) == before
    assert len(_rows(config)) == 2


def test_a_certificate_issued_by_audit_cert_stays(tmp_path):
    config = _prepared(tmp_path)
    audit.issue_source_certificate(config, "papaia-me")
    before = _snapshot(config)

    assert _ensure(config, ["me"]) == []

    assert _snapshot(config) == before
    assert not _outbox(config).exists()


def test_a_run_with_nothing_to_do_prints_nothing_and_opens_no_outbox(tmp_path, capsys):
    config = _prepared(tmp_path)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,audit,egress\n", encoding="utf-8")

    code = cli.main(["--repo-root", str(REPO), "--config-dir", str(config),
                     "audit-source-certs"])  # fmt: skip

    assert code == 0
    assert capsys.readouterr() == ("", "")
    assert not _outbox(config).exists()
    assert not _clients(config).exists()


def test_the_command_issues_for_the_profiles_of_the_installation(tmp_path, capsys):
    config = _prepared(tmp_path)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,audit,egress,me\n", encoding="utf-8")
    args = ["--repo-root", str(REPO), "--config-dir", str(config), "audit-source-certs"]

    assert cli.main(args) == 0

    out = capsys.readouterr().out
    assert "papaia-me" in out and "missing" in out and "papaia-connections" not in out
    assert "PRIVATE KEY" not in out
    assert (_clients(config) / "papaia-me" / "client.crt").is_file()
    assert not (_clients(config) / "papaia-connections").exists()

    # --profiles narrows the run to the profiles `start` was given.
    assert cli.main([*args, "--profiles=keycloak,connections"]) == 0
    assert (_clients(config) / "papaia-connections" / "client.crt").is_file()
    assert cli.main(args) == 0
    assert capsys.readouterr().out.count("issued") == 1


def test_a_profile_of_the_env_file_the_core_does_not_declare_is_named_and_left_alone(
    tmp_path, capsys
):
    # A misspelt or since removed profile in COMPOSE_PROFILES, which Compose ignores, does
    # not stop `start`: the step names it, the file it comes from and the way out, and still
    # issues the certificates of the profiles the core declares.
    config = _prepared(tmp_path)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,audit,me,retired\n", encoding="utf-8")

    code = cli.main(["--repo-root", str(REPO), "--config-dir", str(config),
                     "audit-source-certs"])  # fmt: skip

    assert code == 0
    out, err = capsys.readouterr()
    assert "papaia-me" in out and "missing" in out
    assert "'retired'" in err and str(config / ".env") in err
    assert "not a profile of the core" in err and "remove it or run setup again" in err
    assert (_clients(config) / "papaia-me" / "client.crt").is_file()


def test_a_profile_given_on_the_command_line_the_core_does_not_declare_is_refused(
    tmp_path, capsys
):
    config = _prepared(tmp_path)
    before = _snapshot(config)

    code = cli.main(["--repo-root", str(REPO), "--config-dir", str(config),
                     "audit-source-certs", "--profiles=keycloak,me,retired"])  # fmt: skip

    assert code == 2
    err = capsys.readouterr().err
    assert "'retired'" in err and "--profiles" in err
    assert _snapshot(config) == before


# ─────────────────────────────────────────────────────────────────────────
# unusable certificates are repaired exactly once
# ─────────────────────────────────────────────────────────────────────────


def _expired_certificate(config: Path, source: str) -> None:
    """A client certificate of the ingest CA whose validity ended in 2021."""
    base = config / "infra" / "audit"
    folder = _clients(config) / source
    work = folder.parent / "work"
    work.mkdir()
    (work / "index.txt").write_text("", encoding="ascii")
    (work / "serial").write_text("1000\n", encoding="ascii")
    (work / "ca.cnf").write_text(
        "[ca]\ndefault_ca=d\n[d]\n"
        f"database={work / 'index.txt'}\nnew_certs_dir={work}\nserial={work / 'serial'}\n"
        "default_md=sha256\npolicy=p\nunique_subject=no\n"
        "[p]\ncommonName=supplied\n"
        "[x]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="ascii",
    )
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(folder / "client.key"), "-out", str(work / "csr"),
             "-subj", f"/CN={source}")  # fmt: skip
    _openssl("ca", "-batch", "-config", str(work / "ca.cnf"), "-extensions", "x",
             "-cert", str(base / "pki" / "ca.crt"), "-keyfile", str(base / "pki" / "ca.key"),
             "-startdate", "20200101000000Z", "-enddate", "20210101000000Z",
             "-in", str(work / "csr"), "-out", str(folder / "client.crt"), "-notext")  # fmt: skip
    shutil.rmtree(work)
    sources = audit.load_sources(config)
    sources[source] = [audit.fingerprint(folder / "client.crt")]
    (base / "service" / "sources.json").write_text(
        json.dumps({"format": audit.SOURCES_FORMAT, "sources": sources}), encoding="utf-8"
    )


def _foreign_ca_certificate(config: Path, tmp_path: Path, source: str) -> None:
    """A complete client folder whose certificate and ca.crt come from another CA."""
    other = tmp_path / "other"
    other.mkdir()
    audit.issue_source_certificate(other, source)
    shutil.copytree(_clients(other) / source, _clients(config) / source, dirs_exist_ok=True)
    sources = audit.load_sources(config)
    sources[source] = [_fingerprint(config, source)]
    (config / "infra" / "audit" / "service" / "sources.json").write_text(
        json.dumps({"format": audit.SOURCES_FORMAT, "sources": sources}), encoding="utf-8"
    )


def _break(case: str, config: Path, tmp_path: Path) -> None:
    folder = _clients(config) / "papaia-me"
    if case == "missing":
        (folder / "client.key").unlink()
    elif case == "foreign_ca":
        _foreign_ca_certificate(config, tmp_path, "papaia-me")
    elif case == "not_signed":
        # ca.crt is the current CA, the certificate is of another one.
        _foreign_ca_certificate(config, tmp_path, "papaia-me")
        shutil.copyfile(config / "infra" / "audit" / "pki" / "ca.crt", folder / "ca.crt")
    elif case == "expired":
        _expired_certificate(config, "papaia-me")
    elif case == "key_mismatch":
        other = tmp_path / "other-key"
        other.mkdir()
        audit.issue_source_certificate(other, "papaia-me")
        shutil.copyfile(_clients(other) / "papaia-me" / "client.key", folder / "client.key")
    elif case == "wrong_identity":
        # A certificate of the right CA, listed for papaia-me, but made for papaia-flow.
        audit.issue_source_certificate(config, "papaia-flow")
        for name in ("client.crt", "client.key"):
            shutil.copyfile(_clients(config) / "papaia-flow" / name, folder / name)
        sources = audit.load_sources(config)
        sources["papaia-me"] = [_fingerprint(config, "papaia-me")]
        (config / "infra" / "audit" / "service" / "sources.json").write_text(
            json.dumps({"format": audit.SOURCES_FORMAT, "sources": sources}), encoding="utf-8"
        )
    elif case == "wrong_purpose":
        # The right CA and the source's name, listed for it, but made for `serverAuth`.
        base = config / "infra" / "audit"
        work = tmp_path / "server-purpose"
        work.mkdir()
        _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", str(work / "key"), "-out", str(work / "csr"),
                 "-subj", "/CN=papaia-me")  # fmt: skip
        (work / "ext").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="ascii",
        )
        _openssl("x509", "-req", "-in", str(work / "csr"), "-CA", str(base / "pki" / "ca.crt"),
                 "-CAkey", str(base / "pki" / "ca.key"), "-set_serial", "4242", "-days", "30",
                 "-extfile", str(work / "ext"), "-out", str(folder / "client.crt"))  # fmt: skip
        shutil.copyfile(work / "key", folder / "client.key")
        subject = _openssl("x509", "-in", str(folder / "client.crt"), "-noout", "-subject")
        assert "CN=papaia-me" in subject.replace(" = ", "=")
        sources = audit.load_sources(config)
        sources["papaia-me"] = [_fingerprint(config, "papaia-me")]
        (base / "service" / "sources.json").write_text(
            json.dumps({"format": audit.SOURCES_FORMAT, "sources": sources}), encoding="utf-8"
        )
    elif case == "linked":
        # A valid certificate, but through a link: never read, a new one replaces the link.
        kept = tmp_path / "kept.crt"
        shutil.copyfile(folder / "client.crt", kept)
        (folder / "client.crt").unlink()
        (folder / "client.crt").symlink_to(kept)
    elif case == "not_listed":
        sources = audit.load_sources(config)
        del sources["papaia-me"]
        (config / "infra" / "audit" / "service" / "sources.json").write_text(
            json.dumps({"format": audit.SOURCES_FORMAT, "sources": sources}), encoding="utf-8"
        )
    else:  # pragma: no cover - the parameter list below names every case
        raise AssertionError(case)


@pytest.mark.parametrize(
    ("case", "reason"),
    [("missing", "missing"), ("foreign_ca", "foreign_ca"), ("not_signed", "not_signed"),
     ("expired", "expired"), ("key_mismatch", "key_mismatch"),
     ("wrong_identity", "wrong_identity"), ("wrong_purpose", "wrong_identity"),
     ("linked", "not_regular"), ("not_listed", "not_listed")],
)  # fmt: skip
def test_an_unusable_certificate_is_repaired_exactly_once(case, reason, tmp_path):
    config = _prepared(tmp_path)
    _ensure(config, ["me", "connections"])
    connections_before = (_clients(config) / "papaia-connections" / "client.crt").read_bytes()
    _break(case, config, tmp_path)
    rows_before = len(_rows(config))

    issued = _ensure(config, ["me", "connections"])

    assert [(entry.source, entry.reason) for entry in issued] == [("papaia-me", reason)]
    folder = _clients(config) / "papaia-me"
    ingest_ca = config / "infra" / "audit" / "pki" / "ca.crt"
    _openssl("verify", "-CAfile", str(ingest_ca), "-purpose", "sslclient",
             str(folder / "client.crt"))  # fmt: skip
    assert (folder / "ca.crt").read_bytes() == ingest_ca.read_bytes()
    assert _mode(folder / "client.key") == 0o600
    listed = audit.load_sources(config)
    assert listed["papaia-me"] == [_fingerprint(config, "papaia-me")]
    # The other source keeps its certificate.
    assert (_clients(config) / "papaia-connections" / "client.crt").read_bytes() == (
        connections_before
    )
    assert listed["papaia-connections"] == [_fingerprint(config, "papaia-connections")]
    rows = _rows(config)
    assert len(rows) == rows_before + 1
    assert rows[-1]["operation"] == f"audit_cert.issue_{reason}"

    before = _snapshot(config)
    assert _ensure(config, ["me", "connections"]) == []
    assert _snapshot(config) == before


def test_a_profile_that_is_off_gets_nothing(tmp_path):
    config = _prepared(tmp_path)
    (_clients(config) / "papaia-connections").mkdir(parents=True)

    issued = _ensure(config, ["keycloak", "audit", "me"])

    assert [entry.source for entry in issued] == ["papaia-me"]
    assert list((_clients(config) / "papaia-connections").iterdir()) == []
    assert "papaia-connections" not in audit.load_sources(config)


def test_no_add_on_or_other_source_is_ever_issued(tmp_path):
    config = _prepared(tmp_path)

    _ensure(config, sorted(KNOWN))

    assert sorted(p.name for p in _clients(config).iterdir()) == [
        "papaia-connections",
        "papaia-me",
    ]
    assert sorted(audit.load_sources(config)) == ["papaia-connections", "papaia-me"]


@pytest.mark.parametrize("profiles", [["me", "nonesuch"], ["me", "../me"], ["ME"], [""]])
def test_an_unknown_profile_is_refused_before_anything_is_written(tmp_path, profiles):
    config = _prepared(tmp_path)
    before = _snapshot(config)

    with pytest.raises(audit.AuditError, match="profile"):
        _ensure(config, profiles)

    assert _snapshot(config) == before


def test_a_table_entry_for_an_unknown_source_is_refused(tmp_path, monkeypatch):
    config = _prepared(tmp_path)
    monkeypatch.setitem(audit.PROFILE_SOURCES, "rag", ("papaia-rag",))
    before = _snapshot(config)

    with pytest.raises(audit.AuditError, match="papaia-rag"):
        _ensure(config, ["me", "rag"])

    assert _snapshot(config) == before


def test_without_the_ingest_ca_nothing_is_issued(tmp_path):
    config = tmp_path / "config"
    config.mkdir()

    with pytest.raises(audit.AuditError, match="ingest CA"):
        _ensure(config, ["me"])

    assert not (config / "infra").exists()


def test_a_failed_issue_names_the_source_and_leaves_an_error_row(tmp_path, monkeypatch):
    config = _prepared(tmp_path)

    def refuse(*_args, **_kwargs):
        raise audit.AuditError("openssl req failed: no entropy")

    monkeypatch.setattr(audit, "issue_source_certificate", refuse)
    with pytest.raises(audit.AuditError, match="papaia-me"):
        _ensure(config, ["me"])

    rows = _rows(config)
    assert len(rows) == 1
    assert rows[0]["result"] == "error" and rows[0]["error_code"] == "openssl"


def test_the_command_reports_a_failure_with_the_source_and_the_cause(tmp_path, capsys,
                                                                     monkeypatch):  # fmt: skip
    config = _prepared(tmp_path)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,audit,me\n", encoding="utf-8")

    def refuse(*_args, **_kwargs):
        raise audit.AuditError("openssl req failed: no entropy")

    monkeypatch.setattr(audit, "issue_source_certificate", refuse)
    code = cli.main(["--repo-root", str(REPO), "--config-dir", str(config),
                     "audit-source-certs"])  # fmt: skip

    assert code == 2
    err = capsys.readouterr().err
    assert "papaia-me" in err and "no entropy" in err


# ─────────────────────────────────────────────────────────────────────────
# the folder belongs to the user the services run as
# ─────────────────────────────────────────────────────────────────────────


class _Owners:
    """os.chown and the owner lookup of audit, recorded instead of done: a test does not
    run as root. A path nobody handed over keeps its real owner. Every chown must leave a
    symbolic link alone (`follow_symlinks=False`)."""

    def __init__(self, monkeypatch, *, euid: int, system: str = "Linux") -> None:
        self.owners: dict[Path, int] = {}
        self.calls: list[tuple[Path, int, int]] = []
        monkeypatch.setattr(audit.os, "geteuid", lambda: euid)
        monkeypatch.setattr(audit.platform, "system", lambda: system)
        monkeypatch.setattr(audit.os, "chown", self.chown)
        monkeypatch.setattr(audit, "_uid_of", self.uid_of)

    def chown(self, path, uid, gid, *, follow_symlinks=True) -> None:
        assert follow_symlinks is False, path
        self.calls.append((Path(path), uid, gid))
        self.owners[Path(path)] = uid

    def uid_of(self, path: Path) -> int:
        return self.owners.get(Path(path), Path(path).stat().st_uid)

    def own(self, path: Path, uid: int) -> None:
        self.owners[Path(path)] = uid


_FILES = ("client.key", "client.crt", "ca.crt")


def _assert_handed(owners: _Owners, folder: Path, uid: int) -> None:
    """The files belong to the services' user; the folder stays root's, 0711, so that user
    can open the three files by name but never add, replace or remove an entry."""
    assert owners.uid_of(folder) == 0, folder
    assert _mode(folder) == 0o711, folder
    for name in _FILES:
        assert owners.uid_of(folder / name) == uid, (folder, name)
        assert not (folder / name).is_symlink()


def test_every_mapped_source_names_the_user_its_services_run_as():
    for sources in audit.PROFILE_SOURCES.values():
        for source in sources:
            assert isinstance(audit.SOURCE_READERS.get(source), int), source
    # Where a core compose file names the user, it is the one in the table.
    for mount in audit.client_mounts(audit.core_compose_files(REPO)):
        body = yaml.safe_load(Path(mount.file).read_text(encoding="utf-8"))["services"][
            mount.service
        ]
        if "user" in body:
            assert int(str(body["user"]).split(":")[0]) == audit.SOURCE_READERS[mount.source]


def test_as_root_the_issued_folder_is_handed_to_the_user_of_the_services(tmp_path, monkeypatch):
    config = _prepared(tmp_path)
    owners = _Owners(monkeypatch, euid=0)

    result = _run(config, ["me", "connections"])

    assert [entry.reason for entry in result.issued] == ["missing", "missing"]
    assert result.warnings == []
    for source in ("papaia-me", "papaia-connections"):
        folder = _clients(config) / source
        _assert_handed(owners, folder, audit.SOURCE_READERS[source])
        # Handed over, never opened up.
        assert _mode(folder / "client.key") == 0o600
    # Only the client folders, never the CA or sources.json.
    assert all("/clients/" in path.as_posix() for path, _, _ in owners.calls)
    assert all(gid == -1 for _, _, gid in owners.calls)


def test_as_root_a_usable_certificate_of_the_wrong_owner_is_handed_over_once(
    tmp_path, monkeypatch
):
    # Issued before this rule, by `audit cert`, or by a start that was not root: the
    # certificate is usable, only the services cannot read it. It is handed over, not
    # replaced, and the fingerprint the audit store pins stays.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    first = _fingerprint(config, "papaia-me")
    crt = (_clients(config) / "papaia-me" / "client.crt").read_bytes()
    rows_before = len(_rows(config))
    owners = _Owners(monkeypatch, euid=0)

    result = _run(config, ["me"])

    assert [(e.source, e.reason, e.fingerprint) for e in result.issued] == [
        ("papaia-me", "wrong_owner", first)
    ]
    assert (_clients(config) / "papaia-me" / "client.crt").read_bytes() == crt
    assert audit.load_sources(config)["papaia-me"] == [first]
    rows = _rows(config)
    assert len(rows) == rows_before + 1
    assert rows[-1]["operation"] == "audit_cert.hand_over"
    assert rows[-1]["object_ref"] == {
        "type": "audit_source_certificate",
        "id": f"papaia-me/{first}",
    }
    assert rows[-1]["result"] == "allowed"

    calls = len(owners.calls)
    assert _run(config, ["me"]).issued == []
    assert len(owners.calls) == calls
    assert len(_rows(config)) == rows_before + 1


def test_audit_cert_as_root_hands_the_rotated_files_over_too(tmp_path, monkeypatch):
    config = _prepared(tmp_path)
    owners = _Owners(monkeypatch, euid=0)

    audit.issue_source_certificate(config, "papaia-connections")

    folder = _clients(config) / "papaia-connections"
    _assert_handed(owners, folder, 10001)
    # A source no core service reads from a client folder is handed to nobody: run as root,
    # its folder is root's (0700) and its files stay root's.
    audit.issue_source_certificate(config, "papaia-flow")
    flow = [(path, uid) for path, uid, _ in owners.calls if "papaia-flow" in path.as_posix()]
    assert flow == [(_clients(config) / "papaia-flow", 0)]
    assert _mode(_clients(config) / "papaia-flow") == 0o700


def test_not_as_root_on_linux_the_step_warns_that_the_services_cannot_read_it(
    tmp_path, monkeypatch
):
    config = _prepared(tmp_path)
    me = os.getuid()
    owners = _Owners(monkeypatch, euid=me)

    result = _run(config, ["me"])

    assert [entry.reason for entry in result.issued] == ["missing"]
    assert owners.calls == []
    assert len(result.warnings) == 1
    warning = result.warnings[0]
    assert "papaia-me" in warning and f"uid {me}" in warning and "uid 10001" in warning
    assert "as root" in warning
    # It stays true on the next start, so the next start says it again.
    again = _run(config, ["me"])
    assert again.issued == [] and again.warnings == result.warnings


def test_not_as_root_on_macos_nothing_is_said(tmp_path, monkeypatch):
    # Docker Desktop's file sharing does not enforce the owner of a bind mount.
    config = _prepared(tmp_path)
    _Owners(monkeypatch, euid=os.getuid(), system="Darwin")

    result = _run(config, ["me"])

    assert [entry.reason for entry in result.issued] == ["missing"]
    assert result.warnings == []


def test_not_as_root_a_folder_handed_to_the_services_is_left_alone(tmp_path, monkeypatch):
    # An earlier start as root handed it over (folder root's, files uid 10001); a start
    # that is not root cannot look into it and does not need to.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    owners = _Owners(monkeypatch, euid=os.getuid())
    owners.own(_clients(config) / "papaia-me", 0)
    for name in _FILES:
        owners.own(_clients(config) / "papaia-me" / name, 10001)
    before = _snapshot(config)

    result = _run(config, ["me"])

    assert result.issued == [] and result.warnings == []
    assert _snapshot(config) == before


def _outside(tmp_path: Path, name: str) -> Path:
    """A file outside the client folder that a link planted in it points at (as /etc/shadow
    would): mode 0600, content of its own."""
    target = tmp_path / "outside" / name
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(b"not a certificate: " + name.encode() + b"\n")
    os.chmod(target, 0o600)
    return target


def _held_by_services(config: Path, owners: _Owners) -> Path:
    """The state a hand-over of the folder itself to uid 10001 left: that uid may then
    add and replace entries."""
    folder = _clients(config) / "papaia-me"
    owners.own(folder, 10001)
    for name in _FILES:
        owners.own(folder / name, 10001)
    return folder


@pytest.mark.parametrize("name", _FILES)
def test_as_root_a_link_planted_in_the_folder_is_never_followed(name, tmp_path, monkeypatch):
    # A process with the services' uid replaced one file with a link to a file root owns.
    # Root must not write through it, change its mode, or hand it to that uid.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    owners = _Owners(monkeypatch, euid=0)
    folder = _held_by_services(config, owners)
    target = _outside(tmp_path, name)
    content = target.read_bytes()
    (folder / name).unlink()
    (folder / name).symlink_to(target)

    result = _run(config, ["me"])

    assert [(e.source, e.reason) for e in result.issued] == [("papaia-me", "not_regular")]
    assert target.read_bytes() == content
    assert _mode(target) == 0o600
    assert target not in {path for path, _, _ in owners.calls}
    assert all(path.parent == folder or path == folder for path, _, _ in owners.calls)
    _assert_handed(owners, folder, 10001)
    ingest_ca = config / "infra" / "audit" / "pki" / "ca.crt"
    assert (folder / "ca.crt").read_bytes() == ingest_ca.read_bytes()
    _openssl("verify", "-CAfile", str(ingest_ca), "-purpose", "sslclient",
             str(folder / "client.crt"))  # fmt: skip


def test_as_root_a_link_to_the_ingest_ca_is_not_a_usable_ca_crt(tmp_path, monkeypatch):
    # The link carries the right certificate, so a check through it would call the folder
    # usable and only hand it over: the chown would reach the CA of the audit store.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    pki_ca = config / "infra" / "audit" / "pki" / "ca.crt"
    mode, content = _mode(pki_ca), pki_ca.read_bytes()
    owners = _Owners(monkeypatch, euid=0)
    folder = _held_by_services(config, owners)
    (folder / "ca.crt").unlink()
    (folder / "ca.crt").symlink_to(pki_ca)

    result = _run(config, ["me"])

    assert [e.reason for e in result.issued] == ["not_regular"]
    assert pki_ca.read_bytes() == content and _mode(pki_ca) == mode
    assert all("/pki/" not in path.as_posix() for path, _, _ in owners.calls)
    _assert_handed(owners, folder, 10001)


def test_as_root_a_hard_link_is_not_handed_over(tmp_path, monkeypatch):
    # Where the kernel allows a hard link to a file of another owner, the name in the
    # folder is the outside file itself: never chowned, the name is replaced.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    owners = _Owners(monkeypatch, euid=0)
    folder = _held_by_services(config, owners)
    target = _outside(tmp_path, "client.key")
    content = target.read_bytes()
    (folder / "client.key").unlink()
    os.link(target, folder / "client.key")

    result = _run(config, ["me"])

    assert [e.reason for e in result.issued] == ["not_regular"]
    assert target.read_bytes() == content and _mode(target) == 0o600
    assert target.stat().st_nlink == 1
    assert target not in {path for path, _, _ in owners.calls}
    _assert_handed(owners, folder, 10001)


def test_as_root_the_folder_is_taken_back_before_anything_is_read(tmp_path, monkeypatch):
    # The folder of uid 10001 goes to root (without following a link) first, so nothing
    # in it changes between the check and the write.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    owners = _Owners(monkeypatch, euid=0)
    folder = _held_by_services(config, owners)
    seen = []
    problem = audit._certificate_problem

    def spy(base, source, listed):
        seen.append(owners.uid_of(folder))
        return problem(base, source, listed)

    monkeypatch.setattr(audit, "_certificate_problem", spy)

    result = _run(config, ["me"])

    assert seen == [0]
    assert [e.reason for e in result.issued] == ["wrong_owner"]
    _assert_handed(owners, folder, 10001)


@pytest.mark.parametrize("root", [True, False])
def test_a_client_folder_that_is_a_link_is_refused(root, tmp_path, monkeypatch):
    config = _prepared(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o755)
    _clients(config).mkdir(parents=True, exist_ok=True)
    (_clients(config) / "papaia-me").symlink_to(elsewhere)
    owners = _Owners(monkeypatch, euid=0 if root else os.getuid())

    with pytest.raises(audit.AuditError) as caught:
        _run(config, ["me"])

    assert "papaia-me" in str(caught.value) and "not a folder" in str(caught.value)
    assert list(elsewhere.iterdir()) == []
    assert _mode(elsewhere) == 0o755
    assert owners.calls == []
    with pytest.raises(audit.AuditError):
        audit.issue_source_certificate(config, "papaia-me")
    assert list(elsewhere.iterdir()) == []


def test_not_as_root_a_folder_of_another_account_is_refused_with_the_way_out(
    tmp_path, monkeypatch
):
    # Docker creates a missing bind-mount folder as root while the services loop.
    config = _prepared(tmp_path)
    folder = _clients(config) / "papaia-me"
    folder.mkdir(parents=True)
    owners = _Owners(monkeypatch, euid=os.getuid())
    owners.own(folder, 0)
    before = _snapshot(config)

    with pytest.raises(audit.AuditError) as caught:
        _run(config, ["me"])

    message = str(caught.value)
    assert str(folder) in message and "uid 0" in message
    assert "remove it" in message.lower() and "as root" in message
    assert _snapshot(config) == before
    assert not _outbox(config).exists()


def test_the_command_prints_the_hand_over_and_the_warning(tmp_path, capsys, monkeypatch):
    config = _prepared(tmp_path)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,audit,me\n", encoding="utf-8")
    args = ["--repo-root", str(REPO), "--config-dir", str(config), "audit-source-certs"]
    _Owners(monkeypatch, euid=os.getuid())

    assert cli.main(args) == 0
    out, err = capsys.readouterr()
    assert "issued the audit certificate of papaia-me (missing)" in out
    assert "WARNING" in err and "uid 10001" in err

    _Owners(monkeypatch, euid=0)
    assert cli.main(args) == 0
    out, _ = capsys.readouterr()
    assert "handed the audit certificate of papaia-me to uid 10001" in out


# ─────────────────────────────────────────────────────────────────────────
# the guard over the core's compose files
# ─────────────────────────────────────────────────────────────────────────


def test_every_client_folder_the_core_mounts_is_issued_for_its_profile():
    files = audit.core_compose_files(REPO)
    mounts = audit.client_mounts(files)

    assert audit.unmapped_client_mounts(files) == []
    # The guard reads what it is meant to read: Me's two services and the registry.
    assert {(m.service, m.source) for m in mounts} >= {
        ("me-web", "papaia-me"),
        ("prefs", "papaia-me"),
        ("connections", "papaia-connections"),
    }
    # Every table entry belongs to a profile the core declares and to a known source.
    declared = audit.declared_profiles(files)
    for profile, sources in audit.PROFILE_SOURCES.items():
        assert profile in declared
        assert set(sources) <= set(audit.SOURCES)


def test_the_guard_finds_a_client_folder_of_an_unmapped_profile(tmp_path):
    compose = tmp_path / "src" / "infra" / "future" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(
        yaml.safe_dump({
            "services": {
                "future": {
                    "image": "example.invalid/future@sha256:" + "0" * 64,
                    "profiles": ["future"],
                    "volumes": [
                        "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-flow:/run/papaia/audit:ro"
                    ],
                },
                "long-form": {
                    "image": "example.invalid/long@sha256:" + "0" * 64,
                    "profiles": ["me"],
                    "volumes": [{
                        "type": "bind",
                        "source": "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-studio",
                        "target": "/run/papaia/audit",
                        "read_only": True,
                    }],
                },
                "always-on": {
                    "image": "example.invalid/always@sha256:" + "0" * 64,
                    "volumes": [
                        "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-me:/run/papaia/audit:ro"
                    ],
                },
            }
        }),
        encoding="utf-8",
    )
    files = audit.core_compose_files(tmp_path)

    findings = audit.unmapped_client_mounts(files)

    assert len(findings) == 3
    assert any("future" in f and "papaia-flow" in f for f in findings)
    assert any("long-form" in f and "papaia-studio" in f for f in findings)
    assert any("always-on" in f and "papaia-me" in f for f in findings)


def test_the_issued_folders_are_where_their_services_run():
    # A distributed installation runs these profiles on the controller only, which keeps
    # the configuration directory: the folder start fills is the folder the service
    # mounts, and no node bundle has to carry it.
    for profile in audit.PROFILE_SOURCES:
        assert profile in topology.CONTROLLER_ONLY


def test_a_service_of_a_mapped_profile_restarts_into_its_new_certificate():
    # A service that stopped for want of its certificate is restarted by Docker and reads
    # the bind-mounted folder anew; `start` need not recreate it.
    for mount in audit.client_mounts(audit.core_compose_files(REPO)):
        body = yaml.safe_load(Path(mount.file).read_text(encoding="utf-8"))["services"][
            mount.service
        ]
        assert body.get("restart") in ("unless-stopped", "always"), mount.service
        target = [v for v in body["volumes"] if isinstance(v, str) and mount.source in v]
        # The folder, not single files: a replaced file reaches the running container.
        assert target and target[0].split(":")[0].endswith(f"/clients/{mount.source}")


# ─────────────────────────────────────────────────────────────────────────
# the step in `start`
# ─────────────────────────────────────────────────────────────────────────

_HARNESS = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo @MODE@; }
_require_no_node() { :; }
_require_profiles_resolve() { :; }
_cluster_require_unlocked() { :; }
_stopped_containers_go_stale() { return 1; }
_pull_quietly() { return 1; }
_verify_images() { :; }
_localai_native_start() { :; }
_addon_path() { echo "/addons/$1"; }
_addon_compose_up() { echo "compose-up $1"; }
_addon_image_list() { :; }
docker() {
    case " $* " in *" up "*) echo "docker-up COMPOSE_PROFILES=${COMPOSE_PROFILES:-}" ;; esac
}
py_cli() {
    echo "py_cli $*"
    if [ "$1" = "audit-source-certs" ] && [ -n "${FAIL_SOURCE_CERTS:-}" ]; then
        echo "ERROR: audit source papaia-me: openssl req failed" >&2
        return 1
    fi
    if [ "$1" = "cluster-start" ]; then echo "cluster-up"; fi
    return 0
}
cmd_start @ARGS@
"""


def _run_start(tmp_path: Path, args: str, *, mode: str = "single", fail: bool = False,
               compose_profiles: str | None = None):  # fmt: skip
    harness = (
        _HARNESS.replace("@CONFIG@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@MODE@", mode)
        .replace("@ARGS@", args)
    )
    env = {**os.environ}
    env.pop("FAIL_SOURCE_CERTS", None)
    env.pop("COMPOSE_PROFILES", None)
    if compose_profiles is not None:
        env["COMPOSE_PROFILES"] = compose_profiles
    if fail:
        env["FAIL_SOURCE_CERTS"] = "1"
    assert BASH is not None
    return subprocess.run(
        [BASH, "-c", harness], capture_output=True, text=True, timeout=30, check=False, env=env
    )


def _index(calls: list[str], prefix: str) -> int:
    return next(i for i, call in enumerate(calls) if call.startswith(prefix))


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize(
    ("args", "expected"),
    [("--no-addons", "py_cli audit-source-certs"),
     ("--profiles=keycloak,audit,me", "py_cli audit-source-certs --profiles=keycloak,audit,me")],
)  # fmt: skip
def test_start_issues_after_audit_prepare_and_before_up(tmp_path, args, expected):
    result = _run_start(tmp_path, args)

    assert result.returncode == 0, result.stderr
    calls = result.stdout.splitlines()
    assert expected in calls
    assert _index(calls, "py_cli audit-prepare") < calls.index(expected)
    assert calls.index(expected) < _index(calls, "docker-up")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_start_issues_for_the_profiles_compose_takes_from_the_shell(tmp_path):
    # Without --profiles, Compose takes an exported COMPOSE_PROFILES over the env file;
    # the step issues for the same profiles.
    result = _run_start(tmp_path, "--no-addons", compose_profiles="keycloak,audit,me")

    assert result.returncode == 0, result.stderr
    calls = result.stdout.splitlines()
    assert "py_cli audit-source-certs --profiles=keycloak,audit,me" in calls
    assert "docker-up COMPOSE_PROFILES=keycloak,audit,me" in calls


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_a_failed_issue_stops_start_with_exit_2_before_up(tmp_path):
    result = _run_start(tmp_path, "--profiles=keycloak,audit,me", fail=True)

    assert result.returncode == 2
    calls = result.stdout.splitlines()
    assert "py_cli audit-source-certs --profiles=keycloak,audit,me" in calls
    assert not any(call.startswith(("docker-up", "compose-up")) for call in calls)
    assert "papaia-me" in result.stderr and "nothing was started" in result.stderr


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize(
    ("args", "expected"),
    [("", "py_cli audit-source-certs"),
     ("--profiles=me", "py_cli audit-source-certs --profiles=me")],
)  # fmt: skip
def test_the_distributed_start_issues_after_audit_prepare_and_before_the_nodes(
    tmp_path, args, expected
):
    result = _run_start(tmp_path, args, mode="distributed")

    assert result.returncode == 0, result.stderr
    calls = result.stdout.splitlines()
    assert _index(calls, "py_cli audit-prepare") < calls.index(expected)
    assert calls.index(expected) < _index(calls, "py_cli cluster-start")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_a_failed_issue_stops_the_distributed_start_before_the_nodes(tmp_path):
    result = _run_start(tmp_path, "", mode="distributed", fail=True)

    assert result.returncode == 2
    assert "py_cli cluster-start" not in "\n".join(result.stdout.splitlines())
    assert "nothing was started" in result.stderr


def test_audit_cert_keeps_rotating_a_usable_certificate(tmp_path):
    # Rotation stays the operator's command: it replaces even a usable certificate.
    config = _prepared(tmp_path)
    _ensure(config, ["me"])
    first = _fingerprint(config, "papaia-me")

    audit.issue_source_certificate(config, "papaia-me")

    assert _fingerprint(config, "papaia-me") != first
    assert audit.load_sources(config)["papaia-me"] == [_fingerprint(config, "papaia-me")]
    assert ssl.PEM_cert_to_DER_cert(
        (_clients(config) / "papaia-me" / "client.crt").read_text(encoding="ascii")
    )
