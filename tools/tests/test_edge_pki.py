"""The edge CA of an installation (`papaia.edge-pki/1`, ADR 0035).

With `tls: internal` the bundled proxy serves every host name papaia-ctl creates with a
leaf of a CA of its own: name-constrained to the installation's base and app domain,
separate from the platform CA (ADR 0019) and the Keycloak CA. Certificates are issued for
real with the host's openssl into a temporary configuration directory; time is passed in.
"""

from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from lib import cli, edge_pki, npm_provision, pki, realm_sync

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not available")

ROOT = Path(__file__).resolve().parents[2]
DOMAINS = ("itest.papaia.localhost", "itest.papaia-apps.localhost")
AUTH = ("auth.itest.papaia.localhost",)
CHAT = ("chat.itest.papaia.localhost",)
APPS = ("itest.papaia-apps.localhost", "*.itest.papaia-apps.localhost")
HOSTS = [AUTH, CHAT, APPS]


def openssl(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["openssl", *args], input=stdin, capture_output=True, text=True, check=True
    ).stdout


def _issue(config: Path, hosts=HOSTS, domains=DOMAINS, **kwargs) -> edge_pki.Result:
    return edge_pki.issue(config, [edge_pki.Host(h) for h in hosts], domains, **kwargs)


def _text(cert: Path) -> str:
    return openssl("x509", "-in", str(cert), "-noout", "-text")


AUDIT_SCHEMA = json.loads(
    (ROOT / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json").read_text(
        encoding="utf-8"
    )
)


def _submission_errors(row: dict) -> list[str]:
    """The ways a row of the outbox breaks `papaia.audit/1` as a source submits it."""
    validator = Draft202012Validator(
        {"$defs": AUDIT_SCHEMA["$defs"], "$ref": "#/$defs/submission"},
        format_checker=FormatChecker(),
    )
    return [e.message for e in validator.iter_errors(row)]


def _rows(config: Path) -> list[dict]:
    path = realm_sync.audit_path(config)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "config"
    path.mkdir()
    return path


# ─────────────────────────────────────────────────────────────────────────
# the CA
# ─────────────────────────────────────────────────────────────────────────


def test_the_edge_ca_is_constrained_to_exactly_the_installations_two_domains(config):
    result = _issue(config)

    crt, key = edge_pki.ca_paths(config)
    assert (crt, key) == (config / "certs" / "edge-ca.crt", config / "pki" / "edge" / "ca.key")
    assert result.ca == "created"
    text = _text(crt)
    assert "X509v3 Name Constraints: critical" in text
    permitted = text.split("Permitted:", 1)[1].split("Excluded:", 1)[0]
    assert sorted(line.strip() for line in permitted.splitlines() if line.strip()) == sorted(
        f"DNS:{d}" for d in DOMAINS
    )
    assert "CA:TRUE, pathlen:0" in text
    assert "X509v3 Basic Constraints: critical" in text
    usage = text.split("X509v3 Key Usage: critical", 1)[1].splitlines()[1].strip()
    assert usage == "Certificate Sign, CRL Sign"
    assert "prime256v1" in text or "P-256" in text


def test_the_edge_ca_is_neither_the_platform_ca_nor_the_keycloak_ca(config):
    _issue(config)
    subject = openssl("x509", "-in", str(edge_pki.ca_paths(config)[0]), "-noout", "-subject")
    assert "papaia-edge-ca" in subject
    assert [p.name for p in pki.pki_dir(config).iterdir()] == ["edge"], "no platform CA"
    assert not (config / "certs" / "local-ca.crt").exists(), "the Keycloak CA is not touched"


LONG_DOMAIN = "stadtwerke-musterstadt-energieversorgung.example.de"
LONG_APPS = "stadtwerke-musterstadt-energieversorgung-apps.example.de"


def _subject_cn(cert: Path) -> str | None:
    subject = openssl("x509", "-in", str(cert), "-noout", "-subject", "-nameopt", "multiline")
    found = re.search(r"^\s*commonName\s*=\s*(.*)$", subject, re.M)
    return found.group(1).strip() if found else None


def test_a_base_domain_too_long_for_a_common_name_still_gets_an_edge_ca(config):
    # X.509 allows 64 characters in a commonName; a domain name allows 253.
    assert len(f"{edge_pki.CA_NAME} {LONG_DOMAIN}") > 64
    host = (f"auth.{LONG_DOMAIN}",)
    result = edge_pki.issue(config, [edge_pki.Host(host)], (LONG_DOMAIN, LONG_APPS))

    crt = edge_pki.ca_paths(config)[0]
    assert result.ca == "created" and result.issued == [host[0]]
    common_name = _subject_cn(crt)
    assert common_name is not None and common_name.startswith(edge_pki.CA_NAME)
    assert len(common_name) <= 64
    permitted = _text(crt).split("Permitted:", 1)[1].split("Excluded:", 1)[0]
    assert sorted(line.strip() for line in permitted.splitlines() if line.strip()) == sorted(
        f"DNS:{d}" for d in (LONG_DOMAIN, LONG_APPS)
    )
    leaf = edge_pki.leaf_for(config, host)
    assert leaf is not None
    openssl("verify", "-CAfile", str(crt), str(leaf.cert))


def test_the_common_name_of_the_edge_ca_names_a_short_base_domain(config):
    _issue(config)
    assert _subject_cn(edge_pki.ca_paths(config)[0]) == f"{edge_pki.CA_NAME} {DOMAINS[0]}"


def test_a_host_name_too_long_for_a_common_name_still_gets_a_leaf(config):
    # A local add-on label under a long compose project name passes 64 characters.
    long_host = "knowledge-map.itk-r-core-108-a-rather-long-project.itest.papaia.localhost"
    assert len(long_host) > 64
    hosts = [AUTH, (long_host,)]
    result = _issue(config, hosts=hosts)

    assert sorted(result.issued) == sorted([AUTH[0], long_host])
    leaf = edge_pki.leaf_for(config, (long_host,))
    assert leaf is not None
    text = _text(leaf.cert)
    assert f"DNS:{long_host}" in text
    common_name = _subject_cn(leaf.cert)
    assert common_name is None or len(common_name) <= 64
    openssl("verify", "-CAfile", str(edge_pki.ca_paths(config)[0]), str(leaf.cert))
    short = edge_pki.leaf_for(config, AUTH)
    assert short is not None and _subject_cn(short.cert) == AUTH[0]


def test_one_ca_domain_inside_the_other_is_permitted_once(config):
    edge_pki.issue(config, [edge_pki.Host(("auth.example.org",))],
                   ("example.org", "apps.example.org"))  # fmt: skip
    text = _text(edge_pki.ca_paths(config)[0])
    permitted = text.split("Permitted:", 1)[1].split("Excluded:", 1)[0]
    assert [line.strip() for line in permitted.splitlines() if line.strip()] == ["DNS:example.org"]


def test_keys_stay_private_and_only_the_ca_certificate_is_readable(config):
    _issue(config)
    crt, key = edge_pki.ca_paths(config)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(crt.stat().st_mode) == 0o644
    for leaf in edge_pki.leaves(config):
        assert stat.S_IMODE(leaf.key.stat().st_mode) == 0o600
        assert stat.S_IMODE(leaf.key.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(edge_pki.leaves_dir(config).stat().st_mode) == 0o700
    assert stat.S_IMODE(edge_pki.private_dir(config).stat().st_mode) == 0o700


def test_only_the_public_ca_certificate_is_below_certs(config):
    """`certs/` is mounted into services; the CA key, the leaves and their state are not
    (they live in `pki/edge/`, as the platform CA's key lives in `pki/ca/`)."""
    _issue(config)
    assert sorted(p.relative_to(config).as_posix() for p in (config / "certs").rglob("*")) == [
        "certs/edge-ca.crt"
    ]
    private = edge_pki.private_dir(config)
    assert private == config / "pki" / "edge"
    assert edge_pki.ca_paths(config)[1].parent == private
    assert edge_pki.leaves_dir(config) == private / "leaves"
    assert all(private in leaf.key.parents for leaf in edge_pki.leaves(config))


def test_changed_domains_replace_the_ca_and_every_leaf(config):
    _issue(config)
    old = edge_pki.ca_paths(config)[0].read_text()

    result = _issue(config, hosts=[("auth.example.org",)], domains=("example.org",))

    assert result.ca == "replaced"
    assert edge_pki.ca_paths(config)[0].read_text() != old
    assert result.issued == ["auth.example.org"]
    assert sorted(result.removed) == sorted([AUTH[0], CHAT[0], APPS[0]])


def test_a_ca_key_that_does_not_match_its_certificate_is_replaced(config):
    _issue(config)
    _, key = edge_pki.ca_paths(config)
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(key))  # fmt: skip

    result = _issue(config)

    assert result.ca == "replaced"
    assert sorted(result.renewed) == sorted([AUTH[0], CHAT[0], APPS[0]])
    for leaf in edge_pki.leaves(config):
        verified = openssl("verify", "-CAfile", str(edge_pki.ca_paths(config)[0]), str(leaf.cert))
        assert verified.strip().endswith("OK")


# ─────────────────────────────────────────────────────────────────────────
# leaves
# ─────────────────────────────────────────────────────────────────────────


def test_a_leaf_carries_only_server_auth_and_exactly_its_host_name(config):
    _issue(config)
    leaf = edge_pki.leaf_for(config, AUTH)
    assert leaf is not None
    text = _text(leaf.cert)

    assert "CA:FALSE" in text
    eku = text.split("X509v3 Extended Key Usage:", 1)[1].splitlines()[1].strip()
    assert eku == "TLS Web Server Authentication"
    san = text.split("X509v3 Subject Alternative Name:", 1)[1].splitlines()[1].strip()
    assert san == f"DNS:{AUTH[0]}"
    start = openssl("x509", "-in", str(leaf.cert), "-noout", "-startdate").split("=", 1)[1]
    end = openssl("x509", "-in", str(leaf.cert), "-noout", "-enddate").split("=", 1)[1]
    fmt = "%b %d %H:%M:%S %Y %Z"
    days = (datetime.strptime(" ".join(end.split()), fmt)
            - datetime.strptime(" ".join(start.split()), fmt)).days  # fmt: skip
    assert days == edge_pki.LEAF_DAYS == 90
    ca = str(edge_pki.ca_paths(config)[0])
    assert openssl("verify", "-CAfile", ca, "-purpose", "sslserver", str(leaf.cert)).strip(
    ).endswith("OK")  # fmt: skip


def test_the_app_host_leaf_carries_exactly_the_names_of_its_one_proxy_host(config):
    _issue(config)
    leaf = edge_pki.leaf_for(config, APPS)
    assert leaf is not None
    san = _text(leaf.cert).split("X509v3 Subject Alternative Name:", 1)[1].splitlines()[1]
    assert sorted(part.strip() for part in san.split(",")) == sorted(f"DNS:{n}" for n in APPS)
    assert edge_pki.leaf_for(config, ("other.itest.papaia.localhost",)) is None


@pytest.mark.parametrize(
    "name",
    ["auth.example.org", "papaia.localhost", "evil-itest.papaia.localhost", "localhost",
     "itest.papaia.localhost.example.org", "127.0.0.1", "*.localhost", "a..b", ""],
)  # fmt: skip
def test_a_name_outside_the_domains_is_refused(config, name):
    with pytest.raises(edge_pki.EdgePkiError):
        edge_pki.check_name(name, DOMAINS)

    result = _issue(config, hosts=[AUTH, (name,)])

    assert result.issued == [AUTH[0]]
    assert result.refused == [name]
    assert [leaf.names for leaf in edge_pki.leaves(config)] == [AUTH]


def _force_leaf(config: Path, tmp_path: Path, san: str) -> Path:
    """A leaf signed with the edge CA's key by hand, around the code's refusal."""
    crt, key = edge_pki.ca_paths(config)
    leaf_key, csr, leaf = tmp_path / "f.key", tmp_path / "f.csr", tmp_path / "f.crt"
    ext = tmp_path / "f.ext"
    ext.write_text(f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
                   f"subjectAltName={san}\n", encoding="utf-8")  # fmt: skip
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(leaf_key), "-out", str(csr), "-subj", "/CN=forced")  # fmt: skip
    openssl("x509", "-req", "-in", str(csr), "-CA", str(crt), "-CAkey", str(key),
            "-set_serial", "7", "-days", "30", "-extfile", str(ext), "-out", str(leaf))  # fmt: skip
    return leaf


@pytest.mark.parametrize(
    "san", ["DNS:accounts.example.org", "DNS:auth.papaia.localhost", "IP:127.0.0.1", "IP:::1"]
)
def test_a_forced_leaf_outside_the_domains_does_not_verify(config, tmp_path, san):
    _issue(config)
    leaf = _force_leaf(config, tmp_path, san)

    done = subprocess.run(
        ["openssl", "verify", "-CAfile", str(edge_pki.ca_paths(config)[0]), str(leaf)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip

    assert done.returncode != 0
    assert "subtree violation" in (done.stdout + done.stderr)


def test_a_forced_leaf_inside_the_domains_verifies(config, tmp_path):
    """The counter-check: the constraints refuse by name, not every hand-made leaf."""
    _issue(config)
    leaf = _force_leaf(config, tmp_path, "DNS:x.itest.papaia-apps.localhost")
    verified = openssl("verify", "-CAfile", str(edge_pki.ca_paths(config)[0]), str(leaf))
    assert verified.strip().endswith("OK")


# ─────────────────────────────────────────────────────────────────────────
# runs: idempotence, renewal, removal, audit
# ─────────────────────────────────────────────────────────────────────────


def test_a_run_with_nothing_to_do_writes_nothing(config):
    _issue(config)
    rows = len(_rows(config))
    before = {p: p.stat().st_mtime_ns for p in config.rglob("*") if p.is_file()}

    result = _issue(config)

    assert (result.ca, result.issued, result.renewed, result.removed) == (None, [], [], [])
    assert len(_rows(config)) == rows
    after = {p: p.stat().st_mtime_ns for p in config.rglob("*") if p.is_file()}
    assert after == before


def test_a_leaf_is_renewed_with_30_days_or_less_left(config):
    now = datetime.now(timezone.utc)
    _issue(config, now=now)
    serial = openssl("x509", "-in", str(edge_pki.leaf_for(config, AUTH).cert), "-noout",
                     "-serial")  # fmt: skip

    assert _issue(config, now=now + timedelta(days=59)).renewed == []
    result = _issue(config, now=now + timedelta(days=60, minutes=1))

    assert sorted(result.renewed) == sorted([AUTH[0], CHAT[0], APPS[0]])
    assert openssl("x509", "-in", str(edge_pki.leaf_for(config, AUTH).cert), "-noout",
                   "-serial") != serial  # fmt: skip
    renewals = [r for r in _rows(config) if r["operation"] == "edge_pki.renew"]
    assert len(renewals) == 3


def test_a_changed_name_set_of_a_host_renews_its_leaf(config):
    _issue(config)
    result = _issue(config, hosts=[AUTH, CHAT, (APPS[0],)])
    assert result.renewed == [APPS[0]]
    assert edge_pki.leaf_for(config, (APPS[0],)) is not None
    assert edge_pki.leaf_for(config, APPS) is None


def test_the_leaf_of_a_name_no_longer_served_is_removed(config):
    _issue(config)

    result = _issue(config, hosts=[AUTH])

    assert sorted(result.removed) == sorted([CHAT[0], APPS[0]])
    assert [leaf.names for leaf in edge_pki.leaves(config)] == [AUTH]
    removals = [r for r in _rows(config) if r["operation"] == "edge_pki.remove"]
    assert len(removals) == 2


def test_a_directory_the_edge_pki_did_not_write_is_left_alone(config):
    _issue(config)
    own = edge_pki.leaves_dir(config) / "operator-notes"
    own.mkdir()
    (own / "readme.txt").write_text("mine", encoding="utf-8")
    _issue(config, hosts=[AUTH])
    assert (own / "readme.txt").is_file()


def test_every_write_is_one_audit_row_without_key_material(config):
    _issue(config)
    rows = _rows(config)

    assert sorted(r["operation"] for r in rows) == ["edge_pki.ca_create"] + ["edge_pki.issue"] * 3
    assert {r["format"] for r in rows} == {"papaia.audit/1"}
    assert {r["writer"] for r in rows} == {"papaia-ctl/edge-pki"}
    assert len({r["correlation_id"] for r in rows}) == 1
    text = json.dumps(rows)
    assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
    assert {r["result"] for r in rows} == {"allowed"}
    for row in rows:
        assert _submission_errors(row) == [], row


def test_removal_and_a_new_ca_rows_follow_the_audit_contract(config):
    _issue(config)
    _issue(config, hosts=[("auth.example.org",)], domains=("example.org",))
    rows = _rows(config)
    assert {"edge_pki.ca_replace", "edge_pki.remove"} <= {r["operation"] for r in rows}
    for row in rows:
        assert _submission_errors(row) == [], row


def test_runs_that_overlap_wait_for_each_other(config, monkeypatch):
    import fcntl

    _issue(config)
    monkeypatch.setattr(edge_pki, "LOCK_WAIT_SECONDS", 0.3)
    with open(edge_pki.lock_path(config), "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(edge_pki.EdgePkiError, match="another papaia-ctl run"):
            _issue(config, force=True)
    assert len(_issue(config, force=True).renewed) == 3


# ─────────────────────────────────────────────────────────────────────────
# when the edge CA is used, and for which domains
# ─────────────────────────────────────────────────────────────────────────

LOCAL_ROOT = {
    "REVERSE_PROXY_PROVIDER": "internal_nginx",
    "PAPAIA_HOST": "https://localhost",
    "COMPOSE_PROJECT_NAME": "papaia-itest",
}


def test_local_names_use_the_two_domains_setup_derived():
    assert edge_pki.domains(LOCAL_ROOT) == DOMAINS
    assert edge_pki.domains({**LOCAL_ROOT, "COMPOSE_PROJECT_NAME": "papaia"}) == (
        "papaia.localhost", "papaia-apps.localhost",
    )  # fmt: skip


def test_a_server_uses_its_base_and_app_domain():
    root = {"REVERSE_PROXY_PROVIDER": "internal_nginx", "PAPAIA_HOST": "https://example.org",
            "INGRESS_APP_DOMAIN": "example-apps.org"}  # fmt: skip
    assert edge_pki.domains(root) == ("example.org", "example-apps.org")
    single = {**root, "INGRESS_APP_DOMAIN": "", "INGRESS_APP_SINGLE_SITE": "true"}
    assert edge_pki.domains(single) == ("example.org",)
    assert edge_pki.domains({**root, "INGRESS_APP_DOMAIN": ""}) == ("example.org",)


def _record(config: Path, tls: str) -> None:
    (config / "setup-answers.yaml").write_text(
        yaml.safe_dump({"format": "papaia.setup-answers/1", "answers": {"tls": tls}}),
        encoding="utf-8",
    )


def test_the_edge_ca_is_used_for_internal_tls_behind_the_bundled_proxy_only(config):
    assert edge_pki.enabled(config, LOCAL_ROOT) is True
    _record(config, "internal")
    assert edge_pki.enabled(config, LOCAL_ROOT) is True
    # A PEM bundle of row 3 keeps today's behaviour.
    _record(config, "/root/papaia-answers/edge.pem")
    assert edge_pki.enabled(config, LOCAL_ROOT) is False
    (config / "setup-answers.yaml").unlink()
    for provider in ("external_proxy", "no_proxy", ""):
        assert edge_pki.enabled(config, {**LOCAL_ROOT, "REVERSE_PROXY_PROVIDER": provider}) is False
    # A LAN address names no domain.
    assert edge_pki.enabled(config, {**LOCAL_ROOT, "PAPAIA_HOST": "https://192.168.1.5"}) is False


def test_status_and_doctor_list_the_edge_ca_and_its_leaves(config):
    _issue(config)
    rows = edge_pki.status(config)
    labels = [row["certificate"] for row in rows]
    assert labels[0].startswith("edge ca")
    assert sorted(labels[1:]) == sorted(f"edge/{n}/tls.crt" for n in (AUTH[0], CHAT[0], APPS[0]))
    assert all(row["days_left"] >= 89 for row in rows[1:])
    files = edge_pki.doctor_files(config)
    assert sorted(p.name for p in files) == ["tls.crt"] * 3
    assert {p.parent.parent for p in files} == {edge_pki.leaves_dir(config)}


# ─────────────────────────────────────────────────────────────────────────
# the command: setup, start, addon start and certs renew run `pki-issue`
# ─────────────────────────────────────────────────────────────────────────


def _local_config(config: Path) -> Path:
    (config / ".env").write_text(
        "\n".join([
            "REVERSE_PROXY_PROVIDER=internal_nginx",
            "PAPAIA_HOST=https://localhost",
            "COMPOSE_PROJECT_NAME=papaia-itest",
            "COMPOSE_PROFILES=keycloak,nginx",
            "INGRESS_HTTPS_EXT_PORT=52143",
            "AUTH_HOST=https://auth.itest.papaia.localhost:52143",
            "NPM_ADMIN_HOST=https://npm.itest.papaia.localhost:52143",
            "PAPAIA_SECURITY_PROFILE=standard",
            "",
        ]),
        encoding="utf-8",
    )  # fmt: skip
    return config


def test_pki_issue_issues_the_edge_leaves_of_the_proxy_hosts(config, capsys):
    args = ["--config-dir", str(_local_config(config)), "--repo-root", str(ROOT)]

    assert cli.main([*args, "pki-issue"]) == 0
    out = capsys.readouterr().out
    assert "edge CA created" in out
    assert sorted(leaf.names for leaf in edge_pki.leaves(config)) == [
        ("auth.itest.papaia.localhost",), ("npm.itest.papaia.localhost",),
    ]  # fmt: skip

    assert cli.main([*args, "pki-issue"]) == 0
    assert "edge" not in capsys.readouterr().out

    assert cli.main([*args, "pki-status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(r["certificate"] == "edge/auth.itest.papaia.localhost/tls.crt"
               for r in report["certificates"])  # fmt: skip


def test_pki_issue_leaves_the_edge_alone_with_a_certificate_bundle(config):
    _record(_local_config(config), "/root/papaia-answers/edge.pem")
    args = ["--config-dir", str(config), "--repo-root", str(ROOT)]
    assert cli.main([*args, "pki-issue"]) == 0
    assert not edge_pki.ca_paths(config)[0].exists()


def test_doctor_certs_reads_the_edge_ca_and_its_leaves(config):
    from lib import doctor

    _issue(config)
    files = doctor._certificate_files(config)
    assert edge_pki.ca_paths(config)[0] in files
    assert {leaf.cert for leaf in edge_pki.leaves(config)} <= set(files)


# ─────────────────────────────────────────────────────────────────────────
# the private files stay out of every container
# ─────────────────────────────────────────────────────────────────────────

_CONFIG_VAR = re.compile(r"\$\{PAPAIA_(CONFIG|PKI)_DIR(?::-[^}]*)?\}((?:/[^:}\s]*)?)")
# The services that run papaia-ctl itself with the Docker socket: they act as the host
# account, which holds the edge CA key anyway. Every other service is held to the rule.
HOST_EQUIVALENT = {("src/manager/docker-compose.yml", "papaia-manager")}


def _compose_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "*compose*.yml", "*compose*.yaml"],
        capture_output=True, text=True, check=True,
    ).stdout.split()  # fmt: skip
    return [ROOT / name for name in listed]


def _config_mounts(volume: object) -> str | None:
    """The source of a bind mount below the configuration directory, relative to it ('' for
    the directory itself); None for any other volume."""
    source = volume.get("source") if isinstance(volume, dict) else volume
    if not isinstance(source, str):
        return None
    match = _CONFIG_VAR.search(source)
    if match is None:
        return None
    below = match.group(2).strip("/")
    return f"pki/{below}".rstrip("/") if match.group(1) == "PKI" else below


def test_no_compose_file_mounts_the_edge_ca_key_or_a_leaf_key(config):
    _issue(config)
    private = [edge_pki.ca_paths(config)[1], *(leaf.key for leaf in edge_pki.leaves(config))]
    private += [edge_pki.private_dir(config) / npm_provision.UPLOADS_FILE]
    relative = [p.relative_to(config).as_posix() for p in private]
    mounted, offending = set(), []
    for path in _compose_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = path.relative_to(ROOT).as_posix()
        for service, spec in (doc.get("services") or {}).items():
            volumes = (spec or {}).get("volumes") or []
            if (name, service) in HOST_EQUIVALENT:
                assert any("docker.sock" in str(v) for v in volumes), (name, service)
                continue
            for volume in volumes:
                source = _config_mounts(volume)
                if source is None:
                    continue
                mounted.add(source)
                for target in relative:
                    if source == "" or target == source or target.startswith(f"{source}/"):
                        offending.append(f"{name}: {service} mounts {source or '.'} ({target})")
    assert "certs" in mounted, "the guard sees the mounts of the configuration directory"
    assert offending == []


def test_the_platform_pki_leaves_the_edge_files_alone(config):
    _issue(config)
    keys = {leaf.key: leaf.key.read_bytes() for leaf in edge_pki.leaves(config)}

    pki.issue(config, [])

    assert {leaf.key: leaf.key.read_bytes() for leaf in edge_pki.leaves(config)} == keys
    assert edge_pki.ca_paths(config)[1].is_file()
    assert not set(pki.doctor_files(config)) & set(edge_pki.doctor_files(config))
    with pytest.raises(pki.PkiError, match="cannot name a module directory"):
        pki.parse_request({"services": []}, "edge", "edge/papaia-app.yaml", addon=True)


def test_a_failed_issue_writes_one_error_row_and_stops(config, monkeypatch):
    _issue(config, hosts=[AUTH])

    def broken(*args, **kwargs):
        raise edge_pki.EdgePkiError("openssl failed")

    monkeypatch.setattr(edge_pki, "_issue_leaf", broken)
    with pytest.raises(edge_pki.EdgePkiError):
        _issue(config, hosts=[AUTH, CHAT])

    last = _rows(config)[-1]
    assert (last["operation"], last["result"], last["error_code"]) == (
        "edge_pki.issue", "error", "openssl",
    )  # fmt: skip
    assert _submission_errors(last) == []
