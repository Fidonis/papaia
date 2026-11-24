"""The platform PKI (`papaia.platform-pki/1`, ADR 0019, docs/pki.md).

Certificates are issued for real with the host's openssl into a temporary configuration
directory; no container, no network. Time is passed in, so a renewal or an expired
certificate needs no waiting.
"""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from lib import cli, pki, realm_sync

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not available")


def openssl(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["openssl", *args], input=stdin, capture_output=True, text=True, check=True
    ).stdout


def _write_yaml(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


STUDIO_PKI = {
    "services": [
        {"name": "studio-gateway", "uid": 10001, "server": {"dns": ["studio-gateway"]},
         "client": True},  # fmt: skip
        {"name": "studio-db", "uid": 999, "server": {"dns": ["studio-db"]}},
        {"name": "studio-worker", "uid": 10001, "client": True},
    ]
}


@pytest.fixture
def install(tmp_path: Path) -> dict[str, Path]:
    """A checkout with the lifecycle profile's request, a configuration directory and one
    active add-on with a `pki:` block."""
    repo = tmp_path / "repo"
    _write_yaml(
        repo / "src" / "infra" / "lifecycle" / "pki.yaml",
        {
            "profile": "lifecycle",
            "pki": {
                "services": [
                    {"name": "papaia-lifecycle", "uid": 1000,
                     "server": {"dns": ["papaia-lifecycle"]}, "client": True},  # fmt: skip
                ]
            },
        },
    )
    addon = tmp_path / "addons" / "studio"
    _write_yaml(addon / "papaia-app.yaml", {"name": "studio", "pki": STUDIO_PKI})
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(
        "COMPOSE_PROFILES=keycloak,lifecycle\nPAPAIA_SECURITY_PROFILE=standard\n",
        encoding="utf-8",
    )
    _write_yaml(
        config / "deployment.yaml",
        {"addons": [{"name": "studio", "path": str(addon), "active": True}]},
    )
    return {"repo": repo, "config": config, "addon": addon}


def _issue(install, **kwargs) -> pki.Result:
    requests = pki.collect(install["config"], install["repo"])
    return pki.issue(install["config"], requests, **kwargs)


def _text(cert: Path) -> str:
    return openssl("x509", "-in", str(cert), "-noout", "-text")


# ─────────────────────────────────────────────────────────────────────────
# certificates per service
# ─────────────────────────────────────────────────────────────────────────


def test_every_requested_service_gets_its_own_certificates(install):
    result = _issue(install)
    root = pki.pki_dir(install["config"])

    assert sorted(result.issued) == [
        "core/papaia-lifecycle",
        "studio/studio-db",
        "studio/studio-gateway",
        "studio/studio-worker",
    ]
    gateway = root / "studio" / "studio-gateway"
    assert {p.name for p in gateway.iterdir()} == {
        "ca.crt", "tls.crt", "tls.key", "client.crt", "client.key", "generation", "request.json",
    }  # fmt: skip
    assert not (root / "studio" / "studio-worker" / "tls.crt").exists(), "client only"
    assert not (root / "studio" / "studio-db" / "client.crt").exists(), "server only"

    server = _text(gateway / "tls.crt")
    assert "DNS:studio-gateway" in server and "TLS Web Server Authentication" in server
    assert "CA:FALSE" in server
    client = _text(gateway / "client.crt")
    assert "TLS Web Client Authentication" in client
    assert "CN=studio-gateway" in openssl("x509", "-in", str(gateway / "client.crt"),
                                          "-noout", "-subject").replace(" ", "")  # fmt: skip
    for name in ("tls.crt", "client.crt"):
        verified = openssl("verify", "-CAfile", str(gateway / "ca.crt"), str(gateway / name))
        assert verified.strip().endswith("OK")


def test_keys_are_private_and_the_ca_key_is_out_of_every_service_directory(install):
    _issue(install)
    root = pki.pki_dir(install["config"])

    gateway = root / "studio" / "studio-gateway"
    assert stat.S_IMODE(gateway.stat().st_mode) == 0o700
    for key in ("tls.key", "client.key"):
        assert stat.S_IMODE((gateway / key).stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "ca").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "ca" / "ca.key").stat().st_mode) == 0o600
    keys = sorted(p.relative_to(root).as_posix() for p in root.rglob("ca.key"))
    assert keys == ["ca/ca.key"]


def test_the_platform_ca_may_only_sign_leaves(install):
    _issue(install)
    text = _text(pki.pki_dir(install["config"]) / "ca" / "ca.crt")

    assert "CA:TRUE, pathlen:0" in text
    assert "Certificate Sign" in text


def test_the_inventory_names_the_format_the_ca_and_every_certificate(install):
    _issue(install)
    inventory = pki.read_inventory(install["config"])

    assert inventory["format"] == pki.FORMAT == "papaia.platform-pki/1"
    assert [ca["role"] for ca in inventory["ca"]] == ["active"]
    services = {f"{s['module']}/{s['name']}": s for s in inventory["services"]}
    assert set(services) == {
        "core/papaia-lifecycle", "studio/studio-db", "studio/studio-gateway",
        "studio/studio-worker",
    }  # fmt: skip
    assert services["studio/studio-gateway"]["dns"] == ["studio-gateway"]
    assert set(services["studio/studio-gateway"]) >= {"server_not_after", "client_not_after"}


def test_a_second_run_changes_nothing(install):
    _issue(install)
    gateway = pki.pki_dir(install["config"]) / "studio" / "studio-gateway"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in gateway.iterdir()}

    result = _issue(install)

    assert result.changed == []
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in gateway.iterdir()} == before


def test_a_profile_that_is_off_requests_nothing(install):
    (install["config"] / ".env").write_text("COMPOSE_PROFILES=keycloak\n", encoding="utf-8")

    names = [f"{r.module}/{r.name}" for r in pki.collect(install["config"], install["repo"])]

    assert "core/papaia-lifecycle" not in names


def test_a_changed_request_is_issued_again_and_a_dropped_one_removed(install):
    _issue(install)
    root = pki.pki_dir(install["config"])
    generation = (root / "studio" / "studio-gateway" / "generation").read_text()
    changed = json.loads(json.dumps(STUDIO_PKI))
    changed["services"][0]["server"]["dns"].append("gateway.studio.internal")
    del changed["services"][2]
    _write_yaml(install["addon"] / "papaia-app.yaml", {"name": "studio", "pki": changed})

    result = _issue(install)

    assert result.renewed == ["studio/studio-gateway"]
    assert result.removed == ["studio/studio-worker"]
    assert not (root / "studio" / "studio-worker").exists()
    assert "DNS:gateway.studio.internal" in _text(root / "studio" / "studio-gateway" / "tls.crt")
    new_generation = (root / "studio" / "studio-gateway" / "generation").read_text()
    assert int(new_generation) == int(generation) + 1


def test_leaves_are_renewed_once_two_thirds_of_their_lifetime_have_passed(install):
    now = datetime.now(timezone.utc)
    _issue(install, now=now)

    assert _issue(install, now=now + timedelta(days=59)).renewed == []
    later = _issue(install, now=now + timedelta(days=61))

    assert sorted(later.renewed) == sorted(later.changed) and len(later.renewed) == 4


def test_force_renews_every_leaf_with_the_same_ca(install):
    _issue(install)
    root = pki.pki_dir(install["config"])
    ca_before = (root / "ca" / "ca.crt").read_bytes()
    key_before = (root / "studio" / "studio-db" / "tls.key").read_bytes()

    result = _issue(install, force=True)

    assert len(result.renewed) == 4
    assert (root / "ca" / "ca.crt").read_bytes() == ca_before
    assert (root / "studio" / "studio-db" / "tls.key").read_bytes() != key_before


def test_a_new_ca_keeps_the_old_one_trusted_until_its_last_leaf_has_ended(install):
    now = datetime.now(timezone.utc)
    _issue(install, now=now)
    root = pki.pki_dir(install["config"])
    old_ca = (root / "ca" / "ca.crt").read_text()

    result = _issue(install, now=now, rotate_ca=True)

    assert len(result.renewed) == 4
    bundle = (root / "studio" / "studio-db" / "ca.crt").read_text()
    assert old_ca in bundle and (root / "ca" / "ca.crt").read_text() in bundle
    assert [ca["role"] for ca in pki.read_inventory(install["config"])["ca"]] == [
        "active",
        "retired",
    ]
    # After the lifetime of the old leaves (90 days) the old CA leaves the bundle.
    _issue(install, now=now + timedelta(days=pki.LEAF_DAYS + 1))
    assert old_ca not in (root / "studio" / "studio-db" / "ca.crt").read_text()


def _ca_pair(root: Path) -> tuple[bytes, bytes]:
    return (root / "ca" / "ca.key").read_bytes(), (root / "ca" / "ca.crt").read_bytes()


def _ca_matches(root: Path) -> bool:
    key = openssl("pkey", "-pubout", "-in", str(root / "ca" / "ca.key"))
    return key == openssl("x509", "-noout", "-pubkey", "-in", str(root / "ca" / "ca.crt"))


def test_a_new_ca_that_fails_halfway_leaves_the_old_ca_whole(install, monkeypatch):
    _issue(install)
    root = pki.pki_dir(install["config"])
    before = _ca_pair(root)
    real = pki._openssl

    def failing(args, stdin=None):
        if args[0] == "req":  # the self-signed certificate of the new CA
            raise pki.PkiError("openssl req failed: No space left on device")
        return real(args, stdin)

    monkeypatch.setattr(pki, "_openssl", failing)
    with pytest.raises(pki.PkiError, match="No space left"):
        _issue(install, rotate_ca=True)
    monkeypatch.setattr(pki, "_openssl", real)

    assert _ca_pair(root) == before and _ca_matches(root)
    assert not (root / "ca" / "retired.json").exists()
    assert sorted(p.name for p in (root / "ca").iterdir()) == ["ca.crt", "ca.key"]
    assert _issue(install, rotate_ca=True).ca == "rotated" and _ca_matches(root)


def test_a_ca_key_that_does_not_match_its_certificate_is_replaced(install):
    _issue(install)
    root = pki.pki_dir(install["config"])
    old_ca = (root / "ca" / "ca.crt").read_text()
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(root / "ca" / "ca.key"))  # fmt: skip

    result = _issue(install)

    assert result.ca == "recreated" and _ca_matches(root)
    assert len(result.renewed) == 4
    assert old_ca in (root / "studio" / "studio-db" / "ca.crt").read_text()
    operations = [
        json.loads(line)["operation"]
        for line in realm_sync.audit_path(install["config"]).read_text().splitlines()
    ]
    assert "pki.ca_repair" in operations


def test_runs_that_overlap_wait_for_each_other(install, monkeypatch, tmp_path):
    import fcntl

    _issue(install)
    monkeypatch.setattr(pki, "LOCK_WAIT_SECONDS", 0.3)
    with open(pki.lock_path(install["config"]), "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(pki.PkiError, match="another papaia-ctl run"):
            _issue(install, force=True)
        with pytest.raises(pki.PkiError, match="another papaia-ctl run"):
            pki.import_bundle(install["config"], _company_root(tmp_path / "company"))
    assert len(_issue(install, force=True).renewed) == 4


def test_every_write_is_one_audit_row_with_one_correlation_id(install):
    _issue(install)
    rows = [
        json.loads(line)
        for line in realm_sync.audit_path(install["config"]).read_text().splitlines()
    ]

    operations = sorted(row["operation"] for row in rows)
    assert operations == ["pki.ca_create"] + ["pki.issue"] * 4
    assert {row["format"] for row in rows} == {"papaia.audit/1"}
    assert len({row["correlation_id"] for row in rows}) == 1
    assert {row["writer"] for row in rows} == {"papaia-ctl/pki"}
    text = "\n".join(json.dumps(row) for row in rows)
    assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text


# ─────────────────────────────────────────────────────────────────────────
# the `pki:` block (contract generation 11)
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("yes", "must be a mapping"),
        ({"services": "all"}, "must be a list"),
        ({"services": [], "ca": "own"}, "unknown keys: ca"),
        ({"services": [{"name": "Gateway", "uid": 1, "client": True}]}, "DNS label"),
        ({"services": [{"name": "a", "uid": -1, "client": True}]}, "uid"),
        ({"services": [{"name": "a", "uid": True, "client": True}]}, "uid"),
        ({"services": [{"name": "a", "uid": 1, "client": True, "key": "x"}]}, "unknown keys: key"),
        ({"services": [{"name": "a", "uid": 1}]}, "server, a client certificate or both"),
        ({"services": [{"name": "a", "uid": 1, "server": {"dns": []}}]}, "at least one"),
        ({"services": [{"name": "a", "uid": 1, "server": {"dns": ["*.x"]}}]}, "not a DNS name"),
        ({"services": [{"name": "a", "uid": 1, "server": {"dns": ["a"], "ip": ["1.2.3.4"]}}]},
         "unknown keys: ip"),  # fmt: skip
        ({"services": [{"name": "a", "uid": 1, "client": "yes"}]}, "true or false"),
        ({"services": [{"name": "a", "uid": 1, "client": True}] * 2}, "twice"),
    ],
)
def test_a_malformed_request_is_refused_with_the_reason(block, message):
    with pytest.raises(pki.PkiError, match=message):
        pki.parse_request(block, "studio", "studio/papaia-app.yaml")


def test_module_names_that_would_collide_with_the_layout_are_refused():
    for module in ("ca", "core", "../x"):
        with pytest.raises(pki.PkiError):
            pki.parse_request({"services": []}, module, "x", addon=True)


def test_the_kritis_profile_refuses_an_add_on_without_a_request():
    assert pki.addon_refusal("studio", {"name": "studio"}, {}) is None
    assert pki.addon_refusal("studio", {"name": "studio"}, {"PAPAIA_SECURITY_PROFILE": "kritis"})
    assert (
        pki.addon_refusal(
            "studio", {"name": "studio", "pki": STUDIO_PKI}, {"PAPAIA_SECURITY_PROFILE": "kritis"}
        )
        is None
    )


def test_start_under_kritis_stops_at_an_active_add_on_without_a_request(install):
    _write_yaml(install["addon"] / "papaia-app.yaml", {"name": "studio"})
    (install["config"] / ".env").write_text(
        "COMPOSE_PROFILES=lifecycle\nPAPAIA_SECURITY_PROFILE=kritis\n", encoding="utf-8"
    )

    with pytest.raises(pki.PkiError, match="kritis"):
        pki.collect(install["config"], install["repo"])


def test_addon_install_under_kritis_refuses_before_anything_is_recorded(install, tmp_path, capsys):
    other = tmp_path / "addons" / "plain"
    _write_yaml(other / "papaia-app.yaml", {"name": "plain", "papaia_compat": ">=0.0.0"})
    (install["repo"] / "VERSION").write_text("1.10.0\n", encoding="utf-8")
    (install["config"] / ".env").write_text("PAPAIA_SECURITY_PROFILE=kritis\n", encoding="utf-8")
    before = (install["config"] / "deployment.yaml").read_text()

    code = cli.main(
        ["--config-dir", str(install["config"]), "--repo-root", str(install["repo"]),
         "addon-install", "--name", "plain", "--path", str(other)]  # fmt: skip
    )

    assert code == 2
    assert "kritis" in capsys.readouterr().err
    assert (install["config"] / "deployment.yaml").read_text() == before


# ─────────────────────────────────────────────────────────────────────────
# enterprise CA bundle
# ─────────────────────────────────────────────────────────────────────────


def _company_root(directory: Path, name: str = "Example Corp Root") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / f"{name}.key", directory / f"{name}.pem"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "30", "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")  # fmt: skip
    return cert


def _leaf(directory: Path, subject: str = "/CN=www.example.org") -> Path:
    cert = directory / "leaf.pem"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(directory / "leaf.key"), "-out", str(cert), "-days", "30",
            "-subj", subject, "-addext", "basicConstraints=critical,CA:FALSE")  # fmt: skip
    return cert


def test_a_bundle_of_ca_certificates_is_accepted(tmp_path):
    first, second = _company_root(tmp_path, "Root A"), _company_root(tmp_path, "Root B")
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(first.read_text() + second.read_text(), encoding="utf-8")

    assert len(pki.check_bundle(bundle)) == 2


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "no certificate"),
        ("not a certificate\n", "no certificate"),
        ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "not readable"),
    ],
)
def test_an_unusable_bundle_is_refused_with_the_reason(tmp_path, content, message):
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(content, encoding="utf-8")

    with pytest.raises(pki.PkiError, match=message):
        pki.check_bundle(bundle)


def test_a_bundle_with_a_server_certificate_or_a_private_key_is_refused(tmp_path):
    leaf = _leaf(tmp_path)
    with pytest.raises(pki.PkiError, match="not a CA certificate"):
        pki.check_bundle(leaf)

    root = _company_root(tmp_path)
    mixed = tmp_path / "mixed.pem"
    mixed.write_text(root.read_text() + (tmp_path / "leaf.key").read_text(), encoding="utf-8")
    with pytest.raises(pki.PkiError, match="private key"):
        pki.check_bundle(mixed)

    with pytest.raises(pki.PkiError, match="cannot be read"):
        pki.check_bundle(tmp_path / "missing.pem")


def _self_signed_without_basic_constraints(directory: Path) -> Path:
    """`req -x509` adds CA:TRUE by default; signing a request with an extension file of
    our own does not."""
    key, csr, cert = directory / "plain.key", directory / "plain.csr", directory / "plain.pem"
    ext = directory / "plain.ext"
    ext.write_text("keyUsage=critical,digitalSignature\nnsComment=CA:TRUE\n", encoding="utf-8")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-subj", "/CN=CA:TRUE/O=CA:TRUE")  # fmt: skip
    openssl("x509", "-req", "-in", str(csr), "-signkey", str(key), "-days", "30",
            "-extfile", str(ext), "-out", str(cert))  # fmt: skip
    return cert


@pytest.mark.parametrize("kind", ["ca-false", "no-basic-constraints"])
def test_ca_true_outside_the_basic_constraints_does_not_make_a_ca(tmp_path, kind):
    if kind == "ca-false":
        leaf = _leaf(tmp_path, "/CN=CA:TRUE/O=CA:TRUE")
    else:
        leaf = _self_signed_without_basic_constraints(tmp_path)
        assert "Basic Constraints" not in openssl("x509", "-noout", "-text", "-in", str(leaf))
    assert "CA:TRUE" in openssl("x509", "-noout", "-text", "-in", str(leaf))

    with pytest.raises(pki.PkiError, match="not a CA certificate"):
        pki.check_bundle(leaf)


def test_the_trust_bundle_is_the_one_place_with_platform_and_company_roots(install, tmp_path):
    _issue(install)
    root = _company_root(tmp_path / "company")

    pki.import_bundle(install["config"], root)

    trust = install["config"] / "certs" / "trust" / "ca-bundle.pem"
    assert trust == pki.trust_bundle_path(install["config"])
    text = trust.read_text()
    assert root.read_text() in text
    assert (pki.pki_dir(install["config"]) / "ca" / "ca.crt").read_text() in text
    rows = realm_sync.audit_path(install["config"]).read_text().splitlines()
    assert json.loads(rows[-1])["operation"] == "pki.trust_import"
    # A run of the issuer keeps the company roots in the bundle.
    _issue(install, rotate_ca=True)
    assert root.read_text() in trust.read_text()


def test_the_cli_checks_a_bundle_without_writing_anything(install, tmp_path, capsys):
    leaf = _leaf(tmp_path)
    args = ["--config-dir", str(install["config"]), "--repo-root", str(install["repo"])]

    assert cli.main([*args, "pki-check-bundle", "--file", str(leaf)]) == 3
    assert "not a CA certificate" in capsys.readouterr().err
    assert cli.main([*args, "pki-check-bundle", "--file", str(_company_root(tmp_path))]) == 0
    assert not (install["config"] / "certs").exists()


def test_the_cli_issues_and_reports_what_changed(install, capsys):
    args = ["--config-dir", str(install["config"]), "--repo-root", str(install["repo"])]

    assert cli.main([*args, "pki-issue"]) == 0
    assert "issued studio/studio-gateway" in capsys.readouterr().out
    assert cli.main([*args, "pki-issue"]) == 0
    assert "issued" not in capsys.readouterr().out
    assert cli.main([*args, "pki-status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == pki.FORMAT and len(report["certificates"]) == 7


def test_the_shipped_core_requests_are_valid_and_follow_their_profiles():
    repo = Path(__file__).resolve().parents[2]

    on = pki.core_requests(repo, {"lifecycle", "audit", "me", "nginx"})
    off = pki.core_requests(repo, set())

    assert {r.label: (r.dns, r.client) for r in on} == {
        "core/papaia-lifecycle": (("papaia-lifecycle",), True),
        "core/me-web": (("me-web",), False),
        "core/nginx-proxy-manager": ((), True),
        "core/papaia-replay": (("papaia-replay",), False),
    }
    assert off == []
