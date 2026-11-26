"""Edge certificates at the bundled proxy (ADR 0035): `npm-provision` uploads each leaf of
the edge CA as a custom certificate and sets it on the proxy hosts papaia-ctl creates.

The Nginx Proxy Manager API is a recorded stub: every call is kept, so a test states
exactly which writes a run makes. The leaves are issued for real with the host's openssl.
"""

from __future__ import annotations

import json
import shutil
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lib import edge_pki, envtree, ingress, npm_provision, realm_sync, sign_in

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not available")

ROOT = Path(__file__).resolve().parents[2]
AUTH = "auth.itest.papaia.localhost"
CHAT = "chat.itest.papaia.localhost"
NPM = "npm.itest.papaia.localhost"


class FakeNpm:
    """The proxy hosts and certificates of one Nginx Proxy Manager, and every call made."""

    def __init__(self) -> None:
        self.hosts: list[dict] = []
        self.certificates: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.uploads: dict[int, dict[str, str]] = {}
        self._next = 1

    @property
    def writes(self) -> list[tuple[str, str]]:
        return [call for call in self.calls if call[0] != "GET"]

    def _id(self) -> int:
        self._next += 1
        return self._next

    def send(self, base_url, token, path, method, body=None, answer=False):
        self.calls.append((method, path))
        if path == "/api/nginx/proxy-hosts":
            if method == "GET":
                return json.loads(json.dumps(self.hosts))
            host = {**body, "id": self._id()}
            self.hosts.append(host)
            return None
        if path.startswith("/api/nginx/proxy-hosts/"):
            host_id = int(path.rsplit("/", 1)[1])
            if method == "PUT":
                next(h for h in self.hosts if h["id"] == host_id).update(body)
            elif method == "DELETE":
                self.hosts = [h for h in self.hosts if h["id"] != host_id]
            return None
        if path == "/api/nginx/certificates":
            if method == "GET":
                return json.loads(json.dumps(self.certificates))
            assert body["provider"] == "other" and set(body) == {"provider", "nice_name"}
            cert = {**body, "id": self._id()}
            self.certificates.append(cert)
            return cert
        if path.startswith("/api/nginx/certificates/") and method == "DELETE":
            cert_id = int(path.rsplit("/", 1)[1])
            self.certificates = [c for c in self.certificates if c["id"] != cert_id]
            return None
        raise AssertionError(f"unexpected call {method} {path}")

    def upload(self, base_url, token, cert_id, certificate, key):
        self.calls.append(("UPLOAD", f"/api/nginx/certificates/{cert_id}/upload"))
        assert "BEGIN CERTIFICATE" in certificate and "PRIVATE KEY" in key
        assert any(c["id"] == cert_id for c in self.certificates)
        self.uploads[cert_id] = {"certificate": certificate, "certificate_key": key}

    def host(self, name: str) -> dict:
        return next(h for h in self.hosts if name in h["domain_names"])


@pytest.fixture
def stack(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(
        "\n".join([
            "REVERSE_PROXY_PROVIDER=internal_nginx",
            "PAPAIA_HOST=https://localhost",
            "COMPOSE_PROJECT_NAME=papaia-itest",
            "COMPOSE_PROFILES=keycloak,nginx",
            "INGRESS_HTTPS_EXT_PORT=52143",
            f"AUTH_HOST=https://{AUTH}:52143",
            f"NPM_ADMIN_HOST=https://{NPM}:52143",
            "",
        ]),
        encoding="utf-8",
    )  # fmt: skip
    nginx = config / "infra" / "nginx"
    nginx.mkdir(parents=True)
    (nginx / ".env").write_text("NPM_ADMIN_PASSWORD=pw\nNPM_API_LOCAL_PORT=52181\n")
    fake = FakeNpm()
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_send", fake.send)
    monkeypatch.setattr(npm_provision, "_upload_certificate", fake.upload)
    monkeypatch.setattr(npm_provision, "_gate_steps", lambda *a, **k: True)
    return {"config": config, "npm": fake}


def _tree(stack) -> dict:
    return envtree.load_config_dir_tree(stack["config"], ROOT)


def _issue(stack, now: datetime | None = None) -> edge_pki.Result:
    tree = _tree(stack)
    hosts = npm_provision.edge_hosts(tree, stack["config"], ROOT)
    return edge_pki.issue(
        stack["config"], [edge_pki.Host(h) for h in hosts], edge_pki.domains(tree[""]), now=now
    )


def _provision(stack) -> bool:
    return npm_provision.provision_npm_hosts(_tree(stack), stack["config"], ROOT)


def _rows(stack) -> list[dict]:
    path = realm_sync.audit_path(stack["config"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


# ─────────────────────────────────────────────────────────────────────────
# the bodies
# ─────────────────────────────────────────────────────────────────────────


def test_the_bodies_of_papaia_ctl_hosts_carry_the_uploaded_certificate():
    assert npm_provision.proxy_host_body("a.example.org", "x", 80, "http")["certificate_id"] == 0
    body = npm_provision.proxy_host_body("a.example.org", "x", 80, "http", certificate_id=7)
    assert body["certificate_id"] == 7
    assert (body["ssl_forced"], body["hsts_enabled"]) == (False, False), "unchanged here"

    core = npm_provision.core_host_body(AUTH, "keycloak", 8443, "https", False, False,
                                        certificate_id=8)  # fmt: skip
    assert core["certificate_id"] == 8
    assert npm_provision.IDP_ADMIN_BLOCK in core["advanced_config"]

    root = {"COMPOSE_PROFILES": "me", "ME_PUBLIC_URL": "https://me.example.org"}
    entry = sign_in.Entry("example.org", "https://example.org", "https://me.example.org/")
    assert npm_provision.entry_host_body(entry, root, certificate_id=9)["certificate_id"] == 9
    assert npm_provision.entry_host_body(entry, root)["certificate_id"] == 0

    route = ingress.Route("flow", "flow", ("flow.example.org",), "https://flow.example.org",
                          "flow-web", 8000, "http", "flow-net")  # fmt: skip
    assert npm_provision.route_body(route, certificate_id=10)["certificate_id"] == 10


def test_the_proxy_host_names_of_the_edge_are_the_ones_papaia_ctl_creates(stack):
    hosts = npm_provision.edge_hosts(_tree(stack), stack["config"], ROOT)
    assert sorted(hosts) == [(AUTH,), (NPM,)]


# ─────────────────────────────────────────────────────────────────────────
# provisioning against the recorded API
# ─────────────────────────────────────────────────────────────────────────


def test_new_hosts_are_created_with_their_uploaded_leaf(stack):
    _issue(stack)
    npm = stack["npm"]

    assert _provision(stack) is True

    assert len(npm.certificates) == 2
    for name in (AUTH, NPM):
        host = npm.host(name)
        cert = next(c for c in npm.certificates if c["id"] == host["certificate_id"])
        assert cert["nice_name"] == f"papaia edge {name}"
        leaf = edge_pki.leaf_for(stack["config"], (name,))
        assert npm.uploads[cert["id"]]["certificate"] == leaf.cert.read_text()
        assert npm.uploads[cert["id"]]["certificate_key"] == leaf.key.read_text()
        assert host["ssl_forced"] is False and host["hsts_enabled"] is False
    uploads = [r for r in _rows(stack) if r["operation"] == "npm_provision.upload_certificate"]
    assert len(uploads) == 2
    assert {r["result"] for r in uploads} == {"allowed"}
    assert "PRIVATE KEY" not in json.dumps(_rows(stack))


def test_provisioning_again_with_nothing_changed_makes_no_api_write(stack):
    _issue(stack)
    _provision(stack)
    rows = len(_rows(stack))
    stack["npm"].calls.clear()

    assert _provision(stack) is True

    assert stack["npm"].writes == []
    assert len(_rows(stack)) == rows


def test_existing_papaia_ctl_hosts_without_a_certificate_get_the_leaf(stack):
    npm = stack["npm"]
    _provision(stack)  # before this release: hosts without a certificate
    assert {h["certificate_id"] for h in npm.hosts} == {0}
    _issue(stack)

    _provision(stack)

    assert all(h["certificate_id"] in {c["id"] for c in npm.certificates} for h in npm.hosts)
    puts = [c for c in npm.writes if c[0] == "PUT"]
    assert len(puts) == 2


def test_a_certificate_the_operator_set_stays(stack):
    npm = stack["npm"]
    _provision(stack)
    operator = {"id": 99, "provider": "letsencrypt", "nice_name": "mine"}
    npm.certificates.append(operator)
    npm.host(AUTH)["certificate_id"] = 99
    npm.host(AUTH)["ssl_forced"] = True
    npm.host(AUTH)["hsts_enabled"] = True
    _issue(stack)

    _provision(stack)

    auth = npm.host(AUTH)
    assert (auth["certificate_id"], auth["ssl_forced"], auth["hsts_enabled"]) == (99, True, True)
    assert operator in npm.certificates
    assert npm.host(NPM)["certificate_id"] not in (0, 99)
    assert not any(path.endswith("/99") for _, path in npm.writes)


def test_a_renewed_leaf_replaces_the_uploaded_one(stack):
    npm = stack["npm"]
    now = datetime.now(timezone.utc)
    _issue(stack, now=now)
    _provision(stack)
    old = npm.host(AUTH)["certificate_id"]

    assert len(_issue(stack, now=now + timedelta(days=61)).renewed) == 2
    _provision(stack)

    new = npm.host(AUTH)["certificate_id"]
    assert new != old
    assert old not in {c["id"] for c in npm.certificates}, "the old upload is deleted"
    assert npm.uploads[new]["certificate"] == edge_pki.leaf_for(
        stack["config"], (AUTH,)).cert.read_text()  # fmt: skip
    ops = [r["operation"] for r in _rows(stack) if r["writer"] == "papaia-ctl/npm-provision"]
    assert ops.count("npm_provision.upload_certificate") == 4
    assert ops.count("npm_provision.delete_certificate") == 2


def test_a_removed_names_certificate_is_deleted_once_its_host_is_gone(stack):
    npm = stack["npm"]
    _issue(stack)
    _provision(stack)
    npm_cert = npm.host(NPM)["certificate_id"]
    env = stack["config"] / ".env"
    env.write_text(env.read_text().replace("keycloak,nginx", "keycloak"))
    _issue(stack)

    # The host still uses it: kept.
    _provision(stack)
    assert npm_cert in {c["id"] for c in npm.certificates}

    npm.hosts = [h for h in npm.hosts if NPM not in h["domain_names"]]
    _provision(stack)
    assert npm_cert not in {c["id"] for c in npm.certificates}
    deletes = [r for r in _rows(stack) if r["operation"] == "npm_provision.delete_certificate"]
    assert len(deletes) == 1


def test_an_upload_lost_in_the_proxy_is_uploaded_again(stack):
    npm = stack["npm"]
    _issue(stack)
    _provision(stack)
    npm.certificates.clear()  # a new data volume of the proxy

    _provision(stack)

    assert {h["certificate_id"] for h in npm.hosts} == {c["id"] for c in npm.certificates}
    assert len(npm.certificates) == 2


def test_without_edge_leaves_provisioning_keeps_todays_hosts(stack):
    """A PEM bundle of row 3, or no leaf yet: hosts without a certificate, no upload."""
    npm = stack["npm"]
    _provision(stack)
    assert {h["certificate_id"] for h in npm.hosts} == {0}
    assert npm.certificates == []
    assert not any("certificates" in path for method, path in npm.writes)


def test_an_operator_certificate_on_an_add_on_host_without_a_leaf_stays(stack):
    """No leaf applies (a PEM bundle of row 3, a refused name, a failed upload): a drift
    correction of the add-on host leaves the operator's certificate as it is."""
    npm = stack["npm"]
    route = ingress.Route("flow", "flow", ("flow.example.org",), "https://flow.example.org",
                          "flow-web", 8000, "http", "flow-net")  # fmt: skip
    host = {**npm_provision.route_body(route), "id": 40, "certificate_id": 99}
    host["forward_port"] = 8001  # drifted: corrected
    npm.hosts.append(host)
    certs = npm_provision._EdgeCertificates(stack["config"], "http://npm", "t")

    for given in (None, certs):
        npm.host("flow.example.org")["forward_port"] = 8001
        assert npm_provision._correct_host(
            "http://npm", "t", route, npm_provision.route_body(route), certs=given
        )
        corrected = npm.host("flow.example.org")
        assert (corrected["forward_port"], corrected["certificate_id"]) == (8000, 99)


def test_a_lost_upload_state_still_replaces_and_deletes_the_earlier_uploads(stack):
    npm = stack["npm"]
    now = datetime.now(timezone.utc)
    _issue(stack, now=now)
    _provision(stack)
    earlier = {npm.host(name)["certificate_id"] for name in (AUTH, NPM)}
    (edge_pki.private_dir(stack["config"]) / npm_provision.UPLOADS_FILE).unlink()
    _issue(stack, now=now + timedelta(days=61))  # renewed: the earlier uploads expire

    _provision(stack)

    for name in (AUTH, NPM):
        cert_id = npm.host(name)["certificate_id"]
        assert cert_id not in earlier
        assert npm.uploads[cert_id]["certificate"] == edge_pki.leaf_for(
            stack["config"], (name,)).cert.read_text()  # fmt: skip
    assert not earlier & {c["id"] for c in npm.certificates}, "the earlier uploads are deleted"
    deletes = [r for r in _rows(stack) if r["operation"] == "npm_provision.delete_certificate"]
    assert len(deletes) == 2


def test_an_operator_certificate_named_like_ours_is_not_taken_for_one_of_ours(stack):
    """Only papaia-ctl's name for a leaf of this installation's domains counts."""
    npm = stack["npm"]
    _provision(stack)
    npm.certificates.append(
        {"id": 98, "provider": "other", "nice_name": "papaia edge auth.example.org"}
    )
    npm.host(AUTH)["certificate_id"] = 98
    _issue(stack)

    _provision(stack)

    assert npm.host(AUTH)["certificate_id"] == 98
    assert any(c["id"] == 98 for c in npm.certificates)


# ─────────────────────────────────────────────────────────────────────────
# failed writes: one row each
# ─────────────────────────────────────────────────────────────────────────


def _certificate_rows(stack) -> list[tuple[str, str, str | None]]:
    return [
        (r["operation"].rsplit(".", 1)[1], r["result"], r["error_code"])
        for r in _rows(stack)
        if r["operation"].endswith("_certificate")
    ]


def test_a_failed_creation_of_the_certificate_entry_writes_an_error_row(stack, monkeypatch):
    _issue(stack)
    npm = stack["npm"]
    send = npm.send

    def refuse_create(base_url, token, path, method, body=None, answer=False):
        if path == "/api/nginx/certificates" and method == "POST":
            npm.calls.append((method, path))
            raise urllib.error.URLError("connection reset")
        return send(base_url, token, path, method, body, answer)

    monkeypatch.setattr(npm_provision, "_send", refuse_create)

    assert _provision(stack) is False

    assert _certificate_rows(stack) == [("upload_certificate", "error", "transport")]
    assert npm.certificates == []


def test_a_failed_upload_deletes_the_half_made_entry_with_a_row_of_its_own(stack, monkeypatch):
    _issue(stack)
    npm = stack["npm"]

    def refuse_upload(base_url, token, cert_id, certificate, key):
        raise urllib.error.URLError("connection reset")

    monkeypatch.setattr(npm_provision, "_upload_certificate", refuse_upload)

    assert _provision(stack) is False

    assert _certificate_rows(stack) == [
        ("upload_certificate", "error", "transport"),
        ("delete_certificate", "allowed", None),
    ]
    assert npm.certificates == [], "the half-made entry is deleted"
    assert "PRIVATE KEY" not in json.dumps(_rows(stack))


def test_a_failed_compensating_delete_writes_its_error_row(stack, monkeypatch):
    _issue(stack)
    npm = stack["npm"]
    send = npm.send

    def refuse_upload(base_url, token, cert_id, certificate, key):
        raise urllib.error.URLError("connection reset")

    def refuse_delete(base_url, token, path, method, body=None, answer=False):
        if path.startswith("/api/nginx/certificates/") and method == "DELETE":
            raise urllib.error.URLError("connection reset")
        return send(base_url, token, path, method, body, answer)

    monkeypatch.setattr(npm_provision, "_upload_certificate", refuse_upload)
    monkeypatch.setattr(npm_provision, "_send", refuse_delete)

    assert _provision(stack) is False

    assert _certificate_rows(stack) == [
        ("upload_certificate", "error", "transport"),
        ("delete_certificate", "error", "transport"),
    ]


def test_an_unreadable_leaf_is_an_error_row_of_the_file_and_creates_no_entry(stack):
    _issue(stack)
    leaf = edge_pki.leaf_for(stack["config"], (AUTH,))
    leaf.key.chmod(0o000)  # still there, but it cannot be read

    assert _provision(stack) is False

    rows = _certificate_rows(stack)
    assert ("upload_certificate", "error", "file") in rows
    assert not any(r[2] == "transport" for r in rows)
    assert all(c["nice_name"] != f"papaia edge {AUTH}" for c in stack["npm"].certificates)
