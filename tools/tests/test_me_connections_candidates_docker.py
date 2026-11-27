"""The pinned images of Mein Bereich and the connection registry, started from the core's
own compose files with papaia-audit: both profiles start, a write in Mein Bereich gives one
`papaia.audit/1` row at papaia-audit with its correlation id, and me-web reaches papaia-audit
over mutual TLS with the source certificate of papaia-me. With the profile `smtp` on as
well, prefs gets the mail settings `start` derives (render_core.ensure_me_mail) and hands
the test message of the page "Benachrichtigungen" to the real relay `smtp-relay:587`, which
queues it (its upstream is not configured, so nothing leaves the host).

One Compose project with the profiles `audit`, `me`, `connections` and `smtp` (the compose files of
src/infra), the own image of papaia-audit built from the checkout as in
test_audit_docker.py, and a small signing-key service `idp` (https, certificate of a
throwaway CA that the services trust through SSL_CERT_FILE) in place of the realm. The
write is the one Mein Bereich makes for a person: `PUT /api/v1/preferences/me` at prefs with
a person's token of the client papaia-me for the audience papaia-prefs.

The images are pulled by the pinned reference; with PAPAIA_IMAGE_MIRROR (a loopback registry
prefix, as for `tools/check-image-pins --mode=candidate`) from that mirror. A pin that is
neither local, nor published, nor in the mirror skips the module with that reason. The
revision label of each image must be the source commit its service-env.json records.

Needs Docker; skipped without it. Project and address range: PAPAIA_ME_CANDIDATES_TEST_PROJECT
and PAPAIA_ME_CANDIDATES_TEST_SUBNET (a /24), as for the other live tests (live_names.py).
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import live_names
import pytest
import yaml

from lib import (
    audit,
    common,
    images,
    me_profile,
    own_images,
    render_core,
    service_account_keys,
    smtp,
)

REPO = Path(__file__).resolve().parents[2]
COMPOSE_FILES = (
    # First: Compose resolves the relative paths of every file (connections' ./initdb)
    # against the directory of the first one.
    REPO / "src" / "infra" / "connections" / "docker-compose.yml",
    REPO / "src" / "infra" / "audit" / "docker-compose.yml",
    REPO / "src" / "infra" / "me" / "docker-compose.yml",
    REPO / "src" / "infra" / "smtp-relay" / "docker-compose.yml",
)
ME_LIST = REPO / "src" / "infra" / "me" / "service-env.json"
CONNECTIONS_LIST = REPO / "src" / "infra" / "connections" / "service-env.json"
PROJECT = live_names.project("me-candidates", "PAPAIA_ME_CANDIDATES_TEST_PROJECT")
SUBNET = live_names.subnet("PAPAIA_ME_CANDIDATES_TEST_SUBNET")
AUDIT_IMAGE = f"{PROJECT}-audit:test"
ISSUER = "https://idp:8443/realms/papaia"
KID = "me-candidates-test"
# The relay's sender and the name of the installation, as setup stores them. The relay
# refuses a recipient whose domain takes no mail (the reserved example domains have a null
# MX), so the test uses a domain that does, and the relay looks up its MX: the mail test
# needs public DNS (the shard live-network of tools/tests/shards.toml) and is skipped with
# that reason where the domain does not resolve. The relay of this test must never get an
# upstream (SMTP_RELAY_UPSTREAM_HOST): the mail only waits in its queue and nothing leaves
# the host, which test_the_mail_test_of_mein_bereich_reaches_the_relay asserts before it
# sends.
MAIL_DOMAIN = "fidonis.de"
SENDER = f"noreply@{MAIL_DOMAIN}"
# The relay's fail-closed upstream while none is configured (src/infra/smtp-relay).
NO_UPSTREAM = "[smtp-not-configured.invalid]:587"
INSTALLATION = "papAIa Kandidaten"
PROFILES = ("audit", "me", "connections", "smtp")
NETWORKS = (
    "papaia-net",
    "papaia-audit-net",
    "papaia-audit-ingest-net",
    "papaia-audit-idp-net",
    "papaia-prefs-db-net",
    "papaia-connections-net",
    "papaia-connections-db-net",
)


def _docker_available() -> bool:
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")


def _run(*args: str, env: dict | None = None, check: bool = True, timeout: int = 900,
         cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, env=env, timeout=timeout,
                          check=check, cwd=cwd)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# Serves the signing keys of the throwaway realm over https; argv: certificate, key, JWKS.
_IDP = r"""
import http.server, ssl, sys
body = open(sys.argv[3], "rb").read()
class Keys(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/realms/papaia/protocol/openid-connect/certs":
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Keys)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"""

# Runs in me-web with its own settings: the audit client folder it was given, one call to
# the read route of papaia-audit without a person's token. Prints the HTTP status, or the
# name of the TLS error when the handshake fails.
_ME_AUDIT_CALL = r"""
import http.client
from urllib.parse import urlsplit
from app.config import Settings, audit_tls
settings = Settings.from_env()
context = audit_tls(settings)
if context is None:
    print("no-context"); raise SystemExit(0)
url = urlsplit(settings.audit_url)
try:
    conn = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=10)
    conn.request("GET", "/v1/me/reads")
    print(conn.getresponse().status)
except OSError as error:
    print(type(error).__name__)
"""


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.config = root / "config"
        self.backup = root / "backup"
        self.idp = root / "idp"
        self.override = root / "override.yml"
        self.env: dict[str, str] = {}

    def compose(self, *args: str, check: bool = True, timeout: int = 900):
        files = [arg for path in (*COMPOSE_FILES, self.override) for arg in ("-f", str(path))]
        profiles = [arg for name in PROFILES for arg in ("--profile", name)]
        return _run("docker", "compose", "-p", PROJECT, *files, *profiles, *args,
                    env=self.env, check=check, timeout=timeout)

    def psql(self, sql: str) -> str:
        secret = self.config / "infra" / "audit" / "secrets" / "db-read-password"
        done = self.compose("exec", "-T", "-e", f"PGPASSWORD={secret.read_text()}",
                            "papaia-audit-db", "psql", "-h", "127.0.0.1", "-U", "audit_read",
                            "-d", "audit", "-At", "-v", "ON_ERROR_STOP=1", "-c", sql,
                            check=False)
        assert done.returncode == 0, done.stderr
        return done.stdout.strip()

    def sign(self, claims: dict[str, Any]) -> str:
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": KID}).encode())
        body = _b64(json.dumps(claims).encode())
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.idp / "realm.key")],
            input=f"{head}.{body}".encode(), capture_output=True, check=True, timeout=30,
        ).stdout
        return f"{head}.{body}.{_b64(signed)}"


def _openssl(*args: str, cwd: Path) -> None:
    _run("openssl", *args, cwd=cwd, timeout=60)


def _throwaway_pki(directory: Path) -> None:
    """A CA, the server certificates of `idp` and `connections`, and the realm's key."""
    directory.mkdir(parents=True)
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2",
             "-subj", "/CN=papaia test CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign", cwd=directory)
    for name in ("idp", "connections"):
        _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}",
                 cwd=directory)
        (directory / f"{name}.ext").write_text(
            f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                 "-CAcreateserial", "-out", f"{name}.crt", "-days", "2",
                 "-extfile", f"{name}.ext", cwd=directory)
    _openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", "realm.key", cwd=directory)
    modulus = _run("openssl", "rsa", "-in", "realm.key", "-noout", "-modulus", cwd=directory)
    n = int(modulus.stdout.strip().split("=", 1)[1], 16)
    jwks = {"keys": [{"kid": KID, "kty": "RSA", "alg": "RS256", "use": "sig",
                      "n": _b64(n.to_bytes((n.bit_length() + 7) // 8, "big")), "e": "AQAB"}]}
    (directory / "jwks.json").write_text(json.dumps(jwks), encoding="utf-8")
    # The images run as 10001; the throwaway files are readable by it.
    for path in directory.iterdir():
        path.chmod(0o644)


def _pinned(listed: Path) -> str:
    return json.loads(listed.read_text(encoding="utf-8"))["image"]


def _pull(ref: str, mirror: str) -> str:
    """The reference Compose runs: the pin, or the pin behind the mirror."""
    local = images.mirrored([ref], mirror)[0]
    if _run("docker", "image", "inspect", local, check=False).returncode == 0:
        return local
    pulled = _run("docker", "pull", local, check=False)
    if pulled.returncode != 0:
        pytest.skip(f"{ref} is not published and not in PAPAIA_IMAGE_MIRROR ({mirror or 'unset'})")
    return local


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Iterator[Stack]:
    mirror = os.environ.get(images.MIRROR_VAR, "")
    me_ref = _pull(_pinned(ME_LIST), mirror)
    connections_ref = _pull(_pinned(CONNECTIONS_LIST), mirror)

    root = tmp_path_factory.mktemp("candidates")
    st = Stack(root)
    _throwaway_pki(st.idp)
    audit.prepare(st.config)
    st.backup.mkdir()
    (st.config / ".env").write_text(
        f"PAPAIA_BACKUP_DIR={st.backup}\nCOMPOSE_PROFILES=audit,me,connections,smtp\n"
        "ME_PUBLIC_URL=https://me.candidates.invalid\n",
        encoding="utf-8",
    )
    # The relay as `setup --smtp` stores it, without an upstream: mail stays in its queue.
    relay_dir = st.config / smtp.MODULE_DIR
    relay_dir.mkdir(parents=True)
    relay_env = {smtp.KEY_FROM: SENDER, **smtp.derived_keys("starttls", SENDER, INSTALLATION)}
    (relay_dir / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in relay_env.items()), encoding="utf-8"
    )
    (relay_dir / smtp.PASSWORD_FILE).write_text("", encoding="utf-8")
    prefs_password = secrets.token_urlsafe(24)
    (st.config / "infra" / "me").mkdir(parents=True)
    (st.config / "infra" / "me" / ".env").write_text(
        f"PREFS_DB_PASSWORD={prefs_password}\n", encoding="utf-8"
    )
    # As `papaia-ctl` does before every start: the file secret of prefs and prefs-db, and
    # the mail settings of prefs from the relay, the address and the installation's name.
    render_core.ensure_me_secrets(st.config)
    render_core.ensure_me_mail(st.config, root, installation_name=INSTALLATION)
    me_env = common.parse_env_file(st.config / "infra" / "me" / ".env")
    audit.ensure_heads_folder(st.config)
    for source in ("papaia-me", "papaia-connections"):
        audit.issue_source_certificate(st.config, source)
    # The realm's signing keys as `papaia-ctl audit token-keys` writes them after setup.
    jwks_doc = json.loads((st.idp / "jwks.json").read_text(encoding="utf-8"))
    audit.write_token_keys(st.config, {"issuer": ISSUER}, jwks_doc)
    service_account_keys.KeyStore(st.config / "security" / "service-accounts").generate(
        "svc-papaia-audit-report"
    )
    # Mein Bereich: no module registered, an empty catalog, the throwaway CA as local CA.
    (st.config / "personal-settings" / "module-ca").mkdir(parents=True)
    (st.config / "platform").mkdir()
    (st.config / "platform" / "services.json").write_text(
        json.dumps({"schema": "platform-services.v1", "services": []}), encoding="utf-8")
    (st.config / "certs").mkdir()
    shutil.copyfile(st.idp / "ca.crt", st.config / "certs" / "local-ca.crt")
    azp = st.config / "security" / "azp"
    azp.mkdir(parents=True)
    (azp / "azp-allowlist.json").write_text(json.dumps(
        {"version": 1, "audiences": {"papaia-prefs": {"papaia-me": ["read", "write"]}}}),
        encoding="utf-8")
    tls = st.config / "pki" / "core" / "connections"
    tls.mkdir(parents=True)
    for name, target in (("connections.crt", "tls.crt"), ("connections.key", "tls.key"),
                         ("ca.crt", "ca.crt")):
        shutil.copyfile(st.idp / name, tls / target)
    for folder in (st.config / "infra" / "audit" / "clients").iterdir():
        for path in folder.iterdir():
            path.chmod(0o644)

    (own,) = [i for i in own_images.load(REPO) if "papaia-audit" in i.services]
    context = own_images.stage_context(REPO, own, root / "build")
    built = _run("docker", "buildx", "build", "--load", "--provenance=false", "-t", AUDIT_IMAGE,
                 "-f", str(context / own.dockerfile), str(context), check=False)
    assert built.returncode == 0, built.stderr

    blocks = list(SUBNET.subnets(new_prefix=SUBNET.prefixlen + 3))
    services: dict[str, Any] = {name: {"image": AUDIT_IMAGE} for name in own.services}
    for name in ("me-web", "prefs"):
        services[name] = {"image": me_ref}
    for name in ("connections", "connections-migrate"):
        services[name] = {"image": connections_ref}
    services["idp"] = {
        "image": AUDIT_IMAGE,
        "entrypoint": ["python3", "-I", "-c", _IDP, "/idp/idp.crt", "/idp/idp.key",
                       "/idp/jwks.json"],
        "user": "10001:10001",
        "read_only": True,
        "volumes": [f"{st.idp}:/idp:ro"],
        "networks": ["papaia-net", "papaia-connections-net"],
        "profiles": ["me"],
    }
    st.override.write_text(yaml.safe_dump({
        "services": services,
        "networks": {name: {"ipam": {"config": [{"subnet": str(blocks[i])}]}}
                     for i, name in enumerate(NETWORKS)},
    }), encoding="utf-8")
    st.env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DOCKER_HOST",
                                                        "DOCKER_CONFIG", "DOCKER_CONTEXT")},
        "PAPAIA_CONFIG_DIR": str(st.config),
        "PAPAIA_BACKUP_DIR": str(st.backup),
        "UID": str(os.getuid()),
        "GID": str(os.getgid()),
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUTH_URL": f"{ISSUER}/protocol/openid-connect/auth",
        "OIDC_TOKEN_URL": f"{ISSUER}/protocol/openid-connect/token",
        "OIDC_JWKS_URL": f"{ISSUER}/protocol/openid-connect/certs",
        "ME_PUBLIC_URL": "https://me.candidates.invalid",
        "ME_OIDC_CLIENT_SECRET": secrets.token_urlsafe(32),
        "ME_SESSION_SECRET": secrets.token_urlsafe(48),
        "CONNECTIONS_OWNER_DB_PASSWORD": secrets.token_urlsafe(24),
        "CONNECTIONS_SERVICE_DB_PASSWORD": secrets.token_urlsafe(24),
        **{name: me_env[name] for name in me_profile.MAIL_DERIVED},
        **{k: v for k, v in relay_env.items() if k != smtp.KEY_FROM},
    }
    try:
        up = st.compose("up", "-d", "--wait", "--wait-timeout", "240", check=False)
        if up.returncode != 0:
            logs = st.compose("logs", "--no-color", "--tail", "40", check=False).stdout
            pytest.fail(f"the stack did not start: {up.stderr[-2000:]}\n{logs[-6000:]}")
        st.me_ref, st.connections_ref = me_ref, connections_ref  # type: ignore[attr-defined]
        yield st
    finally:
        st.compose("down", "-v", "--remove-orphans", check=False)
        _run("docker", "image", "rm", AUDIT_IMAGE, check=False)


def _revision(ref: str) -> str:
    return _run("docker", "image", "inspect", ref, "--format",
                '{{ index .Config.Labels "org.opencontainers.image.revision" }}').stdout.strip()


def test_each_image_carries_the_source_commit_its_list_records(stack: Stack):
    me = json.loads(ME_LIST.read_text(encoding="utf-8"))
    connections = json.loads(CONNECTIONS_LIST.read_text(encoding="utf-8"))
    assert _revision(stack.me_ref) == me["source"]["commit"]  # type: ignore[attr-defined]
    assert (
        _revision(stack.connections_ref)  # type: ignore[attr-defined]
        == connections["source"]["commit"]
    )


def test_both_profiles_run_and_the_migration_ended(stack: Stack):
    states = {}
    for line in stack.compose("ps", "-a", "--format", "json").stdout.splitlines():
        row = json.loads(line)
        states[row["Service"]] = (row["State"], row.get("Health", ""), row.get("ExitCode"))
    for name in ("me-web", "prefs", "connections", "smtp-relay"):
        assert states[name][:2] == ("running", "healthy"), (name, states[name])
    assert states["prefs-db"][0] == states["connections-db"][0] == "running"
    assert states["connections-migrate"][0] == "exited"
    assert states["connections-migrate"][2] == 0


def test_me_web_gets_exactly_the_listed_variables(stack: Stack):
    listed = json.loads(ME_LIST.read_text(encoding="utf-8"))["services"]["me-web"]
    inspected = stack.compose("exec", "-T", "me-web", "env").stdout.splitlines()
    names = {line.split("=", 1)[0] for line in inspected}
    assert me_profile.expected_names(listed, names) <= names
    env = dict(line.split("=", 1) for line in inspected if "=" in line)
    assert env["ME_AUDIT_URL"] == "https://papaia-audit:8443"
    assert env["ME_DEFAULT_TIME_ZONE"] == "Europe/Berlin"
    assert env["LOG_LEVEL"] == "INFO"


def test_a_write_in_mein_bereich_gives_one_audit_row_with_its_correlation_id(stack: Stack):
    now = int(time.time())
    sub = str(uuid.uuid4())
    token = stack.sign({
        "iss": ISSUER, "aud": "papaia-prefs", "azp": "papaia-me", "typ": "Bearer",
        "sub": sub, "sid": str(uuid.uuid4()), "iat": now, "exp": now + 300,
    })
    correlation = str(uuid.uuid4())
    call = r"""
import json, sys, urllib.request
token, correlation = sys.argv[1], sys.argv[2]
base = "http://127.0.0.1:8080/api/v1/preferences/me"
head = {"Authorization": "Bearer " + token, "X-Papaia-Correlation-Id": correlation}
with urllib.request.urlopen(urllib.request.Request(base, headers=head), timeout=10) as r:
    etag = r.headers["ETag"]
body = json.dumps({"time_zone": "Europe/Vienna"}).encode()
put = urllib.request.Request(base, data=body, method="PUT", headers={
    **head, "If-Match": etag, "Content-Type": "application/json"})
with urllib.request.urlopen(put, timeout=10) as r:
    print(json.dumps({"status": r.status, "correlation": r.headers["X-Papaia-Correlation-Id"]}))
"""
    done = stack.compose("exec", "-T", "prefs", "python", "-I", "-c", call, token, correlation,
                         check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    answer = json.loads(done.stdout.strip().splitlines()[-1])
    assert answer == {"status": 200, "correlation": correlation}

    query = ("SELECT body::text FROM audit.event WHERE source = 'papaia-me' "
             f"AND body->>'correlation_id' = '{correlation}'")
    rows: list[str] = []
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        rows = [line for line in stack.psql(query).splitlines() if line]
        if any(json.loads(row).get("effect") == "write" for row in rows):
            break
        time.sleep(2)
    writes = [json.loads(row) for row in rows if json.loads(row).get("effect") == "write"]
    if len(writes) != 1:
        stored = stack.psql("SELECT source, count(*) FROM audit.event GROUP BY source")
        logs = stack.compose("logs", "--no-color", "--tail", "30", "prefs", "papaia-audit",
                             check=False).stdout
        pytest.fail(f"rows {rows}; stored per source: {stored!r}\n{logs[-5000:]}")
    (row,) = writes
    assert row["format"] == "papaia.audit/1"
    assert row["azp"] == "papaia-me"
    assert row["sub"] == sub
    assert token not in json.dumps(rows)
    assert "Europe/Vienna" not in json.dumps(rows)


def test_a_row_of_me_web_reaches_papaia_audit_through_prefs(stack: Stack):
    """me-web keeps no outbox: it signs its rows and hands them to prefs before it answers.

    The row comes from a sign-out the provider sends over the back channel (a logout token
    signed with the throwaway realm's key; no session needed). The row me-web logs and
    the row papaia-audit stores carry the same correlation id and writer.
    """
    now = int(time.time())
    sub = str(uuid.uuid4())
    token = stack.sign({
        "iss": ISSUER, "aud": "papaia-me", "iat": now, "exp": now + 120,
        "jti": str(uuid.uuid4()), "sub": sub,
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    })
    call = r"""
import sys, urllib.parse, urllib.request
body = urllib.parse.urlencode({"logout_token": sys.argv[1]}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:8000/auth/backchannel-logout", data=body, method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
with urllib.request.urlopen(request, timeout=20) as r:
    print(r.status)
"""
    done = stack.compose("exec", "-T", "me-web", "python", "-I", "-c", call, token, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip().splitlines()[-1] == "200"

    logged = []
    for line in stack.compose("logs", "--no-color", "me-web", check=False).stdout.splitlines():
        start = line.find("{")
        if " papaia.audit " in line and start >= 0 and sub in line:
            logged.append(json.loads(line[start:]))
    assert len(logged) == 1, logged
    (written,) = logged
    assert written["writer"] == "papaia-me/me-web"
    correlation = written["correlation_id"]

    query = ("SELECT body::text FROM audit.event WHERE source = 'papaia-me' "
             f"AND body->>'correlation_id' = '{correlation}'")
    rows: list[str] = []
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        rows = [line for line in stack.psql(query).splitlines() if line]
        if rows:
            break
        time.sleep(2)
    if len(rows) != 1:
        logs = stack.compose("logs", "--no-color", "--tail", "30", "me-web", "prefs",
                             "papaia-audit", check=False).stdout
        pytest.fail(f"rows {rows}\n{logs[-5000:]}")
    stored = json.loads(rows[0])
    assert stored["format"] == "papaia.audit/1"
    assert stored["writer"] == "papaia-me/me-web"
    assert stored["sub"] == sub
    assert stored["correlation_id"] == correlation
    assert token not in rows[0]


def test_me_web_reaches_papaia_audit_over_mutual_tls_with_its_source_certificate(stack: Stack):
    done = stack.compose("exec", "-T", "me-web", "python", "-c", _ME_AUDIT_CALL, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    # The handshake with papaia-me's certificate succeeds; without a person's token the
    # read route answers 401, never a TLS error.
    assert done.stdout.strip().splitlines()[-1] == "401"


def test_prefs_gets_the_mail_settings_start_derives(stack: Stack):
    listed = json.loads(ME_LIST.read_text(encoding="utf-8"))["services"]["prefs"]
    inspected = stack.compose("exec", "-T", "prefs", "env").stdout.splitlines()
    env = dict(line.split("=", 1) for line in inspected if "=" in line)
    assert me_profile.expected_names(listed, set(env)) <= set(env)
    assert {name: env[name] for name in (*me_profile.MAIL_DERIVED, "PREFS_SMTP_PORT")} == {
        "PREFS_SMTP_HOST": "smtp-relay",
        "PREFS_SMTP_PORT": "587",
        "PREFS_MAIL_FROM": SENDER,
        "PREFS_INSTALLATION_NAME": INSTALLATION,
        "PREFS_NOTIFICATIONS_URL": "https://me.candidates.invalid/notifications",
    }
    # No credential of a mail server reaches prefs.
    assert not [name for name in env if name.startswith("SMTP_RELAY_")]


def test_the_mail_test_of_mein_bereich_reaches_the_relay(stack: Stack):
    try:
        socket.getaddrinfo(MAIL_DOMAIN, None)
    except OSError:
        pytest.skip(f"no public DNS: the relay cannot look up the MX of {MAIL_DOMAIN}")
    # Nothing may leave the host: the relay has no upstream to deliver to.
    relay = stack.compose("exec", "-T", "smtp-relay", "printenv", "RELAYHOST").stdout.strip()
    assert relay == NO_UPSTREAM, relay
    now = int(time.time())
    recipient = f"anna-{uuid.uuid4().hex[:8]}@{MAIL_DOMAIN}"
    token = stack.sign({
        "iss": ISSUER, "aud": "papaia-prefs", "azp": "papaia-me", "typ": "Bearer",
        "sub": str(uuid.uuid4()), "sid": str(uuid.uuid4()), "iat": now, "exp": now + 300,
        "email": recipient, "email_verified": True,
    })
    call = r"""
import json, sys, urllib.error, urllib.request
request = urllib.request.Request(
    "http://127.0.0.1:8080/api/v1/channels/mail/test", data=b"", method="POST",
    headers={"Authorization": "Bearer " + sys.argv[1]})
try:
    with urllib.request.urlopen(request, timeout=30) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as error:
    print(json.dumps({"status": error.code, "body": error.read().decode()[:500]}))
"""
    done = stack.compose("exec", "-T", "prefs", "python", "-I", "-c", call, token, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    answer = json.loads(done.stdout.strip().splitlines()[-1])
    if answer != {"status": 202, "body": {"channel": "mail", "status": "sent"}}:
        logs = stack.compose("logs", "--no-color", "--tail", "40", "prefs", "smtp-relay",
                             check=False).stdout
        pytest.fail(f"{answer}\n{logs[-6000:]}")
    # The relay took it: one queued mail from the relay's sender to the person's address.
    queued: list[dict] = []
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        listing = stack.compose("exec", "-T", "smtp-relay", "postqueue", "-j", check=False)
        queued = [json.loads(line) for line in listing.stdout.splitlines() if line.strip()]
        if any(r["address"] == recipient for q in queued for r in q.get("recipients", [])):
            break
        time.sleep(2)
    mine = [q for q in queued if any(r["address"] == recipient for r in q["recipients"])]
    assert len(mine) == 1, queued
    assert mine[0]["sender"] == SENDER
