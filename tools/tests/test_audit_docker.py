"""papaia-audit with real containers: ingest over mutual TLS into PostgreSQL, refusal of
unknown sources, chain continuity, and a tampered row found by the verification job.

The material is the one `papaia-ctl` produces (lib/audit.py): the ingest CA, the server
certificate, the passwords and the signing key, and client certificates for two sources.
The core compose file of the service is started on its own, with the own image
`ghcr.io/fidonis/papaia-audit` built from the checkout's declared inputs (the path through
a registry, signing and the pinned digest is test_own_images_registry.py); a client
container on papaia-audit-ingest-net delivers batches as a module's audit writer does.

Needs Docker; skipped without it. The Compose project and the address range can be set
with PAPAIA_AUDIT_TEST_PROJECT and PAPAIA_AUDIT_TEST_SUBNET (a /24) so the test does not
collide with other stacks on the same host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from lib import audit, own_images, service_account_keys

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "infra" / "audit" / "docker-compose.yml"
PROJECT = os.environ.get("PAPAIA_AUDIT_TEST_PROJECT", f"papaia-audit-test-{os.getpid()}")
SUBNET = ipaddress.ip_network(os.environ.get("PAPAIA_AUDIT_TEST_SUBNET", "10.250.78.0/24"))
IMAGE = f"{PROJECT}-audit:test"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
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

# Runs in a container on papaia-audit-ingest-net. argv: a JSON list of calls
# [cert_dir or null, body]; prints one JSON result per call.
_CLIENT = r"""
import http.client, json, ssl, sys
results = []
for cert_dir, body in json.loads(sys.argv[1]):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("/certs/server-ca.crt")
    if cert_dir:
        context.load_cert_chain(f"/certs/{cert_dir}/client.crt", f"/certs/{cert_dir}/client.key")
    try:
        conn = http.client.HTTPSConnection("papaia-audit", 8443, context=context, timeout=20)
        conn.request("POST", "/v1/ingest", body=body.encode(),
                     headers={"Content-Type": "application/x-ndjson"})
        response = conn.getresponse()
        results.append({"status": response.status, "body": json.loads(response.read() or b"null")})
    except (ssl.SSLError, OSError) as error:
        results.append({"status": None, "error": type(error).__name__})
print(json.dumps(results))
"""


def _run(
    *args: str,
    env: dict | None = None,
    check: bool = True,
    stdin: str | None = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=timeout,
        check=check,
    )


def _event(source_seq: int, writer: str = "papaia-flow/flow-worker", **changes: Any) -> str:
    event = {
        "format": "papaia.audit/1",
        "time": "2026-11-21T08:00:00.000Z",
        "source_seq": source_seq,
        "correlation_id": f"corr-{source_seq}",
        "writer": writer,
        "role": "server",
        "sub": "4c0a9e1d-2b7f-4f53-9d0e-6a1c2b3d4e5f",
        "identity_kind": "person",
        "service_account": None,
        "azp": "flow-engine",
        "catalog_id": "paperless.documents",
        "operation": "add_note",
        "effect": "write",
        "result": "allowed",
        "event": "operation",
    }
    event.update(changes)
    return json.dumps(event, separators=(",", ":"))


def _batch(*events: str) -> str:
    return "\n".join(events) + "\n"


class Stack:
    def __init__(self, root: Path) -> None:
        self.config = root / "config"
        self.foreign = root / "foreign"
        self.certs = root / "certs"
        self.backup = root / "backup"
        self.override = root / "networks.override.yml"
        self.env = {
            **os.environ,
            "PAPAIA_CONFIG_DIR": str(self.config),
            "PAPAIA_BACKUP_DIR": str(self.backup),
            "UID": str(os.getuid()),
            "GID": str(os.getgid()),
        }

    def compose(self, *args: str, check: bool = True, stdin: str | None = None):
        return _run(
            "docker",
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(COMPOSE),
            "-f",
            str(self.override),
            *args,
            env=self.env,
            check=check,
            stdin=stdin,
        )

    def deliver(self, *calls: tuple[str | None, str]) -> list[dict[str, Any]]:
        result = _run(
            "docker",
            "run",
            "--rm",
            "--network",
            f"{PROJECT}_papaia-audit-ingest-net",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{self.certs}:/certs:ro",
            "--entrypoint",
            "python3",
            IMAGE,
            "-I",
            "-c",
            _CLIENT,
            json.dumps(list(calls)),
        )
        return json.loads(result.stdout)

    def service(self, *args: str, check: bool = False, stdin: str | None = None):
        return self.compose(
            "exec",
            "-T",
            "papaia-audit",
            "python3",
            "-I",
            "-m",
            "papaia_audit",
            *args,
            check=check,
            stdin=stdin,
        )

    def psql(self, role: str, sql: str) -> subprocess.CompletedProcess:
        secret = self.config / "infra" / "audit" / "secrets" / f"db-{role}-password"
        return self.compose(
            "exec",
            "-T",
            "-e",
            f"PGPASSWORD={secret.read_text()}",
            "papaia-audit-db",
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            f"audit_{role}",
            "-d",
            "audit",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
            check=False,
        )


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Iterator[Stack]:
    root = tmp_path_factory.mktemp("audit")
    st = Stack(root)
    audit.prepare(st.config)
    # The signed chain heads go to the backup target, whose folder papaia-ctl creates
    # before the start; Compose itself must not create it.
    st.backup.mkdir()
    (st.config / ".env").write_text(f"PAPAIA_BACKUP_DIR={st.backup}\n", encoding="utf-8")
    audit.ensure_heads_folder(st.config)
    clients = st.config / "infra" / "audit" / "clients"
    for source in ("papaia-flow", "papaia-data", "papaia-me"):
        audit.issue_source_certificate(st.config, source)
    # papaia-me's certificate is from the right CA but no longer listed (a revoked or
    # replaced certificate); the foreign one is from another installation's CA.
    listed = st.config / "infra" / "audit" / "service" / "sources.json"
    document = json.loads(listed.read_text(encoding="utf-8"))
    del document["sources"]["papaia-me"]
    listed.write_text(json.dumps(document), encoding="utf-8")
    audit.issue_source_certificate(st.foreign, "papaia-flow")
    st.certs.mkdir()
    for name, directory in (
        ("flow", clients / "papaia-flow"),
        ("data", clients / "papaia-data"),
        ("me", clients / "papaia-me"),
        ("foreign", st.foreign / "infra" / "audit" / "clients" / "papaia-flow"),
    ):
        shutil.copytree(directory, st.certs / name)
    shutil.copyfile(
        st.config / "infra" / "audit" / "service" / "ca.crt", st.certs / "server-ca.crt"
    )
    # The report account's key folder exists before the start, as `papaia-ctl render`
    # makes it; Compose must not create it.
    service_account_keys.KeyStore(st.config / "security" / "service-accounts").generate(
        "svc-papaia-audit-report"
    )
    (own,) = [i for i in own_images.load(REPO) if "papaia-audit" in i.services]
    context = own_images.stage_context(REPO, own, root / "build")
    built = _run("docker", "buildx", "build", "--load", "--provenance=false", "-t", IMAGE,
                 "-f", str(context / own.dockerfile), str(context), check=False)
    assert built.returncode == 0, built.stderr
    quarters = list(SUBNET.subnets(new_prefix=SUBNET.prefixlen + 2))
    st.override.write_text(
        yaml.safe_dump(
            {
                "services": {name: {"image": IMAGE} for name in own.services},
                "networks": {
                    "papaia-audit-net": {"ipam": {"config": [{"subnet": str(quarters[0])}]}},
                    "papaia-audit-ingest-net": {
                        "ipam": {"config": [{"subnet": str(quarters[1])}]}
                    },
                    "papaia-audit-idp-net": {"ipam": {"config": [{"subnet": str(quarters[2])}]}},
                }
            }
        ),
        encoding="utf-8",
    )
    try:
        st.compose("--profile", "audit", "up", "-d", "--wait")
        yield st
    finally:
        st.compose("--profile", "audit", "down", "-v", "--remove-orphans", check=False)
        _run("docker", "image", "rm", IMAGE, check=False)


def test_valid_rows_are_stored_and_a_repeat_keeps_its_seq(stack: Stack):
    first, repeat = stack.deliver(
        ("flow", _batch(_event(1), _event(2), _event(3))),
        ("flow", _batch(_event(3), _event(4))),
    )

    assert first == {
        "status": 200,
        "body": {
            "acknowledged": [
                {"source_seq": 1, "seq": 1},
                {"source_seq": 2, "seq": 2},
                {"source_seq": 3, "seq": 3},
            ]
        },
    }
    assert repeat["body"]["acknowledged"] == [
        {"source_seq": 3, "seq": 3},
        {"source_seq": 4, "seq": 4},
    ]


def test_invalid_rows_are_refused_and_only_the_valid_prefix_is_stored(stack: Stack):
    data = "papaia-data/api"
    refused_first, prefix, gap, foreign_writer = stack.deliver(
        ("data", _batch(_event(1, writer=data, payload="text"))),
        ("data", _batch(_event(1, writer=data), _event(2, writer=data, source="papaia-flow"))),
        ("data", _batch(_event(5, writer=data))),
        ("data", _batch(_event(2, writer="papaia-flow/flow-worker"))),
    )

    assert refused_first == {"status": 422, "body": {"error_code": "audit.invalid_submission"}}
    assert prefix["body"] == {"acknowledged": [{"source_seq": 1, "seq": 1}]}
    assert gap == {"status": 422, "body": {"error_code": "audit.source_seq_gap"}}
    assert foreign_writer["status"] == 422


def test_an_unknown_source_is_refused(stack: Stack):
    unlisted, foreign_ca, without_certificate = stack.deliver(
        ("me", _batch(_event(1, writer="papaia-me"))),
        ("foreign", _batch(_event(1))),
        (None, _batch(_event(1))),
    )

    assert unlisted == {"status": 403, "body": {"error_code": "audit.unknown_source"}}
    assert foreign_ca["status"] is None and without_certificate["status"] is None
    count = stack.psql("read", "SELECT count(*) FROM audit.event WHERE source = 'papaia-me'")
    assert count.stdout.split()[2] == "0"


def test_the_schema_step_runs_again_without_touching_the_store(stack: Stack):
    before = stack.psql("read", "SELECT count(*) FROM audit.event").stdout.split()[2]

    again = stack.compose("--profile", "audit", "run", "--rm", "--no-deps",
                          "papaia-audit-schema", check=False)

    assert again.returncode == 0, again.stderr
    assert "store created" not in again.stderr
    assert stack.psql("read", "SELECT count(*) FROM audit.event").stdout.split()[2] == before
    # The service holds the role passwords (deletion lock, ingest, read, retention), the
    # signing key and the pseudonym key, never the owner's password.
    secrets = stack.compose("exec", "-T", "papaia-audit", "ls", "/run/secrets").stdout.split()
    assert sorted(secrets) == [
        "audit_db_hold_password", "audit_db_ingest_password", "audit_db_read_password",
        "audit_db_retention_password", "audit_heads_key", "audit_pseudonym_key",
    ]
    tables = stack.psql("read", "SELECT count(*) FROM audit.person_query")
    assert tables.returncode == 0, tables.stderr


def test_service_credentials_cannot_change_or_remove_rows(stack: Stack):
    for role in ("ingest", "read", "hold"):
        for sql in (
            "UPDATE audit.event SET result = 'denied'",
            "DELETE FROM audit.event",
            "TRUNCATE audit.event",
            "INSERT INTO audit.event SELECT * FROM audit.event LIMIT 1",
        ):
            result = stack.psql(role, sql)
            assert result.returncode != 0, (role, sql)
            assert "permission denied" in result.stderr
    # Even the owner cannot change a row while the triggers are in place.
    owner = stack.psql("owner", "UPDATE audit.event SET result = 'denied'")
    assert "cannot be changed or removed" in owner.stderr


def test_the_verification_job_finds_a_tampered_row_and_a_cut_chain(stack: Stack):
    clean = stack.service("verify", "--json")
    assert clean.returncode == 0, clean.stderr
    reports = {r["source"]: r for r in json.loads(clean.stdout)["sources"]}
    assert reports["papaia-flow"] == {
        "source": "papaia-flow",
        "valid": True,
        "count": 4,
        "head_seq": 4,
        "broken_at": None,
        "reason": None,
        "anchor_seq": 0,
    }
    heads = stack.service("heads", check=True).stdout
    assert stack.service("verify", "--against", "-", stdin=heads).returncode == 0

    # A test intervention with the owner's rights, past the update and delete triggers:
    # change event 2 of papaia-flow and remove the only event of papaia-data.
    tamper = stack.psql(
        "owner",
        (
            "ALTER TABLE audit.event DISABLE TRIGGER event_no_update;"
            "ALTER TABLE audit.event DISABLE TRIGGER event_delete_only_by_prune;"
            "UPDATE audit.event SET body = jsonb_set(body, '{result}', '\"denied\"'),"
            " result = 'denied' WHERE source = 'papaia-flow' AND seq = 2;"
            "DELETE FROM audit.event WHERE source = 'papaia-data' AND seq = 1;"
            "ALTER TABLE audit.event ENABLE TRIGGER event_delete_only_by_prune;"
            "ALTER TABLE audit.event ENABLE TRIGGER event_no_update;"
        ),
    )
    assert tamper.returncode == 0, tamper.stderr

    broken = stack.service("verify")
    assert broken.returncode == 1
    assert "papaia-flow: broken at seq 2 (event changed)" in broken.stdout
    # papaia-data's only event is gone: alone the chain looks empty and valid; the signed
    # head shows that it is not.
    assert (
        "papaia-data: valid"
        not in stack.service(
            "verify", "--source", "papaia-data", "--against", "-", stdin=heads
        ).stdout
    )

    forged = heads.replace('"seq":4', '"seq":5')
    rejected = stack.service("verify", "--against", "-", stdin=forged)
    assert rejected.returncode != 0
    assert "not signed by this installation" in rejected.stderr
