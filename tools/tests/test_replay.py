"""papaia-replay: deletions in chat and model gateway for the core start gate
(docs/replay.md; architektur A-02, sicherheit §3.3 and §4.9 (2a), RE-99, RE-105).

papaia-lifecycle holds `manage-users` and must not reach the databases of chat and model
gateway. papaia-replay deletes there on its behalf: one endpoint over mutual TLS, three
fixed request kinds, answers with counts only, one audit row per request.

The service runs from its own image, so `replay.py` is imported straight from the
checkout. The chat database is an in-memory stand-in that understands the two commands
the service sends (and refuses collections outside the role); the model gateway is a
small HTTP server with the management routes. The certificates come from the platform
PKI (lib/pki.py), and the caller is papaia-lifecycle's own `ReplayClient`.
"""

from __future__ import annotations

import base64
import http.server
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
import urllib.error
import urllib.parse
from pathlib import Path

import pytest
import yaml

from lib import pki, replay_access
from tests.test_lifecycle import lc

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "replay"
ANNA = "0b9c7b1e-1c1f-4e55-9a51-2f7c0c3d4e5f"
BEN = "5d0f6a2b-8e1c-4a7d-b3f2-9c8e7d6a5b4c"
GATEWAY_KEY = "test-gateway-key-value"
CORRELATION = "3f2e1d0c-9b8a-4776-8665-544332211000"


def _service_module():
    path = MODULE_DIR / "replay.py"
    module = types.ModuleType("papaia_replay_service")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


rp = _service_module()


# ─────────────────────────────────────────────────────────────────────────
# compose: networks, mounts, hardening
# ─────────────────────────────────────────────────────────────────────────


def _yaml(rel: str) -> dict:
    return yaml.safe_load((REPO / rel).read_text(encoding="utf-8"))


def _services_on(network: str) -> set[str]:
    found = set()
    for path in (REPO / "src").rglob("docker-compose*.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            nets = (body or {}).get("networks") or []
            if network in nets:
                found.add(name)
    return found


def test_the_root_compose_includes_the_replay_file():
    root = _yaml("src/docker-compose.yml")
    assert {"path": "./infra/replay/docker-compose.yml"} in root["include"]


def test_each_replay_network_is_internal_and_shared_with_one_peer_only():
    doc = _yaml("src/infra/replay/docker-compose.yml")
    for net in ("papaia-replay-net", "papaia-replay-chat-net", "papaia-replay-gw-net"):
        assert doc["networks"][net]["internal"] is True
    assert _services_on("papaia-replay-net") == {"papaia-replay", "papaia-lifecycle"}
    assert _services_on("papaia-replay-chat-net") == {"papaia-replay", "librechat-mongodb"}
    assert _services_on("papaia-replay-gw-net") == {"papaia-replay", "litellm"}


def test_the_service_has_three_networks_no_port_no_identity_key_and_is_hardened():
    service = _yaml("src/infra/replay/docker-compose.yml")["services"]["papaia-replay"]
    assert service["networks"] == [
        "papaia-replay-net", "papaia-replay-chat-net", "papaia-replay-gw-net"
    ]
    assert "ports" not in service and "expose" not in service
    assert service["profiles"] == ["lifecycle"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["image"].startswith("ghcr.io/fidonis/papaia-replay:")
    sources = [m["source"] for m in service["volumes"]]
    assert sources == [
        "${PAPAIA_CONFIG_DIR}/pki/core/papaia-replay", "${PAPAIA_CONFIG_DIR}/security/replay"
    ]
    assert all(m["read_only"] is True for m in service["volumes"])
    assert not any("erasure-hmac" in s or "service-accounts" in s for s in sources)
    assert "env_file" not in service


def test_lifecycle_reaches_replay_but_no_database_of_chat_or_gateway():
    service = _yaml("src/infra/lifecycle/docker-compose.yml")["services"]["papaia-lifecycle"]
    assert service["networks"] == ["papaia-lifecycle-net", "papaia-replay-net"]
    command = service["command"]
    assert "--replay-url=https://papaia-replay:8443" in command
    for flag in ("--pki-ca=", "--client-cert=", "--client-key="):
        assert any(arg.startswith(flag + "/run/papaia-lifecycle/tls/") for arg in command)
    assert "${PAPAIA_CONFIG_DIR}/pki/core/papaia-lifecycle" in [
        m["source"] for m in service["volumes"]
    ]


def test_replay_asks_for_a_server_certificate_with_the_lifecycle_profile():
    doc = _yaml("src/infra/replay/pki.yaml")
    requests = pki.core_requests(REPO, {"lifecycle"})
    assert doc["profile"] == "lifecycle"
    assert pki.ServiceRequest("core", "papaia-replay", None, ("papaia-replay",), False) in requests
    assert not [r for r in pki.core_requests(REPO, set()) if r.name == "papaia-replay"]


def test_no_add_on_may_attach_replay():
    from lib import compat

    assert "papaia-replay" in compat.NEVER_ATTACHABLE


def test_the_role_covers_exactly_the_collections_the_service_deletes_in():
    used = {rp.ACCOUNTS} | {coll for coll, _, _ in rp.CHAT_OBJECTS}
    assert set(replay_access.CHAT_COLLECTIONS) == used
    assert len(replay_access.CHAT_COLLECTIONS) == len(used)


# ─────────────────────────────────────────────────────────────────────────
# request validation
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"kind": "erase_subject", "sub": ANNA},
        {"kind": "chat_sessions_reset"},
        {"kind": "key_revoke", "key_id": "a" * 64},
    ],
)
def test_the_three_fixed_request_kinds_are_accepted(body):
    assert rp.parse_job(json.dumps(body).encode()) == body


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"kind": "export", "sub": "x"}', "unknown_kind"),
        (b'{"kind": "erase_subject"}', "unknown_or_missing_field"),
        (b'{"kind": "erase_subject", "sub": "x", "extra": 1}', "unknown_or_missing_field"),
        (b'{"kind": "chat_sessions_reset", "sub": "x"}', "unknown_or_missing_field"),
        (b'{"kind": "key_revoke"}', "unknown_or_missing_field"),
        (b'{"kind": "erase_subject", "sub": "a b"}', "malformed_sub"),
        (b'{"kind": "erase_subject", "sub": 7}', "malformed_sub"),
        (b'{"kind": "erase_subject", "sub": "' + b"a" * 65 + b'"}', "malformed_sub"),
        (b'{"kind": "key_revoke", "key_id": "../x"}', "malformed_key_id"),
        (b'{"kind": "chat_sessions_reset", "kind": "key_revoke"}', "duplicate_field"),
        (b'["chat_sessions_reset"]', "malformed_json"),
        (b'{"kind": NaN}', "malformed_json"),
        (b"\xff", "malformed_json"),
        (b'{"kind": "chat_sessions_reset", "pad": "' + b"x" * 2000 + b'"}', "too_large"),
    ],
)
def test_every_other_body_is_refused(raw, code):
    with pytest.raises(rp.BadRequest) as exc:
        rp.parse_job(raw)
    assert exc.value.code == code


# ─────────────────────────────────────────────────────────────────────────
# wire protocol of the chat database
# ─────────────────────────────────────────────────────────────────────────


def test_bson_round_trip_of_the_types_the_commands_use():
    oid = rp.ObjectId(bytes(range(12)))
    doc = {"a": 1, "b": 1 << 40, "c": 1.5, "d": "x", "e": True, "f": None, "g": oid,
           "h": b"\x00\x01", "i": {"j": [1, "k", oid]}}
    back = rp.bson_decode(rp.bson_encode(doc))
    assert back == doc
    assert isinstance(back["g"], rp.ObjectId)


def test_bson_refuses_a_document_whose_size_lies():
    data = bytearray(rp.bson_encode({"a": "b"}))
    data[0] += 1
    with pytest.raises(ValueError):
        rp.bson_decode(bytes(data))


def test_op_msg_frames_one_document_and_reads_it_back():
    frame = rp.op_msg(7, {"ping": 1, "$db": "admin"})
    stream = io.BytesIO(frame)
    assert rp.read_op_msg(stream.read) == {"ping": 1, "$db": "admin"}


def test_scram_sha_256_matches_the_rfc_7677_example():
    scram = rp.Scram("user", "pencil", nonce="rOprNGfwEbeRWgbNEkqO")
    assert scram.first() == b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
    final = scram.final(
        b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
    )
    assert final == (
        b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
    )
    scram.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
    with pytest.raises(rp.ReplayError):
        scram.verify(b"v=" + base64.b64encode(b"\x00" * 32))


def test_scram_refuses_a_nonce_the_client_did_not_start():
    scram = rp.Scram("user", "pencil", nonce="abc")
    with pytest.raises(rp.ReplayError):
        scram.final(b"r=xyz123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")


# ─────────────────────────────────────────────────────────────────────────
# stand-ins: chat database and model gateway
# ─────────────────────────────────────────────────────────────────────────


def _oid(n: int):
    return rp.ObjectId(n.to_bytes(12, "big"))


class FakeChatDb:
    """The chat database as the role papaia-replay-chat sees it: find and delete on the
    role's collections, everything else refused."""

    def __init__(self) -> None:
        self.data: dict[str, list[dict]] = {}
        self.commands: list[dict] = []
        self.closed = 0

    def seed(self, sub: str, account) -> None:
        text = account.hex()
        self.data.setdefault("users", []).append(
            {"_id": account, "openidId": sub, "email": f"{sub}@example.org"}
        )
        for coll, field, _ in rp.CHAT_OBJECTS:
            # Some collections file the account as a string, others as an object id.
            ref = text if field == "user" and coll in ("conversations", "messages") else account
            self.data.setdefault(coll, []).append({field: ref, "text": f"secret of {sub}"})
        self.data["conversations"].append({"user": text, "title": f"second of {sub}"})

    def command(self, doc: dict) -> dict:
        self.commands.append(doc)
        name = next(iter(doc))
        coll = doc[name]
        if coll not in replay_access.CHAT_COLLECTIONS:
            return {"ok": 0, "codeName": "Unauthorized"}
        rows = self.data.setdefault(coll, [])
        if name == "find":
            (field, value), = doc["filter"].items()
            hits = [r for r in rows if r.get(field) == value]
            return {"ok": 1, "cursor": {"firstBatch": [{"_id": r["_id"]} for r in hits]}}
        if name == "delete":
            (spec,) = doc["deletes"]
            flt = spec["q"]
            if not flt:
                n = len(rows)
                rows.clear()
                return {"ok": 1, "n": n}
            (field, cond), = flt.items()
            keep = [r for r in rows if r.get(field) not in cond["$in"]]
            n = len(rows) - len(keep)
            rows[:] = keep
            return {"ok": 1, "n": n}
        return {"ok": 0, "codeName": "CommandNotFound"}

    def close(self) -> None:
        self.closed += 1

    def holds(self, needle: str) -> bool:
        return needle in repr(self.data)


class FakeGateway:
    """The gateway's management routes for end users and keys, with the key check."""

    def __init__(self) -> None:
        self.end_users = {ANNA, BEN}
        self.keys = {"k" * 64}
        self.calls: list[tuple[str, str]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _reply(self, status: int, doc: dict) -> None:
                body = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                if self.headers.get("Authorization") != f"Bearer {GATEWAY_KEY}":
                    self._reply(401, {"error": "auth"})
                    return False
                return True

            def do_GET(self):  # noqa: N802
                outer.calls.append(("GET", self.path))
                if not self._authorized():
                    return
                parts = urllib.parse.urlsplit(self.path)
                user = urllib.parse.parse_qs(parts.query).get("end_user_id", [""])[0]
                if parts.path == "/customer/info" and user in outer.end_users:
                    self._reply(200, {"user_id": user, "spend": 1.5})
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                outer.calls.append(("POST", self.path))
                if not self._authorized():
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/customer/delete":
                    outer.end_users -= set(body["user_ids"])
                    self._reply(200, {"deleted": body["user_ids"]})
                elif self.path == "/key/delete":
                    gone = [k for k in body["keys"] if k in outer.keys]
                    outer.keys -= set(gone)
                    self._reply(200 if gone else 404, {"deleted_keys": gone})
                else:
                    self._reply(404, {})

            def log_message(self, *args) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ─────────────────────────────────────────────────────────────────────────
# the service over mutual TLS, called by papaia-lifecycle's own client
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def certs(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text("COMPOSE_PROFILES=lifecycle\n", encoding="utf-8")
    pki.issue(config, [
        pki.ServiceRequest("core", "papaia-replay", None, ("papaia-replay",), False),
        pki.ServiceRequest("core", "papaia-lifecycle", None, ("papaia-lifecycle",), True),
        # Another core service with a client certificate of the same CA.
        pki.ServiceRequest("core", "papaia-audit", None, (), True),
    ])  # fmt: skip
    return config / "pki" / "core"


@pytest.fixture
def service(certs, tmp_path, monkeypatch):
    db = FakeChatDb()
    db.seed(ANNA, _oid(1))
    db.seed(BEN, _oid(2))
    db.data["sessions"].append({"user": _oid(3), "refreshTokenHash": "h"})
    gateway = FakeGateway()
    key_file = tmp_path / "gateway-key"
    key_file.write_text(GATEWAY_KEY + "\n", encoding="utf-8")
    out = io.StringIO()
    replayer = rp.Replayer(lambda: rp.Chat(db), rp.Gateway(gateway.url, key_file), out)
    server = rp.make_server("127.0.0.1", 0, rp.server_context(certs / "papaia-replay"), replayer)
    port = server.server_address[1]
    real = socket.getaddrinfo

    def resolve(host, *args, **kwargs):
        return real("127.0.0.1" if host == "papaia-replay" else host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield types.SimpleNamespace(
        db=db, gateway=gateway, out=out, url=f"https://papaia-replay:{port}", certs=certs
    )
    server.shutdown()
    server.server_close()
    gateway.stop()


def _client(svc, name: str = "papaia-lifecycle"):
    folder = svc.certs / name
    ctx = lc.mtls_context(folder / "ca.crt", folder / "client.crt", folder / "client.key")
    return lc.ReplayClient(svc.url, ctx)


def _rows(out: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def test_erase_subject_deletes_the_persons_chat_data_and_usage_and_answers_counts_only(service):
    counts = _client(service).run("erase_subject", CORRELATION, sub=ANNA)
    # Counts only: every value a number, nothing of the person or her data.
    assert all(isinstance(v, int) for v in counts.values())
    assert counts["chat_accounts"] == 1
    assert counts["chat_conversations"] == 2
    assert counts["chat_messages"] == 1
    assert counts["chat_transactions"] == 1
    assert counts["gateway_end_users"] == 1
    assert ANNA not in json.dumps(counts)
    # Anna's chat data and usage are gone; Ben's stay.
    assert not service.db.holds(ANNA)
    assert service.db.holds(BEN)
    assert service.gateway.end_users == {BEN}
    # Only the accounts are read, and only their `_id`.
    finds = [c for c in service.db.commands if "find" in c]
    assert finds == [{"find": "users", "filter": {"openidId": ANNA}, "projection": {"_id": 1},
                      "limit": rp.MAX_ACCOUNTS + 1, "singleBatch": True}]
    # One audit row with the counts and the caller's correlation id.
    (row,) = _rows(service.out)
    assert row["format"] == "papaia.audit/1"
    assert row["correlation_id"] == CORRELATION
    assert row["operation"] == "replay.erase_subject"
    assert row["result"] == "allowed"
    assert row["detail"] == {"kind": "erase_subject", "counts": counts}
    assert row["object_ref"] == {"type": "user", "id": ANNA}
    assert "secret" not in service.out.getvalue()


def test_a_repeated_erase_finds_nothing_and_still_succeeds(service):
    _client(service).run("erase_subject", CORRELATION, sub=ANNA)
    counts = _client(service).run("erase_subject", CORRELATION, sub=ANNA)
    assert counts["chat_accounts"] == 0 and counts["gateway_end_users"] == 0
    assert service.db.holds(BEN)


def test_chat_sessions_reset_deletes_every_stored_session(service):
    assert _client(service).run("chat_sessions_reset", CORRELATION) == {"chat_sessions": 3}
    assert service.db.data["sessions"] == []
    assert service.db.holds(ANNA) and service.db.holds(BEN)


def test_key_revoke_deletes_the_gateway_key_once(service):
    client = _client(service)
    assert client.run("key_revoke", CORRELATION, key_id="k" * 64) == {"gateway_keys": 1}
    assert client.run("key_revoke", CORRELATION, key_id="k" * 64) == {"gateway_keys": 0}
    assert service.gateway.keys == set()
    paths = {path for _, path in service.gateway.calls}
    assert paths == {"/key/delete"}


def test_a_request_from_another_container_is_refused(service):
    with pytest.raises(lc.HttpError) as exc:
        _client(service, "papaia-audit").run("erase_subject", CORRELATION, sub=ANNA)
    assert exc.value.status == 403
    assert service.db.holds(ANNA)
    assert service.gateway.end_users == {ANNA, BEN}
    (row,) = _rows(service.out)
    assert (row["result"], row["error_code"], row["azp"]) == (
        "denied", "caller_not_allowed", "papaia-audit"
    )


def test_a_caller_without_a_client_certificate_gets_no_connection(service):
    folder = service.certs / "papaia-lifecycle"
    ctx = ssl.create_default_context(cafile=str(folder / "ca.crt"))
    with pytest.raises((ssl.SSLError, OSError, urllib.error.URLError)):
        lc.ReplayClient(service.url, ctx).run("chat_sessions_reset", CORRELATION)
    assert service.db.data["sessions"]


def test_a_malformed_request_is_refused_and_audited(service):
    folder = service.certs / "papaia-lifecycle"
    ctx = lc.mtls_context(folder / "ca.crt", folder / "client.crt", folder / "client.key")
    req = urllib.request.Request(
        f"{service.url}/replay", data=b'{"kind": "erase_subject", "sub": "x", "all": true}',
        method="POST", headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, context=ctx, timeout=10)
    assert exc.value.code == 400
    assert service.db.holds(ANNA)
    (row,) = _rows(service.out)
    assert (row["result"], row["error_code"]) == ("denied", "unknown_or_missing_field")


def test_a_failing_backend_answers_502_without_detail_and_is_audited(service):
    service.gateway.stop()
    with pytest.raises(lc.HttpError) as exc:
        _client(service).run("erase_subject", CORRELATION, sub=ANNA)
    assert exc.value.status == 502
    # The gateway goes first, so the chat account is still there for the retry.
    assert service.db.holds(ANNA)
    (row,) = _rows(service.out)
    assert (row["result"], row["error_code"]) == ("error", "backend_failed")


def test_without_chat_and_gateway_there_is_nothing_to_delete():
    replayer = rp.Replayer(None, None, io.StringIO())
    assert replayer.run({"kind": "erase_subject", "sub": ANNA}) == {}
    assert replayer.run({"kind": "chat_sessions_reset"}) == {}
    assert replayer.run({"kind": "key_revoke", "key_id": "k"}) == {}


def test_the_gateway_adapter_calls_its_three_routes_only(tmp_path):
    key = tmp_path / "k"
    key.write_text(GATEWAY_KEY, encoding="utf-8")
    gateway = rp.Gateway("http://litellm:4000", key)
    with pytest.raises(rp.ReplayError):
        gateway._call("POST", "/key/generate", {})
    with pytest.raises(ValueError):
        rp.Gateway("http://litellm:4000/admin", key)


# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl: the logins and the chat role
# ─────────────────────────────────────────────────────────────────────────


def _config(tmp_path: Path, profiles: str, master: str = "test-master-key-value") -> Path:
    config = tmp_path / "config"
    (config / "ai" / "litellm").mkdir(parents=True)
    (config / ".env").write_text(f"COMPOSE_PROFILES={profiles}\n"
                                 "COMPOSE_PROJECT_NAME=papaia-test\n", encoding="utf-8")
    (config / "ai" / "litellm" / ".env").write_text(f"LITELLM_MASTER_KEY={master}\n",
                                                   encoding="utf-8")
    return config


def test_render_writes_the_logins_private_and_only_for_active_profiles(tmp_path):
    config = _config(tmp_path, "keycloak,lifecycle,librechat,litellm")
    replay_access.render(config)
    folder = config / "security" / "replay"
    assert oct(folder.stat().st_mode & 0o777) == "0o700"
    password = (folder / "chat-password").read_text(encoding="ascii")
    assert len(password.strip()) >= 40
    assert (folder / "gateway-key").read_text(encoding="ascii") == "test-master-key-value\n"
    for name in ("chat-password", "gateway-key"):
        assert oct((folder / name).stat().st_mode & 0o777) == "0o600"
    # Made once: a second render keeps the password.
    replay_access.render(config)
    assert (folder / "chat-password").read_text(encoding="ascii") == password
    # A profile switched off takes its login away.
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,lifecycle\n", encoding="utf-8")
    replay_access.render(config)
    assert folder.is_dir()
    assert sorted(p.name for p in folder.iterdir()) == []


def test_render_without_the_lifecycle_profile_leaves_no_login(tmp_path):
    config = _config(tmp_path, "keycloak,lifecycle,librechat,litellm")
    replay_access.render(config)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,librechat,litellm\n",
                                 encoding="utf-8")
    replay_access.render(config)
    assert list((config / "security" / "replay").iterdir()) == []


def test_render_never_copies_a_placeholder_master_key(tmp_path):
    config = _config(tmp_path, "lifecycle,litellm", master="GENERATE_LITELLM_MASTER_KEY")
    replay_access.render(config)
    assert not (config / "security" / "replay" / "gateway-key").exists()


def test_the_role_script_grants_find_and_remove_on_the_chat_collections_only():
    script = replay_access.role_script("pw-test-value-0123456789")
    spec = json.loads(script.split("const spec = ", 1)[1].split(";\n", 1)[0])
    assert spec["role"] == "papaia-replay-chat"
    assert {p["resource"]["db"] for p in spec["privileges"]} == {"LibreChat"}
    assert [p["resource"]["collection"] for p in spec["privileges"]] == list(
        replay_access.CHAT_COLLECTIONS
    )
    assert all(p["actions"] == ["find", "remove"] for p in spec["privileges"])
    assert "roles: []" in script


def test_sync_chat_role_passes_the_password_on_stdin_and_audits(tmp_path):
    config = _config(tmp_path, "lifecycle,librechat")
    replay_access.render(config)
    password = (config / "security" / "replay" / "chat-password").read_text().strip()
    calls = []

    def runner(cmd, stdin, timeout):
        calls.append((cmd, stdin))
        if cmd[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")
        return subprocess.CompletedProcess(cmd, 0, 'PAPAIA_REPLAY_ROLE {"collections":17}\n', "")

    assert replay_access.sync_chat_role(config, runner=runner) == "synced"
    (ps, _), (exec_cmd, stdin) = calls
    assert "label=com.docker.compose.service=librechat-mongodb" in ps
    assert "label=com.docker.compose.project=papaia-test" in ps
    assert exec_cmd[:4] == ["docker", "exec", "-i", "abc123"]
    assert password not in " ".join(exec_cmd)
    assert password in stdin
    log = (config / "audit").rglob("*.jsonl")
    text = "".join(p.read_text() for p in log)
    assert '"replay_chat_role"' in text and password not in text


def test_sync_chat_role_reports_a_refusal_without_repeating_the_output(tmp_path):
    config = _config(tmp_path, "lifecycle,librechat")
    replay_access.render(config)

    def runner(cmd, stdin, timeout):
        if cmd[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")
        return subprocess.CompletedProcess(cmd, 1, stdin, "error near " + stdin)

    with pytest.raises(replay_access.ReplayAccessError) as exc:
        replay_access.sync_chat_role(config, runner=runner)
    assert "pwd" not in str(exc.value)


def test_sync_chat_role_skips_without_its_profiles_and_without_the_database(tmp_path):
    config = _config(tmp_path, "lifecycle,litellm")
    assert replay_access.sync_chat_role(config, runner=None) == "skipped"
    config = _config(tmp_path / "b", "lifecycle,librechat")
    replay_access.render(config)

    def runner(cmd, stdin, timeout):
        return subprocess.CompletedProcess(cmd, 0, "", "")

    assert replay_access.sync_chat_role(config, runner=runner) == "absent"


# ─────────────────────────────────────────────────────────────────────────
# live: the chat database of the pinned image, the role and the real client
# ─────────────────────────────────────────────────────────────────────────

MONGO_IMAGE = _yaml("src/ai/librechat/docker-compose.yml")["services"]["librechat-mongodb"][
    "image"
]
LIVE_NAME = os.environ.get("PAPAIA_REPLAY_TEST_PROJECT", "papaia-replay-test")
LIVE_PORT = int(os.environ.get("PAPAIA_REPLAY_TEST_PORT", "64360"))


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20,
                              check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _mongosh(script: str) -> str:
    done = subprocess.run(
        ["docker", "exec", "-i", LIVE_NAME, "mongosh", "--quiet", "--norc",
         "mongodb://127.0.0.1:27017/admin"],
        input=script, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    return done.stdout


@pytest.mark.skipif(not _docker_available(), reason="Docker is not available")
def test_live_the_role_login_deletes_one_persons_chat_data_in_the_pinned_database(tmp_path):
    subprocess.run(["docker", "rm", "-f", LIVE_NAME], capture_output=True, check=False)
    started = subprocess.run(
        ["docker", "run", "-d", "--name", LIVE_NAME, "-p", f"127.0.0.1:{LIVE_PORT}:27017",
         MONGO_IMAGE, "mongod", "--noauth"],
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert started.returncode == 0, started.stderr
    try:
        for _ in range(60):
            ready = subprocess.run(
                ["docker", "exec", LIVE_NAME, "mongosh", "--quiet", "--eval",
                 "db.adminCommand('ping').ok"], capture_output=True, text=True, check=False,
            )  # fmt: skip
            if ready.stdout.strip() == "1":
                break
            time.sleep(1)
        password = "live-test-password-" + os.urandom(8).hex()
        assert replay_access.RESULT_MARKER in _mongosh(replay_access.role_script(password))
        # Applying it again (every `start`) updates in place.
        assert replay_access.RESULT_MARKER in _mongosh(replay_access.role_script(password))
        _mongosh(
            "const c = db.getSiblingDB('LibreChat');\n"
            f"const a = c.users.insertOne({{openidId: '{ANNA}'}}).insertedId;\n"
            f"const b = c.users.insertOne({{openidId: '{BEN}'}}).insertedId;\n"
            "for (const [u, t] of [[a, 'anna'], [b, 'ben']]) {\n"
            "  c.conversations.insertOne({user: u.toString(), title: t});\n"
            "  c.messages.insertOne({user: u.toString(), text: t});\n"
            "  c.files.insertOne({user: u, filename: t});\n"
            "  c.sessions.insertOne({user: u});\n"
            "}\n"
        )
        secret = tmp_path / "chat-password"
        secret.write_text(password + "\n", encoding="ascii")
        chat = rp.Chat(rp.Mongo("127.0.0.1", LIVE_PORT, secret))
        try:
            accounts = chat.accounts(ANNA)
            counts = chat.erase(accounts)
        finally:
            chat.close()
        assert len(accounts) == 1
        assert (counts["chat_accounts"], counts["chat_conversations"], counts["chat_messages"],
                counts["chat_files"], counts["chat_sessions"]) == (1, 1, 1, 1, 1)
        left = _mongosh(
            "const c = db.getSiblingDB('LibreChat');\n"
            "print('LEFT ' + JSON.stringify([c.users.countDocuments(),"
            " c.conversations.countDocuments(), c.messages.countDocuments({text: 'anna'}),"
            " c.messages.countDocuments()]));\n"
        )
        assert json.loads(left.split("LEFT ", 1)[1].splitlines()[0]) == [1, 1, 0, 1]
        # A wrong password is refused at sign-in.
        secret.write_text("wrong-password-0123456789\n", encoding="ascii")
        with pytest.raises(rp.ReplayError):
            rp.Chat(rp.Mongo("127.0.0.1", LIVE_PORT, secret)).accounts(BEN)
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", LIVE_NAME], capture_output=True, check=False)
