"""papaia-chat-relay: the chat reaches a tool server outside the suite only with a token
whose only audience is that server's (ADR 0029).

The service (`src/infra/chat-relay/relay.py`) is one standard-library file in the core's
own image `ghcr.io/fidonis/papaia-chat-relay`, so it is imported here straight from the
checkout, like papaia-people. Tokens are signed with a throwaway RSA key of the realm
(openssl). The identity provider's token exchange and the add-on's tool server are
stand-ins that record what reaches them; the end-to-end tests run all three over real
sockets on the loopback interface.
"""

from __future__ import annotations

import base64
import http.client
import http.server
import io
import json
import socket
import subprocess
import sys
import threading
import time
import types
import urllib.parse
from pathlib import Path

import jsonschema
import pytest
import yaml

from tests.test_people import ISSUER, Signer

REPO = Path(__file__).resolve().parents[2]
MODULE_DIR = REPO / "src" / "infra" / "chat-relay"
AUDIT_SCHEMA = REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json"
ANNA = "0b9c7b1e-1c1f-4e55-9a51-2f7c0c3d4e5f"
BEN = "5d0f6a2b-8e1c-4a7d-b3f2-9c8e7d6a5b4c"
NOW = 1_790_000_000
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TARGET = "mcp-paperless"


def _service_module():
    path = MODULE_DIR / "relay.py"
    module = types.ModuleType("papaia_chat_relay_service")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


cr = _service_module()


# ─────────────────────────────────────────────────────────────────────────
# fixtures
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    return Signer(tmp_path_factory.mktemp("realm-key"))


@pytest.fixture(scope="module")
def stranger(tmp_path_factory):
    """A key the realm does not publish, with the realm key's kid."""
    return Signer(tmp_path_factory.mktemp("other-key"))


def chat_token(signer, **claims) -> str:
    base = {
        "aud": ["mcp-qdrant", "papaia-chat-relay"],
        "azp": "librechat",
        "sub": ANNA,
        "sid": "4f1c9a7e-2b3d-4c5e-8f6a-7b8c9d0e1f2a",
        "iat": NOW - 10,
        "exp": NOW + 230,
    }
    base.update(claims)
    return signer.token(**base)


SEARCH = {
    "name": "search_documents",
    "title": "Search documents",
    "description": "Full text search over the documents the person may read.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 200},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
    "effect": "read",
    "data_class_max": "confidential",
}
TAG = {
    "name": "tag_document",
    "title": "Tag a document",
    "description": "Adds a tag to one document.",
    "input_schema": {
        "type": "object",
        "properties": {"id": {"type": "integer"}, "tag": {"type": "string"}},
        "required": ["id", "tag"],
        "additionalProperties": False,
    },
    "effect": "write",
    "data_class_max": "internal",
}


def servers_doc(address="http://paperless-connect:8000/mcp", tools=(SEARCH, TAG)) -> dict:
    return {
        "format": "papaia.chat-relay-servers/1",
        "servers": [
            {
                "audience": TARGET,
                "scope": "aud-mcp-paperless",
                "addon": "paperless-connect",
                "catalog_id": "paperless-connect.mcp",
                "address": address,
                "data_class_max": "confidential",
                "tools": [dict(tool) for tool in tools],
            }
        ],
    }


def write_servers(folder: Path, doc: dict | None) -> Path:
    path = folder / "servers.json"
    if doc is not None:
        path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class FakeIdp:
    """Keycloak's standard token exchange as the relay uses it: records every form and
    answers with a token for the one audience of the requested `aud-*` scope."""

    def __init__(self, signer, now=NOW, **answer) -> None:
        self.signer, self.forms, self.answer, self.now = signer, [], answer, now
        self.fail: Exception | None = None

    def exchange(self, form: dict) -> dict:
        self.forms.append(dict(form))
        if self.fail is not None:
            raise self.fail
        subject = form["subject_token"]
        claims = json.loads(base64.urlsafe_b64decode(subject.split(".")[1] + "=="))
        audience = form["scope"].removeprefix("aud-")
        token_claims = {
            "aud": audience,
            "azp": "papaia-chat-relay",
            "sub": claims["sub"],
            "sid": claims.get("sid"),
            "iat": self.now,
            "exp": self.now + 240,
            "scope": form["scope"],
        }
        token_claims.update(self.answer.pop("claims", {}))
        body = {
            "access_token": self.signer.token(**token_claims),
            "token_type": "Bearer",
            "expires_in": 240,
            "issued_token_type": ACCESS,
        }
        body.update(self.answer)
        return body


class FakeUpstream:
    """The add-on's tool server: records every request (headers and body)."""

    def __init__(self, result=None, error=None) -> None:
        self.requests: list[dict] = []
        self.result = result if result is not None else {
            "content": [{"type": "text", "text": "3 documents"}],
            "isError": False,
        }
        self.error = error

    def __call__(self, address, token, correlation, name, arguments, deadline):
        self.requests.append(
            {
                "address": address,
                "token": token,
                "correlation": correlation,
                "name": name,
                "arguments": arguments,
            }
        )
        if self.error is not None:
            raise self.error
        return {"jsonrpc": "2.0", "id": 3, "result": self.result}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def relay_factory(signer, tmp_path):
    def make(doc=None, *, idp=None, upstream=None, missing=False):
        idp = idp or FakeIdp(signer)
        upstream = upstream or FakeUpstream()
        path = write_servers(tmp_path, None if missing else (doc or servers_doc()))
        out = io.StringIO()
        relay = cr.Relay(
            cr.TokenVerifier(cr.Keys(lambda: {"keys": [signer.jwk()]}), ISSUER, wall=lambda: NOW),
            cr.ServerList(path),
            idp.exchange,
            upstream,
            wall=lambda: NOW,
            clock=Clock(),
            out=out,
        )
        relay.idp, relay.upstream, relay.audit_out = idp, upstream, out
        return relay

    return make


def rpc(method, params=None, rid=1, **extra) -> bytes:
    body = {"jsonrpc": "2.0", "method": method, **extra}
    if rid is not None:
        body["id"] = rid
    if params is not None:
        body["params"] = params
    return json.dumps(body).encode()


def call(relay, token, body, *, audience=TARGET, correlation=None, content_type="application/json"):
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if correlation is not None:
        headers["X-Papaia-Correlation-Id"] = correlation
    status, out_headers, raw = relay.handle(
        "POST", f"/servers/{audience}/mcp", headers, body
    )
    return status, out_headers, (json.loads(raw) if raw else None)


def rows(relay) -> list[dict]:
    return [json.loads(line) for line in relay.audit_out.getvalue().splitlines()]


TOOL_CALL = {"name": "search_documents", "arguments": {"query": "invoice 2026", "limit": 3}}


# ─────────────────────────────────────────────────────────────────────────
# the chat token
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "mcp-qdrant"},  # wrong aud: not for the relay
        {"aud": ["mcp-qdrant"]},
        {"exp": NOW - 31},  # expired beyond the clock skew
        {"iss": "https://other.example.test/realms/papaia"},
        {"iat": NOW + 120},
    ],
)
def test_a_token_that_does_not_check_is_refused_before_any_exchange(relay_factory, signer, claims):
    relay = relay_factory()
    status, headers, body = call(relay, chat_token(signer, **claims), rpc("tools/call", TOOL_CALL))
    assert status == 401
    assert headers["WWW-Authenticate"].startswith("Bearer")
    assert body["error"]["data"]["error_code"] == "token_invalid"
    assert relay.idp.forms == [] and relay.upstream.requests == []


def test_an_unsigned_or_foreign_token_is_refused(relay_factory, signer, stranger):
    relay = relay_factory()
    good = chat_token(signer)
    head, claims, _ = good.split(".")
    none_head = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    for token in (f"{none_head}.{claims}.", f"{head}.{claims}.", chat_token(stranger), "x.y"):
        assert call(relay, token, rpc("tools/call", TOOL_CALL))[0] == 401
    assert call(relay, None, rpc("tools/call", TOOL_CALL))[0] == 401
    assert relay.idp.forms == []
    # Without a verified identity there is nobody to name: no row.
    assert rows(relay) == []


@pytest.mark.parametrize(
    "claims, code",
    [
        ({"azp": "flow-engine"}, "token_invalid"),  # wrong azp: not the chat
        ({"sid": None}, "token_invalid"),  # a service token, not a person
    ],
)
def test_a_verified_token_of_another_client_or_of_a_service_is_refused(
    relay_factory, signer, claims, code
):
    relay = relay_factory()
    status, _, body = call(relay, chat_token(signer, **claims), rpc("tools/call", TOOL_CALL))
    assert status == 403
    assert body["error"]["data"]["error_code"] == code
    assert relay.idp.forms == []
    (row,) = rows(relay)
    assert row["result"] == "denied" and row["error_code"] == code


# ─────────────────────────────────────────────────────────────────────────
# targets
# ─────────────────────────────────────────────────────────────────────────


def test_a_target_that_is_not_opted_in_is_refused_before_any_exchange(relay_factory, signer):
    relay = relay_factory()
    for audience in ("mcp-qdrant", "mcp-wiki", "papaia-chat-relay", "..", "MCP"):
        status, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL),
                               audience=audience)
        assert status in (403, 404)
        assert body["error"]["data"]["error_code"] == "not_allowed"
    assert relay.idp.forms == [] and relay.upstream.requests == []


def test_without_the_list_every_call_is_refused(relay_factory, signer):
    relay = relay_factory(missing=True)
    status, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert status == 403
    assert body["error"]["data"]["error_code"] == "not_allowed"
    assert relay.idp.forms == []


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(format="papaia.chat-relay-servers/2"),
        lambda d: d.update(extra=True),
        lambda d: d["servers"][0].update(scope="aud-mcp-paperless aud-mcp-qdrant"),
        lambda d: d["servers"][0].update(audience="papaia-chat-relay", scope="aud-x"),
        lambda d: d["servers"][0].update(address="file:///etc/passwd"),
        lambda d: d["servers"][0].update(address="http://user:pw@host/mcp"),
        lambda d: d["servers"][0]["tools"][0].update(effect="launch"),
        lambda d: d["servers"][0]["tools"][0].update(unknown=1),
        lambda d: d["servers"].append(dict(d["servers"][0])),
        lambda d: d.update(servers=[dict(d["servers"][0], audience=f"mcp-a{i}",
                                         scope=f"aud-mcp-a{i}") for i in range(13)]),
    ],
)
def test_a_malformed_list_refuses_every_call(relay_factory, signer, change):
    doc = servers_doc()
    change(doc)
    relay = relay_factory(doc)
    status, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert status == 403 and body["error"]["data"]["error_code"] == "not_allowed"
    assert relay.idp.forms == []


# ─────────────────────────────────────────────────────────────────────────
# exchange and forwarding
# ─────────────────────────────────────────────────────────────────────────


def test_the_exchange_asks_for_exactly_one_aud_scope_and_keeps_the_person(relay_factory, signer):
    relay = relay_factory()
    token = chat_token(signer)
    status, _, body = call(relay, token, rpc("tools/call", TOOL_CALL, rid=7))
    assert status == 200, body
    assert body == {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"content": [{"type": "text", "text": "3 documents"}], "isError": False},
    }
    (form,) = relay.idp.forms
    assert form["grant_type"] == TE
    assert form["subject_token"] == token
    assert form["subject_token_type"] == ACCESS
    assert form["requested_token_type"] == ACCESS
    assert form["scope"] == "aud-mcp-paperless"
    assert len([s for s in form["scope"].split() if s.startswith("aud-")]) == 1
    (request,) = relay.upstream.requests
    exchanged = json.loads(base64.urlsafe_b64decode(request["token"].split(".")[1] + "=="))
    assert exchanged["aud"] == TARGET
    assert exchanged["azp"] == "papaia-chat-relay"
    assert exchanged["sub"] == ANNA


def test_the_outgoing_request_never_carries_the_incoming_token(relay_factory, signer):
    relay = relay_factory()
    token = chat_token(signer)
    call(relay, token, rpc("tools/call", TOOL_CALL), correlation="c0ffee-1")
    (request,) = relay.upstream.requests
    assert token not in json.dumps(request)
    assert request["token"] != token
    assert request["correlation"] == "c0ffee-1"
    assert request["name"] == "search_documents"
    assert request["arguments"] == {"query": "invoice 2026", "limit": 3}
    assert token not in relay.audit_out.getvalue()


@pytest.mark.parametrize(
    "answer, code",
    [
        ({"refresh_token": "a-refresh-token"}, "exchange_refused"),
        ({"claims": {"aud": [TARGET, "mcp-qdrant"]}}, "exchange_refused"),
        ({"claims": {"aud": "mcp-qdrant"}}, "exchange_refused"),
        ({"claims": {"azp": "librechat"}}, "exchange_refused"),
        ({"claims": {"sub": BEN}}, "exchange_refused"),
        ({"claims": {"exp": NOW + 301}}, "exchange_refused"),
        ({"token_type": "DPoP"}, "exchange_refused"),
    ],
)
def test_an_answer_of_the_identity_provider_that_is_not_exactly_right_fails_closed(
    relay_factory, signer, answer, code
):
    relay = relay_factory(idp=FakeIdp(signer, **answer))
    status, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert body["error"]["data"]["error_code"] == code
    assert relay.upstream.requests == []
    (row,) = rows(relay)
    assert row["result"] == "error" and row["error_code"] == code


@pytest.mark.parametrize(
    "failure, code",
    [
        (cr.ExchangeRefused("invalid_scope"), "exchange_refused"),
        (cr.IdpUnavailable("timeout"), "idp_unavailable"),
    ],
)
def test_a_refused_or_failed_exchange_ends_the_call(relay_factory, signer, failure, code):
    idp = FakeIdp(signer)
    idp.fail = failure
    relay = relay_factory(idp=idp)
    _, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert body["error"]["data"]["error_code"] == code
    assert relay.upstream.requests == []


@pytest.mark.parametrize(
    "error, code",
    [
        (cr.UpstreamTimeout("60 s"), "upstream_timeout"),
        (cr.UpstreamTooLarge("8 MiB"), "response_too_large"),
        (cr.UpstreamUnavailable("refused"), "upstream_unavailable"),
    ],
)
def test_an_add_on_that_fails_ends_the_call_without_a_fallback(relay_factory, signer, error, code):
    relay = relay_factory(upstream=FakeUpstream(error=error))
    _, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert body["error"]["data"]["error_code"] == code
    assert len(relay.upstream.requests) == 1


# ─────────────────────────────────────────────────────────────────────────
# methods, tools and arguments
# ─────────────────────────────────────────────────────────────────────────


def test_tools_list_is_answered_from_the_list_without_an_exchange(relay_factory, signer):
    relay = relay_factory()
    status, _, body = call(relay, chat_token(signer), rpc("tools/list"))
    assert status == 200
    tools = body["result"]["tools"]
    assert [t["name"] for t in tools] == ["search_documents", "tag_document"]
    assert tools[0]["inputSchema"] == SEARCH["input_schema"]
    assert tools[0]["title"] == "Search documents"
    assert relay.idp.forms == []


def test_initialize_and_ping_are_answered_by_the_relay(relay_factory, signer):
    relay = relay_factory()
    params = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x"}}
    status, _, body = call(relay, chat_token(signer), rpc("initialize", params))
    assert status == 200
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert body["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert call(relay, chat_token(signer), rpc("ping"))[2]["result"] == {}
    status, _, body = call(relay, chat_token(signer), rpc("notifications/initialized", rid=None))
    assert status == 202 and body is None
    assert relay.idp.forms == []


@pytest.mark.parametrize(
    "body",
    [
        rpc("resources/list"),
        rpc("prompts/get", {"name": "x"}),
        rpc("sampling/createMessage", {}),
        rpc("elicitation/create", {}),
        rpc("roots/list"),
        rpc("tools/call", TOOL_CALL, extra="field"),
        json.dumps([json.loads(rpc("ping"))]).encode(),
        b'{"jsonrpc": "1.0", "id": 1, "method": "ping"}',
        b"not json",
    ],
)
def test_other_methods_and_unknown_fields_are_refused(relay_factory, signer, body):
    relay = relay_factory()
    status, _, answer = call(relay, chat_token(signer), body)
    assert status in (200, 400)
    assert "error" in answer
    assert relay.idp.forms == [] and relay.upstream.requests == []


@pytest.mark.parametrize(
    "params, code",
    [
        ({"name": "delete_everything", "arguments": {}}, "tool_not_declared"),
        ({"name": "search_documents", "arguments": {}}, "invalid_arguments"),
        ({"name": "search_documents", "arguments": {"query": "x", "other": 1}},
         "invalid_arguments"),
        ({"name": "search_documents", "arguments": {"query": "x", "limit": "3"}},
         "invalid_arguments"),
        ({"name": "search_documents", "arguments": {"query": "x", "limit": 51}},
         "invalid_arguments"),
        ({"name": "search_documents", "arguments": {"query": ""}}, "invalid_arguments"),
        ({"name": "search_documents", "arguments": ["x"]}, "invalid_arguments"),
        ({"name": "search_documents"}, "invalid_arguments"),
        ({"name": "search_documents", "arguments": {"query": "x"}, "extra": 1}, "invalid_request"),
    ],
)
def test_an_undeclared_tool_or_arguments_off_the_schema_are_refused_before_the_exchange(
    relay_factory, signer, params, code
):
    relay = relay_factory()
    _, _, body = call(relay, chat_token(signer), rpc("tools/call", params))
    assert body["error"]["data"]["error_code"] == code
    assert relay.idp.forms == [] and relay.upstream.requests == []
    (row,) = rows(relay)
    assert row["result"] == "denied"
    assert "delete_everything" not in json.dumps(row) or row["object_ref"]["id"].endswith(
        "delete_everything"
    )


def test_a_schema_with_unknown_keywords_fails_closed(relay_factory, signer):
    tool = dict(SEARCH, input_schema={"type": "object", "$ref": "#/defs/x"})
    relay = relay_factory(servers_doc(tools=(tool,)))
    _, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert body["error"]["data"]["error_code"] == "invalid_arguments"
    assert relay.idp.forms == []


# ─────────────────────────────────────────────────────────────────────────
# limits
# ─────────────────────────────────────────────────────────────────────────


def test_a_body_over_one_mebibyte_is_refused_unread(relay_factory, signer):
    relay = relay_factory()
    big = rpc("tools/call", {"name": "search_documents", "arguments": {"query": "x" * (1 << 20)}})
    status, _, body = call(relay, chat_token(signer), big)
    assert status == 413
    assert relay.idp.forms == []


def test_a_wrong_content_type_is_refused(relay_factory, signer):
    relay = relay_factory()
    status, _, _ = call(relay, chat_token(signer), rpc("ping"), content_type="text/plain")
    assert status == 415


def test_sixty_requests_per_minute_per_person_and_add_on(relay_factory, signer):
    relay = relay_factory()
    token = chat_token(signer)
    for _ in range(60):
        assert call(relay, token, rpc("ping"))[0] == 200
    status, headers, body = call(relay, token, rpc("ping"))
    assert status == 429
    assert int(headers["Retry-After"]) >= 1
    assert body["error"]["data"]["error_code"] == "rate_limited"
    # Another person is not slowed down by Anna.
    assert call(relay, chat_token(signer, sub=BEN), rpc("ping"))[0] == 200
    relay.clock.now += 61
    assert call(relay, token, rpc("ping"))[0] == 200


# ─────────────────────────────────────────────────────────────────────────
# audit
# ─────────────────────────────────────────────────────────────────────────


def _submission_validator():
    schema = json.loads(AUDIT_SCHEMA.read_text(encoding="utf-8"))
    sub = dict(schema)
    sub.pop("properties", None)
    sub.pop("required", None)
    sub["$ref"] = "#/$defs/submission"
    sub.pop("allOf", None)
    sub.pop("unevaluatedProperties", None)
    return jsonschema.Draft202012Validator(sub, format_checker=jsonschema.FormatChecker())


def test_every_relayed_call_is_one_audit_row_without_arguments_or_results(relay_factory, signer):
    relay = relay_factory()
    token = chat_token(signer)
    _, headers, _ = call(relay, token, rpc("tools/call", TOOL_CALL), correlation="corr-42")
    assert headers["X-Papaia-Correlation-Id"] == "corr-42"
    call(relay, token, rpc("tools/list"))
    call(relay, token, rpc("tools/call", {"name": "nope", "arguments": {}}))
    first, second, third = rows(relay)
    assert first["operation"] == "chat_relay.tool_call"
    assert first["result"] == "allowed" and first["error_code"] is None
    assert first["sub"] == ANNA and first["identity_kind"] == "person"
    assert first["azp"] == "librechat" and first["aud"] == TARGET
    assert first["role"] == "caller" and first["event"] == "operation"
    assert first["catalog_id"] == "paperless-connect.mcp"
    assert first["object_ref"] == {"type": "tool", "id": "paperless-connect/search_documents"}
    assert first["effect"] == "read" and first["data_class"] == "confidential"
    assert first["correlation_id"] == "corr-42"
    assert first["writer"] == "papaia-chat-relay"
    assert second["operation"] == "chat_relay.session" and second["result"] == "allowed"
    assert third["result"] == "denied" and third["error_code"] == "tool_not_declared"
    text = relay.audit_out.getvalue()
    for secret in (token, "invoice 2026", "3 documents"):
        assert secret not in text
    validator = _submission_validator()
    for number, row in enumerate(rows(relay), 1):
        errors = list(validator.iter_errors(dict(row, source_seq=number)))
        assert errors == [], [e.message for e in errors]


def test_a_correlation_id_that_is_not_valid_is_replaced(relay_factory, signer):
    relay = relay_factory()
    for value in ("x" * 65, "line\nbreak", "sk-" + "a" * 20):
        _, headers, _ = call(relay, chat_token(signer), rpc("ping"), correlation=value)
        assert headers["X-Papaia-Correlation-Id"] != value
        assert len(headers["X-Papaia-Correlation-Id"]) == 36
    assert all(len(row["correlation_id"]) == 36 for row in rows(relay))


def test_a_call_whose_row_cannot_be_written_is_answered_with_an_error(relay_factory, signer):
    relay = relay_factory()

    class Broken(io.StringIO):
        def write(self, text):
            raise OSError("closed")

    relay.out = Broken()
    _, _, body = call(relay, chat_token(signer), rpc("tools/call", TOOL_CALL))
    assert body["error"]["data"]["error_code"] == "audit_unavailable"
    assert "result" not in body
    # Not forwarded: nothing left the relay.
    assert relay.idp.forms == [] and relay.upstream.requests == []


# ─────────────────────────────────────────────────────────────────────────
# end to end over sockets: relay, identity provider and a probe server outside the suite
# ─────────────────────────────────────────────────────────────────────────


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


def _serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Probe:
    """A tool server outside the suite: it checks its own audience like every add-on
    must, logs the claims of each token (never the token) and answers with SSE."""

    def __init__(self, signer) -> None:
        self.claims: list[dict] = []
        self.refused = 0
        probe = self
        keys = cr.Keys(lambda: {"keys": [signer.jwk()]})

        class Handler(_Quiet):
            def do_POST(self):
                auth = self.headers.get("Authorization", "")
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                try:
                    claims = cr.verify_signature(keys, auth.removeprefix("Bearer "))
                except cr.Refused:
                    claims = None
                if claims is None or claims.get("aud") not in (TARGET, [TARGET]):
                    probe.refused += 1
                    return self._json(401, {"error": "invalid_token"})
                probe.claims.append(
                    {k: claims.get(k) for k in ("aud", "azp", "sub")}
                    | {"correlation": self.headers.get("X-Papaia-Correlation-Id")}
                )
                method = body.get("method")
                if method == "initialize":
                    return self._json(
                        200,
                        {"jsonrpc": "2.0", "id": body["id"], "result": {
                            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                            "serverInfo": {"name": "probe", "version": "1"}}},
                        {"Mcp-Session-Id": "probe-session-1"},
                    )
                if method == "notifications/initialized":
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                assert self.headers.get("Mcp-Session-Id") == "probe-session-1"
                answer = {"jsonrpc": "2.0", "id": body["id"], "result": {
                    "content": [{"type": "text", "text": f"hello {claims['sub']}"}],
                    "isError": False}}
                data = f"event: message\ndata: {json.dumps(answer)}\n\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return None

            def do_DELETE(self):
                self.send_response(204)
                self.end_headers()

        self.server = _serve(Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"


class Idp:
    """The realm's token endpoint over HTTP (form post, client assertion)."""

    def __init__(self, signer) -> None:
        fake = FakeIdp(signer, now=int(time.time()))
        self.fake = fake

        class Handler(_Quiet):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
                assertion = form.get("client_assertion", "")
                claims = json.loads(base64.urlsafe_b64decode(assertion.split(".")[1] + "=="))
                if (
                    form.get("client_assertion_type")
                    != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    or claims.get("iss") != "papaia-chat-relay"
                    or claims.get("aud") != ISSUER
                ):
                    return self._json(401, {"error": "invalid_client"})
                return self._json(200, fake.exchange(form))

        self.server = _serve(Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


def _relay_key(tmp_path) -> Path:
    key_dir = tmp_path / "key"
    key_dir.mkdir(mode=0o700)
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(key_dir / "private-key.pem")],
        check=True, capture_output=True,
    )
    (key_dir / "private-key.pem").chmod(0o600)
    return key_dir


@pytest.fixture
def stack_at(signer, tmp_path):
    """The relay in front of the tool server at `address` (the probe when none is given)."""
    running = []

    def make(address=None):
        probe, idp = Probe(signer), Idp(signer)
        path = write_servers(tmp_path, servers_doc(address=address or probe.url))
        out = io.StringIO()
        key = cr.ClientKey(_relay_key(tmp_path))
        exchanger = cr.Exchanger(f"{idp.url}/token", ISSUER, key, None)
        relay = cr.Relay(
            cr.TokenVerifier(cr.Keys(lambda: {"keys": [signer.jwk()]}), ISSUER),
            cr.ServerList(path),
            exchanger.exchange,
            cr.Upstream(None),
            out=out,
        )
        server = cr.make_server(relay, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        running.extend((server, probe.server, idp.server))
        return types.SimpleNamespace(
            probe=probe, idp=idp, relay=relay, out=out, port=server.server_address[1]
        )

    yield make
    for server in running:
        server.shutdown()
        server.server_close()


@pytest.fixture
def stack(stack_at):
    return stack_at()


def _post(port, path, token, body, correlation=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}",
               "Accept": "application/json, text/event-stream"}
    if correlation:
        headers["X-Papaia-Correlation-Id"] = correlation
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), json.loads(data) if data else None


def test_end_to_end_the_probe_sees_only_its_own_audience_and_the_person(stack, signer):
    token = chat_token(signer, exp=NOW + 10**8, iat=NOW - 10)
    status, headers, body = _post(
        stack.port, f"/servers/{TARGET}/mcp", token, rpc("tools/call", TOOL_CALL, rid=5),
        correlation="e2e-1",
    )
    assert status == 200, body
    assert body["result"]["content"][0]["text"] == f"hello {ANNA}"
    assert headers["X-Papaia-Correlation-Id"] == "e2e-1"
    # initialize, notifications/initialized, tools/call: one token, one audience, the person
    assert stack.probe.claims and all(
        c == {"aud": TARGET, "azp": "papaia-chat-relay", "sub": ANNA, "correlation": "e2e-1"}
        for c in stack.probe.claims
    )
    (form,) = stack.idp.fake.forms
    assert form["scope"] == "aud-mcp-paperless"
    (row,) = [json.loads(line) for line in stack.out.getvalue().splitlines()]
    assert row["operation"] == "chat_relay.tool_call" and row["result"] == "allowed"
    assert row["correlation_id"] == "e2e-1"


def test_end_to_end_the_probe_refuses_the_shared_chat_token(stack, signer):
    token = chat_token(signer, exp=NOW + 10**8)
    url = urllib.parse.urlsplit(stack.probe.url)
    status, _, _ = _post(url.port, url.path, token, rpc("tools/call", TOOL_CALL))
    assert status == 401
    assert stack.probe.refused == 1


def test_end_to_end_a_target_outside_the_list_never_reaches_the_identity_provider(stack, signer):
    token = chat_token(signer, exp=NOW + 10**8)
    status, _, body = _post(
        stack.port, "/servers/mcp-wiki/mcp", token, rpc("tools/call", TOOL_CALL)
    )
    assert status == 403 and body["error"]["data"]["error_code"] == "not_allowed"
    assert stack.idp.fake.forms == [] and stack.probe.claims == []


# ─────────────────────────────────────────────────────────────────────────
# slow answers: the deadline holds while headers and body arrive, not per read
# ─────────────────────────────────────────────────────────────────────────

DRIP_SECONDS = 0.1
# A dripping server stops after this long, so a relay without an overall deadline
# fails these tests instead of hanging them.
DRIP_LIMIT = 8.0


class Drip:
    """A server that answers one byte at a time.

    `headers`: the status line and headers drip. `body`: valid headers at once, then a
    long body drips. `delete`: an MCP server that answers every POST at once (with a
    session) and drips the answer to the DELETE that closes the session."""

    def __init__(self, stage: str) -> None:
        stop = self.stop = threading.Event()

        def drip(handler, data: bytes) -> None:
            ends = time.monotonic() + DRIP_LIMIT
            for index in range(len(data)):
                if stop.wait(DRIP_SECONDS) or time.monotonic() > ends:
                    return
                try:
                    handler.wfile.write(data[index : index + 1])
                    handler.wfile.flush()
                except OSError:
                    return

        def slow(handler) -> None:
            handler.close_connection = True
            if stage == "headers":
                drip(handler, b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 60000 + b"\r\n\r\n")
                return
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "100000")
            handler.end_headers()
            handler.wfile.flush()
            drip(handler, b" " * 100000)

        class Handler(_Quiet):
            def do_GET(self):
                slow(self)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                if stage != "delete":
                    return slow(self)
                body = json.loads(raw)
                method = body.get("method")
                if method == "notifications/initialized":
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                result = (
                    {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                     "serverInfo": {"name": "drip", "version": "1"}}
                    if method == "initialize"
                    else {"content": [{"type": "text", "text": "done"}], "isError": False}
                )  # fmt: skip
                return self._json(
                    200, {"jsonrpc": "2.0", "id": body["id"], "result": result},
                    {"Mcp-Session-Id": "drip-session-1"},
                )  # fmt: skip

            def do_DELETE(self):
                slow(self)

        self.server = _serve(Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def drip():
    started = []

    def make(stage: str) -> Drip:
        started.append(Drip(stage))
        return started[-1]

    yield make
    for server in started:
        server.close()


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_an_add_on_that_drips_its_answer_is_cut_off_at_the_deadline(drip, stage):
    slow = drip(stage)
    started = time.monotonic()
    with pytest.raises(cr.UpstreamTimeout):
        cr.Upstream(None)(f"{slow.url}/mcp", "t", "c-1", "search_documents", {}, started + 1.0)
    assert time.monotonic() - started < 1.8


def test_a_dripping_answer_to_the_closing_delete_does_not_outlast_the_call(drip):
    slow = drip("delete")
    started = time.monotonic()
    answer = cr.Upstream(None)(
        f"{slow.url}/mcp", "t", "c-1", "search_documents", {}, started + 1.0
    )
    assert answer["result"]["content"][0]["text"] == "done"
    assert time.monotonic() - started < 1.8


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_a_dripping_token_endpoint_is_cut_off_after_its_limit(drip, tmp_path, monkeypatch, stage):
    monkeypatch.setattr(cr, "IDP_SECONDS", 1.0)
    slow = drip(stage)
    exchanger = cr.Exchanger(f"{slow.url}/token", ISSUER, cr.ClientKey(_relay_key(tmp_path)), None)
    started = time.monotonic()
    with pytest.raises(cr.IdpUnavailable):
        exchanger.exchange({"grant_type": cr.TOKEN_EXCHANGE})
    assert time.monotonic() - started < 1.8


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_a_dripping_key_set_is_cut_off_after_its_limit(drip, monkeypatch, stage):
    monkeypatch.setattr(cr, "IDP_SECONDS", 1.0)
    slow = drip(stage)
    started = time.monotonic()
    with pytest.raises(cr.IdpUnavailable):
        cr._jwks_fetch(slow.url, None)()
    assert time.monotonic() - started < 1.8


def test_end_to_end_a_dripping_add_on_ends_the_call_with_upstream_timeout(
    stack_at, drip, signer, monkeypatch
):
    monkeypatch.setattr(cr, "CALL_SECONDS", 1.5)
    slow = drip("body")
    stack = stack_at(f"{slow.url}/mcp")
    token = chat_token(signer, exp=NOW + 10**8, iat=NOW - 10)
    started = time.monotonic()
    status, _, body = _post(
        stack.port, f"/servers/{TARGET}/mcp", token, rpc("tools/call", TOOL_CALL, rid=7),
        correlation="drip-1",
    )
    elapsed = time.monotonic() - started
    assert status == 504 and body["error"]["data"]["error_code"] == "upstream_timeout"
    assert 1.4 < elapsed < 2.5
    (row,) = [json.loads(line) for line in stack.out.getvalue().splitlines()]
    assert row["error_code"] == "upstream_timeout" and row["correlation_id"] == "drip-1"


# ─────────────────────────────────────────────────────────────────────────
# bounded state: rate windows and handler threads
# ─────────────────────────────────────────────────────────────────────────


def test_the_rate_window_forgets_keys_whose_events_have_expired():
    clock = Clock()
    window = cr.Window(60, 60.0, clock)
    for index in range(1000):
        assert window.admit(("person", index)) == 0
    clock.now += 61
    assert window.admit(("person", "new")) == 0
    assert len(window._events) == 1


def test_a_full_relay_answers_503_instead_of_starting_another_thread(relay_factory):
    server = cr.make_server(relay_factory(), "127.0.0.1", 0, max_handlers=1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        # The first connection holds the only handler: its headers never end.
        held = socket.create_connection(("127.0.0.1", port), timeout=5)
        held.sendall(b"POST /servers/mcp-paperless/mcp HTTP/1.1\r\n")
        time.sleep(0.3)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        assert resp.status == 503
        assert resp.getheader("Retry-After") == "1"
        assert body["error"]["data"]["error_code"] == "busy"
        held.close()
        # Once the held connection is gone, the slot is free again.
        for _ in range(50):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/healthz")
            status = conn.getresponse().status
            conn.close()
            if status == 200:
                break
            time.sleep(0.1)
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()


# ─────────────────────────────────────────────────────────────────────────
# compose service
# ─────────────────────────────────────────────────────────────────────────


def test_the_compose_service_publishes_no_port_and_runs_read_only_without_root():
    doc = yaml.safe_load((MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    (name,) = doc["services"]
    service = doc["services"][name]
    assert name == "papaia-chat-relay"
    assert "ports" not in service
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["user"] == "${UID:-1000}:${GID:-1000}"
    assert set(service["networks"]) == {"papaia-chat-relay-net", "papaia-net"}
    assert doc["networks"]["papaia-chat-relay-net"]["internal"] is True
    mounts = {m["target"]: m for m in service["volumes"]}
    assert all(m["read_only"] is True for m in mounts.values())
    sources = {m["source"] for m in mounts.values()}
    assert "${PAPAIA_CONFIG_DIR}/security/chat-relay" in sources
    assert "${PAPAIA_CONFIG_DIR}/chat-relay" in sources
    assert "environment" not in service or not any(
        "TOKEN" in key or "SECRET" in key for key in service["environment"]
    )
