"""The class guard of the model gateway (ADR 0031, security test T61).

`papaia_hooks.papaia_class_guard` judges every model call made with a key other than the
master key before LiteLLM routes it:

* request class: the header `x-papaia-data-class` (one value of the kit scale, ASCII,
  at most 32 characters), otherwise the class the module declared for the alias
  (`metadata.papaia_need_classes` of its key), otherwise the highest class;
* route class: the class of the alias in the mounted route file;
* refusals before any backend call: 403 `class_exceeded`, 400 `invalid_data_class`,
  503 `route_class_unknown`; the platform halt refuses first;
* one `papaia.audit/1` row per refusal in the gateway's own outbox, with the correlation
  id and without content, key or key hash.

The hook is loaded from the source tree with stand-ins for the two LiteLLM and FastAPI
names it imports. Where the pinned LiteLLM hands the headers to the hook
(`data["proxy_server_request"]["headers"]`, a dict with lower-case names) is proven with
the pinned image in test_model_gateway_docker.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import halt, model_gateway, model_routes

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / "src" / "ai" / "litellm" / "papaia_hooks.py"
AUDIT_SCHEMA = json.loads(
    (REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text("utf-8")
)
MARKER = "MARK-c1a55-guard"
MODULE_KEY = "sk-synthetic-module-key-0001"
TOKEN = hashlib.sha256(MODULE_KEY.encode()).hexdigest()
CORRELATION = "0f0e0d0c-0b0a-4909-8807-060504030201"


# ── loading the hook ───────────────────────────────────────────────────────


@pytest.fixture
def hooks(monkeypatch):
    """papaia_hooks with stand-ins for the LiteLLM and FastAPI names it uses."""

    class CustomLogger:
        def __init__(self, *a, **k):
            pass

    class HTTPException(Exception):
        def __init__(self, status_code, detail=None, headers=None):
            super().__init__(status_code)
            self.status_code, self.detail, self.headers = status_code, detail, headers

    stubs = {
        "litellm": types.ModuleType("litellm"),
        "litellm.integrations": types.ModuleType("litellm.integrations"),
        "litellm.integrations.custom_logger": types.ModuleType("custom_logger"),
        "fastapi": types.ModuleType("fastapi"),
    }
    stubs["litellm.integrations.custom_logger"].CustomLogger = CustomLogger
    stubs["fastapi"].HTTPException = HTTPException
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec = importlib.util.spec_from_file_location("papaia_hooks_class_guard", HOOKS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HTTPException = HTTPException
    return module


class Key:
    """The part of LiteLLM's UserAPIKeyAuth the guard reads."""

    def __init__(self, alias="module-flow", metadata=None, role="internal_user",
                 api_key=TOKEN):
        self.key_alias = alias
        self.metadata = {"tags": ["module:flow"]} if metadata is None else metadata
        self.user_role = role
        self.api_key = api_key
        self.token = api_key


def _declared(**classes) -> dict:
    return {"tags": ["module:flow"], "papaia_need_classes": dict(classes)}


MASTER = Key(alias=None, metadata={}, role="proxy_admin", api_key="litellm_proxy_master_key")


class Gateway:
    """The order of the proxy: the pre-call hooks of the callback list, then the backend.
    The backend records every request it receives."""

    def __init__(self, hooks, tmp_path: Path, routes: dict | None = None, *,
                 route_bytes: bytes | None = None):
        self.dir = tmp_path
        self.halt_dir = tmp_path / "config"
        halt.ensure_dir(self.halt_dir)
        self.routes_path = tmp_path / "model-routes.json"
        if route_bytes is not None:
            self.routes_path.write_bytes(route_bytes)
        elif routes is not None:
            self.write_routes(routes)
        self.outbox = tmp_path / "outbox" / "litellm.jsonl"
        self.outbox.parent.mkdir()
        self.outbox.touch()
        self.outbox.with_name("litellm.seq").touch()
        self.halt = hooks._PlatformHalt(str(halt.state_path(self.halt_dir)))
        self.guard = hooks._ClassGuard(
            routes=str(self.routes_path), outbox=str(self.outbox), halt=self.halt
        )
        self.backend: list[dict] = []
        self.hooks = hooks

    def write_routes(self, routes: dict) -> None:
        doc = {"format": model_routes.FORMAT, "generated_at": "2026-11-25T10:00:00Z",
               "routes": routes}
        self.routes_path.write_text(json.dumps(doc), encoding="utf-8")

    def call(self, key: Key, alias="papaia-chat", headers: dict | None = None,
             call_type="acompletion") -> dict:
        data = {
            "model": alias,
            "messages": [{"role": "user", "content": f"confidential note {MARKER}"}],
            "metadata": {"headers": dict(headers or {})},
            "proxy_server_request": {
                "url": "http://litellm:4000/v1/chat/completions",
                "method": "POST",
                "headers": {"content-type": "application/json", **(headers or {})},
                "body": {"model": alias},
            },
        }
        for hook in (self.halt, self.guard):
            data = asyncio.run(hook.async_pre_call_hook(key, None, data, call_type))
        self.backend.append(data)
        return data

    def refused(self, key: Key, alias="papaia-chat", headers: dict | None = None):
        with pytest.raises(self.hooks.HTTPException) as caught:
            self.call(key, alias, headers)
        return caught.value

    def rows(self) -> list[dict]:
        text = self.outbox.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]


ROUTES = {"papaia-chat": "personal", "papaia-structured": "internal", "papaia-embed": "public"}


@pytest.fixture
def gw(hooks, tmp_path):
    return Gateway(hooks, tmp_path, ROUTES)


def _valid_audit(row: dict) -> None:
    validator = Draft202012Validator({"$defs": AUDIT_SCHEMA["$defs"],
                                      "$ref": "#/$defs/submission"})
    assert [e.message for e in validator.iter_errors(row)] == []


def _assert_refusal(gw: Gateway, exc, status: int, code: str, data_class,
                    correlation: str | None = None, alias: str = "papaia-chat") -> None:
    """Refused with `status`/`code`, nothing reached the backend, and exactly one audit row
    with the correlation id of the answer and without content, key or key hash."""
    assert exc.status_code == status
    assert exc.detail["error"]["code"] == code
    assert exc.detail["error"]["message"]
    assert exc.headers["x-papaia-error-code"] == code
    returned = exc.headers["x-papaia-correlation-id"]
    if correlation is not None:
        assert returned == correlation
    assert gw.backend == []
    (row,) = gw.rows()
    _valid_audit(row)
    assert row["correlation_id"] == returned
    assert row["writer"] == "litellm/class-guard"
    assert (row["role"], row["identity_kind"], row["event"]) == ("server", "service", "operation")
    assert row["catalog_id"] == "litellm.model_request"
    assert (row["operation"], row["effect"]) == ("model.request", "check")
    assert row["object_ref"] == {"type": "model_alias", "id": alias}
    assert row["data_class"] == data_class
    assert (row["result"], row["error_code"], row["detail"]) == ("denied", code, None)
    assert row["source_seq"] == 1
    text = json.dumps(row)
    for secret in (MARKER, "note", MODULE_KEY, TOKEN):
        assert secret not in text


# ── the scale is the kit's ─────────────────────────────────────────────────


def test_the_hook_carries_the_scale_of_the_kit(hooks):
    assert hooks.DATA_CLASSES == model_routes.scale()


def test_the_hook_reads_the_route_file_the_core_writes(hooks):
    assert hooks.ROUTES_FORMAT == model_routes.FORMAT
    assert hooks.ROUTES_MAX_BYTES == model_routes.MAX_FILE_BYTES


# ── passing requests ───────────────────────────────────────────────────────


@pytest.mark.parametrize("header", ["public", "internal", "personal"])
def test_a_header_at_or_below_the_route_and_the_declared_class_passes(gw, header):
    key = Key(metadata=_declared(**{"papaia-chat": "personal"}))
    data = gw.call(key, headers={"x-papaia-data-class": header})
    assert len(gw.backend) == 1
    assert data["messages"][0]["content"].endswith(MARKER), "the hook changes nothing"
    assert gw.rows() == []


def test_without_a_header_the_declared_class_is_judged_and_passes_at_the_route(gw):
    gw.call(Key(metadata=_declared(**{"papaia-chat": "personal"})))
    assert len(gw.backend) == 1
    assert gw.rows() == []


def test_a_high_declared_class_passes_with_a_lower_header(gw):
    key = Key(metadata=_declared(**{"papaia-chat": "special"}))
    gw.call(key, headers={"x-papaia-data-class": "internal"})
    assert len(gw.backend) == 1


def test_the_master_key_is_not_judged(gw):
    gw.write_routes({"papaia-chat": "public"})
    gw.call(MASTER, headers={"x-papaia-data-class": "professional_secret"})
    gw.call(MASTER, alias="papaia-unknown")
    assert len(gw.backend) == 2
    assert gw.rows() == []


@pytest.mark.parametrize("call_type", ["acompletion", "atext_completion", "aembedding"])
def test_every_model_call_type_is_judged(gw, call_type):
    with pytest.raises(gw.hooks.HTTPException):
        asyncio.run(gw.guard.async_pre_call_hook(
            Key(metadata=_declared(**{"papaia-embed": "personal"})), None,
            {"model": "papaia-embed", "input": MARKER,
             "proxy_server_request": {"headers": {}}}, call_type))


# ── class_exceeded ─────────────────────────────────────────────────────────


def test_a_header_above_the_route_is_refused(gw):
    key = Key(metadata=_declared(**{"papaia-chat": "special"}))
    exc = gw.refused(key, headers={"x-papaia-data-class": "employee",
                                   "x-papaia-correlation-id": CORRELATION})
    _assert_refusal(gw, exc, 403, "class_exceeded", "employee", CORRELATION)


def test_a_header_above_the_declared_class_but_below_the_route_is_refused(gw):
    key = Key(metadata=_declared(**{"papaia-chat": "internal"}))
    exc = gw.refused(key, headers={"x-papaia-data-class": "personal"})
    _assert_refusal(gw, exc, 403, "class_exceeded", "personal")


def test_without_a_header_a_declared_class_above_the_route_is_refused(gw):
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "confidential"})))
    _assert_refusal(gw, exc, 403, "class_exceeded", "confidential")


@pytest.mark.parametrize(
    "metadata",
    [
        {"tags": ["module:flow"]},  # a key made before the class rule
        {"tags": ["module:flow"], "papaia_need_classes": {}},
        {"tags": ["module:flow"], "papaia_need_classes": {"papaia-embed": "public"}},
        {"tags": ["module:flow"], "papaia_need_classes": {"papaia-chat": "Internal"}},
        {"tags": ["module:flow"], "papaia_need_classes": {"papaia-chat": "secret"}},
        {"tags": ["module:flow"], "papaia_need_classes": ["papaia-chat"]},
        {},
    ],
)
def test_a_key_without_a_declared_class_counts_as_the_highest_class(gw, metadata):
    exc = gw.refused(Key(metadata=metadata))
    _assert_refusal(gw, exc, 403, "class_exceeded", "professional_secret")


def test_a_key_without_declared_classes_reaches_a_route_of_the_highest_class(gw):
    gw.write_routes({"papaia-chat": "professional_secret"})
    gw.call(Key(metadata={"tags": ["module:flow"]}))
    assert len(gw.backend) == 1


def test_a_key_without_metadata_is_judged_as_the_highest_class(gw):
    key = Key()
    key.metadata = None
    exc = gw.refused(key)
    _assert_refusal(gw, exc, 403, "class_exceeded", "professional_secret")


def test_a_virtual_key_of_an_admin_is_judged(gw):
    """Only the master key itself is spared; a virtual key of an admin user is judged."""
    key = Key(alias="ops-key", metadata={}, role="proxy_admin", api_key=TOKEN)
    exc = gw.refused(key)
    assert exc.status_code == 403
    (row,) = gw.rows()
    assert row["sub"] == row["azp"] == row["service_account"] == "ops-key"


# ── invalid_data_class ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "secret",                 # not on the scale
        "Internal",               # other case
        "internal, personal",     # two values
        "internal,personal",
        " internal",
        "internal ",
        "",
        "p" * 33,                 # 33 characters
        "inter\tnal",             # control characters
        "internal\x00",
        "intern\xe4l",            # not ASCII
        "public\r\n",
    ],
)
def test_a_malformed_header_is_refused(gw, value):
    key = Key(metadata=_declared(**{"papaia-chat": "personal"}))
    exc = gw.refused(key, headers={"x-papaia-data-class": value})
    _assert_refusal(gw, exc, 400, "invalid_data_class", None)
    if value:
        assert value not in json.dumps(gw.rows())


@pytest.mark.parametrize("value", [["internal"], 3, None, {"a": "internal"}])
def test_a_header_that_is_not_one_string_is_refused(gw, value):
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "personal"})),
                     headers={"x-papaia-data-class": value})
    _assert_refusal(gw, exc, 400, "invalid_data_class", None)


def test_a_header_name_in_two_spellings_is_refused(gw):
    """Should the name reach the hook twice (two spellings), it is refused, not merged.
    The pinned LiteLLM folds a repeated header into one entry before any hook runs."""
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "personal"})),
                     headers={"x-papaia-data-class": "public",
                              "X-Papaia-Data-Class": "internal"})
    _assert_refusal(gw, exc, 400, "invalid_data_class", None)


def test_the_class_is_never_taken_from_the_body(gw):
    key = Key(metadata={"tags": ["module:flow"]})
    data = {
        "model": "papaia-chat",
        "messages": [{"role": "user", "content": "x"}],
        "metadata": {"headers": {"x-papaia-data-class": "public"},
                     "papaia_data_class": "public"},
        "user": "public",
        "proxy_server_request": {"headers": {}},
    }
    with pytest.raises(gw.hooks.HTTPException) as caught:
        asyncio.run(gw.guard.async_pre_call_hook(key, None, data, "acompletion"))
    assert caught.value.status_code == 403
    assert gw.rows()[0]["data_class"] == "professional_secret"


# ── route_class_unknown ────────────────────────────────────────────────────


def test_a_missing_route_file_refuses_every_module_call(hooks, tmp_path):
    gw = Gateway(hooks, tmp_path)
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


def test_an_unreadable_route_file_refuses(hooks, tmp_path):
    gw = Gateway(hooks, tmp_path, ROUTES)
    gw.routes_path.unlink()
    gw.routes_path.mkdir()  # a folder in its place cannot be read as the file
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file of mode 0")
def test_a_route_file_without_read_permission_refuses(hooks, tmp_path):
    gw = Gateway(hooks, tmp_path, ROUTES)
    gw.routes_path.chmod(0)
    try:
        exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    finally:
        gw.routes_path.chmod(0o644)
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


def test_a_route_file_without_the_alias_refuses(gw):
    gw.write_routes({"papaia-structured": "internal"})
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


def _doc(**over) -> bytes:
    doc = {"format": model_routes.FORMAT, "generated_at": "2026-11-25T10:00:00Z",
           "routes": dict(ROUTES)}
    doc.update(over)
    return json.dumps(doc).encode()


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{",
        b"[]",
        _doc(format="papaia.model-routes/2"),
        _doc(generated_at="yesterday"),
        _doc(routes=[]),
        _doc(routes={"papaia-chat": "Personal"}),
        _doc(routes={"papaia-chat": "secret"}),
        _doc(routes={"papaia-chat": None}),
        _doc(routes={"PAPAIA-CHAT": "public"}),
        _doc(extra=1),
        b"\xff\xfe",
        _doc(routes={"papaia-chat": "public", "pad": "x" * (256 * 1024)}),
    ],
)
def test_a_malformed_route_file_refuses(hooks, tmp_path, content):
    gw = Gateway(hooks, tmp_path, route_bytes=content)
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


def test_a_symlink_in_place_of_the_route_file_refuses(hooks, tmp_path):
    gw = Gateway(hooks, tmp_path)
    target = tmp_path / "elsewhere.json"
    target.write_bytes(_doc())
    gw.routes_path.symlink_to(target)
    exc = gw.refused(Key(metadata=_declared(**{"papaia-chat": "public"})))
    _assert_refusal(gw, exc, 503, "route_class_unknown", "public")


def test_the_route_file_is_read_again_when_it_changes(gw):
    key = Key(metadata=_declared(**{"papaia-chat": "personal"}))
    gw.call(key)
    gw.write_routes({"papaia-chat": "internal"})
    os.utime(gw.routes_path, ns=(1, 1))  # another identity even within one tick
    with pytest.raises(gw.hooks.HTTPException):
        gw.call(key)


def test_an_unchanged_route_file_is_not_parsed_again(gw, monkeypatch):
    key = Key(metadata=_declared(**{"papaia-chat": "personal"}))
    gw.call(key)
    parsed = []
    original = gw.hooks.parse_routes
    monkeypatch.setattr(gw.hooks, "parse_routes", lambda b: parsed.append(1) or original(b))
    gw.call(key)
    gw.call(key)
    assert parsed == []


def test_an_alias_that_is_not_a_route_name_is_refused_without_naming_it(gw):
    key = Key(metadata=_declared(**{"papaia-chat": "public"}))
    with pytest.raises(gw.hooks.HTTPException) as caught:
        gw.call(key, alias=f"x {MARKER}")
    assert caught.value.status_code == 503
    (row,) = gw.rows()
    _valid_audit(row)
    assert row["object_ref"] == {"type": "model_alias", "id": "unknown"}
    assert MARKER not in json.dumps(row)


# ── the platform halt comes first ──────────────────────────────────────────


def test_the_halt_refuses_before_the_class_is_judged(gw):
    halt.set_halt(gw.halt_dir, None)
    exc = gw.refused(Key(metadata={}), headers={"x-papaia-data-class": "bogus"})
    assert exc.status_code == 503
    assert exc.detail["error"]["code"] == "platform_halt"
    assert gw.backend == [] and gw.rows() == []


def test_the_guard_refuses_with_the_halt_even_when_it_runs_alone(gw):
    halt.set_halt(gw.halt_dir, None)
    with pytest.raises(gw.hooks.HTTPException) as caught:
        asyncio.run(gw.guard.async_pre_call_hook(
            Key(metadata={}), None, {"model": "papaia-chat"}, "acompletion"))
    assert caught.value.detail["error"]["code"] == "platform_halt"
    assert gw.rows() == []


# ── correlation and audit ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "given",
    ["a" * 65, "abc def", "sk-" + "A" * 24, "abc\n", "", "ä"],
)
def test_an_unusable_correlation_id_is_replaced(gw, given):
    exc = gw.refused(Key(metadata={}), headers={"x-papaia-correlation-id": given})
    returned = exc.headers["x-papaia-correlation-id"]
    assert returned != given
    (row,) = gw.rows()
    _valid_audit(row)
    assert row["correlation_id"] == returned


def test_the_audit_row_names_the_module_key_alias_as_actor(gw):
    gw.refused(Key(metadata={}))
    (row,) = gw.rows()
    assert row["sub"] == row["azp"] == row["service_account"] == "module-flow"
    assert row["aud"] is None


def test_source_seq_is_gapless_and_survives_a_drained_outbox(gw, hooks):
    for _ in range(3):
        gw.refused(Key(metadata={}))
    assert [r["source_seq"] for r in gw.rows()] == [1, 2, 3]
    gw.outbox.write_text("", encoding="utf-8")  # delivered and emptied in place
    guard = hooks._ClassGuard(routes=str(gw.routes_path), outbox=str(gw.outbox), halt=gw.halt)
    with pytest.raises(hooks.HTTPException):
        asyncio.run(guard.async_pre_call_hook(Key(metadata={}), None,
                                              {"model": "papaia-chat"}, "acompletion"))
    assert [r["source_seq"] for r in gw.rows()] == [4]


def test_a_refusal_does_not_wait_for_an_unwritable_outbox(hooks, tmp_path, capsys):
    gw = Gateway(hooks, tmp_path, ROUTES)
    gw.outbox.unlink()
    gw.outbox.mkdir()  # cannot be appended to
    exc = gw.refused(Key(metadata={}))
    assert exc.status_code == 403 and gw.backend == []
    err = capsys.readouterr().err
    assert "audit_unavailable" in err
    assert MARKER not in err and TOKEN not in err


def test_the_guard_logs_nothing_of_a_refused_request(gw, capsys):
    gw.refused(Key(metadata={}), headers={"x-papaia-data-class": f"x{MARKER}"})
    gw.refused(Key(metadata={}))
    out = capsys.readouterr()
    assert MARKER not in out.out + out.err
    assert out.out == ""


# ── registration ───────────────────────────────────────────────────────────


def test_the_shipped_configuration_registers_the_guard_right_after_the_halt():
    config = yaml.safe_load((REPO / "src/ai/litellm/config.yaml").read_text("utf-8"))
    assert config["litellm_settings"]["callbacks"] == [
        "prometheus",
        "papaia_hooks.papaia_listing_filter",
        "papaia_hooks.papaia_platform_halt",
        "papaia_hooks.papaia_class_guard",
    ]


def test_the_allowed_callbacks_are_exactly_the_four():
    assert model_gateway.ALLOWED_CALLBACKS == {
        "prometheus",
        "papaia_hooks.papaia_listing_filter",
        "papaia_hooks.papaia_platform_halt",
        "papaia_hooks.papaia_class_guard",
    }


def test_the_module_level_guard_reads_the_mounted_files(hooks):
    guard = hooks.papaia_class_guard
    assert guard._routes == "/app/model-routes.json"
    assert guard._outbox == "/run/papaia-audit/litellm.jsonl"
    assert guard._halt is hooks.papaia_platform_halt


def test_the_gateway_mounts_its_outbox_and_nothing_else_writable():
    compose = yaml.safe_load((REPO / "src/ai/litellm/docker-compose.yml").read_text("utf-8"))
    service = compose["services"]["litellm"]
    writable = [
        m for m in service["volumes"]
        if isinstance(m, dict) and not m.get("read_only")
        and m.get("target") not in ("/app/config.yaml",)
    ]
    assert writable == [
        {
            "type": "bind",
            "source": "${PAPAIA_CONFIG_DIR}/audit/outbox/litellm.jsonl",
            "target": "/run/papaia-audit/litellm.jsonl",
            "bind": {"create_host_path": False},
        },
        {
            "type": "bind",
            "source": "${PAPAIA_CONFIG_DIR}/audit/outbox/litellm.seq",
            "target": "/run/papaia-audit/litellm.seq",
            "bind": {"create_host_path": False},
        },
    ]
    assert service["networks"] == ["papaia-net", "papaia-replay-gw-net"]
    assert "ports" not in service


# ── the outbox of the gateway ──────────────────────────────────────────────


def test_render_makes_the_outbox_files_compose_must_not_create(repo_root, config_dir):
    from lib import render_core
    from tests.test_model_routes import _install, _model

    _install(repo_root, config_dir, _model("checker-model"),
             PAPAIA_DEFAULT_MODEL="checker-model")
    render_core.render(config_dir, repo_root)
    for name in ("litellm.jsonl", "litellm.seq"):
        path = config_dir / "audit" / "outbox" / name
        assert path.is_file() and not path.is_symlink()
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.read_bytes() == b""
    # A second render keeps what the gateway wrote.
    (config_dir / "audit/outbox/litellm.jsonl").write_text('{"source_seq": 1}\n', "utf-8")
    render_core.render(config_dir, repo_root)
    assert (config_dir / "audit/outbox/litellm.jsonl").read_text("utf-8") == '{"source_seq": 1}\n'


def test_the_outbox_is_not_made_without_the_gateway(config_dir):
    config_dir.mkdir()
    (config_dir / ".env").write_text("COMPOSE_PROFILES=audit\n", encoding="utf-8")
    assert model_gateway.ensure_outbox(config_dir) is False
    assert not (config_dir / "audit" / "outbox" / "litellm.jsonl").exists()


def test_a_symlink_in_place_of_the_outbox_stops_the_render(config_dir, tmp_path):
    config_dir.mkdir()
    (config_dir / ".env").write_text("COMPOSE_PROFILES=litellm\n", encoding="utf-8")
    folder = config_dir / "audit" / "outbox"
    folder.mkdir(parents=True)
    (folder / "litellm.jsonl").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(model_gateway.ModelGatewayError, match="litellm.jsonl"):
        model_gateway.ensure_outbox(config_dir)


# ── module keys reach the judged routes only ───────────────────────────────


def test_a_module_key_is_made_with_the_judged_routes_only(config_dir, tmp_path):
    from tests.test_model_gateway import REAL_REPO, FakeLiteLLM, _key_config

    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway,
                                    need_classes={"papaia-chat": "personal"})
    (row,) = gateway.keys.values()
    assert row["allowed_routes"] == [
        "/v1/chat/completions", "/chat/completions",
        "/v1/embeddings", "/embeddings",
        "/v1/models", "/models",
    ]
    assert list(model_gateway.MODULE_ROUTES) == row["allowed_routes"]


@pytest.mark.parametrize("routes", [None, [], ["/v1/chat/completions"],
                                    ["/v1/chat/completions", "/v1/files"]])
def test_a_key_without_the_route_list_is_replaced(config_dir, tmp_path, routes):
    from tests.test_model_gateway import REAL_REPO, FakeLiteLLM, _journal_lines, _key_config

    target = _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    (row,) = gateway.keys.values()
    if routes is None:
        del row["allowed_routes"]  # as a core before the class guard made it
    else:
        row["allowed_routes"] = routes
    old = row["token"]
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway) == "replaced"
    (new,) = gateway.keys.values()
    assert new["token"] != old
    assert new["allowed_routes"] == list(model_gateway.MODULE_ROUTES)
    assert [e["object_ref"] for e in _journal_lines(target)] == [old]


def test_a_key_with_the_route_list_is_kept(config_dir, tmp_path):
    from tests.test_model_gateway import REAL_REPO, FakeLiteLLM, _key_config

    _key_config(config_dir, tmp_path)
    gateway = FakeLiteLLM()
    model_gateway.ensure_module_key(config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway)
    assert model_gateway.ensure_module_key(
        config_dir, REAL_REPO, "flow", ["papaia-chat"], gateway) == "unchanged"
