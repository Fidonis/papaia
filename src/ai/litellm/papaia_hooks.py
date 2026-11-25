# ═══════════════════════════════════════════════════════════════════════════
# papAIa — LiteLLM · Proxy hooks
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════
# Mounted read-only next to /app/config.yaml and registered under
# litellm_settings.callbacks (LiteLLM resolves `papaia_hooks.<name>` against
# the config file's directory).
#
# Three hooks. The first: a deployment marked `model_info: {discoverable: false}` disappears
# from the model listings (`/v1/models`, `/model/info`, ...) for EVERY key.
# LiteLLM's own `discoverable` flag spares keys with an admin view, and the
# one key this stack hands out to LibreChat aliases the master key — without
# this hook the non-chat routes (the voice profile's voice-stt/voice-tts)
# would appear as selectable chat models in every user's model menu and fail
# on first use. Hiding is presentation-only: a hidden route stays callable.
#
# The second: while the platform halt is active (docs/halt.md), every request of
# every key is refused before it reaches a model, chat included. The halt file
# lives in the folder mounted read-only at /run/papaia-halt; it is checked with
# one stat call per request and parsed again only when it changed. A file that
# cannot be read or does not match the format counts as an active halt; no file
# is no halt. A missing folder (the mount is gone) counts as active too.
#
# The third, the class guard (ADR 0031, docs/model-gateway.md): every model call made with
# a key other than the master key is judged before LiteLLM routes it. The request class
# is the header x-papaia-data-class (one value of the kit scale), otherwise the class the
# module declared for the alias (key metadata papaia_need_classes), otherwise the highest
# class; the route class is the alias's class in the route file the core renders
# (/app/model-routes.json, read again when its file identity changes). A request above
# either is refused (403 class_exceeded), a malformed header too (400
# invalid_data_class), and every module call while the route data is missing or does not
# name the alias (503 route_class_unknown). The pinned LiteLLM hands the request headers
# to the hook as data["proxy_server_request"]["headers"], a dict with lower-case names
# that it builds from the HTTP request itself (fields of the body cannot set it). The
# guard reads the alias, that one header and the key's alias and metadata; it never
# reads, logs or stores message content. Each refusal is one papaia.audit/1 row in the
# gateway's own outbox (/run/papaia-audit/litellm.jsonl, source_seq counted in
# litellm.seq next to it); a row that cannot be written leaves the request refused.

import fcntl
import json
import os
import re
import stat
import sys
import time
import uuid

from litellm.integrations.custom_logger import CustomLogger

HALT_FILE = "/run/papaia-halt/halt.json"
HALT_MESSAGE = (
    "Die Plattform ist durch einen Not-Halt angehalten. "
    "The platform is stopped by an emergency halt."
)
_HALT_FIELDS = {"active", "since", "reason", "by"}
_HALT_MAX_BYTES = 4096


def halt_active(data):
    """Whether the bytes of a halt file mean an active halt (fails closed)."""
    if len(data) > _HALT_MAX_BYTES:
        return True
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return True
    if not isinstance(doc, dict) or set(doc) != _HALT_FIELDS:
        return True
    since, reason, by = doc["since"], doc["reason"], doc["by"]
    if isinstance(since, bool) or not isinstance(since, int) or since < 0:
        return True
    if not isinstance(reason, str) or len(reason) > 500:
        return True
    if not isinstance(by, str) or not 0 < len(by) <= 255:
        return True
    return doc["active"] is not False


class _HideUndiscoverableModels(CustomLogger):
    async def async_filter_listed_models(self, user_api_key_dict, model_names):
        try:
            from litellm.proxy.proxy_server import llm_router

            if llm_router is None:
                return model_names
            kept = []
            for name in model_names:
                deployments = llm_router.get_model_list(model_name=name) or ()
                if deployments and all(
                    (deployment.get("model_info") or {}).get("discoverable") is False
                    for deployment in deployments
                ):
                    continue
                kept.append(name)
            return kept
        except Exception:  # noqa: BLE001 — a broken filter must never break the listing
            return model_names


papaia_listing_filter = _HideUndiscoverableModels()


class _PlatformHalt(CustomLogger):
    def __init__(self, path=HALT_FILE):
        super().__init__()
        self._path = path
        self._key = None
        self._active = True

    def halted(self):
        try:
            st = os.stat(self._path, follow_symlinks=False)
        except FileNotFoundError:
            self._key = None
            return not os.path.isdir(os.path.dirname(self._path))
        except OSError:
            self._key = None
            return True
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if key != self._key:
            try:
                fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    regular = stat.S_ISREG(os.fstat(fh.fileno()).st_mode)
                    self._active = not regular or halt_active(fh.read(_HALT_MAX_BYTES + 1))
            except OSError:
                self._active = True
            self._key = key
        return self._active

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if self.halted():
            _refuse_halted()
        return data


def _refuse_halted():
    from fastapi import HTTPException

    raise HTTPException(
        status_code=503,
        detail={"error": {"code": "platform_halt", "message": HALT_MESSAGE}},
    )


papaia_platform_halt = _PlatformHalt()


# ── the class guard ─────────────────────────────────────────────────────────

ROUTES_FILE = "/app/model-routes.json"
OUTBOX_FILE = "/run/papaia-audit/litellm.jsonl"
ROUTES_FORMAT = "papaia.model-routes/1"
ROUTES_MAX_BYTES = 256 * 1024
# The data classes of the platform kit, lowest first (PLT-06).
DATA_CLASSES = (
    "public",
    "internal",
    "partner_contact",
    "personal",
    "employee",
    "confidential",
    "special",
    "professional_secret",
)
_RANK = {name: rank for rank, name in enumerate(DATA_CLASSES)}
HIGHEST_CLASS = DATA_CLASSES[-1]
CLASS_HEADER = "x-papaia-data-class"
CORRELATION_HEADER = "x-papaia-correlation-id"
ERROR_HEADER = "x-papaia-error-code"
NEED_CLASSES_KEY = "papaia_need_classes"
_CLASS_MAX = 32
_ROUTE_FIELDS = {"format", "generated_at", "routes"}
_ALIAS_RE = re.compile(r"papaia-[a-z0-9-]{1,40}")
_STAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_TOKEN_HASH_RE = re.compile(r"[0-9a-f]{64}")
# The actor of an audit row (papaia.audit/1 client_id, which also fits subject).
_ACTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CORRELATION_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
# A correlation id shaped like a prefixed key is replaced (papaia.audit/1, token_free).
_KEY_SHAPED_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{20}|glpat-[A-Za-z0-9_-]{20}|"
    r"xox[abeprs]-[A-Za-z0-9-]{10}|AKIA[0-9A-Z]{16})"
)
AUDIT_WRITER = "litellm/class-guard"
CLASS_MESSAGES = {
    "class_exceeded": (
        "Die Datenklasse der Anfrage liegt über der Klasse der Modell-Route. "
        "The data class of the request is above the class of the model route."
    ),
    "invalid_data_class": (
        "Der Kopf x-papaia-data-class ist ungültig. "
        "The header x-papaia-data-class is invalid."
    ),
    "route_class_unknown": (
        "Die Datenklasse der Modell-Route ist unbekannt. "
        "The data class of the model route is unknown."
    ),
}
_STATUS = {"class_exceeded": 403, "invalid_data_class": 400, "route_class_unknown": 503}


def parse_routes(data):
    """Alias -> class of the bytes of a route file, or None when they are not one."""
    if len(data) > ROUTES_MAX_BYTES:
        return None
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or set(doc) != _ROUTE_FIELDS:
        return None
    if doc["format"] != ROUTES_FORMAT:
        return None
    stamp = doc["generated_at"]
    if not isinstance(stamp, str) or not _STAMP_RE.fullmatch(stamp):
        return None
    routes = doc["routes"]
    if not isinstance(routes, dict):
        return None
    for alias, value in routes.items():
        if not _ALIAS_RE.fullmatch(alias) or not isinstance(value, str) or value not in _RANK:
            return None
    return dict(routes)


def _header_class(headers):
    """(present, class): the class the header names; ValueError when it is malformed."""
    found = [name for name in headers if isinstance(name, str) and name.lower() == CLASS_HEADER]
    if not found:
        return False, None
    if len(found) > 1:
        raise ValueError("repeated")
    value = headers[found[0]]
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= _CLASS_MAX
        or not value.isascii()
        or value not in _RANK
    ):
        raise ValueError("malformed")
    return True, value


def _declared_class(metadata, alias):
    """The class the module declared for the alias; the highest class without one."""
    needs = metadata.get(NEED_CLASSES_KEY) if isinstance(metadata, dict) else None
    value = needs.get(alias) if isinstance(needs, dict) and isinstance(alias, str) else None
    return value if isinstance(value, str) and value in _RANK else HIGHEST_CLASS


def _is_master(user_api_key_dict):
    """The gateway's master key. The pinned LiteLLM shows it with the role proxy_admin,
    no key alias and a fixed marker instead of a key hash; every virtual key carries the
    SHA-256 of the key, so a virtual key of an admin user is judged like any other."""
    role = getattr(user_api_key_dict, "user_role", None)
    role = getattr(role, "value", role)
    api_key = getattr(user_api_key_dict, "api_key", None)
    return (
        role == "proxy_admin"
        and getattr(user_api_key_dict, "key_alias", None) is None
        and isinstance(api_key, str)
        and not _TOKEN_HASH_RE.fullmatch(api_key)
    )


def _correlation(headers):
    value = headers.get(CORRELATION_HEADER)
    if (
        isinstance(value, str)
        and _CORRELATION_RE.fullmatch(value)
        and not _KEY_SHAPED_RE.search(value)
    ):
        return value
    return _new_correlation()


def _new_correlation():
    """A UUIDv7 (RFC 9562)."""
    millis = time.time_ns() // 1_000_000 & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (
        millis << 80 | 0x7 << 76 | (rand >> 68 & 0xFFF) << 64 | 0b10 << 62 | rand & ((1 << 62) - 1)
    )
    return str(uuid.UUID(int=value))


def _log(reason):
    print(f"papaia_class_guard: {reason}", file=sys.stderr, flush=True)


class _Outbox:
    """papaia.audit/1 rows of the gateway, one JSON line each (submission form). The
    counter of source_seq lives in a file of its own next to the outbox, so it outlives an
    outbox that was delivered and emptied; both are locked (flock on the counter) while a
    row is appended, so two workers never reuse a number."""

    def __init__(self, path):
        self.path = path
        self.seq_path = os.path.join(os.path.dirname(path), "litellm.seq")

    def _last_seq(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - 65536))
            lines = [line for line in fh.read().splitlines() if line.strip()]
        if not lines:
            return 0
        seq = json.loads(lines[-1])["source_seq"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("source_seq")
        return seq

    def append(self, row):
        fd = os.open(self.seq_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = os.pread(fd, 32, 0).decode("ascii").strip()
            if raw and not raw.isdigit():
                raise ValueError("counter")
            seq = max(int(raw or 0), self._last_seq()) + 1
            line = json.dumps({**row, "source_seq": seq}, sort_keys=True) + "\n"
            out = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            try:
                os.write(out, line.encode("utf-8"))
                os.fsync(out)
            finally:
                os.close(out)
            os.ftruncate(fd, 0)
            os.pwrite(fd, f"{seq}\n".encode("ascii"), 0)
            os.fsync(fd)
        finally:
            os.close(fd)  # releases the lock


class _ClassGuard(CustomLogger):
    def __init__(self, routes=ROUTES_FILE, outbox=OUTBOX_FILE, halt=None):
        super().__init__()
        self._routes = routes
        self._outbox = outbox
        self._halt = halt if halt is not None else papaia_platform_halt
        self._key = None
        self._classes = None

    def route_classes(self):
        """Alias -> class of the route file; None while it is missing, unreadable or
        malformed. Parsed again only when its file identity changes."""
        try:
            st = os.stat(self._routes, follow_symlinks=False)
        except OSError:
            self._key, self._classes = None, None
            return None
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if key != self._key:
            classes = None
            if stat.S_ISREG(st.st_mode):
                try:
                    fd = os.open(self._routes, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, "rb") as fh:
                        classes = parse_routes(fh.read(ROUTES_MAX_BYTES + 1))
                except OSError:
                    classes = None
            self._key, self._classes = key, classes
        return self._classes

    def judge(self, user_api_key_dict, data):
        """None when the request passes, else (code, request class or None)."""
        request = data.get("proxy_server_request") if isinstance(data, dict) else None
        headers = request.get("headers") if isinstance(request, dict) else None
        headers = headers if isinstance(headers, dict) else {}
        alias = data.get("model") if isinstance(data, dict) else None
        try:
            named, header = _header_class(headers)
        except ValueError:
            return "invalid_data_class", None
        declared = _declared_class(getattr(user_api_key_dict, "metadata", None), alias)
        requested = header if named else declared
        routes = self.route_classes()
        route = routes.get(alias) if routes is not None and isinstance(alias, str) else None
        if route is None:
            return "route_class_unknown", requested
        if _RANK[requested] > _RANK[declared] or _RANK[requested] > _RANK[route]:
            return "class_exceeded", requested
        return None

    def _row(self, user_api_key_dict, alias, data_class, code, correlation):
        actor = getattr(user_api_key_dict, "key_alias", None)
        if not isinstance(actor, str) or not _ACTOR_RE.fullmatch(actor):
            actor = None
        if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
            alias = "unknown"
        now = time.time()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        return {
            "format": "papaia.audit/1",
            "time": f"{stamp}.{int(now % 1 * 1000):03d}Z",
            "correlation_id": correlation,
            "writer": AUDIT_WRITER,
            "role": "server",
            "sub": actor,
            "identity_kind": "service",
            "service_account": actor,
            "azp": actor,
            "aud": None,
            "catalog_id": "litellm.model_request",
            "operation": "model.request",
            "effect": "check",
            "object_ref": {"type": "model_alias", "id": alias},
            "data_class": data_class,
            "result": "denied",
            "error_code": code,
            "detail": None,
            "event": "operation",
        }

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if self._halt.halted():
            _refuse_halted()
        if _is_master(user_api_key_dict):
            return data
        verdict = self.judge(user_api_key_dict, data)
        if verdict is None:
            return data
        code, data_class = verdict
        request = data.get("proxy_server_request") if isinstance(data, dict) else None
        headers = request.get("headers") if isinstance(request, dict) else None
        correlation = _correlation(headers if isinstance(headers, dict) else {})
        alias = data.get("model") if isinstance(data, dict) else None
        try:
            _Outbox(self._outbox).append(
                self._row(user_api_key_dict, alias, data_class, code, correlation)
            )
        except (OSError, ValueError, KeyError, TypeError):
            _log(f"audit_unavailable ({code})")
        from fastapi import HTTPException

        raise HTTPException(
            status_code=_STATUS[code],
            detail={"error": {"code": code, "message": CLASS_MESSAGES[code]}},
            headers={CORRELATION_HEADER: correlation, ERROR_HEADER: code},
        )


papaia_class_guard = _ClassGuard()
