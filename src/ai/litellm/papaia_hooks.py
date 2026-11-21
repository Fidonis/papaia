# ═══════════════════════════════════════════════════════════════════════════
# papAIa — LiteLLM · Proxy hooks
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════
# Mounted read-only next to /app/config.yaml and registered under
# litellm_settings.callbacks (LiteLLM resolves `papaia_hooks.<name>` against
# the config file's directory).
#
# Two hooks. The first: a deployment marked `model_info: {discoverable: false}` disappears
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

import json
import os
import stat

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
            from fastapi import HTTPException

            raise HTTPException(
                status_code=503,
                detail={"error": {"code": "platform_halt", "message": HALT_MESSAGE}},
            )
        return data


papaia_platform_halt = _PlatformHalt()
