# ═══════════════════════════════════════════════════════════════════════════
# papAIa — LiteLLM · Proxy hooks
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════
# Mounted read-only next to /app/config.yaml and registered under
# litellm_settings.callbacks (LiteLLM resolves `papaia_hooks.<name>` against
# the config file's directory).
#
# One hook: a deployment marked `model_info: {discoverable: false}` disappears
# from the model listings (`/v1/models`, `/model/info`, ...) for EVERY key.
# LiteLLM's own `discoverable` flag spares keys with an admin view, and the
# one key this stack hands out to LibreChat aliases the master key — without
# this hook the non-chat routes (the voice profile's voice-stt/voice-tts)
# would appear as selectable chat models in every user's model menu and fail
# on first use. Hiding is presentation-only: a hidden route stays callable.

from litellm.integrations.custom_logger import CustomLogger


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
