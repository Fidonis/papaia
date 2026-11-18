"""Conversation titles in the language of the conversation (src/ai/librechat/librechat.yaml).

LibreChat's default title prompt says nothing about the language, so titles came back
in English for conversations in other languages. The core endpoint carries its own
`titlePrompt`. LibreChat formats it as a LangChain f-string template with `{convo}`,
so any other brace would break title generation; and `endpoints.all` would replace
the title settings of every endpoint, so it stays unset.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

LIBRECHAT_YAML = Path(__file__).resolve().parents[2] / "src" / "ai" / "librechat" / "librechat.yaml"


def _config() -> dict:
    return yaml.safe_load(LIBRECHAT_YAML.read_text(encoding="utf-8"))


def _core_endpoint() -> dict:
    custom = _config()["endpoints"]["custom"]
    return next(e for e in custom if e["name"] == "Private-LLM")


def test_the_core_endpoint_generates_titles_with_its_own_prompt() -> None:
    endpoint = _core_endpoint()
    assert endpoint["titleConvo"] is True
    assert isinstance(endpoint.get("titlePrompt"), str)


def test_the_title_prompt_asks_for_the_language_of_the_user() -> None:
    prompt = _core_endpoint()["titlePrompt"]
    assert "language the user writes in" in prompt
    assert "Never translate" in prompt


def test_the_title_prompt_has_the_conversation_as_its_only_placeholder() -> None:
    prompt = _core_endpoint()["titlePrompt"]
    assert re.findall(r"[{}]", prompt) == ["{", "}"]
    assert prompt.rstrip().endswith("{convo}")


def test_the_title_runs_as_a_plain_completion() -> None:
    # `functions` / `structured` need tool calling or JSON output, which small local
    # models behind LiteLLM often lack; the completion method works with any model.
    assert _core_endpoint().get("titleMethod", "completion") == "completion"


def test_no_endpoint_wide_override_shadows_the_per_endpoint_title_settings() -> None:
    assert "all" not in (_config().get("endpoints") or {})
