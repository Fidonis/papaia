"""Env prompts filled from another add-on's exported value (`default_from_addon`, #316)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lib import addons

_MANIFEST = {
    "requires": {"addons": ["provider"]},
    "env_prompts": {
        "API_KEY": {"label": "API key", "default_from_addon": "provider:PROVIDER_API_KEY"}
    },
}


def _provider_bundle(config_dir: Path, content: str) -> None:
    bundle = config_dir / "addons" / "provider"
    bundle.mkdir(parents=True)
    (bundle / ".env").write_text(content, encoding="utf-8")


def test_resolve_reads_only_exported_keys(tmp_path):
    _provider_bundle(tmp_path, "PROVIDER_API_KEY=abc\nPROVIDER_DB_PASSWORD=secret\n")
    providers = {"provider": {"exports": ["PROVIDER_API_KEY"]}}
    assert addons.resolve_addon_defaults(_MANIFEST, providers, tmp_path) == {"API_KEY": "abc"}


@pytest.mark.parametrize(
    ("manifest", "providers", "message"),
    [
        (
            {**_MANIFEST, "requires": {"addons": []}},
            {"provider": {"exports": ["PROVIDER_API_KEY"]}},
            "not listed in requires.addons",
        ),
        (_MANIFEST, {}, "not installed and active"),
        (_MANIFEST, {"provider": {}}, "does not export 'PROVIDER_API_KEY'"),
        (
            {"env_prompts": {"API_KEY": {"default_from_addon": "provider"}}},
            {},
            "must be '<addon>:<KEY>'",
        ),
    ],
)
def test_resolve_rejects(tmp_path, manifest, providers, message):
    with pytest.raises(ValueError, match=message):
        addons.resolve_addon_defaults(manifest, providers, tmp_path)


def test_resolve_skips_a_value_that_is_not_set_yet(tmp_path):
    _provider_bundle(tmp_path, "PROVIDER_API_KEY=CHANGE_ME\n")
    providers = {"provider": {"exports": ["PROVIDER_API_KEY"]}}
    assert addons.resolve_addon_defaults(_MANIFEST, providers, tmp_path) == {}


def test_interactive_prompt_offers_the_value_without_echoing_it(tmp_path, monkeypatch, capsys):
    env_path = tmp_path / ".env"
    env_path.write_text("API_KEY=CHANGE_ME\n", encoding="utf-8")
    monkeypatch.setattr(addons.sys.stdin, "isatty", lambda: True)
    asked: list[str] = []

    def fake_input(prompt: str) -> str:
        asked.append(prompt)
        return ""

    monkeypatch.setattr("builtins.input", fake_input)
    updates = addons.prompt_change_me_vars(env_path, _MANIFEST, tmp_path, {"API_KEY": "abc"})

    assert updates == {"API_KEY": "abc"}
    assert asked == ["  API key [value from provider]: "]
    assert "abc" not in capsys.readouterr().out
