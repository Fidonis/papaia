"""The SearXNG secret is generated per installation; the checkout ships no fixed value.

An earlier release shipped one fixed `secret_key` in `settings.yml`. That value counts as
public and must never be in use: every installation generates its own `SEARXNG_SECRET`,
which overrides `server.secret_key`, and the shipped settings carry only SearXNG's own
placeholder, never a working key.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from lib import common, envtree, secrets

REPO = Path(__file__).resolve().parents[2]
SEARXNG = REPO / "src" / "services" / "searxng"

# SearXNG's documented default for `server.secret_key`; it marks the value as not set.
UPSTREAM_PLACEHOLDER = "ultrasecretkey"


def _fresh_install() -> str:
    """The SEARXNG_SECRET a fresh setup generates from the shipped seed."""
    seed = envtree.load_seed_tree(REPO)
    tree = {rel_dir: dict(values) for rel_dir, values in seed.items()}
    tree = secrets.generate_missing_secrets(tree, seed)
    return tree["services/searxng"]["SEARXNG_SECRET"]


def test_the_seed_marks_the_searxng_secret_for_generation():
    seed = common.parse_env_file(SEARXNG / ".env.example")
    assert common.marks_generated_secret(seed["SEARXNG_SECRET"])


def test_each_fresh_install_generates_its_own_searxng_secret():
    first, second = _fresh_install(), _fresh_install()
    for value in (first, second):
        assert not common.is_placeholder(value)
        assert len(value) >= 32
    assert first != second


def test_the_generated_secret_reaches_the_container():
    compose = yaml.safe_load((SEARXNG / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["searxng"]["environment"]
    assert environment["SEARXNG_SECRET"] == "${SEARXNG_SECRET}"


def test_the_shipped_settings_carry_no_fixed_secret_key():
    settings = yaml.safe_load((SEARXNG / "settings.yml").read_text(encoding="utf-8"))
    assert settings["server"]["secret_key"] == UPSTREAM_PLACEHOLDER
