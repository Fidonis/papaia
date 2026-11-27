"""The images moved in 1.10.0 keep both halves of their pin: the release the update
asked for and the form every core pin has (`<name>:<tag>@sha256:<digest>`, rotated logs).

Losing either half fails here: an update that drops the digest, a re-pin that falls
back to the older release, or a service that loses its log rotation while its image
line is rewritten."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[2] / "src"

# compose file, service -> the pinned reference
BUMPED = {
    ("ai/librechat", "librechat"): (
        "ghcr.io/librechat-ai/librechat:v0.8.9"
        "@sha256:4a3967a47031c1fdba8302a6a341be7671101e40b617f7934ba25aac69fcea2b"
    ),
    ("ai/librechat", "librechat-ragapi"): (
        "ghcr.io/librechat-ai/librechat-rag-api-dev-lite:v0.9.1"
        "@sha256:6454a8e5df26bbef13b901f5ff57b36d3c5fe34c1c994173569398a1e08d76f4"
    ),
    ("ai/litellm", "litellm"): (
        "ghcr.io/berriai/litellm:1.110.2"
        "@sha256:ef798594ca3db8d81bad2e1439f536f49b71fe095ee9f20416f5e149b4e22035"
    ),
    ("ai/rag", "qdrant"): (
        "qdrant/qdrant:v1.20.2"
        "@sha256:d277592721d2e3b73f9b797b53cf05e6a5bb2134f6d13fdbda4ca51782afbcac"
    ),
    ("ai/rag", "qdrant-ingest"): (
        "ghcr.io/fidonis/qdrant-ingest:1.1.0"
        "@sha256:597dcc5e7efd212c891ad4f7467d9f6411acf597869184c6b58db38cb73f8f7c"
    ),
    ("ai/rag", "qdrant-ingest-tika"): (
        "docker.io/apache/tika:4.2.0-1"
        "@sha256:b99f19c4fd76237dafe7d22f719b9bddfa9a449da687c597a41e2f6d9a595418"
    ),
    ("services/firecrawl", "firecrawl"): (
        "ghcr.io/firecrawl/firecrawl:2.11.807"
        "@sha256:81de6684d17d00f3787b525b341076f96926bfd62cbc387c2abc197d4fc401ac"
    ),
}

# Published under moving tags only: pinned by digest with a recorded tag exception.
TAGLESS = {
    ("ai/mcp-firecrawl", "mcp-firecrawl"): (
        "ghcr.io/firecrawl/firecrawl-mcp-server"
        "@sha256:92feb480268c790c122359a8d875d763ac274f6e40ede5462e106fc964ca14e0"
    ),
}


def _service(directory: str, name: str) -> dict:
    document = yaml.safe_load((SRC / directory / "docker-compose.yml").read_text("utf-8"))
    return document["services"][name]


@pytest.mark.parametrize(("where", "ref"), sorted({**BUMPED, **TAGLESS}.items()))
def test_a_bumped_image_is_pinned_to_the_new_release_by_digest(where, ref):
    service = _service(*where)
    assert service["image"] == ref
    # The core's log rotation (BE-27) is part of every core service, bumped or not.
    assert service.get("logging", {}).get("driver") == "json-file", where


def test_the_tagless_pin_carries_a_tag_exception_for_exactly_its_digest():
    exceptions = yaml.safe_load(
        (SRC.parent / "compat" / "image-exceptions.yaml").read_text("utf-8")
    )["exceptions"]
    for ref in TAGLESS.values():
        name, digest = ref.split("@", 1)
        entries = [e for e in exceptions if e["image"] == name]
        assert [e["digest"] for e in entries] == [digest]
        assert entries[0]["rule"] == "tag" and entries[0]["reason"].strip()
