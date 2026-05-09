"""
doc-rag / api
=============
Role: Query interface and MCP server.

Exposes MCP tools over the streamable-HTTP transport, plus HTTP utility
endpoints for operations and monitoring.

MCP tools:
  search_documents  — semantic search over all (or one) indexed collection(s)
  list_collections  — enumerate available document sources

HTTP endpoints:
  GET  /health    — liveness/readiness check; returns collection list and status
  POST /reindex   — trigger re-indexing of a collection (or all) on next scan
                    ?source=<name>  scope to one collection; omit for full reindex

MCP endpoint:
  POST /mcp       — consumed by LibreChat or any MCP-capable client
"""

import os
import re
import time
import logging
from pathlib import Path

import uvicorn
from openai import OpenAI
from qdrant_client import QdrantClient
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from shared.log import configure

configure("doc-rag-api")
log = logging.getLogger(__name__)


# ── Configuration (all tunable via environment) ───────────────────────────────

LITELLM_URL        = os.environ["LITELLM_URL"]
LITELLM_API_KEY    = os.environ["LITELLM_API_KEY"]
EMBED_MODEL        = os.environ["EMBED_MODEL"]
QDRANT_URL         = os.environ["QDRANT_URL"]

DEFAULT_TOP_K      = int(os.getenv("DEFAULT_TOP_K", "5"))
DEFAULT_MIN_SCORE  = float(os.getenv("DEFAULT_MIN_SCORE", "0.5"))
QDRANT_RETRIES     = int(os.getenv("QDRANT_RETRIES", "30"))
QDRANT_RETRY_DELAY = float(os.getenv("QDRANT_RETRY_DELAY", "3.0"))
MCP_HOST           = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT           = int(os.getenv("MCP_PORT", "8000"))
STATE_PATH         = Path(os.getenv("STATE_PATH", "/data/state"))

REINDEX_DIR = STATE_PATH / "reindex"

# Regex for valid collection names (same sanitization as ingester)
_COLLECTION_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]*$')


# ── Clients ───────────────────────────────────────────────────────────────────

embed_client = OpenAI(base_url=LITELLM_URL, api_key=LITELLM_API_KEY)
qdrant       = QdrantClient(url=QDRANT_URL)


# ── Startup checks ────────────────────────────────────────────────────────────

def wait_for_qdrant() -> None:
    """Block until Qdrant is reachable or raise after QDRANT_RETRIES attempts."""
    for attempt in range(1, QDRANT_RETRIES + 1):
        try:
            qdrant.get_collections()
            log.info("Qdrant is ready.")
            return
        except Exception:
            log.info("Waiting for Qdrant (%d/%d)…", attempt, QDRANT_RETRIES)
            time.sleep(QDRANT_RETRY_DELAY)
    raise RuntimeError(
        f"Qdrant did not become ready after {QDRANT_RETRIES} attempts at {QDRANT_URL}."
    )


def probe_embedding_service() -> None:
    """
    Verify the embedding service is reachable on startup. Non-fatal: the API
    can still serve health and reindex requests if LiteLLM is temporarily down.
    """
    try:
        embed_client.embeddings.create(model=EMBED_MODEL, input="startup-probe")
        log.info("Embedding service is ready (model=%s).", EMBED_MODEL)
    except Exception as exc:
        log.warning(
            "Embedding service probe failed at startup (model=%s): %s. "
            "Search will fail until the service becomes available.",
            EMBED_MODEL, exc,
        )


# ── Search ────────────────────────────────────────────────────────────────────

def get_embedding(text: str) -> list[float]:
    try:
        return embed_client.embeddings.create(model=EMBED_MODEL, input=text).data[0].embedding
    except Exception as exc:
        log.error("Embedding request failed (model=%s): %s", EMBED_MODEL, exc)
        raise


def _get_collections() -> list[str]:
    return [c.name for c in qdrant.get_collections().collections]


def search(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    min_score: float = DEFAULT_MIN_SCORE,
    collection: str | None = None,
) -> list[dict]:
    """
    Embed the query and search one or all Qdrant collections.
    Results are merged across collections and re-ranked by score descending.
    """
    vector      = get_embedding(query)
    collections = [collection] if collection else _get_collections()

    if not collections:
        log.warning("No Qdrant collections found — nothing to search.")
        return []

    results: list[dict] = []
    for col in collections:
        try:
            hits = qdrant.query_points(
                collection_name=col,
                query=vector,
                limit=top_k,
                score_threshold=min_score,
                with_payload=True,
            )
        except Exception as exc:
            log.warning("Search failed in collection '%s' (skipped): %s", col, exc)
            continue

        for h in hits.points:
            payload = h.payload or {}
            results.append({
                "content":    payload.get("text", ""),
                "source":     payload.get("source", "unknown"),
                "title":      payload.get("title", ""),
                "collection": col,
                "score":      round(h.score, 4),
                "ingested_at": payload.get("ingested_at", ""),
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_k]


# ── MCP server ────────────────────────────────────────────────────────────────

mcp = FastMCP("doc-rag", host=MCP_HOST, port=MCP_PORT)


@mcp.tool()
def search_documents(query: str, top_k: int = DEFAULT_TOP_K, collection: str = "") -> str:
    """Search personal documents stored in the connected document sources.

    Performs a semantic (vector) similarity search over all indexed document
    collections. By default all sources are searched and results are merged
    and ranked by relevance.

    Use this tool when the user asks about information that may be contained
    in their personal files: reports, contracts, notes, PDFs, etc.

    Args:
        query:      Natural-language description of what to look for.
                    Must be a non-empty string.
        top_k:      Maximum number of results to return. Default: 5. Range: 1–20.
        collection: Restrict the search to a specific source by name
                    (e.g. "nextcloud"). Leave empty to search all sources.
                    Use list_collections to see available names.

    Returns:
        Formatted search results with source file, collection, relevance
        score, and the relevant text excerpt. Returns a message if no
        results were found or if the query is invalid.
    """
    query = query.strip()
    if not query:
        return "Error: query must not be empty."

    if top_k < 1 or top_k > 20:
        return "Error: top_k must be between 1 and 20."

    scope = collection.strip() or None
    if scope:
        known = _get_collections()
        if scope not in known:
            known_str = ", ".join(f"`{c}`" for c in sorted(known)) or "none"
            return (
                f"Error: unknown collection '{scope}'. "
                f"Known collections: {known_str}. "
                f"Use list_collections to see available sources."
            )

    try:
        results = search(query, top_k=top_k, collection=scope)
    except Exception as exc:
        log.exception("Unhandled error during document search")
        return f"Error: document search failed — {exc}"

    if not results:
        scope_hint = f" in collection '{scope}'" if scope else ""
        return f"No relevant documents found{scope_hint}."

    sections = []
    for r in results:
        header = (
            f"**Source:** `{r['source']}` | "
            f"**Collection:** `{r['collection']}` | "
            f"**Score:** {r['score']}"
        )
        if r.get("title"):
            header += f" | **Title:** {r['title']}"
        sections.append(f"{header}\n\n{r['content']}")

    return "\n\n---\n\n".join(sections)


@mcp.tool()
def list_collections() -> str:
    """List all indexed document collections available for search.

    Returns the names of all document sources that have been indexed and
    are available for semantic search. Use these names with the `collection`
    argument of search_documents to scope a search to a specific source.

    Returns:
        A formatted list of available collection names, or a message if
        no collections have been indexed yet.
    """
    try:
        cols = _get_collections()
    except Exception as exc:
        log.exception("Failed to list collections")
        return f"Error: could not retrieve collections — {exc}"

    if not cols:
        return "No document collections are currently indexed."

    return "Available collections:\n" + "\n".join(f"- `{c}`" for c in sorted(cols))


# ── HTTP utility endpoints ────────────────────────────────────────────────────

async def health_endpoint(request: Request) -> JSONResponse:
    """GET /health — liveness and readiness check."""
    try:
        cols = _get_collections()
        return JSONResponse({
            "status":           "ok",
            "collections":      sorted(cols),
            "collection_count": len(cols),
            "embed_model":      EMBED_MODEL,
            "qdrant_url":       QDRANT_URL,
        })
    except Exception as exc:
        log.exception("Health check failed")
        return JSONResponse(
            {"status": "error", "error": str(exc)},
            status_code=503,
        )


async def reindex_endpoint(request: Request) -> JSONResponse:
    """
    POST /reindex — trigger re-indexing on the next ingester scan cycle.

    Query parameters:
      source=<name>  Scope to a single collection (must match an existing name).
                     Omit to trigger a full reindex of all collections.

    The endpoint writes a trigger file into STATE_PATH/reindex/ that the
    ingester picks up at the start of its next scan.
    """
    source = request.query_params.get("source", "").strip()

    if source and not _COLLECTION_NAME_RE.match(source):
        return JSONResponse(
            {"error": "Invalid source name. Use lowercase alphanumeric characters and hyphens."},
            status_code=400,
        )

    try:
        REINDEX_DIR.mkdir(parents=True, exist_ok=True)
        if source:
            (REINDEX_DIR / source).touch()
            log.info("Reindex trigger created for source '%s'.", source)
            return JSONResponse({"triggered": source, "scope": "collection"})
        else:
            (REINDEX_DIR / "__all__").touch()
            log.info("Full reindex trigger created.")
            return JSONResponse({"triggered": "__all__", "scope": "all"})
    except Exception as exc:
        log.exception("Failed to create reindex trigger")
        return JSONResponse({"error": str(exc)}, status_code=500)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(
        "Starting doc-rag API | qdrant=%s | model=%s | host=%s | port=%d",
        QDRANT_URL, EMBED_MODEL, MCP_HOST, MCP_PORT,
    )
    wait_for_qdrant()
    probe_embedding_service()

    # Compose: custom HTTP routes in front, MCP app behind
    mcp_app = mcp.streamable_http_app()
    app = Starlette(routes=[
        Route("/health",  health_endpoint),
        Route("/reindex", reindex_endpoint, methods=["POST"]),
        Mount("/", app=mcp_app),
    ])

    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT, log_config=None)
