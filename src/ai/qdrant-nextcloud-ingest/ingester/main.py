"""
qdrant-nextcloud-ingest / ingester
==================================
Role: Document processing pipeline driven by Nextcloud (WebDAV) sync.

Watches /data/docs/ on a configurable interval. Each second-level directory
(i.e. each top-level folder inside a WebDAV source) maps to a dedicated
Qdrant collection named after that folder. When a file is new or has
changed (mtime), it is converted to text, split into overlapping chunks,
embedded via LiteLLM, and upserted into Qdrant.

Text extraction:
  .md / .txt  — direct file read
  .pdf        — pypdf (digital PDFs; scanned PDFs are skipped, no OCR)
  .docx       — python-docx

Collection naming:
  /data/docs/{source}/{folder}/...   →  Qdrant collection "{folder}"
  /data/docs/{source}/file-in-root   →  ignored (no per-folder collection)
  Folder names are sanitized to lowercase alphanumeric + hyphens.

State persistence:
  Mtime index is persisted to a SQLite database at STATE_PATH/ingest.db so
  that container restarts do not trigger a full re-index.

Reindex triggers:
  Drop a file named after the collection (or "__all__") into
  STATE_PATH/reindex/ to force re-indexing on the next scan. The bundled
  FastMCP server exposes trigger_reindex() that creates such trigger files.

FastMCP server:
  Runs on INGEST_MCP_HOST:INGEST_MCP_PORT/INGEST_MCP_PATH. Tools:
    - trigger_reindex(collection?)  — force re-ingest
    - get_status()                  — last scan time + per-collection counts
    - list_sources()                — configured WebDAV source names

The Qdrant `_collection_meta` system collection is written in a format
compatible with qdrant-rbac/qdrant-rag, so the RBAC MCP server can use the
correct embedding model for query-time vectorisation.
"""

import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import docx
import pypdf
from fastmcp import FastMCP
from openai import OpenAI
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    FilterSelector,
    MatchValue,
    PointStruct,
    VectorParams,
)


# ── Configuration (all tunable via environment) ───────────────────────────────

DOCS_PATH        = Path(os.environ["DOCS_PATH"])
STATE_PATH       = Path(os.environ.get("STATE_PATH", "/data/state"))
QDRANT_URL       = os.environ["QDRANT_URL"]
QDRANT_API_KEY   = os.environ.get("QDRANT_API_KEY") or None
LITELLM_URL      = os.environ["LITELLM_URL"]
LITELLM_API_KEY  = os.environ["LITELLM_API_KEY"]
EMBED_MODEL      = os.environ["EMBED_MODEL"]

EMBED_META_COLLECTION = os.environ.get("EMBED_META_COLLECTION", "_collection_meta")

SCAN_INTERVAL      = int(os.getenv("SCAN_INTERVAL", "60"))
CHUNK_WORDS        = int(os.getenv("CHUNK_WORDS", "400"))
CHUNK_OVERLAP      = int(os.getenv("CHUNK_OVERLAP", "50"))
EMBED_BATCH_SIZE   = int(os.getenv("EMBED_BATCH_SIZE", "32"))
EMBED_RETRIES      = int(os.getenv("EMBED_RETRIES", "3"))
EMBED_RETRY_DELAY  = float(os.getenv("EMBED_RETRY_DELAY", "5.0"))
QDRANT_RETRIES     = int(os.getenv("QDRANT_RETRIES", "30"))
QDRANT_RETRY_DELAY = float(os.getenv("QDRANT_RETRY_DELAY", "3.0"))

INGEST_MCP_HOST = os.getenv("INGEST_MCP_HOST", "0.0.0.0")
INGEST_MCP_PORT = int(os.getenv("INGEST_MCP_PORT", "8100"))
INGEST_MCP_PATH = os.getenv("INGEST_MCP_PATH", "/mcp")

LOG_LEVEL       = os.getenv("LOG_LEVEL", "INFO").upper()
WEBDAV_SOURCES  = [s.strip() for s in os.getenv("WEBDAV_SOURCES", "").split(",") if s.strip()]

STATE_DB_PATH = STATE_PATH / "ingest.db"
REINDEX_DIR   = STATE_PATH / "reindex"
SUPPORTED     = {".pdf", ".docx", ".md", ".txt"}

# Identical to qdrant-rbac/demo/bootstrap/vectorize.py so meta upserts share
# the same deterministic point id and stay idempotent across both producers.
_META_NAMESPACE = uuid.UUID("9e3a5c2f-8b7d-4f1e-a6b3-2d8c9e4f1a02")
_META_VECTOR    = [0.0]

# Scoped namespace for chunk point ids — keeps qdrant-nextcloud-ingest data
# disjoint from any other producer that might write into the same collection.
_INGEST_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "qdrant-nextcloud-ingest")

PDF_MIN_CHARS_PER_PAGE = 100


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("ingester")


# ── Clients ───────────────────────────────────────────────────────────────────

embed_client = OpenAI(base_url=LITELLM_URL, api_key=LITELLM_API_KEY)
qdrant       = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)

_verified_collections: set[str] = set()


# ── State persistence (SQLite) ────────────────────────────────────────────────

_db: sqlite3.Connection | None = None
_db_lock = threading.Lock()


def _get_db() -> sqlite3.Connection:
    global _db
    if _db is None:
        STATE_PATH.mkdir(parents=True, exist_ok=True)
        _db = sqlite3.connect(str(STATE_DB_PATH), check_same_thread=False)
        _db.execute("""
            CREATE TABLE IF NOT EXISTS indexed_files (
                collection TEXT NOT NULL,
                rel_path   TEXT NOT NULL,
                mtime      REAL NOT NULL,
                PRIMARY KEY (collection, rel_path)
            )
        """)
        _db.commit()
        log.info("State DB ready at %s", STATE_DB_PATH)
    return _db


def load_indexed() -> dict[str, dict[str, float]]:
    result: dict[str, dict[str, float]] = {}
    with _db_lock:
        for collection, rel, mtime in _get_db().execute(
            "SELECT collection, rel_path, mtime FROM indexed_files"
        ):
            result.setdefault(collection, {})[rel] = mtime
    return result


def save_mtime(indexed: dict, collection: str, rel: str, mtime: float) -> None:
    indexed.setdefault(collection, {})[rel] = mtime
    with _db_lock:
        _get_db().execute(
            "INSERT OR REPLACE INTO indexed_files (collection, rel_path, mtime) VALUES (?, ?, ?)",
            (collection, rel, mtime),
        )
        _get_db().commit()


def remove_file_state(indexed: dict, collection: str, rel: str) -> None:
    indexed.get(collection, {}).pop(rel, None)
    with _db_lock:
        _get_db().execute(
            "DELETE FROM indexed_files WHERE collection = ? AND rel_path = ?",
            (collection, rel),
        )
        _get_db().commit()


def apply_reindex_triggers(indexed: dict) -> None:
    """Consume trigger files dropped under STATE_PATH/reindex/ and clear state."""
    if not REINDEX_DIR.exists():
        return
    for trigger in list(REINDEX_DIR.iterdir()):
        if not trigger.is_file():
            continue
        col = trigger.name
        with _db_lock:
            if col == "__all__":
                indexed.clear()
                _get_db().execute("DELETE FROM indexed_files")
                _get_db().commit()
                log.info("Full reindex triggered — all state cleared.")
            else:
                indexed.pop(col, None)
                _get_db().execute(
                    "DELETE FROM indexed_files WHERE collection = ?", (col,)
                )
                _get_db().commit()
                log.info("Reindex triggered for collection '%s'.", col)
        trigger.unlink(missing_ok=True)


# ── Collection naming ─────────────────────────────────────────────────────────

def sanitize_collection_name(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^a-z0-9]+", "-", name)
    name = name.strip("-")
    if not name:
        raise ValueError("Folder name produced an empty collection name after sanitization.")
    return name


def collection_for(path: Path) -> str | None:
    """
    Map a file path to its Qdrant collection.

    The first path component under DOCS_PATH is the WebDAV source name
    (e.g. "nextcloud"); the second component is the Nextcloud top-level
    folder, which becomes the collection. Files placed directly in the
    source root (no second-level folder) are skipped.
    """
    parts = path.relative_to(DOCS_PATH).parts
    if len(parts) < 3:
        return None
    return sanitize_collection_name(parts[1])


# ── Chunking ──────────────────────────────────────────────────────────────────

_HEADING_SPLIT_RE = re.compile(r"(?m)^(?=#{1,6} )")
_FIRST_HEADING_RE = re.compile(r"^#{1,6}\s+(.+)$", re.MULTILINE)


def extract_title(text: str, path: Path) -> str:
    match = _FIRST_HEADING_RE.search(text)
    return match.group(1).strip() if match else path.stem


def chunk_text(text: str) -> list[str]:
    """Markdown heading-aware chunking with word-count fallback."""
    raw_sections = [s.strip() for s in _HEADING_SPLIT_RE.split(text) if s.strip()]

    chunks: list[str] = []
    for section in raw_sections:
        words = section.split()
        if len(words) <= CHUNK_WORDS:
            chunks.append(section)
            continue

        first_line, _, body = section.partition("\n")
        if first_line.startswith("#"):
            heading       = first_line.strip()
            heading_words = heading.split()
            body_words    = body.split()
        else:
            heading       = ""
            heading_words = []
            body_words    = words

        max_body = max(1, CHUNK_WORDS - len(heading_words))
        step     = max(1, max_body - CHUNK_OVERLAP)
        for i in range(0, len(body_words), step):
            sub_words = body_words[i : i + max_body]
            if not sub_words:
                continue
            chunk = (heading + "\n\n" + " ".join(sub_words)) if heading else " ".join(sub_words)
            chunks.append(chunk)

    if not chunks:
        words = text.split()
        step  = max(1, CHUNK_WORDS - CHUNK_OVERLAP)
        return [
            " ".join(words[i : i + CHUNK_WORDS])
            for i in range(0, len(words), step)
            if words[i : i + CHUNK_WORDS]
        ]
    return chunks


# ── Text extraction ───────────────────────────────────────────────────────────

def _try_pypdf(path: Path) -> str | None:
    try:
        reader = pypdf.PdfReader(str(path))
        if not reader.pages:
            return None
        parts = [page.extract_text() or "" for page in reader.pages]
        text  = "\n\n".join(parts).strip()
        if len(text) / len(reader.pages) < PDF_MIN_CHARS_PER_PAGE:
            return None
        return text
    except Exception as exc:
        log.debug("pypdf could not read '%s': %s", path.name, exc)
        return None


def _extract_docx(path: Path) -> str:
    document = docx.Document(str(path))
    return "\n\n".join(p.text for p in document.paragraphs if p.text)


def extract_text(path: Path) -> str | None:
    """Return plain text, or None if the format is unsupported or unparseable."""
    suffix = path.suffix.lower()

    if suffix in {".md", ".txt"}:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".pdf":
        text = _try_pypdf(path)
        if text is None:
            log.info("'%s': skipped — scanned PDF or no extractable text.", path.name)
        return text
    if suffix == ".docx":
        try:
            return _extract_docx(path)
        except Exception as exc:
            log.warning("'%s': docx extraction failed: %s", path.name, exc)
            return None
    return None


# ── Qdrant helpers ────────────────────────────────────────────────────────────

def wait_for_qdrant() -> None:
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


def ensure_collection(name: str, vector_dim: int) -> None:
    if name in _verified_collections:
        return
    existing = {c.name for c in qdrant.get_collections().collections}
    if name not in existing:
        qdrant.create_collection(
            collection_name=name,
            vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE),
        )
        log.info("Created Qdrant collection '%s' (dim=%d).", name, vector_dim)
    else:
        info = qdrant.get_collection(name)
        existing_dim = info.config.params.vectors.size
        if existing_dim != vector_dim:
            raise RuntimeError(
                f"Collection '{name}' exists with dim={existing_dim}, "
                f"but the current embedding model produces dim={vector_dim}. "
                f"Delete the collection manually or switch embedding models."
            )
    _verified_collections.add(name)


def ensure_meta_collection() -> None:
    existing = {c.name for c in qdrant.get_collections().collections}
    if EMBED_META_COLLECTION not in existing:
        qdrant.create_collection(
            collection_name=EMBED_META_COLLECTION,
            vectors_config=VectorParams(size=1, distance=Distance.COSINE),
        )
        log.info("Created meta collection '%s'.", EMBED_META_COLLECTION)


def upsert_meta_entry(collection: str, vector_dim: int) -> None:
    """Write the per-collection embedding model record consumed by qdrant-rbac."""
    point_id = str(uuid.uuid5(_META_NAMESPACE, collection))
    qdrant.upsert(
        collection_name=EMBED_META_COLLECTION,
        points=[
            PointStruct(
                id=point_id,
                vector=_META_VECTOR,
                payload={
                    "collection":       collection,
                    "embedding_model":  EMBED_MODEL,
                    "vector_dimension": vector_dim,
                },
            )
        ],
        wait=True,
    )


# ── Embedding ─────────────────────────────────────────────────────────────────

def get_embedding(text: str) -> list[float]:
    return embed_client.embeddings.create(model=EMBED_MODEL, input=text).data[0].embedding


def get_embeddings_batch(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    response = embed_client.embeddings.create(model=EMBED_MODEL, input=texts)
    return [item.embedding for item in sorted(response.data, key=lambda x: x.index)]


def probe_embedding_dim() -> int:
    last_exc: Exception | None = None
    for attempt in range(1, EMBED_RETRIES + 1):
        try:
            return len(get_embedding("dimension-probe"))
        except Exception as exc:
            last_exc = exc
            if attempt < EMBED_RETRIES:
                log.warning(
                    "Embedding probe failed (%d/%d), retrying in %.0fs: %s",
                    attempt, EMBED_RETRIES, EMBED_RETRY_DELAY, exc,
                )
                time.sleep(EMBED_RETRY_DELAY)
    raise RuntimeError(
        f"Embedding service at {LITELLM_URL} did not respond after "
        f"{EMBED_RETRIES} attempts: {last_exc}"
    )


# ── Ingestion ─────────────────────────────────────────────────────────────────

def _point_id(rel: str, idx: int) -> str:
    """Deterministic point id so re-embeds overwrite cleanly."""
    return str(uuid.uuid5(_INGEST_NAMESPACE, f"{rel}#{idx}"))


def _delete_existing(collection: str, rel: str) -> None:
    try:
        qdrant.delete(
            collection_name=collection,
            points_selector=FilterSelector(
                filter=Filter(
                    must=[FieldCondition(key="source", match=MatchValue(value=rel))]
                )
            ),
        )
    except Exception as exc:
        log.warning("[%s] could not delete stale vectors for '%s': %s", collection, rel, exc)


def ingest(path: Path, collection: str, vector_dim: int, indexed: dict) -> None:
    rel = path.relative_to(DOCS_PATH).as_posix()
    log.info("[%s] ingesting %s", collection, rel)

    text = extract_text(path)
    if text is None:
        return

    chunks = chunk_text(text)
    if not chunks:
        log.warning("[%s] no extractable text in '%s' — skipped.", collection, rel)
        return

    ensure_collection(collection, vector_dim)
    upsert_meta_entry(collection, vector_dim)
    _delete_existing(collection, rel)

    title       = extract_title(text, path)
    file_mtime  = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    ingested_at = datetime.now(tz=timezone.utc).isoformat()

    all_embeddings: list[list[float]] = []
    for batch_start in range(0, len(chunks), EMBED_BATCH_SIZE):
        batch = chunks[batch_start : batch_start + EMBED_BATCH_SIZE]
        try:
            all_embeddings.extend(get_embeddings_batch(batch))
        except Exception as exc:
            log.error(
                "[%s] batch embedding failed (chunks %d-%d of '%s'): %s "
                "— file will be retried on next scan.",
                collection, batch_start + 1, batch_start + len(batch), rel, exc,
            )
            return

    if len(all_embeddings) != len(chunks):
        log.error(
            "[%s] embedding count mismatch for '%s' (%d chunks, %d vectors)",
            collection, rel, len(chunks), len(all_embeddings),
        )
        return

    points = [
        PointStruct(
            id=_point_id(rel, i),
            vector=vector,
            payload={
                "text":         chunk,
                "source":       rel,
                "collection":   collection,
                "title":        title,
                "chunk_index":  i,
                "total_chunks": len(chunks),
                "file_type":    path.suffix.lower().lstrip("."),
                "file_mtime":   file_mtime,
                "ingested_at":  ingested_at,
            },
        )
        for i, (chunk, vector) in enumerate(zip(chunks, all_embeddings))
    ]

    qdrant.upsert(collection_name=collection, points=points)
    log.info("[%s] indexed %d chunks from '%s'.", collection, len(points), rel)
    save_mtime(indexed, collection, rel, path.stat().st_mtime)


def cleanup_deleted(indexed: dict, disk_files: dict[str, set[str]]) -> None:
    for collection, files in list(indexed.items()):
        on_disk = disk_files.get(collection, set())
        for rel in list(files.keys()):
            if rel not in on_disk:
                log.info(
                    "[%s] '%s' removed from source — deleting from index.",
                    collection, rel,
                )
                _delete_existing(collection, rel)
                remove_file_state(indexed, collection, rel)


# ── Scan loop ─────────────────────────────────────────────────────────────────

_last_scan_at: str | None = None
_indexed: dict[str, dict[str, float]] = {}


def scan(vector_dim: int) -> None:
    global _last_scan_at
    apply_reindex_triggers(_indexed)

    disk_files: dict[str, set[str]] = {}
    for path in DOCS_PATH.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED:
            continue
        collection = collection_for(path)
        if collection is None:
            log.debug("Skipping '%s' — no second-level folder.", path)
            continue
        rel   = path.relative_to(DOCS_PATH).as_posix()
        mtime = path.stat().st_mtime
        disk_files.setdefault(collection, set()).add(rel)
        if _indexed.get(collection, {}).get(rel) != mtime:
            ingest(path, collection, vector_dim, _indexed)

    cleanup_deleted(_indexed, disk_files)
    _last_scan_at = datetime.now(tz=timezone.utc).isoformat()


def scan_loop(vector_dim: int) -> None:
    log.info("Scan loop started (interval=%ds).", SCAN_INTERVAL)
    while True:
        try:
            scan(vector_dim)
        except Exception:
            log.exception("Scan cycle failed — will retry in %ds.", SCAN_INTERVAL)
        time.sleep(SCAN_INTERVAL)


# ── FastMCP server ────────────────────────────────────────────────────────────

mcp = FastMCP("qdrant-nextcloud-ingest")


@mcp.tool()
def trigger_reindex(collection: str | None = None) -> dict:
    """
    Force re-ingestion on the next scan cycle.

    Args:
        collection: optional collection name to reindex. Omit to reindex everything.

    Returns:
        A dict describing what was scheduled.
    """
    REINDEX_DIR.mkdir(parents=True, exist_ok=True)
    target = collection.strip() if collection else "__all__"
    if not target:
        target = "__all__"
    (REINDEX_DIR / target).touch()
    return {"triggered": target, "scope": "collection" if target != "__all__" else "all"}


@mcp.tool()
def get_status() -> dict:
    """Return the last scan timestamp and per-collection file counts."""
    counts = {col: len(files) for col, files in _indexed.items()}
    return {
        "last_scan_at":   _last_scan_at,
        "scan_interval":  SCAN_INTERVAL,
        "docs_path":      str(DOCS_PATH),
        "qdrant_url":     QDRANT_URL,
        "embed_model":    EMBED_MODEL,
        "collections":    counts,
        "total_files":    sum(counts.values()),
    }


@mcp.tool()
def list_sources() -> dict:
    """Return the configured WebDAV source names (as declared in WEBDAV_SOURCES)."""
    return {"sources": list(WEBDAV_SOURCES)}


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    log.info(
        "Starting qdrant-nextcloud-ingest | docs=%s | model=%s | qdrant=%s | interval=%ds",
        DOCS_PATH, EMBED_MODEL, QDRANT_URL, SCAN_INTERVAL,
    )
    wait_for_qdrant()

    vector_dim = probe_embedding_dim()
    log.info("Embedding dimension: %d.", vector_dim)

    ensure_meta_collection()

    global _indexed
    _indexed = load_indexed()
    log.info(
        "Loaded %d previously indexed files from state DB.",
        sum(len(v) for v in _indexed.values()),
    )

    t = threading.Thread(target=scan_loop, args=(vector_dim,), daemon=True)
    t.start()

    log.info(
        "FastMCP server listening on %s:%d%s",
        INGEST_MCP_HOST, INGEST_MCP_PORT, INGEST_MCP_PATH,
    )
    mcp.run(
        transport="http",
        host=INGEST_MCP_HOST,
        port=INGEST_MCP_PORT,
        path=INGEST_MCP_PATH,
    )


if __name__ == "__main__":
    main()
