"""
doc-rag / ingester
==================
Role: Document processing pipeline.

Watches /data/docs/ on a configurable interval. Each top-level subdirectory
maps to a dedicated Qdrant collection (named after the directory). When a file
is new or has changed (mtime), it is converted to text, split into overlapping
chunks, embedded via LiteLLM, and upserted into Qdrant.

Text extraction strategy (fastest path first):
  .md / .txt  — direct file read, no AI
  .pdf        — pypdf for digital PDFs (milliseconds); Docling fallback for scans
  .docx / .doc — Docling

Supported formats: PDF, DOCX, DOC, Markdown, plain text.

Collection naming:
  /data/docs/{SOURCE}/{file}  →  Qdrant collection "{SOURCE}"
  Directory names are sanitized to lowercase alphanumeric + hyphens.
  Files directly in /data/docs/ (no subdirectory) are ignored.

State persistence:
  Mtime index is persisted to a SQLite database at STATE_PATH/ingester.db so
  that container restarts do not trigger a full re-index.

Reindex triggers:
  Drop a file named after the collection (or "__all__") into STATE_PATH/reindex/
  to force re-indexing of that collection on the next scan. The API exposes a
  POST /reindex endpoint that creates these trigger files.
"""

import os
import re
import sqlite3
import time
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

import pypdf
from docling.datamodel.base_models import InputFormat
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.document_converter import DocumentConverter, PdfFormatOption
from openai import OpenAI
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    FilterSelector,
)

from shared.log import configure

configure("ingester")
log = logging.getLogger(__name__)


# ── Configuration (all tunable via environment) ───────────────────────────────

DOCS_PATH          = Path(os.environ["DOCS_PATH"])
LITELLM_URL        = os.environ["LITELLM_URL"]
LITELLM_API_KEY    = os.environ["LITELLM_API_KEY"]
EMBED_MODEL        = os.environ["EMBED_MODEL"]
QDRANT_URL         = os.environ["QDRANT_URL"]

SCAN_INTERVAL      = int(os.getenv("SCAN_INTERVAL", "60"))
CHUNK_WORDS        = int(os.getenv("CHUNK_WORDS", "400"))
CHUNK_OVERLAP      = int(os.getenv("CHUNK_OVERLAP", "50"))
QDRANT_RETRIES     = int(os.getenv("QDRANT_RETRIES", "30"))
QDRANT_RETRY_DELAY = float(os.getenv("QDRANT_RETRY_DELAY", "3.0"))
EMBED_BATCH_SIZE   = int(os.getenv("EMBED_BATCH_SIZE", "32"))
EMBED_RETRIES      = int(os.getenv("EMBED_RETRIES", "3"))
EMBED_RETRY_DELAY  = float(os.getenv("EMBED_RETRY_DELAY", "5.0"))
STATE_PATH         = Path(os.getenv("STATE_PATH", "/data/state"))
# Docling PDF options — disable OCR and table detection by default for speed.
# Enable DOCLING_OCR=true only if you need to index scanned/image-only PDFs.
DOCLING_OCR        = os.getenv("DOCLING_OCR",    "false").lower() == "true"
DOCLING_TABLES     = os.getenv("DOCLING_TABLES", "false").lower() == "true"

STATE_DB_PATH = STATE_PATH / "ingester.db"
REINDEX_DIR   = STATE_PATH / "reindex"
SUPPORTED     = {".pdf", ".docx", ".doc", ".md", ".txt"}

# pypdf fast-path: if a PDF page averages fewer than this many characters,
# assume it is a scanned/image PDF and fall back to Docling.
PDF_MIN_CHARS_PER_PAGE = 100


# ── Clients ───────────────────────────────────────────────────────────────────

embed_client = OpenAI(base_url=LITELLM_URL, api_key=LITELLM_API_KEY)
qdrant       = QdrantClient(url=QDRANT_URL)

_pdf_opts = PdfPipelineOptions()
_pdf_opts.do_ocr             = DOCLING_OCR
_pdf_opts.do_table_structure = DOCLING_TABLES
converter = DocumentConverter(
    format_options={InputFormat.PDF: PdfFormatOption(pipeline_options=_pdf_opts)}
)

# Collections confirmed to exist in Qdrant with the correct dimension
_verified_collections: set[str] = set()


# ── State persistence (SQLite) ────────────────────────────────────────────────

_db: sqlite3.Connection | None = None


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
        _db.execute("""
            CREATE TABLE IF NOT EXISTS model_info (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        _db.commit()
        log.info("State DB ready at %s", STATE_DB_PATH)
    return _db


def load_indexed() -> dict[str, dict[str, float]]:
    """Load the full mtime index from SQLite into memory."""
    result: dict[str, dict[str, float]] = {}
    for collection, rel, mtime in _get_db().execute(
        "SELECT collection, rel_path, mtime FROM indexed_files"
    ):
        result.setdefault(collection, {})[rel] = mtime
    return result


def save_mtime(indexed: dict, collection: str, rel: str, mtime: float) -> None:
    """Update the in-memory index and persist to SQLite."""
    indexed.setdefault(collection, {})[rel] = mtime
    _get_db().execute(
        "INSERT OR REPLACE INTO indexed_files (collection, rel_path, mtime) VALUES (?, ?, ?)",
        (collection, rel, mtime),
    )
    _get_db().commit()


def remove_file_state(indexed: dict, collection: str, rel: str) -> None:
    """Remove a file from the in-memory index and SQLite."""
    indexed.get(collection, {}).pop(rel, None)
    _get_db().execute(
        "DELETE FROM indexed_files WHERE collection = ? AND rel_path = ?",
        (collection, rel),
    )
    _get_db().commit()


def check_and_save_model_version(model: str, dim: int) -> None:
    """
    Compare the current embedding model/dimension against what is stored in the DB.
    Logs a warning if they differ (stale vectors may exist from the previous model).
    Always updates the stored values to reflect the current configuration.
    """
    db = _get_db()
    stored = {row[0]: row[1] for row in db.execute("SELECT key, value FROM model_info")}
    if stored:
        stored_model = stored.get("model", "")
        stored_dim   = stored.get("dim", "")
        if stored_model != model or stored_dim != str(dim):
            log.warning(
                "Embedding model changed: stored=%s/dim=%s → current=%s/dim=%d. "
                "Qdrant collections may contain stale vectors from the old model. "
                "To re-index cleanly: delete the Qdrant collections and trigger a "
                "full reindex via POST /reindex.",
                stored_model, stored_dim, model, dim,
            )
    db.execute("INSERT OR REPLACE INTO model_info VALUES ('model', ?)", (model,))
    db.execute("INSERT OR REPLACE INTO model_info VALUES ('dim', ?)", (str(dim),))
    db.commit()


def apply_reindex_triggers(indexed: dict) -> None:
    """
    Check STATE_PATH/reindex/ for trigger files and clear the corresponding
    mtime state so the next scan re-ingests those files from scratch.

    Trigger file names:
      <collection>  — clears state for that specific collection
      __all__       — clears state for all collections
    """
    if not REINDEX_DIR.exists():
        return
    for trigger in list(REINDEX_DIR.iterdir()):
        if not trigger.is_file():
            continue
        col = trigger.name
        if col == "__all__":
            indexed.clear()
            _get_db().execute("DELETE FROM indexed_files")
            _get_db().commit()
            log.info("Full reindex triggered — all state cleared.")
        else:
            indexed.pop(col, None)
            _get_db().execute("DELETE FROM indexed_files WHERE collection = ?", (col,))
            _get_db().commit()
            log.info("Reindex triggered for collection '%s'.", col)
        trigger.unlink(missing_ok=True)


# ── Utilities ─────────────────────────────────────────────────────────────────

def sanitize_collection_name(name: str) -> str:
    """
    Convert an arbitrary directory name into a safe Qdrant collection name.
    Rules: lowercase, alphanumeric and hyphens only, no leading/trailing hyphens.
    """
    name = name.lower()
    name = re.sub(r"[^a-z0-9]+", "-", name)
    name = name.strip("-")
    if not name:
        raise ValueError("Directory name produced an empty collection name after sanitization.")
    return name


def collection_for(path: Path) -> str | None:
    """
    Returns the sanitized Qdrant collection name for a given file path,
    derived from its top-level subdirectory under DOCS_PATH.
    Returns None for files directly in DOCS_PATH (no source directory).
    """
    parts = path.relative_to(DOCS_PATH).parts
    if len(parts) <= 1:
        return None
    return sanitize_collection_name(parts[0])


_HEADING_SPLIT_RE  = re.compile(r'(?m)^(?=#{1,6} )')
_FIRST_HEADING_RE  = re.compile(r'^#{1,6}\s+(.+)$', re.MULTILINE)


def extract_title(text: str, path: Path) -> str:
    """Extract document title from the first Markdown heading, or fall back to filename."""
    match = _FIRST_HEADING_RE.search(text)
    return match.group(1).strip() if match else path.stem


def chunk_text(text: str) -> list[str]:
    """
    Split text into chunks respecting Markdown heading boundaries.

    Each heading section is kept as a single chunk when it fits within
    CHUNK_WORDS. Sections that overflow are split further using word-count
    chunking, with the heading prepended to every sub-chunk for retrieval
    context.

    Falls back to pure word-count chunking for plain text without headings.
    """
    raw_sections = [s.strip() for s in _HEADING_SPLIT_RE.split(text) if s.strip()]

    chunks: list[str] = []
    for section in raw_sections:
        words = section.split()
        if len(words) <= CHUNK_WORDS:
            chunks.append(section)
            continue

        # Section overflows — extract heading and chunk the body
        first_line, _, body = section.partition('\n')
        if first_line.startswith('#'):
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
        # Plain text fallback: no Markdown headings found
        words = text.split()
        step  = max(1, CHUNK_WORDS - CHUNK_OVERLAP)
        return [
            " ".join(words[i : i + CHUNK_WORDS])
            for i in range(0, len(words), step)
            if words[i : i + CHUNK_WORDS]
        ]

    return chunks


# ── Qdrant ────────────────────────────────────────────────────────────────────

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


def ensure_collection(name: str, vector_dim: int) -> None:
    """
    Create the collection if it does not exist.
    If it already exists, validate that its vector dimension matches.
    Raises RuntimeError on dimension mismatch to prevent silent data corruption.
    """
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
        log.info("Collection '%s' verified (dim=%d).", name, vector_dim)

    _verified_collections.add(name)


# ── Embedding ─────────────────────────────────────────────────────────────────

def get_embedding(text: str) -> list[float]:
    try:
        return embed_client.embeddings.create(model=EMBED_MODEL, input=text).data[0].embedding
    except Exception as exc:
        log.error("Embedding request failed (model=%s): %s", EMBED_MODEL, exc)
        raise


def get_embeddings_batch(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts in a single API call. Returns embeddings in input order."""
    if not texts:
        return []
    response = embed_client.embeddings.create(model=EMBED_MODEL, input=texts)
    return [item.embedding for item in sorted(response.data, key=lambda x: x.index)]


def probe_embedding_dim() -> int:
    """Probe the embedding dimension with retries on transient failures."""
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


# ── Text extraction ───────────────────────────────────────────────────────────

def _try_pypdf(path: Path) -> str | None:
    """
    Extract text directly from a digital PDF using pypdf.
    Returns None if the PDF appears to be scanned (average chars/page below
    PDF_MIN_CHARS_PER_PAGE) or if pypdf cannot read the file at all.
    """
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


def extract_text(path: Path) -> str:
    """
    Extract plain text from a supported document file.

      .md / .txt  — direct read, no AI
      .pdf        — pypdf fast path; Docling fallback for scanned PDFs
      .docx / .doc — Docling
    """
    suffix = path.suffix.lower()

    if suffix in {".md", ".txt"}:
        return path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".pdf":
        text = _try_pypdf(path)
        if text is not None:
            log.debug("'%s': extracted via pypdf.", path.name)
            return text
        log.info("'%s': sparse text — falling back to Docling (scanned PDF?).", path.name)

    return converter.convert(str(path)).document.export_to_markdown()


# ── Ingestion ─────────────────────────────────────────────────────────────────

def ingest(path: Path, collection: str, vector_dim: int, indexed: dict) -> None:
    """Extract, chunk, embed and upsert a single file into its collection."""
    rel = str(path.relative_to(DOCS_PATH))
    log.info("[%s] ingesting %s", collection, rel)

    try:
        text = extract_text(path)
    except Exception as exc:
        log.error("[%s] text extraction failed for '%s': %s", collection, rel, exc)
        return

    chunks = chunk_text(text)
    if not chunks:
        log.warning("[%s] no extractable text in '%s' — skipped.", collection, rel)
        return

    ensure_collection(collection, vector_dim)

    # Remove stale vectors for this file before re-indexing
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

    title       = extract_title(text, path)
    file_mtime  = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    ingested_at = datetime.now(tz=timezone.utc).isoformat()

    # Embed all chunks in batches; abort the whole file on any batch failure
    # so that mtime is not updated and the file is retried on the next scan.
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
            return  # mtime NOT updated → guaranteed retry

    if len(all_embeddings) != len(chunks):
        log.error(
            "[%s] embedding count mismatch for '%s' (%d chunks, %d vectors) "
            "— file will be retried on next scan.",
            collection, rel, len(chunks), len(all_embeddings),
        )
        return  # mtime NOT updated → guaranteed retry

    points = [
        PointStruct(
            id=str(uuid.uuid4()),
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
    log.info(
        "[%s] indexed %d chunks from '%s' (title: %s).",
        collection, len(points), rel, title,
    )
    save_mtime(indexed, collection, rel, path.stat().st_mtime)


# ── Deleted-file cleanup ──────────────────────────────────────────────────────

def cleanup_deleted(indexed: dict, disk_files: dict[str, set[str]]) -> None:
    """Remove Qdrant vectors and state for files that no longer exist on disk."""
    for collection, files in list(indexed.items()):
        on_disk = disk_files.get(collection, set())
        for rel in list(files.keys()):
            if rel not in on_disk:
                log.info(
                    "[%s] '%s' removed from source — deleting from index.",
                    collection, rel,
                )
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
                    log.warning(
                        "[%s] could not delete vectors for removed file '%s': %s",
                        collection, rel, exc,
                    )
                remove_file_state(indexed, collection, rel)


# ── Scan loop ─────────────────────────────────────────────────────────────────

def scan(vector_dim: int, indexed: dict) -> None:
    """
    Scan DOCS_PATH and ingest any file that is new or has changed.
    Also applies any pending reindex triggers and removes vectors for
    deleted files.
    """
    apply_reindex_triggers(indexed)

    disk_files: dict[str, set[str]] = {}

    for path in DOCS_PATH.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED:
            continue
        collection = collection_for(path)
        if collection is None:
            log.debug("Skipping root-level file '%s' (no source directory).", path.name)
            continue
        rel   = str(path.relative_to(DOCS_PATH))
        mtime = path.stat().st_mtime
        disk_files.setdefault(collection, set()).add(rel)
        if indexed.get(collection, {}).get(rel) != mtime:
            ingest(path, collection, vector_dim, indexed)

    cleanup_deleted(indexed, disk_files)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(
        "Starting ingester | docs=%s | model=%s | qdrant=%s | interval=%ds",
        DOCS_PATH, EMBED_MODEL, QDRANT_URL, SCAN_INTERVAL,
    )
    wait_for_qdrant()

    log.info("Probing embedding dimension with model '%s'…", EMBED_MODEL)
    vector_dim = probe_embedding_dim()
    log.info("Embedding dimension: %d.", vector_dim)

    check_and_save_model_version(EMBED_MODEL, vector_dim)

    indexed = load_indexed()
    log.info(
        "Loaded %d previously indexed files from state DB.",
        sum(len(v) for v in indexed.values()),
    )
    log.info("Beginning scan loop.")

    while True:
        try:
            scan(vector_dim, indexed)
        except Exception:
            log.exception("Scan cycle failed — will retry in %ds.", SCAN_INTERVAL)
        time.sleep(SCAN_INTERVAL)
