# doc-rag

Retrieval-Augmented Generation (RAG) module for the papAIa stack.
Indexes documents from one or more WebDAV sources into a vector database and
exposes semantic search through MCP tools consumed by LibreChat, n8n, or any
HTTP client.

---

## Architecture overview

```
WebDAV sources (e.g. Nextcloud)
        │
        │  rclone sync  (SYNC_INTERVAL)
        ▼
  /data/docs/{source}/          ← shared Docker volume (read-only for ingester)
        │
        │  mtime-based scan  (SCAN_INTERVAL)
        ▼
  docrag-ingester
    Docling (text extraction)
    heading-aware chunking
    LiteLLM batch embedding
        │
        ▼
  docrag-vectordb  (Qdrant)
    one collection per source
        │
        ▼
  docrag-api  (FastMCP / streamable-HTTP)
    POST /mcp      ← LibreChat (MCP tools)
                   ← n8n (HTTP Request node)
                   ← any MCP-capable client
    GET  /health   ← monitoring / container orchestration
    POST /reindex  ← operations / forced re-indexing
```

**Shared state volume** (`docrag-state`): persists the SQLite mtime index and
reindex trigger files. Mounted read-write by both ingester and API.

---

## Components

### `docrag-sync` — WebDAV integration

- Image: `rclone/rclone:1.69`
- Script: `integrations/webdav/sync.sh`
- Reads `WEBDAV_N_*` environment variables and starts one background sync loop
  per configured source.
- Each source syncs into `/data/docs/{NAME}/`.
- Sync is pull-only: remote deletions are mirrored locally; local changes are
  never synced back.
- Non-fatal: a failed sync is logged and retried on the next interval.

**To add a new source**, add the following to `.env`:

```env
WEBDAV_2_NAME=sharepoint
WEBDAV_2_URL=https://company.sharepoint.com/documents/
WEBDAV_2_USER=user@company.com
WEBDAV_2_PASS=password
WEBDAV_2_VENDOR=sharepoint
```

**To use a different source type** (SMB, S3, local path), replace the volume
mount in `docker-compose.yml` to point at a different integration script in
`integrations/`. The rest of the stack is source-agnostic.

---

### `docrag-vectordb` — Qdrant

- Image: `qdrant/qdrant:v1.13.6`
- Stores document embeddings.
- One collection per document source, named after the source directory.
- Dashboard: `http://host:${QDRANT_EXT_PORT}/dashboard`
- Data is persisted in the `qdrant-storage` Docker volume.

---

### `docrag-ingester` — Document processing pipeline

- Scans `/data/docs/` every `SCAN_INTERVAL` seconds.
- Detects new or changed files by comparing `mtime` against a **SQLite-backed
  index** (persisted across restarts in the `docrag-state` volume).
- For each changed file:
  1. Extracts text using **Docling** (PDF, DOCX, DOC, Markdown, plain text).
  2. Splits text into chunks, respecting **Markdown heading boundaries**
     (`CHUNK_WORDS`, `CHUNK_OVERLAP`). Sections that overflow are sub-chunked
     with the heading prepended to each piece for retrieval context.
  3. Embeds all chunks in batches via **LiteLLM** (`EMBED_MODEL`,
     `EMBED_BATCH_SIZE`).
  4. Upserts vectors into the corresponding Qdrant collection.
  5. Updates the mtime index **only if all chunks succeeded** — guarantees
     retry on any embedding failure.
- **Deleted files** are detected each scan cycle and their vectors are removed
  from Qdrant automatically.
- **Reindex triggers**: dropping a file into `STATE_PATH/reindex/` clears the
  mtime state for that collection so it will be fully re-ingested. The API's
  `POST /reindex` endpoint does this automatically.
- If the embedding model or vector dimension changes between runs, the ingester
  logs a warning at startup (stale vectors may exist from the old model).
- Collection names are derived from the top-level subdirectory name, sanitized
  to lowercase alphanumeric with hyphens (e.g. `My_Docs` → `my-docs`).
- If a collection already exists with a different vector dimension, the ingester
  raises a hard error rather than silently corrupting data.

#### Collection mapping

```
/data/docs/nextcloud/contracts/agreement.pdf  →  collection: nextcloud
/data/docs/sharepoint/reports/Q1.docx         →  collection: sharepoint
/data/docs/orphan.pdf                          →  ignored (no source directory)
```

#### Chunk metadata

Each Qdrant vector point carries the following payload:

| Field | Description |
|---|---|
| `text` | Chunk content |
| `source` | Relative file path within `/data/docs/` |
| `collection` | Qdrant collection name |
| `title` | First Markdown heading, or filename if none |
| `chunk_index` | Position of this chunk within the document |
| `total_chunks` | Total chunks produced from this document |
| `file_type` | File extension without dot (`pdf`, `docx`, …) |
| `file_mtime` | File modification time (ISO 8601 UTC) |
| `ingested_at` | Ingestion timestamp (ISO 8601 UTC) |

---

### `docrag-api` — MCP server and query interface

- Built on **FastMCP** (streamable-HTTP transport) composed with a Starlette
  app that exposes additional HTTP endpoints.

#### MCP tools

| Tool | Description |
|---|---|
| `search_documents` | Semantic search over all (or one) indexed collection(s) |
| `list_collections` | List available document sources by name |

`search_documents` validates the `collection` argument against known
collections and returns a clear error message with available names if an
unknown collection is specified.

#### HTTP endpoints

| Endpoint | Description |
|---|---|
| `POST /mcp` | MCP JSON-RPC — consumed by LibreChat / n8n |
| `GET /health` | Returns status, collection list, and model info; 503 on error |
| `POST /reindex` | Trigger re-indexing (see below) |

---

## Data flow (end-to-end)

```
1.  rclone syncs files from WebDAV into /data/docs/{source}/
2.  ingester scans for new/changed files (mtime vs. SQLite index)
3.  Docling extracts text → exported as Markdown
4.  Text is split into chunks at heading boundaries (word-count fallback)
5.  All chunks are embedded in batches via LiteLLM → nomic-embed-text
6.  Vectors are upserted into Qdrant collection "{source}"
7.  mtime is written to SQLite only after successful upsert
8.  Deleted files: vectors removed from Qdrant + state cleared
9.  LibreChat calls search_documents or list_collections via MCP
10. API embeds the query → searches Qdrant → merges + ranks → returns results
11. LibreChat presents results in context to the LLM
```

---

## Environment variables

### WebDAV sources (repeat for N = 1, 2, 3, ...)

| Variable | Required | Description |
|---|---|---|
| `WEBDAV_N_NAME` | yes | Subfolder name and collection name |
| `WEBDAV_N_URL` | yes | Full WebDAV base URL |
| `WEBDAV_N_USER` | yes | Username |
| `WEBDAV_N_PASS` | yes | Password or app password |
| `WEBDAV_N_VENDOR` | no | rclone vendor hint (default: `webdav`) |

### Sync and scan

| Variable | Default | Description |
|---|---|---|
| `SYNC_INTERVAL` | `60` | Seconds between rclone syncs per source |
| `SCAN_INTERVAL` | `60` | Seconds between ingester scans |

### LiteLLM / embedding

| Variable | Default | Description |
|---|---|---|
| `LITELLM_URL` | `http://litellm:4000/v1` | LiteLLM API endpoint |
| `LITELLM_API_KEY` | — | LiteLLM master key (**required**) |
| `EMBED_MODEL` | `nomic-embed-text` | Embedding model as registered in LiteLLM |

### Ingester tuning

| Variable | Default | Description |
|---|---|---|
| `CHUNK_WORDS` | `400` | Max words per chunk |
| `CHUNK_OVERLAP` | `50` | Words of overlap between consecutive chunks |
| `EMBED_BATCH_SIZE` | `32` | Chunks per LiteLLM embedding call |
| `EMBED_RETRIES` | `3` | Startup embedding probe retry attempts |
| `EMBED_RETRY_DELAY` | `5.0` | Seconds between embedding probe retries |

### State persistence

| Variable | Default | Description |
|---|---|---|
| `STATE_PATH` | `/data/state` | Path for SQLite DB and reindex triggers (shared volume) |

### API tuning

| Variable | Default | Description |
|---|---|---|
| `DEFAULT_TOP_K` | `5` | Default number of search results |
| `DEFAULT_MIN_SCORE` | `0.5` | Minimum cosine similarity score (0.0–1.0) |
| `MCP_HOST` | `0.0.0.0` | Bind address for the MCP server |
| `MCP_PORT` | `8000` | Port for the MCP server (internal) |

### Ports and network

| Variable | Default | Description |
|---|---|---|
| `DOC_RAG_EXT_PORT` | `8700` | Host port for the MCP API |
| `QDRANT_EXT_PORT` | `6333` | Host port for the Qdrant dashboard |
| `DOCKER_NETWORK` | `papaia-net` | External Docker bridge network |

---

## Running the module

```bash
# 1. Copy and fill in the environment file
cp .env.example .env
# Edit WEBDAV_1_*, LITELLM_API_KEY, and any tuning parameters

# 2. Build and start all services
docker compose --env-file .env -f docker-compose.yml up -d --build

# 3. Follow ingester progress
docker logs docrag-ingester -f

# 4. Check rclone sync status
docker logs docrag-sync -f

# 5. Inspect the vector database
open http://localhost:6333/dashboard
```

---

## HTTP endpoint reference

### `GET /health`

Liveness and readiness check. Returns 200 when Qdrant is reachable, 503
otherwise.

```bash
curl -s http://localhost:8700/health | jq
```

```json
{
  "status": "ok",
  "collections": ["nextcloud"],
  "collection_count": 1,
  "embed_model": "nomic-embed-text",
  "qdrant_url": "http://docrag-vectordb:6333"
}
```

---

### `POST /reindex`

Clears the mtime state for one collection or all collections. The ingester
picks up the trigger at the start of its next scan and re-ingests the
affected files from scratch.

```bash
# Re-index a single collection
curl -s -X POST "http://localhost:8700/reindex?source=nextcloud"

# Re-index everything
curl -s -X POST "http://localhost:8700/reindex"
```

```json
{ "triggered": "nextcloud", "scope": "collection" }
{ "triggered": "__all__",   "scope": "all" }
```

Use this after:
- Changing `CHUNK_WORDS` or `CHUNK_OVERLAP`
- Switching `EMBED_MODEL` (delete the Qdrant collection first)
- Suspecting incomplete indexing due to past embedding failures

---

### `POST /mcp` — MCP tools

#### `search_documents`

```
query       string   Required. Natural-language search query.
top_k       int      Optional. 1–20 results. Default: 5.
collection  string   Optional. Restrict to one source. Default: all sources.
```

#### `list_collections`

No arguments. Returns the names of all indexed document sources.

---

## Operational notes

- **First run**: The ingester downloads OCR model weights (~40 MB) on first
  start. Subsequent starts use the cached weights.
- **Re-indexing after config changes**: After changing `CHUNK_WORDS`,
  `CHUNK_OVERLAP`, or `EMBED_MODEL`, trigger a full re-index:
  ```bash
  curl -s -X POST "http://localhost:8700/reindex"
  ```
  When switching embedding models, also delete the affected Qdrant collection(s)
  via the dashboard before restarting, to avoid dimension mismatch errors.
- **Collection cleanup**: Removing a WebDAV source from `.env` stops the sync.
  Files already on disk are deleted by rclone on the next sync. Once deleted,
  the ingester automatically removes their vectors from Qdrant. The now-empty
  Qdrant collection must be deleted manually via the dashboard.
- **Root-level files**: Files placed directly in `/data/docs/` (not inside a
  subdirectory) are silently skipped by the ingester. All files must be under
  a named source directory.
- **Container restart**: Indexing state is persisted in SQLite on the
  `docrag-state` volume. Restarts do not trigger a full re-scan.
- **Embedding model change warning**: If `EMBED_MODEL` or its vector dimension
  changed since the last run, the ingester logs a warning at startup. Existing
  Qdrant vectors from the old model remain until the collection is deleted and
  re-indexed.
- **Structured logging**: All services emit JSON log lines. Filter with `jq`:
  ```bash
  docker logs docrag-ingester -f | jq 'select(.level == "ERROR")'
  ```

---

## Limitations and tradeoffs

| Limitation | Rationale |
|---|---|
| Heading-based chunking (Markdown only) | Non-Markdown formats (PDF, DOCX) are converted to Markdown by Docling before chunking, so most structure is preserved. Plain text without headings falls back to word-count chunking. |
| Single embedding model per deployment | All collections share the same model and dimension. Switching models requires deleting collections and re-indexing. |
| No authentication on MCP endpoint | The MCP port is only exposed on the internal Docker network. Do not expose it externally without adding authentication at the reverse proxy level. |
| rclone eval-based multi-source | POSIX sh has no associative arrays; `eval` is used to iterate numbered variables. This is safe for trusted `.env` files. |

---

## Versioning

| Component | Version |
|---|---|
| rclone | 1.69 |
| Qdrant | v1.13.6 |
| docling | 2.85.0 |
| openai (SDK) | 2.30.0 |
| qdrant-client | 1.17.1 |
| mcp | 1.27.0 |
| starlette | 0.46.2 |
| uvicorn | 0.34.2 |

Dependencies are pinned to exact versions in `requirements.txt` files.
Update deliberately and test after any version bump.

---

## Directory structure

```
doc-rag/
├── integrations/
│   └── webdav/
│       └── sync.sh              # WebDAV sync integration (rclone, multi-source)
├── shared/
│   ├── __init__.py
│   └── log.py                   # shared JSON logging (used by all Python services)
├── ingester/
│   ├── Dockerfile               # build context: doc-rag root
│   ├── requirements.txt         # pinned: docling, openai, qdrant-client
│   └── main.py                  # scan loop, Docling, chunking, embedding, Qdrant upsert
├── api/
│   ├── Dockerfile               # build context: doc-rag root
│   ├── requirements.txt         # pinned: mcp, openai, qdrant-client, starlette, uvicorn
│   └── main.py                  # FastMCP server, MCP tools, /health, /reindex
├── docker-compose.yml
├── .env                         # active configuration (not committed)
├── .env.example                 # template with all variables documented
└── README.md                    # this file
```
