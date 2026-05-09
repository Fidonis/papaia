# AI services

This directory contains the AI workloads that run inside the papAIa stack.
Each service has its own subdirectory with a `docker-compose.yml`,
`.env.example` and any service-specific config files.

For the architecture overview and the OIDC integration model, see the
[top-level README](../../README.md). For Compose-level orchestration (how
services are aggregated, toggled, started) see the
[`src/README.md`](../README.md).

---

## How these services fit together

```
LibreChat  ──▶  LiteLLM  ──▶  LocalAI / hosted providers
   │              ▲
   │ MCP tools    │ embeddings
   ▼              │
MCP Paperless    doc-rag  ─── rclone ───▶  WebDAV (Nextcloud, …)
   │              │
   ▼              ▼
Paperless-ngx   Qdrant
```

- **LibreChat** is the user-facing chat UI. It authenticates with Keycloak
  (native OIDC, PKCE), routes model calls through LiteLLM, and consumes
  MCP tools from doc-rag and MCP Paperless.
- **LiteLLM** unifies access to local and hosted LLMs and is also the
  embedding gateway for doc-rag.
- **LocalAI** runs OpenAI-compatible inference locally (CPU or NVIDIA
  GPU). The setup script offers a model picker on first run.
- **doc-rag** ingests documents from one or more WebDAV sources, chunks
  them with Docling, embeds via LiteLLM, stores vectors in Qdrant and
  exposes `search_documents` / `list_collections` as MCP tools.
- **MCP Paperless** is a per-user proxy that forwards a LibreChat user's
  Keycloak access token into Paperless-ngx, so each user only sees their
  own documents.
- **n8n** is workflow automation behind oauth2-proxy. It can call doc-rag
  via the MCP API or HTTP for retrieval-augmented automations.

---

## Configuration

Per-service configuration lives in each subdirectory. The setup script
(`src/setup-papaia.sh`) takes care of:

1. Copying `.env.example` → `.env` per service.
2. Generating service-specific secrets (JWT, Meili master key, vector DB
   passwords, …) where the value is still `GENERATE_…`.
3. Propagating shared values from `src/.env`:
   - Keycloak client secrets → `OPENID_CLIENT_SECRET` / `GENERIC_CLIENT_SECRET`.
   - LiteLLM master key → LibreChat `LITELLM_API_KEY` and doc-rag
     `LITELLM_API_KEY`.
   - `PAPAIA_HOST` → service public URLs (LibreChat `DOMAIN_*`, LiteLLM
     `GENERIC_REDIRECT_URI`, n8n `N8N_PUBLIC_URL`, …).

Re-running the script is safe and idempotent. Use `--force` only if you
want to discard all generated secrets and start over.

---

## Services

### LibreChat — multi-provider chat UI
- Image: `ghcr.io/danny-avila/librechat`
- External port: `8000`
- Auth: native Keycloak OIDC, PKCE enforced
- Sidecars: MongoDB, Meilisearch, pgvector, RAG API
- Configuration: `librechat.yaml` (model & MCP definitions) + `.env`

### LiteLLM — LLM proxy and gateway
- Image: `ghcr.io/berriai/litellm`
- External ports: `8200` (proxy + UI), `8210` (Postgres), `8230` (Prometheus)
- Auth: generic OIDC for the admin UI, master key for programmatic clients
- Configuration: `config.yaml` (provider routes), `prometheus.yml`, `.env`

### LocalAI — local OpenAI-compatible inference
- Image: `localai/localai` (CPU) or its NVIDIA CUDA variant
- External port: `8080`
- The setup script picks one variant based on whether `nvidia-smi` is
  available, and prompts for which models to download into `models/`.

### doc-rag — RAG over WebDAV sources
- Components: `docrag-sync` (rclone), `docrag-vectordb` (Qdrant),
  `docrag-ingester` (Docling + LiteLLM embeddings),
  `docrag-api` (FastMCP).
- External ports: `8700` (MCP API: `POST /mcp`, `GET /health`,
  `POST /reindex`), `6333` (Qdrant dashboard).
- Configuration: WebDAV credentials, embedding model, chunk parameters
  in `.env`.
- See [`doc-rag/README.md`](doc-rag/README.md) for the full pipeline,
  variable reference, MCP tool schema and operational notes.

### MCP Paperless — per-user Paperless proxy
- Bridges LibreChat to Paperless-ngx as an MCP tool.
- Forwards the user's Keycloak access token to Paperless on each request,
  so per-user document isolation is preserved.
- Internal port: `9520`.
- Auto-enabled when Paperless-ngx is enabled in the setup script.

### n8n — workflow automation
- Image: `docker.n8n.io/n8nio/n8n`
- External port: `8400`
- Auth: oauth2-proxy forward auth (NPM rule guards the upstream).
- Postgres-backed state. The public URL is derived from `PAPAIA_HOST`
  during setup so the oauth2-proxy redirect callback stays correct.

### Jina AI Reranker (optional)
- Image: `ghcr.io/marko-boehm/jina-ai-litellm-reranker`
- External port: `8600`
- Commented out by default. Re-integration is tracked in
  [issue #43](https://github.com/marko-boehm/papaia/issues/43).

---

## Adding a new AI service

1. Create a subdirectory under `src/ai/<your-service>/`.
2. Add a `docker-compose.yml` that joins the shared `papaia-net` network
   and references images via `${YOURSVC_IMAGE}` so versions are pinned in
   the root `.env`.
3. Add a `.env.example` with all required variables documented inline.
4. If the service speaks OIDC, register a client in
   `src/infra/keycloak/realm-import/papaia-realm.json.template` and add a
   `KC_<service>_CLIENT_SECRET` variable to `src/infra/keycloak/.env.example`.
5. If it doesn't, route it through oauth2-proxy via Nginx Proxy Manager
   (see [`src/infra/keycloak/README.md`](../infra/keycloak/README.md) for
   the NPM snippet).
6. Add an `- path: ./ai/<your-service>/docker-compose.yml` entry to the
   root `src/docker-compose.yml`.
7. Document the service in this README.
