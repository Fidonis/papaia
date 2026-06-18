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
   │
   │ MCP tools
   ▼
MCP Paperless    qdrant-rag ──▶ Qdrant
   │
   ▼
Paperless-ngx
```

- **LibreChat** is the user-facing chat UI. It authenticates with Keycloak
  (native OIDC, PKCE), routes model calls through LiteLLM, and consumes
  MCP tools from MCP Paperless and qdrant-rag.
- **LiteLLM** unifies access to local and hosted LLMs.
- **LocalAI** runs chat-completions inference locally (CPU or NVIDIA
  GPU). Models to download are listed in `localai/models.txt`.
- **MCP Paperless** is a per-user proxy that forwards a LibreChat user's
  Keycloak access token into Paperless-ngx, so each user only sees their
  own documents.
- **qdrant-rag** exposes per-user, role-scoped vector search over a Qdrant
  collection as an MCP tool. LibreChat forwards the logged-in user's Keycloak
  Bearer token via the native `{{LIBRECHAT_OPENID_ACCESS_TOKEN}}` placeholder;
  qdrant-rag validates the token and enforces RBAC derived from Keycloak roles.
- **n8n** is workflow automation behind oauth2-proxy.

---

## Configuration

Per-service configuration lives in each subdirectory. For each AI module
you enable:

1. Copy `.env.example` → `.env` in the service directory.
2. Replace every service-specific `GENERATE_…` secret (JWT, Meili master
   key, vector DB passwords, …) with a real value.
3. Keep the shared values consistent with `src/.env`:
   - Keycloak client secrets → `OPENID_CLIENT_SECRET` / `GENERIC_CLIENT_SECRET`.
   - LiteLLM master key → LibreChat `LITELLM_API_KEY`.
   - `PAPAIA_HOST` → service public URLs (LibreChat `DOMAIN_*`, LiteLLM
     `GENERIC_REDIRECT_URI`, n8n `N8N_PUBLIC_URL`, …).

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

### LocalAI — local chat-completions inference
- Image: `localai/localai` (CPU) or its NVIDIA CUDA variant
- External port: `8080`
- Use the CPU or NVIDIA CUDA image variant as appropriate for the host;
  list the models to download in `localai/models.txt`.

### MCP Paperless — OIDC + RBAC Paperless proxy
- Profile: `mcp-paperless`
- Bridges LibreChat to Paperless-ngx as an MCP tool.
- Validates the caller's Keycloak Bearer token (forwarded automatically via the
  `Paperless` entry in `librechat.yaml`) and calls Paperless on the user's
  behalf via a remote-user header — no admin credentials stored. Paperless
  enforces its own per-user permissions.
- External port: `9520` (MCP endpoint `POST /mcp`, `GET /health`).
- Configuration: `MCP_PAPERLESS_*` in `src/.env` (image, port); service-internal
  settings in `ai/mcp-paperless/.env`. `OIDC_ISSUER` is reused from the global
  OIDC block. Requires `PAPERLESS_ENABLE_HTTP_REMOTE_USER` on Paperless-ngx.
- Enable it together with Paperless-ngx via `COMPOSE_PROFILES`.

### n8n — workflow automation
- Image: `docker.n8n.io/n8nio/n8n`
- External port: `8400`
- Auth: oauth2-proxy forward auth (NPM rule guards the upstream).
- Postgres-backed state. The public URL is derived from `PAPAIA_HOST`
  during setup so the oauth2-proxy redirect callback stays correct.

### qdrant-rag — OIDC + RBAC vector search MCP server

- Profile: `qdrant-rag`
- Components: `qdrant-rag` (FastMCP server), `qdrant` (vector store)
- External ports: `8800` (MCP endpoint: `POST /mcp`), `6333` (Qdrant REST),
  `6334` (Qdrant gRPC)
- Auth: validates the caller's Keycloak Bearer token; maps Keycloak roles to
  per-collection Qdrant access via an ACL collection in the vector store.
- LibreChat forwards the logged-in user's token automatically via the
  `QdrantRAG` entry in `librechat.yaml` — no custom patch required.
- Configuration: `QDRANT_RAG_*` variables in `src/.env`; `OIDC_ISSUER` is
  reused from the global OIDC block — no duplicate needed.
- See [`qdrant-rag/.env.example`](qdrant-rag/.env.example) for the full
  variable reference.

### Office Documents — downloadable office-file generator

- Profile: `mcp-office-docs`
- Components: `mcp-office-docs` (MCP server), backed by the `minio` object store
  (see [`../services/minio/`](../services/minio/))
- Generates Word, Excel, PowerPoint, email-draft and XML files from a chat
  prompt, uploads each to MinIO, and returns a time-limited pre-signed download
  URL that LibreChat renders as a clickable link.
- External port: `9530` (MCP endpoint `POST /mcp`).
- Auth: optional `x-api-key` header (`MCP_OFFICE_DOCS_API_KEY`); otherwise relies
  on Docker network isolation. LibreChat reaches it via the `OfficeDocuments`
  entry in `librechat.yaml`.
- Configuration: `MCP_OFFICE_DOCS_*` and `MINIO_*` in `src/.env`;
  service-internal settings in `ai/mcp-office-docs/.env`. See
  [`mcp-office-docs/.env.example`](mcp-office-docs/.env.example).

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
