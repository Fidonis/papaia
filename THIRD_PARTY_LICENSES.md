# Third-party licenses

This file documents the container images bundled with papAIa and their
upstream licenses. It is **manually maintained** — update this file whenever
image versions in `src/.env.example` change or a new service is added.

Images that carry a copyleft or source-available license (AGPL, GPL, SSPL,
RSAL, …) are used strictly as **network services**: papAIa connects to them
over localhost/Docker networking and does not incorporate their source code.
This is legally distinct from embedding copyleft code in the project itself.

The CI workflow [`.github/workflows/license-check.yml`](.github/workflows/license-check.yml)
verifies that every `*_IMAGE` variable in `src/.env.example` appears in this
file. Adding a new service without updating this file will fail the check.

---

## Container images

| Variable | Image | Version | License | Notes |
|---|---|---|---|---|
| `KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak` | 26.5.6 | Apache-2.0 | |
| `KEYCLOAK_POSTGRES_IMAGE` | `postgres` | 18.3 | PostgreSQL License | |
| `OAUTH2_PROXY_IMAGE` | `quay.io/oauth2-proxy/oauth2-proxy` | v7.9.0 | MIT | |
| `NPM_IMAGE` | `jc21/nginx-proxy-manager` | 2.14.0 | MIT | |
| `HOMEPAGE_IMAGE` | `ghcr.io/gethomepage/homepage` | v1.12.3 | GPL-3.0 | used as network service |
| `PAPERLESS_IMAGE` | `ghcr.io/paperless-ngx/paperless-ngx` | 2.20.10 | GPL-3.0 | used as network service |
| `PAPERLESS_REDIS_IMAGE` | `docker.io/library/redis` | 8 | RSALv2 / SSPLv1 / AGPLv3 | used as network service; Redis 8 is tri-licensed (AGPLv3 is OSI-approved) |
| `PAPERLESS_DB_IMAGE` | `docker.io/library/postgres` | 18 | PostgreSQL License | |
| `PAPERLESS_GOTENBERG_IMAGE` | `docker.io/gotenberg/gotenberg` | 8.27 | MIT | |
| `PAPERLESS_TIKA_IMAGE` | `docker.io/apache/tika` | 3.2.3.0 | Apache-2.0 | |
| `SEARXNG_IMAGE` | `searxng/searxng` | 2026.4.24-a7ac696b4 | AGPL-3.0 | used as network service |
| `LIBRECHAT_IMAGE` | `ghcr.io/danny-avila/librechat` | v0.8.5 | MIT | |
| `LIBRECHAT_MONGODB_IMAGE` | `mongo` | 8.0.20 | SSPL | used as network service |
| `LIBRECHAT_MEILISEARCH_IMAGE` | `getmeili/meilisearch` | v1.35.1 | MIT | MIT core; BUSL-1.1 covers Enterprise Edition components |
| `LIBRECHAT_VECTORDB_IMAGE` | `pgvector/pgvector` | 0.8.0-pg15-trixie | PostgreSQL License | |
| `LIBRECHAT_RAGAPI_IMAGE` | `ghcr.io/danny-avila/librechat-rag-api-dev-lite` | latest | MIT | |
| `LITELLM_IMAGE` | `ghcr.io/berriai/litellm` | v1.83.14.rc.1 | MIT | |
| `LITELLM_DB_IMAGE` | `postgres` | 16 | PostgreSQL License | |
| `LITELLM_PROMETHEUS_IMAGE` | `prom/prometheus` | v3.11.1 | Apache-2.0 | |
| `N8N_IMAGE` | `docker.n8n.io/n8nio/n8n` | 2.17.8 | Sustainable Use License | used as network service; source-available, not OSI open source |
| `N8N_POSTGRES_IMAGE` | `postgres` | 16 | PostgreSQL License | |
| `LOCALAI_IMAGE` | `localai/localai` | sha-6c635e8 | MIT | |
| `LOCALAI_MODEL_INIT_IMAGE` | `curlimages/curl` | latest | MIT | |
| `DOCRAG_SYNC_IMAGE` | `rclone/rclone` | 1.69 | MIT | |
| `DOCRAG_VECTORDB_IMAGE` | `qdrant/qdrant` | v1.13.6 | Apache-2.0 | |
| `DOCRAG_INGESTER_IMAGE` | `docrag-ingester` | 2.85.0 | Fidonis proprietary | internal Fidonis image |
| `DOCRAG_API_IMAGE` | `docrag-api` | 1.27.0 | Fidonis proprietary | internal Fidonis image |
| `JINAAI_RERANKER_IMAGE` | `ghcr.io/marko-boehm/jina-ai-litellm-reranker` | 0.2.0 | Apache-2.0 | Fidonis-maintained wrapper; Jina AI reranker base is Apache-2.0 |
| `HOMEASSISTANT_IMAGE` | `ghcr.io/home-assistant/home-assistant` | 2026.4.4 | Apache-2.0 | |
| `FIRECRAWL_IMAGE` | `ghcr.io/firecrawl/firecrawl` | (digest-pinned) | AGPL-3.0 | used as network service |
| `FIRECRAWL_PLAYWRIGHT_IMAGE` | `ghcr.io/firecrawl/playwright-service` | (digest-pinned) | Apache-2.0 | |
| `FIRECRAWL_REDIS_IMAGE` | `redis` | 8.6.1-alpine | RSALv2 / SSPLv1 / AGPLv3 | used as network service; Redis 8 is tri-licensed (AGPLv3 is OSI-approved) |
| `FIRECRAWL_RABBITMQ_IMAGE` | `rabbitmq` | 3-management | MPL-2.0 | |
| `FIRECRAWL_NUCPOSTGRES_IMAGE` | `ghcr.io/firecrawl/nuq-postgres` | (digest-pinned) | PostgreSQL License | |
| `TECHNITIUM_IMAGE` | `technitium/dns-server` | 14.3.0 | GPL-3.0 | used as network service |
| `QDRANT_IMAGE` | `qdrant/qdrant` | v1.18.1 | Apache-2.0 | |
| `QDRANT_RAG_IMAGE` | `ghcr.io/fidonis/qdrant-mcp-rbac` | 0.1.1 | MIT | Fidonis-maintained OIDC+RBAC MCP layer for Qdrant |
| `QWI_SYNC_IMAGE` | `rclone/rclone` | sha-b22fe98 | MIT | |
| `QWI_INGEST_IMAGE` | `papaia-qdrant-webdav-ingest` | 0.1.0 | Fidonis proprietary | internal Fidonis image; built in-repo |
| `MCP_PAPERLESS_IMAGE` | `ghcr.io/fidonis/paperless-mcp-rbac` | 0.1.0 | MIT | Fidonis-maintained OIDC-secured Paperless MCP server |

### Hardcoded image references

The following images are referenced directly in compose files (not via
`src/.env.example` variables) and are therefore not covered by the CI check.
They must be updated manually here when the compose file changes.

| Image | Version | License | Used in |
|---|---|---|---|
| `nginx` | alpine | BSD-2-Clause | n8n logout shim |

---

## License key

| Identifier | Full name |
|---|---|
| Apache-2.0 | Apache License 2.0 |
| MIT | MIT License |
| GPL-3.0 | GNU General Public License v3.0 |
| AGPL-3.0 | GNU Affero General Public License v3.0 |
| SSPL | Server Side Public License v1 (MongoDB / Elastic) |
| RSALv2 | Redis Source Available License v2 |
| BUSL-1.1 | Business Source License 1.1 |
| MPL-2.0 | Mozilla Public License 2.0 |
| PostgreSQL License | PostgreSQL License (permissive, BSD-style) |
| Sustainable Use License | n8n Sustainable Use License (source-available, not OSI) |