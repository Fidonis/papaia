# Third-party licenses

This file documents the container images bundled with papAIa and their
upstream licenses. It is **manually maintained** — update this file whenever an
`image:` reference in `src/**/docker-compose.yml` changes or a new service is
added.

Images that carry a copyleft or source-available license (AGPL, GPL, SSPL,
RSAL, …) are used strictly as **network services**: papAIa connects to them
over localhost/Docker networking and does not incorporate their source code.
This is legally distinct from embedding copyleft code in the project itself.

The CI workflow [`.github/workflows/license-check.yml`](.github/workflows/license-check.yml)
verifies that every image referenced by a compose file under `src/` appears in
this file. Adding a new service without updating this file will fail the check.

Add-ons ship their own compose files in their own repositories and document
their images there; the table below covers the Core only.

---

## Container images

| Image | Version | License | Compose file | Notes |
|---|---|---|---|---|
| `quay.io/keycloak/keycloak` | 26.7.0 | Apache-2.0 | `infra/keycloak` | |
| `postgres` | 18.3 | PostgreSQL License | `infra/keycloak` | Keycloak database |
| `jc21/nginx-proxy-manager` | 2.15.1 | MIT | `infra/nginx` | |
| `quay.io/oauth2-proxy/oauth2-proxy` | v7.15.3 | MIT | `infra/nginx`, `infra/oauth2-proxy` | admin-UI sidecar + standalone gateway |
| `ghcr.io/fidonis/papaia-manager` | 0.4.0 | MIT | `manager` | Fidonis-maintained add-on management UI |
| `ghcr.io/danny-avila/librechat` | v0.8.7 | MIT | `ai/librechat` | |
| `mongo` | 8.0.20 | SSPL | `ai/librechat` | used as network service |
| `getmeili/meilisearch` | v1.35.1 | MIT | `ai/librechat` | MIT core; BUSL-1.1 covers Enterprise Edition components |
| `pgvector/pgvector` | 0.8.0-pg15-trixie | PostgreSQL License | `ai/librechat` | |
| `ghcr.io/danny-avila/librechat-rag-api-dev-lite` | v0.8.0 | MIT | `ai/librechat` | |
| `ghcr.io/berriai/litellm` | v1.91.1 | MIT | `ai/litellm` | |
| `postgres` | 16 | PostgreSQL License | `ai/litellm` | LiteLLM database |
| `prom/prometheus` | v3.13.1 | Apache-2.0 | `ai/litellm` | |
| `localai/localai` | v4.7.1 | MIT | `ai/localai` | CPU image; the NVIDIA CUDA, Intel, hipBLAS and Vulkan variants are the same license |
| `curlimages/curl` | latest | MIT | `ai/localai` | model-init helper |
| `ghcr.io/fidonis/jina-reranker-api` | 0.1.2 | Apache-2.0 | `ai/jinaai` | Fidonis-maintained wrapper; Jina AI reranker base is Apache-2.0 |
| `ghcr.io/firecrawl/firecrawl-mcp-server` | (digest-pinned) | AGPL-3.0 | `ai/mcp-firecrawl` | used as network service |
| `ghcr.io/firecrawl/firecrawl` | 2.11.85 | AGPL-3.0 | `services/firecrawl` | used as network service |
| `ghcr.io/firecrawl/playwright-service` | (digest-pinned) | Apache-2.0 | `services/firecrawl` | |
| `ghcr.io/firecrawl/nuq-postgres` | (digest-pinned) | PostgreSQL License | `services/firecrawl` | |
| `redis` | 8.8.0-alpine | RSALv2 / SSPLv1 / AGPLv3 | `services/firecrawl` | used as network service; Redis 8 is tri-licensed (AGPLv3 is OSI-approved) |
| `rabbitmq` | 3-management | MPL-2.0 | `services/firecrawl` | |
| `searxng/searxng` | 2026.7.10-6a4d5148d | AGPL-3.0 | `services/searxng` | used as network service |

---

## License key

| Identifier | Full name |
|---|---|
| Apache-2.0 | Apache License 2.0 |
| MIT | MIT License |
| AGPL-3.0 | GNU Affero General Public License v3.0 |
| SSPL | Server Side Public License v1 (MongoDB / Elastic) |
| RSALv2 | Redis Source Available License v2 |
| BUSL-1.1 | Business Source License 1.1 |
| MPL-2.0 | Mozilla Public License 2.0 |
| PostgreSQL License | PostgreSQL License (permissive, BSD-style) |
