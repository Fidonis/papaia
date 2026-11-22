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
| `postgres` | 17.12-alpine3.24 (digest-pinned) | PostgreSQL License | `infra/audit` | audit store database `papaia-audit-db` (profile `audit`) |
| `jc21/nginx-proxy-manager` | 2.15.1 | MIT | `infra/nginx` | |
| `quay.io/oauth2-proxy/oauth2-proxy` | v7.15.6 | MIT | `infra/nginx`, `infra/oauth2-proxy` | admin-UI sidecar + standalone gateway |
| `boky/postfix` | 5.1.0-alpine | MIT | `infra/smtp-relay` | optional mail relay (profile `smtp`); the image bundles Postfix (IPL-1.0 or EPL-2.0), OpenDKIM and rsyslog (GPL-3.0-or-later among others), used as network service |
| `haproxy` | 3.2.26-alpine | GPL-2.0 | `infra/link-gateway` | mTLS link gateway between the nodes of a distributed installation (profile `link-gateway`, not in the include list); its include files are LGPL-2.1; used as network service |
| `ghcr.io/fidonis/papaia-manager` | 1.7.0 | MIT | `manager` | Fidonis-maintained add-on management UI |
| `ghcr.io/fidonis/papaia-egress` | 1.9.0 | MIT | `infra/egress` | own image of the core (`compat/own-images.yaml`): the egress proxy on `python:3.12.16-slim-trixie`; CPython is PSF-2.0, the Debian packages keep their copyright files in the image; notice files under `/usr/share/licenses/papaia-egress/` |
| `ghcr.io/fidonis/papaia-lifecycle` | 1.9.0 | MIT | `infra/lifecycle` | own image of the core (`compat/own-images.yaml`): the lifecycle service on `python:3.12.16-slim-trixie`; CPython is PSF-2.0, OpenSSL Apache-2.0, the Debian packages keep their copyright files in the image; notice files under `/usr/share/licenses/papaia-lifecycle/` |
| `ghcr.io/fidonis/papaia-audit` | 1.9.0 | MIT | `infra/audit` | own image of the core (`compat/own-images.yaml`): the audit store service and its schema step (profile `audit`) on `python:3.12.16-alpine3.24`; carries psycopg and psycopg-binary (LGPL-3.0-only, unmodified libraries; the wheel bundles libpq, OpenSSL and further libraries), cryptography (Apache-2.0 OR BSD-3-Clause), cffi (MIT-0), pycparser (BSD-3-Clause), jsonschema, jsonschema-specifications, referencing, attrs and rpds-py (MIT), typing-extensions (PSF-2.0); notice files under `/usr/share/licenses/papaia-audit/` |
| `ghcr.io/fidonis/papaia-people` | 1.9.0 | MIT | `infra/people` | own image of the core (`compat/own-images.yaml`): the people lookup on `python:3.12.16-slim-trixie`; CPython is PSF-2.0, OpenSSL Apache-2.0, the Debian packages keep their copyright files in the image; notice files under `/usr/share/licenses/papaia-people/` |
| `python` | 3.12.16-slim-trixie | PSF-2.0 | `infra/lifecycle` | `papaia-lifecycle-init` (hands the volumes to the service user); also the base of the own images above |
| `python` | 3.12.16-alpine3.24 (digest-pinned) | PSF-2.0 | `infra/audit` | base of the own image `ghcr.io/fidonis/papaia-audit` |
| `ghcr.io/librechat-ai/librechat` | v0.8.8 | MIT | `ai/librechat` | |
| `mongo` | 8.3.17 | SSPL | `ai/librechat` | used as network service |
| `getmeili/meilisearch` | v1.35.1 | MIT | `ai/librechat` | MIT core; BUSL-1.1 covers Enterprise Edition components |
| `pgvector/pgvector` | 0.8.7-pg15-trixie | PostgreSQL License | `ai/librechat` | |
| `ghcr.io/librechat-ai/librechat-rag-api-dev-lite` | v0.9.0 | MIT | `ai/librechat` | |
| `ghcr.io/berriai/litellm` | v1.108.3 | MIT | `ai/litellm` | |
| `postgres` | 16 | PostgreSQL License | `ai/litellm` | LiteLLM database |
| `prom/prometheus` | v3.16.0 | Apache-2.0 | `ai/litellm` | |
| `localai/localai` | v4.12.1 | MIT | `ai/localai` | CPU image; the NVIDIA CUDA, Intel, hipBLAS and Vulkan variants are the same license |
| `curlimages/curl` | 8.16.0 (voice) / latest (localai) | MIT | `ai/localai`, `ai/voice` | model-init helpers |
| `ghcr.io/fidonis/jina-reranker-api` | 0.1.3 | Apache-2.0 | `ai/jinaai` | Fidonis-maintained wrapper; Jina AI reranker base is Apache-2.0 |
| `qdrant/qdrant` | v1.19.0 | Apache-2.0 | `ai/rag` | vector database |
| `ghcr.io/fidonis/qdrant-mcp-rbac` | 0.4.2 | MIT | `ai/rag` | Fidonis-maintained OIDC + RBAC MCP server in front of Qdrant |
| `ghcr.io/fidonis/qdrant-ingest` | 1.0.1 | MIT | `ai/rag` | Fidonis-maintained scheduled ingestion service |
| `ghcr.io/fidonis/papaia-knowledge-map` | 0.2.0 | MIT | `ai/knowledge-map` | Fidonis-maintained role-trimmed MCP directory of knowledge sources |
| `docker.io/apache/tika` | 3.2.3.0 | Apache-2.0 | `ai/rag` | text extraction for qdrant-ingest |
| `ghcr.io/speaches-ai/speaches` | 0.8.3-cpu (digest-pinned) | MIT | `ai/voice` | speech-to-text (profile `voice`); the image bundles piper-tts, phonemizer and espeak-ng (GPL-3.0) plus Ubuntu's ffmpeg build (GPL), used as network service; the shipped default model `deepdml/faster-whisper-large-v3-turbo-ct2` is MIT |
| `ghcr.io/devnen/chatterbox-tts-server` | sha-915ae28-cpu (digest-pinned; accelerator tags `-cu128`/`-rocm` of the same commit selectable via `--voice-variant`) | MIT | `ai/voice` | text-to-speech (profile `voice`); Chatterbox model code and the multilingual weights (Resemble AI) are MIT, the embedded Perth watermarker is MIT |
| `ghcr.io/firecrawl/firecrawl-mcp-server` | (digest-pinned) | AGPL-3.0 | `ai/mcp-firecrawl` | used as network service |
| `ghcr.io/firecrawl/firecrawl` | 2.11.705 | AGPL-3.0 | `services/firecrawl` | used as network service |
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
| GPL-2.0 | GNU General Public License v2.0 |
| GPL-3.0 | GNU General Public License v3.0 |
| LGPL-3.0 | GNU Lesser General Public License v3.0 |
| PSF-2.0 | Python Software Foundation License 2.0 |
| BSD-3-Clause | BSD 3-Clause License |
| SSPL | Server Side Public License v1 (MongoDB / Elastic) |
| RSALv2 | Redis Source Available License v2 |
| BUSL-1.1 | Business Source License 1.1 |
| MPL-2.0 | Mozilla Public License 2.0 |
| PostgreSQL License | PostgreSQL License (permissive, BSD-style) |
