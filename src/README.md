# papAIa — Compose Orchestration

This directory holds the runtime side of the papAIa stack: the root
`docker-compose.yml`, the global `.env` template, and one subdirectory per
service category.

It documents the Compose layer itself. For everything above it — installing,
starting, upgrading, backing up — see the [top-level README](../README.md) and
[`docs/deployment.md`](../docs/deployment.md). The stack is operated through
`tools/papaia-ctl`; the `docker compose` invocations below are for inspection
and troubleshooting, not the normal path.

---

## Layout

```
src/
├── docker-compose.yml      # root compose — shared network + include: list
├── .env.example            # all stack-wide variables, grouped per service
├── sync-config.sh          # deprecated low-level config-dir seeding (manual fallback)
├── infra/                  # core platform
│   ├── keycloak/           # OIDC issuer (realm: papaia, imported on first start)
│   ├── nginx/              # Nginx Proxy Manager + oauth2-proxy sidecar for its admin UI
│   └── oauth2-proxy/       # forward-auth gateway for services without native OIDC
├── manager/                # papaia-manager — add-on lifecycle UI + dashboard
├── services/               # application services
│   ├── firecrawl/          # web crawler (+ Playwright, Redis, RabbitMQ, Postgres)
│   └── searxng/            # privacy-respecting metasearch
└── ai/                     # AI / ML services
    ├── jinaai/             # Jina reranker
    ├── librechat/          # multi-provider chat UI (OIDC)
    ├── litellm/            # LLM proxy + Postgres + Prometheus (OIDC)
    ├── localai/            # local chat-completions inference
    └── mcp-firecrawl/      # Firecrawl MCP bridge for LibreChat
```

Everything else — document management, RAG, workflow automation — ships as an
add-on in its own repository, not as a directory here. See
[Add-ons](../README.md#add-ons).

The root `docker-compose.yml` is intentionally tiny: it declares the shared
`papaia-net` bridge and an `include:` list, nothing else. All per-service
configuration lives in the corresponding subdirectory. Image tags are pinned
directly in each service's `docker-compose.yml`.

---

## Profiles

Every service declares a Compose `profile`, and a service starts only when its
profile is active. The `include:` list is complete — modules are toggled through
`COMPOSE_PROFILES`, never by commenting a `- path:` line out.

| Profile | Contents |
|---|---|
| `keycloak` | Keycloak + its PostgreSQL |
| `nginx` | Nginx Proxy Manager + the oauth2-proxy sidecar guarding its admin UI |
| `oauth2-proxy` | Standalone forward-auth gateway |
| `librechat` | LibreChat + MongoDB, Meilisearch, pgvector, RAG API |
| `litellm` | LiteLLM + PostgreSQL + Prometheus |
| `localai` | LocalAI and its model-init container |
| `manager` | papaia-manager |
| `librechat-websearch` | SearXNG, Firecrawl, the Firecrawl MCP bridge, Jina reranker |

The default set is `keycloak,nginx,oauth2-proxy,librechat,litellm`. To change it
permanently, edit `COMPOSE_PROFILES` in `$PAPAIA_CONFIG_DIR/.env` and run
`tools/papaia-ctl start`; for a single run, use `--profiles=LIST`. The `localai`,
`manager` and `librechat-websearch` profiles have dedicated `setup` flags that also
keep `deployment.yaml` in sync — prefer those.

> Do **not** edit `src/.env`. Every `start` overwrites the checkout's `.env` files
> from the config directory, so changes there are silently discarded.

---

## Externalised service configuration (`PAPAIA_CONFIG_DIR`)

Every bind-mounted configuration file is sourced from
`${PAPAIA_CONFIG_DIR}/<mirrored-path>` rather than from inside the checkout. The
repo ships the canonical defaults under `src/`; the running stack reads only from
the config directory. Customer edits therefore never produce a git diff, and an
upgrade never has to merge YAML or conf files.

`PAPAIA_CONFIG_DIR` **must be an absolute path** — Compose resolves relative paths
in `include:`d files against each file's own directory.

| Bind-mount source | Container target | Service |
|---|---|---|
| `${PAPAIA_CONFIG_DIR}/ai/librechat/librechat.yaml` | `/app/librechat.yaml` | librechat |
| `${PAPAIA_CONFIG_DIR}/ai/litellm/config.yaml` | `/app/config.yaml` | litellm |
| `${PAPAIA_CONFIG_DIR}/ai/litellm/prometheus.yml` | `/etc/prometheus/prometheus.yml` | litellm-prometheus |
| `${PAPAIA_CONFIG_DIR}/ai/localai/models.txt` | `/models-config/models.txt` | localai-model-init |
| `${PAPAIA_CONFIG_DIR}/ai/localai/models` | `/models-config/configs` | localai-model-init |
| `${PAPAIA_CONFIG_DIR}/infra/keycloak/keycloak.conf` | `/opt/keycloak/conf/keycloak.conf` | keycloak |
| `${PAPAIA_CONFIG_DIR}/infra/keycloak/realm-import` | `/opt/keycloak/data/import` | keycloak |
| `${PAPAIA_CONFIG_DIR}/infra/nginx/nginx-data` | `/data` | nginx-proxy-manager |
| `${PAPAIA_CONFIG_DIR}/infra/nginx/nginx-letsencrypt` | `/etc/letsencrypt` | nginx-proxy-manager |
| `${PAPAIA_CONFIG_DIR}/services/searxng/settings.yml` | `/etc/searxng/settings.yml` | searxng |
| `${PAPAIA_CONFIG_DIR}/certs` | `/certs` | keycloak · librechat · litellm · localai · nginx · manager |

The directory is populated and kept in sync by `tools/papaia-ctl setup` and
re-rendered on every `start`. `sync-config.sh` is the deprecated lower-level
predecessor — still present as a manual fallback, but not part of the normal
operating path.

Per-service `.env` files are **not** part of this table: they are copied into the
checkout from `$PAPAIA_CONFIG_DIR` on every `start` and consumed via
`env_file:`. See [Configuration](../docs/configuration.md).

---

## Inspecting a running stack

```bash
docker compose -f docker-compose.yml --env-file .env ps        # what is running
docker compose -f docker-compose.yml --env-file .env logs -f <service>
docker compose -f docker-compose.yml --env-file .env config     # merged compose file
```

`config` expands the `include:` list and resolves every `${VAR}` — the fastest way
to check a change before starting. `src/.env` is written by
`tools/papaia-ctl start`, so run the stack at least once before invoking
`docker compose` directly.

---

## Adding a variable

Every `${VAR}` a compose file interpolates **must** be documented in the
`.env.example` next to it, even when it has an inline `:-` default. Which file a
variable belongs in, and how it reaches the container, is covered in
[Configuration](../docs/configuration.md#how-a-variable-reaches-a-container) —
the collision between `environment:` and `env_file:` described there is the one
trap worth reading before adding anything.

---

## Further reading

- [`../README.md`](../README.md) — installation, `papaia-ctl` reference, add-ons
- [`ai/README.md`](ai/README.md) — per-AI-service summary
- [`infra/keycloak/README.md`](infra/keycloak/README.md) — realm contents, client
  list, external-IdP migration, secret rotation
- [`../docs/configuration.md`](../docs/configuration.md) — environment variable reference
- [`../docs/deployment.md`](../docs/deployment.md) — operations
- [`../docs/troubleshooting.md`](../docs/troubleshooting.md) — common failure modes
