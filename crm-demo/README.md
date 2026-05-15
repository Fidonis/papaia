# crm-demo

Standalone EspoCRM stack with an HTTP-exposed MCP server, intended as an
optional demo module for the papAIa platform. Runs entirely on its own bridge
network — no Keycloak, no oauth2-proxy, no shared service dependencies — and
joins the main `papaia-net` only on the MCP container so that LibreChat (and
any other papAIa-side consumer) can call the MCP tools.

---

## Architecture overview

```
                            ┌──────────────────────────────┐
                            │      Browser / API user      │
                            └──────────────┬───────────────┘
                                           │  http://localhost:9000
                                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                            crm-demo-net (bridge)                      │
│                                                                       │
│   ┌──────────────┐     ┌──────────────┐     ┌────────────────────┐    │
│   │ espocrm-db   │◀────│   espocrm    │────▶│  espocrm-daemon    │    │
│   │  (MariaDB)   │     │  (Apache)    │     │   (cron worker)    │    │
│   └──────────────┘     └──────┬───────┘     └────────────────────┘    │
│                               │                                       │
│                               │             ┌────────────────────┐    │
│                               └────────────▶│ espocrm-websocket  │    │
│                                             │  (real-time push)  │    │
│                                             └────────────────────┘    │
│                                                                       │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │                       espocrm-mcp                               │ │
│   │  ┌──────────────────────┐   supergateway   ┌─────────────────┐  │ │
│   │  │ EspoMCP (Node, stdio)│◀───────────────▶│ Streamable HTTP │  │ │
│   │  │ zaphod-black/EspoMCP │                  │ /mcp  ·  /sse   │  │ │
│   │  └──────────────────────┘                  └────────┬────────┘  │ │
│   └─────────────────────────────────────────────────────┼───────────┘ │
└───────────────────────────────────────────────────────────┼───────────┘
                                                            │
                                                            │  also joins
                                                            ▼
                                              ┌──────────────────────────┐
                                              │       papaia-net         │
                                              │  (external, from src/)   │
                                              │   ─── LibreChat,         │
                                              │       n8n, …             │
                                              └──────────────────────────┘
```

The MCP container is the only one with a foot in both networks. The CRM core
itself is reachable from the host (port `9000`) and within `crm-demo-net`
only.

---

## Components

### `espocrm-db` — MariaDB 11

- Persistent storage for EspoCRM in volume `espocrm-db-data`.
- Credentials are taken from `ESPOCRM_DB_*` (see `.env.example`).
- Not exposed to the host.

### `espocrm` — EspoCRM webserver (Apache)

- Image: `espocrm/espocrm:latest`.
- On **first boot** the container performs an unattended install using
  `ESPOCRM_ADMIN_USERNAME` / `ESPOCRM_ADMIN_PASSWORD` and the database
  variables. Subsequent boots reuse the data in volume `espocrm-data`.
- Public URL for link generation: `ESPOCRM_SITE_URL` (default
  `http://localhost:8080` — adjust when exposing beyond localhost).
- Host port: `ESPOCRM_EXT_PORT` (default `9000`) → container `80`.

### `espocrm-daemon` — Background worker

- Same image as `espocrm`, but launched with `docker-daemon.sh` as entrypoint.
- Runs scheduled jobs (emails, reminders, workflow rules) on the shared
  `espocrm-data` volume.

### `espocrm-websocket` — Real-time notifications

- Same image, entrypoint `docker-websocket.sh`.
- Publishes browser push notifications used by the EspoCRM UI.
- Host port: `ESPOCRM_WS_EXT_PORT` (default `9001`) → container `8080`.

### `espocrm-mcp` — MCP server (HTTP-exposed)

Built from [`zaphod-black/EspoMCP`](https://github.com/zaphod-black/EspoMCP),
which ships stdio-only. We clone, build, and run it behind
[`supergateway`](https://www.npmjs.com/package/supergateway), which translates
stdio into **Streamable HTTP** (`/mcp`) and legacy **SSE** (`/sse`).

- Build context: `./mcp` (see `mcp/Dockerfile`).
- Authenticates against EspoCRM via `ESPOCRM_API_KEY` (or HMAC, see below).
- Internal MCP URL (consumed by other papAIa services on `papaia-net`):
  `http://espocrm-mcp:9010/mcp`.
- Host port: `MCP_EXT_PORT` (default `9010`).
- Health endpoint: `GET /healthz`.

---

## Environment variables

Copy `.env.example` to `.env` and fill in real values. Never commit `.env`.

### Database

| Variable | Default | Description |
|---|---|---|
| `ESPOCRM_DB_NAME` | `espocrm` | Database name |
| `ESPOCRM_DB_USER` | `espocrm` | Application DB user |
| `ESPOCRM_DB_PASSWORD` | — | Password for the application user (**required**) |
| `ESPOCRM_DB_ROOT_PASSWORD` | — | MariaDB root password (**required**) |

### EspoCRM bootstrap

| Variable | Default | Description |
|---|---|---|
| `ESPOCRM_ADMIN_USERNAME` | `admin` | Initial admin user (created on first boot only) |
| `ESPOCRM_ADMIN_PASSWORD` | — | Initial admin password (**required**) |
| `ESPOCRM_SITE_URL` | `http://localhost:8080` | Public URL used for links, cookies, OAuth callbacks |

### Host ports

| Variable | Default | Description |
|---|---|---|
| `ESPOCRM_EXT_PORT` | `9000` | EspoCRM web UI |
| `ESPOCRM_WS_EXT_PORT` | `9001` | EspoCRM websocket endpoint |
| `MCP_EXT_PORT` | `9010` | EspoMCP Streamable HTTP endpoint |

### papAIa integration

| Variable | Default | Description |
|---|---|---|
| `PAPAIA_DOCKER_NETWORK` | `papaia-dev-net` | External bridge network created by the main `src/` stack. Must match `DOCKER_NETWORK` in `src/.env`. |

### MCP server

| Variable | Default | Description |
|---|---|---|
| `ESPOCRM_API_KEY` | — | API key from an EspoCRM API user (**required to start the MCP service**) |
| `ESPOCRM_AUTH_METHOD` | `apikey` | `apikey` or `hmac` |
| `ESPOCRM_SECRET_KEY` | — | Secret for `hmac` auth (ignored when `apikey`) |
| `MCP_RATE_LIMIT` | `100` | Requests per minute towards EspoCRM |
| `MCP_REQUEST_TIMEOUT` | `30000` | EspoCRM request timeout (ms) |
| `MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

---

## Quick start

```bash
# 1. Prepare environment
cp .env.example .env
# Edit .env: set ESPOCRM_DB_PASSWORD, ESPOCRM_DB_ROOT_PASSWORD,
#            ESPOCRM_ADMIN_PASSWORD. Leave ESPOCRM_API_KEY empty for now.

# 2. Start the CRM core (without MCP — it needs the API key first)
docker compose up -d espocrm-db espocrm espocrm-daemon espocrm-websocket

# 3. Wait for EspoCRM to finish its unattended install
docker logs -f crm-demo-espocrm-1
# → look for "EspoCRM is installed" before continuing

# 4. Open the UI and log in
#    http://localhost:9000
#    user: admin   (or whatever ESPOCRM_ADMIN_USERNAME is set to)
#    pass: <ESPOCRM_ADMIN_PASSWORD from .env>
```

### Create an API user and key

EspoMCP authenticates as a dedicated **API User** (not the admin account):

1. In EspoCRM, go to **Administration → Users → API Users → Create API User**.
2. Set **Authentication Method**:
   - **API Key Only** → matches `ESPOCRM_AUTH_METHOD=apikey`.
   - **HMAC** → matches `ESPOCRM_AUTH_METHOD=hmac`. Note the secret too.
3. Assign a role that grants access to the entities the MCP client should
   reach (Accounts, Contacts, Opportunities, …). A read-only role is a
   sensible starting point.
4. Save the user. EspoCRM shows the generated **API Key** (and, for HMAC, the
   **Secret Key**).
5. Paste the values into `.env`:
   ```env
   ESPOCRM_API_KEY=<generated_api_key>
   # only when AUTH_METHOD=hmac:
   ESPOCRM_SECRET_KEY=<generated_secret_key>
   ```

### Start the MCP service

```bash
docker compose up -d espocrm-mcp

# Verify it came up healthy
curl -s http://localhost:9010/healthz
```

The MCP endpoint is now reachable on:

- `http://localhost:9010/mcp` — Streamable HTTP (preferred for new clients)
- `http://localhost:9010/sse`  — legacy SSE
- `http://espocrm-mcp:9010/mcp` — from inside `papaia-net` (LibreChat, n8n, …)

---

## Integration with papAIa / LibreChat

The MCP container joins `papaia-net` (the external network owned by the main
`src/` compose project) so that LibreChat can reach it by container name.

`src/ai/librechat/librechat.yaml` already declares the upstream:

```yaml
mcpServers:
  EspoCRM:
    title: 'EspoCRM'
    description: 'MCP server for EspoCRM customer relationship management system.'
    type: streamable-http
    url: http://espocrm-mcp:9010/mcp

mcpSettings:
  allowedDomains:
    - http://espocrm-mcp:9010
```

For this to resolve, both stacks must share the bridge network:

- `src/.env` defines `DOCKER_NETWORK=papaia-dev-net` (or similar).
- `crm-demo/.env` must set `PAPAIA_DOCKER_NETWORK` to the **same value**.
- The network must already exist when `crm-demo` starts — usually because the
  `src/` stack is up. If not, create it manually:
  ```bash
  docker network create papaia-dev-net
  ```

Once both stacks are running, the EspoCRM MCP tools become available in the
LibreChat UI under **MCP Servers → EspoCRM**.

---

## Operational notes

- **First boot is slow.** The unattended install creates the schema, builds
  caches, and runs database migrations. Watch `docker logs` and wait for
  `EspoCRM is installed` before trying to log in.
- **API key changes.** Rotating the API key in EspoCRM requires updating
  `ESPOCRM_API_KEY` in `.env` and restarting only the MCP service:
  ```bash
  docker compose up -d --force-recreate espocrm-mcp
  ```
- **Schema-aware MCP behaviour.** EspoMCP introspects the EspoCRM metadata at
  startup. Custom entities and fields appear in the tool surface automatically,
  but a restart of `espocrm-mcp` is required after metadata changes.
- **Email / scheduled jobs.** `espocrm-daemon` is required for outgoing email,
  workflow rules, and any other cron-driven feature. The web UI alone will not
  run these.
- **Websocket port.** `espocrm-websocket` is only needed for the UI's
  real-time notifications. If you do not expose port `9001`, the UI still
  works but the websocket bell will show as disconnected.
- **Backups.** The two persistent volumes are `espocrm-db-data` (MariaDB) and
  `espocrm-data` (uploads, config, custom modules). Both must be backed up
  together — they reference each other (file IDs in DB ↔ files on disk).
- **Upgrades.** `espocrm/espocrm:latest` is pinned only by tag; pulling a newer
  image and recreating the containers triggers EspoCRM's built-in upgrade
  routine on the existing data volume. Take a backup first.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `espocrm-mcp` restart-loops, logs `401 Unauthorized` | `ESPOCRM_API_KEY` empty, wrong, or belongs to a disabled user | Verify the key in EspoCRM → API Users, paste into `.env`, `docker compose up -d --force-recreate espocrm-mcp` |
| `espocrm-mcp` logs `network papaia-dev-net not found` | The external network does not exist yet | Start the `src/` stack first, or `docker network create <name>` matching `PAPAIA_DOCKER_NETWORK` |
| LibreChat sees the server but tools return `403` | API user role lacks access to the requested entity | Adjust the role in EspoCRM → Roles, restart `espocrm-mcp` |
| Login fails immediately after first boot | Install not finished yet | Watch `docker logs crm-demo-espocrm-1`, wait for `EspoCRM is installed` |
| Web UI loads but the bell shows "disconnected" | Websocket port not reachable from the browser | Confirm `ESPOCRM_WS_EXT_PORT` is published and not blocked by a firewall |
| `unauthorized` from `curl http://localhost:9010/mcp` | Expected — MCP requires a JSON-RPC handshake, not a plain GET | Use an MCP client (LibreChat, MCP Inspector, etc.) |
| Health check `/healthz` returns nothing | `espocrm-mcp` not running, or supergateway crashed during stdio spawn | `docker logs crm-demo-espocrm-mcp-1` and look for the EspoMCP startup banner |

---

## Limitations and caveats

| Limitation | Rationale |
|---|---|
| Standalone — no Keycloak SSO | This is a demo module. Production deployment behind papAIa's oauth2-proxy is out of scope; EspoCRM has its own user system. |
| `latest` image tags | Convenience over reproducibility. Pin specific versions in your own deployment if you need deterministic upgrades. |
| Single API key for the MCP server | The MCP server acts as a single principal in EspoCRM. Per-user authorisation must be enforced at the LibreChat layer. |
| No TLS termination inside the stack | `ESPOCRM_SITE_URL` defaults to HTTP. Run behind a reverse proxy (Caddy, Traefik, nginx) when exposing publicly. |
| Upstream EspoMCP is third-party | Source: [zaphod-black/EspoMCP](https://github.com/zaphod-black/EspoMCP). Pin the build by setting `ESPOMCP_REF` in `mcp/Dockerfile` when stability matters. |

---

## Directory structure

```
crm-demo/
├── mcp/
│   └── Dockerfile        # builds EspoMCP from source + supergateway HTTP bridge
├── docker-compose.yml    # 5 services: db, web, daemon, websocket, mcp
├── .env.example          # template with all variables documented
├── .env                  # active configuration (not committed)
├── .gitignore
└── README.md             # this file
```

---

## References

- EspoCRM documentation — https://docs.espocrm.com/
- EspoCRM API reference — https://docs.espocrm.com/development/api/
- EspoMCP (upstream) — https://github.com/zaphod-black/EspoMCP
- supergateway — https://github.com/supercorp-ai/supergateway
- Model Context Protocol — https://modelcontextprotocol.io/
