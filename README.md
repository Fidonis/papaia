# papAIa

> Self-hosted, OIDC-first AI & document platform — built with Docker Compose.
> by **Fidonis GmbH** · <https://fidonis.de>

papAIa is a unified Docker Compose stack that bundles a chat UI, an LLM proxy,
local model hosting, document management, RAG over personal files, workflow
automation and metasearch — all behind a single Keycloak SSO.

This is the **0.6.0** release: every service that supports authentication is
wired up to Keycloak via OIDC (native or via oauth2-proxy).

---

## Highlights of 0.6.0

- **OIDC-first SSO** for the whole stack — Keycloak realm, clients, roles and
  test users are pre-provisioned via realm import.
- **Template-driven setup** — every service ships a `.env.example` with
  `GENERATE_…` placeholders; copy it to `.env`, fill in the secrets and
  enable only the modules you need via `COMPOSE_PROFILES`.
- **New services**: n8n, MCP Paperless, doc-rag (RAG over WebDAV sources),
  SearXNG, Homepage dashboard, oauth2-proxy.
- **Single Compose file** at `src/docker-compose.yml` aggregates per-service
  compose files via `include:` — no more juggling many compose invocations.
- **Split-URL OIDC** — browser-facing endpoints use the host's reachable URL
  (`PAPAIA_HOST`, e.g. `host.docker.internal` on Docker Desktop or a LAN IP on
  Linux), while server-to-server token/JWKS lookups stay on internal Docker
  DNS. This keeps the `iss` claim stable across both worlds.
- **Per-user document isolation** in MCP Paperless — Keycloak access tokens
  are forwarded into Paperless on a per-request basis so each user only sees
  their own documents.

---

## Architecture overview

```
                ┌───────────────────────────────────────────────┐
                │                   Browser                     │
                └───────────┬─────────────────┬─────────────────┘
                            │                 │
                            │  native OIDC    │  forward auth (oauth2-proxy)
                            ▼                 ▼
              ┌─────────────────────┐   ┌────────────────┐
              │ LibreChat (8000)    │   │ n8n (8400)     │
              │ Paperless (8010)    │   │ Homepage (8300)│
              │ LiteLLM   (8200)    │   └───────┬────────┘
              └──────┬──────────────┘           │
                     │                          ▼
                     ▼                ┌─────────────────────┐
              ┌──────────────┐        │ oauth2-proxy (4180) │
              │  Keycloak    │◀───────┤                     │
              │   (8110)     │        └─────────────────────┘
              └──────┬───────┘
                     │
                     │ realm: papaia
                     │ clients: librechat, paperless, litellm, oauth2-proxy
                     │ roles:   admin, user, viewer
                     │
                     ▼
        ┌───────────────────────────────────────────────────┐
        │                AI / Backend services              │
        │ LocalAI · doc-rag (Qdrant+rclone+ingester+API)    │
        │ MCP Paperless · SearXNG · Mongo · Postgres · ...  │
        └───────────────────────────────────────────────────┘
```

**Authentication coverage**

| Service        | Approach                | Notes                                |
|----------------|-------------------------|--------------------------------------|
| LibreChat      | Native OIDC             | `openid-client`, PKCE enforced       |
| Paperless-ngx  | Native OIDC             | `django-allauth`                     |
| LiteLLM (UI)   | Generic OIDC            | API key for programmatic access      |
| n8n            | oauth2-proxy forward    | NPM rule guards the upstream         |
| Homepage       | oauth2-proxy forward    | optional, configurable per host      |
| MCP Paperless  | OAuth2 token forwarding | per-user view of Paperless documents |
| Nginx PM admin | Network-level only      | bind to internal interfaces          |

---

## Service catalogue & default port map

External ports are configurable in `src/.env`. Defaults below.

### Infrastructure

| Service              | Port | Purpose                                        |
|----------------------|------|------------------------------------------------|
| Keycloak             | 8110 | Identity & access management (OIDC issuer)     |
| Nginx Proxy Manager  | 8100 | Reverse proxy / TLS termination admin UI       |
| oauth2-proxy         | 4180 | Forward-auth gateway for non-OIDC services     |
| Technitium DNS       | 8120 | Optional DNS server (commented out by default) |

### Application services

| Service        | Port | Purpose                                              |
|----------------|------|------------------------------------------------------|
| LibreChat      | 8000 | Multi-provider chat UI                               |
| Paperless-ngx  | 8010 | Document management system                           |
| LiteLLM        | 8200 | Unified LLM proxy + Postgres (8210) + Prom. (8230)   |
| Homepage       | 8300 | Service dashboard                                    |
| n8n            | 8400 | Workflow automation                                  |
| SearXNG        | 8500 | Privacy-respecting metasearch                        |
| doc-rag API    | 8700 | RAG MCP server (`POST /mcp`, `GET /health`)          |
| Qdrant         | 6333 | Vector store dashboard for doc-rag                   |
| LocalAI        | 8080 | Local model inference, chat-completions API          |
| Firecrawl      | 3002 | Web crawler (commented out by default)               |
| Home Assistant | 8123 | Home automation (host-network mode, optional)        |

### Internal-only / co-deployed

- MCP Paperless (per-user Paperless proxy for LibreChat) — `:9520`
- Jina AI Reranker (optional, `:8600`)
- LibreChat sidecars (Mongo, Meilisearch, pgvector, RAG API)
- Paperless sidecars (Postgres, Redis, Tika, Gotenberg)

> **Tip:** all `*_EXT_PORT` variables are listed in `src/.env.example` and
> grouped per service. Change a single number to relocate a port.

---

## Quick start

### Prerequisites
- Docker and Docker Compose installed
- `openssl` to generate secrets; `python3` for the Keycloak bootstrap helper
- At least 8GB RAM recommended
- Linux, macOS or WSL2 environment

### Single-host setup (default)

papAIa is deployed manually: copy the shipped `.env.example` templates,
fill in your own secrets, and bring the stack up with Docker Compose.

**1. Clone the repository**

```bash
git clone https://github.com/marko-boehm/papaia.git
cd papaia
```

**2. Create the environment files**

Copy `src/.env.example` to `src/.env`, and one `.env` per service
directory, then replace every `GENERATE_…` placeholder with a fresh
secret:

```bash
cp src/.env.example src/.env
# repeat for each module you enable, e.g.:
cp src/infra/keycloak/.env.example  src/infra/keycloak/.env
cp src/ai/librechat/.env.example    src/ai/librechat/.env
cp src/ai/litellm/.env.example      src/ai/litellm/.env
# … and so on

openssl rand -hex 24      # generic secret / password
openssl rand -base64 32   # for any *_COOKIE_SECRET (must be 32 bytes)
```

Review `src/.env` for the host-specific basics — `PAPAIA_HOST`, `HOST_IP`,
`COMPOSE_PROFILES`, `PAPAIA_CONFIG_DIR` — and follow the
[environment setup details](#environment-setup-details) for the one
cross-file rule you must respect (matching Keycloak client secrets).

**3. Prepare the Keycloak realm file**

The realm import keeps client secrets as `${env.…}` placeholders that
Keycloak substitutes at import time, so a plain copy is enough:

```bash
cp src/infra/keycloak/realm-import/papaia-realm.json.template \
   src/infra/keycloak/realm-import/papaia-realm.json
```

**4. Seed the externalised config directory**

```bash
src/sync-config.sh
```

`src/sync-config.sh` copies the shipped service-configuration defaults
from `src/` into the externalised config directory at `${PAPAIA_CONFIG_DIR}`
(see [Externalised service configuration](#externalised-service-configuration)
below). It is non-destructive: existing files in the target are kept, so
running it again after a `git pull` only fills in newly added defaults.

**5. Start the stack**

```bash
docker compose -f src/docker-compose.yml --env-file src/.env up -d
```

Keycloak imports the `papaia` realm automatically on first start
(`--import-realm`). To re-sync realm clients later without recreating the
Keycloak volume, run `src/infra/keycloak/bootstrap.sh`.

### Stopping

```bash
docker compose -f src/docker-compose.yml --env-file src/.env stop      # keep volumes
docker compose -f src/docker-compose.yml --env-file src/.env down      # also remove network
docker compose -f src/docker-compose.yml --env-file src/.env down -v   # also wipe volumes
```

## Multi-environment deployments (dev / stage / demo on one host)

Multiple papAIa stacks can run side-by-side on a single host without
forking the repo. Each environment gets its own:

- `COMPOSE_PROJECT_NAME` (e.g. `papaia-dev`) — namespaces containers and
  volumes so Docker doesn't reuse them across stacks.
- `DOCKER_NETWORK` (e.g. `papaia-dev-net`) — every stack gets its own
  bridge network.
- `HOST_IP` — bind address for published ports. Combine with IP aliases
  on the host's primary interface so two stacks with identical port
  numbers can coexist (`papaia-dev` → `.102`, `papaia-stage` → `.103`,
  `papaia-demo` → `.101`).
- `PAPAIA_HOST` — public URL used in OIDC redirects and service public
  URLs. The hostname depends on whether you are behind a reverse proxy
  (Caddy / Traefik / NPM / …) and what scheme it terminates on. There is
  no enforced hostname convention — pick what fits the platform. It can be
  anything reachable from the browser: a LAN IP, the `host.docker.internal`
  default for Docker Desktop, or a public FQDN.
- HTTPS / `OAUTH2_PROXY_COOKIE_SECURE` — must match the scheme of
  `PAPAIA_HOST`. An HTTPS `PAPAIA_HOST` requires
  `OAUTH2_PROXY_COOKIE_SECURE=true` for every oauth2-proxy sidecar; HTTP
  requires `false`. Browsers ignore Secure cookies over plain HTTP, so a
  mismatch silently breaks login.

Give each environment its own env file (e.g. `src/.env.dev`,
`src/.env.stage`, …) and pass the active one with `--env-file`:

```bash
docker compose -f src/docker-compose.yml --env-file src/.env.dev up -d
```

Set `COMPOSE_PROJECT_NAME`, `DOCKER_NETWORK`, `HOST_IP` and `PAPAIA_HOST`
to distinct values per environment. With the bind addresses pinned through
`HOST_IP`, ports on the public interface stay isolated and can be filtered
at the firewall.

### Reverse Proxy Setup

Two services need a TLS-terminating reverse proxy in front of them for
OIDC login to work reliably:

- **Keycloak** (`AUTH_HOST`) — tokens are issued under this URL and the
  browser POSTs the OIDC callback cross-origin. Behind a TLS-terminating
  edge proxy Keycloak only sees plain HTTP and must trust
  `X-Forwarded-*` headers; the bundled `KC_PROXY_HEADERS=xforwarded`
  default takes care of that.
- **LibreChat** — its container speaks plain HTTP on port 3080 (mapped to
  `HOST_IP:LIBRECHAT_EXT_PORT`). Without HTTPS in front, Keycloak's
  cross-origin POST + LibreChat's cookie / SameSite defaults break the
  OIDC callback in subtle ways, so a TLS-terminating proxy in front of
  LibreChat is strongly recommended for any non-local deployment.

Each public URL must point at the corresponding `HOST_IP:port` mapping:

```
${AUTH_HOST}            →  HOST_IP : KEYCLOAK_EXT_PORT      (default 8110)
${LIBRECHAT_HOST}       →  HOST_IP : LIBRECHAT_EXT_PORT     (default 8000)
```

Add similar routes for any other service exposed through the proxy
(Paperless, n8n, Homepage, …).

#### Caddyfile example

```caddy
auth.papaia-dev.example.com {
    reverse_proxy 192.168.10.102:8110
}

chat.papaia-dev.example.com {
    reverse_proxy 192.168.10.102:8000
}
```

For Traefik / nginx the equivalent rules are a host header match plus
`reverse_proxy` / `proxy_pass` to `HOST_IP:port`.

If the host is already running an edge proxy on ports 80/443, remove
`nginx` from `COMPOSE_PROFILES` in `src/.env` so the bundled Nginx Proxy
Manager does not port-conflict on 80.

### Externalised service configuration

papAIa keeps customer-editable service configuration **outside** the repo so
that local edits do not collide with `git pull` / fast-forward upgrades.
The variable that drives this is `PAPAIA_CONFIG_DIR` in `src/.env`.

```env
# src/.env
PAPAIA_CONFIG_DIR=/srv/papaia/config
```

`PAPAIA_CONFIG_DIR` must be an **absolute path** — Docker Compose resolves
relative paths in `include:`d files against each file's own directory, so a
relative value would resolve differently per service.

The directory layout inside `${PAPAIA_CONFIG_DIR}` mirrors `src/` exactly,
so the diff between the shipped default and the customer copy stays
obvious:

```
${PAPAIA_CONFIG_DIR}/
├── ai/
│   ├── doc-rag/integrations/webdav/sync.sh
│   ├── librechat/librechat.yaml
│   ├── librechat/patches/{entrypoint.sh, mcp-user-headers.js, openidStrategy.js}
│   ├── litellm/{config.yaml, prometheus.yml}
│   ├── localai/models.txt
│   ├── localai/models/{nomic-embed-text.yaml, qwen2.5-1.5b-instruct.yaml}
│   └── n8n/nginx.conf
├── infra/
│   └── keycloak/
│       ├── keycloak.conf
│       └── realm-import/papaia-realm.json[.template]
└── services/
    ├── homepage/config/{bookmarks,custom.css,custom.js,docker,kubernetes,
    │                    proxmox,services,settings,widgets}.{yaml,css,js}
    └── searxng/settings.yml
```

Every bind-mount in `src/**/docker-compose.yml` references
`${PAPAIA_CONFIG_DIR}/<mirrored-path>`. Editing a file inside the config
directory and restarting the affected container therefore applies the
change inside that container.

#### Initial population

```bash
src/sync-config.sh                # uses PAPAIA_CONFIG_DIR from src/.env
src/sync-config.sh /custom/path   # or pass an explicit target
src/sync-config.sh --force        # overwrite (DESTRUCTIVE — discards edits)
```

The script copies every file listed above from `src/` into
`${PAPAIA_CONFIG_DIR}`. By default existing target files are preserved, so
the script is safe to re-run after upgrades.

#### Upgrade flow

```bash
git pull                                                       # new repo version
src/sync-config.sh                                             # add new defaults
                                                               # (non-destructive)
docker compose -f src/docker-compose.yml --env-file src/.env up -d
```

Customer overrides under `${PAPAIA_CONFIG_DIR}` survive the upgrade
untouched. Any **new** files shipped by the upgrade land in the config
directory next to the existing ones. To re-baseline a specific file to
the new shipped default, delete it from `${PAPAIA_CONFIG_DIR}` first and
re-run `src/sync-config.sh`.

#### Backup

`src/backup-papaia.sh` now also archives `${PAPAIA_CONFIG_DIR}` (as
`papaia-config.tar.gz`) on every run if the directory exists. Restoring
the config archive is a plain `tar xzf` into the target path — no Docker
volume operations are required.

### Environment setup details

The [Single-host setup](#single-host-setup-default) above creates the
`.env` files. Two things need extra care:

1. **`GENERATE_…` placeholders** — every value still set to a `GENERATE_…`
   string must be replaced with a real secret (`openssl rand -hex 24`, or
   `openssl rand -base64 32` for the 32-byte `*_COOKIE_SECRET` values).
2. **Matching Keycloak client secrets** — each `KC_<service>_CLIENT_SECRET`
   in `src/infra/keycloak/.env` must hold the **same value** as the
   corresponding client secret in the consuming service's `.env`
   (`OPENID_CLIENT_SECRET` for LibreChat, `GENERIC_CLIENT_SECRET` for
   LiteLLM, `OAUTH2_PROXY_CLIENT_SECRET` in `src/.env`). Generate one
   secret per client and paste it into both files.

Once the stack is up, the default endpoints are:

- Keycloak admin: `http://host.docker.internal:8110` — login as `admin`
  with the password in `src/infra/keycloak/.env` (`KC_ADMIN_PASSWORD`).
- Realm login (e.g. via LibreChat): `admin` / `admin` in realm `papaia`
  (test user — change for anything beyond local development).
- LibreChat: `http://host.docker.internal:8000`
- Paperless: `http://host.docker.internal:8010`
- Homepage: `http://host.docker.internal:8300`
- n8n: `http://host.docker.internal:8400`

### 3. Stop / remove

```bash
docker compose stop      # stop containers, keep volumes
docker compose down      # remove containers + network
docker compose down -v   # also wipe volumes (destructive!)
```

---

## OIDC & SSO — how the pieces fit together

papAIa standardises on **OpenID Connect** for all human-facing
authentication. There are two integration patterns:

### 1. Native OIDC clients (LibreChat, Paperless, LiteLLM)

These services speak OIDC themselves. The configuration model is:

- A Keycloak client per service (`librechat`, `paperless`, `litellm`) is
  created from `papaia-realm.json`, imported on Keycloak's first start.
- Each client secret (`KC_<service>_CLIENT_SECRET`) must hold the same
  value in `infra/keycloak/.env` and in the consuming service's `.env`.
- `OPENID_ISSUER` / `GENERIC_AUTHORIZATION_ENDPOINT` must point at the
  **public** Keycloak URL derived from `PAPAIA_HOST`, so the `iss` claim
  the service receives matches what the browser hits at login.
- PKCE (`OPENID_USE_PKCE=true`) is required where the realm enforces it
  (mandatory for the LibreChat client).

### 2. oauth2-proxy forward auth (n8n, optional Homepage and any custom service)

Services without native OIDC sit behind oauth2-proxy. NPM checks
`/oauth2/auth` before letting requests through; on a 401, the user is
bounced to Keycloak via oauth2-proxy.

oauth2-proxy runs in **`--skip-oidc-discovery` mode** with the three OIDC
endpoints split into:

| Variable                  | Purpose                            | Reachable from |
|---------------------------|------------------------------------|----------------|
| `OIDC_ISSUER_KC_AUTH`     | Browser redirect to login          | Browser        |
| `OIDC_ISSUER_KC_TOKEN`    | Server-side code → token exchange  | Containers     |
| `OIDC_ISSUER_KC_CERTS`    | JWKS for signature verification    | Containers     |

The auth URL uses `PAPAIA_HOST` (e.g. `http://host.docker.internal:8110`)
so it works in the user's browser. The token & JWKS URLs use the internal
service name (`http://keycloak:8080`) so cross-container calls don't
depend on host DNS. Both routes resolve to the **same realm**, which keeps
the `iss` claim consistent.

### Realm contents (out of the box)

| Item                | Value                                       |
|---------------------|---------------------------------------------|
| Realm               | `papaia`                                    |
| Discovery URL       | `${PAPAIA_HOST}:8110/realms/papaia/.well-known/openid-configuration` |
| Clients             | `librechat`, `paperless`, `litellm`, `oauth2-proxy` |
| Realm roles         | `admin`, `user`, `viewer`                   |
| Default test users  | `admin/admin`, `testuser/testuser`          |

> ⚠️ The default test users exist purely for local development. Disable or
> delete them before exposing the stack to anything beyond `localhost`.

### Switching to an external IdP (Entra ID, Authentik, Okta …)

In `src/.env`:

```env
AUTH_PROVIDER=external_oidc
OIDC_ISSUER=https://idp.example.com/realms/your-realm
OIDC_CLIENT_ID=librechat
OIDC_ISSUER_KC_AUTH=https://idp.example.com/realms/your-realm/protocol/openid-connect/auth
OIDC_ISSUER_KC_TOKEN=https://idp.example.com/realms/your-realm/protocol/openid-connect/token
OIDC_ISSUER_KC_CERTS=https://idp.example.com/realms/your-realm/protocol/openid-connect/certs
```

See [`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) for
provider-specific notes.

---

## Service highlights

### LibreChat
- Multi-provider chat UI — hosted and local models via LiteLLM.
- Native Keycloak OIDC login with PKCE.
- Built-in RAG with Meilisearch + pgvector for uploaded files.

### LiteLLM
- Unified API gateway across providers.
- Generic OIDC SSO for the admin UI; master key for programmatic clients.
- Prometheus metrics on `:8230`.

### LocalAI
- Local model inference with a chat-completions API (CPU or NVIDIA GPU image).
- Models to download are listed in `ai/localai/models.txt` (one URL per
  line); edit that file to add or remove models.

### doc-rag
- Pulls documents from one or more WebDAV sources (Nextcloud, SharePoint,
  …) via `rclone` and indexes them with Docling + LiteLLM embeddings into
  per-source Qdrant collections.
- Exposes `search_documents` and `list_collections` as MCP tools (consumed
  by LibreChat and n8n) plus `GET /health` and `POST /reindex` HTTP
  endpoints.
- See [`src/ai/doc-rag/README.md`](src/ai/doc-rag/README.md) for the full
  pipeline, environment variables and operational notes.

### MCP Paperless
- Bridges LibreChat to Paperless-ngx as an MCP tool.
- Forwards the user's Keycloak access token to Paperless on each request,
  so each LibreChat user only ever sees **their own** documents.

### n8n
- Self-hosted workflow automation behind oauth2-proxy.
- Postgres-backed state; public URL set from `PAPAIA_HOST` so the
  oauth2-proxy redirect callback stays correct.

### Paperless-ngx
- Document management with native Keycloak OIDC.
- Pre-wired with Tika + Gotenberg for OCR.
- Admin credentials live in `services/paperless/.env`; the same values
  go into `ai/mcp-paperless/.env`.

### SearXNG
- Privacy-respecting metasearch.
- Bound to LibreChat's web-search integration via
  `SEARXNG_INSTANCE_URL=http://searxng:8080`.

### Homepage
- Curated dashboard for all enabled services.
- `HP_ALLOWED_HOSTS` is derived from `PAPAIA_HOST` so the dashboard is
  reachable on whichever URL the rest of the stack uses.

---

## Operations

### Backup

```bash
src/backup-papaia.sh         # gzipped archives of all named volumes
src/restore-papaia.sh <vol>  # restore one volume from a backup archive
```

The backup script keeps the last 14 days locally. Off-site sync (e.g. to
OneDrive or S3) is left to your environment.

### Selective module enable / disable

`src/docker-compose.yml` aggregates services via `include:`, and each
service declares a Compose `profile`. Enable a module by adding its
profile to `COMPOSE_PROFILES` in `src/.env`; fully optional modules
(commented out in the `include:` list) also need their `include:` line
uncommented. Restart with `docker compose up -d` afterwards.

### Updating images

Image tags are pinned in `src/.env.example`. To upgrade a service, bump the
corresponding `*_IMAGE` variable in `src/.env` and `docker compose up -d
<service>`.

### Resetting Keycloak

The realm import only runs on the **first** Keycloak start. To re-import
(after editing the realm template, for example):

```bash
docker compose down keycloak keycloak-postgresql
docker volume rm papaia_keycloak-postgresql
docker compose up -d
```

This also wipes any users created through the admin UI — back them up first
if you need them.

---

## Troubleshooting

### "redirect_uri does not match" from Keycloak after login

Cause: `PAPAIA_HOST` and the Keycloak client's registered redirect URIs
disagree.

- Check `src/.env` — `PAPAIA_HOST` must be the URL you actually type into
  the browser (host **and** port, scheme included).
- After changing `PAPAIA_HOST`, update every URL derived from it —
  `OIDC_ISSUER`, `OIDC_ISSUER_KC_AUTH`, the LibreChat / LiteLLM /
  Paperless / n8n public URLs and Homepage's `HP_ALLOWED_HOSTS` — then
  recreate the affected containers.
- For first-time changes you may also need to update redirect URIs in the
  Keycloak admin UI (Clients → `librechat` / etc. → Valid redirect URIs).

### LibreChat OIDC login: "invalid_token" or signature errors

Cause: the `iss` claim in the access token doesn't match what LibreChat
expects.

- The token's `iss` always equals `KC_HOSTNAME` (= `PAPAIA_HOST:8110`).
- Make sure `OPENID_ISSUER` in `ai/librechat/.env` is the same URL.
- On Linux, ensure `host.docker.internal` resolves to `127.0.0.1` in
  `/etc/hosts` (add it manually — see the troubleshooting entry below).

### Cookies don't stick / login loops behind oauth2-proxy

oauth2-proxy issues a session cookie tied to the host that served the
login. If you reach n8n via `http://host.docker.internal:8400` but
oauth2-proxy was configured with a different `--redirect-url`, the cookie
won't be sent on subsequent requests.

- Verify that `OAUTH2_PROXY_COOKIE_SECRET` is exactly **32 base64 bytes**
  (`openssl rand -base64 32`); don't shorten it.
- Use the same scheme + host + port in NPM, oauth2-proxy `--redirect-url`,
  and the Keycloak client's "Valid redirect URIs". A mismatch on **any** of
  these breaks the loop.
- When testing, clear cookies for the affected host between attempts —
  stale `_oauth2_proxy*` cookies survive container restarts.

### LibreChat Keycloak login fails over HTTP (issue #40)

Browsers refuse to send `Secure` cookies over plain HTTP. Either:

- Run the stack behind HTTPS (recommended for any non-local deployment), or
- Stay on `http://host.docker.internal` for local development — the realm
  is preconfigured to allow it.

### "host.docker.internal: cannot resolve" on Linux

On Linux, add `127.0.0.1 host.docker.internal` to `/etc/hosts` (requires
sudo):

```bash
echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
```

Or set `PAPAIA_HOST` to the LAN IP of the host instead.

### Out-of-memory when running LocalAI

LocalAI is the heaviest module. If RAM is tight, run a smaller model
(`Qwen2.5 1.5B Q4`), disable LocalAI entirely (comment its line in
`src/docker-compose.yml`) and route LibreChat to a hosted provider via
LiteLLM.

### General debugging

```bash
docker compose ps                 # what's running
docker compose logs -f <service>  # follow one service
docker compose config             # render the merged compose file
```

---

## Repository layout

```
.
├── README.md                  # this file
└── src/
    ├── README.md              # Compose-level operational guide
    ├── docker-compose.yml     # root compose, includes per-service files
    ├── .env.example           # all stack-wide env vars, grouped per service
    ├── sync-config.sh         # seed/refresh PAPAIA_CONFIG_DIR from src/
    ├── backup-papaia.sh       # volume + PAPAIA_CONFIG_DIR backup
    ├── restore-papaia.sh      # volume restore
    ├── infra/                 # keycloak, nginx, oauth2-proxy, technitium
    ├── services/              # firecrawl, home-assistant, homepage,
    │                          # paperless, searxng
    └── ai/                    # doc-rag, jinaai, librechat, litellm,
                               # localai, mcp-paperless, n8n
```

---

## Further reading

- [`src/README.md`](src/README.md) — Compose-level orchestration, service
  toggles, common commands.
- [`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) —
  Realm contents, client list, external-IdP migration, secret rotation.
- [`src/ai/README.md`](src/ai/README.md) — Per-AI-service summary.
- [`src/ai/doc-rag/README.md`](src/ai/doc-rag/README.md) — RAG pipeline
  reference: data flow, env vars, operations.
