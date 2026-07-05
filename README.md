# papAIa

> Self-hosted, OIDC-first AI & document platform — Lean Core, built to extend.
> by **Fidonis GmbH** · <https://fidonis.de>

papAIa is a Docker Compose platform that bundles a chat UI, an LLM proxy, local model
hosting, and a Keycloak-based SSO layer into a self-sufficient **Lean Core**. Additional
services — document management, RAG, workflow automation, search — attach through a
standardised extension contract rather than being hard-wired into the stack.

This is the **1.0.0** release: the Lean Core is stable, `papaia-ctl` is the single
idempotent orchestrator for the full deployment lifecycle, and the extension infrastructure
is in place for first-party and custom service modules.

---

## Architecture overview

papAIa is structured in three tiers:

- **Tier 1 — Core** (always on): identity, ingress, inference, and the chat layer —
  self-sufficient, no extension required.
- **Tier 2 — First-party extensions**: Fidonis-maintained services that plug in through the
  Extension Contract (each in its own repo, version-pinned).
- **Tier 3 — Custom extensions**: bespoke customer services following the same contract.

```
┌──────────────────────────────────────────────────────────────────┐
│  Workspace (parent directory of this checkout)                   │
│                                                                  │
│  papaia/             ← Lean Core (this repo)                    │
│  │  Keycloak · oauth2-proxy · Nginx Proxy Manager               │
│  │  LibreChat · LiteLLM · LocalAI · Homepage                   │
│  │                                                               │
│  extensions/         ← Extensions (separate repos, opt-in)      │
│  │  papaia-ext-qdrant-rag/    OIDC-secured vector search (RAG)  │
│  │  papaia-ext-paperless/     Document management + MCP bridge  │
│  │  papaia-ext-n8n/           Workflow automation               │
│  │  papaia-ext-*/             further first-party or custom     │
│  │                                                               │
│  papaia-config/      ← PAPAIA_CONFIG_DIR (generated state)      │
│     deployment.yaml  rendered configs  generated secrets        │
└──────────────────────────────────────────────────────────────────┘
```

Each extension integrates through five standardised seams — no per-extension edits to the
Core are required:

| Seam | Mechanism |
|------|-----------|
| Network | Extension declares its bridge network; Core containers auto-attach via generated Compose override |
| OIDC | Keycloak clients registered additively at bootstrap |
| LibreChat-MCP | `mcpServers` + `allowedDomains` fragments merged at render time |
| Dashboard | Homepage service card merged at render time |
| Ingress | Nginx Proxy Manager fragment merged at render time (optional) |

An extension ships a manifest (`papaia-app.yaml`) that describes all five seams in
machine-readable form. `papaia-ctl` reads the manifest to render the unified configuration
and generate the network attachment overrides.

**Authentication coverage — Core services**

| Service | Approach | Notes |
|---|---|---|
| LibreChat | Native OIDC | `openid-client`, PKCE enforced |
| LiteLLM (UI) | Generic OIDC | API key for programmatic access |
| LocalAI | Native OIDC | Role-restricted: only users with the `localai-access` realm role can authenticate via SSO |
| Nginx PM admin | Network-level only | bind to internal interfaces |
| oauth2-proxy | Forward-auth gateway | guards services without native OIDC |
| Homepage | oauth2-proxy forward | optional, configurable per host |

---

## Service catalogue

### Core services (always on)

| Service | Port | Purpose |
|---|---|---|
| Keycloak | 8110 | Identity & access management (OIDC issuer) |
| Nginx Proxy Manager | 8100 | Reverse proxy / TLS termination admin UI |
| oauth2-proxy | 4180 | Forward-auth gateway for non-OIDC services |
| LibreChat | 8000 | Multi-provider chat UI |
| LiteLLM | 8200 | Unified LLM proxy (Postgres 8210 · Prometheus 8230) |
| Homepage | 8300 | Service dashboard |

Core sidecars (internal, not directly exposed): Mongo · Meilisearch · pgvector
(LibreChat) · Technitium DNS 8120 (optional, commented out by default)

### Optional modules (Compose profiles, within this repo)

These services ship as Compose profiles in this repository. They follow the Extension
Contract and will graduate to independent extension repos in upcoming releases.

| Module | Profile | Port | Purpose |
|---|---|---|---|
| LocalAI | `localai` | 8080 | Local model inference, chat-completions API (enabled by default) |
| qdrant-rag | `qdrant-rag` | 8800 | OIDC + RBAC MCP server for role-scoped vector search |
| Qdrant | (with qdrant-rag) | 6333 / 6334 | Vector store for qdrant-rag (REST + gRPC) |
| qdrant-webdav-ingest | `qdrant-rag` | — | WebDAV → Qdrant ingestion worker |
| Jina Reranker | `qdrant-rag` | 8600 | Optional semantic reranker |
| Paperless-ngx | `paperless` | 8010 | Document management system |
| MCP Paperless | (with paperless) | 9520 | Per-user Paperless bridge for LibreChat |
| n8n | `n8n` | 8400 | Workflow automation |
| SearXNG | `searxng` | 8500 | Privacy-respecting metasearch |
| Firecrawl | `firecrawl` | 3002 | Web crawler (commented out by default) |
| MCP Office Docs | `mcp-office-docs` | 9530 | Office document generation via LibreChat |
| MinIO | (with mcp-office-docs) | 9000 / 9001 | S3-compatible object store for generated files |
| Home Assistant | `home-assistant` | 8123 | Home automation (host-network mode, optional) |

> **Tip:** all `*_EXT_PORT` variables are listed in `src/.env.example` grouped per service.
> Change a single number to relocate a port.

---

## papaia-ctl reference

`papaia-ctl` (`tools/papaia-ctl`) is the single orchestrator for the papAIa deployment
lifecycle: bootstrapping, configuration rendering, and stack management. The Bash dispatcher
handles CLI parsing, interactive prompts, and `docker compose` calls; all `.env` / YAML /
JSON manipulation is delegated to `tools/lib/*.py`.

All operations are **idempotent by default** — re-running any command leaves already-set
values unchanged.

### `init`

Seeds `$PAPAIA_CONFIG_DIR` from shipped defaults. Non-destructive: existing files are kept
unless `--force` is given. Never generates secrets.

```bash
tools/papaia-ctl init [--config-dir=PATH] [--env=NAME] [--force] [-y]
```

Creates in `$PAPAIA_CONFIG_DIR`:
- `.env` files seeded from every `src/**/.env.example`
- `deployment.yaml` from `tools/deployment.template.yaml`
- `overlay/` and `overrides/` subdirectories

### `setup`

Full bootstrap: prompts for public URLs, generates secrets, derives OIDC endpoints, renders
the complete configuration, and writes `deployment.yaml`. Turns a fresh checkout into a
runnable stack.

```bash
tools/papaia-ctl setup [OPTIONS]
```

| Flag | Default | Purpose |
|---|---|---|
| `--config-dir=PATH` | `../papaia-config` | Config directory location |
| `--env=NAME` | `papaia` | Sets `COMPOSE_PROJECT_NAME` / `DOCKER_NETWORK` to `papaia-<NAME>` / `papaia-<NAME>-net` |
| `--host-ip=IP` | _(prompted)_ | Bind address for published ports |
| `--app-host=URL` | _(prompted)_ | Public papAIa URL (scheme + host + optional port, no trailing path) |
| `--auth-host=URL` | _(derived from app-host)_ | Public Keycloak URL; only relevant with `internal_keycloak` |
| `--librechat-host=URL` | _(derived from app-host)_ | Public LibreChat URL if it differs from `--app-host` |
| `--localai-host=URL` | _(derived from app-host)_ | Public LocalAI URL if it differs from `--app-host` |
| `--enable-local-ai` | _(enabled by default)_ | Include LocalAI in the active Compose profile set |
| `--no-local-ai` | — | Exclude LocalAI from the Compose profile set |
| `--auth-provider=VALUE` | `internal_keycloak` | `internal_keycloak` or `external_oidc` |
| `--oidc-issuer=URL` | _(required for external_oidc)_ | External OIDC issuer URL |
| `--external-reverse-proxy` | _(auto from URL scheme)_ | Suppress bundled Nginx PM (TLS terminated upstream) |
| `--no-external-reverse-proxy` | — | Force bundled Nginx PM regardless of URL scheme |
| `--allow-direct-port-access` | — | Skip Nginx PM entirely; services expose ports directly (expert) |
| `--force` | — | Regenerate all secrets unconditionally |
| `-y` / `--non-interactive` | — | Skip all prompts; supply required values as flags |

**What `setup` does automatically:**

**Secret generation** — fills every `GENERATE_*` placeholder with a fresh secret. Secrets
are sticky: re-running never rotates an already-set value unless `--force` is given.
- Most secrets: 24-byte hex
- `*_COOKIE_SECRET`: 32 bytes base64
- LibreChat AES keys (`CREDS_KEY`, `CREDS_IV`): exact-length hex

**Secret aliasing** — 9 canonical secrets (e.g. `KC_LIBRECHAT_CLIENT_SECRET`) are fanned
out automatically to every service that needs the same value. No manual copy-paste between
`.env` files.

**Hostname derivation** — OIDC issuer, split endpoints (auth / token / JWKS), and
per-service public URLs are derived from `--app-host` / `--auth-host`.

**Reverse proxy detection** — an HTTPS `--app-host` implies an external TLS terminator;
bundled Nginx PM is omitted by default and re-enabled with `--no-external-reverse-proxy`.

**Keycloak TLS** — generates a local self-signed CA and Keycloak server certificate for
HTTPS-mode deployments.

**Realm secret baking** — writes secrets directly into `papaia-realm.json` before the
realm file reaches Keycloak (no reliance on Keycloak's `${env.*}` substitution, which is
unreliable at import time).

**3-layer config render** — merges repo base + active extension fragments + customer overlay
into `$PAPAIA_CONFIG_DIR` (see [Configuration engine](#configuration-engine) below).

**`deployment.yaml`** — writes resolved profiles, platform version, and the active
extension list.

Non-interactive example for CI or unattended setup:

```bash
tools/papaia-ctl setup \
  --non-interactive \
  --app-host=https://papaia.example.com \
  --auth-host=https://auth.example.com
```

### `up`

Re-renders the current configuration and starts the stack.

```bash
tools/papaia-ctl up [PROFILE...] [--config-dir=PATH]
```

Config rendering happens on every `up` call — picks up `git pull` changes, new extension
fragments, and `overlay/` edits automatically. Pass profile names to start a subset:

```bash
tools/papaia-ctl up keycloak librechat litellm
```

### `down`

Stops the stack.

```bash
tools/papaia-ctl down [PROFILE...] [--volumes] [--config-dir=PATH]
```

`--volumes` also removes Docker volumes (destructive).

### `apps render`

Re-renders the configuration without starting or restarting containers. Useful after:
- `git pull` to pick up new config templates before the next `up`
- Editing `$PAPAIA_CONFIG_DIR/overlay/` to apply a custom override
- Adding or removing an extension in `deployment.yaml`

```bash
tools/papaia-ctl apps render [--config-dir=PATH]
```

### Configuration engine

The Python library in `tools/lib/` handles all file manipulation. It reads only from `src/`
and writes only to `$PAPAIA_CONFIG_DIR` (and the gitignored `src/**/.env` files).

**3-layer config merge** (`render_core.py`):

```
repo base (src/<target>)
  + active extension fragments (extensions/<name>/integration/<target>/)
  + customer overlay ($PAPAIA_CONFIG_DIR/overlay/<target>/)
    → $PAPAIA_CONFIG_DIR/<target>
```

Structured files (YAML / JSON) are deep-merged. Plain-text files use the highest non-empty
layer wholesale. The merge is idempotent — byte-identical output for unchanged inputs.

Render targets: `ai/librechat/librechat.yaml` · `ai/litellm/config.yaml` +
`prometheus.yml` · `ai/localai/models.txt` + `models/` · `services/searxng/settings.yml` ·
`services/homepage/config/` · `infra/keycloak/keycloak.conf`.

**Extension networking** (`gen_override.py`):

For each active extension in `deployment.yaml`, generates
`$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml` — attaches Core
containers to the extension's isolated bridge network without modifying any tracked file in
the repo. With an empty `extensions` list (the default for a fresh install), no override
files are generated.

---

## Quick start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ — `papaia-ctl` generates secrets and renders configs itself;
  `openssl` is only needed when Keycloak TLS is enabled
- At least 8 GB RAM recommended
- Linux, macOS, or WSL2

### Single-host setup

**1. Clone the repository**

```bash
git clone https://github.com/Fidonis/papaia.git
cd papaia
```

**2. Run setup**

```bash
tools/papaia-ctl setup
```

Run with no flags, `setup` prompts for the two values it cannot derive on its own — the
public URL of the server (`PAPAIA_HOST`) and the public Keycloak URL (`AUTH_HOST`) —
pre-filled with sensible defaults. Everything else is generated or derived automatically.
See [papaia-ctl reference → setup](#setup) for the full flag list.

For unattended / CI use:

```bash
tools/papaia-ctl setup --non-interactive \
  --app-host=https://papaia.example.com \
  --auth-host=https://auth.papaia.example.com
```

**3. Start the stack**

```bash
tools/papaia-ctl up
```

Re-renders the configuration and runs `docker compose up -d`. Keycloak imports the `papaia`
realm automatically on first start. Pass profile names to start a subset:

```bash
tools/papaia-ctl up keycloak librechat litellm
```

### Stopping

```bash
tools/papaia-ctl down              # remove containers and network, keep volumes
tools/papaia-ctl down --volumes    # also wipe volumes (destructive)
```

---

## Multi-environment deployments (dev / stage / demo on one host)

Multiple papAIa stacks can run side-by-side on a single host without forking the repo.
Each environment gets its own:

- `COMPOSE_PROJECT_NAME` (e.g. `papaia-dev`) — namespaces containers and volumes.
- `DOCKER_NETWORK` (e.g. `papaia-dev-net`) — isolated bridge network per stack.
- `HOST_IP` — bind address for published ports. Combine with IP aliases on the host's
  primary interface so two stacks with identical port numbers can coexist
  (`papaia-dev` → `.102`, `papaia-stage` → `.103`, `papaia-demo` → `.101`).
- `PAPAIA_HOST` — public URL used in OIDC redirects and service public URLs.
- HTTPS / `OAUTH2_PROXY_COOKIE_SECURE` — must match the scheme of `PAPAIA_HOST`.
  An HTTPS `PAPAIA_HOST` requires `OAUTH2_PROXY_COOKIE_SECURE=true` for every
  oauth2-proxy sidecar; plain HTTP requires `false`. Browsers ignore Secure cookies over
  plain HTTP, so a mismatch silently breaks login.

`tools/papaia-ctl setup --env=<name> --host-ip=<ip>` sets all three in one step:

```bash
tools/papaia-ctl setup --env=dev   --host-ip=192.168.1.102 --app-host=http://192.168.1.102
tools/papaia-ctl setup --env=stage --host-ip=192.168.1.103 --app-host=http://192.168.1.103
```

Each `--env` value should also get its own `--config-dir` so concurrent environments
don't share generated state:

```bash
tools/papaia-ctl setup --env=dev --config-dir=/srv/papaia-dev/config ...
```

---

## Reverse proxy setup

Two services need a TLS-terminating reverse proxy for OIDC login to work reliably:

- **Keycloak** (`AUTH_HOST`) — tokens are issued under this URL and the browser POSTs
  the OIDC callback cross-origin. The bundled `KC_PROXY_HEADERS=xforwarded` default takes
  care of the `X-Forwarded-*` trust behind a TLS-terminating edge proxy.
- **LibreChat** — its container speaks plain HTTP on port 3080. Without HTTPS in front,
  Keycloak's cross-origin POST + LibreChat's cookie / SameSite defaults break the OIDC
  callback in subtle ways.

Each public URL must point at the corresponding `HOST_IP:port` mapping:

```
${AUTH_HOST}       →  HOST_IP : KEYCLOAK_EXT_PORT     (default 8110)
${LIBRECHAT_HOST}  →  HOST_IP : LIBRECHAT_EXT_PORT    (default 8000)
```

#### Caddyfile example

```caddy
auth.papaia-dev.example.com {
    reverse_proxy 192.168.10.102:8110
}

chat.papaia-dev.example.com {
    reverse_proxy 192.168.10.102:8000
}
```

For Traefik / nginx the equivalent rules are a host header match plus `reverse_proxy` /
`proxy_pass` to `HOST_IP:port`.

If the host already runs an edge proxy on ports 80/443, pass `--external-reverse-proxy`
to `setup` so the bundled Nginx Proxy Manager is excluded and there is no port conflict.

---

## Externalised service configuration

papAIa keeps operator-editable service configuration **outside** the repo so that local
edits do not collide with `git pull` / fast-forward upgrades. The variable that drives
this is `PAPAIA_CONFIG_DIR` in `src/.env`.

```env
PAPAIA_CONFIG_DIR=/srv/papaia/config
```

`PAPAIA_CONFIG_DIR` must be an **absolute path** — Docker Compose resolves relative paths
in `include:`d files against each file's own directory.

The directory layout inside `${PAPAIA_CONFIG_DIR}` mirrors `src/` exactly:

```
${PAPAIA_CONFIG_DIR}/
├── ai/
│   ├── librechat/librechat.yaml
│   ├── librechat/patches/{entrypoint.sh, mcp-user-headers.js, openidStrategy.js}
│   ├── litellm/{config.yaml, prometheus.yml}
│   ├── localai/models.txt
│   └── localai/models/{nomic-embed-text.yaml, qwen2.5-1.5b-instruct.yaml}
├── infra/
│   └── keycloak/
│       ├── keycloak.conf
│       └── realm-import/papaia-realm.json[.template]
├── services/
│   ├── homepage/config/{bookmarks,custom.css,custom.js,docker,kubernetes,
│   │                    proxmox,services,settings,widgets}.{yaml,css,js}
│   └── searxng/settings.yml
├── overlay/          ← customer-specific config overrides (highest merge layer)
└── overrides/        ← auto-generated extension network override files
```

`tools/papaia-ctl setup` (and `apps render` on its own) populates and updates this directory
through the 3-layer merge engine. Editing a file inside `overlay/` and running
`papaia-ctl apps render` (or `papaia-ctl up`) applies the change on the next container
start.

> `src/sync-config.sh` is a deprecated predecessor of `papaia-ctl apps render`. It remains
> in the repo as a low-level fallback for scripting scenarios but should not be used for
> normal operations.

### `deployment.yaml`

`papaia-ctl init` writes `deployment.yaml` into `$PAPAIA_CONFIG_DIR` from
`tools/deployment.template.yaml`. `setup` refreshes it on every run. This file is the
manifest for the current installation:

```yaml
customer: papaia
platform_version: 1.0.0
hosting: self-hosted

core:
  profiles:
    - keycloak
    - oauth2-proxy
    - nginx
    - librechat
    - litellm
  inference: local-first

extensions: []
```

`extensions` lists active extension repos. Each entry activates the corresponding
extension's integration fragments in the 3-layer render and generates the network attachment
override. With the default empty list, zero override files are produced.

### Upgrade flow

```bash
git pull                     # pull new repo version
tools/papaia-ctl up          # re-render (picks up template changes) + restart
```

Customer overrides under `${PAPAIA_CONFIG_DIR}/overlay/` survive the upgrade untouched.
Any new files shipped by the upgrade land in the config directory next to existing ones.

### Backup

```bash
src/backup-papaia.sh         # gzipped archives of all named volumes + PAPAIA_CONFIG_DIR
src/restore-papaia.sh <vol>  # restore one volume from a backup archive
```

The backup script keeps the last 14 days locally.

---

## Environment setup details

`tools/papaia-ctl setup` handles all of the below automatically. The following is only
relevant when debugging a generated value or running the stack manually.

Two things need extra care when configuring `.env` files by hand:

1. **`GENERATE_…` placeholders** — every value still set to a `GENERATE_…` string must be
   replaced with a real secret (`openssl rand -hex 24`, or `openssl rand -base64 32` for
   the 32-byte `*_COOKIE_SECRET` values).
2. **Matching Keycloak client secrets** — each `KC_<service>_CLIENT_SECRET` in
   `src/infra/keycloak/.env` must hold the **same value** as the matching client secret in
   the consuming service's `.env` (`OPENID_CLIENT_SECRET` for LibreChat,
   `GENERIC_CLIENT_SECRET` for LiteLLM, `OAUTH2_PROXY_CLIENT_SECRET` in `src/.env`).

Once the stack is up, the default endpoints are:

- Keycloak admin: `http://host.docker.internal:8110` — `admin` / `KC_ADMIN_PASSWORD`
- Realm login (via LibreChat): `admin` / `admin` in realm `papaia` (test user — change
  before exposing to any network beyond localhost)
- LibreChat: `http://host.docker.internal:8000`
- Homepage: `http://host.docker.internal:8300`

---

## OIDC & SSO — how the pieces fit together

papAIa standardises on **OpenID Connect** for all human-facing authentication.

### 1. Native OIDC clients (LibreChat, Paperless, LiteLLM)

- A Keycloak client per service is created from `papaia-realm.json`, imported on
  Keycloak's first start.
- Each client secret (`KC_<service>_CLIENT_SECRET`) must hold the same value in
  `infra/keycloak/.env` and in the consuming service's `.env`. `papaia-ctl` keeps them
  in sync automatically via the alias table.
- `OPENID_ISSUER` / `GENERIC_AUTHORIZATION_ENDPOINT` must point at the **public** Keycloak
  URL derived from `PAPAIA_HOST`, so the `iss` claim matches what the browser sees at login.
- PKCE (`OPENID_USE_PKCE=true`) is required where the realm enforces it (mandatory for
  the LibreChat client).

### 2. oauth2-proxy forward auth (n8n, Homepage, custom services)

Services without native OIDC sit behind oauth2-proxy. Nginx PM checks `/oauth2/auth`
before letting requests through; on a 401, the user is bounced to Keycloak via oauth2-proxy.

oauth2-proxy runs in **`--skip-oidc-discovery` mode** with endpoints split:

| Variable | Purpose | Reachable from |
|---|---|---|
| `OIDC_ISSUER_KC_AUTH` | Browser redirect to login | Browser |
| `OIDC_ISSUER_KC_TOKEN` | Server-side code → token exchange | Containers |
| `OIDC_ISSUER_KC_CERTS` | JWKS for signature verification | Containers |

### Realm contents (out of the box)

| Item | Value |
|---|---|
| Realm | `papaia` |
| Clients | `librechat`, `litellm`, `oauth2-proxy`, `localai` |
| Realm roles | `admin`, `user`, `viewer`, `localai-access`, `finance` |
| Default test users | `admin/admin` (admin, user, localai-access) · `testuser/testuser` (user, finance) |

> The default test users exist purely for local development. Disable or delete them
> before exposing the stack to anything beyond `localhost`.

### Configuring an External Keycloak

When your organisation already runs a Keycloak instance, papaia can use it instead of the
bundled one. The bundled Keycloak is then excluded from the stack; its postgres and init
containers do not start.

**Step 1 — Run setup with external OIDC**

```bash
tools/papaia-ctl setup \
  --auth-provider=external_oidc \
  --oidc-issuer=https://keycloak.example.com/realms/your-realm
```

`setup` derives all OIDC endpoints from the issuer URL and writes `GENERATE_*` placeholders
for every client secret you must supply manually.

**Step 2 — Create OIDC clients in the external Keycloak**

Create a confidential OIDC client for each service in the realm your `--oidc-issuer` points at:

| Client ID | PKCE | Redirect URI | Secret env (papaia) |
|---|---|---|---|
| `librechat` | required | `{LIBRECHAT_HOST}/oauth/openid/callback` | `OPENID_CLIENT_SECRET` in `src/ai/librechat/.env` |
| `litellm` | — | `*` | `GENERIC_CLIENT_SECRET` in `src/ai/litellm/.env` |
| `oauth2-proxy` | — | `*` | `OAUTH2_PROXY_CLIENT_SECRET` in `src/infra/oauth2-proxy/.env` |
| `localai` | — | `{LOCALAI_PUBLIC_URL}/api/auth/oidc/callback` | `LOCALAI_OIDC_CLIENT_SECRET` in `src/ai/localai/.env` |

Each client needs a **realm-roles protocol mapper** that places the user's realm roles in
the token under claim name `roles` (multivalued, String, included in ID token, Access token,
and userinfo).

**Step 3 — Set secrets in papaia**

After creating each client, copy its secret from Keycloak (**Clients → `<id>` → Credentials**)
into the matching papaia env file (see the table above). Then restart the affected services:

```bash
docker compose restart librechat localai litellm oauth2-proxy
```

**Step 4 — LocalAI role restriction (optional)**

To limit LocalAI SSO access to specific users, create the realm role `localai-access` and
configure a custom browser flow for the `localai` client (CONDITIONAL sub-flow with a
Condition - User Role authenticator set to negate `localai-access`, followed by Deny Access).
Assign the role to users who should be allowed in. See
[`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) for the step-by-step flow
configuration. The bundled realm template ships this flow pre-configured and auto-imports it
on first start.

### Switching to an external IdP (Entra ID, Authentik, Okta …)

```bash
tools/papaia-ctl setup --auth-provider=external_oidc --oidc-issuer=https://idp.example.com/realms/your-realm
```

Or manually in `src/.env`:

```env
AUTH_PROVIDER=external_oidc
OIDC_ISSUER=https://idp.example.com/realms/your-realm
OIDC_ISSUER_KC_AUTH=https://idp.example.com/realms/your-realm/protocol/openid-connect/auth
OIDC_ISSUER_KC_TOKEN=https://idp.example.com/realms/your-realm/protocol/openid-connect/token
OIDC_ISSUER_KC_CERTS=https://idp.example.com/realms/your-realm/protocol/openid-connect/certs
```

See [`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) for provider-specific
notes.

---

## Service highlights

### Core

#### LibreChat
- Multi-provider chat UI — hosted and local models via LiteLLM.
- Native Keycloak OIDC login with PKCE.
- Built-in RAG with Meilisearch + pgvector for uploaded files.
- Operator provisioning: agents and prompts can be loaded from bind-mount directories and
  are picked up on container restart without rebuilding the image.

#### LiteLLM
- Unified API gateway across providers.
- Generic OIDC SSO for the admin UI; master key for programmatic clients.
- Prometheus metrics on `:8230`.

#### LocalAI
- Local model inference with a chat-completions API (CPU or NVIDIA GPU image); enabled by
  default via the `localai` Compose profile.
- Native OIDC SSO via the `localai` Keycloak client — no oauth2-proxy sidecar required.
  `papaia-ctl setup` generates and syncs `LOCALAI_OIDC_CLIENT_SECRET` automatically.
- Role-based access gate: only users holding the `localai-access` realm role can sign in via
  SSO. The default `admin` user has this role; `testuser` does not. Grant access in Keycloak
  Admin Console → Realm roles → `localai-access` → Users.
- Models to download are listed in `ai/localai/models.txt` (one URL per line); edit the
  file (or its `overlay/` copy) to add or remove models.

### Optional modules

#### qdrant-rag
- OIDC + RBAC MCP server that exposes Qdrant vector search to LibreChat.
- Validates the logged-in user's Keycloak Bearer token and maps Keycloak roles to
  per-collection Qdrant access — each user can only search collections they are
  authorised for.
- LibreChat forwards the user's token automatically via the `QdrantRAG` MCP server entry
  in `librechat.yaml`.
- Ships its own Qdrant instance; optional Jina Reranker for semantic re-scoring.
- Enable via the `qdrant-rag` profile; see `src/ai/qdrant-rag/.env.example`.

#### MCP Paperless
- OIDC-secured MCP server that bridges LibreChat to Paperless-ngx.
- Validates the caller's Keycloak Bearer token (forwarded automatically via the
  `Paperless` entry in `librechat.yaml`), then calls Paperless on the user's behalf
  via a remote-user header — no admin credentials stored.
- Paperless enforces its own per-user permissions, so each user only ever sees their
  own documents.
- Enable via the `paperless` profile; see `src/ai/mcp-paperless/.env.example`.

#### MCP Office Documents
- MCP server that generates Word, Excel, PowerPoint, email drafts, and XML files from a
  LibreChat prompt and returns a clickable, time-limited download link.
- Generated files are uploaded to the bundled MinIO object store; the tool response
  carries a pre-signed URL that resolves from the user's browser.
- Optional profile `mcp-office-docs`; see `src/ai/mcp-office-docs/.env.example`.

#### n8n
- Self-hosted workflow automation behind oauth2-proxy.
- Postgres-backed state; public URL derived from `PAPAIA_HOST` so the oauth2-proxy
  redirect callback stays correct.

#### Paperless-ngx
- Document management with native Keycloak OIDC.
- Pre-wired with Tika + Gotenberg for OCR.
- Accepts a remote-user header from MCP Paperless (`PAPERLESS_ENABLE_HTTP_REMOTE_USER`)
  for per-user document access without sharing admin credentials.

#### SearXNG
- Privacy-respecting metasearch.
- Bound to LibreChat's web-search integration via
  `SEARXNG_INSTANCE_URL=http://searxng:8080`.

#### MinIO
- Self-hosted, S3-compatible object storage backing the Office Documents MCP server.
- A cleanup sidecar prunes objects past their retention window (`CLEANUP_RETENTION_HOURS`).

---

## Operations

### Selective module enable / disable

`src/docker-compose.yml` aggregates services via `include:`, and each service declares
a Compose `profile`. Enable a module by adding its profile to `COMPOSE_PROFILES` in
`src/.env`; fully optional modules also need their `include:` line uncommented. Restart
with `tools/papaia-ctl up` afterwards.

### Updating images

Image tags are pinned in `src/.env.example`. To upgrade a service, bump the corresponding
`*_IMAGE` variable in `src/.env` and restart with `docker compose up -d <service>`.

### Resetting Keycloak

The realm import only runs on the **first** Keycloak start. To re-import (after editing
the realm template, for example):

```bash
docker compose down keycloak keycloak-postgresql
docker volume rm papaia_keycloak-postgresql
docker compose up -d
```

This also wipes any users created through the admin UI — back them up first if needed.

---

## Troubleshooting

### "redirect_uri does not match" from Keycloak after login

Cause: `PAPAIA_HOST` and the Keycloak client's registered redirect URIs disagree.

- Check `src/.env` — `PAPAIA_HOST` must be the URL you actually type into the browser
  (host **and** port, scheme included).
- After changing `PAPAIA_HOST`, run `tools/papaia-ctl setup` again to re-derive all
  dependent URLs and re-render the configuration.

### LibreChat OIDC login: "invalid_token" or signature errors

Cause: the `iss` claim in the access token doesn't match what LibreChat expects.

- The token's `iss` always equals `KC_HOSTNAME` (= `PAPAIA_HOST:8110`).
- Make sure `OPENID_ISSUER` in `ai/librechat/.env` is the same URL.
- On Linux, ensure `host.docker.internal` resolves to `127.0.0.1` in `/etc/hosts`.

### Cookies don't stick / login loops behind oauth2-proxy

- Verify that `OAUTH2_PROXY_COOKIE_SECRET` is exactly **32 base64 bytes**
  (`openssl rand -base64 32`); don't shorten it.
- Use the same scheme + host + port in Nginx PM, oauth2-proxy `--redirect-url`, and the
  Keycloak client's "Valid redirect URIs". A mismatch on **any** of these breaks the loop.
- When testing, clear cookies for the affected host between attempts — stale
  `_oauth2_proxy*` cookies survive container restarts.

### LibreChat Keycloak login fails over HTTP

Browsers refuse to send `Secure` cookies over plain HTTP. Either run the stack behind
HTTPS, or stay on `http://host.docker.internal` for local development (the realm is
preconfigured to allow it).

### "host.docker.internal: cannot resolve" on Linux

```bash
echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
```

Or set `PAPAIA_HOST` to the LAN IP of the host instead.

### Out-of-memory when running LocalAI

Run a smaller model (`Qwen2.5 1.5B Q4`), or disable LocalAI (comment its line in
`src/docker-compose.yml`) and route LibreChat to a hosted provider via LiteLLM.

### General debugging

```bash
docker compose ps                 # what's running
docker compose logs -f <service>  # follow one service
docker compose config             # render the merged compose file
```

---

## Repository layout

```
[workspace root]/
├── papaia/                    ← this repo (read-only at deploy time)
│   ├── tools/
│   │   ├── papaia-ctl          # Bash dispatcher (init · setup · up · down · apps render)
│   │   ├── deployment.template.yaml  # deployment.yaml template seeded by init
│   │   ├── pyproject.toml      # ruff + pytest config for tools/lib
│   │   ├── lib/                # Python: bootstrap.py · render_core.py · gen_override.py
│   │   │                       #          common.py · cli.py
│   │   └── tests/              # pytest suite (96 tests)
│   ├── src/
│   │   ├── docker-compose.yml  # root compose — shared network + include list only
│   │   ├── .env.example        # all stack-wide variables (source of truth)
│   │   ├── backup-papaia.sh    # archive Docker volumes + PAPAIA_CONFIG_DIR
│   │   ├── restore-papaia.sh   # restore a single named volume from archive
│   │   ├── infra/              # keycloak · nginx · oauth2-proxy · technitium
│   │   ├── ai/                 # librechat · litellm · localai · qdrant-rag ·
│   │   │                       # mcp-paperless · mcp-office-docs · n8n · jinaai
│   │   └── services/           # paperless · homepage · searxng · firecrawl · minio
│   └── docs/
│       ├── papaia-architecture-1.0.0.md  # full architecture specification
│       ├── configuration.md
│       ├── deployment.md
│       ├── troubleshooting.md
│       └── adr/                # Architecture Decision Records
│
├── extensions/                ← extension repos cloned alongside (opt-in)
│   └── papaia-ext-<name>/     # papaia-app.yaml + compose + integration fragments
│
└── papaia-config/             ← PAPAIA_CONFIG_DIR (generated, never committed)
    ├── deployment.yaml         # installation manifest
    ├── overlay/                # customer config overrides (highest merge layer)
    └── overrides/              # auto-generated extension network overrides
```

---

## Further reading

- [`src/README.md`](src/README.md) — Compose-level orchestration, service toggles,
  common commands.
- [`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) — Realm contents,
  client list, external-IdP migration, secret rotation.
- [`src/ai/README.md`](src/ai/README.md) — Per-AI-service summary.
- [`docs/papaia-architecture-1.0.0.md`](docs/papaia-architecture-1.0.0.md) — Full
  architecture specification: 3-tier model, Extension Contract, integration seams,
  deployment manifest schema.
- [`docs/configuration.md`](docs/configuration.md) — Environment variable reference.
- [`docs/deployment.md`](docs/deployment.md) — Deployment guide.
- [`CHANGELOG.md`](CHANGELOG.md) — Release history.
