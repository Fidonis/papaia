# papAIa — Compose Orchestration

This directory holds the runtime side of the papAIa stack: the root
`docker-compose.yml`, the global `.env` template, the setup / backup /
restore scripts, and one subdirectory per service category.

For an architecture overview and feature highlights of the **0.6.0**
release, see the [top-level README](../README.md).

---

## Layout

```
src/
├── docker-compose.yml      # root compose — includes per-service compose files
├── .env.example            # all stack-wide variables, grouped per service
├── setup-papaia.sh         # idempotent setup / secret generation
├── backup-papaia.sh        # gzipped backups of all named Docker volumes
├── restore-papaia.sh       # restore one volume from a backup archive
├── infra/                  # core platform
│   ├── keycloak/           # OIDC issuer (realm: papaia, pre-imported)
│   ├── nginx/              # Nginx Proxy Manager
│   ├── oauth2-proxy/       # forward-auth gateway for non-OIDC services
│   └── technitium/         # optional DNS server (commented out by default)
├── services/               # application services
│   ├── firecrawl/          # web crawler (commented out by default)
│   ├── home-assistant/     # home automation (host network, commented out)
│   ├── homepage/           # service dashboard
│   ├── paperless/          # document management (OIDC)
│   └── searxng/            # privacy-respecting metasearch
└── ai/                     # AI / ML services
    ├── doc-rag/            # WebDAV → Qdrant RAG pipeline + MCP API
    ├── jinaai/             # Jina reranker (commented out by default)
    ├── librechat/          # multi-provider chat UI (OIDC)
    ├── litellm/            # LLM proxy + Postgres + Prometheus (OIDC)
    ├── localai/            # local OpenAI-compatible inference
    ├── mcp-paperless/      # per-user Paperless proxy for LibreChat
    └── n8n/                # workflow automation (oauth2-proxy)
```

The root `docker-compose.yml` is intentionally tiny — it only declares the
shared `papaia-net` bridge and an `include:` list. All per-service
configuration lives in the corresponding subdirectory.

---

## First-time setup

```bash
cd src/
./setup-papaia.sh
```

The script is idempotent and safe to re-run:

- Existing `.env` files are preserved unless `--force` is used.
- Secrets are only generated where the value is still `GENERATE_…`.
- `UID` / `GID` in `src/.env` are always overwritten with the current
  host user's IDs (so bind-mounted files end up with the right owner on
  Linux; ignored on Docker Desktop).
- Keycloak client secrets are written into `infra/keycloak/.env` and then
  propagated into each consuming service's `.env`. The
  `realm-import/papaia-realm.json` file is regenerated from the template
  with all `${env.VAR}` placeholders substituted.
- `PAPAIA_HOST` is auto-detected on Linux (primary IP) and falls back to
  `http://host.docker.internal` elsewhere. All OIDC redirect URLs and
  service public URLs are derived from it.

After the first run, only the optional modules need an interactive answer
(LocalAI, doc-rag, n8n, SearXNG, Homepage, Paperless-ngx). Modules you
opt into are uncommented in `docker-compose.yml`; modules you skip stay
commented out and are not started.

> **Re-running:** simply call `./setup-papaia.sh` again. To wipe everything
> and start over with fresh secrets, use `./setup-papaia.sh --force` —
> note that this **replaces** all generated `.env` values and any manual
> edits made to them.

---

## Starting & stopping

```bash
# Start everything that's currently uncommented in docker-compose.yml
docker compose up -d

# Stop containers, keep volumes
docker compose stop

# Stop and remove containers + the papaia-net network
docker compose down

# Same, plus delete all volumes (DESTRUCTIVE — wipes Keycloak users,
# Paperless documents, doc-rag vectors, Mongo, etc.)
docker compose down -v
```

`docker compose ps` shows the running services and their port mappings.

### Logs

```bash
docker compose logs -f <service>
docker compose logs --since 10m
```

### Validating the merged config

After editing `docker-compose.yml` or any included file, render the
merged result before starting:

```bash
docker compose config | less
```

This expands the `include:` list and resolves all `${VARS}` from `.env`.

---

## Toggling modules

Optional modules are listed (commented out) in `docker-compose.yml`:

```yaml
include:
  # Application Services
  # - path: ./services/firecrawl/docker-compose.yml
  # - path: ./services/home-assistant/docker-compose.yml
  - path: ./services/homepage/docker-compose.yml
  ...
  # AI Services
  # - path: ./ai/doc-rag/docker-compose.yml
  - path: ./ai/librechat/docker-compose.yml
  ...
```

To enable or disable a module:

1. Comment / uncomment its `- path:` line.
2. Make sure its `.env` file exists (run `./setup-papaia.sh` if needed).
3. `docker compose up -d` to start, or `docker compose down <service>`
   to stop a no-longer-included one.

The setup script automates this for the modules it asks about
(LocalAI, doc-rag, n8n, SearXNG, Homepage, Paperless-ngx + MCP Paperless).

---

## Configuration model

The stack uses a **single shared `.env`** at `src/.env` that defines:

- Image tags for every service (`*_IMAGE`).
- External port numbers (`*_EXT_PORT`) — change one number to relocate.
- The OIDC topology (`PAPAIA_HOST`, `OIDC_ISSUER*`, `AUTH_PROVIDER`).
- Cross-service secrets that must stay in sync (e.g. the oauth2-proxy
  client secret, propagated by setup).

In addition, each service has its **own** `.env` file (e.g.
`ai/librechat/.env`) for service-specific settings. The setup script
ensures the shared values stay in sync between `src/.env` and the
per-service files.

Never edit `realm-import/papaia-realm.json` by hand — it is regenerated
from `papaia-realm.json.template` whenever the setup script runs.

### Selected variables

| Variable                       | Purpose                                                  |
|--------------------------------|----------------------------------------------------------|
| `PAPAIA_HOST`                  | Public URL the browser uses (drives all OIDC redirects)  |
| `AUTH_PROVIDER`                | `internal_keycloak` (default) or `external_oidc`         |
| `OIDC_ISSUER_KC_AUTH`          | Browser-facing Keycloak auth endpoint                    |
| `OIDC_ISSUER_KC_TOKEN/CERTS`   | Server-side token + JWKS endpoints (internal Docker DNS) |
| `OAUTH2_PROXY_COOKIE_SECRET`   | 32-byte random — DO NOT shorten                          |
| `COMPOSE_PROFILES`             | All known profiles, kept enabled by default              |
| `DOCKER_NETWORK`               | Name of the shared bridge network                        |
| `UID` / `GID`                  | Host user IDs propagated by setup (Linux only)           |

A full list with comments lives in [`.env.example`](.env.example).

---

## Backups

```bash
./backup-papaia.sh          # archive every named volume to ./backups/
./restore-papaia.sh <vol>   # restore a single volume from its archive
```

The current backup script keeps the last 14 days locally. Off-site sync
(OneDrive, S3, …) is left to the host environment. A more robust backup
script with locking, integrity checks and structured logging is tracked in
[issue #34](https://github.com/marko-boehm/papaia/issues/34).

---

## Common pitfalls

- **`PAPAIA_HOST` mismatch.** Whatever URL the browser uses must equal
  `PAPAIA_HOST`, otherwise OIDC redirects break. Re-run the setup script
  after editing `PAPAIA_HOST` so dependent variables (issuer URLs, public
  URLs, `HP_ALLOWED_HOSTS`) are rewritten.
- **HTTP and `Secure` cookies.** Browsers refuse `Secure` cookies over
  plain HTTP. Local development on `http://host.docker.internal` is
  fine; remote deployments need TLS termination at NPM.
- **Missing bind-mounted config files.** The setup script restores
  `infra/keycloak/keycloak.conf` from git if it is missing. Without it,
  Docker would silently create a directory in its place and break
  Keycloak. Don't `.dockerignore` or move that file unless you also
  update the script.
- **Realm import only runs once.** To re-import the realm template (after
  changing it), delete the `keycloak-postgresql` volume — this also wipes
  any Keycloak users created via the admin UI.

For login-specific issues (cookie loops, `redirect_uri` mismatch, JWT
signature errors) see the
[Troubleshooting section in the top-level README](../README.md#troubleshooting).

---

## Security notes

- `.env` files are gitignored — secrets never enter version control.
- Every service generated by the setup script uses a unique random secret;
  no shared defaults.
- Default Keycloak test users (`admin/admin`, `testuser/testuser`) exist
  for local development only. Disable or delete them before exposing the
  stack to anything beyond `localhost`.
- The `papaia-net` bridge isolates inter-service traffic from the host's
  public interface. External access should go through Nginx Proxy Manager
  with TLS termination.
