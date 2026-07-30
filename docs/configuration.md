# Configuration

## Configuration files

papAIa is configured through environment variables spread over two levels:

- **`src/.env`** — stack-wide configuration: profiles, network, public URLs, the
  shared OIDC settings, and the external port allocation.
- **`src/<area>/<service>/.env`** — everything only one service cares about.

Each location ships an `.env.example` that is the source of truth for the variables
available there. Both are gitignored; `tools/papaia-ctl setup` generates them, and a
canonical copy lives under `$PAPAIA_CONFIG_DIR`.

The rule for deciding where a variable belongs: **the root file holds what the stack as
a whole needs** — anything read by more than one service, plus port allocation and
public base URLs, which are stack-wide concerns even when a single service consumes
them. Everything else lives with its service.

## How a variable reaches a container

This is the least obvious part of the layer, and it matters when adding a variable.
There are four independent paths:

| Path | Mechanism | Where the value is read from |
|---|---|---|
| 1 | Compose interpolation — `${VAR}` in a `docker-compose.yml` | `src/.env` **merged with** the `.env` of the directory the file is `include:`d from |
| 2 | `env_file: ./.env` — the container's process environment | only that service's `.env` |
| 3 | Application-level expansion — `${VAR}` inside `librechat.yaml` or `searxng/settings.yml` | the container's process environment, i.e. path 2 |
| 4 | Realm baking — `${env.VAR}` in the Keycloak realm template | `$PAPAIA_CONFIG_DIR/.env` + `$PAPAIA_CONFIG_DIR/infra/keycloak/.env` |

Path 1 is why a service-level variable can be interpolated at all: the root
`docker-compose.yml` pulls each service in with `include:`, and Compose merges that
directory's `.env` into the interpolation scope. A variable in service A's `.env` is
still invisible to service B — anything shared must live in the root file.

Paths 1 and 2 can collide. A variable delivered through `env_file:` must **not** also
appear in the same service's `environment:` block: `environment:` wins, and it resolves
through path 1, which may not know the variable — blanking a value that was correctly
set. `LOCALAI_OIDC_CLIENT_SECRET` is the live example; both
`src/ai/localai/docker-compose.yml` and `src/ai/localai/.env.example` carry a warning.

Every `${VAR}` a compose file interpolates must be documented in the `.env.example`
next to it, even when it has an inline `:-` default.

## Root variables

| Variable | Purpose |
|---|---|
| `PAPAIA_VERSION` | Platform version, stamped by setup — do not edit |
| `COMPOSE_PROJECT_NAME` | Compose project name; keeps parallel environments apart |
| `COMPOSE_PROFILES` | Active Compose profiles — the enabled module set |
| `DOCKER_NETWORK` | Name of the shared bridge network |
| `PAPAIA_CONFIG_DIR` | Absolute host path holding all generated state and operator-editable config |
| `PAPAIA_WORKSPACE_DIR` | Parent directory containing the papaia checkout and add-ons, stamped by setup |
| `PAPAIA_BACKUP_DIR` | Default target of `papaia-ctl backup`; derived by setup as `$PAPAIA_WORKSPACE_DIR/backup` unless `--backup-dir` was passed |
| `UID` / `GID` | Host ownership for bind-mounted files (Linux only) |
| `HOST_IP` | Bind address for published ports — the network layer |
| `PAPAIA_HOST` | Public base URL of the server — the application layer |
| `AUTH_HOST` | Public Keycloak URL; ends up in token `iss` claims |
| `AUTH_PROVIDER` | `internal_keycloak` or `external_oidc` |
| `OIDC_ISSUER` | Issuer URL used for token validation |
| `OIDC_SCOPES` | Scopes requested by the oauth2-proxy sidecars |
| `OIDC_AUTH_URL` | Browser-facing login redirect |
| `OIDC_TOKEN_URL` | Server-side token exchange (internal Docker DNS) |
| `OIDC_JWKS_URL` | Server-side JWKS fetch (internal Docker DNS) |
| `OAUTH2_PROXY_EXT_PORT` | External port of the standalone forward-auth proxy |
| `OAUTH2_PROXY_CLIENT_ID` | OIDC client ID shared by all three sidecars |
| `OAUTH2_PROXY_CLIENT_SECRET` | Matching client secret (generated) |
| `OAUTH2_PROXY_COOKIE_SECRET` | Session cookie key, 32 bytes base64 (generated) |
| `OAUTH2_PROXY_COOKIE_SECURE` | Re-derived every run from the `PAPAIA_HOST` scheme |
| `REVERSE_PROXY_PROVIDER` | `internal_nginx`, `external_proxy` or `no_proxy` |
| `*_EXT_PORT` | External port allocation — kept together to stay collision-free |
| `LOCALAI_PUBLIC_URL` | Browser-facing LocalAI URL, derived by setup |
| `HOMEPAGE_PUBLIC_URL` | Browser-facing Homepage URL, derived by setup |
| `NPM_ADMIN_HOST` | Public URL of the Nginx Proxy Manager admin UI |
| `MANAGER_EXT_PORT` | External port the manager (profile `manager`) is published on |
| `MANAGER_PUBLIC_URL` | Browser-facing papaia-manager URL, derived by setup — interpolated as `MANAGER_HOST` in `src/manager/docker-compose.yml` |

The `OIDC_*` endpoint variables are provider-independent: they apply to
`AUTH_PROVIDER=external_oidc` exactly as they do to the bundled Keycloak. Do not
confuse them with the `KC_*` variables in `src/infra/keycloak/.env`, which configure
the bundled Keycloak container itself.

## Manager variables

`src/manager/.env` — everything only the manager container reads, via
`env_file:` (path 2). This is why the role variables live here and not at
root: the compose file never interpolates them, so a root-level copy would
compile but never reach the container.

| Variable | Purpose |
|---|---|
| `MANAGER_OIDC_CLIENT_SECRET` | Keycloak client secret, synced from `KC_MANAGER_CLIENT_SECRET` during setup |
| `MANAGER_SESSION_SECRET` | Signing key for the manager's session cookie (generated) |
| `MANAGER_ADMIN_ROLE` | Realm role granting full access — add-ons, catalogs, jobs and the dashboard |
| `MANAGER_USER_ROLE` | Realm role granting dashboard-only access; admins hold it implicitly |
| `LOG_LEVEL` | Manager application log level |

## Where values come from

`tools/papaia-ctl setup` derives or generates most variables; few are genuinely
operator-supplied.

| Origin | Examples |
|---|---|
| Operator-supplied (flag or interactive prompt) | `PAPAIA_HOST`, `AUTH_HOST`, `--env`, `--host-ip`, `--backup-dir` |
| Derived from the above | `OIDC_ISSUER`, `OIDC_AUTH_URL`/`OIDC_TOKEN_URL`/`OIDC_JWKS_URL`, `OPENID_ISSUER`, `GENERIC_*_ENDPOINT`, `DOMAIN_SERVER`/`DOMAIN_CLIENT`, `*_PUBLIC_URL`, `HP_ALLOWED_HOSTS`, `OAUTH2_PROXY_COOKIE_SECURE`, `COMPOSE_PROJECT_NAME`, `DOCKER_NETWORK`, `PAPAIA_BACKUP_DIR` |
| Generated (see [Secrets handling](#secrets-handling)) | every key shipped with a `GENERATE_…` placeholder |
| Static defaults | `*_EXT_PORT` variables, `TRUST_PROXY` |

See `tools/lib/resolve.py` for the exact derivation logic, or run
`tools/papaia-ctl setup --help` for the flag reference.

## Secrets handling

`tools/papaia-ctl setup` generates secrets with a sticky-by-default algorithm (also
documented in `tools/lib/secrets.py`'s module docstring):

1. **Which keys are secrets** — those whose *shipped* `.env.example` value uses the
   `GENERATE_…` marker. The marker, rather than a name heuristic, is the source of
   truth: it leaves literals like `KC_DB_PASSWORD=keycloak` and empty third-party API
   keys untouched, and never misses an unconventionally named secret such as
   LibreChat's `CREDS_IV`.
2. **Stickiness** — a value is only (re)generated while it is still a placeholder or
   empty. A customized value is never touched. `--force` regenerates everything
   unconditionally, which invalidates active sessions and externally shared API keys.
3. **Generation method** — 24 raw bytes hex-encoded for most secrets (the shape of
   `openssl rand -hex 24`); exactly 32 raw bytes base64-encoded for `*_COOKIE_SECRET`
   (oauth2-proxy's documented requirement); exact 32/16-byte hex for LibreChat's
   `CREDS_KEY`/`CREDS_IV` AES-256-CBC pair, which must be precisely those lengths or
   LibreChat refuses to start.
4. **Cross-file aliases** — some secrets must hold the *same* value in more than one
   service's `.env` (a Keycloak client secret and the matching
   `OPENID_CLIENT_SECRET` / `GENERIC_CLIENT_SECRET` in the consuming service).
   `secrets.py`'s `SECRET_ALIASES` table generates the canonical value once and fans it
   out to every alias, overwriting a drifted copy even when it is not a placeholder — a
   stale copy here silently breaks OIDC token exchanges.

Only core clients are covered. Addon clients (`paperless`, `qdrant-rag`, …) register
their own OIDC client and generate their own secret during addon installation; the core
neither stores nor generates those values.

Secrets live only in gitignored `.env` files — the per-service `src/**/.env` files
Compose reads, and the canonical copy under `$PAPAIA_CONFIG_DIR` that `papaia-ctl` reads
back on every re-run. Neither is ever committed. The generated Keycloak realm import
(`$PAPAIA_CONFIG_DIR/infra/keycloak/realm-import/papaia-realm.json`) has every
`${env.…}` placeholder substituted with its real value before Keycloak imports it; this
supersedes Keycloak's own import-time substitution, which was found unreliable.

## Migrating an existing installation

`papaia-ctl setup` renames, relocates and drops env keys that changed shape between
releases (`resolve.migrate_env_keys`). It runs unconditionally and is a no-op once a
bundle is current, so upgrading needs no manual edit — re-run `setup` against the
existing `--config-dir` and the values carry over.

Renamed:

| Previously | Now |
|---|---|
| `OIDC_ISSUER_KC_AUTH` | `OIDC_AUTH_URL` |
| `OIDC_ISSUER_KC_TOKEN` | `OIDC_TOKEN_URL` |
| `OIDC_ISSUER_KC_CERTS` | `OIDC_JWKS_URL` |

Relocated from the root `.env` to `src/ai/librechat/.env`:
`LIBRECHAT_AGENTS_DIR`, `LIBRECHAT_PROMPTS_DIR`.

Removed — nothing read them: `TIMEZONE`, `OIDC_CLIENT_ID`, `OIDC_ROLE_CLAIM`,
`OIDC_USERNAME_CLAIM`, `OIDC_EMAIL_CLAIM`, `LITELLM_EXT_PG_PORT`,
`LITELLM_EXT_PROMETHEUS_PORT`, `JINAAI_EXT_PORT`, and the addon client secrets
`KC_PAPERLESS_CLIENT_SECRET` and `KC_QDRANT_RAG_CLIENT_SECRET`.
