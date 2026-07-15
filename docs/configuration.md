# Configuration

> **Status:** Draft — to be expanded.

## Configuration files

papAIa is configured via environment variables and per-service `.env` files.

- Root `.env` — global settings shared across services
- Per service: `src/<area>/<service>/.env` — service-specific overrides
- Each service ships an `.env.example` that documents available variables

## Environment variables

`src/.env.example` (plus each service's own `.env.example`) is the source of
truth for every available variable. `tools/papaia-ctl setup` derives or
generates most of them automatically; only a few inputs are genuinely
operator-supplied:

| Origin | Examples |
|---|---|
| Operator-supplied (flag or interactive prompt) | `PAPAIA_HOST`, `AUTH_HOST`, `--env`, `--host-ip` |
| Derived from the above | `OIDC_ISSUER*`, `OPENID_ISSUER`, `GENERIC_*_ENDPOINT`, `DOMAIN_SERVER`/`DOMAIN_CLIENT`, `*_PUBLIC_URL`, `HP_ALLOWED_HOSTS`, `OAUTH2_PROXY_COOKIE_SECURE`, `COMPOSE_PROJECT_NAME`, `DOCKER_NETWORK` |
| Generated (see [Secrets handling](#secrets-handling)) | every `*_SECRET`/`*_PASSWORD`/`*_KEY`/`*_TOKEN` variable |
| Static defaults | `*_EXT_PORT` variables, `TRUST_PROXY` |

See `tools/lib/resolve.py` for the exact derivation logic, or run
`tools/papaia-ctl setup --help` for the flag reference.

## Secrets handling

`tools/papaia-ctl setup` generates secrets with a sticky-by-default
algorithm (also documented in `tools/lib/secrets.py`'s module docstring):

1. **Which keys are secrets** — any `.env` key matching
   `SECRET|PASSWORD|KEY|TOKEN` (case-insensitive).
2. **Stickiness** — a value is only (re)generated if it's still a shipped
   `GENERATE_…` placeholder or empty. An already-customized value is never
   touched. Pass `--force` to regenerate everything unconditionally (this
   invalidates active sessions and any externally-shared API keys).
3. **Generation method** — 24 raw bytes, hex-encoded, for most secrets
   (matching the byte-for-byte shape of `openssl rand -hex 24`); exactly 32
   raw bytes, base64-encoded, for `*_COOKIE_SECRET` keys (oauth2-proxy's
   documented requirement); exact 32/16-byte hex for LibreChat's
   `CREDS_KEY`/`CREDS_IV` (its AES-256-CBC key/IV pair, which must be
   precisely those lengths or LibreChat refuses to start).
4. **Cross-file aliases** — a handful of secrets must hold the *same* value
   in more than one service's `.env` (e.g. a Keycloak client secret and the
   matching `OPENID_CLIENT_SECRET`/`GENERIC_CLIENT_SECRET` in the consuming
   service). `secrets.py`'s `SECRET_ALIASES` table generates the
   canonical value once and fans it out to every alias, overwriting a
   drifted alias copy even if it isn't a placeholder — a stale copy here
   silently breaks OIDC token exchanges.

Secrets live only in gitignored `.env` files — the per-service `src/**/.env`
files `docker compose` reads from directly, and a canonical copy under
`$PAPAIA_CONFIG_DIR/.env` (and per-service subpaths) that `tools/papaia-ctl`
itself reads back from on every re-run. Neither location is ever committed.
The generated Keycloak realm import
(`$PAPAIA_CONFIG_DIR/infra/keycloak/realm-import/papaia-realm.json`) has
every `${env.…}` placeholder substituted with its real secret value before
Keycloak ever imports it — this supersedes relying on Keycloak's own
`${env.…}` substitution at import time, which was found unreliable.
