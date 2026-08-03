# ═══════════════════════════════════════════════════════════════════════════
# papAIa — Keycloak · Identity & Access Management
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════

# Authentication – Keycloak & OIDC

papAIa ships with a pre-configured Keycloak instance as its default Identity Provider.
Alternatively, any OIDC-compliant provider (Entra ID, Authentik, Okta, …) can be used
without changing any application code.

---

## Architecture Overview

```
Browser / Client
      │
      ├──▶  LibreChat (8000)      ─── native OIDC ──▶  Keycloak (8110)
      │
      ├──▶  LocalAI (8080)        ─── native OIDC ──▶  Keycloak (8110)
      │
      ├──▶  papaia-manager (8120) ─── native OIDC ──▶  Keycloak (8110)
      │
      ├──▶  LiteLLM UI (8200)     ── generic OIDC ──▶  Keycloak (8110)
      │
      ├──▶  Nginx Proxy Manager   ─── forward auth ──▶  oauth2-proxy (4180)
      │         │                                              │
      │         └──▶  NPM admin UI (8100)              Keycloak (8110)
      │
      └──▶  Keycloak Admin (8110)
```

Addon services attach to the same picture: each either speaks OIDC natively against
the `papaia` realm or is routed through oauth2-proxy by an Nginx fragment.

**OIDC coverage by approach:**

| Service | Auth approach | Notes |
|---------|--------------|-------|
| LibreChat | native OIDC | openid-client strategy |
| LocalAI | native OIDC | role-restricted via custom browser flow (`localai-access` required) |
| papaia-manager | native OIDC | role-restricted via `MANAGER_ADMIN_ROLE` / `MANAGER_USER_ROLE` |
| LiteLLM UI | generic OIDC | admin UI only; API key for programmatic access |
| NPM admin UI | oauth2-proxy forward auth | sidecar in `src/infra/nginx/docker-compose.yml` |

---

## Setup

`tools/papaia-ctl setup` fills every `GENERATE_*` placeholder in the shipped
`.env.example` files, so no secret has to be created by hand:

```bash
tools/papaia-ctl setup
```

Secrets that must hold the same value in more than one file — `KC_*_CLIENT_SECRET`
and the consuming service's `OPENID_CLIENT_SECRET` / `GENERIC_CLIENT_SECRET` /
`OAUTH2_PROXY_CLIENT_SECRET` — are generated once and fanned out to every consumer
(`SECRET_ALIASES` in `tools/lib/secrets.py`). Re-running `setup` never rotates a value
that is already set; `--force` regenerates all of them.

The canonical copy of every `.env` lives under `$PAPAIA_CONFIG_DIR`; the files inside
the checkout are derived copies that `papaia-ctl start` overwrites. Edit the config
directory, never `src/**/.env`. All `.env` files are gitignored — secrets never enter
version control.

---

## Default Mode – Internal Keycloak

### Starting

```bash
tools/papaia-ctl start
```

Keycloak imports the `papaia` realm automatically on the first start
(`$PAPAIA_CONFIG_DIR/infra/keycloak/realm-import/papaia-realm.json`). Re-runs skip the
import if the realm already exists.

### Admin Console

Keycloak terminates TLS itself, so the admin console is served over **HTTPS** — with
the self-signed certificate `papaia-ctl setup` generated, which the browser will warn
about on a local install.

| URL | Credentials |
|-----|-------------|
| `https://host.docker.internal:8110` | `admin` / see `KC_ADMIN_PASSWORD` |

> Read the current password with:
> `grep KC_ADMIN_PASSWORD "$PAPAIA_CONFIG_DIR/infra/keycloak/.env" | cut -d= -f2`

### Pre-configured Realm: `papaia`

| Item | Value |
|------|-------|
| Realm | `papaia` |
| OIDC Discovery | `http://host.docker.internal:8110/realms/papaia/.well-known/openid-configuration` |

**Clients**

| Client ID | Service | Secret variable |
|-----------|---------|----------------|
| `librechat` | LibreChat | `KC_LIBRECHAT_CLIENT_SECRET` |
| `litellm` | LiteLLM | `KC_LITELLM_CLIENT_SECRET` |
| `oauth2-proxy` | Nginx Proxy Manager admin UI + other services without native OIDC | `KC_OAUTH2_PROXY_CLIENT_SECRET` |
| `localai` | LocalAI (native OIDC, role-restricted) | `KC_LOCALAI_CLIENT_SECRET` |
| `papaia-manager` | papaia-manager (native OIDC, role-restricted) | `KC_MANAGER_CLIENT_SECRET` |

Addon clients (`paperless`, `qdrant-rag`, ...) are not listed here: an addon
registers its own client and generates its own secret during installation. The
core neither stores nor generates those values.

**Audience Mappers for MCP servers**

An MCP server behind an addon receives access tokens forwarded by LibreChat
(`Authorization: Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}`). It validates the
incoming token against Keycloak's JWKS and checks the `aud` (audience) claim, so the
token LibreChat sends must carry that server's client ID as an audience.

The mappers that produce those audiences ship with the addon, not with the core: an
addon's `integration/keycloak/` fragments contribute both its own client JSON and an
audience mapper added to the **`librechat`** client. `papaia-ctl addon install`
registers them additively; the core realm template stays free of addon references.

Where the MCP server is not a login client, the addon registers it as a resource
server (no flows, no secret) so that the `included.client.audience` reference in the
mapper resolves. It never issues tokens itself.

> **External OIDC provider:** if you use Entra ID, Authentik, or another provider
> instead of the built-in Keycloak, configure equivalent audience claims in that
> provider's token issuance policy before installing an addon that ships an MCP
> server.

**Realm Roles**

| Role | Description |
|------|-------------|
| `admin` | Full administrator access |
| `user` | Regular user (default for all new accounts) |
| `viewer` | Read-only viewer |
| `localai-access` | Required for SSO login to LocalAI |
| `finance` | Finance department (demo role) |

**Default Test Users** (local development only — do not use in production)

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin` | admin, user, localai-access |
| `testuser` | `testuser` | user, finance (no `localai-access` — cannot log in to LocalAI via SSO) |

### Linux Host Note

`host.docker.internal` is used so that both the browser and Docker containers reach
Keycloak at the same URL, keeping the OIDC `iss` claim consistent.

On **Linux**, add the entry manually before starting:

```bash
echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
```

On macOS and Windows (Docker Desktop) it resolves out-of-the-box.

---

## oauth2-proxy — Forward Auth for Services Without Native OIDC

oauth2-proxy runs on port `4180` and protects services that have no native OIDC support.
Nginx Proxy Manager checks authentication via oauth2-proxy before forwarding requests.
In the core it guards the Nginx Proxy Manager admin UI, which runs its own oauth2-proxy
sidecar; addons use the same mechanism for their own UIs.

Set `OAUTH2_PROXY_COOKIE_SECRET` and `OAUTH2_PROXY_CLIENT_SECRET` in
`src/infra/oauth2-proxy/.env` (see the Setup section above).

### Configuring Nginx Proxy Manager for a protected service

For each service to protect:

1. Open Nginx Proxy Manager → **Proxy Hosts** → edit/create the host.
2. Go to the **Advanced** tab and paste:

```nginx
auth_request /oauth2-proxy/auth;
error_page 401 = @error401;

location @error401 {
    return 302 http://localhost:4180/oauth2/start?rd=$scheme://$host$request_uri;
}

location = /oauth2-proxy/auth {
    internal;
    proxy_pass       http://oauth2-proxy:4180/oauth2/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length   "";
    proxy_set_header X-Original-URI  $request_uri;
    proxy_set_header X-Real-IP       $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

3. Save. Unauthenticated users are now redirected to Keycloak login.

> **Redirect URL:** `http://localhost:4180` in the error redirect must match
> `--redirect-url` in `src/infra/oauth2-proxy/docker-compose.yml` and the redirect URI
> registered in the Keycloak `oauth2-proxy` client. Change all three consistently when
> deploying to a non-localhost server.

---

## Switching to an External OIDC Provider

### 1. Run setup with external OIDC

```bash
tools/papaia-ctl setup \
  --auth-provider=external_oidc \
  --oidc-issuer=https://your-provider.example.com/realms/your-realm
```

Or set manually in `src/.env`:

```dotenv
AUTH_PROVIDER=external_oidc
OIDC_ISSUER=https://your-provider.example.com/realms/your-realm
```

`setup` derives all OIDC endpoints from the issuer URL. Client secrets are not derivable —
copy each one from the external provider into the matching papaia env file (see below).

### 2. Create OIDC clients in the external provider

Register a confidential client for each service. When using an external Keycloak the client
settings mirror the bundled realm (`src/infra/keycloak/realm-import/papaia-realm.json.template`):

| Client ID | PKCE | Redirect URI(s) | papaia secret variable |
|---|---|---|---|
| `librechat` | required | `{LIBRECHAT_HOST}/oauth/openid/callback` | `OPENID_CLIENT_SECRET` in `src/ai/librechat/.env` |
| `litellm` | — | `*` | `GENERIC_CLIENT_SECRET` in `src/ai/litellm/.env` |
| `oauth2-proxy` | — | `*` | `OAUTH2_PROXY_CLIENT_SECRET` in `src/infra/oauth2-proxy/.env` |
| `localai` | — | `{LOCALAI_PUBLIC_URL}/api/auth/oidc/callback` | `LOCALAI_OIDC_CLIENT_SECRET` in `src/ai/localai/.env` |

All clients need a **realm-roles protocol mapper** (type: User Realm Role, claim name `roles`,
multivalued, included in ID token, Access token, and userinfo).

After creating each client, paste its secret from **Clients → `<id>` → Credentials** into the
matching papaia env file. Then restart the affected services:

```bash
docker compose restart librechat localai litellm oauth2-proxy
```

### 3. LibreChat configuration for an external Keycloak

LibreChat's OIDC variables in `src/ai/librechat/.env` (set automatically by `setup`):

```env
OPENID_ISSUER=https://keycloak.example.com/realms/papaia
OPENID_CLIENT_ID=librechat
OPENID_CLIENT_SECRET=<Clients → librechat → Credentials → Client secret>
OPENID_CALLBACK_URL=https://librechat.example.com/oauth/openid/callback
OPENID_USE_PKCE=true
```

In the external Keycloak, the `librechat` client requires:

- **PKCE** enforced: set `pkce.code.challenge.method` to `S256` under the client's
  Advanced settings.
- **Realm-roles mapper**: protocol mapper of type "User Realm Role", claim name `roles`,
  multivalued, included in ID token, Access token, and userinfo.
- **Username mapper**: protocol mapper of type "User Property", property `username`,
  claim name `preferred_username`.

### 4. LocalAI configuration and role restriction for an external Keycloak

LocalAI's OIDC variables in `src/ai/localai/.env` (set automatically by `setup`):

```env
LOCALAI_OIDC_ISSUER=https://keycloak.example.com/realms/papaia
LOCALAI_OIDC_CLIENT_ID=localai
LOCALAI_OIDC_CLIENT_SECRET=<Clients → localai → Credentials → Client secret>
```

To restrict SSO access to users with a specific realm role, configure a **custom browser
flow** for the `localai` client:

1. In Keycloak Admin Console → **Authentication → Flows**, duplicate the built-in
   `browser` flow and rename it (e.g. `localai browser`).
2. Inside the `browser forms` sub-flow, add a new **CONDITIONAL** sub-flow
   (e.g. `localai access gate`).
3. Inside `localai access gate` add two steps:
   - **Condition - User Role** (set to `CONDITIONAL`): configure role `localai-access`,
     enable **Negate** so the condition is true when the user *lacks* the role.
   - **Deny Access** (set to `REQUIRED`).
4. Under **Clients → `localai` → Advanced → Authentication flow overrides**, set
   **Browser Flow** to `localai browser`.
5. Create the realm role `localai-access` and assign it to users who should be allowed in.

The bundled `papaia-realm.json.template` ships this flow pre-configured and imports it
automatically on first Keycloak start — the manual steps above are only needed for an
external Keycloak.

### 5. Provider-specific notes

| Provider | Issuer URL pattern | Notes |
|----------|--------------------|-------|
| Keycloak (external) | `https://kc.example.com/realms/<realm>` | Same as internal, different host |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Set `OPENID_USERNAME_CLAIM=email` |
| Authentik | `https://authentik.example.com/application/o/<slug>/` | Trailing slash required |
| Okta | `https://<domain>.okta.com/oauth2/default` | |
| Auth0 | `https://<tenant>.auth0.com/` | |

---

## Key Environment Variables Reference

### `src/infra/keycloak/.env`

| Variable | Description |
|----------|-------------|
| `KC_HOSTNAME` | Public URL written into tokens — must be reachable from browser and containers |
| `KC_ADMIN_PASSWORD` | Bootstrap admin password (generated by setup) |
| `KC_DB_PASSWORD` | Postgres password (generated by setup) |
| `KC_LIBRECHAT_CLIENT_SECRET` | LibreChat OIDC secret |
| `KC_LITELLM_CLIENT_SECRET` | LiteLLM OIDC secret |
| `KC_OAUTH2_PROXY_CLIENT_SECRET` | oauth2-proxy OIDC secret |
| `KC_LOCALAI_CLIENT_SECRET` | LocalAI OIDC secret |
| `KC_MANAGER_CLIENT_SECRET` | papaia-manager OIDC secret |

### `src/infra/oauth2-proxy/.env`

| Variable | Description |
|----------|-------------|
| `OAUTH2_PROXY_CLIENT_ID` | Keycloak client ID (`oauth2-proxy`) |
| `OAUTH2_PROXY_CLIENT_SECRET` | Must match `KC_OAUTH2_PROXY_CLIENT_SECRET` (propagated by setup) |
| `OAUTH2_PROXY_COOKIE_SECRET` | Random cookie signing key (generated by setup) |

---

## Rotating Client Secrets

Clear the `KC_*_CLIENT_SECRET` value in `$PAPAIA_CONFIG_DIR/infra/keycloak/.env` and
re-run setup:

```bash
tools/papaia-ctl setup
tools/papaia-ctl start
```

An empty value counts as a placeholder, so setup generates a fresh secret and fans it
out to every consuming `.env` — there is no second file to edit by hand. Because the
realm is re-rendered from the same values, the new secret reaches Keycloak with the
next realm import; on an already-imported realm, regenerate it in the Admin Console
(`papaia → Clients → <client> → Credentials → Regenerate`) and paste that value into
the config directory instead.

`tools/papaia-ctl setup --force` rotates **every** secret at once, which invalidates
active sessions and any externally shared API key.

> **Realm import note:** the realm template
> (`realm-import/papaia-realm.json.template`) carries `${env.VAR}` placeholders, but
> Keycloak's own import-time substitution is not relied on: `render_core.bake_realm_secrets()`
> writes the real values into `$PAPAIA_CONFIG_DIR/infra/keycloak/realm-import/papaia-realm.json`
> before Keycloak ever reads it. The rendered file is generated state and must never be
> committed.
> The import runs only on the **first** Keycloak start. To re-apply it (e.g. after adding
> a new client), delete the `keycloak-postgresql` volume and restart — this wipes all
> realm data including manually created users.
