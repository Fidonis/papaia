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
      ├──▶  LibreChat (8000)     ─── native OIDC ──▶  Keycloak (8110)
      │
      ├──▶  Paperless-ngx (8010) ─── native OIDC ──▶  Keycloak (8110)
      │
      ├──▶  Nginx Proxy Manager  ─── forward auth ──▶  oauth2-proxy (4180)
      │         │                                             │
      │         └──▶  N8N (8400)                       Keycloak (8110)
      │
      └──▶  Keycloak Admin (8110)
```

**OIDC coverage by approach:**

| Service | Auth approach | Notes |
|---------|--------------|-------|
| LibreChat | native OIDC | openid-client strategy |
| Paperless-ngx | native OIDC | django-allauth |
| N8N | oauth2-proxy forward auth | NPM custom config required |
| LiteLLM UI | — | SSO requires enterprise license; use API key |
| Nginx Proxy Manager | — | protected by network / IP restriction |

---

## Setup

Before the first `docker compose up`, copy `.env.example` → `.env` in each component
directory and fill in the required values:

```bash
cp src/infra/keycloak/.env.example src/infra/keycloak/.env
cp src/infra/oauth2-proxy/.env.example src/infra/oauth2-proxy/.env
```

Replace every `GENERATE_*` placeholder with a random secret, e.g.:

```bash
openssl rand -hex 24   # for client secrets
openssl rand -hex 16   # for database passwords
openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'  # for cookie secrets
```

Make sure the same secret is set in **both** Keycloak's `.env` and the consuming
service's `.env` (e.g. `KC_OAUTH2_PROXY_CLIENT_SECRET` and `OAUTH2_PROXY_CLIENT_SECRET`
must match).

All `.env` files are gitignored — secrets never enter version control.

---

## Default Mode – Internal Keycloak

### Starting

```bash
cd src/
docker compose -f docker-compose.yml up -d
```

Keycloak imports the `papaia` realm automatically on the first start
(`realm-import/papaia-realm.json`). Re-runs skip the import if the realm already exists.

### Admin Console

| URL | Credentials |
|-----|-------------|
| `http://host.docker.internal:8110` | `admin` / see `KC_ADMIN_PASSWORD` in `src/infra/keycloak/.env` |

> Set `KC_ADMIN_PASSWORD` in `src/infra/keycloak/.env` before the first start.
> Read the current value with: `grep KC_ADMIN_PASSWORD src/infra/keycloak/.env | cut -d= -f2`

### Pre-configured Realm: `papaia`

| Item | Value |
|------|-------|
| Realm | `papaia` |
| OIDC Discovery | `http://host.docker.internal:8110/realms/papaia/.well-known/openid-configuration` |

**Clients**

| Client ID | Service | Secret variable |
|-----------|---------|----------------|
| `librechat` | LibreChat | `KC_LIBRECHAT_CLIENT_SECRET` |
| `paperless` | Paperless-ngx | `KC_PAPERLESS_CLIENT_SECRET` |
| `litellm` | LiteLLM | `KC_LITELLM_CLIENT_SECRET` |
| `oauth2-proxy` | N8N + others (forward auth) | `KC_OAUTH2_PROXY_CLIENT_SECRET` |

**Realm Roles**

| Role | Description |
|------|-------------|
| `admin` | Full administrator access |
| `user` | Regular user (default for all new accounts) |
| `viewer` | Read-only viewer |

**Default Test Users** (local development only — do not use in production)

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin` | admin, user |
| `testuser` | `testuser` | user |

### Linux Host Note

`host.docker.internal` is used so that both the browser and Docker containers reach
Keycloak at the same URL, keeping the OIDC `iss` claim consistent.

On **Linux**, add the entry manually before starting:

```bash
echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
```

On macOS and Windows (Docker Desktop) it resolves out-of-the-box.

---

## oauth2-proxy — Forward Auth for N8N and Other Services

oauth2-proxy runs on port `4180` and protects services that have no native OIDC support.
Nginx Proxy Manager checks authentication via oauth2-proxy before forwarding requests.

Set `OAUTH2_PROXY_COOKIE_SECRET` and `OAUTH2_PROXY_CLIENT_SECRET` in
`src/infra/oauth2-proxy/.env` (see the Setup section above).

### Configuring Nginx Proxy Manager for a protected service

For each service to protect (e.g. N8N):

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

### 1. Set `AUTH_PROVIDER=external_oidc` in `src/.env`

```dotenv
AUTH_PROVIDER=external_oidc
```

### 2. Update OIDC variables in `src/.env`

```dotenv
OIDC_ISSUER=https://your-provider.example.com/realms/your-realm
OIDC_CLIENT_ID=librechat
OIDC_CLIENT_SECRET=your-secret
```

Replace the `OPENID_*` / client vars in each service's `.env` as needed.

### 3. Provider-specific notes

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
| `KC_PAPERLESS_CLIENT_SECRET` | Paperless OIDC secret |
| `KC_LITELLM_CLIENT_SECRET` | LiteLLM OIDC secret |
| `KC_OAUTH2_PROXY_CLIENT_SECRET` | oauth2-proxy OIDC secret |

### `src/infra/oauth2-proxy/.env`

| Variable | Description |
|----------|-------------|
| `OAUTH2_PROXY_CLIENT_ID` | Keycloak client ID (`oauth2-proxy`) |
| `OAUTH2_PROXY_CLIENT_SECRET` | Must match `KC_OAUTH2_PROXY_CLIENT_SECRET` (propagated by setup) |
| `OAUTH2_PROXY_COOKIE_SECRET` | Random cookie signing key (generated by setup) |

---

## Rotating Client Secrets

When rotating a client secret, update it in **two places**:

1. `src/infra/keycloak/.env` — the `KC_*_CLIENT_SECRET` variable  
2. The service's own `.env` — the `OPENID_CLIENT_SECRET` or equivalent

Then regenerate the secret in Keycloak Admin Console:
`papaia → Clients → <client> → Credentials → Regenerate`

Restart the affected service after the change.

> **Realm import note:** The realm JSON (`realm-import/papaia-realm.json`) contains
> `${env.VAR}` placeholders that Keycloak substitutes at import time. The actual secrets
> live only in `.env` files and never need to be edited in the realm JSON itself.
> The import runs only on the **first** Keycloak start. To re-apply it (e.g. after adding
> a new client), delete the `keycloak-postgresql` volume and restart — this wipes all
> realm data including manually created users.
