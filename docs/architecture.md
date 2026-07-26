# papAIa Platform — Architecture Specification

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Date** | 2026-06-25 |
| **Status** | Draft — active |
| **Scope** | Platform architecture, add-on contract, workspace topology, deployment model |
| **Author(s)** | Marko Böhm |

---

## 1. Context & Problem Statement

Fidonis is introducing AI into mid-sized businesses with the **papAIa stack**.
The core promise is **data sovereignty** — all data stays with the customer.

### Current state (AS-IS)

The stack is currently a **monolithic Compose bundle**: application-specific
services (Paperless + MCP-Paperless, Qdrant-RAG + Ingest, n8n, SearXNG, Firecrawl)
are pulled in via `include:` into `papaia/src/docker-compose.yml`. Their
integration points are **hard-wired into the Core configs**:

- `librechat.yaml` → `mcpServers` / `allowedDomains`
- `homepage/config/services.yaml` → service cards
- Keycloak realm clients + audience mappers

Every additional application grows the Core and couples it to services that
not every customer needs. This neither scales across many customers nor is
maintainable.

### Target state (TO-BE)

A **Lean Core** (generic platform services only) with **empty, app-agnostic
intake points** is made extensible via a unified **add-on contract** — each
add-on in its own repo, addable or removable at any time without modifying
the Core.

---

## 2. Target Architecture — Overview

### 3-Tier Model + 4 Cross-cutting Principles

```
                   ┌─────────────── PAPAIA PLATFORM (per customer, one host) ────────────────┐
                   │                                                                            │
  Tier 1: CORE     │  Identity (Keycloak + oauth2-proxy)  Ingress (Nginx Proxy Manager)       │
  (always,         │  AI-Runtime (LibreChat + LiteLLM [+ LocalAI])  Dashboard (Homepage)      │
  self-sufficient) │                                                                            │
                   │  Integration Registry = EMPTY, app-agnostic intake points:                │
                   │    mcpServers slot · Homepage slot · Realm (base clients) · NPM host      │
                   │                           ▲     ▲     ▲                                    │
                   │          (5 seams: network · OIDC · MCP · Homepage · Ingress)             │
                   └───────────────────────────┼─────┼─────┼──────────────────────────────────┘
                                               │     │     │   unified add-on contract
               ┌───────────────────────────────┘     │     └───────────────────────────────┐
               │                                      │                                      │
  Tier 2: CURATED FIDONIS ADD-ON CATALOG              │   Tier 3: CUSTOMER APPLICATIONS     │
  (Fidonis-maintained, subscribable, own repo each)   │   (bespoke per customer, own repo   │
                                                       │    each, same contract)             │
  • RAG bundle (qdrant-rbac + Qdrant + Jina)          │   • Pattern A: wrap existing app    │
  • Documents (Paperless + paperless-mcp-rbac)         │     with MCP server                 │
  • Automation (n8n)                                   │   • Pattern B: ingest customer      │
  • Search (SearXNG)                                   │     data into RAG (role-scoped)     │
  • Web crawling (Firecrawl)                           │   • Pattern C: hybrid               │
               │                                       │                                      │
               └─────── each add-on: own network, only MCP seam exposed to AI-Runtime ───────┘

  Cross-cutting:
  ① DATA SOVEREIGNTY   — local-first inference, per-user RBAC at the data edge, network isolation
  ② MIXED HOSTING      — self-hosted + Fidonis-managed, same runtime artifact
  ③ FLEET SCALING      — SemVer compat, image-based, idempotent update runs
  ④ REPO INTEGRITY     — repos stay read-only (git pull), all generated output in the config directory
```

---

## 3. Tier 1 — Core: Platform, not App Collection

Only what every instance needs as a generic platform stays in the Core:

| Service group | Components |
|---|---|
| Identity | Keycloak (OIDC provider), oauth2-proxy (header injection) |
| Ingress | Nginx Proxy Manager (NPM) |
| AI-Runtime | LibreChat (chat UI), LiteLLM (LLM gateway), LocalAI (opt-in local inference) |
| Dashboard | Homepage |

The Core's integration points are hollowed out to **empty, app-agnostic intake
points** — no hard-wired application references. The Core is **self-sufficient**:
it starts and runs fully without any add-on.

### Core intake points

```
librechat.yaml     →  mcpServers: []        (empty, populated by add-ons)
                       allowedDomains: []    (empty, populated by add-ons)
services.yaml      →  Core services only    (add-ons append service cards)
Keycloak realm     →  Base clients          (add-on clients registered additively)
NPM                →  Core hosts            (add-on hosts added additively)
```

---

## 4. Tier 2 — Curated Fidonis Add-on Catalog

Fidonis-owned optional modules — each in its **own repo**, consumed as
**versioned images**. They use the **same** add-on contract as customer apps
(one mechanism), but are Fidonis-maintained, quality-assured, and subscribable
as a catalog.

Difference from Tier 3 = **ownership / trust / catalog listing**, not the
mechanism.

---

## 5. Tier 3 — Customer Applications

Bespoke per customer, own repo each, same contract. Three recurring patterns:

| Pattern | Description | Example |
|---|---|---|
| **A** — MCP-wrap | Wrap an existing app with an OIDC/RBAC MCP server | CRM system + `mcp-crm-rbac` |
| **B** — RAG ingest | Ingest customer data into the RAG bundle, role-scoped retrieval | Product database → Qdrant |
| **C** — Hybrid | MCP-wrap + RAG ingest combined | ERP with MCP + knowledge RAG |

"Onboarding a new customer app" = create repo from template + add entry to `deployment.yaml`.

---

## 6. The Add-on Contract

### 6.1 Add-on file structure

```
addons/papaia-addon-<name>/
├── papaia-app.yaml          # Manifest: declarative contract (all metadata)
├── docker-compose.yml       # App + associated MCP server, on its OWN network
├── .env.example             # App secrets template (seeded into $PAPAIA_CONFIG_DIR/addons/<name>/.env)
├── integration/             # The 5 seams as fragments (all optional)
│   ├── keycloak/            # OIDC client + audience mapper JSONs
│   ├── librechat/           # mcpServers + allowedDomains fragment (YAML)
│   ├── homepage/            # Dashboard service entry (YAML)
│   └── nginx/               # Optional ingress snippet
└── README.md                # Self-contained manual integration path (public-clean)
```

> **No `papaia-app.sh` per add-on.** All lifecycle verbs (`install`,
> `start`, `stop`, `remove`, `uninstall`) are executed centrally by `papaia-ctl`
> — no per-add-on delegation script needed.

### 6.2 `papaia-app.yaml` — Manifest schema

```yaml
name: <short-name>                 # Unique identifier (a-z, 0-9, -)
version: <semver>                  # Add-on version
addon_repo: papaia-addon-<name>    # GitHub repo name
requires:
  addon_api: 1                     # Contract generation the add-on is built against
                                   # (integer or list, e.g. [1, 2]);
                                   # checked against the Core's ADDON_API window
papaia_compat: ">=<semver>"        # Fallback: SemVer range against the Core version
description: "<description>"

networks:
  app_network: papaia-<name>-net   # Add-on's own bridge network
  attach: [nginx, librechat]       # Core containers to attach to the app network

local_ca_env:                      # optional: env vars pointing at the local
  <service>: [SSL_CERT_FILE]       # Keycloak CA certificate — cleared via override
                                   # when auth_provider=external_oidc

integration:
  keycloak:
    clients: [integration/keycloak/<client>.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/<name>.yaml   # optional
  homepage:  integration/homepage/<name>.yaml    # optional
  nginx:     integration/nginx/<name>.conf        # optional

env_prompts:                       # optional: metadata per .env.example key
  SOME_URL:
    label: "Human-readable label"  # default: KEY_NAME title-cased
    hint:  "Short info for the operator"
    type:  url                     # text (default) | integer | decimal | url
    secret: true                   # true | false; overrides name heuristic
    min:   1                       # for integer/decimal: lower bound
    max:   65535                   # for integer/decimal: upper bound
    pattern: "^[a-z]+$"           # regex for type: text (HTML + server)
    default: "http://localhost"    # static fallback value
    default_from_core: ENV_KEY     # value from the Core .env (overrides default)
  AUTO_SECRET:
    secret: true                   # required for GENERATE_* values without _KEY suffix
    label:  "Database password"

env_replace_secrets:               # optional: keys replaced by papaia-ctl
  OIDC_CLIENT_SECRET:              # after the Keycloak import
    hint: "Copy from Keycloak"     # hint is shown in the configuration overview
```

#### `.env.example` value markers

`papaia-manager` recognises four special values in `.env.example`:

| Value | Meaning | Behaviour in the install dialog |
|---|---|---|
| Literal | Operational default | Fields pre-filled; change is optional |
| `CHANGE_ME` | Operator must supply a value | Required field, empty |
| `GENERATE_<NAME>` | Value is generated on first `install` | Not required, shown as "generated automatically"; secret enforced |
| `REPLACE_WITH_<NAME>` | Value is set after the Keycloak import | Not required, shown as "enter after Keycloak import"; secret enforced |

Only values that differ from the `.env.example` literal are written to the config bundle `.env` (diff-based submit). `GENERATE_*` and `REPLACE_WITH_*` fields are left empty so that `seed_addon_env` can do its work.

#### Type mapping (`type:`)

| `type:` | HTML `type=` | `inputmode` | `step` | Server coercion |
|---|---|---|---|---|
| `text` (default) | `text` | — | — | `\n`/`\r` rejection only |
| `integer` | `number` | `numeric` | `1` | `int(v)`, `min`/`max` |
| `decimal` | `number` | `decimal` | `any` | `,`→`.`, then `Decimal(v)`, `min`/`max` |
| `url` | `url` | `url` | — | scheme in `{http, https}` and `netloc` present |

`secret: true` takes precedence over `type` for the HTML input type (masked field) but still governs validation and `inputmode`. An unknown `type:` value is silently ignored (fallback: inference from the literal).

> **Compatibility check** (`papaia-ctl addon check` and gates at
> `addon install`, `addon start`, `start`; see
> [ADR 0002](adr/0002-addon-core-compatibility-gating.md)). Precedence per add-on:
>
> 1. `requires.addon_api` present and the Core exposes an
>    `ADDON_API` window → intersection check against `[min..current]`
>    (authoritative).
> 2. Otherwise `papaia_compat` present → SemVer range against the platform
>    version (`VERSION` file). Supported range subset:
>    `>= > < <= == !=`, caret `^`, tilde `~`, comma-AND
>    (`">=0.8.0,<2.0.0"`), pre-releases (`-rc.1`).
> 3. Otherwise → `UNKNOWN`: warning, never hard-fail — a manifest older than
>    the contract does not lock the add-on out.
>
> In addition, all `networks.attach` entries are structurally validated against
> the Core Compose service names; an unknown name is `INCOMPATIBLE`. Policy:
> hard-fail in production, warning in dev mode
> (`PAPAIA_COMPAT_MODE` → `deployment.yaml → mode:` → default `enforce`);
> `--force` demotes `INCOMPATIBLE`, never a malformed manifest.

### 6.3 Example A: `papaia-addon-paperless`

```yaml
name: paperless
version: 1.0.0
addon_repo: papaia-addon-paperless
papaia_compat: ">=0.8.0"
description: "Paperless-ngx document management + OIDC/RBAC MCP server"
networks:
  app_network: papaia-paperless-net
  attach: [nginx, librechat]
local_ca_env:
  paperless: [REQUESTS_CA_BUNDLE]
  paperless-mcp: [SSL_CERT_FILE]
integration:
  keycloak:
    clients: [integration/keycloak/paperless.json, integration/keycloak/mcp-paperless.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/paperless.yaml
  homepage:  integration/homepage/paperless.yaml
  nginx:     integration/nginx/paperless.conf
```

**Data sovereignty:** `mcp-paperless` validates the Keycloak bearer token + audience and
forwards requests as `X-Papaia-Remote-User` — Paperless enforces its own per-user RBAC.
No admin credential in the MCP layer.

### 6.4 Example B: `papaia-addon-qdrant-rbac`

```yaml
name: qdrant-rbac
version: 0.1.0
addon_repo: papaia-addon-qdrant-rbac
papaia_compat: ">=0.8.0"
description: "Qdrant vector DB + OIDC/RBAC MCP server for RAG workloads"
networks:
  app_network: papaia-qdrant-net
  attach: [librechat]
integration:
  keycloak:
    clients: [integration/keycloak/qdrant-rbac.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/qdrant-rbac.yaml
  homepage:  integration/homepage/qdrant-rbac.yaml
```

**Data sovereignty:** `mcp-qdrant-rbac` validates the bearer token + audience and scopes
Qdrant queries to the collections the user has access to (JWT per collection ACL).

---

## 7. The 5 Seams (Add-on Integration Points)

All 5 seams are **standardised**, not hand-wired. Which seams an add-on uses
is optionally declared in the manifest.

### Seam 1 — Network: "Core attaches to app"

The add-on defines its own bridge network. The orchestrator automatically generates
a **Compose override** (`$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml`)
that references the app network as `external: true` and attaches the Core containers
listed under `attach:` (e.g. `nginx`, `librechat`) to the app network.
The Core Compose remains unchanged.

```yaml
# Example: generated override for paperless
services:
  librechat:
    networks:
      - papaia-paperless-net
  nginx-proxy-manager:
    networks:
      - papaia-paperless-net
networks:
  papaia-paperless-net:
    external: true
```

### Seam 2 — OIDC

Client JSONs from `integration/keycloak/` are registered **additively and
idempotently** in the Keycloak realm (via the Keycloak Admin REST API or a
bootstrap script), including audience mappers for the MCP token flow. Base:
the existing idempotent Keycloak client sync in `papaia/src/infra/keycloak/bootstrap.sh`.

### Seam 3 — LibreChat-MCP

The `mcpServers` and `allowedDomains` fragment from `integration/librechat/`
is **merged at render time** into the effective `librechat.yaml` in the config
directory. Render process: base template + sum of active add-on fragments +
customer overlay.

### Seam 4 — Homepage

The service entry from `integration/homepage/` is merged at render time into
`services.yaml` in the config directory. Homepage mounts exclusively the
rendered file from `$PAPAIA_CONFIG_DIR/services/homepage/config/`.

### Seam 5 — Ingress (optional)

Optional NPM proxy host entry for the add-on UI. Added additively via the
Nginx fragment mechanism (or NPM API).

---

## 8. Inversion of Control — Orchestrator `papaia-ctl`

The orchestrator lives in `papaia/tools/papaia-ctl` and is therefore part of
the public Core repo (community-usable). It reads the **deployment manifest**
(`$PAPAIA_CONFIG_DIR/deployment.yaml`) and invokes the appropriate
`docker compose` command for each add-on in the correct order.

**New add-on = clone repo + `papaia-ctl addon install <name> --path=addons/<name>`.**
No Core changes required.

### Available verbs

| Command | What happens |
|---|---|
| `papaia-ctl setup` | Create config directory, seed `.env`, generate secrets, render configuration, write `deployment.yaml` |
| `papaia-ctl start [--addons] [--profiles=LIST]` | Copy Core `.env` from config bundle into checkout → render config → start Core. With `--addons`: also start active add-ons. |
| `papaia-ctl stop [--clean-up] [--addons]` | `docker compose stop` (stop containers, do not remove). With `--clean-up`: `docker compose down` (remove containers, keep volumes). With `--addons`: same for active add-ons. |
| `papaia-ctl uninstall [--clean-up] [--addons]` | Core `down` → permanently delete `$PAPAIA_CONFIG_DIR`. With `--clean-up`: also delete volumes. With `--addons`: also stop active add-on containers. Warning + confirmation required. |
| `papaia-ctl addon install <name> --path=` | Seed config bundle → register in `deployment.yaml` → generate override → render Core → print Keycloak checklist. **Starts nothing.** |
| `papaia-ctl addon start <name>` | Copy `.env` from config bundle into checkout → render Core → `docker compose up -d` |
| `papaia-ctl addon stop <name>` | `docker compose stop` (stop containers, do not remove) |
| `papaia-ctl addon stop <name> --clean-up` | `docker compose down` (remove containers, keep volumes) |
| `papaia-ctl addon remove <name>` | Remove override → re-render Core → `active: false` in manifest. **Containers untouched, config bundle kept.** |
| `papaia-ctl addon uninstall <name>` | Remove override + deployment entry → delete config bundle → `docker compose down` |
| `papaia-ctl addon uninstall <name> --clean-up` | Like `uninstall` + `docker compose down -v` (also delete volumes) |

### Config bundle seeding at `addon install`

`addon install` reads the add-on's `.env.example` and **non-destructively inserts missing
keys** into `$PAPAIA_CONFIG_DIR/addons/<name>/.env` (sticky reuse — existing values are
preserved). Secret keys (pattern `SECRET|PASSWORD|KEY|TOKEN`) with a placeholder
automatically receive a random value (`secrets.token_urlsafe`), so that the Keycloak
client secret and the app share the same value (one source).

`addon start` copies the config bundle (`.env`) into the add-on checkout so that
`docker compose` can read variables via `env_file: ./.env`. The checkout stays
git-pristine; the source of truth lives in the config directory.

---

## 9. Workspace Topology

### Directory structure

```
[workspace-root]/
│
├── addons/                              # Tier 2 and Tier 3 add-ons (each its own GitHub repo)
│   ├── papaia-addon-paperless/
│   │   ├── papaia-app.yaml
│   │   ├── docker-compose.yml
│   │   ├── .env.example
│   │   └── integration/
│   │       ├── keycloak/
│   │       ├── librechat/
│   │       ├── homepage/
│   │       └── nginx/
│   │
│   └── papaia-addon-qdrant-rbac/
│       ├── papaia-app.yaml
│       ├── docker-compose.yml
│       ├── .env.example
│       └── integration/
│           ├── keycloak/
│           ├── librechat/
│           └── homepage/
│
├── papaia/                              # Tier 1 — Core repo (Fidonis/papaia, public-bound)
│   ├── docs/                            # Architecture docs, ADRs, add-on spec
│   ├── src/                             # Core implementation
│   │   ├── docker-compose.yml           # Lean Core (mounts exclusively from $PAPAIA_CONFIG_DIR)
│   │   ├── .env.example                 # Core env template
│   │   ├── ai/                          # Base templates (librechat.yaml.base, litellm.yaml.base)
│   │   ├── infra/                       # Keycloak realm base, bootstrap scripts
│   │   ├── services/                    # Homepage base config
│   │   └── catalog.yaml                 # Known add-ons (name, repo URL, tags, tier)
│   └── tools/                           # Orchestrator
│       ├── papaia-ctl                   # init · up/down · addon install|start|stop|remove|uninstall
│       ├── deployment.template.yaml     # Template for deployment.yaml in config directory
│       └── lib/
│           ├── render_core.py           # 3-layer merge → config directory
│           └── gen_override.py          # Generate Seam-1 override → config directory
│
└── papaia-config/                       # Config directory (per customer/env, NOT a repo, gitignored)
    ├── deployment.yaml                  # SSOT: active add-ons + versions + Core profiles
    ├── .env                             # Secrets + env vars (gitignored, seeded at init)
    ├── addons/                          # Add-on config bundles (canonical source, backed up)
    │   └── <name>/
    │       └── .env                    # Add-on secrets (seeded at install, sticky)
    ├── ai/librechat/librechat.yaml      # GENERATED (base + add-ons + overlay)
    ├── ai/litellm/config.yaml           # GENERATED
    ├── infra/keycloak/realm-import/     # GENERATED (secrets baked in, always render-owned)
    ├── services/homepage/config/        # GENERATED
    ├── overrides/                       # GENERATED docker-compose.<addon>.override.yml
    └── overlay/                         # Customer overlay (hand-authored, survives re-render)
        ├── ai/librechat/librechat.yaml
        └── services/homepage/config/services.yaml
```

### Repo mapping

| Workspace path | GitHub repo | Visibility |
|---|---|---|
| `papaia/` | `Fidonis/papaia` | public-bound |
| `papaia/tools/` | Part of `Fidonis/papaia` | public-bound |
| `addons/papaia-addon-paperless/` | `Fidonis/papaia-addon-paperless` | public-bound |
| `addons/papaia-addon-qdrant-rbac/` | `Fidonis/qdrant-rbac` | public-bound |
| `papaia-config/` | — (no repo) | gitignored, per customer/env |

---

## 10. Naming Conventions

### Add-on repos: `papaia-addon-<name>`

| Context | Name schema | Example |
|---|---|---|
| GitHub repo | `papaia-addon-<name>` | `papaia-addon-paperless` |
| Workspace directory | `addons/papaia-addon-<name>/` | `addons/papaia-addon-paperless/` |
| Manifest field `name:` | `<name>` (short name) | `paperless` |
| `deployment.yaml` → `path:` | `addons/papaia-addon-<name>` | `addons/papaia-addon-paperless` |
| Docker network | `papaia-<name>-net` | `papaia-paperless-net` |

### Config directory

The config directory is named **`papaia-config`**, configurable via env var:

```bash
export PAPAIA_CONFIG_DIR=/srv/fidonis/papaia-prod/config   # absolute path in production
# Default (without export): <workspace-root>/papaia-config
```

### Internal structure

| Area | Path | Contents |
|---|---|---|
| Core implementation | `papaia/src/` | Compose, base templates, bootstrap scripts |
| Orchestrator | `papaia/tools/` | `papaia-ctl`, render libraries |
| Add-on | `addons/papaia-addon-<name>/` | Manifest, Compose, integration fragments |
| Config directory | `papaia-config/` | Generated configs, secrets, overlay, add-on bundles |

---

## 11. Cross-cutting Principles

### ① Data sovereignty (core promise)

- **State on customer infrastructure**: all data in named volumes on the customer host;
  also in Fidonis-managed operation it is single-tenant — Fidonis holds no customer data.
- **Local-first inference**: LocalAI as the default backend via LiteLLM; external
  LLM APIs are **opt-in** and centrally disableable at exactly one point (LiteLLM)
  → "nothing leaves the building" is enforceable and auditable (one egress point).
- **Authorization at the data edge, not only in the UI**: MCP servers validate the
  Keycloak bearer token + audience and scope **every** request:
  - `mcp-qdrant-rbac` → Qdrant JWT per collection ACL (role-scoped retrieval)
  - `mcp-paperless` → `X-Papaia-Remote-User` → native Paperless RBAC
- **Network isolation**: each add-on on its own bridge network; only the MCP seam
  is exposed to the AI-Runtime; the reverse proxy strips trust headers from external
  traffic (defense-in-depth).

### ② Mixed hosting (same runtime artifact)

| Operating model | Who acts | Path |
|---|---|---|
| **Self-hosted** | Customer or guided installation | `papaia/README.md` (manual) |
| **Fidonis-managed** | Fidonis operates single-tenant per customer | Private tooling + central update distribution |

Both models produce the same runtime artifact from the same repos. The difference
lies in the tooling path, not the stack.

### ③ Fleet scaling & maintainability

- **Two-axis compatibility contract**: the Core publishes a contract generation
  (`ADDON_API` window) alongside the SemVer platform version (`VERSION` file);
  add-ons declare `requires.addon_api` (authoritative) and
  `papaia_compat: ">=x.y.z"` (fallback). The orchestrator rejects incompatible
  combinations at `install`/`start` and answers with
  `papaia-ctl addon check --target-core=PATH` the update question **before** the
  switch (see [ADR 0002](adr/0002-addon-core-compatibility-gating.md)).
  This makes fleet updates safe.

  > **SemVer quick reference:** `MAJOR.MINOR.PATCH` — MAJOR breaks backwards
  > compatibility (add-ons must be explicitly updated), MINOR adds functionality
  > in a backwards-compatible way, PATCH fixes bugs without API changes.
  > `papaia_compat: ">=0.8.0"` means: this add-on runs on any Core version from
  > 0.8.0 upwards, as long as MAJOR stays at 0.

- **Image-based distribution**: add-ons as pinned images from
  `ghcr.io/fidonis/...`, not as source. Update = bump ref + re-apply idempotent
  `install`; rollback = previous image pin.
- **Per-customer deployment manifest**: `deployment.yaml` in the config directory
  is the **single source of truth** per installation (Core profiles + active
  add-ons + versions + hosting type). Drives the orchestrator and update runs.
- **Idempotency throughout**: `install`, `render`, `up` are re-runnable without
  side effects → unattended fleet updates possible.
- **Lean Core = less maintenance**: decoupled lifecycles — Core upgrades
  independently of add-ons, add-ons independently of the Core (within the
  compat range).

### ④ No repo changes at the customer (config directory externalisation)

This is the **load-bearing pattern** for the customer upgrade path:

- **Repos = read-only at deploy time**: Core repo, add-on repos, tooling —
  no mutation through install / deploy / update runs. `git pull` always stays
  conflict-free.
- **`$PAPAIA_CONFIG_DIR` = everything materialised**: rendered effective configs,
  generated overrides, generated `papaia-realm.json` (secrets baked in),
  deployment manifest, `.env`, customer overlay, add-on config bundles.
- **Core Compose mounts exclusively from `$PAPAIA_CONFIG_DIR/...`**.
- **No generated artifact lives in the repo tree** (`.gitignore` discipline).

---

## 12. Deployment Manifest (`deployment.yaml`)

The manifest in the config directory is the **only** declarative source for the
state of an installation.

### Schema

```yaml
customer: <name>                    # Unique identifier for the installation
platform_version: 1.0.0            # Active Core version
hosting: self-hosted | managed      # Operating model

core:
  profiles:                         # Active Docker Compose profiles
    - keycloak
    - oauth2-proxy
    - nginx
    - librechat
    - litellm
    - homepage
  inference: local-first | external # LLM inference mode

addons:
  - name: paperless                 # Short name (= manifest field name:)
    path: addons/papaia-addon-paperless  # Workspace-relative path to the add-on repo
    version: 1.0.0                  # Pinned version
    active: true                    # false = installed but not integrated
  - name: qdrant-rbac
    path: addons/papaia-addon-qdrant-rbac
    version: 0.1.0
    active: false                   # deactivated
```

### Active set

The orchestrator derives the active set (which add-ons participate in render and
`docker compose up`) from `active: true` entries. The manifest itself is never
deleted by `install`/`remove` — only the `active` flag and `version` are updated.

---

## 13. Customer Overlay — 3rd Render Layer

The config directory contains an optional `overlay/` directory for customer-specific
customisations. Overlay files are **never overwritten by `papaia-ctl`** and survive
every re-render.

### 3-layer merge

```
Repo base  (papaia/src/*.base.*)
  + sum of active add-on fragments  (addons/papaia-addon-*/integration/*)
  + customer overlay  ($PAPAIA_CONFIG_DIR/overlay/*)
  ───render──▶  effective config in $PAPAIA_CONFIG_DIR/...
```

### Typical overlay use cases

**Additional LLM endpoint** (`overlay/ai/librechat/librechat.yaml`):
```yaml
endpoints:
  custom:
    - name: "Customer LLM Gateway"
      apiKey: "${CUSTOMER_LLM_API_KEY}"
      baseURL: "https://llm.customer.internal/v1"
      models:
        default: ["gpt-4o"]
```

**Company links in the dashboard** (`overlay/services/homepage/config/services.yaml`):
```yaml
- Company:
    - Intranet:
        href: "https://intranet.customer.internal"
        description: Corporate intranet
        icon: mdi-home-city
```

---

## 14. papaia-manager — Web-based Add-on Management

### Motivation

`papaia-ctl` is a CLI orchestrator — ideal for administrators, but not an
accessible way for non-technical users to browse, try out, or install add-ons.
The **papaia-manager** provides a web UI based on the same orchestrator logic.

### Role: optional Core service (not an add-on)

The manager manages add-ons — it must not itself be an add-on (circular
dependency). It is an **optional Core service** in `papaia/src/docker-compose.yml`
behind a Compose profile (`manager`).

### Stack

| Layer | Choice | Rationale |
|---|---|---|
| Backend | FastAPI (Python) | Direct imports of `render_core.py` + `gen_override.py` |
| Frontend | HTMX + Jinja2 | No build step; stays in the Python ecosystem |
| Docker API | `docker` Python SDK + subprocess | Type-safe + fallback for `docker compose` |
| Catalog | `catalog.yaml` in `papaia/src/` | Versioned, offline-capable |
| Auth | oauth2-proxy (Seam 2, role `admin`) | Already present — no separate OIDC needed |
| Ingress | Nginx fragment (Seam 5) | Analogous to add-on ingress rules |

### File structure

```
papaia/src/
├── catalog.yaml              # Known add-ons: name, repo URL, description, tags, tier
└── manager/
    ├── Dockerfile
    ├── main.py               # FastAPI app
    ├── routers/
    │   └── addons.py         # GET/POST /addons/{name}/install|start|remove|uninstall
    ├── services/
    │   ├── catalog.py        # Reads catalog.yaml — "available" add-ons
    │   ├── deployment.py     # Reads/writes deployment.yaml — "installed" add-ons
    │   └── orchestrator.py   # Calls papaia-ctl via subprocess
    └── templates/
        ├── index.html        # Add-on gallery (catalog + status)
        └── addon.html        # Detail view with action buttons
```

### Catalog format (`catalog.yaml`)

```yaml
addons:
  - name: paperless
    repo: https://github.com/Fidonis/papaia-addon-paperless
    description: Document management with OCR and OIDC/RBAC MCP server
    category: productivity
    tier: 2
    tags: [documents, ocr]
  - name: qdrant-rbac
    repo: https://github.com/Fidonis/papaia-addon-qdrant-rbac
    description: Qdrant vector DB with OIDC/RBAC for RAG workloads
    category: ai
    tier: 2
    tags: [rag, vector-db]
```

### Execution model

The manager calls `papaia-ctl` via subprocess — no re-implementation of logic:

```python
# orchestrator.py
def run_ctl(*args):
    return subprocess.run(
        ["bash", "/workspace/papaia/tools/papaia-ctl", *args],
        capture_output=True, text=True
    )

install   = lambda name, path: run_ctl("addon", "install",   name, f"--path={path}")
start     = lambda name:       run_ctl("addon", "start",     name)
remove    = lambda name:       run_ctl("addon", "remove",    name)
uninstall = lambda name:       run_ctl("addon", "uninstall", name)
```

> **Security note:** The `name` parameter from the URL must be validated against
> `[a-z0-9-]+` before being used in shell commands.

### Docker Compose

```yaml
papaia-manager:
  build: ./manager
  profiles: [manager]
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock   # Docker API
    - ${WORKSPACE_ROOT}:/workspace                 # papaia-ctl + add-ons
    - ${PAPAIA_CONFIG_DIR}:/config                 # read/write deployment.yaml
  networks:
    - papaia-net
```

### Integration with the 5 seams

| Seam | Manager integration |
|---|---|
| Seam 2 (OIDC) | Behind `oauth2-proxy`; Keycloak role `admin` required |
| Seam 4 (Dashboard) | Entry in `services.base.yaml` → appears in Homepage |
| Seam 5 (Ingress) | `manager.${PAPAIA_HOST}` → Nginx forward to container port |
| Seams 1, 3 | Not directly used |

### UI concept: add-on cards

Each card shows:
- Name + description (from `catalog.yaml` / `papaia-app.yaml`)
- Status badge: `available` · `installed` · `active`
- Version + update-available indicator
- Contextual action button: **Download & Install → Start ↔ Stop → Remove → Uninstall**
- Seam indicators: which integration points the add-on uses

### Open design question

| Option | Description | Assessment |
|---|---|---|
| **A — MVP** | Manager handles only locally present add-ons in `addons/` | Faster to implement |
| **B — Store** | Manager clones from `catalog.yaml` automatically on "Install" (`git clone`) | Genuine marketplace feel; recommended for a follow-on iteration |

---

## 15. Roadmap

| Phase | Content | Status |
|---|---|---|
| **Phase 0** — Spec & blueprint | Architecture spec, add-on contract schema, ADR definition; validate manifest schema against existing examples | Completed |
| **Phase 1** — Lean Core + pilot Paperless | Decouple app-specific includes + hard-wired configs from Core; `papaia-addon-paperless` as first companion repo; `papaia-ctl` verbs; end-to-end verification | Prototype present (verified) |
| **Phase 2** — Harden tooling | Full add-on registry + `papaia-ctl addon`; sourceable merge helpers (YAML merge, Keycloak registration, override network generation); per-customer deployment manifest drives composition | Open |
| **Phase 3** — Catalog + customer apps + fleet | Migrate remaining first-party modules individually into catalog (RAG bundle, n8n, search, Firecrawl); companion app template repo for customers (patterns A + B); fleet update distribution (version pinning, compat gating, rollback) | Open |

---

## 16. Open Items

| Item | Description | Recommendation |
|---|---|---|
| Add-on visibility | Generic Tier 2 add-ons public-bound or private? | Public-bound (observe no-trace requirement) |
| MCP reachability | East-west (librechat on the app network) vs. via ingress | East-west as default; selectable per add-on in the manifest |
| `PAPAIA_CONFIG_DIR` default | Sibling `<repo>-config` as today vs. `/srv/fidonis/<env>/config` | Sibling for dev, absolute path for prod |
| Compat policy strictness | Warn vs. hard-fail on compat violation | **Decided** ([ADR 0002](adr/0002-addon-core-compatibility-gating.md)): hard-fail in production, warn in dev mode; `--force` as escape hatch |
| Pre-release channels | `>=x.y.z-rc` or separate channel for beta add-ons | Open |
| `papaia/tools/` public | Orchestrator is public-bound; Fidonis can layer private optimisations | Community orchestrator in `papaia/tools/`; private fast path stays separate |
| papaia-manager: catalog download | Implement git-clone on "Install" (option B) in prototype? | Recommendation: follow-on iteration after Phase 2 tooling |

---

## 17. Verification Checklist

### Architecture validation

- [ ] **Contract reality check**: existing Paperless and Qdrant entries can be expressed
  without loss as `papaia-app.yaml` + fragments.
- [ ] **Mapping dry-run**: hard-wired entries (`librechat.yaml mcpServers`,
  `services.yaml`, realm clients) → target fragments documented.

### Prototype verification

| Check | Expected result |
|---|---|
| `papaia-ctl setup` | Create `papaia-config/`, seed `.env` + `deployment.yaml`, generate secrets |
| `papaia-ctl addon install paperless --path=addons/papaia-addon-paperless` | `papaia-config/addons/paperless/.env` created; repos unchanged |
| Hash `papaia/` + `addons/` before/after install | **Identical** (repo-pristine proof) |
| `papaia-ctl addon start paperless` | `.env` present in checkout; 6 containers running |
| Render (×2) | Identical outputs (idempotency) |
| Overlay applied | `papaia-config/overlay/ai/librechat/librechat.yaml` appears in rendered output |
| `docker compose -f papaia/src/docker-compose.yml config` | Valid; Core services only; no Paperless |
| Seam-1 override active | `librechat` + `nginx` attached to `papaia-net` **and** `papaia-paperless-net` |
| Config bundle seeding | `KC_PAPERLESS_CLIENT_SECRET` (random) + app keys present; second `install` changes nothing |
| `papaia-ctl start --profiles=keycloak` | Only Keycloak + DB start |
| `up` (full) | Core profiles + Paperless app + override active |
| `down --volumes` | All containers + volumes removed |

### Public-clean audit (for artifacts in public-bound repos)

- [ ] No reference to internal tooling repos in `papaia/docs/` + ADRs
- [ ] No reference to internal scripts or installers
- [ ] No "AI" except in the product name papAIa; no "agent" in the sense of tooling
- [ ] All seams described in purely technical terms (LibreChat `mcpServers`, OIDC client, NPM, Homepage)
