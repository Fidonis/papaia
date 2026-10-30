# papAIa Platform — Architecture Specification

| Field | Value |
|---|---|
| **Version** | 1.7.0 |
| **Date** | 2026-10-24 |
| **Status** | Active — describes the 1.7.0 release as built |
| **Scope** | Platform architecture, add-on contract, workspace topology, deployment model |
| **Author(s)** | Marko Böhm |
| **Maintainer** | [Fidonis GmbH](https://www.fidonis.de) |

---

## 1. Context & Problem Statement

**[Fidonis GmbH](https://www.fidonis.de)** builds and maintains the **papAIa stack**.
Fidonis stands for technological sovereignty: bringing local, modular AI to mid-sized
companies — dependable, secure, and vendor-independent. papAIa is the product form of
that position, and its core promise is **data sovereignty**: all data stays with the
customer.

That promise is not a feature that can be added later. It constrains every structural
decision in this document — where state lives, which component may talk to which,
where an authorization check happens, and what may be replaced without asking a
vendor. Where a trade-off appears below, sovereignty is the axis it was resolved on.

### The problem this architecture solves

Up to 0.7.0 the stack was a **monolithic Compose bundle**: application-specific
services (Paperless + MCP-Paperless, Qdrant-RAG + Ingest, n8n, SearXNG, Firecrawl)
were pulled in via `include:` into `papaia/src/docker-compose.yml`, and their
integration points were **hard-wired into the Core configs**:

- `librechat.yaml` → `mcpServers` / `allowedDomains`
- Keycloak realm clients + audience mappers

Every additional application grew the Core and coupled it to services that not every
customer needs. That scales neither across a fleet of customers nor over time — and it
quietly works against the promise, since a customer who cannot remove what they never
asked for is not sovereign over their own deployment.

### The answer, shipped in 1.0.0

A **Lean Core** (generic platform services only) with **empty, app-agnostic intake
points**, made extensible through a unified **add-on contract** — each add-on
self-contained and version-pinned, addable or removable at any time without modifying
the Core. Fidonis maintains a catalogue of first-party add-ons against exactly the
same contract a customer would use for their own; there is no privileged path.

---

## 2. Target Architecture — Overview

### 3-Tier Model + 4 Cross-cutting Principles

```
                   ┌─────────────── PAPAIA PLATFORM (per customer, one host) ────────────────┐
                   │                                                                            │
  Tier 1: CORE     │  Identity (Keycloak + oauth2-proxy)  Ingress (Nginx Proxy Manager)       │
  (always,         │  AI-Runtime (LibreChat + LiteLLM [+ LocalAI])  Management (papaia-manager) │
  self-sufficient) │  Web search (SearXNG + Firecrawl + MCP bridge + reranker, opt-in)          │
                   │  Integration Registry = EMPTY, app-agnostic intake points:                │
                   │    mcpServers slot · Realm (base clients) · NPM host                       │
                   │                           ▲     ▲     ▲                                    │
                   │          (4 seams: network · OIDC · MCP · Ingress)                        │
                   └───────────────────────────┼─────┼─────┼──────────────────────────────────┘
                                               │     │     │   unified add-on contract
               ┌───────────────────────────────┘     │     └───────────────────────────────┐
               │                                      │                                      │
  Tier 2: CURATED FIDONIS ADD-ON CATALOG              │   Tier 3: CUSTOMER APPLICATIONS     │
  (Fidonis-maintained, subscribable, own repo each)   │   (bespoke per customer, own repo   │
                                                       │    each, same contract)             │
  • Documents (Paperless + paperless-mcp-rbac)         │   • Pattern A: wrap existing app    │
  • Automation (n8n)                                   │     with MCP server                 │
  • further first-party modules                        │   • Pattern B: ingest customer      │
                                                       │     data into RAG (role-scoped)     │
                                                       │   • Pattern C: hybrid               │
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
| Identity | Keycloak (OIDC provider), oauth2-proxy (forward auth for services without native OIDC) |
| Ingress | Nginx Proxy Manager (NPM) |
| AI-Runtime | LibreChat (chat UI), LiteLLM (LLM gateway), LocalAI (opt-in local inference) |
| Management | papaia-manager (opt-in; dashboard, add-on lifecycle, host health and backup scheduling UI) |
| Web search | SearXNG, Firecrawl, the Firecrawl MCP bridge and a reranker (opt-in, internal-only) — a generic capability of the chat layer, not an application |
| Mail | `smtp-relay`, a Postfix relay (opt-in, profile `smtp`) that holds the mail server's credentials once; Keycloak and the add-ons that attach it send through it without any — see [ADR 0007](adr/0007-outbound-mail-through-an-internal-relay.md) |
| RAG | Qdrant, `qdrant-mcp-rbac` and `qdrant-ingest` (opt-in, profile `rag`) — retrieval is a capability of the chat layer that an installation either wants or does not; see [ADR 0004](adr/0004-rag-system-as-optional-core-profile.md) |

The Core's integration points are hollowed out to **empty, app-agnostic intake
points** — no hard-wired application references. The Core is **self-sufficient**:
it starts and runs fully without any add-on.

### Core intake points

```
librechat.yaml     →  mcpServers: []        (empty, populated by add-ons)
                       allowedDomains: []    (empty, populated by add-ons)
Keycloak realm     →  Base clients          (add-on clients registered additively)
NPM                →  Core hosts            (add-on hosts added additively)
```

---

## 4. Tier 2 — Curated Fidonis Add-on Catalog

Optional modules built and maintained by [Fidonis](https://www.fidonis.de), consumed
as **versioned images** and pinned per installation. They use the **same** add-on
contract as customer apps — one mechanism — but are quality-assured against each Core
release and listed in a catalogue an operator can subscribe to.

Difference from Tier 3 = **ownership / trust / catalogue listing**, not the mechanism.
This is deliberate: a curated catalogue is only worth trusting if nothing in it needs
a capability the contract does not give everyone else. Fidonis maintaining an add-on
buys a customer support and tested upgrade paths, not access to a back door in the
Core.

---

## 5. Tier 3 — Customer Applications

Bespoke per customer, own repo each, same contract. Three recurring patterns:

| Pattern | Description | Example |
|---|---|---|
| **A** — MCP-wrap | Wrap an existing app with an OIDC/RBAC MCP server | CRM system + `mcp-crm-rbac` |
| **B** — RAG ingest | Ingest customer data into the core RAG system (profile `rag`), role-scoped retrieval | Product database → Qdrant |
| **C** — Hybrid | MCP-wrap + RAG ingest combined | ERP with MCP + knowledge RAG |

"Onboarding a new customer app" = create repo from template + add entry to `deployment.yaml`.

---

## 6. The Add-on Contract

### 6.1 Add-on file structure

```
papaia-addons/<name>/
├── papaia-app.yaml          # Manifest: declarative contract (all metadata)
├── docker-compose.yml       # App + associated MCP server, on its OWN network
├── .env.example             # App secrets template (seeded into $PAPAIA_CONFIG_DIR/addons/<name>/.env)
├── integration/             # The 4 seams as fragments (all optional)
│   ├── keycloak/            # OIDC client + audience mapper JSONs
│   ├── librechat/           # mcpServers + allowedDomains fragment (YAML)
│   └── nginx/               # Optional ingress snippet
└── README.md                # Self-contained manual integration path (public-clean)
```

> **No `papaia-app.sh` per add-on.** All lifecycle verbs (`install`,
> `start`, `stop`, `remove`, `uninstall`) are executed centrally by `papaia-ctl`
> — no per-add-on delegation script needed.

### 6.2 `papaia-app.yaml` — Manifest schema

```yaml
name: <short-name>                 # Unique identifier (a-z, 0-9, -)
version: <semver>                  # Add-on version: counts changes to the bundle,
                                   # not to the software in it (see `components`)
addon_repo: papaia-addon-<name>    # Canonical add-on name, for catalogue display
requires:
  addon_api: 1                     # Contract generation the add-on is built against
                                   # (integer or list, e.g. [1, 2]);
                                   # checked against the Core's ADDON_API window
papaia_compat: ">=<semver>"        # Fallback: SemVer range against the Core version
description: "<description>"

components:                        # optional: the software the add-on packages
  - id: <id>                       # shown by `papaia-ctl addon components` and the manager
    name: <display name>
    role: primary                  # primary | sidecar
    kind: upstream                 # upstream | fidonis
    image_var: <COMPOSE_VAR>       # the compose variable whose default names the image;
                                   # the add-on's .env can pin another tag through it
    version: "<tag>"               # that default's tag (quoted)
    source: https://<project>      # optional link
    pinned: false                  # only for a floating tag such as postgres:18

networks:
  app_network: ${PAPAIA_PROJECT:-papaia}-<name>-net
                                   # Add-on's own bridge network. A literal name
                                   # still works; the ${…} template (addon_api 2)
                                   # is resolved against the core .env by the
                                   # orchestrator so the bridge is scoped per
                                   # deployment. Use the same string in the
                                   # add-on's own compose `networks.<key>.name`.
                                   # PAPAIA_PROJECT (not COMPOSE_PROJECT_NAME):
                                   # the add-on is brought up with `-p <addon>`,
                                   # which pins COMPOSE_PROJECT_NAME during
                                   # compose interpolation.
  attach: [nginx-proxy-manager, librechat]
                                   # Core containers to attach to the app network;
                                   # validated against the Core Compose service names

local_ca_env:                      # optional: env vars pointing at the local
  <service>: [SSL_CERT_FILE]       # Keycloak CA certificate — cleared via override
                                   # when auth_provider=external_oidc

integration:
  keycloak:
    clients: [integration/keycloak/<client>.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/<name>.yaml   # optional
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
requires:
  addon_api: 2
papaia_compat: ">=0.8.0"
description: "Paperless-ngx document management + OIDC/RBAC MCP server"
networks:
  app_network: ${PAPAIA_PROJECT:-papaia}-paperless-net
  attach: [nginx-proxy-manager, librechat]
local_ca_env:
  paperless: [REQUESTS_CA_BUNDLE]
  paperless-mcp: [SSL_CERT_FILE]
integration:
  keycloak:
    clients: [integration/keycloak/paperless.json, integration/keycloak/mcp-paperless.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/paperless.yaml
  nginx:     integration/nginx/paperless.conf
```

**Data sovereignty:** `mcp-paperless` validates the Keycloak bearer token + audience and
forwards requests as `X-Papaia-Remote-User` — Paperless enforces its own per-user RBAC.
No admin credential in the MCP layer.

### 6.4 Example B: `papaia-addon-qdrant-rbac`

> Illustration of a vector-store add-on. The RAG system the stack ships itself is the
> core profile `rag` since 1.5.0 ([ADR 0004](adr/0004-rag-system-as-optional-core-profile.md));
> the manifest below shows the shape for a customer's own store.

```yaml
name: qdrant-rbac
version: 0.1.0
addon_repo: papaia-addon-qdrant-rbac
requires:
  addon_api: 1
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
```

**Data sovereignty:** `mcp-qdrant-rbac` validates the bearer token + audience and scopes
Qdrant queries to the collections the user has access to (JWT per collection ACL).

---

## 7. The 4 Seams (Add-on Integration Points)

All 4 seams are **standardised**, not hand-wired. Which seams an add-on uses
is optionally declared in the manifest.

### Seam 1 — Network: "Core attaches to app"

The add-on defines its own bridge network. The orchestrator automatically generates
a **Compose override** (`$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml`)
that references the app network as `external: true` and attaches the Core containers
listed under `attach:` (e.g. `nginx`, `librechat`) to the app network.
The Core Compose remains unchanged.

When `networks.app_network` is a `${PAPAIA_PROJECT:-papaia}-<name>-net` template
(addon_api 2), the orchestrator resolves it against the rendered core `.env` before
writing the override, so each deployment on a shared host gets its own add-on bridge.
`PAPAIA_PROJECT` mirrors `COMPOSE_PROJECT_NAME` (`papaia`, or `papaia-<env>`) under a
key `docker compose` does not special-case, so the name still scopes correctly when
the add-on is brought up with `-p <addon>`. The default `papaia` resolves to the
legacy `papaia-<name>-net`, so single-deployment hosts are unaffected.

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

An override whose network does not exist yet — the add-on has never been started —
is skipped rather than failing the Core start. `papaia-ctl start --addons` brings
the add-ons up first, so the networks exist by the time the overrides are applied.

The optional mail relay is attachable like any other core service. An add-on that lists
`smtp-relay` under `attach:` can send mail to `smtp-relay:587` — plain SMTP, no login, no
TLS, from an address in the configured sender domain — and needs no credentials of its own.
The service exists from `ADDON_API` generation 3, so such an add-on declares
`requires.addon_api: 3`; an older core reports it incompatible instead of failing on an
unknown service. The profile `smtp` has to be on for the service to exist, and every
container on an attached network can use the relay, so attach it only to add-ons you trust.

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

### Seam 4 — Ingress (optional)

Optional NPM proxy host entry for the add-on UI. Added additively via the
Nginx fragment mechanism (or NPM API).

---

## 8. Inversion of Control — Orchestrator `papaia-ctl`

The orchestrator lives in `papaia/tools/papaia-ctl` and is therefore part of
the public Core repo (community-usable). It reads the **deployment manifest**
(`$PAPAIA_CONFIG_DIR/deployment.yaml`) and invokes the appropriate
`docker compose` command for each add-on in the correct order.

**New add-on = clone repo + `papaia-ctl addon install <name> --path=../papaia-addons/<name>`.**
No Core changes required.

### Available verbs

| Command | What happens |
|---|---|
| `papaia-ctl setup` | Create config directory, seed `.env`, generate secrets, render configuration, write `deployment.yaml` |
| `papaia-ctl start [--addons] [--profiles=LIST]` | Copy Core `.env` from config bundle into checkout → render config → start Core. With `--addons`: also start active add-ons, and gate the start on their compatibility. |
| `papaia-ctl stop [--clean-up] [--addons]` | `docker compose stop` (stop containers, do not remove). With `--clean-up`: `docker compose down` (remove containers, keep volumes). With `--addons`: same for active add-ons. |
| `papaia-ctl upgrade [--version=X.Y.Z] [--dry-run]` | Move the installation to a release: check active add-ons against the target, take a restore point, check out the tag, re-execute from the new tree, run the pending migrations, re-render, start. Downgrades are refused. |
| `papaia-ctl backup [--retention-period-days=N] [--only=SEL[,SEL]]` | Hot backup of `$PAPAIA_CONFIG_DIR`, every Core volume, and every add-on volume and data bind mount into a timestamped restore point. `--only` (`module:`, `addon:` or `volume:` selectors, as for `restore`) archives just those units — never the config directory — and records the scope in the restore point; a selector that matches nothing exits 2 and writes no archive. A scoped restore point is restored with `restore-scoped`; a plain `restore` of it is refused. |
| `papaia-ctl backup-delete --restore-point=ID [...]` | Delete specific restore points — the snapshot directory and its `backup.yaml` entry. Repeatable / comma-separated; every id is validated before anything is removed; only catalogued directories inside the backup directory are touched; the stack is not stopped |
| `papaia-ctl restore [--restore-point=ID] [--list] [--only=SEL[,SEL]]` | Restore a catalogued restore point. Containers are removed and recreated around the restore, not merely stopped. `--only` (`module:`, `addon:` or `volume:` selectors) scopes both the teardown and the restart to the selected units, leaving everything else running; it reads the `version: 2` manifest and is refused with `--restart-clean`, a config-directory selection, or the `manager` profile. |
| `papaia-ctl uninstall [--clean-up] [--addons]` | Core `down` → permanently delete `$PAPAIA_CONFIG_DIR`. With `--clean-up`: also delete volumes. With `--addons`: also stop active add-on containers. Warning + confirmation required. |
| `papaia-ctl npm-provision` | Provision the bundled Nginx Proxy Manager's proxy hosts from the rendered configuration |
| `papaia-ctl keycloak-role-sync` | Reconcile the bundled Keycloak's realm roles, composites and protocol mappers against the rendered realm template, and grant `papaia-admin` to every holder of the legacy `admin` role. Runs on every `start`; no-op with an external OIDC provider |
| `papaia-ctl status [--json] [--profiles=LIST] [--addons]` | Read-only. Match the services the Compose files declare for the active profiles against the containers Docker reports, per `de.fidonis.module` and per profile. A declared service without a container is `missing` ("not deployed"); an unreachable Docker daemon is reported as such, not as an outage. |
| `papaia-ctl doctor [--json] [--skip=CHECK[,CHECK]]` | Read-only preflight and diagnostics: Docker/Compose version, disk space, what Docker's data takes (`docker_usage`, a report that never `warn`s or `fail`s), memory, CPU load, GPU (for a LocalAI GPU variant), published ports, DNS, clock synchronization, certificate expiry, the mail relay and its mail server (`smtp`, only while the `smtp` profile is on), add-on compatibility and container health, each `pass`, `warn`, `fail` or `skip`. Exit 2 if any check fails. Works before `setup`. |
| `papaia-ctl addon install <name> --path=` | Seed config bundle → register in `deployment.yaml` → generate override → render Core → print Keycloak checklist. **Starts nothing.** |
| `papaia-ctl addon components [<name>] [--json]` | Read-only. List the software each registered add-on bundles (the manifest's `components`: name, version, role, image variable), with the tag the add-on's `.env` pins instead of the catalog's marked as overridden. |
| `papaia-ctl addon check [--target-core=PATH]` | Evaluate all active add-ons against the current — or a candidate — Core and print OK / INCOMPATIBLE / UNKNOWN. Exit 2 if any are incompatible. |
| `papaia-ctl addon start <name>` | Copy `.env` from config bundle into checkout → render Core → `docker compose up -d` |
| `papaia-ctl addon upgrade <name> --path=DIR [--dry-run [--json]]` | Move the add-on to the version in `DIR`: preconditions → compatibility gate → plan (`--dry-run` stops here) → values for new `CHANGE_ME` keys → add-on scoped restore point → seed the new keys, repoint `path`/`version`, keep the old ones as `previous` → render → `docker compose up -d --remove-orphans` if it was running. Nothing changes before the restore point; a failed start is not rolled back. |
| `papaia-ctl addon rollback <name> [--restore-data]` | Repoint to `previous` (the gate runs against the current core), forget it, recreate the add-on. With `--restore-data`: also restore the restore point the upgrade took (`restore-scoped`). |
| `papaia-ctl addon list [--json]` | Read-only. Every registered add-on with path, version, components, compatibility verdict and `previous`. |
| `papaia-ctl addon stop <name>` | `docker compose stop` (stop containers, do not remove) |
| `papaia-ctl addon stop <name> --clean-up` | `docker compose down` (remove containers, keep volumes) |
| `papaia-ctl addon remove <name>` | Remove override → re-render Core → `active: false` in manifest. **Containers untouched, config bundle kept.** |
| `papaia-ctl addon uninstall <name>` | Remove override + deployment entry → delete config bundle → `docker compose down` |
| `papaia-ctl addon uninstall <name> --clean-up` | Like `uninstall` + `docker compose down -v` (also delete volumes) |

The Compose calls above run with `-p <addon directory name>`, the add-on's `docker-compose.yml` and the
core `.env`. When that file is missing (a deleted or half-written add-on directory), Compose cannot build
the project, and with the core `.env` in play it would act on the core project instead of the add-on.
`stop` and `down` (so `addon stop`, `addon uninstall` and the add-on part of `stop --addons` and
`restore`) therefore run as `docker compose -p <name> stop|down` alone, without `-f`, `--env-file` or the
caller's `COMPOSE_*` variables, and address the containers, networks and (with `-v`) volumes labelled with
that project. `addon start` and every other verb that needs the file are refused with an error.

### Upgrading an add-on

An upgrade does not write into the directory the add-on is registered at. The new version is a
directory of its own (`--path`, same directory name as before, because Compose derives the project
name from it), and `addon upgrade` repoints `path` and `version` in `deployment.yaml` and keeps the
entry it replaced as `previous` (`path`, `version`, and the id of the restore point taken for the
upgrade). `addon rollback` repoints back and clears `previous`, so one step back is possible and the
files it needs are still on disk. The decision and its trade-offs are in
[ADR 0008](adr/0008-upgrade-add-ons-by-repointing-to-immutable-snapshots.md).

What an upgrade does is decided by a pure function of the two manifests, the two `.env.example`
files and the configuration bundle (`tools/lib/addon_upgrade.py`), so `--dry-run --json` shows what
the real run will do ([`tools/schemas/addon-upgrade.schema.json`](../tools/schemas/addon-upgrade.schema.json)):

- **Keys.** A key the bundle lacks is new and is classified by its value in the candidate's
  `.env.example`: `GENERATE_*` becomes a fresh secret, `CHANGE_ME` is a value to supply (a
  default from `env_prompts` or from the core counts as supplied, everything else is in
  `needs_input` and blocks the upgrade until a prompt or `--answers-file` answers it),
  `REPLACE_WITH_*` or a key under `env_replace_secrets` is a Keycloak client secret to copy in
  after the client is imported, and anything else is copied as shipped. Values already in the
  bundle are never changed; keys that disappeared stay.
- **Components and manifest.** The `components` delta by id, and the changes in `version`,
  `requires.addon_api`, `networks.attach`, new `env_replace_secrets` and new Keycloak clients and
  mappers.
- **Compatibility.** The verdict of the gate against the current core; a refused plan is printed
  with `"blocked": true` and exits 2.

The restore point is `backup --only=addon:NAME`: the add-on's volumes and writable data
directories, never the configuration directory. Rolling back with `--restore-data` replaces them
through `restore-scoped`. An add-on that keeps writable data in its own directory instead of a named
volume does not carry that data to the new directory.

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
├── papaia-addons/                       # Tier 2 and Tier 3 add-ons
│   ├── paperless/
│   │   ├── papaia-app.yaml
│   │   ├── docker-compose.yml
│   │   ├── .env.example
│   │   └── integration/
│   │       ├── keycloak/
│   │       ├── librechat/
│   │       └── nginx/
│   │
│   └── <name>/
│       ├── papaia-app.yaml
│       ├── docker-compose.yml
│       ├── .env.example
│       └── integration/
│           ├── keycloak/
│           └── librechat/
│
├── papaia/                              # Tier 1 — Core repo (Fidonis/papaia, public-bound)
│   ├── docs/                            # Architecture docs, ADRs, add-on spec
│   ├── VERSION                          # Platform SemVer
│   ├── ADDON_API                        # Contract-generation window (current / min)
│   ├── src/                             # Core implementation
│   │   ├── docker-compose.yml           # Lean Core (mounts exclusively from $PAPAIA_CONFIG_DIR)
│   │   ├── .env.example                 # Core env template
│   │   ├── ai/                          # LibreChat, LiteLLM, LocalAI, MCP bridge, reranker
│   │   ├── infra/                       # Keycloak realm template, NPM, oauth2-proxy, mail relay
│   │   ├── manager/                     # papaia-manager (optional Core service)
│   │   └── services/                    # SearXNG, Firecrawl base config
│   └── tools/                           # Orchestrator
│       ├── papaia-ctl                   # setup · start · stop · upgrade · backup · restore · addon …
│       ├── deployment.template.yaml     # Template for deployment.yaml in config directory
│       ├── migrations/                  # Release migrations run by `upgrade`
│       └── lib/
│           ├── render_core.py           # 3-layer merge → config directory
│           ├── gen_override.py          # Generate Seam-1 override → config directory
│           ├── compat.py                # ADDON_API / papaia_compat evaluation
│           ├── backup.py · upgrade.py   # Restore points, release migration runs
│           └── …                        # secrets · resolve · addons · deployment · …
│
└── papaia-config/                       # Config directory (per customer/env, NOT a repo, gitignored)
    ├── deployment.yaml                  # SSOT: active add-ons + versions + Core profiles
    ├── .env                             # Secrets + env vars (gitignored, seeded at setup)
    ├── addons/                          # Add-on config bundles (canonical source, backed up)
    │   └── <name>/
    │       └── .env                    # Add-on secrets (seeded at install, sticky)
    ├── ai/librechat/librechat.yaml      # GENERATED (base + add-ons + overlay)
    ├── ai/litellm/config.yaml           # GENERATED
    ├── infra/keycloak/realm-import/     # GENERATED (secrets baked in, always render-owned)
    ├── manager/                         # papaia-manager state: catalogs · installed · tiles · jobs
    ├── certs/                           # GENERATED local CA + Keycloak server certificate
    ├── migrations/applied.json          # Which release migrations have run
    ├── overrides/                       # GENERATED docker-compose.<addon>.override.yml
    └── overlay/                         # Customer overlay (hand-authored, survives re-render)
        └── ai/librechat/librechat.yaml
```

### Repo mapping

| Workspace path | GitHub repo | Visibility |
|---|---|---|
| `papaia/` | `Fidonis/papaia` | public-bound |
| `papaia/tools/` | Part of `Fidonis/papaia` | public-bound |
| `papaia-addons/<name>/` | `Fidonis/papaia-addons` | public-bound |
| `papaia-config/` | — (no repo) | gitignored, per customer/env |

Add-ons are registered explicitly by path — there is no auto-discovery — so the
directory name above is a convention, not a requirement. What matters is the
`path:` recorded in `deployment.yaml`.

### Distributed installations

By default an installation is one host. A distributed installation spreads the core services
over several machines (nodes), described by the `topology` block of `deployment.yaml` (§12,
ADR 0009). One node is the **controller**: it runs `papaia-ctl`, holds the configuration
tree, the CA keys and the SSH keys, and runs papaia-manager and the RAG system. Every other
node holds only its **bundle**, which every render writes to
`$PAPAIA_CONFIG_DIR/nodes/<name>/bundle/`: the env files, rendered configuration and
certificates of the services placed there.

```
controller (internal)                         edge node
papaia-config/                                /srv/papaia-node/
├── link-ca/ca.key, ca.crt     (never leaves) ├── checkout -> releases/<version>
├── nodes/edge/ssh/id_ed25519  (never leaves) ├── releases/<version>/   (git archive)
├── nodes/edge/link/node.key   ── bundle ──>  ├── config/               (the bundle)
└── nodes/edge/bundle/         ── bundle ──>  │   └── link/haproxy.cfg, node.pem, ca.crt
                                              ├── audit.log
                                              └── .ssh/authorized_keys (forced command)
```

**Control channel** (ADR 0010). The controller reaches a node over SSH as the unprivileged
user `papaia`. The node's `authorized_keys` entry forces `papaia-ctl node-shell`, which
accepts only an allowlist of verbs and checks every name against the node's bundle:
`ping`, `version`, `status`, `doctor`, `compose-up|down|stop|restart|ps|pull|logs`,
`bundle-put`, `checkout-put`, `image-load`, `hook`. Bundles and releases travel as archives
over the same channel, and the node needs neither Git nor access to GitHub. The controller
runs its own node through the same shim (the `local` executor).

**Link gateway** (ADR 0010). Each node runs one HAProxy container (`src/infra/link-gateway/`,
profile `link-gateway`, never loaded on a single host). For a service that runs on another
node, it carries the service's name as a network alias and listens on its usual port, so
`litellm:4000`, `keycloak:8443` and `librechat:3080` keep working everywhere. It wraps the
connection in mutual TLS with a certificate of the link CA (separate from the Keycloak CA)
and hands it to the target node's link port. That port routes by SNI and lets each client
node reach only the services the edge table in `tools/lib/link.py` allows. The inner
protocol is passed through untouched, and a peer that is down means a refused connection.
`papaia-ctl topology firewall` lists the connections between nodes that this opens.

---

## 10. Naming Conventions

### Add-ons

| Context | Name schema | Example |
|---|---|---|
| Canonical add-on name (`addon_repo:`) | `papaia-addon-<name>` | `papaia-addon-paperless` |
| Workspace directory | `papaia-addons/<name>/` | `papaia-addons/paperless/` |
| Manifest field `name:` | `<name>` (short name) | `paperless` |
| `deployment.yaml` → `path:` | path as passed to `addon install` | `../papaia-addons/paperless` |
| Docker network | `${PAPAIA_PROJECT:-papaia}-<name>-net` | `papaia-paperless-net` (default env) |
| Config bundle | `$PAPAIA_CONFIG_DIR/addons/<name>/` | `.../addons/paperless/.env` |

### Config directory

The config directory is named **`papaia-config`** and defaults to a sibling of the
checkout. It is selected **per invocation with a flag**, not through the
environment:

```bash
tools/papaia-ctl setup --config-dir=/srv/fidonis/papaia-prod/config   # absolute path
tools/papaia-ctl start --config-dir=/srv/fidonis/papaia-prod/config
```

`papaia-ctl` is flag-driven: exporting `PAPAIA_CONFIG_DIR` in a shell has no effect
on the CLI. The variable exists inside the generated `.env` files, where Compose
reads it to resolve the bind-mount sources. It must be an **absolute path** —
Compose resolves relative paths in `include:`d files against each file's own
directory.

### Internal structure

| Area | Path | Contents |
|---|---|---|
| Core implementation | `papaia/src/` | Compose, base templates, realm template |
| Orchestrator | `papaia/tools/` | `papaia-ctl`, render libraries, migrations |
| Add-on | `papaia-addons/<name>/` | Manifest, Compose, integration fragments |
| Config directory | `papaia-config/` | Generated configs, secrets, overlay, add-on bundles |

---

## 11. Cross-cutting Principles

### ① Data sovereignty (core promise)

This is the principle [Fidonis](https://www.fidonis.de) exists to deliver, and the one
the other three serve. It is claimed here in four enforceable parts rather than as a
posture:

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
| **Self-hosted** | Customer, or a guided installation | `papaia/README.md` + `papaia-ctl` |
| **Fidonis-managed** | Fidonis operates the installation single-tenant per customer | The same `papaia-ctl` commands, run by Fidonis rather than by the customer |

Both models produce the same runtime artifact from the same repos, driven by the same
published commands. The difference is who operates the installation, not what is
installed — and that is the point: a customer who starts on the managed model can take
over their own installation later, or hand it to someone else, without a migration and
without Fidonis's cooperation. Sovereignty that depends on the vendor's goodwill is not
sovereignty, so the architecture is built so that it does not.

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

- **Image-based distribution**: first-party add-ons as pinned images published by
  [Fidonis](https://www.fidonis.de) under `ghcr.io/fidonis/...`, not as source.
  Upgrade = `papaia-ctl addon upgrade` against the new version's directory; rollback =
  `papaia-ctl addon rollback`, one step back to the previous directory (see
  [ADR 0008](adr/0008-upgrade-add-ons-by-repointing-to-immutable-snapshots.md)).
- **Per-customer deployment manifest**: `deployment.yaml` in the config directory
  is the **single source of truth** per installation (Core profiles + active
  add-ons + versions + hosting type). Drives the orchestrator and update runs.
- **Idempotency throughout**: `setup`, `start` and `addon install` are re-runnable
  without side effects; rendering produces byte-identical output for unchanged
  inputs → unattended fleet updates possible. `papaia-ctl upgrade` exits 0 when the
  installation already runs the target release, so it is safe to schedule.
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
    - manager
  inference: local-first | external # LLM inference mode
  addon_api: 1                      # ADDON_API window served by this installation

addons:
  - name: paperless                 # Short name (= manifest field name:)
    path: ../papaia-addons/paperless   # Path as passed to `addon install --path=`
    version: 1.0.0                  # Pinned version
    active: true                    # false = installed but not integrated
    previous:                       # written by `addon upgrade`, cleared by `addon rollback`
      path: ../snapshots/5d07e8c4/paperless
      version: 0.9.0
      restore_point: 2026-10-25_10-00-00   # absent when no restore point was taken
  - name: qdrant-rbac
    path: ../papaia-addons/qdrant-rbac
    version: 0.1.0
    active: false                   # deactivated
```

### Topology (distributed installations)

An optional `topology` block describes an installation that runs on more than one machine.
Without it — the default, and every installation that existed before it — the installation
is a single host.

```yaml
topology:
  mode: single | distributed
  controller: <node>                # runs papaia-ctl; config tree, CA keys, SSH keys
  link:
    port: 7443                      # the port each node's link gateway listens on
  nodes:
    <name>:
      address: <ip or host>
      executor: local | ssh         # local only for the controller
      ssh: {user: papaia, port: 22, host: <optional>}
      root: /srv/papaia-node        # node directory; config dir <root>/config
      bind_ip: <optional>           # HOST_IP on that node (default 127.0.0.1 behind the proxy)
      gpu: none | nvidia | amd | intel | vulkan   # optional hint for LocalAI
  placement:                        # catalogue service -> node; default: the controller
    <service>: <node>
```

The unit of placement is a service of the catalogue in `tools/lib/topology.py`: a service is
one or two Compose profiles and everything they always bring along. On each node
`COMPOSE_PROFILES` names what starts there, while `PAPAIA_ACTIVE_MODULES` keeps the profiles
of the whole installation for what is decided cluster-wide (realm clients, proxy hosts, the
mail relay). In distributed mode the render projects one bundle per node into
`$PAPAIA_CONFIG_DIR/nodes/<name>/bundle/` with only that node's env files, configuration,
certificates and overrides. The decision is recorded in ADR 0009.

### Active set

The orchestrator derives the active set (which add-ons participate in render and
`docker compose up`) from `active: true` entries. The manifest itself is never
deleted by `install`/`remove` — only the `active` flag and `version` are updated. `upgrade`
and `rollback` change `path` and `version` and write or clear `previous`.

---

## 13. Customer Overlay — 3rd Render Layer

The config directory contains an optional `overlay/` directory for customer-specific
customisations. Overlay files are **never overwritten by `papaia-ctl`** and survive
every re-render.

### 3-layer merge

```
Repo base  (papaia/src/<target>)
  + sum of active add-on fragments  (<addon-path>/integration/<target>/)
  + customer overlay  ($PAPAIA_CONFIG_DIR/overlay/<target>/)
  ───render──▶  effective config in $PAPAIA_CONFIG_DIR/<target>
```

Structured files (YAML / JSON) are deep-merged, with lists appended and
de-duplicated; any other file type is taken wholesale from the highest layer that
provides it. The overlay always wins. Rendering runs on `setup`, on every `start`,
and on every `addon` operation — there is no separate render command.

A layer that does not parse (a typo in a hand-edited overlay) stops the render with one
`ERROR:` line that names the file and the position, and a structured layer must have a
mapping at the top level, because anything else would replace the whole configuration. The
render stops before `docker compose up`, so a running stack is not touched.

**Applying an overlay means recreating the services that read it.** A render replaces each
target with a new file, and most targets are bind-mounted single files, so a running
container keeps the one it was created with. `papaia-ctl stop --clean-up --profiles=<profile>`
followed by `start` recreates the group; a restart is not enough.

**Previewing a draft.** `python3 -m lib.cli --repo-root R --config-dir C render-preview
--target=<path> --overlay-file=<file>` merges a draft overlay onto the same layers `render`
uses, in memory, and prints one JSON document: `{"ok": true, "target", "structured",
"current", "preview", "changed"}`, where `current` is the effective text with the overlay on
disk and `preview` the text with the draft, or `{"ok": false, "error", "line", "column"}`
when the draft does not parse. Nothing is written. Only the file targets of the render list
qualify. `papaia-manager` uses it for the effective-result view of its overlay editor.

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

**Enable the LibreChat memory agent** (`overlay/ai/librechat/librechat.yaml`). The
base config ships no memory model, and automatic extraction is opt-in. The overlay
adds the agent to the base `memory` section; the model must exist in LiteLLM:
```yaml
memory:
  agent:
    enabled: true
    provider: "Private-LLM"
    model: "my-chat-model"
```

**Web search against a SearXNG, Firecrawl or Jina on another private address**
(`overlay/ai/librechat/librechat.yaml`, plus the URL in `ai/librechat/.env`). LibreChat
blocks web-search connections to private addresses unless the exact `host:port` is
exempted; the base config already exempts the bundled services and the overlay list is
appended to it:
```yaml
webSearch:
  allowedAddresses:
    - "10.0.0.5:8080"
```

**SearXNG engine tuning** (`overlay/services/searxng/settings.yml`):
```yaml
search:
  default_lang: de
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
| Backend | FastAPI (Python) | Imports `lib.*` from the checkout directly — no reimplementation |
| Frontend | HTMX + Jinja2 | No build step; stays in the Python ecosystem |
| Docker API | `docker.sock` + `papaia-ctl` subprocess | The CLI stays the single implementation of every verb |
| Catalogue | `catalogs.yaml` in the config directory | Git-backed sources, resolvable offline once fetched |
| Auth | Native OIDC (realm client `papaia-manager`) | Role-gated in the backend; no sidecar to keep in step |
| Ingress | Nginx fragment | Analogous to add-on ingress rules |

### Distribution

The manager is **not built from this repo**. `src/manager/` carries only its
`docker-compose.yml` and `.env.example`; the application itself ships as the pinned
image `ghcr.io/fidonis/papaia-manager:<version>` from its own repository. Bumping
the manager is therefore an image-tag change in the Core, decoupled from the
platform release cadence.

### Path parity

The manager imports `lib.*` from `${PAPAIA_WORKSPACE_DIR}/papaia/tools` and forwards
paths to `papaia-ctl` as subprocess arguments. Both sides must therefore agree on
what a path means, which rules out the usual `-v host:/container` remapping:

```yaml
papaia-manager:
  image: ghcr.io/fidonis/papaia-manager:<version>
  profiles: [manager]
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock          # compose operations
    - ${PAPAIA_WORKSPACE_DIR}:${PAPAIA_WORKSPACE_DIR}    # host path === container path
    - ${PAPAIA_CONFIG_DIR}:${PAPAIA_CONFIG_DIR}
    - ${PAPAIA_BACKUP_DIR}:${PAPAIA_BACKUP_DIR}          # restore-point catalogue
    - ${PAPAIA_CONFIG_DIR}/certs:/certs:ro               # local CA for internal TLS
  user: "${UID}:${GID}"                                  # writes match setup's owner
  group_add: ["${DOCKER_GID}"]                           # access to docker.sock
```

`DOCKER_GID` must match the GID owning `/var/run/docker.sock` on the host; the
container itself runs as a non-root user.

Path parity is the reason the `manager` profile is **Linux-only**: Docker Desktop
on Windows and macOS cannot present a host path unchanged inside the container, so
the mounts above cannot be satisfied there. Every other profile is unaffected —
`--no-manager` leaves an otherwise identical stack.

Mounting the Docker socket grants the container root-equivalent access to the host.
That is inherent to an orchestration UI; the mitigations are role gating on every
route, an audit log, and keeping `MANAGER_ADMIN_ROLE` a host-administrator role.

### Catalogues and snapshot pinning

A catalogue is a source of add-ons — a Git repository or a local directory —
registered at runtime in `catalogs.yaml`, not shipped with the Core. Each is scanned
for top-level `papaia-app.yaml` manifests.

Installing materialises a **pinned snapshot at a specific commit** rather than
tracking a branch, so refreshing a catalogue never moves code out from under a
running container. Upgrading is an explicit operation and the manager does not implement it
itself: it stages the candidate commit as a snapshot of its own (a new directory, never an
overwrite), shows what `papaia-ctl addon upgrade --dry-run --json` reports — new settings,
component changes, compatibility — asks for the values the new version needs, and applies it
with `papaia-ctl addon upgrade`. Rolling back is `papaia-ctl addon rollback`. This is the
add-on-side counterpart to `papaia-ctl upgrade` for the Core — same principle, same
guarantee that nothing changes underneath a running installation without a deliberate
step. It needs a core that has these verbs (1.8.0 or newer); an older core shows the action
with a hint instead.

### State

The manager keeps its state in `$PAPAIA_CONFIG_DIR/manager/`, so it is covered by
`papaia-ctl backup` like everything else:

| File | Contents |
|---|---|
| `catalogs.yaml` | Configured add-on sources (`type: git`, URL, ref, enabled) |
| `installed.yaml` | Which add-on came from which catalogue, at which commit — catalogue provenance on top of `deployment.yaml` |
| `tiles.yaml` | Dashboard tiles, grouped, with per-tile `visibility: all \| admin` |
| `settings.yaml` | The manager's own settings, one section per topic: branding (name, second line) and the host-monitoring interval |
| `branding/` | The uploaded logo |
| `preferences.yaml` | The interface language each account chose, keyed by its OIDC subject; kept apart from `settings.yaml` so an account changing its language never makes an administrator's save fail as stale. A damaged file reads as "no preference" and is never overwritten |
| `schedule.yaml` | The backup schedule |
| `notifications.yaml` | The notification recipients and the events each receives (mode 0600: a webhook URL can carry a secret) |
| `notifications-state.json` | What the notification checks already reported, so a restart repeats nothing |
| `overlay-history/` | The previous versions of the overlay files edited in Settings > Overlay (the latest 20 per file, readable by the owner only) |
| `jobs/` | Records of long-running operations (install, start, upgrade) |
| `audit.log` | Who triggered which operation |

`deployment.yaml` stays the single source of truth for the *installation*;
`installed.yaml` only records catalogue provenance on top of it.

The RAG pages keep their data elsewhere (see *RAG management* below): in the catalog files and
the staged uploads of the `rag` module under `$PAPAIA_CONFIG_DIR/ai/rag/`, which the ingester
reads from the same place.

### Roles

| Variable | Default | Grants |
|---|---|---|
| `MANAGER_ADMIN_ROLE` | `manager-admin` | Full access except Users — add-ons, catalogues, jobs, dashboard, host, backup, mail, settings (modules and overlay) and, while the `rag` profile is active, the RAG pages |
| `MANAGER_USER_ROLE` | `user` | Dashboard only; admins hold it implicitly |
| `MANAGER_IDENTITY_ADMIN_ROLE` | `papaia-admin` | The Users page and `/api/v1/users`, `/api/v1/roles`: the accounts, their roles and sessions, and the realm's roles themselves. A tier above the admin role: `manager-admin` alone is not enough |

All three name **realm roles**; the backend reads them from the access token's `roles`
claim.

The Users page has no credential of its own: the manager calls Keycloak's Admin API with the
access token of the signed-in account, so Keycloak applies that account's rights. That is why
`papaia-admin` carries `manage-users`, `view-users`, `query-users`, `view-realm` and
`manage-realm` of the `realm-management` client as composites (realm template for a new install, the role sync for an
existing one). See [ADR 0006](adr/0006-manage-accounts-with-the-signed-in-users-token.md).

### Integration with the 4 seams

| Seam | Manager integration |
|---|---|
| Seam 4 (Ingress) | `manager.${PAPAIA_HOST}` → Nginx forward to the container port |
| Seams 1, 2, 3 | Not used — the manager is a Core service, not an add-on. It registers its own realm client through the Core realm template, not through an add-on fragment. |

### Status model

Each add-on resolves to one of five states, merged from the catalogue scan,
`deployment.yaml`, and live Docker container labels:

| State | Meaning |
|---|---|
| `available` | Present in a catalogue, not installed |
| `installed` | Registered in `deployment.yaml`, containers not running |
| `running` | Active and up |
| `inactive` | `active: false` — bundle and secrets kept, out of the render |
| `unmanaged` | An operator-managed checkout outside the manager's snapshot directory |

`unmanaged` is what keeps the CLI and the UI from fighting over the same add-on: a
checkout installed by hand with `papaia-ctl addon install --path=…` is surfaced and
reported, but the manager does not claim ownership of its source tree.

### Add-on components and removal

An add-on's own version counts changes to its bundle, not to the software in it. When the
catalogue's manifest lists the bundled `components` (see the add-on contract), the gallery card
names the primary ones and the detail page lists all of them with their role, the version an
update brings and the tags an operator pinned in the add-on's `.env`. The manager reads the
manifest and that file itself, so the pages need no particular core; `papaia-ctl addon components`
prints the same facts on the command line.

*Remove* takes the add-on's containers down (`addon stop --clean-up`, the volumes stay) before
`addon remove` marks it inactive, because the latter alone leaves them running; if the stop
fails the add-on stays active. It is refused while the add-on's `docker-compose.yml` is missing:
a core before 1.7.0 aims its Compose call at the core project then (see the add-on lifecycle table
above), so a manager on such a core could take its own stack down.

### Long-running operations

Installs, updates and lifecycle verbs shell out to `papaia-ctl` and can take minutes
(image pulls, container starts). They run as queued jobs processed by a single
worker, with live status and streamed log output.

`restore` is the exception. `papaia-ctl restore` tears the Core down before unpacking
archives, and the manager is a service of that same stack — an in-process run would
be killed by its own teardown step. It therefore runs in a **detached container cloned
from the manager's own container spec** (same image, binds, user and groups, so path
parity holds by construction), started without `--rm` so its status and log survive
for the recreated manager to read. Stack-wide stop and restart use the same mechanism
for the same reason.

### Host health and scheduled backups

**Host health.** The Host page and the host row of the sidebar status row read the
machine underneath the deployment, not the containers. The manager measures nothing
itself: it runs the Core's read-only `papaia-ctl doctor --json` (the `memory`, `cpu`,
`gpu`, `time_sync`, `disk_space` and `certs` checks, and `docker_usage` in a run of its
own, because sizing every volume costs the daemon real work) and shows the Core's
verdicts and thresholds, so the page and a shell on the host cannot disagree. A Core
without `doctor` — detected by the absence of `lib/doctor.py` in the workspace, not by
comparing versions — leaves the host out, and the page says so instead of reporting a
problem. A reading is cached for a configurable interval (10 seconds to 60 minutes,
60 seconds by default) and shared between everyone who has a page open. The host's
counts reach every role through the sidebar status row; names, paths and certificate
details stay on the admin-only page.

**Scheduled backups.** The Backup page can start `papaia-ctl backup` on a schedule held
in `$PAPAIA_CONFIG_DIR/manager/schedule.yaml` and run by a scheduler inside the manager
process, so the host needs neither a cron job nor a systemd timer. A scheduled run takes
the same path as the *Create backup* button (same job, log and audit entry); while a
restore, an upgrade or another job is running it is held back and retried. After a
restart a missed run is made up, and the retention period is only passed on while the
newest successful restore point is recent, so a series of failed backups cannot prune
every usable one.

### Modules and overlay

Settings has three tabs: *Manager* (the manager's own configuration), *Modules* and *Overlay*.
The last two keep no second source of truth; both drive the core.

**Modules.** The tab is the one place in the manager that switches the optional modules
(LocalAI with its accelerator variant, web search, the RAG system and the mail relay) on and off.
It stores the choice with the core's own `setup`, so validation, sticky values and generated
secrets stay in one implementation, and starts the module's profile. Which volumes a module owns,
what its settings consist of and which questions `setup` still needs answered when the module is
switched on (the public URL of LocalAI and of Qdrant, the relay's mail server) come from the core's
read-only `module-info`; deleting a module's data (its volumes) and/or its settings is the core's
`module-purge`, offered only for a module that is switched off, with the module's name typed back
as confirmation. Both are internal commands of the core's Python entry point, not `papaia-ctl`
verbs, and the manager passes them typed options only: one module, never `--force`, `--env` or any
other part of the configuration. A core without them (before 1.6.0) still switches LocalAI and web
search and switches modules off keeping everything.

**Overlay.** The tab edits the files under `$PAPAIA_CONFIG_DIR/overlay/` for LibreChat, LiteLLM
and SearXNG ([§13](#13-customer-overlay--3rd-render-layer)). The effective result shown next to the
draft is the core's `render-preview`: the draft merged in memory, nothing written. *Apply* saves
the file and recreates the services that read it as a queued job. Before every Apply, Discard and
roll-back the previous file is copied to `$PAPAIA_CONFIG_DIR/manager/overlay-history/` (the latest
20 per file), and if the services do not start with the new file the previous one is put back
automatically. A file changed on the host after it was opened is detected by its revision and
refused instead of overwritten.

### Mail and notifications

The Mail page (System) has two tabs. *Mail Server* edits the mail server behind the optional relay
of the `smtp` profile ([ADR 0007](adr/0007-outbound-mail-through-an-internal-relay.md)). Saving is
a queued job that runs the core's own `setup` with the values; the password reaches that child
process in its environment only, never in an argument or the log. While the relay is on, it is
recreated and the Keycloak realm gets it as its mail server (`papaia-ctl keycloak-role-sync`), which
is what lets the Users page offer a mailed link. *Notifications* belongs to the manager: recipients
(an email address or a webhook URL) choose which events they receive — a failed job, an overdue
backup, a service that stopped or turned unhealthy, an available update, an expiring certificate.
The checks run on an interval and after every job, each event is reported once per occurrence
(`notifications-state.json` keeps what was reported), email goes through the relay and a webhook
gets a JSON `POST`. A notification carries no job log and no error text.

### Language

The interface is available in English and German. Every account chooses *Automatic*, *English* or
*Deutsch* in the account menu at the bottom of the sidebar, and the choice is stored on the server
by the account's OIDC subject (`preferences.yaml`), not in the browser, so it is the same on every
computer the account signs in from. *Automatic*, which is also what an account has before it
chooses, follows the browser's language and falls back to `MANAGER_DEFAULT_LOCALE` (English unless
set). A language is one catalogue file in the manager's image; the code does not change for a new
one. Log lines, the audit log, job logs and the emails and webhooks of notifications stay in
English.

### Dashboard widgets

The default tiles (LibreChat, LiteLLM, Keycloak, NGINX Proxy Manager and Qdrant) show an icon that
ships inside the manager image, so nothing is loaded from another site; a tile of an older
`tiles.yaml` without an icon picks the bundled one up by its name, and an icon set on the tile
always wins. The logos stay the property of their owners.

Besides links, a dashboard group can hold widgets: cards that show one piece of live state and
link to the page that explains it (the installed release, the age of the newest backup, free disk
space, running services, open warnings, the nearest certificate expiry). They are `type: widget`
tiles in `tiles.yaml`; a tile without a `type` is a link, so an existing file reads as before. A
widget reads what the manager already holds (the backup catalogue, the host check, the container
snapshot, the last upgrade check) instead of measuring again, refreshes on its own and honours the
tile's `visibility` on the server, so a widget set to administrators is absent for the user role.

### RAG management

While the core's optional `rag` profile is active ([ADR 0004](adr/0004-rag-system-as-optional-core-profile.md)),
the manager is the interface of the RAG system ([ADR 0005](adr/0005-manage-the-rag-ingester-from-papaia-manager.md)):
`qdrant-ingest` has had no web interface of its own since 1.0.0. Administrators get a *RAG*
category in the sidebar with four pages and a computed *Qdrant* tile on the dashboard. The
pages are reached through the same admin dependency as every other surface and then answer
404 on a deployment without the profile.

| Page | What it manages |
|---|---|
| *Connections* | The vector databases the system works with. The connection `default`, the integrated Qdrant with the stack's api-key, is created by the manager itself. |
| *Collections* | Qdrant collections and the realm roles that may read or write each of them, stored in the format `qdrant-mcp-rbac` reads, so the MCP server enforces them unchanged. |
| *Embedding* | Files put into a collection through the ingester, from an upload or from the documents folder, as *add and update* or *replace the collection*. |
| *Ingest Jobs* | The ingester's jobs, their runs file by file, the credentials of remote sources (stored encrypted) and the catalog file. |

The manager does not run ingestion itself. It writes the ingester's own catalog in
`$PAPAIA_CONFIG_DIR/ai/rag/catalog/` (`connections.yaml`, `jobs.yaml`, `secrets.yaml`) with a
compare-and-swap write, asks it to reload, checks that it serves what was written and starts
and follows runs through its REST API; the ingester mounts the directory read-only. Files for
the Embedding page are staged in `$PAPAIA_CONFIG_DIR/ai/rag/documents/uploads/` and deleted
after a run that succeeded without a failed document. Without the `manager` profile, which
runs on Linux hosts only, there is no interface and the catalog files are edited by hand.

---

## 15. Roadmap

| Phase | Content | Status |
|---|---|---|
| **Phase 0** — Spec & blueprint | Architecture spec, add-on contract schema, ADR definition; validate manifest schema against existing examples | Completed |
| **Phase 1** — Lean Core + pilot Paperless | Decouple app-specific includes + hard-wired configs from Core; `paperless` as first companion add-on; `papaia-ctl` verbs; end-to-end verification | Completed (1.0.0) |
| **Phase 2** — Harden tooling | Full add-on lifecycle in `papaia-ctl addon`; merge helpers (YAML merge, Keycloak registration, override network generation); per-customer deployment manifest drives composition; compat gating via `ADDON_API`; `upgrade` with release migrations; `backup` / `restore` | Completed (1.0.0) |
| **Phase 3** — Catalog + customer apps + fleet | Migrate the remaining first-party modules into the catalogue (automation, search; RAG became the optional core profile `rag` instead, see ADR 0004); companion app template repo for customers (patterns A + B); fleet update distribution (version pinning, compat gating, rollback) | In progress — `papaia-manager` ships the catalogue UI; per-module migration ongoing |

---

## 16. Open Items

| Item | Description | Recommendation |
|---|---|---|
| Add-on visibility | Generic Tier 2 add-ons public-bound or private? | **Decided**: public-bound (`Fidonis/papaia-addons`) |
| MCP reachability | East-west (librechat on the app network) vs. via ingress | **Decided**: east-west via the Seam-1 `attach:` list; ingress remains optional per add-on |
| `PAPAIA_CONFIG_DIR` default | Sibling `<repo>-config` as today vs. `/srv/fidonis/<env>/config` | **Decided**: sibling by default, any absolute path via `--config-dir` |
| Compat policy strictness | Warn vs. hard-fail on compat violation | **Decided** ([ADR 0002](adr/0002-addon-core-compatibility-gating.md)): hard-fail in production, warn in dev mode; `--force` as escape hatch |
| Add-on catalogue source | Where the manager reads available add-ons from | **Decided**: git-backed catalogues in `$PAPAIA_CONFIG_DIR/manager/catalogs.yaml`; the manager fetches and installs from them |
| Pre-release channels | `>=x.y.z-rc` or separate channel for beta add-ons | Open — `upgrade --version` already accepts a pre-release tag; there is no channel concept yet |
| Rollback granularity | Restore point vs. per-add-on rollback | Partly addressed — `restore --only=` scopes a restore to selected modules, add-ons or volumes; a bad upgrade is still undone by restoring the point `upgrade` took beforehand, now optionally only for the units it broke |

---

## 17. Verification Checklist

### Architecture validation

- [x] **Contract reality check**: the Paperless and Qdrant integrations are expressed
  without loss as `papaia-app.yaml` + fragments.
- [x] **Mapping dry-run**: the formerly hard-wired entries (`librechat.yaml
  mcpServers`, realm clients) are documented as target fragments.

### End-to-end verification

| Check | Expected result |
|---|---|
| `papaia-ctl setup` | Creates `papaia-config/`, seeds `.env` + `deployment.yaml`, generates secrets |
| `papaia-ctl addon install paperless --path=../papaia-addons/paperless` | `papaia-config/addons/paperless/.env` created; repos unchanged |
| Hash `papaia/` + `papaia-addons/` before/after install | **Identical** (repo-pristine proof) |
| `papaia-ctl addon start paperless` | `.env` present in checkout; the add-on's containers running |
| Render (×2) | Identical outputs (idempotency) |
| Overlay applied | `papaia-config/overlay/ai/librechat/librechat.yaml` appears in the rendered output |
| `docker compose -f papaia/src/docker-compose.yml config` | Valid; Core services only; no Paperless |
| Seam-1 override active | `librechat` + `nginx-proxy-manager` attached to `papaia-net` **and** `papaia-paperless-net` |
| Config bundle seeding | Add-on client secret (random) + app keys present; a second `install` changes nothing |
| `papaia-ctl start --profiles=keycloak` | Only Keycloak + its database start |
| `papaia-ctl start --addons` | Core profiles + add-on containers + overrides active |
| `papaia-ctl addon check` | OK for every active add-on; exit 0 |
| `papaia-ctl upgrade --dry-run` | Prints current version, target version, and the migrations that would run |
| `papaia-ctl backup` then `restore --list` | The restore point appears in the catalogue with result `ok` |
| `papaia-ctl stop --clean-up --addons` | All containers removed; volumes kept |

### Self-sufficiency audit

The published artifact has to stand on its own — a reader with this repository and
nothing else must be able to deploy and operate papAIa. Before a release:

- [ ] Every deployment and operations step is reachable from `README.md` alone
- [ ] No document depends on a resource the reader cannot obtain
- [ ] All seams described in purely technical terms (LibreChat `mcpServers`, OIDC client, NPM)
- [ ] Every command named in the docs exists in `tools/papaia-ctl`

---

## 18. Maintainer

papAIa is developed and maintained by **[Fidonis GmbH](https://www.fidonis.de)** —
technological sovereignty for mid-sized companies: local, modular AI that is
dependable, secure, and vendor-independent.

The architecture above is the technical expression of that position. Fidonis publishes
the platform under the MIT license, maintains the first-party add-on catalogue, and
operates installations for customers who prefer not to run one themselves — using the
same commands and the same artifact documented here.

**[www.fidonis.de](https://www.fidonis.de)**
