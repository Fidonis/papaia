# papAIa Platform — Architecture Specification

| Field | Value |
|---|---|
| **Version** | 1.9.0 |
| **Date** | 2026-11-20 |
| **Status** | Active — describes the 1.9.0 release as built |
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
| Knowledge map | `knowledge-map-mcp` (opt-in, profile `knowledge-map`) — a role-trimmed MCP directory of the installation's knowledge sources, rendered from the `knowledge:` declarations of active add-ons and core modules; see [ADR 0013](adr/0013-knowledge-map-as-optional-core-profile.md) / [ADR 0014](adr/0014-knowledge-manifest-key-and-map-format.md) / [ADR 0016](adr/0016-knowledge-map-governance-metadata.md) (governance metadata) and [docs/knowledge-map.md](knowledge-map.md) |

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
│   ├── ai/librechat/agents/  # optional: LibreChat agents (addon_api 4, Seam 3)
│   ├── ai/librechat/prompts/ # optional: LibreChat prompts (addon_api 4, Seam 3)
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
  addons:                          # optional (addon_api 4): add-ons this one builds on;
    - <name>                       # each must be installed and active, a mapping adds
    - name: <name>                 # a SemVer range against that add-on's `version`
      version: ">=<semver>"
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
                                   # validated against the Core Compose service names.
                                   # papaia-audit-db and papaia-audit-schema are
                                   # never attachable
                                   # (docs/audit.md)
  join_addons:                     # optional (addon_api 4): services of this add-on
    - addon: <required add-on>     # that join the app network of an add-on listed
      services: [<service>]        # in requires.addons; the others stay isolated.
                                   # Written to overrides/addons/docker-compose.
                                   # <name>-join.override.yml. Single host only: a
                                   # network cannot span two nodes.
  egress:                          # optional (addon_api 7): the add-on's way out
                                   # through papaia-egress (docs/egress.md)
    network: ${PAPAIA_PROJECT:-papaia}-<name>-egress
                                   # an internal: true network of the add-on's own
                                   # compose file (checked), named ${PAPAIA_PROJECT}-
                                   # <name>-..., not a core network, not the add-on's
                                   # app_network, not declared by another add-on;
                                   # papaia-egress joins it under the alias
                                   # egress-<name> (overrides/docker-compose.
                                   # <name>.egress.override.yml)
    allow:                         # host:port pairs this add-on may reach; exact
      - host: api.example.org      # names (at least two labels, not egress-*,
        ports: [443]               # papaia-*, *.docker.internal) or IP addresses,
                                   # no wildcards. The protected hosts override the
                                   # list; internal addresses need the operator's
                                   # security/egress-internal-targets.yaml

client_keys:                       # optional: public keys of the module's own clients
  - client: flow-engine            # a registered client of this module (not public,
    jwks_file: keys/engine.jwks.json  # not bearer-only); the public JWK set the module
                                   # writes below $PAPAIA_CONFIG_DIR/addons/<name>/;
                                   # realm sync registers it with private_key_jwt

local_ca_env:                      # optional: env vars pointing at the local
  <service>: [SSL_CERT_FILE]       # Keycloak CA certificate — cleared via override
                                   # when auth_provider=external_oidc

integration:
  keycloak:
    clients: [integration/keycloak/<client>.json]  # imported by hand, unless named below
    client_secrets:                    # optional (addon_api 4): clients `start` creates
      integration/keycloak/<client>.json:
        secret_env: KC_<CLIENT>_CLIENT_SECRET    # GENERATE_SECRET in .env.example
        root_url_env: <APP>_SERVER               # optional, replaces rootUrl
    client_mappers:                # not for an audience of a platform tool server
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/<name>.yaml   # optional; none needed for an
                                                  # `exposes` entry of kind mcp
  nginx:     integration/nginx/<name>.conf        # optional; or, since addon_api 12,
                                                  # a list of ingress entries:
  # nginx:
  #   - host_key: <name>           # a-z, 0-9, -; unique within the add-on
  #     service: <compose service> # the add-on's service behind the host
  #     port: 8080                 # 1..65535
  #     websocket: false           # optional
  #     max_body: 10m              # optional request-body limit
  # The core names the hosts (`<host_key>.<domain>`, operator rename INGRESS_HOST_<KEY>;
  # host key `apps` is the app host on INGRESS_APP_DOMAIN), creates the bundled proxy's
  # hosts and attaches the proxy to app_network; `papaia-ctl proxy list` prints them.

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
  OTHER_API_KEY:
    secret: true
    default_from_addon: "other-addon:OTHER_API_KEY"
                                   # addon_api 4: value from the config bundle of an
                                   # add-on in requires.addons that lists the key under
                                   # `exports`; filled at install, never echoed. Sticky
                                   # like every bundle value: after the other add-on
                                   # rotates it, set the new value in this add-on's
                                   # $PAPAIA_CONFIG_DIR/addons/<name>/.env and run
                                   # `papaia-ctl addon start <name>`. Installing again
                                   # keeps the old value; `addon uninstall` + `install`
                                   # also regenerates this add-on's own GENERATE_*
                                   # secrets while its volumes stay.
  AUTO_SECRET:
    secret: true                   # required for GENERATE_* values without _KEY suffix
    label:  "Database password"

exports: [OTHER_API_KEY]           # optional (addon_api 4): bundle .env keys other
                                   # add-ons may read via default_from_addon; no other
                                   # key of this add-on is ever read by another add-on

env_replace_secrets:               # optional: keys replaced by papaia-ctl
  OIDC_CLIENT_SECRET:              # after the Keycloak import
    hint: "Copy from Keycloak"     # hint is shown in the configuration overview

actions:                           # optional (addon_api 4): maintenance actions,
  reset:                           # run by `papaia-ctl addon run <name> reset` as
    service: maintenance           # `docker compose run --rm <service> <args>` in the
    args: ["--reset-existing"]     # add-on's project; fixed arguments only. Give the
    description: "Restore the initial data"  # service a compose profile (e.g.
                                   # `profiles: [actions]`) so `addon start` skips it.
    destructive: true              # optional: callers (papaia-manager) confirm first

install_notes:                     # optional: further numbered steps in the checklist,
                                   # a list or a single string; display only
  - "Set MW_SERVER in the add-on .env when the wiki is not on the default URL."

knowledge:                         # optional (addon_api 6): the knowledge sources
  sources:                         # this add-on contributes to the knowledge-map
    - id: <name>.<source>          # profile — see ADR 0014/0015 and
      system: "<human name>"       # docs/knowledge-map.md for the full field
      coverage: "<what is here>"   # reference. Rendered only while the
      not_covered:                 # knowledge-map profile is active; older
        - { what: "<content class>", instead: <other-source-id> }  # cores ignore it.
      example_queries: ["..."]
      required_roles: [user]
      access:                      # one entry per way to reach the source
        - { via: mcp, target: <name>, key_tools: [...], best_for: "..." }
        - { via: rag, target: Qdrant, collection: <name>, best_for: "..." }
      governance_proposal:         # optional suggestion, never effective on its own;
        classification: internal   # the operator decides in governance.yaml (ADR 0016)
        personal_data: ordinary
        data_subjects: [employees]
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
> the Core Compose service names; an unknown name is `INCOMPATIBLE`. Each
> `requires.addons` entry must name an add-on that is active in `deployment.yaml`,
> and its manifest `version` must satisfy the entry's range; a missing, inactive
> or too old add-on is `INCOMPATIBLE`, a malformed entry an error. Each
> `networks.join_addons` entry must name an add-on from `requires.addons` and
> list at least one service; anything else is a malformed manifest. Policy:
> hard-fail in production, warning in dev mode
> (`PAPAIA_COMPAT_MODE` → `deployment.yaml → mode:` → default `enforce`);
> `--force` demotes `INCOMPATIBLE`, never a malformed manifest.
>
> **Generation-gated keys.** From generation 7 on, a manifest key that needs a
> newer core is never silently ignored: a manifest using `exposes` (7),
> `personal_settings` (8), `pki` (11), the ingress-entry list of
> `integration.nginx` (12) or `volumes` (13, the backup declaration: a core
> below it would archive a volume the add-on leaves out) is `INCOMPATIBLE` on
> a core whose window ends below
> that generation, even when `requires.addon_api` lists an older generation
> the core serves. The reason names every missing generation and its meaning,
> for example against `papaia` v1.8.0 (window `[1..3]`):
> `missing generations 4, …, 12; 12: add-on ingress integration.nginx (ADR 0023)`.
> A key above the generations the manifest declares is a warning; malformed
> ingress entries (unknown field, port outside 1..65535, duplicate `host_key`)
> are a malformed manifest.

#### Contract generations

The `ADDON_API` file at the repository root states the window and the binding
meaning of every generation; `tools/lib/compat.py` (`ADDON_API_GENERATIONS`)
and the contract snapshot `tools/tests/test_contract_surface.py` carry the
same table. All generations are additive, so `min` stays 1. The decision
records for generations 7 to 12 use the numbers reserved in
[`docs/adr/README.md`](adr/README.md). Generation 13 (`volumes[]` with
`backup: include|exclude` and a reason) is described with `backup` in the
README.

| Gen. | Meaning | ADR |
|---|---|---|
| 1 | Base contract: `networks.app_network`, `networks.attach`, `integration.<service>` fragments, Keycloak clients, `env_prompts`, `requires.addon_api` | 0002 |
| 2 | `networks.app_network` may be the `${PAPAIA_PROJECT:-papaia}-<name>-net` template | — |
| 3 | `smtp-relay` (profile `smtp`) attachable | 0007 |
| 4 | `requires.addons`, `networks.join_addons`, `exports`, `env_prompts.<key>.default_from_addon`, `actions`, LibreChat agents and prompts, managed Keycloak clients | — |
| 5 | `speaches` and `chatterbox` (profile `voice`) attachable, render target `ai/voice/chatterbox.yaml` | 0011 |
| 6 | `knowledge:` | 0014 |
| 7 | `exposes:` (also `exposes.yaml` of core profiles), rendering of `services.json` and `groups.json`, declared roles, exchange scopes `aud-<addon>`, service accounts, `models.needs`; `keycloak`, `litellm`, `papaia-audit`, `papaia-egress` attachable | 0017, 0018 |
| 8 | `personal_settings:`; `me-web` and `prefs` attachable | 0020 |
| 9 | `connections` attachable, registry client | 0021 |
| 10 | Install-time approval hook: approval at install up to the highest declared class | 0017 (addendum) |
| 11 | `pki:`, internal TLS under the `kritis` security profile | 0019, 0022 |
| 12 | Add-on ingress `integration.nginx` | 0023 |

This table fixes what each generation means. The rendering and runtime
behaviour behind generations 7 to 12 arrive with their own changes; until a
part is in place, the generation number already lets add-ons declare it and
lets older cores refuse them.

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

#### Header identity: the proxy side of the Paperless gate

Because Paperless trusts `X-Papaia-Remote-User`, the header must reach it from the MCP
server only. The add-on puts a gate (`paperless-gate`) into Paperless' network namespace;
Paperless listens on its container's loopback, and the gate passes a request only when
`X-Papaia-Gate` carries the secret of one of its callers. Every caller has its own secret.
The core holds the proxy's and meets this contract (`tools/lib/paperless_gate.py`):

| Part | Core behaviour |
|---|---|
| Header strip | `npm-provision` writes `more_clear_input_headers "X-Papaia-Remote-User" "X-Papaia-Gate";` as a managed block into the proxy manager's `server_proxy.conf` (included in every proxy host, also hand-made ones), through the proxy container; core-created hosts carry the line themselves. `proxy_set_header` at server level is ignored by the proxy manager's own `location /` and is not used |
| Paperless route | While the add-on `paperless` is active and `PAPERLESS_PUBLIC_URL` (add-on bundle `.env`) is a host name without a port: proxy host to `paperless:8001` (the gate, reached through the Paperless service name), advanced configuration with its own `location /` that clears the identity header and includes `/run/papaia/paperless-gate/nginx.conf`. An existing host for that name with other settings is corrected. Without a valid secret the route is not created and `npm-provision` exits 1 |
| Secret | `setup` generates it once (sticky): `$PAPAIA_CONFIG_DIR/secrets/paperless-gate/proxy/secret` (raw value, for the gate) and `nginx.conf` (`more_set_input_headers "X-Papaia-Gate: …";`), directory 0700, files 0600. 32–512 characters of `A-Z a-z 0-9 . _ ~ + / = -`; a file that is a symbolic link, larger than 4 KiB or not of that form is refused and never passed on. The proxy mounts the directory read-only at `/run/papaia/paperless-gate`; no other core service mounts it. It ships with the proxy to its node in a distributed installation |
| Rotation | `papaia-ctl secrets rotate paperless-gate/proxy`: new value in both files, reload of the running proxy; the gate reads the new value when the add-on starts again |
| Audit | One `papaia.audit/1` row in `audit/papaia-ctl.jsonl` for the creation (`paperless_gate_secret_created`) and each rotation (`paperless_gate_secret_rotated`), with the correlation id and the target, never the value |
| Networks | For `paperless`, only `nginx-proxy-manager` joins the add-on's `app_network`. Every other core service in `networks.attach` joins `${PAPAIA_PROJECT:-papaia}-paperless-front` (external in the core override); the add-on side (`overrides/addons/docker-compose.paperless-front.override.yml`, applied at `addon start`) creates that network with `paperless-mcp` on it. Without `paperless-mcp` in the add-on's compose file the other services are not attached at all |

The gate's port (8001), the mount of the secret directory into the gate and the MCP
server's own secret belong to the add-on.

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

**Managed clients (addon_api 4).** A client listed under `clients` and named
under `client_secrets` with its `secret_env` is created without the Admin UI:
`addon install`
generates the secret like any `GENERATE_SECRET` value, and `papaia-ctl start`
(the `keycloak-role-sync` step after `docker compose up`), `papaia-ctl addon
start <name>` and `papaia-ctl addon upgrade <name>` create the client from its
export when the realm lacks it, with that secret and, when `root_url_env` names
a set key, that root URL. An existing client only gets its secret aligned with
the add-on `.env`, as core clients do, so a secret changed there takes effect on
the next start. Nothing else about an existing client is changed. A secret that
is still a placeholder in the add-on `.env` (`GENERATE_*`, `REPLACE_WITH_*`,
`CHANGE_ME`, empty), as an install from before the add-on named its client
there carries, is generated and written to the `.env` before the `.env` reaches
the add-on's checkout, so the add-on's containers start with the value the
client gets. `addon start` and `addon upgrade` wait only a few seconds for
Keycloak; when it is not up, they say so and `start` or `papaia-ctl
keycloak-role-sync` creates the client later. Within `start --addons`, the
add-ons start before Keycloak may be up, so the clients are left to the
`keycloak-role-sync` step that follows. Clients not named under
`client_secrets` keep the manual import, and with `auth_provider=external_oidc`
nothing is created. A core without this step ignores `client_secrets` and shows
the manual import for the same clients, so an add-on can use it without raising
`addon_api`.

In a distributed installation, `keycloak-role-sync` runs on Keycloak's node
with that node's bundle, which carries only the add-ons placed on that node.
The clients of add-ons placed on other nodes are therefore not created by
`start`; until that is supported, import them by hand as before.

### Realm sync of declared clients

The core is the only writer of realm-wide objects. `papaia-ctl realm sync` (also the
last part of every `keycloak-role-sync` step, so of every `start`) reconciles the
`papaia` realm with three sources:

- the naming register `tools/lib/names_register.json`, a snapshot of the platform kit's
  register (release and commit in its `source`): every client, audience, role and
  service account with its owning repository and whether a client may exchange tokens;
- the `exposes:` sections of the active add-ons (generation 7): the module is the
  add-on's name in `deployment.yaml`, and the manifest's `name` must be the same (an
  add-on installed as `foo` whose manifest says `papaia-flow` is refused); its `roles`, the
  `audience` of each entry, `ui[].visible_for_roles`, `delegation` and `service_accounts`;
- `$PAPAIA_CONFIG_DIR/security/pairings.yaml`, which client may exchange tokens for
  which audience. The file grants exchange rights: it and its directory must belong to
  the user running `papaia-ctl` (or root) and must not be writable by group or others; a
  symbolic link is refused:

```yaml
format: papaia.pairings/1
pairings:
  - client: flow-engine        # a registered client with token exchange
    audience: mcp-paperless    # a registered audience
    effects: [r, w]            # r read, w write, d delete, x module interface
    state: confirmed           # or pending: waiting for approval, assigns nothing
    requested_by: host:anna    # who asked for it (host account; optional for a read pairing)
    confirmed_by: host:bert    # who confirmed it
```

`papaia-ctl` writes this file (see "Pairing approval" below); edited by hand, it is read
the same way. A confirmed pairing with effect `w` or `d` (a write pairing) must name two
different host accounts in `requested_by` and `confirmed_by`; otherwise the file is
refused (exit 2) and nothing is changed. Both fields are `host:<login>`.

#### Pairing approval

The confirmation of the pairings at installation (security 1.4): the signed bill of
materials of the checkout (`compat/suite-<version>.yaml`) may list the pairings the suite
ships with (`pairings:` with `client`, `audience`, `effects`). `setup` verifies the file
against the pinned release key, shows each pairing (client, audience, effects, read or
write, recorded state) and the sha256 of the list, and asks once. The digest is
`sha256` over a format line `papaia.pairing-list/1` followed by one line
`<client> <audience> <effects>` per pairing, sorted, effects in the order `rwdx`.

- Confirming the list (the question, or `setup --approve-pairings=<sha256>`, also
  `papaia-ctl pairing confirm --approve-pairings=<sha256>`) confirms every read pairing
  (no `w`, no `d`) and records every write pairing as `pending`, with the confirming host
  account as `requested_by`. A digest of another list confirms nothing.
- `-y` never confirms: `setup -y` without `--approve-pairings` completes, assigns nothing
  of the list and prints the command with the digest.
- A pairing the file already holds is left as it is, in whatever state; a second
  confirmation of the same list changes nothing. The realm sync assigns only confirmed
  pairings, so a write pairing of the bill of materials reaches no client until
  `papaia-ctl pairing approve` is run by another host account than the one that
  requested it. The same person is refused, whatever `approvals.four_eyes` says.
- `pairing approve --client --audience --effects` for a pairing outside the bill of
  materials: a read pairing is confirmed, a write pairing is recorded as `pending` with
  the caller as `requested_by` and needs a second person as well. `pairing revoke`
  removes a pairing in any state.

The acting person is the host account that runs `papaia-ctl` (`host:<login>`; as root,
the `SUDO_USER` that called `sudo`, which is believed only then); running `papaia-ctl` on
the host is the `papaia-admin` role of the installation. A host account that cannot be
named decides nothing. Every change is one `papaia.audit/1` row in the core's audit
outbox, writer `papaia-ctl/pairing`, event `exchange_right_changed`, operation
`pairing.confirm`, `pairing.request`, `pairing.approve` or `pairing.revoke`, object
`pairing` `<client>/<audience>`, `sub` the host account and the time; rows of the
installation step carry the digest of the list (`detail.statement_hash`). A refused
attempt is a row too (`result: denied`, `list_digest_mismatch` or `same_person`). A
decision takes effect with the next realm sync (`papaia-ctl start` runs it). Approval in
the manager is not part of this release.

Task sources ("My tasks", `GET /api/v1/me/tasks[/summary]`, read with the person's
token) are pairings like any other: Me (`papaia-me`) on `flow`, `papaia-data` and
`papaia-studio`; Studio (`papaia-studio-gateway`) on `flow` and `papaia-data`; Flow's
console (`flow-console`) on `papaia-data` and `papaia-studio`, each with effect `x`. The
module serving the audience limits such a pairing to these two routes (any other route
is answered with 403). `flow-console` may be paired with these two audiences only; a
pairing on any other audience (a connection `mcp-*` included) refuses the file.

What the sync manages:

| Object | Rule |
|---|---|
| Clients | Every register client of an installed module and the resource-server client of each registered audience a module declares. Attribute `papaia.managed=true` (a fixed value, no wildcard), `papaia.owner=<module>`, `fullScopeAllowed: false`, no implicit flow, no password grant; `standard.token.exchange.enabled` only where the register grants it; PKCE S256 on every managed client (the client policy `papaia-hardening` refuses an update of a managed client without it). Resource servers are bearer-only. A client-level mapper that adds an audience (audience mapper, audience resolve, any mapper writing `aud`) is removed: audiences come only from `aud-*` scopes. So is a client-level mapper that adds a role whatever the token scope says (hardcoded role, role name mapper, script mappers, any other mapper writing `roles`, `realm_access` or `resource_access`); Keycloak's own realm and client role mappers stay, they only show roles already in the token scope. Keycloak puts a client's own client roles, with their composites, into its token scope whatever `fullScopeAllowed` says; module roles are realm roles, so a client role of a managed client may include only other roles of that client, and every other composite (a realm role, a `realm-management` role) is removed, one audit row each. |
| Exchange scopes | One client scope `aud-<audience>` with exactly one audience mapper per audience of a confirmed pairing whose two sides are installed; protocol `openid-connect`, `include.in.token.scope=true`, `display.on.consent.screen=false`. An exchange scope maps no role: Keycloak adds a scope's mapped roles to every token issued with it, also an exchanged one, so every realm or client role mapped into a managed `aud-*` scope is removed (one audit row each). An existing `aud-*` scope (for example from a module's own setup) is adopted, marked `papaia.managed=true` and stripped of its role mappings in the same run. A managed client's optional scopes are exactly its confirmed pairings (and, for `flow-console`, its sign-in scope `aud-flow`), at most 12; an `aud-*` scope is never a default scope. It is also removed from the realm's default and optional scopes for new clients and from every unmanaged client that can obtain a token (pairings name only register clients, which are managed once their module is installed). A managed `aud-*` scope without a confirmed pairing is removed. |
| `offline_access` | Only `flow-engine` and `assist-gate`, and only while Flow (`flow.*`) or the assistant (`assist.*`) is installed and declares `delegation` with purposes of its own. It is removed from every other client that can obtain a token, including a holder client whose module is not installed, and from the realm's default scopes for new clients. A manifest of any other module that declares `delegation`, or a purpose of the other holder, is refused. |
| Roles | The declared module roles (registered, owned by the declaring module) and the platform roles `papaia-admin`, `papaia-auditor`, `papaia-confirm`. Each declared `<module>-admin` role joins the composite `papaia-admin`; `papaia-auditor`, `papaia-operator` and the admin role of a module that is gone are taken out of it. |
| Token scope | A sign-in client's token carries its module's roles, every existing role of a `visible_for_roles` and `papaia-confirm`. `papaia-admin` never enters a module client's scope (it is a composite of every module's admin role and of `realm-management` roles); an admin gets the module's own admin role through it. A role whose composite reaches outside that set or into client roles is left out and named in a note, and client roles are removed from a module client's scope, so an admin's token of a module client carries nothing of `realm-management` and no other module's admin role. A `visible_for_roles` entry of a module that is not installed waits until its role exists. |
| Shared scopes | Keycloak's default scopes (`basic`, `acr`, `profile`, `email`, `roles`, `web-origins`) and `offline_access`, which every managed client gets, map no role; `offline_access` maps only its own role, and that role is no composite. Any other role mapping, a composite of `offline_access`, a role-adding mapper and a mapper that adds an audience (audience mapper, any mapper writing `aud`; event `exchange_right_changed`) on these scopes are removed: they would put the role or a fixed audience into the token of every managed client, also an exchanged one. Keycloak's own audience resolve mapper of `roles` stays: it only adds clients whose client roles are in the token, and no client role reaches a managed client's token scope. Clients of the realm template share these scopes; apart from the realm hardening their own settings are not changed. |
| Exactly one audience | Per pair `(x, y)` of `aud-*` scopes that one managed client holds, a realm client policy `papaia-one-aud-<x>-<y>` (`x < y`): conditions `client-scopes` (type Optional) `aud-<x>` and `client-scopes` (type Optional) `aud-<y>`, no grant-type condition, profile `papaia-reject` with Keycloak's `reject-request` executor. A sign-in (authorization request, code, refresh, client credentials) or an exchange that asks for two or three `aud-*` scopes, with or without `audience`, is refused; a single one passes. With the task sources this gives (`aud-flow`, `aud-papaia-data`), (`aud-flow`, `aud-papaia-studio`) and (`aud-papaia-data`, `aud-papaia-studio`). The set is derived from the confirmed pairings on every run: missing policies are added, those of a revoked pairing removed (before its scope), at most 12 scopes per client (66 policies). The `scope` claim of an exchanged token is no source of rights; servers check `aud` only. `downscope-assertion-grant-enforcer` is not used. |
| Chain exchange | Only Studio → Data → connection. `papaia-data` is the chain holder: it signs nobody in and carries the client attribute `papaia.chain-holder=true`; the sync sets it there and removes it from every other client, whatever its value (`--check` reports such a client as `fail`, `realm sync` removes the attribute, event `exchange_right_changed`). While `papaia-data` is installed, the policy `data-chain` (conditions: grant type token exchange and `client-attributes` `papaia.chain-holder=true`, no scope condition) applies to every token exchange of the holder: `jwt-claim-enforcer` on the subject token, `azp` must match `upstream_origins` and `aud` must be exactly `papaia-data` (a multi-audience token is refused). `upstream_origins` is a list of client ids on Data's `exposes` entry (default and, in this release, only value `papaia-studio-gateway`); `assist-gate`, `flow-engine`, a Data client or any other client is refused, as is `downstream` or `upstream_origins` declared by any module but Data. A token of Data itself (a third hop) is refused too. |
| Data's own interface | `papaia-data-ui` signs persons in for Data's own interface (code flow with PKCE S256): confidential, client authentication `private_key_jwt` (Keycloak's `client-jwt`; the public key comes from Data's `client_keys` file, see "Client keys"; without a declaration the sync leaves a registered key in place), token exchange only for its own tokens, never an audience, no `offline_access`, no `aud-*` default scope. The policy `data-self` (conditions: token exchange, `papaia.owner=data`, and not `papaia.chain-holder=true`) admits as subject token only one with `azp` = `papaia-data-ui` whose `scope` carries no `aud-*` scope: its own session token, exchanged in one hop to `aud-mcp-*` or `aud-papaia-studio`; a token it got from an exchange and a token it received are refused. With a pairing on `aud-papaia-studio`, `data-handover` (conditions: token exchange, `papaia.owner=data`, `client-scopes` `aud-papaia-studio`) admits the handover to Studio only with a subject token of `papaia-data-ui`. The chain holder never re-exchanges a token of `papaia-data-ui`. Should the holder's attribute be missing, both Data clients fall under `data-self` and the chain is refused (fails closed). |
| Person-only audiences | Data (`papaia-data`), the knowledge map (`mcp-knowledge-map`), every module API for Me (`kind: me`) and every audience whose entry declares `identity: [person]`. Two policies each, condition `client-scopes` of type Any (also a default scope): `papaia-person-<a>-client-credentials` (`client_credentials` → `reject-request`) and `papaia-person-<a>-exchange` (token exchange → `jwt-claim-enforcer` `sid` present; service tokens carry no `sid`). A manifest that lists `service` for Data, the knowledge map or a Me module API is refused; `identity` must be distinct values out of `person`, `service`. |
| Flow's console | `flow-console` signs persons in (code flow, PKCE S256) and exchanges only its own tokens: it is never an audience, so a token issued for `flow` by another client cannot be exchanged with its credentials (403 `access_denied`). Client authentication `private_key_jwt` (`clientAuthenticatorType: client-jwt`); the key pair is Flow's. Declared in Flow's `client_keys`, the sync registers the public keys of Flow's key file (see "Client keys"); without a declaration it leaves a registered key in place. It never sets the redirect address. Its only default scope is `papaia-person`; `aud-flow` is an optional scope it asks for at sign-in, assigned from the declaration while Flow serves `flow` (no pairing); its other optional scopes are its task-source pairings. |
| `papaia-person` | The shared person claims, the only default scope of `flow-console`: `sub`, `auth_time` (Keycloak's `basic` mappers), `person_id` (= `sub`), `roles` (the realm roles of the token scope, flat), `groups` (full paths), `email`, `email_verified`; Keycloak adds `sid` itself, so the person-only policies accept the console's tokens. Exactly these mappers and no role mapping: any other mapper is removed (event `exchange_right_changed` if it adds an audience or takes claims from the request, `config_changed` otherwise), a changed one is replaced. Group ids (`group_ids`) have no Keycloak mapper and are not set. |
| `aud-*` default scopes | No client with token exchange holds an `aud-*` scope as a default scope: a managed client gets none, a declaration that would plan one is refused, and the scope is removed from every other client with `standard.token.exchange.enabled` (bearer-only included); `--check` reports it as `fail`. |
| Never an audience | No exchange client of the register but `papaia-data` is an audience: a client scope `aud-<client>` (for example `aud-flow-engine` or `aud-flow-console`) is removed, and so is every audience mapper naming such a client, on any client scope and any unmanaged client. LibreChat's fixed audience mappers on resource servers stay. |
| Claims parameter | A `oidc-claims-param-token-mapper` takes claims from the caller's request; on a managed client or a shared scope it is removed (event `exchange_right_changed`). |
| Realm hardening | Realm settings of the security profile `PAPAIA_SECURITY_PROFILE` (`standard` or `kritis`; see [configuration.md](configuration.md#security-profile-and-realm-hardening-variables)): `sslRequired`, access tokens 240 s, refresh-token rotation, brute-force protection, no username change, no self-registration, offline-session limits from the delegation lifetime of the installation (`delegations.idle_days` / `delegations.max_days`, default 90 / 180 days, set with `papaia-ctl delegations lifetime` up to 365 days each; `kritis` 7 / 30 days as default and upper bound; see [configuration.md](configuration.md#delegation-lifetime)), maximum age always on. Every client that can obtain a token: no password grant, no implicit flow, PKCE S256 if public with the code flow, no `standard.token.exchange.enabled` if public; redirect URIs, web origins and post-logout redirects of the realm template's sign-in clients from their configured hosts, of other clients only entries with a fully named host and a wildcard at most at the end of the path (Keycloak's own clients keep their relative URIs). Client profile and policy `papaia-hardening` (condition `client-attributes` `papaia.managed=true`; executors `pkce-enforcer`, `reject-implicit-grant`, `reject-ropc-grant`), written last in a run, after every managed client carries PKCE S256; the realm's other client profiles and policies stay. The rendered realm of a new installation carries the same target (`tools/lib/realm_hardening.py`) and no account with a fixed password: no test user, `admin` with the generated `KC_REALM_ADMIN_PASSWORD` as a temporary password. |
| Template accounts | With the master admin: an `admin` or `testuser` of an earlier realm template (its user name and e-mail address, the password unchanged since the account was created, no password change pending) gets `KC_REALM_ADMIN_PASSWORD` as a temporary password (`admin`) or is disabled (`testuser`, and `admin` without that value). One audit row each (`realm_sync.reset_template_password`, `realm_sync.disable_template_user`), never with the password. |
| Client keys | A module declares `client_keys` in its manifest (top level, next to `exposes`) for clients it owns: `client` and `jwks_file`, a path relative to its add-on configuration folder `$PAPAIA_CONFIG_DIR/addons/<module>/`. The module writes only its public JWK set there (0644; the private key stays in the module's own volume). The sync sets `clientAuthenticatorType: client-jwt`, `use.jwks.string=true`, `use.jwks.url=false` and `jwks.string` to exactly the keys of the file, for `flow-engine` too. Accepted: EC P-256 (`ES256`, point on the curve) or RSA of 3072 to 8192 bits (`RS*`, `PS*`), `use: sig`, a `kid`, one or two keys (old and new during a rotation); a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`), a symmetric key, an unknown member or field, a symbolic link or a file or folder writable by group or others refuses the run (exit 2, nothing changed). So does a declaration for a client of another owner (Flow declaring `assist-gate`), an unregistered or unmanaged client, a public or bearer-only client, a client declared twice, or a path with `..`. A changed file is applied by the next `realm sync` or by `papaia-ctl realm keys apply <module>`; Keycloak drops the old key with the update, so it is refused within 60 s. One audit row per change (`realm_sync.set_client_key`, `realm_sync.rotate_client_key`; event `config_changed` until the kit's `papaia.audit/1` schema carries `client_key_rotated`), never with key material. `--check` reports as `fail`: a declared client without key file, registered keys that differ from the file, and `client-secret` authentication of a declared client; with the file missing the sync removes the registered keys (the client cannot sign in). No step writes a realm admin token to disk; the sync uses its own account (`manage-clients`, `manage-realm`), no module gets an account with write access to the Admin API. |
| Service accounts | One client `svc-<module>-<purpose>` per entry of `service_accounts[]` (see "Declared service accounts" below): a service account and nothing else, `private_key_jwt`, only the declared audiences and roles. Undeclared accounts are reported by `--check` and removed by the sync. |
| Paperless name list | `$PAPAIA_CONFIG_DIR/security/paperless-gate/users.json`, see "Name list of the Paperless gate" below. |

Every input is checked before the first write: a refused declaration or pairings file
changes nothing (exit 2). A second run reports 0 changes. `--check` lists each deviation
as `fail: ...` and exits 1; it also prints the realm's current offline-session limits. An
unknown security profile or an offline-session value above the profile's limit refuses
the sync (exit 2). A managed client whose module is gone is reported and left in
place. Clients of the realm template (LibreChat, LiteLLM, oauth2-proxy, LocalAI, the
manager, the RAG resource servers) are not managed here until their modules declare
themselves.

Credentials. Every `realm sync` and every `--check` reads `KC_ADMIN_PASSWORD` (master
realm) from the Keycloak `.env` and signs in with it: it checks the sync account and,
with `realm sync`, creates it or realigns its rights and secret. The `keycloak-role-sync`
step before it on every `start` uses the master admin as well. The changes derived from
declarations and pairings are then made as the service account `svc-papaia-realm-sync`
of the `papaia` realm (client secret `KC_REALM_SYNC_CLIENT_SECRET` in the same `.env`),
not with a master token. That is what the dedicated account limits: the reconcile code
holds no token for the master realm or other realms, and its audit rows carry an identity
of their own. It does not keep the master password off the start path.

The account holds the `realm-management` roles `manage-clients` and `manage-realm` of the
`papaia` realm and nothing in the master realm. This is **not** a narrow right:
`manage-realm` is needed to create roles, add composites and map roles into a client's
scope, and it also allows a partial import, through which the account can give itself
`realm-admin` of the `papaia` realm. Its secret is therefore a second persistent secret
with `realm-admin` reach over `papaia`, usable with `client_credentials` from anywhere
that reaches Keycloak; treat it like `KC_ADMIN_PASSWORD`. Every run checks with the
master admin that the account holds exactly these two roles, in its role mappings and in
its token scope, with no full scope and no other realm or client role, that its user is
in no group and that Keycloak's `service_account` scope (shared by every service-account
client) maps no role; `--check` reports a deviation as `fail`, `realm sync` removes it.
First, before any write, the composites of its target roles (`default-roles-papaia` and
the two roles) are expanded: a `realm-management` role reached through them beyond these
two fails `--check` and stops `realm sync` without any write (the role definitions are
not changed). Keycloak 26.7.0 refuses changes to the
composites of its own `realm-management` roles (HTTP 403, also for the master admin), so
in practice this catches a grown `default-roles-papaia`.

Open maintainer decision on this trade-off. The security condition of the ticket asks
for "a dedicated admin service account with realm-management rights only for the papaia
realm". Alternatives:

- (a) Keep it as described: a separate audit identity and a papaia-realm token for the
  reconcile, against a second secret with `realm-admin` reach.
- (b) Keep the account, but check it only in `papaia-ctl setup` and a doctor step, not on
  every run: the realm sync then reads no master password on `start`. This only pays off
  if `keycloak-role-sync` also stops using the master admin on `start`.
- (c) Drop the separate account and run the realm sync with the master token the run
  already holds: one secret fewer, no separate audit identity, and the reconcile code
  holds a master-realm token. This departs from the ticket's condition and needs that
  decision.
- (d) Split: do role, composite and role scope writes with the master token, and give the
  sync account only `manage-clients` (its own reach to be measured before), or keep no
  persistent sync secret at all.

Every write is one `papaia.audit/1` line (submission form; `source`, `seq` and
`prev_hash` are set by `papaia-audit`) in `$PAPAIA_CONFIG_DIR/audit/outbox/papaia-ctl.jsonl`
(mode 0600) with one UUIDv7 correlation id per run, the host account that ran
`papaia-ctl` as `sub`, and `result: error` for a write Keycloak refused
(`http_<status>`) or one that failed on the way (`transport`; Keycloak may have applied
it); event `exchange_right_changed` for exchange scopes (also their role mappings),
audience mappers, `offline_access` and client policies and profiles, `config_changed`
otherwise. Keycloak replaces the whole list of client policies (or profiles) on each
write, so each policy or profile change is one write of the list and one row. The sync
owns the policies named `papaia-one-aud-*`, `papaia-person-*`, `data-chain`,
`data-self` and `data-handover` and the profiles `papaia-reject`, `papaia-person-subject`,
`data-chain`, `data-self` and `data-handover`; every other policy or profile of the realm is left unchanged. The gapless
`source_seq` is counted in `papaia-ctl.seq`
next to the outbox, locked for the whole run, so a second run waits and the counter
does not restart when the outbox has been delivered. The run opens the outbox for
appending before the first change; if a row still cannot be written after Keycloak
applied a change, the run stops and reports a failed sync. A change that names a client
scope Keycloak does not know (on a managed client, an unmanaged one or the sync account)
is skipped with a note, `realm sync` then ends with exit 1 ("incomplete") and `--check`
keeps reporting it. No client secret is printed or written.

### Name list of the Paperless gate

Paperless takes the identity of a request from the header `X-Papaia-Remote-User` and
creates an account for a name it does not know. The gate in front of Paperless
(`paperless-gate`, part of the Paperless add-on) therefore passes the header only for
names on a list that the realm sync writes on every run, also on every `start`:

```json
{
  "format": "papaia.paperless-users/1",
  "users": ["anna", "ben"]
}
```

- Who is listed: the user name of every active account of the `papaia` realm that holds
  a role declared by the module serving the audience `mcp-paperless`, directly, through a
  group or through a composite role (Keycloak's effective realm roles). Deactivated
  accounts and service accounts are never listed. A user name that cannot be compared
  with a header value safely (anything outside letters, digits and `._@+-`, a leading
  separator, more than 255 characters) is left out and named in a note by account id.
- When it changes: an account that is deleted, deactivated or loses the role is gone
  from the list after the next run. The list is compared before the clients are
  reconciled, so a reconcile that stops does not keep a removed account on it. An
  unchanged list is not rewritten; `--check` reports a stale list as
  `fail: file security/paperless-gate/users.json: ...`.
- A Paperless module that declares no role leaves the list empty (the gate then admits
  no name) and the run says so in a note. When no module serves `mcp-paperless` any
  more, the list is removed.
- Where: the directory `security/paperless-gate/` (mode 0755, created by the sync) holds
  only `users.json` (mode 0644): the gate runs under a user of its own and must read it;
  only the user running `papaia-ctl` (or root) may be able to change the directory, a
  symbolic link or a directory writable by group or others stops the sync. The list is
  written beside the old one and renamed into place, so the gate reads either the old or
  the new list, never a part. The add-on mounts the **directory** read-only (for example
  `${PAPAIA_CONFIG_DIR}/security/paperless-gate:/run/paperless-gate:ro`); a bind mount of
  the single file would keep showing the replaced file.
- Credentials: reading accounts needs `view-users`, which the sync account does not
  hold; the accounts and their effective roles are read with the master admin the run
  already signs in with. Nothing else reads accounts.
- Audit: each write or removal of the list is one `papaia.audit/1` row (operation
  `realm_sync.paperless_users.write` or `.delete`, `object_ref` type `file`, `azp`
  `admin-cli`), with the run's correlation id and without any user name.
### Declared service accounts

A module declares each service account it needs in `service_accounts[]` of an `exposes`
entry, one account per purpose (security 1.9, kit schema `exposes.v1`):

```yaml
service_accounts:
  - id: svc-flow-events              # registered in the naming register, owned by the module
    purpose: {de: Rechnungseingang, en: Incoming invoices}
    owner_sub: ${FLOW_EVENTS_OWNER}  # responsible person; ${NAME} comes from the add-on's .env
    deputy_sub: ${FLOW_EVENTS_DEPUTY}
    roles: []                        # realm roles, e.g. prefs-read
    audiences: [mcp-paperless]
    effects: [read]                  # read, write, send, delete, check
    realm_management_roles: []
    credential: private_key_jwt
```

Every field is checked before the first write; an unknown field, a credential other
than `private_key_jwt`, a platform role (`papaia-*`) or an admin role (`*-admin`), an
audience that exchanges tokens, an audience whose module accepts only persons
(`identity` without `service`), an account declared twice or owner and deputy being the
same person refuse the sync (exit 2, nothing changed). `realm_management_roles` must be
empty: a module's account with `realm-management` rights needs a confirmation at
installation, which the core does not offer yet.

The realm sync creates one client per account and keeps it to the declaration:

| Setting | Value |
|---|---|
| Flows | service account (`client_credentials`) only: no code flow, no implicit flow, no password grant, no token exchange, `fullScopeAllowed: false` |
| Client authentication | `private_key_jwt` (`client-jwt`, ES256). Keycloak holds the public key as a JWK set in the client (`jwks.string`); the private key is in `$PAPAIA_CONFIG_DIR/security/service-accounts/<id>/private-key.pem` (mode 0600, folder 0700) and nowhere else. A missing key file gets a new key pair; any other registered key is removed. |
| Audiences | One optional scope `aud-<audience>` per declared audience whose module is installed. The account asks for it with `client_credentials` and `scope=aud-<audience>`; an audience it does not declare is not assigned, and Keycloak refuses it (`invalid_scope`). Default scopes: `basic`, `roles` and Keycloak's own `service_account`. |
| Roles | The declared realm roles that exist, in the client's token scope and in the service-account user's role mappings, and nothing else: no client role (so no `realm-management` role), no group, no role whose composite reaches further. |
| Record | Attributes `papaia.owner_sub`, `papaia.deputy_sub`, `papaia.purpose`, `papaia.effects`, `papaia.rotation_days` (90) and `papaia.key_rotated_at`. |
| Last use | Keycloak stores `CLIENT_LOGIN` events while any account is declared (added to the event types an operator chose; kept 180 days when the realm stored no events before). |

Clients with an active service account are exactly the declared ones and the sync
account. A managed account that no installed module declares any more (its module is
removed or deactivated, or the declaration is gone) is reported by `--check` and deleted
by the sync together with its key folder; another client's undeclared service account is
turned off. The registered accounts that a module's own setup still creates outside the
`svc-<module>-<purpose>` rule (`flow-directory`, `flow-control`) are named in a note and
left as they are. The service-account users' role mappings, groups and the event
settings are changed with the master admin: the sync account cannot (HTTP 403 in Keycloak
26.7.0), and it gets no `manage-users`.

`papaia-ctl service-account list [--json]` shows each account with module, owner,
deputy, audiences, roles, effects, the last key rotation (marked due after 90 days) and
the last use. `papaia-ctl service-account rotate <id> [--grace=SECONDS]` replaces the
key pair: the new public key is registered (with `--grace`, at most 60 s, the old one
stays registered as well), the new key file replaces the old one, then only the new key
remains registered. The command checks with Keycloak that the new key signs in and that
the old key is refused, at the latest 60 s after the rotation began; otherwise it exits 1.
Measured against Keycloak 26.7.0: the old key is refused as soon as it is no longer
registered. Every change is one `papaia.audit/1` row (`service_account_rotated` for key
changes); the module reads its key file again after a rotation.

The core's own account `svc-papaia-lifecycle` (profile `lifecycle`) is not declared in
`service_accounts[]`: the realm sync keeps it in `lib/lifecycle_account.py`, with
`view-events` and an admin permission on the group `papaia-persons` instead of
`manage-users`; the realm sync leaves it and Keycloak's `admin-permissions` client out of
the undeclared accounts. See [lifecycle.md](lifecycle.md).

Likewise `svc-papaia-people` (profile `people`) is kept by `lib/people_account.py` with
`realm-management` `query-users` and `view-users` only; under the same profile the realm
sync serves the core audience `papaia-people` (persons only) and accepts a pairing for it
from `assist-gate` alone, effect `x`. See [people.md](people.md).

### Seam 3 — LibreChat-MCP

The `mcpServers` and `allowedDomains` fragment from `integration/librechat/`
is **merged at render time** into the effective `librechat.yaml` in the config
directory. Render process: base template + sum of active add-on fragments +
the entries generated from the platform catalog + customer overlay.

**Entries from the catalog.** A tool server declared in `exposes:` with
`kind: mcp` needs no fragment and no audience mapper of its own. The core
derives both from its catalog entry (`lib/chat_servers.py`), so address,
audience and title are the catalog's:

- Only entries with `trust: platform` (a module of the suite matrix, or a core
  profile), identity `person`, an address and an audience qualify. LibreChat
  sends one token that carries the audience of every such server; a server
  outside the suite never receives it.
- The `mcpServers` entry is named after the audience (`mcp-<system>`) and
  calls the catalog address with the person's token (`startup: false`); its
  origin joins `mcpSettings.allowedDomains`. It is generated only for a module
  that ships no `integration/ai/librechat/librechat.yaml`: a shipped fragment
  stays that module's description until the module drops it. The overlay can
  still change or remove a generated entry.
- The audience mapper `<audience>-audience` (`oidc-audience-mapper`, access
  token only) is added to the `librechat` client of the rendered realm unless
  that client maps the audience already. `start` creates it on an existing
  realm (`keycloak-role-sync`, additive); each mapper it creates is one
  `papaia.audit/1` row (`keycloak_role_sync.protocol_mapper_create`, master
  administrator). With the bundled Keycloak the add-on checklist no longer
  lists a `client_mappers.librechat` export for such an audience; with an
  external identity provider it names the audiences to map by hand. Removing
  the add-on removes entry and mapper from the rendered files; a mapper in the
  live realm stays until it is deleted by hand.

**Agents and prompts (addon_api 4).** An add-on may ship LibreChat agents and
prompts in the same formats as `LIBRECHAT_AGENTS_DIR` / `LIBRECHAT_PROMPTS_DIR`
(`src/ai/librechat/agent.yaml.example`, `prompt.md.example`):

```
<addon>/integration/ai/librechat/agents/<file>.yaml
<addon>/integration/ai/librechat/prompts/<file>.md
```

Every render copies the files of the active add-ons to
`$PAPAIA_CONFIG_DIR/ai/librechat/addon-agents/` and `addon-prompts/` as
`<addon>__<file>` and writes `overrides/docker-compose.librechat-addons.override.yml`.
That override mounts both directories into LibreChat and labels the service with a
hash of their content, so the next `papaia-ctl start` recreates LibreChat whenever
the content changes, the add-on is removed included. On start, `agents-init.js` and
`prompts-init.js` upsert the files and store them with `papaia_managed_by: <addon>`:

- **Tombstones:** An agent or prompt whose add-on no longer provides it is deleted,
  together with its access entries and project links. Agents and prompts created in
  the UI or from the operator directories are never touched.
- **Validation at render:** An agent that names an MCP server the rendered
  `librechat.yaml` does not define is skipped with a warning, because it would
  appear without its tools. So is a file that is not valid UTF-8 or YAML, or whose
  `mcpServers` is not a list of server names; the rest of the render goes on.
- **Tools:** LibreChat equips a stored agent from its `tools` list alone;
  `mcpServers` adds no tools by itself. An empty `tools` next to `mcpServers`
  therefore means every tool of those servers: the wildcard key of each server
  (`sys__all__sys_mcp_<server>`) is stored for it. A non-empty list is stored as
  written, so an agent can carry single tools (`<tool>_mcp_<server>`), which
  keeps the tool prompt small for small local models.
- **Operator files win:** An agent in `LIBRECHAT_AGENTS_DIR` with the id of an
  add-on agent replaces it: the add-on file is skipped with a warning, and the
  stored agent loses its add-on mark, so removing the add-on keeps it. Operator
  prompts never take over an add-on prompt of the same name.
- **Overwritten edits:** Changes made in the UI to an add-on agent or prompt are
  overwritten on the next start.
- **Ids:** Agent ids are stored with the `agent_` prefix, so links use
  `?agent_id=agent_<id>`. Add-on prompts are keyed by add-on and `command`.
- **Known limitation:** A distributed installation does not ship the override or
  the two directories to a node bundle, so add-on agents and prompts are not
  provisioned there (Fidonis/papaia#368).

### Seam 4 — Ingress (optional)

Optional NPM proxy host entry for the add-on UI. Added additively via the
Nginx fragment mechanism (or NPM API).

### Platform catalog (`platform/services.json`, `platform/groups.json`)

Modules learn which services, user interfaces and groups the installation offers from
two files under `${PAPAIA_CONFIG_DIR}/platform`. Each module mounts that directory
read-only; the core is their only writer.

- **Declarations.** An add-on declares its surfaces in `exposes:` of its
  `papaia-app.yaml` (contract generation 7). A core profile declares them in
  `exposes.yaml` next to its compose file (`src/ai/rag/exposes.yaml`). Every section is
  checked against the papaia-kit schema `exposes.v1`, vendored under
  `tools/schemas/kit` with the digests of `snapshot.json`. `addon check`, `addon
  install`, `addon start` and `addon upgrade` refuse an invalid section, name the field
  and the reason, and leave the catalog unchanged.
- **`services.json`** (`papaia.platform-services/1`). `papaia-ctl catalog render`
  writes it, and so does every render (`setup`, `start`, every `addon` command) and
  `addon stop` and `stop --addons`. It holds one entry per declared id, sorted by id,
  with `state` (`running` or `stopped`), `trust` (`platform` for core profiles and
  for add-ons of the suite matrix, otherwise `addon`), the resolved internal address,
  the public URL of each user interface (`<HOST_KEY>_HOST`, https only) and a
  `content_hash` (sha256 over the RFC 8785 form of the entry). Branding comes from
  the overlay file `platform/branding.yaml` (`name`, `suffix`, `contact`; logo
  `platform/brand-logo`), and `platform_notices` carries the test-mode notice. A
  stopped add-on stays listed with `state: stopped`; its hash changes, and the
  hashes of the other entries do not. An id declared twice, an address without its
  compose service or a user interface without its public host stops the render.
  `addon install`, `addon start`, `addon upgrade` and `addon rollback` therefore build
  the catalog of the installation they are about to save first and refuse such an
  add-on with exit 2, leaving `deployment.yaml` and the catalog unchanged. The
  installation has no catalog while the core serves no generation 7 or `OIDC_ISSUER`
  is not an https address.
- **`groups.json`** (`papaia.platform-groups/1`). `realm sync` reads the groups of
  the realm through the master administrator and writes `id`, `path`, `display_name`
  (group attributes `papaia.display_name.de` and `.en`, else the name) and `technical`
  (attribute `papaia.technical`). The file holds no members and no other personal
  data. Until the first sync the render writes an empty list.
- **Writes.** Both files are written atomically (temporary file, then rename), mode
  0644 in a 0755 directory, and only when their content changed (`generated_at`
  aside). Every write, the brand logo included, adds one `papaia.audit/1` row
  (`catalog.services_write`, `catalog.brand_logo_write`, `catalog.brand_logo_delete`,
  `platform_groups.write`) to the outbox, attributed to the host.
- **Chat.** LibreChat's tool servers and their audience mappers are derived from
  the catalog entries (Seam 3, "Entries from the catalog").
- **`knowledge:` and `exposes`.** A module that declares `exposes` names only its
  own operations in `knowledge.sources[].access[].key_tools`. `addon check` and
  `addon install` refuse another name (axis `knowledge`), and the knowledge map
  refuses one in a core profile's `knowledge.yaml`. The key `knowledge:` itself
  stays (generation 6).

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
| `papaia-ctl keycloak-role-sync` | Reconcile the bundled Keycloak's realm roles, composites and protocol mappers against the rendered realm template, and grant `papaia-admin` to every holder of the legacy `admin` role, then run the realm sync. Runs on every `start`; no-op with an external OIDC provider |
| `papaia-ctl catalog render` | Write `platform/services.json` from the `exposes` declarations of the installed add-ons and the active core profiles (see "Platform catalog"). Every render does it as well. Exit 3 when the catalog cannot be rendered; the previous file stays |
| `papaia-ctl privacy-pack [--out=DIR] [--check]` | Write the records of processing `docs/de/datenschutz/vvt/<module>.md` from the `storage` declarations of the core profiles; only the part between the `privacy-pack` markers is generated, text around it is kept. `--check` writes nothing and exits 1 when a generated part differs from the declarations, a module file is missing or stale, a generated table has an empty cell, or a claim of a technical lock in the package names no acceptance criterion (a test runs it in CI). An entry without a `storage` declaration is listed as such and warned about |
| `papaia-ctl privacy-pack --installation --out=FILE --backup-retention=DAYS [--format=html\|pdf\|md] [--offsite=PLACE --offsite-retention=DAYS]` | Write the data protection package of this installation as one document (default HTML): the processors it actually sends data to (the hosted model route, the mail server behind the relay, the host service provider), the places that keep copies with their deadlines (backup target, copy off site), and the records of every active core profile and installed add-on. One `papaia.audit/1` row (`privacy_pack.installation_write`) |
| `papaia-ctl realm sync [--check]` | Reconcile the clients, roles, exchange scopes and service accounts the installed modules declare and `security/pairings.yaml` confirms, write the name list of the Paperless gate (see "Realm sync of declared clients") and the group list `platform/groups.json`. `--check` changes nothing and exits 1 on any deviation. Exit 2 when a declaration is refused; nothing is changed then |
| `papaia-ctl realm keys apply <module>` | Register the public keys the module wrote to the files of its `client_keys` (see "Realm sync of declared clients", row "Client keys") without a full sync; every declaration is checked as for `realm sync`. Exit 2 when the module declares no `client_keys` or a declaration or key file is refused, 1 when a client does not exist yet |
| `papaia-ctl pairing list [--json]` | Read-only. The pairings of the signed bill of materials with read or write, their state in `security/pairings.yaml` and the sha256 of the list (see "Pairing approval"). Exit 2 when the bill of materials does not verify |
| `papaia-ctl pairing confirm --approve-pairings=SHA256` | The confirmation step of `setup`: confirms the read pairings of the list with this digest and records its write pairings as waiting for approval. Exit 2 for another list; nothing is changed then |
| `papaia-ctl pairing approve --client=NAME --audience=NAME [--effects=rwdx]` | Confirm a pairing; a write pairing (`w` or `d`) is confirmed only by a second host account, the first one records it as waiting. Exit 2 when refused (same person, other effects, a name the register does not allow) |
| `papaia-ctl pairing revoke --client=NAME --audience=NAME` | Remove a pairing; the next realm sync removes its scope |
| `papaia-ctl service-account list [--json]` | Read-only. The declared service accounts with module, owner, deputy, audiences, roles, effects, last key rotation (due after 90 days) and last use (see "Declared service accounts") |
| `papaia-ctl service-account rotate <id> [--grace=SECONDS]` | Replace an account's key pair; the old key is refused at the latest 60 s after the rotation began (checked against Keycloak, exit 1 otherwise). `--grace` (0 to 60, default 30) keeps the old key registered that long. Exit 2 for an account that is not declared |
| `papaia-ctl status [--json] [--profiles=LIST] [--addons]` | Read-only. Match the services the Compose files declare for the active profiles against the containers Docker reports, per `de.fidonis.module` and per profile. A declared service without a container is `missing` ("not deployed"); an unreachable Docker daemon is reported as such, not as an outage. |
| `papaia-ctl doctor [--json] [--skip=CHECK[,CHECK]]` | Read-only preflight and diagnostics: Docker/Compose version, disk space, what Docker's data takes (`docker_usage`, a report that never `warn`s or `fail`s), memory, CPU load, GPU (for a LocalAI GPU variant), the native LocalAI of a Mac (`localai_native`), published ports, DNS, clock synchronization, certificate expiry, the mail relay and its mail server (`smtp`, only while the `smtp` profile is on), add-on compatibility and container health, each `pass`, `warn`, `fail` or `skip`. Exit 2 if any check fails. Works before `setup`. |
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

> The distributed mode has been validated by hand on a two-node split with a firewall
> between the nodes; the [two-node validation](distributed-validation.md) describes the run that is recorded
> on its tracking issue. Mind the [limits](distributed.md#limits) that hold by design.

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

**Operations** (`tools/lib/cluster.py`). A distributed installation is set up once, as a new
installation (`setup --topology=distributed`); `setup` never changes the shape of an existing
one. `start` renders the bundles, hands each node its release and bundle, and starts the link
gateways first and then the services in groups: Keycloak and the mail relay, LiteLLM, the
application services, and the Nginx Proxy Manager last. `stop` runs backwards. The
provisioning steps (`npm-provision`, `keycloak-role-sync`) run on the node of their service.
`status` merges every node's report and adds `node` per module and container, plus `nodes`.
`doctor` checks the controller's own node and adds `nodes` (version skew, clock deviation,
each node's own checks), `links` (a TLS handshake per link, certificate expiry) and
`file_modes` (the config dir keeps the mode 600 of the link keys). The JSON
schemas grow additively and `schema_version` stays 1.

**Data** (`tools/lib/cluster_data.py`). A restore point of a distributed installation lives on
the controller, in the one catalogue. It holds the controller's configuration directory and
every node's volumes, remote state and add-on data, streamed through the node's executor; each
artifact records its `node`, and `node:NAME` selects one node for `backup --only` and
`restore --only`. An **upgrade** moves every node at once: all nodes answer, a restore point is
taken, a lock (`upgrade.lock`, plus any node on another release) blocks everything but the
upgrade and the way back, every node gets the release, and each migration runs on the node of
the service it names (`# papaia-migration: runs-with=<service>`), recorded with its node in the
ledger. An **add-on** runs on one node: `addon install --node`, and the compatibility gate
refuses an add-on that attaches to core services on two nodes. The operator guide is
[distributed.md](distributed.md).

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
  Everything else that leaves goes through the single exit `papaia-egress` (always on,
  [docs/egress.md](egress.md)): one allow list per add-on, protected hosts that override
  every list, one audit line per connection.
  On an Apple Silicon Mac, LocalAI can run as a host process on the Apple GPU instead of a
  container ([ADR 0012](adr/0012-serve-local-inference-on-apple-silicon-through-a-native-localai.md));
  it is still reached only through LiteLLM.
  The optional voice engines (profile `voice`) process audio locally and sit behind
  the same point; their one outbound exception is the first-start model download
  from huggingface.co (telemetry disabled), documented in the README.
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
      ingress_ip: <optional>        # edge ports on the proxy's node (default: its address)
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

`DOCKER_GID` must match the GID owning `/var/run/docker.sock` inside the container;
`setup` reads it from the host socket on Linux and stamps `0` under Docker Desktop
on macOS, whose socket proxy is owned by root. The container itself runs as a
non-root user.

Path parity decides where the `manager` profile runs: on Linux hosts, and on Docker
Desktop for macOS, which shares `/Users` with its VM under the same path. Docker
Desktop on Windows cannot present a host path unchanged inside the container, so
the mounts above cannot be satisfied there. Every other profile is unaffected —
`--no-manager` leaves an otherwise identical stack.

Mounting the Docker socket grants the container root-equivalent access to the host.
That is inherent to an orchestration UI; the mitigations are role gating on every
route, an audit log, and keeping `MANAGER_ADMIN_ROLE` a host-administrator role.
The core ships the broker `papaia-docker-gate` (docs/docker-gate.md) on the internal
network `papaia-docker-gate-net`, shared with the manager alone: it allows the status
and `start`/`stop` of the installation's own containers and refuses `exec`, `create`
and every other call with an audit row. Once the manager reaches Docker only through
it, the socket mount above goes away.

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
| `MANAGER_ADMIN_ROLE` | `manager-admin` | Full access except Users — add-ons, catalogues, jobs, dashboard, host, models, backup, mail, settings (modules and overlay), nodes, the AI map and, while the `rag` profile is active, the RAG pages |
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

### Add-on requirements and maintenance actions

The manager reads `requires.addons` and `actions` from the manifest itself and leaves the decision
to `papaia-ctl`. Each required add-on is shown with its state (active, inactive, missing, too old,
or unchecked when a version or range cannot be read), and *Install* is disabled while one is unmet,
unless the compatibility mode is `warn`, where `papaia-ctl` installs anyway. The other direction,
the active add-ons that require an add-on, is shown as *Required by*; while there is one, *Remove*
and *Uninstall* answer 409 in every compatibility mode, and the queued job checks again before it
takes anything down, since an install queued ahead can add a dependent. A declared maintenance
action is a button that queues exactly `papaia-ctl addon run <add-on> <action>`: the request
carries the action's name only, never a command or an argument, `run` is not one of the generic
verbs, and an undeclared action or an inactive add-on is a 404. Destructive actions ask for a
confirmation; on a distributed installation actions are refused, as `addon run` is single-host.
Both need a core with these manifest fields (1.9.0 or newer).

### Long-running operations

Installs, upgrades and lifecycle verbs shell out to `papaia-ctl` and can take minutes
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
(LocalAI with its accelerator variant, web search, the RAG system, voice, the mail relay and the
knowledge map) on and off.
It stores the choice with the core's own `setup`, so validation, sticky values and generated
secrets stay in one implementation, and starts the module's profile. Which volumes a module owns,
what its settings consist of and which questions `setup` still needs answered when the module is
switched on (the public URL of LocalAI and of Qdrant, the relay's mail server) come from the core's
read-only `module-info`; deleting a module's data (its volumes) and/or its settings is the core's
`module-purge`, offered only for a module that is switched off, with the module's name typed back
as confirmation. The files an operator wrote by hand for a module (the knowledge map's
declarations, governance records and gold set) are neither data nor settings: they go only when
`module-purge --operator-files` asks for them, a separate choice that is off by default. Both are internal commands of the core's Python entry point, not `papaia-ctl`
verbs, and the manager passes them typed options only: one module, never `--force`, `--env` or any
other part of the configuration. A core without them (before 1.6.0) still switches LocalAI and web
search and switches modules off keeping everything.

**Overlay.** The tab edits the files under `$PAPAIA_CONFIG_DIR/overlay/` for LibreChat, LiteLLM,
SearXNG and Chatterbox, the speech synthesis of the `voice` profile
([§13](#13-customer-overlay--3rd-render-layer)). The effective result shown next to the
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
backup, a service that stopped or turned unhealthy, an available update, an expiring certificate,
a new or changed high finding of the AI map that no exception covers.
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
after a run that succeeded without a failed document. Without the `manager` profile there
is no interface and the catalog files are edited by hand.

### Models and usage

The *Models & Usage* page (`/models`, administrators only) shows which models LiteLLM serves
and what they consumed: tokens, spend and requests per day and per model, for a window of UTC
days. It reads LiteLLM's HTTP API at `LITELLM_URL` (`http://litellm:4000` on the stack network)
with GET requests to three routes only (`/health/readiness`, `/model/info`,
`/user/daily/activity`), so it cannot change LiteLLM; models, prices, teams and keys stay in
LiteLLM's own Admin UI. The master key is read from `$PAPAIA_CONFIG_DIR/ai/litellm/.env` when a
request needs it, like the RAG secrets, so the core needs no change and the key is never a
setting of the manager. A LiteLLM that is down or a key it refuses is a message on the page.

### Nodes

On a [distributed installation](distributed.md) ([ADR 0009](adr/0009-place-services-on-nodes-with-a-topology-block.md),
[ADR 0010](adr/0010-connect-nodes-through-ssh-and-an-mtls-link.md)) the manager runs on the
controller and reaches the other nodes only through the core's Python CLI: read-only questions
and the `compose-up` / `compose-stop` of a node go through `lib.cli node-exec`, and the commands
that change the set of nodes (`node-register`, `node-unregister`, `node-pin`, `node-join-bundle`,
`node-push`) through their own sub-commands. Keys and pinned host keys stay in the configuration
directory, managed by the core; the manager has no raw `docker` or Git on a node. The image
carries an SSH client, and its entrypoint names the host's user id, which OpenSSH needs, since
the container runs as the host's `UID`.

A *Nodes* page lists the machines with their services, address, status, version and link
health. Adding and removing a node, handing it its bundle and confirming a host key need a fresh
sign-in at Keycloak (`prompt=login`, valid for five minutes) on top of the admin role, and are
audited. The other pages follow the placement: the service snapshot comes from the core's merged
`status --json --addons`, a group action and a module, overlay or mail change name the node with
`--node=` (a `start` then also visits the nodes of the proxy and of Keycloak, whose provisioning
steps it needs), backups take `--only=node:NAME` and a restore can pick a remote node as a whole.
The core's `upgrade.lock` and each node's `state.json` drive a banner and the same refusals the
core would make. Switching a module off keeps its data, because the core does not delete volumes
across nodes. Without a topology in `deployment.yaml` none of this runs, and a single host
behaves as before.

### AI map

The *AI map* page (`/knowledge-map`, administrators only) is the management view of the
[knowledge map](knowledge-map.md) ([ADR 0013](adr/0013-knowledge-map-as-optional-core-profile.md)).
It computes no rule of its own: the rendered map and `lints.yaml` come from the configuration
directory, as the core's render wrote them, and the server's own view, usage, gold-set runs and
mined refinements from the map server's admin API at `KNOWLEDGE_MAP_URL`
(`http://knowledge-map-mcp:8200` on the stack network) with the bearer `KM_ADMIN_TOKEN`, read
from `$PAPAIA_CONFIG_DIR/ai/knowledge-map/.env` when a request needs it. The only check it adds
is a live comparison of the model tiers against LiteLLM (findings with `origin: manager`). Every
change, an entry, an override of a declared entry, an operator file or a governance record under
`overlay/knowledge-map/`, is a queued job that checks the file, writes it, renders the map and
puts the previous file back when the render refuses it. A routing test or an entry probe asks
the map server without recording anything. High findings that no exception covers feed the
notifications. The module itself is switched in the Modules tab; deleting its operator files is
the separate `module-purge --operator-files` choice described above.

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
