# papAIa

> Self-hosted, OIDC-first AI & document platform — Lean Core, built to extend.
> by **Fidonis GmbH** · <https://fidonis.de>

papAIa is a Docker Compose platform that bundles a chat UI, an LLM proxy, local model
hosting, and a Keycloak-based SSO layer into a self-sufficient **Lean Core**. Additional
services — document management, RAG, workflow automation — attach through a standardised
**add-on contract** rather than being hard-wired into the stack.

This is the **1.0.0** release: the Lean Core is stable, `papaia-ctl` is the single
idempotent orchestrator for the full deployment lifecycle, and the add-on infrastructure is
in place for first-party and custom service modules.

**Contents** — [Services](#services) · [Quick start](#quick-start) ·
[papaia-ctl reference](#papaia-ctl-reference) · [Architecture](#architecture-overview) ·
[Advanced configuration](#advanced-configuration)

---

## Services

Every service belongs to a Docker Compose **profile**. Nothing starts unless its profile is
listed in `COMPOSE_PROFILES`. The default set is
`keycloak,nginx,oauth2-proxy,librechat,litellm`.

### Core

| Service | Profile | Port | Purpose |
|---|---|---|---|
| Keycloak | `keycloak` | 8110 | Identity & access management, OIDC issuer. Serves **HTTPS** directly. |
| Nginx Proxy Manager | `nginx` | 80 / 443 | Bundled edge reverse proxy and TLS termination |
| NPM admin UI | `nginx` | 8100 | Admin interface, guarded by an oauth2-proxy sidecar |
| oauth2-proxy | `oauth2-proxy` | 4180 | Forward-auth gateway for services without native OIDC |
| LibreChat | `librechat` | 8000 | Multi-provider chat UI, native OIDC with PKCE |
| LiteLLM | `litellm` | 8200 | Unified LLM gateway; generic OIDC for the admin UI |

Internal support containers (no published ports): `keycloak-postgres`,
`librechat-mongodb`, `librechat-meilisearch`, `librechat-vectordb` (pgvector),
`librechat-ragapi`, `litellm-db`, `litellm-prometheus`.

### Optional

| Module | Profile | Port | Purpose |
|---|---|---|---|
| LocalAI | `localai` | 8080 | Local model inference, chat-completions API. Native OIDC, gated by the `localai-access` realm role. |
| Homepage | `homepage` | 8300 | Service dashboard, behind an oauth2-proxy sidecar |
| Web search | `librechat-websearch` | — | SearXNG (metasearch), Firecrawl (crawler), the Firecrawl MCP bridge, and the Jina reranker. All internal-only; consumed by LibreChat. |

`localai` and `librechat-websearch` are toggled by `papaia-ctl setup`
(`--local-ai`, `--web-search`). `homepage` has no setup flag — add it to
`COMPOSE_PROFILES` by hand.

> Everything else — document management, RAG, workflow automation — ships as an
> [add-on](#add-ons), not as a profile in this repository.

> **Tip:** all `*_EXT_PORT` variables are listed in `src/.env.example`, grouped per service.
> Change a single number to relocate a port.

**Authentication coverage**

| Service | Approach | Notes |
|---|---|---|
| LibreChat | Native OIDC | `openid-client`, PKCE enforced |
| LiteLLM (UI) | Generic OIDC | API key for programmatic access |
| LocalAI | Native OIDC | Only users holding the `localai-access` realm role can sign in |
| Homepage | oauth2-proxy sidecar | — |
| NPM admin UI | oauth2-proxy sidecar | — |
| oauth2-proxy | Forward-auth gateway | Guards services without native OIDC |

---

## Quick start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ — `papaia-ctl` generates secrets and renders configs itself
- `openssl`, only when Keycloak TLS is enabled
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

With no flags, `setup` walks through the values it cannot derive on its own — the public URL
of the server (`PAPAIA_HOST`), the public Keycloak URL (`AUTH_HOST`), whether to enable web
search (and an optional reranker model), and whether to enable local AI (and its public URL).
Each prompt is pre-filled with a sensible default. Everything else — secrets, OIDC endpoints,
TLS certificates, rendered configs — is generated automatically.

For unattended / CI use:

```bash
tools/papaia-ctl setup --non-interactive \
  --app-host=https://papaia.example.com \
  --auth-host=https://auth.papaia.example.com
```

> In non-interactive mode, `--local-ai` and `--web-search` are **not** implied. Without those
> flags the corresponding profiles stay as they are — off, on a fresh install.

**3. Start the stack**

```bash
tools/papaia-ctl start
```

This copies the generated `.env` files into the checkout, re-renders the configuration, and
runs `docker compose up -d`. Keycloak imports the `papaia` realm automatically on first start.

Start a subset of profiles for this run only:

```bash
tools/papaia-ctl start --profiles=keycloak,librechat,litellm
```

**4. Sign in**

Once the stack is up, the default endpoints for a local install are:

- LibreChat — `http://host.docker.internal:8000`
- Keycloak admin — `https://host.docker.internal:8110`, user `admin`, password `KC_ADMIN_PASSWORD`
- Homepage — `http://host.docker.internal:8300` (if the `homepage` profile is active)

The realm ships two test users: `admin` / `admin` (roles `admin`, `user`, `localai-access`)
and `testuser` / `testuser` (roles `user`, `finance`).

> The test users exist purely for local development. Disable or delete them before exposing
> the stack to anything beyond `localhost`.

### Stopping

```bash
tools/papaia-ctl stop              # pause containers, keep them (volumes untouched)
tools/papaia-ctl stop --clean-up   # remove containers, keep volumes
```

---

## papaia-ctl reference

`papaia-ctl` (`tools/papaia-ctl`) is the single orchestrator for the papAIa deployment
lifecycle: bootstrapping, configuration rendering, and stack management. The Bash dispatcher
handles CLI parsing, interactive prompts, and `docker compose` calls; all `.env` / YAML /
JSON manipulation is delegated to `tools/lib/*.py`.

All operations are **idempotent by default** — re-running any command leaves already-set
values unchanged.

```
papaia-ctl setup     [OPTIONS]
papaia-ctl start     [--addons] [--profiles=LIST] [--config-dir=PATH]
papaia-ctl stop      [--clean-up] [--addons] [--profiles=LIST] [--config-dir=PATH]
papaia-ctl uninstall [--clean-up] [--addons] [-y] [--config-dir=PATH]
papaia-ctl backup    [--backup-dir=PATH] [--retention-period-days=N] [--config-dir=PATH]
papaia-ctl restore   [--backup-dir=PATH] [--restore-point=ID] [--list]
                     [--restart-clean] [--no-restart] [-y] [--config-dir=PATH]
papaia-ctl addon     <install|start|stop|remove|uninstall> <name> [OPTIONS]
papaia-ctl addon     check [--target-core=PATH] [--json] [--force] [--config-dir=PATH]
papaia-ctl help
```

All flags use the `--flag=VALUE` form. `papaia-ctl` is **flag-driven, not environment-driven**:
exporting `PAPAIA_CONFIG_DIR` in your shell has no effect on the CLI — pass `--config-dir`
instead.

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
| `--host-ip=IP` | `0.0.0.0` | Bind address for published ports |
| `--app-host=URL` | _(prompted)_ | Public papAIa URL — scheme + host + optional port, no trailing path |
| `--auth-host=URL` | _(derived)_ | Public Keycloak URL; only relevant with `internal_keycloak` |
| `--librechat-host=URL` | _(derived)_ | Public LibreChat URL if it differs from `--app-host` |
| `--localai-host=URL` | _(derived)_ | Public LocalAI URL if it differs from `--app-host` |
| `--npm-admin-host=URL` | _(derived)_ | Public URL of the Nginx PM admin UI |
| `--auth-provider=VALUE` | `internal_keycloak` | `internal_keycloak` or `external_oidc` |
| `--oidc-issuer=URL` | _(required for `external_oidc`)_ | External OIDC issuer URL |
| `--reverse-proxy-provider=VALUE` | _(auto-detected)_ | `internal_nginx`, `external_proxy`, or `no_proxy` |
| `--external-reverse-proxy` | _(auto from URL scheme)_ | Legacy alias for `--reverse-proxy-provider=external_proxy` |
| `--no-external-reverse-proxy` | — | Legacy alias for `--reverse-proxy-provider=internal_nginx` |
| `--allow-direct-port-access` | — | Skip the reverse proxy entirely; services expose ports directly (expert) |
| `--web-search` / `--no-web-search` | _(prompted, default on)_ | Toggle the `librechat-websearch` profile |
| `--reranker-model=NAME` | _(prompted, optional)_ | LiteLLM model name used for reranking |
| `--backup-dir=PATH` | `$PAPAIA_WORKSPACE_DIR/backup` | Default target of `papaia-ctl backup`; stored as `PAPAIA_BACKUP_DIR` |
| `--local-ai` / `--no-local-ai` | _(prompted, default on)_ | Toggle the `localai` profile |
| `--force` | — | Regenerate all secrets unconditionally |
| `-y` / `--non-interactive` | — | Skip all prompts; supply required values as flags |
| `--env-only` | — | Re-write the `.env` files only; skip reconfiguration |

Omitting a toggle flag in non-interactive mode is **sticky**: the current profile set is left
untouched rather than reset to a default.

**What `setup` does automatically**

- **Secret generation** — fills every `GENERATE_*` placeholder in the shipped `.env.example`
  files. Only values that literally start with `GENERATE_` are treated as secrets. Most get
  24 bytes of hex; `*_COOKIE_SECRET` gets 32 raw bytes base64url; LibreChat's `CREDS_KEY` /
  `CREDS_IV` get their exact required lengths.
- **Sticky reuse** — an already-set secret is never rotated on re-run. `--force` regenerates
  every one of them unconditionally.
- **Secret aliasing** — canonical secrets (for example `KC_LIBRECHAT_CLIENT_SECRET`) are
  fanned out to every service that must hold the same value. No manual copy-paste between
  `.env` files.
- **Hostname derivation** — the OIDC issuer, its split endpoints (auth / token / JWKS), and
  the per-service public URLs are derived from `--app-host` / `--auth-host`.
- **Reverse-proxy detection** — an HTTPS `--app-host` implies an external TLS terminator, so
  the bundled Nginx Proxy Manager is omitted. Override with `--reverse-proxy-provider`.
- **Keycloak TLS** — generates a local self-signed CA and a Keycloak server certificate.
- **Realm secret baking** — writes secrets directly into `papaia-realm.json` before the realm
  file reaches Keycloak, rather than relying on Keycloak's `${env.*}` substitution at import.
- **Configuration render** — see [Configuration & render lifecycle](#configuration--render-lifecycle).
- **`deployment.yaml`** — writes the resolved profiles, platform version, and add-on list.

### `start`

```bash
tools/papaia-ctl start [--addons] [--profiles=LIST] [--config-dir=PATH]
```

Copies the `.env` files from the config directory into the checkout, re-renders the
configuration, then runs `docker compose up -d`.

Because rendering happens on **every** `start`, a `git pull` followed by
`tools/papaia-ctl start` is the complete upgrade path — new templates, new add-on fragments,
and edits under `overlay/` are all picked up automatically.

`--addons` starts every active add-on **before** bringing up the core, so that the add-on
networks exist by the time the core's generated override files are applied. An override whose
network does not exist yet is skipped rather than failing the start.

When `--addons` is active, `start` runs a compatibility check against all active add-ons
before bringing up the core. If any add-on is INCOMPATIBLE the start is aborted. Pass
`--force` to demote incompatibility to a warning and proceed.

`--profiles` takes a comma-separated list of Compose profiles and overrides `COMPOSE_PROFILES`
for this invocation only.

### `stop`

```bash
tools/papaia-ctl stop [--clean-up] [--addons] [--profiles=LIST] [--config-dir=PATH]
```

Without `--clean-up`: `docker compose stop` — containers are paused but not removed; volumes
and networks are kept. With `--clean-up`: `docker compose down` — containers are removed,
volumes are kept. `--addons` applies the same operation to all active add-ons.

### `uninstall`

```bash
tools/papaia-ctl uninstall [--clean-up] [--addons] [-y] [--config-dir=PATH]
```

Stops and removes all core containers, then **permanently deletes the config directory**.
Prompts for confirmation; `-y` / `--yes` skips the prompt. `--clean-up` also removes the
Docker volumes. `--addons` stops and removes active add-on containers first.

### `backup`

```bash
tools/papaia-ctl backup [--backup-dir=PATH] [--retention-period-days=N] [--config-dir=PATH]
```

Archives the complete installation into a timestamped subdirectory of the backup location:

- **`$PAPAIA_CONFIG_DIR`** in full — this also captures the Nginx Proxy Manager database and the
  Let's Encrypt certificates, which are bind mounts underneath it rather than named volumes.
- **every named volume of the core stack**, resolved from the compose files and prefixed with the
  configured `COMPOSE_PROJECT_NAME`.
- **every named volume of an active add-on**, plus the host directories it bind-mounts for user
  data. An add-on that only talks to an existing external instance owns no volumes, so that
  external instance is never pulled into the backup.

| Flag | Default | Purpose |
|---|---|---|
| `--backup-dir=PATH` | `PAPAIA_BACKUP_DIR` from the root `.env` | Where to write this backup |
| `--retention-period-days=N` | _(no pruning)_ | Delete restore points older than N days and drop their catalogue entries |
| `--config-dir=PATH` | `../papaia-config` | Config directory location |

Backups run **hot** — nothing is stopped. Because copying a live database directory would
otherwise capture it mid-transaction, the containers writing to a volume are paused for the
duration of that one archive and unpaused immediately afterwards, including when the archive
fails or the run is interrupted.

The backup location holds one directory per restore point plus two shared files:

```
$PAPAIA_BACKUP_DIR/
├── backup.yaml                 # catalogue: id, path, size in MB, result
├── backup.log                  # one line per backup / restore, with its result
└── 2026-07-30_14-05-33/
    ├── manifest.yaml           # which archive belongs to which volume or path
    ├── papaia-config.tar.gz
    ├── volumes/*.tar.gz
    └── binds/*.tar.gz
```

Restore-point ids use local time, so they line up with what an incident timeline says;
`created_at` in the catalogue is UTC so sorting and retention stay unambiguous.

A run whose archives partly failed is recorded as `partial` and is never selected automatically
by `restore`. Volumes that a compose file declares but that were never created (a disabled
profile) are reported and skipped rather than failing the run.

### `restore`

```bash
tools/papaia-ctl restore [--backup-dir=PATH] [--restore-point=ID] [--list]
                         [--restart-clean] [--no-restart] [-y] [--config-dir=PATH]
```

| Flag | Default | Purpose |
|---|---|---|
| `--backup-dir=PATH` | `PAPAIA_BACKUP_DIR` from the root `.env` | Where to read restore points from |
| `--restore-point=ID` | _(most recent usable)_ | Which restore point to restore, as listed by `--list` |
| `--list` | — | Print the available restore points and exit |
| `--restart-clean` | — | Delete the named volumes during the teardown as well, so nothing survives that is not in the restore point |
| `--no-restart` | — | Do not touch the running stack at all |
| `-y` / `--yes` | — | Skip the confirmation prompt (required in non-interactive contexts) |

By default the stack is **torn down before and brought up after** the restore: containers are
removed (`docker compose down`, without `-v`, so the volumes being repopulated survive) and
recreated. Removing them is not optional. Writing into a volume underneath a live process
corrupts both, and — more subtly — most core services bind-mount individual *files* out of
`$PAPAIA_CONFIG_DIR` (`searxng/settings.yml`, `keycloak.conf`, `librechat.yaml`, …). A container
that is merely stopped keeps the mount source it was created with, pinned to the inode behind it;
restoring the config directory replaces those files, and starting the container again then fails
in the daemon with `error mounting … no such file or directory`. Only a recreated container
resolves its bind sources afresh and picks the restored files up.

`--restart-clean` additionally deletes the named volumes (`docker compose down -v`) before the
restore, so a volume that is not part of the restore point does not survive it — that data is
gone permanently. `--no-restart` skips the lifecycle handling entirely; if it is combined with
`--restart-clean` it wins, and the restore proceeds with the stack untouched.

The config directory is restored into the config directory currently in use, not the path
recorded at backup time, so a snapshot can be replayed onto a host that keeps its bundle
elsewhere. A bind-mount directory whose add-on is no longer installed is skipped with a warning
rather than recreated.

### `addon`

```bash
tools/papaia-ctl addon install   <name> --path=PATH [--version=VER] [--force] [--config-dir=PATH]
tools/papaia-ctl addon start     <name> [--force] [--config-dir=PATH]
tools/papaia-ctl addon stop      <name> [--clean-up] [--config-dir=PATH]
tools/papaia-ctl addon remove    <name> [--config-dir=PATH]
tools/papaia-ctl addon uninstall <name> [--clean-up] [--config-dir=PATH]
tools/papaia-ctl addon check     [--target-core=PATH] [--target-version=VER] \
  [--target-addon-api=N] [--target-min-addon-api=N] [--json] [--force] [--config-dir=PATH]
```

| Command | Effect |
|---|---|
| `install` | Registers the add-on in `deployment.yaml` as `active`, seeds `addons/<name>/.env` in the config directory, generates the network override, re-renders, and prints an identity-provider checklist. `--path` is required the first time. Aborts if the add-on is incompatible with the current core; `--force` demotes INCOMPATIBLE to a warning and proceeds. |
| `start` | Copies the add-on's `.env` into place, re-renders, and runs `docker compose up -d` for the add-on. Re-checks compatibility before starting; `--force` to override. |
| `stop` | Stops the add-on's containers. `--clean-up` removes them; volumes are kept. |
| `remove` | Deactivates the add-on (`active: false`) and drops its integration fragments from the render. The config bundle and its secrets are **kept**, so `install` can reactivate it later. |
| `uninstall` | Deletes the add-on's entry from `deployment.yaml` entirely. `--clean-up` also removes its volumes. |
| `check` | Evaluates all active add-ons against the current core for compatibility and prints a status table (OK / INCOMPATIBLE / UNKNOWN). Exit 0 when all add-ons are compatible, exit 2 if any are INCOMPATIBLE. `--target-core=PATH` checks against a different core checkout for a dry-run before an upgrade. `--json` prints machine-readable output. `--force` demotes INCOMPATIBLE to a warning (exit 0). |

**`addon check` flags**

| Flag | Purpose |
|---|---|
| `--target-core=PATH` | Check against a different core checkout instead of the current one (pre-upgrade dry-run). |
| `--target-version=VER` | Override the core version used for the check. |
| `--target-addon-api=N` | Override the `current` bound of the ADDON_API window. |
| `--target-min-addon-api=N` | Override the `min` bound of the ADDON_API window. |
| `--json` | Print results as a JSON array (also on exit 2). |
| `--force` | Treat INCOMPATIBLE as a warning instead of a hard failure (exit 0). |

After `addon install` or `addon remove`, run `tools/papaia-ctl start` to apply the changed
core configuration.

### Configuration & render lifecycle

Understanding where state lives is the key to operating papAIa. There are **two** locations
for every `.env` file:

- **`$PAPAIA_CONFIG_DIR`** — the config directory, by default `../papaia-config`, a sibling of
  the checkout. This is the **single source of truth**. It survives `git pull`, and it is the
  only thing you need to back up.
- **`src/**/.env` inside the checkout** — **derived copies**, gitignored, consumed by
  `docker compose --env-file`. Never edit these; they are overwritten.

`PAPAIA_CONFIG_DIR` must be an **absolute path** — Docker Compose resolves relative paths in
`include:`d files against each file's own directory.

**When each file is written**

| Moment | What happens |
|---|---|
| First `setup` | Seeds one `.env` per service directory from the shipped `src/**/.env.example`, plus `deployment.yaml`. Existing files are left alone unless `--force`. |
| Every `setup` | Resolves all values, fills `GENERATE_*` secrets, and writes each `.env` to **both** the config directory and the checkout. |
| Every `start` | Copies the config directory's `.env` files into the checkout. A clean checkout — or a manually deleted `src/.env` — can therefore never start the stack with stale values. |
| `addon start` | Copies `addons/<name>/.env` from the config directory into the add-on's own directory. |

**When rendering happens**

On `setup`, on **every** `start`, and on every `addon install` / `start` / `remove` /
`uninstall`. There is no separate render command, and none is needed — rendering is
idempotent and produces byte-identical output for unchanged inputs.

Rendering merges three layers:

```
  repo base                 src/<target>
+ active add-on fragments   <addon-path>/integration/<target>
+ customer overlay          $PAPAIA_CONFIG_DIR/overlay/<target>
                            ─────────────────────────────────────
                          → $PAPAIA_CONFIG_DIR/<target>
```

Structured files (YAML / JSON) are deep-merged, with lists appended and de-duplicated. Any
other file type is taken wholesale from the highest layer that provides it. The overlay always
wins.

Render targets: `ai/librechat/librechat.yaml` · `ai/litellm/config.yaml` +
`prometheus.yml` · `ai/localai/models.txt` + `models/` · `services/searxng/settings.yml` ·
`services/homepage/config/` · `infra/keycloak/keycloak.conf`.

The same pass also bakes the Keycloak realm (substituting secrets into
`realm-import/papaia-realm.json`) and regenerates the Compose overrides in `overrides/` — one
per active add-on, attaching the core containers to that add-on's isolated bridge network.
With no add-ons installed, no override files are produced.

**Directory layout of `$PAPAIA_CONFIG_DIR`** — it mirrors `src/`:

```
${PAPAIA_CONFIG_DIR}/
├── .env                    # stack-wide variables (source of truth)
├── deployment.yaml         # installation manifest
├── deployed.lock           # JSON summary of the last setup run
├── certs/                  # generated Keycloak CA + server certificate
├── ai/                     # librechat · litellm · localai · jinaai
├── infra/                  # keycloak (incl. realm-import/) · nginx · oauth2-proxy
├── services/               # homepage · searxng · firecrawl
├── addons/<name>/.env      # per-add-on secrets
├── overlay/                # customer config overrides (highest merge layer)
└── overrides/              # auto-generated add-on network overrides
```

To customise a rendered config, drop your changes into `overlay/` — mirroring the target's
path — and run `tools/papaia-ctl start`. Overlay files survive every upgrade untouched.

### `deployment.yaml`

Written into the config directory on the first `setup` from `tools/deployment.template.yaml`
and refreshed on every subsequent run. It is the manifest for this installation, and it is
hand-editable for anything `papaia-ctl` does not manage.

```yaml
customer: papaia            # set from --env
platform_version: 1.0.0     # resolved from the VERSION file
hosting: self-hosted

core:
  profiles:                 # kept in sync with COMPOSE_PROFILES in .env
    - keycloak
    - oauth2-proxy
    - nginx
    - librechat
    - litellm
  inference: local-first
  addon_api: 1              # ADDON_API contract window served by this installation

addons:                     # managed by `papaia-ctl addon ...`
  - name: paperless
    path: ../papaia-addons/paperless
    version: 1.0.0
    active: true
```

Each `active` add-on contributes its integration fragments to the render and gets a generated
network-attachment override. Setting `active: false` — what `addon remove` does — takes it out
of both without discarding its secrets.

---

## Architecture overview

papAIa is structured in three tiers:

- **Tier 1 — Core** (always on): identity, ingress, inference, and the chat layer.
  Self-sufficient; no add-on required.
- **Tier 2 — First-party add-ons**: Fidonis-maintained services that plug in through the
  add-on contract, each in its own repository, version-pinned.
- **Tier 3 — Custom add-ons**: bespoke customer services following the same contract.

```
┌──────────────────────────────────────────────────────────────────┐
│  Workspace (parent directory of this checkout)                   │
│                                                                  │
│  papaia/             ← Lean Core (this repo)                     │
│  │  Keycloak · oauth2-proxy · Nginx Proxy Manager                │
│  │  LibreChat · LiteLLM · LocalAI · Homepage                     │
│  │                                                               │
│  papaia-addons/      ← Add-ons (separate repos, opt-in)          │
│  │  paperless/       Document management + MCP bridge            │
│  │  <name>/          further first-party or custom add-ons       │
│  │                                                               │
│  papaia-config/      ← PAPAIA_CONFIG_DIR (generated state)       │
│     deployment.yaml  rendered configs  generated secrets         │
└──────────────────────────────────────────────────────────────────┘
```

### Request flow

A browser reaches the edge proxy on 80/443, which forwards to the target service. Services
with native OIDC (LibreChat, LocalAI) redirect the user to Keycloak's **public** URL to log
in; server-side token and JWKS lookups go to `keycloak:8443` over the internal network. That
split is why oauth2-proxy runs with `--skip-oidc-discovery` and three explicit endpoints:

| Variable | Purpose | Reachable from |
|---|---|---|
| `OIDC_AUTH_URL` | Browser redirect to the login page | Browser |
| `OIDC_TOKEN_URL` | Server-side code → token exchange | Containers |
| `OIDC_JWKS_URL` | JWKS for signature verification | Containers |

Services **without** native OIDC sit behind oauth2-proxy: Nginx PM calls `/oauth2/auth`
before letting a request through and bounces the user to Keycloak on a 401.

All core containers share one bridge network, `papaia-net` (or `papaia-<env>-net`).

### Add-ons

An add-on is a self-contained directory — usually its own repository — holding:

- `papaia-app.yaml`, the manifest;
- its own `docker-compose.yml`, on its **own isolated bridge network**;
- an `.env.example`;
- an `integration/` tree with the fragments it contributes to the core.

The manifest declares every seam in machine-readable form, so integrating an add-on requires
**no edits to the core**:

| Seam | Mechanism |
|---|---|
| Network | The add-on declares its bridge network and which core containers must attach; `papaia-ctl` writes the Compose override |
| OIDC | Keycloak clients and protocol mappers registered additively |
| LibreChat / MCP | `mcpServers` and `allowedDomains` fragments merged at render time |
| Dashboard | Homepage service card merged at render time |
| Ingress | Nginx Proxy Manager fragment merged at render time (optional) |
| TLS trust | The add-on lists env vars that point at the bundled CA cert (`local_ca_env`); `papaia-ctl` clears them via a generated override when an external OIDC issuer is used |

Add-ons are registered explicitly by path — there is no auto-discovery:

```bash
tools/papaia-ctl addon install paperless --path=../papaia-addons/paperless
# fill in the CHANGE_ME values in $PAPAIA_CONFIG_DIR/addons/paperless/.env
# register the Keycloak clients printed by the checklist
tools/papaia-ctl addon start paperless
tools/papaia-ctl start                    # re-render the core with the new fragments
```

The reference add-on is **Paperless-ngx**: document management with native OIDC, plus an
OIDC/RBAC MCP server that lets LibreChat query a user's documents under that user's own
permissions — no shared admin credentials.

---

## Advanced configuration

### External Keycloak / external OIDC

When your organisation already runs an identity provider, papAIa can use it instead of the
bundled Keycloak. The bundled Keycloak and its database are then excluded from the stack.

**1. Point setup at the external issuer**

```bash
tools/papaia-ctl setup \
  --auth-provider=external_oidc \
  --oidc-issuer=https://keycloak.example.com/realms/your-realm
```

`--oidc-issuer` is mandatory the first time you switch, if you are running non-interactively.
`setup` derives all OIDC endpoints from the issuer URL (RFC 8414 layout), drops the `keycloak`
profile, and clears `SSL_CERT_FILE` for LiteLLM, oauth2-proxy, and LocalAI so they validate
the issuer against the system CA bundle instead of the bundled self-signed CA.

Client secrets cannot be generated for an issuer papAIa does not control, so each one is
written as the literal placeholder `REPLACE_WITH_VALID_SECRET`. `setup` prints the full list.

**2. Create a confidential OIDC client per service**

| Client ID | PKCE | Redirect URI | Secret lands in |
|---|---|---|---|
| `librechat` | required | `{LIBRECHAT_HOST}/oauth/openid/callback` | `OPENID_CLIENT_SECRET` in `src/ai/librechat/.env` |
| `litellm` | — | `*` | `GENERIC_CLIENT_SECRET` in `src/ai/litellm/.env` |
| `oauth2-proxy` | — | `*` | `OAUTH2_PROXY_CLIENT_SECRET` in `src/infra/oauth2-proxy/.env` |
| `localai` | — | `{LOCALAI_PUBLIC_URL}/api/auth/oidc/callback` | `LOCALAI_OIDC_CLIENT_SECRET` in `src/ai/localai/.env` |

Every client needs a **realm-roles protocol mapper** that puts the user's roles into the token
under the claim name `roles` — multivalued, type String, included in the ID token, the access
token, and userinfo. The claim names papAIa reads are configurable:

```env
OIDC_ROLE_CLAIM=roles
OIDC_USERNAME_CLAIM=preferred_username
OIDC_EMAIL_CLAIM=email
```

**3. Write the secrets into the config directory**

Copy each client secret from the identity provider into the matching `.env` file under
`$PAPAIA_CONFIG_DIR`, replacing `REPLACE_WITH_VALID_SECRET`. Then:

```bash
tools/papaia-ctl start
```

**4. Restrict LocalAI to a role (optional)**

Create the realm role `localai-access` and a custom browser flow on the `localai` client — a
CONDITIONAL sub-flow with a *Condition – User Role* authenticator negating `localai-access`,
followed by *Deny Access*. Assign the role to the users who should be allowed in.

Configuring a non-Keycloak provider (Entra ID, Authentik, Okta, Auth0) works the same way; only
the issuer URL layout differs. See
[`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) for the per-provider issuer
patterns and the step-by-step browser-flow configuration.

### External reverse proxy

If the host already terminates TLS — or already runs something on ports 80/443 — exclude the
bundled Nginx Proxy Manager:

```bash
tools/papaia-ctl setup --reverse-proxy-provider=external_proxy \
  --app-host=https://chat.example.com \
  --auth-host=https://auth.example.com
```

This drops the `nginx` profile, so there is no port conflict. `setup` auto-detects this case
when `--app-host` is HTTPS; pass the flag explicitly to be sure.

Your proxy must map two public URLs onto the published container ports:

| Public URL | Target | Scheme on the target |
|---|---|---|
| `${AUTH_HOST}` | `HOST_IP:KEYCLOAK_EXT_PORT` (default 8110) | **HTTPS** |
| `${LIBRECHAT_HOST}` | `HOST_IP:LIBRECHAT_EXT_PORT` (default 8000) | HTTP |

Keycloak terminates TLS itself, on port 8443 inside the container, using the self-signed
certificate `papaia-ctl` generated. Its plain-HTTP listener is never published. **Your proxy
must therefore speak HTTPS to Keycloak and skip certificate verification on that hop** — a
plain-HTTP `proxy_pass` to port 8110 will fail.

Keycloak runs with `KC_PROXY_HEADERS=xforwarded`, so the `X-Forwarded-*` headers are
mandatory. Without them Keycloak treats the request as plain HTTP, drops the `Secure` flag
from its cookies, and cross-origin OIDC POSTs silently lose their state.

#### Caddy

```caddy
auth.example.com {
    reverse_proxy https://10.0.0.10:8110 {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

chat.example.com {
    reverse_proxy 10.0.0.10:8000
}
```

Caddy sets `X-Forwarded-*` on its own.

#### nginx

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass              https://10.0.0.10:8110;
        proxy_ssl_verify        off;          # Keycloak serves a self-signed certificate
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}

server {
    listen 443 ssl;
    server_name chat.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass              http://10.0.0.10:8000;
        proxy_http_version      1.1;
        proxy_set_header Upgrade           $http_upgrade;   # LibreChat uses WebSockets
        proxy_set_header Connection        "upgrade";
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}
```

**Related settings**

- `HOST_IP=127.0.0.1` keeps every published port off the LAN when the proxy runs on the same
  host.
- `OAUTH2_PROXY_COOKIE_SECURE` must match the scheme of `PAPAIA_HOST`: `true` for HTTPS,
  `false` for plain HTTP. Browsers ignore `Secure` cookies over HTTP, so a mismatch breaks
  login without an obvious error.
- `--reverse-proxy-provider=no_proxy` together with `--allow-direct-port-access` runs the stack
  with no proxy and no TLS at all. `setup` asks for confirmation. Development only.

### Multi-environment setup

Several papAIa stacks can run side by side on one host without forking the repo.
`--env=NAME` namespaces the installation:

| `--env` | `COMPOSE_PROJECT_NAME` | `DOCKER_NETWORK` |
|---|---|---|
| _(unset)_ | `papaia` | `papaia-net` |
| `dev` | `papaia-dev` | `papaia-dev-net` |
| `stage` | `papaia-stage` | `papaia-stage-net` |

Two rules make this work:

1. **`--env` is a `setup`-only flag.** `start` and `stop` read the project name from the
   persisted `.env`; you select an environment by pointing them at its `--config-dir`.
2. **Every environment needs its own `--config-dir`.** Otherwise the second `setup`
   overwrites the first environment's generated state.

Give each stack its own bind address — add IP aliases to the host's primary interface — so two
environments can keep identical port numbers:

```bash
tools/papaia-ctl setup --env=dev \
  --config-dir=/srv/papaia-dev/config \
  --host-ip=192.168.1.102 --app-host=http://192.168.1.102

tools/papaia-ctl setup --env=stage \
  --config-dir=/srv/papaia-stage/config \
  --host-ip=192.168.1.103 --app-host=http://192.168.1.103
```

Afterwards, operate each one by its config directory:

```bash
tools/papaia-ctl start --config-dir=/srv/papaia-dev/config
tools/papaia-ctl stop  --config-dir=/srv/papaia-stage/config
```

Remember that `PAPAIA_HOST` feeds the OIDC redirect URIs, and that
`OAUTH2_PROXY_COOKIE_SECURE` must match its scheme in every environment.

---

## Operations

Day-to-day operations — enabling modules, upgrading images, backups, resetting Keycloak — are
documented in [`docs/deployment.md`](docs/deployment.md).

The short version: edit `overlay/` or the profile list, then run `tools/papaia-ctl start`.
Upgrades are `git pull` followed by `tools/papaia-ctl start`; the config directory and
everything under `overlay/` survive untouched.

## Troubleshooting

Common failure modes — OIDC redirect mismatches, cookie loops behind oauth2-proxy,
`host.docker.internal` resolution on Linux — are collected in
[`docs/troubleshooting.md`](docs/troubleshooting.md).

---

## Repository layout

```
[workspace root]/
├── papaia/                    ← this repo (read-only at deploy time)
│   ├── tools/
│   │   ├── papaia-ctl          # Bash dispatcher (setup · start · stop · uninstall · addon)
│   │   ├── deployment.template.yaml  # deployment.yaml template
│   │   ├── pyproject.toml      # ruff + pytest config for tools/lib
│   │   ├── lib/                # Python: cli.py · cli_addon.py · deployment.py · envtree.py
│   │   │                       #   secrets.py · resolve.py · addons.py · defaults.py · reporting.py
│   │   │                       #   compat.py · semver.py · render_core.py · gen_override.py
│   │   │                       #   backup.py · common.py
│   │   │   └── sh/             # Bash command libraries sourced by papaia-ctl
│   │   └── tests/              # pytest suite
│   ├── src/
│   │   ├── docker-compose.yml  # root compose — shared network + include list only
│   │   ├── .env.example        # all stack-wide variables (source of truth)
│   │   ├── infra/              # keycloak · nginx · oauth2-proxy
│   │   ├── ai/                 # librechat · litellm · localai · mcp-firecrawl · jinaai
│   │   └── services/           # homepage · searxng · firecrawl
│   └── docs/
│       ├── architecture.md               # full architecture specification
│       ├── configuration.md
│       ├── deployment.md
│       ├── troubleshooting.md
│       └── adr/                # Architecture Decision Records
│
├── papaia-addons/             ← add-on repos cloned alongside (opt-in)
│   └── <name>/                # papaia-app.yaml + compose + integration fragments
│
└── papaia-config/             ← PAPAIA_CONFIG_DIR (generated, never committed)
    ├── deployment.yaml         # installation manifest
    ├── overlay/                # customer config overrides (highest merge layer)
    └── overrides/              # auto-generated add-on network overrides
```

---

## Further reading

- [`src/README.md`](src/README.md) — Compose-level orchestration, service toggles,
  common commands.
- [`src/infra/keycloak/README.md`](src/infra/keycloak/README.md) — Realm contents,
  client list, external-IdP migration, secret rotation.
- [`src/ai/README.md`](src/ai/README.md) — Per-AI-service summary.
- [`docs/architecture.md`](docs/architecture.md) — Full
  architecture specification: 3-tier model, add-on contract, integration seams,
  deployment manifest schema.
- [`docs/configuration.md`](docs/configuration.md) — Environment variable reference.
- [`docs/deployment.md`](docs/deployment.md) — Deployment guide and operations.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — Common failure modes.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — How to contribute.
- [`CHANGELOG.md`](CHANGELOG.md) — Release history.
