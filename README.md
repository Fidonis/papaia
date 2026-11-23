# papAIa

> Self-hosted, OIDC-first AI & document platform — Lean Core, built to extend.
> Developed and maintained by **Fidonis GmbH** · <https://www.fidonis.de>

papAIa is a Docker Compose platform that bundles a chat UI, an LLM proxy, local model
hosting, and a Keycloak-based SSO layer into a self-sufficient **Lean Core**. Additional
services — document management, workflow automation — attach through a standardised
**add-on contract** rather than being hard-wired into the stack.

It is built by [Fidonis GmbH](https://www.fidonis.de) on one premise: AI is only useful to
a mid-sized company if the company keeps control of its own data. Everything here runs on
the customer's own infrastructure, every model call leaves through a single auditable
gateway, and no component depends on a vendor that could withdraw it. Local, modular,
vendor-independent — that is what the architecture optimises for, and why the trade-offs
throughout this document fall the way they do.

This is the **1.10.0-rc.1** release candidate of 1.10.0: the Lean Core is stable,
`papaia-ctl` is the single idempotent orchestrator for the full deployment lifecycle, and the
add-on infrastructure is in place for first-party and custom service modules.

**Contents** — [Services](#services) · [Quick start](#quick-start) ·
[papaia-ctl reference](#papaia-ctl-reference) · [papaia-manager](#papaia-manager) ·
[Architecture](#architecture-overview) · [Advanced configuration](#advanced-configuration)

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
| papaia-manager | `manager` | 8120 | Browser control plane for the add-on lifecycle, the service overview, host health, model usage, backup/restore with scheduled backups, the nodes of a distributed installation, with the `rag` profile the RAG system's connections, collections and ingest jobs, and with the `knowledge-map` profile the AI map. Native OIDC. Linux hosts and Docker Desktop on macOS — see [papaia-manager](#papaia-manager). |
| Web search | `librechat-websearch` | — | SearXNG (metasearch), Firecrawl (crawler), the Firecrawl MCP bridge, and the Jina reranker. All internal-only; consumed by LibreChat. |
| RAG system | `rag` | 6333 / 8300 | Qdrant vector database, an OIDC + RBAC MCP server for LibreChat, and a scheduled document ingester, managed in papaia-manager. Not LibreChat's built-in file search — see [RAG system](#rag-system). |
| Mail relay | `smtp` | — | One internal SMTP relay that forwards to your mail server, so Keycloak can send password-reset mails and add-ons can attach it. No published port — see [Outbound mail](#outbound-mail). |
| Voice | `voice` | — | Local speech-to-text (Whisper) and text-to-speech (Chatterbox) behind LiteLLM, wired into LibreChat's speech panel. All internal-only — see [Voice](#voice-local-speech). |
| People lookup | `people` | — | Exact-match lookup of persons with an assistant role for the assistant's gate, and the members (`sub` only, at most 50) of a share group for Studio's notices: whole name, mail or group id only, role filter, rate limit, audit. No published port — see [docs/people.md](docs/people.md). |
| Knowledge map | `knowledge-map` | — | An OIDC-secured MCP directory of the installation's knowledge sources: tells the chat where knowledge lives, trimmed to the caller's roles. Internal-only — see [docs/knowledge-map.md](docs/knowledge-map.md). |
| Mein Bereich | `me` | — | The page where every person sees and changes their own settings of the installation's modules (`me-web`), and the preference store the modules read: notification channel, language, appearance, time zone (`prefs`, `prefs-db`). One pinned image, no host port; browsers reach it as `me.<domain>` through the proxy — see [Mein Bereich](#mein-bereich-me). |
| Connection registry | `connections` | — | One store for the saved credentials of mail, calendar and database accounts: a person adds an account once, a module receives it sealed for one call, every use is audited. Mutual TLS, two database logins, keys in their own volume. Reachable by Me and the add-ons that attach it only — see [Connection registry](#connection-registry-connections). |

`localai`, `manager`, `librechat-websearch`, `rag`, `smtp`, `voice`, `knowledge-map` and `connections` are toggled by `papaia-ctl setup`
(`--local-ai`, `--manager`, `--web-search`, `--rag`, `--smtp`, `--voice`, `--knowledge-map`, `--connections`). When LocalAI is enabled, setup also asks
which accelerator image to install — see [GPU acceleration](#gpu-acceleration-for-localai).
The `rag` profile is switched on by adding it to `COMPOSE_PROFILES`. Mein Bereich has no `setup`
option: `me` is switched on by adding it to `COMPOSE_PROFILES` as well. How to enable, address and
disable both, and what an upgrade and a backup do with them: [Mein Bereich](#mein-bereich-me) and
[Connection registry](#connection-registry-connections).

> Everything else — document management, workflow automation — ships as an
> [add-on](#add-ons), not as a profile in this repository.

> **Tip:** behind the bundled proxy only the edge publishes ports (see
> [Published ports](#published-ports)); the ports in the table and the `*_EXT_PORT` variables
> in `src/.env.example` apply with direct port access only.

**Authentication coverage**

| Service | Approach | Notes |
|---|---|---|
| LibreChat | Native OIDC | `openid-client`, PKCE enforced; login requires `librechat-user`, `librechat-admin` grants LibreChat's ADMIN role |
| LiteLLM (UI) | Generic OIDC | API key for programmatic access; `litellm-admin` grants Admin UI access |
| LocalAI | Native OIDC | Only users holding the `localai-access` realm role can sign in |
| papaia-manager | Native OIDC | `MANAGER_ADMIN_ROLE` grants full access, `MANAGER_USER_ROLE` the dashboard only, `MANAGER_IDENTITY_ADMIN_ROLE` the Users page |
| qdrant-mcp, qdrant-ingest (MCP) | OIDC bearer token | Validate the user token LibreChat forwards; audiences `mcp-qdrant` and `mcp-qdrant-ingest`; qdrant-ingest also requires the `qdrant-ingest-operator` realm role |
| NPM admin UI | oauth2-proxy sidecar | Restricted to `npm-admin` via `--allowed-group` |
| oauth2-proxy | Forward-auth gateway | Guards services without native OIDC |

Per-service admin roles (`librechat-admin`, `litellm-admin`, `manager-admin`,
`npm-admin`, ...) compose under one umbrella role, `papaia-admin` — grant that
for "admin everywhere", or grant a single per-service role for narrower
access. See `src/infra/keycloak/README.md` for the full role table.

---

## Quick start

### Prerequisites

- Docker and Docker Compose 2.20.0 or newer (the Compose files use `include:` and
  `depends_on.required`; [`doctor`](#doctor) checks it)
- Python 3.10+ — `papaia-ctl` generates secrets and renders configs itself
- PyYAML — `papaia-ctl` reads and renders YAML with it; not part of the standard
  library. On a minimal host install it with `sudo apt-get install -y
  python3-yaml` (Debian/Ubuntu), `sudo dnf install -y python3-pyyaml`
  (Fedora/RHEL), or `pip install 'PyYAML>=6.0'` in a virtual environment (macOS, see
  below)
- `openssl`, only when Keycloak TLS is enabled
- At least 8 GB RAM recommended ([`doctor`](#doctor) checks it)
- Linux, macOS, or WSL2

#### macOS

papAIa runs on Docker Desktop for Mac, on Apple Silicon and Intel. What differs from a
Linux host:

- **Docker Desktop memory.** The containers run in Docker Desktop's VM, so the 8 GB
  recommendation applies to the memory assigned to it (Settings > Resources). `doctor`
  measures what Docker reports.
- **Python.** The `python3` of the Xcode Command Line Tools is 3.9, too old for
  `papaia-ctl`. Homebrew no longer ships PyYAML as a formula, and its Python refuses a
  plain `pip install`, so install both into a virtual environment:

  ```bash
  brew install python
  "$(brew --prefix)/bin/python3" -m venv ~/.venvs/papaia
  ~/.venvs/papaia/bin/pip install 'PyYAML>=6.0'
  source ~/.venvs/papaia/bin/activate   # before running tools/papaia-ctl
  ```

  `papaia-ctl` then uses the environment's `python3`, and names the version it found
  when none is new enough.
- **Bash and OpenSSL.** The system Bash 3.2 and the system LibreSSL work; Homebrew's
  versions are not needed.
- **Paths.** Docker Desktop bind-mounts only the host paths it shares with its VM
  (Settings > Resources > File sharing; `/Users`, `/Volumes`, `/private`, `/tmp` and
  `/var/folders` by default). Keep the checkout, `--config-dir` and `--backup-dir` there:
  LibreChat mounts files from `src/ai/librechat/` in the checkout, as well as
  `LIBRECHAT_AGENTS_DIR` and `LIBRECHAT_PROMPTS_DIR` when they are set. A checkout under
  `/Users` with the default config directory next to it works. `/opt` works only after it
  is added under File sharing, and `/srv` cannot be created on the read-only system volume.
- **LocalAI on the Apple GPU.** In Docker Desktop's VM LocalAI runs on the CPU. On an
  Apple Silicon Mac with Docker Desktop, `setup` offers to run it natively on the GPU
  instead; see [Native LocalAI on Apple Silicon](#native-localai-on-apple-silicon).
- **papaia-manager.** It runs on Docker Desktop, with its workspace, configuration and
  backup directories below `/Users`; a checkout there with the default directories meets
  this. `setup` recognises Docker Desktop and defaults to *yes* there; with another
  engine it defaults to *no*, so leave the profile off (`--no-manager`). See
  [papaia-manager](#papaia-manager).
- **Keycloak certificate.** With the default local URLs, browsers on the Mac check
  Keycloak's certificate against the login keychain. `setup` offers to trust the
  generated local CA there once, for TLS server certificates only (no admin rights
  needed; macOS may still ask for the login password, and over SSH the step fails and
  `setup` prints the command). In a non-interactive run, or when the offer is declined,
  it prints the command instead:

  ```bash
  security add-trusted-cert -r trustRoot -p ssl \
    -k ~/Library/Keychains/login.keychain-db "$PAPAIA_CONFIG_DIR/certs/local-ca.crt"
  ```

  A local CA that `setup` creates can only sign for Keycloak's names (`keycloak`,
  `localhost`, `host.docker.internal`), and its key `certs/local-ca.key` is readable by
  its owner only. A CA from an earlier release keeps working without that limit. To
  replace it:

  1. Delete `$PAPAIA_CONFIG_DIR/certs/` and run `setup` again.
  2. Restart the stack with `papaia-ctl stop` and `papaia-ctl start`, so that Keycloak
     and the containers that read `local-ca.crt` pick up the new files.
  3. Remove the trust of the old CA from the login keychain. Both CAs are named
     `papaia-local-ca`, and a trust added by an earlier release covers every policy, not
     only TLS. List the certificates with that name and their SHA-1 hashes, then delete the
     old one by its hash (the new one's hash is shown by
     `openssl x509 -noout -fingerprint -sha1 -in "$PAPAIA_CONFIG_DIR/certs/local-ca.crt"`):

     ```bash
     security find-certificate -a -c papaia-local-ca -Z ~/Library/Keychains/login.keychain-db
     security delete-certificate -t -Z <SHA-1 of the old CA> ~/Library/Keychains/login.keychain-db
     ```

  4. Trust the new CA with the `security add-trusted-cert` command above.

  An add-on that issues certificates with this CA for names other than these three is
  affected by the limit as well (see Fidonis/papaia-addons#71).

  The browsers reach Keycloak at `host.docker.internal`, which resolves on the Mac only
  through an `/etc/hosts` entry; `setup` prints the command when it is missing.

  The server certificate is issued for 825 days with `serverAuth`, as macOS requires.
  `setup` renews an older or expiring one with the same CA, so the trust stays; restart
  the stack afterwards (`papaia-ctl stop`, `papaia-ctl start`).
- **Web search on Apple Silicon.** The Firecrawl MCP image exists for `linux/amd64` only and
  runs emulated; Docker Desktop provides the emulation (Rosetta or QEMU).
- **LocalAI.** Docker on macOS has no GPU access, so LocalAI runs on the CPU. `setup`
  detects this and picks the `cpu` variant.

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
search (and an optional reranker model), whether to enable local AI (and its public URL), and
whether to install the [RAG system](#rag-system) (and the public URL of Qdrant), and whether
to send mail through the [mail relay](#outbound-mail) (and the mail server behind it). Each
prompt is pre-filled with a sensible default; the RAG question defaults to *yes* on a new
installation, the mail question to *no*. Everything else — secrets, OIDC endpoints,
TLS certificates, rendered configs — is generated automatically.

For unattended / CI use:

```bash
tools/papaia-ctl setup --non-interactive \
  --app-host=https://papaia.example.com \
  --auth-host=https://auth.papaia.example.com
```

> In non-interactive mode, `--local-ai` and `--web-search` are **not** implied. Without those
> flags the corresponding profiles stay as they are — off, on a fresh install. The same holds
> for `--localai-variant`: omitted, the current image variant is kept. Pass
> `--localai-variant=auto` to let the host detection decide.

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
- Keycloak admin — `https://host.docker.internal:8110`, user `admin` (setup generates the
  password; read it with `grep KC_ADMIN_PASSWORD "$PAPAIA_CONFIG_DIR/infra/keycloak/.env" | cut -d= -f2`)
- papaia-manager — `http://host.docker.internal:8120`, when the `manager` profile is active
  (Linux hosts and Docker Desktop on macOS — see [papaia-manager](#papaia-manager))

The realm ships one account, `admin` (roles `papaia-admin`, `user`, `localai-access`), and
no test user. Its first password is generated by setup and must be changed at the first
sign-in; read it with
`grep KC_REALM_ADMIN_PASSWORD "$PAPAIA_CONFIG_DIR/infra/keycloak/.env" | cut -d= -f2`.
On an installation from an earlier release, the next `start` gives the old `admin` /
`admin` account this password the same way and disables `testuser` / `testuser` while
their passwords were never changed.

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
papaia-ctl stop      [--clean-up [--volumes]] [--addons] [--profiles=LIST] [--config-dir=PATH]
papaia-ctl upgrade   [--version=X.Y.Z] [--dry-run] [--force] [-y] [--identity=FILE|-]
                     [--no-rollback-key] [--stage=NAME[,NAME]] [--addon-path=NAME=DIR]
                     [--config-dir=PATH]
papaia-ctl upgrade   --resume [--identity=FILE|-] [--stage=NAME[,NAME]] | --release-lock [-y]
                     | --finalize [-y]
papaia-ctl rollback  [--restore-point=R0] [--identity=FILE|-] [--accept-data-loss] [-y]
papaia-ctl uninstall [--clean-up] [--addons] [-y] [--config-dir=PATH]
papaia-ctl backup    [--backup-dir=PATH] [--retention-period-days=N]
                     [--only=SELECTOR[,SELECTOR]] [--config-dir=PATH]
papaia-ctl backup-delete --restore-point=ID [--restore-point=ID ...] [--backup-dir=PATH]
                     [-y] [--config-dir=PATH]
papaia-ctl restore   [--from=PATH] [--restore-point=ID|latest] [--list]
                     [--only=SELECTOR[,SELECTOR]] [--restart-clean] [--no-restart]
                     [--insecure-images] [-y] [--config-dir=PATH]
papaia-ctl post-restore [--since=EPOCH] [--config-dir=PATH]
papaia-ctl halt set  [--reason=TEXT] [--config-dir=PATH]
papaia-ctl halt clear --reason=TEXT [--config-dir=PATH]
papaia-ctl halt status [--json] [--config-dir=PATH]
papaia-ctl delegations lifetime [--idle-days=N] [--max-days=N] [--json] [--config-dir=PATH]
papaia-ctl npm-provision [--config-dir=PATH]
papaia-ctl keycloak-role-sync [--config-dir=PATH]
papaia-ctl realm sync [--check] [--config-dir=PATH]
papaia-ctl realm keys apply <module> [--config-dir=PATH]
papaia-ctl pairing   <list [--json]|confirm --approve-pairings=SHA256> [--config-dir=PATH]
papaia-ctl pairing   <approve|revoke> --client=NAME --audience=NAME [--effects=rwdx]
                     [--config-dir=PATH]
papaia-ctl report    permissions --by=person|system [--format=json|csv] --token-file=PATH|-
                     [--config-dir=PATH]   (docs/permission-report.md)
papaia-ctl report    confirm --key=KEY --digest=SHA256 --token-file=PATH|- [--config-dir=PATH]
papaia-ctl breakglass <create --address=EMAIL|rotate|status> [--config-dir=PATH]
papaia-ctl service-account list [--json] [--config-dir=PATH]
papaia-ctl service-account rotate <id> [--grace=SECONDS] [--config-dir=PATH]
papaia-ctl status    [--json] [--profiles=LIST] [--addons] [--config-dir=PATH]
papaia-ctl doctor    [--json] [--skip=CHECK[,CHECK]] [--config-dir=PATH]
papaia-ctl addon     <install|start|stop|remove|uninstall> <name> [OPTIONS]
papaia-ctl addon     check [--target-core=PATH] [--json] [--force] [--config-dir=PATH]
papaia-ctl addon     upgrade <name> --path=DIR [--dry-run [--json]] [--no-backup] [--no-restart]
                     [--answers-file=FILE] [--force] [--insecure-images] [-y] [--config-dir=PATH]
papaia-ctl addon     rollback <name> [--restore-data] [--no-restart] [--force]
                     [--insecure-images] [-y] [--config-dir=PATH]
papaia-ctl addon     list [--json] [--config-dir=PATH]
papaia-ctl librechat clear-history <email> [--before=YYYY-MM-DD] [--dry-run] [-y]
                     [--config-dir=PATH]
papaia-ctl topology  <show [--json]|validate|firewall [--format=table|json|csv]>
                     [--config-dir=PATH]
papaia-ctl node      <add|list|check|remove|join-bundle|renew-link|sync> [OPTIONS]
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
| `--litellm-host=URL` | _(derived)_ | Public LiteLLM URL if it differs from `--app-host` |
| `--localai-host=URL` | _(derived)_ | Public LocalAI URL if it differs from `--app-host` |
| `--manager-host=URL` | _(derived)_ | Public papaia-manager URL if it differs from `--app-host` |
| `--qdrant-host=URL` | _(derived)_ | Public Qdrant URL; derived as `qdrant.<domain>` on the edge, `<app-host>:6333` with direct port access |
| `--npm-admin-host=URL` | _(derived)_ | Public URL of the Nginx PM admin UI |
| `--auth-provider=VALUE` | `internal_keycloak` | `internal_keycloak` or `external_oidc` |
| `--oidc-issuer=URL` | _(required for `external_oidc`)_ | External OIDC issuer URL |
| `--reverse-proxy-provider=VALUE` | _(auto-detected)_ | `internal_nginx`, `external_proxy`, or `no_proxy` |
| `--external-reverse-proxy` | _(auto from URL scheme)_ | Legacy alias for `--reverse-proxy-provider=external_proxy` |
| `--no-external-reverse-proxy` | — | Legacy alias for `--reverse-proxy-provider=internal_nginx` |
| `--allow-direct-port-access` | — | Skip the reverse proxy entirely; the core services publish ports directly through a generated override (expert, development only) |
| `--web-search` / `--no-web-search` | _(prompted, default on)_ | Toggle the `librechat-websearch` profile |
| `--reranker-model=NAME` | _(prompted, optional)_ | LiteLLM model name used for reranking |
| `--backup-dir=PATH` | `$PAPAIA_WORKSPACE_DIR/backup` | Default target of `papaia-ctl backup`; stored as `PAPAIA_BACKUP_DIR` |
| `--local-ai` / `--no-local-ai` | _(prompted, default on)_ | Toggle the `localai` profile |
| `--localai-variant=NAME` | _(prompted, auto-detected)_ | LocalAI accelerator image: `cpu`, `nvidia-cuda-12`, `nvidia-cuda-13`, `intel`, `hipblas`, `vulkan`, or `auto` |
| `--localai-runtime=container\|native` | _(prompted on an Apple Silicon Mac with Docker Desktop, default `native` there; `container` elsewhere)_ | Where LocalAI runs: in its container, or as a process on the Apple GPU ([Native LocalAI on Apple Silicon](#native-localai-on-apple-silicon)). `native` is refused with exit 2 on any other host (and while Docker Desktop is not running); `container` is accepted everywhere |
| `--manager` / `--no-manager` | _(prompted, default on; on macOS off unless Docker Desktop)_ | Toggle the `manager` profile |
| `--rag` / `--no-rag` | _(prompted, default on)_ | Toggle the `rag` profile. `--rag` is refused while the `qdrant`, `qdrant-connect` or `qdrant-ingest` add-on is active |
| `--voice` / `--no-voice` | _(prompted, default off)_ | Toggle the `voice` profile (the local [speech engines](#voice-local-speech)) |
| `--voice-variant=cpu\|nvidia\|hipblas\|auto` | _(prompted while voice is on)_ | Which image the TTS engine runs on; `auto` probes the host like the LocalAI image choice |
| `--knowledge-map` / `--no-knowledge-map` | _(prompted, default off)_ | Toggle the `knowledge-map` profile (the [knowledge map](docs/knowledge-map.md)); switching it on also generates its secrets on an installation set up before the module existed |
| `--connections` / `--no-connections` | _(prompted, default off)_ | Toggle the `connections` profile (the connection registry, [ADR 0021](docs/adr/0021-connection-registry-as-a-core-profile.md)); its two database passwords are generated once |
| `--smtp` / `--no-smtp` | _(prompted, default off)_ | Toggle the `smtp` profile (the [mail relay](#outbound-mail)). `--no-smtp` keeps the stored settings |
| `--smtp-host=HOST` | _(prompted)_ | Mail server the relay forwards to: host name or IPv4 address, no scheme and no port |
| `--smtp-security=MODE` | `starttls` | `starttls`, `tls` (implicit TLS) or `none` (no encryption and no login) |
| `--smtp-port=PORT` | by mode: 587, 465, 25 | Port of the mail server |
| `--smtp-user=NAME` / `--smtp-no-auth` | _(prompted)_ | Login of the mail server, or none. The password is read from the environment variable `PAPAIA_SMTP_PASSWORD`, never from an argument |
| `--smtp-from=ADDRESS` | _(prompted)_ | Address the mails are sent from |
| `--smtp-from-name=NAME` | the installation name | Accepted only when it repeats the name of the installation (`name` in `overlay/platform/branding.yaml`, `papAIa` without it): every mail is sent under that name |
| `--force` | — | Regenerate all secrets unconditionally |
| `-y` / `--non-interactive` | — | Skip all prompts; supply required values as flags. Never confirms pairings |
| `--approve-pairings=SHA256` | _(prompted)_ | Confirm the pairings of the signed bill of materials whose list has this sha256 (as `setup` and `papaia-ctl pairing list` show it); the one way to confirm them without the question |
| `--env-only` | — | Re-write the `.env` files only; skip reconfiguration |
| `--topology=single\|distributed` | `single` (prompted for a new installation) | One machine, or several machines (see [Distributed installations](#distributed-installations)) |
| `--node=NAME=ADDR[,ssh=USER@HOST[:PORT]][,root=DIR][,gpu=HINT]` | — | A machine of a distributed installation, repeatable. A node without `ssh=` is the controller: the machine `setup` runs on |
| `--controller=NAME` | _(the node without `ssh=`)_ | Which node is the controller |
| `--preset=dmz-split\|dmz-edge` | — | Placement for two nodes: `dmz-split` puts Nginx Proxy Manager, Keycloak, the mail relay and LiteLLM on the other node, `dmz-edge` only Nginx Proxy Manager and LiteLLM |
| `--place=SERVICE=NODE` | — | Place one service, repeatable (overrides the preset). Services: `nginx`, `keycloak`, `litellm`, `librechat`, `websearch`, `localai`, `rag`, `smtp`, `manager` |
| `--link-port=PORT` | `7443` | The port the nodes connect to each other on |
| `--topology-file=PATH` | — | The `topology` block from a file instead of the flags above; keeps the choice reviewable |

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
- **Pairings** — when the signed bill of materials of the checkout lists exchange-right
  pairings (which module client may exchange a person's token for which audience),
  `setup` shows each one with client, audience, effects and whether it reads or writes,
  and the sha256 of the list, and asks once. Yes (or `--approve-pairings=<sha256>`)
  confirms the read pairings; every pairing that writes or deletes waits for a second
  person (`papaia-ctl pairing approve`, run by another host account) and is assigned to
  no client until then. `-y` never confirms: `setup -y` completes, assigns nothing of the
  list and prints the command to confirm it later. Each decision is an audit row with
  the host account and the time. See "Pairing approval" in
  [`docs/architecture.md`](docs/architecture.md).
- **Modules offered** — `setup` then names the modules this release offers (Studio, Data,
  Flow, Assistant, Paperless). Paperless is offered only when the signed bill of materials of the checkout lists
  its gate (an image with `component: paperless-gate`); without it, or in a checkout
  without a bill of materials, `setup` says that Paperless is not offered and why. A bill
  of materials that does not verify stops `setup`.

**Distributed setup.** A distributed installation is set up once, as a new installation.
`setup` asks for it interactively ("on this machine" or "on several machines": names and
addresses of the two machines, a preset or a node per service, the link port), or takes
`--topology=distributed` with `--node` and `--preset`/`--place`, or a `--topology-file`. It
validates the placement before anything is written, renders one bundle per node, prints the
topology and the firewall rules to open, and writes a join archive for every node that is not
enrolled yet (see [`node`](#node)). Once every node is enrolled it runs a preflight (SSH,
Docker, Compose, clock) and offers to start the installation.

`setup --topology=distributed` on a config directory that already holds an installation exits
with 2 and changes nothing: an existing installation keeps its shape, and a repeated `setup`
asks nothing new. To move an installation onto several machines, set the distributed one up
in a new config directory and bring the data over with `backup` and `restore`.

```bash
tools/papaia-ctl setup -y --app-host=https://papaia.example.org \
  --auth-host=https://auth.example.org --librechat-host=https://chat.example.org \
  --litellm-host=https://llm.example.org \
  --topology=distributed --node=internal=10.0.2.10 \
  --node=edge=10.0.1.10,ssh=papaia@10.0.1.10 --preset=dmz-split
```

### `start`

```bash
tools/papaia-ctl start [--addons] [--profiles=LIST] [--insecure-images] [--config-dir=PATH]
```

Adds any variable the checkout's `.env.example` files ship and the config directory's
`.env` lacks (existing values are never changed), copies the `.env` files from the config
directory into the checkout, re-renders the configuration, then runs `docker compose up -d`.

Because rendering happens on **every** `start`, new templates, new add-on fragments and
edits under `overlay/` are rendered into the configuration directory automatically. A
container that is already running keeps the file it was created with (most targets are
bind-mounted single files, and a render replaces the file), so an edit takes effect once the
service is recreated: `papaia-ctl stop --clean-up --profiles=<profile>` followed by `start`.
To move the installation to a newer
release, use [`upgrade`](#upgrade) rather than `git pull` — it also runs the migrations
the release ships with.

`--addons` starts every active add-on **before** bringing up the core, so that the add-on
networks exist by the time the core's generated override files are applied. An override whose
network does not exist yet is skipped rather than failing the start.

`start` runs the compatibility check of [`addon check`](#addon) against all active add-ons
before bringing up the core, with or without `--addons`. If any add-on is INCOMPATIBLE the
start is aborted: an add-on the core no longer supports, or one whose required add-ons
(`requires.addons`) are not active or no longer in range. Pass `--force`, or set warn mode
(`PAPAIA_COMPAT_MODE=warn` or `mode: dev` in `deployment.yaml`), to demote incompatibility to
a warning and proceed.

Before the first container starts, `start` checks every image it is about to run against the
signed suite bill of materials of the checkout: see [Image pinning and
signatures](#image-pinning-and-signatures). An image that is not listed with its digest, or
not signed, aborts the start; nothing is started.

`--profiles` takes a comma-separated list of Compose profiles and overrides `COMPOSE_PROFILES`
for this invocation only. The selection is validated up front: a profile list that names no
service, or that cuts off a service from a dependency it hard-requires, is rejected with exit
code 2 instead of being handed to Compose.

In a distributed installation `start` renders the node bundles, hands every node its release
and its bundle, and starts in order: the link gateways, then Keycloak and the mail relay, then
LiteLLM, then LibreChat, web search, the RAG system, LocalAI and papaia-manager, and the Nginx
Proxy Manager last, so nothing is reachable half-started. Every service starts on the node it
is placed on. The provisioning steps run on the node of their service. `--node=NAME` starts
one node only. A node that fails stops the sequence with a message that names it; whatever
already runs keeps running, and running `start` again is safe.

### `stop`

```bash
tools/papaia-ctl stop [--clean-up [--volumes]] [--addons] [--profiles=LIST] [--config-dir=PATH]
```

Without `--clean-up`: `docker compose stop` — containers are paused but not removed; volumes
and networks are kept. With `--clean-up`: `docker compose down` — containers are removed,
volumes are kept. `--addons` applies the same operation to all active add-ons.

`--profiles` restricts the operation to the services of those profiles and is validated the
same way as on [`start`](#start) — without that gate an unresolvable profile list would make
Compose fall back to stopping every container of the project.

In a distributed installation `stop` runs the start order backwards (the proxy first, the
link gateways last). `--node=NAME` stops one node; `--volumes` is not available there.

`--volumes` (only together with `--clean-up` and `--profiles`) also deletes the data of those
profiles: `docker compose down --volumes` removes the named volumes of their services and the
anonymous volumes of their containers (a Redis or Postgres image declares one). It is limited to
the optional modules (`localai`, `librechat-websearch`, `rag`, `smtp`, `voice`, `knowledge-map`, `connections`); the always-on services and
the manager keep their data, and any other profile is refused before anything runs. A volume that
a service of another profile still mounts is left in place by Compose.

With a [native LocalAI](#native-localai-on-apple-silicon), `stop` also unloads and disables its
launchd job first (unless `--profiles` leaves `localai` out), and `--volumes` with the `localai`
profile also deletes its `models/` and `backends/` directories.

papaia-manager's Settings > Modules tab switches the optional modules on and off with these
pieces and offers to delete a module's data and settings when it switches one off. It uses two
internal commands of the core's Python entry point (`python3 -m lib.cli --repo-root R
--config-dir C ...`): `module-info --module=NAME` prints the named volumes the module owns, whether
they exist, what its settings consist of and the questions `setup` asks when the module is
switched on (the public URL of LocalAI and of Qdrant: the `setup` option that takes the answer,
the default derived from the stack's host and whether the question is still open), as JSON, and
writes nothing; `module-purge
--module=NAME [--data] [--config] [--operator-files]` removes the module's named volumes (by name, from the compose
files' own table of who mounts what; for a native LocalAI its `models/` and `backends/`
directories instead, listed under `directories` by `module-info`) and/or puts its settings back
to what the release ships (its
`.env` files and the public URL kept in the root `.env`, plus the files it keeps outside them:
the mail relay's password, the RAG catalog, the rendered knowledge map). `--operator-files`
deletes what the operator wrote by hand for the module (the knowledge map's declarations,
overrides, governance records and gold set, listed under `operator_files` by `module-info`)
and the rendered map built from them; neither `--data` nor `--config` touches these files. A question is open when its stored URL is empty, a
placeholder or the one the release ships, which is what the reset leaves, so a front end can ask it
again before it switches the module on. A later `setup` run derives the URL from the stack's host
again and closes the question.
Both refuse a module that is still switched on, and `--config` for the RAG system only together
with `--data`: the ingester's stored credentials are encrypted with a secret that
`--config` regenerates, so the settings cannot be reset with the data kept. The documents folder
of the RAG system is never deleted. Generated secrets are regenerated only where no other module
holds a copy; for the others the module's generated values stay as they are.

### `upgrade`

```bash
tools/papaia-ctl upgrade [--version=X.Y.Z] [--dry-run] [--force] [-y] \
  [--insecure-images] [--identity=FILE|-] [--no-rollback-key] [--stage=NAME[,NAME]] \
  [--addon-path=NAME=DIR ...] [--config-dir=PATH]
tools/papaia-ctl upgrade --resume [--identity=FILE|-] [--stage=NAME[,NAME]] [-y]
tools/papaia-ctl upgrade --release-lock [-y]
tools/papaia-ctl upgrade --finalize [-y]
tools/papaia-ctl rollback [--restore-point=R0] [--identity=FILE|-] [--accept-data-loss] [-y]
```

Moves the installation to a release. Without `--version` the newest release is used;
when the installation already runs it, the command reports so and exits 0, which makes
it safe to run unattended. `--version` accepts `1.9.0` and `v1.9.0` alike and is the
only way onto a pre-release. Downgrades are refused — restore a backup instead.

The run, in order:

1. Refuses to start unless the checkout is a git clone without uncommitted changes to
   tracked files. Everything `papaia-ctl` writes into the checkout is gitignored, so a
   healthy installation passes.
2. Fetches the release tags and resolves the target version.
3. Checks all active add-ons against the target release — the same evaluation as
   `addon check --target-core=PATH`, run against a temporary worktree of the target
   tag. An incompatible add-on aborts the upgrade before anything is touched, and so
   does an add-on whose required add-ons (`requires.addons`) are not active or not in
   range; `--force` demotes it to a warning.
   Then every image of the target release is checked against the target's signed
   bill of materials, and that bill against the release key of the installed checkout
   (digest and signature, see [Image pinning and
   signatures](#image-pinning-and-signatures)); a mismatch aborts before anything is
   changed. `--force` does not lift this; only `--insecure-images` does.
   Then stage 0 makes the rollback key of this upgrade (see *Rollback key* below); with
   `--no-rollback-key` the backup key of the operator is checked instead, and without a
   matching key nothing is started.
4. Creates restore point R0 (`backup`, encrypted to the backup recipients and to the
   rollback key), switches
   the write lock on and stops the stack. A restore point is mandatory; `--no-backup`
   is refused.
5. Checks out the release tag and re-executes itself from the new tree, so the
   migrations, the render logic and the setup pass of the target release are the ones
   that run.
6. Runs the pending migration scripts (see below), re-renders the configuration
   through the sticky setup pass — every answered question is kept — and starts the
   stack again.
7. Runs the module stages and ends the write lock.

`--dry-run` stops after step 3 and prints the current version, the target version, the
migrations that would run and every stage with what it does to each module. It needs no
key. `-y` skips the confirmation prompt; without a TTY it is required.

**Stages.** The upgrade runs in stages, in this order:

| Stage | What happens |
|---|---|
| 0 `preflight` | add-on check against the target and its suite matrix, image check, backup key check |
| 1 `restore-point` | restore point R0; from here on the write lock is on |
| 2 `core` | core and manager: tag change, migrations, render, start |
| 3 `me` | nothing for the core profile `me`: its image is pinned in the core's compose file and changes with the core in stage 2. Only an installation that still runs Me as an add-on gets an `addon upgrade` here, from `--addon-path=papaia-me=DIR`; otherwise the plan lists the stage as `absent` |
| 4 `data`, 5 `studio`, 6 `flow`, 7 `assist` | `addon upgrade` of the module from the checkout given with `--addon-path=NAME=DIR` |
| 8 `finish` | write lock off; the duration of each stage is printed |

`--stage=core` runs stages 0 to 2 only; after stage 2 the module stages may run one at a
time and in any order with `upgrade --resume --stage=NAME`, as long as a module that
another one requires (`requires.addons`) comes first. Without `--stage` every stage that
is still due runs in the order above (Data before Studio).

A module without `--addon-path` stays at its version when the target core still accepts it
(its version is in the target's suite or the one before it, `compat/suite.yaml`); the plan
then says that an update is recommended. A module the target does not accept stops the
upgrade before anything changes, naming the module and the versions the target accepts.
With `--force` the upgrade goes ahead, and that module is stopped, set inactive and marked
`blocked` in `deployment.yaml` (with the reason); its data is not touched. Install a version
the target accepts with `addon install` and start it to bring it back. A module that is not
installed is not installed by the upgrade.

**Rollback key (stage 0).** Stage 0 makes a one-off age key pair for the upgrade. Restore
point R0 is encrypted to the backup recipients **and** to this key, so `papaia-ctl rollback`
can open R0 without the operator's private key, also at night with the key safe out of
reach. The private key lives on this host only, in
`$PAPAIA_CONFIG_DIR/state/rollback/<upgrade-id>.key` (folder `0700`, file `0600`); `backup`
never archives `state/`, so it never reaches the backup target. It opens R0 only, that is
data that lies on this host in clear anyway; the delegation and revocation list keys are
not in R0. Somebody with access to the backup target alone still cannot read R0.

The key is deleted by `upgrade --finalize -y` once you keep the upgrade, by `rollback` and
`upgrade --release-lock` (the run ends without the upgrade), and otherwise when its window
ends: `PAPAIA_ROLLBACK_WINDOW_HOURS` (root `.env`, default `72`, from `24` to `168`) after the
upgrade finished. `backup` (for example the scheduled one), `upgrade` and `rollback` remove a
key whose window has ended; `doctor rollback_window` shows the time left and fails for a key
still there after its window. Every key made or deleted writes one `papaia.audit/1` row
(`rollback-key`, ids and the public key only).

**Backup key (stage 0, RE-85).** Without a rollback key (`--no-rollback-key`, a distributed
installation, or when none could be made) the way back needs the backup key of a recipient
in `PAPAIA_BACKUP_RECIPIENTS`. Stage 0 then asks for it with `--identity=FILE` (or
`--identity=-` to read it from standard input) and opens a check block encrypted to those
recipients with it. If that fails, the upgrade stops with "Without a matching backup key
there is no way back; the upgrade was not started." and nothing has changed. A key given
with a rollback key in place is checked the same way. The key is only held in memory; it is
never written to disk. `upgrade --resume` needs it only for a run without a rollback key.

**Write lock.** From restore point R0 until the finish stage, `$PAPAIA_CONFIG_DIR/state/
write-lock.json` (`papaia.write-lock/1`) is present. It sits next to the halt file in the
folder every service mounts read-only (see [docs/halt.md](docs/halt.md)); a service that
finds it active accepts reads only and answers every write with "The installation is being
updated. Your change was not saved. Please try again once the update has finished." A lock
file that cannot be read counts as active. When a stage fails, the lock stays, so going
back to R0 loses no data. The failure output names the way back:
`git checkout` of the previous tag, `restore --restore-point=R0`, then
`upgrade --release-lock -y`, which ends the lock only when both the checkout and the
configuration are back at the release the upgrade started from. The same in one command is
`papaia-ctl rollback -y` (see [`rollback`](#rollback)). A retried
`upgrade --version=X.Y.Z` to the same target keeps R0; `upgrade --resume` continues the
module stages. The state of the run is in `$PAPAIA_CONFIG_DIR/state/upgrade.json`; every
change of state (begin, each stage, a blocked module, finish, lock released) writes one
`papaia.audit/1` row with the run's correlation id.

**First upgrade into the staged release.** The first phase of an upgrade (stage 0, the
restore point, the stop and the checkout) always runs from the installed release. Coming
from a release without staged upgrades (1.9.0 and earlier, including 1.8.0), that is the
old first phase: it takes a restore point unless `--no-backup` is given, but checks no
backup key, takes no write lock and accepts no `--identity`, `--stage` or `--addon-path`.
Start it as before, `upgrade --version=X.Y.Z -y`. The target's second phase then takes the
run over: it records the restore point the old phase took as R0, switches the write lock on,
plans the module stages against the target's add-on check and suite matrix (each module
stays, or with `--force` is blocked) and runs stages 2 to 8 as usual; the upgrade exits 0
when they pass. Upgrade the modules afterwards with `addon upgrade`. If the old phase ran
with `--no-backup`, there is no R0: the second phase stops before any migration, with the
stack stopped and the configuration unchanged, and names the way back (`git checkout` of
the previous tag, `start --addons`); run the upgrade again without `--no-backup`. Every
later upgrade runs all stages, the key check included, from its first phase.

**Migrations.** A release may ship scripts in `tools/migrations/` that adapt an
existing config bundle to a change the render pass cannot express on its own. Every
release carries the complete set, so a jump from 1.0.0 to 1.9.0 runs the 1.1.0 … 1.9.0
steps in between, in order. Applied migrations are recorded in
`$PAPAIA_CONFIG_DIR/migrations/applied.json` and never run twice. If one fails, the
upgrade stops and prints the commands to return to the previous release; fixing the
cause and re-running skips everything that already succeeded. The contract for writing
one is documented in [`tools/migrations/README.md`](tools/migrations/README.md).

**Distributed installations** are upgraded as a whole: every node has to answer, a restore
point of the whole installation is taken, the installation is locked and stopped on every node,
every node gets the release, each migration runs on the node whose data it reshapes, and the
installation starts again in order. Until the upgrade has finished — and whenever a node runs
another release than the controller — `start`, `backup`, `setup` and the add-on commands refuse
with the reason. `upgrade` and the way back (`restore`) still work, and `start --unlock` releases
the lock after an upgrade abandoned without a restore point. A failure names the way back for
the controller and for every node. See [docs/distributed.md](docs/distributed.md#upgrades).

### `rollback`

```bash
tools/papaia-ctl rollback [--restore-point=R0] [--identity=FILE|-] [--accept-data-loss] [-y] \
  [--insecure-images] [--config-dir=PATH]
```

Goes back to restore point R0 of the last upgrade in one command, the command a failed
upgrade names. It reads the run from `state/upgrade.json`, checks out the release tag the
upgrade started from, and hands over to that release's `papaia-ctl`, which runs
`restore --restore-point=R0 --restart-clean` (the add-ons' erasure journals and the
post-restore step run before any add-on starts again, with the trigger `rollback`), ends the
run, removes the write lock and the rollback key, and finishes with `doctor`.

- **Key.** While the upgrade's rollback key exists (see *Rollback key* under
  [`upgrade`](#upgrade)), no operator key is needed. After its window, after
  `upgrade --finalize`, or for an upgrade without one, pass the backup key of a recipient
  with `--identity=FILE` or `--identity=-` (standard input, together with `-y`). Before
  anything changes, the key must open every archive of R0 and each archive must still match
  its checksum; otherwise the command stops with exit 2 and nothing changed.
- **Data written after the upgrade.** For an upgrade that already finished, the
  installation accepted writes after it; they are lost. `rollback` says so and needs
  `--accept-data-loss` (or typing `ja` at a terminal); `-y` does not replace it. While an
  upgrade is not finished the write lock kept every write out, so no such confirmation is
  asked.
- `--restore-point` may only name R0 of the run; any other point is restored with
  [`restore`](#restore).
- Not available for a distributed installation, and only back to a release that has the
  `rollback` command; otherwise it prints the steps (checkout, `restore`) and changes
  nothing.

Exit codes: `0` rolled back and `doctor` passed, `2` refused before any change, `3` the
rollback stopped or `doctor` reports a failure afterwards.

### `uninstall`

```bash
tools/papaia-ctl uninstall [--clean-up] [--addons] [-y] [--config-dir=PATH]
```

Stops and removes all core containers, then **permanently deletes the config directory**.
Prompts for confirmation; `-y` / `--yes` skips the prompt. `--clean-up` also removes the
Docker volumes. `--addons` stops and removes active add-on containers first.

Some data below the config directory is written by containers as root (the Nginx Proxy Manager
database and certificates in `infra/nginx/nginx-data/`, for one). What the operator cannot
delete is deleted through a short-lived `alpine:3` container that mounts the directory. If that
fails too, `uninstall` exits 1 and names the directory and the `sudo rm -rf` that removes it.
It never does this for `/` or for a directory that is or contains the home directory or the
papaia checkout.

### `backup`

```bash
tools/papaia-ctl backup [--backup-dir=PATH] [--keep=N] [--retention-period-days=N]
                        [--only=SELECTOR[,SELECTOR]] [--config-dir=PATH]
tools/papaia-ctl backup recipients list|add|remove [--name=NAME] [--key=age1...]
tools/papaia-ctl backup keys generate [--names=betrieb,notfall]
tools/papaia-ctl backup target init|check [--backup-dir=PATH]
tools/papaia-ctl backup key-check --identity=FILE|- [--restore-point=ID] [--from=PATH]
```

Every archive is encrypted with [age](https://age-encryption.org/v1) to the public keys in
`PAPAIA_BACKUP_RECIPIENTS` of the root `.env` before it reaches the target; a backup without a
recipient is refused, never written unencrypted. The private keys are never stored by
papaia-ctl: not in the configuration directory, not in an archive, not at the target. The
encryption uses the OpenSSL library of the Python interpreter papaia-ctl already runs with, so
nothing else has to be installed. See [Backup keys and target](#backup-keys-and-target) below.

Archives the complete installation into a timestamped subdirectory of the backup location:

- **`$PAPAIA_CONFIG_DIR`** in full — this also captures the Nginx Proxy Manager database and the
  Let's Encrypt certificates, which are bind mounts underneath it rather than named volumes.
  The platform halt (`state/`, see [`halt`](#halt)) stays out, and `restore` keeps it as it is
  on the host.
- **every named volume of the core stack**, resolved from the compose files and prefixed with the
  configured `COMPOSE_PROJECT_NAME`.
- **every named volume of an active add-on**, plus the host directories it bind-mounts for user
  data. An add-on that only talks to an existing external instance owns no volumes, so that
  external instance is never pulled into the backup.

Never archived, whatever a manifest says: the delegation keys of the assistant and of flow
(`assist-delegation-key`, `flow-delegation-key`), the signing key of the revocation list
(`papaia-lifecycle-key`), the local copy of the erasure journal (`papaia-erasure`), the rollback
keys of an upgrade (`state/rollback/` in the config directory) and the key of the test stack's
hosted model. A restored installation therefore makes new keys, and delegations issued before
the backup stop being valid. An add-on declares further volumes to leave out in its manifest
(contract generation 13), each with a reason:

```yaml
volumes:
  - name: flow-db
    backup: include
  - name: flow-cache
    backup: exclude
    reason: rebuilt from the database at start
```

A declaration that does not parse, names a volume the add-on's compose file does not declare,
or includes one of the key volumes above stops the backup. While an archive is written, its
stream is read once more: a file under `state/rollback/`, the hosted model's key, or any file
holding a private age key (`AGE-SECRET-KEY-1...`, in any case) fails that archive and nothing
of it is kept. This scan reads every file as stored, so a key inside a nested archive or
compressed file is not seen; the exclusion by volume and path is the first line of defence.
The manifest lists what was left out under `excluded`, with the reason.

| Flag | Default | Purpose |
|---|---|---|
| `--backup-dir=PATH` | `PAPAIA_BACKUP_DIR` from the root `.env` | Where to write this backup; must be a confirmed target (`backup target init`) |
| `--keep=N` | _(no pruning)_ | Keep the N newest usable restore points and delete older ones; failed runs never push a good point out. `--keep=7` with a daily run keeps a week |
| `--retention-period-days=N` | _(no pruning)_ | Delete restore points older than N days and drop their catalogue entries |
| `--only=SELECTOR[,SELECTOR]` | _(whole installation)_ | Archive only the selected units: the volumes and writable data directories owned by `addon:NAME`, the volumes of `module:NAME`, or one `volume:NAME`; the prefix is mandatory. In a distributed installation `node:NAME` selects everything of one node. The config directory is not part of it. A selector that matches nothing exits with code 2 and writes no archive |
| `--config-dir=PATH` | `../papaia-config` | Config directory location |

In a distributed installation the restore point is written on the controller as well: every
node's volumes, the state a remote node keeps (the proxy's database and certificates) and the
data of the add-ons placed on it are streamed into it, and each artifact records its `node`.
The nodes are archived one after another, so the result is not one moment across nodes; see
[docs/distributed.md](docs/distributed.md#backups).

Backups run **hot** — nothing is stopped. Because copying a live database directory would
otherwise capture it mid-transaction, the containers writing to a volume are paused for the
duration of that one archive and unpaused immediately afterwards, including when the archive
fails or the run is interrupted.

The backup location holds one directory per restore point plus two shared files:

```
$PAPAIA_BACKUP_DIR/
├── .papaia-target              # this installation's id: confirms the directory as its target
├── backup.yaml                 # catalogue: id, path, size in MB, result, recipients
├── backup.log                  # one line per backup / restore, with its result
├── latest/
│   ├── RELEASE                 # copy of the RELEASE of the newest good point
│   └── POINT                   # its id
└── 2026-07-30_14-05-33/
    ├── RELEASE                 # unencrypted: core tag, suite, installation id (no person, no key)
    ├── manifest.yaml           # archive per volume or path, its SHA-256, recipients, exclusions
    ├── checksums.tsv           # SHA-256 of each encrypted archive as it was written
    ├── papaia-config.tar.gz.age
    ├── volumes/*.tar.gz.age
    └── binds/*.tar.gz.age
```

Each `.tar.gz.age` file opens with the `age` command and one of the private keys
(`age -d -i key.txt FILE | tar tzf -`). `restore` in this version reads unencrypted restore
points only; for an encrypted one it stops with exit code 2, names the point and its
recipients, and changes nothing.

`RELEASE` is plain text, readable with any editor or file browser, so after the loss of the
host the release to check out is known before there is a checkout:

```
id: 2026-07-30_14-05-33
tag: v1.10.0
suite: 1.10.0
installation_id: 6f1c…
```

`latest/` names the newest restore point of the whole installation with result `ok`; `backup`,
`backup-delete` and the retention run move it. `restore --restore-point=latest` restores that
point.

Restore-point ids use local time, so they line up with what an incident timeline says;
`created_at` in the catalogue is UTC so sorting and retention stay unambiguous.

A scoped backup (`--only`) is a restore point of its own: it holds the selected units and nothing
else, records them as `scope` in its manifest and catalogue entry, and `restore --list` shows
the scope next to the result (`all` for a backup of the whole installation). Restore it with
`restore-scoped --only=...`; a plain `restore` of it is refused with exit code 2, because that
would take the stack down and replace a configuration directory the snapshot does not hold. A
plain `restore` without `--restore-point` skips scoped backups when it picks the newest one.
The backup id is printed in the same line as for a full backup
(`backup complete: <id> (...)`), so a caller can capture it.

A run whose archives partly failed is recorded as `partial` and is never selected automatically
by `restore`. Volumes that a compose file declares but that were never created (a disabled
profile) are reported and skipped rather than failing the run.

### Backup keys and target

**Keys.** `backup keys generate` makes two key pairs, `betrieb` (operations) and `notfall`
(emergency), on a terminal only. The private keys are shown once and not stored; the command
stores the two public keys only after the last eight characters of the first private key were
typed back. Keep the two apart (operations at hand, emergency in a safe). A key made elsewhere
(`age-keygen`, a hardware token's recipient) is added with
`backup recipients add --name=NAME --key=age1...`. Changes apply from the next backup on.
`backup recipients remove --name=NAME` lists the restore points that stay readable with the
removed key, with the date the newest of them was taken, until retention or `backup-delete`
removes them; the last recipient cannot be removed. A run with a single recipient warns: a lost key then makes every point unreadable.

**Key check.** `backup key-check --identity=-` reads a private key from standard input (or
`--identity=FILE`, also a passphrase-protected identity file, whose passphrase is asked on the
terminal), opens the header of the newest encrypted restore point with it and names the
recipient it belongs to. Nothing is restored and the key is never written to disk; the date of
the check is recorded per recipient in `backup-key-check.yaml` of the config directory. Check
the emergency key right after generating it and then at least every 180 days.

If a key is lost: add a new recipient at once, remove the lost one, take a new backup and run
`key-check` with the new key. Older points stay readable only with the other recipient's key;
without one they are lost.

**Target.** There is no default target. A directory (local disk, NFS or SMB mount) becomes the
backup target once `backup target init --backup-dir=PATH` wrote `.papaia-target` with this
installation's id (`installation-id` in the config directory, made on first use). `backup`
stops with exit code 3 and writes nothing when the directory does not exist, has no
`.papaia-target` (an unmounted share looks like this), belongs to another installation, or has
less free space than twice the last complete restore point. The id travels with the config
directory, so a restore on another host recognises the same target. Keep a copy of the target
off-site (3-2-1 rule); the keys are not needed to copy it.

**Schedule.** papaia-manager schedules backups on its Backup page. Without the manager, a
systemd timer runs one backup a day and keeps seven:

```ini
# /etc/systemd/system/papaia-backup.service
[Unit]
Description=papaia backup
[Service]
Type=oneshot
WorkingDirectory=/srv/papaia/workspace/papaia
ExecStart=/srv/papaia/workspace/papaia/tools/papaia-ctl backup --keep=7

# /etc/systemd/system/papaia-backup.timer
[Unit]
Description=papaia backup, daily at 02:30
[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now papaia-backup.timer`. A failed run exits non-zero, which
`systemctl status papaia-backup` and the journal show; `backup.log` at the target has one line
per run with its result.

### `backup-delete`

```bash
tools/papaia-ctl backup-delete --restore-point=ID [--restore-point=ID ...] [--backup-dir=PATH] \
                               [-y] [--config-dir=PATH]
```

Removes specific restore points — the snapshot directory and its `backup.yaml` entry — when
the age-based `--retention-period-days` of `backup` is too blunt (a single known-bad snapshot,
or reclaiming space without moving the retention window).

| Flag | Default | Purpose |
|---|---|---|
| `--restore-point=ID` | _(required)_ | Restore point to delete. Repeatable, and each value may be a comma-separated list |
| `--backup-dir=PATH` | `PAPAIA_BACKUP_DIR` from the root `.env` | Where the restore points live |
| `-y` / `--yes` | _(prompt)_ | Skip the confirmation prompt |
| `--config-dir=PATH` | `../papaia-config` | Config directory location |

Every id is checked against the catalogue first: one unknown id aborts the whole call and
nothing is removed. Only a directory that is catalogued **and** located inside the backup
directory is deleted — a snapshot moved elsewhere loses its catalogue entry but is left on
disk. The running stack is not touched. Each deletion adds a `delete` line to `backup.log`.

### `restore`

```bash
tools/papaia-ctl restore [--from=PATH] [--restore-point=ID|latest] [--list] [--identity=FILE|-]
                         [--only=SELECTOR[,SELECTOR]] [--restart-clean] [--no-restart]
                         [--insecure-images] [-y] [--config-dir=PATH]
```

| Flag | Default | Purpose |
|---|---|---|
| `--from=PATH` | `PAPAIA_BACKUP_DIR` from the root `.env` | The backup target to read restore points from; required on a host without a setup (see below) |
| `--restore-point=ID\|latest` | _(most recent usable)_ | Which restore point to restore, as listed by `--list`; `latest` is the newest point of the whole installation with result `ok` |
| `--list` | — | Print the available restore points and exit |
| `--identity=FILE\|-` | — | The private backup key (`AGE-SECRET-KEY-1...`) of one recipient of the restore point, from a key file or, with `-`, from standard input; a passphrase-protected key file asks for its passphrase once. Required for an encrypted restore point |
| `--only=SELECTOR[,SELECTOR]` | _(whole snapshot)_ | Restore only the selected units and scope the teardown and restart to them. Each `SELECTOR` is `module:NAME`, `addon:NAME` or `volume:NAME` (in a distributed installation also `node:NAME`); the prefix is mandatory. Cannot be combined with `--restart-clean`, and is refused for a selection that touches the config directory or resolves to the `manager` profile |
| `--restart-clean` | — | Delete the named volumes during the teardown as well, so nothing survives that is not in the restore point |
| `--no-restart` | — | Do not touch the running stack at all |
| `--insecure-images` | — | Skip the image check of the containers this restore starts again, for this one command (single host; see [Image pinning and signatures](#image-pinning-and-signatures)) |
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

`--only` narrows the operation to the units you name instead of unpacking the whole snapshot.
A selector is `module:NAME` (a service group such as `librechat`), `addon:NAME` (an installed
add-on) or `volume:NAME` (one named volume); the prefix is required because a bare name like
`librechat` is at once a module, a service, a profile and the prefix of several volumes. Only
the Compose profiles and add-ons the selection resolves to are torn down and brought back up —
everything else keeps serving — and a volume still in use after that scoped teardown is skipped
rather than wiped. Add-ons are restarted before the core, matching `start --addons`. The
selection is read from a manifest written as `version: 2`, which records the `project`,
`module`, `services` and `profiles` behind every artifact; an older `version: 1` manifest still
restores, but only as a whole.

The config directory is restored into the config directory currently in use, not the path
recorded at backup time, so a snapshot can be replayed onto a host that keeps its bundle
elsewhere. A bind-mount directory whose add-on is no longer installed is skipped with a warning
rather than recreated.

In a distributed installation, `restore` stops only what it replaces. `--only=node:NAME` puts
back the data of one node, stops and starts only the services there whose data it replaces,
and touches no other node. A whole restore stops every node, puts the controller's
configuration back, hands every node its bundle and release, writes back each node's data and
starts the installation. A restore point taken of a single host is refused in a distributed
installation, and the other way round. `--restart-clean` is not available there.

**Encrypted restore points.** A restore point written to recipients (every backup since
encryption, see [Backup keys and target](#backup-keys-and-target)) is restored only with the
private key of one of them. Without `--identity` the restore stops with exit code 2 and
`The key for restore point <id> is missing (recipients: <name> <age1...>, ...)`, before anything
is touched; it never starts with new keys in place of the old ones. With a key, every archive the
restore will unpack is checked first: the key opens it, and the file still has the SHA-256 the
manifest recorded. A key that is no recipient (exit 2) or a changed or missing archive (exit 3)
stops the restore at that point, again with nothing changed. Each archive is then decrypted into
the stream the sidecar unpacks, so neither the key nor a decrypted archive is written to disk;
the key is not put into an argument, the environment or a log either. With `--identity=-`
standard input carries the key and cannot answer the confirmation, so the restore needs `-y`
and otherwise stops with exit code 2 before the key is read:

```bash
tools/papaia-ctl restore --restore-point=<ID> --identity=- -y   # paste the key, then Ctrl-D
```

**Deletions survive the restore.** A restore point brings back everything a module deleted after
it was taken. Each module therefore keeps an erasure journal at the backup target
(`$PAPAIA_BACKUP_DIR/erasure-journal/<module>.jsonl`, references only, no content), and the
restore has every module apply it again before the module serves anything. A module declares
this as the reserved action `erasure-replay` under `actions:` (contract generation 14); a holder
of delegations also declares `post-restore` (new sealing key, emptied delegations, halted
triggers and runs). After writing the restore point, `restore` records the actions of every
active add-on of the restore (a scoped restore: of the selected add-ons) in
`$PAPAIA_CONFIG_DIR/module-actions.pending`. Before an add-on starts — in `start`, in the
restart of a scoped restore and in `addon start` — each due action runs as `docker compose run
--rm <service> <args>` in the add-on's project, which starts the add-on's databases and no other
service, with `PAPAIA_ERASURE_TRIGGER` (`restore`, or `rollback` for `addon rollback
--restore-data`) and the restore's `PAPAIA_CORRELATION_ID` in its environment. The journal runs
first, then the holder's step, then the add-on starts. An action that fails keeps its add-on down
and stays due: the next `start --addons` or `addon start <name>` runs it again first (the actions
are idempotent). A pending file that cannot be read keeps every add-on with a pending step down;
a scoped restore does not replace it either (it may hold steps of add-ons outside the selection)
and stops with exit code 3 without starting the stack. Only a whole restore replaces it.
`addon run` neither lists nor runs these two actions. Each run is one `papaia.audit/1` row
(`module_action_run`, with add-on, action, trigger, restore point and exit code) in the host's
audit journal `$PAPAIA_CONFIG_DIR/audit/papaia-ctl.jsonl`. The journals of the core itself
(accounts, chat, model gateway) are applied by the core start gate, not here.

**The release of the point.** A whole restore replaces the configuration the checkout renders
from, so it stops with exit code 2, before the key is asked for and before anything is touched,
when the checkout is another release than the point's `RELEASE` names; the message names the
command, for example `git checkout v1.10.0`. A scoped restore only warns. A point taken before
`RELEASE` files existed is restored with a warning.

**After the loss of the host.** When only the backup target and a backup key are left:

1. Mount the target on the new host and read the tag from `<target>/latest/RELEASE`.
2. `git clone --branch <tag> https://github.com/Fidonis/papaia.git` (and the add-on checkouts
   at the paths the installation used, see `addons` in the point's `manifest.yaml`).
3. `tools/papaia-ctl restore --from=<target> --restore-point=latest --identity=- -y`, paste the
   key, then Ctrl-D.
4. `tools/papaia-ctl doctor`.

Without a setup, `restore` needs `--from` and restores the whole point only (no `--only`); the
target must hold `.papaia-target`, and a point whose `RELEASE` names another installation than
the target is refused. Nothing is stopped first, the configuration directory comes from the
point, and the erasure journals at the target and `post-restore` run before the modules start,
as in every restore. Base domain, app domain and issuer URL must stay the same; TLS material
comes from the point.

**Erasure probe.** After the modules started again, `restore` checks that what was deleted
since the point did not come back: for each journal at the target, the entries written at or
after the point's `created_at` name objects the point brought back. A module passes when its
`erasure-replay` of this restore is in the audit journal (same correlation id and restore point,
exit code 0) and nothing is left due; it fails when no installed add-on replays the journal, the
add-on declares no `erasure-replay`, the replay did not run or failed, or the journal cannot be
read. A scoped restore checks the selected add-ons only. The journals of the core itself
(`identity`, `core-chat`, `model-gateway`) are listed and left to the core start gate. One line
per module (`erasure probe: <module> pass|fail|core (<n> journaled since the point): <reason>`),
one audit row `erasure_probe` and `erasure_probe=pass|fail` in `backup.log`; when it fails,
`restore` exits with code 3. With `--no-restart` the probe does not run.

**How long it took.** `restore` prints `Restore took N s` (from the confirmation to the stack
being up again: the measured recovery time), logs `duration=Ns` and
`module_actions=ok|pending|none` in `backup.log`, and writes one audit row `restore_applied`
with `duration_s`, the result, the artifact count and the state of `post-restore` and of the
module actions.

**Restoring next to the running installation (second compose project).** To try a restore point
without touching the installation it was taken of, restore it into a second installation in its
own Docker engine (a second host or a virtual machine), with its own checkout and configuration
directory: `setup` there without `start`, then
`restore --from=<copy of the target> --restore-point=<ID> --identity=- -y`, then `doctor`.
The time from the restore command to `doctor` passing is the recovery time. The restore writes
the volumes under the names recorded in the point and takes over the configuration of the
point, including `COMPOSE_PROJECT_NAME`, host names and ports, so it must not share a Docker
engine with the original: on the same engine it would write into that installation's volumes.
After a whole teardown, a volume still in use by a container (of another project) is therefore
skipped with a warning rather than overwritten, and the restore ends `partial`.

Once anything was written, [`post-restore`](#post-restore) is pending — for a scoped restore
and with `--no-restart` as well, and so also for `addon rollback --restore-data`. `restore`
records it in `$PAPAIA_CONFIG_DIR/post-restore.pending` and starts Keycloak and its database
alone first, runs the step against them and starts the modules (core services and add-ons)
only after it succeeded. While the step is pending, every `start` does the same before the
first module, and `addon start` refuses. If the step fails (status 3), or the stack does not
come up again before it ran (the restart's status), `restore` logs `post_restore=failed` or
`post_restore=pending` in `backup.log` and prints the command that finishes it. With `--no-restart` the step runs
against the running Keycloak, which may still serve the replaced database from its cache, so
it stays pending and runs again at the next `start`.

### `post-restore`

```bash
tools/papaia-ctl post-restore [--since=EPOCH] [--config-dir=PATH]
```

| Flag | Default | Purpose |
|---|---|---|
| `--since=EPOCH` | _(now)_ | Unix time in seconds when the restore began, as `restore` prints it when the step failed |

A restore point brings back the Keycloak database as it was: sessions and delegations that
persons have revoked since are valid again. `post-restore` makes them unusable in the bundled
Keycloak, with the master admin:

1. The `papaia` realm's "not before" is set one second past the current time. Keycloak then
   refuses every token issued before, offline (refresh) tokens included, for every client;
   every person signs in again. A value that already lies past `--since` is left alone, and
   `realm sync` never writes it, so a later sync does not revive old tokens.
2. For every person, the consents of the two holders of delegations, `flow-engine` and
   `assist-gate`, that predate `--since` are removed (`DELETE /users/{id}/consents/{client}`),
   which also ends their offline sessions — a logout alone does not. A grant without a consent
   is judged by the start of its offline sessions; a grant whose age cannot be read is removed.
   Consents of other clients stay.

A second run with the same `--since` finds nothing to do and writes nothing; a delegation
granted after the restore survives it. Persons grant their delegations again. Every write is
one `papaia.audit/1` row in `$PAPAIA_CONFIG_DIR/audit/outbox/papaia-ctl.jsonl` (operations
`post_restore.not_before` and `post_restore.consent_delete`, one correlation id per run); a
refused write is a row with `result: error` and stops the run with status 1.

A successful run clears the pending step that `restore` recorded, unless `--since` lies before
the second recorded there.

The step does not replace the holders' own steps after a restore (a new sealing key, an
emptied delegation table, halted runs), which belong to each module. With
`AUTH_PROVIDER=external_oidc` there is no bundled Keycloak and the step does nothing: revoke
the sessions at the identity provider. It is not available in a distributed installation yet;
`restore` there says so.

### `halt`

```bash
tools/papaia-ctl halt set    [--reason=TEXT] [--config-dir=PATH]   # also: halt on
tools/papaia-ctl halt clear  --reason=TEXT [--config-dir=PATH]     # also: halt off
tools/papaia-ctl halt status [--json] [--config-dir=PATH]
```

The platform halt: one command on the host stops every write, send and delete of the
installation within 10 s, and model calls and everything else within 60 s. It writes
`$PAPAIA_CONFIG_DIR/state/halt.json`, needs neither Keycloak nor any other service and
outlasts a restart of every container. The model gateway refuses every request while it is
active; modules check it before each effect. Lifting it needs a reason. Setting, lifting and a
refused lift are `papaia.audit/1` rows of the host account. `backup` leaves the halt out and
`restore` keeps it as it is. Details: [docs/halt.md](docs/halt.md).

### `settings`

```bash
tools/papaia-ctl settings show  [--json] [--config-dir=PATH]
tools/papaia-ctl settings set   <key> <value> [--config-dir=PATH]
tools/papaia-ctl settings unset <key> [--config-dir=PATH]
```

The settings of the installation that every module shows or obeys. They are kept in
`$PAPAIA_CONFIG_DIR/overlay/platform/` and published in the platform catalog
(`platform/services.json`, see [docs/architecture.md](docs/architecture.md), "Platform
catalog"), which modules read within 60 s:

| Key | Value | Default |
|---|---|---|
| `branding.name` | Name of the installation, 1 to 60 characters | `papAIa` |
| `branding.suffix` | Second line under the name, 1 to 60 characters | none |
| `branding.logo` | Path of a PNG, JPEG or WebP file of at most 1 MiB; copied to `platform/brand-logo`, and each module serves it under `/_kit/brand/logo` | none |
| `contact.name` | Contact point for users, 1 to 120 characters; named in every "no access" and "not allowed" message | none: modules show "Ansprechstelle nicht hinterlegt" |
| `contact.mail`, `contact.phone` | Mail address or phone number of the contact point (needs `contact.name`) | none |
| `approvals.four_eyes` | `on`: an approval in Studio, Data, Flow or the core needs a second person (role "Bestätigung" is enough), and the submitter cannot approve. `off`: the submitter may approve; the module marks the audit row `selbstfreigabe`. | `off`; always `on` in security profile `kritis` |

`approvals.four_eyes` is the only four-eyes setting of the platform; no module and no size
profile has one of its own. In security profile `kritis` (`PAPAIA_SECURITY_PROFILE`) it is always
`on`: `set approvals.four_eyes off` is refused (exit 1) and the refusal is audited, and
`set approvals.four_eyes on` rewrites an `off` stored before the profile changed (the remedy
`doctor approvals` names). Any profile other than `standard`, `kritis` or empty (for example
`Kritis`) stops `settings`, the catalog render and `doctor approvals` instead of reading as
`standard`. The setting never applies to the resolution of pseudonyms, the deletion lock or write pairings of data
class `vertraulich`: they always need a second person.

Every value is checked before anything is written (lengths, no control characters, mail and phone
format, raster images only, since an SVG served from a module's origin could carry script).
Setting the value already in effect changes nothing. Each change is one `papaia.audit/1` row of
the host account: `config_changed` naming the key (never the value), and for
`approvals.four_eyes` the event `four_eyes_changed` with the old and the new value. The catalog
is rendered right after the change; without a catalog yet (no `OIDC_ISSUER`) the value is stored
and published by the first render. Two changes at once wait for each other
(`overlay/platform/.settings.lock`), so none is lost. `unset` returns a key to its default; `unset contact` removes
the whole contact point. Exit codes: 0 done or unchanged, 1 refused, 2 invalid key or value, 3
stored but the catalog could not be rendered. [`doctor`](#doctor) reports both settings
(`approvals`, `contact_point`).

### `pairing`

```bash
tools/papaia-ctl pairing list    [--json] [--config-dir=PATH]
tools/papaia-ctl pairing confirm --approve-pairings=SHA256 [--config-dir=PATH]
tools/papaia-ctl pairing approve --client=NAME --audience=NAME [--effects=rwdx] [--config-dir=PATH]
tools/papaia-ctl pairing revoke  --client=NAME --audience=NAME [--config-dir=PATH]
```

Exchange rights: which module client may exchange a person's token for which audience,
with which effects (`r` read, `w` write, `d` delete, `x` module interface). `list` shows
the pairings of the signed bill of materials, whether each reads or writes, its state and
the sha256 of the list. `confirm` is the confirmation step of `setup`: it confirms the read
pairings of exactly the list with that digest and records each write pairing as waiting for
approval. `approve` confirms a pairing; one that writes or deletes is confirmed only when a
second person approves it — another host account than the one that asked for it (as root,
the login that called `sudo`). The same person is refused. `revoke` removes a pairing. None
of them takes `-y`. Each decision and each refusal is a `papaia.audit/1` row with the host
account and the time; a decision takes effect with the next realm sync (`start` runs it).
Details: "Pairing approval" in [`docs/architecture.md`](docs/architecture.md).

### `librechat clear-history`

```bash
tools/papaia-ctl librechat clear-history <email> [--before=YYYY-MM-DD] [--dry-run] [-y] \
                                         [--config-dir=PATH]
```

Removes one LibreChat user's history before an account is used again: a training or test
account, or the account of someone who left. It removes the user's conversations with their
sub-threads, their messages, their shared links and the tool call records of those
conversations, and the user's files (records and stored files). Without `--before` that is
every file of the user, including files in "My files" that were never attached to a chat;
with `--before`, only the files of the conversations that go. The account, its sign-in, its
MCP connections, its agents and prompts, its avatar, the files an agent uses, and everything
the stack provisions stay.

Two kinds of data also stay, and matter on a shared or training account:

- **Memories.** When memory extraction is switched on in an overlay, the user's memory
  entries stay and the next person on the account sees them. Remove them in LibreChat's
  memory settings before the account is handed on.
- **Agent checkpoints** of runs paused for a tool approval or a question to the user. LibreChat
  removes them together with its run queue, which this command cannot reach from outside the
  server process. They expire after 24 hours on their own.

The counts list sub-threads under conversations (`4 (including 2 sub-threads)`), so they can be
higher than the number of chats the user sees.

| Flag | Default | Purpose |
|---|---|---|
| `<email>` | _(required)_ | E-mail address of the LibreChat user. An unknown address is an error |
| `--before=YYYY-MM-DD` | _(everything)_ | Only conversations last updated before that day (00:00 UTC), with their sub-threads, messages, files and shared links. A sub-thread goes with its conversation, never on its own date. An empty value is an error |
| `--dry-run` | off | Print what would be removed, per kind, and change nothing |
| `-y` / `--yes` | _(prompt)_ | Skip the confirmation. Without a terminal, `-y` is required |
| `--config-dir=PATH` | `../papaia-config` | Config directory location |

Without `-y` the counts are shown first and the deletion waits for a `y`. **The deletion
cannot be undone** except by restoring a backup; `restore --only=module:librechat` brings back the data of every LibreChat user, not of one.

The command needs the running stack: it runs inside the LibreChat container, through
LibreChat's own data and file-storage code, so it follows LibreChat's layout across
releases. Run it while the user is not chatting; a reply that is still being written can
leave a message behind. In a distributed installation, run it on the node that runs
LibreChat. Exit status 0 on success, 1 when the user is unknown, LibreChat is not running,
or a file could not be removed from storage (its record is kept and named), 2 for wrong
arguments (also an address or a date that is not one), 3 when the confirmation is declined.

### `secrets rotate`

```bash
tools/papaia-ctl secrets rotate paperless-gate/proxy [--config-dir=PATH]
tools/papaia-ctl secrets rotate connections/credentials [--config-dir=PATH]
```

`paperless-gate/proxy` replaces the proxy's own secret for the Paperless gate and reloads the running proxy, which
then sends the new value. The Paperless gate reads it when the add-on starts again
(`papaia-ctl addon start paperless`); until then requests through the proxy to Paperless are
refused. The secret is never printed. Each rotation writes one `papaia.audit/1` row (target
and event, not the value) to `$PAPAIA_CONFIG_DIR/audit/papaia-ctl.jsonl`. See
[Paperless behind the proxy](#paperless-behind-the-proxy).

`connections/credentials` replaces the master key of the connection registry (profile
`connections`): it runs `rotate-keys` in the running registry, which makes a new key active,
seals every stored credential again and removes the keys nothing needs any more. Only the
registry's summary (a count) is printed; no key, key id or credential leaves the container.
It needs the profile on and the registry running (exit status 2 otherwise) and writes one
`papaia.audit/1` row with the outcome, also when the registry refuses. Any other target is
refused with exit status 2.

### `addon`

```bash
tools/papaia-ctl addon install   <name> --path=PATH [--version=VER] [--node=NAME] [--force] \
  [--insecure-images] [--accept-unlisted-images] [--config-dir=PATH]
tools/papaia-ctl addon start     <name> [--force] [--insecure-images] [--config-dir=PATH]
tools/papaia-ctl addon upgrade   <name> --path=DIR [--dry-run [--json]] [--no-backup] \
  [--no-restart] [--answers-file=FILE] [--force] [--insecure-images] [-y] [--config-dir=PATH]
tools/papaia-ctl addon rollback  <name> [--restore-data] [--no-restart] [--force] \
  [--insecure-images] [-y] [--config-dir=PATH]
tools/papaia-ctl addon list      [--json] [--config-dir=PATH]
tools/papaia-ctl addon stop      <name> [--clean-up] [--config-dir=PATH]
tools/papaia-ctl addon remove    <name> [--force] [--config-dir=PATH]
tools/papaia-ctl addon uninstall <name> [--purge-data] [--force] [--config-dir=PATH]
tools/papaia-ctl addon run       <name> [<action>] [--json] [--config-dir=PATH]
tools/papaia-ctl addon check     [--target-core=PATH] [--target-version=VER] \
  [--target-addon-api=N] [--target-min-addon-api=N] [--json] [--force] [--config-dir=PATH]
tools/papaia-ctl addon components [<name>] [--json] [--config-dir=PATH]
```

| Command | Effect |
|---|---|
| `install` | Registers the add-on in `deployment.yaml` as `active`, seeds `addons/<name>/.env` in the config directory, generates the network override, re-renders, and prints an identity-provider checklist. `--path` is required the first time. Before anything is registered, the add-on's images are checked against the signed bill of materials; an add-on outside it needs `--accept-unlisted-images` (see [Image pinning and signatures](#image-pinning-and-signatures)). Aborts if the add-on is incompatible with the current core; `--force` demotes INCOMPATIBLE to a warning and proceeds. Refused, whatever `--force` says, when the add-on would put a second server under an address the installation already has (see [Module selection](#module-selection)), and `paperless` only with its gate. A `--path` that re-points an installed add-on is refused, like `upgrade`, when the version there no longer meets a range another active add-on requires of it. |
| `start` | Copies the add-on's `.env` into place, re-renders, checks the add-on's images (digest and signature) and runs `docker compose up -d` for the add-on. Re-checks compatibility before starting; `--force` to override. A second server under an existing address is refused here too, not forcible. `--insecure-images` skips the image check for this one command. |
| `install --node=NAME` | Distributed installations only: the node the add-on runs on. Without it, the add-on goes to the node of the core services it attaches to. An add-on whose `networks.attach` names services on two nodes is **not placeable** and is refused whatever `--force` says: its network exists on one node only. On a remote node the add-on travels in the node's bundle, and `start`, `stop` and `start --addons` run it there. |
| `upgrade` | Moves an installed add-on to another version of itself, kept in a directory of its own (`--path`). Nothing in the registered directory is touched: the registration is repointed and the old one is kept as `previous` ([ADR 0008](docs/adr/0008-upgrade-add-ons-by-repointing-to-immutable-snapshots.md)). Refused when the new version no longer meets a range another active add-on requires of it (`requires.addons`); `--force` proceeds with a warning. A `paperless` version without its gate is refused, not forcible (see [Module selection](#module-selection)). The images of the new version are checked before its containers are recreated; `--insecure-images` skips that check for this one command. See [Upgrading an add-on](#upgrading-an-add-on). |
| `rollback` | One step back: repoints the add-on at the version it had before the last upgrade and forgets `previous`. The add-on's data is left alone unless `--restore-data` restores the restore point the upgrade took. Refused, like `upgrade`, when the older version does not meet a range another active add-on requires of it, and for a `paperless` version without its gate. The images of the older version are checked before its containers are recreated; `--insecure-images` skips that check for this one command. |
| `list` | Read-only. Every registered add-on with its path, version (from the manifest), bundled components, the compatibility verdict `check` would give, and the `previous` version a rollback would go back to. `--json` prints `{"schema_version": 1, "core": {...}, "addons": [...]}`, described by [`tools/schemas/addon-list.schema.json`](tools/schemas/addon-list.schema.json). |
| `stop` | Stops the add-on's containers. `--clean-up` removes them; volumes are kept. |
| `remove` | Deactivates the add-on (`active: false`) and drops its integration fragments from the render. The config bundle and its secrets are **kept**, so `install` can reactivate it later. Refused while another active add-on lists it under `requires.addons`; `--force` proceeds with a warning. |
| `run` | Runs a maintenance action the add-on declares under `actions:` — `docker compose run --rm <service> <args>` in the add-on's project, with the files and env of `addon start` — and exits with the action's code. Only declared actions with their fixed arguments run; without an action, lists the declared ones (`--json` for tools). The restore steps `erasure-replay` and `post-restore` are neither listed nor run here: only [`restore`](#restore) runs them. Single host only. |
| `uninstall` | Removes the add-on's containers and networks, its override files, config bundle and entry in `deployment.yaml`. Its proxy hosts and its clients in the realm go right after, through `npm-provision` and `keycloak-role-sync` (or at the next `start` when the stack is down); its service accounts and `aud-*` scopes go with them, since no installed module declares them any more. `--purge-data` (formerly `--clean-up`) also removes its volumes; without it the volumes stay and a later `install` uses them again. Refused, before anything is taken down, while another active add-on requires it; `--force` proceeds with a warning. An add-on that uses it optionally does not refuse it and is named. Leaves one audit row. |
| `components` | Read-only. Lists the software each registered add-on bundles, from the `components` of its manifest: name, version, role (`primary` or `sidecar`) and the image variable that carries it. An add-on's own version counts changes to the bundle, this says what runs inside it. A tag the add-on's `.env` pins instead of the catalog's is shown as overridden, and a floating tag (`postgres:18`) is marked. `<name>` narrows the list to one add-on, `--json` prints `{"schema_version": 1, "addons": [...]}`. `install` prints the same list for the add-on it just registered. An add-on whose manifest declares no components is listed without any. |
| `check` | Evaluates all active add-ons against the current core for compatibility and prints a status table (OK / INCOMPATIBLE / UNKNOWN). Exit 0 when all add-ons are compatible, exit 2 if any are INCOMPATIBLE. `--target-core=PATH` checks against a different core checkout for a dry-run before an upgrade. When the core ships the suite matrix `compat/suite.yaml`, every add-on it names must have a version of the core's suite or the suite before it (axis `matrix`, see [`docs/compatibility.md`](docs/compatibility.md)). `--json` prints machine-readable output. `--force` demotes INCOMPATIBLE to a warning (exit 0). An add-on built against a newer contract generation than the target serves is reported with every missing generation and its meaning, for example `missing generations 4, 5, 6, 7, 8, 9, 10, 11, 12; 12: add-on ingress integration.nginx (ADR 0023)`; see the generation table in [`ADDON_API`](ADDON_API). |

#### Module selection

Modules are chosen freely; the core only refuses what cannot work next to the rest.

- **No two servers under one address.** `addon install` and `addon start` check the
  installation as it would be afterwards: a catalog `id` another module or core profile
  declares, an `audience` another service serves, or a Compose service or container name the
  core (its active profiles) or another active add-on already uses ends the command with exit
  2 and the conflict named, for example `service name 'qdrant' is used by the core and
  qdrant` for a Qdrant add-on next to the profile `rag`. Nothing is written; `--force` does
  not lift it. The check runs also before the installation has a catalog.
- **Soft dependencies.** An entry of `requires.addons` names an add-on by `name` (or `id`)
  and may carry `optional: true`: the add-on runs without it and only loses what the other
  one adds (Studio declares `{id: papaia-data, optional: true}` for the handover to Data).
  A missing optional add-on is a notice, not a refusal; installed, its version range is
  checked like any other. Unknown fields in an entry are refused.
- **Order.** `start --addons` and `upgrade` bring add-ons up after the add-ons they require,
  optional ones included: Data before Studio.
- **Paperless only with its gate.** Paperless takes the person from a request header, so
  `addon install paperless`, `addon upgrade paperless` and `addon rollback paperless` are
  refused, whatever `--force` says, unless the version they would put in place has the
  service `paperless-gate` in Paperless' network namespace (`network_mode:
  service:paperless`) in its compose file. When the checkout carries a signed bill of
  materials, they are also refused unless that bill of materials lists the gate as
  `component: paperless-gate`, the same rule by which `setup` offers Paperless (see
  "Modules offered" under [`setup`](#setup)).
- **Uninstall.** What lives outside the configuration directory (the add-on's proxy hosts
  and realm clients) is recorded in `security/uninstalled-modules.json` (names and host
  names only, mode 0600) and removed by the step that owns it; each removal leaves one audit
  row. Installing the add-on again drops the record.

**`addon check` flags**

| Flag | Purpose |
|---|---|
| `--target-core=PATH` | Check against a different core checkout instead of the current one (pre-upgrade dry-run). |
| `--target-version=VER` | Override the core version used for the check. |
| `--target-addon-api=N` | Override the `current` bound of the ADDON_API window. |
| `--target-min-addon-api=N` | Override the `min` bound of the ADDON_API window. |
| `--json` | Print results as a JSON array (also on exit 2). |
| `--force` | Treat INCOMPATIBLE as a warning instead of a hard failure (exit 0). |

After `addon install`, `addon upgrade`, `addon rollback` or `addon remove`, run
`tools/papaia-ctl start` to apply the changed core configuration.

#### Upgrading an add-on

The new version is a directory, as with `install`; resolving a catalogue and a commit to one stays
with the caller. Keep each version in a directory of its own with the same name
(`<snapshots>/<commit>/<name>`): Compose names the project after the directory, so a differently
named one is refused, and an upgrade never overwrites a directory, so the one a rollback goes back
to is still there.

```bash
tools/papaia-ctl addon upgrade paperless --path=/srv/snapshots/9f3c1a2b/paperless --dry-run
tools/papaia-ctl addon upgrade paperless --path=/srv/snapshots/9f3c1a2b/paperless \
  --answers-file=answers.env -y
```

The steps, in this order:

1. **Preconditions.** The add-on is registered and active, the manifest at `--path` has the same
   `name`, and the directory has the same name as the registered one. Otherwise exit 2.
2. **Compatibility gate** against the current core (`--force` demotes INCOMPATIBLE to a warning).
   Nothing is changed up to and including step 4: `deployment.yaml`, the configuration bundle
   and the containers stay as they were.
3. **Plan.** New, removed and default-changed keys of `.env.example` (a new key is a generated
   secret, a value to ask for, a Keycloak client secret to copy in, or a literal), the component
   delta, and what changed in the manifest (version, `requires.addon_api`, attached core services,
   new Keycloak clients). `--dry-run` prints it and stops; `--dry-run --json` prints it for
   machines ([`tools/schemas/addon-upgrade.schema.json`](tools/schemas/addon-upgrade.schema.json)),
   also when the gate refuses (`"blocked": true`).
4. **Values.** A new `CHANGE_ME` key whose `env_prompts` entry has no `default` (or a
   `default_from_core` the core can fill) needs a value, from a prompt or without a terminal from
   `--answers-file` (`KEY=VALUE` lines, only keys the plan asks about, mode 0600 recommended,
   never printed). A missing value exits 2.
5. **Restore point**, unless `--no-backup`: `backup --only=addon:NAME`. Its id is remembered in
   `previous`. An add-on with no volumes or data directories gets none. Failing to take it exits 3
   before anything changed.
6. **Apply.** The new keys are added to `addons/<name>/.env` (existing values never change), the
   registered `path` and `version` are updated, the old ones are kept as `previous`, the core
   configuration is re-rendered, and the bundle's `.env` is copied into the new directory.
7. **Recreate.** If the add-on was running (and not `--no-restart`), `docker compose up -d
   --remove-orphans` recreates it from the new directory. A failure does not roll back; the output
   names the rollback command.

Without `-y` an upgrade asks for confirmation on a terminal and refuses to run without one. A
Keycloak client or secret the new version brings is listed at the end as a manual step, as after
`install`.

`addon rollback` runs the same pipeline backwards: the gate against the current core, then the
registration and the bundle's `.env` move back to `previous`, and the add-on is recreated. It says
whether data is reset. With `--restore-data` the restore point recorded by the upgrade is restored
with `restore-scoped` (the add-on is taken down, its volumes are replaced, and it comes back up);
data written since is lost. It cannot be combined with `--no-restart`, and it refuses, before
anything changes, when no restore point was recorded or the point is gone.

`deployment.yaml` records the step back:

```yaml
addons:
  - name: paperless
    path: /srv/snapshots/9f3c1a2b/paperless
    version: 1.1.0
    active: true
    previous:
      path: /srv/snapshots/5d07e8c4/paperless
      version: 1.0.0
      restore_point: 2026-10-25_10-00-00   # absent when no restore point was taken
```

An upgrade in the directory the add-on is already registered at (a checkout pulled in place) is
accepted, but it keeps no `previous`, since the old files are gone.

### `status`

```bash
tools/papaia-ctl status [--json] [--profiles=LIST] [--addons] [--config-dir=PATH]
```

Read-only. Reports the declared state next to the live state, per module: the services the
Compose files declare for the active profiles, matched against the containers Docker reports.
A *module* is a `de.fidonis.module` label, not a Compose profile. One profile can bring up
several modules (`librechat-websearch`), and the `oauth2-proxy` profile is the module `auth`.

It costs one `docker ps -a`, plus one `docker inspect` for exited containers only, and starts,
stops and writes nothing, so it is cheap enough to run on a short interval.

| Flag | Purpose |
|---|---|
| `--json` | Print the report as JSON; nothing else is written to stdout. The format is described by [`tools/schemas/status.schema.json`](tools/schemas/status.schema.json), and `schema_version` increases on a breaking change. |
| `--profiles=LIST` | Restrict the core section to these Compose profiles (comma-separated or repeated). A profile that is not in `COMPOSE_PROFILES` is rejected with exit code 2. |
| `--addons` | Include the active add-ons, each of which runs in its own Compose project. Without it only the core is reported. |

Status values, worst first:

| Value | Meaning |
|---|---|
| `missing` | Declared, but no container exists ("not deployed"): the profile was never started, or the container was removed. |
| `stopped` | Exited with an error, paused or dead, or exited cleanly although its restart policy (`always`, `unless-stopped`) says it should keep running. |
| `unhealthy` | The healthcheck fails, or the container is restarting in a loop. |
| `starting` | Created, or the healthcheck has not passed yet. |
| `unknown` | A Docker state `papaia-ctl` does not recognise. |
| `completed` | A one-shot job that exited with code 0 (for example the LocalAI model download). It does not count against its module. |
| `healthy` | Running with a passing healthcheck, or without a healthcheck, which is not treated as a problem. |

A module takes the worst value of its containers; the `aggregate` of the core and of the add-ons
takes the worst value of their modules. `modules` lists the worst first, and `groups` maps every
active Compose profile to the modules it brings up.

```json
{
  "schema_version": 1,
  "generated_at": "2026-09-27T10:15:00Z",
  "platform_version": "1.9.0",
  "compose_project": "papaia",
  "docker": { "reachable": true, "reason": null },
  "modules": [
    { "name": "keycloak", "kind": "core", "compose_project": "papaia",
      "profiles": ["keycloak"], "declared": true, "status": "healthy",
      "containers": [
        { "name": "papaia-keycloak-1", "service": "keycloak", "role": "identity-provider",
          "state": "running", "health": "healthy", "status_text": "Up 2 hours (healthy)",
          "host_ports": [8110] }
      ] }
  ],
  "groups": [
    { "profile": "keycloak", "modules": ["keycloak"], "containers": 2, "status": "healthy" }
  ],
  "aggregate": { "core": "healthy", "addons": null }
}
```

If the Docker daemon cannot be reached, the report says so (`docker.reachable` is `false`, there
are no modules and the aggregate is `unknown`) instead of listing every service as `missing`:
not knowing is not the same as knowing it is gone. The exit code is 0 whenever a report was
produced, and 2 when `setup` has not run yet or a flag is invalid.

In a distributed installation `status` asks every node and prints one report, a section per
node. The JSON keeps its shape and `schema_version` 1. It adds `node` to every module and
container, and `nodes`: every node with its address, whether it answered (and why not), and
the release it runs. A node that does not answer contributes no modules, and
`docker.reachable` is then `false` for the whole report.

### `doctor`

```bash
tools/papaia-ctl doctor [CHECK...] [--json] [--skip=CHECK[,CHECK]] [--config-dir=PATH]
```

Preflight and diagnostics, to run before `setup` or `upgrade` and whenever something seems
wrong. Read-only: it never changes anything. It may take a few seconds (name lookups, port
probes) and is not meant for tight polling; use [`status`](#status) for that.

Every check reports `pass`, `warn`, `fail` or `skip` (not applicable here: offline, not set up
yet, nothing to look at). The exit code is 2 if any check is `fail`, otherwise 0. With
`--json` the same results are printed as a document described by
[`tools/schemas/doctor.schema.json`](tools/schemas/doctor.schema.json); each check carries the
raw values behind its summary in `details`.

| Check | Verifies | Result |
|---|---|---|
| `docker_version` | The Docker daemon is reachable and the Compose plugin is 2.20.0 or newer. | `fail` otherwise |
| `disk_space` | Free space for the config directory, `PAPAIA_BACKUP_DIR` and the Docker data root (skipped when the host cannot see it, as with Docker Desktop). | `warn` below 10 GiB, `fail` below 2 GiB |
| `docker_usage` | What Docker's data takes, from `docker system df`: images, containers, volumes and build cache, each with its size and the part the daemon calls reclaimable. It asks the daemon, so it also works where `disk_space` cannot see the data root (Docker Desktop, inside a container). | never `warn` or `fail`; `skip` if Docker cannot be asked, the call times out or the output is not recognised |
| `memory` | Total and available RAM (swap is reported in `details`), from `/proc/meminfo`. Where there is no `/proc` (macOS, Windows) only the total is known, from the Docker daemon. | `warn` below 8 GB total, or when less than 10 % or 1 GiB is available; never `fail` |
| `cpu` | Cores and the 5-minute load average per core. | `warn` at 1.0 or more per core; never `fail`; `skip` where there is no load average (Windows) |
| `gpu` | Only when LocalAI is enabled with a GPU image variant (`LOCALAI_IMAGE_VARIANT`). NVIDIA: `nvidia-smi` works, Docker has the `nvidia` runtime, VRAM use and temperature. AMD (`hipblas`): `/dev/kfd` exists and, if `rocm-smi` is installed, VRAM use and temperature. Intel and Vulkan: a render node under `/dev/dri` exists. | `fail` if the configured variant cannot start (driver, runtime or device missing); `warn` from 90 % VRAM or 85 °C, or for Vulkan without a render node (LocalAI then runs on the CPU); `skip` for the CPU image, for the native runtime, when LocalAI is not enabled, and, inside a container, for everything but NVIDIA (see below) |
| `localai_native` | Only with `LOCALAI_RUNTIME=native`: the native LocalAI answers on `/readyz` (on the host at `127.0.0.1`, inside a container at `host.docker.internal`), the installed binary is the release the checkout pins and, on the Mac, the state of its launchd job (`launchctl print`). | `warn` when it does not answer, is not installed or is another version, when the job is loaded but LocalAI does not answer, or when the job is not loaded although the stack runs; never `fail`; `skip` for the container runtime and while the stack and the job are both stopped |
| `ports` | The host ports the active core services publish are not in use. A port held by a container of this installation counts as free. | `fail` if another process holds one |
| `dns` | The public hostnames in the configuration resolve from this host. Local names and IP addresses are not looked up. | `warn` if a name does not resolve, `skip` if the resolver cannot be reached |
| `time_sync` | The system clock is synchronized by NTP (`timedatectl`; inside a container the kernel's own state, see below). OIDC tokens and TLS certificates are only valid within a time window, so a drifting clock breaks logins in confusing ways. | `warn` if not synchronized; `skip` where neither is usable |
| `certs` | Days until expiry of `certs/*.crt` and of the Let's Encrypt certificates under `infra/nginx/nginx-letsencrypt/live/`. Needs `openssl`. | `warn` below 30 days, `fail` below 7 days or expired |
| `smtp` | Only while the `smtp` profile is on: the [mail relay](#outbound-mail) container runs, the mail server behind it answers (greeting, EHLO, STARTTLS or TLS and the login; no mail is sent), and how many messages wait in the relay's queue. Reports `not configured` while the profile is off. | `fail` for a mail server that does not answer (notices and warning mails stop); `warn` for a stopped relay or a non-empty queue; inside a container the mail server is not contacted (see below) |
| `addon_compat` | The verdict [`addon check`](#addon) computes for every active add-on. | `fail` where `start` would refuse the add-on, `warn` for `UNKNOWN` |
| `container_health` | The module status from [`status`](#status), including add-ons. | `fail` for `stopped` or `unhealthy`, `warn` for `missing`, `starting`, `unknown` or an unreachable daemon |
| `model_gateway` | LiteLLM's container runs and LiteLLM answers `GET /health/readiness`, asked inside its container (the master key stays there). | `fail` for a stopped container, no answer or not ready; `skip` without the `litellm` profile |
| `model_ready` | The default model (`PAPAIA_DEFAULT_MODEL`) answers one request for one token through the alias `papaia-chat`, bounded at 30 s; only status code and seconds are read. | `fail` for an error answer or no answer within 30 s; `skip` while the gateway does not run or no default model is set |
| `modules` | One row per module of the platform catalog (`platform/services.json`, see `papaia-ctl catalog render`) and per active add-on: version and state from the catalog, the container state from [`status`](#status), the answer of `GET /healthz` of every running entry, and the network path to every core service the add-on attaches (`networks.attach`, read with `docker network inspect`). `/healthz` is asked from inside the module's own network by a short-lived probe container: the pinned `papaia-manager` image, never pulled, read-only, without capabilities, volumes or ports, removed when it exits. It sends no token and follows no redirect. | `fail` for a module that reports `down`, answers with a server error or does not answer from its network, for an attached neighbour that is not on the add-on's app network or does not run, and for a catalog that cannot be read; `warn` for `degraded`, a missing `/healthz`, an answer outside the kit form `{"status": ...}` and a probe container that cannot start (for example the manager image is not on the host); `skip` without a catalog and without active add-ons |
| `revocations_age` | The gauge `revocations_age_seconds` every module reports under `/metrics` (age of the revocation list it last applied), read by the same probe. | `fail` above 300 s, `warn` above 60 s, when the gauge is missing or `/metrics` cannot be read; a module whose `/metrics` asks for the operations token is listed as `skip`; `skip` without a catalog |
| `image_signatures` | Every running container of the core project runs an image pinned by digest, listed with that digest in the signed bill of materials of the checkout and signed with its key (see [Image pinning and signatures](#image-pinning-and-signatures)). | `fail` for an unpinned, unlisted or unsigned image, for a running image whose digest is not the pinned one, and while containers run without the pinned release key or bill of materials; `warn` if the registry cannot be asked (no connection, rate limit, server error) or Docker does not say what runs |
| `network` | Only with a SQL source: the direct route of `mcp-mssql` to it (see [docs/network.md](docs/network.md)). The network `<project>-sql-uplink` exists, is not internal, has the rendered range and no member other than `mcp-mssql`; `iptables -S` of the installation's chain equals the rendered host rules and its jump is the first rule of `DOCKER-USER`. | `fail` for a drifted, missing, misplaced or additional rule, another member or another range; `warn` when the network is not created yet or the rules cannot be read (not root, no `iptables`, inside a container); `skip` without a SQL source |
| `egress` | The single exit (see [docs/egress.md](docs/egress.md)): the always-on `egress` profile is on, `papaia-egress` runs, and its configuration `infra/egress/egress.json` holds a source and an attachment override for every active add-on that declares an egress network. | `fail` when the service does not run, the configuration is missing or lacks an add-on, or an add-on needs the exit while the profile is off; `warn` when the profile is off and no add-on needs it (`setup` turns it back on); `skip` where the service runs on another node |
| `source_protection` | Only with a SQL Server source (`mssql-mcp-rbac` add-on): the SQL Server version and the encryption in effect per database, as the server's own commissioning check reports them (`docker exec` of `selftest` in its container; it reads, it changes nothing). | `fail` for an unsupported version, weaker encryption than required, a failed login or a server container that does not run; `warn` for what the server reports as a warning (for example no TDS 8.0 on SQL Server 2019); `skip` without a SQL Server source |
| `lifecycle` | Only while the `lifecycle` profile is on: the health report of `papaia-lifecycle` (see [docs/lifecycle.md](docs/lifecycle.md)), read with `docker exec`: the age of its last reconciliation independent of events, deactivated accounts still holding a consent, the revocation list, gap revokes and accounts it could not revoke. | `fail` when the last reconciliation is older than 2 h or none has run, a deactivated account holds a consent, the list is old, missing or does not verify, or the service does not run; `warn` for a gap revoke in the last 7 days, a parked event or an account outside the group of persons; `skip` while the profile is off or where the service runs on another node |
| `siem` | Only while the `audit` profile is on: the SIEM report of `papaia-audit` (see [docs/audit.md](docs/audit.md#siem)), read with `docker exec`: backlog, lag and failing deliveries per target, targets no longer configured that hold events back, the last hourly chain verification, and the fill level of the `papaia-audit-db` volume (`df` in its container). | `fail` when a target has taken no events for more than 10 minutes, a chain does not verify, the volume is 95 % full or more, or the service does not run; `warn` for more than 60 s behind, from 80 %, for a removed target that still holds events back, when no target is set, when the hourly verification is missing or older than 2 h, and when `PAPAIA_OPERATIONS_MAIL` is set without an active mail relay; `skip` while the profile is off or where the service runs on another node |
| `identity` | Only with a federation (`security/idp.yaml`, see [docs/federation.md](docs/federation.md)): the status sync of `papaia-lifecycle` with the upstream directory, from the same health report. | `fail` when the status sync has failed for longer than 300 s, has not succeeded in the last 300 s or never ran, when `idp.yaml` or the group map is not usable, when the `lifecycle` profile is off or the service does not run; `skip` without a federation or where the service runs on another node |
| `rollback_window` | The rollback key of the last upgrade (see *Rollback key* under [`upgrade`](#upgrade)): how long `rollback` still works without the operator key, and the window (`PAPAIA_ROLLBACK_WINDOW_HOURS`). | `fail` for a key still there after its window or after its run ended, for a key file or folder others can read, a key without a recorded upgrade older than 168 h and a window outside 24–168 h; `warn` for a younger key without a recorded upgrade; `skip` without a rollback key |
| `realm` | The realm matches the declarations: `papaia-ctl realm sync --check`, without a write. A removed scope assignment of a client shows up here. | `fail` for every deviation (`papaia-ctl realm sync` corrects it) or a refused declaration; `warn` when the comparison could not run; `skip` with external OIDC, before the sync account exists, inside a container and while Keycloak is not healthy |
| `person_export` | Archives of information requests without an account in `state/person-export/` (see [docs/person-requests.md](docs/person-requests.md)). | `warn` while an archive waits for its hand-over; `fail` for one older than 14 days or a folder others can open; `pass` without any |
| `halt` | The platform's emergency halt (`state/halt.json`, see `papaia-ctl halt`). | `fail` while the halt is set (every write, send and delete is stopped) and for a halt file that cannot be used, which every service treats as set; `skip` before the first start |
| `approvals` | The four-eyes rule `approvals.four_eyes` as the platform catalog publishes it (see [`settings`](#settings)): `on` or `off`, and whether it is the default, set, or fixed by security profile `kritis`. | `fail` for a malformed `overlay/platform/approvals.yaml` and for a stored `off` in profile `kritis` (the catalog states `on` all the same) |
| `contact_point` | A contact point for users is set (`contact.name`, see [`settings`](#settings)); without one every module shows "Ansprechstelle nicht hinterlegt". | `warn` while none is set, `fail` for a malformed `overlay/platform/branding.yaml` |

Before `setup` has run, the checks that need the installation's configuration report `skip`
instead of failing. `--skip` takes check names (comma-separated or repeated) and reports them as
`skip` without running them, for example `--skip=dns,certs` on a host without internet access.
Check names given as arguments run those checks only, for example `papaia-ctl doctor lifecycle`;
the exit code follows the same rule.

`docker_usage` is a report, not a verdict: how much room is left is `disk_space`'s question, and how
much Docker may take is yours to decide. "Reclaimable" is Docker's word for what no container uses
right now, which for volumes is not the same as safe to delete. Sizes are Docker's own decimal
figures with four significant digits, so the byte counts in `details` are as exact as that. The
daemon works out the size of every volume to answer, which took about 1.5 s on a stack with 75
volumes and grows with the data; the check stops waiting after 20 s, and `--skip=docker_usage`
leaves it out on a host where that is too slow. Anything that runs `doctor` on a timer should skip
it or accept that cost on every run.

Memory, CPU load, VRAM use, GPU temperature and clock drift never make `doctor` fail: a busy host
is not a broken installation, and `doctor` is also the preflight before `setup` and `upgrade`. GPU
utilization is reported in `details` but does not count, because it is high during any inference.
Only a GPU variant that cannot start is a `fail`. The thresholds are constants at the top of
[`tools/lib/doctor.py`](tools/lib/doctor.py).

Run inside a container, as `papaia-manager` does, `memory` and `cpu` are correct (`/proc/meminfo`
and the load average describe the host), and the two checks that need the host's tools are read
another way:

- `gpu` for NVIDIA runs `nvidia-smi` inside the running LocalAI container with `docker exec`
  (bounded by `timeout` from inside, so a hung driver cannot outlive the check) and judges the
  answer by the same limits as on a host. The `nvidia` runtime is still asked of the Docker daemon.
  If LocalAI is not running, the image has no usable `nvidia-smi`, or Docker refuses the `exec`,
  the check reports `skip` with the reason: from inside a container that says nothing about the
  driver, so it is never a `fail`. AMD, Intel and Vulkan still report `skip` there, because
  `/dev/kfd` and the render nodes are the host's devices.
- `time_sync` reads the kernel's clock state with `adjtimex(2)`, which only reads and needs no
  capability, and calls the clock synchronized when its estimated maximum error is under 16
  seconds, which is how `timedatectl` decides. It reports `skip` where the call is not available
  (not 64-bit Linux, or a container runtime that refuses it).

`smtp` does not contact the mail server from inside a container: `papaia-manager` runs `doctor`
on a timer, and the check would reach your provider on every run. Inside a container it reports
the relay's state and queue only, and says so; the handshake runs when you call `doctor` on the
host. The host has to be able to reach the mail server itself for that, which a server that
only the relay's Docker network can see (a test server, say) is not.

AMD utilization is read from the JSON of `rocm-smi`, whose key names differ between ROCm releases;
if they are not recognised the check passes and says that utilization was not measured.
Utilization is never measured for Intel and Vulkan GPUs.

Not covered: Python and PyYAML (`papaia-ctl` verifies both before any command runs), the ports
of add-ons, and certificates that were uploaded to Nginx Proxy Manager instead of requested
through it.

In a distributed installation the checks above describe the controller's own node, and three
checks are added (on one host they never appear):

| Check | Verifies | Result |
|---|---|---|
| `nodes` | Every node answers and runs the controller's release. Each node's own `doctor` result is listed (worst status, failing checks). The node's clock is compared with the controller's: JWTs carry `exp` and `nbf`, so a deviation breaks sign-ins. | `fail` for an unreachable node, a version skew (run [`upgrade`](#upgrade)), a failing check on a node or a clock 60 s or more off; `warn` from 5 s |
| `links` | From the calling side of every link: a TLS handshake with the peer's link port, with the node's certificate, the link CA and the peer's name. Also the expiry of every node's link certificate. | `fail` for a peer that cannot be reached (the message names the firewall rule `<from> -> <to> tcp/<port>`) or a certificate that does not verify or has expired; `warn` 30 days before expiry (run `node renew-link`) |
| `file_modes` | The controller's config dir keeps the file modes it sets. The link CA and the link keys are written with mode 600; a Windows drive under `/mnt` in WSL2 mounted without the `metadata` option refuses or ignores that. `setup`, `start` (also of an existing installation) and `node sync` refuse such a config dir as well. | `fail` when a mode does not stick; move the config dir to a Linux filesystem (inside the WSL distribution) or mount the drive with `metadata` |

`--skip=nodes,links,file_modes` is accepted on every installation.

#### Causes in German

Below every `fail` row, `doctor` names the cause in one German sentence and the section of the
troubleshooting guide in the operations handbook (`siehe Handbuch §S-n`); `--json` carries the
same as `causes` (`text`, `section`, `reference`) on each failing check. The sentences of the nine
documented faults:

| Section | Fault | Check | Sentence |
|---|---|---|---|
| S-1 | Model gateway stopped | `container_health`, `model_gateway` | Das Modell-Gateway (LiteLLM) läuft nicht; Module können keine Modelle nutzen. |
| S-2 | Model not loaded | `model_ready` | Das Modell <name> ist nicht geladen; Anfragen schlagen fehl. |
| S-3 | Identity service stopped | `container_health` | Der Anmeldedienst (Keycloak) ist nicht erreichbar; niemand kann sich anmelden. |
| S-4 | Database of a module stopped | `container_health` | Die Datenbank von <Modul> läuft nicht. |
| S-5 | Emergency halt set | `halt` | Die Plattform ist per Not-Aus abgeschaltet (gesetzt von <Konto> um <Zeit>). |
| S-6 | Scope assignment removed | `realm` | Dem Client <id> fehlt der Scope <scope>; Zugriffe auf <Modul> werden abgelehnt. |
| S-7 | Data disk full | `disk_space` | Auf <Pfad> ist kein Platz mehr; Schreiben ist gestoppt. |
| S-8 | Certificate expired | `certs` | Das Zertifikat für <host> ist seit <Datum> abgelaufen. |
| S-9 | Mail server not reachable | `smtp` | Der Mailserver <host:port> antwortet nicht; <n> Nachrichten warten. |

A failing check none of them explains points at the diagnosis section of the handbook. The
sentences carry host names, paths, module, client and scope names, dates and counts, never a
secret or content.

### `logs`

```bash
tools/papaia-ctl logs <module|service> [--since=30m|DATE] [--lines=N] [--follow] [--config-dir=PATH]
```

The logs of every container of a module (`keycloak` or `papaia-keycloak`), of an add-on (its
name) or of one service, merged in time order. Each line shows the time, the service and the
correlation id (`X-Papaia-Correlation-Id`, `-` when the line has none), then the line as the
service wrote it, so one request can be followed through every service it touched. `--lines`
(default 1000, at most 10000) is per container; `--since` takes a duration (`30m`, `2h`) or a date
or time (`2026-09-27`, `2026-09-27T10:15:00Z`); `--follow` keeps reading until Ctrl-C.

### Logs and log rotation

Every service writes its log through Docker's `json-file` driver and keeps at most 5 files of 10
MiB, 50 MiB per container
([json-file driver](https://docs.docker.com/engine/logging/drivers/json-file/)). The core fragments
set this for each of their 47 core services; with every core profile on, the core's logs therefore
stay below 2350 MiB. Every active add-on gets the same rotation for each of its services through the
generated `overrides/addons/docker-compose.<name>-logging.override.yml`, which `addon start`
applies; add 50 MiB per add-on container to the bound. A container that is recreated starts a new
log.

### `support-bundle`

```bash
tools/papaia-ctl support-bundle [--out=FILE.tar.gz] [--lines=N] [--config-dir=PATH]
```

One archive for a support case, by default `support/papaia-support-<time>.tar.gz` in the config
directory, mode 600:

| File | Content |
|---|---|
| `doctor.json`, `status.json` | `doctor --json` and `status --json` |
| `versions.json` | Platform, Docker and Compose versions, add-on versions, the image of every container |
| `bom.yaml` | The bill of materials of the checkout (`compat/suite.yaml`) |
| `config.txt` | Every key of every `.env` in the config directory; values only for host names, URLs, ports, profiles, variants and models, otherwise `(set)` or `(empty)`; the add-ons of `deployment.yaml` |
| `logs/<project>/<service>.log` | The last `--lines` (default 1000) lines of every container |

Before anything is written, every file is masked: the installation's secrets (the values of
secret keys in every `.env` of the config directory and small secret files), private keys, age
keys, JWTs, bearer and basic credentials, API keys, mail addresses, values of password, token,
secret, `sub` and user name fields, and long random strings. Then every file is searched again;
a single hit stops the command with exit code 1 and nothing is written. An existing file is never
replaced. Writing the archive, or the stop, is one `papaia.audit/1` row in the audit outbox with
the correlation id the command prints. The archive holds what the masking leaves of the log lines;
read it before you pass it on.

### `metrics`

```bash
tools/papaia-ctl metrics [--out=FILE.prom] [--config-dir=PATH]
```

The platform's measurements in the Prometheus text format, on stdout or written atomically to a
`.prom` file for the textfile collector of a node exporter (run it from a timer, for example every
five minutes). It runs `doctor` and prints:

| Metric | Labels | Meaning |
|---|---|---|
| `papaia_check_status` | `check` | 0 pass, 1 warn, 2 fail (skipped checks are left out) |
| `papaia_certificate_days_left` | `file` | Days until a certificate expires |
| `papaia_module_revocations_age_seconds` | `module` | Age of the revocation list of a module |
| `papaia_audit_export_backlog`, `papaia_audit_export_lag_seconds` | `target` | Undelivered audit events per SIEM target and the age of the oldest |
| `papaia_backup_last_ok_age_seconds` | — | Age of the last successful restore point |
| `papaia_smtp_queue_messages` | — | Messages waiting in the mail relay |
| `papaia_status_sync_age_seconds` | — | Age of the last status sync with an upstream directory |
| `papaia_model_ready_seconds` | — | Seconds the default model took for one token |
| `papaia_metrics_generated_timestamp_seconds` | — | When the values were read |

No label carries a person. Request, error and duration counts per operation are the modules' own
`/metrics` endpoints.

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
wins. A layer that does not parse stops the render with one `ERROR:` line that names the file
and the position (`overlay/ai/librechat/librechat.yaml: invalid YAML at line 7, column 3: ...`),
and a structured layer must have a mapping at the top level.

To see what a draft overlay would render to without writing anything, papaia-manager calls the
core's `render-preview` command (`python3 -m lib.cli --repo-root R --config-dir C render-preview
--target=<path> --overlay-file=<file>`). It prints one JSON document with the effective text of
the target now and with the draft.

Render targets: `ai/librechat/librechat.yaml` · `ai/litellm/config.yaml` +
`prometheus.yml` · `ai/localai/models.txt` + `models/` · `services/searxng/settings.yml` ·
`infra/keycloak/keycloak.conf`.

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
├── services/               # searxng · firecrawl
├── manager/                # papaia-manager state: catalogs.yaml · installed.yaml
│                           #   tiles.yaml · jobs/ · audit.log
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

A distributed installation adds a `topology` block: which machines (nodes) there are, which one
is the controller that runs `papaia-ctl`, and which service runs where. Without the block the
installation is a single host, and nothing about it changes. See
[docs/adr/0009](docs/adr/0009-place-services-on-nodes-with-a-topology-block.md).

```yaml
topology:
  mode: distributed
  controller: internal        # runs papaia-ctl, holds the config tree and the CA keys
  link:
    port: 7443
  nodes:
    internal:
      address: 10.0.2.10
      executor: local
    edge:
      address: 10.0.1.10
      executor: ssh
      ssh: {user: papaia, port: 22}
      root: /srv/papaia-node  # the node's directory; its config dir is <root>/config
      gpu: none               # optional hardware hint for LocalAI
  placement:                  # service -> node; unlisted services stay on the controller
    nginx: edge
    keycloak: edge
    smtp: edge
    litellm: edge
```

The services that can be placed are `nginx` (Nginx Proxy Manager with its auth sidecar and
oauth2-proxy), `keycloak`, `litellm`, `librechat`, `websearch`, `localai`, `rag`, `smtp` and
`manager`. `manager` and `rag` always run on the controller, and `websearch` runs with
`librechat`. In distributed mode every render also writes one bundle per node to
`nodes/<name>/bundle/` in the config directory. A bundle holds only what that node's services
need: their `.env` files, rendered configuration and certificates, never the secrets of a
service on another node and never a CA key.

### `topology`

```sh
tools/papaia-ctl topology show [--json]   # nodes and where each service runs
tools/papaia-ctl topology validate        # exit 2 when the placement cannot work
```

`validate` names every problem before anything changes: a service on an unknown node,
`manager` or `rag` away from the controller, web search away from LibreChat, a LocalAI GPU
image on a node without that GPU, a link port that collides with a published port, or a public
URL with a port (in distributed mode the bundled proxy serves every URL by host name).

```sh
tools/papaia-ctl topology firewall [--format=table|json|csv]
```

`firewall` lists, in a distributed installation, the connections the installation opens
between its nodes: SSH from the controller to every other node, and the link port wherever a
service on one node calls a service on another. For the `dmz-split` example that is SSH and
7443 from internal to edge, and 7443 from edge to internal. On one host it lists the routes
of the [communication matrix](docs/network.md) that leave the host, with the configured
targets, and the host rules of the direct route to a SQL source. papaia never changes a
firewall itself.

### `node`

```sh
tools/papaia-ctl node add <name> --address=ADDR [--ssh=USER@HOST[:PORT]] [--root=DIR]
                          [--gpu=HINT] [--bootstrap=join|admin] [--admin=USER@HOST[:PORT]]
                          [--host-key-fingerprint=SHA256:...] [-y]
tools/papaia-ctl node list [--json] [--check]
tools/papaia-ctl node check <name> [--host-key-fingerprint=SHA256:...]
tools/papaia-ctl node remove <name> [-y]
tools/papaia-ctl node join-bundle <name> [--output=FILE]
tools/papaia-ctl node renew-link <name>
tools/papaia-ctl node sync <name>|--all [--checkout]
```

Nodes belong to a distributed installation. The controller talks to a node over SSH as the
unprivileged user `papaia`, with a key of its own per node (in `nodes/<name>/ssh/` of the
config directory, never copied anywhere). The node's `authorized_keys` entry allows exactly
one command, `papaia-ctl node-shell`. That command accepts a short list of verbs (start, stop
and inspect the node's services, install a bundle or a release, run a provisioning hook),
refuses everything else, and writes one audit line per call to `<root>/audit.log` on the node.

`node add` enrols a node in one of two ways:

- `--bootstrap=join` (the default) writes a join archive: the checkout, an install script,
  the `authorized_keys` line and the fingerprint of the controller's key. Copy it to the node
  and run `sudo ./papaia-join-<name>/install.sh` there. Then confirm the node's host key with
  `node check <name>`.
- `--bootstrap=admin --admin=USER@HOST` does the same over your own admin login on the node.
  `sudo` asks for your password if it needs one. Nothing of that login is stored.

The node needs Docker with the compose plugin, Python 3.10 or newer with PyYAML, and an SSH
server. Its host key is pinned when the controller first connects: the fingerprint is shown
and has to be confirmed, or given with `--host-key-fingerprint` in scripts. `node sync` hands
a node its release and its bundle. `node renew-link` issues a new link certificate for the
node and restarts its gateway.

---

## papaia-manager

`papaia-ctl` is a CLI: precise, scriptable, and shell access on the host is the price of
admission. **papaia-manager** is the browser counterpart — an optional core service
(profile `manager`, port 8120) that lets an operator discover, install, start, stop,
upgrade, roll back and remove add-ons, see what the stack is running and how the host is
doing, see which models LiteLLM serves and what they consumed, take, schedule or replay a
backup, switch the optional modules on and off, edit the customer overlay, manage the
realm's accounts and roles, set up the [mail relay](#outbound-mail) and what it is used for,
manage the nodes of a [distributed installation](docs/distributed.md), with the optional
[RAG system](#rag-system) manage its connections, collections and ingest jobs and, with the
optional [knowledge map](docs/knowledge-map.md), see and govern what the AI reaches on the AI
map page, without ever opening a terminal on the host.

It does not reimplement any of it. Every mutating operation shells out to `papaia-ctl`, and
status queries read the same modules under `tools/lib/`, so the UI and the CLI cannot drift
apart in behaviour. Anything done in the browser is visible to the next `papaia-ctl` command
and vice versa; `deployment.yaml` stays the single source of truth for both.

```bash
tools/papaia-ctl setup --manager --manager-host=https://manager.example.com
tools/papaia-ctl start
```

`setup` prompts for it interactively (default: enabled) and derives `MANAGER_PUBLIC_URL`
from `--app-host` when `--manager-host` is omitted. `--no-manager` leaves the profile off.

### What it offers

| Surface | Contents |
|---|---|
| **Dashboard** (`/`) | Tile overview of the deployed applications, configured in `$PAPAIA_CONFIG_DIR/manager/tiles.yaml` and seeded on first run. `{{KEY}}` placeholders in tile links resolve against the core `.env`; each tile's `visibility: all \| admin` is filtered server-side, so an admin-only tile is absent from a regular user's response rather than merely hidden. Administrators edit it in the browser (groups, tiles, drag and drop, a live preview). Besides links, a group can hold *widgets*, cards that show one piece of live state and link to the page that explains it: the installed papAIa release, the age of the newest backup, free disk space, how many services run, open warnings and the nearest certificate expiry. They refresh on their own and read what the manager already knows instead of measuring again. The default tiles (LibreChat, LiteLLM, Keycloak, NGINX Proxy Manager and Qdrant) show an icon that ships inside the manager, so nothing is loaded from another site; the logos stay the property of their owners. |
| **Services** | What this deployment is configured to run, and how much of it is up. Containers are grouped into modules by the `de.fidonis.module` label, and the *declared* state is read alongside them, so a configured-but-never-started service reads as **not deployed** instead of silently missing. Starting and stopping happens per Compose profile — the granularity `papaia-ctl` accepts — with an optional `--clean-up` on every operation that stops something. A status row in the sidebar of every page summarises the core, the add-ons and the host for every signed-in role, as counts only. |
| **Add-ons** | Catalogues, install, start/stop, upgrade, rollback and removal. Each add-on resolves to one of `available`, `installed`, `running`, `inactive` or `unmanaged`, merged from the catalogue scan, `deployment.yaml` and live container labels. When a catalogue's manifest lists the software an add-on bundles (`components`), the gallery card names the primary components and the detail page lists all of them with their role, the version an update brings and the tags an operator pinned in the add-on's `.env`; the manager reads those itself, and [`papaia-ctl addon components`](#addon) prints the same on the command line. *Remove* takes the add-on's containers down before it marks the add-on inactive (volumes and configuration stay) and is refused while the add-on's `docker-compose.yml` is missing. An upgrade is reviewed first: *Review upgrade* stages the catalogue's version and shows what [`papaia-ctl addon upgrade --dry-run`](#addon) reports (compatibility, components, new and removed settings, the add-on's changelog) and asks for the values the new version needs; the upgrade then applies exactly that version with a restore point of the add-on. *Roll back* returns to the version before, with the code and configuration only or with the data of that restore point. The Add-ons page counts and lists the waiting upgrades. Upgrading and rolling back need a core with these verbs (1.8.0 or newer). The add-ons an add-on requires (`requires.addons`) are badges on its card and page, and *Install* stays disabled while one is missing, inactive or too old, unless warn mode lets [`papaia-ctl`](#addon) install anyway; the active add-ons that require an add-on are listed as *Required by*, and *Remove* and *Uninstall* are refused until they are gone. The maintenance actions an add-on declares (`actions`) are buttons on its page that run [`papaia-ctl addon run`](#addon) as a job, a destructive one after a confirmation; on a distributed installation they are refused, like the command. Requirements and actions need a core with these manifest fields (1.9.0 or newer). |
| **Models & Usage** (`/models`) | Which models LiteLLM serves and what they consumed: tokens, spend in USD and requests per day, for all models and per model, over the last 7, 30 or 90 days, this month or a custom range. Administrators only, and read-only: models, prices, teams and keys stay in LiteLLM's own Admin UI, which the page links to. The manager reads LiteLLM at `LITELLM_URL` with the master key from `ai/litellm/.env`, which it never shows or logs. Days are UTC days, and a model without a price shows no spend. |
| **Nodes** (`/nodes`) | Only on a [distributed installation](docs/distributed.md): the machines with their services, address, status, version and link health; adding a node with its enrolment commands, confirming its host keys, handing it its bundle and removing it. Each of these changes needs a fresh sign-in at Keycloak on top of the admin role. The other pages follow the nodes: Services has a section per node and acts on the node that owns a group, Host has a node selector, the widgets and notifications look at every node, Backup backs up one node or all and restores a node as a whole, Upgrade shows the release per node, and module, overlay and mail changes run on their node. While an upgrade has not finished or a node runs another release, every admin page says so and refuses what the core would refuse. On a single host none of this appears. |
| **AI map** (`/knowledge-map`) | The management side of the [knowledge map](docs/knowledge-map.md), for administrators only; while the `knowledge-map` profile is off, the page links to Settings > Modules. It shows which data the AI reaches, for whom, over which access path and with which model: the rendered map as a graph that can be viewed as a chosen role, every entry with its access paths and roles, the findings of the render, a routing test that asks the map server where a question would land for a set of roles without recording it, usage, gold-set runs and the refinements the map server mined from use, to accept or reject. Entries are created and edited as forms, an entry an add-on, a module or the inventory declares as an override of the changed fields only, and the operator files under `overlay/knowledge-map/` are edited in place; every change is a queued job that renders the map and puts the previous file back when the render refuses it. A *Governance* tab records owner, classification and personal data of each source and the tier of each model, shows the findings with what to change, accepts one until a date and exports the facts as `facts.json` or `facts.csv`. The manager reads the map from the configuration directory and the rest from the map server at `KNOWLEDGE_MAP_URL` with the `KM_ADMIN_TOKEN` from `ai/knowledge-map/.env`, which it never shows or logs. Neither the map nor the page restricts data access or model use. It needs a core that ships the `knowledge-map` profile (1.9.0 or newer). |
| **RAG** (`/connections`, `/collections`, `/embedding`, `/ingest/jobs`) | The management side of the [RAG system](#rag-system), for administrators only and only while the `rag` profile is active; without it the pages answer 404 and nothing new appears. *Connections* are the vector databases the system works with (the integrated Qdrant is created as `default`). *Collections* creates and deletes Qdrant collections and keeps the realm roles that may read or write each of them, in the format `qdrant-mcp-rbac` enforces. *Embedding* puts uploaded files, or files already in the documents folder, into a collection through the ingester. *Ingest Jobs* edits the ingester's jobs, shows their runs file by file and stores the credentials of remote sources encrypted. The dashboard gains a *Qdrant* tile for administrators. The ingester has no web interface of its own; these pages replace it. They need a core that ships the `rag` profile (1.5.0 or newer). |
| **Host** (`/host`) | The state of the machine under the deployment: memory, CPU load, GPU, clock synchronisation, free disk space and certificate expiry, plus what Docker's data takes. The manager measures nothing itself: it shows the verdicts of [`papaia-ctl doctor`](#doctor), so the page and a shell on the host cannot disagree about a threshold. It needs a core that ships `doctor` (1.4.0 or newer); on an older one the page says so. How often the host is re-measured is a setting. |
| **Backup / Restore** | `papaia-ctl backup` and `restore` from the browser, with the restore-point catalogue and a configurable retention period. Backups can run on a schedule (every day, on chosen days, every few hours or a cron expression, in a timezone of choice), run by a scheduler inside the manager, so the host needs no cron job or systemd timer. |
| **Users** (`/users`) | The accounts and the realm roles of the bundled Keycloak, without the Admin Console, for the identity role `papaia-admin` only (see [Access control](#access-control)). Create an account with a temporary password or a mailed link, enable or disable it, change its roles, reset its password, and view and end its sessions. The *Roles* tab lists the realm roles, creates and changes them and deletes one after showing who holds it; the roles the stack ships stay as they are. The page acts with the signed-in account's own Keycloak rights, so it needs a core whose realm gives `papaia-admin` the user and role administration rights (1.6.0 or newer; [ADR 0006](docs/adr/0006-manage-accounts-with-the-signed-in-users-token.md)). It does not exist where the accounts live in an external identity provider. |
| **Mail** (`/mail`) | Two tabs under *System*, for administrators. *Notifications* lets recipients (an email address or a webhook URL) choose which events they receive: a failed job, an overdue backup, a service that stopped or turned unhealthy, an available update, an expiring certificate and a new or changed high finding of the AI map; each event is reported once per occurrence and a webhook URL is never shown again after it is saved. *Mail Server* sets up the stack's outbound relay: the mail server behind it (host, connection security, port, login, write-only password, sender), a connection test that sends nothing, a test mail through the relay and the length of its queue. Saving is a queued job that runs the core's own `setup`; the relay itself needs the `smtp` profile ([Outbound mail](#outbound-mail), 1.6.0 or newer), and the page says so on an older core. |
| **Settings** | The manager's own configuration in three tabs. *Manager*: the name and second line at the top of the sidebar, an uploaded logo, and the interval of the Host page's measurements. *Modules*: the one place that switches the optional modules (LocalAI with its accelerator variant, web search, the RAG system, voice, the mail relay and the knowledge map) on and off; it asks what `papaia-ctl setup` asks where an answer is missing, and switching one off asks whether to keep its data and settings, delete the data, or delete both (the module's name has to be typed to delete); for the knowledge map a separate choice, off by default, also deletes the operator files. *Overlay*: edits the customer [overlay](#configuration--render-lifecycle) files for LibreChat, LiteLLM, SearXNG and Chatterbox (the speech synthesis of [voice](#voice-local-speech)) with a syntax check while typing, the effective result as a diff and **Apply** as a queued job that recreates the services reading the file; the previous version of every file is kept (the latest 20) and restored from a *Versions* tab. Switching on the RAG system and the mail relay, deleting a module's data or settings and the effective-result diff need a core with the module operations and `render-preview` (1.6.0 or newer); an older core still switches LocalAI and web search and switches modules off, keeping everything. |
| **Language** | The interface is in English and German. Every account chooses *Automatic*, *English* or *Deutsch* in the account menu at the bottom of the sidebar; the choice is stored on the server by the account's OIDC subject (`preferences.yaml`, part of a backup), so it is the same on every computer. *Automatic* follows the browser's language and falls back to `MANAGER_DEFAULT_LOCALE` in `src/manager/.env` (English unless set). Log lines, the audit log, job logs and the emails and webhooks of notifications stay in English. |

### Catalogues

A catalogue is a source of add-ons — a Git repository or a local directory — registered at
runtime rather than shipped with the Core, in
`$PAPAIA_CONFIG_DIR/manager/catalogs.yaml`. Each is scanned for top-level `papaia-app.yaml`
manifests. Installing materialises a **pinned snapshot at a specific commit**, so refreshing
a catalogue later never moves code out from under a running container. Every version gets a
directory of its own, `addons/_managed/<catalogue>/<revision>/<add-on>`, written once and
never overwritten. An upgrade is an explicit operation that the manager hands to
[`papaia-ctl addon upgrade`](#addon) after the review described above, and a rollback to
`papaia-ctl addon rollback` ([ADR 0008](docs/adr/0008-upgrade-add-ons-by-repointing-to-immutable-snapshots.md)).

### Access control

Authentication is native OIDC against the realm client `papaia-manager` — there is no
oauth2-proxy sidecar in front of it. Realm roles gate the UI, and the same dependencies
guard the JSON API:

| Variable | Default | Grants |
|---|---|---|
| `MANAGER_ADMIN_ROLE` | `manager-admin` | Every surface except Users — add-ons, catalogues, services, host, models, backup, mail, settings (modules and overlay), jobs, nodes, the AI map and, while the `rag` profile is active, the RAG pages |
| `MANAGER_USER_ROLE` | `user` | The dashboard only; admins hold it implicitly |
| `MANAGER_IDENTITY_ADMIN_ROLE` | `papaia-admin` | The Users page: accounts, roles and sessions of the realm. `manager-admin` alone is not enough |

An account holding neither the admin nor the user role is rejected at login. The variables live in
`src/manager/.env`, not in the root `.env`: the compose file never interpolates them, so a
root-level copy would resolve but never reach the container.

### Host requirements

The manager invokes `papaia-ctl`, which invokes `docker compose`, which resolves the
bind-mount sources in the Core and add-on compose files. Those paths must therefore mean
the same thing inside the container as on the host — **path parity**:

- `PAPAIA_WORKSPACE_DIR`, `PAPAIA_CONFIG_DIR` and `PAPAIA_BACKUP_DIR` are each mounted at
  their own host path, not remapped to `/workspace` or `/config`. `setup` stamps all three
  automatically.
- `/var/run/docker.sock` is mounted, and `DOCKER_GID` must match the GID owning it inside
  the container. `setup` stamps it: on Linux from the socket on the host, under Docker
  Desktop on macOS as `0`. Check it with:

  ```bash
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine \
    stat -c '%g' /var/run/docker.sock
  ```

- The container runs as the host `UID`/`GID` so that files it writes into the config
  directory keep the ownership `setup` established.

> **The `manager` profile therefore runs on Linux hosts and on Docker Desktop for macOS.**
> Docker Desktop on macOS shares `/Users` with its VM under the same path, so the workspace,
> configuration and backup directories must live below `/Users` (the default). Docker
> Desktop on Windows does not preserve host-path parity across its VM boundary; there,
> leave the profile off with `--no-manager` and drive the lifecycle through `papaia-ctl`.
>
> On macOS, browsers check Keycloak's certificate against the login keychain and reach
> Keycloak from the Mac itself. `setup` offers to trust the local CA there (or prints the
> `security add-trusted-cert` command) and reports when `host.docker.internal` needs an
> `/etc/hosts` entry.

Granting a container access to the Docker socket is granting it root on the host. That is
inherent to what the manager does, and the reason its access is role-gated and its
operations are recorded in `$PAPAIA_CONFIG_DIR/manager/audit.log`. Expose it behind TLS and
treat `MANAGER_ADMIN_ROLE` as a host-administrator role. With the manager profile the core also
starts `papaia-docker-gate`, a broker that allows only the status and `start`/`stop` of the
installation's containers ([docs/docker-gate.md](docs/docker-gate.md)).

### State

Everything the manager owns lives in `$PAPAIA_CONFIG_DIR/manager/`, so `papaia-ctl backup`
captures it along with the rest of the installation:

| File | Contents |
|---|---|
| `catalogs.yaml` | Registered add-on sources |
| `installed.yaml` | Which add-on came from which catalogue, at which commit |
| `tiles.yaml` | Dashboard tiles, grouped, with per-tile visibility |
| `settings.yaml` | The manager's own settings, one section per topic: branding and the host-monitoring interval |
| `branding/` | The uploaded logo |
| `preferences.yaml` | The interface language each account chose, keyed by its OIDC subject |
| `schedule.yaml` | The backup schedule |
| `notifications.yaml` | The notification recipients and what each receives (mode 0600: a webhook URL can carry a secret) |
| `notifications-state.json` | What the notification checks already reported, so a restart repeats nothing |
| `overlay-history/` | The previous versions of the overlay files edited on the Settings > Overlay tab (the latest 20 per file, readable by the owner only) |
| `jobs/` | Records of long-running operations, with their streamed log output |
| `audit.log` | Who triggered which operation |

The RAG pages keep their data in the RAG module's own directory instead, because the ingester
reads it from there: the catalog files `connections.yaml`, `jobs.yaml` and `secrets.yaml` in
`$PAPAIA_CONFIG_DIR/ai/rag/catalog/` and uploads that are still waiting for a run in
`$PAPAIA_CONFIG_DIR/ai/rag/documents/uploads/`. Comments in `jobs.yaml` are lost when the manager
writes it, and it keeps the previous content of `connections.yaml` and `jobs.yaml` as `.bak`. All
of it is part of the configuration directory and so of `papaia-ctl backup`.

The application itself ships as the pinned image `ghcr.io/fidonis/papaia-manager`, built by
[Fidonis](https://www.fidonis.de) in its own repository; `src/manager/` here carries only
the compose file and `.env.example`. Upgrading the manager is an image-tag change,
independent of the platform release cadence.

---

## Architecture overview

papAIa is structured in three tiers:

- **Tier 1 — Core** (always on): identity, ingress, inference, and the chat layer.
  Self-sufficient; no add-on required.
- **Tier 2 — First-party add-ons**: services maintained by [Fidonis](https://www.fidonis.de),
  plugging in through the add-on contract, version-pinned.
- **Tier 3 — Custom add-ons**: bespoke customer services following the same contract.

The split is deliberate. A stack that grows every service a single customer once asked for
becomes unmaintainable across a fleet, and a customer who cannot remove what they do not
need is not sovereign over their own deployment. Keeping the Core lean and everything else
behind one contract is how Fidonis runs the same artifact for every customer while each
installation contains only what that customer chose.

```
┌──────────────────────────────────────────────────────────────────┐
│  Workspace (parent directory of this checkout)                   │
│                                                                  │
│  papaia/             ← Lean Core (this repo)                     │
│  │  Keycloak · oauth2-proxy · Nginx Proxy Manager                │
│  │  LibreChat · LiteLLM · LocalAI · papaia-manager               │
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

### Published ports

Only the edge proxy publishes ports. It listens on `HOST_IP` on `INGRESS_HTTP_EXT_PORT` and
`INGRESS_HTTPS_EXT_PORT` (default 80 and 443), so a second stack can run next to one that
already holds 80/443 — set other values in `.env` and put the port into the public URLs.
`INGRESS_HOST_IP` binds the edge alone to another address; leave it empty on a single host.
The Nginx Proxy Manager API stays on `127.0.0.1` (`NPM_API_LOCAL_PORT`) for `papaia-ctl`.

Keycloak, LibreChat, LiteLLM, LocalAI, oauth2-proxy, papaia-manager, Qdrant and the NPM admin
UI publish no port of their own: browsers reach them by host name through the edge (below),
the services reach each other on `papaia-net`. [`security/published-ports.yaml`](security/published-ports.yaml)
lists the two ports outside the edge (the NPM API on loopback and the link port of a
distributed installation, which is published on the node's address and accepts mutual TLS
only). The test suite fails on any other published port, and the list only ever shrinks.

- **Keycloak's admin API** is never routed through the edge: the proxy host of `auth.<domain>`
  answers `/admin` with 403. Each `start` and `npm-provision` restores that host's forward
  target and its advanced configuration (with the block), so put your own nginx lines on
  that host into a custom location, not into the advanced field; a certificate, forced SSL,
  HSTS and custom locations you set in the NPM UI are kept. The steps that call it (`keycloak-role-sync`, `realm-sync`,
  `post-restore`, the service accounts, the clients of an add-on) run on the stack network:
  on the host `papaia-ctl` starts them in a one-shot container with the papaia-manager image
  (read-only, no capabilities, no Docker socket), which is removed when the step ends.
- **Direct port access** (`--reverse-proxy-provider=no_proxy`, or `--allow-direct-port-access`)
  is the only way to publish the core ports again. `setup` writes them into the generated
  `overrides/docker-compose.direct-ports.override.yml` (with a digest; `doctor` fails on a
  hand-edited copy and on one left behind the edge). It refuses direct port access while an
  add-on with a header identity (`exposes` with `header_identity: true`), `me-web` or an
  add-on with delegation is active, and refuses any such service that publishes a port, also
  on `127.0.0.1`.

> **Upgrade note (1.10).** The core ports listed above are no longer published behind the
> bundled proxy. `setup` moves the addresses an earlier release derived
> (`https://<host>:8110` and the like) to the service's host name on the edge; an address you
> chose yourself is kept and must then be served by your proxy. A LAN address or a bare host
> name as `PAPAIA_HOST` needs `INGRESS_DOMAIN` (a domain whose names resolve to the host).
> Scripts that called a port directly (for example Qdrant on 6333) use the host name or run on
> `papaia-net`.
>
> Earlier releases published 80/443 on every interface regardless of `HOST_IP`. The edge
> follows `HOST_IP`: an installation with the bundled proxy and `HOST_IP=127.0.0.1` answers on
> loopback only. Set `INGRESS_HOST_IP=0.0.0.0` (or the host's address) in `.env` to keep the
> edge reachable from the network.
>
> In a distributed installation the node running the bundled proxy listens on its node
> `address` only, no longer on every interface. If users reach that node on another
> interface than the one the other nodes use (a dual-homed DMZ host), set `ingress_ip` on
> the node in the topology (`--node=NAME=ADDR,ingress_ip=IP` or `node add --ingress-ip=IP`)
> before upgrading; it moves only the edge.

### Host names and add-on interfaces

Every web interface gets a host name of one scheme; no proxy host is created by hand.

| Installation | Host name of an interface | Example |
|---|---|---|
| Server domain (`PAPAIA_HOST` is a fully qualified name, or `INGRESS_DOMAIN`) | `<name>.<domain>`, with the edge port when it is not the default | `https://flow.example.org` |
| Local (`localhost`, `host.docker.internal`, a loopback address), behind the bundled proxy | `<name>.<env>.papaia.localhost` with the edge port | `https://auth.itest.papaia.localhost:57143` |
| LAN address or bare host name | refused behind the bundled proxy: set `INGRESS_DOMAIN` | – |
| `no_proxy` or `--allow-direct-port-access` | `host.docker.internal` (or the app host) with a port per service | `https://host.docker.internal:8110` |

`<env>` is the `--env` of the installation (`papaia-itest` gives `itest`; the default
project `papaia` has none). Browsers resolve every name below `localhost` to the loopback
address without an `/etc/hosts` entry (RFC 6761, section 6.3); Safari on macOS may not, so
use a Chromium-based browser or Firefox for a local installation. A fresh local setup
behind the bundled proxy derives Keycloak (`auth`), LibreChat (`chat`), LiteLLM (`litellm`),
LocalAI (`localai`), papaia-manager (`manager`), Mein Bereich (`me`), Qdrant (`qdrant`), oauth2-proxy (`oauth2`)
and the NPM admin UI (`npm`) this way. A port address an earlier release derived moves to
the host name; an address the operator chose is kept. The edge port follows `INGRESS_HTTPS_EXT_PORT` (443 is left out of
the URL). The proxy hosts `papaia-ctl` creates carry no certificate of their own, like the
ones it created before; a certificate for these names is set up in Nginx Proxy Manager.

An add-on declares its interfaces in `integration.nginx` (contract generation 12, see
[`docs/architecture.md`](docs/architecture.md)): a host key, the service, its port and
optionally `websocket` and `max_body`. The manifest never names a host. The core gives each
interface the host name `<host key>.<domain>` of the scheme above and

- with the bundled proxy (`internal_nginx`): `start` (`npm-provision`) creates or corrects a
  proxy host per interface, which clears the identity and gate headers like every host
  `papaia-ctl` creates, and attaches the proxy to the add-on's network;
- with an external proxy (`external_proxy`): `papaia-ctl proxy list` and the end of `setup`
  print the forwards to set up (below);
- without a proxy (`no_proxy`): there are no host names.

Settings in the root `.env`:

| Variable | Purpose |
|---|---|
| `INGRESS_HOST_<KEY>` | Renames the host key `<key>` (upper case, `-` as `_`), for example `INGRESS_HOST_FLOW=workflows`. One DNS label, nothing else: an address or a path is refused |
| `INGRESS_DOMAIN` | The domain of the interfaces when it differs from the one of `PAPAIA_HOST` |
| `INGRESS_APP_DOMAIN` | The second domain of the app host (host key `apps`), for example `example-apps.org`. A site of its own: neither the platform domain nor a domain inside or above it, so the platform's cookies never reach it. Locally `<env>.papaia-apps.localhost` |

The app host serves its domain and every subdomain (`*.<app domain>`). Two interfaces that
claim the same host name (also one of the core's) stop `npm-provision` and `proxy list`
with both owners named; rename one.

```bash
tools/papaia-ctl proxy list [--json] [--config-dir=PATH]
```

Prints host name → internal target for every interface of the core and the active add-ons,
with the Docker network the target is reached in and the options the forward needs
(`websocket`, `max_body`, `tls-no-verify` for Keycloak's own certificate).

### Paperless behind the proxy

Paperless takes the signed-in person from the request header `X-Papaia-Remote-User`. Whoever
can send that header to Paperless can act as anyone, so the header must never get there
except from the Paperless MCP server. The Paperless add-on puts a gate in front of Paperless
that passes a request only with a caller's secret in `X-Papaia-Gate`; the core does the
proxy's part:

- **Every proxy host clears both headers.** `npm-provision` (part of `start`) writes
  `more_clear_input_headers "X-Papaia-Remote-User" "X-Papaia-Gate";` into the proxy
  manager's `server_proxy.conf`, which it includes in every proxy host, also in hosts created
  by hand; the hosts `papaia-ctl` creates carry the same line. A `proxy_set_header ... "";`
  in a host's advanced settings does **not** do this in the proxy manager and lets the header
  through. Your own lines in `server_proxy.conf` below the managed block are kept.
- **Only the Paperless route carries the proxy's secret.** While the Paperless add-on is
  active and its `PAPERLESS_PUBLIC_URL` is a host name without a port, `npm-provision` creates
  (or corrects) its proxy host: to the gate (`paperless:8001`), the identity header cleared,
  the gate header set from a file. The value is not stored in the proxy manager's database.
- **The secret is the proxy's own.** `setup` generates it (43 characters, URL-safe) into
  `$PAPAIA_CONFIG_DIR/secrets/paperless-gate/proxy/` (directory 0700, files 0600, never in a
  `.env`); the proxy mounts that directory read-only. The MCP server has a different secret,
  so either can be revoked alone. Rotate it with `papaia-ctl secrets rotate paperless-gate/proxy`.
- **The chat service is not on the Paperless network.** For the Paperless add-on,
  `papaia-ctl` attaches only the proxy to the add-on's network; LibreChat (and any other core
  service the manifest attaches) joins `${PAPAIA_PROJECT}-paperless-front` instead, a network
  the add-on's project creates with only its MCP server on it.

With an external proxy (`external_proxy`), configure the same yourself: clear both headers
on every host, set `X-Papaia-Gate` to the content of
`$PAPAIA_CONFIG_DIR/secrets/paperless-gate/proxy/secret` only on the Paperless host, and
forward that host to the gate.

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
| Network | The add-on declares its bridge network and which core containers must attach; `papaia-ctl` writes the Compose override. Since contract generation 16 it may also declare internal networks that only LiteLLM joins (`networks.isolated`, see [docs/isolated-networks.md](docs/isolated-networks.md)) |
| OIDC | Keycloak clients and protocol mappers registered additively |
| LibreChat / MCP | `mcpServers` and `allowedDomains` fragments merged at render time |
| Ingress | `integration.nginx`: since contract generation 12 a list of interfaces the core gives host names and proxy hosts (see [Host names and add-on interfaces](#host-names-and-add-on-interfaces)); before, a Nginx Proxy Manager fragment merged at render time (optional) |
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
permissions — no shared admin credentials. It is one of the first-party add-ons Fidonis
maintains and version-pins against the `ADDON_API` contract, so a Core upgrade cannot
silently break it.

Because the contract is the only integration point, an add-on you write yourself is
indistinguishable from one Fidonis ships. There is no privileged path, and nothing in the
Core needs to know your add-on exists.

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

No core service publishes a port for your proxy. `papaia-ctl proxy list` lists every public
URL with its internal target (`--json` for a machine-readable list); `setup` prints the same
list at its end. A target is a service name and port inside a Docker network on this host
(the column `NETWORK`), for example `keycloak:8443` (HTTPS) and `librechat:3080` on
`papaia-net`:

- **Proxy on the same host:** attach the proxy container to that network
  (`docker network connect papaia-net <proxy>`) and forward to the target by name.
- **Proxy on another host:** do not choose `external_proxy`; keep the bundled proxy
  (`internal_nginx`) as the edge and let your proxy forward every host name to it
  (`HOST_IP:INGRESS_HTTPS_EXT_PORT`) with the original `Host` header. There is no port per
  service to forward to.

Do not route `/admin` of the Keycloak host: the admin API stays on the stack network. Include
the app host's second domain with its subdomains.

The forward-auth proxy (`oauth2-proxy:4180`) signs in under a host name of its own, without a
port: `setup` derives `OAUTH2_PROXY_PUBLIC_URL` as `oauth2.<domain>` (with
`--app-host=https://chat.example.com` that is `https://oauth2.chat.example.com`, with
`INGRESS_DOMAIN=example.com` it is `https://oauth2.example.com`) and sets oauth2-proxy's
callback and its Keycloak redirect URI from it. Serve that host name on your proxy. To use
another URL, set `OAUTH2_PROXY_PUBLIC_URL` in the root `.env`; `setup` keeps a value you chose.
An app host without a domain (an IP address) needs one of the two, otherwise `setup` stops
with a message that names them.

Keycloak terminates TLS itself, on port 8443 inside the container, using the self-signed
certificate `papaia-ctl` generated. Its plain-HTTP listener is never published. **Your proxy
must therefore speak HTTPS to Keycloak and skip certificate verification on that hop** — a
plain-HTTP `proxy_pass` to `keycloak:8443` will fail.

Keycloak runs with `KC_PROXY_HEADERS=xforwarded`, so the `X-Forwarded-*` headers are
mandatory. Without them Keycloak treats the request as plain HTTP, drops the `Secure` flag
from its cookies, and cross-origin OIDC POSTs silently lose their state.

#### Caddy

```caddy
auth.example.com {
    @admin path /admin /admin/*
    respond @admin 403
    reverse_proxy https://keycloak:8443 {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

chat.example.com {
    reverse_proxy librechat:3080
}
```

Caddy runs on the same host and is attached to `papaia-net`; it sets `X-Forwarded-*` on its
own.

#### nginx

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location ~ ^/admin(/|$) { return 403; }   # the admin API stays on the stack network

    location / {
        proxy_pass              https://keycloak:8443;
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
        proxy_pass              http://librechat:3080;
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

- The nginx container resolves `keycloak` and `librechat` only while it is attached to
  `papaia-net`.
- `OAUTH2_PROXY_COOKIE_SECURE` must match the scheme of `PAPAIA_HOST`: `true` for HTTPS,
  `false` for plain HTTP. Browsers ignore `Secure` cookies over HTTP, so a mismatch breaks
  login without an obvious error.
- `--reverse-proxy-provider=no_proxy` runs the stack with no proxy and no TLS at all and
  publishes the core ports through the generated direct-ports override. `setup` asks for
  confirmation and refuses it while a protected add-on is active
  ([Published ports](#published-ports)). Development only.

### Mein Bereich (`me`)

Mein Bereich is the page where every person sees and changes their own settings of the
installation's modules. Next to it runs the preference store `prefs`, which several modules
read: notification channel, fallback channel and quiet hours, language, appearance and time
zone. The profile has three services, `me-web`, `prefs` and `prefs-db`; `me-web` and `prefs`
run from one pinned image of `papaia-me` ([ADR 0020](docs/adr/0020-mein-bereich-and-the-preference-store-as-core-profile.md)).
No service of the profile publishes a host port.

**Enable.** There is no `setup` option for `me`. Add the profile to `COMPOSE_PROFILES` in the
root `.env` of the config directory, run `setup` once so it derives the address, and start:

```bash
# $PAPAIA_CONFIG_DIR/.env: append me to the list that is there, for example
COMPOSE_PROFILES=keycloak,nginx,oauth2-proxy,librechat,litellm,egress,audit,me

tools/papaia-ctl setup
tools/papaia-ctl start
```

`setup` keeps a profile it does not switch itself, on every later run and during an upgrade.
It seeds `infra/me/.env` in the config directory and fills its generated values
(`ME_OIDC_CLIENT_SECRET`, `ME_SESSION_SECRET`, `PREFS_DB_PASSWORD`); do not edit them by hand. The
database password reaches `prefs` and `prefs-db` as a secret file, never as a variable. The other
settings, such as `ME_DEFAULT_LANG` or `PREFS_DEFAULT_TIME_ZONE`, are listed under
[Mein Bereich variables](docs/configuration.md#mein-bereich-variables). `prefs` delivers one
audit row per write to `papaia-audit`, so keep the `audit` profile on (it is in the default list).
In a [distributed installation](#distributed-installations) the profile runs on the controller.

**Address.** Browsers open `me-web` at `ME_PUBLIC_URL`. `setup` derives it as `me.<domain>`
with the scheme of [Host names and add-on interfaces](#host-names-and-add-on-interfaces), for
example `https://me.example.org`; an address you set yourself in the root `.env` is kept.

- Bundled proxy (`internal_nginx`): `start` creates the proxy host `me.<domain>`.
- External proxy (`external_proxy`): set up the forward that `tools/papaia-ctl proxy list`
  prints for `me` (target `me-web`, port 8000).
- `no_proxy` or `--allow-direct-port-access`: nothing is derived and `me-web` has no address,
  because it never publishes a port.

Add-ons reach the store `prefs` after they list it under `networks.attach` (add-on contract
generation 8, see [`docs/architecture.md`](docs/architecture.md)); `prefs-db` is never attachable.

**Disable.** Remove `me` from `COMPOSE_PROFILES` in `$PAPAIA_CONFIG_DIR/.env`, then remove the
profile's containers:

```bash
tools/papaia-ctl stop --clean-up --profiles=me
```

What stays on disk: the volume `prefs-pgdata` with every person's saved preferences,
`infra/me/.env` in the config directory with its generated values, and `ME_PUBLIC_URL` in the
root `.env`. Adding `me` again and starting finds all of it. `stop --volumes` does not take the
profile `me`; to delete the preferences as well, remove the volume after the stop with
`docker volume rm <project>_prefs-pgdata` (`<project>` is `papaia`, or `papaia-<env>` for a
named environment). Take a [backup](#backup) first if the preferences may be needed again.

**Upgrade.** The image of `me-web` and `prefs` is pinned in `src/infra/me/docker-compose.yml`, so
[`upgrade`](#upgrade) changes it together with the core in stage 2 (`core`) and starts the new
image on the same volume. Stage 3 `me` only applies to an installation that still runs Me as an
add-on; for the profile the plan lists it as `absent`, and no add-on checkout is needed. The
restore point R0 of the upgrade holds `prefs-pgdata`, so [`rollback`](#rollback) brings the
preferences back with the core.

**Backup and restore.** [`backup`](#backup) archives `prefs-pgdata`, encrypted like every core
volume, under the module `me`. `me-web` keeps no state of its own. To bring back the preferences
alone from a backup of the whole installation:

```bash
tools/papaia-ctl restore --restore-point=ID --only=module:me
```

Only the profile `me` is taken down and started again; everything else keeps serving. A
backup made with `backup --only=module:me` is restored with `restore-scoped --only=module:me`.

**Known limit of this release.** The core does not yet register the sign-in client `papaia-me`
in the realm, and it writes neither the module list of the area
(`personal-settings/registry.yaml` in the config directory) nor the `azp` allow-list of `prefs`
(`security/azp/`). Until it does, the profile starts and is reachable at its address, but nobody
can sign in to Mein Bereich, and `prefs` refuses requests.

### Connection registry (`connections`)

The connection registry is the one store for the saved credentials of mail, calendar and
database accounts: a person adds an account once, a module that may use it receives it sealed
for one call and never keeps a copy, and every use is audited. The profile has three services:
`connections` (the registry), `connections-migrate` (a one-shot container that applies the
database migrations as the owner of the schema) and `connections-db`. None publishes a host
port. See [ADR 0021](docs/adr/0021-connection-registry-as-a-core-profile.md).

**Enable.** The profile is off on a fresh install. Switch it on with `setup` and start:

```bash
tools/papaia-ctl setup --connections
tools/papaia-ctl start
```

An interactive `setup` asks for it (default off); the answer is kept on later runs and during an
upgrade. When the profile is on, `setup` adds `connections` to `COMPOSE_PROFILES` and generates
the two database passwords once (`CONNECTIONS_OWNER_DB_PASSWORD`,
`CONNECTIONS_SERVICE_DB_PASSWORD` in `infra/connections/.env` of the config directory; do not
edit them by hand). It also requests the registry's server certificate from the platform PKI and
plans the realm role `connections-admin` (part of `papaia-admin`) and the bearer client
`papaia-connections`. The clients whose tokens the registry accepts (`CONNECTIONS_PERSON_CLIENTS`,
`CONNECTIONS_SERVICE_CLIENTS`, `CONNECTIONS_DELEGATE_CLIENTS`) are empty in the core; a module
that uses the registry names its entries. Every setting is listed under
[Connection registry variables](docs/configuration.md#connection-registry-variables). The
registry sends its journal to `papaia-audit`, so keep the `audit` profile on. In a
[distributed installation](#distributed-installations) the profile runs on the controller.

**Address.** The registry has no browser address and no administration page of its own. It
answers at `https://connections:8080` with TLS 1.3 and, by default, mutual TLS: every caller
needs a client certificate of the platform CA (`CONNECTIONS_TLS_CLIENT_CA`). Only its declared
consumers reach it: `me-web` on `papaia-connections-net`, and add-ons that list `connections`
under `networks.attach`. It is not on `papaia-net`. `me-web` does not present a client
certificate yet, so with the default `CONNECTIONS_TLS_CLIENT_CA` its calls to the registry fail;
clearing the variable allows one-sided TLS, which the security profile `kritis` refuses.

**Disable.** Switch the profile off and remove its containers:

```bash
tools/papaia-ctl setup --no-connections
tools/papaia-ctl stop --clean-up --profiles=connections
```

What stays on disk: the volumes `connections-db` (the accounts and the journal of uses) and
`connections-keys` (the master key), and `infra/connections/.env` with both database passwords.
Keep the `.env` as long as you keep the volumes: the database logins were created with these
passwords, and a new value locks the registry out of its own database. The realm keeps the role
`connections-admin` and the client `papaia-connections` until you remove them. To delete every
stored credential as well, add `--volumes`:

```bash
tools/papaia-ctl stop --clean-up --profiles=connections --volumes
```

This removes both volumes and cannot be undone except from a backup.

**Upgrade.** The registry's image is pinned in `src/infra/connections/docker-compose.yml`, so
[`upgrade`](#upgrade) changes it together with the core in stage 2 (`core`); there is no stage
of its own. At every start `connections-migrate` applies the pending migrations before the
registry starts. The restore point R0 of the upgrade holds both volumes, so
[`rollback`](#rollback) brings the database and its keys back together.

**Backup and restore.** [`backup`](#backup) archives `connections-db` and `connections-keys`,
each encrypted like every core volume, under the module `connections`. A database without its
keys cannot be read, so they are restored together:

```bash
tools/papaia-ctl restore --restore-point=ID --only=module:connections
```

A backup made with `backup --only=module:connections` is restored with
`restore-scoped --only=module:connections`. `tools/papaia-ctl secrets rotate connections/credentials`
makes a new master key active and seals every stored credential again (see
[`secrets rotate`](#secrets-rotate)); take a new backup after it. With `CONNECTIONS_KEY_PROVIDER`
set to `openbao` or `pkcs11` (required under `kritis`) the master key lives outside the volume,
and that key store needs its own backup.

### RAG system

The `rag` profile adds a retrieval stack next to LibreChat: [Qdrant](https://qdrant.tech) as the
vector database, `qdrant-mcp-rbac` as an OIDC- and role-aware MCP server in front of it, and
`qdrant-ingest`, which pulls documents from S3, WebDAV, SFTP, SMB, FTP, Google Drive, Azure Blob,
HTTP or a local directory into Qdrant on a schedule (Apache Tika extracts the text). It is not
LibreChat's built-in file search; `librechat-ragapi` and `librechat-vectordb` belong to the
`librechat` profile and both can run together.

| Service | Port | Reachable from |
|---|---|---|
| `qdrant` | 6333 | `qdrant.<domain>` through the edge, and `papaia-net`. REST and the dashboard under `/dashboard`; every request needs the api-key. With direct port access published on `127.0.0.1:QDRANT_EXT_PORT`. |
| `qdrant-mcp` | 8000 | `papaia-net` only. LibreChat calls it with the signed-in user's token. |
| `qdrant-ingest` | 8300 | `papaia-net` only (papaia-manager). REST under `/v1` (static token) and MCP under `/mcp`; it has no web interface. With direct port access published on `127.0.0.1:QDRANT_INGEST_EXT_PORT`. |
| `qdrant-ingest-tika` | 9998 | `papaia-net` only. |

**Enable it** with `papaia-ctl setup`: the wizard asks whether to install the RAG system and, on
yes, for the public URL of Qdrant, pre-filled with `qdrant.<domain>` on the edge
(`<app-host>:6333` with direct port access). Non-interactively:

```bash
tools/papaia-ctl setup -y --rag --qdrant-host=https://qdrant.example.com
tools/papaia-ctl start
```

`--qdrant-host` is optional, `--no-rag` switches the profile off again, and a run without either
flag leaves the choice and the URL as they are. The URL is stored as `QDRANT_PUBLIC_URL` in
`$PAPAIA_CONFIG_DIR/.env` even while the profile is off. With the bundled Nginx Proxy Manager,
`start` also creates a proxy host for it if it is a plain subdomain. The ingester gets no public
name: it has no web interface, and papaia-manager and LibreChat reach it over `papaia-net`. The
secrets are generated by `setup`; `ai/rag/.env` holds them.

`setup` refuses to switch the profile on while the `qdrant`, `qdrant-connect` or `qdrant-ingest`
add-on is active, because both start services of the same names on the same ports. Stop and
deactivate the add-on first (`papaia-ctl addon stop <name> --clean-up`, then `addon remove
<name>`); its volumes are kept.

With the bundled Keycloak, `start` also creates what the module needs in an existing realm: the
resource-server clients `mcp-qdrant` and `mcp-qdrant-ingest` (no login flows), the audience
mappers on the `librechat` client, and the realm roles `qdrant-admin` and `qdrant-ingest-operator`
(both are part of `papaia-admin`). A client that already exists is left as it is; the
`qdrant-ingest-ui` client of an older install is no longer used and can be deleted. With an
external OIDC provider, create the same objects there yourself.

**First steps after the first start**

1. Make the embedding model available in LiteLLM under the name in `RAG_EMBEDDINGS_MODEL`
   (default `nomic-embed-text`). With LocalAI, activate its line in the LocalAI `models.txt`
   ([LocalAI models in LiteLLM](#localai-models-in-litellm)); otherwise add a model in LiteLLM.
   Nothing can be embedded or searched before that. `setup` leaves this step out when the
   rendered LiteLLM configuration already lists the model.
2. Give the people who run ingestion through the MCP tools the `qdrant-ingest-operator` realm
   role. Without it the ingester's MCP tools reject them. `qdrant-admin` is a break-glass role
   for the MCP server's access rules; both are included in `papaia-admin`.
3. Open [papaia-manager](#papaia-manager) and its *RAG* menu (administrators only). It creates the
   connection `default` to the integrated Qdrant itself, and it is where collections and their
   access roles, the embedding of files and the ingest jobs, their runs and the credentials of
   remote sources are managed. The ingester has no web interface of its own.
4. Without the `manager` profile (see [papaia-manager](#papaia-manager) for the hosts it runs on) there is no interface:
   edit the catalog files `jobs.yaml`, `connections.yaml` and `secrets.yaml` in
   `$PAPAIA_CONFIG_DIR/ai/rag/catalog` yourself, as the qdrant-ingest documentation describes.
   Sources of type `local` read `$PAPAIA_CONFIG_DIR/ai/rag/documents` unless `QI_LOCAL_MOUNT`
   points elsewhere.

**Exposure.** The Qdrant port gives whoever holds the api-key full access and bypasses the MCP
server's role checks, so keep `HOST_IP` on a trusted interface. The ingest port is a control
plane: `/v1` takes a static token and `/mcp` takes OIDC. Do not publish it through a reverse proxy.

The three volumes (`qdrant-storage`, `qdrant-ingest-cache`, `qdrant-ingest-state`) belong to the
module `rag`, so `papaia-ctl backup` includes them and `restore --only=module:rag` restores them.

### Outbound mail

The `smtp` profile adds one service, `smtp-relay`, a Postfix relay that every service of the stack
sends its mail through. The relay holds the credentials of your real mail server (your provider's
smarthost) and forwards to it, so Keycloak and the add-ons that attach it talk to `smtp-relay:587`
without a login and without TLS inside the Docker network, and nothing else needs your provider's
password. Without the profile the stack sends no mail.

What you get once it is on: Keycloak's login page offers **Forgot password?**, and
[papaia-manager](#papaia-manager) can email a link when it creates or resets an account. It does
not change who can sign in or how.

**Enable it** with `papaia-ctl setup`: the wizard asks whether to send mail and, on yes, for the
mail server, how to connect (STARTTLS, TLS or none), its port, the login and password and the sender
address. Non-interactively:

```bash
PAPAIA_SMTP_PASSWORD='the-password' \
  tools/papaia-ctl setup -y --smtp --smtp-host=smtp.example.org --smtp-user=mailer \
  --smtp-from=noreply@example.org
```

`--smtp-security` defaults to `starttls` (port 587); `--smtp-security=tls` uses implicit TLS
(port 465). A mail server that needs no login takes `--smtp-no-auth`. Everything but the password
is stored in `infra/smtp-relay/.env` and kept on re-run; leave the password out and the stored one
stays. The `--smtp-*` options store the settings whether the relay is on or off (without `--smtp`
the profile does not change), so the mail server can be prepared first and switched on later. The password is kept in `$PAPAIA_CONFIG_DIR/infra/smtp-relay/upstream-password` (mode 0600)
and is never written to an `.env` file or passed as an argument, so it can contain any
character except line breaks and cannot start or end with a space. `--no-smtp` switches the
profile off and keeps the settings and the password for a later opt-in.

Credentials never go out unencrypted: with `starttls` or `tls` the relay verifies the mail server's
certificate against the system CAs, and `setup` refuses a login together with `--smtp-security=none`.
A mail server with a certificate from a private CA is not supported yet.

**Keycloak.** A new realm is imported with the relay as its mail server and the reset link
switched on. An existing realm is updated by `papaia-ctl start` (or `keycloak-role-sync`) the same
way, once; a mail server somebody configured by hand in the realm is never overwritten, and
`start` says so. Switching the profile off clears the relay from the realm again.

**Senders and recipients.** The relay accepts mail only for the domain of the sender address, and
only from the private ranges Docker hands out. Your provider decides which sender addresses it
accepts: a verified identity, a mailbox, an alias. A mail the provider refuses is returned to the
sender address. The relay also refuses recipients whose domain does not resolve, so accounts with a
made-up address (the seeded `*.lan` ones, say) cannot receive mail.

**One sender for every mail.** Whatever a module or Keycloak writes into `From`, the relay sends
the mail as `<name of the installation> <sender address>` and drops a `Sender` header, so a task
from Flow and a reminder from the assistant arrive from the same sender. The name is `name` in
`$PAPAIA_CONFIG_DIR/overlay/platform/branding.yaml` (the name the interfaces show; `papAIa`
without it; `papaia-ctl settings set branding.name …` writes it); after renaming the
installation, run `papaia-ctl setup` once so the relay takes the new name over. A name with characters beyond letters, digits, spaces, `-`, `_` and `+` is sent
encoded (RFC 2047); `$`, `#`, quotes and backslashes cannot be part of it.

**Text and a link only.** Notifications of the modules are rendered with the mail template of
papaia-kit (`dist/mail/notification.{html,txt}.j2`: subject `<kind>: <title>`, first line
`From <module>`, one link to the object, the module named again in the footer) and carry no content
from integrations. The relay enforces the part it can see: a mail with an attachment, or with a
part that is not text, HTML or an image, is refused with `550 5.7.1` and never queued.

**Delivery is asynchronous.** The relay accepts a message and delivers it from a queue. Keycloak or
papaia-manager reporting that a mail was sent therefore means it reached the relay. If the mail
server is down, the message waits and is retried every five minutes at first, with growing
intervals up to about an hour, and returned to the sender after a day. The queue sits on the
volume `smtp-relay-queue` and survives a restarted relay. To look at it, with the container name
of your project (`papaia-smtp-relay-1` for the default one):

```bash
docker exec papaia-smtp-relay-1 postqueue -p   # list the queue
docker exec papaia-smtp-relay-1 postqueue -f   # try again now
docker logs papaia-smtp-relay-1                # what was delivered, refused, deferred
```

`papaia-ctl doctor` checks the connection to the mail server and reports a waiting queue.

**Add-ons.** `smtp-relay` is attachable: an add-on that lists it under `networks.attach` and
declares `requires.addon_api: 3` can send through it. Any container on a network the relay is
attached to can send mail as the sender domain without a login, so attach it only to add-ons you
trust.

The relay's one volume (`smtp-relay-queue`) belongs to the module `smtp-relay`, so `papaia-ctl
backup` includes it and `restore --only=module:smtp-relay` restores it. The password is in the
configuration backup in plain text, like the other secrets. The design and its limits are in
[ADR 0007](docs/adr/0007-outbound-mail-through-an-internal-relay.md).

### LocalAI models in LiteLLM

LiteLLM is LocalAI's only API client. While the `localai` profile is on, every render adds the
LocalAI models to LiteLLM's `model_list`: a model is registered under its YAML `name` when a model
YAML in `ai/localai/models/` points (`parameters.model`) at the file of an active line in
`ai/localai/models.txt`. A YAML with `embeddings: true` is registered as an embedding model. The
shipped list has every line commented out, so nothing is registered and downloaded until you
activate lines.

Change the list through an overlay copy, not the rendered file, which every render overwrites:

```bash
mkdir -p "$PAPAIA_CONFIG_DIR/overlay/ai/localai"
cp src/ai/localai/models.txt "$PAPAIA_CONFIG_DIR/overlay/ai/localai/models.txt"
# uncomment e.g. the Qwen2.5-1.5B and nomic-embed-text lines, then
tools/papaia-ctl start
docker restart papaia-litellm-1   # the container name of your project
```

`start` renders the new `model_list`, but LiteLLM reads its configuration only when it starts,
and a running LiteLLM is not recreated for a changed configuration file. Restart it after every
change of the list (and after any other edit of the LiteLLM overlay), as above; until then it
lists the models it had.

The shipped YAMLs cover every line of the list. For a model of your own, put its YAML (named
`<name>.yaml` after its `name`, which is how LocalAI finds it on the first request) in
`$PAPAIA_CONFIG_DIR/overlay/ai/localai/models/` and its URL in the overlay `models.txt`. Only
the `*.yaml` files at the top of that directory are used, as the init job copies nothing else;
other files there (a `.yml`, a dotfile) are ignored. Runtime settings such as `context_size`,
`threads` and `f16` are top-level keys of a model YAML; LocalAI ignores them under `parameters`.
An entry of the LiteLLM overlay with the same `model_name` replaces the generated one.

LiteLLM authenticates with `LOCALAI_API_KEY`, which `setup` generates in `ai/localai/.env` and
copies to `ai/litellm/.env`; an existing installation receives it on the next `start`. A key
you change in `ai/localai/.env` reaches LiteLLM only on the next `setup`. The
generated entries name only the variable (`os.environ/LOCALAI_API_KEY`), never the key. A request
with this key has admin rights in LocalAI (it can install and delete models), so keep it out of
other clients.

A model downloads to `<file>.part` and is renamed when it is complete, so an interrupted
download is fetched again on the next `start`.

> **Upgrading:** if you registered a LocalAI model in the LiteLLM Admin UI under one of the
> generated names (`store_model_in_db: true`), LiteLLM now has two deployments for that name and
> splits the traffic between them. Delete the Admin UI entry.

### Voice (local speech)

The `voice` profile adds two internal services: `speaches`, a Whisper server for speech-to-text,
and `chatterbox`, a Chatterbox Multilingual server for text-to-speech. Neither publishes a host
port. LiteLLM fronts both as the models `voice-stt` and `voice-tts`, so any holder of a LiteLLM
key can call `/v1/audio/transcriptions` and `/v1/audio/speech` on the LiteLLM endpoint — an
automation, an agent, your own web app — with spend tracking attached, and LibreChat's speech
panel goes through the same routes. Audio is processed on your host; nothing reaches a cloud
service.

What you get once it is on: a microphone button next to LibreChat's message box, spoken replies,
and transcription of uploaded audio files. Defaults are tuned for German (`languageSTT: de-DE`);
each user can change language, voice and engines under **Settings → Speech**. A semi-automatic
voice conversation works with one keypress per turn (Shift+Alt+L starts the recording; it stops
on silence, sends, and the reply plays back automatically). Spoken replies use the browser's own
voice by default — the local TTS engine is wired up but **opt-in per user** (switch
**Settings → Speech → Text-to-speech engine** to `External`), because on CPU it synthesizes
slower than real time and LibreChat cuts off a playback stream that stalls 15 s. On a host with
an NVIDIA or AMD GPU, install the accelerator image instead (`--voice-variant`, prompted during
setup) — then the local voice is fast enough for live playback and worth making the per-account
default. Calls through the `voice-tts` LiteLLM route are not affected by the playback timeout —
generating audio files from an automation just takes its time.

**Enable it** with `papaia-ctl setup`: the wizard asks whether to install the voice engines.
Non-interactively:

```bash
tools/papaia-ctl setup -y --voice
```

**Requirements and first start.** The TTS model stays resident once loaded — plan roughly
**6 GB of RAM on top** of the stack's baseline (the container is capped by `VOICE_TTS_MEM_LIMIT`,
default 8g). On the first start the models are downloaded from huggingface.co into named volumes
(~1.6 GB Whisper, installed by the one-shot `speaches-model-init` container; ~3.2 GB Chatterbox,
fetched by the server itself — it answers requests only once that is done); later starts are
offline. An interrupted download is resumed on the next start. For an air-gapped installation,
run the first start on a connected network or copy a populated
`speaches-hf-cache` / `chatterbox-hf-cache` volume over. On a CPU-only host, speech-to-text is
fast enough for dictation; text-to-speech lags behind real time, which is why spoken replies
default to the browser engine (see above). With `--voice-variant=nvidia` (CUDA) or `--voice-variant=hipblas`
(ROCm) the TTS engine runs on the GPU through a generated override in
`$PAPAIA_CONFIG_DIR/overrides/` — the same mechanism as the LocalAI accelerator images, with the
same host prerequisites (driver plus, for NVIDIA, the Container Toolkit). Both engines process
one request at a time; they are sized for a handful of users speaking occasionally, not for
parallel transcription jobs.

**The microphone needs a secure context.** Browsers only expose recording on HTTPS pages or on
literally `localhost` — on `http://host.docker.internal:8000` or a plain-HTTP LAN address the
microphone button reports a permission error. Use the HTTPS route of your reverse proxy (or
`http://localhost:<port>` on the host itself).

**Models and voices.** The transcription model (`deepdml/faster-whisper-large-v3-turbo-ct2`, MIT)
is named twice: `VOICE_STT_MODEL` in `ai/voice/.env` tells the init container what to install,
and the LiteLLM route sends the same id per request. Swapping the model (for example for a
German fine-tune, or `Systran/faster-whisper-small` on tight memory) means: set
`VOICE_STT_MODEL`, add a route for the new id under a **new** model name through the LiteLLM
overlay (`$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml` — `model_list` entries merge
additively, so an overlay entry reusing the name `voice-stt` would be load-balanced against
the shipped route, not replace it), and point `speech.stt.openai.model` at the new name
through the LibreChat overlay. The TTS server is configured through
`ai/voice/chatterbox.yaml` (same overlay mechanism). The TTS engine clones whatever reference
voice a request names — accent included — so the module ships two public-domain German
audiobook voices (default `Karlsson.wav`, see `src/ai/voice/voices/README.md` for sources and
how to add your own); the English samples inside the image remain selectable. The engine
watermarks its audio output (Resemble Perth), which makes generated speech identifiable as such.

**Operator note (GDPR).** Voice recordings are personal data. Recorded audio is transcribed and
discarded, but the **transcripts become ordinary chat messages**: they are stored in LibreChat's
MongoDB and indexed by Meilisearch like anything a user types. Add the voice feature to your
records of processing activities and inform your users. Note also that the browser speech
engines (`Browser` STT/TTS in the user settings) use whatever the browser provides — on many
platforms that is a cloud service of the browser vendor, not a local engine.

The engines' volumes hold only re-downloadable model caches; `papaia-ctl backup` includes them
like every named volume. The design, the engine choice and its trade-offs are in
[ADR 0011](docs/adr/0011-local-voice-as-an-optional-core-profile.md).

### GPU acceleration for LocalAI

LocalAI is pinned to the CPU image by default. Upstream publishes one image per accelerator
for every release, and `papaia-ctl setup` picks between them: with the `localai` profile
enabled it probes the host, reports what it found, and asks which image to install.

| Choice | Image tag | Host prerequisites |
|---|---|---|
| CPU | `localai/localai:<version>` | none |
| NVIDIA GPU (CUDA) | `…-gpu-nvidia-cuda-13` / `…-cuda-12` | proprietary driver + [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) |
| AMD GPU (ROCm) | `…-gpu-hipblas` | ROCm kernel driver (provides `/dev/kfd`) |
| Intel GPU (SYCL) | `…-gpu-intel` | none — the backend ships its own driver |
| Vulkan (generic) | `…-gpu-vulkan` | a Vulkan-capable GPU driver |

**The stack installs none of these prerequisites.** Detection reports what the host exposes at
the moment setup runs; every option stays selectable regardless, so you can configure the stack
before installing the driver. Picking an undetected variant prints a warning.

The CUDA major version is taken from the installed driver, so NVIDIA hosts get CUDA 13 on
recent drivers and CUDA 12 on older ones. Non-interactively:

```bash
tools/papaia-ctl setup -y --app-host=https://papaia.example.com --localai-variant=auto
```

`auto` resolves to the best detected variant; a concrete name (`intel`, `hipblas`, …) forces
one. Omitting the flag leaves the current choice untouched.

Only the *variant* is stored, as `LOCALAI_IMAGE_VARIANT` in `$PAPAIA_CONFIG_DIR/.env`. The
LocalAI version stays pinned in `src/ai/localai/docker-compose.yml`, and the accelerator tag is
recomposed from it on every render — so `papaia-ctl upgrade` moves GPU installs forward just
like CPU ones. The image swap and the device passthrough live in a generated
`overrides/docker-compose.localai-gpu.override.yml`; selecting CPU deletes that file again.

Two caveats worth knowing:

- **Intel:** upstream reports hangs with memory-mapped models. Set `mmap: false` in overlay
  copies of the model YAMLs under `$PAPAIA_CONFIG_DIR/overlay/ai/localai/models/`.
- **AMD:** cards ROCm does not target out of the box need `HSA_OVERRIDE_GFX_VERSION` /
  `GPU_TARGETS` in `src/ai/localai/.env` (both are pre-documented there, commented out).

### Native LocalAI on Apple Silicon

Docker Desktop's VM has no access to the Apple GPU, so LocalAI in its container runs on the CPU
(in the default 8 GB VM it cannot even load a 7B model next to the stack). On an Apple Silicon
Mac with Docker Desktop, LocalAI can run as a process on the Mac instead, on the GPU (Metal),
with the same model list and the same [LiteLLM registration](#localai-models-in-litellm). The
decision and the measurements are in
[ADR 0012](docs/adr/0012-serve-local-inference-on-apple-silicon-through-a-native-localai.md).

```bash
tools/papaia-ctl setup -y --app-host=http://localhost --local-ai --localai-runtime=native
tools/papaia-ctl start
```

Interactively, `setup` asks on such a Mac (default *native*). What changes with `native`:

- No `localai` container runs and no LocalAI image is pulled. The init job still downloads
  the models, into `<PAPAIA_WORKSPACE_DIR>/localai/<COMPOSE_PROJECT_NAME>/models`.
- `start` installs the LocalAI release that `src/ai/localai/docker-compose.yml` pins into
  that directory (`bin/`), after checking it against the release's published checksum, and
  writes `run-localai` next to it. After `docker compose up` it runs that script as a
  launchd job of the logged-in user (a LaunchAgent,
  `~/Library/LaunchAgents/de.fidonis.papaia.<COMPOSE_PROJECT_NAME>.localai.plist`) and waits
  up to 60 s for `/readyz`. Nothing is left to start by hand, and LocalAI keeps running after
  the terminal is closed. The first start downloads the Metal backend (internet access
  needed) and can take longer than 60 s: `start` then says so, with the log path, and LocalAI
  keeps starting in the background. After an upgrade that moves the pin, `start` installs the
  new binary and restarts the job. LocalAI reads `LOCALAI_API_KEY` once, when it starts, so
  `start` also restarts the job when the key changed (`setup --force`, a restore); it keeps
  a sha256 fingerprint of the key in `run-localai.key-sha256` for that, never the key. A
  restart that is due stays noted in `run-localai.restart-pending` until launchd has done
  it, so a `start` that ends early (a failed `docker compose up`) does not lose it.
- `stop` unloads and disables the job, so LocalAI stays off after a logout or a restart of
  the Mac until the next `start`. launchd restarts LocalAI when it crashes (not after a clean
  exit), at most every 10 s. `stop --clean-up --volumes --profiles=localai` also deletes
  `models/` and `backends/`; `uninstall` removes the job, the plist, `run-localai` and
  `bin/`, and `uninstall --clean-up` the whole LocalAI directory.
- LocalAI writes its output to
  `<PAPAIA_WORKSPACE_DIR>/localai/<COMPOSE_PROJECT_NAME>/logs/localai.log`.
  `launchctl print gui/$(id -u)/de.fidonis.papaia.<COMPOSE_PROJECT_NAME>.localai` shows the
  job's state, its process and its last exit code.
- macOS may deny a launchd job access to `~/Documents`, `~/Desktop` and `~/Downloads`.
  `setup` warns when the LocalAI directory or the configuration directory (the job reads the
  key from `$PAPAIA_CONFIG_DIR/ai/localai/.env`) lies below one of them; keep the workspace
  (the directory that holds the `papaia` checkout) and `--config-dir` elsewhere.
- The first switch to `native` seeds `$PAPAIA_CONFIG_DIR/overlay/ai/localai/models.txt` with
  Qwen2.5-7B-Instruct (Q5_K_M, 5.4 GB, about 58 tokens/s on an M4 Max) and `nomic-embed-text`.
  Whether the 7B model runs without swapping on a 16 GB Mac next to the stack is not measured
  yet; on a small Mac, activate the 1.5B line of the list instead. An existing overlay list is
  left alone. The first download of 5.4 GB can take an hour or
  more.
- LocalAI listens on `127.0.0.1:<LOCALAI_EXT_PORT>` only, and its web UI is at
  `http://localhost:<LOCALAI_EXT_PORT>` on the Mac. There is no login: the macOS build of
  LocalAI has no user database, so `LOCALAI_API_KEY` (which has admin rights in LocalAI) is the
  only protection. LiteLLM reaches it at `http://host.docker.internal:<LOCALAI_EXT_PORT>/v1`.
- `doctor` reports the process and its launchd job as `localai_native`; `status` no longer
  lists a missing `localai` container.
- The models are not in the backup; `start` downloads them again after a restore.
- `setup --localai-runtime=container` followed by `start` brings the container back and
  removes the override. It works on any host, also on a Mac whose Docker Desktop is not
  running and with a configuration restored on another machine. `setup` unloads and disables
  the launchd job and removes its plist, so the job neither keeps `LOCALAI_EXT_PORT` nor comes
  back at the next login; where `setup` cannot reach launchd (papaia-manager), the next
  `start` on the Mac does it before the container starts. `bin/`, `run-localai` and the
  models stay for a later switch back (`uninstall` removes them). The seeded model list
  stays, and models in the old `localai-models` volume are not moved in either direction.
- An interactive `setup` on a host that can never run the native process (no Apple Silicon or
  another Docker engine) switches a stored `native` back to `container` and says why. On a Mac
  whose Docker Desktop does not answer it asks instead, with `native` as the default. `setup -y`
  keeps `native` in both cases and warns.

When papaia-manager runs `start` or `stop` from its container, only the Compose part runs:
the launchd job belongs to the user logged in on the Mac, and the manager skips it with a
warning. Run `tools/papaia-ctl start` or `stop` on the Mac for LocalAI.

**Other servers on the host.** Any OpenAI-compatible server on the Mac (LM Studio,
`mlx_lm.server`, Ollama) can serve papAIa the same way, by hand: add an entry to the LiteLLM
overlay with `api_base: http://host.docker.internal:<port>/v1`. Such a server is outside
`papaia-ctl` (`start`, `stop`, `status`, `doctor`, `backup`) and outside the login; LiteLLM's
keys and teams are its access control. On Docker Engine, where `host.docker.internal` does not
resolve in the LiteLLM container, use the gateway address of `papaia-net`
(`docker network inspect papaia-net --format '{{(index .IPAM.Config 0).Gateway}}'`).

### Distributed installations

> The distributed mode has been validated by hand on a two-node split with a firewall
> between the nodes; the [two-node validation](docs/distributed-validation.md) describes the run that is recorded
> on its tracking issue. Mind the [limits](docs/distributed.md#limits) that hold by design.

papAIa can run on several machines: for example Nginx Proxy Manager, Keycloak, the mail relay
and LiteLLM on an edge node in a DMZ, and LibreChat, the RAG system, LocalAI and papaia-manager
behind it. Every service keeps its address on every node (`keycloak:8443`, `litellm:4000`). A
link gateway on each node carries the connections between nodes over mutual TLS, and the
controller (the machine `papaia-ctl` runs on) reaches the other nodes over SSH through a
forced command that accepts a short list of verbs.

A distributed installation is set up as a new installation (see [`setup`](#setup)), runs with
the same commands (`start`, `stop`, `status`, `doctor`, `backup`, `restore`, `upgrade`,
`addon`), and adds [`topology`](#topology) and [`node`](#node). The operator guide covers
planning, the firewall, backups, upgrades, add-ons, the security notes and recovery:
[docs/distributed.md](docs/distributed.md).

### Image pinning and signatures

Every image in the compose files is pinned as `name:tag@sha256:<digest>`: a tag alone can be
moved to other content, a digest cannot. A test (`tools/tests/test_images.py`) refuses an image
without tag or digest, `latest`, a development tag such as `dev` or a branch name. An image
whose upstream keeps no tag for the pinned build may stay digest-only through an entry in
[`compat/image-exceptions.yaml`](compat/image-exceptions.yaml), with a reason and an expiry of
at most 90 days. The sidecar image of `backup` is pinned the same way.

**Own images of the core.** Services that run code of this repository (`papaia-egress`,
`papaia-lifecycle`, `papaia-audit`, `papaia-people`, `papaia-docker-gate`) run it from images built here, `ghcr.io/fidonis/papaia-<service>`, listed
in [`compat/own-images.yaml`](compat/own-images.yaml) and pinned with the core `VERSION` as
tag. `tools/build-images` builds them for linux/amd64 and linux/arm64 (reproducibly: the same
inputs give the same digest), signs them, pins the digests and prints their entries for the
bill of materials; they pass the check below only when listed and signed, like every other
image (see [`docs/compatibility.md`](docs/compatibility.md#own-images-of-the-core)).

**Check before `start` and `upgrade`.** Before any container starts, `papaia-ctl` lists the
images Compose is about to run (with the active profiles and the same override files `up`
gets) and checks each one:

1. It is listed, with the same digest, in the signed suite bill of materials of the
   checkout, `compat/suite-<VERSION>.yaml` with `compat/suite-<VERSION>.yaml.sig` (see
   [`docs/compatibility.md`](docs/compatibility.md)). The bill of materials is trusted only
   through the release key pinned in the checkout, `compat/release-key.pub`; it must have the
   scope `delivery` and the version in `VERSION`, so an older or a test bill of materials is
   refused.
2. It carries a valid cosign signature (`cosign sign --key`, cosign 2.x) by the key of that
   bill of materials. The signature is read from the repository the release names in
   [`compat/image-signatures.yaml`](compat/image-signatures.yaml) (cosign's
   `COSIGN_REPOSITORY`; tag `sha256-<digest>.sig`) and checked with `openssl`; no cosign
   binary is needed on the host.

Any mismatch aborts with the image and the reason, for example `digest differs from the bill
of materials` or `no signature`, and no container is started. Without
`compat/release-key.pub` or without the bill of materials the check refuses: images are
never checked against a key taken from the file it vouches for.

**Upgrade: the installed release vouches for the next one.** `upgrade` checks every image
the target release pins before it backs up, stops or moves anything. The target's bill of
materials must be signed with the release key of the *installed* checkout. A release that
changes the key ships `compat/release-key-rotation.yaml`, a signature by the previous key
over the new `compat/release-key.pub` (`cosign sign-blob --key <previous key>
compat/release-key.pub`); without it a target with another key is refused, however
consistent its own files are. The images of the active add-ons are checked in the same step, against the target's bill
of materials. An installation without a pinned release key cannot upgrade without
`--insecure-images`. The checkout is then moved to exactly the commit that was checked, and
the second phase checks what it starts against the same anchor. The first upgrade from a
core that pinned no release key is the exception: its first phase hands no anchor over, so
the second phase checks against the target's own key and prints that key's fingerprint;
compare it with the published one, obtained out of band (see
[`docs/compatibility.md`](docs/compatibility.md#bootstrap-the-first-upgrade-to-a-pinned-key)).

**Registry access.** The signatures are read with the host's Docker credentials when there
are any (`docker login`, credential helpers); anonymously otherwise. A signature verified
once is remembered per release key and digest in `$PAPAIA_CONFIG_DIR/cache/` (mode `0600`),
so a repeated `start` does not ask the registry again; the bill of materials is checked every
time. A rate limit (HTTP 429), a server error or no connection is reported as "registry not
reachable": `start` and `upgrade` refuse, `doctor` warns. Docker Hub limits anonymous pulls
tightly; log in on the host if the check runs into the limit.

**`--insecure-images`** skips the check for this one command (`start`, `upgrade`, `restore`,
`addon install`, `addon start`, `addon upgrade`, `addon rollback`). It prints a banner and writes one `papaia.audit/1` row (event
`image_verification_skipped`, the command and the number of images; no image content) to
`$PAPAIA_CONFIG_DIR/audit/papaia-ctl.jsonl` (mode `0600`). The flag is not stored anywhere:
the next command checks again. `upgrade --insecure-images` writes two such rows, one when it
skips the check of the target and one when its second phase starts the stack; both carry the
same correlation id.

**Mirror registry.** `PAPAIA_IMAGE_MIRROR` in the root `.env` (for example
`registry.example.com/papaia/`, ending in `/`) pulls every core image through a mirror. The
render writes `overrides/docker-compose.image-mirror.override.yml`, which puts the prefix in
front of each pinned reference, for example
`registry.example.com/papaia/quay.io/keycloak/keycloak:26.7.0@sha256:…`. The mirror must hold
each image under that path and the signature repository under the same prefix
(`registry.example.com/papaia/ghcr.io/fidonis/papaia-signatures`); the digests stay the same,
so the check above still applies. `PAPAIA_IMAGE_SIGNATURES` overrides the signature
repository for a mirror that keeps the signatures elsewhere.

**Add-on images.** The images of an add-on are checked the same way before it starts:
`start --addons` checks the core and every active add-on in one pass before the first
container, `upgrade` checks the active add-ons with the target before anything changes, and
`addon start`, `addon upgrade`, `addon rollback` and a scoped `restore` check the add-on they
start. Each add-on is checked with the `.env` its containers start with: the one in
`$PAPAIA_CONFIG_DIR/addons/<name>/`, which `start` copies into the add-on directory before the
check and a node uses for its add-ons, so an image variable set there is the one checked.
`addon install` checks the add-on's images before it is registered. A listed image
with another digest, or without a valid signature, is refused. So is an image of a
repository the bill of materials lists under another tag, or untagged with a digest it does
not list: a repository of the delivery is never accepted from elsewhere.

An add-on whose image repositories the bill of materials does not list at all (one that is
not part of the delivery) is refused with its origin, the image digests, the operations it
declares with their effect and the networks it asks for. `addon install
--accept-unlisted-images` accepts exactly those digests for that add-on: once the add-on is
registered (a failed install accepts nothing) they are recorded in
`$PAPAIA_CONFIG_DIR/trust/accepted-images.json` (mode `0600`) with a `papaia.audit/1` row
(event `addon_images_accepted`). An acceptance covers only the add-on it was given for, never
another add-on or the core; another digest of that add-on is refused again, and an image
without a digest cannot be accepted. `addon uninstall` drops the acceptance (event
`addon_images_forgotten`); if the file cannot be read, the add-on is still uninstalled and a
warning names the file to repair.

**Who confirms.** Running `papaia-ctl` on the host is the `papaia-admin` role of the
installation: whoever may run it can start, stop and restore the whole stack. The
confirmation `--accept-unlisted-images` is therefore the `papaia-admin` confirmation, and the
audit row records it as `"role": "papaia-admin"` with the host login in `confirmed_by` (the
user behind `sudo` when there is one).

**At run time** `doctor` reports `image_signatures`: every running core container must run an
image that passes the same check, and the image it runs must have the pinned digest.

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
Moving to a newer release is `tools/papaia-ctl upgrade`; the config directory and everything
under `overlay/` survive untouched. To see what is running and whether the host is in shape,
use [`status`](#status) and [`doctor`](#doctor).

These are the same commands Fidonis runs when it operates an installation on a customer's
behalf. There is no separate operator edition and no privileged tooling behind the
published path — anything an operator can do to a papAIa installation is in this README.

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
│   │   ├── papaia-ctl          # Bash dispatcher (setup · start · stop · upgrade · status · doctor · addon · …)
│   │   ├── deployment.template.yaml  # deployment.yaml template
│   │   ├── pyproject.toml      # ruff + pytest config for tools/lib
│   │   ├── lib/                # Python: cli.py · cli_addon.py · deployment.py · envtree.py
│   │   │                       #   secrets.py · resolve.py · addons.py · defaults.py · reporting.py
│   │   │                       #   compat.py · semver.py · render_core.py · gen_override.py
│   │   │                       #   backup.py · upgrade.py · migrations.py · common.py
│   │   │                       #   status.py · doctor.py
│   │   │                       #   distributed: topology.py · link.py · cluster.py · cluster_data.py
│   │   │                       #   nodes.py · executor.py · node_shell.py · cli_node.py
│   │   │   └── sh/             # Bash command libraries sourced by papaia-ctl
│   │   ├── schemas/            # JSON Schemas of `status --json` and `doctor --json`
│   │   ├── migrations/         # release migrations run by `papaia-ctl upgrade`
│   │   └── tests/              # pytest suite
│   ├── src/
│   │   ├── docker-compose.yml  # root compose — shared network + include list only
│   │   ├── .env.example        # all stack-wide variables (source of truth)
│   │   ├── infra/              # keycloak · nginx · oauth2-proxy · smtp-relay (optional, profile: smtp)
│   │   │                       # link-gateway (distributed installations only, not in the include list)
│   │   │                       # me (optional, profile: me) · connections (optional, profile: connections)
│   │   ├── ai/                 # librechat · litellm · localai · mcp-firecrawl · jinaai · rag
│   │   ├── manager/            # papaia-manager (optional, profile: manager)
│   │   └── services/           # searxng · firecrawl
│   └── docs/
│       ├── architecture.md               # full architecture specification
│       ├── configuration.md
│       ├── deployment.md
│       ├── troubleshooting.md
│       ├── distributed.md      # running on several machines
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
- [`docs/compatibility.md`](docs/compatibility.md) — Compatibility matrix of core, manager and modules; signed suite bill of materials and `papaia-ctl suite verify`.
- [`docs/deployment.md`](docs/deployment.md) — Deployment guide and operations.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — Common failure modes.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — How to contribute.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Expected behavior and how to report a violation.
- [`CHANGELOG.md`](CHANGELOG.md) — Release history.

---

## About Fidonis

papAIa is developed and maintained by **[Fidonis GmbH](https://www.fidonis.de)**.

Fidonis stands for technological sovereignty: bringing local, modular AI to mid-sized
companies — dependable, secure, and vendor-independent. papAIa is how that looks in
practice. Every component runs on infrastructure the customer controls, the model layer is
replaceable without touching anything above it, and the whole stack can be taken over,
audited, or moved elsewhere without asking anyone's permission.

Fidonis operates papAIa for customers who would rather not run it themselves, and builds
the first-party add-ons and the custom integrations that connect it to a company's existing
systems. Either way it is the same artifact from this repository — the difference is who
runs it, not what is installed.

The stack is MIT-licensed and free to use, extend and self-host, with or without Fidonis.
See [LICENSE](LICENSE) for the code and [TRADEMARK.md](TRADEMARK.md) for the rules covering
the papAIa and Fidonis names.

**[www.fidonis.de](https://www.fidonis.de)**
