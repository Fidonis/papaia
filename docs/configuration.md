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

Configuration files such as `librechat.yaml` are changed through the customer overlay in
`$PAPAIA_CONFIG_DIR/overlay/` ([architecture, section 13](./architecture.md#13-customer-overlay--3rd-render-layer)).
A worked example is [Parallel Search MCP in LibreChat](./parallel-search-mcp.md), an opt-in
hosted web search.

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
| `PAPAIA_PROJECT` | Mirrors `COMPOSE_PROJECT_NAME` under a key Compose does not special-case; scopes add-on Seam-1 networks per deployment (`${PAPAIA_PROJECT:-papaia}-<addon>-net`) |
| `PAPAIA_CONFIG_DIR` | Absolute host path holding all generated state and operator-editable config |
| `PAPAIA_WORKSPACE_DIR` | Parent directory containing the papaia checkout and add-ons, stamped by setup |
| `PAPAIA_BACKUP_DIR` | Directory `papaia-ctl backup` writes to; derived by setup as `$PAPAIA_WORKSPACE_DIR/backup` unless `--backup-dir` was passed. A backup only runs once the directory was confirmed with `papaia-ctl backup target init`. It must exist before `start`: the audit store keeps its signed chain heads in `audit-heads/` there |
| `PAPAIA_AUDIT_RETENTION_MONTHS` | Months the audit store keeps events, 6 to 36, default 12 ([audit.md](audit.md#retention)) |
| `PAPAIA_AUDIT_SIEM_TARGET`, `_PEN`, `_IDENTITY`, `_BASIS` | SIEM export of the audit store; empty target: none ([audit.md](audit.md#siem)) |
| `PAPAIA_RECERTIFICATION_DAYS` | Optional. Days after which a confirmed row of the permission report is due again, 30 to 730, default 180 ([permission-report.md](permission-report.md#recertification)) |
| `PAPAIA_BACKUP_RECIPIENTS` | Public age keys every backup archive is encrypted to (`NAME:age1...`, comma-separated); empty means `backup` refuses to run. Set with `papaia-ctl backup keys generate` or `backup recipients add` |
| `UID` / `GID` | Host ownership for bind-mounted files (Linux only) |
| `HOST_IP` | Bind address of the edge ports and, with direct port access, of the core ports — the network layer |
| `INGRESS_HTTP_EXT_PORT` / `INGRESS_HTTPS_EXT_PORT` | Host ports of the edge proxy (`internal_nginx`), default 80/443; bound to `HOST_IP` |
| `INGRESS_HOST_IP` | Bind address of the edge ports only; empty falls back to `HOST_IP`. Set per node of a distributed installation |
| `INGRESS_DOMAIN` | Domain of the web interfaces (`<name>.<domain>`) when it differs from the one of `PAPAIA_HOST`; empty for a local installation, which uses `<name>.<env>.papaia.localhost` |
| `INGRESS_APP_DOMAIN` | Second domain of the app host (host key `apps`), a site of its own; locally `<env>.papaia-apps.localhost` |
| `INGRESS_HOST_<KEY>` | Renames an interface's host key to another single DNS label |
| `PAPAIA_HOST` | Public base URL of the server — the application layer |
| `AUTH_HOST` | Public Keycloak URL; ends up in token `iss` claims |
| `AUTH_PROVIDER` | `internal_keycloak` or `external_oidc` |
| `OIDC_ISSUER` | Issuer URL used for token validation |
| `OIDC_SCOPES` | Scopes requested by the oauth2-proxy sidecars |
| `OIDC_AUTH_URL` | Browser-facing login redirect |
| `OIDC_TOKEN_URL` | Server-side token exchange (internal Docker DNS) |
| `OIDC_JWKS_URL` | Server-side JWKS fetch (internal Docker DNS) |
| `OAUTH2_PROXY_EXT_PORT` | Host port of the standalone forward-auth proxy with direct port access only |
| `OAUTH2_PROXY_PUBLIC_URL` | Browser-facing URL of the forward-auth proxy (its sign-in callback), derived by setup: `oauth2.<domain>` on the edge and behind an external proxy (no port), `PAPAIA_HOST:OAUTH2_PROXY_EXT_PORT` with direct port access only; a value set by hand is kept in every mode |
| `OAUTH2_PROXY_CLIENT_ID` | OIDC client ID shared by all three sidecars |
| `OAUTH2_PROXY_CLIENT_SECRET` | Matching client secret (generated) |
| `OAUTH2_PROXY_COOKIE_SECRET` | Session cookie key, 32 bytes base64 (generated) |
| `OAUTH2_PROXY_COOKIE_SECURE` | Re-derived every run from the `PAPAIA_HOST` scheme |
| `REVERSE_PROXY_PROVIDER` | `internal_nginx`, `external_proxy` or `no_proxy` |
| `*_EXT_PORT` | Host ports of the core services with direct port access only (`no_proxy` or `--allow-direct-port-access`, written to the generated `overrides/docker-compose.direct-ports.override.yml`); behind the edge no core service publishes a port |
| `LOCALAI_PUBLIC_URL` | Browser-facing LocalAI URL, derived by setup |
| `LOCALAI_IMAGE_VARIANT` | LocalAI accelerator image chosen during setup (`cpu`, `nvidia-cuda-12`, `nvidia-cuda-13`, `intel`, `hipblas`, `vulkan`); drives the generated GPU override |
| `PAPAIA_DEFAULT_MODEL` | Model the aliases `papaia-chat` and `papaia-structured` map onto (a `model_name` of LiteLLM's model list). `setup --local-ai` names the shipped default model when it is empty (`qwen2.5-7b-instruct-q4`, or `qwen2.5-7b-instruct-q8` with an accelerator variant), and the render adds its download to LocalAI's list; `--no-local-ai` drops a shipped default. See [model gateway](./model-gateway.md) |
| `PAPAIA_DEFAULT_EMBED_MODEL` | Model the alias `papaia-embed` maps onto (an embedding model); empty means no `papaia-embed` |
| `LOCALAI_RUNTIME` | Where LocalAI runs: `container` (default) or `native`, a process on an Apple Silicon Mac with Docker Desktop (ADR 0012); drives the generated runtime override |
| `VOICE_TTS_IMAGE_VARIANT` | Voice TTS accelerator image chosen during setup (`cpu`, `nvidia`, `hipblas`; set via `setup --voice-variant`); drives the generated GPU override, which only materializes while the `voice` profile is active — the image pins live in `src/ai/voice/docker-compose.yml` |
| `NPM_ADMIN_HOST` | Public URL of the Nginx Proxy Manager admin UI |
| `MANAGER_EXT_PORT` | Host port of the manager (profile `manager`) with direct port access only |
| `MANAGER_PUBLIC_URL` | Browser-facing papaia-manager URL, derived by setup — interpolated as `MANAGER_HOST` in `src/manager/docker-compose.yml` |
| `ME_PUBLIC_URL` | Browser-facing URL of Mein Bereich (`me-web`, profile `me`), derived by setup as `me.<domain>` on the edge and behind an external proxy; never a port address, since `me-web` publishes no port ([ADR 0020](adr/0020-mein-bereich-and-the-preference-store-as-core-profile.md)); its overview is the entry page: the main address `https://<domain>/` redirects there (bundled proxy; `papaia-ctl proxy list` names the redirect for an external proxy; [Anmeldung und Einstieg](de/betrieb/anmeldung-und-einstieg.md)); the profile's own settings are under [Mein Bereich variables](#mein-bereich-variables) |
| `QDRANT_EXT_PORT` | Host port of the Qdrant REST API and dashboard (profile `rag`) with direct port access only, on `127.0.0.1` |
| `QDRANT_PUBLIC_URL` | Browser-facing Qdrant URL — the dashboard lives under `/dashboard` |
| `QDRANT_INGEST_EXT_PORT` | Host port of the ingester's REST API and MCP endpoint (profile `rag`) with direct port access only, on `127.0.0.1`; the ingester has no web interface, papaia-manager manages it |

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
| `MANAGER_IDENTITY_ADMIN_ROLE` | Realm role that may manage the realm's users and roles (the Users page); `papaia-admin` by default, which carries Keycloak's user and role administration rights ([ADR 0006](adr/0006-manage-accounts-with-the-signed-in-users-token.md)) |
| `MANAGER_DEFAULT_LOCALE` | Optional. Language of the interface for an account that has not chosen one and whose browser asks for none the manager ships (`de`, `en`); anything else means `en`. Every account picks its own language in the account menu |
| `LITELLM_URL` | Optional. Where the manager reaches LiteLLM's HTTP API for the Models & Usage page (default `http://litellm:4000`, on the stack network). The page only reads; the master key is read from `ai/litellm/.env` at request time and is not a setting |
| `KNOWLEDGE_MAP_URL` | Optional. Where the manager reaches the admin API of the knowledge-map server for the AI map page (default `http://knowledge-map-mcp:8200`, on the stack network). Its bearer `KM_ADMIN_TOKEN` is read from `ai/knowledge-map/.env` at request time and is not a setting |
| `LOG_LEVEL` | Manager application log level |

## RAG variables

`src/ai/rag/.env` (profile `rag`). The host ports of the two published services and the
public Qdrant URL are root variables, see above. `qdrant` and `qdrant-mcp` take their values only
through `environment:`; `qdrant-ingest` additionally receives the whole file through
`env_file:` (path 2), because operators may append `QI_SECRET_<NAME>` keys for their own
sources. A key that `qdrant-ingest` already gets from its `environment:` block therefore
must not be set in this file.

| Variable | Purpose |
|---|---|
| `QDRANT_JWT_SECRET` | Qdrant's api-key and the signing secret of the per-request tokens `qdrant-mcp` derives (generated). papaia-manager stores it, encrypted, as the api-key of the connection `default` to `http://qdrant:6333`. |
| `QDRANT_MCP_EMBEDDING_API_KEY`, `QI_EMBEDDING_API_KEY` | LiteLLM key for embedding calls, synced from `LITELLM_MASTER_KEY` during setup |
| `QI_API_TOKEN` | Static bearer token of the ingester's REST API (generated); papaia-manager uses it to start and follow runs |
| `QI_CONNECTIONS_SECRET` | Encrypts the Qdrant api-keys stored in `connections.yaml` and the source credentials stored in `secrets.yaml` (generated) |
| `QDRANT_MCP_OIDC_JWKS_CACHE_TTL`, `QDRANT_MCP_QDRANT_JWT_TTL`, `QDRANT_MCP_RBAC_ACL_CACHE_TTL`, `QDRANT_MCP_RBAC_SERVICE_TOKEN_TTL`, `QDRANT_MCP_LOG_LEVEL` | Optional tuning of `qdrant-mcp`, commented out with their defaults |
| `EMBEDDING_META_COLLECTION`, `RBAC_ACL_COLLECTION` | Names of the metadata and the ACL collection, commented out with their defaults `_collection_meta` and `_rbac_acl`. One key each reaches both `qdrant-mcp` and `qdrant-ingest` (as `QI_EMBED_META_COLLECTION` and `QI_RBAC_ACL_COLLECTION`, which are set by the compose file and therefore not to be set here). Renaming on an installation with data moves nothing, see [`src/ai/README.md`](../src/ai/README.md#renaming-the-system-collections). |
| `QI_OIDC_OPERATOR_ROLE` | Not configurable: fixed to `qdrant-ingest-operator` in the compose file, because the realm template, `keycloak_role_sync` and the `papaia-admin` composite name that role |
| `QI_LOCAL_MOUNT`, `QI_TIKA_HEAP` | Document directory for local sources and the Tika heap, interpolated in the compose file |
| `QI_*` | Every other ingester setting (scheduling, extraction, embedding batches, metrics) is read straight from this file; the list is in the `qdrant-ingest` repository's `docs/operations.md` |

## Voice variables

`src/ai/voice/.env` (profile `voice`). All services take their values only through
`environment:` interpolation (path 1), so a profile switched on by hand before `setup` has
run still starts — but not usably: `VOICE_API_KEY` has no inline default, and with an empty
key the STT engine treats the empty string as the required bearer key and refuses every
request (the TTS engine never authenticates at all, see ADR 0011). The STT healthcheck fails
on the missing key on purpose — an engine that can serve nobody must show up as unhealthy,
not as fine — so run `setup` to seed the key. The TTS server is configured through the
rendered `ai/voice/chatterbox.yaml`, not through variables, and the accelerator image choice
(`VOICE_TTS_IMAGE_VARIANT`) lives in the root `.env` above, not here.

| Variable | Purpose |
|---|---|
| `VOICE_API_KEY` | Bearer key the STT engine requires on every request (generated); synced to `ai/litellm/.env`, where the LiteLLM route reads it as `os.environ/VOICE_API_KEY` |
| `VOICE_STT_MODEL` | The faster-whisper model the init container installs, commented out with its default. Must stay equal to the id the LiteLLM route `voice-stt` sends (overlay on `ai/litellm/config.yaml`) |
| `VOICE_STT_COMPUTE_TYPE` | faster-whisper quantization, commented out with its default `int8` |
| `VOICE_STT_CPU_THREADS` | CPU threads for transcription; `0` (default) uses all cores — cap it on a host that shares cores with LLM inference |
| `VOICE_STT_MODEL_TTL` | Seconds an idle model stays loaded (default 300; `-1` never unloads) |
| `VOICE_STT_LOG_LEVEL` | One of debug, info, warning, error (default `info`) |
| `VOICE_STT_HEALTHCHECK_START_PERIOD`, `VOICE_TTS_HEALTHCHECK_START_PERIOD` | Grace periods before the containers count as unhealthy; raise the TTS one on a slow line (first start downloads ~3.2 GB) |
| `VOICE_TTS_MEM_LIMIT` | Hard memory ceiling of the TTS container (default `8g`); the loaded model stays resident at ~4-6 GB |

## Mail relay variables

`src/infra/smtp-relay/.env` (profile `smtp`), written by `papaia-ctl setup --smtp` and kept on
every re-run. The compose file reads every key through `${VAR}` interpolation (path 1) and has a
default for each, so a profile switched on by hand before `setup` has run starts a relay that
cannot deliver anywhere and sends nothing. An empty `SMTP_RELAY_UPSTREAM_HOST` means "not
configured".

| Variable | Purpose |
|---|---|
| `SMTP_RELAY_UPSTREAM_HOST`, `SMTP_RELAY_UPSTREAM_PORT` | The mail server the relay forwards to: host name or IPv4 address, and its port (587 for `starttls`, 465 for `tls`, 25 for `none`) |
| `SMTP_RELAY_UPSTREAM_SECURITY` | `starttls`, `tls` (implicit TLS) or `none`. The first two verify the server's certificate against the system CAs; `none` allows no login |
| `SMTP_RELAY_UPSTREAM_USER` | Login at the mail server. Empty: the server needs none |
| `SMTP_RELAY_FROM_ADDRESS` | The address the mails are sent from. Keycloak's `from` |
| `SMTP_RELAY_FROM_NAME`, `SMTP_RELAY_FROM_HEADER` | Derived by setup from the name of the installation (`name` in `overlay/platform/branding.yaml`) and the sender address — do not edit. The name is Keycloak's `fromDisplayName`; the header is the `From` the relay writes into every mail |
| `SMTP_RELAY_SENDER_DOMAINS`, `SMTP_RELAY_TLS_LEVEL`, `SMTP_RELAY_TLS_WRAPPER` | Derived by setup from the sender address and the security mode — do not edit |
| `SMTP_RELAY_PASSWORD_REV` | Raised by setup whenever the password changes, so that Compose recreates the relay (it reads the password file once, at start) |
| `SMTP_RELAY_ALLOWED_CLIENTS` | Optional, commented out. The networks allowed to send, comma separated; the default is the private IPv4 ranges Docker hands out |

The upstream password is not a variable. `setup` keeps it in
`$PAPAIA_CONFIG_DIR/infra/smtp-relay/upstream-password` (mode 0600, empty when the mail server
needs no login) and the relay mounts that file read-only. An `.env` file is written without
quotes and Compose reads `$` and ` #` in it, so a password stored there would not survive; a file
keeps it byte for byte. A non-interactive `setup` takes it from the environment variable
`PAPAIA_SMTP_PASSWORD`, which is not a stack variable and is removed from the process environment
as soon as it has been read.

## Mein Bereich variables

`src/infra/me/.env` (profile `me`, [ADR 0020](adr/0020-mein-bereich-and-the-preference-store-as-core-profile.md)).
The profile has no `setup` option: it is on while `me` is in `COMPOSE_PROFILES` (see
[Mein Bereich in the README](../README.md#mein-bereich-me)). The compose file reads every key
through `${VAR}` interpolation (path 1); `python -m lib.me_profile check` keeps this file, the
compose file and the variables the image reads in step. The browser address is
`ME_PUBLIC_URL` in the root `.env` (above).

| Variable | Purpose |
|---|---|
| `ME_OIDC_CLIENT_SECRET` | Generated. Secret of the confidential client `papaia-me`, which signs the person in and exchanges the person's token per module |
| `ME_SESSION_SECRET` | Generated. Signing key of the session cookie, at least 32 bytes |
| `PREFS_DB_PASSWORD` | Generated. Password of `prefs-db`; it reaches `prefs` and `prefs-db` as a secret file under `/run/secrets`, never as a variable of either service |
| `ME_OIDC_LOGOUT_URL`, `ME_OIDC_INTERNAL_ISSUER` | Sign-in details beyond the shared `OIDC_*` variables. Empty: derived from the issuer (end-session endpoint, back channel on the issuer itself) |
| `ME_OIDC_SCOPE` | Scopes of the sign-in (default `openid profile`) |
| `ME_ACCOUNT_URL` | Account console of the sign-in service. Empty: `<issuer>/account` |
| `ME_SECURITY_PROFILE` | Empty follows `PAPAIA_SECURITY_PROFILE`; `kritis` turns off plain-http module calls of the area even under `standard`. Stricter than the platform only |
| `ME_MODULE_TIMEOUT` | Seconds after which a module that does not answer is shown as unreachable (default 2) |
| `ME_EXPORT_TIMEOUT`, `ME_EXPORT_MAX_BYTES` | Time limit in seconds and size limit in bytes of one module's part of an export (defaults 10 and 16777216) |
| `ME_MODULE_PORT` | Port of a module's API when its declaration names none (default 8080) |
| `ME_DEFAULT_LANG` | Language of the area for a person without a saved language: `de` or `en` (default `de`) |
| `ME_INSTALLATION_NAME` | Name of the installation in page titles while the catalog carries no branding, at most 60 characters. Empty: the name the image ships |
| `PREFS_DEFAULT_TIME_ZONE` | Time zone of a person who never saved one (default `Europe/Berlin`) |
| `PREFS_DEFAULT_CHANNEL` | Notification channel of a person who never saved one: `mail` or `chat_window` (default `mail`) |
| `PREFS_LANG` | Language of the store's messages: `de` or `en` (default `de`) |

The volume `prefs-pgdata` belongs to the module `me` in a backup
(`papaia-ctl restore --only=module:me`).

## Connection registry variables

`src/infra/connections/.env` (profile `connections`, [ADR 0021](adr/0021-connection-registry-as-a-core-profile.md)),
written by `papaia-ctl setup --connections`. The profile is off on a fresh install. How to enable,
address and disable it: [Connection registry in the README](../README.md#connection-registry-connections). The compose
file reads every key through `${VAR}` interpolation (path 1).

| Variable | Purpose |
|---|---|
| `CONNECTIONS_OWNER_DB_PASSWORD` | Generated. The owner of the schema; only the one-shot container `connections-migrate` uses it |
| `CONNECTIONS_SERVICE_DB_PASSWORD` | Generated. The registry's own login, with data rights only. Both passwords reach the database as secret files; a new value locks the registry out of its database |
| `CONNECTIONS_PERSON_CLIENTS`, `CONNECTIONS_SERVICE_CLIENTS`, `CONNECTIONS_DELEGATE_CLIENTS` | The OIDC clients whose tokens the registry accepts: as a person, as a service account (`client=service`), or as a gate with the person's own token. Empty in the core; a module that uses the registry names its entries |
| `CONNECTIONS_MANDATE_DAYS` | Days after which a mandate ends unless the person is active. Empty: the registry's default |
| `CONNECTIONS_PERSON_TOKEN_SERVICES` | Services that never use an account without the person's own token |
| `CONNECTIONS_USE_PERSONS_PER_HOUR` | Brake: a service asking for credentials of more persons within an hour is held until an administrator releases it (default 500, 0 = off) |
| `CONNECTIONS_PROFILE` | `standard` or `kritis`. Empty: `PAPAIA_SECURITY_PROFILE`. It may be stricter than the platform, never weaker |
| `CONNECTIONS_TLS_CLIENT_CA` | The CA whose client certificates every caller needs (default: the platform CA). Empty allows one-sided TLS; `kritis` refuses that |
| `CONNECTIONS_KEY_PROVIDER` | `file` (key files in the volume `connections-keys`, default; refused under `kritis`), `openbao` or `pkcs11`, with the `CONNECTIONS_OPENBAO_*` and `CONNECTIONS_PKCS11_*` settings |

The volumes `connections-db` and `connections-keys` belong to the module `connections` in a
backup and are restored together (`papaia-ctl restore --only=module:connections`); a database
without its keys cannot be read. `papaia-ctl secrets rotate connections/credentials` makes a new
master key active in the running registry and seals every stored credential again; it writes one
`papaia.audit/1` row.

## Egress variables

Root `.env`, read by `papaia-ctl` when it renders `$PAPAIA_CONFIG_DIR/infra/egress/egress.json`
for the single exit `papaia-egress` (profile `egress`, always on; [egress.md](egress.md)). Both
are empty by default: the exit connects directly.

| Variable | Purpose |
|---|---|
| `PAPAIA_EGRESS_UPSTREAM_PROXY` | Corporate proxy behind the exit, `http://host:port` or `http://user@host:port`. A URL with a password, another scheme or no port stops the render |
| `PAPAIA_EGRESS_NO_PROXY` | Comma-separated host names (with their subdomains) the exit reaches directly although a corporate proxy is set |

The password of the proxy user is not a variable: it goes into
`$PAPAIA_CONFIG_DIR/infra/egress/upstream-proxy-password` with mode 0600, which the render
checks. The allow lists come from the add-on manifests (`networks.egress`), the protected
hosts from `$PAPAIA_CONFIG_DIR/security/protected-hosts.yaml` and the internal ranges an
add-on may reach from `$PAPAIA_CONFIG_DIR/security/egress-internal-targets.yaml`.

## SQL uplink variable

Root `.env`, read by `papaia-ctl` when a SQL source is configured ([network.md](network.md)).

| Variable | Purpose |
|---|---|
| `PAPAIA_SQL_UPLINK_SUBNET` | Fixed range of the network `<project>-sql-uplink`, the direct route of `mcp-mssql` to the SQL source. A private IPv4 range from /24 to /29 that overlaps no SQL source; empty means `10.255.254.0/29`. The host rules are written for this range |

## Federation variable

Root `.env`, read by `papaia-ctl` while `$PAPAIA_CONFIG_DIR/security/idp.yaml` exists
([federation.md](federation.md)). Empty by default.

| Variable | Purpose |
|---|---|
| `PAPAIA_OPERATIONS_MAIL` | The operations address. `papaia-lifecycle` sends one warning mail to it through the mail relay (profile `smtp`) when the status sync with the upstream directory fails for longer than 300 s. One address; anything else stops the render. Empty sends no mail; `doctor identity` reports the failure either way |

## Hosted test model variable

Root `.env`, read by `papaia-ctl` when it renders LiteLLM's configuration
([hosted-test-model.md](hosted-test-model.md)). Empty by default.

| Variable | Purpose |
|---|---|
| `PAPAIA_TEST_EXTERNAL_MODEL` | `1` allows one route of LiteLLM to a model hosted outside the stack, for a test stack with synthetic data only. Any other value: a route outside the stack stops the render |

The key of the hosted model is not a variable of `ai/litellm/.env`: it goes into
`$PAPAIA_CONFIG_DIR/ai/litellm/test-hosted.env` with mode 0600, which no backup archives,
under a name `TEST_HOSTED_<NAME>`; the file holds nothing else.

## Security profile and realm hardening variables

`PAPAIA_SECURITY_PROFILE` in the root `.env` and a variable of `infra/keycloak/.env`,
read by `papaia-ctl` when it renders the realm of a new installation and by
`papaia-ctl realm sync` (every `start`), which applies the same values to an existing
realm through the Admin API without ending any session. The lifetime of offline sessions
is no variable but a setting, see [Delegation lifetime](#delegation-lifetime).

| Variable | Purpose |
|---|---|
| `PAPAIA_SECURITY_PROFILE` | `standard` (default) or `kritis`. Any other value stops the render and the realm sync |
| `KC_REALM_ADMIN_PASSWORD` | Password of the realm account `admin` (role `papaia-admin`), generated by setup. The rendered realm gives it to `admin` as a temporary password, to be changed at the first sign-in; unset, `admin` gets no password. A value shorter than 16 characters or a template password stops the render and the realm sync |

### What each security profile means

`PAPAIA_SECURITY_PROFILE` has exactly one definition, `tools/lib/security_profile.py`
([ADR 0022](adr/0022-one-security-profile-for-the-whole-installation.md)). Every part of
`papaia-ctl` asks it, and modules read this variable from the root `.env` instead of a
switch of their own. The table is the same as in that module (a test compares them):

| Setting | `standard` | `kritis` |
|---|---|---|
| Realm `sslRequired` | `external` | `all` |
| Configured public hosts | http or https | https only |
| Offline sessions, idle / max age (days) | default 90 / 180, up to 365 / 365 | default and upper bound 7 / 30 |
| TLS between containers | ends at the reverse proxy; the audit ingest uses mutual TLS with its own CA | same as `standard`; links between core containers do not use TLS yet |
| Platform certificates | issued for every `pki:` request | issued for every `pki:` request |
| Add-on without a `pki:` request | allowed | refused |

The table says what the core enforces today. Under `kritis` an add-on cannot run without
certificates of the platform PKI ([pki.md](pki.md)); whether it uses them on its own
links is up to the add-on. The core services do not use their platform certificates yet.

### Realm settings per profile

| Setting of the `papaia` realm | `standard` | `kritis` |
|---|---|---|
| `sslRequired` | `external` | `all`; every configured host must be `https` |
| Offline sessions: idle / maximum age (maximum age always on) | the delegation lifetime: default 90 / 180 days, up to 365 / 365 | the delegation lifetime: default and upper bound 7 / 30 days |
| Access token lifetime | 240 s | 240 s |
| Refresh tokens | replaced on every use (`revokeRefreshToken`, no reuse) | same |
| Brute-force protection | 5 failures, wait from 60 s rising to 15 min, no permanent lockout | same |
| Username change, self-registration | off | off |

`papaia-ctl realm sync` prints the current offline-session values
(`offline sessions: idle 90 d, max age 180 d (profile standard)`), `--check` the values
the realm has.

Clients: no client has the password grant or the implicit flow; a public client with the
code flow uses PKCE S256. The redirect URIs, web origins and post-logout redirects of
LibreChat, LiteLLM, LocalAI, papaia-manager and oauth2-proxy are computed from
`DOMAIN_CLIENT` / `DOMAIN_SERVER`, `LITELLM_PUBLIC_URL`, `LOCALAI_PUBLIC_URL`,
`MANAGER_PUBLIC_URL`, and `OAUTH2_PROXY_PUBLIC_URL` (with direct port access
`PAPAIA_HOST:OAUTH2_PROXY_EXT_PORT`) and `NPM_ADMIN_HOST` (exact `/oauth2/callback`): `<URL>/*`, never `*` or `+`. Any other client keeps only entries with
a fully named host and a wildcard at most as the last character of the path. A client
policy `papaia-hardening` enforces PKCE and rejects the password grant and the implicit
flow at every client with `papaia.managed=true`; Keycloak then refuses an update of such a
client that does not name its switches and its PKCE method (send the whole client). A
public client never carries `standard.token.exchange.enabled`.

Redirect URIs and web origins start with `https://` only when the configured hosts do. The
`standard` profile accepts a plain-`http` host (the local defaults such as
`http://host.docker.internal`) and names it in a note of the render and of the realm
sync; `sslRequired external` still makes Keycloak refuse plain http from a non-private
address. A production installation in the `standard` profile therefore needs `https`
hosts for every entry to start with `https://`; the `kritis` profile refuses a plain-`http`
host.

Accounts: the realm ships no test account. Its only account, `admin`, has the generated
`KC_REALM_ADMIN_PASSWORD` as a temporary password. On an existing installation
`papaia-ctl realm sync` looks for the accounts earlier realm templates created
(`admin` / `admin`, `testuser` / `testuser`: the template's user name and e-mail address,
the password never changed since the account was created, no password change pending).
`admin` gets `KC_REALM_ADMIN_PASSWORD` as a temporary password (disabled instead while that
variable is not set); `testuser` is disabled. `--check` reports such an account. An
account whose password was changed is left alone.

### User events of the realm

With the `lifecycle` profile, `papaia-ctl realm sync` sets the realm to store the user events
`UPDATE_PASSWORD`, `REMOVE_CREDENTIAL`, `LOGOUT` and `LOGIN`, next to the service-account
sign-ins `CLIENT_LOGIN` it stores in any case. `LOGIN` is stored for every person's sign-in, with account,
client, IP address and session. papaia-lifecycle needs it to alert on a sign-in of the
emergency account ([permission-report.md](permission-report.md),
[lifecycle.md](lifecycle.md#what-it-does)). Keycloak keeps all user events of a realm for
one period, `eventsExpiration`: 180 days (`EVENTS_EXPIRATION`, two rotation intervals of
a service account) unless the operator set a retention, which is kept. A shorter
retention also shortens the record of service-account sign-ins. Name the stored sign-ins
and their retention in the records of processing.

## Delegation lifetime

A delegation is the offline session a person grants Flow (`flow-engine`) or the assistant
(`assist-gate`) to act on their behalf. How long it lives is one setting of the
installation, the same for both holders because Keycloak keeps it per realm:

| Setting | Meaning | `standard` | `kritis` |
|---|---|---|---|
| `delegations.idle_days` | days without use after which a delegation ends (Offline Session Idle) | default 90, 1 to 365 | default 7, at most 7 |
| `delegations.max_days` | days after the grant after which a delegation ends, however often it is used (Offline Session Max, always on) | default 180, 1 to 365 | default 30, at most 30 |

`idle_days` is never greater than `max_days`. With an external identity provider
(federation) 7 / 30 days are recommended in profile `standard` as well.

```sh
papaia-ctl delegations lifetime                      # show the values in effect
papaia-ctl delegations lifetime --json               # the same as JSON (permission report)
papaia-ctl delegations lifetime --idle-days=30 --max-days=90
```

A change is kept in `$PAPAIA_CONFIG_DIR/settings/delegations.json` (mode 0600, part of the
backup of the configuration directory); without that file the defaults of the profile
apply. Then the command renders the platform catalog, which publishes the values as
`delegations {idle_days, max_days}` (holders and the personal area compute expiry dates
from them), and runs `papaia-ctl realm sync`, which writes them into the realm. When the
stack is not running, the value is saved and applied by the next `papaia-ctl start`.
A value left out keeps the one in effect.

- Values outside the bounds are refused and nothing changes (exit status 2); in profile
  `kritis` every value above 7 / 30 days is refused.
- A stored value above the bound of the profile (for example one set before the profile
  was changed to `kritis`) is never used: render, realm sync and catalog stop with a
  message until a value within the bound is set. The command shows such values with
  `"within_bound": false` and exit status 1, and takes new values within the bound (give
  both, as a value left out keeps the stored one); the audit row names the stored values
  as the old ones.
- A settings file that is not the documented document (not JSON, unknown fields, values
  outside 1 to 365 days) is neither shown nor replaced (exit status 1); restore it from the
  backup of the configuration directory.
- Every change writes one audit row `delegation_lifetime_changed` with the values before
  and after, the host account and the time; a refused change writes one with
  `result: denied`, `error_code: PK-INPUT-001` and no values. The row is written before
  the file; when the file cannot be written, a second row with the same correlation id
  follows (`result: error`, `error_code: io`) and the values in effect stay as they were.
- A shorter value applies to existing delegations at their next renewal; a delegation
  that is older than the new maximum age ends then and is granted anew.

The command runs on a single-node installation; it is not available in a distributed one
yet. The variables `KC_OFFLINE_SESSION_IDLE_DAYS` and `KC_OFFLINE_SESSION_MAX_DAYS` of
1.10.0 pre-releases are no longer read; the realm sync names them in a note when they are
still set.

## Where values come from

`tools/papaia-ctl setup` derives or generates most variables; few are genuinely
operator-supplied.

| Origin | Examples |
|---|---|
| Operator-supplied (flag or interactive prompt) | `PAPAIA_HOST`, `AUTH_HOST`, `--env`, `--host-ip`, `--backup-dir` |
| Derived from the above | `OIDC_ISSUER`, `OIDC_AUTH_URL`/`OIDC_TOKEN_URL`/`OIDC_JWKS_URL`, `OPENID_ISSUER`, `GENERIC_*_ENDPOINT`, `DOMAIN_SERVER`/`DOMAIN_CLIENT`, `*_PUBLIC_URL`, `OAUTH2_PROXY_COOKIE_SECURE`, `COMPOSE_PROJECT_NAME`, `PAPAIA_PROJECT`, `DOCKER_NETWORK`, `PAPAIA_BACKUP_DIR` |
| Generated (see [Secrets handling](#secrets-handling)) | every key shipped with a `GENERATE_…` placeholder |
| Static defaults | `*_EXT_PORT` variables, `TRUST_PROXY` |

A later `setup` or `upgrade` without `--auth-host` keeps the stored `AUTH_HOST`, and with
it the token issuer. The exception is a value that only matches what setup derived from the
previous `PAPAIA_HOST`: it follows a changed `--app-host` (or a new answer to the prompt).
For a local host the match ignores the scheme, since older releases derived those as
`http`; a domain name must match with its scheme. A value stored while an external OIDC
provider was in use is not kept either: switching back to the bundled Keycloak derives it
again. The interactive prompt pre-fills by the same rules. Behind the bundled proxy a value
that is the port address an earlier release derived (`https://<host>:8110`) moves to the
edge name, since that port is no longer published. With direct port access, after changing
`KEYCLOAK_EXT_PORT` on a local host, pass `--auth-host` with the new port.

When a plain-http browser URL (`PAPAIA_HOST`, `MANAGER_PUBLIC_URL`,
`LITELLM_PUBLIC_URL`, `LOCALAI_PUBLIC_URL`, `QDRANT_PUBLIC_URL`, `NPM_ADMIN_HOST` or
LibreChat's `DOMAIN_SERVER`) is on the `AUTH_HOST` hostname or a subdomain of it — the
local default: papaia-manager, LiteLLM, LocalAI and Qdrant on `http://host.docker.internal`,
Keycloak on `https://host.docker.internal:8110` — the papaia realm sets Keycloak's
`Strict-Transport-Security` header to `max-age=0`. HSTS applies to a hostname on every
port, and Keycloak's default (one year, `includeSubDomains`) would make the browser
upgrade those http URLs to https. `papaia-ctl start` applies the value to an existing
realm too, as long as the realm still has Keycloak's default header, and restores the
default once the hostnames no longer overlap. A deployment whose plain-http services
live on hostnames of their own keeps Keycloak's default HSTS.

This covers responses of the papaia realm only. Keycloak sends its default header on
responses outside a realm — the static files under `/resources/` that every login page
loads, `/`, and the admin console of the `master` realm — and that cannot be configured.
Each Keycloak page visit therefore pins the hostname again; the next papaia-realm
response clears it, in practice the redirect back to the app after a completed login.
After an aborted login or a visit to the admin console, the browser upgrades the
http services on that hostname until then. To clear it, complete a login (LibreChat
is on `http://localhost:8000` by default and is not affected), or remove the entry in
the browser (Chrome: `chrome://net-internals/#hsts`, *Delete domain security
policies*). Serving the plain-http services on a hostname of their own avoids the
problem completely, e.g. `--manager-host=http://localhost:8120
--litellm-host=http://localhost:8200`; `papaia-ctl realm sync` gives an existing realm
the redirect URIs of the new hosts on the next `start`.

See `tools/lib/resolve.py` for the exact derivation logic, or run
`tools/papaia-ctl setup --help` for the flag reference.

## New variables in a newer release

A release can add variables to a `.env.example`. The canonical `.env` files under
`$PAPAIA_CONFIG_DIR` pick them up without operator action:

- `papaia-ctl start` appends every variable the checkout's `.env.example` ships and the
  bundle `.env` lacks, before the bundle is copied into the checkout. This covers a
  checkout moved by `git pull` or a branch switch, not only by `upgrade`.
- `papaia-ctl setup` and `papaia-ctl upgrade` (which runs `setup`) add them as well, in
  the position the template gives them.

Only missing variables are added. An existing value is never changed, and `start` appends
to the file instead of rewriting it, so hand-written values and comments survive. New
keys are listed on the console (`Added 3 new variable(s) to ai/librechat/.env: …`); a
second start adds nothing. A new `GENERATE_…` secret receives a generated value, and a
new alias of a shared secret takes the canonical value. Nothing is added to
`infra/keycloak/.env` with `AUTH_PROVIDER=external_oidc`, and a key that `setup` still has
to migrate from a renamed one is left to `setup`.

A *changed default* of a variable that already exists is not applied: the value in the
bundle is yours. Change it in `$PAPAIA_CONFIG_DIR` by hand when a release note asks for it.

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

Only core clients are covered. Addon clients (`paperless`, …) register their own OIDC
client and generate their own secret during addon installation; the core neither stores
nor generates those values.

Secrets live only in gitignored `.env` files — the per-service `src/**/.env` files
Compose reads, and the canonical copy under `$PAPAIA_CONFIG_DIR` that `papaia-ctl` reads
back on every re-run. Neither is ever committed. The generated Keycloak realm import
(`$PAPAIA_CONFIG_DIR/infra/keycloak/realm-import/papaia-realm.json`) has every
`${env.…}` placeholder substituted with its real value before Keycloak imports it; this
supersedes Keycloak's own import-time substitution, which was found unreliable.

The audit store is the exception: its database passwords, its signing key and the key of
its pseudonyms are files under `$PAPAIA_CONFIG_DIR/infra/audit/secrets/`, handed to the
containers as Docker secrets, never `.env` variables. `papaia-ctl start` creates missing ones and keeps existing
ones ([audit.md](audit.md)).

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
