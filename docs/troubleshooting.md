# Troubleshooting

> **Status:** Draft — to be expanded.

## Common issues

### "redirect_uri does not match" from Keycloak after login

Cause: `PAPAIA_HOST` and the Keycloak client's registered redirect URIs disagree.

- `PAPAIA_HOST` must be the URL you actually type into the browser — scheme, host, **and**
  port.
- After changing it, re-run `tools/papaia-ctl setup` to re-derive every dependent URL and
  re-render the configuration. Editing `.env` by hand is not enough: the redirect URIs are
  baked into the realm at render time.

### LibreChat OIDC login: "invalid_token" or signature errors

Cause: the `iss` claim in the access token does not match what LibreChat expects.

- The token's `iss` always equals `KC_HOSTNAME` (derived from `AUTH_HOST`).
- Confirm `OPENID_ISSUER` in `$PAPAIA_CONFIG_DIR/ai/librechat/.env` holds the same URL.
- On Linux, make sure `host.docker.internal` resolves — see below.

### LibreChat logs "Index build failed" after the upgrade to 1.5.0

```
error: Index build failed for "User": An existing index has the same name as the requested index ...
warn: This may be a legacy tenant-index conflict. See UPGRADING.md ...
```

Cause: LibreChat 0.8.8 builds tenant-scoped unique indexes. A database written by LibreChat
0.8.7 or older can still hold the previous unique indexes (`email_1`, `name_1`, ...) under
the same names, so the new ones cannot be created. LibreChat keeps running, but logs the
error for User, Role, Preset, AccessRole, MCPServer, AgentCategory, Message and Conversation
on every start.

`tools/papaia-ctl upgrade` repairs this with the migration
`tools/migrations/1.5.0__librechat-tenant-indexes.py`, so nothing needs to be done after a
regular upgrade. If the database reached 1.5.0 another way (for example a dump taken with
LibreChat 0.8.7 or older was restored afterwards), run the migration by hand. It needs the
stack stopped, is safe to repeat, builds the new indexes before dropping the superseded ones
and never touches documents:

```sh
tools/papaia-ctl stop --addons
PAPAIA_CONFIG_DIR=/path/to/papaia-config PAPAIA_REPO_ROOT="$PWD" PYTHONPATH="$PWD/tools" \
    python3 tools/migrations/1.5.0__librechat-tenant-indexes.py
tools/papaia-ctl start --addons
```

### LibreChat web search fails with "SSRF protection: ... resolved to blocked address"

Cause: since LibreChat 0.8.8, web search, scraping and reranking refuse connections to
private addresses, including Docker service names, unless the exact `host:port` is listed
under `webSearch.allowedAddresses`. The shipped `librechat.yaml` lists the bundled services
(`searxng:8080`, `firecrawl:3002`, `jina-reranker-api:8000`).

If you pointed `SEARXNG_INSTANCE_URL`, `FIRECRAWL_API_URL` or `JINA_API_URL` in
`$PAPAIA_CONFIG_DIR/ai/librechat/.env` at another private host or port, add that pair in the
overlay. Overlay lists are appended to the shipped list, so the defaults stay in place:

```yaml
# $PAPAIA_CONFIG_DIR/overlay/ai/librechat/librechat.yaml
webSearch:
  allowedAddresses:
    - "10.0.0.5:8080"
```

Entries must be an exact `host:port` (or `[ipv6]:port`); URLs, paths, CIDR ranges and bare
hosts are rejected when the configuration is loaded. Run `tools/papaia-ctl stop` and
`tools/papaia-ctl start` afterwards so the configuration is rendered again and LibreChat
reads it.

### LibreChat logs "[credentials] Existing database has no credential fingerprint record"

This warning is expected on every start of an upgraded installation. LibreChat 0.8.8 records
a hash of its `CREDS_KEY`, `CREDS_IV`, `JWT_SECRET` and `JWT_REFRESH_SECRET` to detect key
drift, but only does so for a database that has no users yet; an existing database is only
warned about. No action is needed as long as those four values stay unchanged, which
`papaia-ctl` guarantees unless it is run with `--force`. Do not rotate them: encrypted data
stored by LibreChat, such as user-provided API keys, becomes unreadable.

### Cookies do not stick / login loops behind oauth2-proxy

- Verify that `OAUTH2_PROXY_COOKIE_SECRET` is exactly **32 base64 bytes**
  (`openssl rand -base64 32`). A shorter value fails silently.
- Use the same scheme, host, and port in the reverse proxy, in oauth2-proxy's
  `--redirect-url`, and in the Keycloak client's *Valid redirect URIs*. A mismatch in any one
  of them causes the loop.
- Clear cookies for the affected host between attempts — stale `_oauth2_proxy*` cookies
  survive container restarts.

### Keycloak login fails over plain HTTP

Browsers refuse to send `Secure` cookies over plain HTTP. Either run the stack behind HTTPS,
or stay on `http://host.docker.internal` for local development, where the realm is
preconfigured to allow it.

`OAUTH2_PROXY_COOKIE_SECURE` must match the scheme of `PAPAIA_HOST` — `true` for HTTPS,
`false` for HTTP.

### Keycloak unreachable through an upstream reverse proxy

Keycloak terminates TLS itself and publishes only its HTTPS listener (container port 8443,
host port `KEYCLOAK_EXT_PORT`, default 8110), using the self-signed certificate generated by
`papaia-ctl setup`.

An upstream proxy must therefore speak **HTTPS** to Keycloak and skip certificate
verification on that hop. A plain-HTTP `proxy_pass` to port 8110 cannot work. See
[External reverse proxy](../README.md#external-reverse-proxy) for working Caddy and nginx
configurations.

### "host.docker.internal: cannot resolve" on Linux or macOS

```bash
echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
```

Or set `PAPAIA_HOST` to the host's LAN IP instead and re-run `tools/papaia-ctl setup`.

### Out-of-memory when running LocalAI

`tools/papaia-ctl doctor` shows how much memory the host has and how much of it is still
available (the `memory` check). Then run a smaller model — edit `ai/localai/models.txt` (or its
`overlay/` copy) — or disable LocalAI altogether and route LibreChat to a hosted provider
through LiteLLM:

```bash
tools/papaia-ctl setup --no-local-ai
tools/papaia-ctl start
```

### The native LocalAI on a Mac does not answer

With `LOCALAI_RUNTIME=native`, LocalAI is a process on the Mac, run by launchd, not a
container. `tools/papaia-ctl doctor` says in `localai_native` whether it answers and what
launchd reports about the job. Its output is in
`$PAPAIA_WORKSPACE_DIR/localai/<project>/logs/localai.log`, and launchd's view of it in

```bash
launchctl print "gui/$(id -u)/de.fidonis.papaia.<project>.localai"
```

(`state`, `pid` and `last exit code`; "Could not find service" means the job is not loaded).

- **"not loaded although the stack runs"**: the job was stopped by hand (`launchctl bootout`)
  or `start` could not load it. Run `tools/papaia-ctl start`, which loads it again, and read
  its output.
- **"is loaded … but LocalAI does not answer"**: LocalAI is still starting (the first start
  downloads the Metal backend) or exits right away and launchd restarts it every 10 s. The
  log says which.
- **"LOCALAI_API_KEY is missing"** in the log: run `tools/papaia-ctl start`, which fills the
  key into `$PAPAIA_CONFIG_DIR/ai/localai/.env`.
- **"is installed, this release pins"**: run `tools/papaia-ctl start`; it installs the pinned
  binary and restarts the job.
- **"Operation not permitted"** in the log, or launchd cannot open the log file: the
  workspace lies below `~/Documents`, `~/Desktop` or `~/Downloads`, which macOS may keep a
  launchd job out of. Move the workspace elsewhere and run `setup` and `start` again.
- **`start` says "Bootstrap failed: 5: Input/output error"**: the job was disabled by another
  tool, or a job with the same label is still being unloaded. Run `tools/papaia-ctl stop`,
  then `start`.
- **papaia-manager started the stack, but LocalAI did not start**: the manager runs in a
  container and cannot reach launchd; it says so and skips LocalAI. Run
  `tools/papaia-ctl start` on the Mac.
- **The download of the binary failed or its checksum did not match**: `start` says so and
  installs nothing. Check the network and run `start` again; a checksum mismatch that
  persists means the file served is not the published one.
- **The first start hangs**: LocalAI downloads its Metal backend on the first start, which
  needs internet access. The models come from the init job (`docker logs` of
  `localai-model-init`); a 5.4 GB model can take an hour or more.
- **The port is busy**: another process listens on `LOCALAI_EXT_PORT`. Stop it, or change the
  port and re-run `setup` and `start`.
- **Models in LiteLLM answer 404 or connection refused**: LiteLLM reaches the process at
  `http://host.docker.internal:<LOCALAI_EXT_PORT>/v1`, which only Docker Desktop resolves.

### LocalAI comes back after a reboot although the stack is stopped

The native LocalAI of a Mac is a launchd job with `RunAtLoad`: launchd starts it at every
login unless the job is disabled. `tools/papaia-ctl stop` disables it; stopping the stack in
another way (`docker compose stop`, quitting Docker Desktop, `papaia-manager`) does not. Run

```bash
tools/papaia-ctl stop
```

on the Mac. LocalAI then stays off after a logout or a restart until the next
`tools/papaia-ctl start`. `uninstall` removes the job altogether. A job left behind by a
checkout that is gone can be removed by hand:

```bash
launchctl bootout "gui/$(id -u)/de.fidonis.papaia.<project>.localai"
rm ~/Library/LaunchAgents/de.fidonis.papaia.<project>.localai.plist
```

### LocalAI ignores the GPU

Check that the accelerator variant is actually set — `LOCALAI_IMAGE_VARIANT` in
`$PAPAIA_CONFIG_DIR/.env` — and that the generated override exists:

```bash
cat "$PAPAIA_CONFIG_DIR/overrides/docker-compose.localai-gpu.override.yml"
```

If it is missing, the variant is `cpu`; re-run `tools/papaia-ctl setup` and pick another.

`tools/papaia-ctl doctor` runs these host checks for the configured variant (the `gpu` check):
whether `nvidia-smi` works and Docker has the `nvidia` runtime, whether `/dev/kfd` or a render
node under `/dev/dri` exists, and, for NVIDIA and AMD, how much VRAM is in use. It reports `skip`
for the CPU image. Inside a container (as `papaia-manager` runs it) the NVIDIA GPU is read with
`nvidia-smi` in the running LocalAI container instead, and reports `skip` if LocalAI is not
running; AMD, Intel and Vulkan report `skip` there, because their devices are the host's.

The image alone is not enough — the host prerequisites have to be in place:

- **NVIDIA:** the proprietary driver plus the NVIDIA Container Toolkit. `nvidia-smi` must
  work on the host and `docker info` must list the `nvidia` runtime.
- **AMD:** the ROCm kernel driver, so that `/dev/kfd` exists. Without it, use the Vulkan
  variant instead. Cards ROCm does not target by default need `HSA_OVERRIDE_GFX_VERSION` /
  `GPU_TARGETS` in `src/ai/localai/.env`.
- **Intel:** a render node under `/dev/dri`. Upstream also reports hangs with memory-mapped
  models — set `mmap: false` in the model YAMLs under
  `$PAPAIA_CONFIG_DIR/ai/localai/models/`.

### Password-reset and other mails do not arrive

Mail goes through the relay of the `smtp` profile, and a message that Keycloak or papaia-manager
reports as sent has only reached the relay. Start with `papaia-ctl doctor`: its `smtp` check says
whether the mail server answers and how many messages wait. Then read the relay's own log, with
the container name of your project (`papaia-smtp-relay-1` for the default one):

```bash
docker logs papaia-smtp-relay-1 2>&1 | grep -E 'status=|reject|warning|error'
docker exec papaia-smtp-relay-1 postqueue -p      # what waits, and why
docker exec papaia-smtp-relay-1 postqueue -f      # try again now
```

| In the log | Meaning and fix |
|---|---|
| `status=deferred (SASL authentication failed ...)` | The mail server refused the login. Check the login and re-enter the password: `PAPAIA_SMTP_PASSWORD=... papaia-ctl setup -y --smtp`, then `papaia-ctl start` |
| `status=deferred (Server certificate not verified)` or `certificate verification failed` | The mail server's certificate is not signed by a CA the system trusts, or does not match the host name given in `--smtp-host`. Use the name on the certificate. A private CA is not supported yet |
| `status=deferred (... Connection refused / timed out)` | The mail server cannot be reached from the Docker network: host, port or a firewall. `--smtp-security=tls` belongs to port 465, `starttls` to 587 |
| `Client host rejected: Access denied` | The sender is outside the networks the relay serves. Widen `SMTP_RELAY_ALLOWED_CLIENTS` in `infra/smtp-relay/.env` only if your Docker address pools are not private ranges |
| `Recipient address rejected: Access denied` | The sender address is not in the domain the relay was set up for (`--smtp-from`). Mail from other domains is refused on purpose |
| `Recipient address rejected: Domain not found` | The recipient's domain does not resolve. Seeded accounts with `.lan` addresses cannot receive mail; give the account a real address |
| the provider refuses the sender address | Many providers only accept addresses they know: a verified identity, a mailbox, an alias. Set `--smtp-from` to one of those. The refusal comes back to the sender address |

After a password change `setup` raises `SMTP_RELAY_PASSWORD_REV`, and the next `start` recreates the
relay with the new password. The login page offers *Forgot password?* only while the realm has the
relay as its mail server; `papaia-ctl keycloak-role-sync` shows what it did to the realm.

### A service does not start at all

Most likely its Compose profile is not active. Check `COMPOSE_PROFILES` in
`$PAPAIA_CONFIG_DIR/.env`, and see
[Selective module enable / disable](deployment.md#selective-module-enable--disable).

### mcp-firecrawl fails with "exec format error" on an arm64 host

The Firecrawl MCP image (profile `librechat-websearch`) is published for `linux/amd64` only, so
its service pins `platform: linux/amd64` and runs emulated on arm64. Docker Desktop on Apple
Silicon emulates it out of the box (Rosetta). A Linux arm64 host needs QEMU user emulation
registered with binfmt_misc first, e.g.:

```sh
docker run --privileged --rm tonistiigi/binfmt --install amd64
```

Then run `tools/papaia-ctl start` again.

## Logs

Start with `tools/papaia-ctl status` (what is running, and which module is unhealthy or not
deployed) and `tools/papaia-ctl doctor` (Docker version, disk space, memory, CPU load, GPU,
ports, clock synchronization, certificates). Then look at the logs of the service they point to:

```bash
docker compose -f src/docker-compose.yml --env-file src/.env ps       # what is running
docker compose -f src/docker-compose.yml --env-file src/.env logs -f <service>
docker compose -f src/docker-compose.yml --env-file src/.env config   # merged compose file
```

`src/.env` is written by `tools/papaia-ctl start`, so run the stack at least once before
invoking `docker compose` directly.

## Getting help

If your issue is not listed here, please:
- Search [existing issues](https://github.com/Fidonis/papaia/issues)
- Ask on [Discussions](https://github.com/Fidonis/papaia/discussions)
- Open a new [Documentation issue](https://github.com/Fidonis/papaia/issues/new?template=documentation.yml) if the docs are unclear
