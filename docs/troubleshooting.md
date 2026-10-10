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

### "host.docker.internal: cannot resolve" on Linux

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

### A service does not start at all

Most likely its Compose profile is not active. Check `COMPOSE_PROFILES` in
`$PAPAIA_CONFIG_DIR/.env`, and see
[Selective module enable / disable](deployment.md#selective-module-enable--disable).

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
