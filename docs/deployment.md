# Deployment

> **Status:** Draft — to be expanded.

## Local development

```bash
git clone https://github.com/Fidonis/papaia.git
cd papaia
tools/papaia-ctl setup   # interactive bootstrap
tools/papaia-ctl start   # materialises .env files, renders config, starts the stack
```

`setup` is a one-shot, idempotent bootstrap: it seeds an external config directory
(`$PAPAIA_CONFIG_DIR`, default a `papaia-config` directory next to the checkout), generates
every secret, derives the OIDC issuer and per-service hostnames from `PAPAIA_HOST` /
`AUTH_HOST`, and renders the Keycloak realm import with secrets already baked in. Re-running
it reuses every previously-resolved value (sticky) and only refreshes the rendered config —
safe to run again after a `git pull`.

`tools/papaia-ctl stop` pauses all core containers (containers kept, volumes untouched);
`tools/papaia-ctl stop --clean-up` removes them (volumes untouched).

The complete command and flag reference lives in the root README, under
[papaia-ctl reference](../README.md#papaia-ctl-reference) — it is the single source of truth
and is not duplicated here.

## Operations

### Selective module enable / disable

`src/docker-compose.yml` aggregates services via `include:`, and every service declares a
Compose `profile`. A service starts only when its profile is active.

To change the active set permanently, edit `COMPOSE_PROFILES` in
`$PAPAIA_CONFIG_DIR/.env` and restart:

```bash
tools/papaia-ctl start
```

> Do **not** edit `src/.env` — every `start` overwrites the checkout's `.env` files from the
> config directory, so changes there are silently discarded.

To override the profile set for a single run without touching any file:

```bash
tools/papaia-ctl start --profiles=keycloak,librechat,litellm
```

The `localai` and `librechat-websearch` profiles have dedicated setup flags
(`--local-ai` / `--no-local-ai`, `--web-search` / `--no-web-search`), which also keep
`deployment.yaml` in sync. Prefer those over hand-editing.

### Updating images

Image tags are pinned directly in each service's `docker-compose.yml` (for example
`src/infra/keycloak/docker-compose.yml`). The supported upgrade path is to pull a new release
of the repository and restart:

```bash
git pull
tools/papaia-ctl start
```

`start` re-renders the configuration before bringing the stack up, so template changes
shipped by the upgrade are applied automatically. Customer overrides under
`$PAPAIA_CONFIG_DIR/overlay/` survive untouched.

To pin a single service to a different tag ahead of a release, edit the `image:` line in that
service's compose file and run `tools/papaia-ctl start`.

### Resetting Keycloak

The realm import only runs on Keycloak's **first** start. To force a re-import — after editing
the realm template, for example — the Keycloak database volume must be removed:

```bash
tools/papaia-ctl stop --clean-up
docker volume rm papaia_keycloak-postgresql
tools/papaia-ctl start
```

The volume is prefixed with `COMPOSE_PROJECT_NAME`, so a stack created with `--env=dev` uses
`papaia-dev_keycloak-postgresql` instead.

> This wipes every user, client secret, and role created through the Keycloak admin UI. Back
> them up first if they matter.

### Backup and restore

```bash
src/backup-papaia.sh          # gzipped archives of all named volumes + PAPAIA_CONFIG_DIR
src/restore-papaia.sh <vol>   # restore one named volume from its archive
```

The backup script retains the last 14 days locally.

`$PAPAIA_CONFIG_DIR` is the single source of truth for all generated state — secrets, rendered
configs, the Keycloak realm, and `deployment.yaml`. Backing up that directory plus the named
Docker volumes captures the entire installation.

## Server deployment

<!-- TODO: host hardening, systemd unit, log rotation -->

For TLS termination, see the root README:
[External reverse proxy](../README.md#external-reverse-proxy) covers the bundled Nginx Proxy
Manager as well as working Caddy and nginx configurations for an upstream proxy.
[Multi-environment setup](../README.md#multi-environment-setup) covers running dev, stage, and
demo stacks on a single host.

## CI/CD

<!-- TODO: GitHub Actions pipelines (CI lint, release-drafter); future deploy workflows -->
