# Deployment

> **Status:** Draft — to be expanded.

## Local development

```bash
git clone https://github.com/marko-boehm/papaia.git
cd papaia
tools/papaia-ctl setup   # interactive: prompts for PAPAIA_HOST / AUTH_HOST
tools/papaia-ctl start   # materialises .env files, renders config, starts the stack
```

`setup` is a one-shot, idempotent bootstrap: it seeds an external config
directory (`$PAPAIA_CONFIG_DIR`, default a `papaia-config` directory next to
the checkout), generates every secret, derives the OIDC issuer and
per-service hostnames from `PAPAIA_HOST`/`AUTH_HOST`, and renders the
Keycloak realm import with secrets already baked in. Re-running it reuses
every previously-resolved value (sticky) and only refreshes the rendered
config — safe to run again after a `git pull`.

| Flag | Purpose |
|---|---|
| `--config-dir=PATH` | Where to put `$PAPAIA_CONFIG_DIR` (default: sibling `papaia-config/` dir) |
| `--env=NAME` | Multi-env identity — sets `COMPOSE_PROJECT_NAME`/`DOCKER_NETWORK` to `papaia-<NAME>` |
| `--host-ip=IP` | Bind address for published ports (default `0.0.0.0`) |
| `--app-host=URL` | Public URL of this server (`PAPAIA_HOST`) |
| `--auth-host=URL` | Public Keycloak URL (`AUTH_HOST`); derived from `--app-host` if omitted |
| `--external-reverse-proxy` / `--no-external-reverse-proxy` | Whether an edge proxy outside the stack terminates TLS (auto-detected from `https://` hostnames if omitted) |
| `--allow-direct-port-access` | Explicit opt-in to run with no proxy at all (raw ports) |
| `--force` | Regenerate every secret unconditionally |
| `-y`, `--non-interactive` | No prompts; every value must come from a flag or a prior sticky run |

`tools/papaia-ctl stop` pauses all core containers (containers kept, volumes untouched);
`tools/papaia-ctl stop --clean-up` removes them (volumes untouched).
See the root [README's Quick start](../README.md#quick-start) for the full
walkthrough, including the manual fallback steps `setup` automates.

## Server deployment

<!-- TODO: Reverse proxy, TLS via Nginx Proxy Manager, persistent volumes, host hardening -->

## CI/CD

<!-- TODO: GitHub Actions pipelines (CI lint, release-drafter); future deploy workflows -->
