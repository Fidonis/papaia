# Release migrations

Scripts in this directory adapt an existing installation — the config bundle in
`$PAPAIA_CONFIG_DIR` and the data behind it — to the shape a newer release expects.
`papaia-ctl upgrade` runs them.

Most upgrades need nothing here. `papaia-ctl setup` already renames, relocates and
drops env keys (`resolve.migrate_env_keys`) and re-renders every config file on every
run, and the service images run their own schema migrations on start. A migration
script is for what those cannot express: moving a directory inside the config bundle,
rewriting a file whose format changed, or reshaping the contents of a named volume.

## Naming

```
<x.y.z>__<slug>.sh
<x.y.z>__<slug>.py
```

`<x.y.z>` is the release the migration ships with, `<slug>` is a short kebab-case
description, e.g. `1.1.0__npm-binds-to-config-dir.sh`. A file name that does not parse
aborts the upgrade — a migration silently skipped because of a typo is the one failure
mode this directory must not have.

Only `.sh` and `.py` files directly in this directory are executed. This README and
any subdirectory are ignored.

## When they run

`papaia-ctl upgrade` selects every migration with

```
<installed version>  <  migration version  <=  <target version>
```

and runs them in SemVer order, so a jump from 1.0.0 to 1.5.0 executes the 1.1.0,
1.2.0, … steps in between. That works because every release ships the complete set:
after the checkout moves to `v1.5.0`, the intermediate scripts are in this directory.

Successful runs are recorded in `$PAPAIA_CONFIG_DIR/migrations/applied.json` and are
never repeated — which is what lets an upgrade that failed half-way be re-run once the
cause is fixed. A fresh install is seeded in the shape of the version it was installed
at, so the migrations up to that version correctly never run.

Migrations execute **with the stack stopped**, after the checkout has moved to the
target release and before the configuration is re-rendered and the stack starts. The
config bundle is therefore still in its old shape, and the volumes exist but nothing
is reading them.

## Contract

Every script:

- runs with the working directory set to the repository root;
- receives `PAPAIA_CONFIG_DIR`, `PAPAIA_REPO_ROOT`, `PAPAIA_FROM_VERSION`,
  `PAPAIA_TO_VERSION` and `PAPAIA_MIGRATION_VERSION` in its environment;
- runs with `PYTHONPATH` pointing at `tools/`, so a `.py` migration can
  `from lib import common, deployment, envtree` — YAML and `.env` manipulation belongs
  on the Python side, the same split the rest of the tooling follows;
- **must be idempotent**: re-running it after a partial failure must be safe;
- **must exit non-zero on failure**, with a message explaining what went wrong. The
  first failure stops the upgrade, and the operator is shown how to return to the
  previous release.

Shell migrations use `set -euo pipefail` and must pass
`shellcheck --severity=warning`. A migration that has to touch the contents of a named
volume starts a throwaway container for it, the way `tools/lib/sh/backup.sh` does — it
must not assume any service is running.

## Example

```sh
#!/usr/bin/env bash
# 1.1.0 — move the Nginx Proxy Manager data from named volumes to bind mounts
# under $PAPAIA_CONFIG_DIR, so operators can read and back up the files directly.
set -euo pipefail

target="$PAPAIA_CONFIG_DIR/infra/nginx/nginx-data"
mkdir -p "$target"

# Idempotent: once the volume is gone (or was never there), this is a no-op.
if docker volume inspect papaia_npm-data >/dev/null 2>&1; then
    docker run --rm \
        -v papaia_npm-data:/from:ro \
        -v "$target:/to" \
        alpine:3 sh -c 'cp -a /from/. /to/'
    docker volume rm papaia_npm-data >/dev/null
fi
```
