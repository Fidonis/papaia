---
adr: 0008
title: Update add-ons by repointing the registration to a new directory, not by replacing files
status: Accepted
date: 2026-10-25
deciders:
  - marko-boehm
tags:
  - addon-contract
  - papaia-ctl
  - update
  - rollback
supersedes: null
superseded_by: null
---

# 0008. Update add-ons by repointing the registration to a new directory, not by replacing files

## Context

`papaia-ctl addon` could install, start, stop and remove an add-on but not move it to a newer
version. The documentation described an update as "refresh, diff `.env.example`, stop,
re-materialise, reinstall, start" and attributed it to `papaia-manager`. The manager did
less: it replaced the add-on's directory first and ran `addon install --path=<dir>` after,
which is the first place the compatibility gate runs.

- A version that failed the gate had already replaced the files at the registered path, while
  the containers kept running the old version.
- A new `CHANGE_ME` key in the new `.env.example` was seeded as the literal `CHANGE_ME`.
  Without a terminal `prompt_change_me_vars` only prints a warning, so the add-on could start
  with a placeholder.
- There was nothing to look at before the update (new keys, changed components, new Keycloak
  clients) and nothing to go back with afterwards. The old files were gone, and so was the
  data the new version had migrated.
- An operator without the manager had none of it. The CLI is meant to be the single
  implementation of every verb the manager wraps.

## Decision

- **A version is a directory, and an update changes which one is registered.** `addon update
  <name> --path=DIR` never writes into the directory the add-on is registered at. It checks
  `DIR`, takes a restore point, adds the new keys to the configuration bundle, and repoints
  `path` and `version` in `deployment.yaml`. The entry it replaces is kept as `previous`
  (`path`, `version`, and the id of the restore point). `addon rollback <name>` is the same
  repointing in the other direction and clears `previous`, so it is exactly one step back. The
  caller keeps each version in a directory of its own, for example
  `<snapshots>/<commit>/<name>`; the CLI does not know about catalogues or commits.
- **The directory name must stay the same.** Compose names the project after the directory
  (`-p <basename>`), so a differently named directory would leave the running project
  orphaned. `update` refuses it before anything changes.
- **Nothing changes until every check has passed.** The order is: preconditions (registered,
  active, same add-on, same directory name), compatibility gate against the current core, plan,
  values for the new keys, restore point, apply. A refusal up to and including the values
  exits 2 and leaves `deployment.yaml`, the bundle and the containers as they were. A restore
  point that cannot be taken exits 3 at the same point.
- **The plan is a pure function** of the two manifests, the two `.env.example` files and the
  bundle (`lib/addon_update.plan_update`). `--dry-run --json` prints it, described by
  `tools/schemas/addon-update.schema.json`, so a caller can show exactly what the real run will
  do. A new key is `generated`, `change_me`, `replace_secret` (a Keycloak client secret, which
  exists only after the client is imported) or `literal`. A `change_me` key without a default
  from the manifest's `env_prompts` is in `needs_input`: the update does not run until it has a
  value. Values already in the bundle are sticky; an update only adds keys.
- **Values reach the update through a prompt or `--answers-file`, never through the command
  line.** The plan step collects them and hands them to the apply step in a private file. An
  answers file may only set keys the plan asks about, and its values are never printed.
- **The restore point is add-on scoped** (`backup --only=addon:NAME`), taken by default, and
  skipped with `--no-backup`. An add-on without volumes or data directories gets none and the
  update goes on. `rollback` leaves the data alone unless `--restore-data` is given, which
  restores that restore point with `restore-scoped`; the output says which of the two happens.
- **A failed start does not roll back by itself.** If the containers cannot be recreated, the
  command exits 3 and names the rollback command, as `upgrade` leaves the decision to the
  operator. The cause can be anything, and a half-applied automatic rollback is harder to
  reason about than an explicit one.
- **`addon list [--json]` is the one view of what is installed**: path, version from the
  manifest, bundled components, the verdict `addon check` would give, and `previous` with
  whether its directory still exists. It is described by `tools/schemas/addon-list.schema.json`.

## Consequences

- **Positive**: an update that is refused costs nothing. The previous version is on disk and
  its configuration is in the bundle, so a rollback does not depend on the network or on a
  catalogue. Operators and the manager use the same verbs and the same plan. Existing secrets
  are never rewritten.
- **Negative**: every version stays on disk until the caller removes it, so a caller has to
  prune its snapshots. Only one step back is recorded, and a rollback that restores data
  loses what the add-on wrote after the restore point. A data directory that an add-on keeps
  inside its own directory as a writable bind mount is not carried to the new directory; the
  catalogue's add-ons keep their data in named volumes and mount their own directory read-only.
  The `previous` restore point can be pruned by retention, which `rollback --restore-data`
  reports before it changes anything.
- **Neutral**: an update in the registered directory itself (an operator who pulled a
  checkout in place) is accepted, but it records no `previous` and says so. The manifest keys
  `version` and `components` are read for display and for the delta; no gate decision depends
  on them, and `ADDON_API` does not change. `addon install --path=DIR` for a directory other
  than the registered one starts over and forgets `previous`: that entry belongs to the update
  it came from.

## Alternatives considered

- **Replace the files in place and re-run `install`** (what the manager did) — the gate runs
  after the damage, and there is nothing to roll back to.
- **`--ref` and `git archive` inside the CLI** — the CLI has no catalogue concept, and
  overwriting a checkout the operator manages would be destructive.
- **Stop, swap the directory, start** — more downtime for no gain: Compose recreates changed
  services by itself, and `--remove-orphans` removes the services a newer version dropped.
- **Roll back automatically when the new containers fail** — see above; `upgrade` makes the
  same choice.
- **Fold the listing into `addon components`** — that verb answers what software runs inside
  an add-on, for registered add-ons only; the listing also needs the path, the verdict and
  `previous`.

## References

- [ADR 0002](0002-addon-core-compatibility-gating.md) — the compatibility gate that runs first.
- `papaia-ctl backup --only` and `restore-scoped` — the add-on scoped restore point.
