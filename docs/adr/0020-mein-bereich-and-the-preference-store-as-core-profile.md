---
adr: 0020
title: Ship Mein Bereich and the preference store as the core profile me from one pinned image
status: Proposed
date: 2026-11-22
deciders:
  - WilhelmSebastian
tags:
  - addon-contract
  - personal-area
  - preferences
  - core
supersedes: null
superseded_by: null
---

# 0020. Ship Mein Bereich and the preference store as the core profile me from one pinned image

## Context

Every person needs one place to see and change their own settings across the modules of
an installation, and the modules need one store for the preferences that several of them
read: the notification channel, the fallback channel and quiet hours, the language, the
appearance and the time zone. Both come from the `papaia-me` repository: the page
`me-web` (Mein Bereich) and the preference store `prefs`.

Two drafts of the wiring existed. One published `me-web` on a host port and passed values
through an `env_file:` next to `environment:`; the other was the local compose file of the
`papaia-me` repository. Their variable names had drifted apart: a name the image reads was
missing from one, and the other set names the image does not read. Neither drift shows up
before the container starts, and then only as a missing setting at run time.

The area has to work without any add-on, because it shows the core and the manager too,
and the preference store is owned by the core, because several modules read it.

## Decision

1. **One core profile `me`** in `src/infra/me/` with three services: `me-web`, `prefs` and
   `prefs-db`. `me-web` and `prefs` run from **one pinned image** of `papaia-me`
   (`name:tag@sha256:<digest>`); `prefs` starts the store's entry point of the same image.
   `prefs-db` is a pinned PostgreSQL image.
2. **No host port.** Browsers reach `me-web` through the edge proxy as `me.<domain>`
   (`ME_PUBLIC_URL`, derived by `setup` on the edge and behind an external proxy). Direct
   port access never applies to `me-web`.
3. **Attachable at contract generation 8.** An add-on lists `prefs` or `me-web` under
   `networks.attach`; a core without the profile refuses it like any unknown service.
   `prefs-db` is on its own internal network with `prefs` alone and is never attachable.
4. **One list of environment variables.** `src/infra/me/service-env.json` lists, per
   service, the names the image reads. It is generated from the configuration modules of
   the image's source (`python -m lib.me_profile generate`) and records the image and the
   source commit. `python -m lib.me_profile check`, run by the test suite in CI, passes
   only when the `environment:` of each service holds exactly those names (one name of
   each alias group), there is no `env_file:`, and the profile's `.env.example` documents
   exactly the variables the compose file interpolates beyond the root file.
5. **Secrets are generated, never shipped.** The client secret of `papaia-me`, the session
   key and the database password carry the `GENERATE_` marker in `.env.example`; the
   database password reaches both containers as a file under `/run/secrets`.
6. **This record is the one number.** Other repositories cite this decision as
   `papaia ADR 0020`; the contract text and schema of the area live in the kit, not in a
   copy here.

## Consequences

- A new release of `papaia-me` that reads another variable fails the check until the list
  is regenerated and the compose file and `.env.example` follow; the drift can no longer
  reach an installation.
- Bumping the image means regenerating the list from the source of that image, so the
  digest and the source commit always change together.
- `prefs` delivers its audit rows to `papaia-audit` on `papaia-audit-ingest-net` with the
  client certificate of the source `papaia-me`, and reads the `azp` allow list from
  `$PAPAIA_CONFIG_DIR/security/azp/`; without either it refuses to work rather than run
  unaudited or open.
- `me-web` mounts only the rendered registry, the catalog and the CA certificates, all
  read-only; it keeps no state and no volume.

## Alternatives considered

- **Keep the variable list by hand in the core.** Rejected: that is the drift this record
  removes; only the image's source knows what it reads.
- **Separate images for `me-web` and `prefs`.** Rejected for now: two digests to pin and to
  sign for one release of one repository, with no difference in the base image.
- **An add-on instead of a core profile.** Rejected: the area must work without add-ons,
  and the preference store is core-owned.

## References

- [`ADDON_API`](../../ADDON_API) — generation 8
- [`docs/configuration.md`](../configuration.md) — how a variable reaches a container
- Compose secrets from an environment variable:
  https://docs.docker.com/reference/compose-file/secrets/
