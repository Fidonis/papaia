# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release notes are generated automatically by [release-drafter](https://github.com/release-drafter/release-drafter)
based on merged pull requests; this file mirrors the published releases.

## [Unreleased]

<!-- Updated automatically by release-drafter as PRs are merged to `main`. -->

## [1.5.0] - 2026-10-10

### 🚀 Features

- feat(rag): pass the metadata and ACL collection names to both services (#227) @marko-boehm
- feat(setup): install the rag system by default in the wizard (#224) @marko-boehm
- feat(setup): ask for the rag system during setup (#216) @marko-boehm
- feat(rag): add optional rag profile with qdrant, mcp and ingest (#215) @marko-boehm

### 🐛 Bug Fixes

- fix(ctl): parse --config-dir for npm-provision and keycloak-role-sync (#218) @marko-boehm

### 🧹 Maintenance

- chore(librechat): bump librechat to v0.8.8 (#226) @marko-boehm
- refactor(rag): drop the ingester web interface integration (#222) @marko-boehm
- chore: bump papaia-manager to 1.3.0 and qdrant-ingest to 1.0.0 (#220) @marko-boehm

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.4.0...v1.5.0

## [1.4.0] - 2026-10-03

### 🚀 Features

- feat(doctor): read gpu and time_sync from a container and report docker usage (#210) @marko-boehm
- feat(doctor): add memory, cpu, gpu and time sync checks (#208) @marko-boehm
- feat: add status and doctor commands (#206) @marko-boehm

### 🧹 Maintenance

- chore: bump papaia-manager to `1.2.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.3.0...v1.4.0

## [1.3.0] - 2026-09-28

### 🚀 Features

- feat(litellm): ship no default models and make librechat models configurable (#202) @marko-boehm
- feat!: split the shared Keycloak admin role into per-service admin roles (#198) @marko-boehm

### 🐛 Bug Fixes

- fix: add new .env.example variables to the active .env on start (#200) @marko-boehm
- fix(addon): scope the Seam-1 network to the deployment (#194) @marko-boehm
- fix(papaia-ctl): check for PyYAML in preflight and document it (#192) @marko-boehm
- fix(keycloak): generate the bootstrap admin password (#191) @marko-boehm

### 🧹 Maintenance

- chore: bump litellm to v1.100.0 (#196) @marko-boehm
- chore: bump papaia-manager to `1.1.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.2.0...v1.3.0

## [1.2.0] - 2026-09-04

### 🚀 Features

- feat: `papaia-ctl backup-delete --restore-point=ID` — delete specific restore points (the snapshot directory and its `backup.yaml` catalogue entry) for cases the age-based `backup --retention-period-days` is too coarse. `--restore-point` is required, repeatable, and accepts comma-separated values; every id is validated against the catalogue before anything is removed, so one unknown id aborts the whole call. The running stack is not touched; each deletion is recorded in `backup.log`

### 🐛 Bug Fixes

- fix(addon): `addon start <name>` now resolves an add-on's compose overrides in `overrides/addons/` by longest registered-name match instead of a `docker-compose.<name>-*.override.yml` glob, so starting an add-on whose name prefixes another's (e.g. `qdrant` vs. `qdrant-ingest`) no longer pulls in the other add-on's override files and aborts with "neither an image nor a build context specified"
- fix(upgrade): `upgrade` now hands off from phase 1 to phase 2 through `"${BASH:-bash}"` instead of `exec`-ing `tools/papaia-ctl` by path, since the preceding `git checkout <tag>` rewrites that tracked file and made the direct `execve()` fail with exit 126 right after "Moving the checkout to <tag>...". `tools/papaia-ctl` is also now tracked executable (`100755`)

### 🧹 Maintenance

- chore: bump papaia-manager to `1.0.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.1.0...v1.2.0

## [1.1.0] - 2026-09-02

### 🚀 Features

- feat: `papaia-ctl restore --only=SELECTOR[,SELECTOR]` — scoped restore. `module:NAME`, `addon:NAME` or `volume:NAME` selectors limit the teardown and the restart to the units the selection touches; everything outside it keeps serving. Backup manifests gain a v2 form recording `project`, `module`, `services` and `profiles` per artifact (v1 manifests still restore as a whole). Refuses `--restart-clean`, a config-directory selection, or a selection that resolves to the `manager` profile

### 🧹 Maintenance

- chore: bump papaia-manager to `0.6.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.0.0...v1.1.0

## [1.0.0] - 2026-08-03

### 🚀 Features

- feat: introduce add-on contract — `papaia-app.yaml` manifest schema, 4 standardised integration seams (network, OIDC, LibreChat-MCP, Ingress)
- feat: full add-on lifecycle in `papaia-ctl` — `addon install`, `addon start`, `addon stop`, `addon remove`, `addon uninstall`
- feat: `papaia-ctl addon check` — pre-upgrade compatibility dry-run against an update candidate (`--target-core=PATH`)
- feat: `ADDON_API` contract-generation window — integer-based compatibility axis independent of the product SemVer (see ADR 0002)
- feat: structural `networks.attach` validation against Core Compose service names
- feat: 3-layer config render (repo base + active add-on fragments + customer overlay)
- feat: per-installation deployment manifest (`deployment.yaml`) as single source of truth for active add-ons and Core profiles
- feat: `papaia-ctl start --addons` / `stop --addons` for full-stack lifecycle including add-ons
- feat: Lean Core — application-specific services removed from Core compose; add-on infrastructure replaces hard-wired service includes
- feat: `papaia-ctl upgrade [--version=X.Y.Z]` — move an installation to a release. Resolves the newest release when no version is given, refuses downgrades, checks active add-ons against the target before anything is touched, takes a restore point, and re-executes itself from the checked-out release so its own render and setup logic applies the change
- feat: release migrations in `tools/migrations/`, run by `upgrade` for every release between the installed and the target version, recorded in `$PAPAIA_CONFIG_DIR/migrations/applied.json` so they never run twice
- feat: `papaia-ctl backup` — hot backup of `PAPAIA_CONFIG_DIR`, all core volumes, and all add-on volumes and data bind mounts into timestamped restore points, with a `backup.yaml` catalogue, `--retention-period-days` pruning, and a result log
- feat: `papaia-ctl restore` — restore a catalogued restore point, with `--list`, `--restore-point`, `--restart-clean` and `--no-restart`. Containers are removed and recreated around the restore, not merely stopped: a stopped container keeps the mount source of every config file it bind-mounts, which the restore replaces
- feat: `PAPAIA_BACKUP_DIR` root variable, settable via `papaia-ctl setup --backup-dir=PATH` and derived as `$PAPAIA_WORKSPACE_DIR/backup`
- feat: `papaia-manager` as an optional core service (profile `manager`) — web UI for the add-on lifecycle plus a dashboard, with native OIDC and role gating via `MANAGER_ADMIN_ROLE` / `MANAGER_USER_ROLE`
- feat: auto-provision Nginx Proxy Manager proxy hosts on start, and `papaia-ctl npm-provision` to run it on demand
- feat: native OIDC for LocalAI, replacing its oauth2-proxy sidecar, gated by the `localai-access` realm role
- feat: select the LocalAI accelerator image variant (CPU / NVIDIA / AMD / Intel / Vulkan) during setup, proposed by a hardware probe of the host

### 🧹 Maintenance

- chore: remove `src/backup-papaia.sh` and `src/restore-papaia.sh`, superseded by the `papaia-ctl` commands
- chore: remove the Homepage service, superseded by papaia-manager, whose dashboard renders from `manager/tiles.yaml`. The add-on contract loses the Homepage seam with it and now has four seams (network, OIDC, LibreChat-MCP, Ingress)
- chore: pin image tags directly in each service's compose file and drop the `*_IMAGE` variables from `src/.env.example`
- chore: bump LocalAI to `v4.7.1`

### 📖 Documentation

- docs: rename and translate architecture specification to `docs/architecture.md` (English)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.8.0...v1.0.0

## [0.8.0] - 2026-06-29

### 🚀 Features

- feat(firecrawl): activate as internal LibreChat scraper (#84)
- feat(mcp-firecrawl): add Firecrawl MCP server to the stack (#86)
- feat(mcp-office-docs): add office-document generation MCP server with minio-backed downloads (#88)
- feat(jinaai): enable jina-reranker-api with env wiring and healthcheck (#89)

### 🧹 Maintenance

- chore: add public-repo hardening files (#78)
- ci(deps): bump hadolint/hadolint-action from 3.1.0 to 3.3.0 (#79)
- ci(deps): bump amannn/action-semantic-pull-request from 5 to 6 (#80)
- ci(deps): bump release-drafter/release-drafter from 6 to 7 (#81)
- ci(deps): bump actions/checkout from 4 to 6 (#82), then from 6 to 7 (#90)
- ci(deps): bump actions/github-script from 7 to 9 (#83)

### 📖 Documentation

- docs: add engineering reference for contributors (#87)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.7.0...v0.8.0

## [0.7.0] - 2026-06-11

### 🚀 Features

- feat: add qdrant-rbac service and LibreChat MCP integration with OIDC token forwarding (#51)
- feat(qdrant-webdav-ingest): add WebDAV → Qdrant ingestion service with MCP interface (#56)
- feat(librechat): optional agents bind-mount from an external directory (#58)
- feat(paperless): make media, export and consume directories configurable (#61)
- feat(paperless): make SSO and login behaviour configurable via .env (#63)
- feat(librechat): optional prompts bind-mount with markdown front matter (#66)
- feat: replace mcp-paperless with oidc-secured paperless-mcp-rbac (#70)

### 🐛 Bug Fixes

- fix(qdrant-rag): consolidate all env vars into root src/.env (#53)
- fix(librechat): defer QdrantRAG MCP init to first per-user call (startup: false) (#54)
- fix: correct qdrant-rbac image name in env example (#72)

### 🛠 Maintenance

- chore: remove doc-rag module from stack (#71)

### 📖 Documentation

- docs: add architecture overview and big-picture diagrams (#59)
- docs: add license and legal documents (#69)
- docs: document v0.7.0 service images in THIRD_PARTY_LICENSES.md (#75, #76)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0

[Unreleased]: https://github.com/Fidonis/papaia/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Fidonis/papaia/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/Fidonis/papaia/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0
