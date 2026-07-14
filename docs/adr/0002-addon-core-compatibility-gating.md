---
adr: 0002
title: Gate addon compatibility on a contract generation, not the product version
status: Accepted
date: 2026-07-14
deciders:
  - marko-boehm
tags:
  - addons
  - tooling
  - versioning
supersedes: null
superseded_by: null
---

# 0002. Gate addon compatibility on a contract generation, not the product version

## Context

The addon manifest declares `papaia_compat: ">=0.8.0"`, and the architecture
documentation promises that the orchestrator refuses incompatible core/addon
combinations — but nothing in `tools/` ever read the field. A core upgrade
could silently break every installed addon, and no command answered, *before*
an update: "which addons break if the core moves to X?"

Two defects blocked naive enforcement:

1. `resolve_platform_version()` derived the platform version from the first
   released CHANGELOG header and reported `0.7.0` while the repository was
   tagged `v0.8.0`. The core claimed to be older than it is, so enforcing
   `>=0.8.0` would have rejected the only shipped addon.
2. The product version is a weak proxy for what addons actually depend on.
   A core service rename (`nginx` → `nginx-proxy-manager`) broke the
   `networks.attach:` seam without any major version bump (see
   papaia-addons commit `869dec7`), while a hypothetical breaking product
   release might not touch a single seam and would lock addons out for no
   reason. Kubernetes, Docker plugins, and GNOME Shell extensions all
   separate the machine contract version from the product version for
   exactly this reason.

## Decision

- **`VERSION` file** at the repo root is the single source of truth for the
  platform version. Resolution order: `VERSION` → first released CHANGELOG
  header → `0.0.0-dev`. No `git describe`: the core must work from a tarball
  without `.git`, offline. The manual release-time bump is guarded by a test
  asserting `VERSION` is never behind the newest CHANGELOG header.
- **`ADDON_API` file** at the repo root declares the served contract window
  (`current`, `min`). It only moves when one of the five addon seams
  changes — a breaking seam change sets `current += 1, min = current`; an
  additive one bumps `current` only. It is a static file (not a Python
  constant) so `addon check --target-core=PATH` can read it from a foreign
  candidate checkout or unpacked tarball.
- **Addons declare `requires.addon_api`** — the integer generation they are
  built against, or a list of generations they serve. A range (`">=1"`) was
  rejected: an unbounded upper bound would implicitly claim compatibility
  with future generations whose breaking change is precisely what the axis
  exists to catch. Compatible iff the declared set intersects `[min..current]`.
- **Evaluation precedence** per addon: `requires.addon_api` (authoritative,
  when the core exposes a window) → `papaia_compat` SemVer range against the
  platform version (keeps pre-contract addons working) → `UNKNOWN`, which
  warns and never hard-fails. The core never hard-requires the new field —
  this is what lets the core and addon repositories release independently.
- **Structural `attach:` validation**: the core's service names are resolved
  from `src/docker-compose.yml` (include-walk) and every `networks.attach`
  entry is checked against them. The service-rename class of breakage is
  thereby caught mechanically, without anyone remembering a version bump.
  Absent compose file → the check is skipped (fail-open, e.g. synthetic
  test contexts). A contract-surface snapshot test freezes the attachable
  services, render targets, manifest keys, and secret alias map, forcing a
  conscious `ADDON_API` bump or snapshot update on every surface change.
- **Gates** run at `addon install`, `addon start`, and core `start`, before
  anything is mutated or brought up. Policy: **hard-fail in production,
  warn in dev mode** (`PAPAIA_COMPAT_MODE` env → `deployment.yaml` `mode:` →
  default `enforce`). `--force` degrades `INCOMPATIBLE` to a warning;
  malformed manifests (`ERROR`) stay fatal — a broken manifest is a bug,
  not a policy call. Exit code `2` for `INCOMPATIBLE`/`ERROR`, matching the
  existing precondition-failure convention.
- **`papaia-ctl addon check`** answers the pre-update question: evaluate all
  active addons against the current core, or against an update candidate via
  `--target-core=PATH` (reads the target's `VERSION`, `ADDON_API`, and
  compose services), with `--target-version` / `--target-addon-api` as
  honest manual fallbacks and `--json` for fleet tooling.
- **Stdlib-only SemVer comparator** (`tools/lib/semver.py`): `tools/`
  deliberately depends on PyYAML only, so it stays installable offline; a
  `packaging`/`semver` dependency would break that. The comparator covers
  the documented subset (`>= > < <= == !=`, caret, tilde, comma-AND,
  pre-releases) and is exhaustively unit-tested.

## Consequences

- **Positive**: fleet updates can be verified before switching the checkout;
  the rename class of seam breaks is caught structurally and in CI; the two
  repositories keep releasing independently; the shipped addon stays
  compatible without manifest changes.
- **Negative**: `VERSION` and `ADDON_API` are manual bumps (both guarded by
  tests); a single integer cannot express per-seam versions ("seam 3 at v2,
  seam 1 at v1").
- **Neutral**: `requires:` is a map, so a later ascent to per-capability
  negotiation is additive; `papaia_compat` remains as documented fallback
  vocabulary.

## Alternatives considered

- **Gate on `platform_version` only** — misses seam breaks that ship without
  a major bump and locks addons out on majors that touch no seam.
- **Full capability negotiation (per-seam versions)** — over-engineering at
  the current scale (five seams, one addon); most seams are not meaningfully
  schematizable. Deliberately deferred, not precluded.
- **Compatibility matrix / registry** — couples releases across repos and
  contradicts the decoupling requirement.
- **Lockfile** — records what *was* installed; does not answer whether the
  *next* core breaks it.
- **Post-update runtime smoke tests** — complementary, but the requirement
  is a verdict *before* the update.
- **"Every seam break is a product MAJOR"** — makes the product version a
  hostage of the internal contract; the ecosystems cited above split the two
  for good reason.

## References

- `docs/papaia-architecture-1.0.0.md` §6.2 (manifest schema), §7 (the five
  seams), §16 (resolves the "compat policy strictness" open point)
- [ADR 0001](./0001-record-architecture-decisions.md)
- papaia-addons commit `869dec7` (attach service rename — the motivating
  seam break)
