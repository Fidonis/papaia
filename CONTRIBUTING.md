# Contributing to papAIa

Thanks for considering a contribution to papAIa! This document describes how to file issues, propose changes, and what we expect from contributors.

## Code of Conduct

Everyone taking part in this project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to `security@fidonis.de`.

## Where to ask questions

- **General questions, ideas, brainstorming** - [GitHub Discussions](https://github.com/Fidonis/papaia/discussions)
- **Bugs, feature requests, documentation issues** - [GitHub Issues](https://github.com/Fidonis/papaia/issues), using the [issue templates](https://github.com/Fidonis/papaia/issues/new/choose)
- **Security vulnerabilities** - use [Private vulnerability reporting](https://github.com/Fidonis/papaia/security/advisories/new) instead of a public issue

## Reporting bugs and requesting features

We use GitHub Issue Forms. When you click *New issue*, you will see four entry points:

- **Bug report** - for reproducible bugs
- **Feature request** - for new functionality or enhancements
- **Documentation** - for missing, wrong, or unclear docs
- **Question / Discussion** (link) - redirects to Discussions

Each form prefills the right labels and structure, so please use them rather than blank issues.

## Pull request workflow

1. Open or comment on the issue you intend to work on, so duplicate effort can be avoided.
2. Fork the repository and create a feature branch from `main`. Suggested branch naming:
   - `feat/<short-name>` for new features
   - `fix/<short-name>` for bug fixes
   - `docs/<short-name>` for documentation
   - `ci/<short-name>` for CI/CD changes
   - `chore/<short-name>` for maintenance
3. Make your change in small, reviewable commits.
4. Open a pull request against `main`. The repository's PR template is filled in automatically; please complete each section, especially **Linked issues**, **Type of change**, and **Test plan**.
5. CI will run lint, tests, the license, word and secret checks, the build and vulnerability scan of the own images and the PR-title check. Address any failures. Once green, request a review.
6. PRs are merged via **Squash & Merge**. The PR title becomes the squash commit message - make sure it follows Conventional Commits (see below).

## Commit and PR title convention

We use [Conventional Commits](https://www.conventionalcommits.org/) for PR titles, which are squashed into the merge commit. This drives release notes (via release-drafter) and version bumps automatically.

Format: `<type>[(<scope>)][!]: <subject>`

| Type | Use for |
|---|---|
| `feat` | New user-facing feature (minor version bump) |
| `fix` | Bug fix (patch version bump) |
| `docs` | Documentation changes |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `style` | Formatting only, no code change |
| `test` | Adding or fixing tests |
| `ci` | CI configuration |
| `build` | Build system / dependencies |
| `chore` | Maintenance tasks |
| `revert` | Reverts a previous commit |

Examples:

- `feat: add Keycloak SSO for SearXNG`
- `fix(librechat): resolve healthcheck IPv6 binding`
- `docs: clarify env-var usage in deployment guide`
- `feat!: drop support for Docker Compose v1`

A `!` after the type or scope marks a **breaking change** and triggers a major version bump.

The subject must be lowercase, in imperative mood (*"add"*, not *"added"* or *"adds"*), without a trailing period.

A CI check enforces this on PR titles.

## Code style

Linters run on every push and pull request:

- **Shell scripts** - [shellcheck](https://www.shellcheck.net/)
- **YAML** - [yamllint](https://yamllint.readthedocs.io/)
- **Dockerfiles** - [hadolint](https://github.com/hadolint/hadolint)
- **Python** - `ruff check` and `pytest` in `tools/`

Please run them locally before pushing if you can. Configuration lives in `.github/workflows/ci.yml`.

**Python** (`tools/lib/*.py`) - [ruff](https://docs.astral.sh/ruff/) (config in `tools/pyproject.toml`) and `pytest` (`tools/tests/`). CI runs `ruff check` and the full suite; run them locally before pushing changes under `tools/`:

    cd tools
    uv run --locked --extra dev python -m ruff check lib tests
    uv run --locked --extra dev python -m pytest tests/

### Test shards in CI

CI runs the suite as parallel shards, one job `pytest (<shard>)` each, defined in `tools/tests/shards.toml`: every shard lists test file names or globs, and the catch-all shard (`catch_all`) also takes every file no other shard names. The job "Test shards cover the suite" collects the whole suite first and fails when a collected test is in no shard or in two, or when a shard names a file that does not exist; it prints the test count per shard and in total. The required check "Ruff and pytest" passes only when ruff, that job and every shard passed. A shard runs its files whole: no deselection, no `-k`, `-m` or `--ignore`.

- **A new test file** needs nothing: it runs in the catch-all shard. If it takes more than about a minute in CI, give it to a shard with room (the comment above the matrix in `.github/workflows/ci.yml` lists the measured duration of each shard), or add a shard.
- **A new shard** is a `[shards.<name>]` table in `shards.toml` and an entry with the same name in the matrix of the job `pytest`: its `timeout` (about twice its measured duration on a GitHub-hosted runner, at most 30 minutes), its address pool `subnets` (a private /16 no other shard uses) and the tools it needs (`compose`, `haproxy`, `gitleaks`). `tests/test_ci_shards.py` checks that both lists agree and that a file using one of the tools sits in a shard that installs it.
- **One shard locally**: `uv run --locked --extra dev python -m pytest -rs $(python3 tests/shard_check.py files <shard>)` from `tools/`; `python3 tests/shard_check.py check` runs the coverage check.

Docker live tests never use a fixed Compose project or subnet by default, so two shards or two local runs can share one Docker host. `tools/tests/live_names.py` names each project `<prefix>-<test>-<session>` (the session is `<GITHUB_RUN_ID>-<shard>-<pid>` in CI, a random value with the process id otherwise; the prefix is `PAPAIA_TEST_PROJECT_PREFIX`, default `papaia`) and hands every live module its own address block from `PAPAIA_TEST_SUBNET_POOL` (default `10.240.0.0/12`, blocks of `/PAPAIA_TEST_SUBNET_SIZE`, default 24): never one that overlaps a Docker network of the host or a block another running session holds (claim files in the temporary directory). The per-module variables (`PAPAIA_EGRESS_TEST_PROJECT`, `PAPAIA_EGRESS_TEST_SUBNET` and so on) still override the defaults. Every live test removes only the Compose project and the objects it created.

The golden snapshot (`tools/tests/test_golden_single_node.py`) compares `docker compose config` only with the Compose release it records; CI installs that release. Every image bump, including the ones Dependabot proposes, changes that snapshot: regenerate it on the pull request's branch with `PAPAIA_UPDATE_GOLDEN=1 uv run --locked --extra dev python -m pytest tests/test_golden_single_node.py` (from `tools/`) before merging. The realm sync's output for fixed declarations (changes it reports, clients, scopes and realm defaults it leaves) is pinned the same way in `tools/tests/golden/realm-sync.json`; regenerate it with `PAPAIA_UPDATE_GOLDEN=1` and `tests/test_realm_sync_golden.py` only for an intended change of that output. `ruff format` is not enforced.

The core's own images (`compat/own-images.yaml`) are pinned by the digest their inputs build to. A change to one of their declared inputs (Dockerfile, program, notice file), to `LICENSE` or to `VERSION` therefore needs a rebuild and a new pin in the same pull request: commit the change, then `tools/build-images build --registry=<prefix of a test registry> --out=builds.json` and `tools/build-images pin --builds=builds.json`, and commit the pins (see [`docs/compatibility.md`](docs/compatibility.md#own-images-of-the-core)). `tools/build-images check` runs without Docker.

### Load runs

A test that starts real processes must not pass or fail because the host is slow. Its subprocesses and waits share one deadline, `tools/tests/hang_guard.py` (900 s by default), which only stops a hang and never decides a pass; raise it on a slow host with `PAPAIA_TEST_HANG_GUARD_SECONDS` (above 0, at most 14400). With `PAPAIA_REQUIRE_OWN_IMAGE_BUILD=1`, a Docker probe of `tests/test_own_images_registry.py` that runs out of this deadline fails with its measured duration instead of skipping.

To check a test under load, run it next to the CPU-burn helper (from `tools/`):

    nice -n 19 python3 tests/helpers/cpu_burn.py --seconds=1500 &
    PAPAIA_REQUIRE_OWN_IMAGE_BUILD=1 uv run --locked --extra dev --with pytest-xdist==3.6.1 \
        python -m pytest -n auto -q -rfEs tests/test_rollback_cli.py tests/test_rollback_key.py \
        tests/test_own_images_registry.py

The helper keeps at most half of the cores busy (`os.cpu_count() // 2`, at least 1; that is also its default), runs every process at niceness 19, stops after `--seconds` (at most 1800, 30 minutes) and stops its processes on exit, SIGINT and SIGTERM. Repeat the test run (for example 20 times) while the helper runs; start a new helper for a longer series.

### Repository checks

Six more CI jobs guard every pull request. They use the platform's shared contract package `papaia-kit`, vendored as its release wheel under `tools/vendor/papaia-kit/<version>/` and pinned by sha256 in `tools/kit.lock` and `tools/uv.lock`; it is a development dependency only (Python 3.12) and never part of `papaia-ctl` or an image.

- **Kit release and suite kit versions** - the files the core copies from the vendored kit release (the contract schemas under `tools/schemas/kit/` with `snapshot.json`, and the naming register `tools/lib/names_register.json`) must be exactly what `tools/kit_snapshot.py` builds from it; nothing in them is edited by hand. The kit versions of the candidate suite (`compat/suite-kit.yaml`) must pass the kit's suite check `pk-check bom`. To move to a new kit release: rebuild its wheel and source tarball from the release commit with the kit's release build, put them under `tools/vendor/papaia-kit/<version>/`, take `tools/kit.lock` from the release, bump the pin and path in `tools/pyproject.toml`, run `uv lock --upgrade-package papaia-kit`, then write the snapshots and set the core's entry (`kit` and `kit_build`: version, commit, wheel sha256) in `compat/suite-kit.yaml`.

      cd tools
      uv run --locked --extra dev python kit_snapshot.py write   # or: check
      uv run --locked --extra dev pk-check bom ../compat/suite-kit.yaml

- **License check** - every package of `tools/uv.lock` and the base image of the own images (`licenses/base-images.json`) against the kit's license policy. Packages with missing or ambiguous metadata carry a `[[verified]]` entry with its source in `license-exceptions.toml`; an exception for a weak-copyleft package needs an ADR and an approval. The job also checks that a seeded package under a forbidden license is rejected.

      cd tools
      uv run --locked --extra dev papaia-kit licenses check --python-project . \
          --records ../licenses/base-images.json --exceptions ../license-exceptions.toml

- **Word check** - tool and vendor names that do not belong in this repository. Product vocabulary that existed before the check (the chat interface's feature names, the provider API's name) is frozen in `words-baseline.toml` with its location and reason: a listed line passes, every new hit fails, and an entry whose line is gone fails until it is removed. Do not add entries to make a check pass; a new entry needs a review and its own reason.

      uv run --locked --extra dev --project tools papaia-kit repo words --root . --baseline words-baseline.toml

- **Secret scan** - gitleaks (version and sha256 pinned in the workflow) over the full history with `.gitleaks.toml`, whose narrow allow lists cover values that are no secret by construction (file digests of the golden snapshots, the unsigned test token without claims, canary labels in the tests). The reviewed findings of the history are listed in `.gitleaksignore`, one fingerprint each with its reason; the history is not rewritten. A value that was ever committed counts as public and is rotated, never listed as if it were still secret.

- **Own images** (`.github/workflows/images.yml`) - builds every image of `compat/own-images.yaml` for linux/amd64 and linux/arm64 into a registry inside the job, scans each platform of the built digest with a pinned Trivy image and keeps the reports and the CycloneDX SBOMs as an artefact. It applies the image scan rule ([`docs/compatibility.md`](docs/compatibility.md#image-scan-rule)): a critical or high finding with a fix fails; for an own image only a high one can be excepted, by an entry in `security/exceptions.yaml` (id, package, reason, expiry at most 90 days ahead, approval of the security officer). A critical or high finding without a fix passes and is listed in `no-fix.txt` of the `images-report` artefact and counted in the step summary; the list is reviewed monthly. An expired entry, an entry that only covers findings without a fix and an unknown field fail. The job also checks that a seeded critical and a seeded high finding with a fix are rejected and that seeded findings without a fix pass and are listed, and warns when the built digests differ from the compose pins. It runs again every night.

      tools/build-images build --registry=127.0.0.1:5000/unpublished/ --out=builds.json
      tools/scan-images scan --builds=builds.json --out=scan/ --summary=summary.md
      tools/scan-images check

- **Static checks** - the kit's static suite over the code that runs on an installation (`tools/lib`, `tools/migrations`, `src`): no evaluation or subprocess with a command built at runtime, no query text assembled at runtime, no exchange scope (`aud-<audience>`) built from strings, no hard-coded model name. Exchange scopes come from the kit only: the naming register snapshot `tools/lib/names_register.json` carries the scope of every registered audience as the vendored kit builds it (section `exchange_scopes`), `tools/lib/kit_names.py` reads it, and `tests/test_kit_names.py` checks it against the vendored kit. A remaining finding passes only through an entry of `static-exceptions.toml` that names its place (file, enclosing function, subject, count), where its input comes from (`fixed` or `operator-config`; a value a person, an event or a model feeds is never an exception), a reason and an expiry date. The job runs with `--require-approved`: an entry passes only once the security officer has countersigned it (`approved_by` names the security officer and no longer says pending). A stale, expired or miscounted entry fails as well.

      uv run --locked --extra dev --project tools papaia-kit conformance static \
          --root . --require-approved tools/lib tools/migrations src

## Local development

See [`docs/deployment.md`](./docs/deployment.md) (work in progress) for local setup. The short version:

    tools/papaia-ctl setup       # interactive by default; --non-interactive + --*-host flags for CI/scripted use
    tools/papaia-ctl start

`setup` generates secrets, derives the OIDC issuer and per-service hostnames, and renders every config file into the external `PAPAIA_CONFIG_DIR` — see the root [README's Quick start](./README.md#quick-start) for the full flag reference.

## Documentation contributions

The `docs/` directory and the `docs/adr/` Architecture Decision Records are the home of long-form documentation. ADRs follow the template at [`docs/adr/0000-template.md`](./docs/adr/0000-template.md).

For docs-only changes, you can use the **Documentation** issue template.

## License of your contributions (Inbound = Outbound)

This project is published under the [MIT license](LICENSE). By submitting a pull request, comment with a code suggestion, or any other contribution to this repository, **you agree that your contribution is licensed under the same MIT license** that the project itself uses ("Inbound = Outbound"). No separate Contributor License Agreement (CLA) is required.

You also confirm that:

- You have the right to license the contribution under MIT - either because you wrote it yourself, or because the original author has explicitly licensed it under a compatible permissive license (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC) and you preserve the original attribution.
- Your contribution does not knowingly infringe a third party's copyright, patent or trademark.

### Copyleft licenses are not accepted

To keep the project freely redistributable under MIT, **contributions containing or directly depending on code under a copyleft license are not accepted** without prior written approval from the Fidonis management. This includes (non-exhaustive list):

- GNU General Public License (GPL), any version
- GNU Lesser General Public License (LGPL), any version
- GNU Affero General Public License (AGPL), any version
- Mozilla Public License (MPL) 2.0 when used in a way that would make the project a covered work
- Server Side Public License (SSPL)
- Open Software License (OSL)
- European Union Public Licence (EUPL)

If you believe an exception is justified, please open an issue first to discuss it before opening the PR.

## Trademarks

"Fidonis" and "papAIa" are trademarks of Fidonis GmbH (in Gruendung). See [TRADEMARK.md](TRADEMARK.md) for the rules on how you may and may not use them. The MIT license grants you broad rights to the code; the trademark notice governs the project's name and identity.

---

Thanks again for contributing!