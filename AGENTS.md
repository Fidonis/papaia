# Engineering Reference — papAIa

> Read this document before making any change to this repository.

## Project Overview

**papAIa** is a self-hosted, OIDC-secured Docker Compose platform structured in three
tiers:

- **Lean Core**: Keycloak, oauth2-proxy, Nginx Proxy Manager, LibreChat and LiteLLM
  always on; LocalAI and papaia-manager opt-in via their Compose profiles.
  Self-sufficient — runs without any add-on.
- **First-party add-ons** (Fidonis-maintained, version-pinned, installed by path):
  documents (Paperless-ngx + MCP bridge), RAG / vector search (qdrant-rag), workflow
  automation (n8n).
- **Custom add-ons** (per-customer, same add-on contract).

Add-ons integrate through four standardised seams — network attachment, OIDC client
registration, LibreChat-MCP fragments, and Nginx ingress rules — without
requiring changes to any tracked file in the Core repo. A fifth, non-seam mechanism
(`local_ca_env`) lets an add-on declare which of its variables point at the bundled
Keycloak CA, so `papaia-ctl` can clear them for an external OIDC issuer. The add-on
manifest (`papaia-app.yaml`) declares all of it in machine-readable form.

The repository is **configuration-as-code only** — no upstream service source code lives
here. Changes are almost always YAML, shell scripts, or documentation.

## Hard Constraints

Non-negotiable. Any change that violates them must be rejected and undone.

1. **Never commit `.env` files.** Secrets live only in untracked `.env` files.
2. **Never commit generated Keycloak realm JSON**
   (`src/infra/keycloak/realm-import/papaia-realm.json`) — it contains live secrets
   after a setup run.
3. **Never commit private keys, API tokens, or credentials** of any kind.
4. **Never push directly to `main`.** All changes go through a PR.
5. **PR titles must follow Conventional Commits** — CI enforces this strictly.
6. **Never force-push to shared branches** (`main`, `releases/*`).
7. **Before pushing changes that touch secrets-adjacent files**, run:
   `git diff --cached | grep -iE "(password|token|secret|api[_-]?key|bearer)"`
   and review every match.

## Repository Structure

### Workspace topology

papAIa is designed to run in a workspace where add-on repos sit alongside the Core
checkout:

```
[workspace root]/
├── papaia/                    ← this repo (read-only at deploy time)
├── papaia-addons/
│   └── <name>/                ← add-ons cloned alongside (opt-in)
└── papaia-config/             ← PAPAIA_CONFIG_DIR (generated state, never committed)
    ├── deployment.yaml         # installation manifest (active add-ons, profiles)
    ├── overlay/                # customer config overrides (highest merge layer)
    └── overrides/              # auto-generated add-on network Compose overrides
```

`tools/lib/*.py` only reads from `src/` and writes to `$PAPAIA_CONFIG_DIR` plus the
gitignored `src/**/.env` files — never to any other tracked path in the repo.

### Repo tree

```
tools/
  papaia-ctl                  # Bash dispatcher: setup · start · stop · upgrade · addon · …
  deployment.template.yaml    # template → $PAPAIA_CONFIG_DIR/deployment.yaml on setup
                              # describes active addons, core profiles, hosting type
  pyproject.toml              # ruff + pytest config for tools/lib
  lib/                        # Python: cli.py · cli_addon.py · deployment.py · envtree.py
                              #   secrets.py · resolve.py · addons.py · defaults.py · reporting.py
                              #   compat.py · semver.py · render_core.py · gen_override.py
                              #   backup.py · upgrade.py · migrations.py · npm_provision.py
                              #   common.py
    sh/                       # Bash command libraries sourced by papaia-ctl
  migrations/                 # Release migrations run by `papaia-ctl upgrade`
                              #   <x.y.z>__<slug>.sh|.py — contract in its README
  tests/                      # pytest suite (mirrors the lib/ modules)
src/
  docker-compose.yml          # Root compose — shared network + include list only
  .env.example                # All stack-wide variables (source of truth for env docs)
  sync-config.sh              # Deprecated low-level config-dir seeding; manual fallback
  README.md                   # Compose-level orchestration notes
  infra/
    keycloak/                 # OIDC IdP (Java/PostgreSQL)
    nginx/                    # Nginx Proxy Manager (TLS termination) + admin-UI sidecar
    oauth2-proxy/             # Forward-auth gateway (Go)
  ai/
    README.md                 # Per-AI-service summary
    librechat/                # Multi-provider chat interface
    litellm/                  # LLM proxy gateway
    localai/                  # Local inference (CPU / NVIDIA GPU)
    mcp-firecrawl/            # Firecrawl MCP server
    jinaai/                   # Optional Jina reranker
  manager/                    # papaia-manager — addon lifecycle UI (image-based, profile: manager)
  services/
    searxng/                  # Privacy-respecting metasearch
    firecrawl/                # Web crawler
docs/
  architecture.md                # Full architecture specification (3-tier model,
                                 # add-on contract, integration seams, manifest schema)
  configuration.md              # Environment variable reference
  deployment.md                 # Deployment guide
  troubleshooting.md            # Common issues and fixes
  adr/                          # Architecture Decision Records
.github/
  workflows/ci.yml            # Lint (shellcheck, yamllint, hadolint) + PR-title check
  ISSUE_TEMPLATE/             # Bug / Feature / Docs issue forms
  PULL_REQUEST_TEMPLATE.md    # PR body template
```

### Compose architecture pattern

- The **root `docker-compose.yml`** declares only the shared Docker network and an
  `include:` list — no service definitions live there.
- Each subdirectory ships its own `docker-compose.yml` with `profiles:` declarations.
- Optional modules are toggled via `COMPOSE_PROFILES` in `src/.env`.
- Every `${VAR}` substitution in a compose file **must** be documented in the
  corresponding `.env.example`.

### Configuration management

- `src/.env` — stack-wide secrets and settings (gitignored, generated from
  `src/.env.example`)
- Per-service `.env` files in subdirectories — service-specific secrets (all gitignored)
- `$PAPAIA_CONFIG_DIR` — operator-editable config files, populated and kept in sync by
  `tools/papaia-ctl setup` / `start` via a 3-layer merge:
  ```
  repo base (src/<target>)
    + active addon fragments (<addon-path>/integration/<target>/)
    + customer overlay ($PAPAIA_CONFIG_DIR/overlay/<target>/)
      → $PAPAIA_CONFIG_DIR/<target>
  ```
  Rendering runs on `setup`, on every `start`, and on every `addon` operation. There is
  no separate render command. `src/sync-config.sh` is the deprecated lower-level
  predecessor — still present as a manual fallback, but not part of the normal
  operating path.
- `$PAPAIA_CONFIG_DIR/deployment.yaml` — the installation manifest: active addons,
  active Core profiles, platform version, hosting type. Read by `gen_override.py` to
  generate the addon network attachment overrides.
- `$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml` — auto-generated
  by `gen_override.py` for each active add-on (Seam-1: network). Never edit manually.

## Branch Strategy

| Prefix | Purpose |
|--------|---------|
| `feat/<short>` | New user-facing functionality |
| `fix/<short>` | Bug fix |
| `docs/<short>` | Documentation changes |
| `chore/<short>` | Maintenance / housekeeping |
| `ci/<short>` | CI/CD configuration |
| `refactor/<short>` | Refactoring without behavior change |
| `test/<short>` | Adding or fixing tests |

- `<gh-handle>/<short>` — personal scratch branches; may be force-pushed freely,
  never merged directly.
- Feature branches are deleted after merge. `main` and `releases/*` are permanent.
- Squash-merge only. The PR title becomes the commit message on `main`.

## Commit & PR Conventions

PR title format: `<type>[(<scope>)][!]: <subject>`

Subject: lowercase, imperative mood, no trailing period.

Examples:

```
feat: add firecrawl MCP service
fix(librechat): resolve healthcheck IPv6 binding
docs: clarify env-var usage
feat!: drop support for Docker Compose v1
```

PR body must include all sections from the template:

| Section | Content |
|---------|---------|
| **Summary** | What changed and why |
| **Linked issues** | `Closes #N` |
| **Type of change** | Checkbox from template |
| **Test plan** | Concrete verification steps taken |

## Linting & Code Style

Run the linters locally before pushing; `.github/workflows/ci.yml` runs the same
checks on every push and pull request.

| Language | Tool | Requirement |
|----------|------|-------------|
| Shell (`*.sh`, `tools/papaia-ctl`) | shellcheck | `--severity=warning` must pass |
| YAML (`*.yml`, `*.yaml`) | yamllint | Project `.yamllint` config must pass |
| Dockerfiles | hadolint | Project ignore list in CI must pass |
| Python (`tools/lib/*.py`) | ruff + pytest (`tools/pyproject.toml`) | Run locally — not yet wired into CI |

```sh
shellcheck --severity=warning tools/papaia-ctl tools/lib/sh/*.sh src/*.sh
yamllint .
cd tools && ruff check lib tests && pytest tests/
```

Shell conventions:
- `set -euo pipefail` at the top of every script
- Prefer `[[` over `[`
- Always quote variables: `"$var"`, not `$var`

YAML conventions:
- Two-space indent
- Quote values only when syntactically required

General:
- LF line endings (`.gitattributes` enforces)
- No trailing whitespace (`.editorconfig` enforces)
- Comments explain *why*, not *what*

## Security Checklist

Before any push:

- [ ] No `.env` files staged
- [ ] No `src/infra/keycloak/realm-import/papaia-realm.json` staged
- [ ] No secrets, tokens, or credentials in the diff
- [ ] All `.env.example` placeholder values use `__GENERATED__` or `CHANGE_ME`
- [ ] No customer-specific configuration committed

## Issue Routing

- Bugs, feature requests, documentation issues → file here (`Fidonis/papaia`)
- Questions, ideas → use **Discussions**, not Issues
- Security vulnerabilities → **Private Vulnerability Reporting**
  (see `SECURITY.md`), never public Issues

Issue titles must use the template prefix (`[Bug]:`, `[Feature]:`, `[Docs]:`).

## Further Reading

- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution workflow and PR checklist
- [docs/architecture.md](docs/architecture.md) — full
  architecture specification: 3-tier model, add-on contract, integration seams,
  add-on manifest schema, deployment manifest
- [SECURITY.md](SECURITY.md) — security reporting policy and scope
- [CHANGELOG.md](CHANGELOG.md) — release history
