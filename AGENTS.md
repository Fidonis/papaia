# Engineering Reference — papAIa

> Read this document before making any change to this repository.

## Project Overview

**papAIa** is a self-hosted, OIDC-secured Docker Compose platform structured in three
tiers:

- **Lean Core** (always on): Keycloak, oauth2-proxy, Nginx Proxy Manager, LibreChat,
  LiteLLM, LocalAI, Homepage. Self-sufficient — runs without any extension.
- **First-party extensions** (Fidonis-maintained, each in its own repo, version-pinned):
  RAG / vector search (qdrant-rag), documents (Paperless-ngx + MCP bridge), workflow
  automation (n8n), metasearch (SearXNG), web crawling (Firecrawl).
- **Custom extensions** (per-customer, same Extension Contract).

Extensions integrate through five standardised seams — network attachment, OIDC client
registration, LibreChat-MCP fragments, dashboard cards, and Nginx ingress rules — without
requiring changes to any tracked file in the Core repo. The extension manifest
(`papaia-app.yaml`) in each extension repo declares all seams in machine-readable form.

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

papAIa is designed to run in a workspace where extension repos sit alongside the Core
checkout:

```
[workspace root]/
├── papaia/                    ← this repo (read-only at deploy time)
├── extensions/
│   └── papaia-ext-<name>/     ← extension repos cloned alongside (opt-in)
└── papaia-config/             ← PAPAIA_CONFIG_DIR (generated state, never committed)
    ├── deployment.yaml         # installation manifest (active extensions, profiles)
    ├── overlay/                # customer config overrides (highest merge layer)
    └── overrides/              # auto-generated extension network Compose overrides
```

`tools/lib/*.py` only reads from `src/` and writes to `$PAPAIA_CONFIG_DIR` plus the
gitignored `src/**/.env` files — never to any other tracked path in the repo.

### Repo tree

```
tools/
  papaia-ctl                  # Bash dispatcher: setup · start · stop · uninstall · addon
  deployment.template.yaml    # template → $PAPAIA_CONFIG_DIR/deployment.yaml on setup
                              # describes active addons, core profiles, hosting type
  pyproject.toml              # ruff + pytest config for tools/lib
  lib/                        # Python: render_core.py · gen_override.py · bootstrap.py
                              #          common.py · cli.py
  tests/                      # pytest suite (96 tests across bootstrap, common, render_core)
src/
  docker-compose.yml          # Root compose — shared network + include list only
  .env.example                # All stack-wide variables (source of truth for env docs)
  backup-papaia.sh            # Archive all Docker volumes + PAPAIA_CONFIG_DIR
  restore-papaia.sh           # Restore a single named volume from archive
  infra/
    keycloak/                 # OIDC IdP (Java/PostgreSQL)
    nginx/                    # Nginx Proxy Manager (TLS termination)
    oauth2-proxy/             # Forward-auth gateway (Go)
    technitium/               # Optional DNS server
  ai/
    librechat/                # Multi-provider chat interface
    litellm/                  # LLM proxy gateway
    localai/                  # Local inference (CPU / NVIDIA GPU)
    qdrant-rag/               # OIDC + RBAC vector search (MCP, FastMCP/Python)
    qdrant-webdav-ingest/     # WebDAV → Qdrant ingestion worker
    mcp-paperless/            # Per-user Paperless proxy (MCP, Node.js)
    mcp-office-docs/          # Office document generation MCP server
    mcp-firecrawl/            # Firecrawl MCP server
    n8n/                      # Workflow automation
    jinaai/                   # Optional Jina reranker
  services/
    paperless/                # Document management
    homepage/                 # Service dashboard
    searxng/                  # Privacy-respecting metasearch
    firecrawl/                # Web crawler
    minio/                    # S3-compatible object store
    home-assistant/           # Optional home automation
docs/
  papaia-architecture-1.0.0.md  # Full architecture specification (3-tier model,
                                 # Extension Contract, integration seams, manifest schema)
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
  `tools/papaia-ctl setup` / `apps render` via a 3-layer merge:
  ```
  repo base (src/<target>)
    + active addon fragments (<addon-path>/integration/<target>/)
    + customer overlay ($PAPAIA_CONFIG_DIR/overlay/<target>/)
      → $PAPAIA_CONFIG_DIR/<target>
  ```
  Rendering runs on `setup`, on every `start`, and on every `addon` operation.
  `src/sync-config.sh` is the deprecated lower-level predecessor — still present as a
  manual fallback, but not part of the normal operating path.
- `$PAPAIA_CONFIG_DIR/deployment.yaml` — the installation manifest: active addons,
  active Core profiles, platform version, hosting type. Read by `gen_override.py` to
  generate the addon network attachment overrides.
- `$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml` — auto-generated
  by `gen_override.py` for each active extension (Seam-1: network). Never edit manually.

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

Run `make lint` locally before pushing. CI enforces the same checks.

| Language | Tool | Requirement |
|----------|------|-------------|
| Shell (`*.sh`) | shellcheck | `--severity=warning` must pass |
| YAML (`*.yml`, `*.yaml`) | yamllint | Project `.yamllint` config must pass |
| Dockerfiles | hadolint | Project ignore list in CI must pass |
| Python (`tools/lib/*.py`) | ruff (`tools/pyproject.toml`) | Run locally — not yet wired into CI |

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
- [docs/papaia-architecture-1.0.0.md](docs/papaia-architecture-1.0.0.md) — full
  architecture specification: 3-tier model, Extension Contract, integration seams,
  extension manifest schema, deployment manifest
- [SECURITY.md](SECURITY.md) — security reporting policy and scope
- [CHANGELOG.md](CHANGELOG.md) — release history
