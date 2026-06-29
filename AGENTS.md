# Engineering Reference — papAIa

> Read this document before making any change to this repository.

## Project Overview

**papAIa** is a self-hosted, OIDC-secured Docker Compose stack that combines
LLM services (LiteLLM, LibreChat, LocalAI), document management (Paperless-ngx,
qdrant-rag), workflow automation (n8n), and supporting infrastructure (Keycloak,
oauth2-proxy, Nginx Proxy Manager, SearXNG, Homepage).

The repository is **configuration-as-code only** — no upstream service source
code lives here. Changes are almost always YAML, shell scripts, or documentation.

## Hard Constraints

Non-negotiable. Any change that violates them must be rejected and undone.

1. **Never commit `.env` files.** Secrets live only in untracked `.env` files.
2. **Never commit generated Keycloak realm JSON**
   (`src/infra/keycloak/realm-import/papaia-realm.json`) — it contains live
   secrets after a setup run.
3. **Never commit private keys, API tokens, or credentials** of any kind.
4. **Never push directly to `main`.** All changes go through a PR.
5. **PR titles must follow Conventional Commits** — CI enforces this strictly.
6. **Never force-push to shared branches** (`main`, `releases/*`).
7. **Before pushing changes that touch secrets-adjacent files**, run:
   `git diff --cached | grep -iE "(password|token|secret|api[_-]?key|bearer)"`
   and review every match.

## Repository Structure

```
src/
  docker-compose.yml          # Root compose — shared network + include: list only
  .env.example                # All stack-wide variables (source of truth for env docs)
  sync-config.sh              # Populate $PAPAIA_CONFIG_DIR with defaults (non-destructive)
  backup-papaia.sh            # Archive all Docker volumes + config dir
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
    mcp-firecrawl/            # Firecrawl MCP server
    n8n/                      # Workflow automation
    jinaai/                   # Optional Jina reranker
  services/
    paperless/                # Document management
    homepage/                 # Service dashboard
    searxng/                  # Privacy-respecting metasearch
    firecrawl/                # Web crawler
    home-assistant/           # Optional home automation
docs/
  architecture.md             # Service catalog and full architecture diagram
  adr/                        # Architecture Decision Records
  deployment.md               # Deployment guide
  configuration.md            # Configuration reference
.github/
  workflows/ci.yml            # Lint (shellcheck, yamllint, hadolint) + PR-title check
  ISSUE_TEMPLATE/             # Bug / Feature / Docs issue forms
  PULL_REQUEST_TEMPLATE.md    # PR body template
```

### Compose architecture pattern

- The **root `docker-compose.yml`** declares only the shared Docker network and
  an `include:` list — no service definitions.
- Each subdirectory ships its own `docker-compose.yml` with `profiles:` declarations.
- Optional modules are toggled via `COMPOSE_PROFILES` in `src/.env`.
- Every `${VAR}` substitution in a compose file **must** be documented in the
  corresponding `.env.example`.

### Configuration management

- `src/.env` — stack-wide secrets and settings (gitignored, generated from
  `src/.env.example`)
- Per-service `.env` files in subdirectories — service-specific secrets
  (all gitignored)
- `$PAPAIA_CONFIG_DIR` — operator-editable config files populated once by
  `sync-config.sh`; survives `git pull` because `sync-config.sh` is
  non-destructive

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
- [docs/architecture.md](docs/architecture.md) — service catalog and architecture
- [SECURITY.md](SECURITY.md) — security reporting policy and scope
- [CHANGELOG.md](CHANGELOG.md) — release history
