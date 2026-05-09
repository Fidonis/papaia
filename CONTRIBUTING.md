# Contributing to papAIa

Thanks for considering a contribution to papAIa! This document describes how to file issues, propose changes, and what we expect from contributors.

## Code of Conduct

A formal Code of Conduct is being added — see [#23](https://github.com/Fidonis/papaia/issues/23). In the meantime, please follow common sense: be kind, assume good intent, and keep discussions focused on the project.

## Where to ask questions

- **General questions, ideas, brainstorming** → [GitHub Discussions](https://github.com/Fidonis/papaia/discussions)
- **Bugs, feature requests, documentation issues** → [GitHub Issues](https://github.com/Fidonis/papaia/issues), using the [issue templates](https://github.com/Fidonis/papaia/issues/new/choose)
- **Security vulnerabilities** → use [Private vulnerability reporting](https://github.com/Fidonis/papaia/security/advisories/new) instead of a public issue

## Reporting bugs and requesting features

We use GitHub Issue Forms. When you click *New issue*, you'll see four entry points:

- **Bug report** — for reproducible bugs
- **Feature request** — for new functionality or enhancements
- **Documentation** — for missing, wrong, or unclear docs
- **Question / Discussion** (link) — redirects to Discussions

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
5. CI will run lint and PR-title checks. Address any failures. Once green, request a review.
6. PRs are merged via **Squash & Merge**. The PR title becomes the squash commit message — make sure it follows Conventional Commits (see below).

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

- **Shell scripts** — [`shellcheck`](https://www.shellcheck.net/)
- **YAML** — [`yamllint`](https://yamllint.readthedocs.io/)
- **Dockerfiles** — [`hadolint`](https://github.com/hadolint/hadolint)

Please run them locally before pushing if you can. Configuration lives in `.github/workflows/ci.yml`.

## Local development

See [`docs/deployment.md`](./docs/deployment.md) (work in progress) for local setup. The short version:

```sh
cp src/.env.example src/.env       # adjust as needed
docker compose up -d
```

## Documentation contributions

The `docs/` directory and the `docs/adr/` Architecture Decision Records are the home of long-form documentation. ADRs follow the template at [`docs/adr/0000-template.md`](./docs/adr/0000-template.md).

For docs-only changes, you can use the **Documentation** issue template.

## License

A license is being chosen for the project — see [#22](https://github.com/Fidonis/papaia/issues/22). Until it is added, the code is *all rights reserved by default*. Contributions are welcome, but cannot be redistributed under another license until the project is licensed.

---

Thanks again for contributing!
