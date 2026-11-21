# papAIa Documentation

Welcome to the papAIa documentation.

## Contents

- [Architecture](./architecture.md) — system overview, services, data flows
- [Configuration](./configuration.md) — environment variables and configuration files
- [Deployment](./deployment.md) — local and remote deployment paths
- [Troubleshooting](./troubleshooting.md) — common issues and fixes
- [Running on several machines](./distributed.md) — the operator guide of a distributed
  installation
- [Validating a two-node installation](./distributed-validation.md) — the hand-run check of
  the distributed mode on two machines
- [The single exit](./egress.md) — papaia-egress: allow lists per add-on, protected hosts,
  corporate proxy
- [Account lifecycle and revocation](./lifecycle.md) — papaia-lifecycle: revocation on
  deactivation, the signed revocation list, the erasure journal `identity`, its service
  account
- [Hosted test model](./hosted-test-model.md) — a model outside the stack, in the test stack
  only
- [Architecture Decision Records (ADRs)](./adr/) — recorded architecture decisions
- [Parallel Search MCP in LibreChat](./parallel-search-mcp.md) — opt-in hosted web search
  through the customer overlay

## Conventions

- All documentation is written in **English**.
- Markdown is the primary format.
- Code samples use fenced blocks with a language tag for syntax highlighting.

## Contributing to the docs

See the root [`CONTRIBUTING.md`](../CONTRIBUTING.md) for general guidelines. For documentation-specific issues you can also use the [Documentation issue template](https://github.com/Fidonis/papaia/issues/new?template=documentation.yml).
