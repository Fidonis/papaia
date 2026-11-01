# Architecture Decision Records (ADRs)

This directory contains records of architecture decisions made on this project.

## What is an ADR?

An Architecture Decision Record is a short Markdown document that captures one architecture decision: its **context**, the **decision** itself, and the **consequences**.

ADRs are written for humans **and** designed to be machine-readable: each file starts with YAML frontmatter (`adr`, `title`, `status`, `date`, …) so tooling and AI assistants can index, query, and reason about them.

## Conventions

- **Filename**: `NNNN-short-kebab-title.md` (zero-padded four-digit number, e.g. `0007-use-trivy-for-image-scanning.md`)
- **Numbering** starts at `0001` and is assigned in order of acceptance.
- Once **Accepted**, an ADR is immutable. To change a decision, create a new ADR that **supersedes** the old one (update `superseded_by` on the old, `supersedes` on the new).
- **Status** values: `Proposed`, `Accepted`, `Deprecated`, `Superseded`.

## Template

See [`0000-template.md`](./0000-template.md).

## Index

| # | Title | Status | Date |
|---|---|---|---|
| [0001](./0001-record-architecture-decisions.md) | Record architecture decisions | Accepted | 2026-05-09 |
| [0002](./0002-addon-core-compatibility-gating.md) | Gate addon compatibility on a contract generation, not the product version | Accepted | 2026-07-14 |
| [0003](./0003-per-service-admin-roles.md) | Split the shared admin realm role into per-service roles under papaia-admin | Accepted | 2026-09-18 |
| [0004](./0004-rag-system-as-optional-core-profile.md) | Offer the RAG system as an optional core profile instead of three add-ons | Accepted | 2026-10-04 |
| [0005](./0005-manage-the-rag-ingester-from-papaia-manager.md) | Manage the RAG system's ingester from papaia-manager instead of its own web interface | Accepted | 2026-10-09 |
| [0006](./0006-manage-accounts-with-the-signed-in-users-token.md) | Manage accounts and roles from papaia-manager with the signed-in user's token and give papaia-admin Keycloak's user and role administration rights | Accepted | 2026-10-10 |
| [0007](./0007-outbound-mail-through-an-internal-relay.md) | Offer outbound mail as an optional core profile with one internal SMTP relay | Accepted | 2026-10-11 |
| [0008](./0008-upgrade-add-ons-by-repointing-to-immutable-snapshots.md) | Upgrade add-ons by repointing the registration to a new directory, not by replacing files | Accepted | 2026-10-25 |
| [0009](./0009-place-services-on-nodes-with-a-topology-block.md) | Describe a distributed installation with a topology block and place it per service | Proposed | 2026-10-30 |
| [0010](./0010-connect-nodes-through-ssh-and-an-mtls-link.md) | Run node commands through an SSH forced command and connect services through an mTLS link gateway | Proposed | 2026-10-30 |

## References

- Michael Nygard, *Documenting Architecture Decisions* (2011)
- https://adr.github.io/
