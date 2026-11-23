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
| [0011](./0011-local-voice-as-an-optional-core-profile.md) | Offer local voice (STT and TTS) as an optional core profile | Proposed | 2026-11-11 |
| [0012](./0012-serve-local-inference-on-apple-silicon-through-a-native-localai.md) | Serve local inference on Apple Silicon through a native LocalAI | Proposed | 2026-11-13 |
| [0013](./0013-knowledge-map-as-optional-core-profile.md) | Ship the knowledge map as an optional core profile | Proposed | 2026-11-13 |
| [0014](./0014-knowledge-manifest-key-and-map-format.md) | Declare knowledge sources through a `knowledge:` manifest key | Proposed | 2026-11-13 |
| [0015](./0015-knowledge-map-inventory-kinds-and-access-paths.md) | Inventory every reachable server and agent, and give sources several access paths | Proposed | 2026-11-14 |
| [0016](./0016-knowledge-map-governance-metadata.md) | Keep governance metadata in a separate operator file and report model policy findings | Proposed | 2026-11-14 |
| [0019](./0019-issue-internal-tls-from-one-platform-ca.md) | Issue the certificates for internal TLS from one platform CA | Proposed | 2026-11-21 |
| [0020](./0020-mein-bereich-and-the-preference-store-as-core-profile.md) | Ship Mein Bereich and the preference store as the core profile me from one pinned image | Proposed | 2026-11-22 |
| [0022](./0022-one-security-profile-for-the-whole-installation.md) | Define one security profile for the whole installation in one place | Proposed | 2026-11-21 |
| [0025](./0025-build-the-permission-report-in-papaia-audit.md) | Build the permission report in papaia-audit with an account that holds view-users only | Proposed | 2026-11-23 |

## Reserved numbers

These numbers are reserved for the decisions behind the add-on contract generations 7 to 12
(see the generation table in [`ADDON_API`](../../ADDON_API)). Each number is used once, for
the topic below. When a record is written, its row moves from this table to the index.
Records in other repositories cite these decisions with the repository name, for example
`papaia ADR 0020`.

| # | Topic | Generation |
|---|---|---|
| 0017 | Add-on contract generations 7 to 12 | 7, 10 (addendum) |
| 0018 | Identity: roles, exchange scopes and service accounts | 7 |
| 0021 | Connection registry | 9 |
| 0023 | Add-on ingress and delivery | 12 |
| 0024 | Design source | – |

## References

- Michael Nygard, *Documenting Architecture Decisions* (2011)
- https://adr.github.io/
