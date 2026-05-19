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

## References

- Michael Nygard, *Documenting Architecture Decisions* (2011)
- https://adr.github.io/
