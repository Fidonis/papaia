---
adr: 0001
title: Record architecture decisions
status: Accepted
date: 2026-05-09
deciders:
  - WilhelmSebastian
tags:
  - meta
  - documentation
supersedes: null
superseded_by: null
---

# 0001. Record architecture decisions

## Context

papAIa is a multi-service stack with non-trivial design decisions across authentication, RAG, deployment topology, and tooling choices. Without a durable record, it becomes increasingly difficult — for both humans and AI assistants — to understand *why* the system is structured the way it is, not only *how*. Decisions get re-litigated, context is lost, and onboarding becomes harder.

We want a lightweight, low-overhead way to capture decisions at the moment they are made.

## Decision

We will use **Architecture Decision Records (ADRs)** as introduced by Michael Nygard.

- Each ADR is a Markdown file in `docs/adr/`, prefixed with a zero-padded four-digit number.
- Each ADR starts with a YAML frontmatter block exposing `adr`, `title`, `status`, `date`, `deciders`, `tags`, `supersedes`, and `superseded_by`. This makes the records both human-readable and machine-readable (usable by tooling and AI assistants).
- ADRs follow the template at [`0000-template.md`](./0000-template.md).
- Once an ADR is `Accepted`, it is immutable. To change a decision, a new ADR is written that **supersedes** the old one.

## Consequences

- **Positive**: durable, searchable record of architecture decisions and their rationale.
- **Positive**: machine-readable frontmatter — usable by automation and AI assistants.
- **Positive**: low ceremony — a new ADR is just a copy of the template.
- **Negative**: minor per-decision overhead (writing the ADR).
- **Neutral**: the `docs/adr/README.md` index has to be kept in sync when new ADRs are added.

## Alternatives considered

- **No formal record** — relying on commit messages and PR descriptions. Rejected: too dispersed, hard to discover, and not designed to capture rationale.
- **Wiki pages** — easy to edit but hard to review (no PR flow), and not part of the source-of-truth repository.
- **A single `DECISIONS.md`** — simpler but does not scale and conflates orthogonal decisions.

## References

- Michael Nygard, *Documenting Architecture Decisions* (2011) — https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- https://adr.github.io/
