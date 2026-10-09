---
adr: 0005
title: Manage the RAG system's ingester from papaia-manager instead of its own web interface
status: Accepted
date: 2026-10-09
deciders:
  - marko-boehm
tags:
  - rag
  - qdrant
  - manager
  - setup
supersedes: null
superseded_by: null
---

# 0005. Manage the RAG system's ingester from papaia-manager instead of its own web interface

## Context

[ADR 0004](./0004-rag-system-as-optional-core-profile.md) brought the RAG system
back into the core as the optional profile `rag`. It described `qdrant-ingest` as
the ingester with its own web interface: the realm template carried a confidential
client `qdrant-ingest-ui` for its sign-in, `papaia-ctl setup` asked for a public
URL of the ingester and built the OIDC redirect from it, the bundled Nginx Proxy
Manager published that URL with only `/ui` and `/health` let through, and the
operator added the connection to Qdrant by hand in that interface.

`qdrant-ingest` 1.0.0 no longer has that interface. Its connections, jobs, runs
and source credentials are managed in `papaia-manager` 1.3.0 (RAG menu,
administrators only), which edits the same catalog files the ingester reads
(`jobs.yaml`, `connections.yaml`, `secrets.yaml`) and starts and follows runs
through the ingester's REST API. The manager also creates the connection `default`
to the integrated Qdrant itself, so the manual step of ADR 0004 is gone. What
ADR 0004 set up for the web interface is therefore dead configuration: `/ui`
answers 404 and the `QI_UI_*` settings are ignored.

## Decision

- The ingester has no web interface in the core. `papaia-manager` (profile
  `manager`) is the interface for connections, collections and their access roles,
  the embedding of files, and the ingest jobs, runs and credentials.
- Everything that existed only for the web interface leaves the `rag` profile: the
  client `qdrant-ingest-ui` and its secrets, `QDRANT_INGEST_PUBLIC_URL`, the flag
  `--qdrant-ingest-host` and its prompt, and the proxy host for the ingester. The
  resource-server clients `mcp-qdrant` and `mcp-qdrant-ingest`, the audience
  mappers and the realm roles `qdrant-admin` and `qdrant-ingest-operator` stay;
  the operator role now gates the ingester's MCP tools.
- The ingester gets no public name. `papaia-manager` and LibreChat reach it over
  `papaia-net`. Its port stays published for the REST API (static token) and the
  MCP endpoint, and is not meant for a public reverse proxy.
- The ingester only reads its catalog, so the directory is mounted read-only.
  `papaia-manager` writes it. The container keeps running as the host user that
  owns `$PAPAIA_CONFIG_DIR`, so it can read what the manager wrote.
- `--rag` does not require `--manager`. Without the manager profile there is no
  interface; `setup` says so and names the catalog directory, and the catalog files
  are edited by hand.

Where this record and ADR 0004 differ, this one holds. ADR 0004 stays unchanged as
the record of how the module was introduced.

## Consequences

- **Positive**: one interface and one sign-in for the whole RAG system, no second
  OIDC client, no secret to keep in step and no public hostname for a control
  plane. The first connection needs no manual step.
- **Negative**: managing the RAG system needs the `manager` profile, which runs on
  Linux hosts only. Without it the operator edits YAML, and the encrypted values
  (api-keys, credentials) have to be produced by hand as the `qdrant-ingest`
  documentation describes.
- **Neutral**: an installation set up before this change keeps unused keys in its
  `.env`, a `qdrant-ingest-ui` client in its realm and possibly an NPM proxy host
  for the ingester. None of them does anything, and they can be deleted by hand.

## Alternatives considered

- **Keep the web interface settings in the core** — rejected: the ingester ignores
  them, `setup` would keep generating unused secrets and asking for a URL that
  serves nothing.
- **Require the manager whenever `rag` is on** — rejected for now: it couples two
  independent profiles, and the catalog can still be edited as files. It can be
  revisited if the missing interface turns out to matter in practice.
- **Offer connection and job commands in `papaia-ctl`** — rejected: it would add a
  second place that writes the catalog next to the manager and the ingester's REST
  API.

## References

- [ADR 0004](./0004-rag-system-as-optional-core-profile.md), the RAG system as an optional core profile
- `Fidonis/qdrant-ingest#45`, removal of the operator web interface
- `Fidonis/papaia-manager#126`, ingest jobs and runs in the manager
