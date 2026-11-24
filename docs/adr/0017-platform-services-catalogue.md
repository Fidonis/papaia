---
adr: 0017
title: Render a platform services catalogue from exposes declarations
status: Proposed
date: 2026-11-22
deciders:
  - marko-boehm
tags:
  - addon-contract
  - manifest
  - mcp
supersedes: null
superseded_by: null
---

# 0017. Render a platform services catalogue from `exposes` declarations

## Context

Modules that consume the services of an installation have no machine-readable list
of them. What an add-on or a core profile offers -- an MCP server, a REST API -- is
known only from READMEs and from configuration each consumer writes by hand. The one
list of MCP servers the core renders is LibreChat's configuration
(`ai/librechat/librechat.yaml`): it is LibreChat's own format, it carries no audience
and no data class, and it says nothing about whether a server may be consumed by
other modules. Consumers such as papaia Studio and papaia-work need to see a new
add-on's server when it is installed and lose it when it is removed, without
depending on LibreChat (Fidonis/papaia#435).

## Decision

- Core modules declare what they offer in an `exposes.yaml` next to their compose
  file; add-ons declare it under a new optional manifest key `exposes:` (addon_api 7,
  an additive seam change: `current` goes to 7, `min` stays 1).
- An entry has `id`, `kind` (`mcp`, `rest`, `llm_api`, `task_feed`, `flow_provider`),
  `title` (`de` required), `url`, `auth` (`oidc_bearer`, `own_oauth`, `none`),
  `consumable` and optionally `description`, `audience`, `token_exchange`,
  `context_assertion`, `max_class`, `data_owner_group`, `suggested_tools`,
  `classification_hint`, `links` and `reason`.
- Every render writes `$PAPAIA_CONFIG_DIR/platform/services.json`
  (`papaia.platform-services/1`) from the active core modules and add-ons, adding
  `addon`, `version` and `profile`, sorted by id, with a digest over the services.
  `generated_at` is kept while the digest is unchanged. The write is atomic.
- Ids are unique across the installation; `oidc_bearer` needs an audience,
  `own_oauth` is never consumable, and `consumable: false` needs a reason.
  `addon install` refuses an add-on whose entries fail; a render with invalid entries
  fails with a named error.
- The schema of the format is `tools/schemas/platform-services.schema.json`. Additive
  fields keep `papaia.platform-services/1`; a breaking change increments the format.
- LibreChat's configuration and the add-on fragments it is rendered from stay as
  they are and are independent of the catalogue.

## Consequences

- Consumers read one file, mounted read-only, and need no knowledge of LibreChat's
  format; LibreChat can become optional without losing the list of services.
- The file contains internal addresses and audiences but no secrets, and it grants
  nothing: consumers connect an entry only through their own approval.
- Add-ons declare their MCP servers twice for a while: as a LibreChat fragment and as
  an `exposes:` entry. The duplication ends where LibreChat is no longer used.
- The `max_class` values of the core modules are a first proposal (Firecrawl
  `public`, Qdrant `confidential`, Qdrant Ingest and the knowledge map `internal`);
  operators and consumers may apply stricter values.

## Alternatives considered

- **Consumers read the rendered `librechat.yaml`.** Ties every consumer to
  LibreChat's format, which lacks audiences and data classes and is no interface.
- **A hand-written list per consumer.** Goes stale with every add-on change.
- **Derive entries from LibreChat fragments automatically.** Keeps the coupling and
  cannot add what the fragments do not know (audience, data class, consumability).
