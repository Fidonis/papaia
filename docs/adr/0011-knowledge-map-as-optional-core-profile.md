---
adr: 0011
title: Ship the knowledge map as an optional core profile
status: Proposed
date: 2026-11-13
deciders:
  - WilhelmSebastian
tags:
  - knowledge-map
  - mcp
  - core
  - routing
supersedes: null
superseded_by: null
---

# 0011. Ship the knowledge map as an optional core profile

## Context

Installations expose a growing number of knowledge sources to the LLM layer:
MCP servers shipped by add-ons (MediaWiki, Paperless, …), core-profile services
(the RAG system's Qdrant collections), and LibreChat's own file search. Today
the only machine-readable description of these sources is the rendered
`librechat.yaml` (`mcpServers` with title and description). That describes
*capabilities* ("search pages"), not *inventory* ("process documentation lives
here; customer data does NOT — use the CRM"), and it offers no role-based
visibility, no freshness information, and no guidance for routing a question
to the right system.

Source selection — not answer generation — is the dominant failure mode of
multi-source assistants, and listing every tool of every source degrades
selection the moment sources overlap thematically (CRM, DMS and wiki are
exactly that case). An explicit, queryable routing layer (a "knowledge map")
addresses this: the model asks WHERE knowledge lives before reaching for
tools, and gets role-trimmed references with declared non-coverage back.

Such a map is cross-cutting by nature: it aggregates entries contributed by
all active add-ons and core modules. The add-on contract deliberately prevents
add-ons from depending on or discovering other add-ons, so an add-on cannot
own this aggregation. ADR 0004 established the criteria for shipping
cross-cutting optional functionality as a core profile instead of an add-on;
the knowledge map matches them even more strongly, since it also hooks into
the core render pipeline.

## Decision

Ship the knowledge map as an **optional core profile `knowledge-map`**:

1. **A render step** aggregates `knowledge:` declarations (ADR 0012) from all
   active add-ons and core modules into map files under
   `$PAPAIA_CONFIG_DIR/knowledge-map/` (an `index.yaml` plus one manifest per
   source). Like the realm-secret baking, this is a generated artifact with
   its own render function, not a layered merge target in
   `BASE_RENDER_TARGETS`. Render-time validation covers the schema, id
   uniqueness, topic collisions without mutual delimitation, and an
   instruction-injection scan over all free-text fields.
2. **A map MCP server** (`knowledge-map-mcp`, shipped as
   `ghcr.io/fidonis/papaia-knowledge-map`) exposes `find_knowledge_source`,
   `describe_source` and `list_topics` over streamable HTTP. Auth follows the
   established resource-server pattern: bearer pass-through from LibreChat,
   JWKS validation, audience `mcp-knowledge-map` via an audience mapper on the
   `librechat` client, `startup: false` in the fragment. Responses are trimmed
   deterministically to the caller's realm roles before anything reaches the
   model.
3. **A profiler job** (follow-up) enriches and verifies entries via MCP
   introspection, content sampling, generated descriptions and TTL refresh.
   Until it lands, the renderer stamps hash, generation time and TTL.

The profile is off by default and independent of `rag`; when `rag` is active,
the RAG module contributes its own map entry like any other module.

## Consequences

- **Positive**: one queryable, role-trimmed source of routing truth that is
  generated from the same declarations that install the software — it cannot
  disagree with what is actually deployed. Negative knowledge ("not here, use
  X") finally has a machine-readable home.
- **Negative**: `ADDON_API` moves 3 → 4 (additive; `min` stays 1), the
  contract-surface snapshot and the golden single-node snapshot change, and
  the realm template grows a resource-server client — all reviewed in one PR.
- **Neutral**: LibreChat currently loads configured MCP servers statically, so
  the first release delivers routing accuracy, negative knowledge and
  role-trimmed visibility rather than token savings; deferred tool loading
  remains a client-side roadmap item.

## Alternatives considered

- **An add-on instead of a profile** — rejected: add-ons must not aggregate
  over other add-ons, and the render-time hook would still require core
  changes.
- **Always-on core service** — rejected: installations with two or three
  disjoint sources gain little; the lean core stays lean.
- **An external MCP gateway/aggregator** — rejected for now: heavier
  operational footprint, and it federates tools rather than describing
  knowledge inventory. May be revisited for lazy tool loading.

## References

- ADR 0002 (compatibility gating), ADR 0004 (RAG as an optional core profile)
- ADR 0012 (the `knowledge:` manifest key and map format)
