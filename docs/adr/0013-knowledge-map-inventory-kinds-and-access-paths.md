---
adr: 0013
title: Inventory every reachable server and agent, and give sources several access paths
status: Proposed
date: 2026-11-14
deciders:
  - WilhelmSebastian
tags:
  - knowledge-map
  - manifest
supersedes: null
superseded_by: null
---

# 0013. Inventory every reachable server and agent, and give sources several access paths

## Context

The map of ADR 0011/0012 contains only what a `knowledge:` declaration
brings along. Everything else a chat user can reach — MCP servers from core
fragments, from the overlay, from add-ons without a declaration — is invisible
to it. Its abstention ("not available in the connected systems") is then
wrong exactly when an undeclared server would have had the answer, which is
worse than having no map.

Three further gaps showed in the first reference installation:

- A source is often reachable in more than one way: the wiki live over its
  MCP server *and* as a snapshot in the vector index. One entry per way would
  duplicate the source and split its negative knowledge; one entry with one
  `mcp_server` cannot say which way suits which need.
- Some knowledge lives where no tool reaches (a file share without a
  connector, a paper archive). Pointing people there is one of the most
  useful answers a map can give, but overrides cannot create entries.
- Agents — provisioned chat agents and agents reachable over the Agent2Agent
  protocol — are delegation targets. They bundle access and instructions but
  hold no knowledge of their own; mixing them into source routing would rank
  a wrapper against what it wraps.

## Decision

1. **Entry kinds.** `kind: source` (default), `reference` (a location without
   any tool; needs `location`), `mcp` (a connected server) and `agent`.
   Routing considers sources and references; agents have their own lookup.
2. **Access paths.** `access` is a list of paths, each with `via` (`mcp`,
   `rag`, `a2a`, `none`), `target`, optional `key_tools`, `collection`,
   `skills`, `best_for`, `freshness`, `location` and its own
   `required_roles`. The v0.1 single-path fields remain readable. Both forms
   belong to addon_api 4, which is not released yet; no further bump.
3. **Inventory.** On every render the platform reads the merged chat-client
   configuration and the provisioned agent files and adds one `mcp` entry per
   connected server (except the map's own) and one `agent` entry per agent. A
   server no declared path reaches is marked `undeclared`. Inventory reads
   configuration only; it never calls a server. Inventoried text passes the
   same injection scan, but a hit drops the text instead of blocking the
   render — knowing that the server exists is what keeps abstentions honest.
4. **Operator declarations.** `overlay/knowledge-map/sources.yaml` declares
   entries in the add-on schema (own servers, references, Agent2Agent
   agents). Overrides keep their meaning: they change entries, never create
   them.
5. **Lints.** Each render writes `knowledge-map/lints.yaml`: undeclared
   servers, access paths to servers that are not connected, dangling
   references, missing negative knowledge or examples, undelimited shared
   topics — each with a severity by its effect on answers.
6. **Mass-removal guard.** A render that would delete more than half of a map
   with at least four entries keeps the old manifests and warns; an identical
   second render confirms the removal. An unreadable input must not empty the
   map silently.

## Consequences

- The map's abstention distinguishes "nothing mapped fits" from "nothing
  mapped fits, but these undescribed servers are connected"
  (`no_match_unmapped`), so callers know when to keep looking.
- The management view can show what the map does not know, instead of only
  what it does.
- MCP servers created at runtime inside the chat client (stored in its
  database, not in the configuration) remain invisible; restricting their
  creation to administrators is the operational answer.

## Alternatives considered

- **Introspect servers at render time (`tools/list`).** Needs a service
  token per target server and turns the render into a network operation. Left
  to a later profiler.
- **One entry per access path.** Duplicates sources and their negative
  knowledge; rejected.
- **Agents as sources.** An agent holds no knowledge of its own; rejected in
  favour of a separate kind and lookup.

## References

- ADR 0011, ADR 0012
- Model Context Protocol, tool annotations and server metadata
- Agent2Agent protocol, Agent Card
