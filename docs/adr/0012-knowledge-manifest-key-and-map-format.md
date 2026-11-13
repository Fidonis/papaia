---
adr: 0012
title: Declare knowledge sources through a knowledge manifest key
status: Proposed
date: 2026-11-13
deciders:
  - WilhelmSebastian
tags:
  - knowledge-map
  - addon-contract
  - manifest
supersedes: null
superseded_by: null
---

# 0012. Declare knowledge sources through a `knowledge:` manifest key

## Context

The knowledge-map profile (ADR 0011) needs a declarative way for add-ons and
core modules to describe the knowledge sources they contribute: what lives
there, what explicitly does **not**, how to reach it, and who may see it. The
declaration must be additive to the existing manifest contract, must reference
MCP servers instead of duplicating their tool schemas (duplication drifts),
and must produce a useful map before any profiler enriches it.

Three empirical constraints shape the format. Negative delimitation is the
single most valuable field, because most routing mistakes happen between
thematically adjacent sources. Freshness must be explicit and stale entries
must stay visible as stale — a silently outdated map routes confidently wrong.
And the visibility of an entry is itself access-controlled information: that a
"payroll system" exists is something not every account may learn.

## Decision

### Declaration (add-ons and core modules)

Add-ons declare sources under a new optional top-level `knowledge:` key in
`papaia-app.yaml`; core modules declare the same structure in a `knowledge.yaml`
file in their module directory (e.g. `src/ai/rag/knowledge.yaml`), merged only
while their profile is active. Manifest readers ignore unknown keys, so the key
is backward-compatible; add-ons that use it declare `requires.addon_api: 4`
(or a list including 4).

```yaml
knowledge:
  sources:
    - id: <addon>.<source>            # unique, dotted, stable
      system: "<human name>"
      mcp_server: <name>              # reference to the librechat fragment entry;
                                      # never tool schemas — consumers introspect
      topics:
        - { id: org.processes, label: "Processes", synonyms: [SOP] }
      coverage: "<what is in here, since when>"
      not_covered:
        - { what: "<content class>", instead: <other-source-id> }
      example_queries: ["...", "..."]      # 2–5
      counter_examples: ["..."]            # 1–2 queries that must NOT land here
      required_roles: [user]               # realm roles that may see the ENTRY
      on_denied: hidden                    # hidden (default) | acknowledge
      source_of_truth_for: [<topic-id>]    # conflict resolution on overlap
      key_tools: [search_pages]            # names only, for the model's next step
      depends_on: []                       # preconditions (auth flows, lookups)
      owner: ""                            # human contact, optional
```

### Rendered map (generated, under `$PAPAIA_CONFIG_DIR/knowledge-map/`)

- `index.yaml` — a compact per-source digest (system, one-line coverage, topic
  labels, first negative hint); small enough to inline into a prompt.
- `manifests/<id>.yaml` — the declared fields plus generated ones:
  `content_hash` (SHA-256 over the declaration), `generated_at`,
  `valid_until` (render time + 7 days: a map a renderer has not touched for a
  week deserves distrust), and `provenance`.
- Operator overrides live in `$PAPAIA_CONFIG_DIR/overlay/knowledge-map/
  overrides.yaml`, merged per source id as the last layer — manual knowledge
  augments generated entries, it never forks them.

Render-time validation rejects duplicate ids, unknown `on_denied` values and
instruction-injection patterns in free-text fields (a map entry is model-facing
text and therefore an injection surface), and warns when two sources share a
topic without mutual `not_covered`/`source_of_truth_for` delimitation.

### Semantics

- The map references MCP servers; it never stores tool schemas.
- `required_roles` gates the visibility of the entry in every map response;
  enforcement happens in `knowledge-map-mcp` against the validated token,
  before model exposure. `on_denied: acknowledge` opts a source into an
  explicit "exists, requires role X" stub for callers it denies.
- Entries past `valid_until` are served with `stale: true`, never dropped.

## Consequences

- **Positive**: the declaration travels with the software that provides the
  source, so installing an add-on updates the map and removing it removes the
  entry — drift against the installed set is structurally impossible.
- **Negative**: `MANIFEST_KEYS` grows (contract-surface snapshot update) and
  authors must write honest `not_covered` lists — the docs make that the
  centrepiece of the authoring guide.
- **Neutral**: the field vocabulary stays deliberately close to DCAT/SKOS
  naming so future exports are cheap, without adopting RDF tooling. Entity-
  level entries (per-record mappings) are out of scope by decision: they
  belong in the source systems' own search.

## Alternatives considered

- **Describe sources only in MCP tool descriptions** — rejected: descriptions
  carry capabilities, not inventory, and cannot express non-coverage or
  role-gated visibility.
- **A hand-maintained map document** — rejected: unmaintainable at the
  customer, and a stale map is worse than none.
- **A full ontology/graph store** — rejected: at 5–30 sources the map is a
  small registry; graph semantics beyond `instead`/`depends_on` edges buy
  maintenance cost, not routing quality.

## References

- ADR 0011 (knowledge map as an optional core profile)
- ADR 0002 (compatibility gating — additive bump rules)
