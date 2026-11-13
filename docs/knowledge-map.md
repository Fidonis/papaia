# Knowledge Map (profile `knowledge-map`)

The knowledge map answers the question every multi-source assistant gets wrong
first: **where** does the requested knowledge live? It is a small, generated
directory of the installation's knowledge sources — what each system covers,
what it explicitly does *not*, who may see it, and which MCP tools reach it —
served to the chat layer by `knowledge-map-mcp` as three tools:

| Tool | Purpose |
|---|---|
| `find_knowledge_source(need, domain?, k?)` | Rank the sources for a distilled information need: match grades, reasoning, access hints, freshness — or a calibrated abstention. |
| `describe_source(source_id)` | One source's full manifest. |
| `list_topics()` | Compact role-trimmed index of all usable sources. |

Design decisions and their rationale: [ADR 0011](adr/0011-knowledge-map-as-optional-core-profile.md)
(profile) and [ADR 0012](adr/0012-knowledge-manifest-key-and-map-format.md)
(declaration format). Server internals: the `papaia-knowledge-map` repository.

## Enabling

```sh
# in $PAPAIA_CONFIG_DIR/.env
COMPOSE_PROFILES=...,knowledge-map
```

On the next `papaia-ctl start` the map is rendered into
`$PAPAIA_CONFIG_DIR/knowledge-map/` and the `KnowledgeMap` MCP server appears
in LibreChat. The Keycloak realm template already carries the resource-server
client `mcp-knowledge-map` and its audience mapper on the `librechat` client;
external OIDC providers need an equivalent audience claim (see
`src/infra/keycloak/README.md`).

An example navigator agent that routes through the map ships as
`src/ai/knowledge-map/navigator.agent.yaml.example` for the LibreChat agents
seam (`LIBRECHAT_AGENTS_DIR`).

## Where map entries come from

Nothing on the map is hand-maintained in place. Entries are declared by the
software that provides the source and rendered on every `setup`, `start` and
`addon` operation:

- **Add-ons** declare sources under the `knowledge:` key of `papaia-app.yaml`
  (addon_api 4; the schema is in `docs/architecture.md` §6.2).
- **Core modules** declare the same structure in `<module>/knowledge.yaml`
  (e.g. `src/ai/rag/knowledge.yaml`), collected while their profile is active.
- **Operators** augment generated entries in
  `$PAPAIA_CONFIG_DIR/overlay/knowledge-map/overrides.yaml`:

  ```yaml
  sources:
    wiki.main:
      owner: "ops team"
      # Lists REPLACE the declared value: repeat the declared items you want
      # to keep (check manifests/wiki.main.yaml), then add your own.
      not_covered:
        - { what: "customer contracts", instead: paperless.docs }
  ```

  Overrides merge per source id on top of the declaration: mappings merge
  key-wise, scalars and lists are replaced wholesale (replacement is what
  lets an operator remove a wrong declared item). Overrides cannot
  introduce new sources; an override for a source that no longer exists
  (e.g. after an add-on removal) is ignored with a render warning.

Installing an add-on adds its entries, removing it prunes them — the map
cannot disagree with what is deployed. Each rendered manifest carries a
content hash, its generation time and a 7-day `valid_until`; consumers serve
expired entries **marked as stale**, never silently.

## Writing good entries

The map earns its keep through *negative knowledge*. Most routing mistakes
happen between thematically adjacent sources, so for every source answer two
questions:

1. **What should route here?** `coverage`, `topics` (with the synonyms your
   users actually say) and 2–5 `example_queries`.
2. **What must NOT route here, and where does it belong?** `not_covered` with
   an `instead` reference, plus 1–2 `counter_examples`.

When two sources share a topic, either delimit them against each other
(`not_covered`/`source_of_truth_for`) or expect the render to warn — routing
between undelimited twins is guesswork.

## Access control

`required_roles` gates the **visibility of the entry**: trimming happens in
`knowledge-map-mcp` against the caller's validated realm roles before any
ranking or model exposure. The default for a denied caller is `hidden` — the
entry does not exist in any response, because the existence of a source can
itself be sensitive. Sources whose existence is common knowledge can declare
`on_denied: acknowledge` to surface as an explicit "exists, requires role X"
stub instead of a confusing miss.

Note the scope: the map gates *knowing about* a source. Using it is still
enforced by that source's own MCP server (audience check, its own RBAC) — the
map adds a discovery gate in front, it replaces nothing.

## Routing behaviour and calibration

Routing scores one embedding centroid per source (via LiteLLM, so local-first
installations stay local; without an embedding model a lexical fallback keeps
the server functional). Declared non-coverage demotes a source and boosts its
`instead` target; near-ties between sources sharing a topic go to the declared
`source_of_truth_for`; results carry match grades and reasons.

Two honesty mechanisms need deployment-specific calibration in
`ai/knowledge-map/.env`:

- `KM_ABSTENTION_THRESHOLD` — below this relevance the server abstains
  ("not available in the mapped sources") instead of ranking noise.
- `KM_AMBIGUITY_MARGIN` — top-2 results closer than this are reported as
  ambiguous instead of silently resolved.

During an embedding outage the server keeps answering with a lexical fallback
(responses carry `degraded: true` and their own floor,
`KM_LEXICAL_ABSTENTION_THRESHOLD`) instead of erroring out or abstaining on
everything.

Calibrate both against a gold set of real questions with expected sources; the
`papaia-knowledge-map` repository ships the format and an evaluation runner.
Routing telemetry (JSONL) accumulates in the `knowledge-map-telemetry` volume
as the raw material for that gold set. It carries no caller identifiers (the
role set is stored only as a hash), but the distilled need texts are stored
verbatim and routinely derive from user questions — treat the volume as
potentially containing personal data and include it in retention planning.
