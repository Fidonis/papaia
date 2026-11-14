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
| `list_topics()` | Compact role-trimmed index of all usable sources and agents. |
| `plan_lookup(needs)` | Route the parts of a multi-subject question at once. |
| `find_agent(task)` | Agents to delegate a whole task to. |
| `report_outcome(need, source_id, outcome)` | Feedback after using a source; feeds the refinement suggestions. |

The server also offers the resource `knowledge-map://index` (the compact
index for a system prompt), the prompt `navigator` (the working rules), and
the same functions as REST under `/api/v1/` for callers without MCP — always
with the user's token. How another assistant integrates is described in the
`papaia-knowledge-map` repository.

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

Nothing on the map is hand-maintained in place. Entries are rendered on every
`setup`, `start` and `addon` operation from:

- **Add-ons** — the `knowledge:` key of `papaia-app.yaml` (addon_api 4; the
  schema is in `docs/architecture.md` §6.2).
- **Core modules** — `<module>/knowledge.yaml` (e.g. `src/ai/rag/knowledge.yaml`),
  collected while their profile is active.
- **Inventory** — every MCP server in the merged LibreChat configuration
  becomes an entry of kind `mcp`, every agent file in `LIBRECHAT_AGENTS_DIR`
  one of kind `agent`. A server that no declared source reaches is marked
  *undeclared*: the map then knows it exists, so it never claims that
  information is unavailable while such a server is connected.
- **Operator declarations** — `$PAPAIA_CONFIG_DIR/overlay/knowledge-map/sources.yaml`
  in the add-on schema, for the operator's own servers, places without any
  connector and Agent2Agent agents:

  ```yaml
  sources:
    - id: files.protocols
      kind: reference                 # no tool reaches it
      system: "File share"
      coverage: "Signed maintenance protocols, logbooks (PDF)"
      location: "Nextcloud, folder 04_Anlagen"
      topics: [{ id: files.protocols, label: "Maintenance protocols" }]
    - id: agent.partner-stock
      kind: agent
      system: "Supplier stock agent"
      coverage: "Checks stock and delivery dates at the supplier"
      access:
        - { via: a2a, target: "https://partner.example.org/.well-known/agent-card.json",
            skills: [check_stock] }
  ```

- **Operator overrides** — `overlay/knowledge-map/overrides.yaml` augments
  entries (including inventoried ones, e.g. to restrict a server to a role):

  ```yaml
  sources:
    wiki.main:
      owner: "ops team"
      # Lists REPLACE the declared value: repeat the declared items you want
      # to keep (check manifests/wiki.main.yaml), then add your own.
      not_covered:
        - { what: "customer contacts", instead: crm.main }
  ```

  Overrides merge per entry id on top of the declaration: mappings merge
  key-wise, scalars and lists are replaced wholesale. They cannot create
  entries; an override for an entry that no longer exists is ignored with a
  render warning.

### Entry kinds and access paths

| kind | What | Found by |
|---|---|---|
| `source` | Where information lives (default) | `find_knowledge_source` |
| `reference` | A place no tool reaches; answers name the `location` | `find_knowledge_source` |
| `mcp` | A connected MCP server (inventory) | only while *undeclared*, as an unverified hint |
| `agent` | A delegation target | `find_agent` |

A source lists every way to reach it under `access`, e.g. the wiki live over
its MCP server and as a snapshot in the vector index — one entry, two paths,
each saying what it is `best_for`; a path may narrow visibility with its own
`required_roles`.

### Checks and safety nets

Each render writes `knowledge-map/lints.yaml` with what weakens the map —
undeclared servers, paths to servers that are not connected, dangling
references, sources without negative knowledge or examples, undelimited
shared topics — shown on the management page. A render that would remove
more than half of a map with at least four entries keeps the old manifests
and warns; render again to confirm an intended removal.

Installing an add-on adds its entries, removing it prunes them — the map
cannot disagree with what is deployed. Each rendered manifest carries a
content hash, its generation time and a 7-day `valid_until`; consumers serve
expired entries **marked as stale**, never silently. MCP servers created
inside LibreChat at runtime are stored in its database, not its
configuration, and stay invisible to the map — keep their creation to
administrators.

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
Keep the gold set in `overlay/knowledge-map/goldset.yaml`; the service reads
it for evaluation runs and to counter-check refinement suggestions.

## Refinement and telemetry

Routing telemetry (JSONL) accumulates in the `knowledge-map-telemetry` volume.
From it and from `report_outcome` feedback the service derives refinement
**suggestions** (example questions, delimitations, source-of-truth decisions,
declarations for undeclared servers, gold questions). Nothing is applied
automatically: an administrator accepts a suggestion on the management page,
which writes it as an override. Suggestions need support from several
distinct role profiles, are masked and screened, capped per source and
checked against the gold set. It carries no caller identifiers (the
role set is stored only as a hash), but the distilled need texts are stored
verbatim and routinely derive from user questions — treat the volume as
personal data: `KM_TELEMETRY_RETENTION_DAYS` (default 30) deletes older
records, `KM_LEARNING_MODE=off` keeps no need texts at all, and the volume
belongs in the record of processing activities.
