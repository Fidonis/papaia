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
(declaration format), [ADR 0013](adr/0013-knowledge-map-inventory-kinds-and-access-paths.md)
(inventory and access paths) and [ADR 0014](adr/0014-knowledge-map-governance-metadata.md)
(governance metadata). Server internals: the `papaia-knowledge-map` repository.

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
shared topics — plus the governance findings described below, all shown
on the management page. A render that would remove
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

Inventoried entries inherit visibility from what they reach, so a hidden
source cannot leak through them: a server entry that is an access path of
declared sources gets the union of those sources' `required_roles` (entry
and path level) and stays `hidden` unless every one of them acknowledges; an
agent entry gets the union over the sources it reaches through its servers.
As soon as one of them is open (no roles), the inventoried entry is open too;
an undeclared server reaches nothing declared and stays open. An explicit
`required_roles` or `on_denied` override on the inventoried entry wins.

Note the scope: the map gates *knowing about* a source. Using it is still
enforced by that source's own MCP server (audience check, its own RBAC) — the
map adds a discovery gate in front, it replaces nothing.

## Governance metadata

The map is where three facts meet that no single system sees together: how
sensitive a source is, how widely it is visible, and which model tier an
agent or the vector index sends its content to. The operator documents the
first and the model tiers in
`$PAPAIA_CONFIG_DIR/overlay/knowledge-map/governance.yaml` (optional; an
annotated example ships as `src/ai/knowledge-map/governance.yaml.example`);
each render checks the wiring against it. Design and rationale:
[ADR 0014](adr/0014-knowledge-map-governance-metadata.md).

**The map does not enforce.** The findings point at configuration to change;
the map blocks no request, protects no data and changes nothing on its own.
Enforcement lives elsewhere:

- **Data access** — in the target systems. Connect MCP servers with the
  user's token (`{{LIBRECHAT_OPENID_ACCESS_TOKEN}}`), not a shared key, so the
  target system still decides per user.
- **Model use** — in LiteLLM: give each agent its own team or key and restrict
  it to the models (model access groups) its data allows.
- **Free chat** — set `chatMenu: false` on every MCP server that reaches
  confidential data, so it is only usable through agents with a vetted model
  instead of in free chat with any model.

### The file

| Block | Content |
|---|---|
| `sources` | Per entry id (any kind): `owner` (a role, not a person), `classification` (`public` < `internal` < `confidential` < `strictly_confidential`), `personal_data` (`none`, `ordinary`, `special`, `criminal`, `unknown`), optional `data_subjects`, optional `ropa_ref` |
| `models` | Per LiteLLM model name: `tier` (`local`, `eu_hosted`, `third_country_contracted`, `third_country`), optional `role` |
| `policy` | `allowed_tiers` per classification, `personal_data_tiers` for special and criminal data, `broad_roles` (roles that mean "practically everyone", default `[user]`), `embedding_model` (default `nomic-embed-text`) |
| `exceptions` | Accepted risk: `finding`, `subject`, `expires` (required), optional `reason`, `accepted_by_role` and `risk_ref` (a pointer into your risk register or wiki) |

Purposes, retention, review dates and similar records belong in the tools
that already keep them (records of processing, risk register, wiki);
`ropa_ref` and `risk_ref` link there. Unknown keys are ignored with a low
finding; a malformed value refuses the render.

Evaluation is fail-closed. For the checks, an entry the operator has not
classified counts as its add-on's proposal, but never below `internal` (an
add-on cannot declare itself public); without a proposal it counts as
`confidential`. Personal data defaults to `unknown`; a model not listed under
`models` counts as `third_country`.

Governance values belong to this file only. `overrides.yaml` with a
`governance` key, or a declaration/override that sets `classification`,
`personal_data`, `data_subjects`, `handling` or `governance` directly, refuses
the render. An add-on (or an operator declaration) may *suggest* values,
which the operator confirms:

```yaml
knowledge:
  sources:
    - id: wiki.main
      governance_proposal: {classification: internal, personal_data: ordinary, data_subjects: [employees]}
```

### What reaches the map

Each manifest carries only `handling: {classification, personal_data}` with
the values the operator confirmed (`unclassified` / `unknown` otherwise) — an
informational label for answers, not an instruction and not a protection.
Owners, references, proposals and the policy never reach a manifest or the
index. For its checks the inventory also notes an agent's model and, per
server, whether it is selectable in free chat and whether a header named
`Authorization` or containing `api-key`/`token`, or an admin `apiKey`, holds a
credential that is the same for every user (no `{{LIBRECHAT_...}}` placeholder
and no `customUserVars` variable). These facts stay in the renderer and
`lints.yaml`; the credential value itself is never read.

### Policy findings

Each render adds governance findings to `lints.yaml`, next to the quality
findings, each with an action level and a concrete `fix`:

| code | level | when |
|---|---|---|
| `classification_open` | medium | one bundled finding: N entries not yet classified (listed in `subjects`) |
| `classification_downgraded` | high | operator classification below the add-on's proposal |
| `personal_data_unknown` | medium; high with a rag path | personal data not documented |
| `personal_data_without_ropa` | high if set by the operator, medium if only proposed | personal data without `ropa_ref` — only once any entry uses `ropa_ref` |
| `open_confidential` | high | a confidential (or effectively confidential) entry is visible without roles or to a broad role |
| `special_data_broad_access` | high | special/criminal data visible without roles or to a broad role |
| `rag_copy_sensitive` | high (strictly confidential, special, criminal), medium (confidential) | a vector-index copy bypasses the source's rights and deletions |
| `embedding_model_policy` | high | the embedding model's tier is not allowed for a rag source's data |
| `agent_model_policy` | high | an agent's model tier is not allowed for an entry it reaches over its servers |
| `unclassified_model_in_use` | high | an agent or embedding model without a tier (subject: the model name; one finding per model) |
| `confidential_in_free_chat` | medium | a server reaching confidential or special data is selectable in free chat |
| `mcp_static_credentials` | high | a server with a shared credential reaches internal or personal data — the target system no longer sees the user |
| `a2a_external` | medium | an Agent2Agent target outside the installation's network (not a private address, bare service name or internal suffix) and no record for that entry |
| `governance_unknown_key` / `governance_unknown_entry` | low | an ignored key, or a record for an id not on the map |
| `exception_expired` | medium | an exception passed its `expires` date |

Undeclared servers are part of this: they count in `classification_open`
and get `personal_data_unknown` (medium) until the operator records them,
and for the checks they stand for themselves, fail-closed. A declared
server's reach is the declared entries whose access paths target it, plus
its own entry once the operator has a record for it.

An exception is active through its `expires` day and keeps its finding in
the list, marked with the `exception` it falls under; from the day after, the
finding returns unmarked together with `exception_expired`. The management
interface adds its own live checks against the model gateway
(`origin: manager`); exceptions may name those too.

### lints.yaml for the management view

The renderer computes, the management view displays; no governance rule is
implemented twice. Besides `generated_at`, `findings` and `warnings`,
`lints.yaml` carries:

| key | content |
|---|---|
| `proposals` | `{<entry id>: <governance_proposal>}` of the declarations |
| `policy` | the effective policy, defaults filled in |
| `exceptable` | the finding codes an exception may name (renderer and manager codes) |
| `agents` | per agent `{model: {provider, name} or null, tier, tier_declared, result, reached}`; `result` is `ok`, `attention` (a reached entry the tier does not allow, or a model without a declared tier) or `not_assessable` (no model, e.g. an Agent2Agent agent — never `ok`); `reached` lists `{entry, classification, personal_data, via, allowed}` with the effective values the checks used (`allowed` is null without a model) |

Each finding has `severity`, `code`, `target`, `message`, `origin: render`
and `category` (`quality` or `governance`). Governance findings add a `fix`
and `params` — the structured values of `message` and `fix`, so the
management view can phrase them in its own language — and, under an active
exception, `exception: {expires, reason?, accepted_by_role?, risk_ref?}`.
`classification_open` has no target and lists its entries in `subjects`.

| code | `target` | `params` keys |
|---|---|---|
| `classification_open` | null | `count`, `proposed_count`, `entries` |
| `classification_downgraded` | entry id | `entry`, `classification`, `proposed` |
| `personal_data_unknown` | entry id | `entry`, `rag` |
| `personal_data_without_ropa` | entry id | `entry`, `personal_data`, `proposed` |
| `open_confidential` | entry id | `entry`, `classification`, `classified` |
| `special_data_broad_access` | entry id | `entry`, `personal_data` |
| `rag_copy_sensitive` | entry id | `entry`, `classification`, `personal_data` |
| `embedding_model_policy` | entry id | `entry`, `classification`, `personal_data`, `model`, `tier`, `allowed_tiers` |
| `agent_model_policy` | agent id | `agent`, `model`, `tier`, `entries`, `allowed_tiers` |
| `unclassified_model_in_use` | model name | `model`, `agents`, `embedding_for` |
| `confidential_in_free_chat` | server entry id | `entry`, `server`, `entries` |
| `mcp_static_credentials` | server entry id | `entry`, `server`, `entries` |
| `a2a_external` | entry id | `entry`, `host` |
| `governance_unknown_key` | key path | `key` |
| `governance_unknown_entry` | entry id | `entry` |
| `exception_expired` | the exception's subject | `finding`, `subject`, `expires` |

### Wording

Findings support documentation duties such as the record of processing
activities or an asset inventory; they are no legal assessment. Speak of
"policy findings" and "action needed (high/medium/low)"; never describe an
installation as compliant, a rule as enforced, or a finding as a violation,
and call aggregated telemetry "pseudonymised, aggregated", not anonymised.

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
it for evaluation runs and to counter-check refinement suggestions. It is the
only operator file the service mounts — declarations, overrides and
governance metadata stay on the host. The render creates an empty gold set
(`questions: []`) when there is none.

## Refinement and telemetry

Routing telemetry (JSONL) accumulates in the `knowledge-map-telemetry` volume.
From it and from `report_outcome` feedback the service derives refinement
**suggestions** (example questions, delimitations, source-of-truth decisions,
declarations for undeclared servers, gold questions). Nothing is applied
automatically: an administrator accepts a suggestion on the management page,
which writes it as an override. Suggestions need support from several
distinct role profiles, are masked and screened, capped per source and
checked against the gold set. It carries no caller identifiers (the role
set is stored only as a hash). What happens to the distilled need texts,
which routinely derive from user questions, follows `KM_LEARNING_MODE`:

- `off` — no need texts are kept, only counts;
- `aggregate` (default) — need texts are masked when they are written and
  shown only aggregated (pseudonymised, aggregated — not anonymised);
- `full` — need texts are kept verbatim.

Treat the volume as personal data in every mode but `off`:
`KM_TELEMETRY_RETENTION_DAYS` (default 30) deletes older records, and the
volume belongs in the record of processing activities. For professions bound
by professional secrecy (in Germany § 203 StGB: tax advisers, lawyers,
doctors) `off` is recommended.

Where employee representation applies (in Germany the works council), the
telemetry is a technical facility that can observe how people work; settle
these points before enabling it:

- **Purpose limitation** — the data improves routing and nothing else; no
  evaluation of individual users or teams.
- **Access** — name who may open the management page's usage view (the
  `papaia-admin` holders), and keep that list short.
- **Minimum group size** — suggestions and unmatched needs appear only once
  several distinct role profiles share them (the server's minimum, default
  3), so no single person's questions surface.
- **Retention** — at most 30 days.
- **`full`** — only with the works council's consent, e.g. a works agreement.
