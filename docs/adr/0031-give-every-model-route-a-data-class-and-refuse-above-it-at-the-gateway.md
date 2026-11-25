---
adr: 0031
title: Give every model route a data class and refuse requests above it at the gateway
status: Accepted
date: 2026-11-25
deciders:
  - WilhelmSebastian
tags:
  - model-gateway
  - data-classes
  - security
  - audit
supersedes: null
superseded_by: null
---

# 0031. Give every model route a data class and refuse requests above it at the gateway

## Context

Modules reach language models only through the model gateway (LiteLLM), by alias and with a
key of their own ([`model-gateway.md`](../model-gateway.md)). Which data may go to which
model is not decided anywhere in the stack today:

- The platform catalog always renders an empty `models` block (`tools/lib/catalog.py`),
  although the kit schema `platform-services.v1` defines `ModelAlias` with a `max_class`.
- A module need's `max_class` (`exposes[].models.needs`) is checked against a name pattern
  only (`tools/lib/model_gateway.py`) and used nowhere afterwards.
- The gateway's hooks (`src/ai/litellm/papaia_hooks.py`) hide routes from the listings and
  enforce the platform halt; nothing compares a request with the route it goes to.

The modules are required to refuse content above the class of the route their alias maps
onto, and to read that class from the catalog. The security test T61 additionally requires
that a request above the route never reaches the model, which only the gateway can prove,
because it is the one point every module call passes. The scale of data classes is the
kit's: eight levels, ordered, one list for every module (PLT-06).

A route can lead to a model on the host (LocalAI, the default) or, in the test stack only,
to a hosted model that may see synthetic data alone
([`hosted-test-model.md`](../hosted-test-model.md)).
The class a route may receive is the operator's decision about that model; it must have a
safe value when the operator has not made it.

## Decision

**1. Route class.** Every alias in the rendered gateway configuration carries exactly one
data class of the kit scale `public` < `internal` < `partner_contact` < `personal` <
`employee` < `confidential` < `special` < `professional_secret`: the highest class the route
may receive. The render takes it, per alias,

- from `model_info.papaia_max_class` of the alias's entry in the operator overlay
  (`$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`);
- otherwise from the root setting `PAPAIA_MODEL_MAX_CLASS` (root `.env`, documented in
  `.env.example`), which applies to every alias without an overlay value;
- otherwise `internal`: without a decision of the operator the ceiling stays low, so the
  default fails closed for every class above it.

Further rules of the render:

- A value outside the scale (unknown name, other spelling or case, empty, surrounding or
  trailing text) stops the render with the alias and the value; it never falls back to the
  default.
- Only the overlay may set the value. A `model_info.papaia_max_class` written by the repo
  base, a profile or an add-on fragment is dropped and reported, the same rule as for
  `test_backend`: an add-on cannot raise the class of a route.
- A hosted test backend (an entry the render marks `test_backend: true`) is capped at
  `internal` whatever the overlay or the root setting says, and the render reports the cap
  (synthetic data only, M-04).
- An alias that reaches more than one deployment (several entries with the same name, or
  `fallbacks`, `context_window_fallbacks` and `content_policy_fallbacks` that lead to another
  model) gets the lowest class of all deployments it can reach, so no request can end at a
  model whose ceiling is lower than the one the alias shows.
- The render writes the result, alias to class, into the route file
  `$PAPAIA_CONFIG_DIR/ai/litellm/model-routes.json` (format version, generation time, the
  routes; no secret, no key), mounted read-only into the gateway container. `papaia-ctl
  start` writes one `config_changed` row for every alias whose class changed (5., row 2),
  into its host journal like the module key rows.

**2. Catalog.** The `models` block of the platform catalog lists every alias of the rendered
configuration as a kit `ModelAlias` with `alias`, `features`, `context`, `max_class` and
`test_backend`. `max_class` is the route class of 1. `features` follow the alias's purpose
(`papaia-chat`: `chat`, `tools`, `stream`; `papaia-structured`: `chat`, `json_schema`,
`json_object`, `stream`; `papaia-embed`: `embeddings`) unless the overlay names them in
`model_info.papaia_features`; `context` comes from `model_info.papaia_context`, otherwise
from the `context_size` of the shipped LocalAI model the entry names, otherwise `4096`, the
smallest context of a shipped model. Names that are not aliases (`papaia-<purpose>`) are not
listed. Without the gateway profile the block stays empty. Modules take the route class from
this block only, never from their own configuration, an answer of the gateway or a default
of their own, and they refuse content above it before they call (the first line).

**3. Request class at the gateway.** A new pre-call hook of the gateway (the class guard),
registered right after the platform halt, judges every model call made with a key other
than the gateway's master key. A module key reaches the routes the class guard judges and
no other:

- **Key route allowlist.** The core makes every module key with an explicit route allowlist
  (LiteLLM's `allowed_routes` of the key): the model call routes `/v1/chat/completions`,
  `/v1/completions` and `/v1/embeddings` with their unversioned twins, on which the class
  guard runs, and the listing `/v1/models` (`/models`), which sends nothing to a model;
  every other route is refused for a module key before any handler runs (file upload,
  batches, fine-tuning, assistants, responses, audio, images, rerank, realtime and the
  pass-through routes among them). A route joins the list only together with the proof
  that the class guard runs on it. If the pinned LiteLLM does not enforce the list for a
  key, the gateway's own authentication step refuses every other route for a module key;
  without either, the implementation does not ship.
- **Request class.** A module may name the class of a request in the header
  `x-papaia-data-class`: exactly one value of the scale, lower case, ASCII, at most 32
  characters, the header present once. Without the header, the request class is the
  `max_class` the module declared for that alias, which the core stores with the module's
  key as `metadata.papaia_need_classes` (alias to class; with several needs for one alias,
  the highest of them). A key without declared classes, without a class for that alias, or
  with a stored value outside the scale counts as the highest class of the scale. The class
  is never taken from the request body (`metadata`, `user` or any other field).
- **Route class.** The class of the requested alias in the route file of 1.
- **Refusals, before any backend call**, with the error body
  `{"error": {"code": "<code>", "message": "<German / English text>"}}` and the response
  header `x-papaia-correlation-id`:

  | Case | Status | `error.code` |
  |---|---|---|
  | request class above the route class | 403 | `class_exceeded` |
  | header above the key's declared class for that alias | 403 | `class_exceeded` |
  | header empty, repeated, a list, too long, not ASCII or not on the scale | 400 | `invalid_data_class` |
  | route file missing, unreadable, malformed or of another format version; alias missing from it; a class in it outside the scale | 503 | `route_class_unknown` |

  A request at or below both classes passes unchanged; the hook removes nothing and adds
  nothing to it. The route file is read again only when its file identity changes (one
  `stat` per request, as for the halt file); a file that cannot be read is treated as
  missing. The check fails closed: no state of the route data, the key metadata or the
  header lets a judged request through without a class. While the platform halt is active,
  its `platform_halt` refusal comes first and the class is not judged.
- Modules recognise the refusals by `error.code`, never by the status alone or by words of
  the message: `class_exceeded` maps onto the error class `class_exceeded`,
  `invalid_data_class` onto `invalid_input`, `route_class_unknown` onto
  `upstream_unavailable`.
- The key metadata and the route allowlist are written by the core alone, with the master
  key inside the gateway container; a module key reaches no management route of the gateway
  (T60). When a module's declaration changes, its key is replaced like a key whose aliases
  changed.
- **Keys made before the class guard.** A module key without `metadata.papaia_need_classes`,
  with stored classes that differ from the module's declaration, or without the route
  allowlist is stale: `papaia-ctl start` and `papaia-ctl addon start` replace it like a key
  whose declaration changed (revocation and `key_replaced` row as today), so no module runs
  on the update with a key that counts as the highest class or reaches unjudged routes.

**4. Start rule.** A module need whose `max_class` is above the route class of its alias is
reported by `papaia-ctl addon start` and by `papaia-ctl doctor` (module, alias, both
classes). The key is still made: the module may filter its content itself, and the gateway
then judges each request. `papaia-ctl doctor` fails when the route file is missing or does
not match the rendered configuration.

**5. Audit.** Every refused request is one `papaia.audit/1` row that passes the ingest schema
(`audit.v1.schema.json`, form `submission`); a request that passes writes none (the module
records its own operation). The row is an `operation` row, so it fills every field the
schema requires of one: writer `litellm/class-guard`, role `server`, `identity_kind`
`service`, `sub`, `azp` and `service_account` the key alias (`module-<name>`; a gateway key
carries no token subject), `catalog_id` `litellm.model_request`, operation `model.request`,
effect `check`, `object_ref` `model_alias`/`<alias>`, `data_class` the request class (`null`
for `invalid_data_class`), `result` `denied`, `error_code` the refusal code and `detail`
`null`. The schema's `detail` takes only its fixed keys, so the route class, the declared
class and where the request class came from (`header`, `declared` or `highest`) are not in
the row: the route class of the moment is in the route file and its `config_changed` rows,
the declared class in the key's metadata. Adding them to the row would extend `detail` in
the schema, a contract change this decision does not make. Row 1, a refusal:

```json
{"format": "papaia.audit/1", "time": "2026-11-25T10:15:30.125Z", "source_seq": 42,
 "correlation_id": "3f2c9a1e-7b4d-4e8a-9c0f-1a2b3c4d5e6f", "writer": "litellm/class-guard",
 "role": "server", "sub": "module-flow", "identity_kind": "service",
 "service_account": "module-flow", "azp": "module-flow", "aud": null,
 "catalog_id": "litellm.model_request", "operation": "model.request", "effect": "check",
 "object_ref": {"type": "model_alias", "id": "papaia-chat"}, "data_class": "confidential",
 "result": "denied", "error_code": "class_exceeded", "detail": null, "event": "operation"}
```

The correlation id is the request's `x-papaia-correlation-id` when it is valid (at most 64
characters of `[A-Za-z0-9-]`, not shaped like a key), otherwise a new one, which the
response returns. The row carries no message content, no header value that is not on the
scale, no key and no key hash. The gateway writes it into an outbox of its own
(`$PAPAIA_CONFIG_DIR/audit/outbox/litellm.jsonl`, mounted read-write into the gateway
alone) and delivers it as source `litellm` with an ingest certificate of its own, like
every source ([`audit.md`](../audit.md)). The refusal never waits for the row: a row that
cannot be written leaves the request refused and logs the reason code without content.

Row 2, a changed route class written by `papaia-ctl start` (1.), is a `config_changed` row
with writer `papaia-ctl`, operation `model_route.class`, effect `write`, `object_ref`
`model_alias`/`<alias>`, `data_class` the new class and `detail` `null`. The old class is the
`data_class` of the previous row of the same alias; the first start with route classes
writes one row per alias.

```json
{"format": "papaia.audit/1", "time": "2026-11-25T10:00:00.000Z", "source_seq": 7,
 "correlation_id": "9d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6", "writer": "papaia-ctl",
 "role": null, "sub": null, "identity_kind": null, "catalog_id": null,
 "operation": "model_route.class", "effect": "write",
 "object_ref": {"type": "model_alias", "id": "papaia-chat"}, "data_class": "confidential",
 "result": "allowed", "error_code": null, "detail": null, "event": "config_changed"}
```

## Security assessment

- **Second line, server-side.** The module's own refusal stays the first line; the gateway
  judges every module request again from data the module cannot change: the route file
  rendered by the core and the key metadata written by the core. Neither the catalog a
  module reads nor a field of the request body is the control.
- **Fail-closed defaults.** No operator decision: `internal`. Hosted test backend: never
  above `internal`. Several deployments or fallbacks: the lowest class. Unknown class in the
  configuration: no render. No declared class: the highest class of the scale. Malformed
  header: `400 invalid_data_class`, never the default. Route data missing or unreadable,
  alias unknown: `503 route_class_unknown` for every module call. A route the class guard
  does not judge: refused for a module key by the key route allowlist, so no module request
  reaches a model past the check. A key made before the class guard: replaced at the next
  start, and until then judged as the highest class. The gateway fails closed in each of
  these states; no fallback lets a module request reach a model unjudged.
- **Before any backend call.** The hook runs before LiteLLM routes the request, so a
  refused request leaves no trace at a backend (T61: the recording of the test model stays
  empty) and none in the spend logs.
- **Input at the boundary.** The header is checked for count, length, character set and
  membership of the scale; the alias is looked up in the route file, never interpreted.
  Values that fail are not written anywhere.
- **No contents.** The hook reads the alias, one header and the key metadata; it never
  reads, logs or stores message content. The no-content settings of the gateway stay as
  they are, and the callback list grows by the class guard alone.
- **Least privilege.** One read-only route file, one outbox file and one ingest certificate
  for the gateway; no new client, role, scope or port. The gateway joins
  `papaia-audit-ingest-net` to deliver its rows, as every audit source does.
- **Remaining risk.** The header is the module's own statement: the gateway cannot check
  the content against it, so a module that names a lower class than its content has is
  caught only by its own refusal (the header can never raise a request above the module's
  declared class). Requests of the chat (LibreChat) are made with the master key, carry no
  module declaration and are outside this rule until the chat has a key of its own (M-02);
  which models the chat may use for which content stays the operator's decision. A route
  class is the operator's statement about a model and is not verified against the model.

## Consequences

- **Positive**: The class of every route is visible in one place (the catalog) and enforced
  at the one point every module passes. T61 becomes provable at the gateway. A new model,
  local or hosted, starts at `internal` until the operator raises it. Every refusal is
  traceable by module, alias, class and correlation id.
- **Negative**: Modules that do not send the header are judged by their declared class, so
  a module that declares a high class must send the header for low-class requests on a
  low-class route. One `stat` and one dictionary lookup per request. The gateway becomes an
  audit source with a certificate of its own. Operators who route confidential data to the
  local model must now raise the class explicitly. Module keys lose every gateway route
  outside the allowlist; a module that needs one waits until the class guard covers it.
  The first start after the update replaces every module key once (keys without stored
  classes); a module that keeps an old key until then is judged as the highest class and
  refused on every route below `professional_secret`.
- **Neutral**: The decision adds no network path to a model and changes no alias. The
  implementation follows in two steps: route classes, route file and catalog block first,
  then the hook. Until then the `models` block stays empty and the gateway judges nothing.

## Alternatives considered

- **Check the class in the modules only.** Rejected: there would be no second line, a
  defect in one module would send content to a model that must not see it, and T61 could
  not be proven at the gateway, where every request passes.
- **One gateway per class.** Rejected: several gateway services, keys and networks per
  installation for the same result, with more to operate and no gain in safety over one
  check against one route file.
- **Classify the content at the gateway.** Rejected: the gateway would have to inspect, and
  for a model-based check store or forward, the content it is not allowed to keep (the
  no-content rule of the gateway), and a classifier can misjudge in both directions.

## References

- [`docs/model-gateway.md`](../model-gateway.md) (aliases, module keys, no stored contents)
- [`docs/hosted-test-model.md`](../hosted-test-model.md) (`test_backend`, test stack only)
- [`docs/halt.md`](../halt.md) (the platform halt hook)
- [`docs/audit.md`](../audit.md) (`papaia.audit/1`, ingest sources)
- `tools/lib/catalog.py`, `tools/lib/model_gateway.py`, `src/ai/litellm/papaia_hooks.py`
- `tools/schemas/kit/platform-services.v1.schema.json` (`ModelAlias`, `DataClass`)
- ADR 0029 (the data class cap of a tool server outside the suite)
