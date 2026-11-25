# Model gateway

Modules reach language models through LiteLLM (profile `litellm`) and nothing else. They
name an **alias**, never a model or a provider, and each module calls with a **key of its
own**. The gateway keeps usage counts per key and **stores no request or response
contents**.

## Aliases

| Alias | Purpose | Maps onto |
|---|---|---|
| `papaia-chat` | conversation, tool calls | `PAPAIA_DEFAULT_MODEL` |
| `papaia-structured` | structured output (`json_schema`) | `PAPAIA_DEFAULT_MODEL` |
| `papaia-embed` | embeddings (RAG profile only) | `PAPAIA_DEFAULT_EMBED_MODEL` |

Every render of `ai/litellm/config.yaml` adds one entry per alias to LiteLLM's model
list, with the parameters of the model the variable names (a LocalAI model or an entry of
the overlay `$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`). When the variable is
empty there is no alias, and when it names no model of the list the render warns and
leaves the alias out. An overlay entry with an alias's name replaces the generated one,
so an alias can also be pointed at another model directly:

```yaml
# $PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml
model_list:
  - model_name: papaia-chat
    litellm_params:
      model: openai/my-model
      api_base: http://localai:8080/v1
      api_key: os.environ/LOCALAI_API_KEY
```

`papaia-ctl start` renders the file again; no module file changes when an alias moves.

## Default model

`papaia-ctl setup --local-ai` names the shipped default model in `PAPAIA_DEFAULT_MODEL`
(root `.env`) unless a model is named there already:

| Variant (`--localai-variant`) | Default model | File |
|---|---|---|
| `cpu` (default) | `qwen2.5-7b-instruct-q4` | Qwen2.5-7B-Instruct, Q4_K_M (about 4.7 GB) |
| an accelerator variant | `qwen2.5-7b-instruct-q8` | Qwen2.5-7B-Instruct, Q8_0 (about 8 GB) |

Both are Apache-2.0. The smallest variant, `qwen2.5-1.5b-instruct` (Q4_K_M), can be named
by hand for small machines. The render adds the download line of a named shipped default
to the rendered `ai/localai/models.txt`, so LocalAI fetches it on its next start and
LiteLLM registers it: no model has to be entered by hand. `--no-local-ai` drops a shipped
default from `PAPAIA_DEFAULT_MODEL`; a model the operator named stays. Without either flag
`setup` leaves the variable alone, so an existing installation does not start a download
on its own.

## One key per module

A module that declares model needs in its manifest (`exposes[].models.needs`, contract
generation 7) gets a LiteLLM virtual key of its own when it starts. A need names
`alias` (`papaia-<purpose>`) and may name `features` (`chat`, `tools`, `json_schema`,
`json_object`, `stream`, `embeddings`), `min_context` (an integer of at least 1024) and
`max_class` (a data class); `models` holds `needs` only. Any other field is refused with
its name, and so is the add-on's start.

- key alias `module-<name>`, budget tag `metadata.tags: [module:<name>]`;
- models: exactly the aliases the module declares, so it can reach no model by name and
  no alias it did not declare (`403`);
- routes (`allowed_routes`): `/v1/chat/completions`, `/v1/embeddings`, their unversioned
  twins and the listing `/v1/models` (`/models`), the routes the class guard judges (see
  below); every other route of the gateway (text completion, responses, files, batches,
  assistants, audio, images, rerank, pass-through, key and model management) answers
  `403` to a module key before any handler runs;
- stored in `$PAPAIA_CONFIG_DIR/addons/<name>/.env` (mode `0600`) as `PAPAIA_MODEL_KEY`,
  which the add-on's containers receive with its `.env`.

`papaia-ctl addon start <name>` makes or checks the key before the add-on starts.
`papaia-ctl start` does the same for every active module once LiteLLM is up, and starts
again every add-on whose key changed. An add-on whose manifest is malformed is reported
and skipped; the others still get their keys. Should LiteLLM stop answering after an old
key was deleted and before the new one exists, the old key leaves the add-on's `.env`,
and the next `start` makes the new one. A key is kept while LiteLLM knows it and its models,
declared classes and route list match the declaration; otherwise the old key is revoked
and a new one made (so the first start after an update replaces every key made without the
route list). When a module
no longer declares needs, its key is revoked.

The calls run inside the LiteLLM container (`docker exec`) with the master key of that
container's own environment: the master key does not travel over the network, and no
module and no add-on file ever receives it. The calls need LiteLLM on the host where
`papaia-ctl` runs; in a distributed installation with LiteLLM on another node, `start`
reports that the keys could not be checked.

LibreChat still calls with the master key; a key of its own is planned.

## Data class of a route

Each alias carries the highest data class its route may receive, one class of the kit scale
`public` < `internal` < `partner_contact` < `personal` < `employee` < `confidential` <
`special` < `professional_secret`. The render takes it, per alias,

1. from `model_info.papaia_max_class` of the alias's entry in the overlay
   `$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`;
2. otherwise from `PAPAIA_MODEL_MAX_CLASS` in the root `.env`, which applies to every alias;
3. otherwise `internal`.

```yaml
# $PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml
model_list:
  - model_name: papaia-chat
    litellm_params:
      model: hosted_vllm/my-model
      api_base: http://localai:8080/v1
      api_key: os.environ/LOCALAI_API_KEY
    model_info:
      papaia_max_class: confidential
      papaia_features: [chat, tools, stream]   # optional, see below
      papaia_context: 32768                    # optional, see below
```

Rules of the render:

- A value outside the scale (an unknown name, another spelling or case, an empty value,
  surrounding text) stops the render with the model and the value; it never falls back
  to the default. The same holds for `PAPAIA_MODEL_MAX_CLASS`.
- Only the overlay sets the class. A `papaia_max_class` from the repository, a profile or
  an add-on fragment is dropped and reported, so an add-on cannot raise the class of a
  route.
- A hosted test model ([hosted-test-model.md](hosted-test-model.md)) receives at most
  `internal`, whatever the overlay or the root setting say; the render reports the cap.
- An alias that reaches more than one model (several entries with its name, `fallbacks`,
  `context_window_fallbacks`, `content_policy_fallbacks`, `default_fallbacks` or
  `model_group_alias` in `router_settings` or `litellm_settings`) gets the lowest class of
  every model it can reach.

The render writes the result into the route file
`$PAPAIA_CONFIG_DIR/ai/litellm/model-routes.json` (mode 0644; format
`papaia.model-routes/1`, the generation time and alias to class, no endpoint and no key),
which the gateway container mounts read-only. The file is rewritten only when a class
changes, and each alias whose class changed leaves one `config_changed` row
(`model_route.class`, the new class as `data_class`) in the audit outbox of `papaia-ctl`.

**Catalog.** The `models` block of the platform catalog lists every alias as a kit
`ModelAlias`: `alias`, `features`, `context`, `max_class` (the route class) and
`test_backend`. `features` follow the purpose of the alias (`papaia-chat`: `chat`,
`tools`, `stream`; `papaia-structured`: `chat`, `json_schema`, `json_object`, `stream`;
`papaia-embed`: `embeddings`) unless the overlay names them in
`model_info.papaia_features`; `context` comes from `model_info.papaia_context`, otherwise
from the `context_size` of the shipped LocalAI model the entry names, otherwise 4096.
Without the profile `litellm` the block stays empty. Modules take the class of a route
from this block only.

**Module needs.** The `max_class` of a need must be one class of the scale; any other
value refuses the start of the add-on with the value. The module key stores the declared
classes in its metadata `papaia_need_classes` (alias to class; the highest of several needs
of one alias; an alias with a need that names no class is left out and counts as the
highest class). A key whose stored classes differ from the declaration, or a key made
before this rule, is replaced like a key whose aliases changed (revocation journaled as
`key_revoke`).

**Start rule.** `papaia-ctl addon start` warns about each need whose `max_class` is above
the class of its route (module, alias, both classes), each needed alias without a route and
each need without a declared class; the key is made all the same. `papaia-ctl doctor
model_gateway_classes` reports the same as `warn` and fails when the route file is missing,
malformed or differs from the rendered configuration.

## Refusal above the route class

The module's own refusal, which reads the class from the catalog, is the first line. The
second is the class guard of the gateway (`papaia_hooks.papaia_class_guard`, registered
right after the halt hook), decided in
[ADR 0031](adr/0031-give-every-model-route-a-data-class-and-refuse-above-it-at-the-gateway.md).
It judges every model call made with a key other than the master key, before LiteLLM
routes it, so a refused request reaches no model and leaves no content in the gateway.

- **Request class.** A module names the class of a request in the header
  `x-papaia-data-class`: exactly one class of the scale, lower case, ASCII, at most 32
  characters. Without the header, the class the module declared for that alias
  (`papaia_need_classes` of its key) applies; a key without a declared class for the alias,
  or with a stored value off the scale, counts as `professional_secret`. The class is never
  taken from the request body.
- **Route class.** The class of the alias in the route file, mounted read-only at
  `/app/model-routes.json`. The file is checked with one `stat` per request and parsed
  again only when its identity changes; a file that is missing, unreadable, a symlink,
  larger than 256 KiB or not of the format `papaia.model-routes/1` counts as missing.
  Like `config.yaml`, the file is a single-file mount: a running gateway reads a changed
  route file after it is restarted, together with the configuration it describes.
- **Refusals**, before any backend call:

  | Case | Status | Code |
  |---|---|---|
  | request class above the route class | 403 | `class_exceeded` |
  | header above the module's declared class for the alias | 403 | `class_exceeded` |
  | header empty, a list, too long, not ASCII, with control characters or off the scale | 400 | `invalid_data_class` |
  | route file missing, unreadable or malformed; alias not in it | 503 | `route_class_unknown` |

  While the platform halt is active, `503 platform_halt` comes first and the class is not
  judged. A request at or below both classes passes unchanged.
- **Answer.** The response carries the headers `x-papaia-error-code` (the code above) and
  `x-papaia-correlation-id`. In the body, the pinned LiteLLM sets `error.code` to the HTTP
  status and keeps the code of the hook in
  `error.provider_specific_fields.error.code`, with the German / English text in
  `error.message`. Modules recognise a refusal by `x-papaia-error-code` (or that body
  field), never by the status alone or words of the message: `class_exceeded` is the
  error class `class_exceeded`, `invalid_data_class` is `invalid_input`,
  `route_class_unknown` is `upstream_unavailable`.
- **Audit.** Every refusal is one `papaia.audit/1` row (writer `litellm/class-guard`,
  operation `model.request`, effect `check`, `object_ref` `model_alias`/`<alias>`,
  `data_class` the request class, `null` for `invalid_data_class`, `result` `denied`,
  `error_code` the code, actor `module-<name>` as `sub`, `azp` and `service_account`) in
  the gateway's own outbox `$PAPAIA_CONFIG_DIR/audit/outbox/litellm.jsonl`, with the gapless
  `source_seq` counted in `litellm.seq` next to it. Both files (mode 0600) are made by the
  render and are the only files the gateway writes outside its database. The correlation id
  is the request's `x-papaia-correlation-id` when it is 1 to 64 characters of
  `[A-Za-z0-9-]` and not shaped like a key, otherwise a new UUIDv7. The row carries no
  message content, no header value off the scale, no key and no key hash. A row that cannot
  be written leaves the request refused and logs `audit_unavailable` with the code only.

Behaviour of the pinned LiteLLM (`v1.108.3`), checked with the image and covered by
`tools/tests/test_model_gateway_docker.py`:

- The hook receives the request headers as `data["proxy_server_request"]["headers"]`, a
  dict with lower-case names that LiteLLM builds from the HTTP request; a
  `proxy_server_request` or `metadata.headers` in the request body is replaced by it.
- A header sent twice reaches the hook as one entry with the last value, so a repeat
  cannot be told apart; a comma list in one header is refused as `invalid_data_class`.
  Either way the value is judged against the declared class and the route class.
- The master key reaches the hook with the role `proxy_admin`, no key alias and no key
  hash; only such a call is spared. A virtual key, of an admin user too, is judged.
- The text completion route (`/v1/completions`) would answer a refusal without the
  headers above, its code only in the message; no feature of the kit needs it, so it is
  not on the route list of module keys.

Remaining risk: the header is the module's own statement (it can lower the class of a
request within its declared class, never raise it above). Requests of the chat with the
master key are not judged. A route class is the operator's statement about a model. The
gateway's outbox is not yet delivered to `papaia-audit`: the rows are written in the
submission form of source `litellm` and wait in the outbox, like the outbox of
`papaia-ctl`.

## Revocation and the erasure journal

`papaia-ctl addon uninstall <name>` revokes the module key, and so does every replacement.
Before LiteLLM deletes a key, the core writes one entry of kind `key_revoke` into the
erasure journal `model-gateway` (`$PAPAIA_BACKUP_DIR/erasure-journal/model-gateway.jsonl`,
local copy in `$PAPAIA_CONFIG_DIR/state/erasure-journal/`), in the format of the journal
`identity` (see [lifecycle](./lifecycle.md)). The entry names the key by its id, the
SHA-256 LiteLLM stores, never by the key itself. A database brought back from an older
backup therefore cannot hand out a revoked key unnoticed: the journal lists what has to be
deleted again. A journal that cannot take the entry stops the revocation (and the
uninstall) while everything is still in place. The journal exists with the `lifecycle`
profile; without it, keys are revoked without an entry.

When LiteLLM does not answer during an uninstall, the entry is journaled, the key leaves
the add-on's `.env`, and the deletion waits in
`$PAPAIA_CONFIG_DIR/state/model-gateway/pending-revocations.json` (key id and module, no
key) until the next `papaia-ctl start`. All audit rows of one command run share one
correlation id.

Remaining risk: the management calls use LiteLLM's master key inside its container. The
replay of journaled revocations after a restored snapshot runs in `papaia-replay`
([replay.md](replay.md)), which deletes the key again over `/key/delete`. No management
key of the pinned LiteLLM limited to the deletion routes has been verified, so
`papaia-replay` holds the master key (a copy in
`$PAPAIA_CONFIG_DIR/security/replay/gateway-key`, mode 0600), named as a risk of its own;
it calls three routes and refuses every other path.

## No stored contents

The shipped configuration, and every render, carries:

```yaml
general_settings:
  store_prompts_in_spend_logs: false   # spend logs: counts, never prompt or answer
litellm_settings:
  turn_off_message_logging: true       # no messages or responses to any logger
  redact_user_api_key_info: true       # no key or user details in logs and callbacks
  callbacks:                           # none of them passes on a request body
    - "prometheus"                       # counts for /metrics
    - "papaia_hooks.papaia_listing_filter"
    - "papaia_hooks.papaia_platform_halt"  # see halt.md
    - "papaia_hooks.papaia_class_guard"    # see "Refusal above the route class"
```

The render refuses any layer (fragment or overlay) that changes one of these settings or
registers another callback (`callbacks`, `success_callback`, `failure_callback`,
`service_callback`, ...), since a logging callback would ship request contents to a third
place. It also refuses `litellm_settings.set_verbose: true` and `LITELLM_LOG=DEBUG` in
`ai/litellm/.env`, the settings that print request bodies to the log; response caching
(`litellm_settings.cache` or `cache_params`) of any type but `local`, since a Redis, S3,
disk or semantic cache keeps prompts and answers beyond the process (the proxy's default
type is Redis); and `general_settings.alerting`, which sends request details to a third
place.

What the gateway keeps: per request one spend-log row (`LiteLLM_SpendLogs`) with the key
id, the alias, token counts and the cost. Modules never send the `user` field, so their
rows name no person and their usage is counted per module key.

The chat does send `user`: its account id. For its requests the gateway keeps the account
id in the spend-log row (`end_user`), a daily sum per end user
(`LiteLLM_DailyEndUserSpend`) and an end-user record with the usage sum.
`papaia-ctl person export|erase` reads the usage sum of the person's end users
(`GET /customer/info` for her `sub`, chat account ids and mail address) and deletes the
end-user records (`POST /customer/delete`), through the management connection inside the
gateway's container; no other route is added (see
[person-requests.md](person-requests.md#the-core-services)). That erase does not reach the
spend-log rows and the daily sums: they keep the chat account id (counts and cost, no
content) for as long as the gateway database, since no retention period is set. The
erasure names them `not erased` and as not checked, until an erase path for them is
countersigned (proof MN-17). The gateway's container log also holds the chat account id;
it rotates at 5 x 10 MiB. `doctor model_gateway_content`
fails when the rendered configuration or `ai/litellm/.env` breaks one of the settings
above, so a usage record never holds content.

Checking it: send a request with a unique marker through a module key, then search the
LiteLLM database (`pg_dump --data-only` and the data directory of `litellm-postgresql`)
and `docker logs` of LiteLLM for the marker; there is no hit. The test
`tools/tests/test_model_gateway_docker.py` does exactly this with the pinned images.
