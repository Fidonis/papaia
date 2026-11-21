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
- stored in `$PAPAIA_CONFIG_DIR/addons/<name>/.env` (mode `0600`) as `PAPAIA_MODEL_KEY`,
  which the add-on's containers receive with its `.env`.

`papaia-ctl addon start <name>` makes or checks the key before the add-on starts.
`papaia-ctl start` does the same for every active module once LiteLLM is up, and starts
again every add-on whose key changed. An add-on whose manifest is malformed is reported
and skipped; the others still get their keys. Should LiteLLM stop answering after an old
key was deleted and before the new one exists, the old key leaves the add-on's `.env`,
and the next `start` makes the new one. A key is kept while LiteLLM knows it and its models
match the declaration; otherwise the old key is revoked and a new one made. When a module
no longer declares needs, its key is revoked.

The calls run inside the LiteLLM container (`docker exec`) with the master key of that
container's own environment: the master key does not travel over the network, and no
module and no add-on file ever receives it. The calls need LiteLLM on the host where
`papaia-ctl` runs; in a distributed installation with LiteLLM on another node, `start`
reports that the keys could not be checked.

LibreChat still calls with the master key; a key of its own is planned.

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

Remaining risk: the management calls use LiteLLM's master key inside its container. A
later replay of journaled revocations after a restore needs a management key as well;
where the pinned LiteLLM offers no key limited to the key routes, that process holds the
master key, named as a risk of its own.

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

What the gateway keeps: per request one spend-log row with the key id, the alias, token
counts and the cost, without the `user` field (modules never send it). Usage is therefore
counted per module key and never per person.

Checking it: send a request with a unique marker through a module key, then search the
LiteLLM database (`pg_dump --data-only` and the data directory of `litellm-postgresql`)
and `docker logs` of LiteLLM for the marker; there is no hit. The test
`tools/tests/test_model_gateway_docker.py` does exactly this with the pinned images.
